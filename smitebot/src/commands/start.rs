//! Campaign launch orchestration.
//!
//! Builds the Docker image, prepares the Nyx sharedir, spawns parallel
//! `afl-fuzz` processes inside a tmux session, and persists campaign state so
//! that `stop` and `status` can manage the running campaign later.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;

use crate::commands::build::{BuildInputs, run_build};
use crate::config::CampaignConfig;
use crate::state::{CampaignState, RunnerState, Status};
use crate::tmux;
use crate::utils::setup_nyx;
use crate::utils::shell_quote;

/// Safety ceiling for startup verification.
///
/// Genuine launch failures are caught immediately when a runner's tmux window
/// dies (see `verify_startup`), so this only bounds an alive-but-hung runner.
/// Nyx seed calibration can take several minutes because each exec restores a
/// VM snapshot, so the ceiling is deliberately generous; its exact value is not
/// load-bearing — it only prevents an indefinite hang. Kept comfortably above a
/// measured fresh start (~45s) so a large seed corpus is not falsely failed.
const VERIFY_TIMEOUT: Duration = Duration::from_mins(10);

/// How often to poll `fuzzer_stats` files during startup verification.
const VERIFY_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// AFL++ power schedules for round-robin distribution across runners.
const POWER_SCHEDULES: &[&str] = &["fast", "explore", "coe", "lin", "quad", "exploit", "rare"];

/// Command handler for `smitebot start`.
pub struct StartCommand;

/// CLI arguments for `smitebot start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Path to the campaign configuration TOML file.
    path: PathBuf,
}

impl StartCommand {
    /// Launches a fuzzing campaign from the given configuration.
    pub fn execute(args: &StartArgs) -> bool {
        let config = match CampaignConfig::load(&args.path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };

        let path_errors = config.check_paths();
        if !path_errors.is_empty() {
            for err in &path_errors {
                log::error!("{err}");
            }
            return false;
        }

        if !tmux::is_available() {
            log::error!("tmux is not available; install it or run `smitebot doctor` for details");
            return false;
        }

        let campaign_id = config.campaign_id();
        let tmux_session = config
            .tmux_session
            .clone()
            .unwrap_or_else(|| campaign_id.clone());

        if tmux::session_exists(&tmux_session) {
            log::error!(
                "tmux session '{tmux_session}' already exists — is another campaign running?"
            );
            return false;
        }

        if let Some(stats) = existing_campaign_runner(&config.output_dir, config.runners) {
            log::error!(
                "output_dir already holds a campaign ({}); smitebot start only \
                 begins fresh campaigns and does not resume — remove the directory \
                 or set a different output_dir",
                stats.display()
            );
            return false;
        }

        let image = config.image_tag();

        log::info!("building Docker image {image}");
        let inputs = BuildInputs::from_config(&config, &image);
        if !run_build(&inputs) {
            return false;
        }

        if config.scenario.starts_with("ir") && !build_ir_mutator(&config.smite_dir) {
            return false;
        }

        log::info!("setting up Nyx sharedir at {}", config.sharedir.display());
        if !setup_nyx(&config, &image) {
            return false;
        }

        let seed_dir = match ensure_seed_dir(&config) {
            Ok(dir) => dir,
            Err(e) => {
                log::error!("failed to prepare seed directory: {e}");
                return false;
            }
        };

        let Some(runs_dir) = CampaignState::runs_dir() else {
            log::error!("unable to determine home directory");
            return false;
        };

        let state_path = runs_dir.join(&campaign_id).join("state.json");

        let Some(git_hash) = smite_git_hash(&config.smite_dir) else {
            log::error!("could not determine smite git hash");
            return false;
        };
        let Some(image_digest) = docker_image_id(&image) else {
            log::error!("could not determine Docker image digest for {image}");
            return false;
        };

        let mut state = CampaignState::new(
            campaign_id,
            &config,
            image,
            image_digest,
            git_hash,
            tmux_session,
        );

        if let Err(e) = state.save(&state_path) {
            log::error!("{e}");
            return false;
        }

        if !launch_runners(&config, &seed_dir, &mut state, &state_path) {
            return false;
        }
        if let Err(e) = state.save(&state_path) {
            log::error!("{e}");
            return false;
        }

        log::info!("campaign {} is running", state.id);
        log::info!("state saved to {}", state_path.display());

        log::info!("attaching to tmux session '{}'", state.tmux_session);
        if let Err(e) = tmux::attach(&state.tmux_session) {
            log::warn!("failed to attach to tmux session: {e}");
        }

        true
    }
}

/// Spawns all runners inside a tmux session, verifies they produce
/// `fuzzer_stats`, and updates campaign state with PIDs.
fn launch_runners(
    config: &CampaignConfig,
    seed_dir: &Path,
    state: &mut CampaignState,
    state_path: &Path,
) -> bool {
    let session = &state.tmux_session;
    log::info!(
        "starting {} runners in tmux session '{session}'",
        config.runners
    );

    let testcache_mb = testcache_size_mb();
    let mut runners = Vec::new();

    for id in 0..config.runners {
        let cmd = build_runner_shell_cmd(config, id, seed_dir, testcache_mb);
        let window_name = tmux::runner_window_name(id);

        let result = if id == 0 {
            tmux::create_session(session, &window_name, &cmd)
        } else {
            tmux::add_window(session, &window_name, &cmd)
        };

        if let Err(e) = result {
            log::error!("failed to create tmux window for runner {id}: {e}");
            state.runners = runners;
            fail_campaign(state, state_path);
            return false;
        }

        runners.push(RunnerState { id, pid: None });
    }

    state.runners = runners;

    if let Err(e) = state.save(state_path) {
        log::warn!("failed to save state: {e}");
    }

    log::info!("verifying runners started");
    if !verify_startup(
        session,
        &config.output_dir,
        &mut state.runners,
        VERIFY_TIMEOUT,
    ) {
        // verify_startup has already logged the specific reason per runner
        // (window died, or ceiling reached).
        log::error!("one or more runners failed to start");
        fail_campaign(state, state_path);
        return false;
    }

    state.status = Status::Running;
    true
}

/// Marks the campaign as failed, logs instructions to inspect the tmux session,
/// and persists the updated state.
fn fail_campaign(state: &mut CampaignState, state_path: &Path) {
    if !state.runners.is_empty() {
        log::info!(
            "inspect tmux session '{}' for error output, \
             then: tmux kill-session -t {}",
            state.tmux_session,
            state.tmux_session,
        );
    }
    state.status = Status::Failed;
    if let Err(e) = state.save(state_path) {
        log::warn!("failed to save state: {e}");
    }
}

/// Ensures a seed directory exists for AFL++, creating a minimal corpus if needed.
///
/// When the user omits `seed_dir` from the config, AFL++ still requires `-i`
/// pointing to a non-empty directory.
fn ensure_seed_dir(config: &CampaignConfig) -> std::io::Result<PathBuf> {
    if let Some(dir) = &config.seed_dir {
        return Ok(dir.clone());
    }
    let seed_dir = config.output_dir.join(".seeds");
    fs::create_dir_all(&seed_dir)?;
    if seed_dir.read_dir()?.next().is_none() {
        fs::write(seed_dir.join("seed0"), b"\x00")?;
    }
    Ok(seed_dir)
}

/// Returns the path of the first runner `fuzzer_stats` already present under
/// `output_dir`, indicating a prior campaign's output.
///
/// `start` begins fresh campaigns only. A leftover `fuzzer_stats` would make
/// `verify_startup` read a stale PID and wrongly report a runner as started, so
/// its presence is rejected up front. Resuming an existing output dir is not yet
/// supported. AFL++ writes each runner's output to `output_dir/<id>` (see
/// `RunnerState::name`).
fn existing_campaign_runner(output_dir: &Path, runners: u16) -> Option<PathBuf> {
    (0..runners)
        .map(|id| output_dir.join(id.to_string()).join("fuzzer_stats"))
        .find(|p| p.exists())
}

/// Polls for `fuzzer_stats` files to confirm all runners have started,
/// extracting the `fuzzer_pid` from each.
///
/// `fuzzer_stats` is only written after AFL++ finishes calibrating every seed,
/// which under Nyx can take minutes for a large corpus, so a plain wall-clock
/// timeout produces false negatives. Instead, a runner whose tmux window has
/// died before producing `fuzzer_stats` is reported as a launch failure
/// immediately; the `timeout` only bounds a runner that stays alive but never
/// starts fuzzing. `execute` rejects a pre-populated `output_dir` up front (see
/// `existing_campaign_runner`), so a `fuzzer_stats` appearing here always
/// belongs to this run.
fn verify_startup(
    session: &str,
    output_dir: &Path,
    runners: &mut [RunnerState],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;

    loop {
        let mut all_ready = true;
        for runner in runners.iter_mut() {
            if runner.pid.is_some() {
                continue;
            }
            let stats_path = output_dir.join(runner.name()).join("fuzzer_stats");
            if let Some(pid) = read_fuzzer_pid(&stats_path) {
                runner.pid = Some(pid);
            } else {
                all_ready = false;
            }
        }

        if all_ready {
            return true;
        }

        // A runner whose window exited before writing fuzzer_stats failed to
        // launch; report it now rather than waiting out the ceiling.
        match tmux::dead_windows(session) {
            Ok(dead) => {
                let mut failed = false;
                for runner in runners.iter().filter(|r| r.pid.is_none()) {
                    if dead.contains(&tmux::runner_window_name(runner.id)) {
                        log::error!(
                            "runner {} exited before producing fuzzer_stats; \
                             inspect window '{}' in tmux session '{session}'",
                            runner.id,
                            tmux::runner_window_name(runner.id),
                        );
                        failed = true;
                    }
                }
                if failed {
                    return false;
                }
            }
            Err(e) => log::debug!("could not query tmux window liveness: {e}"),
        }

        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(VERIFY_POLL_INTERVAL);
    }

    for runner in runners.iter() {
        if runner.pid.is_none() {
            log::error!(
                "runner {} did not produce fuzzer_stats within timeout",
                runner.id
            );
        }
    }

    false
}

/// Reads the `fuzzer_pid` field from a `fuzzer_stats` file.
fn read_fuzzer_pid(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).ok()?;
    contents
        .lines()
        .find(|l| l.trim_start().starts_with("fuzzer_pid"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
}

/// Returns the strategy flags and env vars for a specific runner.
///
/// Distribution is deterministic by runner index. Runner 0 is primary.
fn runner_strategy(
    runner_id: u16,
    runner_count: u16,
    testcache_mb: Option<u64>,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut flags = Vec::new();
    let mut envs = Vec::new();

    let schedule = POWER_SCHEDULES[runner_id as usize % POWER_SCHEDULES.len()];
    flags.extend(["-p".to_string(), schedule.to_string()]);

    if runner_id == 0 {
        envs.push(("AFL_FINAL_SYNC".to_string(), "1".to_string()));
    }

    // AFL++ docs: the strategy knobs below apply to "the other secondaries",
    // not the primary. See fuzzing_in_depth.md §c "Using multiple cores".
    if runner_id > 0 {
        // -a binary on ~70% of secondary runners.
        let secondary_count = runner_count.saturating_sub(1) as usize;
        let binary_count = (secondary_count * 7).div_ceil(10);
        if ((runner_id - 1) as usize) < binary_count {
            flags.extend(["-a".to_string(), "binary".to_string()]);
        }

        // AFL_DISABLE_TRIM on ~60% of secondary runners.
        let trim_count = (secondary_count * 6).div_ceil(10);
        if ((runner_id - 1) as usize) < trim_count {
            envs.push(("AFL_DISABLE_TRIM".to_string(), "1".to_string()));
        }
    }

    // AFL_IMPORT_FIRST loads test cases from other fuzzers first, but the
    // AFL++ docs warn it "can slow down the start ... if you have many fuzzers."
    // 16 is a heuristic; AFL++ docs don't specify a threshold.
    if runner_count < 16 {
        envs.push(("AFL_IMPORT_FIRST".to_string(), "1".to_string()));
    }

    if let Some(size) = testcache_mb {
        envs.push(("AFL_TESTCACHE_SIZE".to_string(), size.to_string()));
    }

    (flags, envs)
}

/// Returns a suggested `AFL_TESTCACHE_SIZE` in MB based on available RAM.
fn testcache_size_mb() -> Option<u64> {
    let contents = fs::read_to_string("/proc/meminfo").ok()?;
    let free_mb = contents
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb / 1024)?;

    // AFL++ docs recommend 50–500 MB. Thresholds are conservative since
    // multiple runners share the same machine.
    Some(if free_mb > 32_000 {
        500
    } else if free_mb > 8_000 {
        250
    } else {
        50
    })
}

/// Builds the full shell command string for a single runner to be run by tmux.
fn build_runner_shell_cmd(
    config: &CampaignConfig,
    id: u16,
    seed_dir: &Path,
    testcache_mb: Option<u64>,
) -> String {
    let afl_fuzz = config.aflpp_path.join("afl-fuzz");
    let (strategy_flags, strategy_envs) = runner_strategy(id, config.runners, testcache_mb);

    // Env precedence: strategy → IR mutator → user afl_env (last wins).
    let mut envs = strategy_envs;
    for (k, v) in ir_mutator_envs(config) {
        envs.push((k.to_string(), v));
    }
    for (k, v) in &config.afl_env {
        envs.push((k.clone(), v.clone()));
    }

    let mut parts: Vec<String> = envs
        .iter()
        .map(|(k, v)| format!("{}={}", k, shell_quote(v)))
        .collect();

    parts.push("exec".to_string());
    parts.push(shell_quote(&afl_fuzz.display().to_string()));
    parts.extend([
        "-Y".to_string(),
        "-i".to_string(),
        shell_quote(&seed_dir.display().to_string()),
        "-o".to_string(),
        shell_quote(&config.output_dir.display().to_string()),
        if id == 0 { "-M" } else { "-S" }.to_string(),
        id.to_string(),
    ]);

    for flag in &strategy_flags {
        parts.push(shell_quote(flag));
    }
    for flag in &config.afl_flags {
        parts.push(shell_quote(flag));
    }

    parts.push("--".to_string());
    parts.push(shell_quote(&config.sharedir.display().to_string()));

    parts.join(" ")
}

/// Returns the environment variables needed for the smite-ir custom mutator.
///
/// For IR scenarios, these set up AFL++ to use the custom mutator library and
/// disable built-in mutators. Returns an empty vec for non-IR scenarios.
fn ir_mutator_envs(config: &CampaignConfig) -> Vec<(&'static str, String)> {
    if !config.scenario.starts_with("ir") {
        return Vec::new();
    }
    vec![
        (
            "AFL_CUSTOM_MUTATOR_LIBRARY",
            config.ir_mutator_path().to_string_lossy().into_owned(),
        ),
        ("AFL_CUSTOM_MUTATOR_ONLY", "1".to_string()),
        ("AFL_FRAMESHIFT_DISABLE", "1".to_string()),
    ]
}

/// Builds the smite-ir-mutator shared library in release mode.
fn build_ir_mutator(smite_dir: &Path) -> bool {
    log::info!("building IR mutator library");
    let status = match Command::new("cargo")
        .args(["build", "--release", "-p", "smite-ir-mutator"])
        .current_dir(smite_dir)
        .status()
    {
        Ok(status) => status,
        Err(e) => {
            log::error!("failed to run cargo build: {e}");
            return false;
        }
    };

    if !status.success() {
        log::error!("cargo build for smite-ir-mutator failed with {status}");
        return false;
    }

    true
}

/// Runs a command and returns its trimmed stdout on success.
fn command_stdout(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns the smite repository git hash, or `None` if not a git repo.
fn smite_git_hash(smite_dir: &Path) -> Option<String> {
    command_stdout(
        Command::new("git")
            .arg("-C")
            .arg(smite_dir)
            .args(["rev-parse", "HEAD"]),
    )
}

/// Returns the Docker image ID hash for a locally built image.
fn docker_image_id(image: &str) -> Option<String> {
    command_stdout(
        Command::new("docker")
            .args(["inspect", "--format={{.Id}}"])
            .arg(image),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn read_fuzzer_pid_parses_pid() {
        let dir = tempfile::tempdir().unwrap();
        let stats = dir.path().join("fuzzer_stats");
        fs::write(
            &stats,
            "start_time        : 1718000000\nfuzzer_pid        : 12345\nexecs_per_sec     : 0.00\n",
        )
        .unwrap();
        assert_eq!(read_fuzzer_pid(&stats), Some(12345));
    }

    #[test]
    fn read_fuzzer_pid_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_fuzzer_pid(&dir.path().join("missing")), None);
    }

    #[test]
    fn verify_startup_reads_pids_from_fuzzer_stats() {
        let dir = tempfile::tempdir().unwrap();
        let stats_content =
            "start_time        : 1718000000\nfuzzer_pid        : 42\nexecs_per_sec     : 0.00\n";

        let mut runners = vec![
            RunnerState { id: 0, pid: None },
            RunnerState { id: 1, pid: None },
        ];

        for runner in &runners {
            let runner_dir = dir.path().join(runner.name());
            fs::create_dir_all(&runner_dir).unwrap();
            fs::write(runner_dir.join("fuzzer_stats"), stats_content).unwrap();
        }

        // All stats are present on the first poll.
        assert!(verify_startup(
            "no-such-session",
            dir.path(),
            &mut runners,
            Duration::from_secs(5),
        ));
        assert_eq!(runners[0].pid, Some(42));
        assert_eq!(runners[1].pid, Some(42));
    }

    #[test]
    fn verify_startup_returns_false_when_stats_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut runners = vec![RunnerState { id: 0, pid: None }];

        // No fuzzer_stats and no live tmux session — the ceiling is hit and the
        // runner reported as unstarted. A near-zero timeout keeps the test fast.
        assert!(!verify_startup(
            "no-such-session",
            dir.path(),
            &mut runners,
            Duration::from_millis(1),
        ));
        assert!(runners[0].pid.is_none());
    }

    #[test]
    fn existing_campaign_runner_detects_leftover_fuzzer_stats() {
        let dir = tempfile::tempdir().unwrap();
        // A prior run of the secondary left fuzzer_stats behind.
        let runner_dir = dir.path().join("1");
        fs::create_dir_all(&runner_dir).unwrap();
        fs::write(runner_dir.join("fuzzer_stats"), "fuzzer_pid : 7\n").unwrap();

        assert_eq!(
            existing_campaign_runner(dir.path(), 2),
            Some(runner_dir.join("fuzzer_stats"))
        );
    }

    #[test]
    fn existing_campaign_runner_none_for_fresh_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Empty output dir (and one with only the synthesized .seeds) is fresh.
        assert_eq!(existing_campaign_runner(dir.path(), 4), None);
    }

    #[test]
    fn runner_strategy_primary_gets_final_sync() {
        let (flags, envs) = runner_strategy(0, 8, None);
        assert!(envs.iter().any(|(k, v)| k == "AFL_FINAL_SYNC" && v == "1"));
        assert!(flags.contains(&"-p".to_string()));
    }

    #[test]
    fn runner_strategy_secondary_no_final_sync() {
        let (_, envs) = runner_strategy(1, 8, None);
        assert!(!envs.iter().any(|(k, _)| k == "AFL_FINAL_SYNC"));
    }

    #[test]
    fn runner_strategy_cycles_power_schedules() {
        let schedules: Vec<String> = (0..7)
            .map(|id| {
                let (flags, _) = runner_strategy(id, 8, None);
                flags[1].clone()
            })
            .collect();
        assert_eq!(
            schedules,
            ["fast", "explore", "coe", "lin", "quad", "exploit", "rare"]
        );
    }

    #[test]
    fn runner_strategy_wraps_schedules_past_seven() {
        let (flags, _) = runner_strategy(7, 8, None);
        assert_eq!(flags[1], "fast");
    }

    #[test]
    fn runner_strategy_binary_hint_on_70_percent_of_secondaries() {
        // 10 runners: 1 primary + 9 secondary. 70% of 9 = 7 (ceil).
        let binary_count = (0..10u16)
            .filter(|&id| {
                let (flags, _) = runner_strategy(id, 10, None);
                flags.contains(&"-a".to_string())
            })
            .count();
        assert_eq!(binary_count, 7);

        // Primary never gets -a binary.
        let (flags, _) = runner_strategy(0, 10, None);
        assert!(!flags.contains(&"-a".to_string()));
    }

    #[test]
    fn runner_strategy_disable_trim_on_60_percent_of_secondaries() {
        // 10 runners: 1 primary + 9 secondary. 60% of 9 = 6 (ceil).
        let trim_count = (0..10u16)
            .filter(|&id| {
                let (_, envs) = runner_strategy(id, 10, None);
                envs.iter().any(|(k, _)| k == "AFL_DISABLE_TRIM")
            })
            .count();
        assert_eq!(trim_count, 6);

        // Primary never gets AFL_DISABLE_TRIM.
        let (_, envs) = runner_strategy(0, 10, None);
        assert!(!envs.iter().any(|(k, _)| k == "AFL_DISABLE_TRIM"));
    }

    #[test]
    fn runner_strategy_import_first_under_16() {
        let (_, envs) = runner_strategy(0, 8, None);
        assert!(envs.iter().any(|(k, _)| k == "AFL_IMPORT_FIRST"));

        let (_, envs) = runner_strategy(0, 16, None);
        assert!(!envs.iter().any(|(k, _)| k == "AFL_IMPORT_FIRST"));
    }

    #[test]
    fn runner_strategy_includes_testcache() {
        let (_, envs) = runner_strategy(0, 8, Some(500));
        assert!(
            envs.iter()
                .any(|(k, v)| k == "AFL_TESTCACHE_SIZE" && v == "500")
        );
    }

    #[test]
    fn build_runner_shell_cmd_primary() {
        let dir = tempfile::tempdir().unwrap();
        let config = sample_config(dir.path());
        let seed_dir = dir.path().join("seeds");

        let cmd = build_runner_shell_cmd(&config, 0, &seed_dir, Some(500));

        assert!(cmd.contains("exec"));
        assert!(cmd.contains("afl-fuzz"));
        assert!(cmd.contains("-Y"));
        assert!(cmd.contains("-M"));
        assert!(cmd.contains("AFL_FINAL_SYNC='1'"));
        assert!(cmd.contains("AFL_TESTCACHE_SIZE='500'"));
        assert!(cmd.contains("-p"));
    }

    #[test]
    fn build_runner_shell_cmd_secondary() {
        let dir = tempfile::tempdir().unwrap();
        let config = sample_config(dir.path());
        let seed_dir = dir.path().join("seeds");

        let cmd = build_runner_shell_cmd(&config, 1, &seed_dir, None);

        assert!(cmd.contains("-S"));
        assert!(!cmd.contains("-M"));
        assert!(!cmd.contains("AFL_FINAL_SYNC"));
    }

    #[test]
    fn build_runner_shell_cmd_respects_env_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 2
output_dir = "{}"
sharedir = "{}"

[afl_env]
AFL_DISABLE_TRIM = "0"
"#,
                dir.path().display(),
                dir.path().display(),
                dir.path().join("out").display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();
        let seed_dir = dir.path().join("seeds");

        // Use secondary runner (id=1) because primary doesn't get AFL_DISABLE_TRIM.
        let cmd = build_runner_shell_cmd(&config, 1, &seed_dir, None);

        // Strategy sets AFL_DISABLE_TRIM='1' first, user override AFL_DISABLE_TRIM='0' last.
        // Both appear; shell uses last assignment.
        let first_pos = cmd.find("AFL_DISABLE_TRIM='1'").unwrap();
        let last_pos = cmd.find("AFL_DISABLE_TRIM='0'").unwrap();
        assert!(last_pos > first_pos);
    }

    #[test]
    fn ensure_seed_dir_returns_user_path_when_specified() {
        let dir = tempfile::tempdir().unwrap();
        let seed = dir.path().join("my-seeds");
        fs::create_dir(&seed).unwrap();
        fs::write(seed.join("input0"), b"\x00").unwrap();

        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 1
seed_dir = "{}"
output_dir = "{}"
sharedir = "{}"
"#,
                dir.path().display(),
                dir.path().display(),
                seed.display(),
                dir.path().join("out").display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let result = ensure_seed_dir(&config).unwrap();
        assert_eq!(result, seed);
    }

    #[test]
    fn ensure_seed_dir_creates_minimal_corpus_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("out");
        fs::create_dir(&output_dir).unwrap();

        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 1
output_dir = "{}"
sharedir = "{}"
"#,
                dir.path().display(),
                dir.path().display(),
                output_dir.display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let result = ensure_seed_dir(&config).unwrap();
        assert_eq!(result, output_dir.join(".seeds"));
        assert!(result.join("seed0").exists());
    }

    #[test]
    fn ir_mutator_envs_sets_vars_for_ir_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "ir_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 1
output_dir = "{}"
sharedir = "{}"
"#,
                dir.path().display(),
                dir.path().display(),
                dir.path().join("out").display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let envs = ir_mutator_envs(&config);

        assert_eq!(envs.len(), 3);
        assert_eq!(envs[0].0, "AFL_CUSTOM_MUTATOR_LIBRARY");
        assert!(envs[0].1.ends_with("libsmite_ir_mutator.so"));
        assert_eq!(envs[1], ("AFL_CUSTOM_MUTATOR_ONLY", "1".to_string()));
        assert_eq!(envs[2], ("AFL_FRAMESHIFT_DISABLE", "1".to_string()));
    }

    #[test]
    fn ir_mutator_envs_empty_for_non_ir_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let config = sample_config(dir.path());
        assert!(ir_mutator_envs(&config).is_empty());
    }

    fn sample_config(dir: &Path) -> CampaignConfig {
        let config_path = dir.join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 8
output_dir = "{}"
sharedir = "{}"
"#,
                dir.display(),
                dir.display(),
                dir.join("out").display(),
                dir.join("nyx").display(),
            ),
        )
        .unwrap();
        CampaignConfig::load(&config_path).unwrap()
    }
}
