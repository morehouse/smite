//! Campaign launch orchestration.
//!
//! Builds the Docker image, prepares the Nyx sharedir, spawns parallel
//! `afl-fuzz` processes in the background, and persists campaign state so
//! that `stop` and `status` can manage the running campaign later.

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;

use crate::commands::build::{BuildInputs, run_build};
use crate::config::CampaignConfig;
use crate::state::{CampaignState, RunnerState, Status};

/// Maximum time to wait for all runners to report non-zero `execs_per_sec`.
const STARTUP_TIMEOUT: Duration = Duration::from_mins(5);

/// How often to poll `fuzzer_stats` files during startup verification.
const STARTUP_POLL_INTERVAL: Duration = Duration::from_secs(5);

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

        let campaign_id = config.campaign_id();
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

        let mut state = CampaignState::new(campaign_id, &config, image, image_digest, git_hash);

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
        true
    }
}

/// Runs `scripts/setup-nyx.sh` to prepare the Nyx sharedir.
fn setup_nyx(config: &CampaignConfig, image: &str) -> bool {
    let script = config.smite_dir.join("scripts").join("setup-nyx.sh");
    if !script.exists() {
        log::error!("setup-nyx.sh not found: {}", script.display());
        return false;
    }

    let status = match Command::new(&script)
        .arg(&config.sharedir)
        .arg(image)
        .arg(&config.aflpp_path)
        .status()
    {
        Ok(status) => status,
        Err(e) => {
            log::error!("failed to run setup-nyx.sh: {e}");
            return false;
        }
    };

    if !status.success() {
        log::error!("setup-nyx.sh failed with {status}");
        return false;
    }

    log::info!("Nyx sharedir ready at {}", config.sharedir.display());
    true
}

/// Spawns all runners, verifies they reach non-zero `execs_per_sec`, and updates
/// campaign state. Runner PIDs are persisted so `smitebot stop` can terminate them.
fn launch_runners(
    config: &CampaignConfig,
    seed_dir: &Path,
    state: &mut CampaignState,
    state_path: &Path,
) -> bool {
    log::info!("starting {} runners", config.runners);

    let mut runners = Vec::new();
    let mut children = Vec::new();
    for id in 0..config.runners {
        match spawn_runner(config, id, seed_dir) {
            Ok((runner, child)) => {
                log::info!("spawned runner {id} (pid {})", runner.pid);
                runners.push(runner);
                children.push(child);
            }
            Err(e) => {
                log::error!("failed to spawn runner {id}: {e}");
                kill_runners(&runners);
                state.status = Status::Failed;
                state.runners = runners;
                if let Err(e) = state.save(state_path) {
                    log::warn!("failed to save state: {e}");
                }
                return false;
            }
        }
    }

    state.runners = runners;

    // Persist PIDs before the lengthy verify_startup poll so smitebot stop
    // can find the runners if we crash during verification.
    if let Err(e) = state.save(state_path) {
        log::warn!("failed to save state: {e}");
    }

    log::info!("waiting for runners to initialize");
    if !verify_startup(&config.output_dir, &state.runners, &mut children) {
        log::error!("not all runners started within the timeout");
        kill_runners(&state.runners);
        state.status = Status::Failed;
        if let Err(e) = state.save(state_path) {
            log::warn!("failed to save state: {e}");
        }
        return false;
    }

    state.status = Status::Running;
    true
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

/// Spawns a single `afl-fuzz` process in its own process group.
///
/// The child is intentionally orphaned so the campaign outlives the `smitebot`
/// process. The `stop` command uses the persisted PID to terminate it later.
fn spawn_runner(
    config: &CampaignConfig,
    id: u16,
    seed_dir: &Path,
) -> std::io::Result<(RunnerState, Child)> {
    let afl_fuzz = config.aflpp_path.join("afl-fuzz");
    let name = id.to_string();

    let mut cmd = Command::new(&afl_fuzz);
    cmd.arg("-Y");
    cmd.arg("-i").arg(seed_dir);
    cmd.arg("-o").arg(&config.output_dir);

    // Runner 0 is the primary (-M), all others are secondaries (-S).
    if id == 0 {
        cmd.arg("-M").arg(&name);
    } else {
        cmd.arg("-S").arg(&name);
    }

    for flag in &config.afl_flags {
        cmd.arg(flag);
    }

    cmd.arg("--").arg(&config.sharedir);

    // IR mutator defaults first so user afl_env can override them.
    for (key, val) in ir_mutator_envs(config) {
        cmd.env(key, val);
    }

    for (key, val) in &config.afl_env {
        cmd.env(key, val);
    }

    cmd.process_group(0);

    let child = cmd.spawn()?;
    let state = RunnerState {
        id,
        pid: child.id(),
    };
    Ok((state, child))
}

/// Polls for `fuzzer_stats` files to confirm all runners have started executing.
///
/// AFL++ creates `<output_dir>/<runner_name>/fuzzer_stats` once fuzzing begins.
/// We verify `execs_per_sec` is non-zero to confirm actual execution, not just
/// file creation.
fn verify_startup(output_dir: &Path, runners: &[RunnerState], children: &mut [Child]) -> bool {
    let deadline = Instant::now() + STARTUP_TIMEOUT;

    while Instant::now() < deadline {
        let all_started = runners
            .iter()
            .all(|r| has_nonzero_execs(&output_dir.join(r.name()).join("fuzzer_stats")));

        if all_started {
            return true;
        }

        for (child, runner) in children.iter_mut().zip(runners.iter()) {
            match child.try_wait() {
                Ok(Some(_)) => {
                    log::error!(
                        "runner {} (pid {}) died during startup",
                        runner.id,
                        runner.pid
                    );
                    return false;
                }
                Ok(None) => {}
                Err(e) => {
                    log::error!(
                        "failed to check runner {} (pid {}): {e}",
                        runner.id,
                        runner.pid
                    );
                    return false;
                }
            }
        }

        thread::sleep(STARTUP_POLL_INTERVAL);
    }

    for runner in runners {
        let stats = output_dir.join(runner.name()).join("fuzzer_stats");
        if !has_nonzero_execs(&stats) {
            log::error!(
                "runner {} (pid {}) did not reach non-zero execs_per_sec",
                runner.id,
                runner.pid
            );
        }
    }

    false
}

/// Returns true if the `fuzzer_stats` file exists and reports non-zero `execs_per_sec`.
fn has_nonzero_execs(path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    contents.lines().any(|line| {
        line.trim_start().starts_with("execs_per_sec")
            && line
                .split(':')
                .nth(1)
                .and_then(|v| v.trim().parse::<f64>().ok())
                .is_some_and(|n| n > 0.0)
    })
}

/// Kills all runner process groups via SIGKILL.
fn kill_runners(runners: &[RunnerState]) {
    for runner in runners {
        let pgid = format!("-{}", runner.pid);
        match Command::new("kill").args(["-9", &pgid]).status() {
            Ok(status) if status.success() => {
                log::info!("killed runner {} (pgid {})", runner.id, runner.pid);
            }
            _ => {
                log::warn!("failed to kill runner {} (pgid {})", runner.id, runner.pid);
            }
        }
    }
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
    fn verify_startup_detects_fuzzer_stats() {
        let dir = tempfile::tempdir().unwrap();
        let runners = vec![
            RunnerState { id: 0, pid: 100 },
            RunnerState { id: 1, pid: 101 },
        ];

        let stats_content = "start_time        : 1718000000\nexecs_per_sec     : 531.23\n";
        for runner in &runners {
            let runner_dir = dir.path().join(runner.name());
            fs::create_dir_all(&runner_dir).unwrap();
            fs::write(runner_dir.join("fuzzer_stats"), stats_content).unwrap();
        }

        let mut children: Vec<Child> = (0..2)
            .map(|_| Command::new("sleep").arg("60").spawn().unwrap())
            .collect();

        assert!(verify_startup(dir.path(), &runners, &mut children));

        for mut child in children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn verify_startup_detects_dead_runner() {
        let dir = tempfile::tempdir().unwrap();
        let runners = vec![RunnerState { id: 0, pid: 100 }];

        // No fuzzer_stats file — runner hasn't started yet.
        // Child exits immediately, so try_wait should detect death.
        let mut children = vec![Command::new("false").spawn().unwrap()];

        // Give the process a moment to exit.
        thread::sleep(Duration::from_millis(50));

        assert!(!verify_startup(dir.path(), &runners, &mut children));
    }

    #[test]
    fn has_nonzero_execs_rejects_zero() {
        let dir = tempfile::tempdir().unwrap();
        let stats = dir.path().join("fuzzer_stats");
        fs::write(
            &stats,
            "start_time        : 1718000000\nexecs_per_sec     : 0.00\n",
        )
        .unwrap();
        assert!(!has_nonzero_execs(&stats));
    }

    #[test]
    fn has_nonzero_execs_rejects_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_nonzero_execs(&dir.path().join("missing")));
    }

    #[test]
    fn has_nonzero_execs_accepts_positive_value() {
        let dir = tempfile::tempdir().unwrap();
        let stats = dir.path().join("fuzzer_stats");
        fs::write(
            &stats,
            "start_time        : 1718000000\nexecs_per_sec     : 531.23\n",
        )
        .unwrap();
        assert!(has_nonzero_execs(&stats));
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
                dir.path().join("out").display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        assert!(ir_mutator_envs(&config).is_empty());
    }
}
