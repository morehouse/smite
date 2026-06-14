//! Campaign launch orchestration.
//!
//! Builds the Docker image, prepares the Nyx sharedir, spawns parallel
//! `afl-fuzz` processes in the background, and persists campaign state so
//! that `stop` and `status` can manage the running campaign later.

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;

use crate::commands::build::{BuildInputs, run_build};
use crate::config::CampaignConfig;
use crate::state::{CampaignState, RunnerState, Status};

/// Command handler for `smitebot start`.
pub struct StartCommand;

/// CLI arguments for `smitebot start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Path to the campaign configuration TOML file.
    path: PathBuf,
    /// Skip the Docker image build step.
    #[arg(long)]
    skip_build: bool,
    /// Skip the Nyx sharedir setup step.
    #[arg(long)]
    skip_setup: bool,
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

        if !args.skip_build {
            log::info!("building Docker image {image}");
            let inputs = BuildInputs::from_config(&config, &image);
            if !run_build(&inputs) {
                return false;
            }
        }

        if !args.skip_setup {
            log::info!("setting up Nyx sharedir at {}", config.sharedir.display());
            if !setup_nyx(&config, &image) {
                return false;
            }
        }

        let seed_dir = match ensure_seed_dir(&config) {
            Ok(dir) => dir,
            Err(e) => {
                log::error!("failed to prepare seed directory: {e}");
                return false;
            }
        };

        let Some(campaign_id) = generate_campaign_id(&config) else {
            log::error!("failed to generate campaign ID: could not determine current time");
            return false;
        };
        let Some(runs_dir) = CampaignState::runs_dir() else {
            log::error!("unable to determine home directory");
            return false;
        };

        let state_path = runs_dir.join(&campaign_id).join("state.json");
        let mut state = init_campaign_state(&config, campaign_id, &image);

        if let Err(e) = state.save(&state_path) {
            log::error!("{e}");
            return false;
        }

        log::info!("starting {} runners", config.runners);

        let mut runners = Vec::new();
        for id in 0..config.runners {
            let name = runner_name(id);
            match spawn_runner(&config, id, &name, &seed_dir) {
                Ok(pid) => {
                    log::info!("spawned {name} (pid {pid})");
                    runners.push(RunnerState { id, name, pid });
                }
                Err(e) => {
                    log::error!("failed to spawn {name}: {e}");
                    state.status = Status::Failed;
                    state.runners = runners;
                    if let Err(e) = state.save(&state_path) {
                        log::warn!("failed to save state: {e}");
                    }
                    return false;
                }
            }
        }

        state.runners = runners;

        log::info!("waiting for runners to initialize");
        let started = verify_startup(&config.output_dir, &state.runners);
        if !started {
            log::error!("not all runners started within the timeout");
            state.status = Status::Failed;
            if let Err(e) = state.save(&state_path) {
                log::warn!("failed to save state: {e}");
            }
            return false;
        }

        state.status = Status::Running;
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

/// Builds the initial campaign state before runners are spawned.
fn init_campaign_state(config: &CampaignConfig, campaign_id: String, image: &str) -> CampaignState {
    let git_hash = smite_git_hash(&config.smite_dir);
    let image_digest = docker_image_id(image);

    if git_hash.is_none() {
        log::warn!("could not determine smite git hash");
    }
    if image_digest.is_none() {
        log::warn!("could not determine Docker image digest for {image}");
    }

    CampaignState {
        id: campaign_id,
        status: Status::Starting,
        target: config.target,
        scenario: config.scenario.clone(),
        image: image.to_string(),
        image_digest,
        output_dir: config.output_dir.clone(),
        sharedir: config.sharedir.clone(),
        smite_git_hash: git_hash,
        start_time: run_date("--iso-8601=seconds").unwrap_or_else(|| "unknown".to_string()),
        runners: Vec::new(),
    }
}

/// Spawns a single `afl-fuzz` process in its own process group and returns its PID.
///
/// The child is intentionally orphaned so the campaign outlives the `smitebot`
/// process. The `stop` command uses the persisted PID to terminate it later.
fn spawn_runner(
    config: &CampaignConfig,
    id: u16,
    name: &str,
    seed_dir: &Path,
) -> std::io::Result<u32> {
    let afl_fuzz = config.aflpp_path.join("afl-fuzz");

    let mut cmd = Command::new(&afl_fuzz);
    cmd.arg("-Y");
    cmd.arg("-i").arg(seed_dir);
    cmd.arg("-o").arg(&config.output_dir);

    if id == 0 {
        cmd.arg("-M").arg(name);
    } else {
        cmd.arg("-S").arg(name);
    }

    for flag in &config.afl_flags {
        cmd.arg(flag);
    }

    cmd.arg("--").arg(&config.sharedir);

    // AFL++ needs these env vars to use the smite-ir custom mutator library.
    if config.scenario.starts_with("ir") {
        let mutator_lib = config
            .smite_dir
            .join("target")
            .join("release")
            .join("libsmite_ir_mutator.so");
        cmd.env("AFL_CUSTOM_MUTATOR_LIBRARY", &mutator_lib);
        cmd.env("AFL_CUSTOM_MUTATOR_ONLY", "1");
        cmd.env("AFL_FRAMESHIFT_DISABLE", "1");
        cmd.env("AFL_DISABLE_TRIM", "1");
    }

    for (key, val) in &config.afl_env {
        cmd.env(key, val);
    }

    cmd.process_group(0);

    let child = cmd.spawn()?;
    Ok(child.id())
}

/// Returns the AFL++ runner name for the given index.
///
/// Nyx parallel mode (`-Y`) requires numeric names: `-M 0` for the main
/// runner and `-S N` (N >= 1) for secondaries.
fn runner_name(id: u16) -> String {
    id.to_string()
}

/// Polls for `fuzzer_stats` files to confirm all runners have started executing.
///
/// AFL++ creates `<output_dir>/<runner_name>/fuzzer_stats` once fuzzing begins.
/// We verify `execs_per_sec` is non-zero to confirm actual execution, not just
/// file creation.
fn verify_startup(output_dir: &Path, runners: &[RunnerState]) -> bool {
    let timeout = Duration::from_mins(5);
    let poll_interval = Duration::from_secs(5);
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        let all_started = runners
            .iter()
            .all(|r| has_nonzero_execs(&output_dir.join(&r.name).join("fuzzer_stats")));

        if all_started {
            return true;
        }

        thread::sleep(poll_interval);
    }

    for runner in runners {
        let stats = output_dir.join(&runner.name).join("fuzzer_stats");
        if !has_nonzero_execs(&stats) {
            log::error!(
                "runner {} (pid {}) did not reach non-zero execs_per_sec",
                runner.name,
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

/// Generates a campaign ID from the target, scenario, and current time.
fn generate_campaign_id(config: &CampaignConfig) -> Option<String> {
    let timestamp = run_date("+%Y%m%dT%H%M%S")?;
    Some(format!("{}-{}-{timestamp}", config.target, config.scenario))
}

/// Runs the `date` command with the given format and returns its output.
fn run_date(fmt: &str) -> Option<String> {
    let output = Command::new("date").arg(fmt).output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns the smite repository git hash, or `None` if not a git repo.
fn smite_git_hash(smite_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(smite_dir)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns the Docker image ID hash for a locally built image.
fn docker_image_id(image: &str) -> Option<String> {
    let output = Command::new("docker")
        .arg("inspect")
        .arg("--format={{.Id}}")
        .arg(image)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn runner_name_is_numeric() {
        assert_eq!(runner_name(0), "0");
        assert_eq!(runner_name(1), "1");
    }

    #[test]
    fn generate_campaign_id_contains_target_and_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "/home/user/AFLplusplus"
smite_dir = "."
runners = 8
seed_dir = "/tmp/seeds"
output_dir = "/tmp/out"
sharedir = "/tmp/nyx"
"#,
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let id = generate_campaign_id(&config).unwrap();

        assert!(
            id.starts_with("lnd-encrypted_bytes-"),
            "id should start with target-scenario: {id}"
        );
    }

    #[test]
    fn verify_startup_detects_fuzzer_stats() {
        let dir = tempfile::tempdir().unwrap();
        let runners = vec![
            RunnerState {
                id: 0,
                name: "0".to_string(),
                pid: 100,
            },
            RunnerState {
                id: 1,
                name: "1".to_string(),
                pid: 101,
            },
        ];

        let stats_content = "start_time        : 1718000000\nexecs_per_sec     : 531.23\n";
        for runner in &runners {
            let runner_dir = dir.path().join(&runner.name);
            fs::create_dir_all(&runner_dir).unwrap();
            fs::write(runner_dir.join("fuzzer_stats"), stats_content).unwrap();
        }

        assert!(verify_startup(dir.path(), &runners));
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
}
