//! Campaign state persistence.
//!
//! Each running campaign writes its state to a JSON file under
//! `~/.smitebot/runs/<campaign-id>/state.json`. The `stop` and `status`
//! commands read this file to locate and manage running campaigns.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{CampaignConfig, Target};
use crate::utils;

/// Persisted state for a running fuzzing campaign.
#[derive(Debug, Serialize, Deserialize)]
pub struct CampaignState {
    /// Unique campaign identifier (<target>-<scenario>-<timestamp>).
    pub id: String,
    /// Current lifecycle status.
    pub status: Status,
    /// Lightning implementation being fuzzed.
    pub target: Target,
    /// Scenario binary name.
    pub scenario: String,
    /// Docker image tag used for this campaign.
    pub image: String,
    /// Docker image digest (image ID hash for locally built images).
    pub image_digest: String,
    /// AFL++ output directory containing runner findings and stats.
    pub output_dir: PathBuf,
    /// Path to the Nyx sharedir.
    pub sharedir: PathBuf,
    /// Smite repository git hash at campaign start.
    pub smite_git_hash: String,
    /// Unix timestamp (seconds since epoch) when the campaign started.
    pub start_time: u64,
    /// Name of the tmux session hosting the campaign runners.
    pub tmux_session: String,
    /// State of each AFL++ runner process.
    pub runners: Vec<RunnerState>,
}

/// Lifecycle status of a campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Runners are being spawned.
    Starting,
    /// All runners confirmed alive.
    Running,
    /// One or more runners failed to start.
    Failed,
}

/// State of a single AFL++ runner process.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunnerState {
    /// Runner index (0 = primary, 1..N = secondary).
    pub id: u16,
    /// Process ID of the afl-fuzz instance, read from `fuzzer_stats` after
    /// startup verification.
    pub pid: Option<u32>,
}

impl RunnerState {
    /// Returns the AFL++ runner name for this runner.
    ///
    /// Nyx parallel mode (`-Y`) requires numeric names: `0` for the primary
    /// runner and `N` (N >= 1) for secondaries.
    pub fn name(&self) -> String {
        self.id.to_string()
    }
}

/// Errors that can occur during state persistence.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("failed to create state directory {}: {source}", path.display())]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write state to {}: {source}", path.display())]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl CampaignState {
    /// Creates a new campaign state in the `Starting` phase.
    pub fn new(
        id: String,
        config: &CampaignConfig,
        image: String,
        image_digest: String,
        smite_git_hash: String,
        tmux_session: String,
    ) -> Self {
        Self {
            id,
            status: Status::Starting,
            target: config.target,
            scenario: config.scenario.clone(),
            image,
            image_digest,
            output_dir: config.output_dir.clone(),
            sharedir: config.sharedir.clone(),
            smite_git_hash,
            start_time: utils::epoch_secs(),
            tmux_session,
            runners: Vec::new(),
        }
    }

    /// Returns the base directory for all campaign state: `~/.smitebot/runs`.
    ///
    /// Returns `None` if the home directory cannot be determined.
    pub fn runs_dir() -> Option<PathBuf> {
        std::env::home_dir().map(|home| home.join(".smitebot").join("runs"))
    }

    /// Saves the campaign state as JSON, using an atomic write to prevent
    /// corruption if the process is interrupted.
    pub fn save(&self, path: &Path) -> Result<(), StateError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| StateError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let json =
            serde_json::to_string_pretty(self).expect("CampaignState is always serializable");
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &json).map_err(|source| StateError::Write {
            path: tmp.clone(),
            source,
        })?;
        // rename(2) is atomic on the same filesystem, so readers never see a partial file.
        fs::rename(&tmp, path).map_err(|source| StateError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> CampaignState {
        CampaignState {
            id: "lnd-encrypted_bytes-1_749_465_600".to_string(),
            status: Status::Running,
            target: Target::Lnd,
            scenario: "encrypted_bytes".to_string(),
            image: "smite-lnd-encrypted_bytes".to_string(),
            image_digest: "sha256:abc123".to_string(),
            output_dir: PathBuf::from("/tmp/smite-out"),
            sharedir: PathBuf::from("/tmp/smite-nyx"),
            smite_git_hash: "deadbeef".to_string(),
            start_time: 1_749_465_600,
            tmux_session: "lnd-encrypted_bytes-1_749_465_600".to_string(),
            runners: vec![
                RunnerState {
                    id: 0,
                    pid: Some(1234),
                },
                RunnerState {
                    id: 1,
                    pid: Some(1235),
                },
            ],
        }
    }

    #[test]
    fn save_round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = sample_state();

        state.save(&path).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let loaded: CampaignState = serde_json::from_str(&contents).unwrap();

        assert_eq!(loaded.id, state.id);
        assert_eq!(loaded.status, Status::Running);
        assert_eq!(loaded.target, Target::Lnd);
        assert_eq!(loaded.scenario, "encrypted_bytes");
        assert_eq!(loaded.runners.len(), 2);
        assert_eq!(loaded.tmux_session, state.tmux_session);
        assert_eq!(loaded.runners[0].name(), "0");
        assert_eq!(loaded.runners[1].pid, Some(1235));
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("state.json");
        let state = sample_state();

        state.save(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn save_removes_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = sample_state();

        state.save(&path).unwrap();

        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn new_initializes_starting_state() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "/home/user/AFLplusplus"
smite_dir = "."
runners = 4
output_dir = "/tmp/out"
sharedir = "/tmp/nyx"
"#,
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let state = CampaignState::new(
            "lnd-encrypted_bytes-1_749_465_600".to_string(),
            &config,
            "smite-lnd-encrypted_bytes".to_string(),
            "sha256:abc123".to_string(),
            "deadbeef".to_string(),
            "test-session".to_string(),
        );

        assert_eq!(state.status, Status::Starting);
        assert_eq!(state.target, Target::Lnd);
        assert_eq!(state.scenario, "encrypted_bytes");
        assert_eq!(state.image, "smite-lnd-encrypted_bytes");
        assert_eq!(state.image_digest, "sha256:abc123");
        assert_eq!(state.smite_git_hash, "deadbeef");
        assert_eq!(state.tmux_session, "test-session");
        assert!(state.runners.is_empty());
    }

    #[test]
    fn status_serializes_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&Status::Starting).unwrap(),
            "\"starting\""
        );
        assert_eq!(
            serde_json::to_string(&Status::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&Status::Failed).unwrap(),
            "\"failed\""
        );
    }
}
