//! Campaign state persistence.
//!
//! Each running campaign writes its state to a JSON file under
//! `~/.smitebot/runs/<campaign-id>/state.json`. The `stop` and `status`
//! commands read this file to locate and manage running campaigns.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Target;

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
    pub image_digest: Option<String>,
    /// AFL++ output directory containing runner findings and stats.
    pub output_dir: PathBuf,
    /// Path to the Nyx sharedir.
    pub sharedir: PathBuf,
    /// Smite repository git hash at campaign start.
    pub smite_git_hash: Option<String>,
    /// ISO 8601 timestamp when the campaign started.
    pub start_time: String,
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
    /// AFL++ runner name used with -M/-S flag.
    pub name: String,
    /// Process ID of the afl-fuzz instance.
    pub pid: u32,
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
    /// Returns the base directory for all campaign state: `~/.smitebot/runs`.
    ///
    /// Returns `None` if the home directory cannot be determined.
    pub fn runs_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".smitebot").join("runs"))
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
            id: "lnd-encrypted_bytes-20260609T120000".to_string(),
            status: Status::Running,
            target: Target::Lnd,
            scenario: "encrypted_bytes".to_string(),
            image: "smite-lnd-encrypted_bytes".to_string(),
            image_digest: Some("sha256:abc123".to_string()),
            output_dir: PathBuf::from("/tmp/smite-out"),
            sharedir: PathBuf::from("/tmp/smite-nyx"),
            smite_git_hash: Some("deadbeef".to_string()),
            start_time: "2026-06-09T12:00:00Z".to_string(),
            runners: vec![
                RunnerState {
                    id: 0,
                    name: "0".to_string(),
                    pid: 1234,
                },
                RunnerState {
                    id: 1,
                    name: "1".to_string(),
                    pid: 1235,
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
        assert_eq!(loaded.runners[0].name, "0");
        assert_eq!(loaded.runners[1].pid, 1235);
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
    fn save_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = sample_state();

        state.save(&path).unwrap();

        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists());
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
