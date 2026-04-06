//! Target trait and implementations for Lightning nodes.

mod bitcoind;
mod cln;
mod eclair;
mod ldk;
mod lnd;

pub use cln::{ClnConfig, ClnTarget};
pub use eclair::{EclairConfig, EclairTarget};
pub use ldk::{LdkConfig, LdkTarget};
pub use lnd::{LndConfig, LndTarget};
use smite::scenarios::TargetError;

use std::net::SocketAddr;

/// Path where the crash handler writes crash data in local (non-Nyx) mode.
const CRASH_LOG_PATH: &str = "/tmp/smite-crash.log";

/// Checks if the crash handler was triggered in local mode.
///
/// In Nyx mode, crashes are reported directly via hypercall and we never get to
/// this point. In local mode, the crash handler writes crash data to a file.
///
/// Used by targets that have an external crash handler (CLN, Eclair).
///
/// # Errors
///
/// Returns [`TargetError::Crashed`] if the crash log file exists.
pub fn check_crash_log() -> Result<(), TargetError> {
    let crash_log = std::path::Path::new(CRASH_LOG_PATH);
    if crash_log.exists() {
        if let Ok(msg) = std::fs::read_to_string(crash_log) {
            log::error!("crash handler: {}", msg.trim());
        }
        let _ = std::fs::remove_file(crash_log);
        return Err(TargetError::Crashed);
    }
    Ok(())
}

/// A Lightning implementation that can be fuzzed.
///
/// This trait abstracts over different Lightning implementations (LND, CLN, LDK, etc.),
/// allowing scenarios to be written once and run against any target.
pub trait Target: Sized {
    /// Configuration for this target.
    type Config: Default;

    /// Start the target and any dependencies (e.g., bitcoind).
    ///
    /// # Errors
    ///
    /// Returns an error if the target fails to start.
    fn start(config: Self::Config) -> Result<Self, TargetError>;

    /// Target's identity public key.
    fn pubkey(&self) -> &secp256k1::PublicKey;

    /// Target's P2P listen address.
    fn addr(&self) -> SocketAddr;

    /// Check if target is still alive. Returns `Err(Crashed)` if dead.
    ///
    /// Implementation varies by target:
    /// - LND: Pipe-based coverage sync (Go can't write to AFL shm directly)
    /// - CLN/LDK: Process liveness check (C/Rust AFL instrumentation writes directly)
    /// - Eclair: Process liveness check (Java agent writes directly via JNI shmat)
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Crashed`] if the target has crashed.
    fn check_alive(&mut self) -> Result<(), TargetError>;
}
