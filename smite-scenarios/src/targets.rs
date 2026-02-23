//! Target trait and implementations for Lightning nodes.

mod cln;
mod eclair;
mod ldk;
mod lnd;

pub use cln::{ClnConfig, ClnTarget};
pub use eclair::{EclairConfig, EclairTarget};
pub use ldk::{LdkConfig, LdkTarget};
pub use lnd::{LndConfig, LndTarget};

use std::net::SocketAddr;

/// Error from target operations.
#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    /// Target failed to start.
    #[error("failed to start: {0}")]
    StartFailed(String),

    /// Target crashed.
    #[error("target crashed")]
    Crashed,

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
