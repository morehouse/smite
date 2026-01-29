//! Scenario implementations and helpers.

mod raw_bytes;

pub use raw_bytes::RawBytesScenario;

use std::time::Duration;

use secp256k1::SecretKey;
use smite::bolt::{BoltError, Init, Message, Ping};
use smite::noise::{ConnectionError, NoiseConnection};

use crate::targets::{Target, TargetError};

/// Static keys for Noise handshake. Using fixed keys ensures reproducibility
/// of fuzz failures across runs.
const STATIC_KEY: [u8; 32] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const EPHEMERAL_KEY: [u8; 32] = [
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
];

/// Error from scenario operations.
#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    /// Target failed to start or crashed.
    #[error("target error: {0}")]
    Target(#[from] TargetError),

    /// Connection or handshake failed.
    #[error("connection failed: {0}")]
    Connection(#[from] ConnectionError),

    /// Failed to decode a BOLT message.
    #[error("decode error: {0}")]
    Decode(#[from] BoltError),

    /// Protocol error (e.g., unexpected message).
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Connect to a target and perform the init handshake.
///
/// # Errors
///
/// Returns an error if connection, handshake, or init exchange fails.
#[allow(clippy::missing_panics_doc)] // Static keys are known-valid constants
pub fn connect_to_target<T: Target>(
    target: &T,
    timeout: Duration,
) -> Result<NoiseConnection, ScenarioError> {
    let local_static = SecretKey::from_byte_array(STATIC_KEY).expect("valid static key");
    let local_ephemeral = SecretKey::from_byte_array(EPHEMERAL_KEY).expect("valid ephemeral key");

    let mut conn = NoiseConnection::connect(
        target.addr(),
        *target.pubkey(),
        local_static,
        local_ephemeral,
        timeout,
    )?;

    // Receive and validate target's init message
    let init_bytes = conn.recv_message()?;
    let Message::Init(init) = Message::decode(&init_bytes)? else {
        return Err(ScenarioError::Protocol("expected init message".into()));
    };

    // Echo features back, removing TLVs
    let init = Init::echo(&init);
    let encoded = Message::Init(init).encode();
    conn.send_message(&encoded)?;

    log::debug!("Connected to target, init exchange complete");

    Ok(conn)
}

/// Send ping and wait for pong (for synchronization).
///
/// This ensures the target has done initial processing of any previously sent
/// message before we check if it's still alive.
///
/// # Errors
///
/// Returns an error if the connection is closed or times out.
pub fn ping_pong(conn: &mut NoiseConnection) -> Result<(), ScenarioError> {
    conn.send_message(&Message::Ping(Ping::new(0)).encode())?;

    // Read messages until we get a pong
    loop {
        let msg_bytes = conn.recv_message()?;
        if matches!(Message::decode(&msg_bytes)?, Message::Pong(_)) {
            return Ok(());
        }
        // Ignore other messages (warnings, errors, etc.)
    }
}
