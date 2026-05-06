//! Scenario implementations and helpers.

mod encrypted_bytes;
mod init;
mod noise;

pub use encrypted_bytes::EncryptedBytesScenario;
pub use init::InitScenario;
pub use noise::NoiseScenario;
use smite::scenarios::ScenarioError;

use std::time::Duration;

use bitcoin::secp256k1::SecretKey;
use smite::bolt::{Init, Message, Ping};
use smite::noise::NoiseConnection;

use crate::targets::Target;

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

/// Perform a Noise handshake with a target and receive its `Init` message.
///
/// Returns the encrypted connection and the target's `Init`. The caller is
/// responsible for sending its own `Init` response (e.g., via `Init::echo`).
///
/// # Errors
///
/// Returns an error if connection, handshake, or init receive fails.
#[allow(clippy::missing_panics_doc)] // Static keys are known-valid constants
pub fn handshake_with_target<T: Target>(
    target: &T,
    timeout: Duration,
) -> Result<(NoiseConnection, Init), ScenarioError> {
    let local_static = SecretKey::from_slice(&STATIC_KEY).expect("valid static key");
    let local_ephemeral = SecretKey::from_slice(&EPHEMERAL_KEY).expect("valid ephemeral key");

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

    log::debug!("Handshake complete, received target init");

    Ok((conn, init))
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
