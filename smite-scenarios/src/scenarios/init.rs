//! Fuzz init scenario - fuzzes the BOLT 1 init message with valid encryption.

use std::time::Duration;

use secp256k1::SecretKey;
use smite::bolt;
use smite::bolt::Message;
use smite::noise::{MAX_MESSAGE_SIZE, NoiseConnection};
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};

use super::{EPHEMERAL_KEY, STATIC_KEY, connect_to_target, ping_pong};
use crate::targets::Target;

/// Timeout for connection and message operations.
const TIMEOUT: Duration = Duration::from_secs(5);

/// A scenario that fuzzes the BOLT 1 init message.
///
/// Completes the Noise handshake and receives the target's init message
/// pre-snapshot. Each iteration sends a properly encrypted init message
/// with fuzz payload, testing the target's init validation logic (feature
/// negotiation, TLV parsing, dependency graph checks).
///
/// After sending the fuzz init, if the target stays connected we do a
/// ping-pong on the same connection to ensure it has processed the data
/// before checking for crashes.
pub struct InitScenario<T: Target> {
    target: T,
    conn: NoiseConnection,
}

impl<T: Target> Scenario for InitScenario<T> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let config = T::Config::default();
        let target = T::start(config)?;

        // Establish a warmup connection for ping-pong. This warms up the
        // target's message handling code paths before the Nyx snapshot
        // (important for JVM targets like Eclair).
        let mut warmup_conn = connect_to_target(&target, TIMEOUT)?;
        ping_pong(&mut warmup_conn)?;
        drop(warmup_conn);

        // Establish the fuzz connection, complete the handshake, and receive
        // the target's init.
        let local_static = SecretKey::from_byte_array(STATIC_KEY).expect("valid static key");
        let local_ephemeral =
            SecretKey::from_byte_array(EPHEMERAL_KEY).expect("valid ephemeral key");
        let mut conn = NoiseConnection::connect(
            target.addr(),
            *target.pubkey(),
            local_static,
            local_ephemeral,
            TIMEOUT,
        )?;

        let init_bytes = conn.recv_message()?;
        let Message::Init(_) = Message::decode(&init_bytes)? else {
            return Err(ScenarioError::Protocol("expected init message".into()));
        };

        Ok(Self { target, conn })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        let start = std::time::Instant::now();
        log::debug!(
            "[{:?}] Fuzzing init message ({} bytes)",
            start.elapsed(),
            input.len()
        );

        // Send an init-typed message with fuzz payload.
        let msg = bolt::message_with_type(bolt::msg_type::INIT, input);
        let truncated = &msg[..msg.len().min(MAX_MESSAGE_SIZE)];
        self.conn
            .send_message(truncated)
            .expect("fuzz init send successful");

        // Synchronize to ensure the target has processed the fuzz data.
        if let Err(e) = ping_pong(&mut self.conn) {
            log::debug!("[{:?}] ping_pong: {e}", start.elapsed());
            if e.is_timeout() {
                return ScenarioResult::Fail("target hung (ping timeout)".into());
            }
            // Non-timeout error likely means the target closed the connection.
            // This is expected for invalid init messages, but it could also
            // mean the target crashed. Use check_alive below to distinguish.
        } else {
            log::debug!("[{:?}] Target responded with pong", start.elapsed());
        }

        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail("target crashed".into());
        }

        ScenarioResult::Ok
    }
}
