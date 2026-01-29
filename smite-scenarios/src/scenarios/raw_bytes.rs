//! Raw bytes scenario - sends fuzz input directly as Lightning messages.

use std::time::Duration;

use smite::noise::NoiseConnection;
use smite::scenarios::{Scenario, ScenarioResult};

use super::{connect_to_target, ping_pong};
use crate::targets::Target;

/// A scenario that sends raw fuzz input as Lightning messages.
///
/// This is the simplest fuzzing scenario - it takes arbitrary bytes and sends
/// them over an encrypted Lightning connection. This can find parsing bugs or
/// crashes from malformed messages.
pub struct RawBytesScenario<T: Target> {
    target: T,
    conn: NoiseConnection,
}

impl<T: Target> Scenario for RawBytesScenario<T> {
    fn new(_args: &[String]) -> Result<Self, String> {
        let config = T::Config::default();
        let target = T::start(config).map_err(|e| e.to_string())?;
        let conn = connect_to_target(&target, Duration::from_secs(5)).map_err(|e| e.to_string())?;
        Ok(Self { target, conn })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        let start = std::time::Instant::now();

        // Send raw fuzz input over the encrypted connection
        if self.conn.send_message(input).is_err() {
            return ScenarioResult::Skip;
        }
        log::debug!(
            "[{:?}] Sent fuzz input ({} bytes)",
            start.elapsed(),
            input.len()
        );

        // Synchronize to ensure the previous message was received and initial
        // processing has been done. The target node could still be doing
        // further async processing of the message, but we have no good way to
        // tell whether that is happening.
        if let Err(e) = ping_pong(&mut self.conn) {
            log::debug!("[{:?}] ping_pong: {e}", start.elapsed());
        } else {
            log::debug!("[{:?}] Target responded with pong", start.elapsed());
        }

        // Check if target is still alive (and trigger coverage sync for LND)
        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail("target crashed".into());
        }

        ScenarioResult::Ok
    }
}
