//! BOLT 8 Noise protocol implementation for Lightning Network transport.
//!
//! This module implements the `Noise_XK` handshake pattern used by Lightning nodes
//! to establish encrypted, authenticated connections.

mod cipher;
mod connection;
mod error;
mod handshake;

pub use cipher::{ENCRYPTED_LENGTH_SIZE, MAC_SIZE, MAX_MESSAGE_SIZE, NoiseCipher};
pub use connection::{ConnectionError, NoiseConnection};
pub use error::NoiseError;
pub use handshake::{ACT_ONE_SIZE, ACT_THREE_SIZE, ACT_TWO_SIZE, NoiseHandshake};

#[cfg(test)]
mod tests;
