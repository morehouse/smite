//! Program execution context from snapshot setup.
//!
//! A [`ProgramContext`] carries target specific state (public key, chain hash,
//! block height, features) that is recorded before the Nyx snapshot is taken.
//! `Load*FromContext` operations read from this context at execution time.

use serde::{Deserialize, Serialize};

/// State captured during snapshot setup, available to IR programs at execution
/// time via `LoadContext*` operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramContext {
    /// Target node's compressed public key.
    #[serde(with = "serde_array_33")]
    pub target_pubkey: [u8; 33],
    /// Chain hash (genesis block hash).
    pub chain_hash: [u8; 32],
    /// Current block height at snapshot time.
    pub block_height: u32,
    /// Target's advertised feature bits from init message.
    pub target_features: Vec<u8>,
}

/// Custom serde for `[u8; 33]` -- serde's derive only supports arrays up to 32.
mod serde_array_33 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.try_into()
            .map_err(|v: Vec<u8>| D::Error::invalid_length(v.len(), &"33"))
    }
}
