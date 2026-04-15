//! Program execution context from snapshot setup.
//!
//! A [`ProgramContext`] carries target specific state (public key, chain hash,
//! block height, features) that is recorded before the Nyx snapshot is taken.
//! `Load*FromContext` operations read from this context at execution time.

/// State captured during snapshot setup, available to IR programs at execution
/// time via `LoadContext*` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramContext {
    /// Target node's compressed public key.
    pub target_pubkey: [u8; 33],
    /// Chain hash (genesis block hash).
    pub chain_hash: [u8; 32],
    /// Current block height at snapshot time.
    pub block_height: u32,
    /// Target's advertised feature bits from init message.
    pub target_features: Vec<u8>,
}
