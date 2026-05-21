//! Core library for the smite coverage-guided fuzzing framework.
//!
//! Smite finds bugs in Lightning Network implementations by sending
//! fuzz-derived protocol messages to target nodes (LND, LDK, CLN, Eclair)
//! and checking whether they crash or violate invariants. This crate
//! provides the building blocks that scenarios and targets are built on.
//!
//! # Modules
//! - [`bitcoin`] - Utilities for interacting with `bitcoind` instances via `bitcoin-cli`.
//! - [`bolt`] - BOLT message encoding and decoding.
//! - [`channel_tx`] - BOLT 3 channel transaction construction (funding and commitment).
//! - [`noise`] - BOLT 8 `Noise_XK` encrypted transport.
//! - [`oracles`] - Post-scenario invariant checks.
//! - [`process`] - Managed subprocess utilities.
//! - [`runners`] - Fuzz input delivery (Nyx and local modes).
//! - [`scenarios`] - Scenario trait and the [`scenarios::smite_run`] entry point.

pub mod bitcoin;
pub mod bolt;
pub mod channel_tx;
pub mod noise;
pub mod oracles;
pub mod process;
pub mod runners;
pub mod scenarios;
