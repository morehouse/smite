//! BOLT 3 channel transaction construction.
//!
//! This module builds Lightning channel on-chain transactions: the funding
//! transaction and the commitment transaction.

mod commitment;
mod funding;

pub use commitment::{
    ChannelConfig, ChannelPartyConfig, ChannelState, CommitmentError, CommitmentPartyState,
    CommitmentState, HolderIdentity, Side,
};
pub use funding::{FundingError, FundingTransaction, build_funding_transaction};
