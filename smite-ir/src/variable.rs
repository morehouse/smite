//! Runtime variables produced by the executor.
//!
//! Variables exist only during program execution -- they are never serialized.
//! The serialized program stores data only in [`Operation`] literals.

use bitcoin::secp256k1::PublicKey;
use smite::bolt::{AcceptChannel, ChannelId};

const CHAIN_HASH_SIZE: usize = 32;
const PRIVATE_KEY_SIZE: usize = 32;

/// A typed runtime value produced by executing an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Variable {
    /// Raw bytes (scriptpubkeys, onion packets, etc.).
    Bytes(Vec<u8>),
    /// Chain hash (genesis block hash).
    ChainHash([u8; CHAIN_HASH_SIZE]),
    /// 32-byte channel identifier.
    ChannelId(ChannelId),
    /// secp256k1 public key.
    Point(PublicKey),
    /// secp256k1 private key.
    PrivateKey([u8; PRIVATE_KEY_SIZE]),
    /// Satoshi or millisatoshi amount.
    Amount(u64),
    /// Fee rate in sat/kw.
    FeeratePerKw(u32),
    /// Block height or count (`minimum_depth`, `cltv_expiry`, `locktime`).
    BlockHeight(u32),
    /// Generic u16 protocol parameter (`to_self_delay`, `max_accepted_htlcs`,
    /// `cltv_expiry_delta`, etc.).
    U16(u16),
    /// Generic u8 protocol parameter (`channel_flags`, `initiator`, etc.).
    U8(u8),
    /// Feature bits.
    Features(Vec<u8>),
    /// Encoded BOLT message with type prefix, ready to send.
    Message(Vec<u8>),
    /// Parsed `accept_channel` response.
    AcceptChannel(AcceptChannel),
}

impl Variable {
    /// Returns the type tag for this variable.
    #[must_use]
    pub fn var_type(&self) -> VariableType {
        match self {
            Self::Bytes(_) => VariableType::Bytes,
            Self::ChainHash(_) => VariableType::ChainHash,
            Self::ChannelId(_) => VariableType::ChannelId,
            Self::Point(_) => VariableType::Point,
            Self::PrivateKey(_) => VariableType::PrivateKey,
            Self::Amount(_) => VariableType::Amount,
            Self::FeeratePerKw(_) => VariableType::FeeratePerKw,
            Self::BlockHeight(_) => VariableType::BlockHeight,
            Self::U16(_) => VariableType::U16,
            Self::U8(_) => VariableType::U8,
            Self::Features(_) => VariableType::Features,
            Self::Message(_) => VariableType::Message,
            Self::AcceptChannel(_) => VariableType::AcceptChannel,
        }
    }
}

/// Lightweight type tag for variables, used by mutators for type-safe input
/// swapping and by builders for variable selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VariableType {
    Bytes,
    ChainHash,
    ChannelId,
    Point,
    PrivateKey,
    Amount,
    FeeratePerKw,
    BlockHeight,
    U16,
    U8,
    Features,
    Message,
    AcceptChannel,
}
