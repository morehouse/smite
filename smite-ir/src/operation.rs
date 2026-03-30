//! IR operations.

use std::fmt;
use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::VariableType;

/// An IR operation.  Each instruction in a program contains one operation plus
/// input variable indices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    // -- Load: produce a variable from an embedded literal or the context --
    /// Load a satoshi or millisatoshi amount.
    LoadAmount(u64),
    /// Load a fee rate in sat/kw.
    LoadFeeratePerKw(u32),
    /// Load a block height or count.
    LoadBlockHeight(u32),
    /// Load a u16 protocol parameter (e.g., `to_self_delay`).
    LoadU16(u16),
    /// Load a u8 protocol parameter (e.g., `channel_flags`).
    LoadU8(u8),
    /// Load raw bytes.
    LoadBytes(Vec<u8>),
    /// Load feature bits.
    LoadFeatures(Vec<u8>),
    /// Load a secp256k1 private key.  The executor validates that the bytes are
    /// in range `[1, curve_order)` and skips if not.
    LoadPrivateKey([u8; 32]),
    /// Load a 32-byte channel identifier.
    LoadChannelId([u8; 32]),
    /// Load the target node's public key from the program context.
    LoadTargetPubkeyFromContext,
    /// Load the chain hash from the program context.
    LoadChainHashFromContext,

    // -- Compute: derive a variable from inputs --
    /// Derive a compressed public key from a private key.
    /// Input: `PrivateKey`.
    DerivePoint,
    /// Extract a field from a parsed `accept_channel` response.
    /// Input: `AcceptChannel`.
    ExtractAcceptChannel(AcceptChannelField),

    // -- Build: construct a BOLT message from inputs --
    /// Build an `open_channel` message (BOLT 2, type 32).
    ///
    /// Inputs (20, matching wire order):
    ///   0: `chain_hash` (`ChainHash`)
    ///   1: `temporary_channel_id` (`ChannelId`)
    ///   2: `funding_satoshis` (`Amount`)
    ///   3: `push_msat` (`Amount`)
    ///   4: `dust_limit_satoshis` (`Amount`)
    ///   5: `max_htlc_value_in_flight_msat` (`Amount`)
    ///   6: `channel_reserve_satoshis` (`Amount`)
    ///   7: `htlc_minimum_msat` (`Amount`)
    ///   8: `feerate_per_kw` (`FeeratePerKw`)
    ///   9: `to_self_delay` (`U16`)
    ///  10: `max_accepted_htlcs` (`U16`)
    ///  11: `funding_pubkey` (`Point`)
    ///  12: `revocation_basepoint` (`Point`)
    ///  13: `payment_basepoint` (`Point`)
    ///  14: `delayed_payment_basepoint` (`Point`)
    ///  15: `htlc_basepoint` (`Point`)
    ///  16: `first_per_commitment_point` (`Point`)
    ///  17: `channel_flags` (`U8`)
    ///  18: `upfront_shutdown_script` (`Bytes`, empty = omit TLV)
    ///  19: `channel_type` (`Features`, empty = omit TLV)
    BuildOpenChannel,

    // -- Act: side effects against the target --
    /// Send an encoded message over the connection.
    /// Input: `Message`.
    SendMessage,
    /// Receive and parse an `accept_channel` response.
    /// Produces an `AcceptChannel` compound variable.
    RecvAcceptChannel,
}

/// Fields that can be extracted from an `AcceptChannel` compound variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptChannelField {
    TemporaryChannelId,
    DustLimitSatoshis,
    MaxHtlcValueInFlightMsat,
    ChannelReserveSatoshis,
    HtlcMinimumMsat,
    MinimumDepth,
    ToSelfDelay,
    MaxAcceptedHtlcs,
    FundingPubkey,
    RevocationBasepoint,
    PaymentBasepoint,
    DelayedPaymentBasepoint,
    HtlcBasepoint,
    FirstPerCommitmentPoint,
    UpfrontShutdownScript,
    ChannelType,
}

impl fmt::Display for AcceptChannelField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl AcceptChannelField {
    /// Returns the variable type produced by extracting this field.
    #[must_use]
    pub fn output_type(self) -> VariableType {
        match self {
            Self::TemporaryChannelId => VariableType::ChannelId,
            Self::DustLimitSatoshis
            | Self::MaxHtlcValueInFlightMsat
            | Self::ChannelReserveSatoshis
            | Self::HtlcMinimumMsat => VariableType::Amount,
            Self::MinimumDepth => VariableType::BlockHeight,
            Self::ToSelfDelay | Self::MaxAcceptedHtlcs => VariableType::U16,
            Self::FundingPubkey
            | Self::RevocationBasepoint
            | Self::PaymentBasepoint
            | Self::DelayedPaymentBasepoint
            | Self::HtlcBasepoint
            | Self::FirstPerCommitmentPoint => VariableType::Point,
            Self::UpfrontShutdownScript => VariableType::Bytes,
            Self::ChannelType => VariableType::Features,
        }
    }
}

/// Format a byte slice as a hex string. Returns an empty string for empty
/// input.
fn format_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        write!(s, "{b:02x}").expect("write to string");
    }
    s
}

/// Print an Operation. Operations that take no variable inputs include parens
/// (e.g., `LoadAmount(100000)`, `RecvAcceptChannel()`). Operations that do take
/// inputs omit parens so `Program::Display` can append them `(v0, v1, ...)`.
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadAmount(v) => write!(f, "LoadAmount({v})"),
            Self::LoadFeeratePerKw(v) => write!(f, "LoadFeeratePerKw({v})"),
            Self::LoadBlockHeight(v) => write!(f, "LoadBlockHeight({v})"),
            Self::LoadU16(v) => write!(f, "LoadU16({v})"),
            Self::LoadU8(v) => write!(f, "LoadU8({v})"),
            Self::LoadBytes(b) => write!(f, "LoadBytes({})", format_hex(b)),
            Self::LoadFeatures(b) => write!(f, "LoadFeatures({})", format_hex(b)),
            Self::LoadPrivateKey(b) => write!(f, "LoadPrivateKey({})", format_hex(b)),
            Self::LoadChannelId(b) => write!(f, "LoadChannelId({})", format_hex(b)),
            Self::LoadTargetPubkeyFromContext => write!(f, "LoadTargetPubkeyFromContext()"),
            Self::LoadChainHashFromContext => write!(f, "LoadChainHashFromContext()"),
            Self::RecvAcceptChannel => write!(f, "RecvAcceptChannel()"),
            // Operations with inputs: parens added by Program::Display.
            Self::DerivePoint => write!(f, "DerivePoint"),
            Self::ExtractAcceptChannel(field) => write!(f, "Extract{field}"),
            Self::BuildOpenChannel => write!(f, "BuildOpenChannel"),
            Self::SendMessage => write!(f, "SendMessage"),
        }
    }
}

impl Operation {
    /// Returns the variable type produced by this operation, or `None` for void
    /// operations (e.g., `SendMessage`).
    #[must_use]
    pub fn output_type(&self) -> Option<VariableType> {
        match self {
            Self::LoadAmount(_) => Some(VariableType::Amount),
            Self::LoadFeeratePerKw(_) => Some(VariableType::FeeratePerKw),
            Self::LoadBlockHeight(_) => Some(VariableType::BlockHeight),
            Self::LoadU16(_) => Some(VariableType::U16),
            Self::LoadU8(_) => Some(VariableType::U8),
            Self::LoadBytes(_) => Some(VariableType::Bytes),
            Self::LoadFeatures(_) => Some(VariableType::Features),
            Self::LoadPrivateKey(_) => Some(VariableType::PrivateKey),
            Self::LoadChannelId(_) => Some(VariableType::ChannelId),
            Self::LoadTargetPubkeyFromContext | Self::DerivePoint => Some(VariableType::Point),
            Self::LoadChainHashFromContext => Some(VariableType::ChainHash),
            Self::ExtractAcceptChannel(field) => Some(field.output_type()),
            Self::BuildOpenChannel => Some(VariableType::Message),
            Self::SendMessage => None,
            Self::RecvAcceptChannel => Some(VariableType::AcceptChannel),
        }
    }

    /// Returns the expected variable types for each input position.
    #[must_use]
    pub fn input_types(&self) -> Vec<VariableType> {
        match self {
            Self::LoadAmount(_)
            | Self::LoadFeeratePerKw(_)
            | Self::LoadBlockHeight(_)
            | Self::LoadU16(_)
            | Self::LoadU8(_)
            | Self::LoadBytes(_)
            | Self::LoadFeatures(_)
            | Self::LoadPrivateKey(_)
            | Self::LoadChannelId(_)
            | Self::LoadTargetPubkeyFromContext
            | Self::LoadChainHashFromContext
            | Self::RecvAcceptChannel => vec![],

            Self::DerivePoint => vec![VariableType::PrivateKey],
            Self::ExtractAcceptChannel(_) => vec![VariableType::AcceptChannel],
            Self::SendMessage => vec![VariableType::Message],

            Self::BuildOpenChannel => vec![
                VariableType::ChainHash,    // chain_hash
                VariableType::ChannelId,    // temporary_channel_id
                VariableType::Amount,       // funding_satoshis
                VariableType::Amount,       // push_msat
                VariableType::Amount,       // dust_limit_satoshis
                VariableType::Amount,       // max_htlc_value_in_flight_msat
                VariableType::Amount,       // channel_reserve_satoshis
                VariableType::Amount,       // htlc_minimum_msat
                VariableType::FeeratePerKw, // feerate_per_kw
                VariableType::U16,          // to_self_delay
                VariableType::U16,          // max_accepted_htlcs
                VariableType::Point,        // funding_pubkey
                VariableType::Point,        // revocation_basepoint
                VariableType::Point,        // payment_basepoint
                VariableType::Point,        // delayed_payment_basepoint
                VariableType::Point,        // htlc_basepoint
                VariableType::Point,        // first_per_commitment_point
                VariableType::U8,           // channel_flags
                VariableType::Bytes,        // upfront_shutdown_script
                VariableType::Features,     // channel_type
            ],
        }
    }

    /// Returns true if this operation has parameters that can be mutated
    /// by `OperationParamMutator`.
    #[must_use]
    pub fn is_param_mutable(&self) -> bool {
        matches!(
            self,
            Self::LoadAmount(_)
                | Self::LoadFeeratePerKw(_)
                | Self::LoadBlockHeight(_)
                | Self::LoadU16(_)
                | Self::LoadU8(_)
                | Self::LoadBytes(_)
                | Self::LoadFeatures(_)
                | Self::LoadPrivateKey(_)
                | Self::LoadChannelId(_)
                | Self::ExtractAcceptChannel(_)
        )
    }
}
