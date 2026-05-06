//! IR operations that load, compute, build or act.
//!
//! Each [`Operation`] falls into one of four categories:
//!
//! - `Load` - Produce a variable from an embedded literal or from the
//!   `ProgramContext`.
//! - `Compute` - Derive a new variable from existing ones.
//! - `Build` - Construct a BOLT message from input variables.
//! - `Act` - Perform a side effect against the target.

use std::fmt;
use std::fmt::Write;

use rand::{Rng, RngExt};
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
    /// Load a secp256k1 private key.
    LoadPrivateKey([u8; 32]),
    /// Load a 32-byte channel identifier.
    LoadChannelId([u8; 32]),
    /// Load a BOLT 2 compliant `upfront_shutdown_script`.
    ///
    /// Produces a [`VariableType::Bytes`] value whose contents match one of the
    /// standard script templates required by BOLT 2.
    LoadShutdownScript(ShutdownScriptVariant),
    /// Load a valid `channel_type` feature vector.
    ///
    /// Produces a [`VariableType::Features`] value encoding one of a set of
    /// channel types known to be accepted by at least one target.
    LoadChannelType(ChannelTypeVariant),
    /// Load the target node's public key from the program context.
    LoadTargetPubkeyFromContext,
    /// Load the chain hash from the program context.
    LoadChainHashFromContext,

    // -- Compute: derive a variable from inputs --
    /// Derive a compressed public key from a private key. The executor
    /// validates that the bytes are in range `[1, curve_order)` and errors if
    /// not.
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

/// A BOLT 2 compliant `upfront_shutdown_script` template.
///
/// Each variant encodes to a script matching one of the formats required by
/// BOLT 2 for the upfront shutdown TLV. `Empty` opts out of upfront shutdown
/// entirely and is accepted regardless of feature negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShutdownScriptVariant {
    /// Zero-length script. Opts out of upfront shutdown.
    Empty,
    /// `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
    P2pkh([u8; 20]),
    /// `OP_HASH160 <20-byte hash> OP_EQUAL`.
    P2sh([u8; 20]),
    /// `OP_0 <20-byte hash>`.
    P2wpkh([u8; 20]),
    /// `OP_0 <32-byte hash>`.
    P2wsh([u8; 32]),
    /// `OP_<version> <program>` for witness program versions 1..=16 with a
    /// 2..=40 byte program. Requires the counterparty to signal
    /// `option_shutdown_anysegwit`.
    AnySegwit {
        /// Witness program version, in `1..=16`.
        version: u8,
        /// Witness program bytes, length in `2..=40`.
        program: Vec<u8>,
    },
    /// `OP_RETURN <data>` where `data` is 6..=80 bytes. Requires the
    /// counterparty to signal `option_simple_close`.
    OpReturn(Vec<u8>),
}

impl ShutdownScriptVariant {
    /// Number of variants, used for uniform random sampling. Keep in sync with
    /// `random` and the enum definition.
    pub const VARIANT_COUNT: usize = 7;

    /// `AnySegwit` witness program version bounds (BOLT 2 / BIP 141).
    pub const ANYSEGWIT_MIN_VERSION: u8 = 1;
    pub const ANYSEGWIT_MAX_VERSION: u8 = 16;

    /// `AnySegwit` witness program length bounds (BOLT 2 / BIP 141).
    pub const ANYSEGWIT_MIN_PROGRAM_LEN: usize = 2;
    pub const ANYSEGWIT_MAX_PROGRAM_LEN: usize = 40;

    /// `OP_RETURN` payload length bounds (BOLT 2 `option_simple_close`).
    pub const OP_RETURN_MIN_DATA_LEN: usize = 6;
    pub const OP_RETURN_MAX_DATA_LEN: usize = 80;

    /// Generates a random variant with random embedded data. Variants are
    /// chosen uniformly. Embedded hashes / programs are filled with random
    /// bytes; lengths are drawn uniformly from the BOLT-permitted range for
    /// variable-length variants.
    pub fn random(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..Self::VARIANT_COUNT) {
            0 => Self::Empty,
            1 => Self::P2pkh(rng.random()),
            2 => Self::P2sh(rng.random()),
            3 => Self::P2wpkh(rng.random()),
            4 => Self::P2wsh(rng.random()),
            5 => {
                let version =
                    rng.random_range(Self::ANYSEGWIT_MIN_VERSION..=Self::ANYSEGWIT_MAX_VERSION);
                let len = rng.random_range(
                    Self::ANYSEGWIT_MIN_PROGRAM_LEN..=Self::ANYSEGWIT_MAX_PROGRAM_LEN,
                );
                let mut program = vec![0u8; len];
                rng.fill(&mut program[..]);
                Self::AnySegwit { version, program }
            }
            6 => {
                let len =
                    rng.random_range(Self::OP_RETURN_MIN_DATA_LEN..=Self::OP_RETURN_MAX_DATA_LEN);
                let mut data = vec![0u8; len];
                rng.fill(&mut data[..]);
                Self::OpReturn(data)
            }
            _ => unreachable!("ShutdownScriptVariant::random doesn't generate all variants"),
        }
    }

    /// Encodes the variant as raw scriptpubkey bytes.
    ///
    /// # Panics
    ///
    /// Panics if `AnySegwit.version` is outside
    /// `ANYSEGWIT_MIN_VERSION..=ANYSEGWIT_MAX_VERSION`, if the program is
    /// outside `ANYSEGWIT_MIN_PROGRAM_LEN..=ANYSEGWIT_MAX_PROGRAM_LEN` bytes,
    /// or if `OpReturn` data is outside
    /// `OP_RETURN_MIN_DATA_LEN..=OP_RETURN_MAX_DATA_LEN` bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::P2pkh(h) => {
                let mut out = Vec::with_capacity(25);
                out.extend_from_slice(&[0x76, 0xa9, 0x14]);
                out.extend_from_slice(h);
                out.extend_from_slice(&[0x88, 0xac]);
                out
            }
            Self::P2sh(h) => {
                let mut out = Vec::with_capacity(23);
                out.extend_from_slice(&[0xa9, 0x14]);
                out.extend_from_slice(h);
                out.push(0x87);
                out
            }
            Self::P2wpkh(h) => {
                let mut out = Vec::with_capacity(22);
                out.extend_from_slice(&[0x00, 0x14]);
                out.extend_from_slice(h);
                out
            }
            Self::P2wsh(h) => {
                let mut out = Vec::with_capacity(34);
                out.extend_from_slice(&[0x00, 0x20]);
                out.extend_from_slice(h);
                out
            }
            Self::AnySegwit { version, program } => {
                assert!(
                    (Self::ANYSEGWIT_MIN_VERSION..=Self::ANYSEGWIT_MAX_VERSION).contains(version),
                    "AnySegwit version {version} out of range",
                );
                assert!(
                    (Self::ANYSEGWIT_MIN_PROGRAM_LEN..=Self::ANYSEGWIT_MAX_PROGRAM_LEN)
                        .contains(&program.len()),
                    "AnySegwit program length {} out of range",
                    program.len(),
                );
                // OP_1..OP_16 = 0x51..=0x60 (i.e., 0x50 + version).
                let opcode = 0x50 + version;
                let mut out = Vec::with_capacity(2 + program.len());
                #[allow(clippy::cast_possible_truncation)] // program.len() is at most 40.
                out.extend_from_slice(&[opcode, program.len() as u8]);
                out.extend_from_slice(program);
                out
            }
            Self::OpReturn(data) => {
                assert!(
                    (Self::OP_RETURN_MIN_DATA_LEN..=Self::OP_RETURN_MAX_DATA_LEN)
                        .contains(&data.len()),
                    "OpReturn data length {} out of range",
                    data.len(),
                );
                let mut out = Vec::with_capacity(3 + data.len());
                out.push(0x6a); // OP_RETURN
                if data.len() <= 75 {
                    #[allow(clippy::cast_possible_truncation)] // data.len() <= 75 here.
                    out.push(data.len() as u8);
                } else {
                    // OP_PUSHDATA1 followed by length (76..=80).
                    #[allow(clippy::cast_possible_truncation)] // data.len() <= 80 here.
                    out.extend_from_slice(&[0x4c, data.len() as u8]);
                }
                out.extend_from_slice(data);
                out
            }
        }
    }
}

impl fmt::Display for ShutdownScriptVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::P2pkh(h) => write!(f, "P2pkh({})", format_hex(h)),
            Self::P2sh(h) => write!(f, "P2sh({})", format_hex(h)),
            Self::P2wpkh(h) => write!(f, "P2wpkh({})", format_hex(h)),
            Self::P2wsh(h) => write!(f, "P2wsh({})", format_hex(h)),
            Self::AnySegwit { version, program } => {
                write!(f, "AnySegwit(v{version}, {})", format_hex(program))
            }
            Self::OpReturn(data) => write!(f, "OpReturn({})", format_hex(data)),
        }
    }
}

/// A specific BOLT 2 `channel_type` feature-bit combination.
///
/// Each variant corresponds to a channel type accepted by at least one target
/// implementation:
///
/// - `option_static_remotekey` (bit 12)
/// - `option_anchors` (bits 22 and 12)
/// - `zero_fee_commitments` (bit 40)
/// - `option_simple_taproot` (bit 80)
/// - `option_simple_taproot_staging` (bit 180)
/// - `option_script_enforced_lease` (bits 2022, 22, 12)
///
/// Additionally, the following bits can be added to any channel type:
/// - `option_scid_alias` (bit 46)
/// - `option_zeroconf` (bit 50)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelTypeVariant {
    /// bit 12
    StaticRemoteKey,
    /// bits 12, 46
    StaticRemoteKeyScidAlias,
    /// bits 12, 50
    StaticRemoteKeyZeroConf,
    /// bits 12, 46, 50
    StaticRemoteKeyScidAliasZeroConf,
    /// bits 12, 22
    Anchors,
    /// bits 12, 22, 46
    AnchorsScidAlias,
    /// bits 12, 22, 50
    AnchorsZeroConf,
    /// bits 12, 22, 46, 50
    AnchorsScidAliasZeroConf,
    /// bit 40
    ZeroFeeCommitments,
    /// bits 40, 46
    ZeroFeeCommitmentsScidAlias,
    /// bits 40, 50
    ZeroFeeCommitmentsZeroConf,
    /// bits 40, 46, 50
    ZeroFeeCommitmentsScidAliasZeroConf,
    /// bit 80
    SimpleTaproot,
    /// bits 80, 46
    SimpleTaprootScidAlias,
    /// bits 80, 50
    SimpleTaprootZeroConf,
    /// bits 80, 46, 50
    SimpleTaprootScidAliasZeroConf,
    /// bit 180
    SimpleTaprootStaging,
    /// bits 180, 46
    SimpleTaprootStagingScidAlias,
    /// bits 180, 50
    SimpleTaprootStagingZeroConf,
    /// bits 180, 46, 50
    SimpleTaprootStagingScidAliasZeroConf,
    /// bits 12, 22, 2022
    ScriptEnforcedLease,
    /// bits 12, 22, 2022, 46
    ScriptEnforcedLeaseScidAlias,
    /// bits 12, 22, 2022, 50
    ScriptEnforcedLeaseZeroConf,
    /// bits 12, 22, 2022, 46, 50
    ScriptEnforcedLeaseScidAliasZeroConf,
}

impl ChannelTypeVariant {
    /// All variants. Keep in sync with the enum definition.
    pub const ALL: &[Self] = &[
        Self::StaticRemoteKey,
        Self::StaticRemoteKeyScidAlias,
        Self::StaticRemoteKeyZeroConf,
        Self::StaticRemoteKeyScidAliasZeroConf,
        Self::Anchors,
        Self::AnchorsScidAlias,
        Self::AnchorsZeroConf,
        Self::AnchorsScidAliasZeroConf,
        Self::ZeroFeeCommitments,
        Self::ZeroFeeCommitmentsScidAlias,
        Self::ZeroFeeCommitmentsZeroConf,
        Self::ZeroFeeCommitmentsScidAliasZeroConf,
        Self::SimpleTaproot,
        Self::SimpleTaprootScidAlias,
        Self::SimpleTaprootZeroConf,
        Self::SimpleTaprootScidAliasZeroConf,
        Self::SimpleTaprootStaging,
        Self::SimpleTaprootStagingScidAlias,
        Self::SimpleTaprootStagingZeroConf,
        Self::SimpleTaprootStagingScidAliasZeroConf,
        Self::ScriptEnforcedLease,
        Self::ScriptEnforcedLeaseScidAlias,
        Self::ScriptEnforcedLeaseZeroConf,
        Self::ScriptEnforcedLeaseScidAliasZeroConf,
    ];

    /// The feature bits (even/required) contained in this channel type.
    #[must_use]
    pub fn bits(self) -> &'static [usize] {
        // BOLT 9 feature bits:
        //   12 = option_static_remotekey
        //   22 = option_anchors
        //   40 = zero_fee_commitments
        //   46 = option_scid_alias
        //   50 = option_zeroconf
        //   80 = option_simple_taproot
        //  180 = option_simple_taproot_staging
        // 2022 = option_script_enforced_lease
        match self {
            Self::StaticRemoteKey => &[12],
            Self::StaticRemoteKeyScidAlias => &[12, 46],
            Self::StaticRemoteKeyZeroConf => &[12, 50],
            Self::StaticRemoteKeyScidAliasZeroConf => &[12, 46, 50],
            Self::Anchors => &[12, 22],
            Self::AnchorsScidAlias => &[12, 22, 46],
            Self::AnchorsZeroConf => &[12, 22, 50],
            Self::AnchorsScidAliasZeroConf => &[12, 22, 46, 50],
            Self::ZeroFeeCommitments => &[40],
            Self::ZeroFeeCommitmentsScidAlias => &[40, 46],
            Self::ZeroFeeCommitmentsZeroConf => &[40, 50],
            Self::ZeroFeeCommitmentsScidAliasZeroConf => &[40, 46, 50],
            Self::SimpleTaproot => &[80],
            Self::SimpleTaprootScidAlias => &[80, 46],
            Self::SimpleTaprootZeroConf => &[80, 50],
            Self::SimpleTaprootScidAliasZeroConf => &[80, 46, 50],
            Self::SimpleTaprootStaging => &[180],
            Self::SimpleTaprootStagingScidAlias => &[180, 46],
            Self::SimpleTaprootStagingZeroConf => &[180, 50],
            Self::SimpleTaprootStagingScidAliasZeroConf => &[180, 46, 50],
            Self::ScriptEnforcedLease => &[12, 22, 2022],
            Self::ScriptEnforcedLeaseScidAlias => &[12, 22, 2022, 46],
            Self::ScriptEnforcedLeaseZeroConf => &[12, 22, 2022, 50],
            Self::ScriptEnforcedLeaseScidAliasZeroConf => &[12, 22, 2022, 46, 50],
        }
    }

    /// Encodes the channel type as a BOLT feature bitmap (big-endian bytes).
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // bits() is always non-empty
    pub fn encode(self) -> Vec<u8> {
        let bits = self.bits();
        let max_bit = *bits.iter().max().expect("non-empty bits");
        let num_bytes = max_bit / 8 + 1;
        let mut out = vec![0u8; num_bytes];
        for &bit in bits {
            out[num_bytes - 1 - bit / 8] |= 1 << (bit % 8);
        }
        out
    }
}

impl fmt::Display for ChannelTypeVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
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
    /// All variants. Keep in sync with the enum definition.
    pub const ALL: &[Self] = &[
        Self::TemporaryChannelId,
        Self::DustLimitSatoshis,
        Self::MaxHtlcValueInFlightMsat,
        Self::ChannelReserveSatoshis,
        Self::HtlcMinimumMsat,
        Self::MinimumDepth,
        Self::ToSelfDelay,
        Self::MaxAcceptedHtlcs,
        Self::FundingPubkey,
        Self::RevocationBasepoint,
        Self::PaymentBasepoint,
        Self::DelayedPaymentBasepoint,
        Self::HtlcBasepoint,
        Self::FirstPerCommitmentPoint,
        Self::UpfrontShutdownScript,
        Self::ChannelType,
    ];

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
            Self::LoadShutdownScript(v) => write!(f, "LoadShutdownScript({v})"),
            Self::LoadChannelType(v) => write!(f, "LoadChannelType({v})"),
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
            Self::LoadBytes(_) | Self::LoadShutdownScript(_) => Some(VariableType::Bytes),
            Self::LoadFeatures(_) | Self::LoadChannelType(_) => Some(VariableType::Features),
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
            | Self::LoadShutdownScript(_)
            | Self::LoadChannelType(_)
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

    /// Returns extraction operations for compound variable types.
    ///
    /// For example, `RecvAcceptChannel` produces an `AcceptChannel` compound
    /// variable, so this returns `ExtractAcceptChannel` operations for each
    /// field.  Non-compound operations return an empty vec.
    #[must_use]
    pub fn extractable_fields(&self) -> Vec<(Operation, VariableType)> {
        match self {
            Self::RecvAcceptChannel => AcceptChannelField::ALL
                .iter()
                .map(|&f| (Self::ExtractAcceptChannel(f), f.output_type()))
                .collect(),
            _ => vec![],
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
                | Self::LoadShutdownScript(_)
                | Self::LoadChannelType(_)
                | Self::ExtractAcceptChannel(_)
        )
    }

    /// Returns true for Act instructions.
    #[must_use]
    pub fn is_act(&self) -> bool {
        matches!(self, Self::SendMessage | Self::RecvAcceptChannel)
    }
}
