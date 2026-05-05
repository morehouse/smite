//! BOLT message encoding and decoding.
//!
//! This module implements encoding and decoding for Lightning Network
//! protocol messages as specified in the BOLT specifications.

mod accept_channel;
mod accept_channel2;
mod attribution_data;
mod channel_ready;
mod commitment;
mod error;
mod funding_created;
mod funding_signed;
mod gossip_timestamp_filter;
mod init;
mod open_channel;
mod open_channel2;
mod ping;
mod pong;
mod shutdown;
mod tlv;
mod tx_abort;
mod tx_ack_rbf;
mod tx_add_input;
mod tx_complete;
mod tx_init_rbf;
mod tx_remove_input;
mod tx_remove_output;
mod types;
mod update_fail_htlc;
mod update_fail_malformed_htlc;
mod update_fulfill_htlc;
mod warning;
mod wire;

pub use accept_channel::{AcceptChannel, AcceptChannelTlvs};
pub use accept_channel2::{AcceptChannel2, AcceptChannel2Tlvs};
pub use attribution_data::{AttributionData, TruncatedHmac};
pub use channel_ready::{ChannelReady, ChannelReadyTlvs};
pub use commitment::{
    ChannelConfig, ChannelPartyConfig, CommitmentPartyState, CommitmentState, HolderIdentity,
};
pub use error::Error;
pub use funding_created::FundingCreated;
pub use funding_signed::FundingSigned;
pub use gossip_timestamp_filter::GossipTimestampFilter;
pub use init::{Init, InitTlvs};
pub use open_channel::{OpenChannel, OpenChannelTlvs};
pub use open_channel2::{OpenChannel2, OpenChannel2Tlvs};
pub use ping::Ping;
pub use pong::Pong;
pub use shutdown::Shutdown;
pub use tlv::{TlvRecord, TlvStream};
pub use tx_abort::TxAbort;
pub use tx_ack_rbf::{TxAckRbf, TxAckRbfTlvs};
pub use tx_add_input::{TxAddInput, TxAddInputTlvs};
pub use tx_complete::TxComplete;
pub use tx_init_rbf::{TxInitRbf, TxInitRbfTlvs};
pub use tx_remove_input::TxRemoveInput;
pub use tx_remove_output::TxRemoveOutput;
pub use types::{
    BigSize, CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, ChannelId, MAX_MESSAGE_SIZE, PUBLIC_KEY_SIZE,
    SHA256_HASH_SIZE, TXID_SIZE, Txid,
};
pub use update_fail_htlc::{UpdateFailHtlc, UpdateFailHtlcTlvs};
pub use update_fail_malformed_htlc::UpdateFailMalformedHtlc;
pub use update_fulfill_htlc::{UpdateFulfillHtlc, UpdateFulfillHtlcTlvs};
pub use warning::Warning;
pub use wire::WireFormat;

/// Errors that can occur during BOLT message encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoltError {
    // General decoding errors
    /// Not enough bytes to decode (message or field truncated)
    #[error("TRUNCATED expected {expected} got {actual}")]
    Truncated { expected: usize, actual: usize },
    /// Unknown even message type (must close connection per BOLT 1)
    #[error("UNKNOWN_EVEN_TYPE {0}")]
    UnknownEvenType(u16),
    /// The bytes do not represent a valid compressed secp256k1 public key
    #[error("INVALID_PUBLIC_KEY {}", hex::encode(.0))]
    InvalidPublicKey([u8; PUBLIC_KEY_SIZE]),
    /// The bytes do not represent a valid compact ECDSA signature
    #[error("INVALID_SIGNATURE {}", hex::encode(.0))]
    InvalidSignature([u8; COMPACT_SIGNATURE_SIZE]),

    // BigSize errors
    /// `BigSize` not minimally encoded
    #[error("BIGSIZE_NOT_MINIMAL")]
    BigSizeNotMinimal,
    /// `BigSize` truncated (unexpected EOF)
    #[error("BIGSIZE_TRUNCATED")]
    BigSizeTruncated,

    // TLV errors
    /// TLV type not in strictly increasing order
    #[error("TLV_NOT_INCREASING previous {previous} current {current}")]
    TlvNotIncreasing { previous: u64, current: u64 },
    /// TLV length exceeds remaining bytes
    #[error("TLV_LENGTH_OVERFLOW")]
    TlvLengthOverflow,
    /// Unknown even TLV type (must reject per BOLT 1)
    #[error("TLV_UNKNOWN_EVEN_TYPE {0}")]
    TlvUnknownEvenType(u64),
}

/// BOLT message type constants.
pub mod msg_type {
    /// Warning message (BOLT 1).
    pub const WARNING: u16 = 1;
    /// Init message (BOLT 1).
    pub const INIT: u16 = 16;
    /// Error message (BOLT 1).
    pub const ERROR: u16 = 17;
    /// Ping message (BOLT 1).
    pub const PING: u16 = 18;
    /// Pong message (BOLT 1).
    pub const PONG: u16 = 19;
    /// `open_channel` message (BOLT 2).
    pub const OPEN_CHANNEL: u16 = 32;
    /// `accept_channel` message (BOLT 2).
    pub const ACCEPT_CHANNEL: u16 = 33;
    /// `funding_created` message (BOLT 2).
    pub const FUNDING_CREATED: u16 = 34;
    /// `funding_signed` message (BOLT 2).
    pub const FUNDING_SIGNED: u16 = 35;
    /// `channel_ready` message (BOLT 2).
    pub const CHANNEL_READY: u16 = 36;
    /// Shutdown message (BOLT 2).
    pub const SHUTDOWN: u16 = 38;
    /// `open_channel2` message (BOLT 2).
    pub const OPEN_CHANNEL2: u16 = 64;
    /// `accept_channel2` message (BOLT 2).
    pub const ACCEPT_CHANNEL2: u16 = 65;
    /// `tx_add_input` message (BOLT 2).
    pub const TX_ADD_INPUT: u16 = 66;
    /// `tx_remove_input` message (BOLT 2).
    pub const TX_REMOVE_INPUT: u16 = 68;
    /// `tx_remove_output` message (BOLT 2).
    pub const TX_REMOVE_OUTPUT: u16 = 69;
    /// `tx_complete` message (BOLT 2).
    pub const TX_COMPLETE: u16 = 70;
    /// `tx_init_rbf` message (BOLT 2).
    pub const TX_INIT_RBF: u16 = 72;
    /// `tx_ack_rbf` message (BOLT 2).
    pub const TX_ACK_RBF: u16 = 73;
    /// `tx_abort` message (BOLT 2).
    pub const TX_ABORT: u16 = 74;
    /// `update_fulfill_htlc` message (BOLT 2).
    pub const UPDATE_FULFILL_HTLC: u16 = 130;
    /// `update_fail_htlc` message (BOLT 2).
    pub const UPDATE_FAIL_HTLC: u16 = 131;
    /// `update_fail_malformed_htlc` message (BOLT 2).
    pub const UPDATE_FAIL_MALFORMED_HTLC: u16 = 135;
    /// Gossip timestamp filter message (BOLT 7).
    pub const GOSSIP_TIMESTAMP_FILTER: u16 = 265;
}

/// A decoded BOLT message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// Warning message (type 1).
    Warning(Warning),
    /// Init message (type 16).
    Init(Init),
    /// Error message (type 17).
    Error(Error),
    /// Ping message (type 18).
    Ping(Ping),
    /// Pong message (type 19).
    Pong(Pong),
    /// `open_channel` message (type 32).
    OpenChannel(OpenChannel),
    /// `accept_channel` message (type 33).
    AcceptChannel(AcceptChannel),
    /// `funding_created` message (type 34).
    FundingCreated(FundingCreated),
    /// `funding_signed` message (type 35).
    FundingSigned(FundingSigned),
    /// `channel_ready` message (type 36).
    ChannelReady(ChannelReady),
    /// Shutdown message (type 38).
    Shutdown(Shutdown),
    /// `open_channel2` message (type 64).
    OpenChannel2(OpenChannel2),
    /// `accept_channel2` message (type 65).
    AcceptChannel2(AcceptChannel2),
    /// `tx_add_input` message (type 66).
    TxAddInput(TxAddInput),
    /// `tx_remove_input` message (type 68).
    TxRemoveInput(TxRemoveInput),
    /// `tx_remove_output` message (type 69).
    TxRemoveOutput(TxRemoveOutput),
    /// `tx_complete` message (type 70).
    TxComplete(TxComplete),
    /// `tx_init_rbf` message (type 72).
    TxInitRbf(TxInitRbf),
    /// `tx_ack_rbf` message (type 73).
    TxAckRbf(TxAckRbf),
    /// `tx_abort` message (type 74).
    TxAbort(TxAbort),
    /// `update_fulfill_htlc` message (type 130).
    UpdateFulfillHtlc(UpdateFulfillHtlc),
    /// `update_fail_htlc` message (type 131).
    UpdateFailHtlc(UpdateFailHtlc),
    /// `update_fail_malformed_htlc` message (type 135).
    UpdateFailMalformedHtlc(UpdateFailMalformedHtlc),
    /// Gossip timestamp filter message (type 265).
    GossipTimestampFilter(GossipTimestampFilter),
    /// Unknown message type.
    ///
    /// Stored for odd types that we don't recognize but must accept.
    /// Even unknown types cause decode to fail.
    Unknown {
        /// The message type.
        msg_type: u16,
        /// The raw payload (without type prefix).
        payload: Vec<u8>,
    },
}

impl Message {
    /// Returns the message type number.
    #[must_use]
    pub fn msg_type(&self) -> u16 {
        match self {
            Self::Warning(_) => msg_type::WARNING,
            Self::Init(_) => msg_type::INIT,
            Self::Error(_) => msg_type::ERROR,
            Self::Ping(_) => msg_type::PING,
            Self::Pong(_) => msg_type::PONG,
            Self::OpenChannel(_) => msg_type::OPEN_CHANNEL,
            Self::AcceptChannel(_) => msg_type::ACCEPT_CHANNEL,
            Self::FundingCreated(_) => msg_type::FUNDING_CREATED,
            Self::FundingSigned(_) => msg_type::FUNDING_SIGNED,
            Self::ChannelReady(_) => msg_type::CHANNEL_READY,
            Self::Shutdown(_) => msg_type::SHUTDOWN,
            Self::OpenChannel2(_) => msg_type::OPEN_CHANNEL2,
            Self::AcceptChannel2(_) => msg_type::ACCEPT_CHANNEL2,
            Self::TxAddInput(_) => msg_type::TX_ADD_INPUT,
            Self::TxRemoveInput(_) => msg_type::TX_REMOVE_INPUT,
            Self::TxRemoveOutput(_) => msg_type::TX_REMOVE_OUTPUT,
            Self::TxComplete(_) => msg_type::TX_COMPLETE,
            Self::TxInitRbf(_) => msg_type::TX_INIT_RBF,
            Self::TxAckRbf(_) => msg_type::TX_ACK_RBF,
            Self::TxAbort(_) => msg_type::TX_ABORT,
            Self::UpdateFulfillHtlc(_) => msg_type::UPDATE_FULFILL_HTLC,
            Self::UpdateFailHtlc(_) => msg_type::UPDATE_FAIL_HTLC,
            Self::UpdateFailMalformedHtlc(_) => msg_type::UPDATE_FAIL_MALFORMED_HTLC,
            Self::GossipTimestampFilter(_) => msg_type::GOSSIP_TIMESTAMP_FILTER,
            Self::Unknown { msg_type, .. } => *msg_type,
        }
    }

    /// Encodes to wire format (with 2-byte message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.msg_type().write(&mut out);
        match self {
            Self::Warning(m) => out.extend(m.encode()),
            Self::Init(m) => out.extend(m.encode()),
            Self::Error(m) => out.extend(m.encode()),
            Self::Ping(m) => out.extend(m.encode()),
            Self::Pong(m) => out.extend(m.encode()),
            Self::OpenChannel(m) => out.extend(m.encode()),
            Self::AcceptChannel(m) => out.extend(m.encode()),
            Self::FundingCreated(m) => out.extend(m.encode()),
            Self::FundingSigned(m) => out.extend(m.encode()),
            Self::ChannelReady(m) => out.extend(m.encode()),
            Self::Shutdown(m) => out.extend(m.encode()),
            Self::OpenChannel2(m) => out.extend(m.encode()),
            Self::AcceptChannel2(m) => out.extend(m.encode()),
            Self::TxAddInput(m) => out.extend(m.encode()),
            Self::TxRemoveInput(m) => out.extend(m.encode()),
            Self::TxRemoveOutput(m) => out.extend(m.encode()),
            Self::TxComplete(m) => out.extend(m.encode()),
            Self::TxInitRbf(m) => out.extend(m.encode()),
            Self::TxAckRbf(m) => out.extend(m.encode()),
            Self::TxAbort(m) => out.extend(m.encode()),
            Self::UpdateFulfillHtlc(m) => out.extend(m.encode()),
            Self::UpdateFailHtlc(m) => out.extend(m.encode()),
            Self::UpdateFailMalformedHtlc(m) => out.extend(m.encode()),
            Self::GossipTimestampFilter(m) => out.extend(m.encode()),
            Self::Unknown { payload, .. } => out.extend(payload),
        }
        out
    }

    /// Decodes from wire format (with 2-byte message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the message is too short, `UnknownEvenType` if
    /// the message type is an unknown even number, or a decode error from the
    /// specific message type.
    pub fn decode(data: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = data;
        let msg_type = u16::read(&mut cursor)?;

        match msg_type {
            msg_type::WARNING => Ok(Self::Warning(Warning::decode(cursor)?)),
            msg_type::INIT => Ok(Self::Init(Init::decode(cursor)?)),
            msg_type::ERROR => Ok(Self::Error(Error::decode(cursor)?)),
            msg_type::PING => Ok(Self::Ping(Ping::decode(cursor)?)),
            msg_type::PONG => Ok(Self::Pong(Pong::decode(cursor)?)),
            msg_type::OPEN_CHANNEL => Ok(Self::OpenChannel(OpenChannel::decode(cursor)?)),
            msg_type::ACCEPT_CHANNEL => Ok(Self::AcceptChannel(AcceptChannel::decode(cursor)?)),
            msg_type::FUNDING_CREATED => Ok(Self::FundingCreated(FundingCreated::decode(cursor)?)),
            msg_type::FUNDING_SIGNED => Ok(Self::FundingSigned(FundingSigned::decode(cursor)?)),
            msg_type::CHANNEL_READY => Ok(Self::ChannelReady(ChannelReady::decode(cursor)?)),
            msg_type::SHUTDOWN => Ok(Self::Shutdown(Shutdown::decode(cursor)?)),
            msg_type::OPEN_CHANNEL2 => Ok(Self::OpenChannel2(OpenChannel2::decode(cursor)?)),
            msg_type::ACCEPT_CHANNEL2 => Ok(Self::AcceptChannel2(AcceptChannel2::decode(cursor)?)),
            msg_type::TX_ADD_INPUT => Ok(Self::TxAddInput(TxAddInput::decode(cursor)?)),
            msg_type::TX_REMOVE_INPUT => Ok(Self::TxRemoveInput(TxRemoveInput::decode(cursor)?)),
            msg_type::TX_REMOVE_OUTPUT => Ok(Self::TxRemoveOutput(TxRemoveOutput::decode(cursor)?)),
            msg_type::TX_COMPLETE => Ok(Self::TxComplete(TxComplete::decode(cursor)?)),
            msg_type::TX_INIT_RBF => Ok(Self::TxInitRbf(TxInitRbf::decode(cursor)?)),
            msg_type::TX_ACK_RBF => Ok(Self::TxAckRbf(TxAckRbf::decode(cursor)?)),
            msg_type::TX_ABORT => Ok(Self::TxAbort(TxAbort::decode(cursor)?)),
            msg_type::UPDATE_FULFILL_HTLC => {
                Ok(Self::UpdateFulfillHtlc(UpdateFulfillHtlc::decode(cursor)?))
            }
            msg_type::UPDATE_FAIL_HTLC => Ok(Self::UpdateFailHtlc(UpdateFailHtlc::decode(cursor)?)),
            msg_type::UPDATE_FAIL_MALFORMED_HTLC => Ok(Self::UpdateFailMalformedHtlc(
                UpdateFailMalformedHtlc::decode(cursor)?,
            )),
            msg_type::GOSSIP_TIMESTAMP_FILTER => Ok(Self::GossipTimestampFilter(
                GossipTimestampFilter::decode(cursor)?,
            )),
            _ => {
                // Unknown even types must be rejected per BOLT 1
                if msg_type % 2 == 0 {
                    Err(BoltError::UnknownEvenType(msg_type))
                } else {
                    Ok(Self::Unknown {
                        msg_type,
                        payload: cursor.to_vec(),
                    })
                }
            }
        }
    }
}

/// Creates a raw message with the given type and payload.
///
/// This is useful for fuzzing - it allows sending arbitrary payloads
/// with any message type, bypassing normal encoding.
#[must_use]
pub fn message_with_type(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    msg_type.write(&mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
    use types::CHAIN_HASH_SIZE;

    // Tests ordered by message type number: Warning(1), Init(16), Error(17), Ping(18), Pong(19)

    #[test]
    fn message_warning_roundtrip() {
        let warning = Warning::all_channels("test warning");
        let msg = Message::Warning(warning.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Warning(warning));
    }

    #[test]
    fn message_init_roundtrip() {
        let init = Init::empty();
        let msg = Message::Init(init.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Init(init));
    }

    #[test]
    fn message_error_roundtrip() {
        let error = Error::all_channels("test error");
        let msg = Message::Error(error.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Error(error));
    }

    #[test]
    fn message_ping_roundtrip() {
        let ping = Ping::new(10);
        let msg = Message::Ping(ping.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Ping(ping));
    }

    #[test]
    fn message_pong_roundtrip() {
        let pong = Pong::new(5);
        let msg = Message::Pong(pong.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Pong(pong));
    }

    /// Valid `OpenChannel` message for testing.
    fn sample_open_channel() -> OpenChannel {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        OpenChannel {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            funding_satoshis: 100_000,
            push_msat: 0,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            feerate_per_kw: 253,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: pk,
            revocation_basepoint: pk,
            payment_basepoint: pk,
            delayed_payment_basepoint: pk,
            htlc_basepoint: pk,
            first_per_commitment_point: pk,
            channel_flags: 0x01,
            tlvs: OpenChannelTlvs::default(),
        }
    }

    #[test]
    fn message_open_channel_roundtrip() {
        let open = sample_open_channel();
        let msg = Message::OpenChannel(open.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::OpenChannel(open));
    }

    /// Valid `AcceptChannel` message for testing.
    fn sample_accept_channel() -> AcceptChannel {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        AcceptChannel {
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 3,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: pk,
            revocation_basepoint: pk,
            payment_basepoint: pk,
            delayed_payment_basepoint: pk,
            htlc_basepoint: pk,
            first_per_commitment_point: pk,
            tlvs: AcceptChannelTlvs::default(),
        }
    }

    #[test]
    fn message_accept_channel_roundtrip() {
        let accept = sample_accept_channel();
        let msg = Message::AcceptChannel(accept.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::AcceptChannel(accept));
    }

    /// Valid `FundingCreated` message for testing.
    fn sample_funding_created() -> FundingCreated {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let msg = secp256k1::Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        FundingCreated {
            temporary_channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            funding_txid: Txid::from_byte_array([0xcc; TXID_SIZE]),
            funding_output_index: 0,
            signature: sig,
        }
    }

    #[test]
    fn message_funding_created_roundtrip() {
        let fc = sample_funding_created();
        let msg = Message::FundingCreated(fc.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::FundingCreated(fc));
    }

    /// Valid `FundingSigned` message for testing.
    fn sample_funding_signed() -> FundingSigned {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let msg = secp256k1::Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        FundingSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
        }
    }

    #[test]
    fn message_funding_signed_roundtrip() {
        let fs = sample_funding_signed();
        let msg = Message::FundingSigned(fs.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::FundingSigned(fs));
    }

    /// Valid `ChannelReady` message for testing.
    fn sample_channel_ready() -> ChannelReady {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        ChannelReady {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            second_per_commitment_point: pk,
            tlvs: ChannelReadyTlvs::default(),
        }
    }

    #[test]
    fn message_channel_ready_roundtrip() {
        let cr = sample_channel_ready();
        let msg = Message::ChannelReady(cr.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::ChannelReady(cr));
    }

    #[test]
    fn message_shutdown_roundtrip() {
        let shutdown = Shutdown::for_channel(ChannelId::default(), vec![0x00, 0x14, 0xab, 0xcd]);
        let msg = Message::Shutdown(shutdown.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Shutdown(shutdown));
    }

    /// Valid `OpenChannel2` message for testing.
    fn sample_open_channel2() -> OpenChannel2 {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        OpenChannel2 {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            funding_feerate_perkw: 2_500,
            commitment_feerate_perkw: 253,
            funding_satoshis: 100_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            htlc_minimum_msat: 1_000,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            locktime: 800_000,
            funding_pubkey: pk,
            revocation_basepoint: pk,
            payment_basepoint: pk,
            delayed_payment_basepoint: pk,
            htlc_basepoint: pk,
            first_per_commitment_point: pk,
            second_per_commitment_point: pk,
            channel_flags: 0x01,
            tlvs: OpenChannel2Tlvs::default(),
        }
    }

    #[test]
    fn message_open_channel2_roundtrip() {
        let open = sample_open_channel2();
        let msg = Message::OpenChannel2(open.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::OpenChannel2(open));
    }

    /// Valid `AcceptChannel2` message for testing.
    fn sample_accept_channel2(tlvs: Option<AcceptChannel2Tlvs>) -> AcceptChannel2 {
        let secp = Secp256k1::new();
        let secrets: [[u8; 32]; 7] = [
            [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
        ];
        let keys: Vec<PublicKey> = secrets
            .iter()
            .map(|s| {
                let sk = SecretKey::from_slice(s).expect("valid secret");
                PublicKey::from_secret_key(&secp, &sk)
            })
            .collect();

        AcceptChannel2 {
            temporary_channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            funding_satoshis: 50_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 3,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: keys[0],
            revocation_basepoint: keys[1],
            payment_basepoint: keys[2],
            delayed_payment_basepoint: keys[3],
            htlc_basepoint: keys[4],
            first_per_commitment_point: keys[5],
            second_per_commitment_point: keys[6],
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn message_accept_channel2_roundtrip() {
        let accept2 = sample_accept_channel2(None);
        let msg = Message::AcceptChannel2(accept2.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::AcceptChannel2(accept2));
    }

    /// Valid `TxAddInput` message for testing.
    fn sample_tx_add_input() -> TxAddInput {
        TxAddInput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
            prevtx: vec![0xde, 0xad, 0xbe, 0xef],
            prevtx_vout: 0,
            sequence: 0xffff_fffd,
            tlvs: TxAddInputTlvs::default(),
        }
    }

    #[test]
    fn message_tx_add_input_roundtrip() {
        let tx_add_input = sample_tx_add_input();
        let msg = Message::TxAddInput(tx_add_input.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxAddInput(tx_add_input));
    }

    #[test]
    fn message_tx_remove_input_roundtrip() {
        let tx_remove_input = TxRemoveInput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
        };
        let msg = Message::TxRemoveInput(tx_remove_input.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxRemoveInput(tx_remove_input));
    }

    #[test]
    fn message_tx_remove_output_roundtrip() {
        let tx_remove_output = TxRemoveOutput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 99,
        };
        let msg = Message::TxRemoveOutput(tx_remove_output.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxRemoveOutput(tx_remove_output));
    }

    #[test]
    fn message_tx_complete_roundtrip() {
        let tx_complete = TxComplete {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
        };
        let msg = Message::TxComplete(tx_complete.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxComplete(tx_complete));
    }

    #[test]
    fn message_tx_init_rbf_roundtrip() {
        let tx_init_rbf = TxInitRbf {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            locktime: 800_000,
            feerate: 5_000,
            tlvs: TxInitRbfTlvs::default(),
        };
        let msg = Message::TxInitRbf(tx_init_rbf.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxInitRbf(tx_init_rbf));
    }

    #[test]
    fn message_tx_ack_rbf_roundtrip() {
        let tx_ack_rbf = TxAckRbf {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            tlvs: TxAckRbfTlvs::default(),
        };
        let msg = Message::TxAckRbf(tx_ack_rbf.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxAckRbf(tx_ack_rbf));
    }

    #[test]
    fn message_tx_abort_roundtrip() {
        let tx_abort = TxAbort::new(ChannelId::new([0xcd; CHANNEL_ID_SIZE]), "abort reason");
        let msg = Message::TxAbort(tx_abort.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxAbort(tx_abort));
    }

    #[test]
    fn message_update_fulfill_htlc_roundtrip() {
        let msg = UpdateFulfillHtlc {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            id: 42,
            payment_preimage: [0xcd; 32],
            tlvs: UpdateFulfillHtlcTlvs::default(),
        };
        let encoded = Message::UpdateFulfillHtlc(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::UpdateFulfillHtlc(msg));
    }

    #[test]
    fn message_update_fail_htlc_roundtrip() {
        let msg = UpdateFailHtlc {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            id: 7,
            reason: vec![0xde, 0xad, 0xbe, 0xef],
            tlvs: UpdateFailHtlcTlvs::default(),
        };
        let encoded = Message::UpdateFailHtlc(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::UpdateFailHtlc(msg));
    }

    #[test]
    fn message_update_fail_malformed_htlc_roundtrip() {
        let msg = UpdateFailMalformedHtlc {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            id: 12345,
            sha256_of_onion: sha256::Hash::from_byte_array([0xaa; SHA256_HASH_SIZE]),
            failure_code: 0x8001,
        };
        let encoded = Message::UpdateFailMalformedHtlc(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::UpdateFailMalformedHtlc(msg));
    }

    #[test]
    fn message_gossip_timestamp_filter_roundtrip() {
        let chain_hash = [0x6f; 32];
        let filter = GossipTimestampFilter::new(chain_hash, 1_000_000, 86400);
        let msg = Message::GossipTimestampFilter(filter.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::GossipTimestampFilter(filter));
    }

    #[test]
    fn message_unknown_roundtrip() {
        let msg = Message::Unknown {
            msg_type: 101,
            payload: vec![0x11, 0x22, 0x33],
        };
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn message_type_values() {
        assert_eq!(
            Message::Warning(Warning::all_channels("")).msg_type(),
            msg_type::WARNING
        );
        assert_eq!(Message::Init(Init::empty()).msg_type(), msg_type::INIT);
        assert_eq!(
            Message::Error(Error::all_channels("")).msg_type(),
            msg_type::ERROR
        );
        assert_eq!(Message::Ping(Ping::new(0)).msg_type(), msg_type::PING);
        assert_eq!(Message::Pong(Pong::new(0)).msg_type(), msg_type::PONG);
        assert_eq!(
            Message::OpenChannel(sample_open_channel()).msg_type(),
            msg_type::OPEN_CHANNEL
        );
        assert_eq!(
            Message::AcceptChannel(sample_accept_channel()).msg_type(),
            msg_type::ACCEPT_CHANNEL
        );
        assert_eq!(
            Message::FundingCreated(sample_funding_created()).msg_type(),
            msg_type::FUNDING_CREATED
        );
        assert_eq!(
            Message::FundingSigned(sample_funding_signed()).msg_type(),
            msg_type::FUNDING_SIGNED
        );
        assert_eq!(
            Message::ChannelReady(sample_channel_ready()).msg_type(),
            msg_type::CHANNEL_READY
        );
        assert_eq!(
            Message::Shutdown(Shutdown::for_channel(ChannelId([0; 32]), vec![])).msg_type(),
            msg_type::SHUTDOWN
        );
        assert_eq!(
            Message::OpenChannel2(sample_open_channel2()).msg_type(),
            msg_type::OPEN_CHANNEL2
        );
        assert_eq!(
            Message::AcceptChannel2(sample_accept_channel2(None)).msg_type(),
            msg_type::ACCEPT_CHANNEL2
        );
        assert_eq!(
            Message::TxAddInput(sample_tx_add_input()).msg_type(),
            msg_type::TX_ADD_INPUT
        );
        assert_eq!(
            Message::TxRemoveInput(TxRemoveInput {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                serial_id: 0
            })
            .msg_type(),
            msg_type::TX_REMOVE_INPUT
        );
        assert_eq!(
            Message::TxRemoveOutput(TxRemoveOutput {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                serial_id: 0
            })
            .msg_type(),
            msg_type::TX_REMOVE_OUTPUT
        );
        assert_eq!(
            Message::TxComplete(TxComplete {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE])
            })
            .msg_type(),
            msg_type::TX_COMPLETE
        );
        assert_eq!(
            Message::TxInitRbf(TxInitRbf {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                locktime: 0,
                feerate: 0,
                tlvs: TxInitRbfTlvs::default(),
            })
            .msg_type(),
            msg_type::TX_INIT_RBF
        );
        assert_eq!(
            Message::TxAckRbf(TxAckRbf {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                tlvs: TxAckRbfTlvs::default(),
            })
            .msg_type(),
            msg_type::TX_ACK_RBF
        );
        assert_eq!(
            Message::TxAbort(TxAbort::new(ChannelId::new([0; CHANNEL_ID_SIZE]), "")).msg_type(),
            msg_type::TX_ABORT
        );
        assert_eq!(
            Message::UpdateFulfillHtlc(UpdateFulfillHtlc {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                id: 0,
                payment_preimage: [0; 32],
                tlvs: UpdateFulfillHtlcTlvs::default(),
            })
            .msg_type(),
            msg_type::UPDATE_FULFILL_HTLC
        );
        assert_eq!(
            Message::UpdateFailHtlc(UpdateFailHtlc {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                id: 0,
                reason: vec![],
                tlvs: UpdateFailHtlcTlvs::default(),
            })
            .msg_type(),
            msg_type::UPDATE_FAIL_HTLC
        );
        assert_eq!(
            Message::UpdateFailMalformedHtlc(UpdateFailMalformedHtlc {
                channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
                id: 12345,
                sha256_of_onion: sha256::Hash::from_byte_array([0xaa; SHA256_HASH_SIZE]),
                failure_code: 0x8001,
            })
            .msg_type(),
            msg_type::UPDATE_FAIL_MALFORMED_HTLC
        );
        assert_eq!(
            Message::GossipTimestampFilter(GossipTimestampFilter::no_gossip([0u8; 32])).msg_type(),
            msg_type::GOSSIP_TIMESTAMP_FILTER
        );
        assert_eq!(
            Message::Unknown {
                msg_type: 99,
                payload: vec![]
            }
            .msg_type(),
            99
        );
    }

    #[test]
    fn message_decode_unknown_odd() {
        // Type 99 is odd and unknown - should be accepted
        let data = message_with_type(99, &[0xaa, 0xbb]);
        let msg = Message::decode(&data).unwrap();
        assert_eq!(
            msg,
            Message::Unknown {
                msg_type: 99,
                payload: vec![0xaa, 0xbb]
            }
        );
    }

    #[test]
    fn message_decode_unknown_even() {
        // Type 100 is even and unknown - should be rejected
        let data = message_with_type(100, &[0xaa, 0xbb]);
        assert_eq!(Message::decode(&data), Err(BoltError::UnknownEvenType(100)));
    }

    #[test]
    fn message_decode_truncated() {
        // Only 1 byte - need at least 2 for type
        assert_eq!(
            Message::decode(&[0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn message_with_type_helper() {
        let data = message_with_type(msg_type::PING, &[0x00, 0x04, 0x00, 0x00]);
        assert_eq!(data, [0x00, 0x12, 0x00, 0x04, 0x00, 0x00]); // 0x12 = 18 = PING
    }
}
