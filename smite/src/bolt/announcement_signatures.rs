//! BOLT 7 announcement signatures message.

use super::BoltError;
use super::types::{ChannelId, ShortChannelId};
use super::wire::WireFormat;
use bitcoin::secp256k1::ecdsa::Signature;

/// BOLT 7 `announcement_signatures` message (type 259).
///
/// A direct (non-gossip) message between the two endpoints of a channel.
/// Each peer sends their `node_signature` and `bitcoin_signature` over the
/// `channel_announcement` body, allowing the counterparty to assemble and
/// broadcast the fully-signed `channel_announcement`.
///
/// Wire layout (per [BOLT 7]):
///
/// ```text
/// [channel_id:32]
/// [short_channel_id:8]
/// [signature:64]    // node_signature
/// [signature:64]    // bitcoin_signature
/// ```
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-announcement_signatures-message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementSignatures {
    /// The channel ID of the channel being announced.
    pub channel_id: ChannelId,
    /// Reference to the funding transaction.
    pub short_channel_id: ShortChannelId,
    /// Sender's signature with its `node_id` over the `channel_announcement` body.
    pub node_signature: Signature,
    /// Sender's signature with its `bitcoin_key` over the `channel_announcement` body.
    pub bitcoin_signature: Signature,
}

impl AnnouncementSignatures {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.short_channel_id.write(&mut out);
        self.node_signature.write(&mut out);
        self.bitcoin_signature.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field, or
    /// `InvalidSignature` if either signature is not a valid compact ECDSA
    /// signature.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let short_channel_id = WireFormat::read(&mut cursor)?;
        let node_signature = WireFormat::read(&mut cursor)?;
        let bitcoin_signature = WireFormat::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            short_channel_id,
            node_signature,
            bitcoin_signature,
        })
    }
}

#[cfg(test)]
#[allow(clippy::range_plus_one)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, SHORT_CHANNEL_ID_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Valid `AnnouncementSignatures` message for testing.
    fn sample_announcement_signatures() -> AnnouncementSignatures {
        let secp = Secp256k1::new();
        let node_sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let bitcoin_sk = SecretKey::from_slice(&[0x22; 32]).expect("valid secret");
        // The signatures here would normally cover the channel_announcement
        // body; for codec tests any well-formed digest suffices.
        let digest = Message::from_digest([0xab; 32]);

        AnnouncementSignatures {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            short_channel_id: ShortChannelId::new(539_268, 845, 1),
            node_signature: secp.sign_ecdsa(&digest, &node_sk),
            bitcoin_signature: secp.sign_ecdsa(&digest, &bitcoin_sk),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_announcement_signatures();
        let encoded = msg.encode();
        // 32 (channel_id) + 8 (scid) + 64 (node_sig) + 64 (bitcoin_sig) = 168
        assert_eq!(encoded.len(), 168);
    }

    #[test]
    fn roundtrip() {
        let original = sample_announcement_signatures();
        let encoded = original.encode();
        let decoded = AnnouncementSignatures::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        // 10 bytes — short of the 32 needed for channel_id.
        assert_eq!(
            AnnouncementSignatures::decode(&[0u8; 10]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_short_channel_id() {
        // channel_id(32) + 5 bytes of scid (need 8)
        let encoded = sample_announcement_signatures().encode();
        let data = &encoded[..CHANNEL_ID_SIZE + 5];
        assert_eq!(
            AnnouncementSignatures::decode(data),
            Err(BoltError::Truncated {
                expected: SHORT_CHANNEL_ID_SIZE,
                actual: 5,
            })
        );
    }

    #[test]
    fn decode_truncated_node_signature() {
        // channel_id(32) + scid(8) + 10 bytes of node_signature (need 64)
        let encoded = sample_announcement_signatures().encode();
        let data = &encoded[..CHANNEL_ID_SIZE + SHORT_CHANNEL_ID_SIZE + 10];
        assert_eq!(
            AnnouncementSignatures::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_bitcoin_signature() {
        // channel_id(32) + scid(8) + node_signature(64) + 10 bytes of bitcoin_signature (need 64)
        let encoded = sample_announcement_signatures().encode();
        let data =
            &encoded[..CHANNEL_ID_SIZE + SHORT_CHANNEL_ID_SIZE + COMPACT_SIGNATURE_SIZE + 10];
        assert_eq!(
            AnnouncementSignatures::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_invalid_node_signature() {
        let mut encoded = sample_announcement_signatures().encode();
        // r and s are both above curve order.
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        let offset = CHANNEL_ID_SIZE + SHORT_CHANNEL_ID_SIZE;
        encoded[offset..offset + COMPACT_SIGNATURE_SIZE].copy_from_slice(&bad_sig);
        assert_eq!(
            AnnouncementSignatures::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn decode_invalid_bitcoin_signature() {
        let mut encoded = sample_announcement_signatures().encode();
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        let offset = CHANNEL_ID_SIZE + SHORT_CHANNEL_ID_SIZE + COMPACT_SIGNATURE_SIZE;
        encoded[offset..offset + COMPACT_SIGNATURE_SIZE].copy_from_slice(&bad_sig);
        assert_eq!(
            AnnouncementSignatures::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }
}
