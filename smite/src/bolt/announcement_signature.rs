//! BOLT 7 `announcement_signatures` message.

use super::BoltError;
use super::types::{ChannelId, ShortChannelId, Signature};
use super::wire::WireFormat;

/// BOLT 7 `announcement_signatures` message (type 259 / 0x0103).
///
/// Sent directly between the two endpoints of a channel. Signals the
/// sender's willingness to announce the channel publicly and provides
/// the signatures needed to construct the `channel_announcement` message.
///
/// Only sent when `announce_channel` was set in `channel_flags` during
/// channel opening (BOLT 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementSignatures {
    /// The channel this message refers to.
    pub channel_id: ChannelId,
    /// The compact on-chain identifier of the channel's funding output.
    pub short_channel_id: ShortChannelId,
    /// The sender's node signature over the `channel_announcement`.
    pub node_signature: Signature,
    /// The sender's bitcoin key signature over the `channel_announcement`.
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
    /// Returns `Truncated` if the payload is too short for any field.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id       = ChannelId::read(&mut cursor)?;
        let short_channel_id = ShortChannelId::read(&mut cursor)?;
        let node_signature   = Signature::read(&mut cursor)?;
        let bitcoin_signature = Signature::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            short_channel_id,
            node_signature,
            bitcoin_signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{CHANNEL_ID_SIZE, SIGNATURE_SIZE};

    fn dummy() -> AnnouncementSignatures {
        AnnouncementSignatures {
            channel_id:        ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            short_channel_id:  ShortChannelId::new(0x0001_0002_0003),
            node_signature:    Signature::new([0x01; SIGNATURE_SIZE]),
            bitcoin_signature: Signature::new([0x02; SIGNATURE_SIZE]),
        }
    }

    #[test]
    fn encode_field_sizes() {
        let encoded = dummy().encode();
        // channel_id(32) + short_channel_id(8) + node_sig(64) + bitcoin_sig(64)
        assert_eq!(
            encoded.len(),
            CHANNEL_ID_SIZE + 8 + SIGNATURE_SIZE + SIGNATURE_SIZE
        );
    }

    #[test]
    fn roundtrip() {
        let original = dummy();
        let decoded = AnnouncementSignatures::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_different_values() {
        let msg = AnnouncementSignatures {
            channel_id:        ChannelId::new([0xff; CHANNEL_ID_SIZE]),
            short_channel_id:  ShortChannelId::new(0xffff_ffff_ffff_ffff),
            node_signature:    Signature::new([0xab; SIGNATURE_SIZE]),
            bitcoin_signature: Signature::new([0xcd; SIGNATURE_SIZE]),
        };
        let decoded = AnnouncementSignatures::decode(&msg.encode()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            AnnouncementSignatures::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            AnnouncementSignatures::decode(&[0x00; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_truncated_short_channel_id() {
        // full channel_id(32) then 3 of 8 bytes of short_channel_id
        assert_eq!(
            AnnouncementSignatures::decode(&[0x00; CHANNEL_ID_SIZE + 3]),
            Err(BoltError::Truncated { expected: 8, actual: 3 })
        );
    }

    #[test]
    fn decode_truncated_node_signature() {
        // full channel_id(32) + short_channel_id(8) then 10 of 64 bytes of node_sig
        assert_eq!(
            AnnouncementSignatures::decode(&[0x00; CHANNEL_ID_SIZE + 8 + 10]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 10 })
        );
    }

    #[test]
    fn decode_truncated_bitcoin_signature() {
        // full channel_id(32) + short_channel_id(8) + node_sig(64) then 20 of 64 bytes
        assert_eq!(
            AnnouncementSignatures::decode(&[0x00; CHANNEL_ID_SIZE + 8 + SIGNATURE_SIZE + 20]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_trailing_bytes() {
        // valid payload with extra bytes at the end — should succeed
        let mut encoded = dummy().encode();
        encoded.extend_from_slice(&[0xff; 10]);
        let decoded = AnnouncementSignatures::decode(&encoded).unwrap();
        assert_eq!(decoded, dummy());
    }

    #[test]
    fn short_channel_id_roundtrip_boundary_values() {
        for scid in [0u64, 1, u64::MAX] {
            let msg = AnnouncementSignatures {
                short_channel_id: ShortChannelId::new(scid),
                ..dummy()
            };
            let decoded = AnnouncementSignatures::decode(&msg.encode()).unwrap();
            assert_eq!(decoded.short_channel_id, msg.short_channel_id);
        }
    }
}