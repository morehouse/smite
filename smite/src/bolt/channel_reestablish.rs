//! BOLT 2 `channel_reestablish` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::types::PER_COMMITMENT_SECRET_SIZE;
use super::wire::WireFormat;
use secp256k1::PublicKey;

/// BOLT 2 `channel_reestablish` message (type 136).
///
/// Sent after reconnecting to synchronize commitment/revocation counters and
/// reestablish a channel's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReestablish {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The next commitment number expected from the peer.
    pub next_commitment_number: u64,
    /// The next revocation number expected from the peer.
    pub next_revocation_number: u64,
    /// The sender's view of the receiver's last per-commitment secret.
    pub your_last_per_commitment_secret: [u8; PER_COMMITMENT_SECRET_SIZE],
    /// The sender's current per-commitment point.
    pub my_current_per_commitment_point: PublicKey,
    /// Optional TLV extensions.
    pub tlvs: TlvStream,
}

impl ChannelReestablish {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.next_commitment_number.write(&mut out);
        self.next_revocation_number.write(&mut out);
        self.your_last_per_commitment_secret.write(&mut out);
        self.my_current_per_commitment_point.write(&mut out);
        out.extend(self.tlvs.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or
    /// `InvalidPublicKey` if the per-commitment point is invalid.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let next_commitment_number = WireFormat::read(&mut cursor)?;
        let next_revocation_number = WireFormat::read(&mut cursor)?;
        let your_last_per_commitment_secret = WireFormat::read(&mut cursor)?;
        let my_current_per_commitment_point = WireFormat::read(&mut cursor)?;
        let tlvs = TlvStream::decode(cursor)?;

        Ok(Self {
            channel_id,
            next_commitment_number,
            next_revocation_number,
            your_last_per_commitment_secret,
            my_current_per_commitment_point,
            tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, PUBLIC_KEY_SIZE};
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    /// Valid `ChannelReestablish` message for testing.
    fn sample_channel_reestablish() -> ChannelReestablish {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        ChannelReestablish {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            next_commitment_number: 42,
            next_revocation_number: 41,
            your_last_per_commitment_secret: [0xbb; PER_COMMITMENT_SECRET_SIZE],
            my_current_per_commitment_point: pk,
            tlvs: TlvStream::new(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_channel_reestablish();
        let encoded = msg.encode();
        // channel_id(32) + next_commitment_number(8) + next_revocation_number(8)
        // + your_last_per_commitment_secret(32) + my_current_per_commitment_point(33) = 113
        assert_eq!(encoded.len(), 113);
    }

    #[test]
    fn roundtrip() {
        let original = sample_channel_reestablish();
        let encoded = original.encode();
        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let mut original = sample_channel_reestablish();
        original.tlvs.add(3, vec![0xaa, 0xbb]);

        let encoded = original.encode();
        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let msg = sample_channel_reestablish();
        let mut encoded = msg.encode();

        // Append unknown odd TLV: type 5, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x05, 0x02, 0xaa, 0xbb]);

        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert_eq!(decoded.tlvs.get(5), Some(&[0xaa, 0xbb][..]));
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let msg = sample_channel_reestablish();
        let mut encoded = msg.encode();

        // Append unknown even TLV: type 4, length 1, value [0x00]
        encoded.extend_from_slice(&[0x04, 0x01, 0x00]);

        assert!(matches!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(4))
        ));
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            ChannelReestablish::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_next_commitment_number() {
        // channel_id(32) + only 2 bytes into next_commitment_number
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 2]);
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_truncated_next_revocation_number() {
        // channel_id(32) + next_commitment_number(8) + only 3 bytes into next_revocation_number
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&[0x00; 3]);
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_truncated_your_last_per_commitment_secret() {
        // channel_id(32) + next_commitment_number(8) + next_revocation_number(8)
        // + only 10 bytes of your_last_per_commitment_secret
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&41u64.to_be_bytes());
        data.extend_from_slice(&[0xbb; 10]);
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: PER_COMMITMENT_SECRET_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_truncated_my_current_per_commitment_point() {
        // Fixed fields + only 10 bytes of point data
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&41u64.to_be_bytes());
        data.extend_from_slice(&[0xbb; PER_COMMITMENT_SECRET_SIZE]);
        data.extend_from_slice(&[0x02; 10]);
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_invalid_my_current_per_commitment_point() {
        // Full length payload with invalid all-zero compressed key bytes.
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&41u64.to_be_bytes());
        data.extend_from_slice(&[0xbb; PER_COMMITMENT_SECRET_SIZE]);
        data.extend_from_slice(&[0x00; PUBLIC_KEY_SIZE]);
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::InvalidPublicKey([0x00; PUBLIC_KEY_SIZE]))
        );
    }
}
