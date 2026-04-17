//! BOLT 2 revoke and ack message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;
use secp256k1::PublicKey;

/// BOLT 2 `revoke_and_ack` message (type 133).
///
/// Sent to revoke the previous commitment transaction and acknowledge the
/// counterparty's new commitment transaction. Also provides the next
/// per-commitment point for the counterparty's use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAndAck {
    /// The channel ID
    pub channel_id: ChannelId,
    /// The per-commitment secret used to derive the revocation key
    pub per_commitment_secret: [u8; 32],
    /// The next per-commitment point to be used in the subsequent commitment transaction
    pub next_per_commitment_point: PublicKey,
}

impl RevokeAndAck {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.per_commitment_secret.write(&mut out);
        self.next_per_commitment_point.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or
    /// `InvalidPublicKey` if the `next_per_commitment_point` is invalid.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let per_commitment_secret = WireFormat::read(&mut cursor)?;
        let next_per_commitment_point = WireFormat::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            per_commitment_secret,
            next_per_commitment_point,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// Valid `RevokeAndAck` message for testing.
    fn sample_revoke_and_ack() -> RevokeAndAck {
        let pk = PublicKey::from_slice(&[0x02; 33]).expect("valid public key");

        RevokeAndAck {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            per_commitment_secret: [0xbb; 32],
            next_per_commitment_point: pk,
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_revoke_and_ack();
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 97);
    }

    #[test]
    fn roundtrip() {
        let original = sample_revoke_and_ack();
        let encoded = original.encode();
        let decoded = RevokeAndAck::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            RevokeAndAck::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_per_commitment_secret() {
        let msg = sample_revoke_and_ack();
        let encoded = msg.encode();
        let data = &encoded[..50];
        assert_eq!(
            RevokeAndAck::decode(data),
            Err(BoltError::Truncated {
                expected: 32,
                actual: 18
            })
        );
    }

    #[test]
    fn decode_truncated_public_key() {
        let msg = sample_revoke_and_ack();
        let encoded = msg.encode();
        let data = &encoded[..80];
        assert!(RevokeAndAck::decode(data).is_err());
    }

    #[test]
    fn various_secrets() {
        for i in 0..10u8 {
            let pk = PublicKey::from_slice(&[0x02; 33]).expect("valid public key");

            let mut secret = [0u8; 32];
            secret[0] = i;

            let msg = RevokeAndAck {
                channel_id: ChannelId::new([i; CHANNEL_ID_SIZE]),
                per_commitment_secret: secret,
                next_per_commitment_point: pk,
            };

            let encoded = msg.encode();
            let decoded = RevokeAndAck::decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn different_public_keys() {
        let secp = Secp256k1::new();

        let sk1 = SecretKey::from_byte_array([0x01; 32]).unwrap();
        let sk2 = SecretKey::from_byte_array([0x03; 32]).unwrap();

        for sk in &[sk1, sk2] {
            let pk = PublicKey::from_secret_key(&secp, sk);

            let msg = RevokeAndAck {
                channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
                per_commitment_secret: [0xbb; 32],
                next_per_commitment_point: pk,
            };

            let encoded = msg.encode();
            let decoded = RevokeAndAck::decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn invalid_public_key() {
        let mut data = vec![0u8; 97];
        // First 32 bytes: channel_id
        // Next 32 bytes: per_commitment_secret
        // Last 33 bytes: invalid public key (all zeros - not a valid compressed pubkey)
        data[64..97].copy_from_slice(&[0x00; 33]);

        assert!(RevokeAndAck::decode(&data).is_err());
    }

    #[test]
    fn empty_payload() {
        assert!(RevokeAndAck::decode(&[]).is_err());
    }
}
