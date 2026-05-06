//! BOLT 2 `update_fail_malformed_htlc` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;
use bitcoin::secp256k1::hashes::sha256;

/// BOLT 2 `update_fail_malformed_htlc` message (type 135). Sent
/// when a node cannot parse an incoming HTLC's onion packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailMalformedHtlc {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The HTLC ID being failed.
    pub id: u64,
    /// Hash of the received unparsable onion.
    pub sha256_of_onion: sha256::Hash,
    /// The specific error code.
    pub failure_code: u16,
}

impl UpdateFailMalformedHtlc {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.id.write(&mut out);
        self.sha256_of_onion.write(&mut out);
        self.failure_code.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let id = WireFormat::read(&mut cursor)?;
        let sha256_of_onion = WireFormat::read(&mut cursor)?;
        let failure_code = WireFormat::read(&mut cursor)?;
        Ok(Self {
            channel_id,
            id,
            sha256_of_onion,
            failure_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;
    use crate::bolt::SHA256_HASH_SIZE;
    use bitcoin::secp256k1::hashes::Hash;

    /// Valid `UpdateFailMalformedHtlc` message for testing.
    fn sample_msg() -> UpdateFailMalformedHtlc {
        UpdateFailMalformedHtlc {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            id: 12345,
            sha256_of_onion: sha256::Hash::from_byte_array([0xaa; SHA256_HASH_SIZE]),
            failure_code: 0x8001, // BADONION bit + 1
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_msg();
        let encoded = msg.encode();
        // channel_id(32) + id(8) + sha256_of_onion(32) + failure_code(2) = 74
        assert_eq!(encoded.len(), 74);
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = UpdateFailMalformedHtlc::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            UpdateFailMalformedHtlc::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_id() {
        // Full channel_id (32 bytes) + only 4 bytes of id
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 4]);
        assert_eq!(
            UpdateFailMalformedHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_truncated_sha256_of_onion() {
        // Full channel_id (32 bytes) + full id (8 bytes) + only 16 bytes of sha256_of_onion
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 8]);
        data.extend_from_slice(&[0x00; 16]);
        assert_eq!(
            UpdateFailMalformedHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: SHA256_HASH_SIZE,
                actual: 16
            })
        );
    }

    #[test]
    fn decode_truncated_failure_code() {
        // Full channel_id (32) + full id (8) + full sha256_of_onion (32) = 72
        // failure_code needs 2, only give 1
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 8]);
        data.extend_from_slice(&[0x00; SHA256_HASH_SIZE]);
        data.push(0x00);
        assert_eq!(
            UpdateFailMalformedHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            UpdateFailMalformedHtlc::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
