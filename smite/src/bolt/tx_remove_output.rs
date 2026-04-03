//! BOLT 2 `tx_remove_output` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `tx_remove_output` message (type 69).
///
/// Sent during interactive transaction construction to remove a previously
/// added output from the transaction being negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRemoveOutput {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The serial ID of the output to remove, as previously sent in
    /// `tx_add_output`.
    pub serial_id: u64,
}

impl TxRemoveOutput {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.serial_id.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let serial_id = u64::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            serial_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxRemoveOutput {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            serial_id: 1,
        };
        let encoded = msg.encode();
        // channel_id(32) + serial_id(8) = 40
        assert_eq!(encoded.len(), 40);
    }

    #[test]
    fn roundtrip() {
        let original = TxRemoveOutput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 99,
        };
        let encoded = original.encode();
        let decoded = TxRemoveOutput::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxRemoveOutput::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_serial_id() {
        // Full channel_id (32 bytes) + only 4 bytes of serial_id
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 4]);
        assert_eq!(
            TxRemoveOutput::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxRemoveOutput::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
