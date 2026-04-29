//! BOLT 2 `tx_add_output` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `tx_add_output` message (type 67).
///
/// Sent during interactive transaction construction to propose adding an
/// output to the shared transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAddOutput {
    /// The channel this message pertains to
    pub channel_id: ChannelId,
    /// Serial ID for this output, must be even if sent by the initiator,
    /// odd if sent by the non-initiator (BOLT 2 parity rule)
    pub serial_id: u64,
    /// The value of this output in satoshis
    pub sats: u64,
    /// The scriptPubKey for this output
    pub script: Vec<u8>,
}

impl TxAddOutput {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.serial_id.write(&mut out);
        self.sats.write(&mut out);
        self.script.write(&mut out);
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
        let serial_id = WireFormat::read(&mut cursor)?;
        let sats = WireFormat::read(&mut cursor)?;
        let script: Vec<u8> = WireFormat::read(&mut cursor)?;
        Ok(Self {
            channel_id,
            serial_id,
            sats,
            script,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    fn sample_msg() -> TxAddOutput {
        TxAddOutput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
            sats: 100_000,
            script: vec![0x76, 0xa9, 0x14, 0xab, 0xcd],
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = TxAddOutput::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let original = sample_msg();
        let mut encoded = original.encode();
        encoded.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let decoded = TxAddOutput::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxAddOutput::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_serial_id() {
        // channel_id (32 bytes) + 4 bytes of serial_id
        assert_eq!(
            TxAddOutput::decode(&[0x00; CHANNEL_ID_SIZE + 4]),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_truncated_sats() {
        // channel_id (32) + serial_id (8) + 4 bytes of sats
        assert_eq!(
            TxAddOutput::decode(&[0x00; CHANNEL_ID_SIZE + 8 + 4]),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_truncated_script_len() {
        // channel_id (32) + serial_id (8) + sats (8) + only 1 byte of the 2-byte script length
        let mut payload = vec![0x00u8; CHANNEL_ID_SIZE + 8 + 8];
        payload.push(0x00); // only 1 byte of the 2-byte script length field
        assert_eq!(
            TxAddOutput::decode(&payload),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_script_data() {
        // channel_id (32) + serial_id (8) + sats (8) + script_len=10 (2 bytes) + only 3 bytes of data
        let mut payload = vec![0x00u8; CHANNEL_ID_SIZE + 8 + 8];
        payload.push(0x00); // script_len high byte
        payload.push(0x0a); // script_len low byte = 10
        payload.extend_from_slice(&[0xde, 0xad, 0xbe]); // only 3 bytes instead of 10
        assert_eq!(
            TxAddOutput::decode(&payload),
            Err(BoltError::Truncated {
                expected: 10,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxAddOutput::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn roundtrip_empty_script() {
        let msg = TxAddOutput {
            script: vec![],
            ..sample_msg()
        };
        let encoded = msg.encode();
        let decoded = TxAddOutput::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }
}
