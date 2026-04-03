//! BOLT 2 `tx_abort` message.

use super::BoltError;
use super::types::{ChannelId, MAX_MESSAGE_SIZE};
use super::wire::WireFormat;

/// BOLT 2 `tx_abort` message (type 74).
///
/// Sent by either peer during interactive transaction construction to signal
/// that the negotiation has failed and should be abandoned.  Upon receiving
/// `tx_abort`, the peer should forget the current negotiation and respond
/// with its own `tx_abort`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAbort {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// Optional human-readable abort reason.
    ///
    /// Per BOLT 2, this should be printable ASCII (bytes 32-126), but we
    /// don't enforce this to allow fuzzing with arbitrary data.
    pub data: Vec<u8>,
}

impl TxAbort {
    /// Creates a `tx_abort` for the given channel.
    ///
    /// # Panics
    ///
    /// Panics if `msg` exceeds `MAX_MESSAGE_SIZE` bytes.
    #[must_use]
    pub fn new(channel_id: ChannelId, msg: &str) -> Self {
        assert!(
            msg.len() <= MAX_MESSAGE_SIZE,
            "tx_abort message exceeds maximum size"
        );
        Self {
            channel_id,
            data: msg.as_bytes().to_vec(),
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.data.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let data = Vec::<u8>::read(&mut cursor)?;

        Ok(Self { channel_id, data })
    }

    /// Returns data as a string if it's valid UTF-8.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn new_creates_abort() {
        let abort = TxAbort::new(
            ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            "negotiation failed",
        );
        assert_eq!(abort.channel_id, ChannelId::new([0x42; CHANNEL_ID_SIZE]));
        assert_eq!(abort.message(), Some("negotiation failed"));
    }

    #[test]
    fn encode_field_sizes() {
        let abort = TxAbort::new(ChannelId::new([0x42; CHANNEL_ID_SIZE]), "hi");
        let encoded = abort.encode();
        // channel_id(32) + len(2) + "hi"(2) = 36
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE + 2 + 2);
    }

    #[test]
    fn roundtrip() {
        let original = TxAbort::new(ChannelId::new([0xab; CHANNEL_ID_SIZE]), "roundtrip test");
        let encoded = original.encode();
        let decoded = TxAbort::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_empty_data() {
        let original = TxAbort::new(ChannelId::new([0xab; CHANNEL_ID_SIZE]), "");
        let encoded = original.encode();
        let decoded = TxAbort::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxAbort::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_len() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.push(0x00); // only 1 byte of len
        assert_eq!(
            TxAbort::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_data() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x10]); // len = 16
        data.extend_from_slice(b"short"); // only 5 bytes
        assert_eq!(
            TxAbort::decode(&data),
            Err(BoltError::Truncated {
                expected: 16,
                actual: 5
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxAbort::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn non_utf8_data() {
        let abort = TxAbort {
            channel_id: ChannelId::new([0x00; CHANNEL_ID_SIZE]),
            data: vec![0xff, 0xfe],
        };
        assert_eq!(abort.message(), None);
    }

    #[test]
    #[should_panic(expected = "tx_abort message exceeds maximum size")]
    fn new_too_long() {
        let long_msg = "x".repeat(MAX_MESSAGE_SIZE + 1);
        let _ = TxAbort::new(ChannelId::new([0x00; CHANNEL_ID_SIZE]), &long_msg);
    }
}
