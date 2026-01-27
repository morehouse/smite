//! BOLT 1 warning message.

use super::BoltError;
use super::types::{ChannelId, MAX_MESSAGE_SIZE, read_u16_be, write_u16_be};

/// BOLT 1 warning message (type 1).
///
/// Indicates a protocol violation or recoverable error. The receiver should log
/// all warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Channel this warning applies to (all zeros = all channels).
    pub channel_id: ChannelId,
    /// Human-readable warning description.
    ///
    /// Per BOLT 1, this should be printable ASCII (bytes 32-126), but we
    /// don't enforce this to allow fuzzing with arbitrary data.
    pub data: Vec<u8>,
}

impl Warning {
    /// Creates a warning for all channels.
    ///
    /// # Panics
    ///
    /// Panics if `msg` exceeds `MAX_MESSAGE_SIZE` bytes.
    #[must_use]
    pub fn all_channels(msg: &str) -> Self {
        assert!(
            msg.len() <= MAX_MESSAGE_SIZE,
            "warning message exceeds maximum size"
        );
        Self {
            channel_id: ChannelId::ALL,
            data: msg.as_bytes().to_vec(),
        }
    }

    /// Creates a warning for a specific channel.
    ///
    /// # Panics
    ///
    /// Panics if `msg` exceeds `MAX_MESSAGE_SIZE` bytes.
    #[must_use]
    pub fn for_channel(channel_id: ChannelId, msg: &str) -> Self {
        assert!(
            msg.len() <= MAX_MESSAGE_SIZE,
            "warning message exceeds maximum size"
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
        self.channel_id.encode(&mut out);
        #[allow(clippy::cast_possible_truncation)] // Checked in constructors
        write_u16_be(self.data.len() as u16, &mut out);
        out.extend_from_slice(&self.data);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::decode(&mut cursor)?;
        let data_len = read_u16_be(&mut cursor)? as usize;

        if cursor.len() < data_len {
            return Err(BoltError::Truncated {
                expected: data_len,
                actual: cursor.len(),
            });
        }

        Ok(Self {
            channel_id,
            data: cursor[..data_len].to_vec(),
        })
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
    fn warning_all_channels() {
        let warn = Warning::all_channels("test warning");
        assert_eq!(warn.channel_id, ChannelId::ALL);
        assert_eq!(warn.message(), Some("test warning"));
    }

    #[test]
    fn warning_for_channel() {
        let channel_id = ChannelId::new([0x42; CHANNEL_ID_SIZE]);
        let warn = Warning::for_channel(channel_id, "channel warning");
        assert_eq!(warn.channel_id, channel_id);
        assert_eq!(warn.message(), Some("channel warning"));
    }

    #[test]
    fn warning_encode() {
        let warn = Warning::all_channels("hi");
        let encoded = warn.encode();
        // ChannelId::ALL + len(2) + "hi"(2)
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE + 2 + 2);
        assert_eq!(&encoded[..CHANNEL_ID_SIZE], &ChannelId::ALL.as_bytes()[..]);
        assert_eq!(
            &encoded[CHANNEL_ID_SIZE..CHANNEL_ID_SIZE + 2],
            &[0x00, 0x02]
        ); // len = 2
        assert_eq!(&encoded[CHANNEL_ID_SIZE + 2..], b"hi");
    }

    #[test]
    fn warning_decode() {
        let mut data = vec![0x11u8; CHANNEL_ID_SIZE]; // channel_id
        data.extend_from_slice(&[0x00, 0x05]); // len = 5
        data.extend_from_slice(b"hello");

        let warn = Warning::decode(&data).unwrap();
        assert_eq!(warn.channel_id, ChannelId::new([0x11u8; CHANNEL_ID_SIZE]));
        assert_eq!(warn.message(), Some("hello"));
    }

    #[test]
    fn warning_roundtrip() {
        let original =
            Warning::for_channel(ChannelId::new([0xab; CHANNEL_ID_SIZE]), "roundtrip test");
        let encoded = original.encode();
        let decoded = Warning::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn warning_decode_truncated_channel_id() {
        assert_eq!(
            Warning::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn warning_decode_truncated_len() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE]; // channel_id
        data.push(0x00); // only 1 byte of len
        assert_eq!(
            Warning::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn warning_decode_truncated_data() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE]; // channel_id
        data.extend_from_slice(&[0x00, 0x10]); // len = 16
        data.extend_from_slice(b"short"); // only 5 bytes
        assert_eq!(
            Warning::decode(&data),
            Err(BoltError::Truncated {
                expected: 16,
                actual: 5
            })
        );
    }

    #[test]
    fn warning_non_utf8_data() {
        let warn = Warning {
            channel_id: ChannelId::ALL,
            data: vec![0xff, 0xfe], // invalid UTF-8
        };
        assert_eq!(warn.message(), None);
    }

    #[test]
    #[should_panic(expected = "warning message exceeds maximum size")]
    fn warning_all_channels_too_long() {
        let long_msg = "x".repeat(MAX_MESSAGE_SIZE + 1);
        let _ = Warning::all_channels(&long_msg);
    }

    #[test]
    #[should_panic(expected = "warning message exceeds maximum size")]
    fn warning_for_channel_too_long() {
        let long_msg = "x".repeat(MAX_MESSAGE_SIZE + 1);
        let _ = Warning::for_channel(ChannelId::ALL, &long_msg);
    }
}
