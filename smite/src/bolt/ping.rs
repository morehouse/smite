//! BOLT 1 ping message.

use super::BoltError;
use super::types::{read_u16_be, write_u16_be};

/// BOLT 1 ping message (type 18).
///
/// Used for connection liveness checks and traffic obfuscation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    /// Number of bytes the peer should respond with in pong.
    pub num_pong_bytes: u16,
    /// Padding bytes (ignored by receiver).
    pub ignored: Vec<u8>,
}

impl Ping {
    /// Creates a ping requesting `num_pong_bytes` in the pong response.
    #[must_use]
    pub fn new(num_pong_bytes: u16) -> Self {
        Self {
            num_pong_bytes,
            ignored: Vec::new(),
        }
    }

    /// Creates a ping with custom padding length.
    #[must_use]
    pub fn with_padding(num_pong_bytes: u16, padding_len: u16) -> Self {
        Self {
            num_pong_bytes,
            ignored: vec![0u8; padding_len as usize],
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_be(self.num_pong_bytes, &mut out);
        #[allow(clippy::cast_possible_truncation)] // Vec length is bounded by u16 padding_len
        write_u16_be(self.ignored.len() as u16, &mut out);
        out.extend_from_slice(&self.ignored);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let num_pong_bytes = read_u16_be(&mut cursor)?;
        let byteslen = read_u16_be(&mut cursor)? as usize;

        if cursor.len() < byteslen {
            return Err(BoltError::Truncated {
                expected: byteslen,
                actual: cursor.len(),
            });
        }

        Ok(Self {
            num_pong_bytes,
            ignored: cursor[..byteslen].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_padding() {
        let ping = Ping::new(4);
        assert_eq!(ping.num_pong_bytes, 4);
        assert!(ping.ignored.is_empty());
    }

    #[test]
    fn with_padding_creates_zeros() {
        let ping = Ping::with_padding(4, 10);
        assert_eq!(ping.num_pong_bytes, 4);
        assert_eq!(ping.ignored.len(), 10);
        assert!(ping.ignored.iter().all(|&b| b == 0));
    }

    #[test]
    fn encode_no_padding() {
        let ping = Ping::new(4);
        let encoded = ping.encode();
        // num_pong_bytes=4 (0x0004), byteslen=0 (0x0000)
        assert_eq!(encoded, [0x00, 0x04, 0x00, 0x00]);
    }

    #[test]
    fn encode_with_padding() {
        let ping = Ping::with_padding(256, 3);
        let encoded = ping.encode();
        // num_pong_bytes=256 (0x0100), byteslen=3 (0x0003), padding=000000
        assert_eq!(encoded, [0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn decode_no_padding() {
        let data = [0x00, 0x04, 0x00, 0x00];
        let ping = Ping::decode(&data).unwrap();
        assert_eq!(ping.num_pong_bytes, 4);
        assert!(ping.ignored.is_empty());
    }

    #[test]
    fn decode_with_padding() {
        let data = [0x01, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let ping = Ping::decode(&data).unwrap();
        assert_eq!(ping.num_pong_bytes, 256);
        assert_eq!(ping.ignored, [0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn roundtrip() {
        let original = Ping {
            num_pong_bytes: 1000,
            ignored: vec![0x11, 0x22, 0x33, 0x44, 0x55],
        };
        let encoded = original.encode();
        let decoded = Ping::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_header() {
        // Only 1 byte - first read_u16_be fails
        assert_eq!(
            Ping::decode(&[0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
        // Only 3 bytes - second read_u16_be fails (1 byte remaining)
        assert_eq!(
            Ping::decode(&[0x00, 0x04, 0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_padding() {
        // Header says 5 bytes of padding, but only 2 remaining after header
        let data = [0x00, 0x04, 0x00, 0x05, 0xaa, 0xbb];
        assert_eq!(
            Ping::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_extra_bytes_ignored() {
        // Extra bytes after padding are ignored (may be TLV extension)
        let data = [0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd];
        let ping = Ping::decode(&data).unwrap();
        assert_eq!(ping.ignored, [0xaa, 0xbb]);
    }
}
