//! BOLT 1 pong message.

use super::BoltError;
use super::ping::Ping;
use super::types::{read_u16_be, write_u16_be};

/// BOLT 1 pong message (type 19).
///
/// Sent in response to a ping message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    /// Padding bytes (should match ping's `num_pong_bytes`).
    pub ignored: Vec<u8>,
}

impl Pong {
    /// Creates a pong with the specified number of padding bytes.
    #[must_use]
    pub fn new(byteslen: u16) -> Self {
        Self {
            ignored: vec![0u8; byteslen as usize],
        }
    }

    /// Creates a pong response to a ping.
    #[must_use]
    pub fn respond_to(ping: &Ping) -> Self {
        Self::new(ping.num_pong_bytes)
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        #[allow(clippy::cast_possible_truncation)] // Vec length bounded by u16 from new()
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
        let byteslen = read_u16_be(&mut cursor)? as usize;

        if cursor.len() < byteslen {
            return Err(BoltError::Truncated {
                expected: byteslen,
                actual: cursor.len(),
            });
        }

        Ok(Self {
            ignored: cursor[..byteslen].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_zeros() {
        let pong = Pong::new(5);
        assert_eq!(pong.ignored.len(), 5);
        assert!(pong.ignored.iter().all(|&b| b == 0));
    }

    #[test]
    #[allow(clippy::similar_names)] // ping and pong are the canonical names
    fn respond_to_ping() {
        let ping = Ping::new(10);
        let pong = Pong::respond_to(&ping);
        assert_eq!(pong.ignored.len(), 10);
    }

    #[test]
    fn encode_empty() {
        let pong = Pong::new(0);
        let encoded = pong.encode();
        assert_eq!(encoded, [0x00, 0x00]);
    }

    #[test]
    fn encode_with_padding() {
        let pong = Pong::new(3);
        let encoded = pong.encode();
        assert_eq!(encoded, [0x00, 0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn decode_empty() {
        let data = [0x00, 0x00];
        let pong = Pong::decode(&data).unwrap();
        assert!(pong.ignored.is_empty());
    }

    #[test]
    fn decode_with_padding() {
        let data = [0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let pong = Pong::decode(&data).unwrap();
        assert_eq!(pong.ignored, [0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn roundtrip() {
        let original = Pong {
            ignored: vec![0x11, 0x22, 0x33, 0x44, 0x55],
        };
        let encoded = original.encode();
        let decoded = Pong::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_header() {
        assert_eq!(
            Pong::decode(&[]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 0
            })
        );

        assert_eq!(
            Pong::decode(&[0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_padding() {
        // Header says 5 bytes, but only 2 remaining
        let data = [0x00, 0x05, 0xaa, 0xbb];
        assert_eq!(
            Pong::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_extra_bytes_ignored() {
        // Extra bytes after padding are ignored
        let data = [0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd];
        let pong = Pong::decode(&data).unwrap();
        assert_eq!(pong.ignored, [0xaa, 0xbb]);
    }
}
