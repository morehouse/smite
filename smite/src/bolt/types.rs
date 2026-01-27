//! Fundamental types for BOLT message encoding.

use super::BoltError;

/// Maximum Lightning message size (2-byte length prefix limit).
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of a channel ID in bytes.
pub const CHANNEL_ID_SIZE: usize = 32;

/// A 32-byte channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelId(pub [u8; CHANNEL_ID_SIZE]);

impl ChannelId {
    /// Special all-zero channel ID indicating "all channels" (for errors)
    /// or "not channel-specific" (for warnings).
    pub const ALL: Self = Self([0u8; CHANNEL_ID_SIZE]);

    /// Creates a channel ID from a byte array.
    #[must_use]
    pub const fn new(bytes: [u8; CHANNEL_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the channel ID as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CHANNEL_ID_SIZE] {
        &self.0
    }

    /// Decodes a channel ID from bytes, advancing the slice.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if there are fewer than 32 bytes.
    pub fn decode(data: &mut &[u8]) -> Result<Self, BoltError> {
        if data.len() < CHANNEL_ID_SIZE {
            return Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: data.len(),
            });
        }
        #[allow(clippy::missing_panics_doc)] // Size check above
        let bytes: [u8; CHANNEL_ID_SIZE] = data[..CHANNEL_ID_SIZE].try_into().unwrap();
        *data = &data[CHANNEL_ID_SIZE..];
        Ok(Self(bytes))
    }

    /// Encodes the channel ID to a vector.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

/// Decodes a `BigSize` value from bytes.
///
/// `BigSize` is like Bitcoin's `CompactSize` but big-endian:
/// - 0x00-0xFC: 1 byte (value as-is)
/// - 0xFD + 2 bytes BE: values 0xFD-0xFFFF
/// - 0xFE + 4 bytes BE: values 0x10000-0xFFFFFFFF
/// - 0xFF + 8 bytes BE: values > 0xFFFFFFFF
///
/// Returns the decoded value and number of bytes consumed.
///
/// # Errors
///
/// Returns `BigSizeTruncated` if there aren't enough bytes, or
/// `BigSizeNotMinimal` if the encoding is not minimal.
pub fn decode_bigsize(data: &[u8]) -> Result<(u64, usize), BoltError> {
    if data.is_empty() {
        return Err(BoltError::BigSizeTruncated);
    }

    match data[0] {
        0..=0xfc => Ok((u64::from(data[0]), 1)),
        0xfd => {
            if data.len() < 3 {
                return Err(BoltError::BigSizeTruncated);
            }
            let value = u64::from(u16::from_be_bytes([data[1], data[2]]));
            // Must be minimally encoded: value must be >= 0xfd
            if value < 0xfd {
                return Err(BoltError::BigSizeNotMinimal);
            }
            Ok((value, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return Err(BoltError::BigSizeTruncated);
            }
            let value = u64::from(u32::from_be_bytes([data[1], data[2], data[3], data[4]]));
            // Must be minimally encoded: value must be >= 0x10000
            if value < 0x1_0000 {
                return Err(BoltError::BigSizeNotMinimal);
            }
            Ok((value, 5))
        }
        0xff => {
            if data.len() < 9 {
                return Err(BoltError::BigSizeTruncated);
            }
            let value = u64::from_be_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            // Must be minimally encoded: value must be >= 0x100000000
            if value < 0x1_0000_0000 {
                return Err(BoltError::BigSizeNotMinimal);
            }
            Ok((value, 9))
        }
    }
}

/// Encodes a value as `BigSize`.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // Truncation is safe: we check ranges before casting
pub fn encode_bigsize(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value < 0x1_0000 {
        let mut out = vec![0xfd];
        out.extend_from_slice(&(value as u16).to_be_bytes());
        out
    } else if value < 0x1_0000_0000 {
        let mut out = vec![0xfe];
        out.extend_from_slice(&(value as u32).to_be_bytes());
        out
    } else {
        let mut out = vec![0xff];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }
}

/// Returns the encoded length of a `BigSize` value.
#[must_use]
pub const fn bigsize_len(value: u64) -> usize {
    if value < 0xfd {
        1
    } else if value < 0x1_0000 {
        3
    } else if value < 0x1_0000_0000 {
        5
    } else {
        9
    }
}

/// Reads a u16 big-endian from bytes, advancing the slice past the read bytes.
///
/// # Errors
///
/// Returns `Truncated` if there are fewer than 2 bytes.
pub fn read_u16_be(data: &mut &[u8]) -> Result<u16, BoltError> {
    if data.len() < 2 {
        return Err(BoltError::Truncated {
            expected: 2,
            actual: data.len(),
        });
    }
    let value = u16::from_be_bytes([data[0], data[1]]);
    *data = &data[2..];
    Ok(value)
}

/// Writes a u16 big-endian to a vector.
pub fn write_u16_be(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from BOLT 1 Appendix A
    // https://github.com/lightning/bolts/blob/master/01-messaging.md#appendix-a-bigsize-test-vectors

    #[test]
    fn bigsize_decode_valid() {
        let tests: &[(&[u8], u64)] = &[
            (&[0x00], 0),
            (&[0xfc], 252),
            (&[0xfd, 0x00, 0xfd], 253),
            (&[0xfd, 0xff, 0xff], 65535),
            (&[0xfe, 0x00, 0x01, 0x00, 0x00], 65536),
            (&[0xfe, 0xff, 0xff, 0xff, 0xff], 4_294_967_295),
            (
                &[0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
                4_294_967_296,
            ),
            (
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                18_446_744_073_709_551_615,
            ),
        ];

        for (bytes, expected) in tests {
            let (value, len) = decode_bigsize(bytes).expect("valid bigsize");
            assert_eq!(value, *expected, "decoding {bytes:02x?}");
            assert_eq!(len, bytes.len());
        }
    }

    #[test]
    fn bigsize_encode_valid() {
        let tests: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (252, &[0xfc]),
            (253, &[0xfd, 0x00, 0xfd]),
            (65535, &[0xfd, 0xff, 0xff]),
            (65536, &[0xfe, 0x00, 0x01, 0x00, 0x00]),
            (4_294_967_295, &[0xfe, 0xff, 0xff, 0xff, 0xff]),
            (
                4_294_967_296,
                &[0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                18_446_744_073_709_551_615,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, expected) in tests {
            let encoded = encode_bigsize(*value);
            assert_eq!(encoded.as_slice(), *expected, "encoding {value}");
        }
    }

    #[test]
    fn bigsize_roundtrip() {
        let values = [
            0,
            1,
            252,
            253,
            254,
            65535,
            65536,
            0xffff_ffff,
            0x1_0000_0000,
        ];
        for value in values {
            let encoded = encode_bigsize(value);
            let (decoded, len) = decode_bigsize(&encoded).expect("valid bigsize");
            assert_eq!(decoded, value);
            assert_eq!(len, encoded.len());
        }
    }

    #[test]
    fn bigsize_not_minimal() {
        // Two-byte encoding for value < 253
        let invalid = &[0xfd, 0x00, 0xfc];
        assert_eq!(decode_bigsize(invalid), Err(BoltError::BigSizeNotMinimal));

        // Four-byte encoding for value < 65536
        let invalid = &[0xfe, 0x00, 0x00, 0xff, 0xff];
        assert_eq!(decode_bigsize(invalid), Err(BoltError::BigSizeNotMinimal));

        // Eight-byte encoding for value < 4294967296
        let invalid = &[0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode_bigsize(invalid), Err(BoltError::BigSizeNotMinimal));
    }

    #[test]
    fn bigsize_truncated() {
        // Test vectors from BOLT 1 Appendix A "short read" and "no read"

        // No read tests (just prefix, no payload bytes)
        assert_eq!(decode_bigsize(&[]), Err(BoltError::BigSizeTruncated)); // one byte no read
        assert_eq!(decode_bigsize(&[0xfd]), Err(BoltError::BigSizeTruncated)); // two byte no read
        assert_eq!(decode_bigsize(&[0xfe]), Err(BoltError::BigSizeTruncated)); // four byte no read
        assert_eq!(decode_bigsize(&[0xff]), Err(BoltError::BigSizeTruncated)); // eight byte no read

        // Short read tests (prefix + partial payload)
        assert_eq!(
            decode_bigsize(&[0xfd, 0x00]),
            Err(BoltError::BigSizeTruncated)
        ); // two byte short read
        assert_eq!(
            decode_bigsize(&[0xfe, 0xff, 0xff]),
            Err(BoltError::BigSizeTruncated)
        ); // four byte short read
        assert_eq!(
            decode_bigsize(&[0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(BoltError::BigSizeTruncated)
        ); // eight byte short read
    }

    #[test]
    fn bigsize_len_matches_encode() {
        let values = [0, 252, 253, 65535, 65536, 0xffff_ffff, 0x1_0000_0000];
        for value in values {
            assert_eq!(bigsize_len(value), encode_bigsize(value).len());
        }
    }

    #[test]
    fn read_u16_be_valid() {
        let mut data: &[u8] = &[0x00, 0x00, 0x00, 0x01];
        assert_eq!(read_u16_be(&mut data).unwrap(), 0);
        assert_eq!(data, &[0x00, 0x01]); // Slice advanced
        assert_eq!(read_u16_be(&mut data).unwrap(), 1);
        assert!(data.is_empty()); // Fully consumed
    }

    #[test]
    fn read_u16_be_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            read_u16_be(&mut empty),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 0
            })
        );

        let mut one_byte: &[u8] = &[0x00];
        assert_eq!(
            read_u16_be(&mut one_byte),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn write_u16_be_roundtrip() {
        for value in [0u16, 1, 255, 256, 65535] {
            let mut buf = Vec::new();
            write_u16_be(value, &mut buf);
            assert_eq!(buf.len(), 2);
            let mut cursor: &[u8] = &buf;
            assert_eq!(read_u16_be(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn channel_id_all_is_zeros() {
        assert_eq!(ChannelId::ALL.0, [0u8; CHANNEL_ID_SIZE]);
    }

    #[test]
    fn channel_id_new() {
        let bytes = [0x42u8; CHANNEL_ID_SIZE];
        let id = ChannelId::new(bytes);
        assert_eq!(id.0, bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn channel_id_default_is_all() {
        assert_eq!(ChannelId::default(), ChannelId::ALL);
    }

    #[test]
    fn channel_id_roundtrip() {
        let original = ChannelId::new([0xab; CHANNEL_ID_SIZE]);
        let mut buf = Vec::new();
        original.encode(&mut buf);
        assert_eq!(buf.len(), CHANNEL_ID_SIZE);

        let mut cursor: &[u8] = &buf;
        let decoded = ChannelId::decode(&mut cursor).unwrap();
        assert_eq!(decoded, original);
        assert!(cursor.is_empty());
    }

    #[test]
    fn channel_id_decode_truncated() {
        let mut short: &[u8] = &[0x00; 20];
        assert_eq!(
            ChannelId::decode(&mut short),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn channel_id_decode_advances_cursor() {
        let mut data: &[u8] = &[0x11; CHANNEL_ID_SIZE + 8]; // 8 extra bytes
        let id = ChannelId::decode(&mut data).unwrap();
        assert_eq!(id, ChannelId::new([0x11; CHANNEL_ID_SIZE]));
        assert_eq!(data.len(), 8); // 8 bytes remaining
    }
}
