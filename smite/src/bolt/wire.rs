//! Wire format serialization and deserialization primitives.

use crate::bolt::BoltError;
use secp256k1::PublicKey;

/// A type that can be read from and written to the Lightning wire format.
pub trait WireFormat: Sized {
    /// Reads a value from the byte slice, advancing past the consumed bytes.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if the data is truncated or invalid.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError>;

    /// Writes the value in wire format, appending bytes to `out`.
    fn write(&self, out: &mut Vec<u8>);
}

macro_rules! impl_wire_format_int {
    ($type:ty) => {
        impl WireFormat for $type {
            fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
                let size = std::mem::size_of::<$type>();
                if data.len() < size {
                    return Err(BoltError::Truncated {
                        expected: size,
                        actual: data.len(),
                    });
                }
                let bytes = data[..size].try_into().unwrap();
                *data = &data[size..];
                Ok(<$type>::from_be_bytes(bytes))
            }

            fn write(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
        }
    };
}

impl_wire_format_int!(u8);
impl_wire_format_int!(u16);
impl_wire_format_int!(u32);
impl_wire_format_int!(u64);

impl<const N: usize> WireFormat for [u8; N] {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        if data.len() < N {
            return Err(BoltError::Truncated {
                expected: N,
                actual: data.len(),
            });
        }
        let mut buf = [0u8; N];
        buf.copy_from_slice(&data[..N]);
        *data = &data[N..];
        Ok(buf)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl WireFormat for PublicKey {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        const PUBLIC_KEY_SIZE: usize = 33;
        let buf: [u8; PUBLIC_KEY_SIZE] = WireFormat::read(data)?;
        let pubkey = PublicKey::from_slice(&buf).map_err(|_| BoltError::InvalidPublicKey(buf))?;
        Ok(pubkey)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.serialize());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn u8_read_valid() {
        let mut data: &[u8] = &[0x00, 0xff];
        assert_eq!(u8::read(&mut data).unwrap(), 0);
        assert_eq!(data, &[0xff]);
        assert_eq!(u8::read(&mut data).unwrap(), 255);
        assert!(data.is_empty());
    }

    #[test]
    fn u8_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u8::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn u8_write_roundtrip() {
        for value in [0u8, 1, 127, 255] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 1);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u8::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn u16_read_valid() {
        let mut data: &[u8] = &[0x00, 0x00, 0x00, 0x01];
        assert_eq!(u16::read(&mut data).unwrap(), 0);
        assert_eq!(data, &[0x00, 0x01]);
        assert_eq!(u16::read(&mut data).unwrap(), 1);
        assert!(data.is_empty());
    }

    #[test]
    fn u16_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u16::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 0
            })
        );

        let mut one_byte: &[u8] = &[0x00];
        assert_eq!(
            u16::read(&mut one_byte),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn u16_write_roundtrip() {
        for value in [0u16, 1, 255, 256, 65535] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 2);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u16::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn u32_read_valid() {
        let mut data: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(u32::read(&mut data).unwrap(), 0);
        assert_eq!(data, &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(u32::read(&mut data).unwrap(), 1);
        assert!(data.is_empty());
    }

    #[test]
    fn u32_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u32::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0x00, 0x01, 0x02];
        assert_eq!(
            u32::read(&mut short),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 3
            })
        );
    }

    #[test]
    fn u32_write_roundtrip() {
        for value in [0u32, 1, 65535, 65536, u32::MAX] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 4);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u32::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn u64_read_valid() {
        let mut data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(u64::read(&mut data).unwrap(), 0);
        assert_eq!(data.len(), 8);
        assert_eq!(u64::read(&mut data).unwrap(), 1);
        assert!(data.is_empty());
    }

    #[test]
    fn u64_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u64::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0x00; 7];
        assert_eq!(
            u64::read(&mut short),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 7
            })
        );
    }

    #[test]
    fn u64_write_roundtrip() {
        for value in [0u64, 1, u64::from(u32::MAX), u64::MAX] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 8);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u64::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn byte_array_read_valid() {
        let mut data: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let arr = <[u8; 3]>::read(&mut data).unwrap();
        assert_eq!(arr, [0xaa, 0xbb, 0xcc]);
        assert_eq!(data, &[0xdd, 0xee]);
    }

    #[test]
    fn byte_array_read_truncated() {
        let mut short: &[u8] = &[0xaa, 0xbb];
        assert_eq!(
            <[u8; 4]>::read(&mut short),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );

        let mut empty: &[u8] = &[];
        assert_eq!(
            <[u8; 1]>::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn byte_array_write_roundtrip() {
        let original = [0x11, 0x22, 0x33, 0x44, 0x55];
        let mut buf = Vec::new();
        original.write(&mut buf);
        assert_eq!(buf.len(), 5);
        let mut cursor: &[u8] = &buf;
        let decoded = <[u8; 5]>::read(&mut cursor).unwrap();
        assert_eq!(decoded, original);
        assert!(cursor.is_empty());
    }

    #[test]
    fn pubkey_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            PublicKey::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 33,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0x02; 20];
        assert_eq!(
            PublicKey::read(&mut short),
            Err(BoltError::Truncated {
                expected: 33,
                actual: 20
            })
        );
    }

    #[test]
    fn pubkey_read_invalid() {
        let invalid = [0x00; 33];
        let mut data: &[u8] = &invalid;
        assert_eq!(
            PublicKey::read(&mut data),
            Err(BoltError::InvalidPublicKey(invalid))
        );
    }

    #[test]
    fn pubkey_write_roundtrip() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x22; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let mut buf = Vec::new();
        pk.write(&mut buf);
        assert_eq!(buf.len(), 33);
        let mut cursor: &[u8] = &buf;
        let decoded = PublicKey::read(&mut cursor).unwrap();
        assert_eq!(decoded, pk);
        assert!(cursor.is_empty());
    }
}
