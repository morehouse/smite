//! Fundamental types for BOLT message encoding.

/// Maximum Lightning message size (2-byte length prefix limit).
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of a channel ID in bytes.
pub const CHANNEL_ID_SIZE: usize = 32;

/// Size of a chain hash (SHA256).
pub const CHAIN_HASH_SIZE: usize = 32;

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
}

/// A variable-length unsigned integer similar to Bitcoin's `CompactSize`
/// encoding, but big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigSize(pub u64);

impl BigSize {
    /// Creates a `BigSize` from a `u64` value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner `u64` value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the encoded length of this `BigSize` value.
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // BigSize always encodes to at least 1 byte
    pub const fn len(self) -> usize {
        if self.value() < 0xfd {
            1
        } else if self.value() < 0x1_0000 {
            3
        } else if self.value() < 0x1_0000_0000 {
            5
        } else {
            9
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigsize_new() {
        let bs = BigSize::new(42);
        assert_eq!(bs.0, 42);
        assert_eq!(bs.value(), 42);
    }

    #[test]
    fn bigsize_value() {
        for v in [0u64, 1, 252, 253, 65535, 65536, u64::MAX] {
            assert_eq!(BigSize::new(v).value(), v);
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
}
