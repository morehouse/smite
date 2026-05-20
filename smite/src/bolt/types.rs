//! Fundamental types for BOLT message encoding.

use std::fmt;

/// Maximum Lightning message size (2-byte length prefix limit).
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of a channel ID in bytes.
pub const CHANNEL_ID_SIZE: usize = 32;

/// Size of a chain hash (SHA256).
pub const CHAIN_HASH_SIZE: usize = 32;

/// Size of a SHA256 Hash.
pub const SHA256_HASH_SIZE: usize = 32;

/// Size of a transaction ID in bytes.
pub const TXID_SIZE: usize = 32;

/// Size of a compact ECDSA signature in bytes.
pub const COMPACT_SIGNATURE_SIZE: usize = 64;

/// Size of a compressed secp256k1 public key.
pub const PUBLIC_KEY_SIZE: usize = 33;

/// Size of an encoded `short_channel_id` in bytes.
pub const SHORT_CHANNEL_ID_SIZE: usize = 8;

/// Maximum representable block height (3 bytes, big-endian).
const MAX_BLOCK: u32 = 0x00ff_ffff;
/// Maximum representable transaction index (3 bytes, big-endian).
const MAX_TX_INDEX: u32 = 0x00ff_ffff;

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

/// A BOLT 7 `short_channel_id`.
///
/// Per [BOLT 7]:
///   * the most significant 3 bytes encode the block height,
///   * the next 3 bytes encode the transaction index within the block,
///   * the least significant 2 bytes encode the output index of the funding
///     transaction.
///
/// Internally stored as the packed 8-byte big-endian representation:
/// `(block << 40) | (tx_index << 16) | output_index`.
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ShortChannelId(u64);

impl ShortChannelId {
    /// Constructs a `short_channel_id` from its components.
    ///
    /// # Panics
    ///
    /// Panics if `block` or `tx_index` exceed their 24-bit field.
    #[must_use]
    pub const fn new(block: u32, tx_index: u32, output_index: u16) -> Self {
        assert!(block <= MAX_BLOCK, "block is out-of-range");
        assert!(tx_index <= MAX_TX_INDEX, "tx_index is out-of-range");
        let packed = ((block as u64) << 40) | ((tx_index as u64) << 16) | (output_index as u64);
        Self(packed)
    }

    /// Constructs a `short_channel_id` from its raw packed form.
    #[must_use]
    pub const fn from_u64(packed: u64) -> Self {
        Self(packed)
    }

    /// Returns the packed `u64` representation.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the block height component.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // value is masked to 24 bits
    pub const fn block(self) -> u32 {
        ((self.0 >> 40) & 0x00ff_ffff) as u32
    }

    /// Returns the transaction index component.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // value is masked to 24 bits
    pub const fn tx_index(self) -> u32 {
        ((self.0 >> 16) & 0x00ff_ffff) as u32
    }

    /// Returns the output index component.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // low 16 bits
    pub const fn output_index(self) -> u16 {
        (self.0 & 0xffff) as u16
    }
}

impl fmt::Display for ShortChannelId {
    /// Formats as the BOLT 7 human-readable form `<block>x<tx>x<out>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{}x{}",
            self.block(),
            self.tx_index(),
            self.output_index()
        )
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

    #[test]
    fn short_channel_id_new_roundtrips_components() {
        let scid = ShortChannelId::new(539_268, 845, 1);
        assert_eq!(scid.block(), 539_268);
        assert_eq!(scid.tx_index(), 845);
        assert_eq!(scid.output_index(), 1);
    }

    #[test]
    fn short_channel_id_new_accepts_max_components() {
        let scid = ShortChannelId::new(MAX_BLOCK, MAX_TX_INDEX, u16::MAX);
        assert_eq!(scid.block(), MAX_BLOCK);
        assert_eq!(scid.tx_index(), MAX_TX_INDEX);
        assert_eq!(scid.output_index(), u16::MAX);
    }

    #[test]
    #[should_panic(expected = "block is out-of-range")]
    fn short_channel_id_new_panics_on_block_overflow() {
        let _ = ShortChannelId::new(MAX_BLOCK + 1, 0, 0);
    }

    #[test]
    #[should_panic(expected = "tx_index is out-of-range")]
    fn short_channel_id_new_panics_on_tx_index_overflow() {
        let _ = ShortChannelId::new(0, MAX_TX_INDEX + 1, 0);
    }

    #[test]
    fn short_channel_id_display_uses_bolt7_format() {
        let scid = ShortChannelId::new(539_268, 845, 1);
        assert_eq!(format!("{scid}"), "539268x845x1");
    }

    #[test]
    fn short_channel_id_from_u64_inverse_of_as_u64() {
        for packed in [0u64, 1, 0x1234_5678_9abc_def0, u64::MAX] {
            let scid = ShortChannelId::from_u64(packed);
            assert_eq!(scid.as_u64(), packed);
        }
    }

    #[test]
    fn short_channel_id_ord_matches_packed_u64() {
        let a = ShortChannelId::new(100, 0, 0);
        let b = ShortChannelId::new(100, 0, 1);
        let c = ShortChannelId::new(100, 1, 0);
        let d = ShortChannelId::new(101, 0, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(c < d);
    }
}
