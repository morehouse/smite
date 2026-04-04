//! BOLT 7 `channel_update` message.

use super::BoltError;
use super::types::{ChainHash, ShortChannelId, Signature};
use super::wire::WireFormat;

/// BOLT 7 `channel_update` message (type 258 / 0x0102).
///
/// Announces the routing conditions for one direction of a channel.
/// Each side of a channel sends its own `channel_update`. A channel
/// has two directions; `channel_flags` bit 0 identifies which direction
/// this update applies to (0 = node_1 to node_2, 1 = node_2 to node_1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelUpdate {
    /// Signature from the originating node.
    pub signature: Signature,
    /// Chain this channel lives on.
    pub chain_hash: ChainHash,
    /// Compact identifier of the channel being updated.
    pub short_channel_id: ShortChannelId,
    /// Unix timestamp. Higher timestamp wins on conflicts.
    pub timestamp: u32,
    /// Flags signalling presence of optional fields.
    ///
    /// Bit 0: `htlc_maximum_msat` is present.
    pub message_flags: u8,
    /// Direction and status flags.
    ///
    /// Bit 0: direction (0 = from node_1, 1 = from node_2).
    /// Bit 1: channel is disabled.
    pub channel_flags: u8,
    /// Blocks added to HTLC CLTV when forwarding.
    pub cltv_expiry_delta: u16,
    /// Minimum HTLC value accepted, in millisatoshis.
    pub htlc_minimum_msat: u64,
    /// Flat fee charged per HTLC, in millisatoshis.
    pub fee_base_msat: u32,
    /// Proportional fee in millionths of the forwarded amount.
    pub fee_proportional_millionths: u32,
    /// Maximum HTLC value accepted, in millisatoshis.
    ///
    /// Present only when `message_flags` bit 0 is set.
    pub htlc_maximum_msat: Option<u64>,
}

/// Mask for the `htlc_maximum_msat` presence bit in `message_flags`.
const HAS_MAX_HTLC: u8 = 0x01;

impl ChannelUpdate {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.signature.write(&mut out);
        self.chain_hash.write(&mut out);
        self.short_channel_id.write(&mut out);
        self.timestamp.write(&mut out);
        self.message_flags.write(&mut out);
        self.channel_flags.write(&mut out);
        self.cltv_expiry_delta.write(&mut out);
        self.htlc_minimum_msat.write(&mut out);
        self.fee_base_msat.write(&mut out);
        self.fee_proportional_millionths.write(&mut out);

        // htlc_maximum_msat is optional — only written when flag bit is set
        if self.message_flags & HAS_MAX_HTLC != 0 {
            if let Some(max) = self.htlc_maximum_msat {
                max.write(&mut out);
            }
        }
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let signature                   = Signature::read(&mut cursor)?;
        let chain_hash                  = ChainHash::read(&mut cursor)?;
        let short_channel_id            = ShortChannelId::read(&mut cursor)?;
        let timestamp                   = u32::read(&mut cursor)?;
        let message_flags               = u8::read(&mut cursor)?;
        let channel_flags               = u8::read(&mut cursor)?;
        let cltv_expiry_delta           = u16::read(&mut cursor)?;
        let htlc_minimum_msat           = u64::read(&mut cursor)?;
        let fee_base_msat               = u32::read(&mut cursor)?;
        let fee_proportional_millionths = u32::read(&mut cursor)?;

        // Only read htlc_maximum_msat if the flag bit tells us it's present
        let htlc_maximum_msat = if message_flags & HAS_MAX_HTLC != 0 {
            Some(u64::read(&mut cursor)?)
        } else {
            None
        };

        Ok(Self {
            signature, chain_hash, short_channel_id,
            timestamp, message_flags, channel_flags,
            cltv_expiry_delta, htlc_minimum_msat,
            fee_base_msat, fee_proportional_millionths,
            htlc_maximum_msat,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{SIGNATURE_SIZE, CHAIN_HASH_SIZE};

    fn dummy(with_max_htlc: bool) -> ChannelUpdate {
        ChannelUpdate {
            signature:                   Signature::new([0x01; SIGNATURE_SIZE]),
            chain_hash:                  ChainHash::new([0xaa; CHAIN_HASH_SIZE]),
            short_channel_id:            ShortChannelId::new(0x1234_5678_9abc),
            timestamp:                   1_700_000_000,
            message_flags:               if with_max_htlc { HAS_MAX_HTLC } else { 0 },
            channel_flags:               0x01, // direction: node_2 → node_1
            cltv_expiry_delta:           40,
            htlc_minimum_msat:           1_000,
            fee_base_msat:               1_000,
            fee_proportional_millionths: 100,
            htlc_maximum_msat:           if with_max_htlc { Some(100_000_000) } else { None },
        }
    }

    #[test]
    fn encode_field_sizes_without_max_htlc() {
        let encoded = dummy(false).encode();
        // sig(64) + chain_hash(32) + scid(8) + timestamp(4)
        // + msg_flags(1) + chan_flags(1) + cltv(2) + min(8) + base(4) + prop(4) = 128
        assert_eq!(encoded.len(), SIGNATURE_SIZE + CHAIN_HASH_SIZE + 8 + 4 + 1 + 1 + 2 + 8 + 4 + 4);
    }

    #[test]
    fn encode_field_sizes_with_max_htlc() {
        let encoded = dummy(true).encode();
        // same as above + htlc_maximum_msat(8) = 136
        assert_eq!(
            encoded.len(),
            SIGNATURE_SIZE + CHAIN_HASH_SIZE + 8 + 4 + 1 + 1 + 2 + 8 + 4 + 4 + 8
        );
    }

    #[test]
    fn roundtrip_without_max_htlc() {
        let original = dummy(false);
        let decoded = ChannelUpdate::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_max_htlc() {
        let original = dummy(true);
        let decoded = ChannelUpdate::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_signature() {
        assert_eq!(
            ChannelUpdate::decode(&[0x00; 10]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 10 })
        );
    }

    #[test]
    fn decode_truncated_optional_field() {
        // Encode with flag set but truncate before htlc_maximum_msat bytes
        let mut encoded = dummy(true).encode();
        encoded.truncate(encoded.len() - 4); // remove last 4 bytes of the 8-byte field
        assert!(ChannelUpdate::decode(&encoded).is_err());
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            ChannelUpdate::decode(&[]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 0 })
        );
    }
}