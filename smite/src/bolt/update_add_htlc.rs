//! BOLT 2 `update_add_htlc` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;

/// The size of an onion routing packet in bytes.
const ONION_PACKET_SIZE: usize = 1366;

/// TLV type for blinded path key.
const TLV_BLINDED_PATH: u64 = 3;

/// BOLT 2 `update_add_htlc` message (type 128).
///
/// Sent to add an HTLC to the remote node's commitment transaction.
/// This is used to initiate payments across a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateAddHtlc {
    /// The channel ID
    pub channel_id: ChannelId,
    /// The unique ID for this HTLC within this channel (for this sender)
    pub id: u64,
    /// The amount in milli-satoshis that the HTLC carries
    pub amount_msat: u64,
    /// The payment hash (SHA256 of the preimage)
    pub payment_hash: [u8; 32],
    /// The block height at which the HTLC expires
    pub cltv_expiry: u32,
    /// The onion-encrypted routing information.
    ///
    /// This is a fixed-size field of exactly `ONION_PACKET_SIZE` bytes containing the encrypted
    /// route information that only the next hop can decrypt.
    pub onion_routing_packet: [u8; ONION_PACKET_SIZE],
    /// Optional TLV extensions.
    pub tlvs: UpdateAddHtlcTlvs,
}

/// TLV extensions for the `update_add_htlc` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateAddHtlcTlvs {
    /// Optionally specifies the blinded path key for this HTLC
    pub blinded_path: Option<Vec<u8>>,
}

impl UpdateAddHtlc {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.id.write(&mut out);
        self.amount_msat.write(&mut out);
        self.payment_hash.write(&mut out);
        self.cltv_expiry.write(&mut out);
        self.onion_routing_packet.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(blinded_path) = &self.tlvs.blinded_path {
            tlv_stream.add(TLV_BLINDED_PATH, blinded_path.clone());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field
    /// or if the onion packet is truncated.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let id = WireFormat::read(&mut cursor)?;
        let amount_msat = WireFormat::read(&mut cursor)?;
        let payment_hash: [u8; 32] = WireFormat::read(&mut cursor)?;
        let cltv_expiry = WireFormat::read(&mut cursor)?;
        let onion_routing_packet = <[u8; ONION_PACKET_SIZE]>::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = UpdateAddHtlcTlvs::from_stream(&tlv_stream);

        Ok(Self {
            channel_id,
            id,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion_routing_packet,
            tlvs,
        })
    }
}

impl UpdateAddHtlcTlvs {
    /// Extracts `update_add_htlc` TLVs from a parsed TLV stream.
    fn from_stream(stream: &TlvStream) -> Self {
        let blinded_path = stream.get(TLV_BLINDED_PATH).map(Vec::from);
        Self { blinded_path }
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    /// Valid `UpdateAddHtlc` message for testing.
    fn sample_update_add_htlc() -> UpdateAddHtlc {
        UpdateAddHtlc {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            id: 0,
            amount_msat: 1_000_000,
            payment_hash: [0xbb; 32],
            cltv_expiry: 500_000,
            onion_routing_packet: [0xcc; ONION_PACKET_SIZE],
            tlvs: UpdateAddHtlcTlvs::default(),
        }
    }

    #[test]
    fn encode_fixed_fields_size() {
        let msg = sample_update_add_htlc();
        let encoded = msg.encode();
        // channel_id(32) + id(8) + amount_msat(8) + payment_hash(32)
        // + cltv_expiry(4) + onion_packet(ONION_PACKET_SIZE) = 1450
        assert_eq!(encoded.len(), 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE);
    }

    #[test]
    fn roundtrip() {
        let original = sample_update_add_htlc();
        let encoded = original.encode();
        let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_blinded_path() {
        let msg = UpdateAddHtlc {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            id: 42,
            amount_msat: 5_000_000,
            payment_hash: [0xdd; 32],
            cltv_expiry: 600_000,
            onion_routing_packet: [0xee; ONION_PACKET_SIZE],
            tlvs: UpdateAddHtlcTlvs {
                blinded_path: Some(vec![0x01, 0x02, 0x03, 0x04]),
            },
        };

        let encoded = msg.encode();
        let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            UpdateAddHtlc::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_htlc_id() {
        let msg = sample_update_add_htlc();
        let encoded = msg.encode();
        let data = &encoded[..34]; // channel_id(32) + 2 bytes into htlc_id
        assert_eq!(
            UpdateAddHtlc::decode(data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_truncated_amount_msat() {
        let msg = sample_update_add_htlc();
        let encoded = msg.encode();
        let data = &encoded[..42]; // channel_id(32) + htlc_id(8) - 6 (incomplete amount_msat)
        assert!(UpdateAddHtlc::decode(data).is_err());
    }

    #[test]
    fn decode_truncated_payment_hash() {
        let msg = sample_update_add_htlc();
        let encoded = msg.encode();
        let data = &encoded[..56]; // channel_id(32) + htlc_id(8) + amount_msat(8) - 8 (incomplete payment_hash)
        assert!(UpdateAddHtlc::decode(data).is_err());
    }

    #[test]
    fn decode_truncated_cltv_expiry() {
        let msg = sample_update_add_htlc();
        let encoded = msg.encode();
        let data = &encoded[..82]; // channel_id(32) + htlc_id(8) + amount_msat(8) + payment_hash(32) - 2 (incomplete cltv_expiry)
        assert!(UpdateAddHtlc::decode(data).is_err());
    }

    #[test]
    fn decode_truncated_onion_packet() {
        let msg = sample_update_add_htlc();
        let encoded = msg.encode();
        let data = &encoded[..100]; // Truncated onion packet
        assert!(UpdateAddHtlc::decode(data).is_err());
    }

    #[test]
    fn decode_truncated_tlv_value() {
        // Create a message with blinded_path TLV
        let msg = UpdateAddHtlc {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            id: 1,
            amount_msat: 1_000_000,
            payment_hash: [0xbb; 32],
            cltv_expiry: 500_000,
            onion_routing_packet: [0xcc; ONION_PACKET_SIZE],
            tlvs: UpdateAddHtlcTlvs {
                blinded_path: Some(vec![0x01, 0x02, 0x03]),
            },
        };

        let encoded = msg.encode();
        // Remove the last byte from the TLV value to truncate it
        let data = &encoded[..encoded.len() - 1];
        // Should fail because TLV value is truncated
        let decoded = UpdateAddHtlc::decode(data);
        assert!(decoded.is_err());
    }

    #[test]
    fn multiple_htlc_ids() {
        for id in [0u64, 1, 42, u64::MAX] {
            let msg = UpdateAddHtlc {
                id,
                ..sample_update_add_htlc()
            };
            let encoded = msg.encode();
            let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
            assert_eq!(decoded.id, id);
        }
    }

    #[test]
    fn various_amounts() {
        for amount_msat in [0u64, 1, 1_000_000, u64::MAX] {
            let msg = UpdateAddHtlc {
                amount_msat,
                ..sample_update_add_htlc()
            };
            let encoded = msg.encode();
            let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
            assert_eq!(decoded.amount_msat, amount_msat);
        }
    }

    #[test]
    fn various_cltv_values() {
        for cltv_expiry in [0u32, 1, 500_000, u32::MAX] {
            let msg = UpdateAddHtlc {
                cltv_expiry,
                ..sample_update_add_htlc()
            };
            let encoded = msg.encode();
            let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
            assert_eq!(decoded.cltv_expiry, cltv_expiry);
        }
    }
}
