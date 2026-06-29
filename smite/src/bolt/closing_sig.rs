//! BOLT 2 `closing_sig` message.

use super::BoltError;
use super::closing_complete::{ClosingTlvs, TLV_CLOSEE_OUTPUT_ONLY};
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `closing_sig` message (type 41).
///
/// In response to `closing_complete`, the closee signs the proposed closing
/// transaction and sends back `closing_sig` with the signature in the same TLV
/// field that was used in `closing_complete`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingSig {
    /// The ID of the channel to be closed.
    pub channel_id: ChannelId,
    /// Output script for the initiator of the co-op close.
    pub closer_scriptpubkey: Vec<u8>,
    /// Output script for the non-initiator of the co-op close.
    pub closee_scriptpubkey: Vec<u8>,
    /// Suggested absolute fee for the closing tx.
    pub fee_satoshis: u64,
    /// Suggested locktime for the closing tx.
    pub locktime: u32,
    /// Optional TLV extensions.
    pub tlvs: ClosingTlvs,
}

impl ClosingSig {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.closer_scriptpubkey.write(&mut out);
        self.closee_scriptpubkey.write(&mut out);
        self.fee_satoshis.write(&mut out);
        self.locktime.write(&mut out);

        out.extend(self.tlvs.to_stream().encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or
    /// signature TLV, or `InvalidSignature` if a signature TLV is not a valid
    /// compact ECDSA signature.
    #[allow(clippy::similar_names)]
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let closer_scriptpubkey = WireFormat::read(&mut cursor)?;
        let closee_scriptpubkey = WireFormat::read(&mut cursor)?;
        let fee_satoshis = WireFormat::read(&mut cursor)?;
        let locktime = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_CLOSEE_OUTPUT_ONLY])?;
        let tlvs = ClosingTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            closer_scriptpubkey,
            closee_scriptpubkey,
            fee_satoshis,
            locktime,
            tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::ecdsa::Signature;

    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE};
    use super::*;

    /// Valid `ClosingSig` message for testing.
    fn sample_closing_sig(tlvs: Option<ClosingTlvs>) -> ClosingSig {
        ClosingSig {
            channel_id: ChannelId::new([0xaa; 32]),
            closer_scriptpubkey: vec![0x00; 22],
            closee_scriptpubkey: vec![0x11; 22],
            fee_satoshis: 1000,
            locktime: 0,
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample_closing_sig(None);
        let encoded = original.encode();
        let decoded = ClosingSig::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            ClosingSig::decode(&[0x11; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_closer_scriptpubkey_length_prefix() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        // one byte intead of two for length prefix
        data.extend_from_slice(&[0x00]);
        assert_eq!(
            ClosingSig::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_closer_scriptpubkey() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        // 10 as length prefix, but only give 5 bytes
        data.extend_from_slice(&[0x00, 0x0a]);
        data.extend_from_slice(&[0x22; 0x05]);
        assert_eq!(
            ClosingSig::decode(&data),
            Err(BoltError::Truncated {
                expected: 10,
                actual: 5
            })
        );
    }

    #[test]
    fn decode_truncated_closee_scriptpubkey_length_prefix() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x0a]);
        data.extend_from_slice(&[0x22; 0x0a]);
        // one byte instead of two for length prefix
        data.extend_from_slice(&[0x00]);
        assert_eq!(
            ClosingSig::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_closee_scriptpubkey() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x0a]);
        data.extend_from_slice(&[0x22; 0x0a]);
        // 11 as length prefix, but only give 10 bytes
        data.extend_from_slice(&[0x00, 0x0b]);
        data.extend_from_slice(&[0x33; 0x0a]);
        assert_eq!(
            ClosingSig::decode(&data),
            Err(BoltError::Truncated {
                expected: 11,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_truncated_fee_satoshis() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x0a]);
        data.extend_from_slice(&[0x22; 0x0a]);
        data.extend_from_slice(&[0x00, 0x0b]);
        data.extend_from_slice(&[0x33; 0x0b]);
        // only three of eight bytes for fee_satoshis
        data.extend_from_slice(&[0x44; 0x03]);
        assert_eq!(
            ClosingSig::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_truncated_locktime() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x0a]);
        data.extend_from_slice(&[0x22; 0x0a]);
        data.extend_from_slice(&[0x00, 0x0b]);
        data.extend_from_slice(&[0x33; 0x0b]);
        data.extend_from_slice(&[0x44; 0x08]);
        // only 1 of four bytes for locktime
        data.extend_from_slice(&[0x55]);
        assert_eq!(
            ClosingSig::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 1
            })
        );
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let sig = Signature::from_compact(&[1u8; 64]).expect("valid signature");
        let tlvs = ClosingTlvs {
            closer_output_only: Some(sig),
            closee_output_only: Some(sig),
            closer_and_closee_outputs: Some(sig),
        };
        let original = sample_closing_sig(Some(tlvs));
        let encoded = original.encode();
        let decoded = ClosingSig::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_empty_tlv_values() {
        let msg = sample_closing_sig(None);
        let decoded = ClosingSig::decode(&msg.encode()).unwrap();
        assert!(decoded.tlvs.closer_output_only.is_none());
        assert!(decoded.tlvs.closee_output_only.is_none());
        assert!(decoded.tlvs.closer_and_closee_outputs.is_none());
    }

    #[test]
    fn default_tlvs_are_none() {
        let tlvs = ClosingTlvs::default();
        assert!(tlvs.closer_output_only.is_none());
        assert!(tlvs.closee_output_only.is_none());
        assert!(tlvs.closer_and_closee_outputs.is_none());
    }

    #[test]
    fn decode_invalid_signature_tlv() {
        let sig = Signature::from_compact(&[1u8; 64]).expect("valid signature");
        let tlvs = ClosingTlvs {
            closer_output_only: Some(sig),
            ..Default::default()
        };
        let cs = sample_closing_sig(Some(tlvs));
        let mut encoded = cs.encode();

        let sig_start = encoded.len() - COMPACT_SIGNATURE_SIZE;
        encoded[sig_start..].copy_from_slice(&[0xff; COMPACT_SIGNATURE_SIZE]);

        assert!(matches!(
            ClosingSig::decode(&encoded),
            Err(BoltError::InvalidSignature(_))
        ));
    }
}
