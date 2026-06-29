//! BOLT 2 `closing_complete` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;
use bitcoin::secp256k1::ecdsa::Signature;

/// TLV type for closer output only.
pub const TLV_CLOSER_OUTPUT_ONLY: u64 = 1;
/// TLV type for closee output only.
pub const TLV_CLOSEE_OUTPUT_ONLY: u64 = 2;
/// TLV type for closer and closee outputs.
pub const TLV_CLOSER_AND_CLOSEE_OUTPUTS: u64 = 3;

/// BOLT 2 `closing_complete` message (type 40).
///
/// When closing a channel and shutdown is complete, each peer sends
/// `closing_complete` with the transaction details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingComplete {
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

/// TLV extensions for the `closing_complete` and `closing_sig` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosingTlvs {
    /// Signature if closing tx only has local output.
    pub closer_output_only: Option<Signature>,
    /// Signature if closing tx only has remote output.
    pub closee_output_only: Option<Signature>,
    /// Signature if closing tx has local and remote output.
    pub closer_and_closee_outputs: Option<Signature>,
}

impl ClosingComplete {
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

impl ClosingTlvs {
    /// Encodes closing TLVs into a TLV stream.
    #[must_use]
    pub fn to_stream(&self) -> TlvStream {
        let mut tlv_stream = TlvStream::new();
        if let Some(closer_output_only) = &self.closer_output_only {
            tlv_stream.add(
                TLV_CLOSER_OUTPUT_ONLY,
                closer_output_only.serialize_compact().to_vec(),
            );
        }
        if let Some(closee_output_only) = &self.closee_output_only {
            tlv_stream.add(
                TLV_CLOSEE_OUTPUT_ONLY,
                closee_output_only.serialize_compact().to_vec(),
            );
        }
        if let Some(closer_and_closee_outputs) = &self.closer_and_closee_outputs {
            tlv_stream.add(
                TLV_CLOSER_AND_CLOSEE_OUTPUTS,
                closer_and_closee_outputs.serialize_compact().to_vec(),
            );
        }
        tlv_stream
    }

    /// Extracts `closing_complete` and `closing_sig` TLVs from a parsed TLV
    /// stream.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if a signature TLV has invalid length, or
    /// `InvalidSignature` if the bytes are not a valid compact ECDSA signature.
    pub fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        Ok(Self {
            closer_output_only: stream.get_as::<Signature>(TLV_CLOSER_OUTPUT_ONLY)?,
            closee_output_only: stream.get_as::<Signature>(TLV_CLOSEE_OUTPUT_ONLY)?,
            closer_and_closee_outputs: stream.get_as::<Signature>(TLV_CLOSER_AND_CLOSEE_OUTPUTS)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::ecdsa::Signature;

    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE};
    use super::*;

    /// Valid `ClosingComplete` message for testing.
    fn sample_closing_complete(tlvs: Option<ClosingTlvs>) -> ClosingComplete {
        ClosingComplete {
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
        let original = sample_closing_complete(None);
        let encoded = original.encode();
        let decoded = ClosingComplete::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            ClosingComplete::decode(&[0x11; 20]),
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
            ClosingComplete::decode(&data),
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
        data.extend_from_slice(&[0x22; 5]);
        assert_eq!(
            ClosingComplete::decode(&data),
            Err(BoltError::Truncated {
                expected: 10,
                actual: 5
            })
        );
    }

    #[test]
    fn decode_truncated_closee_scriptpubkey_length_prefix() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 10]);
        data.extend_from_slice(&[0x22; 10]);
        // one byte instead of two for length prefix
        data.extend_from_slice(&[0x00]);
        assert_eq!(
            ClosingComplete::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_closee_scriptpubkey() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 10]);
        data.extend_from_slice(&[0x22; 10]);
        // 11 as length prefix, but only give 10 bytes
        data.extend_from_slice(&[0x00, 11]);
        data.extend_from_slice(&[0x33; 10]);
        assert_eq!(
            ClosingComplete::decode(&data),
            Err(BoltError::Truncated {
                expected: 11,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_truncated_fee_satoshis() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 10]);
        data.extend_from_slice(&[0x22; 10]);
        data.extend_from_slice(&[0x00, 11]);
        data.extend_from_slice(&[0x33; 11]);
        // only three of eight bytes for fee_satoshis
        data.extend_from_slice(&[0x44; 3]);
        assert_eq!(
            ClosingComplete::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_truncated_locktime() {
        let mut data = vec![0x11; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 10]);
        data.extend_from_slice(&[0x22; 10]);
        data.extend_from_slice(&[0x00, 11]);
        data.extend_from_slice(&[0x33; 11]);
        data.extend_from_slice(&[0x44; 8]);
        // only 1 of four bytes for locktime
        data.extend_from_slice(&[0x55]);
        assert_eq!(
            ClosingComplete::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 1
            })
        );
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let sig1 =
            Signature::from_compact(&[1u8; COMPACT_SIGNATURE_SIZE]).expect("valid signature");
        let sig2 =
            Signature::from_compact(&[2u8; COMPACT_SIGNATURE_SIZE]).expect("valid signature");
        let sig3 =
            Signature::from_compact(&[3u8; COMPACT_SIGNATURE_SIZE]).expect("valid signature");
        let tlvs = ClosingTlvs {
            closer_output_only: Some(sig1),
            closee_output_only: Some(sig2),
            closer_and_closee_outputs: Some(sig3),
        };
        let original = sample_closing_complete(Some(tlvs));
        let encoded = original.encode();
        let decoded = ClosingComplete::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_empty_tlv_values() {
        let tlvs = ClosingTlvs::default();
        assert!(tlvs.closer_output_only.is_none());
        assert!(tlvs.closee_output_only.is_none());
        assert!(tlvs.closer_and_closee_outputs.is_none());
        let msg = sample_closing_complete(Some(tlvs));
        let decoded = ClosingComplete::decode(&msg.encode()).unwrap();
        assert!(decoded.tlvs.closer_output_only.is_none());
        assert!(decoded.tlvs.closee_output_only.is_none());
        assert!(decoded.tlvs.closer_and_closee_outputs.is_none());
    }

    #[test]
    fn decode_invalid_signature_tlv() {
        let sig1 =
            Signature::from_compact(&[1u8; COMPACT_SIGNATURE_SIZE]).expect("valid signature");
        let tlvs = ClosingTlvs {
            closer_output_only: Some(sig1),
            ..Default::default()
        };
        let msg = sample_closing_complete(Some(tlvs));
        let mut encoded = msg.encode();
        let sig_start = encoded.len() - COMPACT_SIGNATURE_SIZE;
        encoded[sig_start..].copy_from_slice(&[0xff; COMPACT_SIGNATURE_SIZE]);

        assert!(matches!(
            ClosingComplete::decode(&encoded),
            Err(BoltError::InvalidSignature(_))
        ));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn decode_closer_output_only_reject_trailing_bytes() {
        let mut encoded = sample_closing_complete(None).encode();
        encoded.extend_from_slice(&[TLV_CLOSER_OUTPUT_ONLY as u8, 0x41]);
        encoded.extend_from_slice(&[1u8; COMPACT_SIGNATURE_SIZE + 1]);
        assert_eq!(
            ClosingComplete::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_CLOSER_OUTPUT_ONLY,
                expected: COMPACT_SIGNATURE_SIZE,
                actual: COMPACT_SIGNATURE_SIZE + 1,
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn decode_closee_output_only_reject_trailing_bytes() {
        let mut encoded = sample_closing_complete(None).encode();
        encoded.extend_from_slice(&[TLV_CLOSEE_OUTPUT_ONLY as u8, 0x41]);
        encoded.extend_from_slice(&[1u8; COMPACT_SIGNATURE_SIZE + 1]);
        assert_eq!(
            ClosingComplete::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_CLOSEE_OUTPUT_ONLY,
                expected: COMPACT_SIGNATURE_SIZE,
                actual: COMPACT_SIGNATURE_SIZE + 1,
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn decode_closer_and_closee_outputs_reject_trailing_bytes() {
        let mut encoded = sample_closing_complete(None).encode();
        encoded.extend_from_slice(&[TLV_CLOSER_AND_CLOSEE_OUTPUTS as u8, 0x41]);
        encoded.extend_from_slice(&[1u8; COMPACT_SIGNATURE_SIZE + 1]);
        assert_eq!(
            ClosingComplete::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_CLOSER_AND_CLOSEE_OUTPUTS,
                expected: COMPACT_SIGNATURE_SIZE,
                actual: COMPACT_SIGNATURE_SIZE + 1,
            })
        );
    }
}
