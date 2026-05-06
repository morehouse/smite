//! BOLT 2 `tx_add_input` message.

use bitcoin::secp256k1::hashes::Hash;

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, Txid};
use super::wire::WireFormat;

/// BOLT 2 `tx_add_input` message (type 66).
///
/// Sent during interactive transaction construction to propose adding an
/// input to the shared transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAddInput {
    /// The channel this message pertains to.
    pub channel_id: ChannelId,
    /// Serial ID for this input. Must be even if sent by the initiator,
    /// odd if sent by the non-initiator (BOLT 2 parity rule).
    pub serial_id: u64,
    /// Previous transaction being spent (consensus-encoded bytes).
    pub prevtx: Vec<u8>,
    /// The output index within `prevtx` being spent.
    pub prevtx_vout: u32,
    /// The sequence number for this input.
    pub sequence: u32,
    /// Optional TLV extensions.
    pub tlvs: TxAddInputTlvs,
}

/// TLV type for shared input txid.
const TLV_SHARED_INPUT_TXID: u64 = 0;

/// TLV extensions for the `tx_add_input` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxAddInputTlvs {
    /// Optionally specifies a shared input transaction ID.
    pub shared_input_txid: Option<Txid>,
}

impl TxAddInputTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if `shared_input_txid` has invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let shared_input_txid = stream
            .get(TLV_SHARED_INPUT_TXID)
            .map(|v| {
                let mut cursor = v;
                Txid::read(&mut cursor)
            })
            .transpose()?;
        Ok(Self { shared_input_txid })
    }
}

impl TxAddInput {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.serial_id.write(&mut out);
        self.prevtx.write(&mut out);
        self.prevtx_vout.write(&mut out);
        self.sequence.write(&mut out);
        let mut tlv_stream = TlvStream::new();
        if let Some(txid) = &self.tlvs.shared_input_txid {
            tlv_stream.add(TLV_SHARED_INPUT_TXID, txid.to_byte_array().to_vec());
        }
        out.extend(tlv_stream.encode());
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any field.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = WireFormat::read(&mut cursor)?;
        let serial_id = WireFormat::read(&mut cursor)?;
        let prevtx: Vec<u8> = WireFormat::read(&mut cursor)?;
        let prevtx_vout = WireFormat::read(&mut cursor)?;
        let sequence = WireFormat::read(&mut cursor)?;
        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_SHARED_INPUT_TXID])?;
        let tlvs = TxAddInputTlvs::from_stream(&tlv_stream)?;
        Ok(Self {
            channel_id,
            serial_id,
            prevtx,
            prevtx_vout,
            sequence,
            tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, TXID_SIZE};
    use super::*;

    fn sample_msg() -> TxAddInput {
        TxAddInput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
            prevtx: vec![0xde, 0xad, 0xbe, 0xef],
            prevtx_vout: 1,
            sequence: 0xffff_fffd,
            tlvs: TxAddInputTlvs::default(),
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = TxAddInput::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_shared_input_txid() {
        let mut original = sample_msg();
        original.tlvs.shared_input_txid = Some(Txid::from_byte_array([0xcc; 32]));
        let encoded = original.encode();
        let decoded = TxAddInput::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let original = sample_msg();
        let mut encoded = original.encode();
        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);
        let decoded = TxAddInput::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxAddInput::decode(&[0x00; 5]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 5,
            })
        );
    }

    #[test]
    fn decode_truncated_serial_id() {
        assert_eq!(
            TxAddInput::decode(&[0x00; CHANNEL_ID_SIZE + 4]),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4,
            })
        );
    }

    #[test]
    fn decode_truncated_prevtx_len() {
        // channel_id(32) + serial_id(8) + 1 byte of the 2-byte prevtx length
        assert_eq!(
            TxAddInput::decode(&[0x00; CHANNEL_ID_SIZE + 8 + 1]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_prevtx_data() {
        // channel_id(32) + serial_id(8) + prevtx_len=10(2) + 3 bytes of prevtx data
        let mut payload = vec![0x00u8; CHANNEL_ID_SIZE + 8];
        payload.extend_from_slice(&[0x00, 0x0a]); // declare 10 bytes
        payload.extend_from_slice(&[0x00; 3]); // only 3 bytes provided
        assert_eq!(
            TxAddInput::decode(&payload),
            Err(BoltError::Truncated {
                expected: 10,
                actual: 3,
            })
        );
    }

    #[test]
    fn decode_truncated_prevtx_vout() {
        // Full channel_id + serial_id + prevtx, then 2 bytes into prevtx_vout (need 4)
        let encoded = sample_msg().encode();
        let prevtx_field_size = 2 + sample_msg().prevtx.len(); // u16 len + data
        let cutoff = CHANNEL_ID_SIZE + 8 + prevtx_field_size + 2;
        assert_eq!(
            TxAddInput::decode(&encoded[..cutoff]),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_truncated_sequence() {
        // Full channel_id + serial_id + prevtx + prevtx_vout, then 2 bytes into sequence (need 4)
        let encoded = sample_msg().encode();
        let prevtx_field_size = 2 + sample_msg().prevtx.len();
        let cutoff = CHANNEL_ID_SIZE + 8 + prevtx_field_size + 4 + 2;
        assert_eq!(
            TxAddInput::decode(&encoded[..cutoff]),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxAddInput::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0,
            })
        );
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let original = sample_msg();
        let mut encoded = original.encode();
        // Append unknown even TLV: type 2, length 1, value [0xff]
        encoded.extend_from_slice(&[0x02, 0x01, 0xff]);
        assert_eq!(
            TxAddInput::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(2))
        );
    }

    #[test]
    fn decode_wrong_length_shared_input_txid() {
        let original = sample_msg();
        let mut encoded = original.encode();
        // Append TLV type 0 with only 16 bytes instead of 32
        encoded.push(0x00); // type 0
        encoded.push(0x10); // length 16
        encoded.extend_from_slice(&[0xaa; 16]);
        assert_eq!(
            TxAddInput::decode(&encoded),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 16,
            })
        );
    }
}
