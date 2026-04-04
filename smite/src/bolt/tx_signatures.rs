//! BOLT 2 `tx_signatures` message.

use super::BoltError;
use super::types::{ChannelId, Txid};
use super::wire::WireFormat;

/// BOLT 2 `tx_signatures` message (type 71).
///
/// Sent during interactive transaction construction to provide the sender's
/// witnesses for the negotiated transaction.  Both peers exchange
/// `tx_signatures` before broadcasting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSignatures {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The transaction ID (little-endian, Bitcoin serialization).
    pub txid: Txid,
    /// Witnesses for the transaction inputs.
    ///
    /// Outer `Vec`: one entry per input.
    /// Middle `Vec`: the witness stack for that input.
    /// Inner `Vec<u8>`: a single witness stack item.
    pub witnesses: Vec<Vec<Vec<u8>>>,
}

impl TxSignatures {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.txid.write(&mut out);
        u16::try_from(self.witnesses.len()).unwrap_or(u16::MAX).write(&mut out);
        for witness in &self.witnesses {
            u16::try_from(witness.len()).unwrap_or(u16::MAX).write(&mut out);
            for item in witness {
                item.write(&mut out);
            }
        }
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or
    /// declared variable-length data.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id: ChannelId = WireFormat::read(&mut cursor)?;
        let txid: Txid = WireFormat::read(&mut cursor)?;
        let num_witnesses: u16 = WireFormat::read(&mut cursor)?;
        let mut witnesses = Vec::with_capacity(num_witnesses as usize);
        for _ in 0..num_witnesses {
            let num_items: u16 = WireFormat::read(&mut cursor)?;
            let mut stack = Vec::with_capacity(num_items as usize);
            for _ in 0..num_items {
                let item: Vec<u8> = WireFormat::read(&mut cursor)?;
                stack.push(item);
            }
            witnesses.push(stack);
        }
        Ok(Self {
            channel_id,
            txid,
            witnesses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, TXID_SIZE};
    use super::*;
    use secp256k1::hashes::Hash;

    fn sample_txid() -> Txid {
        Txid::from_byte_array([0xcc; TXID_SIZE])
    }

    #[test]
    fn roundtrip() {
        let original = TxSignatures {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            txid: sample_txid(),
            witnesses: vec![
                vec![vec![0x01, 0x02], vec![0x03]],
                vec![vec![0xde, 0xad, 0xbe, 0xef]],
            ],
        };
        let encoded = original.encode();
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_empty_witnesses() {
        let original = TxSignatures {
            channel_id: ChannelId::new([0x00; CHANNEL_ID_SIZE]),
            txid: sample_txid(),
            witnesses: vec![],
        };
        let encoded = original.encode();
        // channel_id(32) + txid(32) + num_witnesses(2) = 66
        assert_eq!(encoded.len(), 66);
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_empty_stack_items() {
        // A witness with zero stack items is valid wire-wise.
        let original = TxSignatures {
            channel_id: ChannelId::new([0x11; CHANNEL_ID_SIZE]),
            txid: sample_txid(),
            witnesses: vec![vec![], vec![]],
        };
        let encoded = original.encode();
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let original = TxSignatures {
            channel_id: ChannelId::new([0xff; CHANNEL_ID_SIZE]),
            txid: sample_txid(),
            witnesses: vec![],
        };
        let mut encoded = original.encode();
        encoded.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_size() {
        // channel_id(32) + txid(32) + num_witnesses(2) + num_items(2) + item_len(2) + item(3) = 73
        let msg = TxSignatures {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            txid: sample_txid(),
            witnesses: vec![vec![vec![0xaa, 0xbb, 0xcc]]],
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 32 + 32 + 2 + 2 + 2 + 3);
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxSignatures::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxSignatures::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_txid() {
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 20]); // only 20 bytes of txid
        assert_eq!(
            TxSignatures::decode(&data),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_witnesses_count() {
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0xcc; TXID_SIZE]);
        data.push(0x00); // only 1 byte of witnesses count
        assert_eq!(
            TxSignatures::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_stack_items_count() {
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0xcc; TXID_SIZE]);
        data.extend_from_slice(&[0x00, 0x01]); // num_witnesses = 1
        data.push(0x00); // only 1 byte of stack items count
        assert_eq!(
            TxSignatures::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_item_data() {
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0xcc; TXID_SIZE]);
        data.extend_from_slice(&[0x00, 0x01]); // num_witnesses = 1
        data.extend_from_slice(&[0x00, 0x01]); // num_stack_items = 1
        data.extend_from_slice(&[0x00, 0x05]); // item_len = 5
        data.extend_from_slice(&[0x11, 0x22]); // only 2 bytes of item data
        assert_eq!(
            TxSignatures::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2
            })
        );
    }
}
