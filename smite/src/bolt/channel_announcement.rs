//! BOLT 7 `channel_announcement` message.

use super::BoltError;
use super::types::{ChainHash, NodeId, ShortChannelId, Signature};
use super::wire::WireFormat;

/// BOLT 7 `channel_announcement` message (type 256 / 0x0100).
///
/// Announces a new channel to the network. Ties each on-chain Bitcoin key to
/// the associated Lightning node key. A channel is not usable for routing
/// until at least one side has also sent a `channel_update`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAnnouncement {
    /// Signature from node_1 over the announcement.
    pub node_signature_1: Signature,
    /// Signature from node_2 over the announcement.
    pub node_signature_2: Signature,
    /// Signature from bitcoin_key_1 over the announcement.
    pub bitcoin_signature_1: Signature,
    /// Signature from bitcoin_key_2 over the announcement.
    pub bitcoin_signature_2: Signature,
    /// Feature bits supported by this channel.
    pub features: Vec<u8>,
    /// Chain this channel lives on.
    pub chain_hash: ChainHash,
    /// Compact channel identifier: encodes block, tx index, and output index.
    pub short_channel_id: ShortChannelId,
    /// Compressed public key of node 1 (numerically lesser).
    pub node_id_1: NodeId,
    /// Compressed public key of node 2 (numerically greater).
    pub node_id_2: NodeId,
    /// On-chain funding public key belonging to node 1.
    pub bitcoin_key_1: NodeId,
    /// On-chain funding public key belonging to node 2.
    pub bitcoin_key_2: NodeId,
}

impl ChannelAnnouncement {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.node_signature_1.write(&mut out);
        self.node_signature_2.write(&mut out);
        self.bitcoin_signature_1.write(&mut out);
        self.bitcoin_signature_2.write(&mut out);       
        (self.features.len() as u16).write(&mut out);      
        out.extend_from_slice(&self.features);
        self.chain_hash.write(&mut out);
        self.short_channel_id.write(&mut out);
        self.node_id_1.write(&mut out);
        self.node_id_2.write(&mut out);
        self.bitcoin_key_1.write(&mut out);
        self.bitcoin_key_2.write(&mut out);
        out
}

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let node_signature_1    = Signature::read(&mut cursor)?;
        let node_signature_2    = Signature::read(&mut cursor)?;
        let bitcoin_signature_1 = Signature::read(&mut cursor)?;
        let bitcoin_signature_2 = Signature::read(&mut cursor)?;
        let len                 = u16::read(&mut cursor)?;
        if cursor.len() < usize::from(len) {
            return Err(BoltError::Truncated {
                expected: usize::from(len),
                actual: cursor.len(),
            });
        }
        let features = cursor[..usize::from(len)].to_vec();
        cursor = &cursor[usize::from(len)..];

        let chain_hash          = ChainHash::read(&mut cursor)?;
        let short_channel_id    = ShortChannelId::read(&mut cursor)?;
        let node_id_1           = NodeId::read(&mut cursor)?;
        let node_id_2           = NodeId::read(&mut cursor)?;
        let bitcoin_key_1       = NodeId::read(&mut cursor)?;
        let bitcoin_key_2       = NodeId::read(&mut cursor)?;

        Ok(Self {
            node_signature_1, node_signature_2,
            bitcoin_signature_1, bitcoin_signature_2,
            features, chain_hash, short_channel_id,
            node_id_1, node_id_2,
            bitcoin_key_1, bitcoin_key_2,
        })
    }

    /// Returns the bytes covered by all four signatures.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // message type prefix
        (self.features.len() as u16).write(&mut out);
        out.extend_from_slice(&self.features);
        self.chain_hash.write(&mut out);
        self.short_channel_id.write(&mut out);
        self.node_id_1.write(&mut out);
        self.node_id_2.write(&mut out);
        self.bitcoin_key_1.write(&mut out);
        self.bitcoin_key_2.write(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{SIGNATURE_SIZE, NODE_ID_SIZE, CHAIN_HASH_SIZE};

    fn dummy() -> ChannelAnnouncement {
        ChannelAnnouncement {
            node_signature_1:    Signature::new([0x01; SIGNATURE_SIZE]),
            node_signature_2:    Signature::new([0x02; SIGNATURE_SIZE]),
            bitcoin_signature_1: Signature::new([0x03; SIGNATURE_SIZE]),
            bitcoin_signature_2: Signature::new([0x04; SIGNATURE_SIZE]),
            features:            vec![],
            chain_hash:          ChainHash::new([0xaa; CHAIN_HASH_SIZE]),
            short_channel_id:    ShortChannelId::new(0x0001_0002_0003),
            node_id_1:           NodeId::new([0x02; NODE_ID_SIZE]),
            node_id_2:           NodeId::new([0x03; NODE_ID_SIZE]),
            bitcoin_key_1:       NodeId::new([0x04; NODE_ID_SIZE]),
            bitcoin_key_2:       NodeId::new([0x05; NODE_ID_SIZE]),
        }
    }

    #[test]
    fn encode_field_sizes() {
        let ann = dummy();
        let encoded = ann.encode();
        let expected = 4 * SIGNATURE_SIZE + 2 + 0
            + CHAIN_HASH_SIZE + 8
            + 4 * NODE_ID_SIZE;
        assert_eq!(encoded.len(), expected);
    }

    #[test]
    fn roundtrip() {
        let original = dummy();
        let encoded = original.encode();
        let decoded = ChannelAnnouncement::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_features() {
        let mut ann = dummy();
        ann.features = vec![0x0a, 0x0b, 0x0c];
        let encoded = ann.encode();
        let decoded = ChannelAnnouncement::decode(&encoded).unwrap();
        assert_eq!(ann, decoded);
    }

    #[test]
    fn decode_truncated_first_signature() {
        // Only 10 bytes way short of the first 64-byte signature
        assert_eq!(
            ChannelAnnouncement::decode(&[0x00; 10]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 10 })
        );
    }

    #[test]
    fn decode_truncated_mid_payload() {
        // 3 full signatures then truncated
        let partial = vec![0x00u8; 3 * SIGNATURE_SIZE + 10];
        assert!(ChannelAnnouncement::decode(&partial).is_err());
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            ChannelAnnouncement::decode(&[]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 0 })
        );
    }
}