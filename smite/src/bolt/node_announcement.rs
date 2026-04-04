//! BOLT 7 `node_announcement` message.

use super::BoltError;
use super::types::{NodeId, Signature};
use super::wire::WireFormat;

/// BOLT 7 `node_announcement` message (type 257 / 0x0101).
///
/// Broadcasts a node's existence, display information, and reachable
/// network addresses. May be re-sent to update any of these fields.
/// Only nodes with at least one public channel will be relayed by peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAnnouncement {
    /// Signature from the announcing node's key.
    pub signature: Signature,
    /// Length in bytes of `features`.
    pub features: Vec<u8>,
    /// Unix timestamp. Higher timestamp wins on conflicts.
    pub timestamp: u32,
    /// The node's compressed public key (its identity).
    pub node_id: NodeId,
    /// A 3-byte RGB display color (cosmetic only).
    pub rgb_color: [u8; 3],
    /// A human-readable node alias, zero-padded to exactly 32 bytes.
    pub alias: [u8; 32],
    /// Encoded network addresses (IP v4/v6, Tor, etc.).
    /// Each address is a 1-byte type descriptor followed by address bytes.
    pub addresses: Vec<u8>,
}

impl NodeAnnouncement {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.signature.write(&mut out);
        (self.features.len() as u16).write(&mut out);  
        out.extend_from_slice(&self.features);
        self.timestamp.write(&mut out);
        self.node_id.write(&mut out);
        out.extend_from_slice(&self.rgb_color);
        out.extend_from_slice(&self.alias);
        (self.addresses.len() as u16).write(&mut out);  
        out.extend_from_slice(&self.addresses);
        out
    }
    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let signature = Signature::read(&mut cursor)?;
        let flen = u16::read(&mut cursor)?;
        if cursor.len() < usize::from(flen) {
            return Err(BoltError::Truncated {
                expected: usize::from(flen),
                actual: cursor.len(),
            });
        }
        let features = cursor[..usize::from(flen)].to_vec();
        cursor = &cursor[usize::from(flen)..];

        let timestamp = u32::read(&mut cursor)?;
        let node_id   = NodeId::read(&mut cursor)?;

        // rgb_color: fixed 3 bytes, no length prefix
        let rgb_color = <[u8; 3]>::read(&mut cursor)?;
        // alias: fixed 32 bytes, zero-padded
        let alias     = <[u8; 32]>::read(&mut cursor)?;

        let addrlen = u16::read(&mut cursor)?;
        if cursor.len() < usize::from(addrlen) {
            return Err(BoltError::Truncated {
                expected: usize::from(addrlen),
                actual: cursor.len(),
            });
        }
        let addresses = cursor[..usize::from(addrlen)].to_vec();

        Ok(Self {
            signature,
            features,
            timestamp,
            node_id,
            rgb_color,
            alias,
            addresses,
        })
    }

    /// Returns the alias as a trimmed string, stripping trailing null bytes.
    #[must_use]
    pub fn alias_str(&self) -> &str {
        let trimmed = self.alias.split(|&b| b == 0).next().unwrap_or(&[]);
        std::str::from_utf8(trimmed).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{SIGNATURE_SIZE, NODE_ID_SIZE};

    fn dummy() -> NodeAnnouncement {
        let mut alias = [0u8; 32];
        alias[..9].copy_from_slice(b"test-node");

        NodeAnnouncement {
            signature:  Signature::new([0x01; SIGNATURE_SIZE]),
            features:   vec![],
            timestamp:  1_700_000_000,
            node_id:    NodeId::new([0x02; NODE_ID_SIZE]),
            rgb_color:  [0xff, 0x80, 0x00],
            alias,
            addresses:  vec![],
        }
    }

    #[test]
    fn encode_field_sizes() {
        let encoded = dummy().encode();
        // sig(64) + features_len(2) + features(0) + timestamp(4)
        // + node_id(33) + rgb(3) + alias(32) + addr_len(2) + addr(0) = 140
        assert_eq!(
            encoded.len(),
            SIGNATURE_SIZE + 2 + 0 + 4 + NODE_ID_SIZE + 3 + 32 + 2 + 0
        );
    }

    #[test]
    fn roundtrip() {
        let original = dummy();
        let decoded = NodeAnnouncement::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_features_and_addresses() {
        let mut ann = dummy();
        ann.features  = vec![0x80, 0x00];
        ann.addresses = vec![
            0x01,                           // type: IPv4
            127, 0, 0, 1,                   // address
            0x23, 0x28,                     // port 9000
        ];
        let decoded = NodeAnnouncement::decode(&ann.encode()).unwrap();
        assert_eq!(ann, decoded);
    }


    #[test]
    fn alias_str_trims_nulls() {
        let ann = dummy();
        assert_eq!(ann.alias_str(), "test-node");
    }

    #[test]
    fn alias_str_all_nulls() {
        let mut ann = dummy();
        ann.alias = [0u8; 32];
        assert_eq!(ann.alias_str(), "");
    }

    #[test]
    fn decode_truncated_signature() {
        assert_eq!(
            NodeAnnouncement::decode(&[0x00; 10]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 10 })
        );
    }

    #[test]
    fn decode_truncated_alias() {
    let partial = vec![0x00u8; SIGNATURE_SIZE + 2 + 4 + NODE_ID_SIZE + 3 + 10];
    assert_eq!(
        NodeAnnouncement::decode(&partial),
        Err(BoltError::Truncated { expected: 32, actual: 10 })
    );
}

    #[test]
    fn decode_empty() {
        assert_eq!(
            NodeAnnouncement::decode(&[]),
            Err(BoltError::Truncated { expected: SIGNATURE_SIZE, actual: 0 })
        );
    }

    // features length says 10 but only 3 bytes follow
    #[test]
    fn decode_truncated_features_content() {
        let mut data = vec![0x00u8; SIGNATURE_SIZE];
        data.extend_from_slice(&[0x00, 0x0a]); // flen = 10
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes
        assert_eq!(
            NodeAnnouncement::decode(&data),
            Err(BoltError::Truncated { expected: 10, actual: 3 })
        );
    }

    // trailing bytes after valid message
    #[test]
    fn decode_trailing_bytes() {
        let mut encoded = dummy().encode();
        encoded.extend_from_slice(&[0xff; 8]);
        let decoded = NodeAnnouncement::decode(&encoded).unwrap();
        assert_eq!(decoded, dummy());
    }
}