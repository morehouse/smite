//! BOLT 7 node announcement message.

use super::BoltError;
use super::wire::WireFormat;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

/// BOLT 7 `node_announcement` message (type 257).
///
/// Allows a node to advertise extra data associated with its public key
/// (features, alias, color, network addresses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAnnouncement {
    /// Signature by `node_id` over the rest of the message body.
    pub signature: Signature,
    /// Feature bits, BOLT 9.
    pub features: Vec<u8>,
    /// Monotonic per-node timestamp; receivers reject older announcements.
    pub timestamp: u32,
    /// Compressed secp256k1 public key identifying the announcing node.
    pub node_id: PublicKey,
    /// RGB color triple for UI display.
    pub rgb_color: [u8; 3],
    /// UTF-8 node alias, zero-padded to 32 bytes.
    pub alias: [u8; 32],
    /// Network address descriptors.
    pub addresses: Vec<u8>,
    /// Trailing bytes. Per BOLT 7 the signature covers future fields appended
    /// to the message, so we need to preserve them even if we can't parse them.
    pub extra: Vec<u8>,
}

impl NodeAnnouncement {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.signature.write(&mut out);
        self.write_body(&mut out);
        out
    }

    /// Computes the BOLT 7 signature over the post-signature body and writes it
    /// into `self.signature`.
    pub fn sign(&mut self, sk: &SecretKey) {
        let secp = Secp256k1::new();
        let mut body = Vec::new();
        self.write_body(&mut body);
        let digest = secp256k1::Message::from_digest(sha256d::Hash::hash(&body).to_byte_array());
        self.signature = secp.sign_ecdsa(&digest, sk);
    }

    /// Verifies `self.signature` against the embedded `node_id` per BOLT 7.
    /// Returns `true` if the signature is valid.
    #[must_use]
    pub fn verify(&self) -> bool {
        let secp = Secp256k1::new();
        let mut body = Vec::new();
        self.write_body(&mut body);
        let digest = secp256k1::Message::from_digest(sha256d::Hash::hash(&body).to_byte_array());
        secp.verify_ecdsa(&digest, &self.signature, &self.node_id)
            .is_ok()
    }

    /// Writes fields after the signature, in spec order. These are the fields
    /// that are signed by `sign` and verified by `verify`.
    fn write_body(&self, out: &mut Vec<u8>) {
        self.features.write(out);
        self.timestamp.write(out);
        self.node_id.write(out);
        self.rgb_color.write(out);
        self.alias.write(out);
        self.addresses.write(out);
        out.extend_from_slice(&self.extra);
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any field,
    /// `InvalidSignature` if the signature bytes are not a valid compact ECDSA
    /// signature, or `InvalidPublicKey` if `node_id` is not a valid compressed
    /// point.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let signature = WireFormat::read(&mut cursor)?;
        let features = WireFormat::read(&mut cursor)?;
        let timestamp = WireFormat::read(&mut cursor)?;
        let node_id = WireFormat::read(&mut cursor)?;
        let rgb_color = WireFormat::read(&mut cursor)?;
        let alias = WireFormat::read(&mut cursor)?;
        let addresses = WireFormat::read(&mut cursor)?;
        let extra = cursor.to_vec();

        Ok(Self {
            signature,
            features,
            timestamp,
            node_id,
            rgb_color,
            alias,
            addresses,
            extra,
        })
    }
}

#[cfg(test)]
#[allow(clippy::range_plus_one)]
mod tests {
    use super::super::{COMPACT_SIGNATURE_SIZE, PUBLIC_KEY_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Valid `NodeAnnouncement` for testing.
    fn sample_node_announcement(extra: &[u8]) -> NodeAnnouncement {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");

        let mut na = NodeAnnouncement {
            signature: Signature::from_compact(&[0u8; 64]).unwrap(),
            features: vec![0x01, 0x02],
            timestamp: 1_700_000_000,
            node_id: PublicKey::from_secret_key(&secp, &sk),
            rgb_color: [0xaa, 0xbb, 0xcc],
            alias: [0x42; 32],
            addresses: vec![0x01, 0x7f, 0x00, 0x00, 0x01, 0x23, 0x45],
            extra: extra.to_vec(),
        };
        na.sign(&sk);
        na
    }

    #[test]
    fn roundtrip() {
        let original = sample_node_announcement(&[]);
        let encoded = original.encode();
        let decoded = NodeAnnouncement::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_extra_bytes() {
        let original = sample_node_announcement(&[0xde, 0xad, 0xbe, 0xef]);
        let encoded = original.encode();
        let decoded = NodeAnnouncement::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn verify_succeeds_after_sign() {
        let original = sample_node_announcement(&[]);
        assert!(original.verify());
    }

    #[test]
    fn verify_fails_on_tampered_body() {
        let mut na = sample_node_announcement(&[]);
        na.timestamp = na.timestamp.wrapping_add(1);
        assert!(!na.verify());
    }

    #[test]
    fn verify_fails_on_invalid_signature() {
        // Overwrite a valid sig with a structurally-parseable but
        // cryptographically-invalid one (r = s = 0).
        let mut na = sample_node_announcement(&[]);
        na.signature = Signature::from_compact(&[0u8; 64]).unwrap();
        assert!(!na.verify());
    }

    #[test]
    fn verify_covers_extra() {
        let mut na = sample_node_announcement(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(na.verify());
        na.extra[0] ^= 0xff;
        assert!(!na.verify());
    }

    #[test]
    fn encode_size_with_empty_variable_fields() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let na = NodeAnnouncement {
            signature: Signature::from_compact(&[0u8; 64]).unwrap(),
            features: vec![],
            timestamp: 0,
            node_id: PublicKey::from_secret_key(&secp, &sk),
            rgb_color: [0; 3],
            alias: [0; 32],
            addresses: vec![],
            extra: Vec::new(),
        };
        // 64 (sig) + 2 (flen=0) + 4 (timestamp) + 33 (node_id) + 3 (rgb) + 32 (alias) + 2 (addrlen=0) = 140
        assert_eq!(na.encode().len(), 140);
    }

    #[test]
    fn decode_truncated_signature() {
        assert_eq!(
            NodeAnnouncement::decode(&[0u8; 20]),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 20,
            })
        );
    }

    #[test]
    fn decode_truncated_features_len() {
        // Valid sig + 1 byte (need 2 for u16 len)
        let encoded = sample_node_announcement(&[]).encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 1];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_features_data() {
        // Valid sig + features_len=5 + only 2 bytes follow
        let mut data = sample_node_announcement(&[]).encode()[..COMPACT_SIGNATURE_SIZE].to_vec();
        data.extend_from_slice(&[0x00, 0x05, 0xaa, 0xbb]);
        assert_eq!(
            NodeAnnouncement::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_truncated_timestamp() {
        // sig(64) + features(2 len + 2 data = 4) + 1 byte of timestamp
        let encoded = sample_node_announcement(&[]).encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 1];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_node_id() {
        // sig(64) + features(4) + timestamp(4) + 10 bytes of node_id (need 33)
        let encoded = sample_node_announcement(&[]).encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + 10];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_rgb_color() {
        // sig(64) + features(4) + timestamp(4) + node_id(33) + 2 bytes of rgb (need 3)
        let encoded = sample_node_announcement(&[]).encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 2];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_truncated_alias() {
        // sig(64) + features(4) + timestamp(4) + node_id(33) + rgb(3) + 10 bytes of alias (need 32)
        let encoded = sample_node_announcement(&[]).encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 3 + 10];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 32,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_addresses_len() {
        // All fields up to and including alias + 1 byte (need 2 for addrlen)
        let encoded = sample_node_announcement(&[]).encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 3 + 32 + 1];
        assert_eq!(
            NodeAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_addresses_data() {
        // All fixed fields valid, addrlen declares 5 but only 2 bytes follow
        let encoded = sample_node_announcement(&[]).encode();
        let prefix_end = COMPACT_SIGNATURE_SIZE + 4 + 4 + PUBLIC_KEY_SIZE + 3 + 32;
        let mut data = encoded[..prefix_end].to_vec();
        data.extend_from_slice(&[0x00, 0x05, 0xaa, 0xbb]);
        assert_eq!(
            NodeAnnouncement::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_invalid_signature() {
        let mut encoded = sample_node_announcement(&[]).encode();
        // r and s are both above curve order.
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[..COMPACT_SIGNATURE_SIZE].copy_from_slice(&bad_sig);
        assert_eq!(
            NodeAnnouncement::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn decode_invalid_node_id() {
        let mut encoded = sample_node_announcement(&[]).encode();
        // All-zero bytes are not a valid compressed pubkey.
        let bad_pubkey = [0u8; PUBLIC_KEY_SIZE];
        let node_id_offset = COMPACT_SIGNATURE_SIZE + 4 + 4;
        encoded[node_id_offset..node_id_offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_pubkey);
        assert_eq!(
            NodeAnnouncement::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_pubkey))
        );
    }

    #[test]
    fn decode_captures_trailing_bytes() {
        let mut encoded = sample_node_announcement(&[]).encode();
        encoded.extend_from_slice(&[0x42, 0x42]);
        let decoded = NodeAnnouncement::decode(&encoded).unwrap();
        assert_eq!(decoded.extra, vec![0x42, 0x42]);
    }
}
