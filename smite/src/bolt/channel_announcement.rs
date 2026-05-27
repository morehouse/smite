//! BOLT 7 channel announcement message.

use super::BoltError;
use super::types::{CHAIN_HASH_SIZE, ShortChannelId};
use super::wire::WireFormat;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

/// BOLT 7 `channel_announcement` message (type 256).
///
/// Announces the existence of a channel between two nodes. The message is
/// signed by all four keys involved: both node identity keys and both
/// funding-output (bitcoin) keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAnnouncement {
    /// Signature by `node_id_1` over the message body.
    pub node_signature_1: Signature,
    /// Signature by `node_id_2` over the message body.
    pub node_signature_2: Signature,
    /// Signature by `bitcoin_key_1` over the message body.
    pub bitcoin_signature_1: Signature,
    /// Signature by `bitcoin_key_2` over the message body.
    pub bitcoin_signature_2: Signature,
    /// Feature bits, BOLT 9.
    pub features: Vec<u8>,
    /// 32-byte hash identifying the chain the channel was opened on.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Reference to the funding transaction.
    pub short_channel_id: ShortChannelId,
    /// Compressed secp256k1 public key for the lex-smaller node identity.
    pub node_id_1: PublicKey,
    /// Compressed secp256k1 public key for the lex-larger node identity.
    pub node_id_2: PublicKey,
    /// Compressed secp256k1 public key for `node_id_1`'s funding output key.
    pub bitcoin_key_1: PublicKey,
    /// Compressed secp256k1 public key for `node_id_2`'s funding output key.
    pub bitcoin_key_2: PublicKey,
    /// Trailing bytes. Per BOLT 7 the signatures cover future fields appended
    /// to the message, so we need to preserve them even if we can't parse them.
    pub extra: Vec<u8>,
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
        self.write_body(&mut out);
        out
    }

    /// Computes the BOLT 7 digest over the post-signature body and writes all
    /// four signatures into the struct.
    ///
    /// Caller is responsible for the `node_id_1 < node_id_2` lex ordering
    /// required by BOLT 7; `sign` does not enforce it.
    pub fn sign(
        &mut self,
        node_sk_1: &SecretKey,
        node_sk_2: &SecretKey,
        bitcoin_sk_1: &SecretKey,
        bitcoin_sk_2: &SecretKey,
    ) {
        let secp = Secp256k1::new();
        let mut body = Vec::new();
        self.write_body(&mut body);
        let digest = secp256k1::Message::from_digest(sha256d::Hash::hash(&body).to_byte_array());
        self.node_signature_1 = secp.sign_ecdsa(&digest, node_sk_1);
        self.node_signature_2 = secp.sign_ecdsa(&digest, node_sk_2);
        self.bitcoin_signature_1 = secp.sign_ecdsa(&digest, bitcoin_sk_1);
        self.bitcoin_signature_2 = secp.sign_ecdsa(&digest, bitcoin_sk_2);
    }

    /// Verifies all four signatures against the embedded pubkeys. Returns
    /// `true` if all signatures are valid.
    #[must_use]
    pub fn verify(&self) -> bool {
        let secp = Secp256k1::new();
        let mut body = Vec::new();
        self.write_body(&mut body);
        let digest = secp256k1::Message::from_digest(sha256d::Hash::hash(&body).to_byte_array());
        secp.verify_ecdsa(&digest, &self.node_signature_1, &self.node_id_1)
            .is_ok()
            && secp
                .verify_ecdsa(&digest, &self.node_signature_2, &self.node_id_2)
                .is_ok()
            && secp
                .verify_ecdsa(&digest, &self.bitcoin_signature_1, &self.bitcoin_key_1)
                .is_ok()
            && secp
                .verify_ecdsa(&digest, &self.bitcoin_signature_2, &self.bitcoin_key_2)
                .is_ok()
    }

    /// Writes fields after the four signatures, in spec order. These are the
    /// fields that are signed by `sign` and verified by `verify`.
    fn write_body(&self, out: &mut Vec<u8>) {
        self.features.write(out);
        self.chain_hash.write(out);
        self.short_channel_id.write(out);
        self.node_id_1.write(out);
        self.node_id_2.write(out);
        self.bitcoin_key_1.write(out);
        self.bitcoin_key_2.write(out);
        out.extend_from_slice(&self.extra);
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any field,
    /// `InvalidSignature` if any signature bytes are not a valid compact ECDSA
    /// signature, or `InvalidPublicKey` if any of the four pubkeys is not a
    /// valid compressed point.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let node_signature_1 = WireFormat::read(&mut cursor)?;
        let node_signature_2 = WireFormat::read(&mut cursor)?;
        let bitcoin_signature_1 = WireFormat::read(&mut cursor)?;
        let bitcoin_signature_2 = WireFormat::read(&mut cursor)?;
        let features = WireFormat::read(&mut cursor)?;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let short_channel_id = WireFormat::read(&mut cursor)?;
        let node_id_1 = WireFormat::read(&mut cursor)?;
        let node_id_2 = WireFormat::read(&mut cursor)?;
        let bitcoin_key_1 = WireFormat::read(&mut cursor)?;
        let bitcoin_key_2 = WireFormat::read(&mut cursor)?;
        let extra = cursor.to_vec();

        Ok(Self {
            node_signature_1,
            node_signature_2,
            bitcoin_signature_1,
            bitcoin_signature_2,
            features,
            chain_hash,
            short_channel_id,
            node_id_1,
            node_id_2,
            bitcoin_key_1,
            bitcoin_key_2,
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

    const SIG_BLOCK_SIZE: usize = 4 * COMPACT_SIGNATURE_SIZE;

    /// Valid `ChannelAnnouncement` for testing.
    fn sample_channel_announcement(extra: &[u8]) -> ChannelAnnouncement {
        let secp = Secp256k1::new();
        let node_sk_1 = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let node_sk_2 = SecretKey::from_slice(&[0x22; 32]).expect("valid secret");
        let bitcoin_sk_1 = SecretKey::from_slice(&[0x33; 32]).expect("valid secret");
        let bitcoin_sk_2 = SecretKey::from_slice(&[0x44; 32]).expect("valid secret");

        let placeholder = Signature::from_compact(&[0u8; COMPACT_SIGNATURE_SIZE]).unwrap();
        let mut ca = ChannelAnnouncement {
            node_signature_1: placeholder,
            node_signature_2: placeholder,
            bitcoin_signature_1: placeholder,
            bitcoin_signature_2: placeholder,
            features: vec![0x01, 0x02],
            chain_hash: [0x6f; CHAIN_HASH_SIZE],
            short_channel_id: ShortChannelId::new(539_268, 845, 1),
            node_id_1: PublicKey::from_secret_key(&secp, &node_sk_1),
            node_id_2: PublicKey::from_secret_key(&secp, &node_sk_2),
            bitcoin_key_1: PublicKey::from_secret_key(&secp, &bitcoin_sk_1),
            bitcoin_key_2: PublicKey::from_secret_key(&secp, &bitcoin_sk_2),
            extra: extra.to_vec(),
        };
        ca.sign(&node_sk_1, &node_sk_2, &bitcoin_sk_1, &bitcoin_sk_2);
        ca
    }

    #[test]
    fn roundtrip() {
        let original = sample_channel_announcement(&[]);
        let encoded = original.encode();
        let decoded = ChannelAnnouncement::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_extra_bytes() {
        let original = sample_channel_announcement(&[0xde, 0xad, 0xbe, 0xef]);
        let encoded = original.encode();
        let decoded = ChannelAnnouncement::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn verify_succeeds_after_sign() {
        let ca = sample_channel_announcement(&[]);
        assert!(ca.verify());
    }

    #[test]
    fn verify_fails_on_tampered_body() {
        let mut ca = sample_channel_announcement(&[]);
        ca.short_channel_id =
            ShortChannelId::from_u64(ca.short_channel_id.as_u64().wrapping_add(1));
        assert!(!ca.verify());
    }

    #[test]
    fn verify_fails_on_invalid_signature() {
        // Overwrite a valid sig with a structurally-parseable but
        // cryptographically-invalid one (r = s = 0).
        let mut ca = sample_channel_announcement(&[]);
        ca.bitcoin_signature_2 = Signature::from_compact(&[0u8; COMPACT_SIGNATURE_SIZE]).unwrap();
        assert!(!ca.verify());
    }

    #[test]
    fn verify_covers_extra() {
        let mut ca = sample_channel_announcement(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(ca.verify());
        ca.extra[0] ^= 0xff;
        assert!(!ca.verify());
    }

    #[test]
    fn encode_size_with_empty_features() {
        let original = ChannelAnnouncement {
            features: vec![],
            ..sample_channel_announcement(&[])
        };
        // 4*64 (sigs) + 2 (flen=0) + 0 + 32 (chain_hash) + 8 (scid) + 4*33 (pubkeys) = 430
        assert_eq!(original.encode().len(), 430);
    }

    #[test]
    fn decode_truncated_first_signature() {
        assert_eq!(
            ChannelAnnouncement::decode(&[0u8; 20]),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 20,
            })
        );
    }

    #[test]
    fn decode_truncated_second_signature() {
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..COMPACT_SIGNATURE_SIZE + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_third_signature() {
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..2 * COMPACT_SIGNATURE_SIZE + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_fourth_signature() {
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..3 * COMPACT_SIGNATURE_SIZE + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_features_len() {
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..SIG_BLOCK_SIZE + 1];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_features_data() {
        let mut data = sample_channel_announcement(&[]).encode()[..SIG_BLOCK_SIZE].to_vec();
        data.extend_from_slice(&[0x00, 0x05, 0xaa, 0xbb]);
        assert_eq!(
            ChannelAnnouncement::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_truncated_chain_hash() {
        // Sigs(256) + features(2 len + 2 data = 4) + 10 bytes of chain_hash (need 32)
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..SIG_BLOCK_SIZE + 4 + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 32,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_scid() {
        // Sigs(256) + features(4) + chain_hash(32) + 5 bytes of scid (need 8)
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..SIG_BLOCK_SIZE + 4 + 32 + 5];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 5,
            })
        );
    }

    #[test]
    fn decode_truncated_node_id_1() {
        // Sigs(256) + features(4) + chain_hash(32) + scid(8) + 10 bytes of node_id_1 (need 33)
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..SIG_BLOCK_SIZE + 4 + 32 + 8 + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_node_id_2() {
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..SIG_BLOCK_SIZE + 4 + 32 + 8 + PUBLIC_KEY_SIZE + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_bitcoin_key_1() {
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..SIG_BLOCK_SIZE + 4 + 32 + 8 + 2 * PUBLIC_KEY_SIZE + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_truncated_bitcoin_key_2() {
        let encoded = sample_channel_announcement(&[]).encode();
        let data = &encoded[..SIG_BLOCK_SIZE + 4 + 32 + 8 + 3 * PUBLIC_KEY_SIZE + 10];
        assert_eq!(
            ChannelAnnouncement::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10,
            })
        );
    }

    #[test]
    fn decode_invalid_signature() {
        let mut encoded = sample_channel_announcement(&[]).encode();
        // r and s are both above curve order.
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[..COMPACT_SIGNATURE_SIZE].copy_from_slice(&bad_sig);
        assert_eq!(
            ChannelAnnouncement::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn decode_invalid_node_id_1() {
        let mut encoded = sample_channel_announcement(&[]).encode();
        // All-zero bytes are not a valid compressed pubkey.
        let bad_pubkey = [0u8; PUBLIC_KEY_SIZE];
        let offset = SIG_BLOCK_SIZE + 4 + 32 + 8;
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_pubkey);
        assert_eq!(
            ChannelAnnouncement::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_pubkey))
        );
    }

    #[test]
    fn decode_captures_trailing_bytes() {
        let mut encoded = sample_channel_announcement(&[]).encode();
        encoded.extend_from_slice(&[0x42, 0x42]);
        let decoded = ChannelAnnouncement::decode(&encoded).unwrap();
        assert_eq!(decoded.extra, vec![0x42, 0x42]);
    }
}
