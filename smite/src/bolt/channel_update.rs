//! BOLT 7 `channel_update` message.

use bitcoin::hashes::{Hash, sha256d};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use super::BoltError;
use super::types::{CHAIN_HASH_SIZE, ShortChannelId};
use super::wire::WireFormat;

/// BOLT 7 `channel_update` message (type 258).
///
/// Each side of a channel independently announces its forwarding parameters
/// using `channel_update`. The message is signed by the originating node.
///
/// Wire layout (per [BOLT 7]):
///
/// ```text
/// [signature:64]
/// [chain_hash:32]
/// [short_channel_id:8]
/// [u32:timestamp]
/// [byte:message_flags]
/// [byte:channel_flags]
/// [u16:cltv_expiry_delta]
/// [u64:htlc_minimum_msat]
/// [u32:fee_base_msat]
/// [u32:fee_proportional_millionths]
/// [u64:htlc_maximum_msat]
/// ```
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelUpdate {
    /// Signature of `node_id` over the double-SHA256 of the message body
    /// following this signature field (see [`Self::write_body`]).
    pub signature: Signature,
    /// 32-byte hash that uniquely identifies the chain the channel was opened on.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Reference to the funding transaction.
    pub short_channel_id: ShortChannelId,
    /// Update timestamp; intended to be a UNIX timestamp.
    pub timestamp: u32,
    /// `message_flags` bitfield (`must_be_one`, `dont_forward`).
    pub message_flags: u8,
    /// `channel_flags` bitfield (`direction`, `disable`).
    pub channel_flags: u8,
    /// Number of blocks to subtract from an incoming HTLC's `cltv_expiry`.
    pub cltv_expiry_delta: u16,
    /// Minimum HTLC value (millisatoshi) the channel peer will accept.
    pub htlc_minimum_msat: u64,
    /// Base fee charged per HTLC (millisatoshi).
    pub fee_base_msat: u32,
    /// Proportional fee per transferred satoshi (millionths).
    pub fee_proportional_millionths: u32,
    /// Maximum HTLC value (millisatoshi) the channel peer will route.
    pub htlc_maximum_msat: u64,
    /// Any trailing bytes that followed the known fields on the wire.
    ///
    /// Per BOLT 7, the signature covers "the entire message following the
    /// signature field (including unknown fields following
    /// `fee_proportional_millionths`)", so we preserve them verbatim to keep
    /// the signature verifiable.
    pub extra: Vec<u8>,
}

impl ChannelUpdate {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.signature.write(&mut out);
        self.write_body(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// Any bytes that follow the last known field are captured into
    /// [`Self::extra`] so that re-encoding preserves them and the signature
    /// remains verifiable.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field, or
    /// `InvalidSignature` if the signature bytes do not form a valid compact
    /// ECDSA signature.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let signature = WireFormat::read(&mut cursor)?;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let short_channel_id = WireFormat::read(&mut cursor)?;
        let timestamp = WireFormat::read(&mut cursor)?;
        let message_flags = WireFormat::read(&mut cursor)?;
        let channel_flags = WireFormat::read(&mut cursor)?;
        let cltv_expiry_delta = WireFormat::read(&mut cursor)?;
        let htlc_minimum_msat = WireFormat::read(&mut cursor)?;
        let fee_base_msat = WireFormat::read(&mut cursor)?;
        let fee_proportional_millionths = WireFormat::read(&mut cursor)?;
        let htlc_maximum_msat = WireFormat::read(&mut cursor)?;
        let extra = cursor.to_vec();

        Ok(Self {
            signature,
            chain_hash,
            short_channel_id,
            timestamp,
            message_flags,
            channel_flags,
            cltv_expiry_delta,
            htlc_minimum_msat,
            fee_base_msat,
            fee_proportional_millionths,
            htlc_maximum_msat,
            extra,
        })
    }

    /// Signs the message body with `sk`, storing the resulting signature in
    /// `self.signature`.
    ///
    /// The signature covers the double-SHA256 of [`Self::write_body`], i.e.
    /// everything after the leading `signature` field (including
    /// [`Self::extra`]), per BOLT 7.
    pub fn sign(&mut self, sk: &SecretKey) {
        let secp = Secp256k1::new();
        let mut body = Vec::new();
        self.write_body(&mut body);
        let digest = secp256k1::Message::from_digest(sha256d::Hash::hash(&body).to_byte_array());
        self.signature = secp.sign_ecdsa(&digest, sk);
    }

    /// Verifies `self.signature` against the expected node `PublicKey`.
    ///
    /// Unlike `node_announcement`, `channel_update` does not embed the signing
    /// node's public key on the wire: the receiver looks it up from the
    /// previously-seen `channel_announcement` for `short_channel_id`. Callers
    /// must therefore pass the expected key explicitly.
    #[must_use]
    pub fn verify(&self, pk: &PublicKey) -> bool {
        let secp = Secp256k1::new();
        let mut body = Vec::new();
        self.write_body(&mut body);
        let digest = secp256k1::Message::from_digest(sha256d::Hash::hash(&body).to_byte_array());
        secp.verify_ecdsa(&digest, &self.signature, pk).is_ok()
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        self.chain_hash.write(out);
        self.short_channel_id.write(out);
        self.timestamp.write(out);
        self.message_flags.write(out);
        self.channel_flags.write(out);
        self.cltv_expiry_delta.write(out);
        self.htlc_minimum_msat.write(out);
        self.fee_base_msat.write(out);
        self.fee_proportional_millionths.write(out);
        self.htlc_maximum_msat.write(out);
        out.extend_from_slice(&self.extra);
    }
}

#[cfg(test)]
mod tests {
    use super::super::COMPACT_SIGNATURE_SIZE;
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Bitcoin mainnet genesis block hash.
    const BITCOIN_MAINNET: [u8; CHAIN_HASH_SIZE] = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// Secret key used to sign sample messages in tests.
    const SAMPLE_SK_BYTES: [u8; 32] = [0x42; 32];

    /// Returns `(signed_message, signing_pubkey)` for the given trailing bytes.
    fn sample(extra: &[u8]) -> (ChannelUpdate, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&SAMPLE_SK_BYTES).expect("valid secret");
        let pk = sk.public_key(&secp);

        let mut cu = ChannelUpdate {
            // Placeholder; overwritten by `sign` below.
            signature: Signature::from_compact(&[0; COMPACT_SIGNATURE_SIZE])
                .expect("zero signature parses"),
            chain_hash: BITCOIN_MAINNET,
            short_channel_id: ShortChannelId::new(539_268, 845, 1),
            timestamp: 1_715_000_000,
            message_flags: 1, // must_be_one
            channel_flags: 0,
            cltv_expiry_delta: 144,
            htlc_minimum_msat: 1_000,
            fee_base_msat: 1_000,
            fee_proportional_millionths: 100,
            htlc_maximum_msat: 99_000_000,
            extra: extra.to_vec(),
        };
        cu.sign(&sk);
        (cu, pk)
    }

    #[test]
    fn roundtrip() {
        let (original, _) = sample(&[]);
        let encoded = original.encode();
        let decoded = ChannelUpdate::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_extra_bytes() {
        let (original, _) = sample(&[0xde, 0xad, 0xbe, 0xef]);
        let encoded = original.encode();
        let decoded = ChannelUpdate::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.extra, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_captures_trailing_bytes() {
        let (msg, _) = sample(&[]);
        let mut encoded = msg.encode();
        encoded.extend_from_slice(&[0x01, 0x02, 0x03]);
        let decoded = ChannelUpdate::decode(&encoded).unwrap();
        assert_eq!(decoded.extra, vec![0x01, 0x02, 0x03]);
        // Re-encoding preserves the trailing bytes verbatim.
        assert_eq!(decoded.encode(), encoded);
    }

    #[test]
    fn verify_succeeds_after_sign() {
        let (msg, pk) = sample(&[]);
        assert!(msg.verify(&pk));
    }

    #[test]
    fn verify_fails_on_tampered_body() {
        let (mut msg, pk) = sample(&[]);
        msg.timestamp = msg.timestamp.wrapping_add(1);
        assert!(!msg.verify(&pk));
    }

    #[test]
    fn verify_fails_on_wrong_pubkey() {
        let secp = Secp256k1::new();
        let other = SecretKey::from_slice(&[0x43; 32])
            .unwrap()
            .public_key(&secp);
        let (msg, _) = sample(&[]);
        assert!(!msg.verify(&other));
    }

    #[test]
    fn verify_covers_extra() {
        // The signature must commit to trailing unknown bytes, per BOLT 7.
        let (mut msg, pk) = sample(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(msg.verify(&pk));
        msg.extra[0] ^= 0x01;
        assert!(!msg.verify(&pk));
    }

    #[test]
    fn verify_roundtrips_through_encode_decode() {
        let (msg, pk) = sample(&[]);
        let decoded = ChannelUpdate::decode(&msg.encode()).unwrap();
        assert!(decoded.verify(&pk));
    }

    #[test]
    fn decode_truncated_signature() {
        assert_eq!(
            ChannelUpdate::decode(&[0u8; 30]),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 30
            })
        );
    }

    #[test]
    fn decode_truncated_body() {
        let (msg, _) = sample(&[]);
        let encoded = msg.encode();
        // Drop the last byte of htlc_maximum_msat.
        let truncated = &encoded[..encoded.len() - 1];
        assert!(matches!(
            ChannelUpdate::decode(truncated),
            Err(BoltError::Truncated { .. })
        ));
    }

    #[test]
    fn decode_invalid_signature() {
        let (msg, _) = sample(&[]);
        let mut encoded = msg.encode();
        encoded[..COMPACT_SIGNATURE_SIZE].copy_from_slice(&[0xff; COMPACT_SIGNATURE_SIZE]);
        assert!(matches!(
            ChannelUpdate::decode(&encoded),
            Err(BoltError::InvalidSignature(_))
        ));
    }

    #[test]
    fn decode_preserves_unknown_flag_bits() {
        // The codec is intentionally lenient: it preserves all flag bits and
        // leaves policy decisions (e.g. `must_be_one` enforcement) to the caller.
        let (mut msg, _) = sample(&[]);
        msg.message_flags = 0xff;
        msg.channel_flags = 0xff;
        let decoded = ChannelUpdate::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.message_flags, 0xff);
        assert_eq!(decoded.channel_flags, 0xff);
    }
}
