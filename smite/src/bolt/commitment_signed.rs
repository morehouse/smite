//! BOLT 2 `commitment_signed` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, Txid};
use super::wire::WireFormat;
use secp256k1::ecdsa::Signature;
use secp256k1::hashes::Hash;

/// BOLT 2 `commitment_signed` message (type 132).
///
/// Sent to sign the counterparty's commitment transaction. Contains the signature
/// for the commitment transaction and signatures for any pending HTLC outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentSigned {
    /// The channel ID derived from the funding outpoint
    pub channel_id: ChannelId,
    /// The sender's signature for the commitment transaction
    pub signature: Signature,
    /// The signatures for the HTLC outputs (one signature per HTLC in-flight)
    pub htlc_signatures: Vec<Signature>,
    /// Optional TLV extensions
    pub tlvs: CommitmentSignedTlvs,
}

/// TLV extensions for the `commitment_signed` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentSignedTlvs {
    /// The funding transaction spent by this commitment transaction (TLV type 1).
    /// Present when splicing is used.
    pub funding_txid: Option<Txid>,
}

impl CommitmentSignedTlvs {
    /// Encodes the TLVs to wire format.
    fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();

        if let Some(txid) = self.funding_txid {
            stream.add(1, txid.to_byte_array().to_vec());
        }

        stream.encode()
    }

    /// Decodes the TLVs from a byte slice.
    fn decode(data: &[u8]) -> Result<Self, BoltError> {
        let tlv_stream = TlvStream::decode(data)?;

        let funding_txid = if let Some(bytes) = tlv_stream.get(1) {
            if bytes.len() != 32 {
                return Err(BoltError::Truncated {
                    expected: 32,
                    actual: bytes.len(),
                });
            }

            Some(Txid::from_byte_array(
                bytes.try_into().expect("length checked above"),
            ))
        } else {
            None
        };

        Ok(Self { funding_txid })
    }
}

impl CommitmentSigned {
    /// Encodes to wire format (without message type prefix).
    ///
    /// # Panics
    ///
    /// Panics if more than `u16::MAX` HTLC signatures are present.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.signature.write(&mut out);
        u16::try_from(self.htlc_signatures.len())
            .expect("htlc_signatures length is within u16::MAX")
            .write(&mut out);

        for sig in &self.htlc_signatures {
            sig.write(&mut out);
        }

        out.extend(self.tlvs.encode());
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field, also can return
    /// `InvalidSignature` and TLV errors.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let signature = WireFormat::read(&mut cursor)?;
        let num_htlcs = u16::read(&mut cursor)?;

        let mut htlc_signatures = Vec::with_capacity(num_htlcs as usize);
        for _ in 0..num_htlcs {
            let sig = WireFormat::read(&mut cursor)?;
            htlc_signatures.push(sig);
        }

        let tlvs = CommitmentSignedTlvs::decode(cursor)?;

        Ok(Self {
            channel_id,
            signature,
            htlc_signatures,
            tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE};
    use super::*;
    use secp256k1::hashes::Hash;
    use secp256k1::{Message, Secp256k1, SecretKey};

    /// Valid `CommitmentSigned` message with no HTLCs for testing.
    fn sample_commitment_signed_no_htlcs() -> CommitmentSigned {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(msg, &sk);

        CommitmentSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
            htlc_signatures: vec![],
            tlvs: CommitmentSignedTlvs {
                funding_txid: Some(Txid::from_byte_array([0xcc; 32])),
            },
        }
    }

    /// Valid `CommitmentSigned` message with 2 HTLC signatures for testing.
    fn sample_commitment_signed_with_htlcs() -> CommitmentSigned {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(msg, &sk);

        let sk2 = SecretKey::from_byte_array([0x22; 32]).expect("valid secret");
        let msg2 = Message::from_digest([0xbb; 32]);
        let sig2 = secp.sign_ecdsa(msg2, &sk2);

        let sk3 = SecretKey::from_byte_array([0x33; 32]).expect("valid secret");
        let msg3 = Message::from_digest([0xcc; 32]);
        let sig3 = secp.sign_ecdsa(msg3, &sk3);

        CommitmentSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
            htlc_signatures: vec![sig2, sig3],
            tlvs: CommitmentSignedTlvs {
                funding_txid: Some(Txid::from_byte_array([0xdd; 32])),
            },
        }
    }

    #[test]
    fn encode_no_htlcs() {
        let msg = sample_commitment_signed_no_htlcs();
        let encoded = msg.encode();
        assert!(encoded.len() > 96);
    }

    #[test]
    fn encode_with_htlcs() {
        let msg = sample_commitment_signed_with_htlcs();
        let encoded = msg.encode();
        assert!(encoded.len() > 32 + 64 + 2 + 2 * 64);
    }

    #[test]
    fn roundtrip_no_htlcs() {
        let original = sample_commitment_signed_no_htlcs();
        let encoded = original.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_htlcs() {
        let original = sample_commitment_signed_with_htlcs();
        let encoded = original.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            CommitmentSigned::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_signature() {
        let msg = sample_commitment_signed_no_htlcs();
        let encoded = msg.encode();
        let data = &encoded[..60]; // channel_id(32) + 28 bytes into signature
        assert_eq!(
            CommitmentSigned::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 28
            })
        );
    }

    #[test]
    fn decode_truncated_num_htlcs() {
        let msg = sample_commitment_signed_no_htlcs();
        let encoded = msg.encode();
        let data = &encoded[..96]; // channel_id(32) + signature(64) = 96, missing num_htlcs(2)
        assert_eq!(
            CommitmentSigned::decode(data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_truncated_htlc_signature() {
        // Create message with 2 HTLC signatures
        let msg = sample_commitment_signed_with_htlcs();
        let encoded = msg.encode();

        // Truncate in the middle of the HTLC signatures (before TLV)
        // We remove bytes from the signature portion, not the TLV
        let data = &encoded[..32 + 64 + 2 + 54]; // channel_id + signature + num_htlcs + 54 bytes of 128 byte HTLC sigs

        assert_eq!(
            CommitmentSigned::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 54
            })
        );
    }

    #[test]
    fn funding_txid_roundtrip() {
        let original = sample_commitment_signed_no_htlcs();
        assert_eq!(
            original.tlvs.funding_txid,
            Some(Txid::from_byte_array([0xcc; 32]))
        );

        let encoded = original.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();

        assert_eq!(
            decoded.tlvs.funding_txid,
            Some(Txid::from_byte_array([0xcc; 32]))
        );
        assert_eq!(original, decoded);
    }

    #[test]
    fn funding_txid_with_htlcs_roundtrip() {
        let original = sample_commitment_signed_with_htlcs();
        assert_eq!(
            original.tlvs.funding_txid,
            Some(Txid::from_byte_array([0xdd; 32]))
        );

        let encoded = original.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();

        assert_eq!(
            decoded.tlvs.funding_txid,
            Some(Txid::from_byte_array([0xdd; 32]))
        );
        assert_eq!(original, decoded);
    }

    #[test]
    fn malformed_funding_txid_fails() {
        let mut encoded = Vec::new();

        encoded.extend([0u8; 32]);
        encoded.extend([0u8; 64]);
        encoded.extend([0u8; 2]);

        // Now add malformed TLV
        encoded.push(1);
        encoded.push(31);
        encoded.extend([0u8; 31]);

        let result = CommitmentSigned::decode(&encoded);

        assert_eq!(
            result,
            Err(BoltError::Truncated {
                expected: 32,
                actual: 31,
            })
        );
    }

    #[test]
    fn no_funding_txid() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(msg, &sk);

        let msg_no_txid = CommitmentSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
            htlc_signatures: vec![],
            tlvs: CommitmentSignedTlvs { funding_txid: None },
        };

        let encoded = msg_no_txid.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();

        assert_eq!(decoded.tlvs.funding_txid, None);
        // Message with no TLVs should be shorter
        assert_eq!(encoded.len(), 98);
    }

    #[test]
    fn invalid_signature_fails() {
        let msg = sample_commitment_signed_no_htlcs();
        let mut encoded = msg.encode();

        let sig_offset = 32;
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[sig_offset..sig_offset + COMPACT_SIGNATURE_SIZE].copy_from_slice(&bad_sig);

        assert_eq!(
            CommitmentSigned::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn different_funding_txids() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(msg, &sk);

        let txid1 = Txid::from_byte_array([0x11; 32]);
        let txid2 = Txid::from_byte_array([0x22; 32]);

        let mut msg1 = CommitmentSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
            htlc_signatures: vec![],
            tlvs: CommitmentSignedTlvs {
                funding_txid: Some(txid1),
            },
        };

        let encoded1 = msg1.encode();
        let decoded1 = CommitmentSigned::decode(&encoded1).unwrap();
        assert_eq!(decoded1.tlvs.funding_txid, Some(txid1));

        msg1.tlvs.funding_txid = Some(txid2);
        let encoded2 = msg1.encode();
        let decoded2 = CommitmentSigned::decode(&encoded2).unwrap();
        assert_eq!(decoded2.tlvs.funding_txid, Some(txid2));

        // Different TLVs should produce different encodings
        assert_ne!(encoded1, encoded2);
    }

    #[test]
    fn roundtrip_with_non_default_tlvs() {
        let mut msg = sample_commitment_signed_no_htlcs();
        msg.tlvs.funding_txid = Some(Txid::from_byte_array([0xaa; 32]));

        let encoded = msg.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();

        assert_eq!(
            decoded.tlvs.funding_txid,
            Some(Txid::from_byte_array([0xaa; 32]))
        );
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(msg, &sk);

        let original = CommitmentSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
            htlc_signatures: vec![],
            tlvs: CommitmentSignedTlvs {
                funding_txid: Some(Txid::from_byte_array([0xcc; 32])),
            },
        };

        let encoded = original.encode();

        // Append an unknown odd TLV (type 3, length 2, value 0xaabb)
        // TLVs must be in strictly increasing order, so we insert it after type 1
        let mut tlv_with_unknown = Vec::new();
        // Copy everything up to and including the funding_txid TLV
        tlv_with_unknown.extend(&encoded);
        // Add unknown odd TLV: type=3 (odd, so should be ignored)
        tlv_with_unknown.push(0x03); // type = 3
        tlv_with_unknown.push(0x02); // length = 2
        tlv_with_unknown.push(0xaa); // value
        tlv_with_unknown.push(0xbb); // value

        // Should successfully decode, ignoring the unknown odd TLV
        let decoded = CommitmentSigned::decode(&tlv_with_unknown).unwrap();
        assert_eq!(
            decoded.tlvs.funding_txid,
            Some(Txid::from_byte_array([0xcc; 32]))
        );
        assert_eq!(decoded.channel_id, original.channel_id);
        assert_eq!(decoded.signature, original.signature);
        assert_eq!(decoded.htlc_signatures, original.htlc_signatures);
    }
}
