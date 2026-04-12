//! BOLT 2 funding signed message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;
use bitcoin::secp256k1::ecdsa::Signature;

/// BOLT 2 `funding_signed` message (type 35).
///
/// Sent by the channel acceptor in response to `funding_created` to provide
/// their signature for the counterparty's first commitment transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingSigned {
    /// The channel ID derived from the funding transaction outpoint
    pub channel_id: ChannelId,
    /// The channel acceptor's signature for the counterparty's first commitment transaction
    pub signature: Signature,
}

impl FundingSigned {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.signature.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or `InvalidSignature`
    /// if the signature bytes are not a valid compact ECDSA signature.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let signature = WireFormat::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Valid `FundingSigned` message for testing.
    fn sample_funding_signed() -> FundingSigned {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        FundingSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_funding_signed();
        let encoded = msg.encode();
        // 32 + 64 = 96
        assert_eq!(encoded.len(), 96);
    }

    #[test]
    fn roundtrip() {
        let original = sample_funding_signed();
        let encoded = original.encode();
        let decoded = FundingSigned::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            FundingSigned::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_signature() {
        // channel_id(32) + 30 bytes into signature
        let msg = sample_funding_signed();
        let encoded = msg.encode();
        let data = &encoded[..62]; // 32 + 30
        assert_eq!(
            FundingSigned::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 30
            })
        );
    }

    #[test]
    fn decode_invalid_signature() {
        let msg = sample_funding_signed();
        let mut encoded = msg.encode();

        // Overwrite the signature (last 64 bytes) with r and s both > curve order
        let sig_offset = encoded.len() - COMPACT_SIGNATURE_SIZE;
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[sig_offset..].copy_from_slice(&bad_sig);

        assert_eq!(
            FundingSigned::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }
}
