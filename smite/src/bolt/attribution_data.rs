//! BOLT 4 attribution data, shared by `update_fail_htlc` and
//! `update_fulfill_htlc` as TLV type 1.

use super::BoltError;
use super::wire::WireFormat;

/// Maximum number of hops for failure attribution.
const ATTRIBUTION_MAX_HOPS: usize = 20;

/// Number of truncated HMACs in attribution data.
const ATTRIBUTION_NUM_HMACS: usize = 210;

/// Size of each truncated HMAC in bytes.
const TRUNCATED_HMAC_SIZE: usize = 4;

/// A 4-byte truncated SHA-256 HMAC used in failure attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TruncatedHmac(pub [u8; TRUNCATED_HMAC_SIZE]);

impl WireFormat for TruncatedHmac {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let bytes: [u8; TRUNCATED_HMAC_SIZE] = WireFormat::read(data)?;
        Ok(Self(bytes))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.0.write(out);
    }
}

/// Attribution data for failure/fulfill attribution (TLV type 1).
///
/// Fixed-size structure (920 bytes) containing per-hop hold times and
/// truncated HMACs for attribution verification, always padded to the
/// maximum of 20 hops.  Defined in the BOLT 4 attribution proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionData {
    /// Per-hop hold times in milliseconds.
    pub htlc_hold_times: [u32; ATTRIBUTION_MAX_HOPS],
    /// Truncated HMACs for hop-by-hop verification.
    pub truncated_hmacs: [TruncatedHmac; ATTRIBUTION_NUM_HMACS],
}

impl AttributionData {
    /// Total wire size in bytes (920).
    ///
    /// Computed directly from the field counts so that any future change
    /// to the struct layout (e.g. compiler-introduced padding) cannot
    /// silently change the on-the-wire size.
    pub const SIZE: usize = ATTRIBUTION_MAX_HOPS * 4 + ATTRIBUTION_NUM_HMACS * TRUNCATED_HMAC_SIZE;

    /// Encodes attribution data to bytes for inclusion in a TLV value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        for &t in &self.htlc_hold_times {
            t.write(&mut out);
        }
        for hmac in &self.truncated_hmacs {
            hmac.write(&mut out);
        }
        out
    }

    /// Decodes attribution data from the raw TLV value bytes.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the data is not exactly 920 bytes.
    pub fn decode(data: &[u8]) -> Result<Self, BoltError> {
        if data.len() != Self::SIZE {
            return Err(BoltError::Truncated {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }
        let mut cursor = data;
        let mut htlc_hold_times = [0u32; ATTRIBUTION_MAX_HOPS];
        for ht in &mut htlc_hold_times {
            *ht = WireFormat::read(&mut cursor)?;
        }
        let mut truncated_hmacs = [TruncatedHmac::default(); ATTRIBUTION_NUM_HMACS];
        for hmac in &mut truncated_hmacs {
            *hmac = WireFormat::read(&mut cursor)?;
        }
        Ok(Self {
            htlc_hold_times,
            truncated_hmacs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_constant() {
        // 20 hold times * 4 bytes + 210 hmacs * 4 bytes = 80 + 840 = 920
        assert_eq!(AttributionData::SIZE, 920);
    }

    #[test]
    fn encode_size() {
        let attr = AttributionData {
            htlc_hold_times: [0u32; ATTRIBUTION_MAX_HOPS],
            truncated_hmacs: [TruncatedHmac::default(); ATTRIBUTION_NUM_HMACS],
        };
        assert_eq!(attr.encode().len(), AttributionData::SIZE);
    }

    #[test]
    fn roundtrip() {
        let htlc_hold_times = std::array::from_fn(|i| u32::try_from(i).unwrap() * 1000);
        let truncated_hmacs =
            std::array::from_fn(|i| TruncatedHmac([u8::try_from(i).unwrap(); TRUNCATED_HMAC_SIZE]));
        let original = AttributionData {
            htlc_hold_times,
            truncated_hmacs,
        };
        let encoded = original.encode();
        let decoded = AttributionData::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_wrong_size() {
        assert_eq!(
            AttributionData::decode(&[0u8; 100]),
            Err(BoltError::Truncated {
                expected: AttributionData::SIZE,
                actual: 100,
            })
        );
    }
}
