//! BOLT 1 init message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{read_u16_be, write_u16_be};

/// TLV type for chain hash list.
const TLV_NETWORKS: u64 = 1;

/// TLV type for remote address.
const TLV_REMOTE_ADDR: u64 = 3;

/// Size of a chain hash (SHA256).
const CHAIN_HASH_SIZE: usize = 32;

/// BOLT 1 init message (type 16).
///
/// Exchanged after the Noise handshake to negotiate features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Init {
    /// Legacy global features (deprecated, should be empty).
    pub globalfeatures: Vec<u8>,
    /// Feature bits supported by this node.
    pub features: Vec<u8>,
    /// Optional TLV extensions.
    pub tlvs: InitTlvs,
}

/// TLV extensions for the init message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitTlvs {
    /// Chain hashes this node is interested in (TLV type 1).
    ///
    /// Each entry is a 32-byte genesis block hash. If empty, the node
    /// supports all chains. If present, only channels for listed chains
    /// should be established.
    pub networks: Option<Vec<[u8; CHAIN_HASH_SIZE]>>,

    /// Remote address as seen by peer (TLV type 3).
    ///
    /// Allows a node to learn its external IP address.
    pub remote_addr: Option<Vec<u8>>,
}

impl Init {
    /// Creates an empty init message with no features.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            globalfeatures: Vec::new(),
            features: Vec::new(),
            tlvs: InitTlvs::default(),
        }
    }

    /// Creates an init that echoes the received init's features.
    ///
    /// This is useful when the fuzzer wants to accept whatever features
    /// the target offers.
    #[must_use]
    pub fn echo(received: &Self) -> Self {
        Self {
            globalfeatures: received.globalfeatures.clone(),
            features: received.features.clone(),
            tlvs: InitTlvs::default(),
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Encode globalfeatures
        #[allow(clippy::cast_possible_truncation)] // Feature vecs are bounded by u16
        write_u16_be(self.globalfeatures.len() as u16, &mut out);
        out.extend_from_slice(&self.globalfeatures);

        // Encode features
        #[allow(clippy::cast_possible_truncation)] // Feature vecs are bounded by u16
        write_u16_be(self.features.len() as u16, &mut out);
        out.extend_from_slice(&self.features);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(networks) = &self.tlvs.networks {
            let mut value = Vec::with_capacity(networks.len() * CHAIN_HASH_SIZE);
            for hash in networks {
                value.extend_from_slice(hash);
            }
            tlv_stream.add(TLV_NETWORKS, value);
        }
        if let Some(remote_addr) = &self.tlvs.remote_addr {
            tlv_stream.add(TLV_REMOTE_ADDR, remote_addr.clone());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short, or TLV errors if
    /// the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        // Decode globalfeatures
        let gflen = read_u16_be(&mut cursor)? as usize;
        if cursor.len() < gflen {
            return Err(BoltError::Truncated {
                expected: gflen,
                actual: cursor.len(),
            });
        }
        let globalfeatures = cursor[..gflen].to_vec();
        cursor = &cursor[gflen..];

        // Decode features
        let flen = read_u16_be(&mut cursor)? as usize;
        if cursor.len() < flen {
            return Err(BoltError::Truncated {
                expected: flen,
                actual: cursor.len(),
            });
        }
        let features = cursor[..flen].to_vec();
        cursor = &cursor[flen..];

        // Decode TLVs (remaining bytes)
        // Init TLVs are all odd (1, 3), so no known even types
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = InitTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            globalfeatures,
            features,
            tlvs,
        })
    }
}

impl InitTlvs {
    /// Extracts init TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the networks TLV has invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let networks = if let Some(data) = stream.get(TLV_NETWORKS) {
            let (chunks, remainder) = data.as_chunks::<CHAIN_HASH_SIZE>();
            if !remainder.is_empty() {
                return Err(BoltError::Truncated {
                    expected: (chunks.len() + 1) * CHAIN_HASH_SIZE,
                    actual: data.len(),
                });
            }
            Some(chunks.to_vec())
        } else {
            None
        };

        let remote_addr = stream.get(TLV_REMOTE_ADDR).map(Vec::from);

        Ok(Self {
            networks,
            remote_addr,
        })
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
mod tests {
    use super::*;

    // Bitcoin mainnet genesis block hash
    const BITCOIN_MAINNET: [u8; CHAIN_HASH_SIZE] = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    #[test]
    fn empty_init() {
        let init = Init::empty();
        assert!(init.globalfeatures.is_empty());
        assert!(init.features.is_empty());
        assert!(init.tlvs.networks.is_none());
        assert!(init.tlvs.remote_addr.is_none());
    }

    #[test]
    fn echo_init() {
        let received = Init {
            globalfeatures: vec![0x01, 0x02],
            features: vec![0xaa, 0xbb, 0xcc],
            tlvs: InitTlvs {
                networks: Some(vec![BITCOIN_MAINNET]),
                remote_addr: Some(vec![0xaa, 0xbb]),
            },
        };

        let echoed = Init::echo(&received);
        assert_eq!(echoed.globalfeatures, received.globalfeatures);
        assert_eq!(echoed.features, received.features);
        // TLVs are not echoed
        assert!(echoed.tlvs.networks.is_none());
        assert!(echoed.tlvs.remote_addr.is_none());
    }

    #[test]
    fn encode_empty() {
        let init = Init::empty();
        let encoded = init.encode();
        // gflen(2) + features_len(2) = 4 bytes
        assert_eq!(encoded, [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_with_features() {
        let init = Init {
            globalfeatures: vec![0x01],
            features: vec![0x02, 0x03],
            tlvs: InitTlvs::default(),
        };
        let encoded = init.encode();
        assert_eq!(
            encoded,
            [
                0x00, 0x01, 0x01, // gflen=1, globalfeatures=0x01
                0x00, 0x02, 0x02, 0x03, // flen=2, features=0x02,0x03
            ]
        );
    }

    #[test]
    fn encode_with_networks_tlv() {
        let init = Init {
            globalfeatures: Vec::new(),
            features: Vec::new(),
            tlvs: InitTlvs {
                networks: Some(vec![BITCOIN_MAINNET]),
                remote_addr: None,
            },
        };
        let encoded = init.encode();

        // gflen(2) + flen(2) + tlv_type(1) + tlv_len(1) + chain_hash(32)
        assert_eq!(encoded.len(), 4 + 1 + 1 + CHAIN_HASH_SIZE);
        assert_eq!(encoded[0..4], [0x00, 0x00, 0x00, 0x00]); // gf + f
        assert_eq!(encoded[4], TLV_NETWORKS as u8);
        assert_eq!(encoded[5], CHAIN_HASH_SIZE as u8);
        assert_eq!(encoded[6..], BITCOIN_MAINNET);
    }

    #[test]
    fn encode_with_remote_addr_tlv() {
        let addr = [0xaa, 0xbb, 0xcc];
        let init = Init {
            globalfeatures: Vec::new(),
            features: Vec::new(),
            tlvs: InitTlvs {
                networks: None,
                remote_addr: Some(addr.to_vec()),
            },
        };
        let encoded = init.encode();

        // gflen(2) + flen(2) + tlv_type(1) + tlv_len(1) + addr(3)
        assert_eq!(encoded.len(), 4 + 1 + 1 + addr.len());
        assert_eq!(encoded[0..4], [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(encoded[4], TLV_REMOTE_ADDR as u8);
        assert_eq!(encoded[5], addr.len() as u8);
        assert_eq!(encoded[6..], addr);
    }

    #[test]
    fn decode_empty() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let init = Init::decode(&data).unwrap();
        assert!(init.globalfeatures.is_empty());
        assert!(init.features.is_empty());
        assert!(init.tlvs.networks.is_none());
        assert!(init.tlvs.remote_addr.is_none());
    }

    #[test]
    fn decode_with_features() {
        let data = [
            0x00, 0x01, 0xaa, // gflen=1, globalfeatures=0xaa
            0x00, 0x02, 0xbb, 0xcc, // flen=2, features=0xbb,0xcc
        ];
        let init = Init::decode(&data).unwrap();
        assert_eq!(init.globalfeatures, [0xaa]);
        assert_eq!(init.features, [0xbb, 0xcc]);
    }

    #[test]
    fn decode_with_networks_tlv() {
        let mut data = vec![0x00, 0x00, 0x00, 0x00]; // empty features
        data.push(TLV_NETWORKS as u8);
        data.push(CHAIN_HASH_SIZE as u8);
        data.extend_from_slice(&BITCOIN_MAINNET);

        let init = Init::decode(&data).unwrap();
        assert_eq!(init.tlvs.networks, Some(vec![BITCOIN_MAINNET]));
    }

    #[test]
    fn decode_with_multiple_networks() {
        let testnet: [u8; CHAIN_HASH_SIZE] = [0x43; CHAIN_HASH_SIZE];

        let mut data = vec![0x00, 0x00, 0x00, 0x00]; // empty features
        data.push(TLV_NETWORKS as u8);
        data.push((CHAIN_HASH_SIZE * 2) as u8); // two chain hashes
        data.extend_from_slice(&BITCOIN_MAINNET);
        data.extend_from_slice(&testnet);

        let init = Init::decode(&data).unwrap();
        assert_eq!(init.tlvs.networks, Some(vec![BITCOIN_MAINNET, testnet]));
    }

    #[test]
    fn decode_with_remote_addr_tlv() {
        let addr = [0xaa, 0xbb, 0xcc];
        let mut data = vec![0x00, 0x00, 0x00, 0x00];
        data.push(TLV_REMOTE_ADDR as u8);
        data.push(addr.len() as u8);
        data.extend_from_slice(&addr);

        let init = Init::decode(&data).unwrap();
        assert_eq!(init.tlvs.remote_addr, Some(addr.to_vec()));
    }

    #[test]
    fn roundtrip() {
        let original = Init {
            globalfeatures: vec![0x01, 0x02],
            features: vec![0xaa, 0xbb, 0xcc, 0xdd],
            tlvs: InitTlvs {
                networks: Some(vec![BITCOIN_MAINNET]),
                remote_addr: Some(vec![0xaa, 0xbb, 0xcc]),
            },
        };
        let encoded = original.encode();
        let decoded = Init::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_gflen() {
        // Only 1 byte, need 2 for gflen
        assert_eq!(
            Init::decode(&[0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_globalfeatures() {
        // gflen=5 but only 3 bytes follow
        let data = [0x00, 0x05, 0xaa, 0xbb, 0xcc];
        assert_eq!(
            Init::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_truncated_flen() {
        // gflen=0, then only 1 byte for flen
        let data = [0x00, 0x00, 0x00];
        assert_eq!(
            Init::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_features() {
        // gflen=0, flen=5, but only 2 bytes follow
        let data = [0x00, 0x00, 0x00, 0x05, 0xaa, 0xbb];
        assert_eq!(
            Init::decode(&data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_networks_invalid_length() {
        // Networks TLV with 33 bytes (not divisible by 32)
        let mut data = vec![0x00, 0x00, 0x00, 0x00];
        data.push(TLV_NETWORKS as u8);
        data.push(33); // invalid: not a multiple of CHAIN_HASH_SIZE
        data.extend_from_slice(&[0x00; 33]);

        assert_eq!(
            Init::decode(&data),
            Err(BoltError::Truncated {
                expected: CHAIN_HASH_SIZE * 2, // Next multiple of 32
                actual: 33
            })
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        // Unknown odd TLV type 5 should be accepted
        let mut data = vec![0x00, 0x00, 0x00, 0x00];
        data.push(0x05); // TLV type = 5 (odd, unknown)
        data.push(0x02); // TLV length = 2
        data.extend_from_slice(&[0xaa, 0xbb]);

        let init = Init::decode(&data).unwrap();
        // Unknown TLVs are parsed but not stored in InitTlvs
        assert!(init.tlvs.networks.is_none());
        assert!(init.tlvs.remote_addr.is_none());
    }

    #[test]
    fn decode_empty_networks_list() {
        // Empty networks TLV is valid (zero chain hashes)
        let mut data = vec![0x00, 0x00, 0x00, 0x00]; // empty features
        data.push(TLV_NETWORKS as u8);
        data.push(0x00); // len=0
        let init = Init::decode(&data).unwrap();
        assert_eq!(init.tlvs.networks, Some(vec![]));
    }
}
