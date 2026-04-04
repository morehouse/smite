//! BOLT 2 open channel v2 message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{CHAIN_HASH_SIZE, ChannelId};
use super::wire::WireFormat;
use secp256k1::PublicKey;

/// TLV type for upfront shutdown script.
const TLV_UPFRONT_SHUTDOWN_SCRIPT: u64 = 0;

/// TLV type for channel type.
const TLV_CHANNEL_TYPE: u64 = 1;

/// TLV type for require confirmed inputs.
const TLV_REQUIRE_CONFIRMED_INPUTS: u64 = 2;

/// BOLT 2 `open_channel2` message (type 64).
///
/// Sent by the channel initiator to begin the v2 (dual-funded) channel
/// establishment flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenChannel2 {
    /// The genesis hash of the blockchain on which the channel is to be opened
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// A temporary channel ID used until the funding outpoint is announced
    pub temporary_channel_id: ChannelId,
    /// The feerate for the funding transaction, in satoshis per 1000 weight units
    pub funding_feerate_perkw: u32,
    /// The feerate for commitment transactions, in satoshis per 1000 weight units
    pub commitment_feerate_perkw: u32,
    /// The amount the channel initiator contributes to the channel, in satoshis
    pub funding_satoshis: u64,
    /// The threshold below which outputs on transactions broadcast by the channel initiator will be omitted
    pub dust_limit_satoshis: u64,
    /// The maximum total value of inbound HTLCs in flight toward the channel initiator, in millisatoshis
    pub max_htlc_value_in_flight_msat: u64,
    /// The minimum HTLC value the channel initiator will accept, in millisatoshis
    pub htlc_minimum_msat: u64,
    /// The number of blocks the counterparty must wait to claim on-chain funds after broadcasting a commitment transaction
    pub to_self_delay: u16,
    /// The maximum number of inbound HTLCs toward the channel initiator
    pub max_accepted_htlcs: u16,
    /// The locktime for the funding transaction
    pub locktime: u32,
    /// The channel initiator's public key for the funding transaction
    pub funding_pubkey: PublicKey,
    /// The basepoint used to derive revocation keys for transactions broadcast by the counterparty
    pub revocation_basepoint: PublicKey,
    /// The basepoint used to derive payment keys for transactions broadcast by the counterparty
    pub payment_basepoint: PublicKey,
    /// The basepoint used to derive delayed payment keys for transactions broadcast by the channel initiator
    pub delayed_payment_basepoint: PublicKey,
    /// The basepoint used to derive HTLC keys for the channel initiator
    pub htlc_basepoint: PublicKey,
    /// The first per-commitment point for transactions broadcast by the channel initiator
    pub first_per_commitment_point: PublicKey,
    /// The second per-commitment point for transactions broadcast by the channel initiator
    pub second_per_commitment_point: PublicKey,
    /// The channel flags to be used
    pub channel_flags: u8,
    /// Optional TLV extensions.
    pub tlvs: OpenChannel2Tlvs,
}

/// TLV extensions for the `open_channel2` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenChannel2Tlvs {
    /// Optionally specifies the scriptPubKey for the channel initiator's output when cooperatively closing the channel
    pub upfront_shutdown_script: Option<Vec<u8>>,
    /// The channel type represented as feature bits
    pub channel_type: Option<Vec<u8>>,
    /// If set, the sender requires the receiver to only use confirmed inputs
    pub require_confirmed_inputs: bool,
}

impl OpenChannel2 {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.temporary_channel_id.write(&mut out);
        self.funding_feerate_perkw.write(&mut out);
        self.commitment_feerate_perkw.write(&mut out);
        self.funding_satoshis.write(&mut out);
        self.dust_limit_satoshis.write(&mut out);
        self.max_htlc_value_in_flight_msat.write(&mut out);
        self.htlc_minimum_msat.write(&mut out);
        self.to_self_delay.write(&mut out);
        self.max_accepted_htlcs.write(&mut out);
        self.locktime.write(&mut out);
        self.funding_pubkey.write(&mut out);
        self.revocation_basepoint.write(&mut out);
        self.payment_basepoint.write(&mut out);
        self.delayed_payment_basepoint.write(&mut out);
        self.htlc_basepoint.write(&mut out);
        self.first_per_commitment_point.write(&mut out);
        self.second_per_commitment_point.write(&mut out);
        self.channel_flags.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(upfront_shutdown_script) = &self.tlvs.upfront_shutdown_script {
            tlv_stream.add(TLV_UPFRONT_SHUTDOWN_SCRIPT, upfront_shutdown_script.clone());
        }
        if let Some(channel_type) = &self.tlvs.channel_type {
            tlv_stream.add(TLV_CHANNEL_TYPE, channel_type.clone());
        }
        if self.tlvs.require_confirmed_inputs {
            tlv_stream.add(TLV_REQUIRE_CONFIRMED_INPUTS, vec![]);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or `InvalidPublicKey`
    /// if any of the public key fields are invalid
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let chain_hash = WireFormat::read(&mut cursor)?;
        let temporary_channel_id = WireFormat::read(&mut cursor)?;
        let funding_feerate_perkw = WireFormat::read(&mut cursor)?;
        let commitment_feerate_perkw = WireFormat::read(&mut cursor)?;
        let funding_satoshis = WireFormat::read(&mut cursor)?;
        let dust_limit_satoshis = WireFormat::read(&mut cursor)?;
        let max_htlc_value_in_flight_msat = WireFormat::read(&mut cursor)?;
        let htlc_minimum_msat = WireFormat::read(&mut cursor)?;
        let to_self_delay = WireFormat::read(&mut cursor)?;
        let max_accepted_htlcs = WireFormat::read(&mut cursor)?;
        let locktime = WireFormat::read(&mut cursor)?;
        let funding_pubkey = WireFormat::read(&mut cursor)?;
        let revocation_basepoint = WireFormat::read(&mut cursor)?;
        let payment_basepoint = WireFormat::read(&mut cursor)?;
        let delayed_payment_basepoint = WireFormat::read(&mut cursor)?;
        let htlc_basepoint = WireFormat::read(&mut cursor)?;
        let first_per_commitment_point = WireFormat::read(&mut cursor)?;
        let second_per_commitment_point = WireFormat::read(&mut cursor)?;
        let channel_flags = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        // Types 0 (`upfront_shutdown_script`) and 2 (`require_confirmed_inputs`)
        // are even types defined by BOLT 2, so we must whitelist them as known.
        let tlv_stream = TlvStream::decode_with_known(
            cursor,
            &[TLV_UPFRONT_SHUTDOWN_SCRIPT, TLV_REQUIRE_CONFIRMED_INPUTS],
        )?;
        let tlvs = OpenChannel2Tlvs::from_stream(&tlv_stream);

        Ok(Self {
            chain_hash,
            temporary_channel_id,
            funding_feerate_perkw,
            commitment_feerate_perkw,
            funding_satoshis,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            htlc_minimum_msat,
            to_self_delay,
            max_accepted_htlcs,
            locktime,
            funding_pubkey,
            revocation_basepoint,
            payment_basepoint,
            delayed_payment_basepoint,
            htlc_basepoint,
            first_per_commitment_point,
            second_per_commitment_point,
            channel_flags,
            tlvs,
        })
    }
}

impl OpenChannel2Tlvs {
    /// Extracts open channel2 TLVs from a parsed TLV stream.
    fn from_stream(stream: &TlvStream) -> Self {
        let upfront_shutdown_script = stream.get(TLV_UPFRONT_SHUTDOWN_SCRIPT).map(Vec::from);
        let channel_type = stream.get(TLV_CHANNEL_TYPE).map(Vec::from);
        let require_confirmed_inputs = stream.get(TLV_REQUIRE_CONFIRMED_INPUTS).is_some();

        Self {
            upfront_shutdown_script,
            channel_type,
            require_confirmed_inputs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::PUBLIC_KEY_SIZE;
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    /// Valid `OpenChannel2` message for testing.
    fn sample_open_channel2(tlvs: Option<OpenChannel2Tlvs>) -> OpenChannel2 {
        let secp = Secp256k1::new();
        let secrets: [[u8; 32]; 7] = [
            [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
        ];
        let keys: Vec<PublicKey> = secrets
            .iter()
            .map(|s| {
                let sk = SecretKey::from_byte_array(*s).expect("valid secret");
                PublicKey::from_secret_key(&secp, &sk)
            })
            .collect();

        OpenChannel2 {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            funding_feerate_perkw: 2_500,
            commitment_feerate_perkw: 253,
            funding_satoshis: 100_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            htlc_minimum_msat: 1_000,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            locktime: 800_000,
            funding_pubkey: keys[0],
            revocation_basepoint: keys[1],
            payment_basepoint: keys[2],
            delayed_payment_basepoint: keys[3],
            htlc_basepoint: keys[4],
            first_per_commitment_point: keys[5],
            second_per_commitment_point: keys[6],
            channel_flags: 0x01,
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let open = sample_open_channel2(None);
        let encoded = open.encode();
        // 32 + 32 + 4 + 4 + 8*4 + 2 + 2 + 4 + 33*7 + 1 = 344
        assert_eq!(encoded.len(), 344);
    }

    #[test]
    fn roundtrip() {
        let original = sample_open_channel2(None);
        let encoded = original.encode();
        let decoded = OpenChannel2::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_chain_hash() {
        assert_eq!(
            OpenChannel2::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: 32,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_temporary_channel_id() {
        // chain_hash(32) + 10 bytes into temporary_channel_id
        let data = [0x00; 42];
        assert_eq!(
            OpenChannel2::decode(&data),
            Err(BoltError::Truncated {
                expected: 32,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_truncated_funding_feerate() {
        // chain_hash(32) + temp_channel_id(32) = 64, funding_feerate needs 4, only give 2
        let data = [0x00; 66];
        assert_eq!(
            OpenChannel2::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_truncated_scalars() {
        // chain_hash(32) + temp_channel_id(32) + funding_feerate(4) + commitment_feerate(4)
        // = 72 bytes, but not enough for funding_satoshis(8)
        let data = [0x00; 72];
        assert_eq!(
            OpenChannel2::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_truncated_to_self_delay() {
        // chain_hash(32) + temp_channel_id(32) + funding_feerate(4) + commitment_feerate(4)
        // + 4 u64s(32) = 104, to_self_delay needs 2, only give 1
        let data = [0x00; 105];
        assert_eq!(
            OpenChannel2::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_locktime() {
        // chain_hash(32) + temp_channel_id(32) + funding_feerate(4) + commitment_feerate(4)
        // + 4 u64s(32) + to_self_delay(2) + max_accepted_htlcs(2) = 108
        // locktime needs 4, only give 2
        let data = [0x00; 110];
        assert_eq!(
            OpenChannel2::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }

    /// Offset of the first public key field (`funding_pubkey`) in the wire
    /// encoding: 32 + 32 + 4 + 4 + 8×4 + 2 + 2 + 4 = 112 bytes of scalar fields.
    const FIRST_PUBKEY_OFFSET: usize = 112;

    #[test]
    fn decode_truncated_funding_pubkey() {
        // Provide all scalar fields (112 bytes) but only 10 bytes into
        // funding_pubkey (needs 33).
        let data = [0x00; FIRST_PUBKEY_OFFSET + 10];
        assert_eq!(
            OpenChannel2::decode(&data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_truncated_revocation_basepoint() {
        // All scalar fields(112) + funding_pubkey(33) + 15 bytes into
        // revocation_basepoint (needs 33).
        let open = sample_open_channel2(None);
        let encoded = open.encode();
        let data = &encoded[..160]; // 112 + 33 + 15
        assert_eq!(
            OpenChannel2::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 15
            })
        );
    }

    #[test]
    fn decode_truncated_first_per_commitment_point() {
        // All scalar fields(112) + 5 pubkeys(165) + 20 bytes into
        // first_per_commitment_point (needs 33).
        let open = sample_open_channel2(None);
        let encoded = open.encode();
        let data = &encoded[..297]; // 112 + 165 + 20
        assert_eq!(
            OpenChannel2::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_second_per_commitment_point() {
        // All scalar fields(112) + 6 pubkeys(198) + 20 bytes into
        // second_per_commitment_point (needs 33).
        let open = sample_open_channel2(None);
        let encoded = open.encode();
        let data = &encoded[..330]; // 112 + 198 + 20
        assert_eq!(
            OpenChannel2::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_channel_flags() {
        // All scalar fields(112) + 7 pubkeys(231) = 343, channel_flags needs 1
        let open = sample_open_channel2(None);
        let encoded = open.encode();
        let data = &encoded[..343];
        assert_eq!(
            OpenChannel2::decode(data),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_invalid_funding_pubkey() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        let offset = FIRST_PUBKEY_OFFSET; // first pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            OpenChannel2::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_revocation_basepoint() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE; // second pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            OpenChannel2::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_payment_basepoint() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 2; // third pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            OpenChannel2::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_delayed_payment_basepoint() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 3; // fourth pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            OpenChannel2::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_htlc_basepoint() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 4; // fifth pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            OpenChannel2::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_first_per_commitment_point() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 5; // sixth pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            OpenChannel2::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_second_per_commitment_point() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 6; // seventh pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            OpenChannel2::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let original = sample_open_channel2(Some(OpenChannel2Tlvs {
            upfront_shutdown_script: Some(vec![0xab; 22]),
            channel_type: Some(vec![0x01, 0x02]),
            require_confirmed_inputs: true,
        }));

        let encoded = original.encode();
        let decoded = OpenChannel2::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_with_channel_type() {
        let open = sample_open_channel2(Some(OpenChannel2Tlvs {
            upfront_shutdown_script: None,
            channel_type: Some(vec![0x01, 0x02]),
            require_confirmed_inputs: false,
        }));

        let encoded = open.encode();
        // 344 fixed + TLV: type(1) + len(1) + value(2) = 4
        assert_eq!(encoded.len(), 344 + 4);

        let decoded = OpenChannel2::decode(&encoded).unwrap();
        assert_eq!(decoded.tlvs.channel_type, Some(vec![0x01, 0x02]));
    }

    #[test]
    fn encode_with_require_confirmed_inputs() {
        let open = sample_open_channel2(Some(OpenChannel2Tlvs {
            upfront_shutdown_script: None,
            channel_type: None,
            require_confirmed_inputs: true,
        }));

        let encoded = open.encode();
        // 344 fixed + TLV type 2: type(1) + len(1) + value(0) = 2
        assert_eq!(encoded.len(), 344 + 2);

        let decoded = OpenChannel2::decode(&encoded).unwrap();
        assert!(decoded.tlvs.require_confirmed_inputs);
    }

    #[test]
    fn encode_with_all_tlvs() {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[0xab; 20]);
        let open = sample_open_channel2(Some(OpenChannel2Tlvs {
            // P2WPKH like script
            upfront_shutdown_script: Some(script),
            channel_type: Some(vec![0x01]),
            require_confirmed_inputs: true,
        }));

        let encoded = open.encode();
        // 344 fixed
        // + TLV type 0: type(1) + len(1) + value(22) = 24
        // + TLV type 1: type(1) + len(1) + value(1) = 3
        // + TLV type 2: type(1) + len(1) + value(0) = 2
        assert_eq!(encoded.len(), 344 + 24 + 3 + 2);
    }

    #[test]
    fn decode_empty_tlv_values() {
        // Empty upfront_shutdown_script
        let open = sample_open_channel2(Some(OpenChannel2Tlvs {
            upfront_shutdown_script: Some(vec![]),
            ..Default::default()
        }));
        let decoded = OpenChannel2::decode(&open.encode()).unwrap();
        assert_eq!(decoded.tlvs.upfront_shutdown_script, Some(vec![]));
        assert_eq!(decoded.tlvs.channel_type, None);
        assert!(!decoded.tlvs.require_confirmed_inputs);

        // Empty channel_type
        let open = sample_open_channel2(Some(OpenChannel2Tlvs {
            channel_type: Some(vec![]),
            ..Default::default()
        }));
        let decoded = OpenChannel2::decode(&open.encode()).unwrap();
        assert_eq!(decoded.tlvs.channel_type, Some(vec![]));
        assert_eq!(decoded.tlvs.upfront_shutdown_script, None);
        assert!(!decoded.tlvs.require_confirmed_inputs);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let open = sample_open_channel2(None);
        let mut encoded = open.encode();

        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);

        let decoded = OpenChannel2::decode(&encoded).unwrap();
        assert!(decoded.tlvs.upfront_shutdown_script.is_none());
        assert!(decoded.tlvs.channel_type.is_none());
        assert!(!decoded.tlvs.require_confirmed_inputs);
    }

    #[test]
    fn default_tlvs_are_none() {
        let tlvs = OpenChannel2Tlvs::default();
        assert!(tlvs.upfront_shutdown_script.is_none());
        assert!(tlvs.channel_type.is_none());
        assert!(!tlvs.require_confirmed_inputs);
    }

    #[test]
    fn require_confirmed_inputs_false_by_default() {
        let open = sample_open_channel2(None);
        let encoded = open.encode();
        let decoded = OpenChannel2::decode(&encoded).unwrap();
        assert!(!decoded.tlvs.require_confirmed_inputs);
    }

    #[test]
    fn roundtrip_without_require_confirmed_inputs() {
        let original = sample_open_channel2(Some(OpenChannel2Tlvs {
            upfront_shutdown_script: Some(vec![0xab; 22]),
            channel_type: Some(vec![0x01]),
            require_confirmed_inputs: false,
        }));

        let encoded = original.encode();
        let decoded = OpenChannel2::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
