//! BOLT 3 commitment transaction construction and signing.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// Anchor output value in satoshis.
const ANCHOR_OUTPUT_VALUE: u64 = 330;

/// Base weight of a non-anchor commitment transaction without HTLCs.
const COMMITMENT_WEIGHT_NON_ANCHOR: u64 = 724;

/// Base weight of an anchor commitment transaction without HTLCs.
const COMMITMENT_WEIGHT_ANCHOR: u64 = 1124;

/// `option_anchors` feature bits (BOLT 9, bits 22/23).
const OPTION_ANCHORS_EVEN_BIT: usize = 22;
const OPTION_ANCHORS_ODD_BIT: usize = 23;

/// Public keys and channel parameters for one side of a channel (opener or acceptor).
pub struct ChannelPartyParams {
    /// Funding pubkey used in the funding output.
    pub funding_pubkey: PublicKey,
    /// Payment basepoint used to derive the `to_remote` output key.
    pub payment_basepoint: PublicKey,
    /// Revocation basepoint used to derive keys that allow punishment of old states.
    pub revocation_basepoint: PublicKey,
    /// Delayed payment basepoint used to derive the time-locked `to_local` output key.
    pub delayed_payment_basepoint: PublicKey,
    /// Per-commitment point used to derive all commitment-specific keys.
    pub per_commitment_point: PublicKey,
    /// Minimum output value below which outputs are trimmed as dust.
    pub dust_limit_satoshis: u64,
    /// CSV delay this party imposes on the other's `to_local` output.
    pub to_self_delay: u16,
}

/// Parameters for building a commitment transaction.
pub struct CommitmentParams {
    /// The commitment transaction number.
    pub commitment_number: u64,
    /// Whether the holder of this commitment is the channel opener.
    pub holder_is_opener: bool,
    /// Holder's funding private key.
    pub holder_funding_privkey: SecretKey,
    /// Funding transaction outpoint.
    pub funding_outpoint: OutPoint,
    /// Total channel funding amount in satoshis.
    pub funding_satoshis: u64,
    /// Amount pushed to the acceptor in millisatoshis.
    pub push_msat: u64,
    /// Fee rate for the commitment transaction.
    pub feerate_per_kw: u32,
    /// Opener's keys and parameters.
    pub opener: ChannelPartyParams,
    /// Acceptor's keys and parameters.
    pub acceptor: ChannelPartyParams,
    /// Channel type feature bits. The commitment format (anchor / legacy) is
    /// derived from the bits set here.
    pub channel_type: Vec<u8>,
}

impl CommitmentParams {
    /// Builds the signature for the counterparty's commitment transaction.
    #[must_use]
    pub fn counterparty_commitment_signature(&self) -> Signature {
        let sighash = self.build_commitment_sighash(false);
        sign(&sighash, &self.holder_funding_privkey)
    }

    /// Verifies a signature received from the counterparty for the holder's
    /// commitment transaction. Returns `true` if the signature is valid.
    #[must_use]
    pub fn verify_received_commitment_signature(&self, signature: &Signature) -> bool {
        let sighash = self.build_commitment_sighash(true);
        let secp = Secp256k1::new();
        let msg = Message::from_digest(sighash);
        let counterparty_funding_pubkey = if self.holder_is_opener {
            &self.acceptor.funding_pubkey
        } else {
            &self.opener.funding_pubkey
        };
        secp.verify_ecdsa(&msg, signature, counterparty_funding_pubkey)
            .is_ok()
    }

    /// Builds the signature for the holder's commitment transaction.
    /// Only used to exercise BOLT 3 test vectors.
    #[cfg(test)]
    fn holder_commitment_signature(&self) -> Signature {
        let sighash = self.build_commitment_sighash(true);
        sign(&sighash, &self.holder_funding_privkey)
    }

    /// Builds the sighash for the commitment transaction. The commitment
    /// format (legacy or anchor) is determined by the `channel_type`.
    ///
    /// When `for_holder` is true, builds the holder's commitment and
    /// when false, builds the counterparty's.
    #[allow(clippy::cast_possible_truncation)]
    fn build_commitment_sighash(&self, for_holder: bool) -> [u8; 32] {
        // Obscured commitment number.
        let obscuring_factor = compute_obscuring_factor(
            &self.opener.payment_basepoint,
            &self.acceptor.payment_basepoint,
        );
        let obscured_commitment_number = self.commitment_number ^ obscuring_factor;

        // Upper 8 bits of sequence are 0x80 and lower 24 bits are the upper 24 bits
        // of the obscured commitment number.
        let sequence = (0x80u32 << (8 * 3)) | ((obscured_commitment_number >> 24) as u32);

        // Upper 8 bits of locktime are 0x20 and lower 24 bits are the lower 24 bits
        // of the obscured commitment number.
        let locktime =
            (0x20u32 << (8 * 3)) | ((obscured_commitment_number & 0x00ff_ffff_u64) as u32);

        // Build the commitment transaction
        let outputs = self.build_commitment_outputs(for_holder);

        // Witness is not included in the BIP 143 sighash, so we leave it empty.
        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(locktime),
            input: vec![input],
            output: outputs,
        };

        // Funding output redeem script.
        let funding_redeemscript =
            build_funding_redeemscript(&self.opener.funding_pubkey, &self.acceptor.funding_pubkey);

        // Compute the BIP143 sighash
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wsh_signature_hash(
                0,
                &funding_redeemscript,
                Amount::from_sat(self.funding_satoshis),
                EcdsaSighashType::All,
            )
            .expect("input index 0 is always in bounds for a single input transaction");

        sighash.to_byte_array()
    }

    /// Builds the lexicographically sorted commitment outputs.
    ///
    /// When `for_holder` is true, builds outputs for the holder's commitment;
    /// otherwise builds outputs for the counterparty's commitment.
    fn build_commitment_outputs(&self, for_holder: bool) -> Vec<TxOut> {
        let anchor = supports_option_anchors(&self.channel_type);

        // Fee and balances.
        let commitment_weight = if anchor {
            COMMITMENT_WEIGHT_ANCHOR
        } else {
            COMMITMENT_WEIGHT_NON_ANCHOR
        };
        let fee = u64::from(self.feerate_per_kw) * commitment_weight / 1000;
        let anchor_cost = if anchor { 2 * ANCHOR_OUTPUT_VALUE } else { 0 };

        let push_sat = self.push_msat / 1000;
        let acceptor_balance = push_sat;
        let opener_balance = self
            .funding_satoshis
            .saturating_sub(push_sat)
            .saturating_sub(fee)
            .saturating_sub(anchor_cost);

        // Map opener/acceptor to holder/counterparty for this commitment side.
        let (to_local_value, to_remote_value) = if self.holder_is_opener == for_holder {
            (opener_balance, acceptor_balance)
        } else {
            (acceptor_balance, opener_balance)
        };

        let (holder, counterparty) = if self.holder_is_opener == for_holder {
            (&self.opener, &self.acceptor)
        } else {
            (&self.acceptor, &self.opener)
        };

        let mut outputs: Vec<TxOut> = Vec::new();

        if to_local_value >= holder.dust_limit_satoshis {
            let local_delayedpubkey = derive_pubkey(
                &holder.delayed_payment_basepoint,
                &holder.per_commitment_point,
            );
            let revocationpubkey = derive_revocation_pubkey(
                &counterparty.revocation_basepoint,
                &holder.per_commitment_point,
            );

            let to_local_spk = build_to_local_scriptpubkey(
                &local_delayedpubkey,
                &revocationpubkey,
                counterparty.to_self_delay,
            );

            outputs.push(TxOut {
                value: Amount::from_sat(to_local_value),
                script_pubkey: to_local_spk,
            });

            if anchor {
                outputs.push(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&holder.funding_pubkey),
                });
            }
        }
        if to_remote_value >= holder.dust_limit_satoshis {
            let to_remote_spk =
                build_to_remote_scriptpubkey(&counterparty.payment_basepoint, anchor);

            outputs.push(TxOut {
                value: Amount::from_sat(to_remote_value),
                script_pubkey: to_remote_spk,
            });

            if anchor {
                outputs.push(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&counterparty.funding_pubkey),
                });
            }
        }

        // BOLT 3 output ordering: sort by (value, script_pubkey).
        outputs.sort_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then_with(|| a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()))
        });

        outputs
    }
}

/// Checks whether the opener can afford the commitment fee at the given
/// feerate, after accounting for the pushed amount and anchor outputs.
#[must_use]
#[allow(clippy::similar_names)]
pub fn can_opener_afford_feerate(
    funding_satoshis: u64,
    push_msat: u64,
    feerate_per_kw: u32,
    channel_type: &[u8],
) -> bool {
    let anchor = supports_option_anchors(channel_type);
    let commitment_weight = if anchor {
        COMMITMENT_WEIGHT_ANCHOR
    } else {
        COMMITMENT_WEIGHT_NON_ANCHOR
    };
    let fee = u64::from(feerate_per_kw) * commitment_weight / 1000;
    let anchor_cost = if anchor { 2 * ANCHOR_OUTPUT_VALUE } else { 0 };
    let push_sat = push_msat / 1000;

    funding_satoshis
        .checked_sub(push_sat)
        .and_then(|balance| balance.checked_sub(fee))
        .and_then(|balance| balance.checked_sub(anchor_cost))
        .is_some()
}

/// Computes the commitment number obscuring factor per BOLT 3.
fn compute_obscuring_factor(
    opener_payment_basepoint: &PublicKey,
    acceptor_payment_basepoint: &PublicKey,
) -> u64 {
    let mut sha = sha256::Hash::engine();

    sha.input(&opener_payment_basepoint.serialize());
    sha.input(&acceptor_payment_basepoint.serialize());
    let hash = sha256::Hash::from_engine(sha).to_byte_array();

    let mut buf = [0u8; 8];
    buf[2..].copy_from_slice(&hash[26..32]);
    u64::from_be_bytes(buf)
}

/// Checks whether `option_anchors` (BOLT 9, bits 22/23) is set in a
/// big-endian `channel_type` feature bitfield.
///
/// Per BOLT 9, even bit (22) = required, odd bit (23) = optional.
/// Either bit indicates anchor support.
fn supports_option_anchors(channel_type: &[u8]) -> bool {
    let byte_offset = OPTION_ANCHORS_EVEN_BIT / 8;
    let len = channel_type.len();
    if len <= byte_offset {
        return false;
    }

    let required_mask = 1 << (OPTION_ANCHORS_EVEN_BIT % 8);
    let optional_mask = 1 << (OPTION_ANCHORS_ODD_BIT % 8);

    channel_type[len - 1 - byte_offset] & (required_mask | optional_mask) != 0
}

/// Derives a public key from a basepoint and per-commitment point per BOLT 3.
fn derive_pubkey(basepoint: &PublicKey, per_commitment_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let mut sha = sha256::Hash::engine();

    sha.input(&per_commitment_point.serialize());
    sha.input(&basepoint.serialize());
    let tweak = sha256::Hash::from_engine(sha).to_byte_array();
    let hashkey = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&tweak).expect("SHA256 output is a valid secret key"),
    );

    basepoint
        .combine(&hashkey)
        .expect("point addition of two valid pubkeys cannot produce infinity")
}

/// Derives the `revocationpubkey` per BOLT 3.
fn derive_revocation_pubkey(
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let rev_append_commit_hash_key = {
        let mut sha = sha256::Hash::engine();
        sha.input(&revocation_basepoint.serialize());
        sha.input(&per_commitment_point.serialize());

        sha256::Hash::from_engine(sha).to_byte_array()
    };

    let commit_append_rev_hash_key = {
        let mut sha = sha256::Hash::engine();
        sha.input(&per_commitment_point.serialize());
        sha.input(&revocation_basepoint.serialize());

        sha256::Hash::from_engine(sha).to_byte_array()
    };

    let revocation_contrib = revocation_basepoint
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(rev_append_commit_hash_key)
                .expect("SHA256 output is a valid scalar"),
        )
        .expect("scalar multiplication of a valid pubkey cannot fail");

    let commitment_contrib = per_commitment_point
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(commit_append_rev_hash_key)
                .expect("SHA256 output is a valid scalar"),
        )
        .expect("scalar multiplication of a valid pubkey cannot fail");

    revocation_contrib
        .combine(&commitment_contrib)
        .expect("point addition of two valid pubkeys cannot produce infinity")
}

/// Builds the `to_local` P2WSH `script_pubkey` per BOLT 3.
fn build_to_local_scriptpubkey(
    local_delayedpubkey: &PublicKey,
    revocationpubkey: &PublicKey,
    to_self_delay: u16,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(opcodes::OP_IF)
        .push_slice(revocationpubkey.serialize())
        .push_opcode(opcodes::OP_ELSE)
        .push_int(i64::from(to_self_delay))
        .push_opcode(opcodes::OP_CSV)
        .push_opcode(opcodes::OP_DROP)
        .push_slice(local_delayedpubkey.serialize())
        .push_opcode(opcodes::OP_ENDIF)
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
        .to_p2wsh()
}

/// Builds the `to_remote` output `script_pubkey` per BOLT 3.
///
/// With `option_anchors`, the output is P2WSH with a 1-block CSV lock.
/// Without anchors, it is a simple P2WPKH to the remote payment basepoint.
fn build_to_remote_scriptpubkey(payment_basepoint: &PublicKey, anchor: bool) -> ScriptBuf {
    if anchor {
        Builder::new()
            .push_slice(payment_basepoint.serialize())
            .push_opcode(opcodes::OP_CHECKSIGVERIFY)
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_CSV)
            .into_script()
            .to_p2wsh()
    } else {
        ScriptBuf::new_p2wpkh(&CompressedPublicKey(*payment_basepoint).wpubkey_hash())
    }
}

/// Builds the anchor output P2WSH `script_pubkey` per BOLT 3.
fn build_anchor_scriptpubkey(funding_pubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_slice(funding_pubkey.serialize())
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_IFDUP)
        .push_opcode(opcodes::OP_NOTIF)
        .push_opcode(opcodes::OP_PUSHNUM_16)
        .push_opcode(opcodes::OP_CSV)
        .push_opcode(opcodes::OP_ENDIF)
        .into_script()
        .to_p2wsh()
}

/// Builds the funding output redeem script per BOLT 3.
fn build_funding_redeemscript(pubkey1: &PublicKey, pubkey2: &PublicKey) -> ScriptBuf {
    let key1_bytes = pubkey1.serialize();
    let key2_bytes = pubkey2.serialize();
    let (lesser, greater) = if key1_bytes < key2_bytes {
        (&key1_bytes, &key2_bytes)
    } else {
        (&key2_bytes, &key1_bytes)
    };
    Builder::new()
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_slice(lesser)
        .push_slice(greater)
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_opcode(opcodes::OP_CHECKMULTISIG)
        .into_script()
}

/// Signs a commitment sighash with the given funding private key.
fn sign(sighash: &[u8; 32], funding_privkey: &SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.sign_ecdsa(&msg, funding_privkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(hex_str: &str) -> PublicKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        PublicKey::from_slice(&bytes).expect("valid pubkey")
    }

    fn secret(hex_str: &str) -> SecretKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        SecretKey::from_slice(&bytes).expect("valid secret key")
    }

    fn der_sig(hex_str: &str) -> Signature {
        let bytes = hex::decode(hex_str).expect("valid hex");
        Signature::from_der(&bytes).expect("valid DER signature")
    }

    /// BOLT 3 Appendix C opener (local) funding private key.
    const OPENER_FUNDING_PRIVKEY: &str =
        "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749";

    /// BOLT 3 Appendix C acceptor (remote) funding private key.
    const ACCEPTOR_FUNDING_PRIVKEY: &str =
        "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13";

    #[test]
    fn obscuring_factor() {
        let opener_payment_basepoint =
            pubkey("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        let acceptor_payment_basepoint =
            pubkey("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
        let factor =
            compute_obscuring_factor(&opener_payment_basepoint, &acceptor_payment_basepoint);
        assert_eq!(factor, 0x2bb0_3852_1914);
    }

    #[test]
    fn supports_option_anchors_detection() {
        // Required (bit 22), optional (bit 23).
        assert!(supports_option_anchors(&[0x40, 0x00, 0x00]));
        assert!(supports_option_anchors(&[0x80, 0x00, 0x00]));
        // No support.
        assert!(!supports_option_anchors(&[0x00, 0x00, 0x40]));
        assert!(!supports_option_anchors(&[0x00, 0x00, 0x80]));
        assert!(!supports_option_anchors(&[]));
        assert!(!supports_option_anchors(&[0xff, 0xff]));
        assert!(!supports_option_anchors(&[0x00, 0x10]));
    }

    // BOLT 3 Appendix B: Funding Transaction Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-b-funding-transaction-test-vectors

    #[test]
    fn funding_redeemscript_is_key_order_independent() {
        let local_funding_pubkey =
            pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
        let remote_funding_pubkey =
            pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");

        let funding_redeemscript_1 =
            build_funding_redeemscript(&local_funding_pubkey, &remote_funding_pubkey);
        let funding_redeemscript_2 =
            build_funding_redeemscript(&remote_funding_pubkey, &local_funding_pubkey);

        // Argument order must not matter as keys are sorted lexicographically.
        assert_eq!(funding_redeemscript_1, funding_redeemscript_2);

        assert_eq!(
            hex::encode(funding_redeemscript_1.as_bytes()),
            "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae",
        );
    }

    // BOLT 3 Appendix C: Commitment and HTLC Transaction Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-c-commitment-and-htlc-transaction-test-vectors

    fn bolt3_commitment_params(
        feerate_per_kw: u32,
        push_msat: u64,
        channel_type: Vec<u8>,
    ) -> CommitmentParams {
        CommitmentParams {
            commitment_number: 42,
            holder_is_opener: true,
            funding_outpoint: OutPoint {
                txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                    .parse()
                    .expect("valid funding txid hex"),
                vout: 0,
            },
            feerate_per_kw,
            funding_satoshis: 10_000_000,
            push_msat,
            holder_funding_privkey: secret(OPENER_FUNDING_PRIVKEY),
            opener: ChannelPartyParams {
                funding_pubkey: pubkey(
                    "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
                ),
                payment_basepoint: pubkey(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ),
                revocation_basepoint: pubkey(
                    "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19",
                ),
                delayed_payment_basepoint: pubkey(
                    "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                ),
                per_commitment_point: pubkey(
                    "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
                ),
                dust_limit_satoshis: 546,
                to_self_delay: 144,
            },
            acceptor: ChannelPartyParams {
                funding_pubkey: pubkey(
                    "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1",
                ),
                payment_basepoint: pubkey(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                ),
                revocation_basepoint: pubkey(
                    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                ),
                delayed_payment_basepoint: pubkey(
                    "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                ),
                per_commitment_point: pubkey(
                    "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
                ),
                dust_limit_satoshis: 546,
                to_self_delay: 144,
            },
            channel_type,
        }
    }

    #[test]
    fn simple_commitment_tx_with_no_htlcs_legacy() {
        let opener_params = bolt3_commitment_params(15_000, 3_000_000_000, vec![]);

        // Holder signs own commitment.
        assert_eq!(
            hex::encode(opener_params.holder_commitment_signature().serialize_der()),
            "30440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae055647142",
        );

        // Counterparty signs holder's commitment.
        let remote_signature = der_sig(
            "3045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b0",
        );
        assert!(opener_params.verify_received_commitment_signature(&remote_signature));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig = opener_params.counterparty_commitment_signature();
        let acceptor_params = CommitmentParams {
            holder_is_opener: false,
            holder_funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            ..bolt3_commitment_params(15_000, 3_000_000_000, vec![])
        };
        assert!(acceptor_params.verify_received_commitment_signature(&acceptor_commit_sig));
    }

    #[test]
    fn simple_commitment_tx_with_no_htlcs_and_single_local_output_legacy() {
        let opener_params = bolt3_commitment_params(15_000, 0, vec![]);

        // Holder signs own commitment.
        assert_eq!(
            hex::encode(opener_params.holder_commitment_signature().serialize_der()),
            "304402202a88d662baa98fbb8eba613c0dbc4f76ee285d5753081f4b934f4cd13b39342a022067dee9c527d05d20037de95b333476e57261cf9fb9ab936e97ce57f4f27f442d",
        );

        // Counterparty signs holder's commitment.
        let remote_signature = der_sig(
            "3045022100a01b8a4d1ba99291120e41f318092758f83975513c038fcff546fb309760ed1e022070aaf47b335092f6fb0ee2a65c1a18d3999010a63412c9dbbb088c05350391b9",
        );
        assert!(opener_params.verify_received_commitment_signature(&remote_signature));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig = opener_params.counterparty_commitment_signature();
        let acceptor_params = CommitmentParams {
            holder_is_opener: false,
            holder_funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            ..bolt3_commitment_params(15_000, 0, vec![])
        };
        assert!(acceptor_params.verify_received_commitment_signature(&acceptor_commit_sig));
    }

    #[test]
    fn simple_commitment_tx_with_no_htlcs_and_single_remote_output_legacy() {
        let opener_params = bolt3_commitment_params(9_667_817, 3_000_000_000, vec![]);

        // Holder signs own commitment.
        assert_eq!(
            hex::encode(opener_params.holder_commitment_signature().serialize_der()),
            "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
        );

        // Counterparty signs holder's commitment.
        let remote_signature = der_sig(
            "304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
        );
        assert!(opener_params.verify_received_commitment_signature(&remote_signature));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig = opener_params.counterparty_commitment_signature();
        let acceptor_params = CommitmentParams {
            holder_is_opener: false,
            holder_funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            ..bolt3_commitment_params(9_667_817, 3_000_000_000, vec![])
        };
        assert!(acceptor_params.verify_received_commitment_signature(&acceptor_commit_sig));
    }

    // BOLT 3 Appendix F: Commitment and HTLC Transaction Test Vectors (anchors)
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-f-commitment-and-htlc-transaction-test-vectors-anchors

    #[test]
    fn simple_commitment_tx_with_no_htlcs_anchor() {
        let opener_params = bolt3_commitment_params(15_000, 3_000_000_000, vec![0x40, 0x00, 0x00]);

        // Holder signs own commitment.
        assert_eq!(
            hex::encode(opener_params.holder_commitment_signature().serialize_der()),
            "30450221008266ac6db5ea71aac3c95d97b0e172ff596844851a3216eb88382a8dddfd33d2022050e240974cfd5d708708b4365574517c18e7ae535ef732a3484d43d0d82be9f7",
        );

        // Counterparty signs holder's commitment.
        let remote_signature = der_sig(
            "3045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f3",
        );
        assert!(opener_params.verify_received_commitment_signature(&remote_signature));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig = opener_params.counterparty_commitment_signature();
        let acceptor_params = CommitmentParams {
            holder_is_opener: false,
            holder_funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            ..bolt3_commitment_params(15_000, 3_000_000_000, vec![0x40, 0x00, 0x00])
        };
        assert!(acceptor_params.verify_received_commitment_signature(&acceptor_commit_sig));
    }

    #[test]
    fn simple_commitment_tx_with_no_htlcs_and_single_local_output_anchor() {
        let opener_params = bolt3_commitment_params(15_000, 0, vec![0x40, 0x00, 0x00]);

        // Holder signs own commitment.
        assert_eq!(
            hex::encode(opener_params.holder_commitment_signature().serialize_der()),
            "3044022007cf6b405e9c9b4f527b0ecad9d8bb661fabb8b12abf7d1c0b3ad1855db3ed490220616d5c1eeadccc63bd775a131149455d62d95a42c2a1b01cc7821fc42dce7778",
        );

        // Counterparty signs holder's commitment.
        let remote_signature = der_sig(
            "30440220655bf909fb6fa81d086f1336ac72c97906dce29d1b166e305c99152d810e26e1022051f577faa46412c46707aaac46b65d50053550a66334e00a44af2706f27a8658",
        );
        assert!(opener_params.verify_received_commitment_signature(&remote_signature));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig = opener_params.counterparty_commitment_signature();
        let acceptor_params = CommitmentParams {
            holder_is_opener: false,
            holder_funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            ..bolt3_commitment_params(15_000, 0, vec![0x40, 0x00, 0x00])
        };
        assert!(acceptor_params.verify_received_commitment_signature(&acceptor_commit_sig));
    }

    #[test]
    fn simple_commitment_tx_with_no_htlcs_and_single_remote_output_anchor() {
        let opener_params =
            bolt3_commitment_params(9_667_817, 3_000_000_000, vec![0x40, 0x00, 0x00]);

        // Holder signs own commitment.
        assert_eq!(
            hex::encode(opener_params.holder_commitment_signature().serialize_der()),
            "30450221009ad80792e3038fe6968d12ff23e6888a565c3ddd065037f357445f01675d63f3022018384915e5f1f4ae157e15debf4f49b61c8d9d2b073c7d6f97c4a68caa3ed4c1",
        );

        // Counterparty signs holder's commitment.
        let remote_signature = der_sig(
            "30450221008fd5dbff02e4b59020d4cd23a3c30d3e287065fda75a0a09b402980adf68ccda022001e0b8b620cd915ddff11f1de32addf23d81d51b90e6841b2cb8dcaf3faa5ecf",
        );
        assert!(opener_params.verify_received_commitment_signature(&remote_signature));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig = opener_params.counterparty_commitment_signature();
        let acceptor_params = CommitmentParams {
            holder_is_opener: false,
            holder_funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            ..bolt3_commitment_params(9_667_817, 3_000_000_000, vec![0x40, 0x00, 0x00])
        };
        assert!(acceptor_params.verify_received_commitment_signature(&acceptor_commit_sig));
    }

    // BOLT 3 Appendix E: Key Derivation Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-e-key-derivation-test-vectors

    #[test]
    fn derive_pubkey_from_basepoint() {
        let basepoint =
            pubkey("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point =
            pubkey("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let localpubkey = derive_pubkey(&basepoint, &per_commitment_point);
        assert_eq!(
            localpubkey,
            pubkey("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"),
        );
    }

    #[test]
    fn derive_revocation_pubkey_from_basepoint() {
        let revocation_basepoint =
            pubkey("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point =
            pubkey("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let revocationpubkey =
            derive_revocation_pubkey(&revocation_basepoint, &per_commitment_point);
        assert_eq!(
            revocationpubkey,
            pubkey("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"),
        );
    }

    #[test]
    fn can_opener_afford_feerate_checks() {
        let anchors = &[0x40u8, 0x00, 0x00][..];
        let legacy = &[][..];
        let feerate_per_kw: u32 = 15_000;
        // Legacy fee: 15000 * 724 / 1000 = 10_860 sat
        // Anchor fee: 15000 * 1124 / 1000 = 16_860 sat; anchor_cost = 660 sat

        // Comfortably affordable
        assert!(can_opener_afford_feerate(20_000, 0, feerate_per_kw, legacy));

        // Exact zero opener balance
        assert!(can_opener_afford_feerate(
            11_860,
            1_000_000,
            feerate_per_kw,
            legacy
        ));

        // Fails: push alone exceeds funding
        assert!(!can_opener_afford_feerate(
            1_000,
            2_000_000,
            feerate_per_kw,
            legacy
        ));

        // Fails: push fits but fee does not
        assert!(!can_opener_afford_feerate(
            10_000,
            0,
            feerate_per_kw,
            legacy
        ));

        // Fails: push + fee fit but anchor cost does not
        assert!(!can_opener_afford_feerate(
            17_500,
            0,
            feerate_per_kw,
            anchors
        ));
    }
}
