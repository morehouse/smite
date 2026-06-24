//! BOLT 3 commitment transaction construction and signing.

use super::funding::build_funding_witness_script;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};

/// Anchor output value in satoshis.
const ANCHOR_OUTPUT_VALUE: u64 = 330;

/// Weight of a non-anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR: u64 = 724;

/// Weight of an anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_ANCHOR: u64 = 1124;

/// Additional commitment weight per non-trimmed HTLC output.
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;

/// Weight of an HTLC-timeout transaction on a non-anchor channel.
const HTLC_TIMEOUT_TX_WEIGHT_NON_ANCHOR: u64 = 663;

/// Weight of an HTLC-success transaction on a non-anchor channel.
const HTLC_SUCCESS_TX_WEIGHT_NON_ANCHOR: u64 = 703;

/// `option_anchors` feature bits (BOLT 9, bits 22/23).
const OPTION_ANCHORS_FEATURE_BITS: &[usize] = &[22, 23];

/// Errors that can occur when constructing or validating commitment transactions.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    /// Funding amount overflowed when converting to millisatoshis.
    #[error("funding_satoshis overflowed when converting to msat")]
    FundingMsatOverflow,

    /// Push amount exceeds the total funding amount.
    #[error("push_msat exceeds funding_msat")]
    PushExceedsFunding,

    /// Adding an HTLC would underflow the offerer's balance.
    #[error("htlc amount exceeds offerer's balance")]
    HtlcExceedsBalance,

    /// No in-flight HTLC matched the given id and offerer.
    #[error("htlc with the given id and offerer was not found")]
    HtlcNotFound,
}

/// Identifies the channel participant relative to the funding flow.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Opener,
    Acceptor,
}

/// Holder's identity and funding secret for the commitment.
pub struct HolderIdentity {
    /// Whether the holder is the channel opener or acceptor.
    pub side: Side,
    /// Holder's funding private key.
    pub funding_privkey: SecretKey,
    /// Holder's HTLC basepoint private key.
    pub htlc_basepoint_privkey: SecretKey,
}

/// Static public keys and channel parameters for one side of a channel (opener or acceptor).
pub struct ChannelPartyConfig {
    /// Funding pubkey used in the funding output.
    pub funding_pubkey: PublicKey,
    /// Payment basepoint used to derive the `to_remote` output key.
    pub payment_basepoint: PublicKey,
    /// Revocation basepoint used to derive keys that allow punishment of old states.
    pub revocation_basepoint: PublicKey,
    /// Delayed payment basepoint used to derive the time-locked `to_local` output key.
    pub delayed_payment_basepoint: PublicKey,
    /// HTLC basepoint used to derive HTLC keys.
    pub htlc_basepoint: PublicKey,
    /// Minimum output value below which outputs are trimmed as dust.
    pub dust_limit_satoshis: u64,
    /// CSV delay this party imposes on the other's `to_local` output.
    pub to_self_delay: u16,
}

/// Channel configuration including funding details and both parties configuration.
pub struct ChannelConfig {
    /// Funding transaction outpoint.
    pub funding_outpoint: OutPoint,
    /// Total channel funding amount in satoshis.
    pub funding_satoshis: u64,
    /// Channel type feature bits. The commitment format (anchor / legacy) is
    /// derived from the bits set here.
    pub channel_type: Vec<u8>,
    /// Opener's static keys and parameters.
    pub opener: ChannelPartyConfig,
    /// Acceptor's static keys and parameters.
    pub acceptor: ChannelPartyConfig,
    /// Minimum funding confirmations required before `channel_ready` messages
    /// are exchanged and the channel becomes active.
    pub minimum_depth: u32,
}

/// An in-flight HTLC that appears (subject to dust trimming) as an output in
/// the commitment transaction.
#[derive(Clone, Copy)]
pub struct Htlc {
    /// HTLC ID, unique per channel and offering direction.
    id: u64,
    /// The party that offered this HTLC.
    ///
    /// Combined with the commitment owner, this determines whether the HTLC
    /// is treated as an "offered" or "received" output.
    pub offerer: Side,
    /// HTLC amount in millisatoshis.
    pub amount_msat: u64,
    /// The expiry height of the HTLC.
    pub cltv_expiry: u32,
    /// `SHA256` of the payment preimage.
    pub payment_hash: [u8; 32],
}

/// Per-party parameters used in a commitment transaction.
pub struct CommitmentPartyState {
    /// Per-commitment point used to derive all commitment-specific keys.
    pub per_commitment_point: PublicKey,

    /// Amount allocated to this party in millisatoshis.
    /// Represents the balance before subtraction of fees, and anchors outputs.
    /// In-flight HTLCs are represented as separate outputs in the commitment
    /// transaction, so those values are already deducted from these balance values.
    pub balance_msat: u64,
}

/// Parameters for building a commitment transaction.
pub struct CommitmentState {
    /// The commitment transaction number.
    pub commitment_number: u64,
    /// Fee rate for the commitment transaction.
    pub feerate_per_kw: u32,
    /// Parameters for the channel opener.
    pub opener: CommitmentPartyState,
    /// Parameters for the channel acceptor.
    pub acceptor: CommitmentPartyState,
    /// In-flight HTLCs offered in either direction.
    pub htlcs: Vec<Htlc>,
}

/// Per-commitment keys used when constructing and signing a commitment
/// transaction from the local party's perspective.
struct TxCreationKeys {
    /// The per-commitment point used to derive the commitment-specific keys.
    #[allow(dead_code)]
    per_commitment_point: PublicKey,
    /// Local delayed payment pubkey.
    local_delayedpubkey: PublicKey,
    /// Revocation pubkey for this commitment.
    revocationpubkey: PublicKey,
    /// Local per-commitment HTLC pubkey.
    local_htlcpubkey: PublicKey,
    /// Remote per-commitment HTLC pubkey.
    remote_htlcpubkey: PublicKey,
}

/// A fully built commitment transaction with the metadata needed to construct
/// and sign its second-stage HTLC transactions.
struct BuiltCommitmentTx {
    /// Per-commitment keys for the local side.
    #[allow(dead_code)]
    keys: TxCreationKeys,
    /// The assembled commitment transaction.
    tx: Transaction,
}

/// State of a single channel, including its static configuration, holder
/// identity, and current commitment state.
pub struct ChannelState {
    /// Channel configuration established at channel creation and unchanged
    /// for the lifetime of the channel.
    pub config: ChannelConfig,
    /// Holder-specific identity data (channel side and funding secret) used to
    /// sign commitment transactions and verify the counterparty's signatures.
    pub holder: HolderIdentity,
    /// Current commitment state, updated as commitments are exchanged and
    /// revoked.
    pub commitment: CommitmentState,
    /// Opener's next per-commitment point used to build its next commitment,
    /// revealed by `channel_ready` and then each `revoke_and_ack`. `None` until
    /// known.
    pub opener_next_per_commitment_point: Option<PublicKey>,
    /// Acceptor's next per-commitment point used to build its next commitment,
    /// revealed by `channel_ready` and then each `revoke_and_ack`. `None` until
    /// known.
    pub acceptor_next_per_commitment_point: Option<PublicKey>,
    /// Whether the on-chain output at the advertised funding outpoint matches
    /// the negotiated funding script and amount.
    pub is_funding_outpoint_valid: bool,
    /// Whether the funding transaction was already mined when we sent
    /// `funding_created`. Some targets only watch for the funding confirmation
    /// after the block height at which they receive `funding_created`, so they
    /// may never observe it and never send `channel_ready`.
    pub was_funding_mined_prematurely: bool,
}

impl Side {
    /// Returns the counterparty side.
    fn other(self) -> Self {
        match self {
            Self::Opener => Self::Acceptor,
            Self::Acceptor => Self::Opener,
        }
    }
}

impl HolderIdentity {
    /// Returns the counterparty side.
    #[must_use]
    fn counterparty_side(&self) -> Side {
        self.side.other()
    }
}

impl ChannelState {
    /// Constructs a channel state with both next per-commitment points unknown.
    #[must_use]
    pub fn new(
        config: ChannelConfig,
        holder: HolderIdentity,
        commitment: CommitmentState,
        is_funding_outpoint_valid: bool,
        was_funding_mined_prematurely: bool,
    ) -> Self {
        Self {
            config,
            holder,
            commitment,
            opener_next_per_commitment_point: None,
            acceptor_next_per_commitment_point: None,
            is_funding_outpoint_valid,
            was_funding_mined_prematurely,
        }
    }

    /// Returns the holder's next per-commitment point.
    #[must_use]
    pub fn next_holder_per_commitment_point(&self) -> &Option<PublicKey> {
        match self.holder.side {
            Side::Opener => &self.opener_next_per_commitment_point,
            Side::Acceptor => &self.acceptor_next_per_commitment_point,
        }
    }

    /// Returns a mutable reference to the holder's next per-commitment point.
    pub fn next_holder_per_commitment_point_mut(&mut self) -> &mut Option<PublicKey> {
        match self.holder.side {
            Side::Opener => &mut self.opener_next_per_commitment_point,
            Side::Acceptor => &mut self.acceptor_next_per_commitment_point,
        }
    }

    /// Returns the counterparty's next per-commitment point.
    #[must_use]
    pub fn next_counterparty_per_commitment_point(&self) -> &Option<PublicKey> {
        match self.holder.side.other() {
            Side::Opener => &self.opener_next_per_commitment_point,
            Side::Acceptor => &self.acceptor_next_per_commitment_point,
        }
    }

    /// Returns a mutable reference to the counterparty's next per-commitment
    /// point.
    pub fn next_counterparty_per_commitment_point_mut(&mut self) -> &mut Option<PublicKey> {
        match self.holder.side.other() {
            Side::Opener => &mut self.opener_next_per_commitment_point,
            Side::Acceptor => &mut self.acceptor_next_per_commitment_point,
        }
    }
}

impl ChannelConfig {
    /// Returns the config for the given channel side.
    fn party(&self, side: Side) -> &ChannelPartyConfig {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Constructs the initial commitment state after channel funding.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`CommitmentError::FundingMsatOverflow`] if `funding_satoshis` overflows when
    ///   converting to millisatoshis.
    /// - [`CommitmentError::PushExceedsFunding`] if `push_msat` exceeds the total
    ///   funding amount in millisatoshis.
    pub fn new_initial_commitment(
        &self,
        push_msat: u64,
        feerate_per_kw: u32,
        opener_per_commitment_point: PublicKey,
        acceptor_per_commitment_point: PublicKey,
    ) -> Result<CommitmentState, CommitmentError> {
        let funding_msat = self
            .funding_satoshis
            .checked_mul(1000)
            .ok_or(CommitmentError::FundingMsatOverflow)?;
        let to_opener_balance_msat = funding_msat
            .checked_sub(push_msat)
            .ok_or(CommitmentError::PushExceedsFunding)?;
        let to_acceptor_balance_msat = push_msat;

        Ok(CommitmentState {
            commitment_number: 0,
            feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: opener_per_commitment_point,
                balance_msat: to_opener_balance_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: acceptor_per_commitment_point,
                balance_msat: to_acceptor_balance_msat,
            },
            htlcs: Vec::new(),
        })
    }

    /// Checks whether the opener can afford the commitment fee at the given
    /// feerate, after accounting for the non-dust HTLCs and the anchor outputs.
    #[must_use]
    pub fn can_opener_afford_feerate(&self, state: &CommitmentState, local_side: Side) -> bool {
        let nondust_htlc_count = state
            .htlcs
            .iter()
            .filter(|htlc| {
                !htlc.is_dust(
                    self.party(local_side).dust_limit_satoshis,
                    state.feerate_per_kw,
                    &self.channel_type,
                    local_side,
                )
            })
            .count();
        let fee = commit_tx_fee_sat(state.feerate_per_kw, nondust_htlc_count, &self.channel_type);
        let anchor_cost = total_anchors_sat(&self.channel_type);

        (state.opener.balance_msat / 1000)
            .checked_sub(fee)
            .and_then(|balance| balance.checked_sub(anchor_cost))
            .is_some()
    }

    /// Builds the signature for the counterparty's commitment transaction.
    #[must_use]
    pub fn sign_counterparty_commitment(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> Signature {
        let commitment = self.build_commitment_tx(state, holder.counterparty_side());
        self.sign_commitment_tx(&commitment, &holder.funding_privkey)
    }

    /// Verifies the counterparty's signatures on the holder's commitment
    /// transaction.
    #[must_use]
    pub fn verify_counterparty_signature(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
        commit_sig: &Signature,
    ) -> bool {
        let commitment = self.build_commitment_tx(state, holder.side);
        self.verify_commit_sig(&commitment, holder, commit_sig)
    }

    /// Builds the signature for the holder's commitment transaction.
    /// Only used to exercise BOLT 3 test vectors.
    #[cfg(test)]
    fn sign_holder_commitment(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> Signature {
        let commitment = self.build_commitment_tx(state, holder.side);
        self.sign_commitment_tx(&commitment, &holder.funding_privkey)
    }

    /// Builds the commitment transaction. The commitment format (legacy or
    /// anchor) is determined by the `channel_type`.
    ///
    /// `local_side` selects whose commitment is built: the opener's or
    /// the acceptor's.
    fn build_commitment_tx(&self, state: &CommitmentState, local_side: Side) -> BuiltCommitmentTx {
        // Obscured commitment number.
        let obscuring_factor = compute_obscuring_factor(
            &self.opener.payment_basepoint,
            &self.acceptor.payment_basepoint,
        );
        let obscured_commitment_number = state.commitment_number ^ obscuring_factor;

        // Upper 8 bits of sequence are 0x80 and lower 24 bits are the upper 24 bits
        // of the obscured commitment number.
        let sequence = (0x80u32 << (8 * 3))
            | u32::try_from(obscured_commitment_number >> 24)
                .expect("commitment_number cannot be more than 48 bits");

        // Upper 8 bits of locktime are 0x20 and lower 24 bits are the lower 24 bits
        // of the obscured commitment number.
        let locktime = (0x20u32 << (8 * 3))
            | u32::try_from(obscured_commitment_number & 0x00ff_ffff_u64)
                .expect("commitment_number cannot be more than 48 bits");

        // Build the commitment transaction
        let keys = self.derive_commitment_keys(state, local_side);
        let outputs = self.build_commitment_outputs(state, &keys, local_side);

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

        BuiltCommitmentTx { keys, tx }
    }

    /// Builds the sighash for the given commitment transaction.
    fn build_commitment_sighash(&self, tx: &Transaction) -> [u8; 32] {
        // Funding output witness script.
        let funding_witness_script = build_funding_witness_script(
            &self.opener.funding_pubkey,
            &self.acceptor.funding_pubkey,
        );

        // Compute the BIP143 sighash
        let sighash = SighashCache::new(tx)
            .p2wsh_signature_hash(
                0,
                &funding_witness_script,
                Amount::from_sat(self.funding_satoshis),
                EcdsaSighashType::All,
            )
            .expect("input index 0 is always in bounds for a single input transaction");

        sighash.to_byte_array()
    }

    /// Builds the lexicographically sorted commitment outputs.
    ///
    /// `local_side` selects whose commitment outputs are built: the
    /// opener's or the acceptor's.
    fn build_commitment_outputs(
        &self,
        state: &CommitmentState,
        keys: &TxCreationKeys,
        local_side: Side,
    ) -> Vec<TxOut> {
        let anchor = supports_option_anchors(&self.channel_type);
        let mut outputs: Vec<TxOut> = Vec::new();

        // Fee and balances.
        let fee = commit_tx_fee_sat(state.feerate_per_kw, 0, &self.channel_type);
        let anchor_cost = total_anchors_sat(&self.channel_type);

        let acceptor_balance = state.acceptor.balance_msat / 1000;
        let opener_balance = (state.opener.balance_msat / 1000)
            .saturating_sub(fee)
            .saturating_sub(anchor_cost);

        // Map opener/acceptor to local/remote for this commitment side.
        let (to_local_value, to_remote_value) = match local_side {
            Side::Opener => (opener_balance, acceptor_balance),
            Side::Acceptor => (acceptor_balance, opener_balance),
        };
        let local = self.party(local_side);
        let remote = self.party(local_side.other());

        if to_local_value >= local.dust_limit_satoshis {
            let to_local_spk = build_revocable_scriptpubkey(
                &keys.local_delayedpubkey,
                &keys.revocationpubkey,
                remote.to_self_delay,
            );

            outputs.push(TxOut {
                value: Amount::from_sat(to_local_value),
                script_pubkey: to_local_spk,
            });
        }
        if to_remote_value >= local.dust_limit_satoshis {
            let to_remote_spk = build_to_remote_scriptpubkey(&remote.payment_basepoint, anchor);

            outputs.push(TxOut {
                value: Amount::from_sat(to_remote_value),
                script_pubkey: to_remote_spk,
            });
        }

        if anchor {
            if to_local_value >= local.dust_limit_satoshis {
                outputs.push(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&local.funding_pubkey),
                });
            }

            if to_remote_value >= local.dust_limit_satoshis {
                outputs.push(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&remote.funding_pubkey),
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

    /// Signs the commitment transaction using the local party's funding private
    /// key.
    fn sign_commitment_tx(
        &self,
        commitment: &BuiltCommitmentTx,
        funding_privkey: &SecretKey,
    ) -> Signature {
        let sighash = self.build_commitment_sighash(&commitment.tx);
        sign(&sighash, funding_privkey)
    }

    /// Verifies the commitment signature against the counterparty's funding
    /// public key.
    fn verify_commit_sig(
        &self,
        commitment: &BuiltCommitmentTx,
        holder: &HolderIdentity,
        commit_sig: &Signature,
    ) -> bool {
        let sighash = self.build_commitment_sighash(&commitment.tx);
        let counterparty = self.party(holder.counterparty_side());
        verify(&sighash, commit_sig, &counterparty.funding_pubkey)
    }

    /// Derives the per-commitment keys for the `local_side`.
    fn derive_commitment_keys(&self, state: &CommitmentState, local_side: Side) -> TxCreationKeys {
        let local = self.party(local_side);
        let remote = self.party(local_side.other());
        let per_commitment_point = state.party(local_side).per_commitment_point;

        TxCreationKeys {
            per_commitment_point,
            local_delayedpubkey: derive_pubkey(
                &local.delayed_payment_basepoint,
                &per_commitment_point,
            ),
            revocationpubkey: derive_revocation_pubkey(
                &remote.revocation_basepoint,
                &per_commitment_point,
            ),
            local_htlcpubkey: derive_pubkey(&local.htlc_basepoint, &per_commitment_point),
            remote_htlcpubkey: derive_pubkey(&remote.htlc_basepoint, &per_commitment_point),
        }
    }
}

impl CommitmentState {
    /// Returns the parameters for the given commitment side.
    fn party(&self, side: Side) -> &CommitmentPartyState {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Returns a mutable reference to the parameters for the given commitment side.
    fn party_mut(&mut self, side: Side) -> &mut CommitmentPartyState {
        match side {
            Side::Opener => &mut self.opener,
            Side::Acceptor => &mut self.acceptor,
        }
    }

    /// Adds `htlc` to the in-flight set, debiting its amount from the offerer's
    /// balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcExceedsBalance`] if the HTLC amount
    /// would underflow the offerer's balance.
    pub fn add_htlc(&mut self, htlc: Htlc) -> Result<(), CommitmentError> {
        let offerer_balance = &mut self.party_mut(htlc.offerer).balance_msat;
        *offerer_balance = offerer_balance
            .checked_sub(htlc.amount_msat)
            .ok_or(CommitmentError::HtlcExceedsBalance)?;
        self.htlcs.push(htlc);
        Ok(())
    }

    /// Settles the in-flight HTLC that `offerer` added with the given `id`,
    /// removing it from the in-flight set and crediting its amount to the
    /// receiver's balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcNotFound`] if no in-flight HTLC matches
    /// `id` and `offerer`.
    pub fn fulfill_htlc(&mut self, id: u64, offerer: Side) -> Result<(), CommitmentError> {
        let pos = self
            .htlcs
            .iter()
            .position(|h| h.id == id && h.offerer == offerer)
            .ok_or(CommitmentError::HtlcNotFound)?;
        let htlc = self.htlcs.remove(pos);
        self.party_mut(htlc.offerer.other()).balance_msat += htlc.amount_msat;
        Ok(())
    }

    /// Fails the in-flight HTLC that `offerer` added with the given `id`,
    /// removing it from the in-flight set and refunding its amount to the
    /// offerer's balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcNotFound`] if no in-flight HTLC matches
    /// `id` and `offerer`.
    pub fn fail_htlc(&mut self, id: u64, offerer: Side) -> Result<(), CommitmentError> {
        let pos = self
            .htlcs
            .iter()
            .position(|h| h.id == id && h.offerer == offerer)
            .ok_or(CommitmentError::HtlcNotFound)?;
        let htlc = self.htlcs.remove(pos);
        self.party_mut(htlc.offerer).balance_msat += htlc.amount_msat;
        Ok(())
    }

    /// Updates the fee rate for the commitment transaction.
    pub fn update_fee(&mut self, feerate_per_kw: u32) {
        self.feerate_per_kw = feerate_per_kw;
    }

    /// Updates the per-commitment point for the given commitment side.
    pub fn update_per_commitment_point(&mut self, side: Side, per_commitment_point: PublicKey) {
        self.party_mut(side).per_commitment_point = per_commitment_point;
    }

    /// Advances the commitment transaction number by one.
    pub fn advance_commitment_number(&mut self) {
        self.commitment_number += 1;
    }
}

impl Htlc {
    /// Returns whether this HTLC is offered on the commitment owned by
    /// `local_side` (otherwise it is received).
    fn is_offered(&self, local_side: Side) -> bool {
        self.offerer == local_side
    }

    /// Returns whether this HTLC would be trimmed from the commitment
    /// transaction due to dust limits.
    fn is_dust(
        &self,
        dust_limit_satoshis: u64,
        feerate_per_kw: u32,
        channel_type: &[u8],
        local_side: Side,
    ) -> bool {
        let stage_fee = htlc_tx_fee_sat(channel_type, feerate_per_kw, self.is_offered(local_side));
        let amount_sat = self.amount_msat / 1000;
        amount_sat < dust_limit_satoshis.saturating_add(stage_fee)
    }

    /// Converts the HTLC amount from millisatoshis to satoshis.
    pub const fn amount(&self) -> Amount {
        Amount::from_sat(self.amount_msat / 1000)
    }
}

/// Get the fee cost of a commitment tx with a given number of HTLC outputs in
/// satoshis.
/// Note that `num_htlcs` should not include dust HTLCs.
fn commit_tx_fee_sat(feerate_per_kw: u32, num_htlcs: usize, channel_type: &[u8]) -> u64 {
    let commitment_base_weight = if supports_option_anchors(channel_type) {
        COMMITMENT_TX_BASE_WEIGHT_ANCHOR
    } else {
        COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR
    };

    let commitment_weight =
        commitment_base_weight + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC;
    u64::from(feerate_per_kw) * commitment_weight / 1000
}

/// Get the anchor cost of a commitment tx in satoshis.
fn total_anchors_sat(channel_type: &[u8]) -> u64 {
    if supports_option_anchors(channel_type) {
        ANCHOR_OUTPUT_VALUE * 2
    } else {
        0
    }
}

/// Get the fee cost of a second-stage HTLC transaction in satoshis.
/// `is_offered` selects between the HTLC-timeout and HTLC-success weights.
fn htlc_tx_fee_sat(channel_type: &[u8], feerate_per_kw: u32, is_offered: bool) -> u64 {
    if supports_option_anchors(channel_type) {
        return 0;
    }

    if is_offered {
        u64::from(feerate_per_kw) * HTLC_TIMEOUT_TX_WEIGHT_NON_ANCHOR / 1000
    } else {
        u64::from(feerate_per_kw) * HTLC_SUCCESS_TX_WEIGHT_NON_ANCHOR / 1000
    }
}

/// Returns `SHA256(pubkey1 || pubkey2)`.
///
/// Both public keys are serialized in compressed form before hashing.
fn hash_pubkeys(pubkey1: &PublicKey, pubkey2: &PublicKey) -> [u8; 32] {
    let mut sha = Sha256::engine();
    sha.input(&pubkey1.serialize());
    sha.input(&pubkey2.serialize());

    Sha256::from_engine(sha).to_byte_array()
}

/// Computes the commitment number obscuring factor per BOLT 3.
fn compute_obscuring_factor(
    opener_payment_basepoint: &PublicKey,
    acceptor_payment_basepoint: &PublicKey,
) -> u64 {
    let hash = hash_pubkeys(opener_payment_basepoint, acceptor_payment_basepoint);

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
    let byte_offset = OPTION_ANCHORS_FEATURE_BITS[0] / 8;
    let len = channel_type.len();
    if len <= byte_offset {
        return false;
    }

    let required_mask = 1 << (OPTION_ANCHORS_FEATURE_BITS[0] % 8);
    let optional_mask = 1 << (OPTION_ANCHORS_FEATURE_BITS[1] % 8);

    channel_type[len - 1 - byte_offset] & (required_mask | optional_mask) != 0
}

/// Derives a public key from a basepoint and per-commitment point per BOLT 3.
fn derive_pubkey(basepoint: &PublicKey, per_commitment_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let tweak = hash_pubkeys(per_commitment_point, basepoint);
    let hashkey = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&tweak).expect("SHA256 output is a valid secret key"),
    );

    basepoint
        .combine(&hashkey)
        .expect("point addition of two valid pubkeys cannot produce infinity")
}

/// Derives a private key from a basepoint secret and a per-commitment point per
/// BOLT 3.
#[allow(dead_code)]
fn derive_privkey(basepoint_secret: &SecretKey, per_commitment_point: &PublicKey) -> SecretKey {
    let secp = Secp256k1::new();
    let basepoint = basepoint_secret.public_key(&secp);
    let tweak = hash_pubkeys(per_commitment_point, &basepoint);
    let scalar = Scalar::from_be_bytes(tweak).expect("SHA256 output is a valid scalar");
    basepoint_secret
        .add_tweak(&scalar)
        .expect("derived HTLC privkey tweak must be valid")
}

/// Derives the `revocationpubkey` per BOLT 3.
fn derive_revocation_pubkey(
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let rev_append_commit_hash_key = hash_pubkeys(revocation_basepoint, per_commitment_point);
    let commit_append_rev_hash_key = hash_pubkeys(per_commitment_point, revocation_basepoint);

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

/// Builds the revocable P2WSH `script_pubkey` per BOLT 3.
/// Used by the `to_local` commitment output and by 2nd-stage HTLC outputs.
fn build_revocable_scriptpubkey(
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

/// Builds the HTLC output witness script per BOLT 3.
///
/// `is_offered` selects between the offered and received HTLC scripts.
#[allow(dead_code)]
fn build_htlc_witness_script(
    htlc: &Htlc,
    keys: &TxCreationKeys,
    is_offered: bool,
    anchor: bool,
) -> ScriptBuf {
    let payment_hash160 = Ripemd160::hash(&htlc.payment_hash[..]).to_byte_array();

    let mut bldr = Builder::new()
        .push_opcode(opcodes::OP_DUP)
        .push_opcode(opcodes::OP_HASH160)
        .push_slice(PubkeyHash::hash(&keys.revocationpubkey.serialize()))
        .push_opcode(opcodes::OP_EQUAL)
        .push_opcode(opcodes::OP_IF)
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_ELSE)
        .push_slice(keys.remote_htlcpubkey.serialize())
        .push_opcode(opcodes::OP_SWAP)
        .push_opcode(opcodes::OP_SIZE)
        .push_int(32)
        .push_opcode(opcodes::OP_EQUAL);

    bldr = if is_offered {
        bldr.push_opcode(opcodes::OP_NOTIF)
            .push_opcode(opcodes::OP_DROP)
            .push_int(2)
            .push_opcode(opcodes::OP_SWAP)
            .push_slice(keys.local_htlcpubkey.serialize())
            .push_int(2)
            .push_opcode(opcodes::OP_CHECKMULTISIG)
            .push_opcode(opcodes::OP_ELSE)
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(payment_hash160)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_opcode(opcodes::OP_CHECKSIG)
            .push_opcode(opcodes::OP_ENDIF)
    } else {
        bldr.push_opcode(opcodes::OP_IF)
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(payment_hash160)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(opcodes::OP_SWAP)
            .push_slice(keys.local_htlcpubkey.serialize())
            .push_int(2)
            .push_opcode(opcodes::OP_CHECKMULTISIG)
            .push_opcode(opcodes::OP_ELSE)
            .push_opcode(opcodes::OP_DROP)
            .push_int(i64::from(htlc.cltv_expiry))
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(opcodes::OP_DROP)
            .push_opcode(opcodes::OP_CHECKSIG)
            .push_opcode(opcodes::OP_ENDIF)
    };

    if anchor {
        bldr = bldr
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_CSV)
            .push_opcode(opcodes::OP_DROP);
    }
    bldr.push_opcode(opcodes::OP_ENDIF).into_script()
}

/// Signs a sighash with the given private key.
fn sign(sighash: &[u8; 32], privkey: &SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.sign_ecdsa(&msg, privkey)
}

/// Verifies that `sig` is a valid signature for `sighash` under `pubkey`.
fn verify(sighash: &[u8; 32], sig: &Signature, pubkey: &PublicKey) -> bool {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.verify_ecdsa(&msg, sig, pubkey).is_ok()
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

    fn bolt3_commitment_params(
        feerate_per_kw: u32,
        to_opener_msat: u64,
        to_acceptor_msat: u64,
        dust_limit_satoshis: u64,
        channel_type: Vec<u8>,
    ) -> (
        ChannelConfig,
        CommitmentState,
        HolderIdentity,
        HolderIdentity,
    ) {
        let chan_config = ChannelConfig {
            funding_outpoint: OutPoint {
                txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                    .parse()
                    .expect("valid funding txid hex"),
                vout: 0,
            },
            funding_satoshis: 10_000_000,
            channel_type,
            opener: ChannelPartyConfig {
                funding_pubkey: pubkey(
                    "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
                ),
                payment_basepoint: pubkey(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ),
                revocation_basepoint: pubkey(
                    "02c6047f9441ed7d6d3045406e95c07cd85a0f5f0f3b9b3f3d5f9b1e5e4a7c4f09",
                ),
                delayed_payment_basepoint: pubkey(
                    "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                ),
                htlc_basepoint: pubkey(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ),
                dust_limit_satoshis,
                to_self_delay: 144,
            },
            acceptor: ChannelPartyConfig {
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
                    "02a1633caf7bf0b7d9e5c4b8a1d6f2e3c4b5a6978877665544332211ffeeddccbb",
                ),
                htlc_basepoint: pubkey(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                ),
                dust_limit_satoshis,
                to_self_delay: 144,
            },
            minimum_depth: 8,
        };

        let state = CommitmentState {
            commitment_number: 42,
            feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: pubkey(
                    "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
                ),
                balance_msat: to_opener_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: pubkey(
                    "03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
                ),
                balance_msat: to_acceptor_msat,
            },
            htlcs: vec![],
        };

        let opener_holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret(OPENER_FUNDING_PRIVKEY),
            htlc_basepoint_privkey: secret(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
        };

        let acceptor_holder = HolderIdentity {
            side: Side::Acceptor,
            funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            htlc_basepoint_privkey: secret(
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        };

        (chan_config, state, opener_holder, acceptor_holder)
    }

    // BOLT 3 Appendix C: Commitment and HTLC Transaction Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-c-commitment-and-htlc-transaction-test-vectors

    // name: simple commitment tx with no HTLCs (BOLT 3 Appendix C)
    #[test]
    fn simple_commitment_tx_with_no_htlcs_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 7_000_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "30440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae055647142",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b0",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // name: commitment tx with two outputs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(4_915, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "30450221008a953551f4d67cb4df3037207fc082ddaf6be84d417b0bd14c80aab66f1b01a402207508796dc75034b2dee876fe01dc05a08b019f3e5d689ac8842ade2f1befccf5",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402203a286936e74870ca1459c700c71202af0381910a6bfab687ef494ef1bc3e02c902202506c362d0e3bee15e802aa729bf378e051644648253513f1c085b264cc2a720",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // name: commitment tx with two outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_180, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "3045022100e11b638c05c650c2f63a421d36ef8756c5ce82f2184278643520311cdf50aa200220259565fb9c8e4a87ccaf17f27a3b9ca4f20625754a0920d9c6c239d8156a11de",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402200a8544eba1d216f5c5e530597665fa9bec56943c0f66d98fc3d028df52d84f7002201e45fa5c6bc3a506cc2553e7d1c0043a9811313fc39c954692c0d47cfce2bbd3",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // name: commitment tx with one output untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_one_output_untrimmed_minimum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_181, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // name: commitment tx with fee greater than funder amount (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_fee_greater_than_funder_amount_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_936, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the edge case where `push_msat % 1000 != 0` to ensure there is
    /// no off-by-one error in opener balance calculation.
    #[test]
    fn commitment_tx_with_balance_msat_not_multiple_of_1000_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 6_999_999_000, 3_000_000_123, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "3045022100a41609df3e71b939046d6dfface892aa6161ef8fb61898e142aeffc0ce1462df02201d1ca13eb145436593b0cb1a201c48bf2fdd6fc0c754784240d5f407c06ab4cf",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402202c85c0eb44ff3c5133e0a1e9f120a1af215b43d73da69b994e04c545b6cf7b600220331d81cacccfd7ae71eb3a1407bd767fc39a30776638e1048531441c95889bc2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Covers the case where commitment outputs have equal values,
    /// ensuring outputs are ordered by `script_pubkey`.
    #[test]
    fn commitment_tx_with_equal_output_values_orders_by_script_pubkey_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 5_005_430_000, 4_994_570_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "3045022100a51021a83202743cb336edad88ee08bd14f434779bff21351c8f39d78d035f9602200d889a4a98332aff37f02938157cd3d7cf336313e5663848ac18bcd09ad5ff13",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402206ad05e8243d8fa04953cf14fff140fbf00999c3b6ffe63670d8edbf2eccf82c502201ca99860981ee1df1d93a02129f5b54f5c18e2ff047e8d8864a017eca48f94c9",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // BOLT 3 Appendix F: Commitment and HTLC Transaction Test Vectors (anchors)
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-f-commitment-and-htlc-transaction-test-vectors-anchors

    // name: simple commitment tx with no HTLCs (BOLT 3 Appendix F)
    #[test]
    fn simple_commitment_tx_with_no_htlcs_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                7_000_000_000,
                3_000_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "30450221008266ac6db5ea71aac3c95d97b0e172ff596844851a3216eb88382a8dddfd33d2022050e240974cfd5d708708b4365574517c18e7ae535ef732a3484d43d0d82be9f7",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f3",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // name: simple commitment tx with no HTLCs and single anchor (BOLT 3 Appendix F)
    #[test]
    fn simple_commitment_tx_with_no_htlc_and_single_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 10_000_000_000, 0, 546, vec![0x40, 0x00, 0x00]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "3044022007cf6b405e9c9b4f527b0ecad9d8bb661fabb8b12abf7d1c0b3ad1855db3ed490220616d5c1eeadccc63bd775a131149455d62d95a42c2a1b01cc7821fc42dce7778",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30440220655bf909fb6fa81d086f1336ac72c97906dce29d1b166e305c99152d810e26e1022051f577faa46412c46707aaac46b65d50053550a66334e00a44af2706f27a8658",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // name: commitment tx with two outputs untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                4_894,
                6_988_000_000,
                3_000_000_000,
                4_001,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "30450221009f16ac85d232e4eddb3fcd750a68ebf0b58e3356eaada45d3513ede7e817bf4c02207c2b043b4e5f971261975406cb955219fa56bffe5d834a833694b5abc1ce4cfd",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100e784a66b1588575801e237d35e510fd92a81ae3a4a2a1b90c031ad803d07b3f3022021bc5f16501f167607d63b681442da193eb0a76b4b7fd25c2ed4f8b28fd35b95",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    // name: commitment tx with one output untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_one_output_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                6_216_010,
                6_988_000_000,
                3_000_000_000,
                4_001,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "30450221009ad80792e3038fe6968d12ff23e6888a565c3ddd065037f357445f01675d63f3022018384915e5f1f4ae157e15debf4f49b61c8d9d2b073c7d6f97c4a68caa3ed4c1",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30450221008fd5dbff02e4b59020d4cd23a3c30d3e287065fda75a0a09b402980adf68ccda022001e0b8b620cd915ddff11f1de32addf23d81d51b90e6841b2cb8dcaf3faa5ecf",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the edge case where `push_msat % 1000 != 0` to ensure there is
    /// no off-by-one error in opener balance calculation.
    #[test]
    fn commitment_tx_with_balance_msat_not_multiple_of_1000_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                6_999_999_000,
                3_000_000_123,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "304402202573a6da7fffc40fffb98d106dc4c83a5c94266118b3b0b44ea03100e20dab1e022038d9e65b3b84096ccebc91f9b56117d30c1cc249e21426d2d3dbf3e4617935fd",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "3044022036e0e75ab8bd15f1232da3974db1a4cfca2491912b1fb06bfe2fbfca4f416e29022035c5a4f4b09f344a595ffdfb73aebf5982d41f1fcf5e90b141d8141c857e9aed",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Covers the case where commitment outputs have equal values,
    /// ensuring outputs are ordered by `script_pubkey`.
    #[test]
    fn commitment_tx_with_equal_output_values_orders_by_script_pubkey_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                5_008_760_000,
                4_991_240_000,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .serialize_der()
            ),
            "30440220156f857fc1cfaa0e13dadc5a07553244971a91d99a3f53bf87305189864043a402200bd512ace372ac10c54a3745ae123e69d99305c564bd0420ade72ebcac994bd8",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "3044022035fd44caf320fdca9f2a866fe88e27f186a4a93ecf390549c3ed9950a9042c2f0220237525890e37617749e1eae4c2cce10e19d1a796acea1937c29cb888ee992d19",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
        ));
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

    fn sample_chan_config(funding_satoshis: u64, channel_type: Vec<u8>) -> ChannelConfig {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let sample_party = || ChannelPartyConfig {
            funding_pubkey: sample_key,
            payment_basepoint: sample_key,
            revocation_basepoint: sample_key,
            delayed_payment_basepoint: sample_key,
            htlc_basepoint: sample_key,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };

        ChannelConfig {
            funding_outpoint: OutPoint {
                txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                    .parse()
                    .expect("valid txid hex"),
                vout: 0,
            },
            funding_satoshis,
            channel_type,
            opener: sample_party(),
            acceptor: sample_party(),
            minimum_depth: 8,
        }
    }

    #[test]
    fn new_initial_from_funding_msat_overflow() {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let chan_config = sample_chan_config(u64::MAX, vec![]);
        let result = chan_config.new_initial_commitment(0, 15_000, sample_key, sample_key);
        assert!(matches!(result, Err(CommitmentError::FundingMsatOverflow)));
    }

    #[test]
    fn new_initial_from_funding_push_exceeds_funding() {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let chan_config = sample_chan_config(1_000, vec![]);
        let result = chan_config.new_initial_commitment(2_000_000, 15_000, sample_key, sample_key);
        assert!(matches!(result, Err(CommitmentError::PushExceedsFunding)));
    }

    #[test]
    fn can_opener_afford_feerate_checks() {
        let feerate_per_kw: u32 = 15_000;
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        // Legacy fee: 15000 * 724 / 1000 = 10_860 sat
        // Anchor fee: 15000 * 1124 / 1000 = 16_860 sat; anchor_cost = 660 sat

        // Comfortably affordable
        let chan_config = sample_chan_config(20_000, vec![]);
        let state = chan_config
            .new_initial_commitment(0, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Opener));

        // Exact zero opener balance
        let chan_config = sample_chan_config(11_860, vec![]);
        let state = chan_config
            .new_initial_commitment(1_000_000, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Opener));

        // Push fits but fee does not
        let chan_config = sample_chan_config(10_000, vec![]);
        let state = chan_config
            .new_initial_commitment(0, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));

        // Push + fee fit but anchor cost does not
        let chan_config = sample_chan_config(17_500, vec![0x40, 0x00, 0x00]);
        let state = chan_config
            .new_initial_commitment(0, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));
    }

    #[test]
    fn can_opener_afford_feerate_with_htlc_checks() {
        let feerate_per_kw: u32 = 15_000;
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let htlc = |id: u64, offerer: Side, amount_msat: u64| Htlc {
            id,
            offerer,
            amount_msat,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        let state_with = |chan_config: &ChannelConfig, push_msat: u64, htlcs: &[Htlc]| {
            let mut state = chan_config
                .new_initial_commitment(push_msat, feerate_per_kw, sample_key, sample_key)
                .expect("valid commitment");
            for h in htlcs {
                state.add_htlc(*h).unwrap();
            }
            state
        };
        // Legacy fee: 15000 * (724 + 172 per non-dust HTLC) / 1000
        //   = 10_860 / 13_440 / 16_020 sat for 0 / 1 / 2 HTLCs
        // Legacy dust thresholds: 546 + 15000 * 663 / 1000 = 10_491 sat (offered);
        //   546 + 15000 * 703 / 1000 = 11_091 sat (received)
        // Anchor fee: 15000 * (1124 + 172) / 1000 = 19_440 sat for 1 HTLC; anchor_cost = 660 sat

        // Opener balance exactly covers the one-HTLC fee
        let chan_config = sample_chan_config(50_000, vec![]);
        let offered = htlc(0, Side::Opener, 12_000_000);
        let state = state_with(&chan_config, 24_560_000, &[offered]);
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Acceptor));

        // One msat short of the one-HTLC fee
        let state = state_with(&chan_config, 24_560_001, &[offered]);
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Acceptor));

        // Dust HTLC is trimmed and adds no fee
        let state = state_with(
            &chan_config,
            24_560_000,
            &[offered, htlc(1, Side::Acceptor, 1_000_000)],
        );
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Acceptor));

        // Second non-dust HTLC pushes the fee out of reach
        let state = state_with(
            &chan_config,
            24_560_000,
            &[offered, htlc(1, Side::Acceptor, 12_000_000)],
        );
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Acceptor));

        // Exactly at the offered dust threshold: kept on the opener's
        // commitment, trimmed as received on the acceptor's
        let state = state_with(
            &chan_config,
            27_509_000,
            &[htlc(0, Side::Opener, 10_491_000)],
        );
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Acceptor));

        // Dust limit of the evaluated side decides trimming
        let mut chan_config = sample_chan_config(50_000, vec![]);
        chan_config.acceptor.dust_limit_satoshis = 20_000;
        let state = state_with(&chan_config, 26_000_000, &[offered]);
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Acceptor));

        // Anchor dust threshold is the dust limit alone
        let chan_config = sample_chan_config(50_000, vec![0x40, 0x00, 0x00]);
        let htlcs = [
            htlc(0, Side::Opener, 546_000),
            htlc(1, Side::Opener, 545_000),
        ];
        let state = state_with(&chan_config, 28_809_000, &htlcs);
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Acceptor));

        // One msat short of the anchor one-HTLC fee plus anchor cost
        let state = state_with(&chan_config, 28_809_001, &htlcs);
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Acceptor));
    }
}
