//! IR program executor.
//!
//! Executes an IR program against a target node over an established connection,
//! producing side effects (sending/receiving messages).

use bitcoin::ScriptBuf;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use smite::bitcoin::{BitcoinCli, Utxo};
use smite::bolt::{
    AcceptChannel, ChannelAnnouncement, ChannelId, Message, NodeAnnouncement, OpenChannel,
    OpenChannelTlvs, Pong, ShortChannelId, msg_type,
};
use smite::channel_tx::{FundingTransaction, build_funding_transaction};
use smite::noise::{ConnectionError, NoiseConnection};
use smite_ir::operation::AcceptChannelField;
use smite_ir::{Operation, Program, Variable, VariableType};

/// Abstraction over bitcoin-cli operations, allowing mock implementations in tests.
pub trait BitcoinRpc {
    /// Mines the given number of blocks.
    fn mine_blocks(&mut self, num_blocks: u8);

    /// Returns the wallet's spendable UTXOs.
    fn get_utxos(&mut self) -> Vec<Utxo>;

    /// Returns the scriptPubKey for a newly generated wallet address.
    fn get_new_address_script_pubkey(&mut self) -> ScriptBuf;

    /// Signs and broadcasts a transaction
    fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction);
}

impl BitcoinRpc for BitcoinCli {
    fn mine_blocks(&mut self, num_blocks: u8) {
        BitcoinCli::mine_blocks(self, num_blocks);
    }

    fn get_utxos(&mut self) -> Vec<Utxo> {
        BitcoinCli::get_utxos(self)
    }

    fn get_new_address_script_pubkey(&mut self) -> ScriptBuf {
        BitcoinCli::get_new_address_script_pubkey(self)
    }

    fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction) {
        BitcoinCli::sign_and_broadcast_tx(self, tx);
    }
}

/// State captured during snapshot setup, available to IR programs at execution
/// time via `LoadContext*` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramContext {
    /// Target node's identity public key.
    pub target_pubkey: PublicKey,
    /// Chain hash (genesis block hash).
    pub chain_hash: [u8; 32],
    /// Current block height at snapshot time.
    pub block_height: u32,
    /// Target's advertised feature bits from init message.
    pub target_features: Vec<u8>,
}

/// Abstraction over a Noise-encrypted connection, allowing mock implementations
/// in tests.
pub trait Connection {
    /// Sends an encrypted message.
    ///
    /// # Errors
    ///
    /// Returns an error if the send fails.
    fn send_message(&mut self, msg: &[u8]) -> Result<(), ConnectionError>;

    /// Receives and decrypts the next message.
    ///
    /// # Errors
    ///
    /// Returns an error if the receive fails.
    fn recv_message(&mut self) -> Result<Vec<u8>, ConnectionError>;
}

impl Connection for NoiseConnection {
    fn send_message(&mut self, msg: &[u8]) -> Result<(), ConnectionError> {
        NoiseConnection::send_message(self, msg)
    }

    fn recv_message(&mut self) -> Result<Vec<u8>, ConnectionError> {
        NoiseConnection::recv_message(self)
    }
}

/// Error from executing an IR program.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// Referenced a variable slot that doesn't exist.
    #[error("variable index {index} out of bounds (have {len})")]
    VariableIndexOutOfBounds { index: usize, len: usize },

    /// Referenced a variable slot that holds a void result.
    #[error("variable {index} is void (produced by a void instruction)")]
    VoidVariable { index: usize },

    /// Input variable has the wrong type.
    #[error("type mismatch: expected {expected:?}, got {got:?}")]
    TypeMismatch {
        expected: VariableType,
        got: VariableType,
    },

    /// Wrong number of inputs for the operation.
    #[error("wrong input count: expected {expected}, got {got}")]
    WrongInputCount { expected: usize, got: usize },

    /// Private key bytes are not in the valid range `[1, curve_order)`.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// An affine variable is consumed more than once.
    #[error("affine variable {index} consumed more than once")]
    AffineOverUse { index: usize },

    /// Connection or send/receive failure.
    #[error("connection: {0}")]
    Connection(#[from] smite::noise::ConnectionError),

    /// Failed to decode a received message.
    #[error("decode: {0}")]
    Decode(#[from] smite::bolt::BoltError),

    /// Received a different message type than expected.
    #[error("unexpected message: expected type {expected}, got {got}")]
    UnexpectedMessage { expected: u16, got: u16 },

    /// Wallet UTXOs could not cover the funding amount and fees.
    #[error("funding: {0}")]
    InsufficientFunds(#[from] smite::channel_tx::InsufficientFunds),
}

/// Executes an IR program against a target over the given connection.
///
/// # Errors
///
/// Returns an error if any instruction fails (type mismatch, connection error,
/// decode error, etc.).
#[allow(clippy::too_many_lines)]
pub fn execute(
    program: &Program,
    context: &ProgramContext,
    conn: &mut impl Connection,
    bitcoin_cli: &mut impl BitcoinRpc,
    start: std::time::Instant,
) -> Result<(), ExecuteError> {
    let secp = Secp256k1::new();
    let mut variables: Vec<Option<Variable>> = Vec::with_capacity(program.instructions.len());

    for instr in &program.instructions {
        // Validate input count before accessing inputs by index.
        let expected_count = instr.operation.input_types().len();
        if instr.inputs.len() != expected_count {
            return Err(ExecuteError::WrongInputCount {
                expected: expected_count,
                got: instr.inputs.len(),
            });
        }

        let result = match &instr.operation {
            // -- Load operations --
            Operation::LoadAmount(v) => Some(Variable::Amount(*v)),
            Operation::LoadShortChannelId(v) => {
                Some(Variable::ShortChannelId(ShortChannelId::from_u64(*v)))
            }
            Operation::LoadFeeratePerKw(v) => Some(Variable::FeeratePerKw(*v)),
            Operation::LoadBlockHeight(v) => Some(Variable::BlockHeight(*v)),
            Operation::LoadTimestamp(v) => Some(Variable::Timestamp(*v)),
            Operation::LoadForwardingFee(v) => Some(Variable::ForwardingFee(*v)),
            Operation::LoadU16(v) => Some(Variable::U16(*v)),
            Operation::LoadU8(v) => Some(Variable::U8(*v)),
            Operation::LoadBytes(b) => Some(Variable::Bytes(b.clone())),
            Operation::LoadFeatures(b) => Some(Variable::Features(b.clone())),
            Operation::LoadPrivateKey(k) => Some(Variable::PrivateKey(*k)),
            Operation::LoadChannelId(id) => Some(Variable::ChannelId(ChannelId::new(*id))),
            Operation::LoadShutdownScript(variant) => Some(Variable::Bytes(variant.encode())),
            Operation::LoadChannelType(variant) => Some(Variable::Features(variant.encode())),
            Operation::LoadTargetPubkeyFromContext => Some(Variable::Point(context.target_pubkey)),
            Operation::LoadChainHashFromContext => Some(Variable::ChainHash(context.chain_hash)),

            // -- Compute operations --
            Operation::DerivePoint => {
                let key_bytes = resolve_private_key(&variables, instr.inputs[0])?;
                let sk = SecretKey::from_slice(&key_bytes)
                    .map_err(|_| ExecuteError::InvalidPrivateKey)?;
                let pk = PublicKey::from_secret_key(&secp, &sk);
                Some(Variable::Point(pk))
            }

            Operation::ExtractAcceptChannel(field) => {
                let ac = resolve_accept_channel(&variables, instr.inputs[0])?;
                Some(extract_field(ac, *field))
            }

            Operation::CreateFundingTransaction => {
                let ft = create_funding_transaction(&variables, &instr.inputs, bitcoin_cli)?;
                Some(Variable::FundingTransaction(ft))
            }

            // -- Build operations --
            Operation::BuildOpenChannel => {
                let oc = build_open_channel(&variables, &instr.inputs)?;
                let encoded = Message::OpenChannel(oc).encode();
                Some(Variable::OpenChannelMessage(encoded))
            }

            Operation::BuildChannelAnnouncement => {
                let ca = build_channel_announcement(&variables, &instr.inputs)?;
                let encoded = Message::ChannelAnnouncement(ca).encode();
                Some(Variable::Message(encoded))
            }

            Operation::BuildNodeAnnouncement { rgb_color, alias } => {
                let na = build_node_announcement(&variables, &instr.inputs, *rgb_color, *alias)?;
                let encoded = Message::NodeAnnouncement(na).encode();
                Some(Variable::Message(encoded))
            }

            // -- Act operations --
            Operation::SendMessage => {
                let bytes = resolve_message(&variables, instr.inputs[0])?;
                let msg_type = bytes.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
                log::debug!(
                    "[{:?}] SendMessage: type {msg_type:?}, {} bytes",
                    start.elapsed(),
                    bytes.len(),
                );
                conn.send_message(bytes)?;
                None
            }

            Operation::SendOpenChannel => {
                let bytes = resolve_open_channel_message(&variables, instr.inputs[0])?;
                log::debug!(
                    "[{:?}] SendOpenChannel: {} bytes",
                    start.elapsed(),
                    bytes.len(),
                );
                conn.send_message(bytes)?;
                Some(Variable::SentOpenChannel)
            }

            Operation::RecvAcceptChannel => {
                consume_sent_open_channel(&mut variables, instr.inputs[0])?;
                log::debug!("[{:?}] RecvAcceptChannel: waiting", start.elapsed());
                let ac = recv_accept_channel(conn)?;
                log::debug!("[{:?}] RecvAcceptChannel: received", start.elapsed());
                Some(Variable::AcceptChannel(ac))
            }

            Operation::MineBlocks(v) => {
                bitcoin_cli.mine_blocks(*v);
                log::debug!("[{:?}] MineBlocks: mined {} block(s)", start.elapsed(), v);
                None
            }

            Operation::BroadcastTransaction => {
                let ft = resolve_funding_transaction(&variables, instr.inputs[0])?;
                log::debug!(
                    "[{:?}] BroadcastTransaction: txid={}",
                    start.elapsed(),
                    ft.tx.compute_txid(),
                );
                bitcoin_cli.sign_and_broadcast_tx(&ft.tx);
                None
            }
        };

        variables.push(result);
    }

    Ok(())
}

// -- Variable resolution --
//
// Each resolver looks up a variable by index and checks its type, returning the
// resolved variable.

fn resolve(variables: &[Option<Variable>], index: usize) -> Result<&Variable, ExecuteError> {
    let slot = variables
        .get(index)
        .ok_or(ExecuteError::VariableIndexOutOfBounds {
            index,
            len: variables.len(),
        })?;
    slot.as_ref().ok_or(ExecuteError::VoidVariable { index })
}

fn type_err(expected: VariableType, got: &Variable) -> ExecuteError {
    ExecuteError::TypeMismatch {
        expected,
        got: got.var_type(),
    }
}

fn resolve_amount(variables: &[Option<Variable>], index: usize) -> Result<u64, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Amount(v) => Ok(*v),
        _ => Err(type_err(VariableType::Amount, var)),
    }
}

fn resolve_feerate(variables: &[Option<Variable>], index: usize) -> Result<u32, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::FeeratePerKw(v) => Ok(*v),
        _ => Err(type_err(VariableType::FeeratePerKw, var)),
    }
}

fn resolve_timestamp(variables: &[Option<Variable>], index: usize) -> Result<u32, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Timestamp(v) => Ok(*v),
        _ => Err(type_err(VariableType::Timestamp, var)),
    }
}

fn resolve_u16(variables: &[Option<Variable>], index: usize) -> Result<u16, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::U16(v) => Ok(*v),
        _ => Err(type_err(VariableType::U16, var)),
    }
}

fn resolve_u8(variables: &[Option<Variable>], index: usize) -> Result<u8, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::U8(v) => Ok(*v),
        _ => Err(type_err(VariableType::U8, var)),
    }
}

fn resolve_bytes(variables: &[Option<Variable>], index: usize) -> Result<&[u8], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Bytes(v) => Ok(v),
        _ => Err(type_err(VariableType::Bytes, var)),
    }
}

fn resolve_features(variables: &[Option<Variable>], index: usize) -> Result<&[u8], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Features(v) => Ok(v),
        _ => Err(type_err(VariableType::Features, var)),
    }
}

fn resolve_chain_hash(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<[u8; 32], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::ChainHash(v) => Ok(*v),
        _ => Err(type_err(VariableType::ChainHash, var)),
    }
}

fn resolve_channel_id(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<ChannelId, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::ChannelId(v) => Ok(*v),
        _ => Err(type_err(VariableType::ChannelId, var)),
    }
}

fn resolve_short_channel_id(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<ShortChannelId, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::ShortChannelId(v) => Ok(*v),
        _ => Err(type_err(VariableType::ShortChannelId, var)),
    }
}

fn resolve_pubkey(variables: &[Option<Variable>], index: usize) -> Result<PublicKey, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Point(pk) => Ok(*pk),
        _ => Err(type_err(VariableType::Point, var)),
    }
}

fn resolve_private_key(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<[u8; 32], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::PrivateKey(v) => Ok(*v),
        _ => Err(type_err(VariableType::PrivateKey, var)),
    }
}

fn resolve_message(variables: &[Option<Variable>], index: usize) -> Result<&[u8], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Message(v) => Ok(v),
        _ => Err(type_err(VariableType::Message, var)),
    }
}

fn resolve_open_channel_message(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<&[u8], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::OpenChannelMessage(v) => Ok(v),
        _ => Err(type_err(VariableType::OpenChannelMessage, var)),
    }
}

fn resolve_accept_channel(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<&AcceptChannel, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::AcceptChannel(v) => Ok(v),
        _ => Err(type_err(VariableType::AcceptChannel, var)),
    }
}

fn resolve_funding_transaction(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<&FundingTransaction, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::FundingTransaction(v) => Ok(v),
        _ => Err(type_err(VariableType::FundingTransaction, var)),
    }
}

fn consume_sent_open_channel(
    variables: &mut [Option<Variable>],
    index: usize,
) -> Result<(), ExecuteError> {
    match resolve(variables, index) {
        Ok(Variable::SentOpenChannel) => {
            // Consume the affine `SentOpenChannel`.
            variables[index] = None;
            Ok(())
        }
        Ok(wrong_var) => Err(type_err(VariableType::SentOpenChannel, wrong_var)),
        // Map `VoidVariable` to `AffineOverUse`.
        Err(ExecuteError::VoidVariable { index }) => Err(ExecuteError::AffineOverUse { index }),
        Err(e) => Err(e),
    }
}

// -- Operation handlers --

/// Create a funding transaction by querying the bitcoind for UTXOs and a
/// change address, then calling [`build_funding_transaction`].
fn create_funding_transaction(
    variables: &[Option<Variable>],
    inputs: &[usize],
    cli: &mut impl BitcoinRpc,
) -> Result<FundingTransaction, ExecuteError> {
    let opener_pubkey = resolve_pubkey(variables, inputs[0])?;
    let acceptor_pubkey = resolve_pubkey(variables, inputs[1])?;
    let funding_satoshis = resolve_amount(variables, inputs[2])?;
    let feerate_per_kw = resolve_feerate(variables, inputs[3])?;

    // Query wallet state from bitcoind for coin selection and change.
    let utxos = cli.get_utxos();
    let change_spk = cli.get_new_address_script_pubkey();

    // Create the funding transaction.
    let funding = build_funding_transaction(
        &opener_pubkey,
        &acceptor_pubkey,
        funding_satoshis,
        feerate_per_kw,
        utxos,
        change_spk,
    )?;

    Ok(funding)
}

/// Builds an `OpenChannel` from 20 input variables (wire order).
fn build_open_channel(
    variables: &[Option<Variable>],
    inputs: &[usize],
) -> Result<OpenChannel, ExecuteError> {
    Ok(OpenChannel {
        chain_hash: resolve_chain_hash(variables, inputs[0])?,
        temporary_channel_id: resolve_channel_id(variables, inputs[1])?,
        funding_satoshis: resolve_amount(variables, inputs[2])?,
        push_msat: resolve_amount(variables, inputs[3])?,
        dust_limit_satoshis: resolve_amount(variables, inputs[4])?,
        max_htlc_value_in_flight_msat: resolve_amount(variables, inputs[5])?,
        channel_reserve_satoshis: resolve_amount(variables, inputs[6])?,
        htlc_minimum_msat: resolve_amount(variables, inputs[7])?,
        feerate_per_kw: resolve_feerate(variables, inputs[8])?,
        to_self_delay: resolve_u16(variables, inputs[9])?,
        max_accepted_htlcs: resolve_u16(variables, inputs[10])?,
        funding_pubkey: resolve_pubkey(variables, inputs[11])?,
        revocation_basepoint: resolve_pubkey(variables, inputs[12])?,
        payment_basepoint: resolve_pubkey(variables, inputs[13])?,
        delayed_payment_basepoint: resolve_pubkey(variables, inputs[14])?,
        htlc_basepoint: resolve_pubkey(variables, inputs[15])?,
        first_per_commitment_point: resolve_pubkey(variables, inputs[16])?,
        channel_flags: resolve_u8(variables, inputs[17])?,
        tlvs: OpenChannelTlvs {
            // Always send the TLV: a zero-length value is the BOLT 2 opt-out
            // signal when option_upfront_shutdown_script is negotiated.
            // Omitting it is a protocol violation in that case. Including if
            // not negotiated is not.
            upfront_shutdown_script: Some(resolve_bytes(variables, inputs[18])?.to_vec()),
            channel_type: nonempty_or_none(resolve_features(variables, inputs[19])?),
        },
    })
}

/// Builds a signed `ChannelAnnouncement` from 7 input variables.
fn build_channel_announcement(
    variables: &[Option<Variable>],
    inputs: &[usize],
) -> Result<ChannelAnnouncement, ExecuteError> {
    let features = resolve_features(variables, inputs[0])?.to_vec();
    let chain_hash = resolve_chain_hash(variables, inputs[1])?;
    let short_channel_id = resolve_short_channel_id(variables, inputs[2])?;
    let node_sk_1_bytes = resolve_private_key(variables, inputs[3])?;
    let node_sk_2_bytes = resolve_private_key(variables, inputs[4])?;
    let bitcoin_sk_1_bytes = resolve_private_key(variables, inputs[5])?;
    let bitcoin_sk_2_bytes = resolve_private_key(variables, inputs[6])?;

    let node_sk_1 =
        SecretKey::from_slice(&node_sk_1_bytes).map_err(|_| ExecuteError::InvalidPrivateKey)?;
    let node_sk_2 =
        SecretKey::from_slice(&node_sk_2_bytes).map_err(|_| ExecuteError::InvalidPrivateKey)?;
    let bitcoin_sk_1 =
        SecretKey::from_slice(&bitcoin_sk_1_bytes).map_err(|_| ExecuteError::InvalidPrivateKey)?;
    let bitcoin_sk_2 =
        SecretKey::from_slice(&bitcoin_sk_2_bytes).map_err(|_| ExecuteError::InvalidPrivateKey)?;

    let secp = Secp256k1::new();
    let node_id_1 = PublicKey::from_secret_key(&secp, &node_sk_1);
    let node_id_2 = PublicKey::from_secret_key(&secp, &node_sk_2);
    let bitcoin_key_1 = PublicKey::from_secret_key(&secp, &bitcoin_sk_1);
    let bitcoin_key_2 = PublicKey::from_secret_key(&secp, &bitcoin_sk_2);

    let placeholder = Signature::from_compact(&[0u8; 64]).expect("zero bytes parse as a signature");
    let mut ca = ChannelAnnouncement {
        node_signature_1: placeholder,
        node_signature_2: placeholder,
        bitcoin_signature_1: placeholder,
        bitcoin_signature_2: placeholder,
        features,
        chain_hash,
        short_channel_id,
        node_id_1,
        node_id_2,
        bitcoin_key_1,
        bitcoin_key_2,
        extra: Vec::new(),
    };
    ca.sign(&node_sk_1, &node_sk_2, &bitcoin_sk_1, &bitcoin_sk_2);
    Ok(ca)
}

/// Builds a signed `NodeAnnouncement` from 4 input variables.
fn build_node_announcement(
    variables: &[Option<Variable>],
    inputs: &[usize],
    rgb_color: [u8; 3],
    alias: [u8; 32],
) -> Result<NodeAnnouncement, ExecuteError> {
    let sk_bytes = resolve_private_key(variables, inputs[0])?;
    let features = resolve_features(variables, inputs[1])?.to_vec();
    let timestamp = resolve_timestamp(variables, inputs[2])?;
    let addresses = resolve_bytes(variables, inputs[3])?.to_vec();

    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| ExecuteError::InvalidPrivateKey)?;
    let secp = Secp256k1::new();
    let node_id = PublicKey::from_secret_key(&secp, &sk);

    let mut na = NodeAnnouncement {
        signature: Signature::from_compact(&[0u8; 64]).expect("zero bytes parse as a signature"),
        features,
        timestamp,
        node_id,
        rgb_color,
        alias,
        addresses,
        extra: Vec::new(),
    };
    na.sign(&sk);
    Ok(na)
}

/// Receives the next message of interest, auto-responding to pings and silently
/// skipping unknown odd-type messages.
#[allow(clippy::similar_names)] // ping and pong are canonical names
fn recv_non_ping(conn: &mut impl Connection) -> Result<Message, ExecuteError> {
    loop {
        let msg_bytes = conn.recv_message()?;
        let msg = Message::decode(&msg_bytes)?;
        match msg {
            Message::Ping(ping) => {
                let pong = Message::Pong(Pong::respond_to(&ping)).encode();
                conn.send_message(&pong)?;
            }
            Message::Unknown { msg_type, .. } => {
                log::debug!("skipping unknown message type {msg_type}");
            }
            other => return Ok(other),
        }
    }
}

/// Receives and decodes an `accept_channel` message.
fn recv_accept_channel(conn: &mut impl Connection) -> Result<AcceptChannel, ExecuteError> {
    match recv_non_ping(conn)? {
        Message::AcceptChannel(ac) => Ok(ac),
        other => Err(ExecuteError::UnexpectedMessage {
            expected: msg_type::ACCEPT_CHANNEL,
            got: other.msg_type(),
        }),
    }
}

/// Extracts a field from a parsed `accept_channel` message.
fn extract_field(ac: &AcceptChannel, field: AcceptChannelField) -> Variable {
    match field {
        AcceptChannelField::TemporaryChannelId => Variable::ChannelId(ac.temporary_channel_id),
        AcceptChannelField::DustLimitSatoshis => Variable::Amount(ac.dust_limit_satoshis),
        AcceptChannelField::MaxHtlcValueInFlightMsat => {
            Variable::Amount(ac.max_htlc_value_in_flight_msat)
        }
        AcceptChannelField::ChannelReserveSatoshis => Variable::Amount(ac.channel_reserve_satoshis),
        AcceptChannelField::HtlcMinimumMsat => Variable::Amount(ac.htlc_minimum_msat),
        AcceptChannelField::MinimumDepth => Variable::BlockHeight(ac.minimum_depth),
        AcceptChannelField::ToSelfDelay => Variable::U16(ac.to_self_delay),
        AcceptChannelField::MaxAcceptedHtlcs => Variable::U16(ac.max_accepted_htlcs),
        AcceptChannelField::FundingPubkey => Variable::Point(ac.funding_pubkey),
        AcceptChannelField::RevocationBasepoint => Variable::Point(ac.revocation_basepoint),
        AcceptChannelField::PaymentBasepoint => Variable::Point(ac.payment_basepoint),
        AcceptChannelField::DelayedPaymentBasepoint => {
            Variable::Point(ac.delayed_payment_basepoint)
        }
        AcceptChannelField::HtlcBasepoint => Variable::Point(ac.htlc_basepoint),
        AcceptChannelField::FirstPerCommitmentPoint => {
            Variable::Point(ac.first_per_commitment_point)
        }
        AcceptChannelField::UpfrontShutdownScript => {
            Variable::Bytes(ac.tlvs.upfront_shutdown_script.clone().unwrap_or_default())
        }
        AcceptChannelField::ChannelType => {
            Variable::Features(ac.tlvs.channel_type.clone().unwrap_or_default())
        }
    }
}

/// Returns `None` for empty slices, `Some(vec)` otherwise.
fn nonempty_or_none(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::str::FromStr;

    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Amount, OutPoint, Transaction};
    use smite::bolt::{AcceptChannelTlvs, Init, Ping};
    use smite_ir::Instruction;

    // -- MockConnection --

    struct MockConnection {
        recv_queue: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl MockConnection {
        fn new() -> Self {
            Self {
                recv_queue: VecDeque::new(),
                sent: Vec::new(),
            }
        }

        fn queue_recv(&mut self, msg_bytes: Vec<u8>) {
            self.recv_queue.push_back(msg_bytes);
        }
    }

    impl Connection for MockConnection {
        fn send_message(&mut self, msg: &[u8]) -> Result<(), ConnectionError> {
            self.sent.push(msg.to_vec());
            Ok(())
        }

        fn recv_message(&mut self) -> Result<Vec<u8>, ConnectionError> {
            self.recv_queue
                .pop_front()
                .ok_or_else(|| ConnectionError::Io(std::io::ErrorKind::UnexpectedEof.into()))
        }
    }

    // Mocking BitcoinCli via MockBitcoinCli

    #[derive(Default)]
    struct MockBitcoinCli {
        mine_blocks_calls: Vec<u8>,
        broadcast_calls: Vec<Transaction>,
        utxos: Vec<Utxo>,
        change_spk: ScriptBuf,
    }

    impl BitcoinRpc for MockBitcoinCli {
        fn mine_blocks(&mut self, num_blocks: u8) {
            self.mine_blocks_calls.push(num_blocks);
        }

        fn get_utxos(&mut self) -> Vec<Utxo> {
            self.utxos.clone()
        }

        fn get_new_address_script_pubkey(&mut self) -> ScriptBuf {
            self.change_spk.clone()
        }

        fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction) {
            self.broadcast_calls.push(tx.clone());
        }
    }

    // -- Helpers --

    fn sample_pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = byte;
        let sk = SecretKey::from_slice(&key_bytes).expect("valid secret key");
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn sample_context() -> ProgramContext {
        ProgramContext {
            target_pubkey: sample_pubkey(1),
            chain_hash: [0xcc; 32],
            block_height: 800_000,
            target_features: vec![],
        }
    }

    fn sample_utxo() -> Utxo {
        Utxo {
            amount: Amount::from_sat(10_008_942),
            outpoint: OutPoint {
                txid: "a1f7b953dc8c3db0222d931d3e2613f9971af75a09a005b31af057f8414cc5d7"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("0014a10d9257489e685dda030662390dc177852faf13")
                    .expect("valid P2WPKH scriptpubkey hex"),
            ),
        }
    }

    fn sample_change_spk() -> ScriptBuf {
        ScriptBuf::from(
            hex::decode("00142e532c12351a5c81e23c8a76d19345ca7b6de57a")
                .expect("valid P2WPKH scriptpubkey hex"),
        )
    }

    fn sample_accept_channel() -> AcceptChannel {
        AcceptChannel {
            temporary_channel_id: ChannelId::new([0xaa; 32]),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 6,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: sample_pubkey(1),
            revocation_basepoint: sample_pubkey(2),
            payment_basepoint: sample_pubkey(3),
            delayed_payment_basepoint: sample_pubkey(4),
            htlc_basepoint: sample_pubkey(5),
            first_per_commitment_point: sample_pubkey(6),
            tlvs: AcceptChannelTlvs {
                upfront_shutdown_script: Some(vec![0xde, 0xad]),
                channel_type: Some(vec![0x01]),
            },
        }
    }

    /// Builds the 20 `open_channel` input instructions in wire order.
    fn open_channel_instructions() -> Vec<Instruction> {
        vec![
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChannelId([0xbb; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(100_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(0),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(546),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(100_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(10_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(1_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeeratePerKw(253),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU16(144),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU16(483),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU8(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadBytes(vec![]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(vec![]),
                inputs: vec![],
            },
        ]
    }

    fn create_and_broadcast_tx_instructions() -> Vec<Instruction> {
        let opener_privkey =
            SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
                .unwrap()
                .secret_bytes();
        let acceptor_privkey =
            SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
                .unwrap()
                .secret_bytes();

        vec![
            Instruction {
                operation: Operation::LoadPrivateKey(opener_privkey),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(acceptor_privkey),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![2],
            },
            Instruction {
                operation: Operation::LoadAmount(10_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeeratePerKw(15_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::CreateFundingTransaction,
                inputs: vec![1, 3, 4, 5],
            },
            Instruction {
                operation: Operation::BroadcastTransaction,
                inputs: vec![6],
            },
        ]
    }

    fn decode_open_channel(bytes: &[u8]) -> OpenChannel {
        match Message::decode(bytes).expect("valid message") {
            Message::OpenChannel(oc) => oc,
            other => panic!("expected OpenChannel, got type {}", other.msg_type()),
        }
    }

    fn send_open_channel_instructions() -> Vec<Instruction> {
        let mut instructions = open_channel_instructions();
        instructions.extend([
            Instruction {
                operation: Operation::BuildOpenChannel,
                inputs: (0..20).collect(),
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![20],
            },
        ]);
        instructions
    }

    // -- execute() tests --

    #[test]
    fn execute_load_build_send() {
        let pk = sample_pubkey(1);
        let mut instrs = open_channel_instructions();
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: (0..20).collect(),
        });
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap();

        assert_eq!(conn.sent.len(), 1);
        let oc = decode_open_channel(&conn.sent[0]);
        assert_eq!(oc.chain_hash, [0xcc; 32]);
        assert_eq!(oc.temporary_channel_id, ChannelId::new([0xbb; 32]));
        assert_eq!(oc.funding_satoshis, 100_000);
        assert_eq!(oc.push_msat, 0);
        assert_eq!(oc.dust_limit_satoshis, 546);
        assert_eq!(oc.max_htlc_value_in_flight_msat, 100_000_000);
        assert_eq!(oc.channel_reserve_satoshis, 10_000);
        assert_eq!(oc.htlc_minimum_msat, 1_000);
        assert_eq!(oc.feerate_per_kw, 253);
        assert_eq!(oc.to_self_delay, 144);
        assert_eq!(oc.max_accepted_htlcs, 483);
        assert_eq!(oc.funding_pubkey, pk);
        assert_eq!(oc.revocation_basepoint, pk);
        assert_eq!(oc.payment_basepoint, pk);
        assert_eq!(oc.delayed_payment_basepoint, pk);
        assert_eq!(oc.htlc_basepoint, pk);
        assert_eq!(oc.first_per_commitment_point, pk);
        assert_eq!(oc.channel_flags, 1);
        assert_eq!(oc.tlvs.upfront_shutdown_script, Some(vec![]));
        assert!(oc.tlvs.channel_type.is_none());
    }

    #[test]
    fn execute_build_channel_announcement() {
        let node_sk_1_bytes = [0x11; 32];
        let node_sk_2_bytes = [0x22; 32];
        let bitcoin_sk_1_bytes = [0x33; 32];
        let bitcoin_sk_2_bytes = [0x44; 32];
        let scid = ShortChannelId::new(539_268, 845, 1);
        let features = vec![0x01, 0x02];

        let instrs = vec![
            Instruction {
                operation: Operation::LoadFeatures(features.clone()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShortChannelId(scid.as_u64()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(node_sk_1_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(node_sk_2_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(bitcoin_sk_1_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(bitcoin_sk_2_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::BuildChannelAnnouncement,
                inputs: vec![0, 1, 2, 3, 4, 5, 6],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![7],
            },
        ];

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap();

        assert_eq!(conn.sent.len(), 1);
        let ca = match Message::decode(&conn.sent[0]).expect("valid message") {
            Message::ChannelAnnouncement(ca) => ca,
            other => panic!(
                "expected ChannelAnnouncement, got type {}",
                other.msg_type()
            ),
        };

        let secp = Secp256k1::new();
        let pk =
            |b: &[u8; 32]| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(b).unwrap());
        assert_eq!(ca.features, features);
        assert_eq!(ca.chain_hash, sample_context().chain_hash);
        assert_eq!(ca.short_channel_id, scid);
        assert_eq!(ca.node_id_1, pk(&node_sk_1_bytes));
        assert_eq!(ca.node_id_2, pk(&node_sk_2_bytes));
        assert_eq!(ca.bitcoin_key_1, pk(&bitcoin_sk_1_bytes));
        assert_eq!(ca.bitcoin_key_2, pk(&bitcoin_sk_2_bytes));
        assert!(ca.extra.is_empty());
        assert!(ca.verify());
    }

    #[test]
    fn execute_build_node_announcement() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 0x42;
        let rgb_color = [0x11, 0x22, 0x33];
        let mut alias = [0u8; 32];
        alias[..5].copy_from_slice(b"smite");
        let addresses = vec![0xaa, 0xbb, 0xcc];

        let instrs = vec![
            Instruction {
                operation: Operation::LoadPrivateKey(sk_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(vec![0x01, 0x02]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTimestamp(1_700_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadBytes(addresses.clone()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::BuildNodeAnnouncement { rgb_color, alias },
                inputs: vec![0, 1, 2, 3],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![4],
            },
        ];

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap();

        assert_eq!(conn.sent.len(), 1);
        let na = match Message::decode(&conn.sent[0]).expect("valid message") {
            Message::NodeAnnouncement(na) => na,
            other => panic!("expected NodeAnnouncement, got type {}", other.msg_type()),
        };

        let secp = Secp256k1::new();
        let expected_node_id =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
        assert_eq!(na.node_id, expected_node_id);
        assert_eq!(na.features, vec![0x01, 0x02]);
        assert_eq!(na.timestamp, 1_700_000_000);
        assert_eq!(na.rgb_color, rgb_color);
        assert_eq!(na.alias, alias);
        assert_eq!(na.addresses, addresses);
        assert!(na.extra.is_empty());
        assert!(na.verify());
    }

    #[test]
    fn execute_build_open_channel_with_tlvs() {
        let mut instrs = open_channel_instructions();
        instrs[18] = Instruction {
            operation: Operation::LoadBytes(vec![0x00, 0x14, 0xab]),
            inputs: vec![],
        };
        instrs[19] = Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
            inputs: vec![],
        };
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: (0..20).collect(),
        });
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap();

        let oc = decode_open_channel(&conn.sent[0]);
        assert_eq!(
            oc.tlvs.upfront_shutdown_script,
            Some(vec![0x00, 0x14, 0xab])
        );
        assert_eq!(oc.tlvs.channel_type, Some(vec![0x01, 0x02]));
    }

    #[test]
    fn execute_derive_point() {
        let mut instrs = vec![
            Instruction {
                operation: Operation::LoadPrivateKey([0x11; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ];

        // Use the derived point in a BuildOpenChannel to verify it produced a
        // valid Point variable.
        let base = instrs.len();
        instrs.extend(open_channel_instructions());
        // Replace funding_pubkey (input 11) with the derived point (v1).
        let mut build_inputs: Vec<usize> = (base..base + 20).collect();
        build_inputs[11] = 1;
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: build_inputs,
        });
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![base + 20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap();

        let oc = decode_open_channel(&conn.sent[0]);
        let secp = Secp256k1::new();
        let expected =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
        assert_eq!(oc.funding_pubkey, expected);
    }

    #[test]
    fn execute_recv_and_extract_all_fields() {
        let ac = sample_accept_channel();
        let ac_bytes = Message::AcceptChannel(ac).encode();

        // Receive accept_channel (v0), then extract all 16 fields (v1..v16).
        let fields = [
            AcceptChannelField::TemporaryChannelId,
            AcceptChannelField::DustLimitSatoshis,
            AcceptChannelField::MaxHtlcValueInFlightMsat,
            AcceptChannelField::ChannelReserveSatoshis,
            AcceptChannelField::HtlcMinimumMsat,
            AcceptChannelField::MinimumDepth,
            AcceptChannelField::ToSelfDelay,
            AcceptChannelField::MaxAcceptedHtlcs,
            AcceptChannelField::FundingPubkey,
            AcceptChannelField::RevocationBasepoint,
            AcceptChannelField::PaymentBasepoint,
            AcceptChannelField::DelayedPaymentBasepoint,
            AcceptChannelField::HtlcBasepoint,
            AcceptChannelField::FirstPerCommitmentPoint,
            AcceptChannelField::UpfrontShutdownScript,
            AcceptChannelField::ChannelType,
        ];

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });
        let accept_channel_idx = instrs.len() - 1;
        for field in fields {
            instrs.push(Instruction {
                operation: Operation::ExtractAcceptChannel(field),
                inputs: vec![accept_channel_idx],
            });
        }

        // TODO: Once we add IR support for building accept_channel messages,
        // rebuild a message from the extracted fields and verify it matches the
        // original.

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        conn.queue_recv(ac_bytes);
        execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap();
    }

    #[test]
    fn execute_recv_unexpected_message() {
        let init_bytes = Message::Init(Init::empty()).encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        conn.queue_recv(init_bytes);
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::UnexpectedMessage {
                expected: msg_type::ACCEPT_CHANNEL,
                got: msg_type::INIT,
            }
        ));
    }

    #[test]
    #[allow(clippy::similar_names)] // ping and pong are the canonical names
    fn execute_recv_auto_pong() {
        let ping = Ping {
            num_pong_bytes: 4,
            ignored: vec![0xaa],
        };
        let ping_bytes = Message::Ping(ping).encode();
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        conn.queue_recv(ping_bytes);
        conn.queue_recv(ac_bytes);
        execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap();

        // Verify exactly two messages were sent: `open_channel` and `pong`.
        assert_eq!(conn.sent.len(), 2);

        // Verify the first message was `open_channel`.
        let oc = Message::decode(&conn.sent[0]).unwrap();
        let Message::OpenChannel(_) = oc else {
            panic!("expected OpenChannel, got {:?}", oc.msg_type());
        };

        // Verify the second message was the pong.
        let pong = Message::decode(&conn.sent[1]).unwrap();
        let Message::Pong(pong) = pong else {
            panic!("expected Pong, got {:?}", pong.msg_type());
        };
        assert_eq!(pong.ignored.len(), 4);
    }

    // -- Error path tests --

    #[test]
    fn execute_wrong_input_count() {
        let instrs = vec![Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![], // expects 1 input
        }];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::WrongInputCount {
                expected: 1,
                got: 0,
            }
        ));
    }

    #[test]
    fn execute_type_mismatch() {
        let instrs = vec![
            Instruction {
                operation: Operation::LoadAmount(42),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0], // v0 is Amount, not PrivateKey
            },
        ];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::TypeMismatch {
                expected: VariableType::PrivateKey,
                got: VariableType::Amount,
            }
        ));
    }

    #[test]
    fn execute_variable_out_of_bounds() {
        let instrs = vec![Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![99],
        }];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(err, ExecuteError::VariableIndexOutOfBounds { .. }));
    }

    #[test]
    fn execute_forward_variable_reference() {
        // v0 tries to use v1 which hasn't been produced yet.
        let instrs = vec![
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![1],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([0x11; 32]),
                inputs: vec![],
            },
        ];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(err, ExecuteError::VariableIndexOutOfBounds { .. }));
    }

    #[test]
    fn execute_void_variable_reference() {
        // MineBlocks produces no output variable. Referencing it should fail.
        let instrs = vec![
            // v0 = void
            Instruction {
                operation: Operation::MineBlocks(1),
                inputs: vec![],
            },
            // Try to use the void variable.
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ];

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(err, ExecuteError::VoidVariable { index: 0 }));
    }

    // MineBlocks should track calls to mine_blocks
    #[test]
    fn execute_mine_blocks_invokes_cli() {
        let instrs = vec![Instruction {
            operation: Operation::MineBlocks(6),
            inputs: vec![],
        }];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let mut mock_cli = MockBitcoinCli::default();
        let context = sample_context();
        execute(
            &program,
            &context,
            &mut conn,
            &mut mock_cli,
            std::time::Instant::now(),
        )
        .unwrap();

        // Verify that mine_blocks was called with the correct number
        assert_eq!(mock_cli.mine_blocks_calls, vec![6]);
    }

    #[test]
    fn execute_mine_blocks_wrong_input() {
        let instrs = vec![
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::MineBlocks(6),
                inputs: vec![0],
            },
        ];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::WrongInputCount {
                expected: 0,
                got: 1,
            }
        ));
    }

    #[test]
    fn execute_create_and_broadcast_tx() {
        let mut conn = MockConnection::new();
        let mut mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        execute(
            &Program {
                instructions: create_and_broadcast_tx_instructions(),
            },
            &sample_context(),
            &mut conn,
            &mut mock_cli,
            std::time::Instant::now(),
        )
        .expect("tx construction and broadcast should succeed");

        assert_eq!(mock_cli.broadcast_calls.len(), 1);
        let broadcast_tx = &mock_cli.broadcast_calls[0];
        assert_eq!(
            broadcast_tx.compute_txid().to_string(),
            "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
        );
    }

    #[test]
    fn execute_create_funding_transaction_insufficient_funds() {
        // UTXO too small to cover the funding amount and fees.
        let small_utxo = Utxo {
            amount: Amount::from_sat(1_000),
            ..sample_utxo()
        };
        let mut conn = MockConnection::new();
        let mut mock_cli = MockBitcoinCli {
            utxos: vec![small_utxo],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let err = execute(
            &Program {
                instructions: create_and_broadcast_tx_instructions(),
            },
            &sample_context(),
            &mut conn,
            &mut mock_cli,
            std::time::Instant::now(),
        )
        .unwrap_err();
        let ExecuteError::InsufficientFunds(funds_err) = err else {
            panic!("expected InsufficientFunds, got {err:?}");
        };
        assert_eq!(funds_err.available, Amount::from_sat(1_000));
        assert_eq!(funds_err.required, Amount::from_sat(10_007_290));
    }

    #[test]
    fn execute_invalid_private_key() {
        let instrs = vec![
            Instruction {
                operation: Operation::LoadPrivateKey([0; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(err, ExecuteError::InvalidPrivateKey));
    }

    #[test]
    fn execute_send_open_channel_wrong_type() {
        let instrs = vec![
            Instruction {
                operation: Operation::LoadAmount(42),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
        ];

        let program = Program {
            instructions: instrs,
        };

        let err = execute(
            &program,
            &sample_context(),
            &mut MockConnection::new(),
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::TypeMismatch {
                expected: VariableType::OpenChannelMessage,
                got: VariableType::Amount,
            }
        ));
    }

    #[test]
    fn execute_affine_overuse() {
        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.extend([
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![sent_open_channel],
            },
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![sent_open_channel],
            },
        ]);
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();
        conn.queue_recv(ac_bytes);
        let err = execute(
            &program,
            &sample_context(),
            &mut conn,
            &mut MockBitcoinCli::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(err, ExecuteError::AffineOverUse { index } if index == sent_open_channel));
    }

    // -- extract_field tests --

    // TODO: Once we can actually construct and send accept_channel messages, it
    // would be better to test field extraction through an IR program that
    // receives an accept_channel, extracts all fields, constructs a new
    // accept_channel from those fields, and sends the new accept_channel. Then
    // we'll have a full roundtrip test instead of testing the extract_field
    // helper function in isolation.

    #[test]
    fn extract_scalar_fields() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::DustLimitSatoshis),
            Variable::Amount(546)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::MaxHtlcValueInFlightMsat),
            Variable::Amount(100_000_000)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ChannelReserveSatoshis),
            Variable::Amount(10_000)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::HtlcMinimumMsat),
            Variable::Amount(1_000)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::MinimumDepth),
            Variable::BlockHeight(6)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ToSelfDelay),
            Variable::U16(144)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::MaxAcceptedHtlcs),
            Variable::U16(483)
        );
    }

    #[test]
    fn extract_channel_id() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::TemporaryChannelId),
            Variable::ChannelId(ChannelId::new([0xaa; 32]))
        );
    }

    #[test]
    fn extract_pubkeys() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::FundingPubkey),
            Variable::Point(sample_pubkey(1))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::RevocationBasepoint),
            Variable::Point(sample_pubkey(2))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::PaymentBasepoint),
            Variable::Point(sample_pubkey(3))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::DelayedPaymentBasepoint),
            Variable::Point(sample_pubkey(4))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::HtlcBasepoint),
            Variable::Point(sample_pubkey(5))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::FirstPerCommitmentPoint),
            Variable::Point(sample_pubkey(6))
        );
    }

    #[test]
    fn extract_tlvs_present() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
            Variable::Bytes(vec![0xde, 0xad])
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ChannelType),
            Variable::Features(vec![0x01])
        );
    }

    #[test]
    fn extract_tlvs_absent() {
        let ac = AcceptChannel {
            tlvs: AcceptChannelTlvs::default(),
            ..sample_accept_channel()
        };
        assert_eq!(
            extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
            Variable::Bytes(vec![])
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ChannelType),
            Variable::Features(vec![])
        );
    }
}
