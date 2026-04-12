//! IR program executor.
//!
//! Executes an IR program against a target node over an established connection,
//! producing side effects (sending/receiving messages).

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use smite::bolt::{
    AcceptChannel, ChannelId, Message, OpenChannel, OpenChannelTlvs, Pong, msg_type,
};
use smite::noise::{ConnectionError, NoiseConnection};
use smite_ir::operation::AcceptChannelField;
use smite_ir::{Operation, Program, Variable, VariableType};

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

    /// Connection or send/receive failure.
    #[error("connection: {0}")]
    Connection(#[from] smite::noise::ConnectionError),

    /// Failed to decode a received message.
    #[error("decode: {0}")]
    Decode(#[from] smite::bolt::BoltError),

    /// Received a different message type than expected.
    #[error("unexpected message: expected type {expected}, got {got}")]
    UnexpectedMessage { expected: u16, got: u16 },
}

/// Executes an IR program against a target over the given connection.
///
/// # Errors
///
/// Returns an error if any instruction fails (type mismatch, connection error,
/// decode error, etc.).
pub fn execute(
    program: &Program,
    context: &ProgramContext,
    conn: &mut impl Connection,
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
            Operation::LoadFeeratePerKw(v) => Some(Variable::FeeratePerKw(*v)),
            Operation::LoadBlockHeight(v) => Some(Variable::BlockHeight(*v)),
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

            // -- Build operations --
            Operation::BuildOpenChannel => {
                let oc = build_open_channel(&variables, &instr.inputs)?;
                let encoded = Message::OpenChannel(oc).encode();
                Some(Variable::Message(encoded))
            }

            // -- Act operations --
            Operation::SendMessage => {
                let bytes = resolve_message(&variables, instr.inputs[0])?;
                conn.send_message(bytes)?;
                None
            }

            Operation::RecvAcceptChannel => {
                let ac = recv_accept_channel(conn)?;
                Some(Variable::AcceptChannel(ac))
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

// -- Operation handlers --

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

    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
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

    fn decode_open_channel(bytes: &[u8]) -> OpenChannel {
        match Message::decode(bytes).expect("valid message") {
            Message::OpenChannel(oc) => oc,
            other => panic!("expected OpenChannel, got type {}", other.msg_type()),
        }
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
            operation: Operation::SendMessage,
            inputs: vec![20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(&program, &sample_context(), &mut conn).unwrap();

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
            operation: Operation::SendMessage,
            inputs: vec![20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(&program, &sample_context(), &mut conn).unwrap();

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
            operation: Operation::SendMessage,
            inputs: vec![base + 20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        execute(&program, &sample_context(), &mut conn).unwrap();

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

        let mut instrs = vec![Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![],
        }];
        for field in fields {
            instrs.push(Instruction {
                operation: Operation::ExtractAcceptChannel(field),
                inputs: vec![0],
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
        execute(&program, &sample_context(), &mut conn).unwrap();
    }

    #[test]
    fn execute_recv_unexpected_message() {
        let init_bytes = Message::Init(Init::empty()).encode();

        let instrs = vec![Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![],
        }];

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        conn.queue_recv(init_bytes);
        let err = execute(&program, &sample_context(), &mut conn).unwrap_err();
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

        let instrs = vec![Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![],
        }];

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        conn.queue_recv(ping_bytes);
        conn.queue_recv(ac_bytes);
        execute(&program, &sample_context(), &mut conn).unwrap();

        // Verify a correctly-sized pong was sent.
        assert_eq!(conn.sent.len(), 1);
        let pong = Message::decode(&conn.sent[0]).unwrap();
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
        let err = execute(&program, &sample_context(), &mut conn).unwrap_err();
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
        let err = execute(&program, &sample_context(), &mut conn).unwrap_err();
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
            operation: Operation::SendMessage,
            inputs: vec![99],
        }];
        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(&program, &sample_context(), &mut conn).unwrap_err();
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
        let err = execute(&program, &sample_context(), &mut conn).unwrap_err();
        assert!(matches!(err, ExecuteError::VariableIndexOutOfBounds { .. }));
    }

    #[test]
    fn execute_void_variable_reference() {
        // SendMessage produces no output variable. Referencing it should fail.
        let mut instrs = open_channel_instructions();
        // v20 = Message
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: (0..20).collect(),
        });
        // v21 = void
        instrs.push(Instruction {
            operation: Operation::SendMessage,
            inputs: vec![20],
        });
        // Try to use the void variable.
        instrs.push(Instruction {
            operation: Operation::SendMessage,
            inputs: vec![21],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut conn = MockConnection::new();
        let err = execute(&program, &sample_context(), &mut conn).unwrap_err();
        assert!(matches!(err, ExecuteError::VoidVariable { index: 21 }));
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
        let err = execute(&program, &sample_context(), &mut conn).unwrap_err();
        assert!(matches!(err, ExecuteError::InvalidPrivateKey));
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
