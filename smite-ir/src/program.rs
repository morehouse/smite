//! IR program definition.
//!
//! A [`Program`] is an ordered list of [`Instruction`]s.  Programs are
//! serialized with `postcard` for transport between the AFL++ custom mutator
//! and the scenario executor inside the Nyx VM.

use std::fmt;

use serde::{Deserialize, Serialize};
use smite::bolt::MAX_MESSAGE_SIZE;
use thiserror::Error;

use super::VariableType;
use super::instruction::Instruction;
use super::operation::Operation;

/// An IR program: an ordered list of instructions.
///
/// Programs are serialized with postcard for transport between the AFL++ custom
/// mutator and the scenario executor. Execution context (target pubkey, chain
/// hash, etc.) is supplied separately by the executor at run time and is not
/// part of the serialized program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    /// Instructions in SSA order.
    pub instructions: Vec<Instruction>,
}

/// Reasons a program can fail [`Program::validate`].
///
/// Mirrors the assertions in `ProgramBuilder::append`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidateError {
    /// An instruction has the wrong number of inputs for its operation.
    #[error("instruction {instr}: expected {expected} inputs, got {got}")]
    WrongInputCount {
        /// Index of the offending instruction.
        instr: usize,
        /// Number of inputs the operation expects.
        expected: usize,
        /// Number of inputs actually present.
        got: usize,
    },
    /// An input references an instruction index that does not exist or is not
    /// strictly less than the referencing instruction's own index (SSA
    /// violation).
    #[error("instruction {instr} input {input}: index {index} out of bounds")]
    InputOutOfBounds {
        /// Index of the offending instruction.
        instr: usize,
        /// Position of the input within the instruction's input list.
        input: usize,
        /// The out-of-range index that was referenced.
        index: usize,
    },
    /// An input references an instruction whose operation produces no output
    /// (e.g., `SendMessage`).
    #[error("instruction {instr} input {input}: index {index} refers to a void instruction")]
    VoidInput {
        /// Index of the offending instruction.
        instr: usize,
        /// Position of the input within the instruction's input list.
        input: usize,
        /// The referenced instruction index.
        index: usize,
    },
    /// An input has the wrong variable type for its position in the operation.
    #[error("instruction {instr} input {input}: expected {expected:?}, got {got:?}")]
    TypeMismatch {
        /// Index of the offending instruction.
        instr: usize,
        /// Position of the input within the instruction's input list.
        input: usize,
        /// The variable type the operation expects.
        expected: VariableType,
        /// The variable type actually produced by the referenced instruction.
        got: VariableType,
    },
    /// A `LoadBytes` or `LoadFeatures` operation contains more bytes than
    /// `MAX_MESSAGE_SIZE`, which would panic in the BOLT encoder.
    #[error("instruction {instr}: byte field length {len} exceeds MAX_MESSAGE_SIZE")]
    OversizedBytes {
        /// Index of the offending instruction.
        instr: usize,
        /// Actual byte length.
        len: usize,
    },
    /// An affine variable is used more than once.
    #[error("Variable {index}: affine {var_type:?} consumed twice (max 1)")]
    AffineOverUse {
        /// The overused affine variable index.
        index: usize,
        /// Type of the affine variable.
        var_type: VariableType,
    },
}

impl Program {
    /// Validates that the program is well-formed: every instruction has the
    /// right number of inputs, every input references a prior non-void
    /// instruction, and every input's type matches what its operation expects.
    ///
    /// `ProgramBuilder` enforces most of these properties during construction;
    /// this method exists so mutators can check programs that arrived from an
    /// untrusted source (e.g., a corpus file decoded by the AFL++ custom
    /// mutator) before attempting to mutate them.
    ///
    /// # Errors
    ///
    /// Returns the first violation encountered.
    pub fn validate(&self) -> Result<(), ValidateError> {
        let mut affine_consumed = vec![false; self.instructions.len()];

        for (instr_idx, instr) in self.instructions.iter().enumerate() {
            let expected = instr.operation.input_types();
            if instr.inputs.len() != expected.len() {
                return Err(ValidateError::WrongInputCount {
                    instr: instr_idx,
                    expected: expected.len(),
                    got: instr.inputs.len(),
                });
            }
            for (input_pos, (&input_idx, &expected_type)) in
                instr.inputs.iter().zip(expected.iter()).enumerate()
            {
                if input_idx >= instr_idx {
                    return Err(ValidateError::InputOutOfBounds {
                        instr: instr_idx,
                        input: input_pos,
                        index: input_idx,
                    });
                }
                let Some(actual_type) = self.instructions[input_idx].operation.output_type() else {
                    return Err(ValidateError::VoidInput {
                        instr: instr_idx,
                        input: input_pos,
                        index: input_idx,
                    });
                };
                if actual_type != expected_type {
                    return Err(ValidateError::TypeMismatch {
                        instr: instr_idx,
                        input: input_pos,
                        expected: expected_type,
                        got: actual_type,
                    });
                }
                if expected_type.is_affine() {
                    if affine_consumed[input_idx] {
                        return Err(ValidateError::AffineOverUse {
                            index: input_idx,
                            var_type: expected_type,
                        });
                    }
                    affine_consumed[input_idx] = true;
                }
            }
            if let Operation::LoadBytes(b) | Operation::LoadFeatures(b) = &instr.operation
                && b.len() > MAX_MESSAGE_SIZE
            {
                return Err(ValidateError::OversizedBytes {
                    instr: instr_idx,
                    len: b.len(),
                });
            }
        }
        Ok(())
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, instr) in self.instructions.iter().enumerate() {
            let op = &instr.operation;

            if op.output_type().is_some() {
                write!(f, "v{i} = {op}")?;
            } else {
                write!(f, "{op}")?;
            }

            if !instr.inputs.is_empty() {
                let inputs: Vec<String> =
                    instr.inputs.iter().map(|idx| format!("v{idx}")).collect();
                write!(f, "({})", inputs.join(", "))?;
            }

            writeln!(f)?;
        }
        Ok(())
    }
}
