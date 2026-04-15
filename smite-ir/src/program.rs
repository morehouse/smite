//! IR program definition.
//!
//! A [`Program`] is an ordered list of [`Instruction`]s.  Programs are
//! serialized with `postcard` for transport between the AFL++ custom mutator
//! and the scenario executor inside the Nyx VM.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::instruction::Instruction;

/// An IR program: an ordered list of instructions.
///
/// Programs are serialized with postcard for transport between the AFL++ custom
/// mutator and the scenario executor. Execution context (target pubkey, chain
/// hash, etc.) is supplied separately by the executor at run time and is not
/// part of the serialized program.
// TODO: add `validate` method for mutators to check deserialized programs
// before mutation. Invalid programs should be rejected so that we don't panic
// when modifying and rebuilding them via `ProgramBuilder`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    /// Instructions in SSA order.
    pub instructions: Vec<Instruction>,
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
