//! IR program definition.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::context::ProgramContext;
use super::instruction::Instruction;

/// An IR program: an ordered list of instructions plus execution context.
///
/// Programs are serialized with postcard for transport between the AFL++ custom
/// mutator and the scenario executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    /// Instructions in SSA order.
    pub instructions: Vec<Instruction>,
    /// Snapshot context (target pubkey, chain hash, etc.).
    pub context: ProgramContext,
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
