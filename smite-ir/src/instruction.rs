//! IR instructions (operation + input variable references).

use serde::{Deserialize, Serialize};

use super::Operation;

/// A single IR instruction: an operation plus indices into the variable store.
///
/// In SSA form, each instruction produces at most one variable (at the index
/// equal to the instruction's position in the program).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// The operation to perform.
    pub operation: Operation,
    /// Indices of input variables in the executor's variable store.
    pub inputs: Vec<usize>,
}
