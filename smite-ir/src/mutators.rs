//! IR program mutators.
//!
//! Mutators transform programs to explore new protocol states while preserving
//! structural validity. Each mutator makes a small, targeted change.

mod input_swap;
mod instruction_reorder;
mod operation_param;

pub use input_swap::InputSwapMutator;
pub use instruction_reorder::InstructionReorderMutator;
pub use operation_param::OperationParamMutator;

use rand::Rng;

use super::Program;

/// A mutator that transforms an IR program in place.
pub trait Mutator {
    /// Applies a single mutation to the program. Returns `true` if a mutation
    /// was made.
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool;
}
