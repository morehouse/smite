//! IR program minimizers.
//!
//! A [`Minimizer`] reduces a [`Program`] to a smaller, behaviourally
//! equivalent version in a single pass. Both transforms are safe in IR
//! semantics, so they don't need an oracle to drive the search.
//!
//! Run them in pipeline order for best results:
//! 1. [`DeadCodeEliminator`] — drop dead instructions and reindex
//! 2. [`CommonSubexpressionEliminator`] — merge equivalent pure expressions

mod cse;
mod dead_code;

pub use cse::CommonSubexpressionEliminator;
pub use dead_code::DeadCodeEliminator;

use super::Program;

/// A minimizer that reduces an IR program in one call.
pub trait Minimizer {
    /// Returns a smaller program that is behaviourally equivalent to
    /// `program` in IR semantics.
    fn minimize(&self, program: Program) -> Program;
}
