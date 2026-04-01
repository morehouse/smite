//! Smite IR: intermediate representation for structured Lightning protocol
//! fuzzing.
//!
//! This crate defines the IR types, generators, and mutators used to produce
//! and transform structured fuzzing programs.  It is engine-agnostic -- no
//! dependency on AFL++ or `LibAFL`.

pub mod builder;
pub mod context;
pub mod generators;
pub mod instruction;
pub mod operation;
pub mod program;
pub mod variable;

pub use builder::ProgramBuilder;
pub use context::ProgramContext;
pub use generators::Generator;
pub use instruction::Instruction;
pub use operation::Operation;
pub use program::Program;
pub use variable::{Variable, VariableType};

#[cfg(test)]
mod tests;
