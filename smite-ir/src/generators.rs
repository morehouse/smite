//! IR program generators.
//!
//! Generators produce type-correct instruction sequences that represent
//! interesting protocol interactions. Each generator knows the *shape* of a
//! protocol flow but delegates value selection and variable reuse to
//! `ProgramBuilder`.

mod open_channel;

pub use open_channel::OpenChannelGenerator;

use rand::Rng;

use super::builder::ProgramBuilder;

/// A generator that emits instructions into a `ProgramBuilder`.
pub trait Generator {
    /// Emits instructions for this generator's protocol interaction.
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng);
}
