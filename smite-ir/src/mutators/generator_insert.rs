//! Mutator that inserts generated programs.

use rand::{Rng, RngExt};

use super::Mutator;
use crate::{Generator, Program, ProgramBuilder};

/// Inserts a generated program at a random point in the given program.
pub struct GeneratorInsertionMutator<G: Generator> {
    generator: G,
}

impl<G: Generator> GeneratorInsertionMutator<G> {
    pub fn new(generator: G) -> Self {
        Self { generator }
    }
}

impl<G: Generator> Mutator for GeneratorInsertionMutator<G> {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        let insert_idx = rng.random_range(0..=program.instructions.len());
        let mut builder = ProgramBuilder::new();
        let mut iter = std::mem::take(&mut program.instructions).into_iter();

        // Consume and append the pre-insertion instructions.
        for instr in iter.by_ref().take(insert_idx) {
            builder.append(instr.operation, &instr.inputs);
        }

        // Generate and insert a new program.
        self.generator.generate(&mut builder, rng);
        let offset = builder.instructions_len() - insert_idx;

        // Consume, shift, and append the post-insertion instructions.
        for mut instr in iter {
            for input in &mut instr.inputs {
                if *input >= insert_idx {
                    *input += offset;
                }
            }
            builder.append(instr.operation, &instr.inputs);
        }
        *program = builder.build();

        true
    }
}
