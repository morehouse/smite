//! Mutator that removes an instruction.

use rand::{Rng, RngExt, seq::IteratorRandom};

use super::Mutator;
use crate::Program;

/// Deletes a randomly selected instruction by removing it from
/// the instructions list and reindexing the subsequent instructions.
pub struct InstructionDeleteMutator;

impl Mutator for InstructionDeleteMutator {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        if program.instructions.is_empty() {
            return false;
        }
        // Pick a random instruction to delete.
        let deleted_idx = rng.random_range(0..program.instructions.len());
        let deleted_type = program.instructions[deleted_idx].operation.output_type();

        // If any instruction downstream depends on the deleted one, pick a prior
        // type-matching variable to redirect those inputs to.
        let replacement_idx = if program.instructions[(deleted_idx + 1)..]
            .iter()
            .any(|instr| instr.inputs.contains(&deleted_idx))
        {
            let mut is_consumed = vec![false; program.instructions.len()];
            if deleted_type
                .expect("`None` shouldn't be consumed")
                .is_affine()
            {
                for (i, instr) in program.instructions.iter().enumerate() {
                    if i == deleted_idx {
                        continue;
                    }
                    for &input in &instr.inputs {
                        if program.instructions[input].operation.output_type() == deleted_type {
                            is_consumed[input] = true;
                        }
                    }
                }
            }
            match program.instructions[..deleted_idx]
                .iter()
                .enumerate()
                .filter_map(|(i, instr)| {
                    (instr.operation.output_type() == deleted_type && !is_consumed[i]).then_some(i)
                })
                .choose(rng)
            {
                Some(idx) => Some(idx),
                // Abort if no valid replacement variable exists in the preceding scope.
                None => return false,
            }
        } else {
            None
        };

        // Delete from the program.
        program.instructions.remove(deleted_idx);

        // Heal downstream inputs: redirect references to the deleted index, and
        // decrement references past it.
        for instr in &mut program.instructions[deleted_idx..] {
            for input in &mut instr.inputs {
                if *input == deleted_idx {
                    *input = replacement_idx.expect("dependent input implies replacement");
                } else if *input > deleted_idx {
                    *input -= 1;
                }
            }
        }
        true
    }
}
