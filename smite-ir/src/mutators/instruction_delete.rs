//! Mutator that removes an instruction by replacing it with a Nop or
//! index renumbering.

use rand::{Rng, RngExt, seq::IteratorRandom};

use super::Mutator;
use crate::{Instruction, Operation, Program};

/// Deletes a randomly selected instruction by:
/// (i) Replacing it with a Nop (50% chance).
/// (ii) Removing it from the instuctions list and reindexing the
/// subsequent instructions (50% chance).
pub struct InstructionDeleteMutator;

impl Mutator for InstructionDeleteMutator {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        if program.instructions.is_empty() {
            return false;
        }
        // Pick a random instruction to delete.
        let deleted_idx = rng.random_range(0..program.instructions.len());
        let deleted_type = program.instructions[deleted_idx].operation.output_type();

        // Heal downstream dependencies by swapping references to a prior,
        // type-matching variable.
        if program.instructions[(deleted_idx + 1)..]
            .iter()
            .any(|instr| instr.inputs.contains(&deleted_idx))
        {
            // Abort if no valid replacement variable exists in the preceding scope.
            let Some(replacement_idx) = program.instructions[..deleted_idx]
                .iter()
                .enumerate()
                .filter_map(|(i, instr)| {
                    let out_type = instr.operation.output_type();
                    (out_type.is_some() && out_type == deleted_type).then_some(i)
                })
                .choose(rng)
            else {
                return false;
            };
            // Update dependent inputs.
            for instr in &mut program.instructions[(deleted_idx + 1)..] {
                for input in &mut instr.inputs {
                    if *input == deleted_idx {
                        *input = replacement_idx;
                    }
                }
            }
        }

        // Choose either with a uniform 50/50 split.
        if rng.random() {
            // Replace with Nop.
            program.instructions[deleted_idx] = Instruction {
                operation: Operation::Nop,
                inputs: vec![],
            };
        } else {
            // Delete from the program.
            program.instructions.remove(deleted_idx);

            // Decrement subsequent references pointing past the deleted index.
            program.instructions[deleted_idx..]
                .iter_mut()
                .for_each(|instr| {
                    for input in &mut instr.inputs {
                        if *input > deleted_idx {
                            *input -= 1;
                        }
                    }
                });
        }
        true
    }
}
