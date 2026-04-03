//! Mutator that swaps an instruction's input to a different variable of the
//! same type.

use rand::Rng;
use rand::seq::IteratorRandom;

use super::Mutator;
use crate::Program;

/// Swaps a randomly chosen input reference to point at a different variable of
/// the same type.  This explores alternative data-flow paths while preserving
/// type correctness.
pub struct InputSwapMutator;

impl Mutator for InputSwapMutator {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        // Pick a random (instruction index, input position) pair.
        let Some((instr_idx, input_pos)) = program
            .instructions
            .iter()
            .enumerate()
            .flat_map(|(i, instr)| (0..instr.inputs.len()).map(move |j| (i, j)))
            .choose(rng)
        else {
            return false;
        };

        let current_input = program.instructions[instr_idx].inputs[input_pos];
        let expected_type = program.instructions[instr_idx].operation.input_types()[input_pos];

        // Pick an alternative variable defined before this instruction with the
        // matching type, excluding the current input.
        let Some(new_input) = program.instructions[..instr_idx]
            .iter()
            .enumerate()
            .filter_map(|(i, instr)| {
                let out_type = instr.operation.output_type()?;
                (out_type == expected_type && i != current_input).then_some(i)
            })
            .choose(rng)
        else {
            return false;
        };

        program.instructions[instr_idx].inputs[input_pos] = new_input;
        true
    }
}
