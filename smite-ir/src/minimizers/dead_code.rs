//! Dead-code elimination minimizer.

use super::Minimizer;
use crate::Program;

/// Removes unreferenced instructions and reindexes the remaining inputs.
///
/// An instruction is removed when (a) its operation has no side effects
/// and (b) no later instruction references its output. The reverse
/// traversal lets a chain of dead instructions collapse, once we drop the
/// user of some load, that load's reference count falls to zero and the
/// load itself becomes eligible.
pub struct DeadCodeEliminator;

impl Minimizer for DeadCodeEliminator {
    fn minimize(&self, program: &mut Program) -> bool {
        let n = program.instructions.len();
        let mut keep = vec![false; n];
        for idx in (0..n).rev() {
            if !keep[idx] && !program.instructions[idx].operation.has_side_effects() {
                continue;
            }
            keep[idx] = true;
            for &input in &program.instructions[idx].inputs {
                keep[input] = true;
            }
        }

        let mut remap = vec![0usize; n];
        let mut instructions = Vec::with_capacity(n);
        for (old, mut instr) in std::mem::take(&mut program.instructions)
            .into_iter()
            .enumerate()
        {
            if !keep[old] {
                continue;
            }
            for input in &mut instr.inputs {
                *input = remap[*input];
            }
            remap[old] = instructions.len();
            instructions.push(instr);
        }

        let changed = instructions.len() < n;
        program.instructions = instructions;
        changed
    }
}
