//! Dead-code elimination minimizer.

use super::Minimizer;
use crate::Program;

/// Removes unreferenced instructions and reindexes the remaining inputs.
///
/// An instruction is removed when (a) its operation is safe to drop
/// (`is_removable`) and (b) no later instruction references its output. The
/// reverse traversal lets a chain of dead instructions collapse, once we
/// drop the user of some load, that load's reference count falls to zero
/// and the load itself becomes eligible.
pub struct DeadCodeEliminator;

impl Minimizer for DeadCodeEliminator {
    fn minimize(&self, program: Program) -> Program {
        let n = program.instructions.len();
        let mut ref_count = vec![0usize; n];
        for instr in &program.instructions {
            for &input in &instr.inputs {
                if input < n {
                    ref_count[input] += 1;
                }
            }
        }

        let mut keep = vec![true; n];
        for idx in (0..n).rev() {
            if ref_count[idx] != 0 || !program.instructions[idx].operation.is_removable() {
                continue;
            }
            for &input in &program.instructions[idx].inputs {
                if input < n {
                    ref_count[input] -= 1;
                }
            }
            keep[idx] = false;
        }

        let mut remap = vec![0usize; n];
        let mut next = 0;
        for (old, &k) in keep.iter().enumerate() {
            if k {
                remap[old] = next;
                next += 1;
            }
        }

        let instructions = program
            .instructions
            .into_iter()
            .enumerate()
            .filter_map(|(old, mut instr)| {
                if !keep[old] {
                    return None;
                }
                for input in &mut instr.inputs {
                    *input = remap[*input];
                }
                Some(instr)
            })
            .collect();

        Program { instructions }
    }
}
