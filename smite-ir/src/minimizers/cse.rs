//! Common-subexpression elimination minimizer.

use std::collections::HashMap;

use super::Minimizer;
use crate::{Operation, Program};

/// Merges instructions that compute the same pure expression.
///
/// Two pure instructions are equivalent when they share the same operation
/// and the same canonicalized inputs. Walking the program in order makes
/// the merge transitive: by the time we reach instruction `i`, every input
/// it references has already been canonicalized, so two compute ops whose
/// inputs collapsed to the same canonical loads are themselves recognized
/// as equivalent.
///
/// Three linear passes:
/// 1. Build a remap from each pure instruction's index to the earliest
///    equivalent occurrence.
/// 2. Assign new indices to the survivors.
/// 3. Filter and rewrite inputs through the composite remap.
pub struct CommonSubexpressionEliminator;

impl Minimizer for CommonSubexpressionEliminator {
    fn minimize(&self, program: Program) -> Program {
        let n = program.instructions.len();

        let mut canonical: HashMap<(&Operation, Vec<usize>), usize> = HashMap::new();
        let mut canon_remap: Vec<usize> = (0..n).collect();
        for (i, instr) in program.instructions.iter().enumerate() {
            if !instr.operation.is_removable() {
                continue;
            }
            let canon_inputs: Vec<usize> = instr.inputs.iter().map(|&x| canon_remap[x]).collect();
            let key = (&instr.operation, canon_inputs);
            match canonical.get(&key) {
                Some(&first) => canon_remap[i] = first,
                None => {
                    canonical.insert(key, i);
                }
            }
        }

        let mut new_idx = vec![0usize; n];
        let mut next = 0;
        for i in 0..n {
            if canon_remap[i] == i {
                new_idx[i] = next;
                next += 1;
            }
        }

        let instructions = program
            .instructions
            .into_iter()
            .enumerate()
            .filter_map(|(i, mut instr)| {
                if canon_remap[i] != i {
                    return None;
                }
                for input in &mut instr.inputs {
                    *input = new_idx[canon_remap[*input]];
                }
                Some(instr)
            })
            .collect();

        Program { instructions }
    }
}
