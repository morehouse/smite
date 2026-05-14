//! Minimal AFL++ harness for the smite IR custom-mutator e2e test.
//!
//! ## Design principle: coverage comes only from side-effecting work
//!
//! Smite only cares about what the IR program *does* against the
//! target -- bytes it sends, responses it receives. Pure setup
//! instructions (load a literal, derive a point, extract a field)
//! are means to that end and aren't fuzzing signal by themselves.
//! This is true for any smite workload, not just this e2e test: the
//! harness emits coverage feedback only for instructions
//! transitively feeding a side-effect root.
//! Programs that load and compute but never act produce *zero*
//! coverage and AFL never queues them.
//!
//! ## Why we hand-roll the bitmap
//!
//! The bitmap must be *bit-identical* across DCE/CSE-trimmed variants
//! of the same program (so AFL's trim cksum accepts the shrunk
//! candidate) yet *vary* under our mutators (so AFL queues new
//! entries). Any compiler-inserted edge whose hit count tracks
//! `program.instructions.len()` fails the first half: DCE/CSE move
//! the count across AFL's hit-count buckets and the cksum mismatches.
//! `postcard::from_bytes` and `Program::validate` both contain such
//! loops, and rustc doesn't expose a SanitizerCoverage allowlist to
//! exclude them.
//!
//! So we disable SanitizerCoverage entirely (build with
//! `RUSTFLAGS=-Cllvm-args=-sanitizer-coverage-level=0`) and publish
//! coverage manually. The signal: for each instruction reachable from
//! a side-effect root, mark a slot derived from a content hash of
//! `(operation, hashes of inputs)`. Because the hash folds *input
//! content* (not indices), DCE renumbering doesn't change it; CSE
//! merges duplicates whose hashes were already equal;
//! `OperationParamMutator` shifts an operation's hash (and its
//! consumers'); `InputSwapMutator` rewires an edge and shifts the
//! consumer's hash.
//!
//! We don't use `afl::fuzz!`: it forces persistent + shmem delivery,
//! which hangs during calibration when SanitizerCoverage is off. We
//! call `__afl_manual_init` and read each test case from stdin.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;

use smite_ir::{Operation, Program};

unsafe extern "C" {
    static __afl_area_ptr: *mut u8;
    fn __afl_manual_init();
}

/// Overrides afl-compiler-rt's weak symbol to keep test cases on
/// stdin instead of shared memory (see module docs).
#[unsafe(no_mangle)]
pub static mut __afl_sharedmem_fuzzing: i32 = 0;

/// Matches `AFL_MAP_SIZE=65536` set by the test driver.
const MAP_MASK: u32 = (1 << 16) - 1;

fn main() {
    unsafe { __afl_manual_init() };

    let mut data = Vec::new();
    if std::io::stdin().lock().read_to_end(&mut data).is_err() {
        return;
    }
    let Ok(program) = postcard::from_bytes::<Program>(&data) else {
        return;
    };
    if program.validate().is_err() {
        return;
    }

    // Content hash per instruction. SSA order means an instruction's
    // inputs are already hashed by the time we reach it, so one
    // forward pass is enough -- no recursion or memoization needed.
    let n = program.instructions.len();
    let mut hashes = vec![0u64; n];
    for (i, instr) in program.instructions.iter().enumerate() {
        let mut h = DefaultHasher::new();
        instr.operation.hash(&mut h);
        for &inp in &instr.inputs {
            if inp < i {
                hashes[inp].hash(&mut h);
            }
        }
        hashes[i] = h.finish();
    }

    // Mark slots for instructions reachable from side-effect roots.
    // Pure instructions that never feed a SendMessage/RecvAcceptChannel
    // contribute no coverage. Walk in reverse so a marked instruction 
    // propagates to its (earlier) inputs in one pass.
    let mut reachable = vec![false; n];
    let ptr = unsafe { __afl_area_ptr };
    for i in (0..n).rev() {
        let instr = &program.instructions[i];
        let is_root = matches!(
            instr.operation,
            Operation::SendMessage | Operation::RecvAcceptChannel
        );
        if !(is_root || reachable[i]) {
            continue;
        }
        reachable[i] = true;
        for &inp in &instr.inputs {
            if inp < n {
                reachable[inp] = true;
            }
        }
        if !ptr.is_null() {
            let slot = (hashes[i] as u32) & MAP_MASK;
            unsafe { *ptr.add(slot as usize) = 1 };
        }
    }
}
