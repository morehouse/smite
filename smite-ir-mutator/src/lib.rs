//! AFL++ custom mutator C ABI shim.
//!
//! This crate exports the `afl_custom_*` symbols that AFL++ looks up via
//! `dlsym` when a shared library is supplied through
//! `AFL_CUSTOM_MUTATOR_LIBRARY`. The resulting `.so` (built via
//! `crate-type = ["cdylib"]`) is the *only* way AFL++ produces inputs for the
//! IR fuzzer.
//!
//! # AFL++ environment contract
//!
//! Set the following when launching `afl-fuzz`:
//! - `AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/libsmite_ir_mutator.so`
//! - `AFL_CUSTOM_MUTATOR_ONLY=1` -- disable AFL++'s byte mutators. This also
//!   disables the havoc stage entirely, so we deliberately do not implement
//!   `afl_custom_havoc_mutation`.
//!
//! # Buffer ownership
//!
//! `MutatorState` owns a `Vec<u8>` (`out_buf`) that holds the serialized
//! mutated program. When AFL++ requests a new input from us, we hand it a
//! pointer to that `Vec<u8>` along with its length. AFL++ never saves the
//! pointer across calls, so we're safe to reuse the buffer for the next input.

use std::os::raw::{c_char, c_uint, c_void};
use std::slice;

use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use smite_ir::generators::OpenChannelGenerator;
use smite_ir::minimizers::{CommonSubexpressionEliminator, DeadCodeEliminator, Minimizer};
use smite_ir::mutators::{InputSwapMutator, OperationParamMutator};
use smite_ir::{Generator, Mutator, Program, ProgramBuilder};

/// Mutator state owned by AFL++ across calls. Allocated by [`afl_custom_init`],
/// destroyed by [`afl_custom_deinit`].
struct MutatorState {
    rng: SmallRng,
    /// Reusable buffer for serialized mutated programs. The pointer to its
    /// contents is what we hand back to AFL++ when it requests an input.
    out_buf: Vec<u8>,
    /// Reusable null-terminated description string returned by
    /// [`afl_custom_describe`].
    description: Vec<u8>,
    /// Sequence of actions taken in the last [`afl_custom_fuzz`] call, used by
    /// [`afl_custom_describe`] to name queue entries.
    last_sequence: Vec<&'static str>,
    /// `true` after [`afl_custom_init_trim`] has serialized a trimmed
    /// candidate into `out_buf`; cleared by the first [`afl_custom_trim`]
    /// call when it hands the buffer back to AFL.
    trim_pending: bool,
}

impl MutatorState {
    fn new(seed: u32) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(u64::from(seed)),
            out_buf: Vec::new(),
            description: Vec::new(),
            last_sequence: vec!["init"],
            trim_pending: false,
        }
    }

    /// Generates a fresh program from scratch using `OpenChannelGenerator`.
    fn generate_fresh(&mut self) -> Program {
        let mut builder = ProgramBuilder::new();
        OpenChannelGenerator.generate(&mut builder, &mut self.rng);
        self.last_sequence.clear();
        self.last_sequence.push("fresh");
        builder.build()
    }

    /// Applies a random number of stacked mutations to `program`. The stack
    /// count is a power of two in `[1, 16]` to give a mix of small tweaks and
    /// larger leaps per execution, similar in spirit to AFL++'s havoc stage.
    /// Records the ordered list of mutator names in `last_sequence`.
    fn mutate_stacked(&mut self, program: &mut Program) {
        self.last_sequence.clear();
        // Power-of-two stack count: 1, 2, 4, 8, or 16 mutations.
        let stack = 1u32 << self.rng.random_range(0..=4);
        for _ in 0..stack {
            // Uniform pick between the available mutators.
            let name = if self.rng.random() {
                OperationParamMutator.mutate(program, &mut self.rng);
                "op-param"
            } else {
                InputSwapMutator.mutate(program, &mut self.rng);
                "input-swap"
            };
            self.last_sequence.push(name);
        }
    }

    /// Postcard-encodes `program` into `self.out_buf`, reusing the existing
    /// allocation. Returns `true` if the encoded length fits within `max_size`.
    fn serialize(&mut self, program: &Program, max_size: usize) -> bool {
        let mut buf = std::mem::take(&mut self.out_buf);
        buf.clear();
        match postcard::to_extend(program, buf) {
            Ok(buf) => {
                self.out_buf = buf;
                self.out_buf.len() <= max_size
            }
            Err(_) => false,
        }
    }
}

/// Decodes `bytes` as a postcard-encoded `Program` and validates it. Returns
/// `Some(program)` only if both decoding and validation succeed.
fn decode_and_validate(bytes: &[u8]) -> Option<Program> {
    let program: Program = postcard::from_bytes(bytes).ok()?;
    program.validate().ok()?;
    Some(program)
}

// -- AFL++ custom mutator ABI -------------------------------------------------

/// Allocates a new [`MutatorState`] and returns an opaque pointer to it. AFL++
/// passes this pointer back on every function call as the `data` argument.
///
/// # Safety
///
/// The returned pointer is heap-allocated via `Box::into_raw` and must be freed
/// by a matching call to [`afl_custom_deinit`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_init(_afl: *const c_void, seed: c_uint) -> *mut c_void {
    Box::into_raw(Box::new(MutatorState::new(seed))).cast::<c_void>()
}

/// Frees the [`MutatorState`] previously returned by [`afl_custom_init`].
///
/// # Safety
///
/// `data` must be a pointer previously returned by [`afl_custom_init`] and
/// not yet freed. After this call, `data` must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_deinit(data: *mut c_void) {
    drop(unsafe { Box::from_raw(data.cast::<MutatorState>()) });
}

/// Generates one mutated input from the seed at `buf`.
///
/// If `buf_size == 0` or postcard decoding/validation fails, falls back to
/// generating a fresh program. Otherwise applies a stack of mutations (see
/// [`MutatorState::mutate_stacked`]) to the decoded program; with 5%
/// probability of regenerating from scratch anyway to avoid getting stuck on a
/// single seed.
///
/// `*out_buf` is always set to a valid, non-null pointer before returning (even
/// on failure, where we return 0 and point at our empty buffer). The buffer at
/// `*out_buf` remains valid until the next call to `afl_custom_fuzz`.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - `buf` must point to `buf_size` readable bytes.
/// - `out_buf` must be a valid, writable pointer to a `*const u8` slot.
/// - `_add_buf` is unused; we export `afl_custom_splice_optout` so AFL++ never
///   populates it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_fuzz(
    data: *mut c_void,
    buf: *mut u8,
    buf_size: usize,
    out_buf: *mut *const u8,
    _add_buf: *mut u8,
    _add_buf_size: usize,
    max_size: usize,
) -> usize {
    let state = unsafe { &mut *data.cast::<MutatorState>() };

    let generate_fresh = buf_size == 0 || state.rng.random_range(0..20) == 0;
    let program = if generate_fresh {
        state.generate_fresh()
    } else {
        let input = unsafe { slice::from_raw_parts(buf, buf_size) };
        match decode_and_validate(input) {
            Some(mut p) => {
                state.mutate_stacked(&mut p);
                p
            }
            None => state.generate_fresh(),
        }
    };

    let len = if state.serialize(&program, max_size) {
        state.out_buf.len()
    } else {
        0
    };
    unsafe { *out_buf = state.out_buf.as_ptr() };
    len
}

/// Runs the full minimizer pipeline (`DeadCodeEliminator` then
/// `CommonSubexpressionEliminator`) on the corpus entry and stages the
/// resulting candidate for [`afl_custom_trim`] to hand back.
///
/// Both minimizers are deterministic in-process transforms safe in IR
/// semantics, so we don't need iterative AFL feedback. We compose them
/// once and offer a single candidate. AFL still gets to verify it (its
/// coverage cksum is the source of truth); on rejection AFL silently
/// discards the candidate and keeps the original corpus entry.
///
/// AFL drives the trim loop with `while (stage_cur < stage_max)`, where
/// `stage_max` is this function's return value and `stage_cur` is updated
/// from [`afl_custom_post_trim`]'s return.
///
/// # Returns
///
/// - `1` if there's a candidate to offer (decode succeeded, validate
///   passed, and the trim actually shrank the program). AFL enters the
///   trim loop for one iteration.
/// - `0` if there's nothing to do (decode/validate failed, or the trim
///   was a no-op). AFL skips trim entirely.
/// - Negative would signal a fatal error to AFL; we never produce one.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - `buf` must point to `buf_size` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_init_trim(
    data: *mut c_void,
    buf: *mut u8,
    buf_size: usize,
) -> i32 {
    let state = unsafe { &mut *data.cast::<MutatorState>() };
    state.trim_pending = false;

    let input = unsafe { slice::from_raw_parts(buf, buf_size) };
    let Some(program) = decode_and_validate(input) else {
        return 0;
    };

    let trimmed =
        CommonSubexpressionEliminator.minimize(DeadCodeEliminator.minimize(program.clone()));
    if trimmed == program || !state.serialize(&trimmed, usize::MAX) {
        return 0;
    }

    state.trim_pending = true;
    1
}

/// Hands the pre-serialized trimmed candidate back to AFL.
///
/// The pointer written into `*out_buf` borrows from `MutatorState::out_buf`
/// and is valid until the next call into this library; AFL copies the
/// bytes before re-entering us. We always write a non-null pointer (even
/// on the zero-length path) to satisfy AFL's `if (unlikely(!retbuf))
/// FATAL(...)` check.
///
/// # Returns
///
/// - `> 0` on the first call after [`afl_custom_init_trim`]: the byte
///   length of the candidate at `*out_buf`.
/// - `0` afterwards. AFL treats this as "skip this iteration" rather than
///   a stop signal; the loop terminates via [`afl_custom_post_trim`]'s
///   return.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - `out_buf` must be a valid, writable pointer to a `*const u8` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_trim(data: *mut c_void, out_buf: *mut *const u8) -> usize {
    let state = unsafe { &mut *data.cast::<MutatorState>() };
    unsafe { *out_buf = state.out_buf.as_ptr() };
    if state.trim_pending {
        state.trim_pending = false;
        state.out_buf.len()
    } else {
        0
    }
}

/// Always returns `1` to terminate AFL's trim loop after a single
/// iteration.
///
/// AFL drives trim with `while (stage_cur < stage_max)` and assigns
/// `stage_cur` from this function's return value. With `stage_max = 1`
/// (set by [`afl_custom_init_trim`]), returning `1` makes the condition
/// `1 < 1` false and breaks the loop.
///
/// `success` indicates whether the candidate's coverage cksum matched the
/// original. We don't need to act on it: AFL itself either persists the
/// trimmed buffer (on success) or keeps the original corpus entry (on
/// failure), and we don't track partial state across iterations because
/// there's only one.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_post_trim(_data: *mut c_void, _success: u8) -> i32 {
    1
}

/// Marker symbol that tells AFL++ not to populate `add_buf` for
/// [`afl_custom_fuzz`]. AFL++ never actually calls this function -- it only
/// checks for the symbol's presence via `dlsym` and, if found, skips picking a
/// splice input before each fuzz call.
///
/// # Safety
///
/// Never invoked; the signature exists only so the symbol has the correct
/// linkage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_splice_optout(_data: *mut c_void) {}

/// Returns a null-terminated description of the most recently applied mutation.
/// AFL++ uses this when naming queue entries.
///
/// The description is trimmed to fit within `max_description_len` bytes
/// (excluding the trailing null).
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - The returned pointer is owned by the [`MutatorState`] and remains valid
///   only until the next call into this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_describe(
    data: *mut c_void,
    max_description_len: usize,
) -> *const c_char {
    let state = unsafe { &mut *data.cast::<MutatorState>() };
    state.description.clear();
    state.description.extend_from_slice(b"smite-ir:");
    for (i, name) in state.last_sequence.iter().enumerate() {
        if i > 0 {
            state.description.push(b',');
        }
        state.description.extend_from_slice(name.as_bytes());
    }
    // Leave room for the trailing null terminator.
    if state.description.len() > max_description_len {
        state.description.truncate(max_description_len);
    }
    state.description.push(0);
    state.description.as_ptr().cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr;

    use super::*;

    /// RAII wrapper that calls `afl_custom_init` on construction and
    /// `afl_custom_deinit` on drop.
    struct State(*mut c_void);

    impl State {
        fn new(seed: u32) -> Self {
            Self(unsafe { afl_custom_init(ptr::null(), seed) })
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            unsafe { afl_custom_deinit(self.0) };
        }
    }

    /// Calls `afl_custom_fuzz` and returns `(out, len)`. The returned pointer
    /// is borrowed from the state's internal buffer and is only valid until the
    /// next call into the library.
    fn fuzz_via_ffi(state: &State, mut input: Vec<u8>, max_size: usize) -> (*const u8, usize) {
        let mut out: *const u8 = ptr::null();
        let len = unsafe {
            afl_custom_fuzz(
                state.0,
                input.as_mut_ptr(),
                input.len(),
                &raw mut out,
                ptr::null_mut(),
                0,
                max_size,
            )
        };
        (out, len)
    }

    fn decode_and_validate(out: *const u8, len: usize) -> Program {
        let bytes = unsafe { slice::from_raw_parts(out, len) };
        let program: Program = postcard::from_bytes(bytes).expect("decode");
        program.validate().expect("valid program");
        program
    }

    fn verify_fresh_generation(state: &State) {
        let ptr = unsafe { afl_custom_describe(state.0, 64) };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("valid utf-8");
        assert_eq!(s, "smite-ir:fresh", "fresh generation did not occur");
    }

    fn seed_program_bytes() -> Vec<u8> {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut builder = ProgramBuilder::new();
        OpenChannelGenerator.generate(&mut builder, &mut rng);
        postcard::to_allocvec(&builder.build()).expect("postcard serialization")
    }

    /// `seed_program_bytes()` plus an unreferenced `LoadAmount`, so the
    /// pipeline has something for DCE to drop (and thus `init_trim`
    /// returns `1`).
    fn reducible_seed_bytes() -> Vec<u8> {
        let bytes = seed_program_bytes();
        let mut program: Program = postcard::from_bytes(&bytes).expect("decode");
        program.instructions.push(smite_ir::Instruction {
            operation: smite_ir::Operation::LoadAmount(0xdead_beef),
            inputs: vec![],
        });
        postcard::to_allocvec(&program).expect("encode")
    }

    #[test]
    fn init_returns_nonnull() {
        let state = State::new(0);
        assert!(!state.0.is_null());
    }

    #[test]
    fn fuzz_with_empty_input_generates_fresh() {
        let state = State::new(1);
        let (out, len) = fuzz_via_ffi(&state, Vec::new(), 1 << 16);
        assert!(len > 0);
        decode_and_validate(out, len);
        verify_fresh_generation(&state);
    }

    #[test]
    fn fuzz_valid_input_produces_valid_output() {
        let state = State::new(2);
        let mut current = seed_program_bytes();
        for _ in 0..50 {
            let (out, len) = fuzz_via_ffi(&state, current, 1 << 16);
            assert!(len > 0);
            // Copy before the next call, which will overwrite the state's
            // out_buf.
            let bytes = unsafe { slice::from_raw_parts(out, len) }.to_vec();
            decode_and_validate(bytes.as_ptr(), bytes.len());
            current = bytes;
        }
    }

    #[test]
    fn fuzz_with_garbage_input_generates_fresh() {
        let state = State::new(3);
        let (out, len) = fuzz_via_ffi(&state, vec![0xFFu8; 16], 1 << 16);
        assert!(len > 0);
        decode_and_validate(out, len);
        verify_fresh_generation(&state);
    }

    #[test]
    fn fuzz_returns_zero_on_oversize_with_non_null_out_buf() {
        // max_size = 4 is smaller than any encoded program; expect the fuzz
        // path to return 0 and still leave *out_buf pointing at something
        // non-null.
        let state = State::new(4);
        let (out, len) = fuzz_via_ffi(&state, Vec::new(), 4);
        assert_eq!(len, 0);
        assert!(!out.is_null());
    }

    #[test]
    fn describe_lists_stacked_mutator_sequence() {
        let state = State::new(6);
        // Loop until we hit the stacked-mutation branch (5% of calls generate
        // fresh instead).
        for _ in 0..10 {
            let _ = fuzz_via_ffi(&state, seed_program_bytes(), 1 << 16);
            let ptr = unsafe { afl_custom_describe(state.0, 256) };
            let s = unsafe { CStr::from_ptr(ptr) }
                .to_str()
                .expect("valid utf-8");
            let suffix = s
                .strip_prefix("smite-ir:")
                .expect("smite-ir: prefix on description");
            if suffix == "fresh" {
                continue;
            }
            for name in suffix.split(',') {
                assert!(
                    name == "op-param" || name == "input-swap",
                    "unexpected mutator name in description: {name:?} (full: {s:?})",
                );
            }
            return;
        }
        panic!("no stacked mutations of existing input after 10 attempts");
    }

    #[test]
    fn describe_respects_max_description_len() {
        let state = State::new(7);
        let _ = fuzz_via_ffi(&state, Vec::new(), 1 << 16);
        // Cap the description at 5 bytes.
        let ptr = unsafe { afl_custom_describe(state.0, 5) };
        let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        assert!(
            bytes.len() <= 5,
            "description must leave room for the null terminator within max_description_len",
        );
    }

    #[test]
    fn splice_optout_symbol_exists() {
        // AFL++ should never call this function, but invoking it should not
        // crash either.
        unsafe { afl_custom_splice_optout(ptr::null_mut()) };
    }

    // -- Trim tests --

    fn init_trim_via_ffi(state: &State, mut input: Vec<u8>) -> i32 {
        unsafe { afl_custom_init_trim(state.0, input.as_mut_ptr(), input.len()) }
    }

    fn trim_via_ffi(state: &State) -> (*const u8, usize) {
        let mut out: *const u8 = ptr::null();
        let len = unsafe { afl_custom_trim(state.0, &raw mut out) };
        (out, len)
    }

    fn post_trim_via_ffi(state: &State, success: bool) -> i32 {
        unsafe { afl_custom_post_trim(state.0, u8::from(success)) }
    }

    #[test]
    fn trim_init_returns_1_when_reduction_possible() {
        let state = State::new(0);
        let rv = init_trim_via_ffi(&state, reducible_seed_bytes());
        assert_eq!(rv, 1);
    }

    #[test]
    fn trim_init_returns_0_when_no_reduction_possible() {
        // Generator output has no dead code or duplicate loads; the
        // pipeline is a no-op, so we tell AFL to skip trim entirely.
        let state = State::new(0);
        let rv = init_trim_via_ffi(&state, seed_program_bytes());
        assert_eq!(rv, 0);
    }

    #[test]
    fn trim_init_returns_0_for_garbage() {
        let state = State::new(0);
        let rv = init_trim_via_ffi(&state, vec![0xFF; 16]);
        assert_eq!(rv, 0);
    }

    #[test]
    fn trim_yields_one_candidate_then_zero() {
        let state = State::new(0);
        init_trim_via_ffi(&state, reducible_seed_bytes());

        // First call: the trimmed candidate.
        let (out, len) = trim_via_ffi(&state);
        assert!(len > 0);
        decode_and_validate(out, len);

        // Subsequent calls: zero, regardless of post_trim verdicts.
        post_trim_via_ffi(&state, true);
        let (_, len) = trim_via_ffi(&state);
        assert_eq!(len, 0);
    }

    #[test]
    fn trim_post_trim_returns_1_to_terminate_loop() {
        let state = State::new(0);
        init_trim_via_ffi(&state, reducible_seed_bytes());
        let _ = trim_via_ffi(&state);
        // post_trim returns 1 unconditionally — it's the load-bearing
        // termination signal that pushes AFL's `stage_cur` to `stage_max`.
        assert_eq!(post_trim_via_ffi(&state, true), 1);
        assert_eq!(post_trim_via_ffi(&state, false), 1);
    }

    #[test]
    fn trim_candidate_is_smaller_than_input() {
        let original_bytes = reducible_seed_bytes();
        let original_program: Program = postcard::from_bytes(&original_bytes).expect("decode");

        let state = State::new(0);
        init_trim_via_ffi(&state, original_bytes);

        let (out, len) = trim_via_ffi(&state);
        assert!(len > 0, "trim should yield a candidate");
        let trimmed: Program =
            postcard::from_bytes(unsafe { slice::from_raw_parts(out, len) }).expect("decode");
        assert!(
            trimmed.instructions.len() < original_program.instructions.len(),
            "trim should shrink instruction count"
        );
    }

    #[test]
    fn trim_returns_0_immediately_after_pipeline_exhausted() {
        let state = State::new(0);
        init_trim_via_ffi(&state, reducible_seed_bytes());
        // Drain by taking the single candidate.
        let _ = trim_via_ffi(&state);
        post_trim_via_ffi(&state, false);
        // A second call with no re-init should immediately return 0.
        let (_, len) = trim_via_ffi(&state);
        assert_eq!(len, 0, "trim should return 0 after pipeline is exhausted");
    }
}
