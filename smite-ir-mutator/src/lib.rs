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
//! - `AFL_DISABLE_TRIM=1` -- this library does not implement custom trim and
//!   AFL++'s default byte-level trim would corrupt our structured programs.
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
use smite_ir::mutators::{InputSwapMutator, InstructionDeleteMutator, OperationParamMutator};
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
}

impl MutatorState {
    fn new(seed: u32) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(u64::from(seed)),
            out_buf: Vec::new(),
            description: Vec::new(),
            last_sequence: vec!["init"],
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
            let name = match self.rng.random_range(0..3) {
                0 => {
                    OperationParamMutator.mutate(program, &mut self.rng);
                    "op-param"
                }
                1 => {
                    InputSwapMutator.mutate(program, &mut self.rng);
                    "input-swap"
                }
                2 => {
                    InstructionDeleteMutator.mutate(program, &mut self.rng);
                    "instr-delete"
                }
                _ => unreachable!(),
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
                    name == "op-param" || name == "input-swap" || name == "instr-delete",
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
}
