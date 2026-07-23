//! Runtime bindings to AFL++'s `libnyx.so`.
//!
//! smitebot links nothing against libnyx at build time: the library lives in
//! the user's AFL++ tree (`aflpp_path/libnyx.so`) and is resolved at runtime
//! with `dlopen`, mirroring how `afl-fuzz` itself loads it (see
//! `src/afl-forkserver.c` in `AFLplusplus`). Only the handful of host-side
//! entry points needed to boot a Nyx VM and drive single executions are bound;
//! the full C API is documented in `nyx_mode/libnyx/libnyx/libnyx.h`.

use std::ffi::{CStr, CString, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

/// Layout of the fields we read from libnyx's 4 KiB auxiliary buffer.
///
/// The buffer is a fixed sequence of sections; the per-execution `result`
/// section (`auxilary_buffer_result_s`) starts at byte 896. Within it, the
/// `#[repr(C, packed)]` fields we care about sit at fixed offsets. QEMU-Nyx
/// rewrites these on every execution, so they describe the exec that just ran.
/// See `nyx_mode/libnyx/fuzz_runner/src/nyx/aux_buffer.rs` in AFL++.
mod aux {
    /// `0x54502d554d4551` ("QEMU-PT" little-endian), at buffer offset 0.
    pub const MAGIC: u64 = 0x0054_502d_554d_4551;
    /// Aux-buffer format version this binding's offsets were derived from.
    pub const VERSION: u16 = 3;

    /// Start of the `result` section within the buffer.
    const RESULT: usize = 896;
    /// `result.dirty_pages` (`u32`): pages restored for the last exec.
    pub const DIRTY_PAGES: usize = RESULT + 16;
    /// `result.runtime_usec` (`u32`): microsecond part of guest payload runtime.
    pub const RUNTIME_USEC: usize = RESULT + 28;
    /// `result.runtime_sec` (`u32`): second part of guest payload runtime.
    pub const RUNTIME_SEC: usize = RESULT + 32;
}

/// A single Nyx execution outcome, matching libnyx's `NyxReturnValue` enum.
///
/// The enum is `#[repr(C)]` in libnyx, so it crosses the FFI boundary as a
/// plain `int`; `Normal` is `0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NyxReturn {
    Normal,
    Crash,
    Asan,
    Timeout,
    InvalidWriteToPayload,
    Error,
    IoError,
    Abort,
    /// A value libnyx returned that this binding does not know about.
    Unknown(i32),
}

impl NyxReturn {
    fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::Crash,
            2 => Self::Asan,
            3 => Self::Timeout,
            4 => Self::InvalidWriteToPayload,
            5 => Self::Error,
            6 => Self::IoError,
            7 => Self::Abort,
            other => Self::Unknown(other),
        }
    }

    /// Whether the execution completed cleanly (no crash, timeout, or error).
    #[must_use]
    pub fn is_normal(self) -> bool {
        self == Self::Normal
    }
}

/// `NyxProcessRole::StandAlone` — a single VM not sharing a snapshot with peers.
const ROLE_STANDALONE: u32 = 0;

// Host-side function signatures from `libnyx.h`. Opaque `config` and
// `NyxProcess` handles are represented as `*mut c_void`.
type ConfigLoad = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type ConfigFree = unsafe extern "C" fn(*mut c_void);
type ConfigSetWorkdir = unsafe extern "C" fn(*mut c_void, *const c_char);
type ConfigSetU32 = unsafe extern "C" fn(*mut c_void, u32);
type ConfigSetBool = unsafe extern "C" fn(*mut c_void, bool);
type New = unsafe extern "C" fn(*mut c_void, u32) -> *mut c_void;
type OptionSetBool = unsafe extern "C" fn(*mut c_void, bool);
type OptionSetTimeout = unsafe extern "C" fn(*mut c_void, u8, u32);
type OptionApply = unsafe extern "C" fn(*mut c_void);
type SetInput = unsafe extern "C" fn(*mut c_void, *mut u8, u32);
type Exec = unsafe extern "C" fn(*mut c_void) -> i32;
type GetAuxBuffer = unsafe extern "C" fn(*mut c_void) -> *mut u8;
type GetBitmapBuffer = unsafe extern "C" fn(*mut c_void) -> *mut u8;
type GetBitmapBufferSize = unsafe extern "C" fn(*mut c_void) -> usize;
type Shutdown = unsafe extern "C" fn(*mut c_void);

/// A loaded `libnyx.so` with its host-side entry points resolved once.
///
/// Function pointers are resolved up front so the hot execution loop performs
/// no per-call symbol lookup; `handle` is the `dlopen` handle, retained to keep
/// the object mapped for as long as those pointers are used and closed on drop.
pub struct Libnyx {
    handle: *mut c_void,
    config_load: ConfigLoad,
    config_free: ConfigFree,
    config_set_workdir: ConfigSetWorkdir,
    config_set_input_buffer_size: ConfigSetU32,
    config_set_input_buffer_write_protection: ConfigSetBool,
    config_set_process_role: ConfigSetU32,
    new: New,
    option_set_reload_mode: OptionSetBool,
    option_set_timeout: OptionSetTimeout,
    option_apply: OptionApply,
    set_afl_input: SetInput,
    exec: Exec,
    get_aux_buffer: GetAuxBuffer,
    get_bitmap_buffer: GetBitmapBuffer,
    get_bitmap_buffer_size: GetBitmapBufferSize,
    shutdown: Shutdown,
}

/// Per-execution measurements split into the target's own runtime and the Nyx
/// machinery around it, read from the auxiliary buffer after an execution.
#[derive(Clone, Copy, Debug)]
pub struct ExecStats {
    /// The execution outcome.
    pub result: NyxReturn,
    /// Guest time the target actually spent running the input, measured inside
    /// the VM. Excludes the host-side snapshot restore/reset, so subtracting it
    /// from the host-observed exec wall time isolates the Nyx overhead.
    pub target_runtime: Duration,
    /// Pages the VM had to restore for this execution. The dominant driver of
    /// restore cost, so it explains variation in the Nyx overhead.
    pub dirty_pages: u32,
}

/// Resolves a required function symbol from a `dlopen` handle into a typed
/// function pointer, returning early with a naming error if it is absent.
///
/// Every libnyx symbol we bind is a function, so a null `dlsym` result means the
/// symbol is missing; there is no data symbol whose real address could be null.
macro_rules! sym {
    ($handle:expr, $name:literal, $ty:ty) => {{
        // `concat!` yields a NUL-terminated `&str` literal, so its pointer is a
        // valid C string for `dlsym` without a heap allocation.
        // SAFETY: `$handle` is a live `dlopen` handle for a genuine libnyx.so.
        let ptr = unsafe { libc::dlsym($handle, concat!($name, "\0").as_ptr().cast::<c_char>()) };
        if ptr.is_null() {
            return Err(format!("libnyx.so is missing required symbol `{}`", $name));
        }
        // SAFETY: `$name` names a function whose C signature the caller vouches
        // is `$ty`; transmuting its address to that `extern "C"` fn pointer is
        // the standard `dlsym` idiom (both are a single pointer wide).
        unsafe { std::mem::transmute::<*mut c_void, $ty>(ptr) }
    }};
}

impl Libnyx {
    /// Loads `libnyx.so` from `path` and resolves its host-side API.
    ///
    /// # Errors
    /// Returns an error if the library cannot be opened or a required symbol is
    /// missing.
    pub fn load(path: &Path) -> Result<Self, String> {
        let path_c = path_to_cstring(path)?;

        // `RTLD_NOW` resolves every symbol at load time (surfacing an
        // incompatible libnyx immediately rather than mid-run); `RTLD_LOCAL`
        // keeps its symbols out of the global namespace.
        // SAFETY: `path_c` is a valid NUL-terminated path. dlopen runs the
        // library's initializers; libnyx has no problematic constructors.
        let handle = unsafe { libc::dlopen(path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(format!(
                "failed to dlopen {}: {}",
                path.display(),
                dlerror_string()
            ));
        }

        // SAFETY: `handle` is the live handle just returned by dlopen.
        match unsafe { Self::resolve(handle) } {
            Ok(libnyx) => Ok(libnyx),
            Err(e) => {
                // A symbol was missing; close the handle we opened before failing.
                // SAFETY: `handle` came from dlopen above and is closed once.
                unsafe { libc::dlclose(handle) };
                Err(e)
            }
        }
    }

    /// Binds every host-side entry point from an open `dlopen` handle.
    ///
    /// # Safety
    /// `handle` must be a live `dlopen` handle for a genuine `libnyx.so`.
    unsafe fn resolve(handle: *mut c_void) -> Result<Self, String> {
        Ok(Self {
            config_load: sym!(handle, "nyx_config_load", ConfigLoad),
            config_free: sym!(handle, "nyx_config_free", ConfigFree),
            config_set_workdir: sym!(handle, "nyx_config_set_workdir_path", ConfigSetWorkdir),
            config_set_input_buffer_size: sym!(
                handle,
                "nyx_config_set_input_buffer_size",
                ConfigSetU32
            ),
            config_set_input_buffer_write_protection: sym!(
                handle,
                "nyx_config_set_input_buffer_write_protection",
                ConfigSetBool
            ),
            config_set_process_role: sym!(handle, "nyx_config_set_process_role", ConfigSetU32),
            new: sym!(handle, "nyx_new", New),
            option_set_reload_mode: sym!(handle, "nyx_option_set_reload_mode", OptionSetBool),
            option_set_timeout: sym!(handle, "nyx_option_set_timeout", OptionSetTimeout),
            option_apply: sym!(handle, "nyx_option_apply", OptionApply),
            set_afl_input: sym!(handle, "nyx_set_afl_input", SetInput),
            exec: sym!(handle, "nyx_exec", Exec),
            get_aux_buffer: sym!(handle, "nyx_get_aux_buffer", GetAuxBuffer),
            get_bitmap_buffer: sym!(handle, "nyx_get_bitmap_buffer", GetBitmapBuffer),
            get_bitmap_buffer_size: sym!(handle, "nyx_get_bitmap_buffer_size", GetBitmapBufferSize),
            shutdown: sym!(handle, "nyx_shutdown", Shutdown),
            handle,
        })
    }

    /// Boots a standalone Nyx VM from `sharedir`, using `workdir` as libnyx's
    /// scratch directory (which libnyx wipes on startup).
    ///
    /// The returned [`NyxVm`] restores the snapshot before every execution
    /// (reload mode) so each [`NyxVm::exec`] measures one snapshot restore plus
    /// one target run. `timeout_secs` bounds a single execution; an input that
    /// runs longer trips [`NyxReturn::Timeout`] instead of hanging the caller.
    ///
    /// # Errors
    /// Returns an error string if the sharedir path is not valid UTF-8 with no
    /// interior NUL, or if libnyx fails to create the VM.
    pub fn boot(
        &self,
        sharedir: &Path,
        workdir: &Path,
        input_buffer_size: u32,
        worker_id: u32,
        timeout_secs: u8,
    ) -> Result<NyxVm<'_>, String> {
        let sharedir_c = path_to_cstring(sharedir)?;
        let workdir_c = path_to_cstring(workdir)?;

        // SAFETY: every pointer below is a live handle produced by libnyx or a
        // NUL-terminated string that outlives the call. The sequence mirrors
        // AFL++'s `afl_fsrv_start` Nyx setup.
        let process = unsafe {
            let config = (self.config_load)(sharedir_c.as_ptr());
            if config.is_null() {
                return Err(format!(
                    "nyx_config_load failed for sharedir {}",
                    sharedir.display()
                ));
            }
            (self.config_set_workdir)(config, workdir_c.as_ptr());
            (self.config_set_input_buffer_size)(config, input_buffer_size);
            (self.config_set_input_buffer_write_protection)(config, true);
            (self.config_set_process_role)(config, ROLE_STANDALONE);

            let process = (self.new)(config, worker_id);
            (self.config_free)(config);
            if process.is_null() {
                return Err("nyx_new failed to create the VM".to_string());
            }
            process
        };

        // The bitmap size is fixed for the life of the VM; read it once here so
        // `bitmap_size()` is a field access on hot paths rather than an FFI call.
        // SAFETY: `process` is the live handle just returned by `nyx_new`.
        let bitmap_size = unsafe { (self.get_bitmap_buffer_size)(process) };

        let vm = NyxVm {
            lib: self,
            process,
            bitmap_size,
        };
        vm.set_reload_mode(true);
        vm.set_timeout(timeout_secs, 0);
        Ok(vm)
    }
}

/// A booted Nyx VM. Dropping it shuts the VM down.
pub struct NyxVm<'a> {
    lib: &'a Libnyx,
    process: *mut c_void,
    /// Coverage bitmap size, fixed once the VM is booted. Cached so hot loops
    /// don't re-cross the FFI boundary for a constant.
    bitmap_size: usize,
}

impl NyxVm<'_> {
    /// Enables or disables snapshot reload before each execution.
    pub fn set_reload_mode(&self, enable: bool) {
        // SAFETY: `process` is a live handle; option changes require a following
        // `option_apply` to take effect.
        unsafe {
            (self.lib.option_set_reload_mode)(self.process, enable);
            (self.lib.option_apply)(self.process);
        }
    }

    /// Sets the per-execution timeout.
    pub fn set_timeout(&self, seconds: u8, micros: u32) {
        // SAFETY: `process` is a live handle.
        unsafe {
            (self.lib.option_set_timeout)(self.process, seconds, micros);
            (self.lib.option_apply)(self.process);
        }
    }

    /// Runs `input` once through the VM and returns the outcome.
    ///
    /// `input` is copied into libnyx's input buffer, so the same slice can be
    /// executed repeatedly. libnyx treats the buffer as read-only (write
    /// protection is enabled at boot), but its C signature takes `*mut u8`.
    pub fn exec(&self, input: &[u8]) -> NyxReturn {
        let len = u32::try_from(input.len()).unwrap_or(u32::MAX);
        // SAFETY: `input` outlives the call; libnyx copies at most `len` bytes
        // out of it and does not retain the pointer past the call.
        let raw = unsafe {
            (self.lib.set_afl_input)(self.process, input.as_ptr().cast_mut(), len);
            (self.lib.exec)(self.process)
        };
        NyxReturn::from_raw(raw)
    }

    /// Runs `input` once and returns the outcome plus the auxiliary-buffer
    /// measurements ([`ExecStats`]) for that execution: the target's own guest
    /// runtime and the pages restored. The caller's own wall-clock timing of
    /// this call, minus [`ExecStats::target_runtime`], is the Nyx overhead.
    pub fn exec_with_stats(&self, input: &[u8]) -> ExecStats {
        let result = self.exec(input);
        // SAFETY: `nyx_get_aux_buffer` returns libnyx's live 4 KiB aux-buffer
        // mapping; QEMU-Nyx has just written this exec's `result` section. The
        // field offsets are byte-aligned within that mapping, so the reads stay
        // in bounds and are correctly aligned; `read_unaligned` is used anyway
        // because the source struct is `#[repr(packed)]`.
        let (target_runtime, dirty_pages) = unsafe {
            let aux = (self.lib.get_aux_buffer)(self.process).cast_const();
            let sec = read_u32(aux, aux::RUNTIME_SEC);
            let usec = read_u32(aux, aux::RUNTIME_USEC);
            let dirty = read_u32(aux, aux::DIRTY_PAGES);
            let runtime = Duration::new(u64::from(sec), usec.saturating_mul(1_000));
            (runtime, dirty)
        };
        ExecStats {
            result,
            target_runtime,
            dirty_pages,
        }
    }

    /// Checks that the auxiliary buffer has the magic and version this binding's
    /// field offsets were derived from, so [`ExecStats`] readings are trustworthy.
    /// Returns `false` (rather than erroring) if not: benchmarking can still run,
    /// only the target/overhead split is unreliable.
    #[must_use]
    pub fn aux_buffer_layout_matches(&self) -> bool {
        // SAFETY: as in `exec_with_stats`; the header sits at offset 0.
        unsafe {
            let aux = (self.lib.get_aux_buffer)(self.process).cast_const();
            let magic = aux.cast::<u64>().read_unaligned();
            let version = aux.add(8).cast::<u16>().read_unaligned();
            magic == aux::MAGIC && version == aux::VERSION
        }
    }

    /// Size in bytes of the AFL coverage bitmap backing this VM (one byte per
    /// edge). Zero if libnyx reports no bitmap.
    #[must_use]
    pub fn bitmap_size(&self) -> usize {
        self.bitmap_size
    }

    /// Copies the current coverage bitmap into `dst`.
    ///
    /// The bitmap is a live mapping QEMU-Nyx overwrites on every execution, so
    /// to compare coverage across executions it must be copied out before the
    /// next `exec`. At most `min(bitmap_size(), dst.len())` bytes are copied;
    /// pass a `dst` of `bitmap_size()` bytes to capture the whole map.
    pub fn copy_bitmap_into(&self, dst: &mut [u8]) {
        let n = self.bitmap_size().min(dst.len());
        // SAFETY: `get_bitmap_buffer` returns the live bitmap mapping whose
        // length is `get_bitmap_buffer_size`; copying the min of that and
        // `dst.len()` stays in bounds of both, and the regions do not overlap.
        unsafe {
            let src = (self.lib.get_bitmap_buffer)(self.process);
            std::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
        }
    }
}

/// Reads a little-endian `u32` at `offset` bytes into the aux buffer at `base`.
///
/// # Safety
/// `base + offset .. + 4` must lie within the mapped aux buffer.
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe { base.add(offset).cast::<u32>().read_unaligned() }
}

impl Drop for NyxVm<'_> {
    fn drop(&mut self) {
        // SAFETY: `process` is a live handle used exactly once for teardown.
        unsafe {
            (self.lib.shutdown)(self.process);
        }
    }
}

impl Drop for Libnyx {
    fn drop(&mut self) {
        // A `NyxVm` borrows `&Libnyx`, so all VMs are gone before this runs and
        // no copied-out function pointer can outlive the mapping.
        // SAFETY: `handle` came from dlopen in `load` and is closed exactly once.
        unsafe {
            libc::dlclose(self.handle);
        }
    }
}

/// Returns the dynamic loader's current error text, or a placeholder if none.
fn dlerror_string() -> String {
    // SAFETY: dlerror returns NULL or a pointer to a loader-owned C string; we
    // read it immediately, before any other dl call can overwrite it.
    let err = unsafe { libc::dlerror() };
    if err.is_null() {
        "unknown error".to_string()
    } else {
        // SAFETY: `err` is non-null and points to a valid NUL-terminated string.
        unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Converts a path to a C string.
fn path_to_cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("path contains an interior NUL byte: {}", path.display()))
}
