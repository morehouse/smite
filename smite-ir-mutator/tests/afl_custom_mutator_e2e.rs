//! End-to-end test for the smite IR custom mutator. Drives the real
//! `afl-fuzz` binary against our harness with the cdylib loaded as
//! `AFL_CUSTOM_MUTATOR_LIBRARY`, and asserts every hook we export is
//! actually used in a real fuzzing run.
//!
//! Marked `#[ignore]`; run with:
//!
//! ```
//! cargo test -p smite-ir-mutator --test afl_custom_mutator_e2e -- \
//!     --ignored --nocapture
//! ```
//!
//! Skips cleanly if `cargo-afl` isn't on `PATH`. Working files (seeds,
//! queue, AFL stdout/stderr) live in `/tmp/smite-e2e/` so they survive
//! a panic for post-mortem.
//!
//! ## Signals (all from AFL's own output with `AFL_DEBUG=1`)
//!
//! 1. **Hooks resolved.** AFL prints `Found 'afl_custom_<name>'` per
//!    `dlsym` hit at startup; we assert all six.
//! 2. **fuzz + describe produced queue entries.** Queue filenames carry
//!    `smite-ir:<last_sequence>` from `afl_custom_describe`. We require
//!    both branches of `mutate_stacked`: `fresh` and one of
//!    `op-param` / `input-swap`.
//! 3. **Trim was invoked** (`[Custom Trimming] START`).
//! 4. **Trim produced a smaller candidate** (`START: Max 1`). The
//!    seed corpus mixes one DCE-reducible program (dead `LoadAmount`
//!    appended) and one CSE-reducible program (duplicate
//!    `LoadPrivateKey` injected) so both minimizers can fire.
//! 5. **AFL accepted a trimmed candidate** (`[Custom Trimming]
//!    SUCCESS`). Only emitted when the trimmed bytes' coverage cksum
//!    matches the original. Verifies DCE+CSE preserve coverage
//!    end-to-end -- relies on the harness publishing a DCE/CSE-invariant
//!    signal, see `smite-ir-e2e-test/src/main.rs`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rand::SeedableRng;
use rand::rngs::SmallRng;
use smite_ir::generators::OpenChannelGenerator;
use smite_ir::{Generator, Instruction, Operation, Program, ProgramBuilder};

const AFL_RUN_SECONDS: u64 = 30;

/// `true` when `bin` isn't on `PATH`.
fn missing(bin: &str) -> bool {
    Command::new(bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
}

/// Builds the cdylib and the harness, returning their paths.
///
/// The harness is built with `SanitizerCoverage` disabled
/// (`-Cllvm-args=-sanitizer-coverage-level=0`) because postcard's
/// decoder and `Program::validate` emit length-dependent edges that
/// bucket-shift under trim and break AFL's trim cksum. The harness
/// publishes coverage manually instead (see its module docs).
/// cargo-afl appends user RUSTFLAGS to its own and LLVM honors the
/// last `-Cllvm-args=` seen, so level=0 overrides cargo-afl's level=3.
fn build_artifacts(workspace: &Path) -> (PathBuf, PathBuf) {
    let cargo = env!("CARGO");
    let run = |args: &[&str], dir: &Path, env: &[(&str, &str)]| {
        let mut cmd = Command::new(cargo);
        cmd.args(args).current_dir(dir);
        for (k, v) in env {
            cmd.env(k, v);
        }
        assert!(
            cmd.status().expect("spawn cargo").success(),
            "{args:?} failed"
        );
    };
    run(
        &["build", "--release", "-p", "smite-ir-mutator"],
        workspace,
        &[],
    );
    let harness_dir = workspace.join("smite-ir-e2e-test");
    run(
        &["afl", "build", "--release"],
        &harness_dir,
        &[("RUSTFLAGS", "-Cllvm-args=-sanitizer-coverage-level=0")],
    );
    (
        workspace.join("target/release/libsmite_ir_mutator.so"),
        harness_dir.join("target/release/smite-ir-e2e-test"),
    )
}

/// Generator output, mutated by `f`, postcard-encoded.
fn build_seed(seed: u64, f: impl FnOnce(&mut Program)) -> Vec<u8> {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    let mut program = builder.build();
    f(&mut program);
    program.validate().expect("seed validates");
    postcard::to_allocvec(&program).expect("encode seed")
}

/// Writes one DCE-reducible and one CSE-reducible seed into `in_dir`.
fn write_seeds(in_dir: &Path) {
    let dce = build_seed(0, |p| {
        p.instructions.push(Instruction {
            operation: Operation::LoadAmount(0xdead_beef),
            inputs: vec![],
        });
    });
    let cse = build_seed(1, |p| {
        let keys: Vec<usize> = p
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(i, instr)| {
                matches!(instr.operation, Operation::LoadPrivateKey(_)).then_some(i)
            })
            .collect();
        assert!(
            keys.len() >= 2,
            "CSE seed needs >=2 LoadPrivateKey instructions to inject a duplicate; got {}",
            keys.len(),
        );
        p.instructions[keys[1]] = p.instructions[keys[0]].clone();
    });
    fs::write(in_dir.join("dce.bin"), dce).expect("write dce seed");
    fs::write(in_dir.join("cse.bin"), cse).expect("write cse seed");
}

/// Spawns `cargo afl fuzz`, blocks until self-termination, returns
/// the combined stdout+stderr.
///
/// `AFL_MAP_SIZE`+`AFL_SKIP_BIN_CHECK` are needed because the harness
/// has sancov disabled, so `__afl_final_loc` is 0 and AFL wouldn't
/// otherwise know the binary is fuzzable.
fn run_afl(cdylib: &Path, harness: &Path, work: &Path) -> String {
    let in_dir = work.join("in");
    let out_dir = work.join("out");
    let stdout = work.join("afl.stdout");
    let stderr = work.join("afl.stderr");
    let status = Command::new(env!("CARGO"))
        .args(["afl", "fuzz"])
        .env("AFL_CUSTOM_MUTATOR_LIBRARY", cdylib)
        .env("AFL_CUSTOM_MUTATOR_ONLY", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .env("AFL_NO_AFFINITY", "1")
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_DEBUG", "1")
        .env("AFL_MAP_SIZE", "65536")
        .env("AFL_SKIP_BIN_CHECK", "1")
        .args([
            "-V",
            &AFL_RUN_SECONDS.to_string(),
            "-i",
            in_dir.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
            "--",
            harness.to_str().unwrap(),
        ])
        .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
        .status()
        .expect("spawn cargo afl fuzz");
    assert!(status.code().is_some(), "afl-fuzz killed by signal");
    format!(
        "{}{}",
        fs::read_to_string(&stdout).unwrap_or_default(),
        fs::read_to_string(&stderr).unwrap_or_default(),
    )
}

#[test]
#[ignore = "spawns afl-fuzz for ~30s; run with --ignored"]
fn afl_drives_custom_mutator() {
    if missing("cargo-afl") {
        eprintln!("SKIP: cargo-afl not on PATH (install with `cargo install cargo-afl`)");
        return;
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let (cdylib, harness) = build_artifacts(&workspace);

    let work = std::env::temp_dir().join("smite-e2e");
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(work.join("in")).expect("mkdir in");
    write_seeds(&work.join("in"));

    let logs = run_afl(&cdylib, &harness, &work);
    let hint = format!("see {}", work.display());

    // 1. Every exported hook was resolved by AFL at startup.
    for hook in [
        "afl_custom_mutator",
        "afl_custom_describe",
        "afl_custom_init_trim",
        "afl_custom_trim",
        "afl_custom_post_trim",
        "afl_custom_splice_optout",
    ] {
        assert!(
            logs.contains(&format!("Found '{hook}'")),
            "AFL did not log \"Found '{hook}'\"; {hint}",
        );
    }

    // 2. fuzz + describe surfaced both mutate_stacked branches.
    let names: Vec<String> = fs::read_dir(work.join("out/default/queue"))
        .expect("read queue")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n.contains("smite-ir:fresh")),
        "no 'smite-ir:fresh' queue entry; {hint}",
    );
    assert!(
        names
            .iter()
            .any(|n| n.contains("op-param") || n.contains("input-swap")),
        "no stacked-mutation queue entry; {hint}",
    );

    // 3. Trim was invoked.
    let starts = logs.matches("[Custom Trimming] START").count();
    assert!(starts > 0, "init_trim was never invoked; {hint}");

    // 4. Trim produced a smaller candidate (DCE or CSE fired).
    let useful = logs.matches("[Custom Trimming] START: Max 1").count();
    assert!(
        useful > 0,
        "init_trim ran {starts} times but never returned a smaller candidate; {hint}",
    );

    // 5. AFL accepted a trimmed candidate (coverage cksum matched).
    let success = logs.matches("[Custom Trimming] SUCCESS").count();
    assert!(
        success > 0,
        "init_trim offered {useful} candidate(s) but AFL accepted none (coverage mismatch); {hint}",
    );

    eprintln!(
        "e2e summary: queue={} entries, trim starts={starts}, useful={useful}, success={success}",
        names.len(),
    );
}
