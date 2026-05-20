//! Host prerequisite checks for Smite fuzzing campaigns.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Output, Command};

use clap::Args;
use serde::Serialize;

use crate::utils::file_ops::{expand_tilde, find_in_path, is_executable};

/// AFL++ binaries required for campaign execution and corpus minimization.
const AFL_TOOLS: &[&str] = &["afl-fuzz", "afl-cmin", "afl-tmin", "afl-whatsup"];

/// Host tools required by Smite helper scripts.
const HOST_TOOLS: &[&str] = &["bash", "python3"];

/// Repository scripts required by doctor and upcoming orchestration commands.
const REQUIRED_SCRIPTS: &[&str] = &[
    "setup-nyx.sh",
    "coverage-report.sh",
    "symbolize-crash.sh",
    "enable-vmware-backdoor.sh",
];

/// Workload Dockerfiles required for normal and coverage image builds.
const REQUIRED_DOCKERFILES: &[&str] = &[
    "workloads/lnd/Dockerfile",
    "workloads/lnd/Dockerfile.coverage",
    "workloads/ldk/Dockerfile",
    "workloads/ldk/Dockerfile.coverage",
    "workloads/cln/Dockerfile",
    "workloads/cln/Dockerfile.coverage",
    "workloads/eclair/Dockerfile",
    "workloads/eclair/Dockerfile.coverage",
];

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit machine-readable JSON output.
    #[arg(long)]
    json: bool,
    /// Path to AFL++ source tree (used to verify Nyx packer binaries).
    #[arg(long)]
    aflpp_path: Option<PathBuf>,
    /// Path to smite repository root.
    #[arg(long, default_value = ".")]
    smite_dir: PathBuf,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CheckFailure>,
}

impl DoctorCheck {
    /// Creates a report entry from a named doctor check result.
    fn new(name: impl Into<String>, result: Result<(), CheckFailure>) -> Self {
        Self {
            name: name.into(),
            passed: result.is_ok(),
            reason: result.err(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    overall: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, thiserror::Error)]
enum CheckFailure {
    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
    #[error("neither vmx nor svm flag found in /proc/cpuinfo")]
    MissingCpuVirtualization,
    #[error("{} not found", .0.display())]
    MissingPath(PathBuf),
    #[error("{} not executable", .0.display())]
    NotExecutable(PathBuf),
    #[error("{}: {error}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        error: io::Error,
    },
    #[error("{tool} not found on PATH{detail}")]
    ToolNotFound { tool: String, detail: String },
    #[error("{command}: {detail}")]
    Command { command: String, detail: String },
    #[error("unable to infer AFL++ root; pass --aflpp-path or ensure afl-fuzz is on PATH")]
    MissingAflppRoot,
    #[error("libnyx.so not found in LD_LIBRARY_PATH or --aflpp-path")]
    LibnyxNotFound,
    #[error("backdoor disabled; run ./scripts/enable-vmware-backdoor.sh to enable")]
    VMwareBackdoorDisabled,
}

impl CheckFailure {
    /// Creates an I/O failure associated with a filesystem path.
    fn io(path: &Path, error: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            error,
        }
    }
}

impl Serialize for CheckFailure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Runs all doctor checks and prints either human-readable or JSON output.
pub fn run(args: &DoctorArgs) -> bool {
    let aflpp_path = args.aflpp_path.as_deref().map(expand_tilde);
    let smite_dir = expand_tilde(&args.smite_dir);
    let aflpp_root = resolve_aflpp_root(aflpp_path.as_deref());
    let aflpp_root = aflpp_root.as_deref();

    let mut checks = vec![
        DoctorCheck::new("x86_64 architecture", check_architecture()),
        DoctorCheck::new(
            "CPU virtualization enabled (vmx/svm)",
            check_cpu_virtualization_enabled(),
        ),
        DoctorCheck::new("/dev/kvm accessible", check_kvm_access()),
        DoctorCheck::new("Docker daemon reachable", check_docker_daemon()),
        DoctorCheck::new("AFL++ Nyx packer hget", check_nyx_hget(aflpp_root)),
        DoctorCheck::new("libnyx.so locatable", check_libnyx(aflpp_root)),
        DoctorCheck::new("VMware backdoor enabled", check_vmware_backdoor_enabled()),
    ];

    for tool in AFL_TOOLS {
        checks.push(DoctorCheck::new(*tool, require_tool(tool, aflpp_root)));
    }

    for tool in HOST_TOOLS {
        checks.push(DoctorCheck::new(*tool, require_tool(tool, None)));
    }

    for script in REQUIRED_SCRIPTS {
        let path = smite_dir.join("scripts").join(script);
        checks.push(DoctorCheck::new(
            format!("script executable: scripts/{script}"),
            require_executable(&path),
        ));
    }

    for dockerfile in REQUIRED_DOCKERFILES {
        let path = smite_dir.join(dockerfile);
        checks.push(DoctorCheck::new(
            format!("dockerfile present: {dockerfile}"),
            require_exists(&path),
        ));
    }

    let overall = checks.iter().all(|check| check.passed);
    let report = DoctorReport { overall, checks };

    if args.json {
        let json =
            serde_json::to_string_pretty(&report).expect("DoctorReport is always serializable");
        println!("{json}");
    } else {
        print_human_report(&report);
    }

    report.overall
}

/// Prints a compact checklist report intended for interactive terminal use.
fn print_human_report(report: &DoctorReport) {
    for check in &report.checks {
        match &check.reason {
            None => println!("[ok] {}", check.name),
            Some(reason) => println!("[fail] {}: {reason}", check.name),
        }
    }

    let total = report.checks.len();
    if report.overall {
        println!("\nsmitebot doctor: all {total} checks passed");
    } else {
        let failed = report.checks.iter().filter(|check| !check.passed).count();
        println!("\nsmitebot doctor: {failed} of {total} checks failed");
    }
}

/// Verifies that the host architecture is supported by Nyx mode.
fn check_architecture() -> Result<(), CheckFailure> {
    let arch = std::env::consts::ARCH;
    if arch == "x86_64" {
        Ok(())
    } else {
        Err(CheckFailure::UnsupportedArchitecture(arch.to_string()))
    }
}

/// Checks for CPU virtualization flags required by KVM acceleration.
fn check_cpu_virtualization_enabled() -> Result<(), CheckFailure> {
    let path = Path::new("/proc/cpuinfo");
    let cpuinfo = fs::read_to_string(path).map_err(|e| CheckFailure::io(path, e))?;

    let has_flag = cpuinfo
        .split_whitespace()
        .any(|flag| flag == "vmx" || flag == "svm");

    if has_flag {
        Ok(())
    } else {
        Err(CheckFailure::MissingCpuVirtualization)
    }
}

/// Verifies that `/dev/kvm` exists and is openable by the current user.
fn check_kvm_access() -> Result<(), CheckFailure> {
    let path = Path::new("/dev/kvm");
    require_exists(path)?;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| CheckFailure::io(path, e))?;
    Ok(())
}

/// Checks that the Docker CLI can reach a running Docker daemon.
fn check_docker_daemon() -> Result<(), CheckFailure> {
    require_tool("docker", None)?;

    let output = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map_err(|e| CheckFailure::Command {
            command: "docker version".to_string(),
            detail: e.to_string(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(CheckFailure::Command {
            command: "docker version".to_string(),
            detail: command_failure_detail(&output),
        })
    }
}

/// Resolves the AFL++ root from `--aflpp-path`, falling back to the parent of `afl-fuzz`.
fn resolve_aflpp_root(aflpp_path: Option<&Path>) -> Option<PathBuf> {
    aflpp_path.map(Path::to_path_buf).or_else(|| {
        find_in_path("afl-fuzz").and_then(|afl_fuzz_path| afl_fuzz_path.parent().map(Path::to_path_buf))
    })
}

/// Verifies that AFL++ Nyx packer produced an executable `hget` helper.
fn check_nyx_hget(aflpp_root: Option<&Path>) -> Result<(), CheckFailure> {
    let root = aflpp_root.ok_or(CheckFailure::MissingAflppRoot)?;

    require_executable(&root.join("nyx_mode/packer/packer/linux_x86_64-userspace/bin64/hget"))
}

/// Checks whether `libnyx.so` is discoverable by the runtime or under the AFL++ root.
fn check_libnyx(aflpp_root: Option<&Path>) -> Result<(), CheckFailure> {
    let in_ld_library_path = std::env::var_os("LD_LIBRARY_PATH").is_some_and(|path_var| {
        std::env::split_paths(&path_var).any(|dir| dir.join("libnyx.so").exists())
    });

    let in_aflpp_path = aflpp_root.is_some_and(|root| root.join("libnyx.so").exists());

    if in_ld_library_path || in_aflpp_path {
        Ok(())
    } else {
        Err(CheckFailure::LibnyxNotFound)
    }
}

/// Checks whether the KVM `VMware` backdoor needed by Nyx is enabled.
fn check_vmware_backdoor_enabled() -> Result<(), CheckFailure> {
    let path = Path::new("/sys/module/kvm/parameters/enable_vmware_backdoor");
    let contents = fs::read_to_string(path).map_err(|e| CheckFailure::io(path, e))?;

    if contents.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err(CheckFailure::VMwareBackdoorDisabled)
    }
}

/// Returns success only when the path exists.
fn require_exists(path: &Path) -> Result<(), CheckFailure> {
    if path.exists() {
        Ok(())
    } else {
        Err(CheckFailure::MissingPath(path.to_path_buf()))
    }
}

/// Returns success only when the path exists and has an executable bit set.
fn require_executable(path: &Path) -> Result<(), CheckFailure> {
    require_exists(path)?;
    if is_executable(path) {
        Ok(())
    } else {
        Err(CheckFailure::NotExecutable(path.to_path_buf()))
    }
}

/// Returns success when a tool is executable on PATH or under the AFL++ root.
fn require_tool(tool: &str, aflpp_root: Option<&Path>) -> Result<(), CheckFailure> {
    let found_on_path = find_in_path(tool).is_some();
    let found_in_aflpp = aflpp_root
        .map(|root| root.join(tool))
        .is_some_and(|candidate| candidate.is_file() && is_executable(&candidate));

    if found_on_path || found_in_aflpp {
        Ok(())
    } else {
        Err(CheckFailure::ToolNotFound {
            tool: tool.to_string(),
            detail: aflpp_root.map_or_else(String::new, |root| {
                format!(" or at {}", root.join(tool).display())
            }),
        })
    }
}

/// Builds a useful failure detail from a completed command.
fn command_failure_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr.trim();
    if detail.is_empty() {
        let detail = stdout.trim();
        if detail.is_empty() {
            output.status.to_string()
        } else {
            format!("{} ({detail})", output.status)
        }
    } else {
        format!("{} ({})", output.status, detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_failure_display_is_user_visible_for_all_variants() {
        let cases = vec![
            (
                CheckFailure::UnsupportedArchitecture("aarch64".to_string()),
                "unsupported architecture: aarch64".to_string(),
            ),
            (
                CheckFailure::MissingCpuVirtualization,
                "neither vmx nor svm flag found in /proc/cpuinfo".to_string(),
            ),
            (
                CheckFailure::MissingPath(PathBuf::from("/tmp/missing")),
                "/tmp/missing not found".to_string(),
            ),
            (
                CheckFailure::NotExecutable(PathBuf::from("/tmp/tool")),
                "/tmp/tool not executable".to_string(),
            ),
            (
                CheckFailure::io(
                    Path::new("/tmp/kvm"),
                    io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
                ),
                "/tmp/kvm: denied".to_string(),
            ),
            (
                CheckFailure::ToolNotFound {
                    tool: "afl-fuzz".to_string(),
                    detail: " or at /opt/AFLplusplus/afl-fuzz".to_string(),
                },
                "afl-fuzz not found on PATH or at /opt/AFLplusplus/afl-fuzz".to_string(),
            ),
            (
                CheckFailure::Command {
                    command: "docker version".to_string(),
                    detail: "daemon unavailable".to_string(),
                },
                "docker version: daemon unavailable".to_string(),
            ),
            (
                CheckFailure::MissingAflppRoot,
                "unable to infer AFL++ root; pass --aflpp-path or ensure afl-fuzz is on PATH"
                    .to_string(),
            ),
            (
                CheckFailure::LibnyxNotFound,
                "libnyx.so not found in LD_LIBRARY_PATH or --aflpp-path".to_string(),
            ),
            (
                CheckFailure::VMwareBackdoorDisabled,
                "backdoor disabled; run ./scripts/enable-vmware-backdoor.sh to enable".to_string(),
            ),
        ];

        for (failure, expected) in cases {
            assert_eq!(failure.to_string(), expected);
        }
    }

    #[test]
    fn require_exists_reports_missing_path() {
        let path = Path::new("/definitely/not/a/smitebot/path");
        let err = require_exists(path).unwrap_err();
        assert_eq!(err.to_string(), "/definitely/not/a/smitebot/path not found");
    }

    #[test]
    fn require_executable_rejects_non_executable_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("tool");
        fs::write(&path, "#!/bin/sh\n").unwrap();

        let err = require_executable(&path).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{} not executable", path.display())
        );
    }

    #[test]
    fn require_tool_finds_executable_under_aflpp_root() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let tool_path = tempdir.path().join("afl-fuzz");
        fs::write(&tool_path, "#!/bin/sh\n").unwrap();
        // Force executable permissions so the test doesn't depend on umask defaults.
        let mut perms = fs::metadata(&tool_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tool_path, perms).unwrap();

        assert!(require_tool("afl-fuzz", Some(tempdir.path())).is_ok());
    }

    #[test]
    fn doctor_report_json_is_machine_readable() {
        let report = DoctorReport {
            overall: false,
            checks: vec![
                DoctorCheck::new("check-a", Ok(())),
                DoctorCheck::new("check-b", Err(CheckFailure::MissingCpuVirtualization)),
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["overall"], false);
        assert_eq!(parsed["checks"][0]["name"], "check-a");
        assert!(parsed["checks"][0].get("reason").is_none());
        assert_eq!(parsed["checks"][1]["passed"], false);
        assert_eq!(
            parsed["checks"][1]["reason"],
            "neither vmx nor svm flag found in /proc/cpuinfo"
        );
    }

    #[test]
    fn resolve_aflpp_root_prefers_explicit_path() {
        let root = PathBuf::from("/opt/AFLplusplus");
        assert_eq!(resolve_aflpp_root(Some(root.as_path())), Some(root));
    }

    #[test]
    fn command_failure_detail_prefers_stderr() {
        let output = output_with("stdout msg", "stderr msg");
        assert_eq!(
            command_failure_detail(&output),
            "exit status: 1 (stderr msg)"
        );
    }

    #[test]
    fn command_failure_detail_uses_stdout_if_stderr_empty() {
        let output = output_with("stdout msg", "");
        assert_eq!(command_failure_detail(&output), "exit status: 1 (stdout msg)");
    }

    #[test]
    fn command_failure_detail_handles_no_output() {
        let output = output_with("", "");
        assert_eq!(command_failure_detail(&output), "exit status: 1");
    }

    fn output_with(stdout: &str, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;

        // Build a synthetic Output so tests don't rely on executing external commands.
        std::process::Output {
            status: ExitStatus::from_raw(1 << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }
}
