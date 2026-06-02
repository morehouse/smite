//! Docker image builds for Smite workloads.
//! The command keeps Docker's output visible so rebuild failures are easy to debug.

use std::fmt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

use clap::{Args, ValueEnum};

/// Command handler for `smitebot build`.
pub struct BuildCommand;

/// CLI arguments for `smitebot build`.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Target implementation to build.
    #[arg(long)]
    target: WorkloadTarget,
    /// Scenario binary selected by the workload Dockerfile.
    #[arg(long)]
    scenario: String,
    /// Build the coverage-instrumented Docker image.
    #[arg(long)]
    coverage: bool,
    /// Override the Docker image tag.
    #[arg(long)]
    image: Option<String>,
    /// Path to smite repository root.
    #[arg(long, default_value = ".")]
    smite_dir: PathBuf,
    /// Pass --no-cache to docker build.
    #[arg(long)]
    no_cache: bool,
}

/// Smite workload targets with Dockerfiles under `workloads/`.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum WorkloadTarget {
    /// Lightning Network Daemon workload.
    Lnd,
    /// Core Lightning workload.
    Cln,
    /// LDK Node workload.
    Ldk,
    /// Eclair workload.
    Eclair,
}

impl fmt::Display for WorkloadTarget {
    /// Formats the lowercase target name used in paths and Docker image tags.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lnd => write!(f, "lnd"),
            Self::Cln => write!(f, "cln"),
            Self::Ldk => write!(f, "ldk"),
            Self::Eclair => write!(f, "eclair"),
        }
    }
}

/// Fully resolved Docker build inputs.
#[derive(Debug, PartialEq, Eq)]
struct BuildInputs {
    /// Docker image tag to produce.
    image: String,
    /// Workload Dockerfile selected from `--target` and `--coverage`.
    dockerfile: PathBuf,
    /// Smite repository root used as the Docker build context.
    smite_dir: PathBuf,
    /// Scenario passed to Docker as `--build-arg SCENARIO=...`.
    scenario: String,
    /// Whether Docker should rebuild without using its layer cache.
    no_cache: bool,
}

impl BuildInputs {
    /// Resolves Docker build inputs from parsed CLI arguments.
    fn from_args(args: &BuildArgs) -> Self {
        let dockerfile_name = if args.coverage {
            "Dockerfile.coverage"
        } else {
            "Dockerfile"
        };

        Self {
            image: args.image.clone().unwrap_or_else(|| {
                default_workload_image_tag(args.target, &args.scenario, args.coverage)
            }),
            dockerfile: args
                .smite_dir
                .join("workloads")
                .join(args.target.to_string())
                .join(dockerfile_name),
            smite_dir: args.smite_dir.clone(),
            scenario: args.scenario.clone(),
            no_cache: args.no_cache,
        }
    }
}

impl BuildCommand {
    /// Builds the requested Smite Docker image and returns whether Docker succeeded.
    pub fn execute(args: &BuildArgs) -> bool {
        let inputs = BuildInputs::from_args(args);
        if !inputs.dockerfile.exists() {
            log::error!("Dockerfile not found: {}", inputs.dockerfile.display());
            return false;
        }

        log::info!(
            "building {} with {}",
            inputs.image,
            inputs.dockerfile.display()
        );

        let status = match run_docker_build(&inputs) {
            Ok(status) => status,
            Err(e) => {
                log::error!("failed to run docker build: {e}");
                return false;
            }
        };

        if !status.success() {
            log::error!("docker build failed with {status}");
            return false;
        }

        log::info!("built {}", inputs.image);
        true
    }
}

/// Returns the default image tag used by Smite's manual Docker build flow.
fn default_workload_image_tag(target: WorkloadTarget, scenario: &str, coverage: bool) -> String {
    let suffix = if coverage { "-coverage" } else { "" };
    format!("smite-{target}-{scenario}{suffix}")
}

/// Runs `docker build`, streaming stdout/stderr directly to the terminal.
fn run_docker_build(inputs: &BuildInputs) -> std::io::Result<ExitStatus> {
    let mut command = Command::new("docker");
    command.arg("build");
    if inputs.no_cache {
        command.arg("--no-cache");
    }
    command
        .arg("-t")
        .arg(&inputs.image)
        .arg("--build-arg")
        .arg(format!("SCENARIO={}", inputs.scenario))
        .arg("-f")
        .arg(&inputs.dockerfile)
        .arg(&inputs.smite_dir);

    command.status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample_build_args(target: WorkloadTarget, scenario: &str) -> BuildArgs {
        BuildArgs {
            target,
            scenario: scenario.to_string(),
            coverage: false,
            image: None,
            smite_dir: PathBuf::from("/repo/smite"),
            no_cache: false,
        }
    }

    #[test]
    fn default_workload_image_tag_matches_smite_convention() {
        assert_eq!(
            default_workload_image_tag(WorkloadTarget::Lnd, "encrypted_bytes", false),
            "smite-lnd-encrypted_bytes"
        );
        assert_eq!(
            default_workload_image_tag(WorkloadTarget::Cln, "noise", true),
            "smite-cln-noise-coverage"
        );
    }

    #[test]
    fn build_inputs_use_normal_dockerfile_by_default() {
        let args = sample_build_args(WorkloadTarget::Ldk, "init");
        let inputs = BuildInputs::from_args(&args);

        assert_eq!(inputs.image, "smite-ldk-init");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/ldk/Dockerfile")
        );
        assert_eq!(inputs.smite_dir, Path::new("/repo/smite"));
        assert_eq!(inputs.scenario, "init");
        assert!(!inputs.no_cache);
    }

    #[test]
    fn build_inputs_select_expected_dockerfile_for_each_target() {
        let cases = [
            (WorkloadTarget::Lnd, "/repo/smite/workloads/lnd/Dockerfile"),
            (WorkloadTarget::Cln, "/repo/smite/workloads/cln/Dockerfile"),
            (WorkloadTarget::Ldk, "/repo/smite/workloads/ldk/Dockerfile"),
            (
                WorkloadTarget::Eclair,
                "/repo/smite/workloads/eclair/Dockerfile",
            ),
        ];

        for (target, expected_dockerfile) in cases {
            let args = sample_build_args(target, "noise");
            let inputs = BuildInputs::from_args(&args);

            assert_eq!(inputs.dockerfile, Path::new(expected_dockerfile));
        }
    }

    #[test]
    fn build_inputs_support_coverage_and_custom_image() {
        let mut args = sample_build_args(WorkloadTarget::Eclair, "encrypted_bytes");
        args.coverage = true;
        args.image = Some("local/eclair-eb:debug".to_string());
        args.no_cache = true;

        let inputs = BuildInputs::from_args(&args);

        assert_eq!(inputs.image, "local/eclair-eb:debug");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/eclair/Dockerfile.coverage")
        );
        assert!(inputs.no_cache);
    }

    #[test]
    fn build_inputs_use_default_coverage_image_when_not_overridden() {
        let mut args = sample_build_args(WorkloadTarget::Cln, "noise");
        args.coverage = true;

        let inputs = BuildInputs::from_args(&args);

        assert_eq!(inputs.image, "smite-cln-noise-coverage");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/cln/Dockerfile.coverage")
        );
    }

    #[test]
    fn build_inputs_preserve_custom_smite_dir() {
        let mut args = sample_build_args(WorkloadTarget::Lnd, "encrypted_bytes");
        args.smite_dir = PathBuf::from("/tmp/local-smite");

        let inputs = BuildInputs::from_args(&args);

        assert_eq!(inputs.smite_dir, Path::new("/tmp/local-smite"));
        assert_eq!(
            inputs.dockerfile,
            Path::new("/tmp/local-smite/workloads/lnd/Dockerfile")
        );
    }
}
