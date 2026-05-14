use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "smitebot", version, about = "Smite fuzzing campaign manager")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate host prerequisites.
    Doctor(DoctorArgs),
    /// Build workload Docker images.
    Build(BuildArgs),
    /// Start a fuzzing campaign.
    Start(StartArgs),
    /// Stop a fuzzing campaign.
    Stop(StopArgs),
    /// Show campaign status.
    Status(StatusArgs),
    /// Manage corpus artifacts.
    Corpus {
        #[command(subcommand)]
        command: CorpusCommand,
    },
    /// Triage crash artifacts.
    Crashes(CrashesArgs),
    /// Reproduce a single crash input.
    Reproduce(ReproduceArgs),
    /// Generate and diff coverage artifacts.
    Coverage(CoverageArgs),
}

#[derive(Debug, Subcommand)]
enum CorpusCommand {
    /// Merge AFL++ queue directories into a single corpus.
    Merge(CorpusMergeArgs),
    /// Minimize a merged corpus with afl-cmin.
    Minimize(CorpusMinimizeArgs),
}

#[derive(Debug, Args)]
struct DoctorArgs {}

#[derive(Debug, Args)]
struct BuildArgs {}

#[derive(Debug, Args)]
struct StartArgs {
    /// Maximum time to wait for AFL++ runner readiness.
    #[arg(long, default_value_t = 300)]
    startup_timeout_secs: u64,
    /// Build Docker image before launching campaign.
    #[arg(long, default_value_t = true)]
    auto_build: bool,
}

#[derive(Debug, Args)]
struct StopArgs {}

#[derive(Debug, Args)]
struct StatusArgs {}

#[derive(Debug, Args)]
struct CorpusMergeArgs {}

#[derive(Debug, Args)]
struct CorpusMinimizeArgs {
    /// One or more corpus input directories. If multiple are provided, they are
    /// merged before minimization.
    #[arg(long = "input-dir", required = true, num_args = 1..)]
    input_dirs: Vec<PathBuf>,
    /// Output directory for minimized corpus.
    #[arg(long)]
    out_dir: PathBuf,
    /// Nyx sharedir passed to afl-cmin target command.
    #[arg(long)]
    sharedir: PathBuf,
}

#[derive(Debug, Args)]
struct CrashesArgs {}

#[derive(Debug, Args)]
struct ReproduceArgs {
    /// Crash input file to reproduce.
    #[arg(long)]
    input: PathBuf,
    /// Number of reproduction attempts before declaring flaky.
    #[arg(long, default_value_t = 3)]
    retries: u32,
}

#[derive(Debug, Args)]
struct CoverageArgs {}

#[derive(Debug, thiserror::Error)]
enum SmitebotError {
    #[error("command not implemented yet: {command}")]
    NotImplemented { command: &'static str },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("smitebot: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), SmitebotError> {
    match cli.command {
        Command::Doctor(_args) => Err(not_implemented("doctor")),
        Command::Build(_args) => Err(not_implemented("build")),
        Command::Start(_args) => Err(not_implemented("start")),
        Command::Stop(_args) => Err(not_implemented("stop")),
        Command::Status(_args) => Err(not_implemented("status")),
        Command::Corpus { command } => match command {
            CorpusCommand::Merge(_args) => Err(not_implemented("corpus merge")),
            CorpusCommand::Minimize(_args) => Err(not_implemented("corpus minimize")),
        },
        Command::Crashes(_args) => Err(not_implemented("crashes")),
        Command::Reproduce(_args) => Err(not_implemented("reproduce")),
        Command::Coverage(_args) => Err(not_implemented("coverage")),
    }
}

fn not_implemented(command: &'static str) -> SmitebotError {
    SmitebotError::NotImplemented { command }
}
