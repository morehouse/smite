//! `smitebot` command-line interface.

mod commands;
mod config;
mod state;
mod tmux;
mod utils;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::{
    BuildArgs, BuildCommand, ConfigArgs, ConfigCommand, DoctorArgs, DoctorCommand, PrintIrArgs,
    PrintIrCommand, StartArgs, StartCommand, StatusArgs, StatusCommand, StopArgs, StopCommand,
};

#[derive(Debug, Parser)]
#[command(name = "smitebot", version, about = "Smite campaign manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Build Smite workload Docker images.
    Build(BuildArgs),
    /// Validate a campaign configuration file.
    Config(ConfigArgs),
    /// Validate host prerequisites for running Smite campaigns.
    Doctor(DoctorArgs),
    /// Decode a fuzzer input and print it as readable IR.
    PrintIr(PrintIrArgs),
    /// Launch a fuzzing campaign.
    Start(StartArgs),
    /// Report the status of a campaign.
    Status(StatusArgs),
    /// Stop a running campaign and reap its processes.
    Stop(StopArgs),
}

fn main() -> ExitCode {
    simple_logger::init_with_env().expect("Failed to initialize logger");

    let cli = Cli::parse();
    let success = match cli.command {
        Commands::Build(args) => BuildCommand::execute(&args),
        Commands::Config(args) => ConfigCommand::execute(&args),
        Commands::Doctor(args) => DoctorCommand::execute(&args),
        Commands::PrintIr(args) => PrintIrCommand::execute(&args),
        Commands::Start(args) => StartCommand::execute(&args),
        Commands::Status(args) => StatusCommand::execute(&args),
        Commands::Stop(args) => StopCommand::execute(&args),
    };

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
