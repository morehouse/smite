//! `smitebot` command-line interface.

mod commands;
mod utils;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::{BuildArgs, BuildCommand, DoctorArgs, DoctorCommand};

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
    /// Validate host prerequisites for running Smite campaigns.
    Doctor(DoctorArgs),
}

fn main() -> ExitCode {
    simple_logger::init_with_env().expect("Failed to initialize logger");

    let cli = Cli::parse();
    let success = match cli.command {
        Commands::Build(args) => BuildCommand::execute(&args),
        Commands::Doctor(args) => DoctorCommand::execute(&args),
    };

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
