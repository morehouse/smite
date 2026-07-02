//! `smitebot` command-line interface.

mod commands;
mod config;
mod state;
mod tmux;
mod utils;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::{
    BuildArgs, BuildCommand, ConfigArgs, ConfigCommand, DoctorArgs, DoctorCommand, StartArgs,
    StartCommand,
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
    /// Launch a fuzzing campaign.
    Start(StartArgs),
}

fn main() -> ExitCode {
    simple_logger::init_with_env().expect("Failed to initialize logger");

    let cli = Cli::parse();
    let success = match cli.command {
        Commands::Build(args) => BuildCommand::execute(&args),
        Commands::Config(args) => ConfigCommand::execute(&args),
        Commands::Doctor(args) => DoctorCommand::execute(&args),
        Commands::Start(args) => StartCommand::execute(&args),
    };

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
