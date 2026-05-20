//! `smitebot` command-line interface.

mod commands;
mod utils;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::DoctorArgs;

#[derive(Debug, Parser)]
#[command(name = "smitebot", version, about = "Smite campaign manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate host prerequisites for running Smite campaigns.
    Doctor(DoctorArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if run(cli) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run(cli: Cli) -> bool {
    match cli.command {
        Commands::Doctor(args) => commands::doctor::run(&args),
    }
}
