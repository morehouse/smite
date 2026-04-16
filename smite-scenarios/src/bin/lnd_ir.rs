//! LND IR fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{IrScenario, PostInitSetup};
use smite_scenarios::targets::LndTarget;

fn main() -> std::process::ExitCode {
    smite_run::<IrScenario<LndTarget, PostInitSetup>>()
}
