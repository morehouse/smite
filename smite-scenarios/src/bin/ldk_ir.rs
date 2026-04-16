//! LDK IR fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{IrScenario, PostInitSetup};
use smite_scenarios::targets::LdkTarget;

fn main() -> std::process::ExitCode {
    smite_run::<IrScenario<LdkTarget, PostInitSetup>>()
}
