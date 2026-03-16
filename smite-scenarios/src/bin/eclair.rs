//! Eclair fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::ActiveScenario;
use smite_scenarios::targets::EclairTarget;

fn main() -> std::process::ExitCode {
    smite_run::<ActiveScenario<EclairTarget>>()
}
