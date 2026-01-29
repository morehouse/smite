//! LND fuzzing scenario binary.

use smite::smite_main;
use smite_scenarios::scenarios::{RawBytesScenario, RawInput};
use smite_scenarios::targets::LndTarget;

smite_main!(RawBytesScenario<LndTarget>, RawInput);
