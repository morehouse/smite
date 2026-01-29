/// `ScenarioResult` describes the outcomes of running a scenario
pub enum ScenarioResult {
    /// Scenario ran successfully
    Ok,
    /// Scenario indicated that the test case should be skipped
    Skip,
    /// Scenario indicated that the test case failed (i.e. the target node crashed)
    Fail(String),
}

/// `Scenario` is the interface for test scenarios that can be run against a target node
pub trait Scenario: Sized {
    /// Create a new instance of the scenario, preparing the initial state of the test
    ///
    /// # Errors
    /// Returns an error if scenario initialization fails.
    fn new(args: &[String]) -> Result<Self, String>;

    /// Run the test with the given fuzz input
    fn run(&mut self, input: &[u8]) -> ScenarioResult;
}

/// Run a scenario with the standard runner.
///
/// This is the main entry point for smite scenario binaries. It initializes
/// the runner and scenario, then executes the fuzz input.
///
/// # Panics
///
/// Panics if the logger fails to initialize.
#[must_use]
pub fn smite_run<S: Scenario>() -> std::process::ExitCode {
    use std::process::ExitCode;

    use crate::runners::{Runner, StdRunner};

    simple_logger::init_with_env().expect("Failed to initialize logger");

    // Initialize the runner before the scenario. This is important when
    // using Nyx to ensure nyx_init is called before spawning targets.
    let runner = StdRunner::new();

    let args: Vec<String> = std::env::args().collect();
    let mut scenario = match S::new(&args) {
        Ok(scenario) => scenario,
        Err(e) => {
            log::error!("Failed to initialize scenario: {e}");
            let exit_code =
                std::env::var("SMITE_INIT_ERROR_EXIT_CODE").map_or(0, |v| v.parse().unwrap_or(0));
            return ExitCode::from(exit_code);
        }
    };

    log::info!("Scenario initialized! Executing input...");

    // In Nyx mode the snapshot is taken here and a new fuzz input is provided each reset.
    let input = runner.get_fuzz_input();

    match scenario.run(&input) {
        ScenarioResult::Ok => {}
        ScenarioResult::Skip => {
            runner.skip();
            return ExitCode::SUCCESS;
        }
        ScenarioResult::Fail(err) => {
            runner.fail(&format!("Test case failed: {err}"));
            return ExitCode::from(1);
        }
    }

    log::info!("Test case ran successfully!");

    // Drop runner before scenario. This provides a huge speedup in Nyx
    // mode since nyx_release() resets the VM before scenario cleanup
    // ever runs.
    drop(runner);

    ExitCode::SUCCESS
}
