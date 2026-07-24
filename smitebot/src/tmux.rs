//! Thin wrapper around the tmux CLI for managing campaign sessions.

use std::io;
use std::process::{Command, Stdio};

/// Returns `true` if `tmux` is installed and runnable.
pub fn is_available() -> bool {
    Command::new("tmux")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Returns the tmux window name that hosts the runner with the given id.
///
/// Shared by `start` (which creates the window) and `status` (which checks
/// whether it is still alive via that window).
pub fn runner_window_name(id: u16) -> String {
    format!("runner-{id}")
}

/// Returns `true` if a tmux session with the given exact name exists.
pub fn session_exists(name: &str) -> bool {
    let target = format!("={name}");
    Command::new("tmux")
        .args(["has-session", "-t", &target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Returns `true` if `session` has a window named exactly `name`.
///
/// Used by `status` to reuse an existing status window instead of stacking a
/// second one when the command is run again on a live campaign. Errors if the
/// `tmux list-windows` command fails (e.g. the session vanished).
pub fn window_exists(session: &str, name: &str) -> io::Result<bool> {
    let target = format!("={session}");
    let output = Command::new("tmux")
        .args(["list-windows", "-t", &target, "-F", "#{window_name}"])
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "tmux list-windows failed for session {session}: {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|window| window == name))
}

/// Creates a new detached tmux session with one window running `shell_cmd`.
///
/// Sets `remain-on-exit` atomically so dead windows preserve error output
/// even if the command exits immediately.
pub fn create_session(name: &str, window_name: &str, shell_cmd: &str) -> io::Result<()> {
    run_tmux(&[
        "new-session",
        "-d",
        "-s",
        name,
        "-n",
        window_name,
        shell_cmd,
        ";",
        "set-option",
        "-t",
        name,
        "remain-on-exit",
        "on",
    ])
}

/// Adds a new window running `shell_cmd` to an existing tmux session.
///
/// Sets `remain-on-exit` on the new window because session-level
/// `remain-on-exit` does not propagate to windows created after the fact.
pub fn add_window(session: &str, window_name: &str, shell_cmd: &str) -> io::Result<()> {
    let target = format!("={session}");
    run_tmux(&[
        "new-window",
        "-t",
        &target,
        "-n",
        window_name,
        shell_cmd,
        ";",
        "set-option",
        "-w",
        "remain-on-exit",
        "on",
    ])
}

/// Returns the names of windows in `session` whose command has exited.
///
/// Used during startup verification to tell a runner that failed to launch
/// (its pane is dead) apart from one still calibrating (pane alive). Relies on
/// `remain-on-exit`, which keeps dead windows queryable instead of destroying
/// them. Window names are assumed free of spaces (they are `runner-<id>`).
pub fn dead_windows(session: &str) -> io::Result<Vec<String>> {
    windows_by_liveness(session, true)
}

/// Returns the names of windows in `session` whose pane is still running.
///
/// Unlike the complement of [`dead_windows`], this counts a runner alive only
/// if its window still exists with a running pane. A window whose pane was
/// closed entirely is absent from both lists, so it is correctly treated as not
/// alive. Window names are assumed free of spaces (they are `runner-<id>`).
pub fn alive_windows(session: &str) -> io::Result<Vec<String>> {
    windows_by_liveness(session, false)
}

/// Lists window names in `session` whose pane's dead-state matches `dead`.
fn windows_by_liveness(session: &str, dead: bool) -> io::Result<Vec<String>> {
    let target = format!("={session}");
    let output = Command::new("tmux")
        .args([
            "list-panes",
            "-s",
            "-t",
            &target,
            "-F",
            "#{pane_dead} #{window_name}",
        ])
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "tmux list-panes failed for session {session}: {}",
            output.status
        )));
    }
    let prefix = if dead { "1 " } else { "0 " };
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(str::to_owned)
        .collect())
}

/// Returns the foreground PID of each pane in `session`.
///
/// Each pane runs `exec afl-fuzz`, so these are the live afl-fuzz PIDs. `stop`
/// uses them as the authoritative source because state.json PIDs can be missing
/// when startup verification times out. Errors if the `tmux list-panes` command
/// fails (e.g. the session vanished); an empty vec means the session has no panes.
pub fn list_pane_pids(session: &str) -> io::Result<Vec<u32>> {
    let target = format!("={session}");
    let output = Command::new("tmux")
        .args(["list-panes", "-s", "-t", &target, "-F", "#{pane_pid}"])
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "tmux list-panes failed for session {session}: {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect())
}

/// Kills a tmux session and all of its windows.
pub fn kill_session(session: &str) -> io::Result<()> {
    let target = format!("={session}");
    run_tmux(&["kill-session", "-t", &target])
}

/// Makes `window` the active window in `session`.
pub fn select_window(session: &str, window: &str) -> io::Result<()> {
    let target = format!("={session}:{window}");
    run_tmux(&["select-window", "-t", &target])
}

/// Attaches to a session, using `switch-client` when already inside tmux.
pub fn attach(session: &str) -> io::Result<()> {
    let target = format!("={session}");
    let cmd = if std::env::var_os("TMUX").is_some() {
        "switch-client"
    } else {
        "attach-session"
    };
    run_tmux(&[cmd, "-t", &target])
}

fn run_tmux(args: &[&str]) -> io::Result<()> {
    let status = Command::new("tmux").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tmux {} failed: {status}",
            args[0]
        )))
    }
}
