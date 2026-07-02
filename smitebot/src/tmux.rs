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

/// Returns `true` if a tmux session with the given name exists.
pub fn session_exists(name: &str) -> bool {
    Command::new("tmux")
        .args(["has-session", "-t", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Creates a new detached tmux session with one window running `shell_cmd`.
pub fn create_session(name: &str, window_name: &str, shell_cmd: &str) -> io::Result<()> {
    run_tmux(&[
        "new-session",
        "-d",
        "-s",
        name,
        "-n",
        window_name,
        shell_cmd,
    ])
}

/// Adds a new window running `shell_cmd` to an existing tmux session.
pub fn add_window(session: &str, window_name: &str, shell_cmd: &str) -> io::Result<()> {
    run_tmux(&["new-window", "-t", session, "-n", window_name, shell_cmd])
}

/// Enables `remain-on-exit` so dead windows preserve their error output.
pub fn set_remain_on_exit(session: &str) -> io::Result<()> {
    run_tmux(&["set-option", "-t", session, "remain-on-exit", "on"])
}

/// Attaches to a session, using `switch-client` when already inside tmux.
pub fn attach(session: &str) -> io::Result<()> {
    let cmd = if std::env::var_os("TMUX").is_some() {
        "switch-client"
    } else {
        "attach-session"
    };
    run_tmux(&[cmd, "-t", session])
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
