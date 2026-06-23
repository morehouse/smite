//! Small helpers shared across smitebot commands.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
pub fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

/// Returns true if `path` exists and has at least one executable bit set.
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Finds an executable named `tool` on the process `PATH`.
pub fn find_in_path(tool: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    find_in_path_with_path(tool, &path_var)
}

/// Finds an executable tool using an explicit PATH value, mainly for tests.
fn find_in_path_with_path(tool: &str, path_var: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path_var)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file() && is_executable(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn find_in_path_with_path_finds_existing_executable() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let binary_path = tempdir.path().join("afl-fuzz");
        fs::write(&binary_path, "#!/bin/sh\n").unwrap();
        // Ensure the test binary is executable regardless of umask defaults.
        let mut perms = fs::metadata(&binary_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&binary_path, perms).unwrap();

        let path_value = OsString::from(tempdir.path());
        let found = find_in_path_with_path("afl-fuzz", &path_value).unwrap();
        assert_eq!(found, binary_path);
    }

    #[test]
    fn find_in_path_with_path_ignores_non_executable_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let binary_path = tempdir.path().join("afl-fuzz");
        fs::write(&binary_path, "#!/bin/sh\n").unwrap();

        let path_value = OsString::from(tempdir.path());
        let found = find_in_path_with_path("afl-fuzz", &path_value);
        assert!(found.is_none());
    }

    #[test]
    fn is_executable_detects_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("tool");
        fs::write(&path, "#!/bin/sh\n").unwrap();

        assert!(!is_executable(&path));

        // Flip the executable bit explicitly to validate the permission check.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();

        assert!(is_executable(&path));
    }
}
