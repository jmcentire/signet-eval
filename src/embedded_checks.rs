//! Trusted check scripts embedded in the binary and materialized on demand.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const GITHUB_IDENTITY_CHECK: &str = "gh-identity-matches-remote";
const GITHUB_IDENTITY_CHECK_BODY: &[u8] = include_bytes!("../checks/gh-identity-matches-remote");

/// Install a shipped check before it is resolved by the hook.
///
/// The destination only becomes visible after the complete executable file has
/// been written. Existing regular files are preserved so a human can maintain
/// a host-specific implementation of the same check.
pub fn install_if_builtin(check_name: &str) -> Result<(), String> {
    if check_name != GITHUB_IDENTITY_CHECK {
        return Ok(());
    }

    let checks_dir = crate::vault::signet_dir().join("checks");
    install_at(
        &checks_dir,
        GITHUB_IDENTITY_CHECK,
        GITHUB_IDENTITY_CHECK_BODY,
    )
}

#[cfg(unix)]
fn install_at(checks_dir: &Path, check_name: &str, body: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(checks_dir).map_err(|error| {
        format!(
            "Cannot create built-in checks directory '{}': {error}",
            checks_dir.display()
        )
    })?;

    let directory_metadata = fs::symlink_metadata(checks_dir).map_err(|error| {
        format!(
            "Cannot inspect built-in checks directory '{}': {error}",
            checks_dir.display()
        )
    })?;
    if !directory_metadata.file_type().is_dir() {
        return Err(format!(
            "Built-in checks path is not a real directory: {}",
            checks_dir.display()
        ));
    }

    let destination = checks_dir.join(check_name);
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        if !metadata.file_type().is_file() {
            return Err(format!(
                "Built-in check path is not a regular file: {}",
                destination.display()
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o100 == 0 {
            fs::set_permissions(&destination, fs::Permissions::from_mode(mode | 0o100)).map_err(
                |error| {
                    format!(
                        "Cannot make built-in check executable '{}': {error}",
                        destination.display()
                    )
                },
            )?;
        }
        return Ok(());
    }

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temporary = checks_dir.join(format!(
        ".{check_name}.{}.{}.tmp",
        std::process::id(),
        nonce
    ));

    let install = || -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                format!(
                    "Cannot create temporary built-in check '{}': {error}",
                    temporary.display()
                )
            })?;
        file.write_all(body).map_err(|error| {
            format!(
                "Cannot write built-in check '{}': {error}",
                temporary.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "Cannot sync built-in check '{}': {error}",
                temporary.display()
            )
        })?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "Cannot mark built-in check executable '{}': {error}",
                temporary.display()
            )
        })?;

        match fs::hard_link(&temporary, &destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(format!(
                "Cannot install built-in check '{}': {error}",
                destination.display()
            )),
        }
    };

    let result = install();
    let _ = fs::remove_file(&temporary);
    result
}

#[cfg(not(unix))]
fn install_at(_checks_dir: &Path, check_name: &str, _body: &[u8]) -> Result<(), String> {
    Err(format!(
        "Built-in shell check '{check_name}' is only supported on Unix hosts"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_complete_executable_check() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let checks_dir = dir.path().join("checks");
        install_at(&checks_dir, "example-check", b"#!/bin/sh\nexit 0\n").unwrap();

        let installed = checks_dir.join("example-check");
        assert_eq!(fs::read(&installed).unwrap(), b"#!/bin/sh\nexit 0\n");
        assert_ne!(
            fs::metadata(installed).unwrap().permissions().mode() & 0o100,
            0
        );
    }

    #[test]
    fn preserves_existing_human_managed_check() {
        let dir = tempfile::tempdir().unwrap();
        let checks_dir = dir.path().join("checks");
        fs::create_dir_all(&checks_dir).unwrap();
        let installed = checks_dir.join("example-check");
        fs::write(&installed, b"human managed\n").unwrap();

        install_at(&checks_dir, "example-check", b"embedded\n").unwrap();

        assert_eq!(fs::read(installed).unwrap(), b"human managed\n");
    }

    #[test]
    fn rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let checks_dir = dir.path().join("checks");
        fs::create_dir_all(&checks_dir).unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"target\n").unwrap();
        symlink(&target, checks_dir.join("example-check")).unwrap();

        let error = install_at(&checks_dir, "example-check", b"embedded\n").unwrap_err();
        assert!(error.contains("not a regular file"));
        assert_eq!(fs::read(target).unwrap(), b"target\n");
    }
}
