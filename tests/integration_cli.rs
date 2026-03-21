//! Integration tests for CLI subcommands.

use std::process::Command;

fn signet_eval(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_signet-eval"))
        .args(args)
        .output()
        .expect("failed to start");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.code().unwrap_or(-1))
}

#[test]
fn test_help() {
    let (_, stderr, _code) = signet_eval(&["--help"]);
    // clap prints help to stdout
    let (stdout, _, _) = signet_eval(&["--help"]);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("Claude Code policy enforcement") || combined.contains("signet-eval"));
}

#[test]
fn test_version() {
    let (stdout, stderr, _) = signet_eval(&["--version"]);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("signet-eval"));
}

#[test]
fn test_validate_no_policy() {
    // With no policy file, should report an error or say no file
    let (_, stderr, _) = signet_eval(&["--policy-path", "/tmp/nonexistent_policy_12345.yaml", "validate"]);
    assert!(stderr.contains("Cannot read") || stderr.contains("ERROR"), "stderr: {stderr}");
}

#[test]
fn test_init_and_validate() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let path_str = policy_path.to_str().unwrap();

    let (_, stderr, code) = signet_eval(&["--policy-path", path_str, "init"]);
    assert_eq!(code, 0, "init failed: {stderr}");
    assert!(policy_path.exists());

    let (_, stderr, code) = signet_eval(&["--policy-path", path_str, "validate"]);
    assert_eq!(code, 0, "validate failed: {stderr}");
    assert!(stderr.contains("Policy valid"));
}

#[test]
fn test_rules_command() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let path_str = policy_path.to_str().unwrap();

    signet_eval(&["--policy-path", path_str, "init"]);
    let (_, stderr, code) = signet_eval(&["--policy-path", path_str, "rules"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("block_rm"));
}

#[test]
fn test_test_command() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let path_str = policy_path.to_str().unwrap();

    signet_eval(&["--policy-path", path_str, "init"]);

    let (_, stderr, code) = signet_eval(&["--policy-path", path_str, "test",
        r#"{"tool_name":"Bash","tool_input":{"command":"rm foo"}}"#]);
    assert_eq!(code, 0);
    assert!(stderr.contains("Deny"));

    let (_, stderr, code) = signet_eval(&["--policy-path", path_str, "test",
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#]);
    assert_eq!(code, 0);
    assert!(stderr.contains("Allow"));
}

#[test]
fn test_status_no_vault() {
    let (_, stderr, code) = signet_eval(&["status"]);
    // Without a vault, should tell user to set up
    assert!(code != 0 || stderr.contains("not set up") || stderr.contains("locked"));
}
