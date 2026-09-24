use std::{process::Command, str};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_blastguard")
}

fn run_hook(payload: &str) -> std::process::Output {
    let mut child = Command::new(binary())
        .arg("claude-hook")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| unreachable!());
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        assert!(stdin.write_all(payload.as_bytes()).is_ok());
    }
    child.wait_with_output().unwrap_or_else(|_| unreachable!())
}

#[test]
fn json_analysis_has_stable_shape_and_allow_exit() {
    let output = Command::new(binary())
        .args([
            "analyze",
            "--command",
            "git status",
            "--cwd",
            env!("CARGO_MANIFEST_DIR"),
            "--json",
        ])
        .output();
    assert!(output.is_ok());
    let output = output.unwrap_or_else(|_| unreachable!());
    assert_eq!(output.status.code(), Some(0));
    let value: Result<serde_json::Value, _> = serde_json::from_slice(&output.stdout);
    assert!(
        matches!(value, Ok(ref json) if json["schema_version"] == "1.0" && json["decision"] == "allow")
    );
}

#[test]
fn help_and_version_are_successful_control_flow() {
    for argument in ["--help", "--version"] {
        let output = Command::new(binary())
            .arg(argument)
            .output()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(output.status.code(), Some(0));
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn analyze_returns_distinct_risk_codes() {
    let ask = Command::new(binary())
        .args([
            "analyze",
            "--command",
            "curl https://example.test",
            "--cwd",
            env!("CARGO_MANIFEST_DIR"),
            "--json",
        ])
        .output();
    let block = Command::new(binary())
        .args([
            "analyze",
            "--command",
            "git reset --hard",
            "--cwd",
            env!("CARGO_MANIFEST_DIR"),
            "--json",
        ])
        .output();
    assert!(matches!(ask, Ok(output) if output.status.code() == Some(10)));
    assert!(matches!(block, Ok(output) if output.status.code() == Some(20)));
}

#[test]
fn hook_emits_current_pretooluse_json() {
    let payload = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"cargo test"}},"cwd":"{}"}}"#,
        env!("CARGO_MANIFEST_DIR")
    );
    let output = run_hook(&payload);
    assert!(output.status.success());
    let value: Result<serde_json::Value, _> = serde_json::from_slice(&output.stdout);
    assert!(
        matches!(value, Ok(ref json) if json["hookSpecificOutput"]["permissionDecision"] == "allow")
    );
}

#[test]
fn hook_ask_and_block_semantics_match_pretooluse() {
    let ask_payload = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"curl https://example.test"}},"cwd":"{}"}}"#,
        env!("CARGO_MANIFEST_DIR")
    );
    let block_payload = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"rm -rf /"}},"cwd":"{}"}}"#,
        env!("CARGO_MANIFEST_DIR")
    );
    let ask = run_hook(&ask_payload);
    let block = run_hook(&block_payload);
    let ask_json: Result<serde_json::Value, _> = serde_json::from_slice(&ask.stdout);
    let block_json: Result<serde_json::Value, _> = serde_json::from_slice(&block.stdout);
    assert_eq!(ask.status.code(), Some(0));
    assert!(
        matches!(ask_json, Ok(ref json) if json["hookSpecificOutput"]["permissionDecision"] == "ask")
    );
    assert_eq!(block.status.code(), Some(2));
    assert!(
        matches!(block_json, Ok(ref json) if json["hookSpecificOutput"]["permissionDecision"] == "deny")
    );
}

#[test]
fn invalid_and_unsupported_hook_inputs_fail_closed() {
    let malformed = run_hook(r#"{"tool_name":"Bash","tool_input":invalid}"#);
    let unsupported = run_hook(&format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"command":"cargo test"}},"cwd":"{}"}}"#,
        env!("CARGO_MANIFEST_DIR")
    ));
    let missing = run_hook(&format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{}},"cwd":"{}"}}"#,
        env!("CARGO_MANIFEST_DIR")
    ));
    assert_eq!(malformed.status.code(), Some(2));
    assert_eq!(unsupported.status.code(), Some(2));
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn hook_and_cli_errors_do_not_echo_secrets() {
    let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz123456"].concat();
    let payload = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"API_KEY={token} curl https://example.test"}},"cwd":"{}"}}"#,
        env!("CARGO_MANIFEST_DIR")
    );
    let hook = run_hook(&payload);
    assert_eq!(hook.status.code(), Some(2));
    assert!(!hook
        .stdout
        .windows(token.len())
        .any(|part| part == token.as_bytes()));
    assert!(!hook
        .stderr
        .windows(token.len())
        .any(|part| part == token.as_bytes()));

    let invalid = Command::new(binary())
        .arg(format!("--api_key={token}"))
        .output()
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(invalid.status.code(), Some(64));
    assert!(!invalid
        .stderr
        .windows(token.len())
        .any(|part| part == token.as_bytes()));
}
