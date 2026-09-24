use std::{io::Read, path::PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::{
    analyze,
    config::Config,
    error::BlastguardError,
    model::{Analysis, Decision},
    redaction,
};

pub struct HookRequest {
    pub command: String,
    pub cwd: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookResponse {
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: &'static str,
    pub permission_decision: &'static str,
    pub permission_decision_reason: String,
}

const MAX_HOOK_INPUT_BYTES: usize = 1024 * 1024;

pub fn read_request(reader: &mut impl Read) -> Result<HookRequest, BlastguardError> {
    let mut input = String::new();
    reader
        .take((MAX_HOOK_INPUT_BYTES + 1) as u64)
        .read_to_string(&mut input)?;
    if input.len() > MAX_HOOK_INPUT_BYTES {
        return Err(BlastguardError::HookInputTooLarge(MAX_HOOK_INPUT_BYTES));
    }
    let value: Value = serde_json::from_str(&input)?;
    extract_request(&value)
}

pub fn extract_request(value: &Value) -> Result<HookRequest, BlastguardError> {
    if !value.is_object() {
        return Err(BlastguardError::HookObjectRequired);
    }
    match value.get("hook_event_name").and_then(Value::as_str) {
        Some("PreToolUse") => {}
        Some(_) => return Err(BlastguardError::HookEventUnsupported),
        None => return Err(BlastguardError::HookEventMissing),
    }
    match value.get("tool_name").and_then(Value::as_str) {
        Some("Bash") => {}
        Some(_) => return Err(BlastguardError::HookToolUnsupported),
        None => return Err(BlastguardError::HookToolMissing),
    }
    let command = value
        .pointer("/tool_input/command")
        .and_then(Value::as_str)
        .filter(|candidate| !candidate.trim().is_empty())
        .ok_or(BlastguardError::HookCommandMissing)?
        .to_owned();
    let cwd = value
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|candidate| !candidate.trim().is_empty())
        .map(PathBuf::from)
        .ok_or(BlastguardError::HookCwdMissing)?;
    Ok(HookRequest { command, cwd })
}

pub fn analyze_request(
    request: &HookRequest,
    config_path: Option<&std::path::Path>,
) -> Result<(Analysis, HookResponse), BlastguardError> {
    if !request.cwd.is_dir() {
        return Err(BlastguardError::InvalidCwd(
            redaction::redact(&request.cwd.display().to_string()).text,
        ));
    }
    let config = Config::load(config_path, &request.cwd)?;
    analyze_command(&request.command, &request.cwd, &config)
}

pub fn analyze_command(
    command: &str,
    cwd: &std::path::Path,
    config: &Config,
) -> Result<(Analysis, HookResponse), BlastguardError> {
    let analysis = analyze(command, cwd, config)?;
    let permission_decision = match analysis.decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Block => "deny",
    };
    let detail = analysis
        .findings
        .first()
        .map(|finding| finding.explanation.as_str())
        .unwrap_or(analysis.summary.as_str());
    let reason = redaction::redact(&format!(
        "BlastGuard: {} {detail}",
        analysis.decision.as_str()
    ))
    .text;
    Ok((
        analysis,
        HookResponse {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision,
                permission_decision_reason: reason,
            },
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_the_documented_shape() {
        let current = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": "/repo"
        });
        let undocumented = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "input": {"command": "cargo test"},
            "cwd": "/repo"
        });
        assert!(
            matches!(extract_request(&current), Ok(request) if request.command == "git status" && request.cwd == std::path::Path::new("/repo"))
        );
        assert!(matches!(
            extract_request(&undocumented),
            Err(BlastguardError::HookCommandMissing)
        ));
    }

    #[test]
    fn missing_command_fails_closed() {
        assert!(matches!(
            extract_request(
                &serde_json::json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}, "cwd": "/repo"})
            ),
            Err(BlastguardError::HookCommandMissing)
        ));
    }

    #[test]
    fn unsupported_or_ambiguous_inputs_fail_closed() {
        let unsupported = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"command": "cargo test"},
            "cwd": "/repo"
        });
        let wrong_event = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cargo test"},
            "cwd": "/repo"
        });
        assert!(matches!(
            extract_request(&unsupported),
            Err(BlastguardError::HookToolUnsupported)
        ));
        assert!(matches!(
            extract_request(&wrong_event),
            Err(BlastguardError::HookEventUnsupported)
        ));
    }

    #[test]
    fn maps_policy_to_pretooluse_decisions() {
        let request = HookRequest {
            command: "curl https://example.test".into(),
            cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        };
        let result = analyze_request(&request, None);
        assert!(
            matches!(result, Ok((_, response)) if response.hook_specific_output.permission_decision == "ask")
        );
    }

    #[test]
    fn oversized_input_fails_closed_before_json_parsing() {
        let mut input = std::io::Cursor::new(vec![b' '; MAX_HOOK_INPUT_BYTES + 1]);
        assert!(matches!(
            read_request(&mut input),
            Err(BlastguardError::HookInputTooLarge(MAX_HOOK_INPUT_BYTES))
        ));
    }
}
