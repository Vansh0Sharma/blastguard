use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    sync::mpsc,
    thread,
    time::Duration,
};

use serde_json::{json, Value};

use crate::{
    claude_hook::{self, HookResponse},
    config::Config,
    error::BlastguardError,
    redaction, sandbox,
};

pub const SESSION_ID_ENV: &str = "BLASTGUARD_SESSION_ID";
pub const STATE_DIR_ENV: &str = "BLASTGUARD_STATE_DIR";
pub const HOOK_WATCHDOG_SECONDS: u64 = 5;
pub const CLAUDE_HOOK_TIMEOUT_SECONDS: u64 = 10;

pub struct LaunchResult {
    pub session_id: String,
    pub worktree: PathBuf,
    pub status: ExitStatus,
}

pub fn hook_settings(id: &str) -> Result<Value, BlastguardError> {
    let lease = sandbox::lock_for_execution(id)?;
    let executable = current_executable()?;
    settings_value(id, lease.state_root(), &executable)
}

pub fn hook_settings_json(id: &str) -> Result<String, BlastguardError> {
    let value = hook_settings(id)?;
    serde_json::to_string_pretty(&value)
        .map(|text| redaction::redact(&text).text)
        .map_err(|error| BlastguardError::Serialization(error.to_string()))
}

pub fn start(id: &str, arguments: &[OsString]) -> Result<LaunchResult, BlastguardError> {
    reject_conflicting_arguments(arguments)?;
    let (lease, claude_launch_lock) = sandbox::lock_for_claude_start(id)?;
    let executable = current_executable()?;
    let settings = settings_value(id, lease.state_root(), &executable)?;
    let settings = serde_json::to_string(&settings)
        .map_err(|error| BlastguardError::Serialization(error.to_string()))?;
    let worktree = lease.worktree().to_path_buf();
    let state_root = lease.state_root().as_os_str().to_owned();

    let mut child = Command::new("claude")
        .current_dir(&worktree)
        .arg("--settings")
        .arg(settings)
        .args(arguments)
        .env(SESSION_ID_ENV, id)
        .env(STATE_DIR_ENV, &state_root)
        .spawn()
        .map_err(|error| {
            BlastguardError::Claude(format!(
                "could not launch the installed `claude` executable: {error}"
            ))
        })?;

    // Launch is complete. Hooks take fresh locks and revalidate the session on
    // every invocation, so the launch-time lease must not deadlock them.
    drop(lease);
    let status = child.wait().map_err(|error| {
        BlastguardError::Claude(format!("could not wait for Claude Code: {error}"))
    })?;
    drop(claude_launch_lock);
    Ok(LaunchResult {
        session_id: id.to_owned(),
        worktree,
        status,
    })
}

pub fn evaluate_hook_with_timeout(
    request: claude_hook::HookRequest,
) -> Result<(crate::model::Analysis, HookResponse), BlastguardError> {
    let id = required_environment(SESSION_ID_ENV)?
        .into_string()
        .map_err(|_| {
            BlastguardError::Claude("launcher session ID is not valid UTF-8".to_owned())
        })?;
    let state_root = PathBuf::from(required_environment(STATE_DIR_ENV)?);
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = evaluate_hook(request, &id, &state_root);
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(Duration::from_secs(HOOK_WATCHDOG_SECONDS)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(BlastguardError::Claude(
            "hook policy evaluation exceeded its internal safety deadline".to_owned(),
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(BlastguardError::Claude(
            "hook policy evaluation failed unexpectedly".to_owned(),
        )),
    }
}

fn evaluate_hook(
    request: claude_hook::HookRequest,
    id: &str,
    state_root: &Path,
) -> Result<(crate::model::Analysis, HookResponse), BlastguardError> {
    let lease = sandbox::lock_for_hook(id, state_root)?;
    let config = Config::load(None, lease.source())?;
    claude_hook::analyze_command(&request.command, lease.worktree(), &config)
}

fn settings_value(
    id: &str,
    state_root: &Path,
    executable: &Path,
) -> Result<Value, BlastguardError> {
    let state = state_root.to_str().ok_or_else(|| {
        BlastguardError::Claude("managed state path is not valid UTF-8".to_owned())
    })?;
    let binary = executable.to_str().ok_or_else(|| {
        BlastguardError::Claude("BlastGuard executable path is not valid UTF-8".to_owned())
    })?;
    Ok(json!({
        "env": {
            SESSION_ID_ENV: id,
            STATE_DIR_ENV: state
        },
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": binary,
                    "args": ["claude", "hook"],
                    "timeout": CLAUDE_HOOK_TIMEOUT_SECONDS
                }]
            }]
        }
    }))
}

fn current_executable() -> Result<PathBuf, BlastguardError> {
    let executable = env::current_exe().map_err(|error| {
        BlastguardError::Claude(format!(
            "could not resolve the BlastGuard executable: {error}"
        ))
    })?;
    executable.canonicalize().map_err(|error| {
        BlastguardError::Claude(format!(
            "could not canonicalize the BlastGuard executable: {error}"
        ))
    })
}

fn required_environment(name: &str) -> Result<OsString, BlastguardError> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BlastguardError::Claude(format!("required launcher context `{name}` is missing"))
        })
}

fn reject_conflicting_arguments(arguments: &[OsString]) -> Result<(), BlastguardError> {
    if arguments.iter().any(|argument| {
        argument == OsStr::new("--settings")
            || argument
                .to_str()
                .is_some_and(|value| value.starts_with("--settings="))
    }) {
        return Err(BlastguardError::ClaudeInvalid(
            "Claude arguments must not include `--settings`; BlastGuard reserves it for the session policy hook"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_use_exec_form_and_exact_bash_matcher() {
        let value = settings_value(
            "session-one",
            Path::new("/tmp/repo/.git/blastguard"),
            Path::new("/tmp/blastguard"),
        )
        .unwrap_or_else(|error| panic!("settings: {error}"));
        assert_eq!(value["hooks"]["PreToolUse"][0]["matcher"], "Bash");
        assert_eq!(
            value["hooks"]["PreToolUse"][0]["hooks"][0]["args"],
            json!(["claude", "hook"])
        );
        assert_eq!(value["env"][SESSION_ID_ENV], "session-one");
    }

    #[test]
    fn conflicting_settings_are_rejected() {
        assert!(reject_conflicting_arguments(&[OsString::from("--settings=x")]).is_err());
        assert!(
            reject_conflicting_arguments(&[OsString::from("--settings"), OsString::from("x")])
                .is_err()
        );
    }
}
