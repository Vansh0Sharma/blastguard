use thiserror::Error;

use crate::{execution_error::ExecutionError, sandbox_error::SandboxError};

#[derive(Debug, Error)]
pub enum BlastguardError {
    #[error("the command must not be empty")]
    EmptyCommand,
    #[error("working directory is not a directory: {0}")]
    InvalidCwd(String),
    #[error("could not initialize the Bash parser: {0}")]
    ParserInitialization(String),
    #[error("the Bash parser did not return a syntax tree")]
    ParserUnavailable,
    #[error("could not read configuration at {path}: {source}")]
    ConfigRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid configuration at {path}: {message}")]
    ConfigParse { path: String, message: String },
    #[error("invalid override pattern `{pattern}`: {message}")]
    InvalidPattern { pattern: String, message: String },
    #[error("could not read hook input: {0}")]
    HookRead(#[from] std::io::Error),
    #[error("hook input is not valid JSON: {0}")]
    HookJson(#[from] serde_json::Error),
    #[error("hook input did not contain a non-empty shell command; expected `tool_input.command`")]
    HookCommandMissing,
    #[error("hook input contains conflicting shell command fields")]
    HookCommandAmbiguous,
    #[error("hook input must be a JSON object")]
    HookObjectRequired,
    #[error("hook input must identify the Bash tool")]
    HookToolMissing,
    #[error("hook input is for an unsupported tool; only Bash is accepted")]
    HookToolUnsupported,
    #[error("hook input must identify the PreToolUse event")]
    HookEventMissing,
    #[error("hook input is for an unsupported event; only PreToolUse is accepted")]
    HookEventUnsupported,
    #[error("hook input did not contain a non-empty working directory")]
    HookCwdMissing,
    #[error("hook input exceeds the {0}-byte safety limit")]
    HookInputTooLarge(usize),
    #[error("failed to serialize output: {0}")]
    Serialization(String),
    #[error("Claude Code integration failed: {0}")]
    Claude(String),
    #[error("invalid Claude Code integration input: {0}")]
    ClaudeInvalid(String),
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
}
