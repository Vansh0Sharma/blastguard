//! BlastGuard's reusable policy engine.

pub mod claude;
pub mod claude_hook;
pub mod config;
pub mod error;
pub mod execution;
pub mod execution_error;
pub mod execution_journal;
pub mod execution_render;
pub mod git;
pub mod isolation;
pub mod manifest;
pub mod model;
pub mod policy;
pub mod redaction;
pub mod render;
pub mod sandbox;
pub mod sandbox_error;
pub mod sandbox_render;
pub mod session_lock;
pub mod shell;

use std::path::Path;

use config::Config;
use error::BlastguardError;
use model::Analysis;

/// Parse and evaluate a shell command without executing it.
pub fn analyze(command: &str, cwd: &Path, config: &Config) -> Result<Analysis, BlastguardError> {
    let parsed = shell::parse(command)?;
    policy::evaluate(command, cwd, &parsed, config)
}

/// Parse and evaluate a command in the context of a managed worktree.
pub fn analyze_for_execution(
    command: &str,
    worktree: &Path,
    config: &Config,
) -> Result<Analysis, BlastguardError> {
    let parsed = shell::parse(command)?;
    policy::evaluate_for_execution(command, worktree, &parsed, config)
}
