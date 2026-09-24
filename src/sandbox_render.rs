use serde::Serialize;

use crate::{
    redaction,
    sandbox::{AcceptResult, CreateResult, DiffResult, ListResult, RejectResult, StatusResult},
    sandbox_error::SandboxError,
};

pub fn json<T: Serialize>(value: &T) -> Result<String, SandboxError> {
    let output = serde_json::to_string_pretty(value).map_err(|error| {
        SandboxError::operation("serializing sandbox output", error.to_string())
    })?;
    Ok(redaction::redact(&output).text)
}

pub fn create(value: &CreateResult) -> String {
    redact(format!(
        "╭─ Sandbox Created ───────────────────────────────────────\n\
         │ Session    {}\n\
         │ Source     {}\n\
         │ Worktree   {}\n\
         │ Base       {}\n\
         │ Rollback   {}\n\
         ╰──────────────────────────────────────────────────",
        value.session_id,
        value.source_path,
        value.worktree_path,
        value.base_commit,
        value.rollback_scope
    ))
}

pub fn status(value: &StatusResult) -> String {
    let git = value.worktree_git_state.as_ref().map_or_else(
        || "unavailable".to_owned(),
        |state| {
            format!(
                "{} (staged {}, unstaged {}, untracked {}, conflicted {})",
                if state.clean { "clean" } else { "changed" },
                state.staged,
                state.unstaged,
                state.untracked,
                state.conflicted
            )
        },
    );
    redact(format!(
        "╭─ Sandbox Status ────────────────────────────────────────\n\
         │ Session      {}\n\
         │ State        {}\n\
         │ Worktree     {}\n\
         │ Git state    {}\n\
         │ Source HEAD  {}\n\
         │ Source clean {}\n\
         │ Base         {}\n\
         ╰──────────────────────────────────────────────────",
        value.session_id,
        value.lifecycle_state,
        if value.worktree_exists {
            "present"
        } else {
            "missing"
        },
        git,
        if value.source_head_matches_base {
            "matches base"
        } else {
            "changed"
        },
        value.source_clean,
        value.base_commit
    ))
}

pub fn diff(value: &DiffResult) -> String {
    let notice = if value.redacted {
        "# BlastGuard redacted likely secret values from this display.\n"
    } else {
        ""
    };
    redact(format!(
        "# Session: {}\n# Base: {}\n{notice}{}",
        value.session_id, value.base_commit, value.patch
    ))
}

pub fn list(value: &ListResult) -> String {
    if value.sessions.is_empty() {
        return redact(format!(
            "No BlastGuard sandbox sessions for {}.",
            value.source_path
        ));
    }
    let mut output = format!("BlastGuard sandbox sessions for {}:\n", value.source_path);
    for session in &value.sessions {
        output.push_str(&format!(
            "- {} [{}] worktree={} base={} created={}\n",
            session.session_id,
            session.lifecycle_state,
            if session.worktree_exists {
                "present"
            } else {
                "missing"
            },
            session.base_commit,
            session.created_at_unix_seconds
        ));
    }
    redact(output.trim_end().to_owned())
}

pub fn accept(value: &AcceptResult) -> String {
    redact(format!(
        "Accepted sandbox `{}` into {} as {} staged change(s). Cleanup complete: {}. {}",
        value.session_id,
        value.source_path,
        value.staged_changes,
        value.cleanup_complete,
        value.rollback_scope
    ))
}

pub fn reject(value: &RejectResult) -> String {
    redact(format!(
        "Rejected sandbox `{}`. Managed worktree, ref, and manifest were removed. Source repository unchanged: {} ({}).",
        value.session_id, value.source_untouched, value.source_path
    ))
}

fn redact(value: String) -> String {
    redaction::redact(&value).text
}
