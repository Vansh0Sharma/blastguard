use thiserror::Error;

use crate::redaction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SandboxExit {
    Repository = 30,
    Session = 31,
    Locked = 32,
    SourceChanged = 33,
    Operation = 34,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("repository precondition failed: {0}")]
    Repository(String),
    #[error("invalid sandbox session ID; use 1-64 lowercase ASCII letters, digits, hyphens, or underscores and start with a letter or digit")]
    InvalidId,
    #[error("sandbox session `{0}` was not found in this repository")]
    SessionNotFound(String),
    #[error("sandbox session already exists: {0}")]
    SessionExists(String),
    #[error("sandbox manifest is invalid or inconsistent: {0}")]
    Manifest(String),
    #[error("sandbox session is busy: {0}")]
    Locked(String),
    #[error("sandbox session has a stale lock: {0}")]
    StaleLock(String),
    #[error("source repository changed since sandbox creation: {0}")]
    SourceChanged(String),
    #[error("sandbox operation failed during {action}: {detail}")]
    Operation { action: String, detail: String },
    #[error("sandbox cleanup failed: {detail}. Recovery: {recovery}")]
    Cleanup { detail: String, recovery: String },
}

impl SandboxError {
    pub fn repository(message: impl AsRef<str>) -> Self {
        Self::Repository(clean(message))
    }

    pub fn manifest(message: impl AsRef<str>) -> Self {
        Self::Manifest(clean(message))
    }

    pub fn operation(action: impl AsRef<str>, detail: impl AsRef<str>) -> Self {
        Self::Operation {
            action: clean(action),
            detail: clean(detail),
        }
    }

    pub fn cleanup(detail: impl AsRef<str>, recovery: impl AsRef<str>) -> Self {
        Self::Cleanup {
            detail: clean(detail),
            recovery: clean(recovery),
        }
    }

    pub fn exit(&self) -> SandboxExit {
        match self {
            Self::Repository(_) | Self::InvalidId => SandboxExit::Repository,
            Self::SessionNotFound(_) | Self::SessionExists(_) | Self::Manifest(_) => {
                SandboxExit::Session
            }
            Self::Locked(_) | Self::StaleLock(_) => SandboxExit::Locked,
            Self::SourceChanged(_) => SandboxExit::SourceChanged,
            Self::Operation { .. } | Self::Cleanup { .. } => SandboxExit::Operation,
        }
    }
}

fn clean(value: impl AsRef<str>) -> String {
    redaction::redact(value.as_ref()).text
}
