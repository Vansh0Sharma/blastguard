use thiserror::Error;

use crate::redaction;

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("invalid execution request: {0}")]
    InvalidInput(String),
    #[error("command execution failed: {0}")]
    Internal(String),
}

impl ExecutionError {
    pub fn invalid(message: impl AsRef<str>) -> Self {
        Self::InvalidInput(redaction::redact(message.as_ref()).text)
    }

    pub fn internal(message: impl AsRef<str>) -> Self {
        Self::Internal(redaction::redact(message.as_ref()).text)
    }
}
