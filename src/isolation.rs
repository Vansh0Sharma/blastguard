//! Boundary for a future operating-system isolation provider.
//!
//! Milestone 4 launch and controlled execution deliberately do not implement this trait:
//! a working directory, minimal environment, limits, and process group are not
//! an operating-system containment boundary.

use std::path::Path;

/// Describes whether an execution backend can provide rollback.
pub trait IsolationProvider {
    fn rollback_available(&self) -> bool;
    fn description(&self) -> &'static str;
    fn prepare(&self, _repository: &Path) -> Result<(), IsolationUnavailable>;
}

#[derive(Debug, thiserror::Error)]
#[error("operating-system command isolation is not available in Milestone 4")]
pub struct IsolationUnavailable;

/// Placeholder used when no operating-system isolation provider is configured.
#[derive(Debug, Default)]
pub struct AnalysisOnly;

impl IsolationProvider for AnalysisOnly {
    fn rollback_available(&self) -> bool {
        false
    }

    fn description(&self) -> &'static str {
        "Git worktree rollback only; no operating-system isolation is provided"
    }

    fn prepare(&self, _repository: &Path) -> Result<(), IsolationUnavailable> {
        Err(IsolationUnavailable)
    }
}
