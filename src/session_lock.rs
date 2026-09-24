use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{redaction, sandbox_error::SandboxError};

const STALE_AFTER: Duration = Duration::from_secs(30 * 60);

pub struct SessionLock {
    path: PathBuf,
}

impl SessionLock {
    pub fn acquire_session(locks_dir: &Path, id: &str) -> Result<Self, SandboxError> {
        Self::acquire(locks_dir.join(format!("session-{id}.lock")))
    }

    pub fn acquire_repository(locks_dir: &Path) -> Result<Self, SandboxError> {
        Self::acquire(locks_dir.join("repository.lock"))
    }

    pub fn acquire_claude_launch(locks_dir: &Path, id: &str) -> Result<Self, SandboxError> {
        Self::acquire(locks_dir.join(format!("claude-{id}.lock")))
    }

    fn acquire(path: PathBuf) -> Result<Self, SandboxError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        owner_only_file(&mut options);
        match options.open(&path) {
            Ok(mut file) => {
                if let Err(error) = writeln!(file, "pid={}", std::process::id()) {
                    let _ = fs::remove_file(&path);
                    return Err(SandboxError::operation(
                        "writing the session lock",
                        error.to_string(),
                    ));
                }
                if let Err(error) = file.sync_all() {
                    let _ = fs::remove_file(&path);
                    return Err(SandboxError::operation(
                        "syncing the session lock",
                        error.to_string(),
                    ));
                }
                Ok(Self { path })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let age = fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok());
                let display = redaction::redact(&path.display().to_string()).text;
                if age.is_some_and(|value| value >= STALE_AFTER) {
                    Err(SandboxError::StaleLock(format!(
                        "{display}; verify that no BlastGuard process is running, then remove this exact lock file"
                    )))
                } else {
                    Err(SandboxError::Locked(format!(
                        "lock file exists at {display}; wait for the active operation to finish"
                    )))
                }
            }
            Err(error) => Err(SandboxError::operation(
                "acquiring the session lock",
                error.to_string(),
            )),
        }
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn owner_only_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only_file(_options: &mut OpenOptions) {}
