use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::sandbox_error::SandboxError;

pub const MANIFEST_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Active,
    Applying,
    Applied,
    Rejecting,
}

impl LifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Rejecting => "rejecting",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionManifest {
    pub schema_version: String,
    pub session_id: String,
    pub source_path: String,
    pub worktree_path: String,
    pub base_commit: String,
    pub created_at_unix_seconds: u64,
    pub lifecycle_state: LifecycleState,
}

impl SessionManifest {
    pub fn new(
        session_id: String,
        source_path: String,
        worktree_path: String,
        base_commit: String,
    ) -> Result<Self, SandboxError> {
        let created_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                SandboxError::operation(
                    "recording creation time",
                    "system clock is before the Unix epoch",
                )
            })?
            .as_secs();
        Ok(Self {
            schema_version: MANIFEST_SCHEMA_VERSION.to_owned(),
            session_id,
            source_path,
            worktree_path,
            base_commit,
            created_at_unix_seconds,
            lifecycle_state: LifecycleState::Active,
        })
    }
}

pub fn read(path: &Path) -> Result<SessionManifest, SandboxError> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SandboxError::manifest("manifest file disappeared during the operation")
        } else {
            SandboxError::operation("reading the session manifest", error.to_string())
        }
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::manifest(format!("manifest JSON is invalid: {error}")))
}

pub fn write_atomic(path: &Path, manifest: &SessionManifest) -> Result<(), SandboxError> {
    let parent = path
        .parent()
        .ok_or_else(|| SandboxError::manifest("manifest path has no parent directory"))?;
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
        SandboxError::operation("serializing the session manifest", error.to_string())
    })?;
    let temp = parent.join(format!(
        ".manifest-{}-{}.tmp",
        std::process::id(),
        next_nonce()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    owner_only_file(&mut options);
    let mut file = options.open(&temp).map_err(|error| {
        SandboxError::operation("creating a temporary session manifest", error.to_string())
    })?;
    let result = (|| {
        file.write_all(&bytes).map_err(|error| {
            SandboxError::operation("writing the session manifest", error.to_string())
        })?;
        file.write_all(b"\n").map_err(|error| {
            SandboxError::operation("finishing the session manifest", error.to_string())
        })?;
        file.sync_all().map_err(|error| {
            SandboxError::operation("syncing the session manifest", error.to_string())
        })?;
        replace_manifest(&temp, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(not(windows))]
fn replace_manifest(temp: &Path, destination: &Path) -> Result<(), SandboxError> {
    fs::rename(temp, destination).map_err(|error| {
        SandboxError::operation("installing the session manifest", error.to_string())
    })
}

#[cfg(windows)]
fn replace_manifest(temp: &Path, destination: &Path) -> Result<(), SandboxError> {
    match fs::rename(temp, destination) {
        Ok(()) => Ok(()),
        Err(error)
            if destination.exists()
                && matches!(
                    error.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
                ) =>
        {
            fs::remove_file(destination).map_err(|remove_error| {
                SandboxError::operation(
                    "replacing the session manifest on Windows",
                    remove_error.to_string(),
                )
            })?;
            fs::rename(temp, destination).map_err(|rename_error| {
                SandboxError::operation(
                    "installing the session manifest on Windows",
                    rename_error.to_string(),
                )
            })
        }
        Err(error) => Err(SandboxError::operation(
            "installing the session manifest",
            error.to_string(),
        )),
    }
}

pub fn remove(path: &Path) -> Result<(), SandboxError> {
    fs::remove_file(path).map_err(|error| {
        SandboxError::operation("removing the session manifest", error.to_string())
    })?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), SandboxError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            SandboxError::operation("syncing the manifest directory", error.to_string())
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), SandboxError> {
    Ok(())
}

fn next_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(unix)]
fn owner_only_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only_file(_options: &mut OpenOptions) {}

pub fn manifest_path(sessions_dir: &Path, id: &str) -> PathBuf {
    sessions_dir.join(format!("{id}.json"))
}
