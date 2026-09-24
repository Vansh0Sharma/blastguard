use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use serde::Serialize;

use crate::execution_error::ExecutionError;

pub const JOURNAL_SCHEMA: &str = "blastguard.execution.journal/2.0";
const MAX_MIGRATION_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Serialize)]
pub struct JournalStream {
    pub bytes_observed: u64,
    pub bytes_captured: usize,
    pub truncated: bool,
    pub redactions: usize,
    pub terminal_sequences_removed: usize,
}

#[derive(Serialize)]
pub struct JournalEntry<'a> {
    pub schema_version: &'static str,
    pub session_id: &'a str,
    pub timestamp_unix_seconds: u64,
    pub policy_decision: &'a str,
    pub execution_state: &'a str,
    pub child_exit_code: Option<i32>,
    pub timed_out: bool,
    pub output_limit_reached: bool,
    pub termination_complete: bool,
    pub stdout: JournalStream,
    pub stderr: JournalStream,
}

pub fn append(
    directory: &Path,
    session_id: &str,
    entry: &JournalEntry<'_>,
) -> Result<(), ExecutionError> {
    validate_id_component(session_id)?;
    let path = directory.join(format!("{session_id}.jsonl"));
    let exists = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            validate_path_metadata(&metadata)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(ExecutionError::internal(format!(
                "inspecting the execution journal: {error}"
            )))
        }
    };

    if exists {
        migrate_legacy_journal(&path)?;
    }

    let bytes = serde_json::to_vec(entry).map_err(|error| {
        ExecutionError::internal(format!("serializing the execution journal: {error}"))
    })?;
    let mut options = OpenOptions::new();
    options.append(true);
    if exists {
        options.create(false);
    } else {
        options.create_new(true);
    }
    owner_only_file(&mut options);
    let mut file = options.open(&path).map_err(|error| {
        ExecutionError::internal(format!("opening the execution journal: {error}"))
    })?;
    validate_open_file(&path, &file)?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            ExecutionError::internal(format!("writing the execution journal: {error}"))
        })
}

fn migrate_legacy_journal(path: &Path) -> Result<(), ExecutionError> {
    let mut source = OpenOptions::new().read(true).open(path).map_err(|error| {
        ExecutionError::internal(format!(
            "opening the execution journal for migration: {error}"
        ))
    })?;
    validate_open_file(path, &source)?;
    let size = source
        .metadata()
        .map_err(|error| {
            ExecutionError::internal(format!("inspecting the execution journal: {error}"))
        })?
        .len();
    if size > MAX_MIGRATION_BYTES {
        return Err(ExecutionError::internal(
            "legacy execution journal is too large to migrate safely",
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    source.read_to_end(&mut bytes).map_err(|error| {
        ExecutionError::internal(format!(
            "reading the execution journal for migration: {error}"
        ))
    })?;
    if !bytes
        .windows(b"command_fingerprint".len())
        .any(|window| window == b"command_fingerprint")
    {
        return Ok(());
    }

    let mut migrated = Vec::with_capacity(bytes.len());
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let mut value: serde_json::Value = serde_json::from_slice(line).map_err(|error| {
            ExecutionError::internal(format!("parsing a legacy execution journal: {error}"))
        })?;
        let object = value.as_object_mut().ok_or_else(|| {
            ExecutionError::internal("legacy execution journal entry is not an object")
        })?;
        object.remove("command_fingerprint");
        object.insert(
            "schema_version".to_owned(),
            serde_json::Value::String(JOURNAL_SCHEMA.to_owned()),
        );
        serde_json::to_writer(&mut migrated, &value).map_err(|error| {
            ExecutionError::internal(format!("serializing a migrated execution journal: {error}"))
        })?;
        migrated.push(b'\n');
    }

    let temporary = path.with_extension(format!("migrate-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    owner_only_file(&mut options);
    let mut target = options.open(&temporary).map_err(|error| {
        ExecutionError::internal(format!("creating the migrated execution journal: {error}"))
    })?;
    let result = target
        .write_all(&migrated)
        .and_then(|_| target.sync_all())
        .and_then(|_| fs::rename(&temporary, path));
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(ExecutionError::internal(format!(
            "replacing the legacy execution journal: {error}"
        )));
    }
    Ok(())
}

fn validate_path_metadata(metadata: &fs::Metadata) -> Result<(), ExecutionError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ExecutionError::internal(
            "execution journal path is not a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ExecutionError::internal(
                "execution journal permissions are not owner-only",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(ExecutionError::internal(
                "execution journal must not have hard links",
            ));
        }
    }
    Ok(())
}

fn validate_open_file(path: &Path, file: &fs::File) -> Result<(), ExecutionError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        ExecutionError::internal(format!("rechecking the execution journal: {error}"))
    })?;
    validate_path_metadata(&path_metadata)?;
    let file_metadata = file.metadata().map_err(|error| {
        ExecutionError::internal(format!("inspecting the open execution journal: {error}"))
    })?;
    validate_path_metadata(&file_metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(ExecutionError::internal(
                "execution journal changed while it was being opened",
            ));
        }
    }
    Ok(())
}

fn validate_id_component(value: &str) -> Result<(), ExecutionError> {
    if !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        Ok(())
    } else {
        Err(ExecutionError::internal(
            "invalid journal session identifier",
        ))
    }
}

#[cfg(unix)]
fn owner_only_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only_file(_options: &mut OpenOptions) {}
