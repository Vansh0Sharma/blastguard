//! Composite-action adapter. Only explicit inputs/runner file locations are read;
//! the analyzer child receives no runner environment and can only run `analyze`.

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{model::Analysis, render};

const INVALID: u8 = 64;
const INTERNAL: u8 = 70;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_JSON_BYTES: u64 = 8 * 1024 * 1024;

struct Inputs {
    command: String,
    directory: String,
    pack: String,
    fail_on: String,
    report: String,
}

struct Outcome {
    decision: &'static str,
    code: u8,
    report: Option<String>,
}

/// Called only by the composite action's fixed bootstrap, never by normal analyze.
pub fn run() -> u8 {
    let output = env::var_os("GITHUB_OUTPUT").map(PathBuf::from);
    let result = (|| {
        if !cfg!(unix) {
            return Err(INTERNAL);
        }
        let inputs = Inputs {
            command: input("BG_ACTION_COMMAND")?,
            directory: input("BG_ACTION_DIRECTORY")?,
            pack: input("BG_ACTION_PACK")?,
            fail_on: input("BG_ACTION_FAIL_ON")?,
            report: input("BG_ACTION_REPORT")?,
        };
        let workspace = env::var_os("GITHUB_WORKSPACE")
            .map(PathBuf::from)
            .ok_or(INTERNAL)?;
        let executable = env::current_exe().map_err(|_| INTERNAL)?;
        let outcome = check(&inputs, &workspace, &executable)?;
        let step_code = if outcome.decision == "ask" && inputs.fail_on == "block" {
            0
        } else {
            outcome.code
        };
        Ok((outcome, step_code))
    })();
    let (outcome, step_code) = match result {
        Ok(result) => result,
        Err(code) => (
            Outcome {
                decision: "error",
                code,
                report: None,
            },
            code,
        ),
    };
    let written = output
        .as_deref()
        .ok_or(INTERNAL)
        .and_then(|path| emit(path, &outcome));
    if written.is_err() {
        eprintln!("BlastGuard action: could not write action outputs.");
        return INTERNAL;
    }
    if outcome.decision == "error" {
        // Never relay arbitrary subprocess stderr, OS errors, paths, or inputs.
        eprintln!("BlastGuard action: invalid input, analysis failure, or report failure; see the integration guide.");
    } else {
        println!("BlastGuard static decision: {}", outcome.decision);
    }
    step_code
}

fn input(name: &str) -> Result<String, u8> {
    env::var(name).map_err(|_| INVALID)
}

fn check(inputs: &Inputs, workspace: &Path, executable: &Path) -> Result<Outcome, u8> {
    if inputs.command.trim().is_empty()
        || inputs.command.len() > MAX_COMMAND_BYTES
        || inputs.command.contains('\0')
        || !matches!(inputs.fail_on.as_str(), "ask" | "block")
        || !matches!(inputs.pack.as_str(), "" | "balanced" | "strict" | "ci")
        || !workspace.is_absolute()
    {
        return Err(INVALID);
    }
    let workspace = workspace.canonicalize().map_err(|_| INVALID)?;
    let directory = relative_path(&inputs.directory, true)?;
    let cwd = checked_directory(&workspace, &directory, false)?;
    // Local configuration remains opt-in-by-presence as for ordinary analyze,
    // but do not follow configuration symlinks or special files on a runner.
    match fs::symlink_metadata(cwd.join("blastguard.toml")) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err(INVALID),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(INVALID),
        _ => {}
    }
    let report = if inputs.report.is_empty() {
        None
    } else {
        let path = relative_path(&inputs.report, false)?;
        // Validate existing components before analysis; no directories created yet.
        validate_destination(&cwd, &path)?;
        Some(path)
    };

    let mut command = Command::new(executable);
    command
        .args(["analyze", "--json", "--cwd"])
        .arg(&cwd)
        // One argv element, including leading dashes, quotes and newlines.
        .arg(format!("--command={}", inputs.command))
        .current_dir(&cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if !inputs.pack.is_empty() {
        command.args(["--policy-pack", &inputs.pack]);
    }
    let mut child = command.spawn().map_err(|_| INTERNAL)?;
    let mut bytes = Vec::new();
    let read = child.stdout.take().ok_or(INTERNAL).and_then(|stream| {
        stream
            .take(MAX_JSON_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| INTERNAL)
    });
    if read.is_err() || bytes.len() as u64 > MAX_JSON_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(INTERNAL);
    }
    let status = child.wait().map_err(|_| INTERNAL)?;
    let code = status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .ok_or(INTERNAL)?;
    let (decision, json) = verified_analysis(code, &bytes)?;
    let report = match report {
        Some(path) => {
            publish(&cwd, &path, json.as_bytes())?;
            let relative = directory.join(path);
            Some(relative.to_str().ok_or(INVALID)?.to_owned())
        }
        None => None,
    };
    Ok(Outcome {
        decision,
        code,
        report,
    })
}

fn verified_analysis(code: u8, bytes: &[u8]) -> Result<(&'static str, String), u8> {
    let decision = match code {
        0 => "allow",
        10 => "ask",
        20 => "block",
        // Even plausible JSON accompanying an error never becomes a decision.
        other => return Err(other),
    };
    let analysis: Analysis = serde_json::from_slice(bytes).map_err(|_| INTERNAL)?;
    if analysis.schema_version != crate::model::SCHEMA_VERSION
        || analysis.decision.as_str() != decision
    {
        return Err(INTERNAL);
    }
    let json = render::json(&analysis).map_err(|_| INTERNAL)?;
    // Fail rather than publishing malformed JSON if redaction changes its syntax.
    serde_json::from_str::<Analysis>(&json).map_err(|_| INTERNAL)?;
    Ok((decision, format!("{json}\n")))
}

fn relative_path(value: &str, directory: bool) -> Result<PathBuf, u8> {
    if value.is_empty()
        || value.chars().any(char::is_control)
        || value.contains(['\\', ':'])
        || render::safe_text(value) != value
    {
        return Err(INVALID);
    }
    let mut result = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) if !name.eq_ignore_ascii_case(".git") => result.push(name),
            _ => return Err(INVALID),
        }
    }
    if !directory && result.as_os_str().is_empty() {
        return Err(INVALID);
    }
    Ok(result)
}

fn checked_directory(root: &Path, path: &Path, create: bool) -> Result<PathBuf, u8> {
    let mut current = root.to_path_buf();
    for part in path.components() {
        current.push(part);
        if create {
            match fs::create_dir(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(INTERNAL),
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| INVALID)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(INVALID);
        }
    }
    let canonical = current.canonicalize().map_err(|_| INVALID)?;
    if !canonical.starts_with(root) || canonical != current {
        return Err(INVALID);
    }
    Ok(current)
}

fn validate_destination(root: &Path, path: &Path) -> Result<(), u8> {
    let parent = path.parent().ok_or(INVALID)?;
    let mut current = root.to_path_buf();
    for part in parent.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            _ => return Err(INVALID),
        }
    }
    match fs::symlink_metadata(root.join(path)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(INVALID), // Never overwrite a file, directory, or dangling symlink.
    }
}

fn publish(root: &Path, path: &Path, json: &[u8]) -> Result<(), u8> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().ok_or(INVALID)?;
    let directory = checked_directory(root, parent, true)?;
    let temporary = directory.join(format!(
        ".blastguard-report-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temporary).map_err(|_| INTERNAL)?;
    let result = (|| {
        file.write_all(json).map_err(|_| INTERNAL)?;
        file.sync_all().map_err(|_| INTERNAL)?;
        checked_directory(root, parent, false)?;
        // Atomic, no-clobber publication on the same filesystem. A rename could
        // overwrite a concurrently created destination. Only complete JSON is visible.
        fs::hard_link(&temporary, root.join(path)).map_err(|_| INTERNAL)
    })();
    let removed = fs::remove_file(&temporary).map_err(|_| INTERNAL);
    result.and(removed)
}

fn emit(path: &Path, outcome: &Outcome) -> Result<(), u8> {
    if !fs::symlink_metadata(path).map_err(|_| INTERNAL)?.is_file() {
        return Err(INTERNAL);
    }
    let mut options = File::options();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| INTERNAL)?;
    writeln!(file, "decision={}", outcome.decision).map_err(|_| INTERNAL)?;
    writeln!(file, "exit-code={}", outcome.code).map_err(|_| INTERNAL)?;
    if let Some(report) = &outcome.report {
        writeln!(file, "report-path={report}").map_err(|_| INTERNAL)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn publication_rejects_destinations_created_after_validation_without_clobbering() {
        use std::os::unix::fs::symlink;

        let root = env::temp_dir().join(format!(
            "blastguard-action-publication-test-{}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let sentinel = root.join("sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();
        // Deterministic ordering of the race: preflight succeeds, another writer
        // creates the destination, then publication must atomically refuse it.
        for kind in ["file", "directory", "symlink"] {
            let path = Path::new(kind);
            assert!(validate_destination(&root, path).is_ok());
            match kind {
                "file" => fs::write(root.join(path), b"unchanged").unwrap(),
                "directory" => fs::create_dir(root.join(path)).unwrap(),
                _ => symlink(&sentinel, root.join(path)).unwrap(),
            }
            assert!(publish(&root, path, b"{}\n").is_err());
        }
        assert_eq!(fs::read(root.join("file")).unwrap(), b"unchanged");
        assert!(root.join("directory").is_dir());
        assert_eq!(fs::read_link(root.join("symlink")).unwrap(), sentinel);
        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");

        // Also recheck a parent substituted with a symlink after preflight.
        let path = Path::new("parent/report.json");
        fs::create_dir(root.join("parent")).unwrap();
        fs::create_dir(root.join("other")).unwrap();
        assert!(validate_destination(&root, path).is_ok());
        fs::remove_dir(root.join("parent")).unwrap();
        symlink(root.join("other"), root.join("parent")).unwrap();
        assert!(publish(&root, path, b"{}\n").is_err());
        assert!(fs::read_dir(root.join("other")).unwrap().next().is_none());
        assert!(!fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".blastguard-report-")));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn malformed_mismatched_or_error_results_never_become_policy_decisions() {
        let analysis = Analysis::new("cargo test".to_owned(), Path::new("/fixture"));
        let json = render::json(&analysis).unwrap();
        assert!(verified_analysis(0, json.as_bytes()).is_ok());
        for status in [10, 20, 64, 70, 1, 127] {
            assert!(verified_analysis(status, json.as_bytes()).is_err());
        }
        for bytes in [b"".as_slice(), b"{}", b"not JSON"] {
            assert!(verified_analysis(0, bytes).is_err());
        }
        let future = json.replace("\"1.0\"", "\"999.0\"");
        assert!(verified_analysis(0, future.as_bytes()).is_err());
    }
}
