//! Read-only onboarding checks. In particular, never execute `claude --version`.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{config::Config, error::BlastguardError, git::Git, render::safe_text, sandbox};

pub const SCHEMA: &str = "blastguard.claude.doctor/1.0";
pub const PREREQUISITE_EXIT: u8 = 30;

#[derive(Serialize)]
pub struct Check {
    pub id: &'static str,
    pub passed: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct ClaudeInstallation {
    pub path: Option<String>,
    pub version: Option<String>,
    pub version_note: &'static str,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: &'static str,
    pub ready: bool,
    pub repository: String,
    pub checks: Vec<Check>,
    pub claude: ClaudeInstallation,
    pub next_commands: Vec<String>,
    pub limitations: &'static str,
}

pub fn inspect(repo: Option<&Path>) -> Result<Report, BlastguardError> {
    inspect_for(repo, "claude")
}

// Share the already-hardened, non-executing discovery and repository checks.
// The Codex doctor converts this internal result to its own schema; it never
// renders the Claude-specific version note, readiness claim, or next commands.
pub(crate) fn inspect_for(
    repo: Option<&Path>,
    client: &'static str,
) -> Result<Report, BlastguardError> {
    let input = match repo {
        Some(path) => path.to_path_buf(),
        None => env::current_dir()
            .map_err(|error| BlastguardError::ClaudeInvalid(safe_text(&error.to_string())))?,
    };
    if !input.is_dir() {
        return Err(BlastguardError::InvalidCwd(safe_text(
            &input.display().to_string(),
        )));
    }

    let mut checks = Vec::new();
    check(&mut checks, "platform", cfg!(any(target_os = "linux", target_os = "macos")),
        &format!("{}: controlled execution requires Unix process groups; Windows execution remains fail-closed", env::consts::OS));

    let stable_path = env::var_os("PATH")
        .is_some_and(|path| env::split_paths(&path).all(|entry| entry.is_absolute()));
    check(&mut checks, "path", stable_path, "Use only absolute PATH entries so changing to the worktree cannot change executable discovery.");
    let claude_path = find_executable(client);
    check(
        &mut checks,
        client,
        claude_path.is_some(),
        &if claude_path.is_some() {
            if client == "claude" {
                "Claude executable found; it was not launched.".to_owned()
            } else {
                format!("{client} executable found; it was not launched.")
            }
        } else if client == "claude" {
            "Claude was not found as an executable on PATH; install/configure Claude Code before launch.".to_owned()
        } else {
            format!("{client} was not found as an executable on PATH.")
        },
    );

    let bash = ["/bin/bash", "/usr/bin/bash"]
        .iter()
        .any(|path| executable(Path::new(path)));
    check(&mut checks, "bash", bash, "An executable /bin/bash or /usr/bin/bash is required for direct sandbox exec; neither was executed.");
    let hook_binary = env::current_exe().is_ok_and(|path| executable(&path));
    check(
        &mut checks,
        "blastguard",
        hook_binary,
        "The current BlastGuard binary must remain executable for session-bound hooks.",
    );

    let git = Git::read_only(&input);
    let git_version = if !stable_path {
        Err("Git checks were skipped: PATH must contain only absolute directories.".to_owned())
    } else if find_executable("git").is_some() {
        git.checked("reading the Git version", &["--version"])
            .map(|bytes| safe_text(String::from_utf8_lossy(&bytes).trim()))
            .map_err(|error| safe_text(&error.to_string()))
    } else {
        Err("Git was not found as an executable on PATH; install Git.".to_owned())
    };
    check_result(&mut checks, "git", &git_version);

    let repository = if git_version.is_ok() {
        git.checked("checking the Git repository", &["rev-parse", "--git-dir"])
            .map(|_| "Valid Git repository found.".to_owned())
            .map_err(|error| safe_text(&error.to_string()))
    } else {
        Err("Repository checks require Git.".to_owned())
    };
    check_result(&mut checks, "repository", &repository);

    let source = if repository.is_ok() {
        sandbox::inspect_create_source(&input).map_err(|error| safe_text(&error.to_string()))
    } else {
        Err("Source preconditions could not be checked without a valid repository.".to_owned())
    };
    let source_result = source
        .as_ref()
        .map(|_| {
            "Source satisfies sandbox creation preconditions (including ignored files).".to_owned()
        })
        .map_err(Clone::clone);
    check_result(&mut checks, "source_preconditions", &source_result);
    let policy = match &source {
        Ok(source) => Config::load(None, source)
            .and_then(|config| config.matching_override("").map(|_| ()))
            .map(|_| "Source policy configuration is valid.".to_owned())
            .map_err(|error| safe_text(&error.to_string())),
        Err(_) => Err(
            "Source policy check requires a source satisfying creation preconditions.".to_owned(),
        ),
    };
    check_result(&mut checks, "source_policy", &policy);

    let ready = checks.iter().all(|check| check.passed);
    let mut next_commands = Vec::new();
    if ready && client == "claude" {
        if let Ok(source) = &source {
            if let Some(raw) = source.to_str() {
                // Never turn a redacted or control-bearing path into executable advice.
                if safe_text(raw) == raw && !raw.chars().any(char::is_control) {
                    next_commands = vec![
                        format!("cd -- {}", shell_words::quote(raw)),
                        "blastguard sandbox create --repo . --id claude-eval".to_owned(),
                        "blastguard claude start --id claude-eval".to_owned(),
                        "blastguard sandbox diff --id claude-eval".to_owned(),
                        "blastguard sandbox reject --id claude-eval".to_owned(),
                    ];
                }
            }
        }
    }
    Ok(Report {
        schema_version: SCHEMA,
        ready,
        repository: safe_text(&input.display().to_string()),
        checks,
        claude: ClaudeInstallation {
            path: claude_path.map(|path| safe_text(&path.display().to_string())),
            version: None,
            version_note: "Not queried: doctor never launches Claude, including --version. Check version and authentication manually.",
        },
        next_commands,
        limitations: "Snapshot only: creation revalidates all preconditions. No write-permission probe, worktree, lock, configuration write, Bash execution, or Claude launch. Git must be trusted. Hook enforcement and Claude compatibility require a manual session check. Next commands use the fresh example ID claude-eval; choose another if it exists. Commands are omitted for failed prerequisites or paths requiring redaction/sanitization.",
    })
}

pub fn json(report: &Report) -> Result<String, BlastguardError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| BlastguardError::Serialization(error.to_string()))
}

pub fn human(report: &Report) -> String {
    let mut text = format!(
        "Claude Code doctor: {}\nRepository: {}",
        if report.ready {
            "ready for evaluation"
        } else {
            "prerequisites failed"
        },
        report.repository
    );
    for item in &report.checks {
        text.push_str(&format!(
            "\n[{}] {}: {}",
            if item.passed { "ok" } else { "fail" },
            item.id,
            item.detail
        ));
    }
    if let Some(path) = &report.claude.path {
        text.push_str(&format!("\nClaude: {path}"));
    }
    text.push_str(&format!(
        "\nVersion: {}\n{}",
        report.claude.version_note, report.limitations
    ));
    if !report.next_commands.is_empty() {
        text.push_str("\nNext commands (run in order):");
        for command in &report.next_commands {
            text.push_str(&format!("\n  {command}"));
        }
    }
    safe_text(&text)
}

fn check(checks: &mut Vec<Check>, id: &'static str, passed: bool, detail: &str) {
    checks.push(Check {
        id,
        passed,
        detail: safe_text(detail),
    });
}

fn check_result(checks: &mut Vec<Check>, id: &'static str, result: &Result<String, String>) {
    let detail = match result {
        Ok(detail) | Err(detail) => detail,
    };
    check(checks, id, result.is_ok(), detail);
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let search = env::var_os("PATH")?;
    for directory in env::split_paths(&search) {
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(name);
        if executable(&candidate) {
            return candidate.canonicalize().ok();
        }
        #[cfg(windows)]
        for extension in ["exe", "cmd", "bat"] {
            let candidate = directory.join(format!("{name}.{extension}"));
            if executable(&candidate) {
                return candidate.canonicalize().ok();
            }
        }
    }
    None
}

fn executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}
