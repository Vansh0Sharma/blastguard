use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_blastguard")
}

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "blastguard-exec-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("create test root: {error}"));
        Self { path }
    }

    fn repo(&self) -> PathBuf {
        self.path.join("repo")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        if self.path.starts_with(std::env::temp_dir())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("blastguard-exec-"))
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn git(repo: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap_or_else(|error| panic!("run git: {error}"))
}

fn git_ok(repo: &Path, args: &[&str]) -> Vec<u8> {
    let output = git(repo, args);
    assert!(output.status.success(), "git command failed");
    output.stdout
}

fn init_repo(root: &TestRoot) -> PathBuf {
    let repo = root.repo();
    fs::create_dir(&repo).unwrap_or_else(|error| panic!("create repo: {error}"));
    git_ok(&repo, &["init", "--quiet"]);
    git_ok(&repo, &["config", "user.name", "BlastGuard Tests"]);
    git_ok(
        &repo,
        &["config", "user.email", "blastguard@example.invalid"],
    );
    fs::write(repo.join("tracked.txt"), "base\n")
        .unwrap_or_else(|error| panic!("write fixture: {error}"));
    git_ok(&repo, &["add", "-A"]);
    git_ok(&repo, &["commit", "--quiet", "-m", "initial"]);
    let created = blastguard(&repo, &["sandbox", "create", "--id", "exec-one"]);
    assert_eq!(created.status.code(), Some(0));
    repo
}

fn blastguard(cwd: &Path, args: &[&str]) -> Output {
    Command::new(binary())
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run BlastGuard: {error}"))
}

fn exec(repo: &Path, command: &str, extra: &[&str]) -> Output {
    let mut args = vec![
        "sandbox",
        "exec",
        "--id",
        "exec-one",
        "--command",
        command,
        "--json",
    ];
    args.extend_from_slice(extra);
    blastguard(repo, &args)
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("parse execution JSON: {error}"))
}

fn worktree(repo: &Path) -> PathBuf {
    let status = blastguard(repo, &["sandbox", "status", "--id", "exec-one", "--json"]);
    assert_eq!(status.status.code(), Some(0));
    PathBuf::from(
        json(&status)["worktree_path"]
            .as_str()
            .unwrap_or_else(|| panic!("missing worktree path")),
    )
}

#[test]
fn allow_executes_in_managed_worktree_and_reports_stable_json() {
    let root = TestRoot::new("allow");
    let repo = init_repo(&root);
    let managed = worktree(&repo);
    let output = exec(&repo, "printf 'made\\n' > result.txt; pwd", &[]);
    assert_eq!(output.status.code(), Some(0));
    let value = json(&output);
    assert_eq!(value["schema_version"], "blastguard.sandbox.exec/1.0");
    assert_eq!(value["policy"]["decision"], "allow");
    assert_eq!(value["execution_state"], "completed");
    assert_eq!(value["process"]["exit_code"], 0);
    assert_eq!(
        value["process"]["stdout"]["text"].as_str().map(str::trim),
        managed.to_str()
    );
    assert_eq!(
        fs::read_to_string(managed.join("result.txt"))
            .ok()
            .as_deref(),
        Some("made\n")
    );
    assert!(!repo.join("result.txt").exists());
    let second = exec(&repo, "printf second > second.txt", &[]);
    assert_eq!(second.status.code(), Some(0));
    assert!(json(&second)["worktree_git_state_before"]["untracked"]
        .as_u64()
        .is_some_and(|count| count >= 1));
    assert!(git_ok(&repo, &["status", "--porcelain=v1"]).is_empty());
}

#[test]
fn ask_requires_approval_and_block_ignores_approval() {
    let root = TestRoot::new("decisions");
    let repo = init_repo(&root);
    let managed = worktree(&repo);

    let ask = exec(&repo, "/bin/echo approved > asked.txt", &[]);
    assert_eq!(ask.status.code(), Some(41));
    assert_eq!(json(&ask)["execution_state"], "approval_required");
    assert!(!managed.join("asked.txt").exists());

    let approved = exec(&repo, "/bin/echo approved > asked.txt", &["--approve"]);
    assert_eq!(approved.status.code(), Some(0));
    assert!(managed.join("asked.txt").is_file());

    fs::write(managed.join("protected.txt"), "keep\n")
        .unwrap_or_else(|error| panic!("write protected fixture: {error}"));
    let blocked = exec(&repo, "rm -rf protected.txt", &["--approve"]);
    assert_eq!(blocked.status.code(), Some(40));
    assert_eq!(json(&blocked)["execution_state"], "blocked");
    assert!(managed.join("protected.txt").is_file());
}

#[test]
fn child_environment_is_constructed_and_host_secrets_are_not_inherited() {
    let root = TestRoot::new("environment");
    let repo = init_repo(&root);
    let managed = worktree(&repo);
    let output = Command::new(binary())
        .current_dir(&repo)
        .args([
            "sandbox",
            "exec",
            "--id",
            "exec-one",
            "--command",
            "test -z \"${AWS_SECRET_ACCESS_KEY+x}\" && test -z \"${CUSTOM_HOST_ONLY+x}\" && test -z \"${HOME+x}\" && printf clean",
            "--json",
        ])
        .env("AWS_SECRET_ACCESS_KEY", "synthetic-host-only-value")
        .env("CUSTOM_HOST_ONLY", "synthetic-custom-value")
        .output()
        .unwrap_or_else(|error| panic!("run environment test: {error}"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(json(&output)["process"]["stdout"]["text"], "clean");
    assert!(managed.is_dir());
}

#[test]
fn stdout_stderr_and_nonzero_exit_are_reported_separately() {
    let root = TestRoot::new("streams");
    let repo = init_repo(&root);
    let output = exec(
        &repo,
        "printf stdout-value; printf stderr-value >&2; exit 7",
        &[],
    );
    assert_eq!(output.status.code(), Some(42));
    let value = json(&output);
    assert_eq!(value["execution_state"], "child_failed");
    assert_eq!(value["process"]["exit_code"], 7);
    assert_eq!(value["process"]["stdout"]["text"], "stdout-value");
    assert_eq!(value["process"]["stderr"]["text"], "stderr-value");
}

#[test]
fn output_limit_truncates_and_terminates_unbounded_output() {
    let root = TestRoot::new("output-limit");
    let repo = init_repo(&root);
    let output = exec(
        &repo,
        "yes X",
        &["--max-output-bytes", "128", "--timeout-seconds", "5"],
    );
    assert_eq!(output.status.code(), Some(44));
    let value = json(&output);
    assert_eq!(value["execution_state"], "output_limit");
    assert_eq!(value["process"]["output_limit_reached"], true);
    assert_eq!(value["process"]["stdout"]["truncated"], true);
    let stdout_bytes = value["process"]["stdout"]["bytes_captured"]
        .as_u64()
        .unwrap_or(u64::MAX);
    let stderr_bytes = value["process"]["stderr"]["bytes_captured"]
        .as_u64()
        .unwrap_or(u64::MAX);
    assert!(stdout_bytes + stderr_bytes <= 128);
}

#[test]
fn timeout_terminates_background_descendant_in_the_process_group() {
    let root = TestRoot::new("timeout");
    let repo = init_repo(&root);
    let managed = worktree(&repo);
    let output = exec(
        &repo,
        "(trap '' TERM; printf ready > child.ready; sleep 2; printf escaped > post-timeout-side-effect) & while test ! -s child.ready; do sleep 0.01; done; wait",
        &["--timeout-seconds", "1"],
    );
    assert_eq!(output.status.code(), Some(43));
    let value = json(&output);
    assert_eq!(value["execution_state"], "timed_out");
    assert_eq!(value["process"]["termination_complete"], true);
    assert_eq!(
        fs::read_to_string(managed.join("child.ready"))
            .ok()
            .as_deref(),
        Some("ready")
    );
    assert!(
        !managed.join("post-timeout-side-effect").exists(),
        "background descendant performed its delayed side effect after timeout"
    );
}

#[test]
fn output_is_redacted_sanitized_and_journal_never_contains_raw_content() {
    let root = TestRoot::new("redaction");
    let repo = init_repo(&root);
    let journal_path = repo.join(".git/blastguard/journal/exec-one.jsonl");
    fs::write(
        &journal_path,
        "{\"schema_version\":\"blastguard.execution.journal/1.0\",\"session_id\":\"exec-one\",\"command_fingerprint\":\"git-object:guessable\"}\n",
    )
    .unwrap_or_else(|error| panic!("write legacy journal: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("chmod legacy journal: {error}"));
    }
    let secret = ["abcdefgh", "ijklmno"].concat();
    let token = ["ghp_", "abcdefghijklmnopqrstuvwx"].concat();
    let command =
        format!("printf 'journal-marker api_key={secret}\\n\\033[2J'; printf '{token}' >&2");
    let output = exec(&repo, &command, &["--approve"]);
    assert_eq!(output.status.code(), Some(0));
    let rendered = String::from_utf8_lossy(&output.stdout);
    assert!(!rendered.contains(&secret));
    assert!(!rendered.contains(&token));
    assert!(!rendered.contains('\u{1b}'));
    let value = json(&output);
    assert!(value["process"]["stdout"]["terminal_sequences_removed"]
        .as_u64()
        .is_some_and(|count| count >= 1));

    let journal = fs::read_to_string(&journal_path)
        .unwrap_or_else(|error| panic!("read execution journal: {error}"));
    assert!(!journal.contains(&secret));
    assert!(!journal.contains(&token));
    assert!(!journal.contains("journal-marker"));
    assert!(!journal.contains("printf"));
    assert!(!journal.contains("command_fingerprint"));
    assert!(!journal.contains("git-object:guessable"));
    for line in journal.lines() {
        let value = serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|error| panic!("parse journal line: {error}"));
        assert_eq!(value["schema_version"], "blastguard.execution.journal/2.0");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&journal_path)
            .unwrap_or_else(|error| panic!("journal metadata: {error}"))
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}

#[test]
fn source_drift_lock_contention_missing_session_and_invalid_limits_fail_closed() {
    let root = TestRoot::new("fail-closed");
    let repo = init_repo(&root);

    let missing = blastguard(
        &repo,
        &[
            "sandbox",
            "exec",
            "--id",
            "missing",
            "--command",
            "touch should-not-exist",
            "--json",
        ],
    );
    assert_eq!(missing.status.code(), Some(31));

    let invalid_id = blastguard(
        &repo,
        &[
            "sandbox",
            "exec",
            "--id",
            "../invalid",
            "--command",
            "touch should-not-exist",
            "--json",
        ],
    );
    assert_eq!(invalid_id.status.code(), Some(30));

    let invalid = exec(&repo, "touch should-not-exist", &["--timeout-seconds", "0"]);
    assert_eq!(invalid.status.code(), Some(64));

    let lock_path = repo.join(".git/blastguard/locks/session-exec-one.lock");
    fs::write(&lock_path, "test lock\n")
        .unwrap_or_else(|error| panic!("write lock fixture: {error}"));
    let locked = exec(&repo, "touch should-not-exist", &[]);
    assert_eq!(locked.status.code(), Some(32));
    fs::remove_file(&lock_path).unwrap_or_else(|error| panic!("remove lock fixture: {error}"));

    fs::write(repo.join("tracked.txt"), "source drift\n")
        .unwrap_or_else(|error| panic!("write source drift: {error}"));
    let drifted = exec(&repo, "touch should-not-exist", &[]);
    assert_eq!(drifted.status.code(), Some(33));
    assert!(!worktree(&repo).join("should-not-exist").exists());
}

#[test]
fn inactive_rejected_and_tampered_worktrees_cannot_execute() {
    let inactive_root = TestRoot::new("inactive");
    let inactive_repo = init_repo(&inactive_root);
    let manifest_path = inactive_repo.join(".git/blastguard/sessions/exec-one.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).unwrap_or_else(|error| panic!("read manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse manifest: {error}"));
    manifest["lifecycle_state"] = serde_json::Value::String("applying".to_owned());
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .unwrap_or_else(|error| panic!("serialize manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("write inactive manifest: {error}"));
    assert_eq!(
        exec(&inactive_repo, "touch never-created", &[])
            .status
            .code(),
        Some(31)
    );

    let manifest_root = TestRoot::new("manifest-tamper");
    let manifest_repo = init_repo(&manifest_root);
    let manifest_path = manifest_repo.join(".git/blastguard/sessions/exec-one.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).unwrap_or_else(|error| panic!("read manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse manifest: {error}"));
    manifest["worktree_path"] = serde_json::Value::String("/tmp/not-owned".to_owned());
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .unwrap_or_else(|error| panic!("serialize manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("write tampered manifest: {error}"));
    assert_eq!(
        exec(&manifest_repo, "touch never-created", &[])
            .status
            .code(),
        Some(31)
    );

    let tampered_root = TestRoot::new("tampered");
    let tampered_repo = init_repo(&tampered_root);
    let tampered_worktree = worktree(&tampered_repo);
    git_ok(&tampered_worktree, &["checkout", "--detach", "--quiet"]);
    assert_eq!(
        exec(&tampered_repo, "touch never-created", &[])
            .status
            .code(),
        Some(31)
    );
    assert!(!tampered_worktree.join("never-created").exists());

    let rejected_root = TestRoot::new("rejected");
    let rejected_repo = init_repo(&rejected_root);
    let rejected = blastguard(&rejected_repo, &["sandbox", "reject", "--id", "exec-one"]);
    assert_eq!(rejected.status.code(), Some(0));
    assert_eq!(
        exec(&rejected_repo, "touch never-created", &[])
            .status
            .code(),
        Some(31)
    );
}

#[test]
fn explicit_directory_escape_requires_approval_and_does_not_run_by_default() {
    let root = TestRoot::new("path-escape");
    let repo = init_repo(&root);
    let managed = worktree(&repo);
    let escaped_file = managed
        .parent()
        .unwrap_or_else(|| panic!("worktree has no parent"))
        .join("escape-attempt");
    let output = exec(&repo, "cd ..; touch escape-attempt", &[]);
    assert_eq!(output.status.code(), Some(41));
    let value = json(&output);
    assert_eq!(value["policy"]["decision"], "ask");
    assert!(value["policy"]["findings"]
        .as_array()
        .is_some_and(|findings| findings
            .iter()
            .any(|finding| { finding["rule_id"] == "execution.outside_worktree_path" })));
    assert!(!escaped_file.exists());
}

#[test]
fn execution_errors_redact_secret_shaped_paths() {
    let root = TestRoot::new("error-redaction");
    let repo = init_repo(&root);
    let secret = ["abcdefgh", "ijklmno"].concat();
    let config = root.path.join(format!("api_key={secret}"));
    fs::write(&config, "not valid = [")
        .unwrap_or_else(|error| panic!("write invalid config: {error}"));
    let output = Command::new(binary())
        .current_dir(&repo)
        .arg("--config")
        .arg(&config)
        .args([
            "sandbox",
            "exec",
            "--id",
            "exec-one",
            "--command",
            "printf safe",
            "--json",
        ])
        .output()
        .unwrap_or_else(|error| panic!("run config error test: {error}"));
    assert_eq!(output.status.code(), Some(64));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&secret));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&secret));
}
