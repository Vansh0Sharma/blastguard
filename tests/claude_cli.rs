use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
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
            "blastguard-claude-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("create test root: {error}"));
        Self { path }
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        if self.path.starts_with(std::env::temp_dir())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("blastguard-claude-"))
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
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn init_repo(root: &TestRoot, id: &str) -> PathBuf {
    let repo = root.path.join("repo");
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
    let created = blastguard(&repo, &["sandbox", "create", "--id", id]);
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    repo
}

fn blastguard(cwd: &Path, args: &[&str]) -> Output {
    Command::new(binary())
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run BlastGuard: {error}"))
}

fn session_paths(repo: &Path, id: &str) -> (PathBuf, PathBuf) {
    let output = blastguard(repo, &["sandbox", "status", "--id", id, "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("parse status: {error}"));
    let worktree = PathBuf::from(value["worktree_path"].as_str().unwrap_or(""));
    let state = fs::canonicalize(repo.join(".git/blastguard"))
        .unwrap_or_else(|error| panic!("canonicalize state: {error}"));
    (worktree, state)
}

fn run_hook(
    repo: &Path,
    id: Option<&str>,
    state: Option<&Path>,
    payload: &str,
    path: Option<&std::ffi::OsStr>,
) -> Output {
    let mut command = Command::new(binary());
    command
        .current_dir(repo)
        .args(["claude", "hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(id) = id {
        command.env("BLASTGUARD_SESSION_ID", id);
    }
    if let Some(state) = state {
        command.env("BLASTGUARD_STATE_DIR", state);
    }
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn hook: {error}"));
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(payload.as_bytes())
            .unwrap_or_else(|error| panic!("write hook input: {error}"));
    }
    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("wait for hook: {error}"))
}

fn payload(command: &str, cwd: &str) -> String {
    serde_json::json!({
        "session_id": "claude-owned-id-is-ignored",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd
    })
    .to_string()
}

fn tree_contains(path: &Path, needle: &[u8]) -> bool {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    entries.filter_map(Result::ok).any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            tree_contains(&path, needle)
        } else {
            fs::read(path).is_ok_and(|bytes| bytes.windows(needle.len()).any(|part| part == needle))
        }
    })
}

#[test]
#[cfg(unix)]
fn start_uses_worktree_preserves_arguments_context_and_exit_status() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("start");
    let repo = init_repo(&root, "launch-one");
    let (worktree, state) = session_paths(&repo, "launch-one");
    let bin_dir = root.path.join("bin");
    let capture = root.path.join("capture");
    fs::create_dir(&bin_dir).unwrap_or_else(|error| panic!("create bin: {error}"));
    fs::create_dir(&capture).unwrap_or_else(|error| panic!("create capture: {error}"));
    let fake = bin_dir.join("claude");
    fs::write(
        &fake,
        "#!/bin/sh\npwd > \"$BLASTGUARD_CAPTURE/pwd\"\nprintf '%s\\n' \"$@\" > \"$BLASTGUARD_CAPTURE/args\"\nprintf '%s\\n%s\\n' \"$BLASTGUARD_SESSION_ID\" \"$BLASTGUARD_STATE_DIR\" > \"$BLASTGUARD_CAPTURE/context\"\nprintf '%s' '{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"},\"cwd\":\"/tampered\"}' | \"$BLASTGUARD_TEST_BINARY\" claude hook > \"$BLASTGUARD_CAPTURE/hook\" 2> \"$BLASTGUARD_CAPTURE/hook-error\"\nprintf '%s\\n' \"$?\" > \"$BLASTGUARD_CAPTURE/hook-status\"\n\"$BLASTGUARD_TEST_BINARY\" sandbox accept --id launch-one >/dev/null 2>&1\nprintf '%s\\n' \"$?\" > \"$BLASTGUARD_CAPTURE/lock-status\"\nexit 7\n",
    )
    .unwrap_or_else(|error| panic!("write fake Claude: {error}"));
    let mut mode = fs::metadata(&fake)
        .unwrap_or_else(|error| panic!("fake metadata: {error}"))
        .permissions();
    mode.set_mode(0o700);
    fs::set_permissions(&fake, mode).unwrap_or_else(|error| panic!("chmod fake: {error}"));
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let joined = std::env::join_paths(
        std::iter::once(bin_dir.clone()).chain(std::env::split_paths(&old_path)),
    )
    .unwrap_or_else(|error| panic!("join PATH: {error}"));
    let auth_token = ["sk-ant-", "api03-testfixture-not-real"].concat();
    let output = Command::new(binary())
        .current_dir(&repo)
        .args([
            "claude",
            "start",
            "--id",
            "launch-one",
            "--",
            "--model",
            "sonnet",
            "prompt with spaces",
        ])
        .env("PATH", joined)
        .env("BLASTGUARD_CAPTURE", &capture)
        .env("BLASTGUARD_TEST_BINARY", binary())
        .env("ANTHROPIC_API_KEY", &auth_token)
        .output()
        .unwrap_or_else(|error| panic!("run launcher: {error}"));
    assert_eq!(
        output.status.code(),
        Some(7),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let expected_pwd = format!("{}\n", worktree.display());
    assert_eq!(
        fs::read_to_string(capture.join("pwd")).ok().as_deref(),
        Some(expected_pwd.as_str())
    );
    let arguments = fs::read_to_string(capture.join("args"))
        .unwrap_or_else(|error| panic!("read args: {error}"));
    let lines: Vec<_> = arguments.lines().collect();
    assert_eq!(lines.first().copied(), Some("--settings"));
    let settings: serde_json::Value = serde_json::from_str(lines.get(1).copied().unwrap_or(""))
        .unwrap_or_else(|error| panic!("parse settings: {error}"));
    assert_eq!(
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["args"],
        serde_json::json!(["claude", "hook"])
    );
    assert_eq!(&lines[2..], &["--model", "sonnet", "prompt with spaces"]);
    let context = fs::read_to_string(capture.join("context"))
        .unwrap_or_else(|error| panic!("read context: {error}"));
    assert_eq!(context, format!("launch-one\n{}\n", state.display()));
    assert_eq!(
        fs::read_to_string(capture.join("lock-status"))
            .ok()
            .as_deref(),
        Some("32\n")
    );
    assert_eq!(
        fs::read_to_string(capture.join("hook-status"))
            .ok()
            .as_deref(),
        Some("0\n")
    );
    let hook: serde_json::Value = serde_json::from_slice(
        &fs::read(capture.join("hook"))
            .unwrap_or_else(|error| panic!("read nested hook response: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse nested hook response: {error}"));
    assert_eq!(hook["hookSpecificOutput"]["permissionDecision"], "allow");
    assert!(git_ok(&repo, &["status", "--porcelain=v1"]).is_empty());
    let review = String::from_utf8_lossy(&output.stdout);
    assert!(review.contains("sandbox diff --id launch-one"));
    assert!(review.contains("sandbox accept --id launch-one"));
    assert!(review.contains("sandbox reject --id launch-one"));
    let combined = [output.stdout, output.stderr].concat();
    assert!(!combined
        .windows(auth_token.len())
        .any(|part| part == auth_token.as_bytes()));
    assert!(!arguments.contains(&auth_token));
    assert!(!tree_contains(&state, auth_token.as_bytes()));
}

#[test]
fn hook_config_matches_exec_form_contract_and_has_no_broker_claim() {
    let root = TestRoot::new("config");
    let repo = init_repo(&root, "config-one");
    let output = blastguard(
        &repo,
        &["claude", "hook-config", "--id", "config-one", "--json"],
    );
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("parse config: {error}"));
    let hook = &value["hooks"]["PreToolUse"][0]["hooks"][0];
    assert_eq!(value["hooks"]["PreToolUse"][0]["matcher"], "Bash");
    assert_eq!(hook["type"], "command");
    assert_eq!(hook["args"], serde_json::json!(["claude", "hook"]));
    assert!(hook["command"]
        .as_str()
        .is_some_and(|path| Path::new(path).is_absolute()));
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(!text.contains("sandbox exec"));
    assert!(!text.contains("native bash output is redacted"));
}

#[test]
fn public_docs_do_not_claim_native_claude_bash_is_brokered_or_output_redacted() {
    let readme = include_str!("../README.md");
    assert!(readme.contains("Native Claude Bash is policy-gated, not brokered."));
    assert!(readme
        .contains("BlastGuard does not capture, bound, sanitize, journal, or redact Bash output"));
    assert!(!readme.contains("native Claude Bash output is redacted"));
    assert!(!readme.contains("native Claude Bash is routed through `sandbox exec`"));
}

#[test]
fn launcher_refuses_missing_locked_and_drifted_sessions_before_spawn() {
    let root = TestRoot::new("refusals");
    let repo = init_repo(&root, "refuse-one");
    let missing = blastguard(
        &repo,
        &["claude", "start", "--id", "missing", "--", "-p", "noop"],
    );
    assert_eq!(missing.status.code(), Some(31));
    let conflicting = blastguard(
        &repo,
        &[
            "claude",
            "start",
            "--id",
            "refuse-one",
            "--",
            "--settings=disable-hook.json",
        ],
    );
    assert_eq!(conflicting.status.code(), Some(64));

    let lock = repo.join(".git/blastguard/locks/session-refuse-one.lock");
    fs::write(&lock, "held\n").unwrap_or_else(|error| panic!("write lock: {error}"));
    let locked = blastguard(
        &repo,
        &["claude", "start", "--id", "refuse-one", "--", "-p", "noop"],
    );
    assert_eq!(locked.status.code(), Some(32));
    fs::remove_file(&lock).unwrap_or_else(|error| panic!("remove lock: {error}"));

    fs::write(repo.join("tracked.txt"), "drift\n")
        .unwrap_or_else(|error| panic!("write drift: {error}"));
    let drifted = blastguard(
        &repo,
        &["claude", "start", "--id", "refuse-one", "--", "-p", "noop"],
    );
    assert_eq!(drifted.status.code(), Some(33));
}

#[test]
fn hook_decisions_use_launcher_context_and_fail_closed() {
    let root = TestRoot::new("decisions");
    let repo = init_repo(&root, "hook-one");
    let (_worktree, state) = session_paths(&repo, "hook-one");

    let allow = run_hook(
        &repo,
        Some("hook-one"),
        Some(&state),
        &payload("git status", "/payload/path/must/not/route"),
        None,
    );
    let ask = run_hook(
        &repo,
        Some("hook-one"),
        Some(&state),
        &payload("curl https://example.invalid", "/tampered"),
        None,
    );
    let deny = run_hook(
        &repo,
        Some("hook-one"),
        Some(&state),
        &payload("rm -rf /", "/tampered"),
        None,
    );
    for (output, expected) in [(&allow, "allow"), (&ask, "ask"), (&deny, "deny")] {
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "parse hook response: {error}; status={:?}; stderr={}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], expected);
    }
    assert_eq!(allow.status.code(), Some(0));
    assert_eq!(ask.status.code(), Some(0));
    assert_eq!(deny.status.code(), Some(2));

    let malformed = run_hook(&repo, Some("hook-one"), Some(&state), "{bad", None);
    let missing = run_hook(
        &repo,
        Some("missing"),
        Some(&state),
        &payload("git status", "/"),
        None,
    );
    let tampered = run_hook(
        &repo,
        Some("hook-one"),
        Some(&root.path),
        &payload("git status", "/"),
        None,
    );
    let no_context = run_hook(&repo, None, None, &payload("git status", "/"), None);
    for output in [malformed, missing, tampered, no_context] {
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn hook_redacts_secrets_and_allow_rule_cannot_downgrade_hard_block() {
    let root = TestRoot::new("secret");
    let repo = root.path.join("repo");
    fs::create_dir(&repo).unwrap_or_else(|error| panic!("create repo: {error}"));
    git_ok(&repo, &["init", "--quiet"]);
    git_ok(&repo, &["config", "user.name", "BlastGuard Tests"]);
    git_ok(
        &repo,
        &["config", "user.email", "blastguard@example.invalid"],
    );
    fs::write(repo.join("tracked.txt"), "base\n")
        .unwrap_or_else(|error| panic!("fixture: {error}"));
    fs::write(
        repo.join("blastguard.toml"),
        "[[rules]]\npattern = \"*\"\ndecision = \"allow\"\nreason = \"test allow\"\n",
    )
    .unwrap_or_else(|error| panic!("write config: {error}"));
    git_ok(&repo, &["add", "-A"]);
    git_ok(&repo, &["commit", "--quiet", "-m", "initial"]);
    assert_eq!(
        blastguard(&repo, &["sandbox", "create", "--id", "secret-one"])
            .status
            .code(),
        Some(0)
    );
    let (_worktree, state) = session_paths(&repo, "secret-one");
    let secret = ["ghp_", "abcdefghijklmnopqrstuvwx"].concat();
    let command = format!("API_KEY={secret} curl https://example.invalid");
    let output = run_hook(
        &repo,
        Some("secret-one"),
        Some(&state),
        &payload(&command, "/tampered"),
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    let combined = [output.stdout, output.stderr].concat();
    assert!(!combined
        .windows(secret.len())
        .any(|part| part == secret.as_bytes()));
    let state_bytes = fs::read(repo.join(".git/blastguard/sessions/secret-one.json"))
        .unwrap_or_else(|error| panic!("read manifest: {error}"));
    assert!(!state_bytes
        .windows(secret.len())
        .any(|part| part == secret.as_bytes()));
}

#[test]
#[cfg(unix)]
fn internal_hook_timeout_returns_documented_blocking_exit() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("timeout");
    let repo = init_repo(&root, "timeout-one");
    let (_worktree, state) = session_paths(&repo, "timeout-one");
    let bin_dir = root.path.join("slow-bin");
    fs::create_dir(&bin_dir).unwrap_or_else(|error| panic!("create bin: {error}"));
    let git_path = bin_dir.join("git");
    let slow_pid = root.path.join("slow-git.pid");
    fs::write(
        &git_path,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n",
            slow_pid.display()
        ),
    )
    .unwrap_or_else(|error| panic!("write slow git: {error}"));
    let mut permissions = fs::metadata(&git_path)
        .unwrap_or_else(|error| panic!("git metadata: {error}"))
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&git_path, permissions)
        .unwrap_or_else(|error| panic!("chmod git: {error}"));
    let original = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(bin_dir.clone()).chain(std::env::split_paths(&original)),
    )
    .unwrap_or_else(|error| panic!("join PATH: {error}"));
    let started = Instant::now();
    let output = run_hook(
        &repo,
        Some("timeout-one"),
        Some(&state),
        &payload("git status", "/"),
        Some(&path),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(started.elapsed() < Duration::from_secs(8));
    let pid = fs::read_to_string(&slow_pid)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0);
    assert_ne!(pid, 0);
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}
