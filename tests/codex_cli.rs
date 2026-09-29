#![cfg(unix)]

use blastguard::codex_hook::{LAUNCH_ID_ENV, SESSION_ID_ENV, STATE_DIR_ENV};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::symlink,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const REQUEST: &str = include_str!("fixtures/codex/v1/pre-tool-use-bash.json");

struct Fixture {
    root: PathBuf,
    repo: PathBuf,
    state: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "blastguard-codex-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let repo = root.join("repo");
        fs::create_dir(&repo).unwrap();
        let state = repo.join(".git/blastguard");
        let fixture = Self { root, repo, state };
        fixture.git(&["init", "--quiet"]);
        fixture.git(&["config", "user.name", "BlastGuard Tests"]);
        fixture.git(&["config", "user.email", "blastguard@example.invalid"]);
        fs::write(fixture.repo.join("tracked.txt"), "base\n").unwrap();
        fixture.git(&["add", "-A"]);
        fixture.git(&["commit", "--quiet", "-m", "fixture"]);
        fixture
    }
    fn git(&self, args: &[&str]) {
        assert!(Command::new("git")
            .args([
                "-c",
                "maintenance.autoDetach=false",
                "-c",
                "gc.autoDetach=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C"
            ])
            .arg(&self.repo)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap()
            .status
            .success());
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_blastguard"));
        cmd.current_dir(&self.repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove(SESSION_ID_ENV)
            .env_remove(STATE_DIR_ENV)
            .env_remove(LAUNCH_ID_ENV);
        cmd
    }
    fn create(&self) {
        assert!(
            self.command()
                .args(["sandbox", "create", "--id", "fixture"])
                .output()
                .unwrap()
                .status
                .success(),
            "session fixture failed"
        );
    }
    fn hook(&self, context: bool) -> Command {
        let mut cmd = self.command();
        cmd.args(["codex", "hook"]);
        if context {
            cmd.env(SESSION_ID_ENV, "fixture")
                .env(STATE_DIR_ENV, &self.state)
                .env(LAUNCH_ID_ENV, "fabricated-launch");
        }
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.parent() == std::env::temp_dir().canonicalize().ok().as_deref()
            && self
                .root
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("blastguard-codex-cli-"))
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn invoke(mut cmd: Command, input: &[u8]) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    child.wait_with_output().unwrap()
}
fn denied(output: &Output) {
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "unverified adapter emitted a decision"
    );
    assert!(!output.stderr.is_empty());
    assert!(!output.stderr.contains(&0x1b));
}

#[test]
fn malformed_oversized_truncated_invalid_utf8_wrong_tool_and_missing_fields_deny() {
    let fixture = Fixture::new();
    for input in [
        b"".to_vec(),
        b"{".to_vec(),
        b"[]".to_vec(),
        vec![0xff],
        vec![b' '; blastguard::codex_hook::MAX_INPUT_BYTES + 1],
    ] {
        denied(&invoke(fixture.hook(false), &input));
    }
    for (field, value) in [
        ("hook_event_name", json!("PostToolUse")),
        ("tool_name", json!("shell")),
        ("tool_input", json!({})),
        ("tool_input", json!({"command": ["cargo", "test"]})),
    ] {
        let mut request: Value = serde_json::from_str(REQUEST).unwrap();
        request[field] = value;
        denied(&invoke(fixture.hook(false), request.to_string().as_bytes()));
    }
}

#[test]
fn payload_and_even_complete_environment_cannot_fabricate_launch_authorization() {
    let fixture = Fixture::new();
    fixture.create();
    let mut request: Value = serde_json::from_str(REQUEST).unwrap();
    request["session_id"] = json!("fixture");
    request["cwd"] = json!(fixture.repo);
    request["transcript_path"] = json!(fixture.state.join("sessions/fixture.json"));
    for missing in [
        Some(SESSION_ID_ENV),
        Some(STATE_DIR_ENV),
        Some(LAUNCH_ID_ENV),
        None,
    ] {
        let mut cmd = fixture.hook(true);
        if let Some(name) = missing {
            cmd.env_remove(name);
        }
        let output = invoke(cmd, request.to_string().as_bytes());
        denied(&output);
        if missing.is_none() {
            assert!(String::from_utf8_lossy(&output.stderr).contains("no trusted Codex launcher"));
        }
    }
    // An unrelated Claude binding must never authorize Codex.
    let mut cmd = fixture.hook(false);
    cmd.env("BLASTGUARD_SESSION_ID", "fixture")
        .env("BLASTGUARD_STATE_DIR", &fixture.state);
    denied(&invoke(cmd, REQUEST.as_bytes()));
}

#[test]
fn unbound_hook_rejects_before_git_or_session_lock_access() {
    let fixture = Fixture::new();
    fixture.create();
    let trace = fixture.root.join("git-before-binding.log");
    let locks = fixture.state.join("locks");
    let before = fs::metadata(&locks).unwrap().modified().unwrap();
    let mut cmd = fixture.hook(true);
    // A Git invocation would write this inherited trace destination. Neither
    // Git nor temporary session locks should be reached without authorization.
    cmd.env("GIT_TRACE", &trace);
    let output = invoke(cmd, REQUEST.as_bytes());
    denied(&output);
    assert!(
        !trace.exists(),
        "unbound hook invoked Git before authorization"
    );
    assert!(
        fs::metadata(&locks).unwrap().modified().unwrap() == before,
        "unbound hook changed session lock state"
    );
}

#[test]
fn stale_tampered_symlinked_inactive_drifted_and_locked_contexts_deny() {
    for kind in [
        "missing",
        "stale",
        "tampered",
        "symlink",
        "inactive",
        "drift",
        "session-lock",
        "repository-lock",
    ] {
        let fixture = Fixture::new();
        fixture.create();
        let mut cmd = fixture.hook(true);
        let manifest_path = fixture.state.join("sessions/fixture.json");
        match kind {
            "missing" => {
                cmd.env(STATE_DIR_ENV, fixture.root.join("missing"));
            }
            "stale" => {
                cmd.env(SESSION_ID_ENV, "absent-session");
            }
            "symlink" => {
                let alias = fixture.root.join("blastguard");
                symlink(&fixture.state, &alias).unwrap();
                cmd.env(STATE_DIR_ENV, alias);
            }
            "tampered" | "inactive" => {
                let mut manifest: Value =
                    serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
                if kind == "tampered" {
                    manifest["worktree_path"] = json!(fixture.repo);
                } else {
                    manifest["lifecycle_state"] = json!("applied");
                }
                fs::write(&manifest_path, manifest.to_string()).unwrap();
            }
            "drift" => fs::write(fixture.repo.join("tracked.txt"), "source drift\n").unwrap(),
            "session-lock" => {
                fs::write(fixture.state.join("locks/session-fixture.lock"), "fixture").unwrap()
            }
            "repository-lock" => {
                fs::write(fixture.state.join("locks/repository.lock"), "fixture").unwrap()
            }
            _ => unreachable!(),
        }
        let output = invoke(cmd, REQUEST.as_bytes());
        denied(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("no trusted Codex launcher"),
            "unbound context reached session validation: {kind}"
        );
    }
}

#[test]
fn secret_shaped_metadata_and_errors_never_leak_and_commands_never_execute() {
    let fixture = Fixture::new();
    fixture.create();
    let secret = ["ghp_", "abcdefghijklmnopqrstuvwxyz123456"].concat();
    let mut request: Value = serde_json::from_str(REQUEST).unwrap();
    for key in ["session_id", "cwd", "transcript_path", "model"] {
        request[key] = json!(format!("{secret}\u{1b}[31m"));
    }
    request["tool_input"]["command"] = json!(format!(
        "touch {}; printf {secret}",
        fixture.root.join("never-created").display()
    ));
    for malformed in [false, true] {
        let mut cmd = fixture.hook(true);
        cmd.env(STATE_DIR_ENV, fixture.root.join(&secret));
        let mut input = request.to_string();
        if malformed {
            input.pop();
        }
        let output = invoke(cmd, input.as_bytes());
        denied(&output);
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|part| part == secret.as_bytes()),
                "secret fixture leaked"
            );
        }
    }
    assert!(!fixture.root.join("never-created").exists());
}

#[test]
fn open_stdin_is_bounded_by_the_hook_internal_deadline() {
    let fixture = Fixture::new();
    let mut child = fixture
        .hook(false)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _open_pipe = child.stdin.take();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(12) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("hook failed to enforce input deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    denied(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("deadline"));
}

#[test]
fn no_launcher_config_or_plugin_command_is_exposed() {
    let fixture = Fixture::new();
    for name in ["start", "hook-config", "install"] {
        assert_eq!(
            fixture
                .command()
                .args(["codex", name])
                .output()
                .unwrap()
                .status
                .code(),
            Some(64)
        );
    }
    let output = fixture
        .command()
        .args(["codex", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("doctor"));
    assert!(!help.contains("hook-config"));
}
