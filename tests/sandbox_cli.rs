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
            "blastguard-{label}-{}-{}",
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
                .is_some_and(|name| name.starts_with("blastguard-"))
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

fn init_repo(root: &TestRoot) -> PathBuf {
    let repo = root.repo();
    fs::create_dir(&repo).unwrap_or_else(|error| panic!("create repo: {error}"));
    git_ok(&repo, &["init", "--quiet"]);
    git_ok(&repo, &["config", "user.name", "BlastGuard Tests"]);
    git_ok(
        &repo,
        &["config", "user.email", "blastguard@example.invalid"],
    );
    fs::write(repo.join(".gitignore"), "ignored.log\n")
        .unwrap_or_else(|error| panic!("write ignore file: {error}"));
    fs::write(repo.join("tracked.txt"), "base\n")
        .unwrap_or_else(|error| panic!("write tracked file: {error}"));
    fs::write(repo.join("delete.txt"), "delete me\n")
        .unwrap_or_else(|error| panic!("write deletion fixture: {error}"));
    fs::write(repo.join("rename-old.txt"), "rename me\n")
        .unwrap_or_else(|error| panic!("write rename fixture: {error}"));
    fs::write(repo.join("mode.sh"), "#!/bin/sh\nexit 0\n")
        .unwrap_or_else(|error| panic!("write mode fixture: {error}"));
    git_ok(&repo, &["add", "-A"]);
    git_ok(&repo, &["commit", "--quiet", "-m", "initial"]);
    repo
}

fn blastguard(cwd: &Path, args: &[&str]) -> Output {
    Command::new(binary())
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run BlastGuard: {error}"))
}

fn create(cwd: &Path, id: &str) -> Output {
    if id.starts_with('-') {
        let argument = format!("--id={id}");
        blastguard(cwd, &["sandbox", "create", &argument])
    } else {
        blastguard(cwd, &["sandbox", "create", "--id", id])
    }
}

fn json_output(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("parse BlastGuard JSON: {error}"))
}

fn status_json(repo: &Path, id: &str) -> serde_json::Value {
    let output = blastguard(repo, &["sandbox", "status", "--id", id, "--json"]);
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    json_output(&output)
}

fn worktree(repo: &Path, id: &str) -> PathBuf {
    PathBuf::from(
        status_json(repo, id)["worktree_path"]
            .as_str()
            .unwrap_or_else(|| panic!("missing worktree path")),
    )
}

fn source_status(repo: &Path) -> Vec<u8> {
    git_ok(
        repo,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    )
}

#[test]
fn clean_repo_creates_manifest_worktree_and_list_entry() {
    let root = TestRoot::new("create");
    let repo = init_repo(&root);
    let initially_empty = blastguard(&repo, &["sandbox", "list", "--json"]);
    assert_eq!(initially_empty.status.code(), Some(0));
    assert_eq!(
        json_output(&initially_empty)["sessions"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    let created = create(&repo, "create-one");
    assert_eq!(created.status.code(), Some(0));
    let status = status_json(&repo, "create-one");
    assert_eq!(status["schema_version"], "blastguard.sandbox.status/1.0");
    assert_eq!(status["lifecycle_state"], "active");
    assert_eq!(status["worktree_exists"], true);
    assert_eq!(status["source_clean"], true);
    assert!(!Path::new(status["worktree_path"].as_str().unwrap_or("")).starts_with(&repo));
    assert!(repo
        .join(".git/blastguard/sessions/create-one.json")
        .is_file());
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(repo.join(".git/blastguard/sessions/create-one.json"))
            .unwrap_or_else(|error| panic!("read created manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse created manifest: {error}"));
    let mut manifest_keys: Vec<_> = manifest
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default();
    manifest_keys.sort_unstable();
    assert_eq!(
        manifest_keys,
        [
            "base_commit",
            "created_at_unix_seconds",
            "lifecycle_state",
            "schema_version",
            "session_id",
            "source_path",
            "worktree_path",
        ]
    );
    let managed_worktree = PathBuf::from(status["worktree_path"].as_str().unwrap_or(""));
    assert_eq!(
        String::from_utf8_lossy(&git_ok(
            &managed_worktree,
            &["symbolic-ref", "--short", "HEAD"]
        ))
        .trim(),
        "blastguard/create-one"
    );
    assert_eq!(
        blastguard(
            &managed_worktree,
            &["sandbox", "status", "--id", "create-one", "--json"]
        )
        .status
        .code(),
        Some(0)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let manifest_mode = fs::metadata(repo.join(".git/blastguard/sessions/create-one.json"))
            .unwrap_or_else(|error| panic!("manifest metadata: {error}"))
            .permissions()
            .mode();
        let worktree_mode = fs::metadata(worktree(&repo, "create-one").parent().unwrap_or(&repo))
            .unwrap_or_else(|error| panic!("worktree parent metadata: {error}"))
            .permissions()
            .mode();
        assert_eq!(manifest_mode & 0o077, 0);
        assert_eq!(worktree_mode & 0o077, 0);
    }

    let listed = blastguard(&repo, &["sandbox", "list", "--json"]);
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(
        json_output(&listed)["sessions"][0]["session_id"],
        "create-one"
    );
    let listed_by_path = blastguard(
        &root.path,
        &[
            "sandbox",
            "list",
            "--repo",
            fs::canonicalize(&repo)
                .unwrap_or_else(|error| panic!("canonical repo: {error}"))
                .to_str()
                .unwrap_or(""),
            "--json",
        ],
    );
    assert_eq!(
        listed_by_path.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&listed_by_path.stderr)
    );
    assert_eq!(
        json_output(&listed_by_path)["sessions"][0]["session_id"],
        "create-one"
    );
    assert_eq!(
        blastguard(&repo, &["sandbox", "reject", "--id", "create-one"])
            .status
            .code(),
        Some(0)
    );
    let empty_list = blastguard(&repo, &["sandbox", "list", "--json"]);
    assert_eq!(empty_list.status.code(), Some(0));
    assert_eq!(
        json_output(&empty_list)["sessions"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let generated = blastguard(&repo, &["sandbox", "create"]);
    assert_eq!(generated.status.code(), Some(0));
    let generated_list = json_output(&blastguard(&repo, &["sandbox", "list", "--json"]));
    let generated_id = generated_list["sessions"][0]["session_id"]
        .as_str()
        .unwrap_or("");
    assert!(generated_id.starts_with("bg-"));
    assert!(generated_id.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    }));
    assert_eq!(
        blastguard(&repo, &["sandbox", "reject", "--id", generated_id])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn repository_preconditions_reject_unsafe_sources() {
    type Preparation = Box<dyn Fn(&TestRoot, &Path)>;
    let cases: Vec<(&str, Preparation)> = vec![
        (
            "dirty",
            Box::new(|_, repo| {
                fs::write(repo.join("tracked.txt"), "dirty\n")
                    .unwrap_or_else(|error| panic!("dirty file: {error}"));
            }),
        ),
        (
            "untracked",
            Box::new(|_, repo| {
                fs::write(repo.join("new.txt"), "new\n")
                    .unwrap_or_else(|error| panic!("untracked file: {error}"));
            }),
        ),
        (
            "staged",
            Box::new(|_, repo| {
                fs::write(repo.join("staged.txt"), "staged\n")
                    .unwrap_or_else(|error| panic!("staged file: {error}"));
                git_ok(repo, &["add", "staged.txt"]);
            }),
        ),
        (
            "ignored",
            Box::new(|_, repo| {
                fs::write(repo.join("ignored.log"), "ignored\n")
                    .unwrap_or_else(|error| panic!("ignored file: {error}"));
            }),
        ),
        (
            "nested",
            Box::new(|_, repo| {
                let nested = repo.join("nested");
                fs::create_dir(&nested).unwrap_or_else(|error| panic!("nested directory: {error}"));
                git_ok(&nested, &["init", "--quiet"]);
            }),
        ),
        (
            "nested-bare",
            Box::new(|_, repo| {
                let nested = repo.join("nested-bare");
                fs::create_dir(&nested)
                    .unwrap_or_else(|error| panic!("nested bare directory: {error}"));
                git_ok(&nested, &["init", "--bare", "--quiet"]);
            }),
        ),
        (
            "sparse",
            Box::new(|_, repo| {
                git_ok(repo, &["config", "core.sparseCheckout", "true"]);
            }),
        ),
        (
            "gitlink",
            Box::new(|_, repo| {
                let head = String::from_utf8(git_ok(repo, &["rev-parse", "HEAD"]))
                    .unwrap_or_else(|error| panic!("decode HEAD: {error}"));
                git_ok(
                    repo,
                    &[
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        &format!("160000,{},vendor/sub", head.trim()),
                    ],
                );
                git_ok(repo, &["commit", "--quiet", "-m", "gitlink"]);
            }),
        ),
    ];

    for (label, prepare) in cases {
        let root = TestRoot::new(label);
        let repo = init_repo(&root);
        prepare(&root, &repo);
        let output = create(&repo, "must-fail");
        assert_eq!(output.status.code(), Some(30), "{label}");
    }

    let bare_root = TestRoot::new("bare");
    let bare = bare_root.repo();
    fs::create_dir(&bare).unwrap_or_else(|error| panic!("bare directory: {error}"));
    git_ok(&bare, &["init", "--bare", "--quiet"]);
    assert_eq!(create(&bare, "must-fail").status.code(), Some(30));

    let empty_root = TestRoot::new("no-head");
    let empty = empty_root.repo();
    fs::create_dir(&empty).unwrap_or_else(|error| panic!("empty repo: {error}"));
    git_ok(&empty, &["init", "--quiet"]);
    assert_eq!(create(&empty, "must-fail").status.code(), Some(30));
}

#[test]
fn managed_worktree_ids_and_symlink_sources_are_rejected() {
    let root = TestRoot::new("unsafe");
    let repo = init_repo(&root);
    for id in ["../escape", "UPPER", "-prefix", "contains.dot"] {
        assert_eq!(create(&repo, id).status.code(), Some(30), "{id}");
    }
    assert_eq!(create(&repo, "first").status.code(), Some(0));
    let managed = worktree(&repo, "first");
    assert_eq!(create(&managed, "second").status.code(), Some(30));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = root.path.join("repo-link");
        symlink(&repo, &link).unwrap_or_else(|error| panic!("source symlink: {error}"));
        let output = blastguard(
            &root.path,
            &[
                "sandbox",
                "create",
                "--repo",
                link.to_str().unwrap_or(""),
                "--id",
                "linked",
            ],
        );
        assert_eq!(output.status.code(), Some(30));

        let state_root = TestRoot::new("state-symlink");
        let state_repo = init_repo(&state_root);
        let outside = state_root.path.join("outside-state");
        fs::create_dir(&outside).unwrap_or_else(|error| panic!("outside state: {error}"));
        symlink(&outside, state_repo.join(".git/blastguard"))
            .unwrap_or_else(|error| panic!("state symlink: {error}"));
        assert_eq!(create(&state_repo, "unsafe-state").status.code(), Some(31));
        assert!(fs::read_dir(&outside)
            .unwrap_or_else(|error| panic!("read outside state: {error}"))
            .next()
            .is_none());
    }
}

#[test]
fn status_reports_source_drift_without_modifying_it() {
    let root = TestRoot::new("status-drift");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "drift").status.code(), Some(0));
    fs::write(repo.join("tracked.txt"), "source drift\n")
        .unwrap_or_else(|error| panic!("source drift: {error}"));
    let status = status_json(&repo, "drift");
    assert_eq!(status["source_head_matches_base"], true);
    assert_eq!(status["source_clean"], false);
    assert_eq!(
        blastguard(&repo, &["sandbox", "accept", "--id", "drift"])
            .status
            .code(),
        Some(33)
    );
    assert!(worktree(&repo, "drift").is_dir());
}

fn make_complete_change_set(worktree: &Path) {
    fs::write(worktree.join("tracked.txt"), "modified\n")
        .unwrap_or_else(|error| panic!("modify tracked: {error}"));
    fs::remove_file(worktree.join("delete.txt"))
        .unwrap_or_else(|error| panic!("delete tracked: {error}"));
    fs::rename(
        worktree.join("rename-old.txt"),
        worktree.join("rename-new.txt"),
    )
    .unwrap_or_else(|error| panic!("rename tracked: {error}"));
    fs::write(worktree.join("binary.bin"), [0_u8, 1, 2, 0, 255, 128])
        .unwrap_or_else(|error| panic!("write binary: {error}"));
    fs::write(worktree.join("untracked.txt"), "untracked\n")
        .unwrap_or_else(|error| panic!("write untracked: {error}"));
    fs::write(worktree.join("ignored.log"), "not accepted\n")
        .unwrap_or_else(|error| panic!("write ignored: {error}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(worktree.join("mode.sh"), fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|error| panic!("set executable mode: {error}"));
    }
}

#[test]
fn diff_includes_complete_non_ignored_snapshot() {
    let root = TestRoot::new("diff");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "diff-all").status.code(), Some(0));
    let worktree = worktree(&repo, "diff-all");
    make_complete_change_set(&worktree);
    let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz123456"].concat();
    fs::write(worktree.join("secret.txt"), format!("token={token}\n"))
        .unwrap_or_else(|error| panic!("write redaction fixture: {error}"));
    let output = blastguard(&repo, &["sandbox", "diff", "--id", "diff-all", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let patch = json_output(&output)["patch"]
        .as_str()
        .unwrap_or_else(|| panic!("missing patch"))
        .to_owned();
    for expected in [
        "tracked.txt",
        "delete.txt",
        "rename-old.txt",
        "rename-new.txt",
        "binary.bin",
        "untracked.txt",
        "GIT binary patch",
    ] {
        assert!(patch.contains(expected), "missing {expected}");
    }
    assert!(!patch.contains("ignored.log"));
    assert!(!patch.contains(&token));
    assert_eq!(json_output(&output)["redacted"], true);
    #[cfg(unix)]
    assert!(patch.contains("new mode 100755"));
}

#[test]
fn reject_removes_only_managed_resources_and_preserves_source() {
    let root = TestRoot::new("reject");
    let repo = init_repo(&root);
    let before_file = fs::read(repo.join("tracked.txt"))
        .unwrap_or_else(|error| panic!("read source before reject: {error}"));
    let before_status = source_status(&repo);
    git_ok(&repo, &["branch", "blastguard/keep"]);
    assert_eq!(create(&repo, "reject-me").status.code(), Some(0));
    let worktree = worktree(&repo, "reject-me");
    make_complete_change_set(&worktree);
    let output = blastguard(&repo, &["sandbox", "reject", "--id", "reject-me"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!worktree.exists());
    assert!(!repo
        .join(".git/blastguard/sessions/reject-me.json")
        .exists());
    assert_eq!(
        fs::read(repo.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read source after reject: {error}")),
        before_file
    );
    assert_eq!(source_status(&repo), before_status);
    assert!(git(
        &repo,
        &[
            "show-ref",
            "--verify",
            "--quiet",
            "refs/heads/blastguard/keep"
        ]
    )
    .status
    .success());
}

#[test]
fn accept_applies_binary_modes_renames_and_untracked_as_staged() {
    let root = TestRoot::new("accept");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "accept-all").status.code(), Some(0));
    let branch_before = git_ok(&repo, &["symbolic-ref", "HEAD"]);
    let head_before = git_ok(&repo, &["rev-parse", "HEAD"]);
    let worktree = worktree(&repo, "accept-all");
    make_complete_change_set(&worktree);
    let output = blastguard(&repo, &["sandbox", "accept", "--id", "accept-all"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!worktree.exists());
    assert_eq!(
        fs::read_to_string(repo.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read accepted text: {error}")),
        "modified\n"
    );
    assert!(!repo.join("delete.txt").exists());
    assert!(repo.join("rename-new.txt").is_file());
    assert!(!repo.join("rename-old.txt").exists());
    assert_eq!(
        fs::read(repo.join("binary.bin"))
            .unwrap_or_else(|error| panic!("read accepted binary: {error}")),
        [0_u8, 1, 2, 0, 255, 128]
    );
    assert!(repo.join("untracked.txt").is_file());
    assert!(!repo.join("ignored.log").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(repo.join("mode.sh"))
                .unwrap_or_else(|error| panic!("accepted mode metadata: {error}"))
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
    assert!(git_ok(&repo, &["diff", "--quiet"]).is_empty());
    let cached = git_ok(&repo, &["diff", "--cached", "--binary"]);
    let cached = String::from_utf8_lossy(&cached);
    assert!(cached.contains("tracked.txt"));
    assert!(cached.contains("GIT binary patch"));
    assert_eq!(git_ok(&repo, &["symbolic-ref", "HEAD"]), branch_before);
    assert_eq!(git_ok(&repo, &["rev-parse", "HEAD"]), head_before);
}

#[test]
fn accept_refuses_changed_head_and_preserves_sessions() {
    let root = TestRoot::new("head-drift");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "head-drift").status.code(), Some(0));
    let worktree = worktree(&repo, "head-drift");
    fs::write(repo.join("source-only.txt"), "new commit\n")
        .unwrap_or_else(|error| panic!("write source commit: {error}"));
    git_ok(&repo, &["add", "source-only.txt"]);
    git_ok(&repo, &["commit", "--quiet", "-m", "source moved"]);
    let status = status_json(&repo, "head-drift");
    assert_eq!(status["source_head_matches_base"], false);
    assert_eq!(status["source_clean"], true);
    let output = blastguard(&repo, &["sandbox", "accept", "--id", "head-drift"]);
    assert_eq!(output.status.code(), Some(33));
    assert!(worktree.is_dir());
    assert!(repo
        .join(".git/blastguard/sessions/head-drift.json")
        .is_file());
}

#[test]
fn patch_build_failure_keeps_source_and_session() {
    let root = TestRoot::new("apply-failure");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "failing").status.code(), Some(0));
    let worktree = worktree(&repo, "failing");
    fs::write(
        worktree.join(".gitattributes"),
        "*.fail filter=blastguard_fail\n",
    )
    .unwrap_or_else(|error| panic!("write attributes: {error}"));
    fs::write(worktree.join("payload.fail"), "content\n")
        .unwrap_or_else(|error| panic!("write filtered file: {error}"));
    let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz123456"].concat();
    git_ok(&repo, &["config", "filter.blastguard_fail.clean", &token]);
    git_ok(
        &repo,
        &["config", "filter.blastguard_fail.required", "true"],
    );
    let before = source_status(&repo);
    let output = blastguard(&repo, &["sandbox", "accept", "--id", "failing"]);
    assert_eq!(output.status.code(), Some(34));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&token));
    assert_eq!(source_status(&repo), before);
    assert!(worktree.is_dir());
    assert!(repo.join(".git/blastguard/sessions/failing.json").is_file());
}

#[test]
fn lifecycle_paths_are_redacted_in_human_and_json_output() {
    let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz123456"].concat();
    let root = TestRoot::new(&token);
    let repo = init_repo(&root);
    let created = create(&repo, "redacted-path");
    assert_eq!(created.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&created.stdout).contains(&token));
    let status = blastguard(
        &repo,
        &["sandbox", "status", "--id", "redacted-path", "--json"],
    );
    assert_eq!(status.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&status.stdout).contains(&token));
    assert_eq!(
        blastguard(&repo, &["sandbox", "reject", "--id", "redacted-path"])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn tampering_missing_worktrees_stale_states_and_locks_fail_safely() {
    let root = TestRoot::new("state-errors");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "tamper").status.code(), Some(0));
    let manifest_path = repo.join(".git/blastguard/sessions/tamper.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).unwrap_or_else(|error| panic!("read manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse manifest: {error}"));
    manifest["worktree_path"] = serde_json::Value::String(root.path.display().to_string());
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .unwrap_or_else(|error| panic!("serialize manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("tamper manifest: {error}"));
    assert_eq!(
        blastguard(&repo, &["sandbox", "reject", "--id", "tamper"])
            .status
            .code(),
        Some(31)
    );
    assert!(root.path.is_dir());

    let second_root = TestRoot::new("missing");
    let second_repo = init_repo(&second_root);
    assert_eq!(create(&second_repo, "missing").status.code(), Some(0));
    let missing_worktree = worktree(&second_repo, "missing");
    git_ok(
        &second_repo,
        &[
            "worktree",
            "remove",
            "--force",
            missing_worktree.to_str().unwrap_or(""),
        ],
    );
    let missing_status = status_json(&second_repo, "missing");
    assert_eq!(missing_status["worktree_exists"], false);
    assert_eq!(
        blastguard(&second_repo, &["sandbox", "accept", "--id", "missing"])
            .status
            .code(),
        Some(31)
    );

    let lock_path = second_repo.join(".git/blastguard/locks/session-missing.lock");
    fs::write(&lock_path, "pid=1\n").unwrap_or_else(|error| panic!("write lock: {error}"));
    assert_eq!(
        blastguard(&second_repo, &["sandbox", "status", "--id", "missing"])
            .status
            .code(),
        Some(32)
    );

    #[cfg(unix)]
    {
        let touched = Command::new("touch")
            .args(["-t", "200001010000", lock_path.to_str().unwrap_or("")])
            .output()
            .unwrap_or_else(|error| panic!("age lock: {error}"));
        assert!(touched.status.success());
        let stale = blastguard(&second_repo, &["sandbox", "status", "--id", "missing"]);
        assert_eq!(stale.status.code(), Some(32));
        assert!(String::from_utf8_lossy(&stale.stderr).contains("stale lock"));
    }

    let third_root = TestRoot::new("stale-state");
    let third_repo = init_repo(&third_root);
    assert_eq!(create(&third_repo, "stale").status.code(), Some(0));
    let stale_manifest = third_repo.join(".git/blastguard/sessions/stale.json");
    let mut value: serde_json::Value = serde_json::from_slice(
        &fs::read(&stale_manifest).unwrap_or_else(|error| panic!("read stale manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse stale manifest: {error}"));
    value["lifecycle_state"] = serde_json::Value::String("applying".to_owned());
    fs::write(
        &stale_manifest,
        serde_json::to_vec_pretty(&value)
            .unwrap_or_else(|error| panic!("serialize stale state: {error}")),
    )
    .unwrap_or_else(|error| panic!("write stale state: {error}"));
    assert_eq!(
        blastguard(&third_repo, &["sandbox", "reject", "--id", "stale"])
            .status
            .code(),
        Some(31)
    );

    let repository_lock = third_repo.join(".git/blastguard/locks/repository.lock");
    fs::write(&repository_lock, "pid=1\n")
        .unwrap_or_else(|error| panic!("write repository lock: {error}"));
    assert_eq!(
        blastguard(&third_repo, &["sandbox", "accept", "--id", "stale"])
            .status
            .code(),
        Some(32)
    );
}

#[cfg(unix)]
#[test]
fn cleanup_failure_retains_manifest_and_can_be_retried() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("cleanup-failure");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "cleanup").status.code(), Some(0));
    let worktree = worktree(&repo, "cleanup");
    let refs = repo.join(".git/refs/heads/blastguard");
    fs::set_permissions(&refs, fs::Permissions::from_mode(0o500))
        .unwrap_or_else(|error| panic!("restrict refs: {error}"));
    let output = blastguard(&repo, &["sandbox", "reject", "--id", "cleanup"]);
    fs::set_permissions(&refs, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("restore refs: {error}"));
    assert_eq!(output.status.code(), Some(34));
    assert!(!worktree.exists());
    assert!(repo.join(".git/blastguard/sessions/cleanup.json").is_file());
    assert_eq!(
        blastguard(&repo, &["sandbox", "reject", "--id", "cleanup"])
            .status
            .code(),
        Some(0)
    );
}

#[cfg(unix)]
#[test]
fn accept_cleanup_failure_records_applied_state_and_resumes_without_reapplying() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("accept-cleanup-failure");
    let repo = init_repo(&root);
    assert_eq!(create(&repo, "accept-cleanup").status.code(), Some(0));
    let worktree = worktree(&repo, "accept-cleanup");
    fs::write(worktree.join("tracked.txt"), "accepted once\n")
        .unwrap_or_else(|error| panic!("modify worktree: {error}"));
    let refs = repo.join(".git/refs/heads/blastguard");
    fs::set_permissions(&refs, fs::Permissions::from_mode(0o500))
        .unwrap_or_else(|error| panic!("restrict refs: {error}"));
    let first = blastguard(&repo, &["sandbox", "accept", "--id", "accept-cleanup"]);
    fs::set_permissions(&refs, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("restore refs: {error}"));
    assert_eq!(first.status.code(), Some(34));
    assert!(!worktree.exists());
    let manifest_path = repo.join(".git/blastguard/sessions/accept-cleanup.json");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).unwrap_or_else(|error| panic!("read applied manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse applied manifest: {error}"));
    assert_eq!(manifest["lifecycle_state"], "applied");
    let second = blastguard(&repo, &["sandbox", "accept", "--id", "accept-cleanup"]);
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(repo.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read accepted source: {error}")),
        "accepted once\n"
    );
    assert!(!manifest_path.exists());
}
