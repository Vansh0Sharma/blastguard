use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    git::{self, Git},
    manifest::{self, LifecycleState, SessionManifest, MANIFEST_SCHEMA_VERSION},
    redaction,
    sandbox_error::SandboxError,
    session_lock::SessionLock,
};

const CREATE_SCHEMA: &str = "blastguard.sandbox.create/1.0";
const STATUS_SCHEMA: &str = "blastguard.sandbox.status/1.0";
const DIFF_SCHEMA: &str = "blastguard.sandbox.diff/1.0";
const LIST_SCHEMA: &str = "blastguard.sandbox.list/1.0";
const ACCEPT_SCHEMA: &str = "blastguard.sandbox.accept/1.0";
const REJECT_SCHEMA: &str = "blastguard.sandbox.reject/1.0";

#[derive(Serialize)]
pub struct CreateResult {
    pub schema_version: &'static str,
    pub session_id: String,
    pub source_path: String,
    pub worktree_path: String,
    pub base_commit: String,
    pub rollback_scope: String,
}

#[derive(Clone, Default, Serialize)]
pub struct GitState {
    pub clean: bool,
    pub staged: usize,
    pub unstaged: usize,
    pub untracked: usize,
    pub conflicted: usize,
}

#[derive(Serialize)]
pub struct StatusResult {
    pub schema_version: &'static str,
    pub session_id: String,
    pub lifecycle_state: String,
    pub source_path: String,
    pub worktree_path: String,
    pub base_commit: String,
    pub worktree_exists: bool,
    pub source_head_matches_base: bool,
    pub source_clean: bool,
    pub worktree_git_state: Option<GitState>,
}

#[derive(Serialize)]
pub struct DiffResult {
    pub schema_version: &'static str,
    pub session_id: String,
    pub base_commit: String,
    pub patch: String,
    pub redacted: bool,
}

#[derive(Serialize)]
pub struct ListResult {
    pub schema_version: &'static str,
    pub source_path: String,
    pub sessions: Vec<ListEntry>,
}

#[derive(Serialize)]
pub struct ListEntry {
    pub session_id: String,
    pub lifecycle_state: String,
    pub worktree_path: String,
    pub base_commit: String,
    pub created_at_unix_seconds: u64,
    pub worktree_exists: bool,
}

#[derive(Serialize)]
pub struct AcceptResult {
    pub schema_version: &'static str,
    pub session_id: String,
    pub source_path: String,
    pub staged_changes: usize,
    pub cleanup_complete: bool,
    pub rollback_scope: String,
}

#[derive(Serialize)]
pub struct RejectResult {
    pub schema_version: &'static str,
    pub session_id: String,
    pub source_path: String,
    pub source_untouched: bool,
}

struct Repository {
    source: PathBuf,
    common_dir: PathBuf,
    base_commit: String,
}

struct StatePaths {
    root: PathBuf,
    sessions: PathBuf,
    locks: PathBuf,
    temp: PathBuf,
    journal: PathBuf,
}

struct LoadedSession {
    manifest_path: PathBuf,
    manifest: SessionManifest,
    source: PathBuf,
    worktree: PathBuf,
    state: StatePaths,
}

/// A validated active session whose per-session lock remains held for the
/// lifetime of a command execution.
pub struct ExecutionLease {
    session_id: String,
    source: PathBuf,
    worktree: PathBuf,
    base_commit: String,
    journal_dir: PathBuf,
    state_root: PathBuf,
    git_state: GitState,
    _lock: SessionLock,
    _repository_lock: SessionLock,
    _claude_launch_lock: Option<SessionLock>,
}

impl ExecutionLease {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    pub fn worktree(&self) -> &Path {
        &self.worktree
    }

    pub fn base_commit(&self) -> &str {
        &self.base_commit
    }

    pub fn journal_dir(&self) -> &Path {
        &self.journal_dir
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub fn git_state(&self) -> &GitState {
        &self.git_state
    }
}

/// Locate, lock, and revalidate an active managed worktree before execution.
pub fn lock_for_execution(id: &str) -> Result<ExecutionLease, SandboxError> {
    validate_id(id)?;
    let common = context_common_dir()?;
    let state = state_paths(&common, false)?;
    let claude_launch_lock = SessionLock::acquire_claude_launch(&state.locks, id)?;
    let mut lease = lock_active_session(&common, state, id)?;
    lease._claude_launch_lock = Some(claude_launch_lock);
    Ok(lease)
}

/// Lock and validate a session for a Claude launch. The returned launch lock
/// remains held while Claude runs; hook evaluations intentionally do not take it.
pub fn lock_for_claude_start(id: &str) -> Result<(ExecutionLease, SessionLock), SandboxError> {
    validate_id(id)?;
    let common = context_common_dir()?;
    let state = state_paths(&common, false)?;
    let claude_launch_lock = SessionLock::acquire_claude_launch(&state.locks, id)?;
    let lease = lock_active_session(&common, state, id)?;
    Ok((lease, claude_launch_lock))
}

/// Revalidate a hook session using only the launcher-provided state root.
/// The hook payload's cwd is deliberately not used to locate the session.
pub fn lock_for_hook(id: &str, provided_state_root: &Path) -> Result<ExecutionLease, SandboxError> {
    validate_id(id)?;
    let root = canonical_without_symlink(provided_state_root, "launcher state directory")?;
    if root.file_name().and_then(OsStr::to_str) != Some("blastguard") {
        return Err(SandboxError::manifest(
            "launcher state directory is not a BlastGuard state root",
        ));
    }
    let common = root
        .parent()
        .ok_or_else(|| SandboxError::manifest("launcher state directory has no parent"))?
        .to_path_buf();
    let state = state_paths(&common, false)?;
    if canonical_without_symlink(&state.root, "managed state directory")? != root {
        return Err(SandboxError::manifest(
            "launcher state directory does not match managed session state",
        ));
    }
    lock_active_session(&common, state, id)
}

fn lock_active_session(
    common: &Path,
    state: StatePaths,
    id: &str,
) -> Result<ExecutionLease, SandboxError> {
    let lock = SessionLock::acquire_session(&state.locks, id)?;
    let repository_lock = SessionLock::acquire_repository(&state.locks)?;
    let loaded = load_session(common, &state, id, false)?;
    require_active(&loaded.manifest, "execute a command in")?;
    verify_source_unchanged(&loaded)?;
    validate_execution_worktree(&loaded, common)?;
    ensure_secure_directory(&state.journal)?;
    let git_state = git_state(&Git::new(&loaded.worktree))?;
    Ok(ExecutionLease {
        session_id: loaded.manifest.session_id,
        source: loaded.source,
        worktree: loaded.worktree,
        base_commit: loaded.manifest.base_commit,
        journal_dir: state.journal,
        state_root: state.root,
        git_state,
        _lock: lock,
        _repository_lock: repository_lock,
        _claude_launch_lock: None,
    })
}

pub fn create(
    repo: Option<&Path>,
    requested_id: Option<&str>,
) -> Result<CreateResult, SandboxError> {
    let repository = discover_source(repo, true)?;
    verify_create_preconditions(&repository)?;
    let id = match requested_id {
        Some(id) => {
            validate_id(id)?;
            id.to_owned()
        }
        None => generate_id()?,
    };
    let state = state_paths(&repository.common_dir, true)?;
    let _session_lock = SessionLock::acquire_session(&state.locks, &id)?;
    let _repository_lock = SessionLock::acquire_repository(&state.locks)?;
    verify_create_preconditions(&repository)?;
    if head_commit(&Git::new(&repository.source))? != repository.base_commit {
        return Err(SandboxError::repository(
            "HEAD changed while the sandbox was being created; retry from a stable source",
        ));
    }
    let manifest_path = manifest::manifest_path(&state.sessions, &id);
    if manifest_path.exists() {
        return Err(SandboxError::SessionExists(clean(&id)));
    }

    let worktree_parent = worktree_parent(&repository.source)?;
    let worktree_root = worktree_parent
        .parent()
        .ok_or_else(|| SandboxError::manifest("controlled worktree path has no parent"))?;
    ensure_secure_directory(worktree_root)?;
    ensure_secure_directory(&worktree_parent)?;
    let worktree = worktree_parent.join(&id);
    if fs::symlink_metadata(&worktree).is_ok() {
        return Err(SandboxError::SessionExists(clean(&id)));
    }
    let branch = branch_name(&id);
    let reference = format!("refs/heads/{branch}");
    let source_git = Git::new(&repository.source);
    let branch_check = source_git.output(&["show-ref", "--verify", "--quiet", &reference])?;
    if branch_check.status.success() {
        return Err(SandboxError::SessionExists(clean(&id)));
    } else if branch_check.status.code() != Some(1) {
        return Err(SandboxError::operation(
            "checking for an existing managed branch",
            String::from_utf8_lossy(&branch_check.stderr),
        ));
    }

    let args = vec![
        OsString::from("worktree"),
        OsString::from("add"),
        OsString::from("-b"),
        OsString::from(&branch),
        git::path_argument(&worktree),
        OsString::from(&repository.base_commit),
    ];
    if let Err(error) = source_git.checked_os("creating the linked worktree", &args) {
        cleanup_failed_create(&source_git, &worktree, &branch);
        return Err(error);
    }
    let finalized = (|| {
        validate_created_worktree(&worktree)?;
        owner_only_directory(&worktree)?;
        let source_text = path_text(&repository.source, "source repository")?;
        let worktree_text = path_text(&worktree, "sandbox worktree")?;
        let session_manifest = SessionManifest::new(
            id.clone(),
            source_text.clone(),
            worktree_text.clone(),
            repository.base_commit.clone(),
        )?;
        manifest::write_atomic(&manifest_path, &session_manifest)?;
        Ok(CreateResult {
            schema_version: CREATE_SCHEMA,
            session_id: id.clone(),
            source_path: source_text,
            worktree_path: worktree_text,
            base_commit: repository.base_commit.clone(),
            rollback_scope: rollback_scope(),
        })
    })();
    if finalized.is_err() {
        cleanup_failed_create(&source_git, &worktree, &branch);
    }
    finalized
}

pub fn status(id: &str) -> Result<StatusResult, SandboxError> {
    validate_id(id)?;
    let common = context_common_dir()?;
    let state = state_paths(&common, false)?;
    let _lock = SessionLock::acquire_session(&state.locks, id)?;
    let loaded = load_session(&common, &state, id, true)?;
    let source_git = Git::new(&loaded.source);
    let head = head_commit(&source_git)?;
    let source_clean = source_is_clean(&source_git)?;
    let exists = loaded.worktree.exists();
    let worktree_git_state = if exists {
        Some(git_state(&Git::new(&loaded.worktree))?)
    } else {
        None
    };
    Ok(StatusResult {
        schema_version: STATUS_SCHEMA,
        session_id: loaded.manifest.session_id,
        lifecycle_state: loaded.manifest.lifecycle_state.as_str().to_owned(),
        source_path: path_text(&loaded.source, "source repository")?,
        worktree_path: path_text(&loaded.worktree, "sandbox worktree")?,
        base_commit: loaded.manifest.base_commit.clone(),
        worktree_exists: exists,
        source_head_matches_base: head == loaded.manifest.base_commit,
        source_clean,
        worktree_git_state,
    })
}

pub fn diff(id: &str) -> Result<DiffResult, SandboxError> {
    validate_id(id)?;
    let common = context_common_dir()?;
    let state = state_paths(&common, false)?;
    let _lock = SessionLock::acquire_session(&state.locks, id)?;
    let loaded = load_session(&common, &state, id, false)?;
    require_active(&loaded.manifest, "diff")?;
    let patch = build_patch(&loaded)?;
    let patch_text = String::from_utf8(patch).map_err(|_| {
        SandboxError::operation(
            "rendering the sandbox diff",
            "Git returned a non-UTF-8 patch",
        )
    })?;
    let redacted = redaction::redact(&patch_text);
    Ok(DiffResult {
        schema_version: DIFF_SCHEMA,
        session_id: loaded.manifest.session_id,
        base_commit: loaded.manifest.base_commit,
        patch: redacted.text,
        redacted: !redacted.matches.is_empty(),
    })
}

pub fn list(repo: Option<&Path>) -> Result<ListResult, SandboxError> {
    let repository = discover_source(repo, false)?;
    match fs::symlink_metadata(repository.common_dir.join("blastguard")) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ListResult {
                schema_version: LIST_SCHEMA,
                source_path: path_text(&repository.source, "source repository")?,
                sessions: Vec::new(),
            });
        }
        Err(error) => {
            return Err(SandboxError::operation(
                "inspecting sandbox state",
                error.to_string(),
            ));
        }
    }
    let state = state_paths(&repository.common_dir, false)?;
    let mut sessions = Vec::new();
    let entries = fs::read_dir(&state.sessions)
        .map_err(|error| SandboxError::operation("listing sandbox manifests", error.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            SandboxError::operation("reading a manifest directory entry", error.to_string())
        })?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(OsStr::to_str)
            .ok_or_else(|| SandboxError::manifest("a manifest filename is not valid UTF-8"))?;
        validate_id(id)?;
        let loaded = load_session(&repository.common_dir, &state, id, true)?;
        sessions.push(ListEntry {
            session_id: loaded.manifest.session_id,
            lifecycle_state: loaded.manifest.lifecycle_state.as_str().to_owned(),
            worktree_path: path_text(&loaded.worktree, "sandbox worktree")?,
            base_commit: loaded.manifest.base_commit,
            created_at_unix_seconds: loaded.manifest.created_at_unix_seconds,
            worktree_exists: loaded.worktree.exists(),
        });
    }
    sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    Ok(ListResult {
        schema_version: LIST_SCHEMA,
        source_path: path_text(&repository.source, "source repository")?,
        sessions,
    })
}

pub fn accept(id: &str) -> Result<AcceptResult, SandboxError> {
    validate_id(id)?;
    let common = context_common_dir()?;
    let state = state_paths(&common, false)?;
    let _claude_launch_lock = SessionLock::acquire_claude_launch(&state.locks, id)?;
    let _session_lock = SessionLock::acquire_session(&state.locks, id)?;
    let _repository_lock = SessionLock::acquire_repository(&state.locks)?;
    let mut loaded = load_session(&common, &state, id, true)?;

    if loaded.manifest.lifecycle_state == LifecycleState::Applied {
        cleanup_completed_session(&loaded)?;
        return Ok(AcceptResult {
            schema_version: ACCEPT_SCHEMA,
            session_id: id.to_owned(),
            source_path: path_text(&loaded.source, "source repository")?,
            staged_changes: git_state(&Git::new(&loaded.source))?.staged,
            cleanup_complete: true,
            rollback_scope: rollback_scope(),
        });
    }
    require_active(&loaded.manifest, "accept")?;
    if !path_exists_without_following(&loaded.worktree)? {
        return Err(SandboxError::manifest(
            "managed worktree is missing; acceptance was not attempted",
        ));
    }
    verify_source_unchanged(&loaded)?;
    let patch = build_patch(&loaded)?;
    verify_source_unchanged(&loaded)?;

    loaded.manifest.lifecycle_state = LifecycleState::Applying;
    manifest::write_atomic(&loaded.manifest_path, &loaded.manifest)?;
    let source_git = Git::new(&loaded.source);
    if !patch.is_empty() {
        if let Err(error) = source_git.checked_input(
            "checking the patch against the source repository",
            &[
                "apply",
                "--check",
                "--binary",
                "--index",
                "--whitespace=nowarn",
                "-",
            ],
            &patch,
        ) {
            loaded.manifest.lifecycle_state = LifecycleState::Active;
            manifest::write_atomic(&loaded.manifest_path, &loaded.manifest)?;
            return Err(SandboxError::operation(
                "checking the patch against the source repository",
                format!(
                    "{error}; the source was not modified and the session was retained for inspection"
                ),
            ));
        }
        if let Err(error) = verify_source_unchanged(&loaded) {
            loaded.manifest.lifecycle_state = LifecycleState::Active;
            manifest::write_atomic(&loaded.manifest_path, &loaded.manifest)?;
            return Err(error);
        }
        if let Err(error) = source_git.checked_input(
            "applying the patch to the source repository",
            &["apply", "--binary", "--index", "--whitespace=nowarn", "-"],
            &patch,
        ) {
            let source_unchanged = source_is_clean(&source_git)?
                && head_commit(&source_git)? == loaded.manifest.base_commit;
            if source_unchanged {
                loaded.manifest.lifecycle_state = LifecycleState::Active;
                manifest::write_atomic(&loaded.manifest_path, &loaded.manifest)?;
                return Err(SandboxError::operation(
                    "applying the patch to the source repository",
                    format!(
                        "{error}; Git left the source clean and the session was retained for retry"
                    ),
                ));
            }
            return Err(SandboxError::cleanup(
                format!(
                    "Git reported an apply failure and the source no longer appears unchanged: {error}"
                ),
                "do not retry automatically; inspect `git status`, the staged diff, and the retained session manifest",
            ));
        }
    }

    if let Err(error) = verify_applied_snapshot(&source_git, &loaded.manifest.base_commit, &patch) {
        return Err(SandboxError::cleanup(
            format!("Git returned success, but the source no longer matches the accepted patch: {error}"),
            "do not retry automatically; inspect `git status`, the staged diff, and the retained session manifest",
        ));
    }

    loaded.manifest.lifecycle_state = LifecycleState::Applied;
    manifest::write_atomic(&loaded.manifest_path, &loaded.manifest).map_err(|error| {
        SandboxError::cleanup(
            format!("the patch was staged, but the applied state could not be recorded: {error}"),
            "inspect the source index and session manifest before any retry",
        )
    })?;
    let staged = git_state(&source_git)?.staged;
    cleanup_completed_session(&loaded)?;
    Ok(AcceptResult {
        schema_version: ACCEPT_SCHEMA,
        session_id: id.to_owned(),
        source_path: path_text(&loaded.source, "source repository")?,
        staged_changes: staged,
        cleanup_complete: true,
        rollback_scope: rollback_scope(),
    })
}

pub fn reject(id: &str) -> Result<RejectResult, SandboxError> {
    validate_id(id)?;
    let common = context_common_dir()?;
    let state = state_paths(&common, false)?;
    let _claude_launch_lock = SessionLock::acquire_claude_launch(&state.locks, id)?;
    let _session_lock = SessionLock::acquire_session(&state.locks, id)?;
    let _repository_lock = SessionLock::acquire_repository(&state.locks)?;
    let mut loaded = load_session(&common, &state, id, true)?;
    match loaded.manifest.lifecycle_state {
        LifecycleState::Active => {
            if !loaded.worktree.exists() {
                return Err(SandboxError::manifest(
                    "the active session worktree is missing; no automatic deletion was attempted",
                ));
            }
            loaded.manifest.lifecycle_state = LifecycleState::Rejecting;
            manifest::write_atomic(&loaded.manifest_path, &loaded.manifest)?;
        }
        LifecycleState::Rejecting => {}
        LifecycleState::Applying | LifecycleState::Applied => {
            return Err(SandboxError::manifest(
                "the session may already have affected the source repository; inspect it before cleanup",
            ));
        }
    }
    cleanup_completed_session(&loaded)?;
    Ok(RejectResult {
        schema_version: REJECT_SCHEMA,
        session_id: id.to_owned(),
        source_path: path_text(&loaded.source, "source repository")?,
        source_untouched: true,
    })
}

fn discover_source(repo: Option<&Path>, require_head: bool) -> Result<Repository, SandboxError> {
    let input = match repo {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().map_err(|error| {
            SandboxError::operation("reading the current directory", error.to_string())
        })?,
    };
    let candidate = canonical_without_symlink(&input, "repository path")?;
    if !candidate.is_dir() {
        return Err(SandboxError::repository(
            "the repository path is not a directory",
        ));
    }
    let candidate_git = Git::new(&candidate);
    let bare = git::text(
        "checking whether the repository is bare",
        candidate_git.checked(
            "checking whether the repository is bare",
            &["rev-parse", "--is-bare-repository"],
        )?,
    )?;
    if bare == "true" {
        return Err(SandboxError::repository(
            "bare repositories are not supported",
        ));
    }
    let top = git::text(
        "resolving the repository root",
        candidate_git.checked(
            "resolving the repository root",
            &["rev-parse", "--show-toplevel"],
        )?,
    )?;
    let source = canonical_without_symlink(Path::new(&top), "repository root")?;
    let source_git = Git::new(&source);
    let git_dir_text = git::text(
        "resolving the Git directory",
        source_git.checked("resolving the Git directory", &["rev-parse", "--git-dir"])?,
    )?;
    let common_text = git::text(
        "resolving the Git common directory",
        source_git.checked(
            "resolving the Git common directory",
            &["rev-parse", "--git-common-dir"],
        )?,
    )?;
    let git_dir = canonical_git_path(&source, &git_dir_text, "Git directory")?;
    let common_dir = canonical_git_path(&source, &common_text, "Git common directory")?;
    if git_dir != common_dir || source.join(".git").is_file() {
        return Err(SandboxError::repository(
            "linked worktrees, submodule worktrees, and separate Git directories are not supported as sources",
        ));
    }
    let base_commit = if require_head {
        head_commit(&source_git).map_err(|_| {
            SandboxError::repository(
                "HEAD does not resolve to a commit; create an initial commit first",
            )
        })?
    } else {
        head_commit(&source_git).unwrap_or_default()
    };
    Ok(Repository {
        source,
        common_dir,
        base_commit,
    })
}

fn verify_create_preconditions(repository: &Repository) -> Result<(), SandboxError> {
    let git = Git::new(&repository.source);
    if has_gitlink(&git)? || repository.source.join(".gitmodules").exists() {
        return Err(SandboxError::repository("submodules are not supported"));
    }
    if contains_nested_repository(&repository.source)? {
        return Err(SandboxError::repository(
            "a nested Git repository was found; nested repositories are not supported",
        ));
    }
    if git_config_true(&git, "core.sparseCheckout")? || git_config_true(&git, "index.sparse")? {
        return Err(SandboxError::repository(
            "sparse checkouts are not supported",
        ));
    }
    if !source_is_clean(&git)? {
        return Err(SandboxError::repository(
            "the source must have no staged, unstaged, untracked, or ignored files",
        ));
    }
    Ok(())
}

fn source_is_clean(git: &Git) -> Result<bool, SandboxError> {
    let output = git.checked(
        "checking source repository cleanliness",
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    )?;
    Ok(output.is_empty())
}

fn git_state(git: &Git) -> Result<GitState, SandboxError> {
    let output = git.checked(
        "reading worktree status",
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=no",
        ],
    )?;
    let mut state = GitState::default();
    let mut entries = output
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty());
    while let Some(entry) = entries.next() {
        if entry.len() < 3 {
            return Err(SandboxError::operation(
                "parsing Git status",
                "Git returned a truncated status entry",
            ));
        }
        let x = entry[0];
        let y = entry[1];
        if x == b'?' && y == b'?' {
            state.untracked += 1;
        } else {
            if x != b' ' {
                state.staged += 1;
            }
            if y != b' ' {
                state.unstaged += 1;
            }
            if matches!(
                (x, y),
                (b'D', b'D')
                    | (b'A', b'U')
                    | (b'U', b'D')
                    | (b'U', b'A')
                    | (b'D', b'U')
                    | (b'A', b'A')
                    | (b'U', b'U')
            ) {
                state.conflicted += 1;
            }
            if matches!(x, b'R' | b'C') || matches!(y, b'R' | b'C') {
                let _ = entries.next().ok_or_else(|| {
                    SandboxError::operation(
                        "parsing Git status",
                        "Git omitted a rename source path",
                    )
                })?;
            }
        }
    }
    state.clean =
        state.staged == 0 && state.unstaged == 0 && state.untracked == 0 && state.conflicted == 0;
    Ok(state)
}

fn build_patch(session: &LoadedSession) -> Result<Vec<u8>, SandboxError> {
    validate_worktree(&session.worktree)?;
    ensure_secure_directory(&session.state.temp)?;
    let index_path = session.state.temp.join(format!(
        "{}-{}-{}.index",
        session.manifest.session_id,
        std::process::id(),
        next_nonce()
    ));
    if fs::symlink_metadata(&index_path).is_ok() {
        return Err(SandboxError::operation(
            "creating the temporary index",
            "temporary path already exists",
        ));
    }
    let result = (|| {
        let git = Git::new(&session.worktree);
        let env = [("GIT_INDEX_FILE", index_path.as_os_str())];
        git.checked_with_env(
            "initializing the temporary index",
            &["read-tree", &session.manifest.base_commit],
            &env,
        )?;
        git.checked_with_env("capturing sandbox changes", &["add", "-A", "--", "."], &env)?;
        git.checked_with_env(
            "building the sandbox patch",
            &[
                "diff",
                "--cached",
                "--binary",
                "--full-index",
                "--find-renames",
                "--no-ext-diff",
                &session.manifest.base_commit,
                "--",
            ],
            &env,
        )
    })();
    let _ = fs::remove_file(&index_path);
    result
}

fn verify_source_unchanged(session: &LoadedSession) -> Result<(), SandboxError> {
    let git = Git::new(&session.source);
    let head = head_commit(&git)?;
    if head != session.manifest.base_commit {
        return Err(SandboxError::SourceChanged(
            "HEAD no longer matches the recorded base commit; no merge or rebase was attempted"
                .to_owned(),
        ));
    }
    if !source_is_clean(&git)? {
        return Err(SandboxError::SourceChanged(
            "the source has staged, unstaged, untracked, or ignored changes; clean it before accepting".to_owned(),
        ));
    }
    Ok(())
}

fn verify_applied_snapshot(
    git: &Git,
    base: &str,
    expected_patch: &[u8],
) -> Result<(), SandboxError> {
    if head_commit(git)? != base {
        return Err(SandboxError::SourceChanged(
            "HEAD changed while the accepted patch was being verified".to_owned(),
        ));
    }
    let state = git_state(git)?;
    if state.unstaged != 0 || state.untracked != 0 || state.conflicted != 0 {
        return Err(SandboxError::SourceChanged(
            "the source gained unstaged, untracked, or conflicted changes during acceptance"
                .to_owned(),
        ));
    }
    let actual_patch = git.checked(
        "verifying the staged source patch",
        &[
            "diff",
            "--cached",
            "--binary",
            "--full-index",
            "--find-renames",
            "--no-ext-diff",
            base,
            "--",
        ],
    )?;
    if actual_patch != expected_patch {
        return Err(SandboxError::SourceChanged(
            "the staged source patch differs from the captured sandbox patch".to_owned(),
        ));
    }
    Ok(())
}

fn cleanup_completed_session(session: &LoadedSession) -> Result<(), SandboxError> {
    let git = Git::new(&session.source);
    if session.worktree.exists() {
        let args = vec![
            OsString::from("worktree"),
            OsString::from("remove"),
            OsString::from("--force"),
            git::path_argument(&session.worktree),
        ];
        git.checked_os("removing the managed worktree", &args)
            .map_err(|error| {
                cleanup_error(session, "Git could not remove the managed worktree", error)
            })?;
    } else if session.manifest.lifecycle_state != LifecycleState::Rejecting
        && session.manifest.lifecycle_state != LifecycleState::Applied
    {
        return Err(SandboxError::manifest("managed worktree is missing"));
    }
    let branch = branch_name(&session.manifest.session_id);
    let branch_result = git.output(&[
        "show-ref",
        "--verify",
        "--quiet",
        &format!("refs/heads/{branch}"),
    ])?;
    if branch_result.status.success() {
        git.checked(
            "deleting the managed branch",
            &["branch", "-D", "--", &branch],
        )
        .map_err(|error| {
            cleanup_error(session, "Git could not delete the managed branch", error)
        })?;
    } else if branch_result.status.code() != Some(1) {
        let command = if session.manifest.lifecycle_state == LifecycleState::Applied {
            "accept"
        } else {
            "reject"
        };
        return Err(SandboxError::cleanup(
            "Git could not determine whether the managed branch still exists",
            format!(
                "inspect refs/heads/{branch}, then run `blastguard sandbox {command} --id {}` again; manifest: {}",
                session.manifest.session_id,
                session.manifest_path.display()
            ),
        ));
    }
    manifest::remove(&session.manifest_path).map_err(|error| {
        cleanup_error(
            session,
            "the worktree was removed but the manifest remains",
            error,
        )
    })
}

fn cleanup_error(session: &LoadedSession, detail: &str, error: SandboxError) -> SandboxError {
    let command = if session.manifest.lifecycle_state == LifecycleState::Applied {
        "accept"
    } else {
        "reject"
    };
    SandboxError::cleanup(
        format!("{detail}: {error}"),
        format!(
            "inspect the session, then run `blastguard sandbox {command} --id {}` again; manifest: {}",
            session.manifest.session_id,
            session.manifest_path.display(),
        ),
    )
}

fn cleanup_failed_create(git: &Git, worktree: &Path, branch: &str) {
    if worktree.exists() {
        let args = vec![
            OsString::from("worktree"),
            OsString::from("remove"),
            OsString::from("--force"),
            git::path_argument(worktree),
        ];
        let _ = git.checked_os("rolling back worktree creation", &args);
        if worktree.exists() {
            let _ = fs::remove_dir(worktree);
        }
    }
    let reference = format!("refs/heads/{branch}");
    if git
        .output(&["show-ref", "--verify", "--quiet", &reference])
        .is_ok_and(|output| output.status.success())
    {
        let _ = git.checked(
            "rolling back branch creation",
            &["branch", "-D", "--", branch],
        );
    }
}

fn load_session(
    common: &Path,
    state: &StatePaths,
    id: &str,
    allow_missing_worktree: bool,
) -> Result<LoadedSession, SandboxError> {
    let manifest_path = manifest::manifest_path(&state.sessions, id);
    let manifest_metadata = match fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SandboxError::SessionNotFound(clean(id)));
        }
        Err(error) => {
            return Err(SandboxError::operation(
                "inspecting the session manifest",
                error.to_string(),
            ));
        }
    };
    if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
        return Err(SandboxError::manifest(
            "manifest path is not a regular non-symlink file",
        ));
    }
    if !manifest_path.is_file() {
        return Err(SandboxError::SessionNotFound(clean(id)));
    }
    let session_manifest = manifest::read(&manifest_path)?;
    if session_manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(SandboxError::manifest(
            "unsupported manifest schema version",
        ));
    }
    if session_manifest.session_id != id {
        return Err(SandboxError::manifest(
            "manifest session ID does not match its filename",
        ));
    }
    validate_id(&session_manifest.session_id)?;
    if !valid_object_id(&session_manifest.base_commit) {
        return Err(SandboxError::manifest(
            "base commit is not a valid hexadecimal object ID",
        ));
    }
    let source = PathBuf::from(&session_manifest.source_path);
    let source_canonical = canonical_without_symlink(&source, "manifest source path")?;
    if source_canonical != source {
        return Err(SandboxError::manifest(
            "manifest source path is not canonical",
        ));
    }
    let source_repo = discover_source(Some(&source), false)?;
    if source_repo.common_dir != common {
        return Err(SandboxError::manifest(
            "manifest belongs to a different Git common directory",
        ));
    }
    let expected_worktree = worktree_parent(&source)?.join(id);
    let worktree = PathBuf::from(&session_manifest.worktree_path);
    if worktree != expected_worktree {
        return Err(SandboxError::manifest(
            "worktree path is outside the controlled session location",
        ));
    }
    if path_exists_without_following(&worktree)? {
        validate_worktree(&worktree)?;
    } else if !allow_missing_worktree {
        return Err(SandboxError::manifest(
            "managed worktree is missing; no cleanup was attempted",
        ));
    }
    Ok(LoadedSession {
        manifest_path,
        manifest: session_manifest,
        source,
        worktree,
        state: StatePaths {
            root: state.root.clone(),
            sessions: state.sessions.clone(),
            locks: state.locks.clone(),
            temp: state.temp.clone(),
            journal: state.journal.clone(),
        },
    })
}

fn validate_execution_worktree(
    session: &LoadedSession,
    expected_common: &Path,
) -> Result<(), SandboxError> {
    validate_worktree(&session.worktree)?;
    let git = Git::new(&session.worktree);
    let top = git::text(
        "resolving the managed worktree root",
        git.checked(
            "resolving the managed worktree root",
            &["rev-parse", "--show-toplevel"],
        )?,
    )?;
    let top = canonical_git_path(&session.worktree, &top, "managed worktree root")?;
    if top != session.worktree {
        return Err(SandboxError::manifest(
            "managed worktree no longer resolves to its recorded root",
        ));
    }
    let common = git::text(
        "resolving the managed worktree Git common directory",
        git.checked(
            "resolving the managed worktree Git common directory",
            &["rev-parse", "--git-common-dir"],
        )?,
    )?;
    let common = canonical_git_path(
        &session.worktree,
        &common,
        "managed worktree Git common directory",
    )?;
    if common != expected_common {
        return Err(SandboxError::manifest(
            "managed worktree belongs to a different Git common directory",
        ));
    }
    let reference_output = git.output(&["symbolic-ref", "--quiet", "HEAD"])?;
    if !reference_output.status.success() {
        return Err(SandboxError::manifest(
            "managed worktree is detached or its branch cannot be verified",
        ));
    }
    let reference = git::text(
        "resolving the managed worktree branch",
        reference_output.stdout,
    )?;
    if reference != format!("refs/heads/{}", branch_name(&session.manifest.session_id)) {
        return Err(SandboxError::manifest(
            "managed worktree is no longer on its recorded BlastGuard branch",
        ));
    }
    let _ = head_commit(&git)?;
    Ok(())
}

fn context_common_dir() -> Result<PathBuf, SandboxError> {
    let cwd = canonical_without_symlink(
        &std::env::current_dir().map_err(|error| {
            SandboxError::operation("reading the current directory", error.to_string())
        })?,
        "current repository path",
    )?;
    let git = Git::new(&cwd);
    let common = git::text(
        "resolving the Git common directory",
        git.checked(
            "resolving the Git common directory",
            &["rev-parse", "--git-common-dir"],
        )?,
    )?;
    canonical_git_path(&cwd, &common, "Git common directory")
}

fn state_paths(common: &Path, create: bool) -> Result<StatePaths, SandboxError> {
    let root = common.join("blastguard");
    let state = StatePaths {
        sessions: root.join("sessions"),
        locks: root.join("locks"),
        temp: root.join("tmp"),
        journal: root.join("journal"),
        root,
    };
    if create {
        ensure_secure_directory(&state.root)?;
        ensure_secure_directory(&state.sessions)?;
        ensure_secure_directory(&state.locks)?;
        ensure_secure_directory(&state.temp)?;
        ensure_secure_directory(&state.journal)?;
    } else if fs::symlink_metadata(&state.root).is_err() {
        return Err(SandboxError::SessionNotFound(
            "no BlastGuard session state exists for this repository".to_owned(),
        ));
    } else {
        validate_secure_directory(&state.root)?;
        validate_secure_directory(&state.sessions)?;
        validate_secure_directory(&state.locks)?;
    }
    Ok(state)
}

fn worktree_parent(source: &Path) -> Result<PathBuf, SandboxError> {
    let parent = source
        .parent()
        .ok_or_else(|| SandboxError::repository("the source repository has no parent directory"))?;
    let name = source
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("repository")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let hash = stable_path_hash(path_text(source, "source repository")?.as_bytes());
    Ok(parent
        .join(".blastguard-worktrees")
        .join(format!("{name}-{hash:016x}")))
}

fn ensure_secure_directory(path: &Path) -> Result<(), SandboxError> {
    if path_exists_without_following(path)? {
        validate_secure_directory(path)?;
        owner_only_directory(path)?;
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut cursor = lexical_absolute(path)?;
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(SandboxError::manifest(
                        "a managed directory ancestor is not a real directory",
                    ));
                }
                if fs::canonicalize(&cursor).map_err(|error| {
                    SandboxError::operation(
                        "canonicalizing a directory ancestor",
                        error.to_string(),
                    )
                })? != cursor
                {
                    return Err(SandboxError::manifest(
                        "a managed directory ancestor traverses a symlink",
                    ));
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                cursor = cursor.parent().map(Path::to_path_buf).ok_or_else(|| {
                    SandboxError::manifest("managed directory has no existing ancestor")
                })?;
            }
            Err(error) => {
                return Err(SandboxError::operation(
                    "inspecting a directory ancestor",
                    error.to_string(),
                ));
            }
        }
    }
    for directory in missing.iter().rev() {
        fs::create_dir(directory).map_err(|error| {
            SandboxError::operation("creating a secure state directory", error.to_string())
        })?;
        owner_only_directory(directory)?;
    }
    validate_secure_directory(path)?;
    owner_only_directory(path)
}

fn path_exists_without_following(path: &Path) -> Result<bool, SandboxError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(SandboxError::operation(
            "inspecting a managed path",
            error.to_string(),
        )),
    }
}

fn validate_secure_directory(path: &Path) -> Result<(), SandboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SandboxError::operation("validating a state directory", error.to_string())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SandboxError::manifest(
            "a managed state path is not a real directory",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        SandboxError::operation("canonicalizing a state directory", error.to_string())
    })?;
    let lexical = lexical_absolute(path)?;
    if canonical != lexical {
        return Err(SandboxError::manifest(
            "a managed state path traverses a symlink",
        ));
    }
    Ok(())
}

fn validate_created_worktree(path: &Path) -> Result<(), SandboxError> {
    validate_worktree(path)
}

fn validate_worktree(path: &Path) -> Result<(), SandboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SandboxError::operation("validating the managed worktree", error.to_string())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SandboxError::manifest(
            "managed worktree path is not a real directory",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        SandboxError::operation("canonicalizing the managed worktree", error.to_string())
    })?;
    if canonical != lexical_absolute(path)? {
        return Err(SandboxError::manifest(
            "managed worktree path traverses a symlink",
        ));
    }
    Ok(())
}

fn canonical_without_symlink(path: &Path, label: &str) -> Result<PathBuf, SandboxError> {
    let lexical = lexical_absolute(path)?;
    let metadata = fs::symlink_metadata(&lexical).map_err(|error| {
        SandboxError::repository(format!("{label} cannot be inspected: {error}"))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(SandboxError::repository(format!(
            "{label} must not be a symlink"
        )));
    }
    let canonical = fs::canonicalize(&lexical).map_err(|error| {
        SandboxError::repository(format!("{label} cannot be canonicalized: {error}"))
    })?;
    if canonical != lexical {
        return Err(SandboxError::repository(format!(
            "{label} traverses a symlink or inconsistent path"
        )));
    }
    Ok(canonical)
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, SandboxError> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                SandboxError::operation("reading the current directory", error.to_string())
            })?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component)
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(SandboxError::repository(
                        "path traversal escaped the filesystem root",
                    ));
                }
            }
        }
    }
    Ok(normalized)
}

fn canonical_git_path(source: &Path, value: &str, label: &str) -> Result<PathBuf, SandboxError> {
    let path = Path::new(value);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        source.join(path)
    };
    canonical_without_symlink(&joined, label)
}

fn has_gitlink(git: &Git) -> Result<bool, SandboxError> {
    let output = git.checked("checking for submodules", &["ls-files", "--stage", "-z"])?;
    Ok(output
        .split(|byte| *byte == 0)
        .any(|entry| entry.starts_with(b"160000 ")))
}

fn git_config_true(git: &Git, key: &str) -> Result<bool, SandboxError> {
    let output = git.output(&["config", "--bool", "--get", key])?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim() == "true");
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    Err(SandboxError::operation(
        "reading Git configuration",
        String::from_utf8_lossy(&output.stderr),
    ))
}

fn contains_nested_repository(root: &Path) -> Result<bool, SandboxError> {
    fn visit(path: &Path, root: &Path) -> Result<bool, SandboxError> {
        if path != root
            && path.join("HEAD").is_file()
            && path.join("objects").is_dir()
            && path.join("refs").is_dir()
        {
            return Ok(true);
        }
        for entry in fs::read_dir(path).map_err(|error| {
            SandboxError::operation("scanning for nested repositories", error.to_string())
        })? {
            let entry = entry.map_err(|error| {
                SandboxError::operation("reading a repository directory", error.to_string())
            })?;
            let child = entry.path();
            let metadata = fs::symlink_metadata(&child).map_err(|error| {
                SandboxError::operation("inspecting a repository entry", error.to_string())
            })?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if child != root.join(".git") && entry.file_name() == ".git" {
                return Ok(true);
            }
            if metadata.is_dir() && child != root.join(".git") && visit(&child, root)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    visit(root, root)
}

fn head_commit(git: &Git) -> Result<String, SandboxError> {
    git::text(
        "resolving HEAD",
        git.checked(
            "resolving HEAD",
            &["rev-parse", "--verify", "HEAD^{commit}"],
        )?,
    )
}

fn require_active(manifest: &SessionManifest, action: &str) -> Result<(), SandboxError> {
    if manifest.lifecycle_state == LifecycleState::Active {
        Ok(())
    } else {
        Err(SandboxError::manifest(format!(
            "cannot {action} a session in `{}` state",
            manifest.lifecycle_state.as_str()
        )))
    }
}

fn valid_object_id(value: &str) -> bool {
    (40..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_id(id: &str) -> Result<(), SandboxError> {
    let valid = (1..=64).contains(&id.len())
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(SandboxError::InvalidId)
    }
}

fn generate_id() -> Result<String, SandboxError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            SandboxError::operation(
                "generating a session ID",
                "system clock is before the Unix epoch",
            )
        })?
        .as_secs();
    Ok(format!(
        "bg-{timestamp:x}-{:x}-{:x}",
        std::process::id(),
        next_nonce()
    ))
}

fn next_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

fn stable_path_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn branch_name(id: &str) -> String {
    format!("blastguard/{id}")
}

fn path_text(path: &Path, label: &str) -> Result<String, SandboxError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| SandboxError::repository(format!("{label} is not valid UTF-8")))
}

fn clean(value: &str) -> String {
    redaction::redact(value).text
}

fn rollback_scope() -> String {
    "Git-tracked and non-ignored worktree content only; no rollback of external effects, ignored files, hooks, network activity, or prior commands."
        .to_owned()
}

#[cfg(unix)]
fn owner_only_directory(path: &Path) -> Result<(), SandboxError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        SandboxError::operation(
            "setting owner-only directory permissions",
            error.to_string(),
        )
    })
}

#[cfg(not(unix))]
fn owner_only_directory(_path: &Path) -> Result<(), SandboxError> {
    Ok(())
}
