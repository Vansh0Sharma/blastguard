use std::{
    io::{self, Read},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    analyze_for_execution,
    config::Config,
    error::BlastguardError,
    execution_error::ExecutionError,
    execution_journal::{self, JournalEntry, JournalStream, JOURNAL_SCHEMA},
    model::{Analysis, Decision},
    redaction::{self, RedactionMatch},
    sandbox::{self, ExecutionLease, GitState},
};

pub const EXECUTION_SCHEMA: &str = "blastguard.sandbox.exec/1.0";
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 60;
pub const MAX_TIMEOUT_SECONDS: u64 = 300;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Serialize)]
pub struct ExecutionLimits {
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Blocked,
    ApprovalRequired,
    Completed,
    ChildFailed,
    TimedOut,
    OutputLimit,
}

impl ExecutionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::ApprovalRequired => "approval_required",
            Self::Completed => "completed",
            Self::ChildFailed => "child_failed",
            Self::TimedOut => "timed_out",
            Self::OutputLimit => "output_limit",
        }
    }
}

#[derive(Serialize)]
pub struct StreamResult {
    pub text: String,
    pub bytes_observed: u64,
    pub bytes_captured: usize,
    pub truncated: bool,
    pub redactions: Vec<RedactionMatch>,
    pub terminal_sequences_removed: usize,
}

#[derive(Serialize)]
pub struct ProcessResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_milliseconds: u128,
    pub timed_out: bool,
    pub output_limit_reached: bool,
    pub termination_complete: bool,
    pub termination_scope: String,
    pub stdout: StreamResult,
    pub stderr: StreamResult,
}

#[derive(Serialize)]
pub struct ExecutionReport {
    pub schema_version: &'static str,
    pub session_id: String,
    pub worktree_path: String,
    pub base_commit: String,
    pub command: String,
    pub policy: Analysis,
    pub approval_provided: bool,
    pub execution_state: ExecutionState,
    pub limits: ExecutionLimits,
    pub worktree_git_state_before: GitState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessResult>,
    pub rollback_scope: String,
    pub boundary_warning: String,
    pub next_step: String,
}

pub struct PrepareRequest<'a> {
    pub session_id: &'a str,
    pub command: &'a str,
    pub approve: bool,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    pub config_path: Option<&'a Path>,
}

pub struct PreparedExecution {
    pub(crate) session_id: String,
    pub(crate) worktree_path: String,
    pub(crate) base_commit: String,
    pub(crate) safe_command: String,
    pub(crate) analysis: Analysis,
    pub(crate) approval_provided: bool,
    pub(crate) limits: ExecutionLimits,
    pub(crate) git_state: GitState,
    lease: ExecutionLease,
    command: String,
}

impl PreparedExecution {
    pub fn will_execute(&self) -> bool {
        self.analysis.decision == Decision::Allow
            || (self.analysis.decision == Decision::Ask && self.approval_provided)
    }
}

pub fn prepare(request: PrepareRequest<'_>) -> Result<PreparedExecution, BlastguardError> {
    validate_limits(request.timeout_seconds, request.max_output_bytes)?;
    if request.command.trim().is_empty() {
        return Err(ExecutionError::invalid("the command must not be empty").into());
    }
    if !cfg!(unix) {
        return Err(ExecutionError::invalid(
            "controlled execution currently requires Unix process-group support",
        )
        .into());
    }

    let lease = sandbox::lock_for_execution(request.session_id)?;
    let config = Config::load(request.config_path, lease.source())?;
    let analysis = analyze_for_execution(request.command, lease.worktree(), &config)?;
    let safe_command = redaction::redact(request.command).text;
    let worktree_path = redaction::redact(&lease.worktree().display().to_string()).text;
    Ok(PreparedExecution {
        session_id: lease.session_id().to_owned(),
        worktree_path,
        base_commit: lease.base_commit().to_owned(),
        safe_command,
        analysis,
        approval_provided: request.approve,
        limits: ExecutionLimits {
            timeout_seconds: request.timeout_seconds,
            max_output_bytes: request.max_output_bytes,
        },
        git_state: lease.git_state().clone(),
        lease,
        command: request.command.to_owned(),
    })
}

pub fn execute(prepared: PreparedExecution) -> Result<ExecutionReport, BlastguardError> {
    let state_without_process = match prepared.analysis.decision {
        Decision::Block => Some(ExecutionState::Blocked),
        Decision::Ask if !prepared.approval_provided => Some(ExecutionState::ApprovalRequired),
        Decision::Allow | Decision::Ask => None,
    };

    let (execution_state, process) = if let Some(state) = state_without_process {
        (state, None)
    } else {
        let result = run_process(
            prepared.lease.worktree(),
            &prepared.command,
            prepared.limits,
        )?;
        let state = if result.timed_out {
            ExecutionState::TimedOut
        } else if result.output_limit_reached {
            ExecutionState::OutputLimit
        } else if result.exit_code == Some(0) {
            ExecutionState::Completed
        } else {
            ExecutionState::ChildFailed
        };
        (state, Some(result))
    };

    let report = ExecutionReport {
        schema_version: EXECUTION_SCHEMA,
        session_id: prepared.session_id,
        worktree_path: prepared.worktree_path,
        base_commit: prepared.base_commit,
        command: prepared.safe_command,
        policy: prepared.analysis,
        approval_provided: prepared.approval_provided,
        execution_state,
        limits: prepared.limits,
        worktree_git_state_before: prepared.git_state,
        process,
        rollback_scope: "Git-tracked and non-ignored worktree changes only; external effects and processes are not rolled back.".to_owned(),
        boundary_warning: "Git-isolated, not OS-sandboxed. Runtime expansion, symlinks, arbitrary binaries, network access, and external paths can escape Git rollback.".to_owned(),
        next_step: format!(
            "Run `blastguard sandbox diff --id {}` to review Git-visible changes.",
            prepared.lease.session_id()
        ),
    };
    append_journal(prepared.lease.journal_dir(), &report)?;
    Ok(report)
}

pub fn exit_code(report: &ExecutionReport) -> u8 {
    match report.execution_state {
        ExecutionState::Completed => 0,
        ExecutionState::Blocked => 40,
        ExecutionState::ApprovalRequired => 41,
        ExecutionState::ChildFailed => 42,
        ExecutionState::TimedOut => 43,
        ExecutionState::OutputLimit => 44,
    }
}

fn validate_limits(timeout_seconds: u64, max_output_bytes: usize) -> Result<(), ExecutionError> {
    if timeout_seconds == 0 || timeout_seconds > MAX_TIMEOUT_SECONDS {
        return Err(ExecutionError::invalid(format!(
            "timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        )));
    }
    if max_output_bytes == 0 || max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(ExecutionError::invalid(format!(
            "maximum output must be between 1 and {MAX_OUTPUT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn run_process(
    worktree: &Path,
    command_text: &str,
    limits: ExecutionLimits,
) -> Result<ProcessResult, ExecutionError> {
    let bash = bash_path()?;
    let mut command = Command::new(bash);
    command
        .args(["--noprofile", "--norc", "-c"])
        .arg(command_text)
        .arg("blastguard-sandbox")
        .current_dir(worktree)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    #[cfg(target_os = "linux")]
    enable_child_subreaper()?;

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| ExecutionError::internal(format!("starting Bash: {error}")))?;
    let process_group = child.id();
    #[cfg(unix)]
    validate_process_group(&mut child, process_group)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecutionError::internal("captured stdout was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExecutionError::internal("captured stderr was unavailable"))?;
    let budget = Arc::new(Mutex::new(limits.max_output_bytes));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_thread = capture_thread(stdout, Arc::clone(&budget), Arc::clone(&exceeded));
    let stderr_thread = capture_thread(stderr, Arc::clone(&budget), Arc::clone(&exceeded));
    let timeout = Duration::from_secs(limits.timeout_seconds);

    let mut timed_out = false;
    let mut output_limit_reached = false;
    let status = loop {
        if exceeded.load(Ordering::Acquire) {
            output_limit_reached = true;
            break terminate_running_child(&mut child, process_group)?;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            break terminate_running_child(&mut child, process_group)?;
        }
        match child
            .try_wait()
            .map_err(|error| ExecutionError::internal(format!("waiting for Bash: {error}")))?
        {
            Some(status) => break status,
            None => thread::sleep(Duration::from_millis(10)),
        }
    };

    let termination_complete = cleanup_process_group(process_group)?;
    let stdout = join_capture(stdout_thread, "stdout")?;
    let stderr = join_capture(stderr_thread, "stderr")?;
    output_limit_reached |= exceeded.load(Ordering::Acquire);
    let stdout = finish_stream(stdout, output_limit_reached);
    let stderr = finish_stream(stderr, output_limit_reached);
    Ok(ProcessResult {
        exit_code: status.code(),
        signal: exit_signal(status),
        duration_milliseconds: started.elapsed().as_millis(),
        timed_out,
        output_limit_reached,
        termination_complete,
        termination_scope: "Unix process group created for the Bash child; descendants that deliberately leave that group are outside cleanup scope.".to_owned(),
        stdout,
        stderr,
    })
}

fn bash_path() -> Result<&'static Path, ExecutionError> {
    for candidate in [Path::new("/bin/bash"), Path::new("/usr/bin/bash")] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(ExecutionError::internal(
        "no supported absolute Bash executable was found",
    ))
}

struct RawCapture {
    bytes: Vec<u8>,
    observed: u64,
}

fn capture_thread(
    mut pipe: impl Read + Send + 'static,
    budget: Arc<Mutex<usize>>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<RawCapture>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut observed = 0_u64;
        let mut chunk = [0_u8; 8192];
        loop {
            let count = pipe.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            observed = observed.saturating_add(count as u64);
            let take = {
                let mut remaining = budget
                    .lock()
                    .map_err(|_| io::Error::other("output budget lock was poisoned"))?;
                let take = count.min(*remaining);
                *remaining -= take;
                take
            };
            bytes.extend_from_slice(&chunk[..take]);
            if take < count {
                exceeded.store(true, Ordering::Release);
            }
        }
        Ok(RawCapture { bytes, observed })
    })
}

fn join_capture(
    handle: thread::JoinHandle<io::Result<RawCapture>>,
    label: &str,
) -> Result<RawCapture, ExecutionError> {
    handle
        .join()
        .map_err(|_| ExecutionError::internal(format!("{label} capture thread panicked")))?
        .map_err(|error| ExecutionError::internal(format!("reading child {label}: {error}")))
}

fn finish_stream(raw: RawCapture, forced_truncation: bool) -> StreamResult {
    let captured = raw.bytes.len();
    let (sanitized, terminal_sequences_removed) = sanitize_terminal(&raw.bytes);
    let redacted = redaction::redact(&sanitized);
    StreamResult {
        text: redacted.text,
        bytes_observed: raw.observed,
        bytes_captured: captured,
        truncated: forced_truncation || raw.observed > captured as u64,
        redactions: redacted.matches,
        terminal_sequences_removed,
    }
}

fn sanitize_terminal(bytes: &[u8]) -> (String, usize) {
    let mut safe = Vec::with_capacity(bytes.len());
    let mut removed = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == 0x1b {
            removed += 1;
            index += 1;
            if index >= bytes.len() {
                break;
            }
            if bytes[index] == b'[' {
                index += 1;
                while index < bytes.len() {
                    let current = bytes[index];
                    index += 1;
                    if (0x40..=0x7e).contains(&current) {
                        break;
                    }
                }
            } else if bytes[index] == b']' {
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == 0x07 {
                        index += 1;
                        break;
                    }
                    if bytes[index] == 0x1b
                        && bytes.get(index + 1).is_some_and(|next| *next == b'\\')
                    {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            } else {
                index += 1;
            }
            continue;
        }
        match byte {
            b'\n' | b'\t' => safe.push(byte),
            0x20..=0x7e => safe.push(byte),
            0x80..=0xff => safe.push(byte),
            _ => safe.extend_from_slice(format!("\\x{byte:02x}").as_bytes()),
        }
        index += 1;
    }
    let mut text = String::from_utf8_lossy(&safe).into_owned();
    text = text
        .chars()
        .flat_map(|character| {
            if ('\u{80}'..='\u{9f}').contains(&character) {
                format!("\\u{{{:04x}}}", character as u32)
                    .chars()
                    .collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect();
    (text, removed)
}

#[cfg(unix)]
fn terminate_running_child(
    child: &mut Child,
    process_group: u32,
) -> Result<ExitStatus, ExecutionError> {
    signal_process_group(process_group, libc::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(|error| {
            ExecutionError::internal(format!("waiting after termination: {error}"))
        })? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(10));
    }
    signal_process_group(process_group, libc::SIGKILL)?;
    child.wait().map_err(|error| {
        ExecutionError::internal(format!("waiting after forced termination: {error}"))
    })
}

#[cfg(not(unix))]
fn terminate_running_child(
    child: &mut Child,
    _process_group: u32,
) -> Result<ExitStatus, ExecutionError> {
    child
        .kill()
        .map_err(|error| ExecutionError::internal(format!("terminating Bash: {error}")))?;
    child
        .wait()
        .map_err(|error| ExecutionError::internal(format!("waiting after termination: {error}")))
}

#[cfg(unix)]
fn cleanup_process_group(process_group: u32) -> Result<bool, ExecutionError> {
    reap_adopted_group_members(process_group)?;
    if !process_group_exists(process_group)? {
        return Ok(true);
    }
    signal_process_group(process_group, libc::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        reap_adopted_group_members(process_group)?;
        if !process_group_exists(process_group)? {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(10));
    }
    signal_process_group(process_group, libc::SIGKILL)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        reap_adopted_group_members(process_group)?;
        if !process_group_exists(process_group)? {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(10));
    }
    reap_adopted_group_members(process_group)?;
    Ok(!process_group_exists(process_group)?)
}

#[cfg(not(unix))]
fn cleanup_process_group(_process_group: u32) -> Result<bool, ExecutionError> {
    Ok(false)
}

#[cfg(unix)]
fn process_group_exists(process_group: u32) -> Result<bool, ExecutionError> {
    let process_group = process_group_id(process_group)?;
    loop {
        // A negative PID addresses every process in the process group.
        if unsafe { libc::kill(-process_group, 0) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => return Ok(false),
            Some(libc::EPERM) => return Ok(true),
            Some(libc::EINTR) => continue,
            _ => {
                return Err(ExecutionError::internal(format!(
                    "checking the child process group: {error}"
                )))
            }
        }
    }
}

#[cfg(unix)]
fn signal_process_group(process_group: u32, signal: libc::c_int) -> Result<(), ExecutionError> {
    let process_group = process_group_id(process_group)?;
    loop {
        // Invoke kill(2) directly so a negative process-group ID cannot be
        // reinterpreted as an option by a platform-specific `kill` binary.
        if unsafe { libc::kill(-process_group, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => return Ok(()),
            Some(libc::EINTR) => continue,
            _ => {
                return Err(ExecutionError::internal(format!(
                    "signaling the child process group: {error}"
                )))
            }
        }
    }
}

#[cfg(unix)]
fn process_group_id(process_group: u32) -> Result<libc::pid_t, ExecutionError> {
    let process_group = libc::pid_t::try_from(process_group)
        .map_err(|_| ExecutionError::internal("the child process-group ID was out of range"))?;
    if process_group <= 0 {
        return Err(ExecutionError::internal(
            "the child process-group ID was invalid",
        ));
    }
    Ok(process_group)
}

#[cfg(unix)]
fn validate_process_group(child: &mut Child, process_group: u32) -> Result<(), ExecutionError> {
    let expected = process_group_id(process_group)?;
    loop {
        let actual = unsafe { libc::getpgid(expected) };
        if actual == expected {
            return Ok(());
        }
        if actual >= 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ExecutionError::internal(
                "Bash did not start in its dedicated process group",
            ));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ESRCH) => {
                let exited = child.try_wait().map_err(|wait_error| {
                    ExecutionError::internal(format!(
                        "checking Bash after process-group setup: {wait_error}"
                    ))
                })?;
                if exited.is_some() {
                    // The requested PGID is still the correct cleanup target:
                    // descendants can outlive a shell that exits immediately.
                    return Ok(());
                }
            }
            _ => {}
        }
        let _ = child.kill();
        let _ = child.wait();
        return Err(ExecutionError::internal(format!(
            "validating the Bash process group: {error}"
        )));
    }
}

#[cfg(target_os = "linux")]
fn enable_child_subreaper() -> Result<(), ExecutionError> {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(ExecutionError::internal(format!(
            "enabling descendant reaping: {}",
            io::Error::last_os_error()
        )))
    }
}

#[cfg(target_os = "linux")]
fn reap_adopted_group_members(process_group: u32) -> Result<(), ExecutionError> {
    let process_group = process_group_id(process_group)?;
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(-process_group, &mut status, libc::WNOHANG) };
        if waited > 0 {
            continue;
        }
        if waited == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ECHILD) => return Ok(()),
            Some(libc::EINTR) => continue,
            _ => {
                return Err(ExecutionError::internal(format!(
                    "reaping child process-group members: {error}"
                )))
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn reap_adopted_group_members(_process_group: u32) -> Result<(), ExecutionError> {
    Ok(())
}

#[cfg(unix)]
fn exit_signal(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: ExitStatus) -> Option<i32> {
    None
}

fn append_journal(directory: &Path, report: &ExecutionReport) -> Result<(), ExecutionError> {
    let timestamp_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExecutionError::internal("system clock is before the Unix epoch"))?
        .as_secs();
    let (stdout, stderr, child_exit_code, timed_out, output_limit_reached, termination_complete) =
        if let Some(process) = &report.process {
            (
                journal_stream(&process.stdout),
                journal_stream(&process.stderr),
                process.exit_code,
                process.timed_out,
                process.output_limit_reached,
                process.termination_complete,
            )
        } else {
            (
                empty_journal_stream(),
                empty_journal_stream(),
                None,
                false,
                false,
                true,
            )
        };
    let entry = JournalEntry {
        schema_version: JOURNAL_SCHEMA,
        session_id: &report.session_id,
        timestamp_unix_seconds,
        policy_decision: report.policy.decision.as_str(),
        execution_state: report.execution_state.as_str(),
        child_exit_code,
        timed_out,
        output_limit_reached,
        termination_complete,
        stdout,
        stderr,
    };
    execution_journal::append(directory, &report.session_id, &entry)
}

fn empty_journal_stream() -> JournalStream {
    JournalStream {
        bytes_observed: 0,
        bytes_captured: 0,
        truncated: false,
        redactions: 0,
        terminal_sequences_removed: 0,
    }
}

fn journal_stream(stream: &StreamResult) -> JournalStream {
    JournalStream {
        bytes_observed: stream.bytes_observed,
        bytes_captured: stream.bytes_captured,
        truncated: stream.truncated,
        redactions: stream.redactions.iter().map(|item| item.replacements).sum(),
        terminal_sequences_removed: stream.terminal_sequences_removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_sequences_and_controls_are_neutralized() {
        let (value, removed) = sanitize_terminal(b"ok\x1b[2J\x1b]0;owned\x07\rbad\x08");
        assert_eq!(removed, 2);
        assert_eq!(value, "ok\\x0dbad\\x08");
        assert!(!value.contains('\u{1b}'));
    }

    #[test]
    fn rejects_limits_outside_hard_bounds() {
        assert!(validate_limits(0, 1).is_err());
        assert!(validate_limits(MAX_TIMEOUT_SECONDS + 1, 1).is_err());
        assert!(validate_limits(1, 0).is_err());
        assert!(validate_limits(1, MAX_OUTPUT_BYTES + 1).is_err());
    }
}
