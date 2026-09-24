use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use crate::{redaction, sandbox_error::SandboxError};

pub struct Git {
    cwd: PathBuf,
}

pub struct GitOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Git {
    pub fn new(cwd: impl Into<PathBuf>) -> Self {
        Self { cwd: cwd.into() }
    }

    pub fn checked(&self, operation: &str, args: &[&str]) -> Result<Vec<u8>, SandboxError> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let output = self.run(&args, None, &[])?;
        checked_output(operation, output)
    }

    pub fn checked_os(&self, operation: &str, args: &[OsString]) -> Result<Vec<u8>, SandboxError> {
        checked_output(operation, self.run(args, None, &[])?)
    }

    pub fn checked_with_env(
        &self,
        operation: &str,
        args: &[&str],
        env: &[(&str, &OsStr)],
    ) -> Result<Vec<u8>, SandboxError> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        checked_output(operation, self.run(&args, None, env)?)
    }

    pub fn checked_input(
        &self,
        operation: &str,
        args: &[&str],
        input: &[u8],
    ) -> Result<Vec<u8>, SandboxError> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        checked_output(operation, self.run(&args, Some(input), &[])?)
    }

    pub fn output(&self, args: &[&str]) -> Result<GitOutput, SandboxError> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        self.run(&args, None, &[])
    }

    fn run(
        &self,
        args: &[OsString],
        input: Option<&[u8]>,
        env: &[(&str, &OsStr)],
    ) -> Result<GitOutput, SandboxError> {
        let null_hooks = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut command = Command::new("git");
        command
            .arg("--no-pager")
            .arg("-c")
            .arg(format!("core.hooksPath={null_hooks}"))
            .arg("-c")
            .arg("core.quotePath=true")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("diff.external=")
            .arg("-C")
            .arg(&self.cwd)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat")
            .env("LC_ALL", "C")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (key, _) in std::env::vars_os().filter(|(key, _)| {
            let key = key.to_string_lossy();
            key == "GIT_DIR"
                || key == "GIT_WORK_TREE"
                || key == "GIT_INDEX_FILE"
                || key == "GIT_OBJECT_DIRECTORY"
                || key == "GIT_ALTERNATE_OBJECT_DIRECTORIES"
                || key == "GIT_EXTERNAL_DIFF"
                || key == "GIT_CONFIG_COUNT"
                || key.starts_with("GIT_CONFIG_KEY_")
                || key.starts_with("GIT_CONFIG_VALUE_")
        }) {
            command.env_remove(key);
        }
        for (key, value) in env {
            command.env(key, value);
        }

        let mut child = command.spawn().map_err(|error| {
            SandboxError::operation("starting Git", redaction::redact(&error.to_string()).text)
        })?;
        if let Some(bytes) = input {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                SandboxError::operation("writing Git input", "Git stdin was unavailable")
            })?;
            if let Err(error) = stdin.write_all(bytes) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::operation(
                    "writing Git input",
                    error.to_string(),
                ));
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|error| SandboxError::operation("waiting for Git", error.to_string()))?;
        Ok(GitOutput {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn checked_output(operation: &str, output: GitOutput) -> Result<Vec<u8>, SandboxError> {
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = redaction::redact(&String::from_utf8_lossy(&output.stderr)).text;
    let detail = if stderr.trim().is_empty() {
        format!("Git exited with status {}", status_label(output.status))
    } else {
        stderr.trim().to_owned()
    };
    Err(SandboxError::operation(operation, detail))
}

fn status_label(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
}

pub fn text(operation: &str, bytes: Vec<u8>) -> Result<String, SandboxError> {
    String::from_utf8(bytes)
        .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| SandboxError::operation(operation, "Git returned non-UTF-8 metadata"))
}

pub fn path_argument(path: &Path) -> OsString {
    path.as_os_str().to_owned()
}
