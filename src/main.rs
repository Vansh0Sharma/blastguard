use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use blastguard::{
    analyze, claude, claude_hook, config::Config, error::BlastguardError, execution,
    execution_error, execution_render, model::Decision, redaction, render, sandbox, sandbox_render,
};
use clap::{error::ErrorKind, Parser, Subcommand};

const EXIT_ALLOW: u8 = 0;
const EXIT_ASK: u8 = 10;
const EXIT_BLOCK: u8 = 20;
const EXIT_INVALID: u8 = 64;
const EXIT_INTERNAL: u8 = 70;
const CLAUDE_BLOCK: u8 = 2;

#[derive(Parser)]
#[command(name = "blastguard", version, about)]
struct Cli {
    /// Load overrides from TOML (defaults to analyzed cwd or exec session source).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a shell command without executing it.
    Analyze {
        /// Shell command to analyze.
        #[arg(long)]
        command: String,
        /// Working directory in which the command would run.
        #[arg(long)]
        cwd: PathBuf,
        /// Emit the stable JSON schema instead of a terminal card.
        #[arg(long)]
        json: bool,
    },
    /// Act as a Claude Code PreToolUse hook, reading one JSON object from stdin.
    ClaudeHook,
    /// Launch Claude Code in a managed worktree or run its policy hook.
    Claude {
        #[command(subcommand)]
        command: ClaudeCommand,
    },
    /// Manage an ephemeral Git worktree lifecycle and controlled execution.
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
}

#[derive(Subcommand)]
enum ClaudeCommand {
    /// Launch Claude Code in an active managed worktree.
    Start {
        #[arg(long)]
        id: String,
        /// Arguments passed verbatim to Claude Code after `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    /// Print the per-session Claude settings used by `claude start`.
    HookConfig {
        #[arg(long)]
        id: String,
        /// Emit only the settings JSON.
        #[arg(long)]
        json: bool,
    },
    /// Process one Claude Code PreToolUse Bash hook event from stdin.
    Hook,
}

#[derive(Subcommand)]
enum SandboxCommand {
    /// Create a managed linked worktree from an exactly clean repository.
    Create {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        id: Option<String>,
    },
    /// Show lifecycle and Git state for a session.
    Status {
        #[arg(long)]
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the complete non-ignored patch relative to the recorded base.
    Diff {
        #[arg(long)]
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Apply the exact sandbox snapshot to the source as staged changes.
    Accept {
        #[arg(long)]
        id: String,
    },
    /// Remove the managed worktree and ref without changing the source.
    Reject {
        #[arg(long)]
        id: String,
    },
    /// List sessions stored in a repository's Git common directory.
    List {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Policy-check and execute a Bash command in an active managed worktree.
    Exec {
        #[arg(long)]
        id: String,
        #[arg(long)]
        command: String,
        /// Approve an `ask` decision for this invocation only.
        #[arg(long)]
        approve: bool,
        #[arg(long, default_value_t = execution::DEFAULT_TIMEOUT_SECONDS)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = execution::DEFAULT_MAX_OUTPUT_BYTES)]
        max_output_bytes: usize,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let message = redaction::redact(&error.to_string()).text;
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = write!(io::stdout(), "{message}");
                return ExitCode::SUCCESS;
            }
            let _ = write!(io::stderr(), "{message}");
            return ExitCode::from(EXIT_INVALID);
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err((error, hook_mode)) => {
            let message = redaction::redact(&error.to_string()).text;
            let _ = writeln!(io::stderr(), "BlastGuard: {message}");
            ExitCode::from(if hook_mode {
                // Claude Code documents status 2 as a blocking hook error.
                CLAUDE_BLOCK
            } else if is_invalid_input(&error) {
                EXIT_INVALID
            } else if let BlastguardError::Sandbox(error) = &error {
                error.exit() as u8
            } else {
                EXIT_INTERNAL
            })
        }
    }
}

fn run(cli: Cli) -> Result<u8, (BlastguardError, bool)> {
    match cli.command {
        Command::Analyze { command, cwd, json } => {
            if !cwd.is_dir() {
                let path = redaction::redact(&cwd.display().to_string()).text;
                return Err((BlastguardError::InvalidCwd(path), false));
            }
            let config =
                Config::load(cli.config.as_deref(), &cwd).map_err(|error| (error, false))?;
            let analysis = analyze(&command, &cwd, &config).map_err(|error| (error, false))?;
            let output = if json {
                render::json(&analysis).map_err(|error| (error, false))?
            } else {
                render::human(&analysis)
            };
            println!("{output}");
            Ok(match analysis.decision {
                Decision::Allow => EXIT_ALLOW,
                Decision::Ask => EXIT_ASK,
                Decision::Block => EXIT_BLOCK,
            })
        }
        Command::ClaudeHook => {
            let request =
                claude_hook::read_request(&mut io::stdin()).map_err(|error| (error, true))?;
            let (analysis, response) =
                claude_hook::analyze_request(&request, cli.config.as_deref())
                    .map_err(|error| (error, true))?;
            let output = serde_json::to_string(&response)
                .map_err(|error| (BlastguardError::Serialization(error.to_string()), true))?;
            println!("{}", redaction::redact(&output).text);
            if analysis.decision == Decision::Block {
                let reason = response.hook_specific_output.permission_decision_reason;
                let _ = writeln!(io::stderr(), "{reason}");
                Ok(CLAUDE_BLOCK)
            } else {
                // Claude Code consumes allow/ask decisions only from successful JSON hooks.
                Ok(EXIT_ALLOW)
            }
        }
        Command::Claude { command } => run_claude(command).map_err(|error| {
            let hook_mode = matches!(error.1, ClaudeFailureMode::Hook);
            (error.0, hook_mode)
        }),
        Command::Sandbox { command } => {
            run_sandbox(command, cli.config.as_deref()).map_err(|error| (error, false))
        }
    }
}

#[derive(Clone, Copy)]
enum ClaudeFailureMode {
    Command,
    Hook,
}

fn run_claude(command: ClaudeCommand) -> Result<u8, (BlastguardError, ClaudeFailureMode)> {
    match command {
        ClaudeCommand::Hook => {
            let request = claude_hook::read_request(&mut io::stdin())
                .map_err(|error| (error, ClaudeFailureMode::Hook))?;
            let (analysis, response) = claude::evaluate_hook_with_timeout(request)
                .map_err(|error| (error, ClaudeFailureMode::Hook))?;
            let output = serde_json::to_string(&response).map_err(|error| {
                (
                    BlastguardError::Serialization(error.to_string()),
                    ClaudeFailureMode::Hook,
                )
            })?;
            println!("{}", redaction::redact(&output).text);
            if analysis.decision == Decision::Block {
                let reason = response.hook_specific_output.permission_decision_reason;
                let _ = writeln!(io::stderr(), "{reason}");
                Ok(CLAUDE_BLOCK)
            } else {
                Ok(EXIT_ALLOW)
            }
        }
        ClaudeCommand::HookConfig { id, json } => {
            let settings = claude::hook_settings_json(&id)
                .map_err(|error| (error, ClaudeFailureMode::Command))?;
            if json {
                println!("{settings}");
            } else {
                println!(
                    "Claude Code per-session settings for `{id}`:\n{settings}\n\nManual launch:\n  claude --settings '<JSON above>'"
                );
            }
            Ok(EXIT_ALLOW)
        }
        ClaudeCommand::Start { id, arguments } => {
            let result = claude::start(&id, &arguments)
                .map_err(|error| (error, ClaudeFailureMode::Command))?;
            let worktree = redaction::redact(&result.worktree.display().to_string()).text;
            let session = redaction::redact(&result.session_id).text;
            println!(
                "\nBlastGuard Claude review\n  session: {session}\n  status: Claude exited with {}\n  worktree: {worktree}\n  next: `blastguard sandbox diff --id {session}`\n        `blastguard sandbox accept --id {session}`\n        `blastguard sandbox reject --id {session}`",
                render_exit_status(result.status)
            );
            Ok(child_exit_code(result.status))
        }
    }
}

fn render_exit_status(status: std::process::ExitStatus) -> String {
    status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "a signal".to_owned())
}

fn child_exit_code(status: std::process::ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(EXIT_INTERNAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status
            .signal()
            .and_then(|signal| u8::try_from(128 + signal).ok())
            .unwrap_or(EXIT_INTERNAL)
    }
    #[cfg(not(unix))]
    EXIT_INTERNAL
}

fn run_sandbox(
    command: SandboxCommand,
    config: Option<&std::path::Path>,
) -> Result<u8, BlastguardError> {
    let output = match command {
        SandboxCommand::Create { repo, id } => {
            let result = sandbox::create(repo.as_deref(), id.as_deref())?;
            sandbox_render::create(&result)
        }
        SandboxCommand::Status { id, json } => {
            let result = sandbox::status(&id)?;
            if json {
                sandbox_render::json(&result)?
            } else {
                sandbox_render::status(&result)
            }
        }
        SandboxCommand::Diff { id, json } => {
            let result = sandbox::diff(&id)?;
            if json {
                sandbox_render::json(&result)?
            } else {
                sandbox_render::diff(&result)
            }
        }
        SandboxCommand::Accept { id } => sandbox_render::accept(&sandbox::accept(&id)?),
        SandboxCommand::Reject { id } => sandbox_render::reject(&sandbox::reject(&id)?),
        SandboxCommand::List { repo, json } => {
            let result = sandbox::list(repo.as_deref())?;
            if json {
                sandbox_render::json(&result)?
            } else {
                sandbox_render::list(&result)
            }
        }
        SandboxCommand::Exec {
            id,
            command,
            approve,
            timeout_seconds,
            max_output_bytes,
            json,
        } => {
            let prepared = execution::prepare(execution::PrepareRequest {
                session_id: &id,
                command: &command,
                approve,
                timeout_seconds,
                max_output_bytes,
                config_path: config,
            })?;
            if !json {
                writeln!(
                    io::stdout(),
                    "{}",
                    execution_render::decision_card(&prepared)
                )
                .and_then(|_| io::stdout().flush())
                .map_err(|error| {
                    execution_error::ExecutionError::internal(format!(
                        "showing the execution decision: {error}"
                    ))
                })?;
            }
            let report = execution::execute(prepared)?;
            let code = execution::exit_code(&report);
            let rendered = if json {
                execution_render::json(&report)?
            } else {
                execution_render::result(&report)
            };
            println!("{rendered}");
            return Ok(code);
        }
    };
    println!("{output}");
    Ok(EXIT_ALLOW)
}

fn is_invalid_input(error: &BlastguardError) -> bool {
    matches!(
        error,
        BlastguardError::EmptyCommand
            | BlastguardError::InvalidCwd(_)
            | BlastguardError::ConfigRead { .. }
            | BlastguardError::ConfigParse { .. }
            | BlastguardError::InvalidPattern { .. }
            | BlastguardError::HookJson(_)
            | BlastguardError::HookCommandMissing
            | BlastguardError::HookCommandAmbiguous
            | BlastguardError::HookObjectRequired
            | BlastguardError::HookToolMissing
            | BlastguardError::HookToolUnsupported
            | BlastguardError::HookEventMissing
            | BlastguardError::HookEventUnsupported
            | BlastguardError::HookCwdMissing
            | BlastguardError::HookInputTooLarge(_)
            | BlastguardError::Execution(execution_error::ExecutionError::InvalidInput(_))
            | BlastguardError::ClaudeInvalid(_)
    )
}
