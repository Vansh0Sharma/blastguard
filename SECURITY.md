# Security Policy

## Supported versions

BlastGuard has not yet published a release. Security fixes are currently made on the default development branch.

| Version | Security fixes |
| --- | --- |
| Default branch / future `0.1.x` line | Supported |
| Earlier snapshots | Not supported |

No public release or backward-compatibility guarantee is implied by this table. After releases exist, this table will name the maintained release lines explicitly.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could expose credentials, bypass a hard block, or enable destructive execution.

Use GitHub private vulnerability reporting after the repository owner enables it. Until that channel exists, contact Vansh Sharma through a private contact method published on the maintainer's GitHub profile. Do not send a vulnerability to a public issue, discussion, or pull request. Include:

- the affected revision;
- the command or hook input, with real secrets removed;
- the observed and expected decision;
- a minimal reproduction and impact assessment.

Do not include live credentials, private keys, customer data, or weaponized payloads. Maintainers should acknowledge a report privately, reproduce it, agree on disclosure timing, and credit the reporter if requested.

## Security scope and non-goals

BlastGuard combines a command-policy guardrail with a reviewable Git-worktree lifecycle. It can launch Claude Code with its initial cwd set to a validated active worktree and gate native Claude Bash calls through a session-bound `PreToolUse` hook. It can classify only the shell input it receives and redact only recognized secret shapes.

Direct `sandbox exec` clears the caller environment, supplies a small fixed operational environment without `HOME` or credential variables, disables Bash startup files, bounds time and captured output, and uses a fresh Unix process group for best-effort descendant cleanup. Captured streams are terminal-control sanitized and pattern-redacted before rendering. Journal schema v2 contains no command text, output text, or fingerprint; an existing v1 fingerprint is stripped on the next append. These are exposure-reduction and reliability measures, not confinement.

Native Claude hook mode is different. Claude inherits the normal launch environment needed for authentication, and Claude executes Bash itself after the hook decision. BlastGuard does not capture, bound, sanitize, redact, terminate, or journal native Claude Bash output. The hook does not rewrite the tool call into `sandbox exec`.

Reject guarantees only that BlastGuard does not apply the managed worktree's Git patch to the source and removes only manifest-owned Git resources after ownership validation. Accept applies the current tracked and non-ignored worktree snapshot as staged source changes only when the source remains clean at the recorded base.

It is not an OS isolation boundary and does not claim protection against:

- arbitrary or compromised binaries;
- malicious repositories, build scripts, aliases, or shell functions;
- kernel-level attacks or privilege-escalation vulnerabilities;
- symlink races, mount changes, or runtime filesystem mutation;
- fully dynamic shell behavior or every possible credential format;
- commands executed outside the configured hook path;
- ignored-file changes, network effects, processes, or writes outside the worktree;
- descendants that create a new session/process group and escape Unix cleanup;
- secret formats not recognized by the pattern-based redactor;
- build/test workflows that require caller environment variables; no inherit-all escape hatch exists;
- custom Git filters or other behavior triggered by a malicious repository;
- filesystem races after canonical-path validation;
- restoration after a user manually edits or deletes BlastGuard metadata.

Claude Code's official contract makes a `PreToolUse` command hook non-blocking if Claude cannot start it or kills it at its timeout. BlastGuard uses an internal five-second watchdog beneath a ten-second Claude timeout so ordinary internal stalls can return blocking status `2`, but this cannot close Claude's outer fail-open boundary. Verify the installed binary path and permissions, inspect `/hooks`, and test a known denial rather than treating configuration presence as proof of enforcement. Organization-managed Claude settings can also constrain which hooks run and take precedence over command-line settings.

Launcher metadata contains only a safe session ID and canonical state-directory path. Hook payload cwd/session/path fields are not trusted for authorization. The hook revalidates the active manifest, source base/cleanliness, canonical worktree ownership, and branch before each policy decision. This validation still cannot eliminate filesystem races after the check.

Use an OS sandbox, least-privilege credentials, repository protections, and human review as independent controls.

Controlled execution currently fails closed on non-Unix platforms because equivalent process-tree termination is not implemented. On supported Unix systems, a reported `termination_complete` means the created process group disappeared after signaling; it does not prove that every descendant remained in that group or that external effects were reversed.
