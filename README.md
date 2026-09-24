# BlastGuard

BlastGuard is a local Rust CLI that policy-checks Bash commands and keeps AI-assisted changes in reviewable, disposable Git worktrees.

It exists because a clean Git diff and a shell safety check solve different problems. BlastGuard combines both with an explicit developer decision: inspect the patch, then accept or reject it. It is a command guardrail and Git workflow—not an OS sandbox, secret vault, or complete agent-security solution.

## The three-layer model

| Layer | What it provides | What it does not provide |
| --- | --- | --- |
| Policy gate | Structural Bash analysis; `allow`, `ask`, or `block`; non-overridable hard blocks | Proof of arbitrary program behavior or fully dynamic shell behavior |
| Git worktree isolation | A separate working tree and reviewable patch | Filesystem, process, network, or kernel isolation |
| Developer approval | Explicit `diff`, `accept`, or `reject` lifecycle | Automatic assurance that a change is safe or correct |

## Safe quickstart

Prerequisites: stable Rust, Git, and a clean Git repository with at least one commit.

Install from this checkout; BlastGuard has not been published to crates.io:

```sh
cargo install --path . --locked
blastguard --version
```

From a disposable or backed-up clean repository:

```sh
blastguard analyze --command "cargo test" --cwd .
blastguard sandbox create --repo . --id review-1
blastguard sandbox exec --id review-1 --command "git status --short"
blastguard sandbox diff --id review-1
blastguard sandbox reject --id review-1
```

To see the complete lifecycle without touching an existing repository, run [`docs/demo.sh`](docs/demo.sh). It creates and removes its own temporary Git repository.

## Typical review flow

```console
$ blastguard sandbox create --repo . --id review-1
╭─ Sandbox Created ───────────────────────────────────────
│ Session    review-1
│ Worktree   .../.blastguard-worktrees/.../review-1
╰─────────────────────────────────────────────────────────

$ blastguard sandbox exec --id review-1 --command "printf 'reviewed\n' > note.txt"
BlastGuard execution decision
Session: review-1
Policy decision: allow
Scope warning: Git-isolated, not OS-sandboxed. ...
BlastGuard execution result
State: completed

$ blastguard sandbox diff --id review-1
diff --git a/note.txt b/note.txt
new file mode 100644
...

$ blastguard sandbox accept --id review-1
```

`accept` stages the reviewed worktree snapshot in the source repository; it does not create a commit. Use `reject` instead to remove the managed worktree without applying its patch.

## Claude Code integration

BlastGuard can launch an installed Claude Code CLI in a validated worktree and install a session-scoped `PreToolUse` hook without editing project, user, or global settings:

```sh
blastguard sandbox create --repo . --id claude-review
blastguard claude hook-config --id claude-review --json
blastguard claude start --id claude-review -- --model sonnet
blastguard sandbox diff --id claude-review
# Choose exactly one after review:
blastguard sandbox accept --id claude-review
# blastguard sandbox reject --id claude-review
```

Arguments after `--` are passed to Claude in their original order. BlastGuard reserves Claude's `--settings` argument because it supplies an inline, per-launch hook configuration using Claude's documented settings mechanism. The launcher passes only the session ID and canonical state-directory path to the hook, keeps a launch lock while Claude runs, preserves Claude's numeric exit status, and never auto-accepts or auto-rejects.

The implementation was checked on 2026-09-24 against the official Claude Code documentation:

- [Hooks reference](https://code.claude.com/docs/en/hooks): `PreToolUse`, Bash input, permission decisions, command-hook configuration, exit status, and timeout behavior.
- [CLI reference](https://code.claude.com/docs/en/cli-reference): the session-scoped `--settings` argument.
- [Settings reference](https://code.claude.com/docs/en/settings): settings locations and precedence.

Confirm the generated hook in Claude's `/hooks` view and manually test a known denial before relying on it. Claude documents hook process-start failure and hook timeout as non-blocking for `PreToolUse`; BlastGuard's shorter internal watchdog can fail closed for its own ordinary failures, but cannot close that upstream boundary.

### Native Claude hook versus `sandbox exec`

| Capability | Native Claude hook mode | `sandbox exec` mode |
| --- | --- | --- |
| Worktree routing | Claude starts in the validated worktree | Bash starts in the validated worktree |
| Policy gate | `PreToolUse` returns `allow`, `ask`, or `deny` | Same engine; `ask` also requires `--approve` |
| Executor | Claude Code | BlastGuard |
| Environment | Claude's launch environment | Cleared, fixed minimal environment |
| Output controls | None provided by BlastGuard | Combined byte limit, sanitization, pattern redaction |
| Runtime controls | Claude-controlled | Timeout and best-effort Unix process-group cleanup |
| Journal | None | Metadata only; no command or output text |

Native Claude Bash is policy-gated, not brokered. Claude's hook contract does not let BlastGuard rewrite the tool invocation into `sandbox exec`. BlastGuard does not capture, bound, sanitize, journal, or redact Bash output when Claude executes Bash natively.

## Command reference

```text
blastguard analyze --command <shell> --cwd <path> [--json]
blastguard sandbox create [--repo <path>] [--id <session-id>]
blastguard sandbox status --id <session-id> [--json]
blastguard sandbox diff --id <session-id> [--json]
blastguard sandbox exec --id <session-id> --command <shell> [--approve]
                        [--timeout-seconds <1..300>]
                        [--max-output-bytes <1..16777216>] [--json]
blastguard sandbox accept --id <session-id>
blastguard sandbox reject --id <session-id>
blastguard sandbox list [--repo <path>] [--json]
blastguard claude start --id <session-id> [-- <claude arguments...>]
blastguard claude hook-config --id <session-id> [--json]
blastguard claude hook
```

`sandbox exec` runs `/bin/bash` or `/usr/bin/bash` with startup files disabled, a cleared environment, a 60-second default timeout, and a 1 MiB default combined output limit. It executes `ask` decisions only with `--approve`; it never executes a `block`. The working directory, minimal environment, limits, and process group reduce exposure but do not confine the command.

Run lifecycle commands from the source repository or one of its Git worktrees. Creation rejects dirty repositories, ignored files, submodules, nested repositories, sparse checkouts, linked-worktree sources, symlinked repository paths, separate Git directories, and unresolved `HEAD` states.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success or policy `allow` |
| `10` | Policy `ask` |
| `20` | Policy `block` |
| `30` | Repository precondition or invalid sandbox ID |
| `31` | Missing, duplicate, invalid, tampered, or stale session state |
| `32` | Active or stale session/repository lock |
| `33` | Source repository changed since session creation |
| `34` | Git operation, patch application, or conservative cleanup failure |
| `40` | Execution blocked; no child started |
| `41` | Execution needs `--approve`; no child started |
| `42` | Child returned non-zero |
| `43` | Execution timed out; cleanup attempted |
| `44` | Output limit reached; cleanup attempted |
| `64` | Invalid input, path, or configuration |
| `70` | Internal error |

`claude hook` returns Claude's documented decision JSON. An `allow` or `ask` response exits `0`; `deny`, malformed input, invalid session context, and internal failure exit `2`. After a successful launch, `claude start` propagates Claude's numeric exit code; on Unix, a signal is mapped to `128 + signal`.

## Policy and configuration

BlastGuard parses Bash with `tree-sitter-bash` and recursively covers chains, pipelines, redirects, command substitutions, subshells, process substitutions, and supported `sh -c`/`bash -c` payloads. Parse errors, missing nodes, malformed syntax, unsupported constructs, and unresolved dynamic behavior become `ask`, not `allow`.

By default, BlastGuard loads `blastguard.toml` from the analyzed directory. Select another file with global `--config <path>`. Rules match the whole command using shell globs. Precedence is fixed:

1. built-in hard blocks;
2. user `block` rules;
3. user `ask` rules;
4. user `allow` rules;
5. default built-in policy.

The safest matching user rule wins. An allow rule may suppress an ordinary built-in `ask`, but cannot downgrade a hard block such as recognized secret exfiltration, recursive forced deletion, or decode-and-execute behavior. See [`blastguard.example.toml`](blastguard.example.toml).

## Security boundaries

BlastGuard can make these limited guarantees when its preconditions hold:

- the submitted shell text receives a structural policy decision before BlastGuard-brokered execution or a functioning Claude hook decision;
- built-in hard blocks cannot be overridden by user allow rules;
- managed lifecycle operations revalidate session ownership, canonical paths, Git branch, source cleanliness, and base commit;
- `reject` does not apply the managed worktree patch to the source;
- recognized secrets are pattern-redacted from BlastGuard-rendered text and JSON;
- the execution journal stores metadata, not raw commands, raw output, or command fingerprints.

BlastGuard cannot guarantee containment or complete detection. It does not protect against arbitrary or compromised binaries, malicious repositories or build scripts, kernel-level attacks, privilege escalation, filesystem races after validation, dynamic shell behavior, unknown secret formats, commands run outside the hook, or effects outside Git-visible worktree state. Absolute paths, `cd`, symlinks, child processes, network access, platform credential stores, and Git filters remain possible. Reject cannot undo external writes, requests, processes, ignored files, or credential access.

The redactor and sensitive-path rules are defense in depth, not a secret vault. Git worktrees are a review and rollback mechanism, not an OS isolation boundary. Use least-privilege credentials, an independent OS sandbox where appropriate, repository protections, and human review.

See [the architecture](docs/architecture.md) for component and data-flow details and [the security policy](SECURITY.md) for the full threat boundary and private-reporting guidance.

## Recovery and cleanup

- If a lock is reported stale, inspect the named process/session and repository before manually removing any lock. BlastGuard never removes stale locks automatically.
- If a session is left in `applying`, inspect the source index and worktree; BlastGuard cannot safely infer whether a crash occurred before or after Git changed the source.
- If reject cleanup fails, keep the manifest and follow the printed recovery instruction. Do not recursively delete an unverified path.
- To remove an active session safely, run `blastguard sandbox reject --id <session-id>` from its repository.
- To uninstall a locally installed binary, remove the `blastguard` executable from the Cargo install root you used. BlastGuard does not install a daemon, service, shell profile, or global configuration.

## Project documents

- [Architecture](docs/architecture.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Release checklist](RELEASE_CHECKLIST.md)
- [Apache License 2.0](LICENSE)

BlastGuard is licensed under the Apache License, Version 2.0. No public package or GitHub release is claimed by this repository state.
