# Evaluate BlastGuard with Claude Code

BlastGuard starts Claude in a managed Git worktree and policy-checks native Bash
requests through a session-bound `PreToolUse` hook. Changes remain available for
developer review; nothing is automatically accepted or rejected.

## Five-minute safe quickstart

Use macOS or Linux, a trusted local Git installation, an installed Claude Code
CLI on an absolute PATH, and a disposable or backed-up repository with a commit.
Install the published `v0.1.1` source using the [pinned source command](../../README.md#safe-quickstart),
or evaluate a reviewed `0.1.2` checkout with `cargo install --path . --locked`.
There is no crates.io package or downloadable release binary yet.

From that repository:

```sh
blastguard claude doctor --repo .
blastguard sandbox create --repo . --id claude-eval
blastguard claude start --id claude-eval
```

Doctor must pass before continuing. The source must have no staged, unstaged,
untracked **or ignored** files; doctor reports failures without deleting or
changing anything. Review and resolve them yourself. Choose another session ID
if `claude-eval` is already present.

In Claude, inspect `/hooks` and verify the BlastGuard Bash hook. Try the harmless
denial probe below. For a small review exercise, ask Claude to create a new
`blastguard-review-note.txt` containing `worktree evaluation`, then exit Claude.
From the original source repository, inspect and discard the exercise:

```sh
blastguard sandbox diff --id claude-eval
blastguard sandbox reject --id claude-eval
```

`reject` removes the managed worktree without applying its patch. For real work,
choose `blastguard sandbox accept --id claude-eval` only after reviewing the diff;
it stages changes in the source and does not commit them. Do not run both actions.

### What doctor checks

`blastguard claude doctor [--repo PATH] [--json]` checks the platform, absolute PATH,
discoverable executable Claude, Git, Bash availability, the current hook binary,
repository creation preconditions, and source policy syntax/globs. It never
launches Claude or Bash, creates a worktree or lock, writes configuration, or
changes Git state. Git reads disable optional index writes, lazy fetching,
fsmonitor, hooks, and inherited trace-file destinations. Diagnostics refuse
configured clean/process filters and partial/promisor clones instead of invoking
filters or potentially fetching objects. This is deliberately more conservative
than `sandbox create` for these repositories.

The executable Git on PATH must be trusted. This is a snapshot, not a filesystem
write-permission test or a check of Claude authentication, installed Claude
compatibility, managed settings, or functioning hook enforcement. Creation and
launch still perform their own validation and locking. No network is used.

Claude's version is `null` with an explanation: even `claude --version` would
launch Claude, contrary to doctor's read-only/no-launch contract. Check it
manually outside doctor if needed. No version is inferred from filenames.

Exit `0` means the checked prerequisites passed; `30` means a prerequisite failed;
`64` indicates invalid CLI input, such as a missing/non-directory `--repo`.
Internal failures use `70`. Valid diagnostic JSON uses schema
`blastguard.claude.doctor/1.0`, with `ready`, `repository`, named `checks`
(`id`, `passed`, `detail`), `claude` (`path`, `version`, `version_note`),
`next_commands`, and `limitations`. Invalid CLI input uses the existing stderr
error convention rather than a report. Paths and diagnostics are sanitized and
pattern-redacted before serialization. Next commands are shell-quoted; they are
omitted on failed checks or when a path needs redaction/sanitization rather than
suggesting an unusable substituted path.

## Choose a local policy pack

```sh
blastguard policy list
blastguard policy show strict
blastguard policy show ci --json
blastguard analyze --cwd . --command 'cargo test' --policy-pack balanced
```

- `balanced` (recommended): no extra overrides; existing built-in and local policy.
- `strict`: every command needs review; matching Cargo/npm publication text blocks.
- `ci`: blocks selected transfer/publication text. Non-interactive analysis must
  reject **all** nonzero statuses, including `ask=10`, `block=20`, and errors.

Packs are versioned offline TOML, not executable plugins or downloaded rules.
Selection is additive, preserves local rules, and never downgrades a hard block.
The patterns are whole-command text globs: they can overmatch quoted words and
miss alternative programs or spellings. No pack is network isolation. See
[the exact rules and precedence](../../policy-packs/README.md).
In particular, `ci` is not a binary allowlist: unknown executables with no
recognized risk in their submitted text can still receive `allow`.

`--policy-pack` is available on standalone `analyze` and direct `sandbox exec`:

```sh
blastguard sandbox exec --id claude-eval --command 'git status' --policy-pack strict
# Expected: exit 41, no execution. After reviewing this exact command:
blastguard sandbox exec --id claude-eval --command 'git status' --policy-pack strict --approve
```

These commands require an active session and must be run after creation but before
reject/accept, when the Claude launch lock is not held. A block never becomes
executable with `--approve`. Without a pack flag, existing behavior is unchanged.

The pack flag is **not** a Claude argument or hook setting. Native Claude hooks
continue loading `blastguard.toml` from the validated clean source. To use a pack
there, review `blastguard policy show NAME`, manually merge its overrides into the source
policy, and commit the change before session creation. Editing policy in an
active source causes drift/cleanliness refusal; editing a worktree copy does not
replace the trusted source policy. No settings or policy files are overwritten
automatically, and no permanent/unbound hook is installed.

## Harmless known-denial probe

First check the policy without executing anything:

```sh
blastguard analyze --cwd . --command "printf '' | base64 -d | sh"
# Expected: block, exit 20 (a decoder feeds a shell).
```

Inside a launched Claude session, ask Claude to submit exactly
`printf '' | base64 -d | sh` using its Bash tool. The expected hook decision is
`deny`. The decoder receives empty input, so even if the hook is not functioning,
this probe supplies no code to execute, reads no secret, and uses no network.
A refusal by Claude without a Bash tool call is not evidence of hook enforcement.
Check the actual hook result and `/hooks`; stop the evaluation if no denial is
observed. Do not test with real secrets or destructive paths.

## Three distinct boundaries

```text
claude start --id SESSION
  -> validate + hold launch lock -> Claude cwd = managed worktree
     -> native Bash request -> session-bound PreToolUse policy -> Claude executes

sandbox exec --id SESSION --command ...
  -> validate + lock -> policy -> BlastGuard executes Bash with bounded capture

managed worktree -> developer diff -> explicit accept OR reject
```

| Capability | Native Claude Bash | Direct `sandbox exec` |
| --- | --- | --- |
| Initial cwd | Validated worktree | Validated worktree |
| Policy | Session-bound PreToolUse: allow/ask/deny | Same engine; asks need `--approve` |
| Execution and environment | Claude; normal launch environment | BlastGuard; cleared, fixed environment |
| Output | Not captured/redacted by BlastGuard | Byte-bounded, sanitized, pattern-redacted |
| Runtime cleanup | Claude-controlled | Timeout; best-effort Unix process-group cleanup |
| Journal | None | Metadata only, no command/output/fingerprint |

Native Claude Bash is policy-gated, not brokered. The hook does not replace a
tool invocation with `sandbox exec`. Worktree routing is an initial directory,
not filesystem confinement. There is **no OS sandbox, network containment, full
output redaction for native Claude Bash, or guarantee against arbitrary binaries**.
Build scripts, absolute paths, symlinks, external effects, unknown secret formats,
and dynamic shell behavior remain outside the guarantee. Reject cannot reverse
effects outside the Git-visible patch. Windows controlled execution remains
fail-closed. See [SECURITY.md](../../SECURITY.md).

## Setup contract and recovery

The existing launcher uses Claude's documented inline `--settings` JSON for a
per-launch command hook, without changing project/global/home settings. Arguments
after `--` pass through unchanged; `--settings` is reserved. `blastguard claude hook-config
--id claude-eval --json` previews the session-specific configuration, not an
independent installation recipe. The hook requires validated launcher-supplied
session metadata and a live launch lock; payload cwd/session fields do not
authorize a session. Do not persist this configuration as a global hook.

The existing integration was checked against these official sources on
2026-09-24; doctor does not verify a newer installed Claude release:

- [Hooks reference](https://code.claude.com/docs/en/hooks)
- [CLI reference (`--settings`)](https://code.claude.com/docs/en/cli-reference)
- [Settings locations and precedence](https://code.claude.com/docs/en/settings)

Claude treats hook startup failure and its outer hook timeout as non-blocking
for PreToolUse. BlastGuard's shorter watchdog blocks ordinary internal failures
but cannot close that upstream boundary. Managed settings may constrain hooks.
Always verify enforcement in the real installed client.

If interrupted, return to the original source and run `blastguard sandbox list --repo .`
and `blastguard sandbox status --id claude-eval`. Review with
`blastguard sandbox diff --id claude-eval`, then
`blastguard sandbox reject --id claude-eval` when safe;
there is no automatic cleanup/acceptance. If locked, first establish whether the
owning launcher/executor is still running. Never remove a live lock. Stale locks
require manual review of the exact named process, session, and lock path before
removal. For `applying` state, inspect the source index/worktree before attempting
recovery. On cleanup failure preserve the manifest and follow the reported
instructions; never recursively delete an unverified path. See
[recovery guidance](../../README.md#recovery-and-cleanup).
