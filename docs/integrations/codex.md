# Codex: experimental compatibility foundation

BlastGuard 6A provides offline diagnostics and an internal protocol adapter.
It is **not a supported native Codex integration**. There is no
`blastguard codex start`, `blastguard codex hook-config`, plugin bundle,
installation, or automatic user/project/global settings write.

## Read-only diagnostics

```sh
blastguard codex doctor --repo .
blastguard codex doctor --repo . --json
```

Doctor checks executable discovery, local prerequisites, source cleanliness and
policy configuration using the existing hardened Git-read path. Codex is never
executed, including for `--help` or `--version`; no Bash command, worktree,
session, lock, plugin or configuration is created. No network requests are made.
Trusted Git is required. Optional index writes, hooks, fsmonitor, lazy fetching
and inherited trace-file destinations are disabled. Configured clean/process
filters and partial/promisor clones are refused before cleanliness inspection.

JSON schema `blastguard.codex.doctor/1.0` contains `schema_version`,
`prerequisites_passed`, `compatibility`, `repository`, `checks`, `codex`, and
`limitations`. Each check has `id`, `passed`, and `detail`. `codex` contains
`found`, `path`, `version`, and `discovery`. `compatibility` is always
`unverified`, and `version` is always null. Discovery checks filesystem metadata;
it does not verify executable identity, runtime behavior, authentication, or
hook trust. Dynamic strings are sanitized and pattern-redacted before JSON
serialization. No credentials are reported.

Exit codes: `0` means only local prerequisites passed; `30` means a prerequisite
failed; invalid CLI input or a nonexistent repository directory returns `64`.
Unexpected operational errors use the existing error conventions. Errors are
sanitized on stderr; invalid CLI input does not produce a JSON report.

## Internal adapter, not an installation recipe

`blastguard codex hook` reads one bounded JSON request on stdin. It is hidden
from normal command help. Do not configure it as a persistent Codex hook.

The internal evaluator uses the existing policy engine and source configuration
with a validated session lease. It cannot execute or rewrite command text.
Offline mapping is:

| Policy result | Adapter response |
| --- | --- |
| `allow` | `permissionDecision: "allow"` |
| `ask` | `permissionDecision: "deny"`; developer review required |
| `block` | `permissionDecision: "deny"`; no override |

Decision responses use only `hookSpecificOutput`, `hookEventName`,
`permissionDecision`, and a fixed sanitized `permissionDecisionReason`.
Successful decision JSON uses exit `0`. Protocol/context/internal errors use
exit `2` and sanitized stderr, without echoing input or findings. The five-second
internal deadline includes stdin reading, parsing and session validation; the
input limit is 1 MiB. This does not establish upstream timeout behavior.

The adapter requires the proposed `BLASTGUARD_CODEX_SESSION_ID`,
`BLASTGUARD_CODEX_STATE_DIR`, and `BLASTGUARD_CODEX_LAUNCH_ID` context variables.
It never selects state from payload cwd/session/transcript/model fields. Existing
session ownership, manifest, source drift, active-state and path/lock validation
are reused by the private offline test path. The CLI rejects an unverified live
binding before accessing session state, acquiring locks, or invoking Git.

**Environment variables alone are not a trusted launch binding.** There is no
trusted Codex launcher or live-binding issuer in this milestone. Consequently,
the CLI hook always fails closed, even when all three variables name an otherwise
valid session. There is no test-only CLI switch, fabricated lock/marker protocol,
or production environment bypass. Only offline tests pass validated leases
directly to the private evaluator to exercise the three mappings.

Synthetic [versioned fixtures](../../tests/fixtures/codex/v1/README.md) document
the intentionally strict request subset. They are not authenticated runtime
captures or proof that Codex loads, trusts, or enforces this adapter.

## Manual worktree-only evaluation

The available workaround is manually running Codex from a BlastGuard-managed
worktree. **This provides no BlastGuard hook policy gating, launch lock, native
output capture/redaction, OS sandbox, or network containment.** No authenticated
Codex runtime test was performed for this milestone.

From a clean disposable source repository:

```sh
blastguard sandbox create --repo . --id codex-review
blastguard sandbox status --id codex-review --json
```

Copy the exact `worktree_path` from status. If you independently choose to use
Codex, open a terminal in that directory and run your installed `codex` there.
Do not change to the source checkout or create a second Codex-managed worktree.
The adapter above is not installed or active in this manual workflow.

After Codex and its background work have stopped, return to the source directory:

```sh
blastguard sandbox diff --id codex-review
blastguard sandbox reject --id codex-review
```

Choose `blastguard sandbox accept --id codex-review` **instead of reject** only
after reviewing the complete diff; accept stages the snapshot, not a commit.
For interrupted evaluation, inspect `sandbox list` and `sandbox status`, stop
remaining processes, then review and reject. Do not delete lock/state files
blindly or accept/reject while Codex is still running.

An initial directory is not confinement. Arbitrary binaries, dynamic shell
behavior, absolute paths, symlinks and network requests can affect resources
outside the worktree. Reject cannot undo those effects. Windows controlled
execution remains fail-closed. See [SECURITY.md](../../SECURITY.md).

## Runtime compatibility gates

The official [hook contract](https://learn.chatgpt.com/docs/hooks), verified
2026-09-29, documents `PreToolUse` for Bash but does not support its `ask` decision:
that response can fail non-blockingly. Installing a hook is not proof of trust.
Follow-on `write_stdin` input is not rechecked. These facts prohibit claiming a
complete enforcement boundary.

Before any launcher is implemented, establish a tested runtime/version contract
for trusted context transport, effective shell/cwd, hook loading and trust,
multiple-hook composition, and startup/error/timeout handling. Tests using fake
executables cannot prove these properties in Codex. Native output capture and
redaction are not provided; the separate `sandbox exec` broker is unchanged.
No approval/trust bypass flags or shell-interception wrappers are proposed.
