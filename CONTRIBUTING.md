# Contributing to BlastGuard

BlastGuard is security-sensitive. Keep changes narrow, make conservative behavior explicit, and add adversarial tests for every parser or policy change.

## Local setup

Install the current stable Rust toolchain and Git, then build from the repository root:

```sh
cargo build --locked
```

## Required validation

Run all checks before submitting a change:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
```

Run the disposable end-to-end demonstration as a separate check:

```sh
bash docs/demo.sh
```

The demo creates a temporary repository and does not operate on an existing user repository.

## Dependency review

This repository does not yet run a third-party security action in CI. Maintainers should install the official RustSec client and review the committed dependency graph before a release:

```sh
cargo install cargo-audit --locked
cargo audit
```

Treat audit output as an input to review, not proof that the dependency set is safe. Any future automated dependency scanner must use a reviewed, immutable action reference and a documented configuration.

Policy changes should test the expected decision, rule ID, affected-path handling, override precedence, and both human and JSON redaction where applicable. Parser changes should include malformed syntax, quoting, nesting, wrapper commands, and a benign counterexample to control false positives.

Sandbox lifecycle changes must use temporary repositories with a test-only Git identity. Cover source preconditions, canonical path ownership, manifest transitions, session and repository locking, binary/mode/rename/untracked patches, source drift, acceptance failure, cleanup recovery, and source preservation on reject. Never make lifecycle tests depend on the developer's global Git identity.

Controlled-execution changes must additionally cover all three policy decisions, no-execution proofs, exact worktree cwd, source preservation, cleared-environment behavior, separate concurrent streams, total output caps, terminal sanitization, secret redaction, non-zero exits, timeout/process-group cleanup on Unix, invalid/tampered/inactive/rejected sessions, source/worktree drift, outside-worktree path escalation, and journal minimization. Tests must use short hard-bounded timeouts and clean up their temporary repositories and descendants.

Claude integration changes must be checked against the current official [hooks reference](https://code.claude.com/docs/en/hooks), [CLI reference](https://code.claude.com/docs/en/cli-reference), and [settings precedence](https://code.claude.com/docs/en/settings). Cover fake-child cwd and exact argv preservation, inline settings/exec-form schema, launcher-only context, source preservation, exit propagation, all three policy decisions, malformed/oversized input, missing/locked/drifted/tampered sessions, payload path tampering, hard-block precedence, redaction, and the internal watchdog. Keep a test assertion that public documentation does not describe native Claude Bash as brokered or output-redacted.

## Security expectations

- Never log or place raw credential values in assertions, snapshots, findings, errors, or examples.
- Build synthetic secret fixtures from fragments where possible so test failures do not print reusable-looking values.
- Parse shell structure before applying command policy; do not replace structural parsing with regex matching.
- Malformed, missing, ambiguous, or unsupported input must not become `allow`.
- User configuration must never downgrade a built-in hard block.
- Do not weaken the minimal `sandbox exec` environment, add an inherit-all switch there, reroute native Claude Bash without a separately reviewed design, add telemetry/network reporting, or collect credentials as part of an unrelated change.

Report security issues using the private process in [`SECURITY.md`](SECURITY.md), not a public issue.

## Pull requests

Keep pull requests focused, explain their security impact, and include tests for changed behavior. Confirm that documentation names only commands and guarantees that the implementation provides. Do not include real credentials, private repository content, generated recordings, build artifacts, or local BlastGuard state.
