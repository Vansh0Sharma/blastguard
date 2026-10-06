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
cargo build --release --locked
git diff --check
```

Run the disposable end-to-end demonstration as a separate check:

```sh
bash docs/demo.sh
```

The demo creates a temporary repository and does not operate on an existing user repository.

## Distribution validation (no publication)

The CLI is the supported interface; public Rust modules are implementation
details, not a stable library API. Do not change runtime behavior as part of a
packaging-only patch. Keep `Cargo.toml`'s include rules and
`scripts/package-files.txt` synchronized, including compile-time fixtures and
policy packs. Python 3's standard library is sufficient for distribution checks:

```sh
python3 -B -m unittest discover -s tests -p distribution_test.py
```

Follow [the disposable package procedure](docs/distribution.md#source-package-validation)
to package, dry-run, test the extracted crate, and install into a temporary root.
Never bypass Cargo checks with `--allow-dirty` or `--no-verify`. No credentials
are needed for the intended preparation path; if a registry requests them,
stop and record an owner gate rather than logging in.

The separate manual `Release verification` workflow tests the selected commit
on native Linux x86_64, macOS arm64, and macOS Intel. It compares two clean-target
builds and verifies disposable candidate archives. It does not publish, upload
assets/attestations, or establish general reproducibility. Ordinary CI and the
static Action's offline prerequisites are unchanged. Mach-O UUID differences
(plus verified signature-page hash differences when present) produce a visible,
non-blocking **unresolved** diagnostic requiring owner review before public
binaries. Other differences or
unknown/invalid metadata remain blocking; Linux still requires exact bytes.
Never remove UUIDs/signatures or normalize artifacts to manufacture equality.
Naturally unsigned Intel files may differ only in UUID bytes after layout
validation; ARM64 still requires a valid signature. A malformed present signature
must never fall back to unsigned handling, even for byte-identical inputs.

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

GitHub Action changes are covered by `cargo test --test github_action_cli` and
the internal adapter unit tests. Keep input interpolation out of shell source,
forward Bash text as one argv value, preserve exit/JSON agreement checks and
non-overridable hard blocks, and test no-execution markers, source preservation,
redaction, output allowlisting and path-escape/no-clobber failures. Bootstrap
tests use a fake Cargo that copies the already-built test binary. The
`Action end-to-end` workflow must also pass on the exact proposed revision: it
provisions Rust/compiler prerequisites, starts with an empty Cargo cache, fetches
locked dependencies, and exercises the real `uses: ./` composite action. Its
missing-cache negative test must fail with `error/70`, not silently fetch online.
Do not introduce network-enabled build fallback,
global-binary fallback, workflow timeouts, uploads or runner-environment dumps.

## Security expectations

Onboarding checks are covered by `cargo test --test onboarding_cli`. Doctor tests
must snapshot repository/Git metadata and prove no Claude launch, filter execution,
configuration write, or optional index/trace write. Keep stable JSON schema and
redacted/control-safe diagnostic tests. Embedded policy pack changes must remain
valid existing-format TOML, test default equivalence and additive precedence,
and never introduce an allow rule. Test hard blocks with broad user allow rules
and prove denied/ask broker commands do not execute. Do not install persistent
hooks or change launcher session binding to select a pack.

- Never log or place raw credential values in assertions, snapshots, findings, errors, or examples.
- Build synthetic secret fixtures from fragments where possible so test failures do not print reusable-looking values.
- Parse shell structure before applying command policy; do not replace structural parsing with regex matching.
- Malformed, missing, ambiguous, or unsupported input must not become `allow`.
- User configuration must never downgrade a built-in hard block.
- Do not weaken the minimal `sandbox exec` environment, add an inherit-all switch there, reroute native Claude Bash without a separately reviewed design, add telemetry/network reporting, or collect credentials as part of an unrelated change.

Report security issues using the private process in [`SECURITY.md`](SECURITY.md), not a public issue.

## Pull requests

Keep pull requests focused, explain their security impact, and include tests for changed behavior. Confirm that documentation names only commands and guarantees that the implementation provides. Do not include real credentials, private repository content, generated recordings, build artifacts, or local BlastGuard state.
