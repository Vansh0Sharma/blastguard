# Static policy checks in GitHub Actions

The first-party composite action analyzes one supplied Bash command string with
`blastguard analyze`. It **never executes that command**, intercepts another
step, creates a sandbox, invokes Git, or launches Claude. No Marketplace listing
or published release is implied.

## Prerequisites and pinning

**Supported installation model: prerequisite-based (Option A), not standalone.**
An unprepared `uses:` step on a fresh runner is expected to fail: offline builds
cannot fetch missing dependencies or install missing toolchains. The complete
workflow below explicitly provisions both before invoking BlastGuard.

Use a trusted Linux or macOS runner with Bash, stable Rust/Cargo, a C compiler,
and the source dependencies from the pinned action's `Cargo.lock` already cached
in Cargo's normal cache. Windows action execution fails closed.

The action copies its Rust source and policy packs from `GITHUB_ACTION_PATH` to
a private runner-temporary directory and builds there with
`cargo build --locked --offline`. It does not use a global BlastGuard binary,
download a binary/toolchain, use `jq`, or make product network/telemetry calls.
Missing prerequisites/cache entries fail with `decision=error`, `exit-code=70`.
Provision them separately; a fresh hosted runner will normally need a dependency
fetch first. Build tools, cached dependencies and global Cargo configuration must
be trusted. The analyzed checkout's `.cargo/config` is not used for this build.

Pin BlastGuard to a reviewed **full commit SHA**, or a release tag once one
actually exists, never an unpinned branch. Full SHAs are preferable because tags
can move. The examples pin the merged, hosted-tested 5B implementation at
`cb28ed1af6337e7b463cb18ce977896b2b4eba0e`, before the `0.1.1` metadata update.
`v0.1.1` is the upcoming stable release tag, **not an available tag yet**. Use
`Vansh0Sharma/blastguard@v0.1.1` only after the owner publishes that release;
prefer its reviewed full commit SHA for an immutable release pin. Update both
the dependency-preparation checkout and action reference together.

## Minimal workflow

This complete example separates network-enabled source/dependency preparation
from the offline action. The second checkout pins the action independently of
the project under review. The checkout action itself is also SHA-pinned.

```yaml
name: Static command policy
on: [push, pull_request]

permissions:
  contents: read

jobs:
  policy:
    runs-on: ubuntu-latest
    env:
      RUSTUP_TOOLCHAIN: stable
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: Vansh0Sharma/blastguard
          ref: cb28ed1af6337e7b463cb18ce977896b2b4eba0e
          path: .github/actions/blastguard
          persist-credentials: false
      - name: Install the compiler and stable Rust toolchain
        working-directory: ${{ runner.temp }}
        run: |
          sudo apt-get update
          sudo apt-get install --yes --no-install-recommends build-essential
          command -v rustup >/dev/null
          rustup toolchain install stable --profile minimal
          rustc --version
          cargo --version
          cc --version
      # This explicit setup step may contact the Cargo registry; the action won't.
      - name: Prepare the pinned source dependencies
        working-directory: ${{ runner.temp }}
        run: cargo fetch --locked --manifest-path "$GITHUB_WORKSPACE/.github/actions/blastguard/Cargo.toml"
      - uses: ./.github/actions/blastguard
        id: policy
        with:
          command: 'cargo test'
```

On runners already provisioned with the matching dependencies, the normal remote
form is also supported, without the second checkout or fetch step:

```yaml
- uses: Vansh0Sharma/blastguard@cb28ed1af6337e7b463cb18ce977896b2b4eba0e
  with:
    command: 'cargo test'
```

Neither example actually runs `cargo test`. Protect this workflow and any local
`blastguard.toml` with code review; do not grant write credentials to untrusted
pull-request code. No write permission or token input is needed by BlastGuard.

These provisioning commands target GitHub-hosted Ubuntu, which supplies `sudo`
and `rustup`; they explicitly install/check the required compiler and toolchain
rather than assuming the image's default Rust version. On another runner, first
provision a trusted rustup installation and native compiler using your platform's
approved process. Setup downloads use the OS package manager, rustup and Cargo;
they happen outside the offline action. Keep `RUSTUP_TOOLCHAIN: stable` for both
fetch and action build. Cache restoration is optional: correctness does not
depend on an earlier workflow run.

If the action reports an offline source-build error, verify Rust/Cargo and `cc`
are available and run `cargo fetch --locked` against the **same action revision's**
manifest using the **same `CARGO_HOME`** as the action. The action deliberately
does not retry online or fall back to a global binary. A source/compiler failure
after prerequisites are satisfied is also an error; diagnose that build in a
separate trusted setup step, not by exposing arbitrary stderr through outputs.

## Hosted end-to-end verification

[`action-e2e.yml`](../../.github/workflows/action-e2e.yml) runs on `ubuntu-latest`
and uses `uses: ./` from the exact checkout under test. Every matrix job starts
with a new, empty Cargo cache (no cache restore), explicitly provisions the
toolchain/compiler above, and fetches locked source dependencies. One negative
job intentionally omits the fetch and must return `error/70` with a failed step.
The others check allow, both ask thresholds, block, command-substitution and
redirection non-execution, and owner-only redacted report creation.

Only the test harness uses `continue-on-error`: an always-running verifier checks
the raw `steps.analysis.outcome`, exact declared outputs, absence of execution
markers, and report bytes. An unexpected failure or success fails the job. A
green run is evidence for that exact commit, not a Marketplace/release claim.

## Inputs and results

| Input | Default | Meaning |
| --- | --- | --- |
| `command` | Required | Nonempty Bash text, at most 64 KiB; quotes/newlines/substitutions are data |
| `working-directory` | `.` | Existing directory relative to `GITHUB_WORKSPACE` |
| `policy-pack` | Empty | Existing policy, or additive `balanced`, `strict`, `ci` rules |
| `fail-on` | `block` | `block` or `ask`; errors always fail |
| `report-path` | Empty | Optional **new** JSON file relative to `working-directory` |

| Analysis | `decision` output | `exit-code` output | `fail-on: block` | `fail-on: ask` |
| --- | --- | ---: | --- | --- |
| Allow | `allow` | `0` | Success | Success |
| Needs review | `ask` | `10` | Success | Failure |
| Blocked | `block` | `20` | Failure | Failure |
| Invalid input/configuration | `error` | `64` | Failure | Failure |
| Build, adapter or report failure | `error` | `70` | Failure | Failure |

Unexpected analyzer statuses remain errors, with their numeric status if
available. A signal/missing status becomes `70`. Malformed JSON, schema mismatch,
or disagreement between JSON decision and process status becomes an error, never
an allowed decision. Captured JSON is limited to 8 MiB. `exit-code` is the analysis
or error status, **not** the final step status: an ask with `fail-on: block` emits
`10` but succeeds. Do not use `continue-on-error` if this must be a required check.
Missing/unwritable GitHub output metadata can prevent outputs from being emitted;
the step still fails. Outputs contain no command text, findings or full JSON.

### Fail on review-required decisions

```yaml
- uses: ./.github/actions/blastguard
  with:
    command: 'curl https://example.invalid'
    fail-on: ask
```

Expected: `ask`, exit-code `10`, failed step. No network request is made.

### Strict pack and a redacted report

```yaml
- uses: ./.github/actions/blastguard
  id: strict_policy
  with:
    command: 'cargo test'
    policy-pack: strict
    fail-on: ask
    report-path: reports/blastguard.json
```

Expected: `ask`, failed step, and a written JSON report. `strict` asks for every
command and blocks selected publication text; it is intentionally conservative.
`balanced` adds no rules. `ci` blocks selected transfer/publication text; use
**`fail-on: ask` with `ci`** to meet that pack's intended non-interactive policy.
Packs add to `blastguard.toml` in the selected working directory. No pack or local
allow rule can downgrade built-in hard blocks. Unselected packs do not change
existing policy. See [pack limitations](../../policy-packs/README.md).

A harmless known block is `printf '' | base64 -d | sh`: it produces a blocked
static decision. The action never runs it, even with `fail-on: block`.

## Report and filesystem boundaries

Reports contain only the existing redacted analysis JSON, schema `1.0`. This
includes a pattern-redacted command field; ordinary non-secret command text
remains visible **in the requested report**, never in action outputs or logs.
Reports are written even for ask/block decisions. On analysis/input errors there
is no report. Raw subprocess stderr is discarded and diagnostics are fixed text.

Both path inputs reject absolute paths, `..`, `.git` components, control characters,
Windows-style separators/drive paths, and values requiring redaction. Working
directories and report parents may not traverse symlinks, even to internal
destinations. Existing report files/directories and dangling/final symlinks are
refused, never overwritten. Symlinked/special-file local policy is also refused.
Keep the workspace and configuration stable during the action: concurrent
filesystem replacement, mount changes, and a hostile runner are outside this
boundary, not an OS-isolation guarantee.

Missing report parents are created. Complete JSON is written to an owner-only
temporary file, synchronized, then atomically published using a same-directory
no-clobber hard link and temporary-file removal. Filesystems without hard-link
support fail closed. `report-path` is emitted only after successful publication,
as a workspace-relative path (for example `project/reports/check.json` when the
working directory is `project`). No report is uploaded automatically. Choose a
fresh destination for each invocation; remove reviewed artifacts in a separate
explicit workflow step. A failure can leave newly created parent directories;
an interruption can leave a temporary file or completed report, without an output.

## Non-goals

- Static analysis only: does not execute or intercept commands or inspect runner
  secret/environment values. Only named action inputs and required runner file
  locations are read; the analysis child gets a cleared environment.
- Does not sandbox or contain the runner, restrict network access by other
  workflow steps/build tools, or prove arbitrary binary/dynamic-shell behavior.
- Does not protect secrets already available to the workflow. Do not submit real
  credentials: GitHub or other workflow steps can log inputs independently, and
  pattern redaction cannot recognize all secret formats.
- Does not replace local Claude Code `PreToolUse` protection or session binding.
  It provides neither Git rollback nor `sandbox exec` runtime/output controls.

The action only gates the text explicitly supplied to it. It does not scan a
workflow or establish that a later step executes the same text. See
[SECURITY.md](../../SECURITY.md).

Implementation references: [GitHub composite-action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax),
[GitHub output files](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#setting-an-output-parameter),
and [Cargo offline/locked builds](https://doc.rust-lang.org/cargo/commands/cargo-build.html).
