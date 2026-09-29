# Changelog

All notable changes to BlastGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-28

Release preparation date. These changes are implemented in the repository;
the `v0.1.1` tag and release have not been published.

### Added

- Read-only `claude doctor` readiness checks, actionable next commands, and a versioned, redacted JSON report. Doctor does not launch Claude, create sessions, or modify repository state.
- Opt-in, offline `balanced`, `strict`, and `ci` policy packs, with `policy list` / `policy show` discovery and additive selection for `analyze` and `sandbox exec`. Built-in hard blocks remain non-overridable.
- A focused Claude Code onboarding guide covering session-bound hooks, harmless denial checks, review, cleanup, and the distinction between native Claude Bash and brokered execution.
- A first-party composite GitHub Action for static analysis of supplied Bash text, with decision/status outputs, explicit failure thresholds, and optional redacted JSON reports. The supplied command is never executed or intercepted.
- GitHub-hosted Ubuntu end-to-end coverage using the real local action and fresh Cargo caches: allow, both ask thresholds, block, non-execution, redacted reports, and missing-cache failure. The [merged 5B revision passed all seven cases](https://github.com/Vansh0Sharma/blastguard/actions/runs/36446270753); the release-preparation revision must pass again before tagging.

### Changed

- Documented the Action's prerequisite-based installation model: stable Rust/Cargo, a C compiler, and dependencies populated from the pinned lockfile with `cargo fetch --locked` before its offline build. It is not a standalone action; missing prerequisites fail with `error/70` and setup guidance.

### Fixed

- Unix timeout cleanup targets the dedicated process group and checks for remaining descendants; a Linux regression test verifies that a background descendant cannot perform its post-timeout side effect.
- Linux doctor-test fixture stability, with repository/Git metadata snapshots checking that diagnostics leave source state unchanged.

## [0.1.0] - Unreleased

Historical implementation baseline; this version was not tagged or published.

### Added

- Tree-sitter-based Bash analysis with fail-closed handling for malformed, incomplete, and unsupported syntax.
- Built-in policy findings for destructive commands, sensitive paths, secret exfiltration, encoded execution, and network activity.
- Non-overridable hard blocks and configurable block, ask, and allow rules with conservative precedence.
- Secret-pattern redaction for human output, JSON, errors, Claude hook responses, and captured command streams.
- Managed ephemeral Git worktree creation, status, diff, acceptance, rejection, and session listing.
- Controlled `sandbox exec` with explicit approval, a minimal environment, bounded output, timeouts, Unix process-group cleanup, and metadata-only journals.
- Claude Code worktree launch and session-bound `PreToolUse` Bash policy integration.
- Adversarial unit and integration tests covering parser, policy, lifecycle, execution, redaction, and Claude integration behavior.

### Security

- Active sessions are revalidated before lifecycle changes, controlled execution, Claude launch, and every Claude hook decision.
- Legacy unkeyed command fingerprints are removed when version 1 journals are migrated to journal schema version 2.
- BlastGuard documents Git rollback, hook timeout, native Claude execution, dynamic shell, malicious repository, and OS-isolation limitations explicitly.
