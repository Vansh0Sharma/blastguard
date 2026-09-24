# Changelog

All notable changes to BlastGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

This version has not been tagged or published.

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
