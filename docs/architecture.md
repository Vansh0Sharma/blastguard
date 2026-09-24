# BlastGuard architecture

BlastGuard combines three independent controls: a command-policy gate, disposable Git worktrees, and an explicit developer decision to accept or reject changes. These controls reduce common local-development risks; they do not create an operating-system isolation boundary.

## Data flow

```text
command or Claude Bash request
             |
             v
  tree-sitter Bash parser ---- malformed or unresolved ----> ask
             |
             v
  built-in policy + config precedence
             |
       allow / ask / block
             |
      +------+-------------------+
      |                          |
      v                          v
native Claude Bash        sandbox exec broker
(Claude executes)         (BlastGuard executes)
      |                          |
      +-------------+------------+
                    v
          managed Git worktree
                    |
             diff / accept / reject
                    |
                    v
             developer decision
```

## Policy engine

`analyzer` parses Bash with `tree-sitter-bash` and recursively inspects commands, chains, pipelines, redirects, substitutions, subshells, process substitutions, and supported `sh -c`/`bash -c` payloads. Parse errors, unsupported or unresolved constructs, and ambiguous semantics become `ask`; they are never inferred safe by tokenizing quoted shell text.

Policy precedence is fixed:

1. built-in hard blocks;
2. user `block` rules;
3. user `ask` rules;
4. user `allow` rules;
5. the default built-in decision.

Hard blocks include recognized secret exfiltration and selected destructive or decode-and-execute patterns. Configuration cannot downgrade them. Pattern-based detection is necessarily incomplete, and static analysis cannot prove the behavior of arbitrary binaries or runtime expansion.

## Worktree lifecycle

`sandbox create` requires a clean, non-bare source repository with a resolvable `HEAD`. It creates a `blastguard/<session-id>` branch, a sibling linked worktree, and an owner-only manifest beneath the repository's Git common directory. Canonical source and worktree paths, base commit, branch ownership, lifecycle state, and clean-source conditions are revalidated before sensitive operations.

`sandbox diff` builds a binary patch from a temporary Git index and redacts recognized secrets before display. `sandbox accept` rechecks the clean source at the recorded base and applies the snapshot to the source worktree and index without committing. `sandbox reject` removes only validated session-owned Git resources. Locks serialize session and repository mutations; stale locks and interrupted apply states require manual review rather than automatic removal.

Git rollback applies only to Git-visible state inside the managed worktree. It cannot reverse network calls, external filesystem writes, ignored-file changes, processes, credential access, or effects produced by malicious repositories and binaries.

## Execution paths

| Property | Native Claude hook mode | `sandbox exec` mode |
| --- | --- | --- |
| Initial directory | Validated worktree | Validated worktree |
| Policy decision | Claude `PreToolUse` hook | BlastGuard before spawning Bash |
| Executor | Claude Code | BlastGuard |
| Environment | Claude's launch environment | Cleared, minimal environment |
| Output handling | Not captured by BlastGuard | Bounded, sanitized, and pattern-redacted |
| Timeout/process cleanup | Claude-controlled | BlastGuard timeout and Unix process-group cleanup |
| Journal | None | Metadata only; no command or output text |

The Claude hook cannot rewrite a Bash invocation into brokered execution. Claude's own hook timeout/start-failure behavior is an upstream fail-open boundary documented in the security policy. `sandbox exec` is more controlled, but its working directory, environment, timeout, and process group are not confinement: absolute paths, symlinks, subprocesses, platform credential stores, and arbitrary binaries remain outside its guarantee.

## State and secrets

Session manifests and the execution journal live under the source repository's Git common directory, outside the project worktree. On Unix, BlastGuard applies owner-only permissions. Manifests contain session metadata, not commands, output, or authentication tokens. Journal schema 2 stores aggregate execution metadata and no command fingerprint; legacy schema 1 fingerprints are removed during migration.

Human output, JSON, hook diagnostics, captured broker output, and displayed diffs pass through the shared redactor. Recognition is pattern-based, so users must still avoid placing live secrets in commands or repositories.

## Trust boundaries and non-goals

BlastGuard trusts the local operating system, the BlastGuard executable, Git executable, and the developer controlling the account. Native Claude mode additionally trusts the installed Claude executable and its hook transport. The project does not claim protection against arbitrary binaries, malicious repositories, kernel-level attacks, privilege escalation, symlink races, or fully dynamic shell behavior. See [SECURITY.md](../SECURITY.md) for the complete boundary and recovery guidance.
