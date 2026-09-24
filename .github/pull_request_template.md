## Summary

Describe the problem and the narrow change that addresses it.

## Security impact

Explain any effect on command parsing, policy precedence, secret handling, Git state, execution, hooks, or trust boundaries. Write "None" only after checking each area.

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-targets --all-features`
- [ ] New or changed behavior has adversarial and benign tests.
- [ ] Documentation and exit-code claims match the implementation.
- [ ] Test data and output contain no real secrets or private repository content.

## Manual checks

List any platform, Claude Code, worktree, or recovery checks that reviewers should repeat.
