# Release checklist

BlastGuard 0.1.0 is not released until every required item below is completed by the repository owner.

## Repository

- [ ] Review every file in the initial commit.
- [ ] Confirm `LICENSE`, `NOTICE`, package metadata, and copyright attribution.
- [ ] Create the public GitHub repository without generating replacement files.
- [ ] Make and inspect the first commit.
- [ ] Push the default branch.
- [ ] Confirm the GitHub Actions CI workflow is green.
- [ ] Enable GitHub private vulnerability reporting.

## Validation

- [ ] Run formatting, Clippy, all tests, and the release build from a clean checkout.
- [ ] Install into a temporary Cargo root and check the installed binary's version and help output.
- [ ] Run `cargo audit` and review every advisory or warning.
- [ ] Run `docs/demo.sh` in a clean local environment.
- [ ] Perform a real, interactive Claude Code test and verify the generated hook in `/hooks`.
- [ ] Confirm `allow`, `ask`, and `deny` behavior in that real Claude session.

## Documentation and release

- [ ] Record the README demo with `vhs docs/demo.tape`, review it, and decide whether to commit the generated media.
- [ ] Recheck README commands, links, security boundaries, and exit codes against the release candidate.
- [ ] Move the changelog entry from `Unreleased` to the release date.
- [ ] Create and push the signed or annotated `v0.1.0` tag.
- [ ] Draft GitHub release notes from `CHANGELOG.md`.
- [ ] Publish the GitHub release only after CI passes for the tagged commit.
