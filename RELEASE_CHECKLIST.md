# Release checklist: v0.1.1

This is release preparation, not a published release. Do not tag, push, publish,
upload assets, or change repository settings as part of local preparation.
The owner performs those actions separately after review and validation.

## Baseline and local preparation

- [x] The public repository and initial commit exist; Milestones 5A and 5B are merged into `main` at `cb28ed1af6337e7b463cb18ce977896b2b4eba0e`.
- [x] That merged baseline passed [Rust CI](https://github.com/Vansh0Sharma/blastguard/actions/runs/36446270914) and [all seven hosted Action cases](https://github.com/Vansh0Sharma/blastguard/actions/runs/36446270753). This is not evidence for a later release commit.
- [x] Prepare `0.1.1` package/lockfile metadata, a dated changelog, and pinned Action examples. Keep `license = "Apache-2.0"` without a redundant `license-file`; retain the complete `LICENSE` and Vansh Sharma's 2026 `NOTICE`.
- [x] Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-targets --all-features`, `cargo build --release --locked`, and `git diff --check` on the release candidate.
- [x] Smoke-test version, policy packs, allow/block analysis, read-only doctor, and the Action's prerequisite/offline-build path in disposable fixtures.
- [x] Install into a temporary Cargo root and check the installed binary's version/help; run `docs/demo.sh` in its disposable repository.

Local preparation checks passed on 2026-09-28 with macOS arm64 and stable Rust
1.98.1: 92 tests passed, none failed or ignored. The Action smoke used a fresh
Cargo cache populated by `cargo fetch --locked`, followed by its offline build;
the supplied command did not execute. Doctor discovered Claude without launching
it, and repository/Git file bytes and status were unchanged. These local results
do not replace hosted CI or a real interactive Claude test of the release commit.

## Owner review after the preparation commit

- [ ] Review the release diff, license/attribution, source-only installation, security boundaries, command examples, and dated changelog. Confirm the actual release date before tagging; remove the preparation-status wording only when publishing.
- [ ] Merge the reviewed preparation commit and require both `CI` and `Action end-to-end` to pass on the exact release commit. Repeat the local validation and disposable smoke checks from a clean checkout of that commit.
- [ ] Run `cargo audit` and review every advisory or warning; an automated test pass is not a dependency-security review.
- [ ] Perform a real interactive Claude Code test: inspect `/hooks`, verify the managed worktree and session binding, and confirm `allow`, `ask`, and a harmless `deny`. Review the diff and reject the test session.
- [ ] Enable or confirm GitHub private vulnerability reporting and a working private disclosure channel. Do not infer this setting from the existence of `SECURITY.md`.
- [ ] Record the README demo with `vhs docs/demo.tape`, review it, and decide whether to include the recording. If intentionally omitted, record that decision; do not claim a GIF was generated.

## Owner-only release actions

- [ ] Create an annotated or signed `v0.1.1` tag on the reviewed, green release commit, then explicitly push that tag. Never move an existing release tag.
- [ ] Draft GitHub release notes from the `0.1.1` changelog, preserving the Action's Rust/compiler/Cargo-cache prerequisites and static-only limitations.
- [ ] Confirm the tagged commit's CI results, then publish the GitHub Release. Make `v0.1.1` usage public only after it exists; prefer full-SHA Action pins.
- [ ] Update the security support table and release-status wording to reflect the actual published state. Do not imply crates.io, Homebrew, Marketplace, or downloadable binaries are available.

This checklist does not authorize package publication or binary uploads.
