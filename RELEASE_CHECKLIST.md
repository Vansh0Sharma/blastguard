# Release checklist: v0.1.2 preparation

`v0.1.1` is an existing [published source release](https://github.com/Vansh0Sharma/blastguard/releases/tag/v0.1.1)
at `ade42ddb72fcc7ed270d075514ec274746ea1a17`. Do not move or republish that tag.
`0.1.2` is unreleased. There is no crates.io package, release binary, Homebrew
formula, or GitHub Marketplace publication yet.

This checklist does not authorize commits, pushes, tags, registry publication,
GitHub Releases, binary uploads, signing credentials, or repository-setting changes.

## Local preparation evidence

- [ ] Review `0.1.2` package/lockfile metadata, draft changelog, and source-release wording.
- [ ] Confirm Apache-2.0 metadata, complete LICENSE/NOTICE, and dependency attribution review.
- [ ] Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-targets --all-features`, `cargo build --release --locked`, and `git diff --check`.
- [ ] Run Python distribution tests and inspect the exact allowlisted package inventory.
- [ ] In a disposable clean source copy, run `cargo package --list --locked`, `cargo package --locked`, and `cargo publish --dry-run --locked --registry crates-io`; stop if credentials are requested.
- [ ] Inspect/extract the crate, compare source bytes, test/build it, install into a temporary root, and smoke version/packs/static allow/block without executing supplied commands.
- [ ] Record local repeat-build and candidate archive/checksum/extracted-binary results, including their limited scope.

Use [the distribution procedure](docs/distribution.md). Local results apply only
to the inspected tree/toolchain/platform; repeat on the final release commit.
Historical `v0.1.1` validation is not evidence for this candidate.

## Owner gates after review

- [ ] Commit/merge through normal review; require existing CI and Action end-to-end checks to pass on the exact candidate.
- [ ] Run the manual Release verification workflow on that same commit: native Ubuntu 22.04 x86_64, macOS 15 arm64, and macOS 15 Intel must pass. Record run URLs and resolved SHA.
- [ ] Explicitly review repeat-build diagnostic summaries before public binary distribution, including any non-blocking UUID/signature-only warning. A green job is not approval or a reproducibility pass; all other differences block. BlastGuard makes no reproducible-build claim.
- [ ] Run `cargo audit` and review all advisories/warnings; review dependency licenses.
- [ ] Establish Linux dependency/glibc floors and test the actual artifact on baseline/newer distributions.
- [ ] Resolve macOS signing/notarization and Gatekeeper behavior, or defer macOS binary distribution. No Windows artifacts.
- [ ] Perform a real owner-controlled Claude validation: worktree/session binding, actual allow/ask/harmless deny, diff review, reject, unchanged source. Do not infer Codex runtime support from offline tests.
- [ ] Confirm private vulnerability reporting and a working private contact. Do not infer settings from SECURITY.md.
- [ ] Review/record the demo if desired; do not claim a recording exists without generating and inspecting it.

## Separately authorized publication, not part of preparation

- [ ] Recheck crates.io name ownership/availability; approve the exact reviewed archive. A dry run does not reserve a name or guarantee acceptance.
- [ ] Decide release channels independently: source tag, crate, and binaries have separate gates. Prefer version-pinned Cargo installation once it exists.
- [ ] Confirm final version/changelog date and green checks; create an owner-authorized annotated/signed `v0.1.2` tag on the reviewed commit. Never move a published tag.
- [ ] Review the GitHub Release draft and installation claims before publishing.
- [ ] Before any binary upload, review archive contents, SHA-256 checksums, provenance verification, and platform/signing disclosures. Keep build and publishing permissions separate.
- [ ] Update availability/support documentation only after each publication succeeds.

Until separately approved, stop after validation. No token, account, release,
Marketplace, Homebrew, installer, or public artifact is needed for preparation.
