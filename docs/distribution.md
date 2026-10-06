# Distribution preparation: 0.1.2 (unreleased)

[`v0.1.1`](https://github.com/Vansh0Sharma/blastguard/releases/tag/v0.1.1) is a
published **source release**. This checkout prepares `0.1.2`; it is not a new
release. No crates.io package, public release binaries, Homebrew formula, or
GitHub Marketplace publication exists yet. Local/CI candidate files are test
outputs, not releases. Nothing in this procedure publishes or authenticates.

The supported user-facing interface is the BlastGuard CLI and its documented
contracts. The Rust library modules are implementation details, not a stable,
supported Rust API. No MSRV is claimed: verification pins Rust **1.98.1**, which
is a tested compiler choice, not the minimum compatible compiler.

## Installation choices

Current source-install bridge, pinned to the published `v0.1.1` commit (requires
trusted Rust/Cargo, a C compiler/linker, and Git; no manual clone):

```sh
cargo install --git https://github.com/Vansh0Sharma/blastguard \
  --rev ade42ddb72fcc7ed270d075514ec274746ea1a17 --locked --bin blastguard blastguard
```

The primary future method is the following **only after actual crates.io
publication**. It is not usable for BlastGuard today:

```sh
cargo install blastguard --version 0.1.2 --locked --bin blastguard
```

Verified release binaries are the proposed fallback for users without Rust.
Git/Bash are still needed for worktree/execution features; Claude is optional.
Compilation runs trusted dependency build scripts. Use a non-root account and
keep credentials out of build environments. `--locked` pins dependencies, not the
compiler, SDK, build scripts' behavior, or every source of nondeterminism.

There is intentionally no `curl | sh` installer, auto-updater, or shell-profile
modification. Review a pinned source or independently verify an artifact before
executing it. Keep the static GitHub Action's existing Rust/compiler/Cargo-cache
prerequisites: it does not download or use these candidate binaries.

## Source-package validation

`Cargo.toml` explicitly includes source, all Rust integration tests, compile-time
Codex fixtures, embedded policy packs, license/notice, configuration example,
public Markdown documentation, demo sources, Action metadata/bootstrap needed by
tests, and distribution validation helpers/tests. `scripts/package-files.txt`
is the exact reviewed source inventory. Cargo adds its normalized manifest copy
and, when packaging from Git, VCS metadata. No workflow, editor state, local
configuration, credential, recording, Git metadata, target directory, or Python
bytecode is intended in the crate. The inventory check fails on missing or extra
files; `.gitignore` alone is not the publication boundary.

Use a disposable **plain source copy**, not `--allow-dirty`, `--no-verify`, a
real publication, or modifications to the original Git index. This copy does not
invent a VCS commit/provenance claim. Start with the reviewed candidate checkout,
trusted Rust 1.98.1 on PATH, and Python 3.9+:

```sh
set -e
python3 -B -m unittest discover -s tests -p distribution_test.py
package_check=$(mktemp -d "${TMPDIR:-/tmp}/blastguard-package.XXXXXXXX")
python3 -B scripts/verify_distribution.py copy-source "$package_check/source"
(
  cd "$package_check/source"
  # Fresh registry configuration: do not copy credentials or Cargo config here.
  export CARGO_HOME="$package_check/cargo-home"
  export CARGO_TARGET_DIR="$package_check/package-build"
  cargo fetch --locked
  cargo package --list --locked > "$package_check/inventory.txt"
  python3 -B scripts/verify_distribution.py check-list "$package_check/inventory.txt"
  cargo package --locked
  cargo publish --dry-run --locked --registry crates-io
  python3 -B scripts/verify_distribution.py extract-crate \
    "$CARGO_TARGET_DIR/package/blastguard-0.1.2.crate" \
    "$package_check/extracted" --version 0.1.2
  cd "$package_check/extracted"
  export CARGO_TARGET_DIR="$package_check/extracted-build"
  cargo test --all-targets --all-features
  cargo build --release --locked
  cargo install --path . --root "$package_check/install" --locked
  "$package_check/install/bin/blastguard" --version
  "$package_check/install/bin/blastguard" policy list
  python3 -B scripts/verify_distribution.py smoke \
    "$package_check/install/bin/blastguard" --version 0.1.2
)
```

Stop at the first failure. If the dry run requests credentials, **stop and report
an owner gate**; do not log in, inspect tokens, or retry without `--dry-run`. A
successful dry run does not reserve the name or prove server-side acceptance.

Extraction validates the exact inventory, regular-file-only members, bounded
sizes, paths, duplicate entries, and source bytes (using `Cargo.toml.orig` for
the original manifest). It refuses existing destinations. Smoke checks call the
binary directly with argv data: version, embedded packs, allow, a harmless marker
redirection, and a hard-block decoder/shell pattern. Exit statuses and JSON must
agree, and the disposable analysis directory must remain empty. No submitted
command, agent client, or model task is executed.

After inspection, remove only the exact `package_check` directory created above,
never a repository, home, or broad temporary-directory root. None of its packages
or installed binaries is a release.

## Manual native verification workflow

The separate [Release verification workflow](../.github/workflows/release-verification.yml)
has only `workflow_dispatch`. An owner must first commit/merge it through normal
review, then select the reviewed ref and record the resolved SHA. It explicitly
checks out `github.sha`, not a moving `main` ref. It is suitable for an audit-branch
run with read-only permissions and no publication, but GitHub requires the
`workflow_dispatch` definition to exist on the default branch before dispatch;
then the owner can select the audit branch/ref. An uncommitted workflow cannot be
run remotely. Existing CI/Action workflows and timeouts remain unchanged.

| Candidate platform | Native runner | Proposed archive |
| --- | --- | --- |
| Linux x86_64 GNU | `ubuntu-22.04` | `blastguard-v0.1.2-x86_64-unknown-linux-gnu.tar.gz` |
| macOS Apple Silicon | `macos-15` | `blastguard-v0.1.2-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `macos-15-intel` | `blastguard-v0.1.2-x86_64-apple-darwin.tar.gz` |

Each job uses SHA-pinned checkout with read-only repository permissions and no
persisted checkout credentials. It explicitly installs Rust 1.98.1, records the
commit/lockfile/compiler/SDK, runs formatting, locked Clippy and native tests,
checks a disposable source package, builds twice in independent target
directories, and reports exact executable comparison results. It creates and checksums an
archive, validates/extracts it, and smoke-tests **that extracted executable**.
The archive contains only `blastguard`, `LICENSE`, `NOTICE`, and `INSTALL.txt`.

There are no uploads, public assets, attestations, registry authentication, or
release-creation steps. Candidates remain on the disposable runner and are
discarded with it; logs retain checksums and results. Python helper tests mock
binary execution only when testing archive formatting; the native workflow
smokes the real executable. A checked-in workflow is not a hosted pass.

Ubuntu 22.04 is the proposed Linux build/test baseline, **not proof of generic
glibc/Linux compatibility**. Before public binaries, inspect ELF dependencies
and required symbol versions, then test the same artifact on the baseline and a
newer distribution. Musl, Linux ARM, and Windows artifacts are out of scope.
Windows controlled execution remains fail-closed, not newly supported.

Both macOS jobs set `MACOSX_DEPLOYMENT_TARGET=15.0`; older macOS support is not
claimed. Native Intel validation cannot be replaced by ARM cross-compilation or
Rosetta. Developer ID signing, notarization, Gatekeeper behavior, and final support
floors are owner gates. Candidates are not Developer ID signed or notarized.
Never disable platform protections to make a candidate appear supported.

## Checksums, provenance, and reproducibility

The helper writes `SHA256SUMS` and `<archive>.sha256`. For a locally generated
candidate, or a future actual release download, verify **before extraction**:

```sh
# macOS: choose the checksum file matching your downloaded archive.
shasum -a 256 -c blastguard-v0.1.2-aarch64-apple-darwin.tar.gz.sha256
# Linux equivalent:
sha256sum -c blastguard-v0.1.2-x86_64-unknown-linux-gnu.tar.gz.sha256
```

These names describe proposed/candidate files, not available download URLs.
Checksums detect changed bytes but do not authenticate a compromised release
account. Future publication should bind each archive to its reviewed commit and
trusted workflow with provenance attestations and document verification using
`gh attestation verify ARCHIVE --repo Vansh0Sharma/blastguard`. No attestations are
generated here. Future publishing permissions require separate review; normal
checks must not receive publish credentials.

Archive entries are sorted, with fixed uid/gid/mode/mtime and a timestamp-free
gzip header. This makes packaging repeatable **for identical inputs and compatible
tools**. Two matching builds in independent target directories on one runner are
limited repeat-build evidence, not cross-host or cross-toolchain reproducibility.
Runner labels and SDKs can change. Record exact inputs, then independently rebuild
on another matching host and investigate byte differences before broader claims.
BlastGuard makes **no reproducible-build claim**. Keep the normal compiler/linker
output intact, including UUIDs and linker-generated ad-hoc signatures. Those
Apple Silicon candidates are not literally unsigned, even before Developer ID
signing. The observed Intel linker output is naturally unsigned; absence of a
signature is not permission to remove one from a signed artifact.
Future signing/notarization needs separate review; checksum the final distributed
bytes, never a normalized substitute.

The last workflow step is a **repeat-build diagnostic**, not a successful
reproducibility check. Its versioned JSON and GitHub job summary distinguish:

- `exact_match`: the original files match for this pair only.
- `macho_metadata_only_unresolved`: visible warning, non-blocking **only** for the
  narrow observed macOS difference below. Explicit owner review is still required
  before any public binary distribution, even if the job is green.
- Any other difference, unknown format, malformed metadata, or invalid page hash:
  blocking failure. Linux still requires exact bytes. There is no blanket
  `continue-on-error` or exemption for the entire signature blob.

The comparator accepts only thin little-endian 64-bit executables of the requested
macOS architecture with a bounded, non-overlapping segment layout. Present
signatures must use the observed linker ad-hoc CodeDirectory format (v0x20400,
flags 0x20002, SHA-256, 4 KiB pages, one CodeDirectory, no special slots). It verifies
every signed page hash. The only exempt bytes are the 16-byte UUID and its
corresponding 32-byte page hash.
All other bytes, including signature flags, identifier, offsets, load commands,
and other page hashes, must match. Changed formats require investigation, not an
expanded exception by default. This is not publisher authentication, a general
signature verifier, or permission to bypass Gatekeeper.

Only generic Intel x86_64 (CPU subtype 3) may use the observed naturally unsigned
layout with **no** `LC_CODE_SIGNATURE` command. This path validates the observed
load-command set, segment bounds, bounded/disjoint linkedit tables, and a final
string table ending at EOF (no orphaned signature tail). Every file-backed section
must fit both EOF and its containing segment, agree with the segment's file/VM
mapping, and not overlap the headers. The three zero-fill section types have no
file-backed content but must fit their virtual segment; wrapping virtual ranges
and unsupported high-VM mappings are rejected. An `LC_MAIN` entry point must lie
past the headers and within executable, file-backed `__TEXT`, not at or beyond
EOF. These checks precede both exact-match and UUID-only outcomes. Only UUID bytes
are exempt; no signature verification is claimed for unsigned files. A present but
malformed signature never falls back to this path, and ARM64 still requires its
signature. Identical Mach-O inputs are validated too: byte equality cannot bypass
header or signature-hash rejection.

Run the same read-only comparison locally (no binary rewriting):

```sh
python3 -B scripts/verify_distribution.py compare-builds \
  "$first_binary" "$second_binary" --target aarch64-apple-darwin
```

### Local repeat-build evidence (2026-09-29)

Follow-up builds reproduced the previous UUID/signature-only finding. Recorded
tools: macOS 26.7 (25G229), arm64; rustc 1.98.1
(`48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8); Apple clang 21.0.0
(`clang-2100.1.1.101`); Apple ld 1267 (LTO LLVM 21.0.0); SDK 26.5.
Each build used a plain source snapshot, a new target directory, an isolated
credential-free Cargo cache, and the normal rustup entry point:

```sh
cargo build --release --locked --target aarch64-apple-darwin
```

The subprocess environment was cleared, then explicitly set to: trusted rustup
proxies/system-tool PATH, isolated `CARGO_HOME`, the existing isolated
`RUSTUP_HOME`, `RUSTUP_TOOLCHAIN=stable` (the recorded 1.98.1),
`CARGO_NET_OFFLINE=true`, `CARGO_INCREMENTAL=0`,
`MACOSX_DEPLOYMENT_TARGET=15.0`, `SDKROOT` from the installed Command Line Tools,
disposable `TMPDIR`, `LC_ALL=C`, `TZ=UTC`, and a distinct `CARGO_TARGET_DIR`.
There were no inherited Rust/C/C++ flags, wrappers, Cargo configuration, or profile
overrides. The existing release profile (`lto="thin"`, `strip=true`) was unchanged;
no post-build transformation or explicit signing command was used.

| Control | Equal-length directory names | Different-length directory names |
| --- | --- | --- |
| Baseline | Exact bytes matched | 16 UUID + 32 signature-hash bytes differed |
| `SOURCE_DATE_EPOCH=1790677994` | Exact bytes matched | 15 UUID + 32 signature-hash bytes differed |
| Epoch plus `RUSTFLAGS="-C link-arg=-Wl,-reproducible"` | Exact bytes matched | 16 UUID + 32 signature-hash bytes differed |

The epoch is the inspected base commit's timestamp; the workflow derives it from
its selected commit. `-reproducible` is documented in this installed Apple `ld(1)`
manual, and Rust documents forwarding linker arguments through `-C link-arg`.
Neither control solved the different-length-path case, so no ineffective linker
flag is added to the release workflow. Matching one pair with equal-length names
is not evidence that the existing workflow's differently named directories match.

Exact baseline evidence (zero-based offsets, end exclusive; both files 4,769,680
bytes): `LC_UUID` command at 1760, length 24, payload `[1768,1784)`;
`LC_CODE_SIGNATURE` command at 2000, length 16, payload `[4732544,4769680)`.
Only its first page-hash slot `[4732688,4732720)` differed. All load-command
headers, every other signature byte, and all other executable bytes were equal.

| Field | First build | Independent longer-path build |
| --- | --- | --- |
| Executable SHA-256 | `11ff0cbf05b7f85d181781fcd39bcdf3982ef8335d5e73035136d35bc1f6456e` | `8dec9fc4ae3509446cca1a46555a13a94a3356a46125b1727d8a56b91b5dc090` |
| UUID payload (hex) | `ec28323966eb38b3a395e6b2892bd8bd` | `c19f91731868347597f1a618c9f91340` |
| Signature page hash (hex) | `13233ddc6befaa9533588ebf803d2bafc1cb049f1d1b3d0321380b27a2e92bf8` | `7432ac5855ea0da86831a862bd725abe4f63d96b6e40f8ec826e09cdd5d98b3a` |

Both original candidates passed read-only `codesign --verify --strict`; metadata
inspection reported an ad-hoc, linker-signed signature, not Developer ID signing.
The first candidate's archive passed checksum, extraction, version/policy, and
static allow/block/no-execution smoke checks. Its archive SHA-256 was
`52bb945201cb87e823df1637f71e624896dfffedb6beacc4aa2c684a9b5c3a83`.

The immediate failure was an unconditional equality gate for path-sensitive
Mach-O UUIDs and the signature hashes covering those UUIDs. Path-length
sensitivity is observed; the precise internal linker hash input has not been
established. Do not infer that all macOS builds always differ.

An initial experiment bypassed rustup and produced `rust-objcopy` LLVM-loader
warnings; its unstripped outputs retained differing path bytes outside the
permitted regions. Those runs were excluded from release evidence, rerun through
rustup without warnings, and used as a negative comparator check. The gate does
not excuse such differences. Naturally emitted unsigned `.rlib` intermediates
also differed for the longer-path case; no reproducible unsigned executable or
complete intermediate was demonstrated. Rust's documented object emission is
not a replacement for a linked CLI, nor authorization to disable signing.

**Outcome B: reproducibility remains unresolved.** No UUID, signature, or security
metadata was removed or normalized. This is local macOS evidence, not a hosted
macOS 15, Intel, Linux, or cross-host result.

### Intel parser correction evidence (2026-10-05)

[Run 36663383132](https://github.com/Vansh0Sharma/blastguard/actions/runs/36663383132)
on `09421e8975b904f7ac950bc19f1055bfd1f35b22` passed Linux and Apple Silicon.
Its Intel job passed build/archive/checksum/extraction/smoke and failed only at
comparison. Public job metadata confirmed that sequence; the run retained no
artifacts, and unauthenticated full-log retrieval returned HTTP 403. Its exact
binary bytes and native linker version were not available for inspection.

The same rejection was reproduced with real BlastGuard binaries built for both
targets on macOS 26.7 arm64, Rust 1.98.1 (LLVM 22.1.8), Apple clang 21.0.0,
Apple ld 1267, SDK 26.5, deployment target 15.0. Each architecture used two fresh,
different-length target paths, the unchanged lockfile/release profile, and:

```sh
cargo build --release --locked --target aarch64-apple-darwin
cargo build --release --locked --target x86_64-apple-darwin
```

Builds ran offline with an isolated Cargo/rustup installation, `CARGO_INCREMENTAL=0`,
`SOURCE_DATE_EPOCH=1790737825` (the inspected commit timestamp), `LC_ALL=C`, and
`TZ=UTC`; no custom signing, stripping, or linker flags were added. These are
cross-compiled Intel binaries, **not a native Intel runtime validation**.

| Observation | ARM64 | Intel x86_64 |
| --- | --- | --- |
| Header magic / CPU / subtype | `0xfeedfacf` / `0x0100000c` / 0 | `0xfeedfacf` / `0x01000007` / 3 |
| File type / header size | `MH_EXECUTE` / 32 bytes | `MH_EXECUTE` / 32 bytes |
| File size (each build) | 4,769,680 bytes | 4,936,552 bytes |
| UUID command / payload | offset 1760 / `[1768,1784)` | offset 1760 / `[1768,1784)` |
| Signature | Command at 2000; valid ad-hoc SHA-256 pages | No signature command; `codesign -dv` reports unsigned |
| Differing bytes | 16 UUID + 32 UUID-page hash | 16 UUID only |
| Original comparator | Unresolved metadata-only diagnostic | Rejected at mandatory-signature check |
| Corrected comparator | Unchanged unresolved diagnostic | Unresolved UUID-only diagnostic |

The Intel string table ends at EOF: offset 4,934,472 plus 2,080 bytes equals
4,936,552. Its first/second executable SHA-256 values are
`bf62b3a147c285d54fcf7a6769cabdf0a7fb60bb163eda5f7900887cf3be51a2` and
`e4195c46cd45f7cf5b77ff0902244d48da9b803f07b7d90fcbb112ddc8f3d8aa`.
Both ARM64 signatures passed read-only `codesign --verify --strict`. All four
original executable hashes were unchanged by inspection/comparison. No signature
was removed, disabled, added, or normalized; there is no reproducibility claim.

The reproduced defect is architecture-independent signature-required logic,
not incorrect endianness, CPU constants, or 64-bit header decoding. Apple documents
ad-hoc signing as the default for Apple Silicon; naturally unsigned Intel output
must be distinguished from a corrupt embedded signature. Hosted confirmation of
the corrected comparator on the native Intel runner remains an owner gate.

## Remaining release gates and boundaries

- Review the exact candidate/version and extracted-package results.
- Obtain green hosted jobs on all three targets; explicitly review repeat-build
  diagnostic summaries and approve any known metadata-only exception before
  public binary distribution. A green job alone does not satisfy this gate.
- Review dependency advisories and third-party license obligations.
- Resolve platform floors and macOS signing/notarization, or defer those binaries.
- Confirm a private disclosure contact and owner-controlled publication identity.
- Recheck crates.io name availability; separately authorize any real publication.
- Update installation claims only after each channel exists. Never move `v0.1.1`.

Packaging does not strengthen policy or containment. BlastGuard is **not an OS
sandbox or network-containment system**. Native Claude Bash is policy-gated,
not brokered or output-redacted by BlastGuard. The Codex foundation has no
launcher, installed/trusted hook, or demonstrated native enforcement. Arbitrary
binaries, malicious repositories/build scripts, and dynamic shell behavior
remain outside the guarantee. See [SECURITY.md](../SECURITY.md).

## Official references

Checked 2026-09-29:

- [Cargo package contents and verification](https://doc.rust-lang.org/cargo/commands/cargo-package.html)
- [Cargo publication dry run](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)
- [Cargo installation and lockfiles](https://doc.rust-lang.org/cargo/commands/cargo-install.html)
- [GitHub native runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub manual workflow prerequisites and branch selection](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
- [GitHub build provenance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Rust macOS targets and deployment versions](https://doc.rust-lang.org/rustc/platform-support/apple-darwin.html)
- [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Apple build UUID guidance](https://developer.apple.com/documentation/technotes/tn3178-checking-for-and-resolving-build-uuid-problems)
- [Rust linker argument controls](https://doc.rust-lang.org/rustc/codegen-options/index.html#link-arg)
- [Rust output emission](https://doc.rust-lang.org/rustc/command-line-arguments.html#--emit-specifies-the-types-of-output-files-to-generate)
- [SOURCE_DATE_EPOCH specification](https://reproducible-builds.org/docs/source-date-epoch/)
- [Apple code-signature structures](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- Installed Apple `man ld`, section `-reproducible` (ld 1267).

Additionally checked 2026-10-05 for the Intel parser correction:

- [Apple Mach-O structures and load commands](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [Apple linker ad-hoc signing defaults](https://github.com/apple-oss-distributions/ld64/blob/main/doc/man/man1/ld-classic.1)
