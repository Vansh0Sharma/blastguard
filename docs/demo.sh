#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
demo_root=$(mktemp -d "${TMPDIR:-/tmp}/blastguard-demo.XXXXXX")

cleanup() {
  case "$demo_root" in
    "${TMPDIR:-/tmp}"/blastguard-demo.*) rm -rf -- "$demo_root" ;;
    *) printf '%s\n' "Refusing to remove unexpected demo path: $demo_root" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' "Building BlastGuard from $project_root"
(cd "$project_root" && cargo build --locked)

blastguard_bin=${BLASTGUARD_BIN:-$project_root/target/debug/blastguard}
test -x "$blastguard_bin"

repo="$demo_root/repository"
mkdir -p "$repo"
git -C "$repo" init --quiet
git -C "$repo" config user.name "BlastGuard Demo"
git -C "$repo" config user.email "demo@example.invalid"
printf '%s\n' "# Temporary BlastGuard demo" > "$repo/README.md"
git -C "$repo" add README.md
git -C "$repo" commit --quiet -m "demo baseline"

printf '%s\n' "Creating an isolated session in a disposable repository"
(cd "$repo" && "$blastguard_bin" sandbox create --repo . --id public-demo)

printf '%s\n' "Running a bounded command in the managed worktree"
(cd "$repo" && "$blastguard_bin" sandbox exec --id public-demo --command "printf 'reviewed\\n' > demo.txt")

printf '%s\n' "Reviewing the worktree patch"
(cd "$repo" && "$blastguard_bin" sandbox diff --id public-demo)

printf '%s\n' "Rejecting the session and verifying that the source stayed unchanged"
(cd "$repo" && "$blastguard_bin" sandbox reject --id public-demo)
test ! -e "$repo/demo.txt"
test -z "$(git -C "$repo" status --porcelain --untracked-files=all)"

printf '%s\n' "Demo complete: the temporary source repository remained clean."
