#!/usr/bin/env bash
# No input expressions in shell source. Command text is read only by the adapter.
set +x
set -euo pipefail
umask 077

fail_build() {
  { printf '%s\n' 'decision=error' 'exit-code=70' >> "$GITHUB_OUTPUT"; } 2>/dev/null || true
  printf '%s\n' 'BlastGuard action: offline source build failed. A stable Rust toolchain, C compiler, and populated Cargo dependency cache are required; a missing toolchain or offline dependency is not downloaded automatically. Run the prerequisite setup and cargo fetch --locked from docs/integrations/github-actions.md before this action. If prerequisites are present, check the pinned source build separately.' >&2
  exit 70
}

# Do not print missing metadata, tool output, environment values, or input text.
if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  printf '%s\n' 'BlastGuard action: required runner metadata is missing.' >&2
  exit 70
fi
if [[ -z "${GITHUB_ACTION_PATH:-}" || -z "${GITHUB_WORKSPACE:-}" || -z "${RUNNER_TEMP:-}" ]]; then
  fail_build
fi
if [[ "$RUNNER_TEMP" != /* || ! -d "$RUNNER_TEMP" ]]; then
  fail_build
fi

action_build=$(mktemp -d "$RUNNER_TEMP/blastguard-action.XXXXXXXX" 2>/dev/null) || fail_build
cleanup() {
  # Only the exact private directory created by mktemp, never an input path.
  if [[ -n "$action_build" && "$action_build" == "$RUNNER_TEMP"/blastguard-action.* ]]; then
    rm -rf -- "$action_build" 2>/dev/null
  fi
}
trap cleanup EXIT

# Build outside the analyzed checkout: no checkout .cargo/config or target writes.
# Cargo source dependencies must already be cached. No binary/toolchain download.
if ! (
  mkdir "$action_build/source" || exit 70
  cp -- "$GITHUB_ACTION_PATH/Cargo.toml" "$GITHUB_ACTION_PATH/Cargo.lock" "$action_build/source/" || exit 70
  cp -R -- "$GITHUB_ACTION_PATH/src" "$GITHUB_ACTION_PATH/policy-packs" "$action_build/source/" || exit 70
  cd "$action_build/source" || exit 70
  export CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0
  cargo build --locked --offline --bin blastguard --target-dir "$action_build/target"
) >/dev/null 2>&1; then
  fail_build
fi

# This internal adapter invokes only this very binary's `analyze` subcommand.
# Never search PATH for a globally installed blastguard or execute command text.
if [[ ! -x "$action_build/target/debug/blastguard" ]]; then
  fail_build
fi
# Keep startup/loader errors from echoing runner paths. The private output file
# also lets a failure before adapter startup return error rather than no decision.
adapter_output="$action_build/outputs"
if ! { : > "$adapter_output"; } 2>/dev/null; then
  fail_build
fi
action_status=0
GITHUB_OUTPUT="$adapter_output" "$action_build/target/debug/blastguard" github-action >/dev/null 2>&1 || action_status=$?
if [[ ! -s "$adapter_output" ]]; then
  fail_build
fi
if ! { cat -- "$adapter_output" >> "$GITHUB_OUTPUT"; } 2>/dev/null; then
  printf '%s\n' 'BlastGuard action: could not write action outputs.' >&2
  exit 70
fi
if [[ "$action_status" != 0 ]]; then
  printf '%s\n' 'BlastGuard action: static policy check failed; see decision/exit-code and the integration guide.' >&2
fi
exit "$action_status"
