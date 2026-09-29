# Codex protocol fixtures v1

Synthetic fixtures, not captured runtime traffic. Verified 2026-09-29 against
the official [Codex hook contract](https://learn.chatgpt.com/docs/hooks).
`v1` versions BlastGuard's fixture set, not an upstream protocol or CLI release.

The request uses the documented common and PreToolUse fields. The adapter accepts
only the Bash string-command subset: unknown/duplicate fields, argv arrays,
alternate command fields, wrong types and unsupported permission modes fail.
`transcript_path` may be absent or null. Other fixture fields are required;
identifier/cwd/model/command strings must be nonempty and NUL-free. Metadata is
never used to select state or read a transcript. This strict subset may reject
real runtime extensions; compatibility is deliberately unverified.

The three response files cover the pure adapter's allow, ask-to-deny and block
mapping. Successful decision JSON uses exit 0; operational/protocol failures use
exit 2 and a fixed, sanitized stderr message. The CLI hook cannot reach an allow
response in 6A: environment variables are not proof of a trusted live launcher.
Only offline tests supply an already validated session lease directly to the
internal evaluator. No fixture creates a production launch authorization.
