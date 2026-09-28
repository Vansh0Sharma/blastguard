# Local policy packs

These embedded, offline TOML assets use the existing `[[overrides]]` schema.
Pack version **1.0.0** is independent of the binary version; `v1/` identifies the
asset's major version. `policy list --json` and `policy show NAME --json` expose
the exact pack version. No download, auto-update, or configuration write occurs.

| Pack | Added rules | Intended use |
| --- | --- | --- |
| `balanced` | None | Recommended starting point: existing built-in decisions and local configuration |
| `strict` | Ask for every command; block `cargo publish` and `npm publish` text | Interactive review of every command |
| `ci` | Block `curl`, `wget`, `ssh`, `scp`, `cargo publish`, and `npm publish` text | Non-interactive analysis that treats **every nonzero exit** as a failure |

```sh
blastguard policy list
blastguard policy show strict
blastguard analyze --cwd . --command 'cargo test' --policy-pack balanced
blastguard analyze --cwd . --command 'cargo test' --policy-pack ci --json
blastguard sandbox exec --id review-1 --command 'git status' --policy-pack strict
```

The last command needs explicit `--approve` to execute an `ask`; nothing prompts
or auto-approves in the broker. For analysis, `allow=0`, `ask=10`, `block=20`.
CI callers must reject all nonzero statuses, including errors, rather than
treating `ask` as success. The pack does not run commands or provide a CI runner.

Selection **adds** rules to `blastguard.toml` (or the explicit `--config` file);
it does not replace it. Precedence remains built-in hard blocks, then matching
block, ask, allow, and finally built-in defaults. No pack contains an allow rule.
Selecting no pack preserves existing behavior; `balanced` is equivalent to no
pack. User allow rules can still override ordinary built-in asks unless a pack
or user ask/block rule matches. They cannot override hard blocks.

These globs match the **entire command text**, case-sensitively, not executable
identity or semantic intent. They can block harmless quoted words and miss
alternative tools, spellings, whitespace, or dynamic behavior. `ci` is not
network containment; `strict` review is not proof of safety. Hard blocks cover
recognized destructive deletion, secret-exfiltration, and remote/decode-execute
patterns; no pack makes those recognized patterns allowable. Arbitrary binaries
and unrecognized patterns are not guaranteed detectable.
Like the existing default policy, `ci` can allow an unknown executable when its
submitted text has no recognized risk; it is not a binary allowlist.

Pack flags apply only to `analyze` and `sandbox exec`, not `claude start` or its
session-bound hook. For native Claude, review/merge the displayed TOML into the
**source** repository's `blastguard.toml` and commit it **before creating a
session**. Do not overwrite existing rules blindly. There is no pack installer
and no persistent Claude hook configuration. See the
[Claude guide](../docs/integrations/claude-code.md).
