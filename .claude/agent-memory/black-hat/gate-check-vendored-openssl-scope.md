---
name: gate-check-vendored-openssl-scope
description: Three proven PASS-bypasses of scripts/check-vendored-openssl-scope.sh — the ARTIFACTS reader takes only the first bash array block, and its maturin TOML reader is a strictly weaker copy of the hardened one in check-shipped-feature-graph.sh
metadata:
  type: project
---

`scripts/check-vendored-openssl-scope.sh` claims that exactly one shipped
configuration selects `vendored-openssl`, that it is the wheel's, and that
`openssl-src` reaches no other shipped artifact. Three planted trees make it
print PASS while that claim is false.

1. **`shipped_configurations` reads the first `ARTIFACTS=(` … `)` block only.**
   Its awk exits at the first `)` at column 0. Splitting the array with
   `ARTIFACTS+=(` — or writing two plain `ARTIFACTS=(` assignments, where bash
   keeps the second and the gate reads the first — hides every entry after the
   first block. `MINIMUM_SHIPPED_CONFIGURATIONS=2` is the only floor, and the
   real array holds 10. The sibling gate expands the array through bash, so it
   sees all 10, but `scp-platform/vendored-openssl` sits on its one repo-wide
   `PERMITTED_ALLOWLIST`, so both binaries can vendor OpenSSL with the whole CI
   suite green. This is the bypass with no compensating control.

2. **Its `maturin_table_text` does not strip comment lines.** The `features`,
   `no-default-features`, `all-features` and `manifest-path` regexes take the
   FIRST match in the joined table text, so a commented-out key placed above the
   live one wins. `check-shipped-feature-graph.sh` carries the same function with
   `sub(/(^|[[:space:]])#.*$/, "")` added, plus an inline-table/dotted-key
   rejection, plus a line join that makes a multi-line TOML array parse. The
   vendored gate's copy has none of the three, so it also rejects a legal
   multi-line `features = [` array that the hardened copy accepts.

3. Both readers are otherwise byte-identical duplicates across the two scripts.
   The fix is to delete the duplicate and to have the owner print its own array
   (a `--print-artifacts` mode) instead of re-parsing its source text.

What resists: the pull request #2119 regression itself (a workspace dependency
table vendoring into every artifact while the wheel still names the feature) is
caught. Both previously reported defects are genuinely fixed — a non-zero
`cargo tree` exit now fails the run, and the wheel is identified by its whole
`<package>|<feature args>` entry rather than by package name.

`PERMITTED_ALLOWLIST` cannot replace this gate, for two reasons read off the
code: line 497 of `check-shipped-feature-graph.sh` extracts only
`scp-[a-z0-9-]+ feature "..."` edges, so `openssl-src` never enters its input;
and its allowlist is one repo-wide union applied to every artifact, so it cannot
say which artifact owns a row.

See [[surfaces-http-and-transport]] for the sibling pattern of a reader that
answers about a tree it never read.
