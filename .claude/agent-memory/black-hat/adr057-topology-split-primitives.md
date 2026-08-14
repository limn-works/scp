# ADR-057 topology refactor (branch refactor/dissolve-primitives-split-identity, HEAD 280983dd7)

scp-primitives dissolved → wasm-safe leaves scp-clock/scp-crypto/scp-did + scp-mls/scp-client/scp-client-wasm.
New gate: scripts/check-no-shim-reexports.sh (grep-based, defense-in-depth per its own header).

## Finding 1 (LOW) — comment-filter evasion in check-no-shim-reexports.sh
- Lines 79-84: filter skips any grep-matched line whose trimmed text starts with `//`.
- Assumption "starts with // ⇒ inactive Rust" is FALSE under an open block comment.
- PoC (compiles as ACTIVE code, gate SKIPS it):
    /* hidden shim:
    // */ pub use scp_did::DID as X;
  Because Rust nested block comments: on line 2 the ` */` (space before star, so no `/*`
  nest-open token) closes the outer `/*`, making `pub use ...` live code. Verified via rustc.
- The prompt's other examples are all SAFELY flagged: `/* */ pub use ...` (trimmed `/*`),
  `pub use ...; //note` (trimmed `pub`), tab/space whitespace (trimmed `pub`). Only `// */` evades.
- Impact LOW: gate is defense-in-depth; load-bearing invariants (acyclicity via rustc,
  wasm fence via wasm32 job, banned-deps via check-protocol-deps.sh) independently hold.
- Fix: also skip only if line has no `*/`, or accept as documented KNOWN-LIMITATION.

## Finding 2 (MEDIUM) — release.yml publishes a publish=false crate
- crates/scp-client-wasm/Cargo.toml:9 has `publish = false` (cdylib wasm artifact, npm-distributed).
- release.yml:436-439 runs `cargo publish -p scp-client-wasm` → hard error, breaks release job.
- Also enumerated in TAGS (line 177) and dry-run summary crates.io list (line 872).
- Three lists self-consistent but all contradict publish=false. scp-ffi/scp-testing are
  publish=false and correctly ABSENT from release.yml — scp-client-wasm should match.
- Introduced in this range (base 86519aa6f had 0 refs to scp-client-wasm in release.yml).

## Clean
- Publish topological order valid (leaves→event-log→protocol→identity→mls→client→...→runtime→core).
  Earlier false edges (client→runtime/identity) were grep matching crate names in Cargo.toml COMMENTS.
- wasm32 CI job covers all 8 wasm-safe crates (laundering scp-runtime into scp-client caught).
- rust paths-filter is `crates/**` (broad) — no coverage gap for new crates; only fuzz filter swapped.
- check-protocol-deps.sh / check-no-mutable-globals.sh / .clippy.toml: comment-text only, not weakened.
