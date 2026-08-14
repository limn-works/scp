---
name: adr056-keying-gate-review
description: ADR-056 context-id keying chokepoint gate (check-context-id-keying.sh) brace-depth awk tracker — fail-open + false-positive bugs from cfg(test) regex matching comments/strings
metadata:
  type: project
---

# ADR-056 keying gate (check-context-id-keying.sh) — awk brace-tracker defects

Branch feat/123-canonical-context-id-digest @ bb183ba70 (PR #1924 follow-up).

**Why:** Gate is a CI tripwire enforcing all context-id→keying-bytes funnel through
`scp_runtime::context::state::context_id_to_bytes` (decode-64-hex-else-SHA256). The WHY
section explicitly frames a missed production raw call as a fail-OPEN (wrong event-log slot).

**How to apply:** The awk test-scope tracker is unsound BOTH directions because
`line ~ /#\[cfg\(test\)\]/` matches the literal inside doc comments/line comments/strings,
and `gsub(/{/...)`/`gsub(/}/...)` count braces inside comments+string literals.

- **FAIL-OPEN (HIGH):** A doc/line comment that mentions `#[cfg(test)]` on the line
  BEFORE a fn/impl that opens a block arms `pending=1`; the next `{` marks that real
  production fn as test scope → its raw-primitive call is silently exempted. Reproduced
  with a shape mirroring class_s.rs:2517 (`/// callers are #[cfg(test)] ...` then a real
  pub(crate) fn). Real tree safe ONLY by luck (no such comment precedes a raw call today).
- **FAIL-OPEN (HIGH):** a stray `{` in a comment/string on the cfg(test)-mention line (or
  any line) inflates depth so the test window NEVER closes → everything after is exempt.
- **FALSE-POSITIVE / breaks CI (MEDIUM):** a `}` inside a string literal in the FIRST test
  fn of a trailing `mod tests` closes the window one fn early → a later legitimate test
  call is DENIED. Strings with unbalanced braces (format strings, JSON, error msgs) are
  everywhere in this codebase.

The self-test passes because it only covers balanced, comment-free fixtures. Single
`#[cfg(test)]` attribute on ONE fn inside impl works correctly (braces balance).

**Out-of-scope keying site (LOW gap):** gate scans only scp-runtime/src + scp-ffi. A
production-shaped keying site `crates/scp-testing/src/fullstack/node.rs:289`
(`scp_core::context::context_id_bytes`, add_member key-package deposit) is NOT scanned.
Byte-identical today only because fullstack tests use non-64-hex ids ("e2e-encrypted-ctx").
Latent divergence if any harness test uses a real 64-hex id.

**Core change is SOUND:** state.rs context_id_to_bytes (strict 64-char lowercase-hex guard,
hex::decode → [u8;32], total fn no-panic, raw fallback) + all FFI/runtime/mls seal-open
call-site reroutes + tests are correct. The DEFECT is confined to the gate's awk tracker.
Proper fix per ADR comment = ContextDigest newtype (compiler-enforced); the gate is interim.
