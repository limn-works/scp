---
name: gate-brace-counting-unsound
description: check-error-codes.sh Phase 4 (SCP-OUT-030) history — awk brace-counting v1 was UNSOUND; v2 sound-by-construction rewrite (b782b0656) is sound modulo one LOW unanchored-exclusion hole
metadata:
  type: project
---

# check-error-codes.sh Phase 4 (SCP-OUT-030) — v1 unsound, v2 sound + one residual hole

## v1 (commit 9e095b702) — UNSOUND, superseded
Phase 4 AC2 live-usage scan used awk brace-counting to skip `#[cfg(test)]` bodies.
Not a lexer → FALSE-NEG (unbalanced `{` in a cfg(test) string keeps skip past the
module close, hiding an unallocated prod literal after it) + FALSE-POS (block
comments, `#[cfg(all(test,...))]`, trailing comments). Replaced.

## v2 (commit b782b0656) — sound-by-construction rewrite, VERIFIED
Lexer-free split:
- (0) allocated 61NN set from `pub const CODE_* = "SCP-OUTLET-61NN"` in
  `crates/scp-protocol/src/context/outlets/error_codes.rs`.
- (1a) RUST: any raw `"SCP-OUTLET-61NN"` string literal in ANY .rs except the
  registry = violation (Rust must ref CODE_* consts). `SCP-CODE-OK:` opts out.
- (1b) SDK (kt/swift/py/ts/js): restated literals must be in allocated set; test
  files excluded by PATH glob anchored on `$f` (the path field). Correct.
- Rust test `all_codes_lists_exactly_the_defined_code_constants` source-parses its
  own file for `pub const CODE_*` defs, asserts set-equal to ALL_CODES — bijective
  + non-vacuous (catches const-omitted-from-ALL_CODES). Verified.
Case H (raw unallocated 6199 in prod .rs) now FAILS. Gate exit 0; 18 tests pass.
All ~15-file raw-literal→CODE_* conversions verified value-preserving
(6110→AUTHORIZATION_DENIED, 6130→EXECUTION_FAULT, 6131→EXECUTION_CREDIT,
6133→EXECUTION_CREDIT_STALL, 6135→CANCEL_ACK_TIMEOUT, 6140→OUTPUT_VIOLATION,
6160→TRANSPORT_FAULT, 6114→AUTHORIZATION_ATTENUATION). crate-root re-exports
`scp_protocol::CODE_*` exist (lib.rs:81-85). 6180/6199 SCP-CODE-OK markers are
genuine reserved codes (no const). caveats.rs CAVEAT_MINT_LIMIT_EXCEEDED_CODE now
aliases CODE_AUTHORIZATION_ATTENUATION.

## FIX LANDED + VERIFIED (commit bc2ec07fc)
Dropped `grep -v`; added `case "$f" in ./"$OUTLET_REGISTRY"|"$OUTLET_REGISTRY")
continue ;; esac` (exact-path anchor on parsed path field) + `--exclude-dir='.claude'`
on (1a)+(1b). Independently verified: original bypass now FAILS; superstring path
(error_codes_evil.rs) FAILS; sibling-crate error_codes.rs still SCANNED; real
registry still excluded (baseline PASS); .claude worktrees not scanned (no false
pos); colon-in-filename + CRLF still FAIL; plain unallocated prod literal FAILS;
gate exit 0; 18 error_codes tests pass. No new bypass. ZERO DEFECTS.
Note (pre-existing, repo-wide, non-actionable): `grep -r` doesn't traverse
recursion-symlinks — shared by all 4 phases, needs an obvious in-tree symlink,
not a regression of this fix.

## (historical) RESIDUAL HOLE (was LOW, now FIXED): (1a) registry exclusion was UNANCHORED
`grep -rn ... | grep -v "$OUTLET_REGISTRY"` filters the WHOLE `path:ln:content`
line, not the path field. A raw literal on a line that ALSO contains the string
`crates/scp-protocol/src/context/outlets/error_codes.rs` (e.g. trailing comment)
is silently excluded → gate PASSES. DEMONSTRATED. Falsifies the "sound / exact
path" claim. Low impact (SCP-CODE-OK already a sanctioned one-line opt-out;
accidental needs literal+47char-path on one line). Note two error_codes.rs exist
(scp-ffi/common + outlet registry) so a basename `--exclude` would over-exclude.
Fix: drop `grep -v`; add `case "$f" in ./"$OUTLET_REGISTRY"|"$OUTLET_REGISTRY")
continue;; esac` in the loop (anchor on $f like 1b).
Inherent (not-new) limit: concat!/format!-built codes evade any literal-grep;
backtick doc-comment refs (not double-quoted) correctly not flagged.
