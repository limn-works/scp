---
name: class-s-nttest-brace-depth
description: check-class-s NTTEST guard is now classifier-free brace-depth tracking (wave-18), not an item-kind regex; how to extend/verify it
metadata:
  type: reference
---

`scripts/check-class-s-fail-closed.sh` NON-TRAILING-TEST-MODULE (NTTEST) guard was reframed (wave-18, SHA d21e699fd on feat/actor-2c-6.2.4-xctx-saga) from an item-kind classifier (`is_column0_item_start`, DELETED) to **brace-depth tracking** of the trailing test module.

How it works now:
- Detector: `#[cfg(test)]`/`all(test..)`/`any(test..)` gate (`is_column0_reopening_test_gate`) immediately before a column-0 `mod NAME {` (`is_column0_mod_decl`, full `pub`/`pub(crate)`/`pub(in path)` grammar) → enter `in_test_module`, init `test_mod_depth` from stripped-line `{`/`}` counts.
- Module closes when `test_mod_depth` returns to 0 → `after_test_module=1`.
- After close: ANY column-0 non-blank/non-comment/non-attribute line (`is_column0_code_line`) that is NOT a re-opening `#[cfg(test)]` gate → NTTEST HIT. A re-opening gate + its `mod` is consumed by the same detector path (legit second test module, no HIT).
- Multi-line attributes (`#[allow(\n..\n)]`, `#[derive(\n..\n)]`) are skipped via an `attr_bracket_depth` carry counting `(`/`[` vs `)`/`]` — otherwise a bare column-0 `)]` closer before `mod tests {` would be misread as a code line (this is the real supervisor.rs shape).

**Why this matters / DO NOT regress:** the old classifier leaked a NEW item/macro spelling every review wave (`unsafe fn`/`const fn`; `unsafe impl`/`unsafe trait`; `pub(crate) mod`; path-qualified item macro `foo::bar! {}`). That is the non-convergent "one-more-spelling" anti-pattern flagged by CLAUDE.md §"Guard against over-engineering" (~line 189) and `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`. If a future "the gate misses spelling X" finding appears, the answer is NOT a 6th classifier branch — the brace-depth model is already immune (it matches the ABSENCE of blank/comment/attribute, not item shapes). Investigate whether the issue is actually the attribute carry or strip_code, not the missing spelling.

Verifying changes to this gate:
- `bash scripts/check-class-s-fail-closed.sh` must exit 0 (self-test + real scan of `crates/scp-runtime/src/context`).
- Real-tree invariant: SCANNED_TOTAL=1065, NTTEST=0, HIT=0, GOVHIT=0 (unchanged across wave-17→18). A drop in SCANNED means the function tracker broke / a module is over-swallowing.
- Drive `scan_file` directly: `head -n $(($(grep -n 'if \[\[ ! -d "\$SCAN_DIR"' script | cut -d: -f1)-1)) script > lib.sh; source lib.sh; FC_FUNCS="" scan_file fixture.rs`.
- AWK is in shell single-quotes: NO apostrophes in awk comments (closes the quote → shell syntax error). See [[class-s-gate-trailing-test-module-only]].
- shellcheck: pre-existing 37× SC2016 (info, backticks in single-quoted printf) — accepted file style; CI runs `-S warning` where it is clean. Match the existing message style; do not "fix" SC2016.
