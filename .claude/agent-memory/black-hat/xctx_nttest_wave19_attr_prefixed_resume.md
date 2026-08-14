# NTTEST gate wave-19 (commit d963d4291) — RESIDUAL CLASS-A-LIVE: attr-prefixed single-line production resume

Gate: `scripts/check-class-s-fail-closed.sh` `scan_file` (awk). Wave-19 closed 3 line-granularity gaps
(GAP-1 close-line resume via brace_close_pos+remainder re-eval; GAP-2 same-line `#[cfg(test)] mod`;
GAP-3 multi-line `#[cfg(all(test,..))]` carry). Wave-18 brace-depth reframe permanently closed the
spelling dimension (path-macro etc.) — confirmed intact.

## CONFIRMED BLINDING (false negative) — CLASS-A-live, fmt-clean
Shape: after a closed trailing test module, a column-0 production item whose attribute AND the whole
item sit on ONE bracket-BALANCED physical line:
  `#[rustfmt::skip] pub fn evil() { state.xctx_caller_reservations.insert(a,b); persist_state_best_effort(s,d,c); }`
Result: SCANNED=0, NO NTTEST, NO HIT. Real Class-S mutation (BLACK-001 replay) silently swallowed.

Root cause: TWO filters both exclude `^#!?\[`:
- `is_column0_code_line` (line 486) returns 0 for any `^#!?\[` line → after_test_module guard (1276) skips it → `if(after_test_module) next` (1285).
- `is_production_remainder` (580) same exclusion → GAP-1 close-line variant `} #[rustfmt::skip] pub fn evil(){..}` ALSO blinded (A22).
The attr-carry (1185) needs net brackets >0; an attr+fn whole-line is bracket-balanced (`[]`+`()` net 0) so it is NOT consumed as a multi-line attr either. Falls through every branch → next.

Why fmt-clean: `#[rustfmt::skip]` is an explicit instruction to preserve hand formatting; rustfmt
leaves `#[rustfmt::skip] pub fn evil(){...}` byte-for-byte unchanged (verified). `#[inline] pub fn`
IS split by rustfmt (that variant fmt-prevented). Compiles clean (verified rustc).

Caught variants (NOT blind): attr+fn where the fn opens a brace and the BODY/mutation is on later
indented lines (A23) → NTTEST fires. Only the WHOLE-fn-on-one-line (or close-line remainder) form blinds.

No live occurrence in scan dir today (latent-but-fmt-reachable, insider-introducible).

## FIX DIRECTION (keep convergent / whitelist-shaped)
The guard already matches "ABSENCE of {blank,comment,attribute}". The attribute case must not be a
terminal skip when the attribute is BALANCED and FOLLOWED by content on the same line. Soundest:
strip a leading balanced column-0 attribute from the line (reuse `strip_leading_attr`, already exists)
BEFORE the is_column0_code_line / is_production_remainder test; if the remainder is non-empty
production content, it's a vacuum. This is the same strip_leading_attr machinery GAP-2 already uses —
extend it to the after-module guard + is_production_remainder, do NOT enumerate attribute spellings.

## CLASS-B (over-report / fail-closed, low) — noted, not security
- A15: multi-line test-cfg gate whose `))]` shares the line with `mod {` → arms pending, next's the
  mod, body false-HITs. fmt-prevented (rustfmt separates close `))]` from `mod`). No live occ.
- A17: `mod tests` with `{` on next line → degenerate-close → NTTEST over-report. fmt-prevented.

## Resisted (all real scan_file): char/byte/unicode-escape brace literals, lifetimes, multi-line
strings/comments carrying braces across the close, cfg-on-struct, multi-line gate over a production
fn (correctly SCANNED/HIT), prior-win path-macro & ident-macro NTTEST, real trailing module clean.

Driver: head -3385 of script + per-arg `FC_FUNCS="" scan_file "$f"` loop; SCAN_DIR + NO_CLASS_S_SELFTEST=1.
