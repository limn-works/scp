# NTTEST brace-depth reframe wave-18 (commit d21e699fd) — CONVERGENT, 2 pre-existing CLASS-A latent gaps

scripts/check-class-s-fail-closed.sh: the item-spelling CLASSIFIER (is_column0_item_start, which black-hat repeatedly defeated with new spellings — unsafe impl, pub(crate) mod, path-macro foo::bar!) was DELETED and replaced with structural BRACE-DEPTH tracking of the trailing #[cfg(test)] mod body. is_column0_code_line = NOT(blank/comment/attribute) — matches the ABSENCE of non-content shapes, so no item/macro spelling can evade it.

## VERDICT: the reframe is the right move and is ROBUST on the dimension it targets.
- Path-macro gap (the wave-17 black-hat residual) is genuinely CLOSED: a16 path-macro, a18 paren-delimited macro, a9 non-test mod resume — all HIT regardless of spelling/delimiter.
- strip_code (char-by-char state machine) removes braces/brackets in strings/raw-strings/chars/comments BEFORE tm_opens/tm_closes count them. Defeats every literal-evasion: a1 string {{{{ / raw r#"}"# / block comment braces, a8 `(` in doc string, a13 multi-line string closing on the brace line — all HIT correctly.
- attr_bracket_depth multi-line-attribute carry is sound: a5 multi-line #[allow(..)] before 2nd test mod (no false NTTEST), a6/a14 multi-line attr on prod resume (HIT), a15 dangling attr (no HIT). Strip neutralizes brackets-in-attr-string.
- Nested test mod (a10), multi test mod then prod (a11, first gate line preserved), empty `mod x {}` degenerate close (a12) — all correct.
- Full gate green: 48 self-test fixtures pass + live scan of scp-runtime/src/context clean (no false positive).

## TWO CLASS-A LATENT GAPS (both PRE-EXISTING — wave-17 ALSO missed them; NOT regressions):
1. **Same-line gate+mod**: `#[cfg(test)] mod NAME {` on ONE physical line is NOT recognized as a test module. The detector arms pending_test_gate on the gate but only re-examines the NEXT line for mod-vs-item; the `mod {` on the same line falls into the production fn scanner. Consequence: test-module body SCANNED as production → test-only mutation FALSE-POSITIVE HIT (a3d: test_helper flagged), AND trailing prod vacuum MISSED (a3c). Root cause: is_column0_reopening_test_gate + is_column0_mod_decl both assume gate and mod on SEPARATE lines.
2. **Content on the module-closing line**: `} fn resumed() { ...mutation... }` — when in_test_module and the line drives test_mod_depth<=0, code sets after_test_module=1 and immediately `next` WITHOUT scanning the rest of that physical line. a4/a4b: trailing prod fn + its Class-S mutation completely invisible (SCANNED=1, no HIT, no NTTEST). Double-miss.

Both gaps: NO live occurrence in scanned tree (rustfmt puts mod-gate on its own line and a top-level `}` on its own line). Realistic Rust though. CLASS-A latent, matching the prior path-macro residual pattern. Fix for #2: in the in_test_module close branch, instead of bare `next`, re-scan the post-close remainder of the line as a potential production resume. Fix for #1: when a gate line ALSO contains a column-0 `mod`, treat it as the mod-decl in the same iteration (split, or check is_column0_mod_decl on the gate line after stripping the leading attr).

## CONVERGENCE
The non-convergent "one-more-spelling" anti-pattern IS resolved — the classifier is gone, replaced by structural detection that matches absence-of-non-content. The 2 residual gaps are NOT new spellings; they are LINE-GRANULARITY assumptions (gate-and-mod-on-separate-lines, close-brace-on-own-line) shared by the gate/mod-decl recognizers, pre-dating the reframe. They are bounded (two specific multi-token-on-one-line shapes), not an open denylist. This is genuinely convergent.
