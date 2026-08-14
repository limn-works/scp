---
name: review-class-s-nttest-brace-depth-wave18
description: CLEAN review of check-class-s-fail-closed.sh wave-18 NTTEST classifier→brace-depth rewrite (no weakening, strengthening)
metadata:
  type: project
---

# Class-S fail-closed gate — wave-18 NTTEST brace-depth reframe (CLEAN)

Worktree `xctx-saga` HEAD `d21e699fd`, parent `5d9993af4`. Diff touches ONLY
`scripts/check-class-s-fail-closed.sh` (385+/159-, 8 hunks). Sound strengthening,
no weakening, no regression. **Why:** restructures the NTTEST un-scanned-vacuum
guard from an item-KIND enumerator (`is_column0_item_start`) to a CLASSIFIER-FREE
brace-depth approach. **How to apply:** template for "convergent vs one-more-spelling"
gate reviews.

- WHAT CHANGED: deleted `is_column0_item_start` (enumerated every item keyword +
  fn/impl qualifier permutation + single-ident item macro) → replaced with
  `is_column0_code_line` (TRUE iff non-blank, non-comment, non-attribute, column-0).
  NTTEST now TRACKS the trailing `#[cfg(test)] mod`'s CODE brace depth (`in_test_module`/
  `test_mod_depth`/`after_test_module`) and flags ANY column-0 production line after the
  module's closing brace — immune to item/macro spelling. Closes the black-hat gap:
  path-qualified item macro `foo::bar! {}` (the MAJORITY macro spelling) that the old
  single-ident `^[A-Za-z_][A-Za-z0-9_]*!` branch could not match (`::` outside ident class).
- UNTOUCHED (verified by grep — none appear as +/- lines): MUTATORS (line 321),
  PERSIST_DELEGATES (360), CLASS_C_GOVERNANCE_LEAVES/govleaf allowlist (417), FC_FUNCS,
  GOVHIT/GOVFN rules, core persist_state_fail_closed detection. Diff's first hunk starts
  at the awk invocation (454); the `-v MUTATORS=`/`-v GOVLEAVES=` flags are CONTEXT lines.
- LIVE COUNTS identical at HEAD and parent: hits=0 govhits=0 nttest=0 **scanned=1065**
  (matches wave-17 ~1065; saga subsystem fully scanned, same HIT/GOVHIT set, no new FP,
  no new vacuum). Probed by patching a copy's `scanned_total` print, run from scripts/ dir
  (REPO_ROOT = `dirname $0/..`, so copy MUST live in scripts/ or SCAN_DIR resolves to `/`).
- SELF-TEST: full gate exits 0; new fixtures 46 (path-macro resume → HIT, non-vacuity
  proof), 47 (deeply-nested trailing module closing at EOF → no HIT, premature-close guard),
  48 (comments/blanks after close → no HIT) all pass + all prior (1-45).
- NEW-BLINDING analysis (the only real risk): the wave-18 multi-line ATTRIBUTE CARRY
  (`attr_bracket_depth`, lines 968-982) runs UNCONDITIONALLY (not just in/after a test
  module). Verified it does NOT blind production: it skips only the `#[..(\n..\n)]`
  attribute lines; the decorated `fn` follows at depth 0, not an attribute, falls through
  to the production scan. All new gsubs (938-939 `{`→`{`, 968-969 `(`/`[`→`&`) are
  content-PRESERVING (count-only, `&`=self-match), so `line` survives intact for the
  downstream production brace model (1072-1073, identical no-op pattern). ADVERSARIAL TEST
  PASSED: production fn with Class-S `xctx_caller_reservations.insert` behind a multi-line
  `#[allow(...)]` before any test module → hits=1 (still detected, not blinded).
- VERDICT: sound strengthening. NTTEST is now ≥ as strong (flags ALL column-0 resumes incl
  the path-macro the classifier missed), cannot newly blind a Class-S mutation, no new FP
  on legit trailing/second test module.
