---
name: sdk-coverage-failclosed-parity-06d15bb6a
description: fix/sdk-coverage-fail-closed-and-parity @ 06d15bb6a (2026-06-22) APPROVED — single ADR-053 citation fix on top of APPROVED e807b3f9c
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ `06d15bb6a` — APPROVED, 0 findings (2026-06-22)

ONE commit past prior-APPROVED `e807b3f9c`. Base `1f1ea7cd2` IS ancestor (clean three-dot, 6 behind = unrelated main, 62 ahead). Delta = 1 file +1/-1: ADR-053 line 49.

**Why:** This was check (3) of the review request — both "Partial-publish recovery" references in ADR-053 must cite §9.7.4.1, not §9.12.

**The fix (correct):** ADR-053 line 49 `consume` description: `§9.12 "Partial-publish recovery"` → `§9.7.4.1 "Partial-publish recovery"`. VERIFIED: the "Partial-publish recovery." paragraph physically lives at `09-security-model.md:696`, inside `### 9.7.4.1 Pre-Rotation Key Custody` (heading line 655; §9.12 Compromise Recovery Protocol starts at line 1150). So §9.7.4.1 is the correct anchor. Line 86 (Consequences) already cited §9.7.4.1 — now BOTH references consistent. `§9.7.4.1 item 6 "Post-rotation key cycling"` anchor confirmed present at 09:686. Remaining §9.12 cites in ADR-053 (lines 6/10/25) are correct Identity-Key-Migration/Recovery refs (untouched, never wrong). Spec prose internally consistent: the §9.7.4.1 paragraph cross-refs §9.12 ONLY for the defense-in-depth destroy-OLD-keys clause = correct separate citation, NOT a mis-attached Partial-publish cite.

**Carry-forward:** Named-scope diff stat (26 files, +2280/-442) byte-identical to APPROVED e807b3f9c except this one line. Checks (1) PERM-3030 re-raise, (2) §9.12-vs-§3.2.1 across files, (4) `source_id: str | None` always-present nullable, (5) Literal wire-format — all deep-verified at e807b3f9c, files unchanged → verdicts carry. ADR-053 still `Status: Proposed`, 0 impl leaked.

**LESSON:** single-citation-fix-past-APPROVED → diff-stat to confirm scope is the one line, locate the cited paragraph's ACTUAL section by grepping the heading range (don't trust the cite — verify the paragraph sits between the claimed heading and the next), re-confirm the rest of the diff stat is byte-identical to the prior APPROVED commit.
