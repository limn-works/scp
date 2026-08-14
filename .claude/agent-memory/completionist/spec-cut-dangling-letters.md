---
name: spec-cut-dangling-letters
description: When a spec cut removes lettered sub-items mid-sequence, check for orphaned surviving letters + downstream ADR cross-refs to the removed letters
metadata:
  type: feedback
---

When a spec section deletes some but not all lettered sub-items (e.g. removes §9.7.4.1 items 3a(a) and 3a(b) but keeps 3a(c)), two gaps hide predictably:

1. **Orphaned sub-item letter in the spec itself.** The surviving item retains its label ("c.") with no preceding a/b — a half-deleted-list artifact. It often survives review because a *downstream* artifact cross-references that exact label (here ADR-054:5 cites "item 3a(c)"), so the author kept the letter but left it visibly dangling.

2. **Downstream ADR/PRD citations to the removed letters.** The realization ADR (ADR-054:151/152) kept citing "§3a(a)"/"§3a(b)" after the spec cut moved that content to an RFC — dangling provenance to non-existent clauses, contradicting the ADR's own scope note.

**Why:** SCP artifact flow is one-way (spec → ADR). A spec cut MUST fix downstream refs; internal consistency of the ADR is not correctness.

**How to apply:** After any `grep`-confirmed spec-section cut, run: (a) `grep -n "^   [a-z]\." <spec>` around the cut to spot orphaned letters; (b) `grep -rn "§?3a(a)\|§?3a(b)\|<removed-label>" .docs/` for downstream citations to removed sub-items. Both are broken-provenance findings ⇒ INCOMPLETE.
