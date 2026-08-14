---
name: trust-extract-all-uris-residue
description: extractAllCapabilityUris / _extract_all_capability_uris extract full att list but consume only [0] after multi-att revert — cosmetic rename finding, not a blocker
metadata:
  type: project
---

PR #1867 branch fix/sdk-coverage-fail-closed-and-parity @65eba404b. Top commit 205966ced reverted multi-att AND-intersection back to att[0]-only (multi-att consumes the nonce on att[0] → every later att[i] gets NonceReused → false verdict). Residue: `__extractAllCapabilityUris` (trust.ts:321) and `_extract_all_capability_uris` (trust.py:155) still build/return the FULL att[i].with list, but both call sites collapse to a single element (`?.[0]` trust.ts:548 / `cap_uris[0]` trust.py:841).

Finding: rename to extractFirst*/_extract_first_* returning string|null, drop the indexing at call sites. CLARITY/minor-COMPLEXITY, NOT a blocker — code is correct, current behavior fine. "Future multi-att" does NOT justify keeping the full list: the future path is a SINGLE bridge call verifying all URIs (nonce once) that takes the token/att-array, not a pre-extracted client list — so this helper's full-list output is unlikely to be the surviving seam. YAGNI.

**Why:** att[0]-only is deliberate (nonce constraint), so the "All" name advertises a capability consumers structurally can't use.
**How to apply:** if this comes back in a later round, hold the same line — cosmetic rename, decide consciously, don't grind.

Cleared in same review (all NON-issues):
- isAllFalse/hasAnyFalse: DO NOT EXIST on this branch (zero grep hits). Nothing to inline.
- validateOneCapUri vs evaluateLayer1 (trust.ts:452 vs :526): correct separation, keep.
- mapBridgeError per-method try/catch ×204 in scp.ts: simplest CORRECT approach; a generic wrap() HOF would erase per-method types + fight agent-first one-pattern tenet. APPROVED again (matches [[ts_typed_error_exemption]]).
- coverage gate floor guard (check-sdk-coverage.py:1646): minimal fail-closed, 6 lines, can only ADD a failure. Suffix matcher GONE; all-exempted guard (:1626) closes prose bypass. Convergent — matches [[project_sdk_coverage_failclosed_converged]].

Stale artifact noted for orchestrator: bindings/typescript/.claude/agent-memory/api-design-reviewer/trust-layer1-multiatt-parity.md still describes the DELETED multi-att algorithm. Risks a future agent re-introducing the reverted approach.
