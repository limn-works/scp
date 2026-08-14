---
name: pr-1867-revert-reimpl-stale-docs
description: PR #1867 trust AND-intersection — commit 935298ba3 reverted it, 8909092eb re-implemented it; doc artifacts left stale describing the reverted att[0]-only state
metadata:
  type: project
---

PR #1867 (`fix/sdk-coverage-fail-closed-and-parity`, HEAD `8909092eb`) implements AND-intersection of multi-att UCAN capability verdicts in TS (`bindings/typescript/src/trust.ts`) and Python (`bindings/python/scp_sdk/trust.py`).

Commit sequence created a revert/re-implement whipsaw:
- `c0bee8d22` narrow error absorption to PERM-3001 allowlist
- `62bbf8e41` first AND-intersection attempt (+ deletes `__extractCapabilityUri`, routes WASM via ucan_error_code)
- `935298ba3` REVERT to att[0]-only (BLACK-1867-01 fail-fast masking + cryptographer nonce-reuse MEDIUM)
- `8909092eb` re-implement AND-intersection (the final landed state)

**Why:** the revert→reimpl churn left documentation describing the reverted (att[0]-only) state while code does AND-intersection.

**How to apply:** when a PR reverts then re-implements, audit ALL prose (lesson files, docstrings) for the intermediate reverted state. Two stale spots found in PR #1867:
1. `.docs/lessons/ucan-validate-needs-real-capability-uri.md` — "Multi-att limitation: only att[0]" section (~lines 61-67) + "Fix" code block using `?.[0]`; never mentions `__extractCapabilityUri` deletion.
2. `bindings/python/scp_sdk/trust.py` `evaluate_trust` docstring (~lines 779-786) — says "first declared capability URI (att[0])" + "Multi-att ceiling validation ... not yet implemented" while the body loops all `cap_uris` and AND-intersects.

TS JSDoc (evaluateLayer1, __extractAllCapabilityUris, intersectCapabilityValidation) and Python helper docstrings (_intersect/_extract) were CORRECT. Only the Python evaluate_trust module docstring lagged.

Note: `.docs/adrs/adr-053-pre-rotation-custody-substrate-isolation.md` exists on disk but is UNTRACKED (not in HEAD) — not part of this PR's commits.
