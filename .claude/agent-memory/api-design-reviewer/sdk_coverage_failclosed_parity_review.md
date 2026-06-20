---
name: sdk-coverage-failclosed-parity-review
description: Review of fix/sdk-coverage-fail-closed-and-parity — TS/Python SDK parity additions (identity lifecycle, economyVerifyPaymentReceipts, discover_contexts)
metadata:
  type: project
---

Review of `fix/sdk-coverage-fail-closed-and-parity` (2026-06-20, branch rebased onto current main dabf13364 — phantom-deletion warning in stale memory NO LONGER applies).

Verdict: NEEDS REVISION (one MED).

**Why:** Branch brings TS+Python SDK surfaces to parity. Scope: 5 identity-lifecycle methods (rotateKey/migrate/add+rotate+removeAgentKey, all Identity→Identity), economyVerifyPaymentReceipts, discover_contexts, test-guard.

**Findings:**
- MED: `discover_contexts` cross-SDK shape divergence — Python `discover_contexts(query)` (singleton _bridge, no SCP) vs TS `discoverContexts(scp, query)` (requires SCP instance). Internally Python is consistent (siblings parse_address/create_query/normalize_address all use _bridge singleton); divergence is BETWEEN the two SDKs. Reconcile on merit (is discovery stateless or per-instance?).
- LOW: `identityCreate` custody default differs — TS="in_memory", Python=CustodyType.FILE. Pre-existing; "no silent security defaults" tenet argues for identical default.
- LOW: TS `custody` is bare `string` (recurring untyped-custody finding); Python uses CustodyType|str. TS exports CustodyType but doesn't use it here.

**Good:** economyVerifyPaymentReceipts return type faithfully mirrors Rust verification_results_to_json wire shape (receipt.rs:185-204); snake_case fields correct for parsed JSON; JSDoc+docstring both warn ok≠valid (excellent misuse-resistance). identity lifecycle naming clean 1:1 parity, rotateKey(same DID)/migrate(NEW DID+rotationEventJson distribution) cross-referenced. test-guard frozen-at-import fail-closed, defaults false, internal-only.

**How to apply:** The economyVerifyPaymentReceipts + identity-lifecycle additions are clean and approved; only the discover_contexts signature split blocks. Confirms recurring [[cross-sdk-shape-parity]] signature-divergence defect class and untyped-custody pattern.
