---
name: pr1867-trust-layer1-multiatt-divergence
description: PR #1867 fix/sdk-coverage-fail-closed-and-parity — TS evaluateTrust Layer-1 diverged from Python (multi-att AND-intersect vs att[0]-only) despite "mirrors Python" claim; stale JSDoc
metadata:
  type: project
---

PR #1867 (branch fix/sdk-coverage-fail-closed-and-parity) reworked the four-layer `evaluateTrust` in TS (`bindings/typescript/src/trust.ts`) and Python (`bindings/python/scp_sdk/trust.py`).

Cross-SDK Layer-1 semantics DIVERGED while both files claim to mirror each other:
- TS `evaluateLayer1`: validates each token against ALL declared `att[i].with` URIs via `__extractAllCapabilityUris`, AND-intersects per-URI and per-token verdicts via `intersectCapabilityValidation` (false wins). No fail-fast — continues all tokens, only short-circuits when all-false.
- Python `evaluate_trust`: extracts all URIs but uses only `cap_uris[0]` (att[0]), validates once per token, `break`s on first failing token. No `_intersect_capability_validation` helper exists in Python.

**Why:** The agent-first API tenet (CLAUDE.md) requires identical shape across bindings; both files' docstrings assert they mirror each other. The prompt for the review even asked about a Python `_intersect_capability_validation` that does not exist — a sign the intended parity (full multi-att in both) was only landed in TS.

**How to apply:** When reviewing trust/UCAN parity PRs, diff the actual Layer-1 loop semantics across SDKs, not just type shapes. Also: TS `__extractAllCapabilityUris` JSDoc (trust.ts) still says "evaluateLayer1 uses the first element (att[0].with)" — stale, contradicts the multi-att implementation it documents.

Related: [[cross-sdk-shape-parity]], [[ts-python-trust-parity]]
