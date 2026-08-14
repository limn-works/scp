---
name: pr-sdk-parity-e807b3f9c
description: APPROVED — fix/sdk-coverage-fail-closed-and-parity @e807b3f9c; total=True vs NotRequired parity rule against TS discriminated unions; BridgeTrustLevel Literal; per-SDK discover_contexts arg asymmetry; ADR-053 separate pre-rotation provider
metadata:
  type: project
---

Reviewed `fix/sdk-coverage-fail-closed-and-parity` @e807b3f9c (Python discovery/economy/bridge/trust + TS trust/bridge/economy/discovery + ADR-053). Verdict APPROVED, no blocking.

**Durable rule — Python TypedDict totality vs TS discriminated union:** when mapping a TS type to a Python TypedDict, judge each field independently against the *bridge projection*, not just sibling-SDK presence:
- A field present on EVERY record of the type (even if nullable) → `total=True` field typed `X | None`. Example: `ResolutionPathDict.source_id: str | None` matches TS `ResolutionPath.sourceId: string | null` (the bridge always set_items it — this is the e807b3f9c fix; at the prior HEAD 6bc9dfead it was wrongly `NotRequired`, which I had flagged).
- A field present only on ONE variant of a TS discriminated union → `NotRequired`, because Python TypedDict can't express per-variant fields. Example: `TrustLevelDict.sources` is `NotRequired` (TS `sources` exists only on the `MultiLayerCorroborated` variant). Flatten the union to one TypedDict with `kind: Literal[...all variants...]` + the variant-specific fields as `NotRequired`. This asymmetry (one field total, one NotRequired, same file) is CORRECT, not a bug.

**Other confirmed-good patterns (don't re-litigate):**
- `BridgeTrustLevel = Literal[0,1,2,3]` (Py) / `0|1|2|3` (TS): closed discriminant for the Rust enum's integer wire tier — more misuse-resistant than bare int/number; identical shape across bindings.
- `discover_contexts(query)` async, no SCP arg in Python (module-level `#[pyfunction]`) vs TS `discoverContexts(scp, query)` (getBridge dispatch). Intentional per-SDK idiom from a bridge-projection difference — documented inline. [[cross-sdk-method-naming-matches-canonical-sdk]].
- TS dual `evaluateTrust` (4-layer from ./trust) vs `bridgeEvaluateTrust` re-export (provenance tier from ./bridge) — distinct ops, not a dup; mirrors Python `bridge_evaluate_trust` re-export.
- ADR-053 proposes a SEPARATE `PreRotationCustodyProvider` (4 flat methods: generate/public_key/import_seed_bytes/consume, Zeroizing seeds) NOT new methods on KeyCustodyProvider — the separate-interface choice structurally enforces spec §9.7.4.1 §3 substrate isolation via the type system. Flat, agent-first, identical-shape table across bindings.
- `economy_verify_payment_receipts`: ok==True ≠ valid payment footgun now documented in BOTH SDK docstrings + on the result types. Receipt wire = top-level all_valid/results, per-entry ok/valid, no top-level ok.
