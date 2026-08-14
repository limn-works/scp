---
name: pr-sdk-parity-trust-discovery
description: fix/sdk-coverage-fail-closed-and-parity review — TS identity/trust/bridge + Python economy/discover parity; rotation-event drop + discover naming/typing divergence
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` (HEAD 8c0713499) closed cross-SDK parity gaps by adding TS public methods + Python wrappers.

**Findings (API design):**
- MED — TS `SCP.identityMigrate` drops the `DidRotationEvent`. NAPI handle exposes `rotationEventJson` getter (BridgeIdentityHandle declares `readonly rotationEventJson?: string`, populated only by migrate). Python `identity_migrate` surfaces it as public `identity.rotation_event_json` so callers can distribute the event to active context members (spec §3.2.1 step 4b). TS `_fromHandle` re-wrap discards it; only reachable via `@internal _rawHandle`. Parity + protocol-consequence gap.
- MED — Discover naming/typing divergence: TS already has `discoverContexts(scp, query): Promise<DiscoveryResult[]>` (typed parse via parseDiscoveryResult). New Python `discover(query: str) -> list[dict]` (untyped). Same op, different name (`discover` vs `discoverContexts`) AND different return fidelity. Python discovery module IS internally consistent though (parse_address also returns dict[str,Any]).
- LOW — Python `economy_verify_payment_receipts -> Any`; sibling parsed-dict economy/identity methods annotate `-> dict[str, Any]`. Doc says returns a dict; annotate as such.

**Good patterns confirmed:**
- TS `bridge.evaluateTrust` (tier int 0-3) vs `trust.evaluateTrust` (4-layer TrustEvaluation) are intentionally distinct ops, both mirror Python (`bridge.evaluate_trust` / `trust.evaluate_trust`); disambiguated on export as `bridgeEvaluateTrust` (mirrors Python `bridge_evaluate_trust` re-export). NOT a duplicate.
- TS identity methods take bare `identity: Identity` (NO options bag) — matches Python `identity_rotate_key(self, identity)` exactly. (Task prompt claimed `options?` — inaccurate.)
- Options-bag `BridgeTrustOptions` with `?? default` mirrors Python keyword-only `*` defaults; no positional transposition.
- All 5 identity ops declared on internal Bridge iface for BOTH NAPI + WASM backends (uniform).
- index.ts exports complete: DiscoveryResult, ResolutionPath, TrustEvaluation + 4-layer sub-types all exported; stale TrustEvaluation/BehavioralRecord/AttestationSummary moved out of types.ts (had no consumers).
