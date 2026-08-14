---
name: ts-python-trust-parity
description: Cross-SDK API parity conventions for TS↔Python trust evaluation, bridge trust tier, and identity lifecycle; known intentional divergences and parity smells
metadata:
  type: project
---

The TS SDK (`bindings/typescript/src/trust.ts`, `bridge.ts`) mirrors the Python SDK
(`bindings/python/scp_sdk/trust.py`, `bridge.py`) for trust APIs.

**Fact:** Four-layer `TrustEvaluation` model is the cross-SDK trust contract.
Interfaces `CapabilityValidation`, `BehavioralRecord`, `Attestation`, `Endorsement`,
`ChallengeResult`, `TrustEvaluation` are field-for-field identical between TS (camelCase)
and Python (snake_case dataclasses). `_PASSED_BEFORE` / `__PASSED_BEFORE` is the UCAN
11-step pipeline failure-stage → known-passed-fields map.

**Why:** ADR-048 explicit-instance pattern + agent-first API design tenet require an
identical shape across all language bindings.

**How to apply when reviewing:**
- Intentional, documented divergence: TS `evaluateTrust(scp, subjectDid, context, tokens?)`
  takes a `Context` HANDLE; Python `evaluate_trust(scp, subject_did, context_id, tokens?)`
  takes a context-id STRING. Reason: NAPI/WASM `ucanValidate`/`eventLogQuery` need a handle;
  PyO3 resolves by id. This is a real binding-substrate constraint — do NOT flag as inconsistency.
- Parity SMELL to watch: Python keeps `_PASSED_BEFORE` private (underscore, not in `__all__`)
  and exposes NO failure-category type publicly. TS should match — exporting
  `UcanFailureCategory` from `index.ts` when its only consumers are `__`-prefixed internal
  helpers is a minimality/parity leak.
- `bridge.evaluateTrust` (re-exported as `bridgeEvaluateTrust` from index to disambiguate
  from the four-layer one) returns an integer trust tier 0–3 (ShadowBridged..NativeNative).
  Both SDKs default `isBridged=false, isNativeTransport=true, shadowStatus="shadow"`.
- `economyVerifyPaymentReceipts`: Python takes `list[dict]` + returns `dict`; TS takes
  `receiptsJson: string` + returns `unknown` (parsed JSON). Input/return-type asymmetry —
  TS does not accept a typed array nor return a typed result.
