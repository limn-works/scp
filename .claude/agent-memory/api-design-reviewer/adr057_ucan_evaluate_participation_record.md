---
name: adr057-ucan-evaluate-participation-record
description: API review of ADR-057 ucan_evaluate diagnostic + typed participation_record/evaluateTrust across PyO3/NAPI/UniFFI + Python/TS/Swift/Kotlin SDKs
metadata:
  type: project
---

ADR-057 / §7.2.4 change set (branch c3c-ts-work, commit fd3c8b625; merge-base 72b912a89). Adds read-only `ucan_evaluate` diagnostic (optional capability, returns CapabilityValidation 6-bool) vs throwing `ucan_validate` gate (mandatory capability); makes `presenting_agent_did` required (fail-closed, no aud self-default); adds typed `participation_record` -> BehavioralRecord and rebuilt typed `evaluateTrust`.

**Why:** eliminate cross-binding trust divergence — core computes participation facts ONCE, SDK receives typed result instead of reverse-engineering error prose / client-side re-aggregation.

**How to apply (verdict NEEDS REVISION):**
- PASS: `presenting_agent_did` genuinely required at every PUBLIC SDK surface — TS `string` (no `?`), Swift `presenterDid: String`, Kotlin `presentingAgentDid: String` no default, Python `str` no default. Runtime-only (Option<String>) enforcement is confined to internal PyO3/NAPI bridge; UniFFI generated layer is `String` (compile-time). Argument order consistent for ucan_validate everywhere (capability, did).
- PASS: CapabilityValidation 6-bool shape identical across Rust/PyO3/NAPI/UniFFI/Python(snake)/TS(camel): tokens_valid, signatures_valid, within_ceiling, nonce_valid, not_revoked, time_bounds_valid + all_valid()/allValid().
- PASS: BehavioralRecord + CachedAttestation/CachedAttestationEnvelope Python<->TS 1:1 and exported from both SDKs' public surface. CachedAttestationEnvelope intentionally snake_case in TS (pass-through wire DTO).
- PASS: evaluateTrust returns contextId resolved from handle (resolvedContextId = handle.contextId ?? labelArg), labels the context the record was actually computed for. Python label==lookup by construction.
- BLOCKING #1: Swift/Kotlin SDK wrappers (Ucan.swift, Trust.swift, Scp.kt) lack ucan_evaluate, participation_record, and the typed evaluateTrust — Swift evaluateTrust still returns untyped [String:Any] participationRecord + client-side aggregateTrust (the very divergence this eliminates for Py/TS). UniFFI bridge.rs DOES export ucan_evaluate + participation_record, so it's FFI-export-without-wrapper ("half-done"). check-sdk-coverage.py ALIASES for ("UCAN","evaluate") and ("Trust","participation_record") list only python+typescript (no swift/kotlin keys), hiding the gap — contrast established ("Trust","verify_participation_requirements") which lists all 4.
- BLOCKING #2: ucan_evaluate arg-order asymmetry across bindings. Python/TS SDK reorder to (presenting_agent_did, capability) so the required param is first; PyO3/NAPI/UniFFI bridges + Swift/Kotlin generated consumers keep (capability, presenting_agent_did). Not "identical shape across bindings."
- OBSERVATIONS: sibling-method order divergence within Py/TS (validate=capability,did; evaluate=did,capability) — both strings, positional swap fails loudly via did/capability validators; empty-string capability silently downgrades evaluate to intrinsic (no-challenge) mode rather than erroring (contained to diagnostic; validate keeps capability mandatory non-empty); intrinsic all-true could be misread as authorization (heavily documented "NOT AN AUTHORIZATION DECISION").
