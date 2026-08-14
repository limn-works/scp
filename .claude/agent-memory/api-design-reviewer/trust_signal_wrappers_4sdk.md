---
name: trust-signal-wrappers-4sdk
description: Review of ucan_evaluate/validate + evaluateTrust + participation_record trust-signal SDK wrappers across Python/TS/Swift/Kotlin (branch feat/actor-2c-xctx-tool-saga, c4075916d)
metadata:
  type: project
---

Trust-signal wrapper cross-SDK review (ADR-057 / spec §7.2.4,§7.3.2). Swift/Kotlin wrappers newly added for parity with Python/TS.

**Verdict: NEEDS REVISION** — core types parity is excellent; the headline `evaluateTrust` op has 4 distinct shapes + a Python name collision.

GOOD (identical across all four, by construction):
- CapabilityValidation: 6 bools + `allValid` accessor; allValid documented diagnostic-never-authorization in all four.
- BehavioralRecord: 12 fields incl. toolInvocationCountAnchored + attestationCountAnchored.
- CachedAttestation/Envelope typed input: Swift Codable structs, Kotlin data classes, Python TypedDict, TS interface — snake_case wire keys consistent.
- ucan_validate sig (ctx, token, capability, presenting_agent_did, proofs?) and ucan_evaluate sig (ctx, token, presenting_agent_did, capability?, proofs?) consistent across all four; presenting_agent_did REQUIRED (non-optional) at SDK layer in all four.
- evaluateTrust computes participation record ONCE in Rust (participationRecord), never client-side, all four; SCP-CTX-2076 empty-log folding branches on structured code not prose, all four.

FINDINGS:
1. Python `evaluate_trust` is module-fn only (`scp_sdk.trust.evaluate_trust(scp, subject_did, context_id, tokens)`), NO `SCP.evaluate_trust` method — but SCP.participation_record / SCP.ucan_evaluate ARE methods. TS/Swift/Kotlin all have `scp.evaluateTrust(...)` method. Discoverability gap on the headline op.
2. Python NAME COLLISION: `scp_sdk.bridge.evaluate_trust(*, is_bridged,...) -> int` (bridge-provenance tier 0-3) is exported top-level as `bridge_evaluate_trust`; the canonical four-layer `scp_sdk.trust.evaluate_trust` is NOT re-exported top-level. Agent likely confuses the two / can't find canonical.
3. TS `evaluateTrust(handle, subjectDid, contextId, tokens?)` keeps a vestigial `contextId` param that is SILENTLY IGNORED when handle carries contextId (own docstring: "a mismatched label here does not relabel the result"). Swift/Kotlin correctly DROPPED it (use handle.contextId()). TS footgun + shape mismatch.
4. Python `TrustEvaluation` has extra Layer-4 fields (endorsements, challenge_results, consequence_structure) that evaluate_trust NEVER populates; TS/Swift/Kotlin TrustEvaluation lack them. Type advertises availability that isn't there.
5. Python TrustEvaluation.attestations element = `Attestation` (type, signature_valid, evidence_valid, fresh, issuer, claim); TS/Swift/Kotlin = `AttestationSummary` (type, issuer, valid, revoked). Divergent Layer-3 element shape.

MINOR/OBSERVATIONS:
- capability vs presenting_agent_did positional FLIP between validate (cap before presenter) and evaluate (presenter before cap); both adjacent String → transposition footgun. Consistent across langs, well-documented.
- Bridge layer: presenting_agent_did is compile-time `String` in UniFFI bridge.rs but `Option<String>`/`Option<&str>` (runtime fail-closed) in NAPI + PyO3. Not consumer-facing (SDK wrappers require it) but Py/TS fail-closed is runtime not compile-time.
- PRE-EXISTING adjacent: Swift Trust.swift still carries old admission-gating ParticipationFact (messagesSent/toolsInvoked... — does NOT match Rust enum ParticipationDuration/GovernanceActions...) + a PURE-LOCAL verifyParticipationRequirements with NO signature check, while Python/Kotlin/TS delegate to the bridge that verifies signatures/freshness/distinct-signers. Security-relevant divergence, separate subsystem.
