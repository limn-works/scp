---
name: adr057-trust-readpath-revalidation
description: ADR-057 trust verify-on-ingest + read-path re-validation defensive assessment (branch feat/actor-2c-xctx-tool-saga @c4075916d, 2026-06-30) — all invariants hold fail-closed
metadata:
  type: project
---

# ADR-057 Trust Read-Path Re-Validation Defense Review (2026-06-30)

Branch feat/actor-2c-xctx-tool-saga @c4075916d. Verdict: invariants hold fail-closed at every layer. No residual read-path fail-open for attestations OR challenge results.

**Why:** PR wires real UniFFI trust exports (Swift/Kotlin SDKs) for evaluateTrust/ucanEvaluate/participationRecord; this review confirms the defensive architecture before merge.

**How to apply:** Treat these as the verified baseline for trust-layer reviews. If a future networked resolver is injected, re-examine read-path `.is_ok()` drops (see note below).

## Verified invariants (all STRONG)
- Attestation read path `get_verified_attestations` (aggregate.rs L292-327): drops revoked AND expired on BOTH fresh-return (L314-318 check_revocation + expires_at>=now) and stale-reverify (L296-312 verify_attestation_with_revocation) branches.
- Challenge read path `aggregate_trust_input` (aggregate.rs L504-512): re-runs verify_challenge_verification (sig + context-binding + expiry) on every persisted result. Store-read faults propagate via `?` BEFORE the filter.
- check_capability_requirements (admission.rs L133-136): all caller CVs run through verify_challenge_verification before satisfying any req. Cross-context replay + None-context + expired all rejected. Tests prove forged/empty-sig/wrong-context/None don't satisfy.
- Rejection-vs-infra: closed allowlist `is_verification_rejection` (trust_store.rs L179-192) keyed on DEDICATED `TrustError::CanonicalizationFailed` (not old InvalidEventData overload). Infra faults (StoreError, lock_error) propagate. is_ok()-style drops in core read paths are safe because IdentityDidPublicKeyResolver is PURE (attestation.rs L630-642: deterministic key extraction from DID string, no network) and its only error AttestationSignatureInvalid IS in the rejection allowlist.
- ucan_evaluate side-effect-free: evaluate_ucan (validate.rs L780-784) takes ctx by SHARED ref `&ValidationContext`; uses NonceTracker::check_replay only; record() requires &mut → structurally impossible to record. TYPE-ENFORCED, no gate needed (would be redundant negative-value).
- presenting_agent_did fail-closed: required across PyO3 (ucan.rs L421), NAPI (ucan.rs L392), UniFFI (bridge.rs ucan_validate + ucan_evaluate). Swift/Kotlin = non-nullable String (fail-closed by type). Rejects empty/whitespace. Reason: prevents tautological aud==aud audience self-check / trust inflation.
- Participation fail-closed: supervisor.rs participation_record L9760-9764 substitutes [0u8;32] root ONLY when events.is_empty(); core returns EmptyEventLog for empty → zero root NEVER paired with real facts. Empty-log → NoParticipationFacts → CTX_2076.
- CTX_2076 folding: all 4 SDKs (Swift Trust.swift L763, Kotlin Scp.kt L1817-1819, TS scp.ts L2512, Python) branch on STRUCTURED code, never prose; produce zeroed BehavioralRecord (eventLogRoot ""). evaluateTrust returns structured TrustEvaluation, never a boolean verdict — never authorizes off the diagnostic. Empty-tokens Layer 1 = all-false (fail-closed).

## Minor hardening note (P3, forward-looking, NOT a current hole)
- Core read-path filters (aggregate.rs L296 attestation stale, L509-511 challenge) use `.is_ok()` which collapses any verify error into a per-entry drop. Currently SOUND because the injected resolver is pure/total (no transient faults possible) and store faults propagate before the filter. If a NETWORKED DidPublicKeyResolver is ever injected, a transient resolution fault would silently zero a subject's trust signal. Worth a doc-comment asserting the read-path `.is_ok()` soundness depends on resolver totality. The FFI INGEST helper (populate_and_aggregate) already classifies infra-vs-rejection correctly via is_verification_rejection.

## Well-Defended (recognition)
- Dedicated CanonicalizationFailed variant makes the rejection allowlist closed BY CONSTRUCTION (no infra path produces it).
- DurableProviders same-backend invariant + trust store namespace isolation (all keys trust/, traversal/null-byte rejected, delete_context cleans up).
- Type-enforced read-only nonce probe (shared-ref ValidationContext) — exemplary "crypto/type enforces, not code checks".
