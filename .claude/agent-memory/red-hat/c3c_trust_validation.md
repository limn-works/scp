---
name: c3c-trust-validation
description: Attack chains against branch c3c-ts (ADR-055 structured trust validation + §7.3.2 participation facts)
metadata:
  type: project
---

# c3c-ts Assessment (2026-06-29)

Branch `c3c-ts`: ADR-057 (renumbered from 055) structured `ucan_evaluate` diagnostic + §7.3.2 typed `participation_record`. WASM removed (native only: PyO3/NAPI/UniFFI).

## ROUND 3 — POST verify-on-ingest + founder-leaf (2026-06-29, HEAD fcd7ee1d7, a19aa5352..HEAD)
New since round 2: f49ef862a (challenge verify-on-ingest + external revocation + infra/rejection split = closes old RED-C3C-03), dfb12baff (founder MemberJoined leaf), 8544bf9c5/0f793e0a1 (presenting_agent_did REQUIRED all 3 bridges). All 4 requested chains essentially HOLD; no new HIGH/CRITICAL.
- **Chain 1 attestation forgery → BLOCKED.** verified_attestations + populate_and_aggregate route every caller attestation through `verify_and_cache_with_revocation` (sig vs resolver issuer key + expiry + issuer-field rev + EXTERNAL context revocation list via RevocationStateChecker from get_revocation_state). Trusted verified_at; raw store_cached_attestation NOT used at ingest → no store poisoning. is_verification_rejection = CLOSED allowlist; infra faults propagate (no silent zeroing). Production uses MANDATORY persistent store (get_storage fails closed, no ephemeral fallback) so revocation list is the real durable one. PoC tests pass.
- **Chain 1 challenge forgery → BLOCKED (sig).** verify_challenge_verification checks verifier Ed25519 sig over canonical bytes binding all consumed fields incl context_id.
- **RED-C3C-04 (LOW): challenge verify-on-ingest has NO expiry + NO context-id-match check.** verify_challenge_verification takes no clock; rejection allowlist has no Expired variant; aggregate_trust_input collects get_challenge_results UNFILTERED for expiry → TrustInput.challenge_results carries expired passed=true. Ingest keys store by CALLER's context_id param, never compares cr.context_id (signed=A) → challenge signed for ctx A portable into ctx B ("bound but unchecked"). Impact bounded: admission.rs check_capability_requirements DOES filter expiry (line 109) but has NO production caller (export+tests only) and does NOT restrict/distinct verifier_did (self-issued valid-sig challenge passes — spec §7.3.4.2 only promises "sig prevents forgery"; verifier-trust is consumer responsibility, verifier_did surfaced). All consumer-side/advisory; throwing gate unaffected. Fix: thread clock+expiry into verify_challenge_verification (+ ChallengeVerificationExpired in allowlist) and assert cr.context_id==ingest ctx (or drop the binding if portable by design).
- **Chain 2 HOLDS.** evaluate_ucan now Option<&CapabilityUri>; None skips ONLY step-6 grant-match, never flips a bool true. Called ONLY from 3 FFI diagnostic wrappers. ALL enforcement (tools/invoke.rs:1148, saga.rs:1135, broadcast/mod.rs:1741) uses throwing validate_ucan w/ MANDATORY cap.
- **Chain 3 HOLDS.** presenting_agent_did REQUIRED+fail-closed for BOTH validate AND evaluate all 3 bridges (PyO3 ucan.rs:285/416, NAPI 266/386, UniFFI bridge.rs:13309/13462) — trim+filter(!empty)+ok_or_else, no aud self-default.
- **Chain 4 HOLDS.** Founder MemberJoined appended ONCE in builder::create_context at convergent creation_timestamp_secs (no double-leaf; lifecycle_helpers line 392=leave, 1028=join). Duration uses saturating_sub (no underflow). EmptyEventLog→NoParticipationFacts (CTX_2076) fires only when WHOLE log empty (now ~never for created ctx); non-member-subject query returns ZERO record not CTX_2076 — error names subject_did but condition is context-wide-empty (mild mislabel, not exploitable).
- **RED-C3C-05 (LOW, advisory/pre-existing): founder duration inflation + view-divergence.** Creator assigns creation_timestamp_secs; backdating inflates own participation_duration_seconds. Non-anchored, verifier-relative, convergent ts visible. Founder MemberJoined is committer-appended-only (membership-leaf replication dormant §7.3.1) → founder duration nonzero only in CREATOR's local log; cross-member divergence by-design pending ADR-051.

### Round-1/2 history (CLOSED)

## ROUND 2 — POST-FIX REASSESSMENT (2026-06-29, commits ba2e3cc90..a19aa5352)
RED-C3C-01 and RED-C3C-02 (below) were the findings that DROVE these fixes. Both now CLOSED.
- **RED-C3C-01 → FIXED.** FFI `verified_attestations` AND `populate_and_aggregate` (trust_store.rs:164,236) route EVERY caller `cached_attestation` through `cache.verify_and_cache` (resolver-resolved issuer sig + expiry + self-revocation, trusted clock `verified_at`) BEFORE caching; failures dropped (debug log). The "fresh entry skips verify" in `get_verified_attestations` is now SOUND because `verified_at` is trusted (set only by verify_and_cache). All 3 native bridges (PyO3 trust.rs:626, NAPI trust.rs:455, UniFFI bridge.rs:14878) call `verified_attestations` → supervisor.participation_record(&verified). PoC tests `forged_fresh_attestation_excluded_by_*` PASS. Supervisor forwards caller attestations unverified but the bridge is the boundary and all 3 verify.
- **RED-C3C-02 → FIXED.** Both `ucan_validate` (gate) AND `ucan_evaluate` (diagnostic) FAIL CLOSED on absent/empty `presenting_agent_did` across all 3 bridges (PyO3 ucan.rs:278/406, NAPI ucan.rs:266/383, UniFFI bridge.rs:13309/13458) — `.map(trim).filter(!empty).ok_or_else(err)`. No aud self-default tautology. `evaluate_ucan` cap now `Option`; `None` skips step-6 grant-match but never flips a bool true.
- **Chain 2 HOLDS:** `evaluate_ucan` called ONLY from the 3 FFI diagnostic wrappers; every enforcement path (tools/invoke.rs:1148, saga.rs:1135, broadcast/mod.rs:1741) uses throwing `validate_ucan` w/ MANDATORY cap. Gate always between diagnostic and authz.
- **Chain 4 HOLDS:** empty-log → distinct CTX_2076 (`ContextError::NoParticipationFacts`), mapped identically in all 3 bridges; VALID_7059 for participation validation. No rejection/resolution confusion.
- **RESIDUAL RED-C3C-03 (LOW-MED, pre-existing, now load-bearing):** attestation external/context revocation list (`store_revocation_state`/`get_revocation_state`) is NEVER consulted for `attestation_count`. `verify_and_cache`→`verify_attestation` (NO checker); `verify_attestation_with_revocation`'s checker is wired ONLY into the UCAN-token validate path (economy_logic/invoke/saga), not attestations. A validly-issued-then-context-revoked attestation (self-field still Active, original valid sig) inflates attestation_count. Needs real issuer sig (no forgery). attestation_count is verifier-relative + anchored=false + gate stands between it and authz → impact app-level only. Fix: thread a ContextRevocationChecker (from get_revocation_state) into verify_and_cache in the FFI helpers.

## RED-C3C-01 (HIGH) — attestation_count forgery (CONFIRMED w/ PoC)
- `AttestationCache::get_verified_attestations` (crates/scp-protocol/src/trust/aggregate.rs:215-232) verifies signature ONLY for EXPIRED cache entries. FRESH entries (`!is_expired`) are pushed straight to result with NO `verify_attestation` call.
- FFI `participation_record`/`aggregate_trust_input` accept caller-supplied `cached_attestations_json` → `store_cached_attestation` (raw, bypasses `verify_and_cache`) → `verified_attestations` (scp-ffi/common/src/trust_store.rs:203). Caller controls `verified_at`+`ttl_secs`, so any forged attestation marked fresh is never verified.
- `credential_attestation_history` (participation.rs:369) re-filters by subject-match + self-declared `RevocationStatus::Active` — both attacker-controlled. Signature/expires_at/resolver-revocation all skipped.
- Impact: `attestation_count` (BehavioralRecord, §7.4 credential layer) inflatable with garbage. Docstrings FALSELY claim "signature-verified". All 3 native bridges affected (NAPI trust.rs:448, UniFFI bridge.rs:14841 identical).
- PoC: added `poc_forged_fresh_attestation_counts_without_verification` in trust_store.rs tests — PASSES (forged 0-sig, expired, made-up issuer returned as verified).
- Fix: in `get_verified_attestations`, ALWAYS `verify_attestation` regardless of freshness (cache should store last-verify time, not skip verify); OR have FFI route caller attestations through `verify_and_cache` not raw `store_cached_attestation`.

## RED-C3C-02 (MEDIUM) — audience self-check + None-cap grant-skip footgun
- `ucan_evaluate` now takes `Option<capability>`; `None` SKIPS step-6 grant-match (validate.rs:827). PyO3/NAPI/UniFFI DEFAULT `presenting_agent_did` to token's own `aud` → tautological `aud==aud` audience check. WASM requires explicit `expected_aud_did` (safer).
- Combined: caller using defaults (no subject, no cap) gets all_valid=true for a token addressed to anyone granting nothing. Violates "no silent security defaults" tenet. Documented as WARNING only.
- SDK `evaluate_trust`/`evaluateTrust` pass subject + null cap correctly, so SDK path safe. Raw bridge op exposed to consumers.

## Holds up (not exploitable)
- Throwing gate `validate_ucan` UNCHANGED (mandatory cap). `evaluate_ucan` is called ONLY from diagnostic bridges + tests — NEVER from runtime enforcement. Protocol-internal authz unaffected.
- Supervisor `participation_record` (supervisor.rs) reads FULL log scoped by `context_id_to_bytes` — cross-context isolation holds. governance_actions_against cannot be suppressed via query scope (supervisor reads its own complete local log).
- NoOp→Merkle provider swap (runtime.rs build_event_log_provider): provider namespaced by context_id; one supervisor per bridge instance; no cross-context leak.
- SDK error-prose classification (_classify_ucan_error/_PASSED_BEFORE) DELETED — replaced by structured bools. errors.ts mapBridgeError now passes typed errors through (no UNKNOWN downgrade). Good.
- ParticipationProfile (signed, §7.3.2.1) sig-verified by admitting contexts; min_contexts distinct-signers defends forged attestation_count in admission. The unsigned ParticipationFacts view is the forgeable surface.
- H18 standing-deflation filter intact (ADVERSE_ACTION_TYPES; beneficial actions don't count against).
