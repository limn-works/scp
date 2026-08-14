---
name: adr057-participation-freshness-c35c62703
description: Black-hat pass on ADR-057 participation/capability FFI hardening @c35c62703 (verify_participation_requirements subject binding + freshness skew + fail-closed clock + .pyi arg-order fix) — CLEAN, no exploitable findings
metadata:
  type: project
---

# ADR-057 participation/capability FFI hardening @c35c62703 — CLEAN

Branch worktree agent-a1400c1b005b502a3, HEAD c35c62703. ADR-055 (WASM removed, 3 bridges).

## Verdict: no exploitable findings. All flagged concerns sound.

- **Subject binding CRYPTOGRAPHICALLY sound**: `signable_bytes()` (participation.rs:785) length-prefixes `subject_did` as first signed field AND covers `signer_public_key`. Step-0 filter `s.subject_did == expected_subject` + full-set signature verify → mutating subject_did to pass filter breaks sig. Cross-subject profile replay closed. Capability side: `verify_challenge_verification` (challenge.rs:888) enforces subject_did AND context_id, both in canonical signed preimage. ChallengeSubjectMismatch/ChallengeContextMismatch.
- **Empty subject**: core rejects `is_empty()` up front (both fns, BEFORE requirements.is_empty() early return); bridges do full validate_did (rejects malformed too). Non-empty-malformed subject reaching core → exact-match filter yields empty set → ThresholdNotMet, fail-closed.
- **FFI contract**: all 3 bridges return unit + `?`-propagate → PyRuntimeError / napi throw / ScpError throw. No swallow.
- **Arg order (expected_subject, requirements_json, profile_json)**: consistent across PyO3/NAPI/UniFFI + NAPI per-instance wrapper + all SDK wrappers (Python trust.py:1094, TS scp.ts:2377, Kotlin, Swift) + all tests. The stale `.pyi` `(profile_json, requirements_json)` transposition (missing subject too) is FIXED (_scp_core.pyi:835). No remaining transposition (both JSON are String — would compile — but all correct).
- **Freshness**: `MAX_PARTICIPATION_FUTURE_SKEW_SECS`=5min bound closes "far-future updated_at reads as age 0 forever" gap; within-5min-future still fresh by design (matches challenge.rs §9.14). best_value diagnostic filter also gains the bound.
- **Fail-closed clock**: `scp_primitives::Clock::now_secs(&SystemClock)` panics pre-epoch (safe direction = admission DENIED, silent-0 bypass avoided). Pre-epoch not attacker-reachable across FFI (host wall-clock <1970); panic caught by pyo3/napi/uniffi → not UB. Theoretical DoS only.
- **attestation_count verify-on-ingest**: bridge sources via `verified_attestations`→verify_and_cache_with_revocation (sig+expiry+issuer-field+context-revlist, trusted verified_at stamp)→get_verified_attestations re-read. Caller cannot inflate. Prior HIGH (caller-controlled verified_at, memory c3c_attestation_count_freshness_bypass) stays CLOSED.
- **Self-certification (authenticity≠authorization)**: extensively/honestly surfaced (min_contexts Sybil via subject-controlled context signing keys; attestation_count self-issuable endorsement ring). Docs point consumers to independence-scored threshold path.
- **H18 governance_actions_against**: now keyed on GovernanceActionExecuted + GovernanceActionExecutedPayload (was JSON); remains documented LOWER-BOUND (undercount adverse, never over) — upstream H18 design, preserved.
