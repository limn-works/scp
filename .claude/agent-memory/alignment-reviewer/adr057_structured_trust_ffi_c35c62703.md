---
name: adr057-structured-trust-ffi-c35c62703
description: ALIGNED review of ADR-057 structured capability/trust FFI + SCP-302/303 at HEAD c35c62703 (worktree agent-a1400c1b005b502a3)
metadata:
  type: project
---

# ADR-057 Structured Trust/Capability FFI + SCP-302/303 @ `c35c62703` — ALIGNED

Reviewed 2026-07-02 in worktree `agent-a1400c1b005b502a3` (NOT main; main on unrelated branch — wrong-tree signal is `reconcile_to_ceiling` in diff). No WASM bridge (removed per ADR-055, correct). Diff `origin/main...HEAD` = 102 files +13939/-2833.

**Why:** enacts ADR-057 (structured CapabilityValidation crosses FFI as typed record; SDKs never parse error prose) + grounds participation facts in leaf/credential split (§7.3.2) + adds clock-skew future bound to participation freshness (§9.14).
**How to apply:** if re-reviewing this branch or a follow-up, the core+bridges+Python were verified DIRECTLY; TS/Swift/Kotlin breadth verified by subagent (all 11 SCP-302/303 SDK criteria TRUE, no gamed refs, check-sdk-coverage=0).

## Verdict: ALIGNED, 0 blocking, 3 doc-precision nits

## Verified aligned
- ADR-057 D2/2a: `evaluate_ucan` = `Option<&CapabilityUri>` + `&ValidationContext` (read-only, `check_replay`); `validate_ucan` = `&CapabilityUri` mandatory + `&mut` (records nonce). validate.rs:545/:780.
- Intrinsic mode fail-closed: omitting challenge skips ONLY step-6 grant-match (validate.rs:836); within_ceiling (step 8) still over token's own att set (:862). Ordered/short-circuit.
- Prose-parser deleted (Python `_classify_ucan_error`/6 `_*_PREFIXES` = 0). evaluate_trust calls ucan_evaluate(...,None,subject_did) per token, AND-combines 6 booleans. all_valid docstring warns intrinsic≠authz.
- Single mapBridgeError chokepoint (TS errors.ts:265) keyed on `[SCP-CAT-NNNN]` regex; no .message prose-branching in trust paths.
- Subject binding protocol-enforced: verify_participation_requirements takes expected_subject, filters signed subject_did, rejects empty/malformed at all bridges. subject_did IN signed preimage (signable_bytes) → cross-subject replay closed cryptographically.
- attestation_count = credential-layer, verifier-relative, NEVER Merkle-anchored. NO AttestationPublished/Revoked EventType (enum lib.rs:112 confirms; all AttestationRevoked hits = TrustError variant). ATTESTATION_COUNT_ANCHORED=false const. attestation_count_anchored deliberately OFF signed ParticipationProfile (would be tamperable const on signed struct) — only on unsigned projection. GOOD design call.
- payload.rs:317 projection has BOTH target_did (governance/access) AND subject_did (role/membership) — two precise fields, matches §7.3.2 attribution split.
- Freshness future-skew: MAX_PARTICIPATION_FUTURE_SKEW_SECS=5*60=300s (participation.rs:838), enforced in verify (admission gate, NOT aggregate.rs which is attestation TTL cache). §9.14 confirmed says "5 minutes...more than 5 min in future rejected". Spec §7.3.2 step-5 edit cites §9.14 verbatim — accurate + downstream. Test verify_rejects_far_future_updated_at.
- Corpus-wide de-stale (attestation removed from convergent stream): §7.3.1, §9.9.3, ADR-051 Context, 00-open-questions — same justification all 4 places.
- Matrix cells flipped true, exemptions removed→descriptive notes. Additive enforcement-file changes only (participation_record alias, __repr__ allowlist). No #NNNN in source.

## 3 non-blocking nits
1. §7.3.2.1 step 5(e) freshness prose doesn't name future-skew bound (lives in §7.3.2 step 5, which code implements) — could cross-ref.
2. §7.4 pairs verify_participation_requirements/check_capability_requirements as verifying "participation profiles" but check_capability_requirements is capability reqs (takes subject though, so binding claim holds). FFI-wiring of check_capability_requirements is pre-existing separate Q (see #1988 wire-or-remove).
3. 00-open-questions still lists internal ParticipationRecord old field names (participation_count/tool_invocations/role_history/attestation_history/computed_at) — that's the full-record type, distinct from flat ParticipationFacts/BehavioralRecord 12-field projection. Not a contradiction.
