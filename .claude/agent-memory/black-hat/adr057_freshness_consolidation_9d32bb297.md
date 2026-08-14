---
name: adr057-freshness-consolidation-9d32bb297
description: ADR-057 structured-trust @9d32bb297 (delta over c35c62703) — freshness predicate consolidation + FFI arg-order/void re-verify; CLEAN, no exploitable findings
metadata:
  type: project
---

Re-attack of ADR-057 structured-trust change set at HEAD 9d32bb297 (2 commits past prior CLEAN pass c35c62703). Delta files: participation.rs, admission.rs, 3 FFI bridges, .pyi, SDK wrappers.

**CLEAN — no exploitable findings.** All 4 probe areas resolve sound:

1. **Freshness predicate consolidation** (participation.rs verify_participation_requirements):
   - NEW `MAX_PARTICIPATION_FUTURE_SKEW_SECS = 300` (mirrors challenge.rs). `if updated_at > now.saturating_add(300) { continue }` BEFORE `any_fresh=true` → far-future can't read as age-0-forever. Closes latent age-0 window.
   - `best_fresh_value` accumulated in the SAME single pass, AFTER both skew guard and age guard continues → diagnostic ThresholdNotMet.value uses IDENTICAL predicate as the gate (old separate-iteration diagnostic was actually LOOSER — omitted skew bound). No caller-exploitable divergence.
   - `newest_updated_at` (RecordTooStale diagnostic only) updates before skew check → can show far-future, but it's a diagnostic field, not a gate. Not exploitable.
   - within-skew (≤300s) future dating = intentional bounded clock tolerance; at most 300s freshness extension by the same trusted context signer who could re-sign anyway. Negligible.

2. **Fail-closed clock**: all 3 bridges swapped `SystemTime::now()...map_or(0,...)` → `scp_primitives::Clock::now_secs(&SystemClock)`. SystemClock::now_secs `.expect()` PANICS on pre-epoch (time.rs:95) = deny direction, NOT attacker-reachable (can't set host clock pre-epoch remotely). Prior map_or(0) would have made everything maximally fresh.

3. **Arg order `(expected_subject, requirements_json, profile_json)` + void return**: consistent everywhere — PyO3/NAPI/UniFFI exports, napi Scp:: JS wrapper, .pyi stub (:846-848), Python/TS/Swift(free-fn)/Kotlin SDK wrappers. All return unit/void; rejection via `?`/throw, no swallow path. SDK wrappers don't catch.
   - Python mock tests NOW discriminate positions by CONTENT (`requirements_json[0]["fact"]` vs `profiles_json[0]["subject_did"]`) → a transposition KeyErrors and fails. Prior-pass gap (mock silently accepts transposition) CLOSED.
   - result assertions are `assert result is None` (not the mock's stale `return_value=True`); failure path `pytest.raises(RuntimeError)`.

4. **Empty/malformed subject**: participation core rejects empty (EmptyExpectedSubject) before subject filter; admission.rs check_capability_requirements NOW rejects empty (EmptySubjectDid) up front BEFORE any short-circuit (test empty_subject_is_rejected passes `&[]` reqs + `""` → EmptySubjectDid). FFI bridges validate_did before core. Malformed non-empty subject just fails to match any subject_did (fail-closed). check_capability_requirements STILL has no prod caller (only scp-core re-export + tests, #1988) → guard = honest defense-in-depth for future caller.

Subject-binding (Step 0) + signature hard-fail (Step 1) unchanged and sound. Supersedes/confirms prior adr057_participation_freshness_c35c62703 pass.
