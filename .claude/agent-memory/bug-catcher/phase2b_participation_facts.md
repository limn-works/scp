# Phase 2B participation-facts review (b4c0cf9c2 + 01eb5a655, branch c3c-ts-work)

CLEAN review — no BLOCKER/WARNING bugs found. 2026-06-29.

## What changed
- 3 native FFI bridges (PyO3 src/event_log.rs, NAPI napi/src/event_log.rs, UniFFI uniffi/src/bridge.rs) now project `subject_did` into event_log_query payload_json alongside `target_did`, via shared scp_event_log::payload::project_payload.
- compute_participation_record reconciled off legacy EventType (GovernanceAction/ContextCreated/ToolVerified) onto canonical (GovernanceActionExecuted/ChildContextCreated/RoleAssigned/MemberJoined/MemberLeft). attestation_count now from NEW `accessible_attestations: &[Attestation]` param, not event log. New membership-interval duration algorithm.

## Verified correct
- Duration algo (participation.rs ~155-260): single open_join_ts, saturating_sub everywhere protects clock-skew/unordered (latest_event_ts<open_join_ts -> 0). Re-join closes prior open interval at new join ts. MemberLeft with no prior join: open_join_ts.take() is None -> no-op. subject_did=None (empty payload) correctly ignored (projected.as_deref()==Some(subject) is false). Still-open-at-end runs to global latest_event_ts (documented §7.3.2).
- is_adverse_governance_action: decode fail -> .ok()=None -> is_none_or true (adverse); empty action_type -> filtered to None -> adverse. Correct conservative fall-through.
- credential_attestation_history: filters subject==subject_did AND RevocationStatus::Active (excludes Revoked). Correct.
- aggregate.rs reorder: verified_attestations computed first, borrowed (&) into compute_participation_record, moved into TrustInput at end. No use-after-move, no needless clone.
- All 5 runtime callers (lifecycle_logic, messaging_helpers, tools/invoke, governance_helpers x2) pass &[] with rationale (no attestation-cache access, gate on participation_count only). Only aggregate.rs passes &verified_attestations. Matches design.
- ParticipationInput gained accessible_attestations field, threaded through produce_participation_profile.
- UniFFI UCAN-fallback (~12890): old tuple-pattern `if let (Some(obj), Some(target_did))` would have dropped subject_did; new form guards as_object_mut() once, injects each key independently. No silent-drop asymmetry.
- Supervisor::test_append_event_log (#[cfg(any(test, feature="testing"))]): writes via self.event_log_ref() = same Arc<dyn ContextEventLogProvider> that event_log_entries (manager read) uses. Correct same-store.
- e2e_bridge.rs PyDict.get_item: payload is PyObject -> Bound<PyAny>, PyAnyMethods::get_item raises KeyError on missing -> .is_err() correct for absent target_did; .expect().extract() correct for present subject_did. Matches pre-existing target_did test idiom.
- All recomputed test durations correct (Alice 10, Bob 9, full-scenario 7, rejoin 15, admin-driven 50, integration 300/2000). 68 participation unit tests pass.

## Minor (SUGGESTION only, not filed)
- No unit test exercises is_adverse_governance_action's decode-failure/empty-action_type adverse fall-through directly (behavior is correct; H18 happy/adverse paths well-tested).
