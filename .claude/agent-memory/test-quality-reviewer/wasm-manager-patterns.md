# WASM ContextManager Test Patterns (crates/scp-ffi/wasm/src/manager.rs + consequence.rs)

## Structure
- Tests inline in `#[cfg(test)] mod tests` at bottom of manager.rs (~7434+) and consequence.rs (~295+, ~878+).
- WASM is single-threaded (thread_local MANAGER + RefCell) -- no concurrency flakiness in tests. Tests use plain `#[test]`, not `#[wasm_bindgen_test]`, running native.
- Native-time-stub hazard: production create_context path calls `crate::time::now_secs()` which panics under native test runner (wasm-bindgen extern stub). Pattern: test the GATE HELPER directly (validate_ceiling_capabilities, stored_policy_requires_payment) rather than full create_context; accept-path end-to-end is deferred to the WASM conformance suite under a real JS host. This is a legitimate, documented workaround -- not a coverage dodge.

## Test-only helpers (pub(crate), #[cfg(test)])
- make_bare_per_context_state(ctx, creator): creator auto-admin
- test_insert_ceiling(cap): seeds ceiling AND refreshes role defs + member caps (built-ins intersect desired set with ceiling)
- test_insert_member(did, role), test_set_governance, test_insert_context
- suspend_all_pub(did): SuspendAccess semantics (suspends full effective set); returns bool "had caps"
- member_has_capability / member_role / test_context_event_log_events

## Good patterns (replicate)
- Auth-gate tests assert BOTH error code (PERM_3000) AND distinct message substring ("does not grant messages:write" vs "suspended") AND side-effect (member_sequence_numbers ==0 on reject, ==1 on accept). member_sequence_numbers is REAL production state (advanced on send path ~5329, exported ~6177) -- these are genuine fail-closed assertions, not vacuous.
- Reject/accept PAIRING: out_of_ceiling tests pair "rejected => 0 GovernanceActionExecuted leaves" with "in-ceiling => exactly 1 leaf". cross_impl_* in consequence.rs. Strong non-vacuity.
- ModifyCeiling fail-closed: test asserts before==after ceiling projection on malformed reject. set_ceiling_and_refresh validates via set_ceiling FIRST, returns before mutating (genuinely fail-closed).
- Canonical-form parity tests assert WASM stored form (ContextRoleState::ceiling().to_ucan_string_set()) == native (Capability::ucan_capability_name set), AND assert the specific bug spelling is GONE (custom_payments:approve must NOT be present). Closes the create-store split + BLACK-002/003/005.

## Weaknesses found (slice1-roles review 2026-06-24)
- #1886 role-validation tests (change_role_to_undefined_role_is_rejected_wasm, add_member_with_undefined_role_is_rejected_wasm) assert only `result.is_err()` -- NOT the CTX_2015 code or "role assignment failed" message. Non-vacuous ONLY because the paired defined-role companion (change_role_to_defined_role_succeeds_wasm) is the control. A setup regression (e.g. missing governance:propose) producing a DIFFERENT error would still pass. Fix: assert ScpWasmError::Context code==CTX_2015.
- add_member rollback gap: dispatch_add_member rolls back members + member_sequence_numbers on undefined-role reject (fail-closed atomicity), but the test only asserts is_err() -- never asserts newcomer absent from members / no sequence entry. Doc comment claims "must not end up as a member" but test doesn't verify it.
- No full manager-level export_context -> import_context round-trip asserting member roles + suspended_capabilities + member_sequence_numbers survive verbatim onto new ContextRoleState. Coverage exists only at snapshot-signature/digest level (snapshot_digest_changes_when_suspended_capabilities_tampered) and broadcast block-list level -- not the role-state model itself.
