#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

//! Pipeline Wiring Structural Test
//!
//! Verifies that spec-required function calls exist in the correct functions
//! within the message send/receive pipeline. Uses `include_str!()` to embed
//! source files at compile time and a brace-matching parser to extract
//! individual function bodies.
//!
//! Baseline assertions (non-ignored) represent currently-wired pipeline steps.
//! `#[ignore]` assertions represent steps that are specified but not yet wired;
//! each references a GitHub issue tracking the work. As wiring PRs land, the
//! `#[ignore]` is removed and the assertion becomes enforced.

// ---------------------------------------------------------------------------
// Source files embedded at compile time
// ---------------------------------------------------------------------------

// Production submodules first so extract_fn_body finds real implementations
// before test mocks in mod.rs (the parser returns the first match).
const MANAGER_SRC: &str = concat!(
    include_str!("../../../../crates/scp-runtime/src/context/manager/economy.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/messaging.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/broadcast.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/governance.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/lifecycle.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/queries.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/standing.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/outlets.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/trust_recovery.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/ttl_close.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/mod.rs"),
);
const PROVIDER_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/crypto/mls/provider.rs");

// WASM bridge sources. Bridge has its own consequence-dispatch path and is
// asserted separately below — scp-runtime and scp-ffi-wasm are two parallel
// implementations of the same protocol and both must honor the wiring.
const WASM_MANAGER_SRC: &str = include_str!("../../../../crates/scp-ffi/wasm/src/manager.rs");
const WASM_CONSEQUENCE_SRC: &str =
    include_str!("../../../../crates/scp-ffi/wasm/src/consequence.rs");

// Non-WASM FFI bridge sources. PR #1606 / C4 wired all 3 of these to
// `ContextManager::invoke_outlet_with_economy` so per-invocation pricing,
// spending UCAN, velocity tracking, budget enforcement, and the hard
// rate limit are enforced for Python / Node / Swift / Kotlin clients.
// The structural assertions in `c4_outlet_invoke_economy_*` below pin
// the bridge → runtime delegation so a future refactor cannot silently
// regress to the bypass path.
const PYO3_OUTLETS_SRC: &str = include_str!("../../../../crates/scp-ffi/src/outlets.rs");
const NAPI_OUTLETS_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/outlets.rs");
const UNIFFI_BRIDGE_SRC: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs");

// Transport layer sources for Batch 3 assertions
const ADAPTER_SRC: &str = include_str!("../../../../crates/scp-transport/src/native/adapter.rs");

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================
// Raised from 38 -> 52 by SCP-OUT-008: ratchet brought up to reflect the
// current active-assertion count (total_tests=57 − 1 stale-ignore-comment
// false-positive − meta_tests=4 = 52 active). Adds 5 new outlet-surface
// assertions pinning register_outlet / invoke_outlet / deregister_outlet /
// verify_outlet / update_outlet delegation from the 3 non-WASM FFI bridges
// to the runtime pipeline — AC22. The negative meta-assertion
// `out008_no_tool_symbols_in_outlet_assertion_table` counts toward the
// meta_tests deduction below, not the active-assertion floor.
//
// Raised 52 -> 53 by SCP-OUT-042c: adds
// `admin_removal_emits_induced_rotations` pinning the §6.2.0.1
// round-6 atomic admin-removal salt-rotation invariant. The single
// `#[test]` adds 2 inner asserts but contributes 1 to the
// total_tests count.
//
// Raised 53 -> 54 by SCP-OUT-042b + SCP-OUT-042d remediation: adds
// `accept_outlet_interface_routed_from_governance` pinning the
// runtime governance dispatch arm that wires
// `GovernanceAction::AcceptOutletInterface` to
// `ContextManager::accept_outlet_interface`. The single `#[test]`
// runs 4 inner asserts (dispatch → wrapper → both rejection slugs)
// but contributes 1 to the total_tests count.
const MIN_ACTIVE_PIPELINE_ASSERTIONS: usize = 54;

// ---------------------------------------------------------------------------
// Function body extraction — brace-matching parser
// ---------------------------------------------------------------------------

/// Extracts the body of a function named `fn_name` from `source`.
///
/// Searches for `fn <fn_name>(` or `fn <fn_name><` (generic params), then
/// finds the opening `{` and does brace-matching to locate the closing `}`.
/// Returns the text between (and including) the braces.
///
/// If the function appears multiple times (e.g. in test mocks), returns the
/// FIRST occurrence. For functions that may also appear in `#[cfg(test)]`
/// blocks, the first occurrence is the production implementation.
fn extract_fn_body(source: &str, fn_name: &str) -> Option<String> {
    // Find the function signature — match `fn <name>(` or `fn <name><`
    let needle_paren = format!("fn {fn_name}(");
    let needle_generic = format!("fn {fn_name}<");

    let sig_pos = source
        .find(&needle_paren)
        .or_else(|| source.find(&needle_generic))?;

    // Find the opening brace after the signature
    let after_sig = &source[sig_pos..];
    let open_brace_offset = after_sig.find('{')?;
    let body_start = sig_pos + open_brace_offset;

    // Brace-matching: count depth from the opening brace
    let mut depth = 0u32;
    let mut body_end = body_start;
    let mut in_line_comment = false;
    let mut in_string = false;
    let mut prev_char = '\0';

    for (i, ch) in source[body_start..].char_indices() {
        // Track line comments
        if ch == '/' && prev_char == '/' && !in_string {
            in_line_comment = true;
        }
        if ch == '\n' {
            in_line_comment = false;
        }

        // Track string literals (simplified — doesn't handle raw strings,
        // but sufficient for brace matching in Rust source)
        if ch == '"' && prev_char != '\\' && !in_line_comment {
            in_string = !in_string;
        }

        if !in_line_comment && !in_string {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    body_end = body_start + i;
                    break;
                }
            }
        }
        prev_char = ch;
    }

    if depth != 0 {
        return None; // Unbalanced braces
    }

    Some(source[body_start..=body_end].to_string())
}

/// Returns `true` if the body of `fn_name` in `source` contains `callee`.
fn fn_body_contains(source: &str, fn_name: &str, callee: &str) -> bool {
    extract_fn_body(source, fn_name).is_some_and(|body| body.contains(callee))
}

// ===========================================================================
// Baseline assertions — currently wired, must pass today
// ===========================================================================

// Manager level: send_message path calls crypto.seal (full envelope pipeline)
// seal is in build_encrypted_envelope helper called from send_message
#[test]
fn send_message_calls_seal() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", ".seal(")
            || fn_body_contains(MANAGER_SRC, "build_encrypted_envelope", ".seal("),
        "send_message path must call crypto.seal (envelope pipeline)"
    );
}

// Manager level: send_message delegates to encrypt_and_send which calls transport.send_message
#[test]
fn send_message_calls_transport_send() {
    // send_message delegates to encrypt_and_send, which calls transport.send_message.
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "encrypt_and_send"),
        "send_message must call encrypt_and_send"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "encrypt_and_send", ".send_message("),
        "encrypt_and_send must call transport.send_message"
    );
}

// Manager level: deliver_incoming calls crypto.open (full envelope pipeline)
// Note: the `.open(` call is now inside the `decrypt_and_dispatch` helper
// which `deliver_incoming` delegates to. The assertion accepts either the
// direct call in `deliver_incoming` or the call in the helper, plus the
// delegation from `deliver_incoming` to `decrypt_and_dispatch`.
#[test]
fn deliver_incoming_calls_open() {
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", ".open(")
            || (fn_body_contains(MANAGER_SRC, "deliver_incoming", "decrypt_and_dispatch")
                && fn_body_contains(MANAGER_SRC, "decrypt_and_dispatch", ".open(")),
        "deliver_incoming must call crypto.open (envelope pipeline), either directly \
         or via decrypt_and_dispatch"
    );
}

// Provider level: seal calls create_outer_envelope (envelope construction)
#[test]
fn seal_calls_create_outer_envelope() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "seal", "create_outer_envelope"),
        "seal (provider) must call create_outer_envelope"
    );
}

// Provider level: seal calls encrypt_sender_layer (sender key encryption)
#[test]
fn seal_calls_encrypt_sender_layer() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "seal", "encrypt_sender_layer"),
        "seal (provider) must call encrypt_sender_layer"
    );
}

// Provider level: open calls decrypt_sender_layer
#[test]
fn open_calls_decrypt_sender_layer() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "open", "decrypt_sender_layer"),
        "open (provider) must call decrypt_sender_layer"
    );
}

// --- Envelope layer (#1534) — NOW WIRED ---

#[test]
fn encrypt_path_calls_create_outer_envelope_or_seal() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "seal", "create_outer_envelope")
            || fn_body_contains(MANAGER_SRC, "send_message", "create_outer_envelope"),
        "send/encrypt path must call create_outer_envelope"
    );
}

// --- Inner envelope / signatures (#1534, #1547) — NOW WIRED ---

#[test]
fn encrypt_path_calls_create_inner_envelope() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "create_inner_envelope_raw")
            || fn_body_contains(
                MANAGER_SRC,
                "build_encrypted_envelope",
                "create_inner_envelope_raw"
            ),
        "send path must call create_inner_envelope_raw"
    );
}

#[test]
fn decrypt_path_calls_verify_inner_signature() {
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", "verify_inner_signature")
            || fn_body_contains(MANAGER_SRC, "verify_and_unwrap", "verify_inner_signature"),
        "receive/decrypt path must call verify_inner_signature"
    );
}

// --- Content wrapping (#1529) — NOW WIRED ---

#[test]
fn encrypt_path_calls_wrap_content() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "wrap_content")
            || fn_body_contains(MANAGER_SRC, "build_encrypted_envelope", "wrap_content"),
        "send path must call wrap_content"
    );
}

#[test]
fn decrypt_path_calls_unwrap_content() {
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", "unwrap_content")
            || fn_body_contains(MANAGER_SRC, "verify_and_unwrap", "unwrap_content"),
        "receive/decrypt path must call unwrap_content"
    );
}

// --- Padding (#1534) — NOW WIRED ---

#[test]
fn decrypt_path_calls_strip_padding() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "open", "strip_padding")
            || fn_body_contains(MANAGER_SRC, "deliver_incoming", "strip_padding")
            || fn_body_contains(MANAGER_SRC, "verify_and_unwrap", "strip_padding"),
        "receive/decrypt path must call strip_padding"
    );
}

// --- Provenance (#1536) — WIRED (conditional on cross-context source) ---
// attach_provenance is called in build_encrypted_envelope when
// source_provenance is Some (cross-context data flow). For intra-context
// direct messages source_provenance is None and attach_provenance is not
// invoked. The pipeline test verifies the code path exists.

#[test]
fn encrypt_path_references_attach_provenance() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "attach_provenance")
            || fn_body_contains(MANAGER_SRC, "build_encrypted_envelope", "attach_provenance"),
        "send path must reference attach_provenance"
    );
}

// --- Anti-replay + reorder buffer (#1546, §9.8.5) — NOW WIRED ---

#[test]
fn deliver_incoming_calls_validate_received_envelope() {
    // deliver_incoming delegates to validate_and_drain_timeouts which
    // uses SequenceTracker::validate and TimestampValidator::validate
    // separately, enabling out-of-order buffering per §9.8.5 while
    // maintaining anti-replay protection.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "deliver_incoming",
            "validate_and_drain_timeouts"
        ) && fn_body_contains(
            MANAGER_SRC,
            "validate_and_drain_timeouts",
            "sequence_tracker"
        ) && fn_body_contains(MANAGER_SRC, "validate_and_drain_timeouts", "tv.validate"),
        "deliver_incoming must validate timestamps and sequence numbers (anti-replay + reorder)"
    );
}

// --- Access key generation on member add (#1529) — NOW WIRED ---

#[test]
fn execute_add_member_calls_generate_access_key() {
    assert!(
        fn_body_contains(MANAGER_SRC, "execute_add_member", "generate_access_key"),
        "execute_add_member must call generate_access_key"
    );
}

// --- Join-time sender key MLS framing (H3) ---
//
// `join_context` must MLS-wrap pending HPKE-sealed sender key distributions
// via the shared `drain_and_deliver_sender_keys` helper before posting them
// to transport. The helper calls `mls_encrypt_management`, which prepends
// the SCPM management magic and wraps the bytes in an OuterEnvelope so the
// receive-side dispatcher routes them through `OpenResult::Management`.
//
// The original join path called `transport.send_message` directly with the
// raw HPKE bytes, which the joiner could not deserialize as an OuterEnvelope.
// This regression silently dropped sender key distributions on join.

#[test]
fn join_context_calls_drain_and_deliver_sender_keys() {
    assert!(
        fn_body_contains(MANAGER_SRC, "join_context", "drain_and_deliver_sender_keys"),
        "join_context must delegate sender key distribution to \
         drain_and_deliver_sender_keys so distributions are MLS-wrapped (H3). \
         Sending raw HPKE-sealed bytes via transport.send_message bypasses the \
         OuterEnvelope/SCPM framing the receive-side dispatcher requires."
    );
}

#[test]
fn join_context_does_not_send_raw_drained_sender_keys() {
    // Negative assertion: the join path must NOT loop over the drained
    // pending messages and call transport.send_message directly. The
    // bug shape was a `for ... in drain_pending_sender_key_messages`
    // loop posting raw bytes. The fix uses the helper exclusively.
    let body = extract_fn_body(MANAGER_SRC, "join_context")
        .expect("join_context body must exist for H3 negative assertion");
    assert!(
        !body.contains(".drain_pending_sender_key_messages("),
        "join_context must NOT call drain_pending_sender_key_messages directly — \
         use drain_and_deliver_sender_keys so distributions are MLS-wrapped (H3)"
    );
}

#[test]
fn drain_and_deliver_sender_keys_calls_mls_encrypt_management() {
    // The helper itself must MLS-wrap each distribution. This is the
    // root invariant — without it, callers (including join_context and
    // the rotation paths) would still post raw HPKE bytes.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "drain_and_deliver_sender_keys",
            "mls_encrypt_management"
        ),
        "drain_and_deliver_sender_keys must call mls_encrypt_management so \
         pending sender key distributions are wrapped in the management channel \
         framing the receive-side dispatcher recognizes (H3, §9.16.2)"
    );
}

// --- Negative assertion: send_message must NOT call old encrypt_message ---

#[test]
fn send_message_does_not_call_encrypt_message() {
    assert!(
        !fn_body_contains(MANAGER_SRC, "send_message", ".encrypt_message("),
        "send_message must NOT call the old encrypt_message (replaced by seal)"
    );
}

// ===========================================================================
// Ignored assertions — unwired pipeline steps
//
// Each assertion references the GitHub issue that will wire it.
// When the wiring PR lands, remove the #[ignore] attribute.
// ===========================================================================

// --- Governance / lifecycle ---

#[test]
fn execute_remove_member_calls_remove_member_sender_key() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "execute_remove_member",
            "remove_member_sender_key"
        ),
        "execute_remove_member must call remove_member_sender_key"
    );
}

#[test]
fn execute_remove_member_calls_rotate_sender_key() {
    assert!(
        fn_body_contains(MANAGER_SRC, "execute_remove_member", "rotate_sender_key"),
        "execute_remove_member must call rotate_sender_key (§9.16.4)"
    );
}

#[test]
fn leave_context_calls_rotate_sender_key() {
    assert!(
        fn_body_contains(MANAGER_SRC, "leave_context", "rotate_sender_key"),
        "leave_context must call rotate_sender_key (§9.16.4)"
    );
}

// SCP-OUT-042b + SCP-OUT-042d — accept-time IKM verification + the
// quadratic interface-spam-cost gate. The runtime governance
// dispatch MUST route `GovernanceAction::AcceptOutletInterface` to
// `accept_outlet_interface`, which runs §6.2.0.1 step-1 IKM
// derivation, the `SCP-OUTLET-IKM-COMMITMENT-V1:` signature
// verification, and the round-6 quadratic-fee
// `protocol.interface-spam-cost` gate before appending the
// `OutletInterfaceAccepted` event. Without this assertion, the
// handler is exported but never called from production code — every
// defense (IKM signature verification, capability_holder_set
// capture, InterfaceEstablished event emission, quadratic-fee
// rejection) becomes structurally dead.
#[test]
fn accept_outlet_interface_routed_from_governance() {
    // Inner dispatcher: the `AcceptOutletInterface` arm in
    // `dispatch_content_governance_action` MUST call
    // `execute_accept_outlet_interface`.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "dispatch_content_governance_action",
            "execute_accept_outlet_interface"
        ),
        "dispatch_content_governance_action must dispatch \
         AcceptOutletInterface to execute_accept_outlet_interface \
         (§6.2.0.1 step 4, SCP-OUT-042b/d remediation)"
    );
    // Wrapper: the runtime's `execute_accept_outlet_interface`
    // method MUST invoke the cryptographic handler
    // `accept_outlet_interface`, which is what runs IKM signature
    // verification + the quadratic-fee gate.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "execute_accept_outlet_interface",
            "accept_outlet_interface"
        ),
        "execute_accept_outlet_interface must call \
         ContextManager::accept_outlet_interface (the OUT-042b \
         crypto pipeline + OUT-042d quadratic-fee gate)"
    );
    // Pin the rejection slugs to non-test source so future
    // refactors cannot silently drop the canonical mappings. The
    // dispatch wrapper delegates the post-handler error mapping to
    // `finalize_accept_outlet_interface`; the slugs live there.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "finalize_accept_outlet_interface",
            "AUTHORIZATION_IKM_SIGNATURE_INVALID_SLUG"
        ),
        "finalize_accept_outlet_interface must surface the §6.2.0.1 \
         verifier-rule slug authorization.ikm-signature-invalid"
    );
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "finalize_accept_outlet_interface",
            "INTERFACE_SPAM_COST_SLUG"
        ),
        "finalize_accept_outlet_interface must surface the OUT-042d \
         round-6 slug protocol.interface-spam-cost"
    );
    // Wrapper MUST delegate to the finalizer — pin that wiring too
    // so the slug-pinning above cannot be bypassed by a future
    // refactor that inlines the error mapping somewhere else.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "execute_accept_outlet_interface",
            "finalize_accept_outlet_interface"
        ),
        "execute_accept_outlet_interface must delegate post-handler \
         error mapping to finalize_accept_outlet_interface so the \
         canonical slug + code constants stay reachable"
    );
}

// SCP-OUT-042c — atomic admin-removal salt rotation. Per spec §6.2.0.1
// round-6 "Atomic removal+rotation — local-side semantics", the
// `RemoveMember` handler MUST emit one `InterfaceSaltRotated` per
// active interface as a sibling commit-batch entry. This assertion
// pins the wiring so a future refactor cannot silently regress to
// the round-5 best-effort pattern that admitted the BLOCKER-2 /
// MAJOR-3 covert-channel race.
#[test]
fn admin_removal_emits_induced_rotations() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "execute_remove_member",
            "emit_admin_removal_with_rotations"
        ),
        "execute_remove_member must call \
         governance::admin_removal::emit_admin_removal_with_rotations \
         (§6.2.0.1 round-6 atomic admin-removal salt rotation, SCP-OUT-042c)"
    );
    // Defense in depth — the handler MUST also append the rotation
    // events to the local event log as sibling commit-batch entries
    // (§6.2.0.1 "Commit atomicity"). The append uses the
    // `InterfaceSaltRotated` event-name constant.
    assert!(
        fn_body_contains(MANAGER_SRC, "execute_remove_member", "InterfaceSaltRotated"),
        "execute_remove_member must append InterfaceSaltRotated events \
         alongside the RemoveMember commit (§6.2.0.1 commit atomicity)"
    );
}

// --- Proposer eligibility / Participation (#1530) ---

#[test]
fn propose_governance_checks_proposer_eligibility() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "propose_governance_action_inner",
            "check_proposer_eligibility"
        ),
        "propose_governance_action_inner must consult proposer eligibility \
         (pending removal + participation threshold)"
    );
}

// --- Consequences (#1531) ---

#[test]
fn governance_dispatch_calls_evaluate_consequences() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "dispatch_consequences",
            "evaluate_consequence_rules"
        ),
        "dispatch_consequences must call evaluate_consequence_rules"
    );
}

// --- Economy (#1537) ---

#[test]
fn governance_enforces_economic_policy() {
    // Economy enforcement is unified in enforce_economy (economy.rs) which calls
    // evaluate_cost. Both enforce_send_economy and enforce_join_economy delegate
    // to enforce_economy. Check the unified function and the delegation.
    assert!(
        fn_body_contains(MANAGER_SRC, "enforce_economy", "evaluate_cost"),
        "enforce_economy must call evaluate_cost"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "enforce_send_economy", "enforce_economy"),
        "enforce_send_economy must delegate to enforce_economy"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "enforce_join_economy", "enforce_economy"),
        "enforce_join_economy must delegate to enforce_economy"
    );
    // F9: enforce_economy must take the EnforceEconomyRequest struct (not a
    // long positional argument list). Both call sites must construct one.
    assert!(
        MANAGER_SRC.contains("fn enforce_economy(\n    req: EnforceEconomyRequest"),
        "enforce_economy must take EnforceEconomyRequest (F9 refactor)"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "enforce_send_economy", "EnforceEconomyRequest"),
        "enforce_send_economy must construct EnforceEconomyRequest"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "enforce_join_economy", "EnforceEconomyRequest"),
        "enforce_join_economy must construct EnforceEconomyRequest"
    );
}

// --- Per-DID anti-spam escalation for outlet invocations (§19.7) ---

#[test]
fn invoke_outlet_with_economy_wires_escalation_and_rollback() {
    // The manager wrapper must (a) call the free invoke_outlet, (b) record the
    // new velocity entry so compute_escalated_cost sees it, (c) thread the
    // per-context velocity_tracker and message_pricing into OutletEconomyContext,
    // and (d) roll back the velocity entry on invocation failure.
    assert!(
        fn_body_contains(MANAGER_SRC, "invoke_outlet_with_economy", "invoke_outlet"),
        "invoke_outlet_with_economy must delegate to invoke_outlet"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "invoke_outlet_with_economy", "record_message"),
        "invoke_outlet_with_economy must record the invocation for velocity tracking"
    );
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_outlet_with_economy",
            "velocity_tracker"
        ),
        "invoke_outlet_with_economy must thread velocity_tracker into OutletEconomyContext"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "invoke_outlet_with_economy", "message_pricing"),
        "invoke_outlet_with_economy must thread message_pricing into OutletEconomyContext"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "invoke_outlet_with_economy", ".rollback("),
        "invoke_outlet_with_economy must roll back the velocity entry on failure \
         via the F5 identity-based `rollback(token)` API"
    );
}

/// D4: `invoke_outlet_with_economy` must reference the hard rate limit.
/// Enforced structurally so a future refactor cannot silently drop
/// the Matrix Synapse–style defense-in-depth cap on the outlet path.
#[test]
fn invoke_outlet_with_economy_enforces_hard_rate_limit() {
    assert!(
        fn_body_contains(MANAGER_SRC, "invoke_outlet_with_economy", "hard_rate_limit"),
        "invoke_outlet_with_economy must reference hard_rate_limit so the Matrix Synapse–style \
         defense-in-depth cap is enforced on the outlet path (D4)"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "invoke_outlet_with_economy", "try_consume"),
        "invoke_outlet_with_economy must call try_consume on the hard rate limit token bucket \
         before any Phase 1 bookkeeping — mirrors enforce_send_economy at messaging.rs:346"
    );
}

/// D4: every Phase 1 failure branch in `invoke_outlet_with_economy`
/// MUST refund the hard rate limit token. We expect at least 3 inline
/// refund sites: `economy_pre_check` failure, `record_spend` failure,
/// and `authorize_outlet_payment` failure. Dropping any branch leaks a
/// rate-limit token on failure.
#[test]
fn invoke_outlet_with_economy_refunds_hard_rate_limit_on_every_phase1_failure() {
    let body = extract_fn_body(MANAGER_SRC, "invoke_outlet_with_economy")
        .expect("invoke_outlet_with_economy body must exist");
    let refund_sites = body.matches("hard_rate_limit.refund").count();
    assert!(
        refund_sites >= 3,
        "invoke_outlet_with_economy must have at least 3 inline hard_rate_limit.refund sites \
         (economy_pre_check failure, record_spend failure, authorize_outlet_payment failure); \
         found {refund_sites}. Dropping any branch leaks a rate-limit token on failure."
    );
}

#[test]
fn invoke_outlet_with_economy_releases_lock_before_executor() {
    // F1-F3 lock-split invariant: the caller-supplied executor must run
    // WITHOUT holding the `ContextManager.contexts` mutex. The wrapper
    // must explicitly release the Phase-1 lock before dispatching the
    // executor. A mis-behaving outlet executor blocked every concurrent
    // manager call until this refactor landed; regressions here reintroduce
    // a process-wide stall bug.
    //
    // We assert:
    //   (1) The function body contains an explicit `drop(contexts)` call.
    //       This is the exit boundary of Phase 1.
    //   (2) The function body acquires `self.contexts.lock()` at least
    //       twice — once in Phase 1 (pre-check / record_spend / escrow
    //       authorize) and once in Phase 3 (post-invocation bookkeeping).
    //       A single lock acquisition would imply the lock is held across
    //       the executor future.
    // Phase B: invoke_outlet_with_economy uses lock_context (Phase 1) and
    // relock_context (Phase 3) instead of bare self.contexts.lock().await.
    // The lock is dropped between phases so the executor future runs unlocked.
    let body = extract_fn_body(MANAGER_SRC, "invoke_outlet_with_economy")
        .expect("invoke_outlet_with_economy body must exist");
    assert!(
        body.contains("lock_context") && body.contains("relock_context"),
        "invoke_outlet_with_economy must use lock_context (Phase 1) and \
         relock_context (Phase 3) for per-context locking with generation check"
    );
}

// --- Content key rotation (#1548) ---

#[test]
fn rotate_content_keys_calls_propose_update() {
    assert!(
        fn_body_contains(MANAGER_SRC, "execute_rotate_content_keys", "advance_epoch")
            || fn_body_contains(MANAGER_SRC, "execute_rotate_content_keys", "propose_update"),
        "execute_rotate_content_keys must call advance_epoch or propose_update for encrypted mode MLS rotation"
    );
}

// ---------------------------------------------------------------------------
// WASM bridge: consequence dispatch wiring
//
// The WASM bridge (scp-ffi-wasm) is a parallel implementation of consequence
// rule enforcement to the scp-runtime path. Both must dispatch consequences at
// every mutation site the plan identifies so rate- and participation-based
// rules fire on either bridge. These assertions catch the wiring regression
// (observed historically as "consequence rules declared but never enforced in
// WASM") by structurally verifying the dispatch call sites on the WASM manager
// and the delegation from the dispatcher to the shared scp-protocol evaluator.
// ---------------------------------------------------------------------------

#[test]
fn wasm_send_message_dispatches_consequences() {
    assert!(
        fn_body_contains(
            WASM_MANAGER_SRC,
            "send_message",
            "dispatch_consequences_for_subject",
        ),
        "WASM send_message body must call dispatch_consequences_for_subject \
         after appending MessageSent so rate-based rules fire on the sender"
    );
}

#[test]
fn wasm_execute_governance_action_dispatches_consequences() {
    let body = extract_fn_body(WASM_MANAGER_SRC, "execute_governance_action")
        .expect("WASM execute_governance_action body must exist");
    let call_count = body.matches("dispatch_consequences_for_subject").count();
    assert!(
        call_count >= 2,
        "WASM execute_governance_action must call dispatch_consequences_for_subject \
         at least twice (once for the executor DID, once for the action's target \
         DID); found {call_count}"
    );
}

#[test]
fn wasm_dispatch_consequences_calls_evaluate_consequence_rules() {
    assert!(
        fn_body_contains(
            WASM_CONSEQUENCE_SRC,
            "dispatch_consequences_for_subject",
            "evaluate_consequence_rules",
        ),
        "WASM dispatch_consequences_for_subject must delegate to the shared \
         scp-protocol evaluate_consequence_rules function so rule-matching \
         logic stays consistent between bridges"
    );
}

// ---------------------------------------------------------------------------
// C2 — WASM economy fail-closed gate (PR #1606 follow-up)
//
// The WASM bridge cannot run scp-runtime's `enforce_economy` pipeline (no
// payment adapter, no budget tracker, no velocity tracker, no hard rate
// limit token bucket — see ADR-034). Without a fail-closed gate, paid
// contexts would silently bypass economic enforcement on every send / join.
//
// These assertions verify the gate exists at the AST level so a future
// refactor cannot silently delete the spending_ucan_jwt parameter wiring
// or the economic_policy inspection branch.
// ---------------------------------------------------------------------------

#[test]
fn wasm_send_message_inspects_spending_ucan_and_economic_policy() {
    let body = extract_fn_body(WASM_MANAGER_SRC, "send_message")
        .expect("WASM send_message body must exist");

    // The parameter must NOT be underscore-prefixed: that name silently
    // discards the JWT and was the original C2 bug. The C2 fix renames
    // it to `spending_ucan_jwt` and references it in the rejection
    // branch so the parameter is no longer dropped.
    assert!(
        body.contains("spending_ucan_jwt"),
        "WASM send_message body must reference `spending_ucan_jwt` so the \
         parameter is no longer silently discarded (C2 fail-closed gate)"
    );

    // The body must inspect the context's economic_policy to drive the
    // fail-closed rejection branch.
    assert!(
        body.contains("economic_policy"),
        "WASM send_message body must reference `economic_policy` to drive \
         the fail-closed rejection (C2 — paid policies cannot be enforced \
         on the WASM bridge per ADR-034)"
    );

    // The reject branch must surface the SCP-ECON-12096 code so the SDK
    // layer can convert it to a typed `WasmCannotValidateSpendingUcan`
    // error.
    assert!(
        body.contains("SCP_ECON_WASM_CANNOT_VALIDATE_SPENDING_UCAN")
            || body.contains("SCP-ECON-12096"),
        "WASM send_message must emit SCP-ECON-12096 in the C2 rejection branch"
    );
}

// C4 (#1606) — Bridge outlet-invoke economy wiring
//
// All 3 non-WASM FFI bridges (PyO3, NAPI, UniFFI) MUST route outlet
// invocation through `ContextManager::invoke_outlet_with_economy`. The
// previous bypass path called `try_consume_hard_rate_limit_*` directly
// against the bridge-owned outlet registry, which disabled per-invocation
// pricing, spending UCAN AND-composition, velocity tracking, budget
// enforcement, and the `OutletEconomyTicket` lifecycle for Python /
// Node / Swift / Kotlin clients.
//
// These structural assertions catch any future regression to the
// bypass path. Each assertion is `fn_body_contains` against the actual
// bridge function source — calling the runtime helper from a different
// function would fail the test.
// ---------------------------------------------------------------------------

#[test]
fn c4_pyo3_outlet_invoke_routes_through_invoke_outlet_with_economy() {
    assert!(
        fn_body_contains(
            PYO3_OUTLETS_SRC,
            "py_outlet_invoke",
            "invoke_outlet_with_economy"
        ),
        "PyO3 py_outlet_invoke must call ContextManager::invoke_outlet_with_economy \
         (PR #1606 / C4). Calling try_consume_hard_rate_limit_blocking against \
         a bridge-owned registry instead disables per-invocation pricing, \
         spending UCAN, velocity tracking, and budget enforcement for Python \
         clients."
    );
}

#[test]
fn c4_pyo3_outlet_invoke_accepts_spending_ucan() {
    // The bridge MUST accept the spending UCAN parameter — the
    // runtime's `invoke_outlet_with_economy` requires it for §19.5
    // AND-composition on paid actions.
    let body = extract_fn_body(PYO3_OUTLETS_SRC, "py_outlet_invoke")
        .expect("py_outlet_invoke body must exist");
    assert!(
        body.contains("spending_ucan"),
        "PyO3 py_outlet_invoke must accept and forward a spending UCAN argument \
         (PR #1606 / C4). Without it, paid outlet invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "PyO3 py_outlet_invoke must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_outlet_with_economy."
    );
}

#[test]
fn c4_napi_outlet_invoke_routes_through_invoke_outlet_with_economy() {
    assert!(
        fn_body_contains(
            NAPI_OUTLETS_SRC,
            "outlet_invoke",
            "invoke_outlet_with_economy"
        ),
        "NAPI outlet_invoke must call ContextManager::invoke_outlet_with_economy \
         (PR #1606 / C4). The previous bypass path called \
         try_consume_hard_rate_limit against the bridge-owned outlet registry, \
         disabling per-invocation pricing, spending UCAN, velocity tracking, \
         and budget enforcement for Node clients."
    );
}

#[test]
fn c4_napi_outlet_invoke_accepts_spending_ucan() {
    let body = extract_fn_body(NAPI_OUTLETS_SRC, "outlet_invoke")
        .expect("NAPI outlet_invoke body must exist");
    assert!(
        body.contains("spending_ucan_jwt"),
        "NAPI outlet_invoke must accept and forward a spending_ucan_jwt argument \
         (PR #1606 / C4). Without it, paid outlet invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "NAPI outlet_invoke must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_outlet_with_economy."
    );
}

#[test]
fn wasm_join_context_inspects_spending_ucan_and_economic_policy() {
    let body = extract_fn_body(WASM_MANAGER_SRC, "join_context")
        .expect("WASM join_context body must exist");

    assert!(
        body.contains("spending_ucan_jwt"),
        "WASM join_context body must reference `spending_ucan_jwt` so the \
         parameter is no longer silently discarded (C2 fail-closed gate)"
    );

    assert!(
        body.contains("economic_policy"),
        "WASM join_context body must reference `economic_policy` to drive \
         the fail-closed rejection (C2 — paid policies cannot be enforced \
         on the WASM bridge per ADR-034)"
    );

    assert!(
        body.contains("SCP_ECON_WASM_CANNOT_VALIDATE_SPENDING_UCAN")
            || body.contains("SCP-ECON-12096"),
        "WASM join_context must emit SCP-ECON-12096 in the C2 rejection branch"
    );
}

#[test]
fn wasm_create_context_rejects_paid_economic_policy() {
    let body = extract_fn_body(WASM_MANAGER_SRC, "create_context")
        .expect("WASM create_context body must exist");

    // The gate is implemented via the `stored_policy_requires_payment`
    // helper so the gate logic can be unit-tested independently. The
    // create-time gate ALSO references `economic_policy` (because that
    // is the field whose paid-ness is being checked) and surfaces the
    // SCP-ECON-12095 code in the rejection.
    assert!(
        body.contains("stored_policy_requires_payment"),
        "WASM create_context must call `stored_policy_requires_payment` to \
         drive the C2 fail-closed rejection of paid economic policies"
    );

    assert!(
        body.contains("SCP_ECON_PAID_POLICY_UNSUPPORTED_ON_WASM")
            || body.contains("SCP-ECON-12095"),
        "WASM create_context must emit SCP-ECON-12095 in the C2 rejection branch"
    );
}

#[test]
fn wasm_set_economic_policy_governance_rejects_paid_policy() {
    // The C2 gate also fires through governance dispatch so a paid
    // policy cannot enter WASM state via the back door. The dispatch
    // path was extracted to `dispatch_set_economic_policy` to keep the
    // parent match arm under `clippy::too_many_lines`.
    let body = extract_fn_body(WASM_MANAGER_SRC, "dispatch_set_economic_policy")
        .expect("WASM dispatch_set_economic_policy body must exist");

    assert!(
        body.contains("policy_requires_payment"),
        "WASM dispatch_set_economic_policy must call `policy_requires_payment` \
         to drive the C2 fail-closed rejection of paid economic policies via \
         governance"
    );

    assert!(
        body.contains("SCP_ECON_PAID_POLICY_UNSUPPORTED_ON_WASM")
            || body.contains("SCP-ECON-12095"),
        "WASM dispatch_set_economic_policy must emit SCP-ECON-12095 in the \
         C2 rejection branch"
    );
}

#[test]
fn c4_uniffi_outlet_invoke_routes_through_invoke_outlet_with_economy() {
    // `extract_fn_body` returns the first match, which is the
    // top-level `outlet_invoke` (not `outlet_invoke_cross_context`).
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "outlet_invoke",
            "invoke_outlet_with_economy"
        ),
        "UniFFI outlet_invoke must call ContextManager::invoke_outlet_with_economy \
         (PR #1606 / C4). The previous bypass path called \
         try_consume_hard_rate_limit against the bridge-owned outlet registry, \
         disabling per-invocation pricing, spending UCAN, velocity tracking, \
         and budget enforcement for Swift / Kotlin clients."
    );
}

#[test]
fn c4_uniffi_outlet_invoke_accepts_spending_ucan() {
    let body = extract_fn_body(UNIFFI_BRIDGE_SRC, "outlet_invoke")
        .expect("UniFFI outlet_invoke body must exist");
    assert!(
        body.contains("spending_ucan_jwt"),
        "UniFFI outlet_invoke must accept and forward a spending_ucan_jwt argument \
         (PR #1606 / C4). Without it, paid outlet invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "UniFFI outlet_invoke must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_outlet_with_economy."
    );
}

// ===========================================================================
// SCP-OUT-008 AC22 — outlet surface reaches runtime pipeline
//
// The FFI bridges MUST delegate register / invoke / deregister / verify /
// update to the scp_core::context::tools runtime facade (which re-exports
// the protocol-level outlet registry + runtime invocation pipeline).
// Each outlet lifecycle verb is asserted on all 3 non-WASM FFI bridges
// (PyO3, NAPI, UniFFI). invoke is already covered by the C4 assertions
// above; these additions cover the remaining verbs.
// ===========================================================================

/// `register_outlet` reaches the runtime pipeline via the protocol-level
/// registry function (`scp_core::context::tools::register_outlet`) from all
/// three non-WASM FFI bridges.
#[test]
fn out008_register_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(PYO3_OUTLETS_SRC, "py_outlet_register", "register_outlet"),
        "PyO3 py_outlet_register must delegate to scp_core::context::tools::register_outlet \
         so outlet registration flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(NAPI_OUTLETS_SRC, "outlet_register", "register_outlet"),
        "NAPI outlet_register must delegate to scp_core::context::tools::register_outlet \
         so outlet registration flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "outlet_register", "register_outlet"),
        "UniFFI outlet_register must delegate to scp_core::context::tools::register_outlet \
         so outlet registration flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
}

/// `invoke_outlet` reaches the runtime pipeline via
/// `ContextManager::invoke_outlet_with_economy` on all three non-WASM FFI
/// bridges. The C4 assertions above cover the same invariant in isolation;
/// this test asserts the 3-bridge set under the SCP-OUT-008 AC22 name so the
/// outlet surface is enumerated uniformly with register / update / verify /
/// deregister.
#[test]
fn out008_invoke_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(
            PYO3_OUTLETS_SRC,
            "py_outlet_invoke",
            "invoke_outlet_with_economy"
        ),
        "PyO3 py_outlet_invoke must call ContextManager::invoke_outlet_with_economy \
         (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(
            NAPI_OUTLETS_SRC,
            "outlet_invoke",
            "invoke_outlet_with_economy"
        ),
        "NAPI outlet_invoke must call ContextManager::invoke_outlet_with_economy \
         (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "outlet_invoke",
            "invoke_outlet_with_economy"
        ),
        "UniFFI outlet_invoke must call ContextManager::invoke_outlet_with_economy \
         (SCP-OUT-008 AC22)"
    );
}

/// `update_outlet` reaches the runtime pipeline via the protocol-level
/// registry function (`scp_core::context::tools::update_outlet`) from all
/// three non-WASM FFI bridges.
#[test]
fn out008_update_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(PYO3_OUTLETS_SRC, "py_outlet_update", "update_outlet"),
        "PyO3 py_outlet_update must delegate to scp_core::context::tools::update_outlet \
         so outlet updates flow through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(NAPI_OUTLETS_SRC, "outlet_update", "update_outlet"),
        "NAPI outlet_update must delegate to scp_core::context::tools::update_outlet \
         so outlet updates flow through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "outlet_update", "update_outlet"),
        "UniFFI outlet_update must delegate to scp_core::context::tools::update_outlet \
         so outlet updates flow through the runtime pipeline (SCP-OUT-008 AC22)"
    );
}

/// `verify_outlet` reaches the runtime pipeline via the protocol-level
/// registry function (`scp_core::context::tools::verify_outlet`) from all
/// three non-WASM FFI bridges.
#[test]
fn out008_verify_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(PYO3_OUTLETS_SRC, "py_outlet_verify", "verify_outlet"),
        "PyO3 py_outlet_verify must delegate to scp_core::context::tools::verify_outlet \
         so outlet verification flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(NAPI_OUTLETS_SRC, "outlet_verify", "verify_outlet"),
        "NAPI outlet_verify must delegate to scp_core::context::tools::verify_outlet \
         so outlet verification flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "outlet_verify", "verify_outlet"),
        "UniFFI outlet_verify must delegate to scp_core::context::tools::verify_outlet \
         so outlet verification flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
}

/// `deregister_outlet` reaches the runtime pipeline via the protocol-level
/// `outlet_registry` mutation (`OutletRegistry::remove`) from all three
/// non-WASM FFI bridges. The protocol registry IS the runtime pipeline for
/// outlet deregistration (no higher-level wrapper exists — mirrors the
/// shape of register/update/verify which also delegate to registry-level
/// functions).
#[test]
fn out008_deregister_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(PYO3_OUTLETS_SRC, "py_outlet_deregister", "outlet_registry"),
        "PyO3 py_outlet_deregister must mutate the runtime outlet_registry \
         (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(NAPI_OUTLETS_SRC, "outlet_deregister", "outlet_registry"),
        "NAPI outlet_deregister must mutate the runtime outlet_registry \
         (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "outlet_deregister", "outlet_registry"),
        "UniFFI outlet_deregister must mutate the runtime outlet_registry \
         (SCP-OUT-008 AC22)"
    );
}

/// Negative assertion: no `tool_*` runtime-pipeline symbols remain in the
/// pipeline_wiring assertion table. After the SCP-OUT-002/004/005/006
/// rename, every outlet-surface assertion references `outlet_*` and
/// `invoke_outlet_with_economy` — any `tool_*` symbol appearing in a
/// live assertion (outside this negative meta-test, its own forbidden list,
/// and the MCP external boundary vocabulary) indicates the rename regressed.
///
/// The forbidden symbols are deliberately quoted with angle-brackets instead
/// of parentheses so this meta-test's own forbidden list does NOT contain
/// literal `tool_*` tokens that would self-match. The check rebuilds the
/// actual runtime-pipeline token from an angle-bracket-quoted template at
/// runtime before scanning the source.
/// Rebuild the literal tool_* token from an angle-bracket-quoted template,
/// preserving the original capitalization (so "T<>l" → "Tool", "t<>l" →
/// "tool"). Used by the `out008_no_tool_symbols_in_outlet_assertion_table`
/// meta-test so this file can list forbidden tokens without self-matching.
fn unquote_tool_template(template: &str) -> String {
    template.replace("T<>l", "Tool").replace("t<>l", "tool")
}

#[test]
fn out008_no_tool_symbols_in_outlet_assertion_table() {
    let source = include_str!("pipeline_wiring.rs");

    // Forbidden-list entries are angle-bracket-quoted templates rather than
    // the literal tool_* strings so this test's own body does not match.
    // Each template maps t<>l to `tool` at runtime via `unquote_tool_template`.
    let forbidden_templates: &[&str] = &[
        "invoke_t<>l_with_economy",
        "register_t<>l(",
        "update_t<>l(",
        "verify_t<>l(",
        "deregister_t<>l(",
        "T<>lRegistration",
        "T<>lRegistry",
        "T<>lSchema",
        "T<>lEconomyTicket",
    ];

    // Build the stripped source: replace this function's body with a
    // placeholder so the forbidden-list templates in our source code do
    // not themselves self-match after unquoting. We use a sentinel comment
    // marker rather than brace matching so string literals and nested
    // braces don't confuse us.
    let self_fn = "fn out008_no_tool_symbols_in_outlet_assertion_table";
    let end_marker = "// END_OF_OUT008_NO_TOOL_SYMBOLS_FN";
    let cleaned: String = source.find(self_fn).map_or_else(
        || source.to_string(),
        |start| {
            let after = &source[start..];
            after.find(end_marker).map_or_else(
                || source.to_string(),
                |end_off| {
                    let abs_end = start + end_off + end_marker.len();
                    format!(
                        "{}\n{}_STRIPPED_FOR_SELF_CHECK\n{}",
                        &source[..start],
                        self_fn,
                        &source[abs_end..]
                    )
                },
            )
        },
    );

    let mut hits: Vec<String> = Vec::new();
    for template in forbidden_templates {
        let needle = unquote_tool_template(template);
        if cleaned.contains(&needle) {
            hits.push(needle);
        }
    }
    assert!(
        hits.is_empty(),
        "pipeline_wiring.rs assertion table still references tool_* runtime-pipeline \
         symbols after SCP-OUT-008 rename: {hits:?}. Rename them to outlet_* or \
         remove the assertion."
    );
}
// END_OF_OUT008_NO_TOOL_SYMBOLS_FN

// ===========================================================================
// Batch 3 — Transport/infra wiring (all #[ignore] until implemented)
// ===========================================================================

/// Cover traffic must auto-start when a relay connection is established.
/// NativeRelayAdapter::connect_sourced (or a post-connect hook) must call
/// start_cover_traffic based on the TransportProfile tier. After the
/// finalize_connection refactor, the logic may live in `finalize_connection`.
#[test]
fn b3_cover_traffic_auto_start() {
    // Check connect_sourced, connect_sourced_with_bearer, AND finalize_connection —
    // the logic may be in any of them (including after refactor to a shared helper).
    let bodies: String = [
        extract_fn_body(ADAPTER_SRC, "connect_sourced"),
        extract_fn_body(ADAPTER_SRC, "connect_sourced_with_bearer"),
        extract_fn_body(ADAPTER_SRC, "finalize_connection"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n");
    assert!(
        !bodies.is_empty(),
        "connect_sourced, connect_sourced_with_bearer, or finalize_connection must exist in adapter.rs"
    );
    assert!(
        bodies.contains("start_cover_traffic"),
        "NativeRelayAdapter connection path must auto-start cover traffic"
    );
}

/// HeartbeatMonitor must be created when a relay connection is established.
/// The adapter (or client) must instantiate HeartbeatMonitor and start
/// a background heartbeat send/check loop. After the finalize_connection
/// refactor, the logic may live in `finalize_connection`.
#[test]
fn b3_heartbeat_monitor_instantiated() {
    let bodies: String = [
        extract_fn_body(ADAPTER_SRC, "connect_sourced"),
        extract_fn_body(ADAPTER_SRC, "connect_sourced_with_bearer"),
        extract_fn_body(ADAPTER_SRC, "finalize_connection"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n");
    assert!(
        !bodies.is_empty(),
        "connect_sourced, connect_sourced_with_bearer, or finalize_connection must exist in adapter.rs"
    );
    assert!(
        bodies.contains("HeartbeatMonitor") || bodies.contains("heartbeat"),
        "NativeRelayAdapter connection path must create a HeartbeatMonitor"
    );
}

/// Checkpoint generation must be wired into the context lifecycle.
/// close_context must call force_create_checkpoint for archival.
/// send_message/deliver_incoming should call create_checkpoint_if_due periodically.
#[test]
fn b3_checkpoint_generation_wired() {
    // close_context_with_key must call force_create_checkpoint for archival.
    let body = extract_fn_body(MANAGER_SRC, "close_context_with_key")
        .expect("close_context_with_key must exist in manager source");
    assert!(
        body.contains("force_create_checkpoint") || body.contains("create_checkpoint"),
        "close_context_with_key must generate a final checkpoint"
    );

    // finalize_send must call create_checkpoint_if_due for periodic checkpoints.
    let send_body = extract_fn_body(MANAGER_SRC, "finalize_send")
        .expect("finalize_send must exist in manager source");
    assert!(
        send_body.contains("create_checkpoint_if_due") || send_body.contains("checkpoint"),
        "finalize_send must track checkpoint events"
    );
}

/// Merkle proof verification must be wired into the equivocation detection path.
/// compare_remote_checkpoint must compare local and remote Merkle roots
/// and emit EquivocationDetected when divergent (§9.9.3, ADR-011 AC-8).
#[test]
fn b3_merkle_proof_verification_wired() {
    // compare_remote_checkpoint must exist and perform comparison.
    let body = extract_fn_body(MANAGER_SRC, "compare_remote_checkpoint")
        .expect("compare_remote_checkpoint must exist in manager source");
    assert!(
        body.contains("merkle_root") || body.contains("event_log_merkle_root"),
        "compare_remote_checkpoint must compare Merkle roots"
    );
    assert!(
        body.contains("Divergent") || body.contains("EquivocationDetected"),
        "compare_remote_checkpoint must detect divergence / equivocation"
    );
}

/// Webhook dispatch must exist and be wired into bridge event handling.
/// ApplicationNode must dispatch webhooks when context events occur for
/// registered bridges with webhook_url.
#[test]
fn b3_webhook_dispatch_wired() {
    let node_src = include_str!("../../../../crates/scp-node/src/lib.rs");
    assert!(
        node_src.contains("mod webhook"),
        "ApplicationNode must have webhook module registered"
    );

    let webhook_src = include_str!("../../../../crates/scp-node/src/webhook.rs");
    assert!(
        webhook_src.contains("dispatch_webhook"),
        "webhook module must export dispatch_webhook function"
    );
    assert!(
        webhook_src.contains("WebhookEvent"),
        "webhook module must define WebhookEvent type"
    );
    assert!(
        webhook_src.contains("X-SCP-Signature"),
        "webhook dispatch must set X-SCP-Signature header"
    );
    assert!(
        webhook_src.contains("X-SCP-Timestamp"),
        "webhook dispatch must set X-SCP-Timestamp header"
    );
    assert!(
        webhook_src.contains("validate_webhook_url"),
        "webhook module must include SSRF validation"
    );
}

// ===========================================================================
// Meta-tests — ratchet and tamper detection
// ===========================================================================

/// Ensures the number of active (non-ignored) pipeline assertions never
/// decreases. This prevents weakening the test suite by adding `#[ignore]`
/// to passing tests or removing assertions entirely.
#[test]
fn pipeline_active_assertions_never_decrease() {
    let source = include_str!("pipeline_wiring.rs");
    // Count lines that are exactly `#[test]` (after trim) — this excludes
    // #[test] appearing in comments, string literals, or this counting code.
    let total_tests = source
        .lines()
        .filter(|line| line.trim() == "#[test]")
        .count();
    let ignored = source.matches("#[ignore = \"").count();
    let meta_tests = 4; // this test + claude_md_enforcement_sections_present + no_stale_ignores + out008_no_tool_symbols_in_outlet_assertion_table
    let active = total_tests - ignored - meta_tests;
    assert!(
        active >= MIN_ACTIVE_PIPELINE_ASSERTIONS,
        "Active pipeline assertions ({active}) dropped below minimum \
         ({MIN_ACTIVE_PIPELINE_ASSERTIONS}). Do not weaken the test suite — \
         fix the code instead."
    );
}

/// Asserts that no `#[ignore]` attributes remain in this test file.
///
/// Each batch-2 issue's wiring is verified individually: if the wiring
/// has landed (function body contains the expected callee), any
/// remaining `#[ignore]` referencing that issue is stale and must be
/// removed. A catch-all at the end rejects any `#[ignore]` at all.
#[test]
fn no_stale_ignores() {
    let mut stale: Vec<&str> = vec![];
    let source = include_str!("pipeline_wiring.rs");

    // Helper: returns true if source has an #[ignore = "..."] line mentioning `issue`.
    let has_ignore_for = |issue: &str| {
        source
            .lines()
            .any(|l| l.contains("#[ignore = \"") && l.contains(issue))
    };

    // #1531 — consequence evaluation wired in dispatch_consequences
    if fn_body_contains(
        MANAGER_SRC,
        "dispatch_consequences",
        "evaluate_consequence_rules",
    ) && has_ignore_for("#1531")
    {
        stale.push("consequence evaluation wired but #[ignore] for #1531 still present");
    }

    // #1537 — economy enforcement wired in enforce_economy
    if fn_body_contains(MANAGER_SRC, "enforce_economy", "evaluate_cost") && has_ignore_for("#1537")
    {
        stale.push("economy enforcement wired but #[ignore] for #1537 still present");
    }

    // #1530 — proposer eligibility check wired in propose_governance_action_inner
    if fn_body_contains(
        MANAGER_SRC,
        "propose_governance_action_inner",
        "check_proposer_eligibility",
    ) && has_ignore_for("#1530")
    {
        stale.push("proposer eligibility check wired but #[ignore] for #1530 still present");
    }

    // #1548 — content key rotation wired in execute_rotate_content_keys
    if (fn_body_contains(MANAGER_SRC, "execute_rotate_content_keys", "advance_epoch")
        || fn_body_contains(MANAGER_SRC, "execute_rotate_content_keys", "propose_update"))
        && has_ignore_for("#1548")
    {
        stale.push("content key rotation wired but #[ignore] for #1548 still present");
    }

    // #1541 — sender key rotation wired in execute_remove_member and leave_context
    if fn_body_contains(MANAGER_SRC, "execute_remove_member", "rotate_sender_key")
        && fn_body_contains(MANAGER_SRC, "leave_context", "rotate_sender_key")
        && has_ignore_for("#1541")
    {
        stale.push("sender key rotation wired but #[ignore] for #1541 still present");
    }

    // Catch-all: no ignores should exist
    let has_any_ignore = source.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("#[ignore") && trimmed.contains("= \"")
    });
    if has_any_ignore {
        stale.push("unexpected #[ignore] attributes found");
    }

    assert!(stale.is_empty(), "Stale ignores:\n  {}", stale.join("\n  "));
}

/// Verifies that CLAUDE.md contains the required enforcement sections.
/// These sections instruct agents to check integration wiring before
/// writing code and to never weaken enforcement files.
#[test]
fn claude_md_enforcement_sections_present() {
    let claude_md = include_str!("../../../../CLAUDE.md");
    assert!(
        claude_md.contains("Integration checklist (MANDATORY"),
        "CLAUDE.md must contain the 'Integration checklist (MANDATORY' section"
    );
    assert!(
        claude_md.contains("NEVER modify enforcement files"),
        "CLAUDE.md must contain the 'NEVER modify enforcement files' section"
    );
}
