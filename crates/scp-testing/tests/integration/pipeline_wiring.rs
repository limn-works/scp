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
const WASM_OUTLETS_SRC: &str = include_str!("../../../../crates/scp-ffi/wasm/src/outlets.rs");

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

// SCP-OUT-033 bridge-naming assertions: every implementer of the MCP
// `ContextProvider::invoke_outlet_one_shot` trait method (and the parallel
// non-MCP one-shot collapse on the WASM bridge + the MCP client outlet
// helper) MUST use the explicit `_one_shot` suffix so the wire-format
// collapse from a chunk receiver to a single `serde_json::Value` is
// unambiguous at every site. The runtime free function
// `scp_runtime::context::outlets::invoke::invoke_outlet` returns a
// `mpsc::Receiver<OutletStreamChunk>`; bridges that cannot stream
// natively (MCP `tools/call` JSON-RPC reply, single-threaded WASM JS)
// collapse via a method whose name carries the suffix. Strategy B from
// the OUT-033 remediation plan.
const MCP_SERVER_SRC: &str = include_str!("../../../../crates/scp-mcp/src/server.rs");
const MCP_CLIENT_SRC: &str = include_str!("../../../../crates/scp-mcp/src/client.rs");
const PYO3_MCP_SRC: &str = include_str!("../../../../crates/scp-ffi/src/mcp.rs");
const NAPI_MCP_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/mcp.rs");
const WASM_MANAGER_FOR_OUT033_SRC: &str =
    include_str!("../../../../crates/scp-ffi/wasm/src/manager.rs");

// Transport layer sources for Batch 3 assertions
const ADAPTER_SRC: &str = include_str!("../../../../crates/scp-transport/src/native/adapter.rs");

// SCP-OUT-025 registry-callers assertion sources. The §5.4.4 registry helpers
// `error_code_to_class`, `slug_to_class`, and `validate_slug` live in
// `scp_protocol::context::outlets::error_codes`. Prior to OUT-025 these
// helpers had zero production callers — only test/comment references — so
// the registry was dead-data on the production code path. The assertion
// below pins the wiring so a future refactor that drops the registry hooks
// is caught structurally.
const PROTOCOL_ERRORS_SRC: &str =
    include_str!("../../../../crates/scp-protocol/src/context/outlets/errors.rs");
const RUNTIME_OUTLET_ERRORS_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/outlets/errors.rs");
const RUNTIME_OUTLETS_MANAGER_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/manager/outlets.rs");

// R4 interior-edge attenuation source — the UCAN chain walk MUST enforce
// Step 7 (capability subset) + Step 7b (caveat narrow) at EVERY edge of the
// delegation chain, not just leaf -> direct-parent (§5.4.5 / §7.3.8). The
// assertion below pins the per-edge call inside the recursive walk.
const PROTOCOL_UCAN_VALIDATE_SRC: &str =
    include_str!("../../../../crates/scp-protocol/src/crypto/ucan/validate.rs");

// E1 streaming-settlement source — the dispatch pump's settlement block
// fires the `StreamSettlementSink` exactly once at terminal chunk.
const RUNTIME_DISPATCH_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/outlets/dispatch.rs");

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
//
// Raised 54 -> 56 by SCP-OUT-021 + SCP-OUT-022 remediation: adds
// `dispatch_with_economy_passes_layer_composition` and
// `dispatch_with_economy_passes_caveat_enforcement` pinning the
// dispatch-layer wiring that constructs and forwards the
// `LayerCompositionEnforcement` bundle and forwards the
// `caveat_enforcement` parameter to `invoke_outlet_with_economy`. The
// audit caught both stories as ghost code — the dispatcher used to
// pass `None` for both, so the §7.3.8 post-input gate AND the §7.3.8 /
// §6.2 / §19.5 / §19.3 layer-composition AND fold never ran for real
// invocations. Two `#[test]` items, +2 to the active count.
//
// Raised 56 -> 63 by SCP-OUT-033 bridge-naming remediation: adds 7
// `out033_*_uses_one_shot_suffix` assertions pinning the explicit
// `invoke_outlet_one_shot` naming at every MCP `ContextProvider` impl
// site (server trait declaration + dispatcher + 3 FFI bridges + WASM
// manager + MCP client outlet helper). Without these, the bridge layer
// could regress to a bare `invoke_outlet` returning `Result<Value, _>`
// that contradicts the AC1 spirit (every surface either streams natively
// via the runtime free function OR is an explicitly-named one-shot
// collapse). Seven `#[test]` items, +7 to the active count.
//
// Raised 63 -> 64 by SCP-OUT-029 cross-context wrap remediation: adds
// `cross_context_bridge_wraps_errors` pinning the runtime cross-context
// bridge body to call `wrap_cross_context_error` so terminal Error
// chunks carry the §5.4.4 typed envelope (ContextHop chain, HMAC
// pseudonymization, oracle collapse, trail padding) instead of free-form
// strings. Prior to this, `synth_output_violation_chunk` /
// `synth_bridge_failure_chunk` were ghost code — exported but the
// production return path bypassed them. One `#[test]` item, +1 to the
// active count.
//
// Raised 64 -> 65 by SCP-OUT-036 cross-context bridge wiring: adds
// `cross_context_bridge_wired_to_manager` pinning the ContextManager
// public method `invoke_outlet_streaming_cross_context` as the
// production entry point that drives the §6.2.0.5 free-function bridge
// `invoke_outlet_cross_context`. Prior to this remediation, the free
// function had 0 production callers (5 `#[tokio::test]` callers only)
// — ghost code. One `#[test]` item, +1 to the active count.
//
// Raised 65 -> 66 by SCP-OUT-004 AC5 lifecycle-surface remediation:
// adds `context_manager_exposes_outlet_lifecycle_methods` pinning the
// 8 outlet lifecycle verbs (register / update / deregister / verify /
// list / get / open_session / invoke) as `pub async fn` on
// `impl ContextManager`. Prior to this fix, every verb except
// `invoke_outlet_with_economy` lived only as a free function in
// `scp-protocol` or `scp-runtime/.../outlets/`, forcing FFI bridges to
// import the underlying free function directly and bypassing the
// integration-checklist invariant that protocol logic flow through
// the `ContextManager`. The single `#[test]` item runs N inner
// assertions over a constant-table of (method, substring) tuples but
// contributes 1 to the total_tests count.
//
// Raised 66 -> 67 by SCP-OUT-025 registry-callers wiring: adds
// `out025_registry_callers_present` pinning the production callers of
// the §5.4.4 error-code registry helpers `error_code_to_class`,
// `slug_to_class`, and `validate_slug`. Prior audit caught the registry
// as dead-data — the helpers existed and were exported, but every
// production reference lived in module rustdoc comments. OUT-025
// remediation wires the helpers into `OutletError::new`,
// `OutletError::from_invocation_error_template`, the receiver-side
// `verify_outlet_error`, and the runtime caveat-violation envelope
// dispatcher. One `#[test]` item, +1 to the active count.
//
// Raised 67 -> 68 by the E1/E2 outlet-streaming economy remediation: adds
// `streaming_settlement_fires_sink` pinning the dispatch pump's settlement
// block to call `settlement_sink.settle(` so the §5.4.5 close-time
// settlement (refund unspent escrow + §19.15.5 PaymentReceipt) actually
// runs for real streams. Prior to this, paid streams never charged — the
// pump computed `(billed, refund)` into the close summary but never moved
// the budget. The companion `#[tokio::test]`
// `streaming_settlement_moves_budget_via_in_memory_sink` (not counted by
// the `#[test]`-line ratchet) drives a real in-memory `StreamSettlementSink`
// end-to-end and asserts the `MemberBudgetTracker` net spend equals the
// billed amount. One `#[test]` item, +1 to the active count.
const MIN_ACTIVE_PIPELINE_ASSERTIONS: usize = 68;

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

// SCP-OUT-021 + SCP-OUT-022 — caveat enforcement + layer-composition
// wiring through the dispatch layer. The audit caught both stories as
// ghost code: production callers `invoke_outlet_dispatch_with_economy`
// and `invoke_outlet_dispatch_with_economy_stream` passed
// `caveat_enforcement: None` and `layer_composition: None` to
// `invoke_outlet_with_economy`, so the §7.3.8 post-input gate
// (`input_schema`, `allowed_adapters`, `allowed_target_dids`,
// `max_calls`, `amount_max_cumulative`, `rate_window`) and the §7.3.8 /
// §6.2.0.1 / §19.5 / §19.3 AND fold (Outbound ∧ Inbound ∧
// SpendingCapability ∧ MemberBudgetTracker) NEVER ran for real
// invocations. These two assertions pin the remediation: the dispatch
// layer MUST construct a `LayerCompositionEnforcement` bundle and pass
// it through, AND it MUST forward the optional `caveat_enforcement`
// bundle from the caller so the §7.3.8 caveat gate runs end-to-end.
//
// A future refactor that reverts either to `None` would silently re-
// open the ghost-code regression — the structural assertions catch it
// at CI time before the regression can land.
#[test]
fn dispatch_with_economy_passes_layer_composition() {
    // The dispatcher MUST construct a real `LayerCompositionEnforcement`
    // — the bundle type appears in the function body. Construction site
    // is non-test (the tests-only fixture in OUT-022's
    // `ac2_ac3_integration_wiring_outbound_policy_denial_surfaces_through_manager`
    // builds its own bundle, but that body is below `extract_fn_body`'s
    // first-match — the dispatcher's body comes first in the manager
    // source so this assertion pins the production call site).
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_outlet_dispatch_with_economy",
            "LayerCompositionEnforcement {",
        ),
        "invoke_outlet_dispatch_with_economy must construct a \
         LayerCompositionEnforcement bundle (§7.3.8 / §6.2 / §19.5 / \
         §19.3 AND fold over Outbound ∧ Inbound ∧ SpendingCapability \
         ∧ MemberBudgetTracker — SCP-OUT-022 remediation; passing \
         `None` here re-opens the ghost-code regression)"
    );
    // The bundle MUST flow into `invoke_outlet_with_economy` as the
    // `layer_composition` argument — the body must reference the
    // local binding (`layer_composition`) so the call site cannot
    // silently regress to a hardcoded `None`.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_outlet_dispatch_with_economy",
            "layer_composition,",
        ),
        "invoke_outlet_dispatch_with_economy must pass `layer_composition` \
         (the constructed bundle) to invoke_outlet_with_economy — never \
         a hardcoded `None`. SCP-OUT-022 remediation."
    );
    // Source-context interface lookup MUST happen on the dispatch
    // path — the §6.2.0.1 `OutboundPolicy` / `InboundPolicy` resolve
    // from the per-context `tool_interfaces` snapshot. Pin the lookup
    // identifier so a future refactor that drops the policy snapshot
    // is caught structurally.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_outlet_dispatch_with_economy",
            "tool_interfaces",
        ),
        "invoke_outlet_dispatch_with_economy must resolve the \
         §6.2.0.1 OutboundPolicy / InboundPolicy from \
         ctx.governance.tool_interfaces (SCP-OUT-022 remediation)"
    );
}

#[test]
fn dispatch_with_economy_passes_caveat_enforcement() {
    // The dispatcher MUST accept and forward the `caveat_enforcement`
    // bundle. Pinning the local identifier name (the parameter is
    // named `caveat_enforcement`) catches a future refactor that
    // drops the parameter and reverts to a hardcoded `None`.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_outlet_dispatch_with_economy",
            "caveat_enforcement,",
        ),
        "invoke_outlet_dispatch_with_economy must forward \
         `caveat_enforcement` to invoke_outlet_with_economy — never a \
         hardcoded `None` (SCP-OUT-021 remediation)"
    );
    // The streaming sibling MUST forward the same bundle so streaming
    // dispatch enforces caveats on the same terms as the single-shot
    // dispatcher.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_outlet_dispatch_with_economy_stream",
            "caveat_enforcement,",
        ),
        "invoke_outlet_dispatch_with_economy_stream must forward \
         `caveat_enforcement` to the underlying aggregating dispatcher \
         (SCP-OUT-021 remediation — streaming surface MUST enforce \
         caveats on parity with the single-shot path)"
    );
}

// SCP-OUT-021 single-shot parity. The streaming outlet path enforced the
// §7.3.8 post-input caveat gate while the NON-streaming (single-shot) bridge
// invoke paths passed `caveat_enforcement: None` — a delegate could evade
// `max_calls` / `amount_max_cumulative` / `rate_window` /
// `amount_max_per_call` / `allowed_target_dids` / narrowed `input_schema`
// simply by invoking single-shot. These assertions are the SIBLING of
// `dispatch_with_economy_passes_caveat_enforcement` (the streaming-side pin):
// they prove every single-shot bridge `outlet_invoke` path BUILDS and
// FORWARDS caveat enforcement so the bypass cannot be reintroduced by a future
// refactor that drops the bundle back to a hardcoded `None`.
//
// The three native bridges (PyO3 / NAPI / UniFFI) resolve the action UCAN's
// validated-narrowed `nb` caveats (via the shared `resolve_action_caveats`
// helper) and forward a `CaveatEnforcement` bundle to
// `invoke_outlet_with_economy`. WASM has no async runtime / durable counter
// store (ADR-034) and rejects paid contexts, so it enforces the subset it can
// — the non-counter local caveats + `max_calls` from the validated `nb` — via
// the WASM-local `enforce_single_shot_caveats` helper.
#[test]
fn single_shot_pyo3_outlet_invoke_builds_caveat_enforcement() {
    let body =
        extract_fn_body(PYO3_OUTLETS_SRC, "py_outlet_invoke").expect("py_outlet_invoke body");
    assert!(
        body.contains("resolve_action_caveats"),
        "PyO3 py_outlet_invoke must resolve the action UCAN's validated-narrowed \
         nb caveats (resolve_action_caveats) — single-shot §7.3.8 parity with the \
         streaming path"
    );
    assert!(
        body.contains("CaveatEnforcement {"),
        "PyO3 py_outlet_invoke must construct a CaveatEnforcement bundle so the \
         runtime runs the §7.3.8 post-input gate on single-shot"
    );
    assert!(
        body.contains("caveat_enforcement"),
        "PyO3 py_outlet_invoke must forward `caveat_enforcement` to \
         invoke_outlet_with_economy — never a hardcoded `None` (single-shot \
         caveat-bypass remediation)"
    );
}

#[test]
fn single_shot_napi_outlet_invoke_builds_caveat_enforcement() {
    let body = extract_fn_body(NAPI_OUTLETS_SRC, "outlet_invoke").expect("NAPI outlet_invoke body");
    assert!(
        body.contains("resolve_action_caveats"),
        "NAPI outlet_invoke must resolve the action UCAN's validated-narrowed nb \
         caveats (resolve_action_caveats) — single-shot §7.3.8 parity"
    );
    assert!(
        body.contains("CaveatEnforcement {"),
        "NAPI outlet_invoke must construct a CaveatEnforcement bundle so the \
         runtime runs the §7.3.8 post-input gate on single-shot"
    );
    assert!(
        body.contains("caveat_enforcement"),
        "NAPI outlet_invoke must forward `caveat_enforcement` to \
         invoke_outlet_with_economy — never a hardcoded `None`"
    );
}

#[test]
fn single_shot_uniffi_outlet_invoke_builds_caveat_enforcement() {
    // `extract_fn_body` returns the first match — the top-level
    // `outlet_invoke` (not `outlet_invoke_cross_context`).
    let body =
        extract_fn_body(UNIFFI_BRIDGE_SRC, "outlet_invoke").expect("UniFFI outlet_invoke body");
    assert!(
        body.contains("resolve_action_caveats"),
        "UniFFI outlet_invoke must resolve the action UCAN's validated-narrowed nb \
         caveats (resolve_action_caveats) — single-shot §7.3.8 parity"
    );
    assert!(
        body.contains("CaveatEnforcement {"),
        "UniFFI outlet_invoke must construct a CaveatEnforcement bundle so the \
         runtime runs the §7.3.8 post-input gate on single-shot"
    );
    assert!(
        body.contains("caveat_enforcement"),
        "UniFFI outlet_invoke must forward `caveat_enforcement` to \
         invoke_outlet_with_economy — never a hardcoded `None`"
    );
}

#[test]
fn single_shot_wasm_outlet_invoke_enforces_validated_caveats() {
    // WASM single-shot lives in `outlet_invoke_inner` (the async body the
    // `outlet_invoke` wrapper delegates to). It must enforce the validated
    // `nb` caveats it is capable of enforcing.
    let body = extract_fn_body(WASM_OUTLETS_SRC, "outlet_invoke_inner")
        .expect("WASM outlet_invoke_inner body");
    assert!(
        body.contains("enforce_single_shot_caveats"),
        "WASM outlet_invoke_inner must call enforce_single_shot_caveats so the \
         action UCAN's validated-narrowed nb caveats (the non-counter local set \
         + max_calls from the validated nb) are enforced on single-shot — \
         §7.3.8 parity for everything WASM is capable of enforcing (ADR-034)"
    );
    assert!(
        body.contains("payload.nb"),
        "WASM outlet_invoke_inner must read the action UCAN's validated `nb` \
         field (payload.nb) — max_calls and the local caveats come FROM the \
         validated nb, not a caller estimate"
    );
}

// SIBLING single-shot caveat-enforcement pins for the cross-context and
// session paths. The original single-shot pins above scoped ONLY the top-level
// `outlet_invoke` path; the cross-context and session siblings dispatched
// directly (PyO3/NAPI/UniFFI via `with_context`/handle, WASM via the manager)
// and NEVER built a `CaveatEnforcement` / never enforced the validated `nb` —
// so a delegated UCAN's `max_calls` / `amount_*` / `rate_window` /
// `allowed_adapters` / `allowed_target_dids` / narrowed `input_schema` were all
// skipped on these paths. Cross-context is exactly where `allowed_target_dids`
// must bite. These assertions pin the remediation: every sibling single-shot
// path BUILDS and FORWARDS enforcement, and the native cross-context paths set
// a real `target_did` (not `None`) so `allowed_target_dids` is enforced.

#[test]
fn single_shot_pyo3_cross_context_builds_caveat_enforcement() {
    let body = extract_fn_body(PYO3_OUTLETS_SRC, "py_outlet_invoke_cross_context")
        .expect("py_outlet_invoke_cross_context body");
    assert!(
        body.contains("resolve_action_caveats"),
        "PyO3 py_outlet_invoke_cross_context must resolve the action UCAN's \
         validated-narrowed nb caveats (resolve_action_caveats)"
    );
    assert!(
        body.contains("invoke_outlet_with_caveats") || body.contains("caveat_enforcement"),
        "PyO3 py_outlet_invoke_cross_context must route through the §7.3.8 \
         enforcement path (invoke_outlet_with_caveats / caveat_enforcement) — \
         never a direct dispatch that skips the gate"
    );
    assert!(
        body.contains("target_did_typed") || body.contains("Some(&target"),
        "PyO3 py_outlet_invoke_cross_context must set a real cross-context \
         target_did so allowed_target_dids is enforced — not None"
    );
}

#[test]
fn single_shot_pyo3_session_invoke_builds_caveat_enforcement() {
    let body = extract_fn_body(PYO3_OUTLETS_SRC, "py_outlet_session_invoke")
        .expect("py_outlet_session_invoke body");
    assert!(
        body.contains("resolve_action_caveats"),
        "PyO3 py_outlet_session_invoke must resolve the action UCAN's \
         validated-narrowed nb caveats (resolve_action_caveats)"
    );
    assert!(
        body.contains("invoke_outlet_with_caveats") || body.contains("caveat_enforcement"),
        "PyO3 py_outlet_session_invoke must route through the §7.3.8 \
         enforcement path — never a direct dispatch that skips the gate"
    );
}

#[test]
fn single_shot_napi_cross_context_builds_caveat_enforcement() {
    let body = extract_fn_body(NAPI_OUTLETS_SRC, "outlet_invoke_cross_context")
        .expect("NAPI outlet_invoke_cross_context body");
    assert!(
        body.contains("resolve_action_caveats"),
        "NAPI outlet_invoke_cross_context must resolve the action UCAN's \
         validated-narrowed nb caveats (resolve_action_caveats)"
    );
    assert!(
        body.contains("CaveatEnforcement {"),
        "NAPI outlet_invoke_cross_context must construct a CaveatEnforcement \
         bundle so the runtime runs the §7.3.8 post-input gate"
    );
    assert!(
        body.contains("invoke_outlet_with_economy"),
        "NAPI outlet_invoke_cross_context must forward enforcement to \
         invoke_outlet_with_economy — never a direct dispatch"
    );
    assert!(
        body.contains("target_did: Some"),
        "NAPI outlet_invoke_cross_context must set a real cross-context \
         target_did so allowed_target_dids is enforced — not None"
    );
}

#[test]
fn single_shot_napi_session_invoke_builds_caveat_enforcement() {
    let body = extract_fn_body(NAPI_OUTLETS_SRC, "outlet_session_invoke")
        .expect("NAPI outlet_session_invoke body");
    assert!(
        body.contains("resolve_action_caveats"),
        "NAPI outlet_session_invoke must resolve the action UCAN's \
         validated-narrowed nb caveats (resolve_action_caveats)"
    );
    assert!(
        body.contains("CaveatEnforcement {"),
        "NAPI outlet_session_invoke must construct a CaveatEnforcement bundle"
    );
    assert!(
        body.contains("invoke_outlet_with_economy"),
        "NAPI outlet_session_invoke must forward enforcement to \
         invoke_outlet_with_economy — never a direct dispatch"
    );
}

#[test]
fn single_shot_uniffi_cross_context_builds_caveat_enforcement() {
    let body = extract_fn_body(UNIFFI_BRIDGE_SRC, "outlet_invoke_cross_context")
        .expect("UniFFI outlet_invoke_cross_context body");
    assert!(
        body.contains("resolve_action_caveats"),
        "UniFFI outlet_invoke_cross_context must resolve the action UCAN's \
         validated-narrowed nb caveats (resolve_action_caveats)"
    );
    assert!(
        body.contains("CaveatEnforcement {"),
        "UniFFI outlet_invoke_cross_context must construct a CaveatEnforcement \
         bundle so the runtime runs the §7.3.8 post-input gate"
    );
    assert!(
        body.contains("invoke_outlet_with_economy"),
        "UniFFI outlet_invoke_cross_context must forward enforcement to \
         invoke_outlet_with_economy — never a direct dispatch"
    );
    assert!(
        body.contains("target_did: Some"),
        "UniFFI outlet_invoke_cross_context must set a real cross-context \
         target_did so allowed_target_dids is enforced — not None"
    );
}

#[test]
fn single_shot_uniffi_session_invoke_builds_caveat_enforcement() {
    let body = extract_fn_body(UNIFFI_BRIDGE_SRC, "outlet_session_invoke")
        .expect("UniFFI outlet_session_invoke body");
    assert!(
        body.contains("resolve_action_caveats"),
        "UniFFI outlet_session_invoke must resolve the action UCAN's \
         validated-narrowed nb caveats (resolve_action_caveats)"
    );
    assert!(
        body.contains("CaveatEnforcement {"),
        "UniFFI outlet_session_invoke must construct a CaveatEnforcement bundle"
    );
    assert!(
        body.contains("invoke_outlet_with_economy"),
        "UniFFI outlet_session_invoke must forward enforcement to \
         invoke_outlet_with_economy — never a direct dispatch"
    );
}

#[test]
fn single_shot_wasm_cross_context_enforces_validated_caveats() {
    let body = extract_fn_body(WASM_OUTLETS_SRC, "outlet_invoke_cross_context")
        .expect("WASM outlet_invoke_cross_context body");
    assert!(
        body.contains("enforce_single_shot_caveats"),
        "WASM outlet_invoke_cross_context must call enforce_single_shot_caveats \
         so the validated nb caveats are enforced (and counter-bearing caps fail \
         closed) — §7.3.8 parity (ADR-034)"
    );
    assert!(
        body.contains("payload.nb"),
        "WASM outlet_invoke_cross_context must read the action UCAN's validated \
         `nb` field (payload.nb)"
    );
    assert!(
        body.contains("creator_did"),
        "WASM outlet_invoke_cross_context must resolve the target context's \
         creator DID as the cross-context peer target_did so \
         allowed_target_dids is enforced"
    );
}

#[test]
fn single_shot_wasm_session_invoke_enforces_validated_caveats() {
    let body = extract_fn_body(WASM_OUTLETS_SRC, "outlet_session_invoke")
        .expect("WASM outlet_session_invoke body");
    assert!(
        body.contains("enforce_single_shot_caveats"),
        "WASM outlet_session_invoke must call enforce_single_shot_caveats so the \
         validated nb caveats are enforced (and counter-bearing caps fail \
         closed) — §7.3.8 parity (ADR-034)"
    );
    assert!(
        body.contains("payload.nb"),
        "WASM outlet_session_invoke must read the action UCAN's validated `nb` \
         field (payload.nb)"
    );
}

// R4 — interior-edge attenuation. The UCAN chain walk MUST run the per-edge
// Step 7 (capability subset) + Step 7b (caveat narrow) check at EVERY edge of
// the delegation chain, not only leaf -> direct-parent (§5.4.5 / §7.3.8
// interior-edge clarification). Before the fix, `validate_ucan` ran a single
// leaf-only `verify_attenuation` pass and `verify_chain_recursive` walked the
// interior edges WITHOUT any attenuation check — so a mid-chain token could
// widen a capability or relax a caveat that a more-distant ancestor bound and
// still validate. This assertion pins the remediation: the recursive walk's
// body MUST call `verify_edge_attenuation` so attenuation is enforced at every
// edge it traverses. A future refactor that drops this call re-opens the
// interior-edge-widening gap and is caught structurally at CI time.
#[test]
fn ucan_chain_walk_enforces_attenuation_at_every_edge() {
    assert!(
        fn_body_contains(
            PROTOCOL_UCAN_VALIDATE_SRC,
            "verify_chain_recursive",
            "verify_edge_attenuation(",
        ),
        "verify_chain_recursive must call verify_edge_attenuation at every \
         delegation edge so Step 7 (capability subset) + Step 7b (caveat \
         narrow) run on interior edges (parent -> grandparent ...), not only \
         leaf -> direct-parent (§5.4.5 / §7.3.8 R4 remediation). Dropping this \
         call re-opens the interior-edge-widening gap."
    );
    // And the chain walk MUST thread the caveat resolver through so Step 7b
    // (caveat narrow) can run at interior edges — pin the parameter name on
    // both the entry point and the recursive helper.
    assert!(
        fn_body_contains(
            PROTOCOL_UCAN_VALIDATE_SRC,
            "verify_delegation_chain",
            "caveat_resolver",
        ),
        "verify_delegation_chain must thread `caveat_resolver` into the chain \
         walk so per-edge Step 7b caveat narrowing runs at every edge (R4)"
    );
}

// R4 HIGH-2 — the durable counter CAS MUST commit at the LAST open-time gate:
// after the node-level pump permit is acquired (`try_acquire_owned`) AND after
// `invoke_outlet` returns. Committing earlier (in the synchronous post-input
// hook) burned `max_calls` / `amount_cumulative` / `rate_window` capacity on
// opens that then failed at the pump-permit (`StreamCapExhausted`) or
// executor-launch gate with no compensating revert — a DoS where saturating
// the node pump ceiling exhausts a victim's authorization. This assertion pins
// the ordering: `commit_counter_reservation` is called in `open_stream_session`
// strictly AFTER both `try_acquire_owned` (pump permit) and `invoke_outlet`.
#[test]
fn open_stream_commits_counter_cas_after_pump_permit_and_invoke() {
    let body = extract_fn_body(RUNTIME_DISPATCH_SRC, "open_stream_session")
        .expect("open_stream_session body must exist in dispatch.rs");
    let permit_pos = body
        .find("try_acquire_owned")
        .expect("open_stream_session must acquire the pump permit via try_acquire_owned");
    let invoke_pos = body
        .find("invoke_outlet(")
        .expect("open_stream_session must launch the executor via invoke_outlet");
    let cas_pos = body.find("commit_counter_reservation(").expect(
        "open_stream_session must commit the durable counter CAS via \
         commit_counter_reservation (R4 HIGH-2)",
    );
    assert!(
        cas_pos > permit_pos,
        "the durable counter CAS (commit_counter_reservation) MUST run AFTER \
         the pump-permit acquisition so a StreamCapExhausted rejection burns no \
         counter capacity (R4 HIGH-2)"
    );
    assert!(
        cas_pos > invoke_pos,
        "the durable counter CAS (commit_counter_reservation) MUST run AFTER \
         invoke_outlet returns Ok so an executor-launch failure burns no \
         counter capacity (R4 HIGH-2)"
    );
}

// R4 HIGH-1 — close-time settlement MUST release the unspent cumulative
// reserve. `outlet_stream_settle` reserves `cost_per_chunk × estimated_chunks`
// at open but bills only `billed_count`; the unspent portion is returned to
// the durable `AmountCumulative` counter via `CaveatCounterApi::release`. This
// assertion pins the release call in the settlement method.
#[test]
fn outlet_stream_settle_releases_unspent_cumulative_reserve() {
    const RUNTIME_OUTLETS_MANAGER_FULL: &str =
        include_str!("../../../../crates/scp-runtime/src/context/manager/outlets.rs");
    // The settlement entry point delegates the reconciliation to the
    // dedicated helper...
    assert!(
        fn_body_contains(
            RUNTIME_OUTLETS_MANAGER_FULL,
            "outlet_stream_settle",
            "release_unspent_cumulative_reserve("
        ),
        "outlet_stream_settle must invoke release_unspent_cumulative_reserve at \
         close (R4 HIGH-1)"
    );
    // ...and the helper releases the unspent reserve back to the durable
    // counter via CaveatCounterApi::release.
    assert!(
        fn_body_contains(
            RUNTIME_OUTLETS_MANAGER_FULL,
            "release_unspent_cumulative_reserve",
            ".release("
        ),
        "release_unspent_cumulative_reserve must call CaveatCounterApi::release \
         to return the unspent `(reserved − billed) × cost` to the durable \
         AmountCumulative counter (R4 HIGH-1)"
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

// --- SCP-OUT-029 cross-context error wrapping ---
//
// `wrap_cross_context_error` must be reachable from the production
// cross-context bridge return path. Prior audit caught this function
// as ghost code (0 production callers; only test references). With
// SCP-OUT-029 wired, `run_cross_context_bridge` MUST call the wrap
// helper for every terminal Error chunk it emits — directly or via
// the `synth_*_chunk` helpers, which themselves now route through
// `wrap_terminal_error_envelope -> wrap_cross_context_error`. This
// assertion pins the wiring so a future refactor cannot silently
// regress to free-form code+message synthesis without a §5.4.4
// `ContextHop` chain.
#[test]
fn cross_context_bridge_wraps_errors() {
    // Path 1: `run_cross_context_bridge` body must reference the
    // wrap path (either via the synth helpers OR a direct call to
    // wrap_terminal_error_envelope OR wrap_cross_context_error).
    let bridge_body = extract_fn_body(MANAGER_SRC, "run_cross_context_bridge")
        .expect("run_cross_context_bridge body must exist");
    assert!(
        bridge_body.contains("synth_output_violation_chunk")
            || bridge_body.contains("wrap_terminal_error_envelope")
            || bridge_body.contains("wrap_cross_context_error"),
        "run_cross_context_bridge must wire terminal-Error chunks through \
         wrap_cross_context_error (directly or via synth_* / \
         wrap_terminal_error_envelope helpers)"
    );
    assert!(
        bridge_body.contains("synth_bridge_failure_chunk")
            || bridge_body.contains("wrap_terminal_error_envelope")
            || bridge_body.contains("wrap_cross_context_error"),
        "run_cross_context_bridge must wrap mid-stream-disconnect terminals \
         through wrap_cross_context_error"
    );

    // Path 2: the synth helpers (if retained) MUST call the wrap
    // helper. This guards against a future refactor that re-introduces
    // free-form code+message synthesis under the same name.
    if let Some(synth_out) = extract_fn_body(MANAGER_SRC, "synth_output_violation_chunk") {
        assert!(
            synth_out.contains("wrap_terminal_error_envelope")
                || synth_out.contains("wrap_cross_context_error"),
            "synth_output_violation_chunk must call wrap_terminal_error_envelope \
             or wrap_cross_context_error to attach a ContextHop chain"
        );
    }
    if let Some(synth_bridge) = extract_fn_body(MANAGER_SRC, "synth_bridge_failure_chunk") {
        assert!(
            synth_bridge.contains("wrap_terminal_error_envelope")
                || synth_bridge.contains("wrap_cross_context_error"),
            "synth_bridge_failure_chunk must call wrap_terminal_error_envelope \
             or wrap_cross_context_error to attach a ContextHop chain"
        );
    }

    // Path 3: the wrap helper itself (if retained) MUST call the
    // SCP-OUT-029 `wrap_cross_context_error` to apply oracle collapse,
    // pseudonymization, and trail padding.
    if let Some(wrap_helper) = extract_fn_body(MANAGER_SRC, "wrap_terminal_error_envelope") {
        assert!(
            wrap_helper.contains("wrap_cross_context_error"),
            "wrap_terminal_error_envelope must call wrap_cross_context_error"
        );
    }
}

// --- SCP-OUT-036 cross-context bridge wired into ContextManager API ---
//
// The audit caught `invoke_outlet_cross_context` as ghost code: the free
// function existed and was exported through `manager::*`, but every caller
// lived in `#[tokio::test]` blocks. There was no production path from the
// public ContextManager API into the bridge. SCP-OUT-036 remediation adds
// `ContextManager::invoke_outlet_streaming_cross_context` as the production
// entry. This assertion pins that wiring: a future refactor that drops or
// renames the method MUST update the assertion in lockstep, preventing a
// silent regression to ghost-only state.
//
// Path A (per §5.4.4): the bridge-failure code is `SCP-TOOL-6160`; AC9 in
// the PRD was updated from a tentative 6161 to 6160 so spec, registry, and
// AC agree (6161-6169 is a §5.4.4 reserved gap).
#[test]
fn cross_context_bridge_wired_to_manager() {
    let manager_method = extract_fn_body(MANAGER_SRC, "invoke_outlet_streaming_cross_context")
        .expect(
            "ContextManager::invoke_outlet_streaming_cross_context must exist as a public method",
        );
    assert!(
        manager_method.contains("invoke_outlet_cross_context"),
        "invoke_outlet_streaming_cross_context must call invoke_outlet_cross_context to drive \
         the §6.2.0.5 cross-context bridge"
    );
}

// ---------------------------------------------------------------------------
// SCP-OUT-004 AC5 — outlet lifecycle ContextManager surface
//
// Asserts that the eight outlet lifecycle verbs the rename target enumerated
// — `register_outlet`, `update_outlet`, `deregister_outlet`, `verify_outlet`,
// `list_outlets`, `get_outlet`, `open_outlet_session`, `invoke_outlet` — are
// each `pub async fn`s on `impl ContextManager`. Without this assertion the
// integration-checklist requirement (Rust function called from a
// ContextManager method, not just exported) drifts: bridges previously
// imported `scp_protocol::context::outlets::register_outlet` directly,
// bypassing the manager. The eight shims close the gap; this test pins them
// so a future rename or merge cannot silently regress.
//
// The body of each shim is also asserted to contain a call into a real
// implementation (forwarding to a scp-protocol free function or to an
// existing manager method) so that `let _ = function_name;` style
// dead-reference cheats — the failure mode CLAUDE.md explicitly calls out —
// are caught here, not at runtime.
// ---------------------------------------------------------------------------

#[test]
fn context_manager_exposes_outlet_lifecycle_methods() {
    // The `MANAGER_SRC` concatenation above includes
    // `crates/scp-runtime/src/context/manager/outlets.rs`, which is where
    // the SCP-OUT-004 AC5 shims live. Asserting against `MANAGER_SRC`
    // also guards against the methods being moved to a non-included file
    // by accident — the assertion fails until the source is wired into
    // the test concat.
    const SHIMS: &[(&str, &[&str])] = &[
        // Each entry: (method_name, [substrings the body must contain])
        // The substrings prove the shim forwards to a real implementation
        // rather than stubbing with `todo!()` or `let _ = ...;`.
        (
            "register_outlet",
            &["snapshot_role_state", "registry::register_outlet"],
        ),
        (
            "update_outlet",
            &["snapshot_role_state", "registry::update_outlet"],
        ),
        (
            "deregister_outlet",
            &["snapshot_role_state", "registry.remove"],
        ),
        (
            "verify_outlet",
            &["snapshot_role_state", "registry::verify_outlet"],
        ),
        ("list_outlets", &["registered_outlets"]),
        ("get_outlet", &["registered_outlets"]),
        ("open_outlet_session", &["self.open_outlet_stream"]),
        (
            "invoke_outlet",
            &["self.invoke_outlet_dispatch_with_economy_stream"],
        ),
    ];

    for (name, must_contain) in SHIMS {
        let body = extract_fn_body(MANAGER_SRC, name).unwrap_or_else(|| {
            panic!(
                "ContextManager::{name} must be defined on impl ContextManager \
                 (SCP-OUT-004 AC5)"
            )
        });
        for needle in *must_contain {
            assert!(
                body.contains(needle),
                "ContextManager::{name} body must contain `{needle}` so the shim \
                 forwards to a real implementation. Stub/dead-reference cheats \
                 (`let _ = {name};`, `todo!()`) are forbidden by CLAUDE.md \
                 (SCP-OUT-004 AC5)."
            );
        }
    }

    // Defense-in-depth: the shims must be `pub async fn`. The
    // `extract_fn_body` helper is signature-agnostic, so a `fn` (sync) or
    // `pub(crate) async fn` would still match — that would re-introduce
    // the bridge-direct-call regression because FFI bridges cannot import
    // crate-private items. Pin the surface explicitly.
    let outlets_src = include_str!("../../../../crates/scp-runtime/src/context/manager/outlets.rs");
    for (name, _) in SHIMS {
        let needle = format!("pub async fn {name}");
        assert!(
            outlets_src.contains(&needle),
            "ContextManager::{name} must be declared `pub async fn` so FFI \
             bridges can call it across crate boundaries (SCP-OUT-004 AC5)"
        );
    }
}

// --- SCP-OUT-025 §5.4.4 registry-callers wiring ---
//
// The audit caught `error_code_to_class`, `slug_to_class`, and
// `validate_slug` as dead-data: every helper existed and was exported
// from `scp_protocol::context::outlets::error_codes`, but the only
// references in production crates lived in module rustdoc comments.
// Construction sites (`OutletError::new`,
// `OutletError::from_invocation_error_template`) and wire-deserialization
// sites (`verify_outlet_error`) bypassed the registry entirely; the
// runtime caveat dispatcher used hand-rolled prefix string matching
// rather than `slug_to_class`.
//
// SCP-OUT-025 remediation wires all three helpers into real production
// call sites. This assertion pins those call sites structurally so a
// future refactor cannot silently regress the registry to dead-data.
#[test]
fn out025_registry_callers_present() {
    // Path A: validate_slug must be called in OutletError::new on the
    // protocol side AND in verify_outlet_error on the runtime side.
    let outlet_error_new_body = extract_fn_body(PROTOCOL_ERRORS_SRC, "new")
        .expect("OutletError::new body must exist in scp-protocol errors.rs");
    assert!(
        outlet_error_new_body.contains("validate_slug("),
        "OutletError::new must call validate_slug to enforce the §5.4.4 \
         slug regex via the registry's typed entry point (SCP-OUT-025)"
    );
    let verify_outlet_error_body =
        extract_fn_body(RUNTIME_OUTLET_ERRORS_SRC, "verify_outlet_error")
            .expect("verify_outlet_error body must exist in scp-runtime outlets/errors.rs");
    assert!(
        verify_outlet_error_body.contains("validate_slug("),
        "verify_outlet_error must call validate_slug at the wire \
         deserialization boundary so a malformed envelope is rejected \
         before any HMAC reverse runs (SCP-OUT-025)"
    );

    // Path B: error_code_to_class must be called from OutletError::new
    // and verify_outlet_error to enforce class/code consistency.
    assert!(
        outlet_error_new_body.contains("error_code_to_class("),
        "OutletError::new must call error_code_to_class to enforce the \
         §5.4.4 class/code consistency invariant (SCP-OUT-025)"
    );
    assert!(
        verify_outlet_error_body.contains("error_code_to_class("),
        "verify_outlet_error must call error_code_to_class to reject \
         wire envelopes whose class/code drift on the wire (SCP-OUT-025)"
    );

    // Path C: slug_to_class must be called in three places — the
    // protocol-side construction check, the wire-side verification
    // check, and the runtime caveat-violation envelope dispatcher.
    assert!(
        outlet_error_new_body.contains("slug_to_class("),
        "OutletError::new must call slug_to_class to enforce the \
         §5.4.4 class/slug consistency invariant (SCP-OUT-025)"
    );
    assert!(
        verify_outlet_error_body.contains("slug_to_class("),
        "verify_outlet_error must call slug_to_class to reject wire \
         envelopes whose class/slug drift on the wire (SCP-OUT-025)"
    );
    let caveat_envelope_body =
        extract_fn_body(RUNTIME_OUTLETS_MANAGER_SRC, "caveat_violation_to_envelope")
            .expect("caveat_violation_to_envelope body must exist in scp-runtime outlets.rs");
    assert!(
        caveat_envelope_body.contains("slug_to_class("),
        "caveat_violation_to_envelope must consult slug_to_class as the \
         §5.4.4 source of truth for slug → class dispatch rather than \
         hand-rolled prefix string matching (SCP-OUT-025)"
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
// update to the scp_core::context::outlets runtime facade (which re-exports
// the protocol-level outlet registry + runtime invocation pipeline).
// Each outlet lifecycle verb is asserted on all 3 non-WASM FFI bridges
// (PyO3, NAPI, UniFFI). invoke is already covered by the C4 assertions
// above; these additions cover the remaining verbs.
// ===========================================================================

/// `register_outlet` reaches the runtime pipeline via the protocol-level
/// registry function (`scp_core::context::outlets::register_outlet`) from all
/// three non-WASM FFI bridges.
#[test]
fn out008_register_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(PYO3_OUTLETS_SRC, "py_outlet_register", "register_outlet"),
        "PyO3 py_outlet_register must delegate to scp_core::context::outlets::register_outlet \
         so outlet registration flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(NAPI_OUTLETS_SRC, "outlet_register", "register_outlet"),
        "NAPI outlet_register must delegate to scp_core::context::outlets::register_outlet \
         so outlet registration flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "outlet_register", "register_outlet"),
        "UniFFI outlet_register must delegate to scp_core::context::outlets::register_outlet \
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
/// registry function (`scp_core::context::outlets::update_outlet`) from all
/// three non-WASM FFI bridges.
#[test]
fn out008_update_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(PYO3_OUTLETS_SRC, "py_outlet_update", "update_outlet"),
        "PyO3 py_outlet_update must delegate to scp_core::context::outlets::update_outlet \
         so outlet updates flow through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(NAPI_OUTLETS_SRC, "outlet_update", "update_outlet"),
        "NAPI outlet_update must delegate to scp_core::context::outlets::update_outlet \
         so outlet updates flow through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "outlet_update", "update_outlet"),
        "UniFFI outlet_update must delegate to scp_core::context::outlets::update_outlet \
         so outlet updates flow through the runtime pipeline (SCP-OUT-008 AC22)"
    );
}

/// `verify_outlet` reaches the runtime pipeline via the protocol-level
/// registry function (`scp_core::context::outlets::verify_outlet`) from all
/// three non-WASM FFI bridges.
#[test]
fn out008_verify_outlet_reaches_runtime_pipeline() {
    assert!(
        fn_body_contains(PYO3_OUTLETS_SRC, "py_outlet_verify", "verify_outlet"),
        "PyO3 py_outlet_verify must delegate to scp_core::context::outlets::verify_outlet \
         so outlet verification flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(NAPI_OUTLETS_SRC, "outlet_verify", "verify_outlet"),
        "NAPI outlet_verify must delegate to scp_core::context::outlets::verify_outlet \
         so outlet verification flows through the runtime pipeline (SCP-OUT-008 AC22)"
    );
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "outlet_verify", "verify_outlet"),
        "UniFFI outlet_verify must delegate to scp_core::context::outlets::verify_outlet \
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
// SCP-OUT-033 bridge-naming assertions
//
// AC1 spirit: every API surface either streams natively (the runtime free
// function `scp_runtime::context::outlets::invoke::invoke_outlet` returns
// `Result<mpsc::Receiver<OutletStreamChunk>, _>`) OR is an explicitly-named
// one-shot collapse. MCP `tools/call` is one-shot by wire format; the WASM
// bridge is single-threaded JS per ADR-034 and exposes the collapse only.
// These assertions pin the explicit `invoke_outlet_one_shot` naming at
// every implementer site so a future rename or a regression to a bare
// `invoke_outlet` returning `Result<Value, _>` fails CI.
// ===========================================================================

/// MCP `ContextProvider` trait declares `invoke_outlet_one_shot` (not bare
/// `invoke_outlet`).
#[test]
fn out033_mcp_provider_trait_uses_one_shot_suffix() {
    assert!(
        MCP_SERVER_SRC.contains("fn invoke_outlet_one_shot("),
        "scp-mcp::ContextProvider must declare `fn invoke_outlet_one_shot(` to make \
         the wire-format collapse from chunk-stream to single Value explicit per \
         SCP-OUT-033 / SCP-OUT-007."
    );
}

/// MCP server's `tools/call` dispatcher invokes the renamed trait method.
#[test]
fn out033_mcp_server_dispatcher_calls_one_shot() {
    assert!(
        fn_body_contains(
            MCP_SERVER_SRC,
            "handle_tools_call",
            ".invoke_outlet_one_shot("
        ),
        "scp-mcp::McpServer::handle_tools_call must collapse to a single value via \
         `provider.invoke_outlet_one_shot(...)` — this is the MCP wire boundary \
         where the runtime chunk receiver folds into a JSON-RPC `CallToolResult`."
    );
}

/// MCP client's outlet-vocabulary helper carries the explicit one-shot suffix.
#[test]
fn out033_mcp_client_outlet_helper_uses_one_shot_suffix() {
    assert!(
        MCP_CLIENT_SRC.contains("pub fn invoke_outlet_one_shot("),
        "scp-mcp::McpClient must expose `pub fn invoke_outlet_one_shot(` so callers \
         see that the response is a one-shot `McpToolResult` (no chunk semantics)."
    );
}

/// PyO3 bridge's `FfiBridgeProvider` impl uses the explicit suffix.
#[test]
fn out033_pyo3_bridge_provider_uses_one_shot_suffix() {
    assert!(
        PYO3_MCP_SRC.contains("fn invoke_outlet_one_shot("),
        "PyO3 FfiBridgeProvider impl in scp-ffi/src/mcp.rs must implement \
         `fn invoke_outlet_one_shot(...)` per SCP-OUT-033."
    );
}

/// NAPI bridge's `McpNapiBridgeProvider` impl uses the explicit suffix.
#[test]
fn out033_napi_bridge_provider_uses_one_shot_suffix() {
    assert!(
        NAPI_MCP_SRC.contains("fn invoke_outlet_one_shot("),
        "NAPI McpNapiBridgeProvider impl in scp-ffi/napi/src/mcp.rs must implement \
         `fn invoke_outlet_one_shot(...)` per SCP-OUT-033."
    );
}

/// UniFFI bridge's `McpUniFfiBridgeProvider` impl uses the explicit suffix.
#[test]
fn out033_uniffi_bridge_provider_uses_one_shot_suffix() {
    assert!(
        UNIFFI_BRIDGE_SRC.contains("fn invoke_outlet_one_shot("),
        "UniFFI McpUniFfiBridgeProvider impl in scp-ffi/uniffi/src/bridge.rs must \
         implement `fn invoke_outlet_one_shot(...)` per SCP-OUT-033."
    );
}

/// WASM bridge's `WasmContextManager` exposes only a one-shot collapse
/// (no streaming receiver — single-threaded JS per ADR-034). The method
/// name MUST carry the explicit `_one_shot` suffix.
#[test]
fn out033_wasm_manager_uses_one_shot_suffix() {
    assert!(
        WASM_MANAGER_FOR_OUT033_SRC.contains("pub fn invoke_outlet_one_shot("),
        "WasmContextManager in scp-ffi/wasm/src/manager.rs must expose \
         `pub fn invoke_outlet_one_shot(...)` per SCP-OUT-033 — WASM has no \
         tokio mpsc receiver to surface to JavaScript (ADR-034), so the \
         collapse is the only available form and must be named explicitly."
    );
}

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
// E1 — streaming settlement fires the sink (close-time budget movement)
// ===========================================================================

/// Structural guard: the dispatch pump's settlement block MUST call
/// `settlement_sink.settle(` so the §5.4.5 close-time settlement (refund
/// unspent escrow + §19.15.5 PaymentReceipt) runs for real streams. Prior to
/// the E1 remediation the pump computed `(billed, refund)` into the close
/// summary but never moved the budget — paid streams never charged.
#[test]
fn streaming_settlement_fires_sink() {
    let body = extract_fn_body(RUNTIME_DISPATCH_SRC, "run_stream_pump_v2")
        .expect("run_stream_pump_v2 body must exist in dispatch.rs");
    assert!(
        body.contains("settlement_sink.settle("),
        "run_stream_pump_v2 settlement block must fire settlement_sink.settle(...) \
         so the §5.4.5 close-time refund + PaymentReceipt runs (E1)"
    );
}

/// Real end-to-end assertion: drives a REAL in-memory `StreamSettlementSink`
/// against a live `ContextManager` and proves the `MemberBudgetTracker` net
/// spend equals the billed amount after the settlement runs. This is the
/// non-dead-`let _` companion to `streaming_settlement_fires_sink`: it
/// exercises the actual sink → `outlet_stream_settle` → budget-tracker path.
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::items_after_statements)]
async fn streaming_settlement_moves_budget_via_in_memory_sink() {
    use scp_core::context::builder::{
        ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
        ContextTransportProvider,
    };
    use scp_core::context::governance::KeyResolver;
    use scp_core::context::manager::ContextManager;
    use scp_core::context::params::ContextParams;
    use scp_core::context::{AddMemberOutput, ContextError, RemoveMemberOutput};
    use scp_identity::DID;
    use scp_runtime::context::outlets::invoke::{StreamSettlement, StreamSettlementSink};
    use std::sync::Arc;

    // -- Minimal mock providers (no real crypto / transport / event log) --
    struct MockCrypto;
    impl ContextCryptoProvider for MockCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn add_member(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<AddMemberOutput, ContextError> {
            Ok(AddMemberOutput::default())
        }
        fn remove_member(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<RemoveMemberOutput, ContextError> {
            Ok(RemoveMemberOutput::default())
        }
        fn distribute_sender_key(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member_sender_key(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn seal(
            &self,
            _context_id: &[u8; 32],
            inner: &scp_core::envelope::inner::InnerEnvelope,
            _routing_id: &[u8],
            _blob_ttl: u32,
        ) -> Result<Vec<u8>, ContextError> {
            rmp_serde::to_vec_named(inner)
                .map_err(|e| ContextError::CryptoFailed(format!("mock seal: {e}")))
        }
        fn open(
            &self,
            _context_id: &[u8; 32],
            outer_bytes: &[u8],
        ) -> Result<scp_core::context::builder::OpenResult, ContextError> {
            let inner: scp_core::envelope::inner::InnerEnvelope =
                rmp_serde::from_slice(outer_bytes)
                    .map_err(|e| ContextError::CryptoFailed(format!("mock open: {e}")))?;
            let sender_did = inner.sender_did.clone();
            Ok(scp_core::context::builder::OpenResult::Application(
                Box::new(scp_core::context::builder::OpenedEnvelope { inner, sender_did }),
            ))
        }
    }
    struct MockTransport;
    impl ContextTransportProvider for MockTransport {
        fn is_connected(&self) -> bool {
            true
        }
        fn publish_context(
            &self,
            _id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn send_message(
            &self,
            _ctx_id: &[u8; 32],
            _encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }
    struct MockEventLog;
    impl ContextEventLogProvider for MockEventLog {
        fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
            _actor_did: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }
    let key_resolver: KeyResolver = Arc::new(|_did: &DID| None);

    let manager = Arc::new(ContextManager::new(
        Box::new(MockCrypto),
        Box::new(MockTransport),
        Box::new(MockEventLog),
        key_resolver,
    ));
    let ctx_id = "settlement-sink-test";
    let creator: DID = "did:key:creator".into();
    manager
        .create_context(
            ctx_id.into(),
            ContextParams::default(),
            creator.as_ref().into(),
            None,
        )
        .await
        .expect("create_context");

    // Grant budget and reserve (DEBIT) the open-time hold: cost 10 × 5 = 50.
    manager
        .grant_budget_for_test(
            ctx_id,
            &creator,
            scp_protocol::economy::types::Amount::new(1_000),
        )
        .await;
    let reservation = manager
        .outlet_stream_reserve_escrow(
            ctx_id,
            &creator,
            scp_protocol::economy::types::Amount::new(10),
            5,
            None,
        )
        .await
        .expect("reserve");
    assert_eq!(reservation.reserved.value(), 50);

    // A REAL in-memory settlement sink: mirrors the production native-bridge
    // sink (Handle::spawn of the async `outlet_stream_settle`). It records
    // that it fired and drives the real budget-moving manager method.
    struct InMemorySettlementSink {
        manager: Arc<ContextManager>,
        handle: tokio::runtime::Handle,
        fired: Arc<std::sync::atomic::AtomicBool>,
    }
    impl StreamSettlementSink for InMemorySettlementSink {
        fn settle(&self, s: StreamSettlement) {
            self.fired.store(true, std::sync::atomic::Ordering::SeqCst);
            let manager = Arc::clone(&self.manager);
            self.handle.spawn(async move {
                let _ = manager
                    .outlet_stream_settle(
                        &s.context_id,
                        &s.invoker_did,
                        s.billed_amount,
                        s.refund_amount,
                        s.billed_count,
                        s.request_id,
                        &s.outlet_id,
                        s.economic_policy_snapshot,
                        scp_runtime::context::outlets::dispatch::CounterReserveSettlement::zero(),
                    )
                    .await;
            });
        }
    }
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sink: Arc<dyn StreamSettlementSink> = Arc::new(InMemorySettlementSink {
        manager: Arc::clone(&manager),
        handle: tokio::runtime::Handle::current(),
        fired: Arc::clone(&fired),
    });

    // Fire the sink with a settlement that bills 3 of the 5 reserved chunks
    // (billed 30, refund 20) — exactly what the dispatch pump produces at a
    // partial-consumption close.
    sink.settle(StreamSettlement {
        context_id: ctx_id.to_owned(),
        invoker_did: creator.clone(),
        reserved: scp_protocol::economy::types::Amount::new(50),
        billed_amount: scp_protocol::economy::types::Amount::new(30),
        refund_amount: scp_protocol::economy::types::Amount::new(20),
        billed_count: 3,
        request_id: *uuid::Uuid::now_v7().as_bytes(),
        outlet_id: scp_protocol::context::outlets::OutletId::from("outlet-z"),
        economic_policy_snapshot: None,
        // R4 HIGH-1 — no cumulative reserve in this E1 settlement-wiring test.
        amount_cumulative_reserved: 0,
        reserved_chunks: 0,
        ucan_cid: String::new(),
        cost_per_chunk: scp_protocol::economy::types::Amount::new(0),
    });
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "in-memory settlement sink must fire"
    );

    // The spawned settlement is async; poll the budget until the refund lands
    // (net spent must drop from 50 to 30). Bounded wait so a regression that
    // never refunds fails the test rather than hanging.
    let mut net_spent = u64::MAX;
    for _ in 0..50 {
        tokio::task::yield_now().await;
        net_spent = manager.total_spent_for_test(ctx_id, &creator).await.value();
        if net_spent == 30 {
            break;
        }
    }
    assert_eq!(
        net_spent, 30,
        "after settlement the MemberBudgetTracker net spend must equal the \
         billed amount (50 reserved − 20 refunded == 30 billed)"
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
