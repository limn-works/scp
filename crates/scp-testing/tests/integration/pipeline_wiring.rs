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

// Production helper modules + domain logic modules. The legacy
// `manager/<domain>.rs` submodules and `manager/mod.rs` were deleted
// in ADR-049 commit 12 — every method body that the pipeline-wiring
// assertions probe now lives in `<domain>_helpers.rs` (forwarder-free),
// `<domain>_helpers_legacy.rs` during Phase 2A actor migration windows,
// or in `<domain>_logic.rs` (the free-function logic that used to share
// a file with `impl ContextManager` blocks).
const MANAGER_SRC: &str = concat!(
    include_str!("../../../../crates/scp-runtime/src/context/economy_logic.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/lifecycle_logic.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/governance_logic.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/messaging_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/lifecycle_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/governance_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/standing_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/tools_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/broadcast_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/queries_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/economy_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/trust_recovery_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/ttl_close_helpers.rs"),
);
const PROVIDER_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/crypto/mls/provider.rs");

// Supervisor dispatch source — owns `dispatch_lifecycle_direct`, whose
// bootstrap arms (Create / Import / Restore) moved to the actor-shape
// `lifecycle_helpers::{create,import,restore}_context` in the ADR-049
// Phase 2A finalization (storage-foundation keystone). The structural
// assertion below pins that wiring so a future refactor cannot silently
// regress the bootstrap path back to the `_legacy` `&Supervisor` helpers
// (which no longer spawn a per-context actor).
const SUPERVISOR_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/supervisor/supervisor.rs");

// WASM bridge sources. Bridge has its own consequence-dispatch path and is
// asserted separately below — scp-runtime and scp-ffi-wasm are two parallel
// implementations of the same protocol and both must honor the wiring.
const WASM_MANAGER_SRC: &str = include_str!("../../../../crates/scp-ffi/wasm/src/manager.rs");
const WASM_CONSEQUENCE_SRC: &str =
    include_str!("../../../../crates/scp-ffi/wasm/src/consequence.rs");

// Non-WASM FFI bridge sources. PR #1606 / C4 wired all 3 of these to
// `ContextManager::invoke_tool_with_economy` so per-invocation pricing,
// spending UCAN, velocity tracking, budget enforcement, and the hard
// rate limit are enforced for Python / Node / Swift / Kotlin clients.
// The structural assertions in `c4_tool_invoke_economy_*` below pin
// the bridge → runtime delegation so a future refactor cannot silently
// regress to the bypass path.
const PYO3_TOOLS_SRC: &str = include_str!("../../../../crates/scp-ffi/src/tools.rs");
const NAPI_TOOLS_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/tools.rs");
const UNIFFI_BRIDGE_SRC: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs");

// NAPI context bridge — the only bridge with a live relay subscribe loop
// (`context_subscribe_on`). The `b3_heartbeat_send_receive_loop_wired`
// assertion pins the §9.9.2 send scheduler + the received-heartbeat
// `record_heartbeat_received` call to this loop so a refactor cannot silently
// sever the closed heartbeat loop.
const NAPI_CONTEXT_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/context.rs");

// PyO3 reference bridge context source — owns `broadcast_open_key`, the
// pure-crypto FFI entry point that opens an HPKE-sealed broadcast key
// (§5.14.2). The `broadcast_open_key_calls_open_broadcast_key` assertion
// below pins this entry point to the protocol-layer `open_broadcast_key`
// primitive so a refactor cannot silently sever the FFI surface from the
// real crypto.
const PYO3_CONTEXT_SRC: &str = include_str!("../../../../crates/scp-ffi/src/context.rs");

// Shared heartbeat scheduler (scp-ffi-common) — `run_heartbeat_scheduler`
// drives `Supervisor::send_heartbeat` at the per-profile cadence. Pinned by
// `b3_heartbeat_send_receive_loop_wired`.
const HEARTBEAT_SCHEDULER_SRC: &str =
    include_str!("../../../../crates/scp-ffi/common/src/heartbeat_scheduler.rs");

// Shared broadcast key-distribution helpers (scp-ffi-common §5.14.2). The
// Grant→sealed-JSON and sealed-JSON→raw-key value-shape logic is extracted here
// once; the PyO3, napi-rs, and UniFFI bridges delegate to it. Pinned by
// `broadcast_open_key_calls_open_broadcast_key` so the FFI open path still
// reaches the real HPKE `open_broadcast_key` primitive through the shared seam.
const COMMON_BROADCAST_SRC: &str =
    include_str!("../../../../crates/scp-ffi/common/src/broadcast.rs");

// Transport layer sources for Batch 3 assertions
const ADAPTER_SRC: &str = include_str!("../../../../crates/scp-transport/src/native/adapter.rs");

// Reconnection-driver source (ADR-029 reconnection-driver addendum).
// The FFI/SDK-layer RelayActorSyncDriver lives here because the actor's
// ContextTransportProvider is send-only; the b3_reconnect assertion below
// pins the driver's event_log_sync to the build + compare checkpoint
// exchange so a future refactor cannot silently sever the reconnection
// path from the equivocation-detection core.
const RECONNECT_DRIVER_SRC: &str =
    include_str!("../../../../crates/scp-ffi/common/src/reconnect.rs");

// Actor messaging-handler source — owns `handle_build_local_checkpoint`,
// the actor-turn body that builds AND broadcasts the Phase-3 checkpoint so
// the FFI driver never needs the `pub(crate)` `send_checkpoint` across the
// crate boundary (ADR-029).
const HANDLERS_MESSAGING_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/messaging.rs");

// UCAN validation pipeline source — owns `validate_ucan`, the 11-step
// capability authorization gate. The `ucan_step8_enforces_ceiling_over_all_att`
// assertion below pins step 8 to checking the FULL parsed attestation set
// (`&granted_caps`) against the ceiling — not just the invoked capability
// (spec §7.2.1 step 8) — so a refactor cannot silently regress to
// `from_ref(required_capability)`, which would let a token smuggle an
// out-of-ceiling attestation past validation.
const UCAN_VALIDATE_SRC: &str =
    include_str!("../../../../crates/scp-protocol/src/crypto/ucan/validate.rs");

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================
const MIN_ACTIVE_PIPELINE_ASSERTIONS: usize = 43;

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

/// Extracts the signature text of `fn_name` — everything from `fn <name>` up to
/// (but excluding) the opening `{` of the body. Used to assert which parameters
/// a function does / does not accept (e.g. a by-id execute that must NOT take a
/// caller-supplied proposal/action).
fn extract_fn_signature(source: &str, fn_name: &str) -> Option<String> {
    let needle_paren = format!("fn {fn_name}(");
    let needle_generic = format!("fn {fn_name}<");
    let sig_pos = source
        .find(&needle_paren)
        .or_else(|| source.find(&needle_generic))?;
    let after_sig = &source[sig_pos..];
    let open_brace_offset = after_sig.find('{')?;
    Some(after_sig[..open_brace_offset].to_string())
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

// Broadcast key-distribution pull protocol (§5.14.2): the PyO3 reference
// bridge's `broadcast_open_key` FFI entry point must reach the protocol-layer
// `open_broadcast_key` primitive (the real HPKE open). The open path now routes
// through the shared `scp-ffi-common` helper `open_sealed_broadcast_key`
// (deduped across PyO3/napi-rs/UniFFI), which calls `open_broadcast_key`
// internally — so the assertion accepts either a direct call OR the delegation
// chain (bridge → shared helper → primitive), mirroring how
// `deliver_incoming_calls_open` accepts the `decrypt_and_dispatch` delegation.
// This still pins the FFI surface to the real crypto so a refactor cannot
// silently stub the open path or route it away from `open_broadcast_key`.
#[test]
fn broadcast_open_key_calls_open_broadcast_key() {
    let direct = fn_body_contains(
        PYO3_CONTEXT_SRC,
        "broadcast_open_key",
        "open_broadcast_key(",
    );
    let via_shared_helper = fn_body_contains(
        PYO3_CONTEXT_SRC,
        "broadcast_open_key",
        "open_sealed_broadcast_key(",
    ) && fn_body_contains(
        COMMON_BROADCAST_SRC,
        "open_sealed_broadcast_key",
        "open_broadcast_key(",
    );
    assert!(
        direct || via_shared_helper,
        "PyO3 broadcast_open_key must reach open_broadcast_key (HPKE open \
         primitive), either directly or via the shared \
         open_sealed_broadcast_key helper"
    );
}

// Supervisor level: the lifecycle bootstrap arms spawn a real per-context
// actor by delegating to the actor-shape `lifecycle_helpers::*` bodies
// (each of which spawns an owned-state actor via `spawn_actor_with_state`).
// ADR-049 Phase 2A finalization. This is an additive assertion —
// `dispatch_lifecycle_direct` still references the `_legacy` helpers for the
// per-context Join / Leave / Close / Export / AccessKey arms, so we pin the
// presence of the actor-shape bootstrap calls rather than the absence of all
// legacy references.
#[test]
fn dispatch_lifecycle_direct_bootstrap_arms_call_actor_shape_helpers() {
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "dispatch_lifecycle_direct",
            "lifecycle_helpers::create_context("
        ),
        "dispatch_lifecycle_direct CreateContext arm must delegate to the \
         actor-shape lifecycle_helpers::create_context (spawns the per-context actor)"
    );
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "dispatch_lifecycle_direct",
            "lifecycle_helpers::import_context("
        ),
        "dispatch_lifecycle_direct ImportContext arm must delegate to the \
         actor-shape lifecycle_helpers::import_context (spawns the per-context actor)"
    );
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "dispatch_lifecycle_direct",
            "lifecycle_helpers::restore_context("
        ),
        "dispatch_lifecycle_direct RestoreContext arm must delegate to the \
         actor-shape lifecycle_helpers::restore_context (spawns the per-context actor)"
    );
}

// Supervisor level: import is actor-native. The replaceability gate (NEVER
// overwrite a live context) + the §23.17 epoch-floor capture/teardown/merge
// run INSIDE the existing actor via `dispatch_prepare_for_replace`
// (PrepareForReplace), and the imported state is spawned as an owned-state
// actor via `spawn_actor_with_state`. ADR-049 Phase 2A finalization keystone.
// Pins the actor-native shape AND the absence of the deleted DashMap
// dual-write machinery so a regression cannot reintroduce a silent
// live-context overwrite. Additive assertion.
#[test]
fn import_context_is_actor_native_not_dashmap_dual_write() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "import_context",
            "dispatch_prepare_for_replace"
        ),
        "lifecycle_helpers::import_context must run the replaceability gate + \
         crypto teardown inside the existing actor via dispatch_prepare_for_replace"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "import_context", "spawn_actor_with_state"),
        "lifecycle_helpers::import_context must spawn the imported state as an \
         owned-state actor via spawn_actor_with_state"
    );
    for legacy in [
        "with_existing_context_for_import",
        "replace_context(",
        "spawn_actor_for_context(",
    ] {
        assert!(
            !fn_body_contains(MANAGER_SRC, "import_context", legacy),
            "lifecycle_helpers::import_context must not reach the deleted DashMap \
             dual-write machinery ({legacy}) — the gate is actor-native now"
        );
    }
    // Note: the lifecycle_control handler's dispatch of PrepareForReplace and
    // the actor run-loop's terminal-exit arm are compiler-guaranteed (the
    // match is exhaustive and the `is_terminal` arm would not compile if the
    // variant were unhandled), so no string assertion is needed for those.
}

// Timer level: the actor-shape TTL timer helpers install the timer on
// actor-owned state via `ttl_close_helpers::spawn_ttl_timer` (registry +
// `FireTimer` mailbox tick), NOT the legacy `spawn_ttl_timer_legacy`
// DashMap-reading task. ADR-049 Phase 2A finalization (timer → actor
// registry + mailbox). Additive assertion — pins the actor-shape call so
// a future refactor cannot regress the timer back to the legacy
// `&Supervisor` / `contexts` DashMap path.
#[test]
fn ttl_timer_helpers_call_actor_shape_spawn_not_legacy() {
    assert!(
        fn_body_contains(MANAGER_SRC, "start_ttl_timer", "spawn_ttl_timer(")
            && !fn_body_contains(MANAGER_SRC, "start_ttl_timer", "spawn_ttl_timer_legacy("),
        "ttl_close_helpers::start_ttl_timer must install via the actor-shape \
         spawn_ttl_timer (registry + FireTimer tick), not spawn_ttl_timer_legacy"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "reset_ttl_timer", "spawn_ttl_timer(")
            && !fn_body_contains(MANAGER_SRC, "reset_ttl_timer", "spawn_ttl_timer_legacy("),
        "ttl_close_helpers::reset_ttl_timer must install via the actor-shape \
         spawn_ttl_timer (registry + FireTimer tick), not spawn_ttl_timer_legacy"
    );
}

// Timer level: the lifecycle bootstrap paths install timers by mailboxing
// the freshly-spawned actor (`dispatch_start_ttl_timer` /
// `start_governance_timeout_task` → StartTimeoutTask), NOT by reaching the
// legacy `spawn_ttl_timer_legacy` / `start_governance_timeout_task_legacy`
// `&Supervisor` helpers. ADR-049 Phase 2A finalization. Additive.
#[test]
fn lifecycle_bootstrap_installs_timers_via_mailbox_not_legacy() {
    for fn_name in ["finalize_create", "restore_context", "import_context"] {
        assert!(
            !fn_body_contains(MANAGER_SRC, fn_name, "spawn_ttl_timer_legacy("),
            "lifecycle_helpers::{fn_name} must not reach the legacy \
             spawn_ttl_timer_legacy — install the TTL timer via the actor \
             mailbox (dispatch_start_ttl_timer)"
        );
    }
    // The non-legacy governance-timeout entry point installs via the
    // actor mailbox (StartTimeoutTask), not the legacy DashMap-reading
    // spawn dance.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "start_governance_timeout_task",
            "StartTimeoutTask"
        ) && !fn_body_contains(
            MANAGER_SRC,
            "start_governance_timeout_task",
            "start_governance_timeout_task_legacy("
        ),
        "governance_helpers::start_governance_timeout_task must dispatch \
         StartTimeoutTask to the actor, not delegate to the legacy \
         start_governance_timeout_task_legacy DashMap spawn dance"
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

// --- Envelope layer (§13) — NOW WIRED ---

#[test]
fn encrypt_path_calls_create_outer_envelope_or_seal() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "seal", "create_outer_envelope")
            || fn_body_contains(MANAGER_SRC, "send_message", "create_outer_envelope"),
        "send/encrypt path must call create_outer_envelope"
    );
}

// --- Inner envelope / signatures (§9.8, #1547) — NOW WIRED ---

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

// --- Padding (§13) — NOW WIRED ---

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
    // ADR-049 actor migration relocated the post-delivery consequence
    // dispatch from the legacy `dispatch_consequences` wrapper into the
    // actor-shape `run_buffered_post_delivery` (messaging_helpers.rs),
    // which evaluates consequence rules against the buffered events.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "run_buffered_post_delivery",
            "evaluate_consequence_rules"
        ),
        "run_buffered_post_delivery must call evaluate_consequence_rules"
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

// --- Per-DID anti-spam escalation for tool invocations (§19.7) ---

#[test]
fn invoke_tool_with_economy_wires_escalation_and_rollback() {
    // ADR-049 actor split: the Phase-1 economy reserve runs on actor-owned
    // state in `reserve_tool_economy`. It must (a) record the new velocity
    // entry so compute_escalated_cost sees it, (b) thread the per-context
    // velocity_tracker and message_pricing into ToolEconomyContext, and the
    // Phase-3 `rollback_tool_economy` must roll back the velocity entry on
    // executor failure. The orchestrator `invoke_tool_with_economy` runs the
    // tool executor between the two phases.
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_tool_economy", "record_message"),
        "reserve_tool_economy must record the invocation for velocity tracking"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_tool_economy", "velocity_tracker"),
        "reserve_tool_economy must thread velocity_tracker into ToolEconomyContext"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_tool_economy", "message_pricing"),
        "reserve_tool_economy must thread message_pricing into ToolEconomyContext"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "rollback_tool_economy", ".rollback("),
        "rollback_tool_economy must roll back the velocity entry on executor failure \
         via the F5 identity-based `rollback(token)` API"
    );
    // The orchestrator runs the tool executor between reserve and settle.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_tool_with_economy",
            "invoke_tool_execute_and_validate"
        ),
        "invoke_tool_with_economy must run the executor via invoke_tool_execute_and_validate \
         between the reserve (Phase 1) and settle (Phase 3) mailbox round-trips"
    );
}

/// D4: the Phase-1 reserve (`reserve_tool_economy`) must reference the
/// hard rate limit. Enforced structurally so a future refactor cannot
/// silently drop the Matrix Synapse–style defense-in-depth cap on the
/// tool path.
#[test]
fn invoke_tool_with_economy_enforces_hard_rate_limit() {
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_tool_economy", "hard_rate_limit"),
        "reserve_tool_economy must reference hard_rate_limit so the Matrix Synapse–style \
         defense-in-depth cap is enforced on the tool path (D4)"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_tool_economy", "try_consume"),
        "reserve_tool_economy must call try_consume on the hard rate limit token bucket \
         before any Phase 1 bookkeeping — mirrors enforce_send_economy at messaging.rs:346"
    );
}

/// D4: every Phase 1 failure branch in `reserve_tool_economy` MUST refund
/// the hard rate limit token. We expect at least 3 inline refund sites:
/// `economy_pre_check` failure, `record_spend` failure, and
/// `authorize_tool_payment` failure. Dropping any branch leaks a
/// rate-limit token on failure.
#[test]
fn invoke_tool_with_economy_refunds_hard_rate_limit_on_every_phase1_failure() {
    let body = extract_fn_body(MANAGER_SRC, "reserve_tool_economy")
        .expect("reserve_tool_economy body must exist");
    // The hard-rate-limit token is refunded through the field-granular Class-C
    // governance view (`hard_rate_limit_mut().refund(..)`) on every Phase-1
    // failure branch (ADR-049 §9). Match the accessor form so a renamed bucket
    // access does not silently drop a refund site.
    let refund_sites = body.matches("hard_rate_limit_mut().refund").count();
    assert!(
        refund_sites >= 3,
        "reserve_tool_economy must have at least 3 inline hard_rate_limit_mut().refund sites \
         (economy_pre_check failure, record_spend failure, authorize_tool_payment failure); \
         found {refund_sites}. Dropping any branch leaks a rate-limit token on failure."
    );
}

#[test]
fn invoke_tool_with_economy_releases_lock_before_executor() {
    // ADR-049 actor-split invariant (supersedes the legacy lock_context /
    // relock_context generation-guard mechanism, which is gone with the
    // `contexts` DashMap): the caller-supplied non-Send executor must run
    // OUTSIDE the per-context actor — between the Phase-1 economy reserve and
    // the Phase-3 settle. The economy bookkeeping that mutates per-context
    // state lives entirely in `reserve_tool_economy` / `settle_tool_economy`
    // (which run on `&mut PerContextState` inside the actor); the executor
    // never crosses the actor mailbox and never holds per-context state
    // exclusively. A mis-behaving tool executor blocked every concurrent
    // manager call until the original lock-split landed; the actor split
    // preserves the same off-state-executor guarantee.
    //
    // We assert the orchestrator:
    //   (1) hands the reserve closure to the helper (Phase 1),
    //   (2) hands the settle closure to the helper (Phase 3), and
    //   (3) runs the executor (Phase 2) between them.
    let body = extract_fn_body(MANAGER_SRC, "invoke_tool_with_economy")
        .expect("invoke_tool_with_economy body must exist");
    assert!(
        body.contains("reserve()")
            && body.contains("settle(")
            && body.contains("invoke_tool_execute_and_validate"),
        "invoke_tool_with_economy must run the reserve (Phase 1) and settle (Phase 3) \
         mailbox round-trips around the off-actor executor (Phase 2) so the non-Send tool \
         executor never holds per-context state exclusively"
    );
    // Defense in depth: the settle path must cover BOTH the success
    // (Capture) and failure (Rollback) branches.
    assert!(
        body.contains("Capture") && body.contains("Rollback"),
        "invoke_tool_with_economy must settle via Capture on executor success and Rollback \
         on executor failure"
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

// ---------------------------------------------------------------------------
// Direct-execute governance trust boundary (quorum-bypass fix)
//
// `execute_governance_action` must dispatch the action the *engine* tracked for
// a proposal id — never a caller-supplied proposal/action/status. These
// positive (closed-by-construction) assertions pin the trust boundary at the
// AST level on BOTH the native runtime and the WASM bridge so a future refactor
// cannot reintroduce the bypass by re-accepting caller-trusted governance data.
// ---------------------------------------------------------------------------

#[test]
fn native_execute_governance_action_resolves_proposal_by_id_from_engine() {
    // The native entry point resolves the authoritative proposal from the
    // context actor's own quorum-validated engine via `engine.get_proposal`,
    // keyed by a `proposal_id` parameter — and never takes a caller-supplied
    // `&GovernanceProposal`. The signature carries `proposal_id: &ProposalId`,
    // not `proposal: &GovernanceProposal`.
    let sig = extract_fn_signature(MANAGER_SRC, "execute_governance_action")
        .expect("native execute_governance_action signature must exist");
    assert!(
        sig.contains("proposal_id: &ProposalId"),
        "native execute_governance_action must take the proposal id by reference \
         (proposal_id: &ProposalId), so the action is resolved from engine state — \
         not handed in by the caller; signature was: {sig}"
    );
    assert!(
        !sig.contains("proposal: &GovernanceProposal"),
        "native execute_governance_action must NOT accept a caller-supplied \
         &GovernanceProposal — that is the quorum-bypass the by-id resolution closes; \
         signature was: {sig}"
    );

    let body = extract_fn_body(MANAGER_SRC, "execute_governance_action")
        .expect("native execute_governance_action body must exist");
    assert!(
        body.contains("engine") && body.contains("get_proposal(proposal_id)"),
        "native execute_governance_action must resolve the authoritative proposal \
         from the governance engine via engine.get_proposal(proposal_id)"
    );
    assert!(
        body.contains("not tracked"),
        "native execute_governance_action must reject a proposal id the engine \
         never tracked (the forgery path)"
    );
}

#[test]
fn wasm_execute_governance_action_resolves_action_from_tracked_proposal() {
    // The WASM bridge entry (`context_execute_governance`) takes no caller
    // action and no caller identity/subject: the public `#[wasm_bindgen]`
    // surface carries ONLY (handle, proposal_id_hex). No `action_json` parameter
    // exists for a caller to populate (action substitution is structurally
    // impossible), and no `identity_did` parameter exists for a caller to supply
    // a consequence subject / executor — both are resolved from the tracked
    // proposal's proposer inside the manager.
    let wasm_ctx_src: &str = include_str!("../../../../crates/scp-ffi/wasm/src/context.rs");
    let entry_sig = extract_fn_signature(wasm_ctx_src, "context_execute_governance")
        .expect("WASM context_execute_governance signature must exist");
    assert!(
        !entry_sig.contains("action_json"),
        "WASM context_execute_governance must NOT take an action_json parameter — \
         a caller cannot supply an action to substitute; signature was: {entry_sig}"
    );
    assert!(
        !entry_sig.contains("identity_did"),
        "WASM context_execute_governance must NOT take an identity_did parameter — \
         the executor and consequence subject are resolved from the tracked \
         proposal's proposer, never a caller-supplied DID; signature was: {entry_sig}"
    );
    assert!(
        entry_sig.contains("proposal_id_hex"),
        "WASM context_execute_governance must take the tracked proposal id \
         (proposal_id_hex); signature was: {entry_sig}"
    );

    // The WASM manager resolves BOTH the convergent timestamp AND the action to
    // dispatch from the manager's own tracked proposal state
    // (pending_proposals / resolved_proposals) — never a caller action.
    let body = extract_fn_body(WASM_MANAGER_SRC, "execute_governance_action")
        .expect("WASM execute_governance_action body must exist");
    assert!(
        body.contains("pending_proposals") && body.contains("resolved_proposals"),
        "WASM execute_governance_action must resolve the action from its own \
         tracked proposal state (pending_proposals / resolved_proposals)"
    );
    assert!(
        body.contains("tracked_action") || body.contains("tracked.action"),
        "WASM execute_governance_action must dispatch the TRACKED proposal's \
         action, not a caller-supplied one"
    );
    let mgr_sig = extract_fn_signature(WASM_MANAGER_SRC, "execute_governance_action")
        .expect("WASM manager execute_governance_action signature must exist");
    assert!(
        !mgr_sig.contains("action: &GovernanceAction"),
        "WASM manager execute_governance_action must NOT accept a caller-supplied \
         action: &GovernanceAction; signature was: {mgr_sig}"
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

// C4 (#1606) — Bridge tool-invoke economy wiring
//
// All 3 non-WASM FFI bridges (PyO3, NAPI, UniFFI) MUST route tool
// invocation through `ContextManager::invoke_tool_with_economy`. The
// previous bypass path called `try_consume_hard_rate_limit_*` directly
// against the bridge-owned tool registry, which disabled per-invocation
// pricing, spending UCAN AND-composition, velocity tracking, budget
// enforcement, and the `ToolEconomyTicket` lifecycle for Python /
// Node / Swift / Kotlin clients.
//
// These structural assertions catch any future regression to the
// bypass path. Each assertion is `fn_body_contains` against the actual
// bridge function source — calling the runtime helper from a different
// function would fail the test.
// ---------------------------------------------------------------------------

// Phase 4 PR 4 (#1549 façade deletion) renamed the PyO3 free function
// `py_tool_invoke` → `#[pymethods] impl PyScp { pub fn tool_invoke(&self, ...) }`
// delegating to the private `tool_invoke_impl` free function that
// carries the real wiring. The assertion targets `tool_invoke_impl` —
// the implementation body — so a refactor cannot silently regress to a
// bypass path even if the public method signature is preserved.
#[test]
fn c4_pyo3_tool_invoke_routes_through_invoke_tool_with_economy() {
    assert!(
        fn_body_contains(
            PYO3_TOOLS_SRC,
            "tool_invoke_impl",
            "invoke_tool_with_economy"
        ),
        "PyO3 tool_invoke_impl must call ContextManager::invoke_tool_with_economy \
         (PR #1606 / C4). Calling try_consume_hard_rate_limit_blocking against \
         a bridge-owned registry instead disables per-invocation pricing, \
         spending UCAN, velocity tracking, and budget enforcement for Python \
         clients."
    );
}

#[test]
fn c4_pyo3_tool_invoke_accepts_spending_ucan() {
    // The bridge MUST accept the spending UCAN parameter — the
    // runtime's `invoke_tool_with_economy` requires it for §19.5
    // AND-composition on paid actions.
    let body = extract_fn_body(PYO3_TOOLS_SRC, "tool_invoke_impl")
        .expect("tool_invoke_impl body must exist");
    assert!(
        body.contains("spending_ucan"),
        "PyO3 tool_invoke_impl must accept and forward a spending UCAN argument \
         (PR #1606 / C4). Without it, paid tool invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "PyO3 tool_invoke_impl must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_tool_with_economy."
    );
}

// Phase 4 PR 4 moved the NAPI free-function export into
// `impl Scp { pub async fn tool_invoke(&self, ...) }` that delegates to
// `tool_invoke_on` in `tools.rs`. The wiring (spending_ucan_jwt parse +
// `invoke_tool_with_economy` call) lives on the `tool_invoke_on` helper,
// so that is the function we assert against.
#[test]
fn c4_napi_tool_invoke_routes_through_invoke_tool_with_economy() {
    assert!(
        fn_body_contains(NAPI_TOOLS_SRC, "tool_invoke_on", "invoke_tool_with_economy"),
        "NAPI tool_invoke_on must call ContextManager::invoke_tool_with_economy \
         (PR #1606 / C4). The previous bypass path called \
         try_consume_hard_rate_limit against the bridge-owned tool registry, \
         disabling per-invocation pricing, spending UCAN, velocity tracking, \
         and budget enforcement for Node clients."
    );
}

#[test]
fn c4_napi_tool_invoke_accepts_spending_ucan() {
    let body = extract_fn_body(NAPI_TOOLS_SRC, "tool_invoke_on")
        .expect("NAPI tool_invoke_on body must exist");
    assert!(
        body.contains("spending_ucan_jwt"),
        "NAPI tool_invoke_on must accept and forward a spending_ucan_jwt argument \
         (PR #1606 / C4). Without it, paid tool invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "NAPI tool_invoke_on must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_tool_with_economy."
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
fn c4_uniffi_tool_invoke_routes_through_invoke_tool_with_economy() {
    // `extract_fn_body` returns the first match, which is the
    // top-level `tool_invoke` (not `tool_invoke_cross_context`).
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "tool_invoke", "invoke_tool_with_economy"),
        "UniFFI tool_invoke must call ContextManager::invoke_tool_with_economy \
         (PR #1606 / C4). The previous bypass path called \
         try_consume_hard_rate_limit against the bridge-owned tool registry, \
         disabling per-invocation pricing, spending UCAN, velocity tracking, \
         and budget enforcement for Swift / Kotlin clients."
    );
}

#[test]
fn c4_uniffi_tool_invoke_accepts_spending_ucan() {
    let body = extract_fn_body(UNIFFI_BRIDGE_SRC, "tool_invoke")
        .expect("UniFFI tool_invoke body must exist");
    assert!(
        body.contains("spending_ucan_jwt"),
        "UniFFI tool_invoke must accept and forward a spending_ucan_jwt argument \
         (PR #1606 / C4). Without it, paid tool invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "UniFFI tool_invoke must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_tool_with_economy."
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
/// finalize_send must call create_checkpoint_if_due_view periodically AND broadcast
/// a due checkpoint to peers via send_checkpoint (§9.9.3, §23.7).
#[test]
fn b3_checkpoint_generation_wired() {
    // close_context_with_key must call force_create_checkpoint for archival.
    let body = extract_fn_body(MANAGER_SRC, "close_context_with_key")
        .expect("close_context_with_key must exist in manager source");
    assert!(
        body.contains("force_create_checkpoint") || body.contains("create_checkpoint"),
        "close_context_with_key must generate a final checkpoint"
    );

    // finalize_send must DELEGATE periodic checkpoint creation + broadcast to
    // create_and_broadcast_checkpoint_if_due. Real call-site assertion (not a
    // bare string search): finalize_send → create_and_broadcast_checkpoint_if_due
    // → create_checkpoint_if_due_view (create + retain locally) AND send_checkpoint
    // (broadcast to peers for equivocation detection, §23.7). The callee token
    // carries its `_view` suffix so the assertion names the ACTUAL field-granular
    // entry and cannot be satisfied by a renamed sibling's substring.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "finalize_send",
            "create_and_broadcast_checkpoint_if_due",
        ),
        "finalize_send must drive periodic checkpoint create+broadcast via \
         create_and_broadcast_checkpoint_if_due"
    );
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "create_and_broadcast_checkpoint_if_due",
            "create_checkpoint_if_due_view(",
        ),
        "create_and_broadcast_checkpoint_if_due must call create_checkpoint_if_due_view"
    );
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "create_and_broadcast_checkpoint_if_due",
            "send_checkpoint",
        ),
        "create_and_broadcast_checkpoint_if_due must broadcast a due checkpoint \
         to peers via send_checkpoint (§9.9.3 checkpoint exchange)"
    );
}

/// Merkle proof verification must be wired into the equivocation detection path.
/// compare_remote_checkpoint must compare local and remote Merkle roots and emit
/// EquivocationDetected when divergent (§9.9.3, ADR-011 AC-8), AND it must be
/// reached from the receive path: deliver_incoming dispatches a received
/// ConsistencyCheckpoint message to compare_remote_checkpoint (§9.9.3).
#[test]
fn b3_merkle_proof_verification_wired() {
    // The Merkle-root comparison + divergence classification live in the shared
    // `classify_remote_checkpoint` core, which `compare_remote_checkpoint`
    // delegates to (the cell-view receive path and the bare-state callers reach
    // the SAME core). Assert the core performs the comparison, and that
    // `compare_remote_checkpoint` actually reaches it + the equivocation emit.
    let classify_body = extract_fn_body(MANAGER_SRC, "classify_remote_checkpoint")
        .expect("classify_remote_checkpoint must exist in manager source");
    assert!(
        classify_body.contains("merkle_root") || classify_body.contains("event_log_merkle_root"),
        "classify_remote_checkpoint must compare Merkle roots"
    );
    assert!(
        classify_body.contains("Divergent") || classify_body.contains("EquivocationDetected"),
        "classify_remote_checkpoint must detect divergence / equivocation"
    );
    // compare_remote_checkpoint must REACH the comparison core and, on a divergent
    // result, emit the equivocation alert (§9.9.3 / §9.9.4).
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "compare_remote_checkpoint",
            "classify_remote_checkpoint",
        ),
        "compare_remote_checkpoint must delegate the Merkle/divergence comparison \
         to classify_remote_checkpoint"
    );
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "compare_remote_checkpoint",
            "emit_equivocation_alert",
        ),
        "compare_remote_checkpoint must emit an equivocation alert on a divergent \
         checkpoint (§9.9.4)"
    );

    // Real call-site assertion: the receive path must actually REACH the
    // comparison. deliver_incoming dispatches a ConsistencyCheckpoint message to
    // deliver_checkpoint_message, which calls compare_remote_checkpoint. Without
    // this chain the detection logic is dead code (the reconnection-path gap).
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "deliver_incoming",
            "deliver_checkpoint_message"
        ),
        "deliver_incoming must dispatch ConsistencyCheckpoint messages to \
         deliver_checkpoint_message"
    );
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "deliver_checkpoint_message",
            "compare_remote_checkpoint",
        ),
        "deliver_checkpoint_message must call compare_remote_checkpoint so a \
         received checkpoint is checked for equivocation (§9.9.3)"
    );
}

/// The suppression-detection heartbeat loop (§9.9.2) must be closed end to
/// end: a periodic SEND driven by the bridge subscribe scheduler, the SEND
/// helper actually emitting a `MessageType::Heartbeat` envelope, the RECEIVE
/// path classifying it, and the receive loop RECORDING it against the
/// transport monitor. Real call-site assertions (not bare string searches):
/// without each link the HeartbeatMonitor stays a dead component — built but
/// never fed (the suppression-detection gap §9.9.2 closes).
#[test]
fn b3_heartbeat_send_receive_loop_wired() {
    // SEND link 1 — the shared scheduler must drive Supervisor::send_heartbeat
    // at the periodic tick.
    assert!(
        fn_body_contains(
            HEARTBEAT_SCHEDULER_SRC,
            "run_heartbeat_scheduler",
            "send_heartbeat",
        ),
        "run_heartbeat_scheduler must call Supervisor::send_heartbeat each tick (§9.9.2 send side)"
    );

    // SEND link 2 — the napi subscribe loop must spawn the scheduler so the
    // periodic send actually runs while subscribed.
    assert!(
        fn_body_contains(
            NAPI_CONTEXT_SRC,
            "context_subscribe_on",
            "run_heartbeat_scheduler",
        ),
        "context_subscribe_on must spawn run_heartbeat_scheduler alongside the subscribe loop"
    );

    // SEND link 3 — the core send helper must emit an actual heartbeat-typed
    // envelope through the encrypt-and-send machinery.
    assert!(
        fn_body_contains(MANAGER_SRC, "send_heartbeat", "encrypt_and_send"),
        "send_heartbeat must route through encrypt_and_send"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "send_heartbeat", "MessageType::Heartbeat"),
        "send_heartbeat must tag the envelope MessageType::Heartbeat"
    );

    // RECEIVE link 1 — deliver_incoming must classify heartbeats (returning
    // DeliverOutcome::Heartbeat) before the content sequence tracker.
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", "MessageType::Heartbeat")
            && fn_body_contains(MANAGER_SRC, "deliver_incoming", "DeliverOutcome::Heartbeat"),
        "deliver_incoming must classify MessageType::Heartbeat as DeliverOutcome::Heartbeat"
    );

    // RECEIVE link 2 — the napi receive loop must record the heartbeat against
    // the transport monitor so suppression gap detection has a fresh baseline.
    assert!(
        fn_body_contains(
            NAPI_CONTEXT_SRC,
            "context_subscribe_on",
            "record_heartbeat_received",
        ),
        "the napi subscribe loop must call record_heartbeat_received on a received heartbeat"
    );

    // TEARDOWN link — the napi subscribe loop must cancel the per-subscription
    // token when it exits so the co-scheduled run_heartbeat_scheduler tears
    // down in lockstep. Without this, every non-unsubscribe exit path (stream
    // exhaustion, relay Terminated, bridge shutdown) would leave the scheduler
    // firing Supervisor::send_heartbeat on a dead subscription — leaking the
    // task, its Arc<Supervisor>, and the exported signing key, and emitting
    // false liveness. A re-subscribe overwrites the handle's token without
    // cancelling the old one, so this teardown is the only stop.
    assert!(
        fn_body_contains(
            NAPI_CONTEXT_SRC,
            "context_subscribe_on",
            "cancel_token.cancel()"
        ),
        "context_subscribe_on must cancel_token.cancel() on subscribe-loop exit so the \
         heartbeat scheduler tears down in lockstep (no orphaned scheduler on a dead \
         subscription)"
    );
}

/// The FFI/SDK reconnection driver must DRIVE the checkpoint exchange, not
/// merely re-implement it. The ADR-029 reconnection driver lives at the
/// relay-client layer (the actor's transport provider is send-only); its
/// Phase-3 `event_log_sync` must build + broadcast the local checkpoint via
/// `Supervisor::build_local_checkpoint` AND surface remote-checkpoint
/// equivocation alerts. Phase 2 (`epoch_reconciliation`) feeds retrieved
/// blobs through `deliver_commit_blob`, whose `deliver_incoming` path reaches
/// `compare_remote_checkpoint` (pinned by `b3_merkle_proof_verification_wired`)
/// — so feeding the blobs is what reaches the comparison. Real call-site
/// assertions (not bare string searches): without these the driver would be a
/// dead reconnection path severed from the equivocation core (§9.9.3).
#[test]
fn b3_reconnect_drives_checkpoint_exchange() {
    // Phase 3: event_log_sync must build (and, via the actor turn, broadcast)
    // the local checkpoint through the supervisor mailbox wrapper.
    assert!(
        fn_body_contains(
            RECONNECT_DRIVER_SRC,
            "event_log_sync",
            "build_local_checkpoint",
        ),
        "RelayActorSyncDriver::event_log_sync must build the local checkpoint \
         via Supervisor::build_local_checkpoint (§9.9.3 Phase 3)"
    );

    // Phase 3: event_log_sync must surface the EquivocationDetected alerts the
    // actor emitted while comparing retrieved remote checkpoints.
    assert!(
        fn_body_contains(
            RECONNECT_DRIVER_SRC,
            "event_log_sync",
            "collect_equivocation_alerts",
        ),
        "RelayActorSyncDriver::event_log_sync must collect EquivocationDetected \
         alerts surfaced by compare_remote_checkpoint (§9.9.3)"
    );

    // Phase 2: epoch_reconciliation must feed retrieved blobs through
    // deliver_commit_blob — the DeliverIncoming path that dispatches
    // ConsistencyCheckpoint messages to compare_remote_checkpoint. This is the
    // composition seam with the equivocation core (§9.9.3): feeding the blobs is what reaches
    // the comparison.
    assert!(
        fn_body_contains(
            RECONNECT_DRIVER_SRC,
            "epoch_reconciliation",
            "deliver_commit_blob",
        ),
        "RelayActorSyncDriver::epoch_reconciliation must feed retrieved blobs \
         through Supervisor::deliver_commit_blob so received checkpoints reach \
         compare_remote_checkpoint (composes with b3_merkle_proof_verification)"
    );

    // The build wrapper itself must reach send_checkpoint inside the actor turn
    // (build + broadcast in one mailbox round-trip) so the driver never needs
    // the pub(crate) send_checkpoint helper across the crate boundary.
    assert!(
        fn_body_contains(
            HANDLERS_MESSAGING_SRC,
            "handle_build_local_checkpoint",
            "send_checkpoint",
        ),
        "handle_build_local_checkpoint must broadcast the freshly-built \
         checkpoint to peers via send_checkpoint (Phase 3 build + broadcast)"
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

    // The consumer that bridges Supervisor events to the dispatcher must
    // exist (§12.10.5). Without it, local context events can never reach
    // registered webhooks — the dispatcher would only ever be fed by the
    // inbound HTTP relay endpoint.
    assert!(
        webhook_src.contains("fn spawn_event_consumer"),
        "webhook module must export spawn_event_consumer (local-event → dispatcher bridge)"
    );
    assert!(
        webhook_src.contains("fn map_context_event"),
        "webhook module must map ContextEvent variants to webhook event types"
    );

    // The consumer must be wired in production: the node exposes the wire, and
    // the FFI node-startup path enables the Supervisor event channel and spawns
    // the consumer. A string match here guards against the regression where the
    // plumbing existed but was never connected.
    assert!(
        node_src.contains("fn wire_context_events"),
        "ApplicationNode must expose wire_context_events to connect events to the dispatcher"
    );

    // The producer seam: the supervisor exposes the public subscribe surface
    // that FFI node startup drives. After ADR-049 the event channel moved off
    // the deleted ContextManager onto the Supervisor, so the live symbol is
    // `Supervisor::subscribe_events` (the former `ContextManager::with_event_channel`
    // accessor is gone).
    let supervisor_src =
        include_str!("../../../../crates/scp-runtime/src/context/supervisor/supervisor.rs");
    assert!(
        supervisor_src.contains("fn subscribe_events"),
        "Supervisor must expose subscribe_events so the node webhook dispatcher \
         consumer can subscribe (otherwise no events are dispatched)"
    );

    // Every non-WASM bridge (PyO3 reference, NAPI, UniFFI) must independently
    // (a) enable the Supervisor event channel at supervisor construction and
    // (b) wire the consumer into the dispatcher at node startup. The original
    // wiring was first fixed only on PyO3; NAPI/UniFFI had structurally
    // identical startup paths that were never wired, so local events never
    // reached the dispatcher on Node/Bun/Swift/Kotlin. These per-bridge string
    // matches guard against that drift recurring.
    //
    // The shared supervision seam (`spawn_supervised_event_consumer`) lives in
    // `scp-ffi-common`; assert it exists so the consolidated wire cannot be
    // silently inlined-and-diverged again.
    let common_server_src = include_str!("../../../../crates/scp-ffi/common/src/server.rs");
    assert!(
        common_server_src.contains("fn spawn_supervised_event_consumer"),
        "scp-ffi-common must expose the shared spawn_supervised_event_consumer \
         supervision seam used by all bridges"
    );
    assert!(
        common_server_src.contains("fn wire_and_supervise_context_events"),
        "RunningNode must expose wire_and_supervise_context_events (shared \
         subscribe → wire → supervise seam for all bridges)"
    );

    // PyO3 reference bridge.
    let ffi_server_src = include_str!("../../../../crates/scp-ffi/src/server.rs");
    assert!(
        ffi_server_src.contains("wire_node_webhook_events")
            && ffi_server_src.contains("wire_and_supervise_context_events"),
        "PyO3 node startup must call wire_node_webhook_events into the shared \
         wire_and_supervise_context_events seam so local events reach the \
         webhook dispatcher"
    );
    let ffi_runtime_src = include_str!("../../../../crates/scp-ffi/src/runtime.rs");
    assert!(
        ffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && ffi_runtime_src.contains("Some(event_tx)"),
        "PyO3 production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None and no events are dispatched)"
    );

    // NAPI bridge (Node.js/Bun).
    let napi_server_src = include_str!("../../../../crates/scp-ffi/napi/src/server.rs");
    assert!(
        napi_server_src.contains("wire_and_supervise_context_events"),
        "NAPI node startup must wire Supervisor events into the webhook \
         dispatcher (regression guard on Node/Bun)"
    );
    let napi_runtime_src = include_str!("../../../../crates/scp-ffi/napi/src/runtime.rs");
    assert!(
        napi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && napi_runtime_src.contains("Some(event_tx)"),
        "NAPI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None and no events are dispatched)"
    );

    // UniFFI bridge (Swift/Kotlin).
    let uniffi_server_src = include_str!("../../../../crates/scp-ffi/uniffi/src/server.rs");
    assert!(
        uniffi_server_src.contains("wire_and_supervise_context_events"),
        "UniFFI node startup must wire Supervisor events into the webhook \
         dispatcher (regression guard on Swift/Kotlin)"
    );
    let uniffi_runtime_src = include_str!("../../../../crates/scp-ffi/uniffi/src/runtime.rs");
    assert!(
        uniffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && uniffi_runtime_src.contains("Some(event_tx)"),
        "UniFFI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None and no events are dispatched)"
    );
}

// ===========================================================================
// UCAN validation step 8 — all-attestation ceiling enforcement
// ===========================================================================

/// Step 8 of `validate_ucan` must enforce the ceiling over the token's FULL
/// parsed attestation set (`&granted_caps`), not only the invoked capability
/// (spec §7.2.1 step 8). Pins the fix against a silent regression to
/// `from_ref(required_capability)`, which would allow a token to smuggle an
/// out-of-ceiling attestation past validation.
#[test]
fn ucan_step8_enforces_ceiling_over_all_att() {
    assert!(
        fn_body_contains(
            UCAN_VALIDATE_SRC,
            "validate_ucan",
            "verify_ceiling_compliance(&granted_caps,"
        ),
        "validate_ucan step 8 must call verify_ceiling_compliance over the full \
         parsed attestation set (&granted_caps), per spec §7.2.1 step 8"
    );
    assert!(
        !fn_body_contains(
            UCAN_VALIDATE_SRC,
            "validate_ucan",
            "verify_ceiling_compliance(std::slice::from_ref(required_capability)"
        ),
        "validate_ucan step 8 must NOT scope the ceiling check to only the \
         invoked capability — that lets a token smuggle an out-of-ceiling \
         attestation (spec §7.2.1 step 8)"
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
    let meta_tests = 3; // this test + claude_md_enforcement_sections_present + no_stale_ignores
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
