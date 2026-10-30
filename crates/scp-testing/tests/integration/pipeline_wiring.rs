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
// in ADR-049 §15 — every method body that the pipeline-wiring
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
    include_str!("../../../../crates/scp-runtime/src/context/outlets_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/broadcast_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/queries_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/economy_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/trust_recovery_helpers.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/ttl_close_helpers.rs"),
);
const PROVIDER_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/crypto/mls/provider.rs");

// Actor per-context state source — owns the `ContextCryptoState::{seal,open}`
// steady-state crypto seam. ADR-049 PR-7 (SCP-CRYPTOMOVE-001) moved the seal /
// open bodies off the `NodeMlsFactory` (deleted) onto the actor-owned
// `PerContextState` here, so the seal-internal envelope-pipeline assertions scan
// this source (the moved code), not `PROVIDER_SRC`. This is a repoint to the new
// home of the same seal/open pipeline, not a weakening.
const STATE_SRC: &str = include_str!("../../../../crates/scp-runtime/src/context/actor/state.rs");

// Supervisor dispatch source — owns `dispatch_lifecycle_direct`, whose
// bootstrap arms (Create / Import / Restore) moved to the actor-shape
// `lifecycle_helpers::{create,import,restore}_context` in the ADR-049
// Phase 2A finalization (storage-foundation keystone). The structural
// assertion below pins that wiring so a future refactor cannot silently
// regress the bootstrap path back to the `_legacy` `&Supervisor` helpers
// (which no longer spawn a per-context actor).
const SUPERVISOR_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/supervisor/supervisor.rs");

// Outlet invocation source — owns the SCP-OUT-046 off-mailbox streaming-saga
// seal task (`run_streaming_saga_seal_task`). The `ac8_*` structural assertion
// below pins the ADR-061 "commit once over the bounded root" invariant: the
// per-chunk pump loop folds each chunk via `StreamCaptureAppend` but issues NO
// per-chunk two-phase commit — the single `CommitBStreamSettle` fires once at
// stream-close, outside the loop.
const OUTLETS_INVOKE_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/outlets/invoke.rs");

// FFI bridge sources. PR #1606 / C4 wired all 3 of these to
// `ContextManager::invoke_outlet_with_economy` so per-invocation pricing,
// spending UCAN, velocity tracking, budget enforcement, and the hard
// rate limit are enforced for Python / Node / Swift / Kotlin clients.
// The structural assertions in `c4_outlet_invoke_economy_*` below pin
// the bridge → runtime delegation so a future refactor cannot silently
// regress to the bypass path.
const PYO3_OUTLETS_SRC: &str = include_str!("../../../../crates/scp-ffi/src/outlets.rs");
// §5.4.5 streaming-native outlet invocation (SCP-OUT-037, C7). The PyO3
// reference bridge for the streaming open + control plane.
const PYO3_OUTLET_STREAM_SRC: &str =
    include_str!("../../../../crates/scp-ffi/src/outlet_stream.rs");
const NAPI_OUTLETS_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/outlets.rs");
// §5.4.5 streaming-native outlet invocation (SCP-OUT-037, C8a). The NAPI
// bridge for the streaming open + control plane (mirrors the PyO3 reference).
const NAPI_OUTLET_STREAM_SRC: &str =
    include_str!("../../../../crates/scp-ffi/napi/src/outlet_stream.rs");
const UNIFFI_BRIDGE_SRC: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs");
// §5.4.5 streaming-native outlet invocation (SCP-OUT-037, C8b). The UniFFI
// bridge for the streaming open + control plane (mirrors the PyO3 reference).
const UNIFFI_OUTLET_STREAM_SRC: &str =
    include_str!("../../../../crates/scp-ffi/uniffi/src/outlet_stream.rs");

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

// Shared bridge-instance core (scp-ffi-common) — owns the production
// startup/resume path `restore_all_persisted_contexts`, which MUST route
// through `Supervisor::restore_on_startup` so the §17.16.4 saga-journal
// replay runs after context restore on every process restart (ADR-049).
// Pinned by `restore_on_startup_runs_restore_before_replay` and
// `bridge_resume_path_routes_through_restore_on_startup`.
const BRIDGE_INSTANCE_SRC: &str =
    include_str!("../../../../crates/scp-ffi/common/src/bridge_instance.rs");

// Node builder source — owns `build_domain_inner` and `build_no_domain_inner`,
// the two bodies every `Node::start` path funnels through.
// `every_node_start_path_starts_the_self_did_republish_cycle` pins ADR-003 §2
// step "republishing starts when an identity is loaded" to both of them, so a
// node can no longer publish its DID document once and never refresh it.
const NODE_BUILDER_SRC: &str = include_str!("../../../../crates/scp-node/src/lib.rs");

// Node self-host source — where the republish cycle used to be constructed. The
// same assertion checks it constructs none now, because two cycles over one
// BEP44 record would give its monotonic sequence two independent writers.
const NODE_SELF_HOST_SRC: &str = include_str!("../../../../crates/scp-node/src/self_host.rs");

// Node published-state source — owns `apply_tier_change`, the NAT-tier task's
// one writer, which moves the relay's live URL handle (PUSH-007, §10.7.1).
const NODE_PUBLISHED_STATE_SRC: &str =
    include_str!("../../../../crates/scp-node/src/published_state.rs");

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

// Push-wake handler source (ADR-029 §2 push-wake pull mode). The
// push_wake_pulls_without_signing assertion below pins `handle_wake` to the
// signer-free pull in `reconnect.rs`.
const PUSH_WAKE_SRC: &str = include_str!("../../../../crates/scp-ffi/common/src/push.rs");

// Actor messaging-handler source — owns `handle_build_local_checkpoint`,
// the actor-turn body that builds AND broadcasts the Phase-3 checkpoint so
// the FFI driver never needs the `pub(crate)` `send_checkpoint` across the
// crate boundary (ADR-029).
const HANDLERS_MESSAGING_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/messaging.rs");

// Actor broadcast-handler source — owns `handle_subscribe_broadcast`, the
// actor-turn body that builds a REAL UCAN `ValidationContext` from actor-owned
// state and passes it (`Some(&mut validation_ctx)`) into
// `broadcast_helpers::subscribe_broadcast` so a GATED broadcast context runs the
// full `messages:read` validation pipeline (spec §5.14.4, §07:70). The
// `gated_broadcast_subscribe_builds_real_validation_context` assertion below
// pins this so a refactor cannot silently regress the handler back to passing
// `None` (which made gated subscribe unreachable — every SDK gated-subscribe
// died at the protocol's missing-UCAN reject before validation ran).
const HANDLERS_BROADCAST_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/broadcast.rs");

// ContextActor run-loop source — owns `run()`, `reconcile_timers`,
// `on_ttl_tick`, `on_governance_timeout` (the ACTOR-OWNED timer arms,
// ADR-049 Decision-1 / finding A3). Pinned by
// `actor_owned_timer_arms_reconcile_from_state`.
const ACTOR_MOD_SRC: &str = include_str!("../../../../crates/scp-runtime/src/context/actor/mod.rs");

// Actor pseudonym-rotation source — owns `note_processed_commit`, which applies
// a processed membership Commit to the registry and the rotation state (spec 09
// §9.10.4.1). Pinned by `processed_membership_commit_reaches_rotation_and_registry`.
const PSEUDONYM_ROTATION_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/actor/pseudonym_rotation.rs");

// Push handler source — owns `handlers::push::dispatch`, the mailbox step of
// the PUSH-013 push routing-ID query (§10.7.1).
const HANDLERS_PUSH_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/push.rs");
const HANDLERS_LOG_UNIT_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/log_unit.rs");
// Push helpers source — owns `push_helpers::wake_target`, the push-wake pull
// target (ADR-029 §2). Pinned by `push_wake_targets_reach_push_helpers`.
const PUSH_HELPERS_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/push_helpers.rs");
// Push registrar source — owns `PushRegistrar::register`, which signs one
// `PushRegistration` per relay and publishes it at that relay's push routing ID
// (PUSH-014, §10.7.1). Pinned by `push_registrar_register_reaches_relay_publish`.
const PUSH_REGISTRAR_SRC: &str = include_str!("../../../../crates/scp-runtime/src/push/mod.rs");
// Push publisher source — owns `TransportPushPublisher::publish`, the relay
// PUBLISH the registrar's messages leave through (PUSH-014).
const PUSH_PUBLISHER_SRC: &str =
    include_str!("../../../../crates/scp-transport/src/native/push_publisher.rs");
// Actor queries-handler source — owns the `QueriesCommand::LocalRoutingIds`
// arm that answers through `queries_helpers::local_routing_ids` (spec 09
// §9.10.4.1). Pinned by `local_pseudonym_rotation_reaches_its_helpers`.
const HANDLERS_QUERIES_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/queries.rs");

// UCAN validation pipeline source — owns `validate_ucan`, the 11-step
// capability authorization gate. The `ucan_step8_enforces_ceiling_over_all_att`
// assertion below pins step 8 to checking the FULL parsed attestation set
// (`&granted_caps`) against the ceiling — not just the invoked capability
// (spec §7.2.1 step 8) — so a refactor cannot silently regress to
// `from_ref(required_capability)`, which would let a token smuggle an
// out-of-ceiling attestation past validation.
const UCAN_VALIDATE_SRC: &str =
    include_str!("../../../../crates/scp-protocol/src/crypto/ucan/validate.rs");

// PyO3 bridge UCAN source — owns `ucan_evaluate`, the structured read-only
// diagnostic op. The `ucan_evaluate_routes_to_core_evaluate_ucan` assertion
// below pins the bridge to consuming the shared core `evaluate_ucan` pipeline
// rather than re-implementing capability evaluation locally (which would let
// the diagnostic and the enforcing `validate_ucan` gate silently diverge).
const PYO3_UCAN_SRC: &str = include_str!("../../../../crates/scp-ffi/src/ucan.rs");

// The other two FFI bridges' UCAN sources. Each owns its own `ucan_evaluate`
// entry point and MUST route to the shared core `evaluate_ucan` pipeline rather
// than re-implementing capability evaluation locally (which would let the
// read-only diagnostic and the enforcing `validate_ucan` gate silently diverge).
// NAPI's body lives in the `ucan_evaluate_on` per-instance helper; UniFFI's
// lives in the `ucan_evaluate` bridge method.
const NAPI_UCAN_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/ucan.rs");

// Trust-engine bridge sources for the typed `participation_record` op (§7.3.2).
// Each native bridge owns its own participation entry point and MUST route to
// the shared `Supervisor::participation_record` (which itself calls core
// `compute_participation_record`) rather than re-deriving facts locally — that
// is the whole point of the typed op: SDKs RECEIVE the facts, never recompute
// them. PyO3's body lives in `participation_record_impl`, NAPI's in
// `participation_record_on`, UniFFI's in the `participation_record` bridge
// method.
const PYO3_TRUST_SRC: &str = include_str!("../../../../crates/scp-ffi/src/trust.rs");
const NAPI_TRUST_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/trust.rs");
// The shared bridge trust helpers: `verify_attestation_in_context`, the one body
// every bridge's `trust_verify_attestation` reaches, lives here.
const FFI_TRUST_STORE_SRC: &str =
    include_str!("../../../../crates/scp-ffi/common/src/trust_store.rs");
// The shared challenge operations (spec 07 §7.3.4) every bridge's
// `trust_create_challenge`, `trust_respond_to_challenge`,
// `trust_grade_response` and `check_capability_requirements` reach, the
// challenger ledger actor the supervisor dispatches them to, the common context
// params builder, and the NAPI class whose exported methods delegate to the
// `_on` bodies.
const FFI_CHALLENGE_SRC: &str = include_str!("../../../../crates/scp-ffi/common/src/challenge.rs");
const LEDGER_SRC: &str = include_str!(
    "../../../../crates/scp-runtime/src/context/supervisor/challenger_ledger_actor.rs"
);
const FFI_CONTEXT_PARAMS_SRC: &str =
    include_str!("../../../../crates/scp-ffi/common/src/context_params.rs");
const NAPI_SCP_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/scp.rs");
// Each bridge's `node_start` (construction.md §"Node start — `NodeStartConfig`"):
// PyO3's and napi-rs's bodies live in `node_start_on` in their `server.rs`,
// UniFFI's in `node_start_on` in `uniffi/src/server.rs`.
const PYO3_SERVER_SRC: &str = include_str!("../../../../crates/scp-ffi/src/server.rs");
const NAPI_SERVER_SRC: &str = include_str!("../../../../crates/scp-ffi/napi/src/server.rs");
const UNIFFI_SERVER_SRC: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/server.rs");

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================
// Raised 46 -> 49 when the `ucan_evaluate` routing assertion was extended from
// PyO3-only to the bridges, adding per-bridge routing tests.
// Raised 49 -> 50 when the production saga-journal swap added
// `prod_supervisor_construction_wires_durable_saga_journal` — pinning that every
// production seam constructs the durable `ProtocolRepositorySagaJournal` rather
// than `NoOpSagaJournal` — locking that assertion into the ratchet floor.
// Lowered 50 -> 41 when the WASM bridge was deleted (ADR-055): the 9 WASM-bridge
// structural assertions (consequence dispatch, governance trust boundary,
// C2 economy fail-closed gate, ucan_evaluate routing) lost their subject and
// were removed. This is a deleted-target cleanup, not a weakening of the
// remaining native/PyO3/NAPI/UniFFI assertions.
// Raised 41 -> 44 when the §6.2.4 cross-context outlet-invocation saga export
// (ADR-049 §3a) was wired through all three native bridges: one per-bridge
// structural assertion (PyO3 / NAPI / UniFFI) pins each export body to the
// caller-principal binding, the ADR-056 `context_id_to_bytes` keying chokepoint,
// AND the `start_cross_context_outlet_invocation_saga` producer. Pure coverage
// expansion locking the new export wiring into the ratchet floor.
// Raised 44 -> 48 when the typed `participation_record` op (§7.3.2) added four
// routing assertions: `Supervisor::participation_record` → core
// `compute_participation_record`, plus PyO3/NAPI/UniFFI bridge ops → the shared
// `Supervisor::participation_record` (Phase 2C-1).
// Raised 48 -> 52 when the ADR-049 Phase 2J joiner handshake wired the two FFI
// joiner ops through the PyO3 + NAPI bridges: per-bridge structural assertions
// pin `reserve_key_package` → `Supervisor::reserve_key_package` and
// `context_join_from_welcome` → `Supervisor::spawn_actor_from_welcome`. Pure
// coverage expansion locking the joiner-path seams into the ratchet floor.
// Raised 52 -> 55 (merge with origin/main) when the capability-admission op
// `check_capability_requirements` (§7.3.4.4, SCP-ACR-008) was wired through all
// three native bridges: one per-bridge assertion pins each export body to the
// core `scp_core::trust::check_capability_requirements` call and the instance
// DID resolver. The 2J joiner (+4) and capability-admission
// (+3) additions are disjoint, so the merged floor is 48 + 4 + 3 = 55.
// Raised 55 -> 59 when attestation verification began reading the context's
// revocation list (§7.4.4 step 5): one assertion pins the shared
// `verify_attestation_in_context` to the list read and its checker, and one per
// native bridge pins each `trust_verify_attestation` export to that helper over
// the instance's own repository.
// Raised 59 -> 67 when the challenge operations (spec 07 §7.3.4) gained their
// routing assertions: two pin the shared `create_challenge` and
// `verify_response_and_sign` to their checks and to `CommandSigner::sign_bounded_ed25519`, and one per
// native bridge pins each of `trust_create_challenge` and
// `trust_verify_response` to the shared operation.
// Raised 67 -> 88 when challenge grading moved to the challenger ledger
// (spec 07 §7.3.4): the verify assertions became grade assertions, and 21 new
// ones pin the shared respond, grade, evaluator, and check bodies, each
// supervisor challenge dispatch to the ledger mailbox, the ledger's attempt
// checks and its ban on the synchronous trust store, each bridge's respond
// export, grade repository, and evaluator invoker, the context params reading
// `capability_requirements`, and the governance leaf's direction choice.
// Raised 88 -> 89 when each bridge gained its modify-requirements proposal
// export: one assertion pins all three to the shared decode and to the
// bridge's governance propose path.
// Raised 89 -> 90 when the local member's pseudonym rotation (spec 09
// §9.10.4.1) was wired: one assertion pins the rotate command, the routing-ID
// query, and the actor's rotation arm to their helpers. (The grace arm it also
// pinned was deleted with Alec's approval when spec 09 dropped the grace.)
// Raised 90 -> 91 when non-committing members began rotating on a processed
// membership Commit (spec 09 §9.10.4.1): one assertion pins the incoming-Commit
// handler to the DID classifier, the fail-closed commit, and the rotation signal.
// Raised 91 -> 92 when the `0xFF02` extension began committing `T0` (spec 05
// §5.13.3 rule 9): one assertion pins the Welcome join, import, and restore to
// the binding check that returns the committed `T0`.
const MIN_ACTIVE_PIPELINE_ASSERTIONS: usize = 92;

// ---------------------------------------------------------------------------
// Function body extraction — brace-matching parser
// ---------------------------------------------------------------------------

/// Extracts the body of a function named `fn_name` from `source`.
///
/// Searches for `fn <fn_name>(` or `fn <fn_name><` (generic params), then
/// finds the opening `{` and does brace-matching to locate the closing `}`.
/// Returns the CODE between (and including) the braces with the contents of
/// every Rust lexical "non-code" span STRIPPED (replaced by spaces) — so a
/// `find`/`contains` on the returned body matches only real call sites, never a
/// token that merely appears inside a comment, a string, or a char literal (a
/// structural assertion that matched commented-out or stringized text would
/// silently false-pass — and would be trivially evadable by an attacker who
/// hides a decoy call in a comment or a string).
///
/// The scanner is a SOUND Rust lexer for the comment/string/char grammar — it
/// recognizes the full set of spans the language defines, not an ad-hoc subset:
///
/// - `//` line comments (to end of line),
/// - `/* … */` block comments, **nesting-aware** (Rust block comments nest),
/// - `"…"` string literals (with `\"` escapes),
/// - `r"…"`, `r#"…"#`, `r##"…"##`, … raw strings (closing matched by the exact
///   opening `#` count — a `"` inside a raw string does NOT end it),
/// - `'x'` / `'\n'` / `'\''` char literals, DISTINGUISHED from lifetimes /
///   labels (`'a`, `'static`, `'loop:`): a lifetime has no closing `'`, so a
///   `'` is only treated as a char-literal opener when a properly-formed
///   closing `'` follows within the char-literal grammar.
///
/// Brace depth is counted only over CODE spans, so a `{`/`}` inside any of the
/// above non-code spans (e.g. a `/* } */` decoy or a `'}'` char) neither opens
/// nor closes the body and cannot truncate the extracted slice. Stripped chars
/// become spaces, so byte offsets of surviving code tokens move but their
/// relative ORDER is unchanged — order-sensitive assertions ("X before Y")
/// remain valid. Delimiters (`/`, `*`, `"`, `'`, `#`, `r`) are themselves
/// emitted as code so the surrounding token structure is preserved.
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

    clean_and_extract_braced(&source[body_start..])
}

/// Brace-match + strip non-code spans over a slice that BEGINS at the body's
/// opening `{`. Returns the cleaned body (braces included) up to and including
/// the matching `}`, or `None` if the braces never balance.
///
/// Implemented as an index-based scan over the char vector so the raw-string
/// `#`-count and char-vs-lifetime decisions can look ahead. Every non-code span
/// is consumed by a dedicated `skip_*` helper that emits the right number of
/// spaces (preserving length/order) and returns the index just past the span.
fn clean_and_extract_braced(s: &str) -> Option<String> {
    clean_code(s, true)
}

/// Returns `s` with every comment, string and char literal blanked as
/// [`clean_and_extract_braced`] blanks them, over the whole of `s`.
fn strip_non_code(s: &str) -> String {
    clean_code(s, false).unwrap_or_default()
}

/// The lexer behind [`clean_and_extract_braced`] (`balanced_body`: stop at the
/// `}` that balances the leading `{`, or return `None` when none does) and
/// [`strip_non_code`] (scan all of `s`).
fn clean_code(s: &str, balanced_body: bool) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut cleaned = String::with_capacity(chars.len());
    let mut depth = 0u32;
    let mut i = 0usize;

    while i < chars.len() {
        let ch = chars[i];

        // ---- Comments -----------------------------------------------------
        if ch == '/' && chars.get(i + 1) == Some(&'/') {
            i = skip_line_comment(&chars, i, &mut cleaned);
            continue;
        }
        if ch == '/' && chars.get(i + 1) == Some(&'*') {
            i = skip_block_comment(&chars, i, &mut cleaned);
            continue;
        }

        // ---- Raw strings: r"...", r#"..."#, r##"..."##, ... ---------------
        // Recognize `r` (or `br`) followed by zero-or-more `#` then `"`.
        if (ch == 'r' || ch == 'b') && is_raw_string_start(&chars, i) {
            i = skip_raw_string(&chars, i, &mut cleaned);
            continue;
        }

        // ---- Ordinary / byte strings: "...", b"..." -----------------------
        if ch == '"' {
            i = skip_string(&chars, i, &mut cleaned);
            continue;
        }
        if ch == 'b' && chars.get(i + 1) == Some(&'"') {
            cleaned.push('b');
            i = skip_string(&chars, i + 1, &mut cleaned);
            continue;
        }

        // ---- Char literals (NOT lifetimes/labels) -------------------------
        if ch == '\'' {
            if let Some(next) = skip_char_literal(&chars, i, &mut cleaned) {
                i = next;
                continue;
            }
            // Not a char literal — a lifetime/label `'a` / `'static`. Emit the
            // `'` as code; the following identifier chars flow through normally.
            cleaned.push('\'');
            i += 1;
            continue;
        }

        // ---- Code ---------------------------------------------------------
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
        }
        cleaned.push(ch);
        if balanced_body && ch == '}' && depth == 0 {
            return Some(cleaned);
        }
        i += 1;
    }

    // A body scan whose braces never balance yields no body.
    (!balanced_body).then_some(cleaned)
}

/// Consume a `//` line comment starting at `start` (`chars[start] == '/'`,
/// `chars[start+1] == '/'`), emitting a space per char up to (but NOT
/// including) the newline. Returns the index of the newline (or EOF).
fn skip_line_comment(chars: &[char], start: usize, cleaned: &mut String) -> usize {
    let mut i = start;
    while i < chars.len() && chars[i] != '\n' {
        cleaned.push(' ');
        i += 1;
    }
    i
}

/// Consume a `/* … */` block comment starting at `start`, NESTING-AWARE (Rust
/// block comments nest, so an inner `/*` must be matched by an inner `*/`).
/// Emits a space per consumed char (newlines preserved as newlines so line
/// structure is retained). Returns the index just past the closing `*/`.
fn skip_block_comment(chars: &[char], start: usize, cleaned: &mut String) -> usize {
    let mut i = start;
    let mut nesting = 0u32;
    while i < chars.len() {
        if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            nesting += 1;
            cleaned.push(' ');
            cleaned.push(' ');
            i += 2;
        } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
            nesting -= 1;
            cleaned.push(' ');
            cleaned.push(' ');
            i += 2;
            if nesting == 0 {
                break;
            }
        } else {
            // Preserve newlines as newlines so emitted line structure matches
            // the source; blank everything else.
            cleaned.push(if chars[i] == '\n' { '\n' } else { ' ' });
            i += 1;
        }
    }
    i
}

/// Consume an ordinary string literal starting at the opening `"` (`start`).
/// Emits the opening and closing `"` as code and blanks the interior; honors
/// `\"` escapes. Returns the index just past the closing `"`.
fn skip_string(chars: &[char], start: usize, cleaned: &mut String) -> usize {
    cleaned.push('"'); // opening delimiter (code)
    let mut i = start + 1;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' {
            // Escape: blank both the backslash and the escaped char.
            cleaned.push(' ');
            if i + 1 < chars.len() {
                cleaned.push(' ');
            }
            i += 2;
            continue;
        }
        if ch == '"' {
            cleaned.push('"'); // closing delimiter (code)
            return i + 1;
        }
        cleaned.push(if ch == '\n' { '\n' } else { ' ' });
        i += 1;
    }
    i
}

/// Returns `true` if a raw-string literal opens at `start` — i.e. `chars[start]`
/// is `r` (or `br`, with the `b` at `start`) followed by zero-or-more `#` and
/// then a `"`. (`br` shares the raw-string close rule; `b` alone is handled as a
/// byte string elsewhere.)
fn is_raw_string_start(chars: &[char], start: usize) -> bool {
    let mut i = start;
    if chars.get(i) == Some(&'b') {
        i += 1;
    }
    if chars.get(i) != Some(&'r') {
        return false;
    }
    i += 1;
    while chars.get(i) == Some(&'#') {
        i += 1;
    }
    chars.get(i) == Some(&'"')
}

/// Consume a raw string starting at `start` (`r"..."`, `r#"..."#`, `br##"..."##`,
/// …). The closing is `"` followed by EXACTLY the opening `#` count, so an inner
/// `"` (even `"#` with too few hashes) does NOT terminate it. Emits the `r`/`b`,
/// the `#` fences, and the `"` delimiters as code; blanks the interior. Returns
/// the index just past the close.
fn skip_raw_string(chars: &[char], start: usize, cleaned: &mut String) -> usize {
    let mut i = start;
    if chars.get(i) == Some(&'b') {
        cleaned.push('b');
        i += 1;
    }
    // `r`
    cleaned.push('r');
    i += 1;
    // opening hashes
    let mut hashes = 0usize;
    while chars.get(i) == Some(&'#') {
        cleaned.push('#');
        hashes += 1;
        i += 1;
    }
    // opening quote
    cleaned.push('"');
    i += 1;
    // interior until `"` + `hashes` `#`
    while i < chars.len() {
        if chars[i] == '"' && raw_close_matches(chars, i + 1, hashes) {
            cleaned.push('"');
            for _ in 0..hashes {
                cleaned.push('#');
            }
            return i + 1 + hashes;
        }
        cleaned.push(if chars[i] == '\n' { '\n' } else { ' ' });
        i += 1;
    }
    i
}

/// Returns `true` if `chars[at..]` begins with exactly `hashes` `#` characters
/// (the raw-string close fence).
fn raw_close_matches(chars: &[char], at: usize, hashes: usize) -> bool {
    (0..hashes).all(|k| chars.get(at + k) == Some(&'#'))
}

/// Attempt to consume a CHAR literal starting at the `'` at `start`. Returns
/// `Some(index_past_close)` if `start` opens a well-formed char literal
/// (`'x'`, `'\n'`, `'\''`, `'\u{1F600}'`), or `None` if the `'` is a lifetime /
/// label introducer (`'a`, `'static`, `'loop:`) — which has NO closing `'`.
///
/// Discrimination rule (matches Rust lexing): a `'` opens a char literal iff it
/// is followed by either
///   (a) a backslash escape `'\...'` closed by `'`, or
///   (b) exactly ONE non-`'`, non-`\` char then a closing `'`.
/// A `'` followed by an identifier-start char and then NOT a closing `'` is a
/// lifetime (e.g. `'a,` or `'static>`), so we return `None`.
fn skip_char_literal(chars: &[char], start: usize, cleaned: &mut String) -> Option<usize> {
    // start == '\''
    match chars.get(start + 1) {
        Some('\\') => {
            // Escaped char literal: '\n', '\'', '\\', '\u{..}', '\x41', ...
            // Scan to the closing `'` (the next unescaped `'`).
            let mut i = start + 2;
            // Consume the escape payload up to the closing quote. A `\u{...}`
            // contains `{`/`}`/hex; none of it is code, so just scan to `'`.
            while i < chars.len() {
                if chars[i] == '\'' {
                    // Emit the whole literal as spaces (length-preserving), with
                    // the opening + closing `'` kept as code delimiters.
                    cleaned.push('\'');
                    for _ in (start + 1)..i {
                        cleaned.push(' ');
                    }
                    cleaned.push('\'');
                    return Some(i + 1);
                }
                i += 1;
            }
            None // unterminated — treat the `'` as non-char (caller emits it)
        }
        Some(&c) if c != '\'' => {
            // Single-char body iff a closing `'` immediately follows.
            if chars.get(start + 2) == Some(&'\'') {
                cleaned.push('\''); // opening delimiter
                cleaned.push(' '); // blanked body char
                cleaned.push('\''); // closing delimiter
                Some(start + 3)
            } else {
                // No closing quote after one char ⇒ lifetime/label (`'a`, `'static`).
                None
            }
        }
        // `''` (empty) or EOF ⇒ not a valid single-char literal; let caller
        // emit the `'` as code.
        _ => None,
    }
}

/// The cleaned body of the one `fn <fn_name>(` declared directly inside the
/// `impl <type_name> {` blocks of `source`, comments and literals blanked as
/// [`strip_non_code`] blanks them.
///
/// Panics when no such block declares the function or more than one does, so
/// a moved, renamed or duplicated method fails the caller's check instead of
/// letting it read a trait default or another type's method of the same name.
fn inherent_method_body(source: &str, type_name: &str, fn_name: &str) -> String {
    let code = strip_non_code(source);
    let header = format!("impl {type_name} {{");
    let mut bodies = Vec::new();
    let mut from = 0;
    while let Some(offset) = code[from..].find(&header) {
        let open = from + offset + header.len() - 1;
        let block = clean_and_extract_braced(&code[open..])
            .unwrap_or_else(|| panic!("an `impl {type_name} {{` block never closes"));
        from = open + block.len();
        if let Some(body) = extract_fn_body(&block, fn_name) {
            bodies.push(body);
        }
    }
    assert_eq!(
        bodies.len(),
        1,
        "expected exactly one `fn {fn_name}(` across the `impl {type_name} {{` blocks"
    );
    bodies.remove(0)
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
// `extract_fn_body` parser hardening — evasion-defeat unit tests
// ===========================================================================
//
// These pin the lexer's handling of every Rust non-code span so a future
// refactor of `extract_fn_body` cannot silently reintroduce a hole an attacker
// could use to smuggle a decoy call (which would make an order/presence gate
// false-pass). Each test is modeled on a concrete proven evasion: a block-comment
// decoy call, a block-comment `}` brace-truncation, a char-literal `'}'` desync,
// and a raw-string decoy call.

/// A real call hidden inside a `//` line comment must NOT appear in the cleaned
/// body (the original guarantee — kept as a regression pin).
#[test]
fn parser_line_comment_decoy_excluded() {
    let src = "fn f() {\n    // real_call();\n    let x = 1;\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    assert!(
        !body.contains("real_call"),
        "a `// real_call()` line-comment decoy must be stripped, got: {body:?}"
    );
    assert!(body.contains("let x"), "real code must survive: {body:?}");
}

/// A real call hidden inside a `/* … */` BLOCK comment must NOT appear in the
/// cleaned body. This is the CRITICAL evasion: a `/* restore_all_contexts() */`
/// decoy placed before the real `replay()` call previously false-passed an
/// order gate because the old parser did not strip block comments.
#[test]
fn parser_block_comment_decoy_excluded() {
    let src = "fn f() {\n    /* real_call(); */\n    other();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    assert!(
        !body.contains("real_call"),
        "a `/* real_call() */` block-comment decoy must be stripped, got: {body:?}"
    );
    assert!(body.contains("other"), "real code must survive: {body:?}");
}

/// A `/* } */` brace inside a block comment must NOT close the body early — the
/// HIGH evasion: brace-injection in a comment previously TRUNCATED the extracted
/// body, hiding everything after it from a `contains` gate.
#[test]
fn parser_block_comment_brace_does_not_truncate() {
    let src = "fn f() {\n    /* } */\n    tail_call();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts (not truncated)");
    assert!(
        body.contains("tail_call"),
        "a `/* }} */` comment brace must NOT truncate the body — code after it must \
         survive, got: {body:?}"
    );
}

/// NESTED block comments: Rust block comments nest, so an inner `/*` needs an
/// inner `*/`. A single `*/` must not close a doubly-opened comment early and
/// expose a decoy.
#[test]
fn parser_nested_block_comment_excluded() {
    let src = "fn f() {\n    /* outer /* inner */ real_call(); */\n    tail();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    assert!(
        !body.contains("real_call"),
        "a decoy after a NESTED `*/` is still inside the outer comment and must be \
         stripped, got: {body:?}"
    );
    assert!(body.contains("tail"), "real code must survive: {body:?}");
}

/// A `'}'` CHAR literal must NOT desync brace depth (its `}` is not a real
/// closing brace) and must not truncate the body.
#[test]
fn parser_char_literal_brace_does_not_desync() {
    let src = "fn f() {\n    let c = '}';\n    tail_call();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts (char brace ignored)");
    assert!(
        body.contains("tail_call"),
        "a `'}}'` char literal must NOT close the body — code after it must survive, \
         got: {body:?}"
    );
}

/// A real call hidden inside a `'{'`-style char or a quote char must not break
/// scanning; an escaped-quote char `'\''` must be consumed whole.
#[test]
fn parser_escaped_quote_char_literal_consumed() {
    let src = "fn f() {\n    let q = '\\'';\n    tail_call();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    assert!(
        body.contains("tail_call"),
        "an escaped-quote char `'\\''` must be consumed as one literal, code after must \
         survive, got: {body:?}"
    );
}

/// A LIFETIME (`'a`) must NOT be mistaken for an unterminated char literal — the
/// scanner must keep going and still see real code.
#[test]
fn parser_lifetime_not_treated_as_char() {
    let src = "fn f() {\n    let r: &'static str = pick();\n    tail_call();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    assert!(
        body.contains("pick") && body.contains("tail_call"),
        "a `'static` lifetime must not swallow following code, got: {body:?}"
    );
}

/// A real call hidden inside a RAW STRING (`r#"call()"#`) must NOT appear in the
/// cleaned body — a `"` inside the raw string does not end it, and the decoy is
/// interior.
#[test]
fn parser_raw_string_decoy_excluded() {
    let src = "fn f() {\n    let s = r#\"real_call() and a \\\" quote\"#;\n    other();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    assert!(
        !body.contains("real_call"),
        "a `r#\"real_call()\"#` raw-string decoy must be stripped, got: {body:?}"
    );
    assert!(body.contains("other"), "real code must survive: {body:?}");
}

/// A raw string carrying a `}` (`r"}"`)  must NOT truncate the body.
#[test]
fn parser_raw_string_brace_does_not_truncate() {
    let src = "fn f() {\n    let s = r\"}\";\n    tail_call();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts (raw-string brace ignored)");
    assert!(
        body.contains("tail_call"),
        "a `r\"}}\"` raw-string brace must NOT truncate the body, got: {body:?}"
    );
}

/// An ordinary string carrying a decoy call + a `}` must be stripped and must
/// not truncate (the original string guarantee — kept as a regression pin).
#[test]
fn parser_string_decoy_and_brace_handled() {
    let src = "fn f() {\n    let s = \"real_call() }\";\n    tail_call();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    assert!(
        !body.contains("real_call"),
        "a string decoy must be stripped, got: {body:?}"
    );
    assert!(
        body.contains("tail_call"),
        "a string `}}` must not truncate the body, got: {body:?}"
    );
}

/// Order preservation: a real `a()` before a real `b()` must keep `a` before `b`
/// in the cleaned body even when comments/strings sit between them (blanked to
/// spaces, not removed, so offsets shift but order holds).
#[test]
fn parser_preserves_call_order_through_noncode() {
    let src = "fn f() {\n    a(); /* x */ \"y\"; r#\"z\"#; b();\n}";
    let body = extract_fn_body(src, "f").expect("body extracts");
    let pa = body.find("a()").expect("a present");
    let pb = body.find("b()").expect("b present");
    assert!(
        pa < pb,
        "call order must be preserved: a@{pa} before b@{pb}"
    );
}

// ===========================================================================
// Baseline assertions — currently wired, must pass today
// ===========================================================================

// Manager level: send_message path calls crypto.seal (full envelope pipeline).
// ADR-049 PR-7: the seal is invoked from the `build_encrypted_envelope_actor`
// helper (which calls `crypto_state.seal(...)` on the actor-owned
// `ContextCryptoState`), reached from `send_message`. Repointed from the deleted
// `build_encrypted_envelope` provider-twin to its actor successor.
#[test]
fn send_message_calls_seal() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", ".seal(")
            || fn_body_contains(MANAGER_SRC, "build_encrypted_envelope_actor", ".seal("),
        "send_message path must call crypto.seal (envelope pipeline)"
    );
}

// §7.3.8 value-caveat runtime enforcement: the reserve phase of the outlet
// economy pipeline MUST run the synchronous local caveat check
// (`check_invocation_local`), consume the counter-bearing caps
// (`consume_caveat_counters`, which calls `try_consume` on the owned Class-S
// record), and do so through a fail-closed `commit_class_s_keep`-family
// combinator so a consumed cap can never un-consume across a crash. This is
// the wiring-coverage assertion for the caveat gate (adds coverage; it does
// not weaken any existing check).
#[test]
fn reserve_outlet_economy_enforces_value_caveats() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "reserve_outlet_economy",
            "check_invocation_local"
        ),
        "reserve_outlet_economy must run the §7.3.8 synchronous local caveat \
         check (check_invocation_local) before consuming counter capacity"
    );
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "reserve_outlet_economy",
            "consume_caveat_counters"
        ),
        "reserve_outlet_economy must consume the counter-bearing §7.3.8 caveats \
         (consume_caveat_counters)"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "consume_caveat_counters", "try_consume"),
        "consume_caveat_counters must call CaveatCounters::try_consume"
    );
    // The counter consume rides a fail-closed KEEP combinator on BOTH the paid
    // path (folded into commit_class_s_keep_compensating) and the free path
    // (dedicated commit_class_s_keep) — a consumed cap must survive a persist
    // failure rather than un-consume (ADR-049 §9).
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_outlet_economy", "commit_class_s_keep"),
        "reserve_outlet_economy must consume caveat counters through a \
         commit_class_s_keep-family combinator (KEEP on persist failure)"
    );
}

// #2196 — the fail-closed ContextState::Active gate must be wired as the FIRST
// predicate on every forward-debit outlet reserve path (same-context unary,
// stream open, and mid-stream grant top-up), and the gate itself must read the
// authoritative sync handle state. Asserts the REAL `ensure_context_active`
// call in each reserve (not a dead `let _ =`) plus the `.state()` read inside
// the gate, so a Closing / Expired / MigratingOut context can never take on new
// spend. (`MANAGER_SRC` embeds `outlets_helpers.rs`.)
#[test]
fn outlet_reserves_gate_on_context_active_state() {
    for reserve in [
        "reserve_outlet_economy",
        "reserve_outlet_stream_economy",
        "reserve_stream_grant_escrow",
    ] {
        assert!(
            fn_body_contains(MANAGER_SRC, reserve, "ensure_context_active"),
            "{reserve} must call ensure_context_active as its fail-closed #2196 \
             context-lifecycle gate before any escrow / budget debit"
        );
    }
    assert!(
        fn_body_contains(MANAGER_SRC, "ensure_context_active", ".state()"),
        "ensure_context_active must read the authoritative sync handle .state() \
         (the ArcSwap load), not a lagging cache"
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

// Gated broadcast subscribe (spec §5.14.4): the actor `handle_subscribe_broadcast`
// turn MUST build a real UCAN `ValidationContext` from actor-owned state (the
// production DID/revocation adapters) and pass it (`Some(&mut validation_ctx)`)
// into `broadcast_helpers::subscribe_broadcast`, which threads it into the
// protocol's `bc.subscribe(...)` gated arm so `validate_messages_read_ucan` runs
// the full pipeline on the presented token (spec §07:70). Before this wiring the
// handler passed `None`, so the protocol rejected every gated subscribe on the
// missing-UCAN check BEFORE any validation — the capability was unreachable.
// These assertions pin the real-`ValidationContext` construction + threading so
// a refactor cannot silently regress to the unvalidated `None` path.
#[test]
fn gated_broadcast_subscribe_builds_real_validation_context() {
    assert!(
        fn_body_contains(
            HANDLERS_BROADCAST_SRC,
            "handle_subscribe_broadcast",
            "ValidationContext {"
        ),
        "handle_subscribe_broadcast must construct a real ValidationContext for \
         the gated messages:read UCAN (spec §5.14.4), not pass None"
    );
    assert!(
        fn_body_contains(
            HANDLERS_BROADCAST_SRC,
            "handle_subscribe_broadcast",
            "Some(&mut validation_ctx)"
        ),
        "handle_subscribe_broadcast must pass Some(&mut validation_ctx) into \
         subscribe_broadcast so the gated arm can verify the UCAN — passing None \
         makes gated subscribe unreachable"
    );
    assert!(
        fn_body_contains(
            HANDLERS_BROADCAST_SRC,
            "handle_subscribe_broadcast",
            "KeyResolverDidResolver::new("
        ),
        "handle_subscribe_broadcast must wire the production VM-aware DID→key \
         resolver into the ValidationContext (same adapter as the saga UCAN \
         re-validation path), not a no-op resolver"
    );
    // The helper must THREAD the validation context through to the protocol's
    // gated `bc.subscribe(...)` arm (MANAGER_SRC concatenates broadcast_helpers).
    assert!(
        fn_body_contains(MANAGER_SRC, "subscribe_broadcast", "validation_ctx"),
        "broadcast_helpers::subscribe_broadcast must thread validation_ctx into \
         bc.subscribe so the protocol gated arm reaches validate_messages_read_ucan"
    );
    // Durable governance-ban admission gate (#2088): subscribe_broadcast MUST
    // consult the AUTHORITATIVE durable `banned_subscribers` record via
    // `is_banned`, so a banned DID cannot launder the ban by self-leaving (which
    // clears `read_exclusion_list`) and replaying a retained grant. This is the
    // primary fix; pin it so a refactor cannot silently drop the gate.
    assert!(
        fn_body_contains(MANAGER_SRC, "subscribe_broadcast", "is_banned("),
        "broadcast_helpers::subscribe_broadcast must consult the durable ban record \
         via bc.is_banned(...) at admission (fail-closed)"
    );
    // Defense-in-depth: RETAIN the `read_exclusion_list` consult (the SAME set the
    // serve path checks) for a still-present read-revoked member.
    assert!(
        fn_body_contains(MANAGER_SRC, "subscribe_broadcast", "read_exclusion_list"),
        "broadcast_helpers::subscribe_broadcast must retain the read_exclusion_list \
         consult as defense-in-depth"
    );
    // BLACK-303: the SECOND broadcast-read grant surface — the key-request SERVE
    // path — must ALSO consult the durable ban, else a banned author (the creator
    // is always an author) launders the ban by requesting a broadcast key after
    // self-leaving. Pin `is_banned` in `handle_broadcast_key_request` so the two
    // read-grant surfaces (subscribe + serve) stay symmetric and no fourth surface
    // opens.
    assert!(
        fn_body_contains(MANAGER_SRC, "handle_broadcast_key_request", "is_banned("),
        "broadcast_helpers::handle_broadcast_key_request must consult the durable ban \
         record via bc.is_banned(...) before granting a broadcast key (BLACK-303)"
    );
}

// PUSH-025 (§5.12.3.1 `relay_urls`, §9.18.2): every path that writes a
// context's relay set stores it through `normalize_relay_urls`, which maps each
// URL to its canonical relay URL when it has one. Create, import and restore
// call it in `lifecycle_helpers`; a Welcome joiner calls it in
// `Supervisor::build_welcome_joiner_state`, after bundle verification.
const LIFECYCLE_HELPERS_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/context/lifecycle_helpers.rs");

#[test]
fn relay_set_writes_store_canonical_relay_urls() {
    assert!(
        fn_body_contains(
            LIFECYCLE_HELPERS_SRC,
            "normalize_relay_urls",
            "canonical_relay_url("
        ),
        "normalize_relay_urls must map each relay URL through canonical_relay_url"
    );
    for entry in ["create_context", "import_context", "restore_context"] {
        assert!(
            fn_body_contains(LIFECYCLE_HELPERS_SRC, entry, "normalize_relay_urls("),
            "lifecycle_helpers::{entry} must store its relay set through normalize_relay_urls"
        );
    }
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "build_welcome_joiner_state",
            "normalize_relay_urls("
        ),
        "Supervisor::build_welcome_joiner_state must store the bundle's relay set through \
         normalize_relay_urls"
    );
}

// PUSH-007 (§10.7.1 step 2): the NAT-tier task writes the relay's live URL
// handle, so every relay listener reserves the push routing ID of the URL the
// node advertises after a tier change. `build_no_domain_inner` binds the node's
// publisher to the live URL handle of the relay config it runs its relay with
// (`NodePublisher::new` takes the `RelayConfig` and clones its handle), hands
// that publisher to the tier task, the task calls `apply_tier_change` with it,
// and `apply_tier_change` has the publisher set its handle before it publishes
// the document.
#[test]
fn nat_tier_task_writes_the_relay_push_url_handle() {
    // The tier task holds the relay config's handle through the publisher the
    // builder hands it.
    let compact = compact_body(NODE_BUILDER_SRC, "build_no_domain_inner");
    let tier_task_args = call_args(&compact, "spawn_tier_reevaluation")
        .expect("build_no_domain_inner must spawn the tier task");
    assert_eq!(
        top_level_args(tier_task_args).get(2).map(String::as_str),
        Some("publisher"),
        "build_no_domain_inner must give the tier task the publisher it bound to the relay \
         config's live URL handle, got arguments {tier_task_args}"
    );
    // The publisher carries the relay handle, so binding it to the relay
    // config is what sets the probed tier's URL on that config's handle.
    assert_eq!(
        call_args(&compact, "NodePublisher::new").map(|args| args.trim_end_matches(',')),
        Some("Arc::clone(&did_method),dht_mode,&relay_config"),
        "build_no_domain_inner must set the probed tier's URL on the relay handle by binding \
         its publisher to the relay config it runs its relay with"
    );
    for (source, name) in [
        (NODE_BUILDER_SRC, "spawn_tier_reevaluation"),
        (NODE_PUBLISHED_STATE_SRC, "apply_tier_change"),
    ] {
        let signature =
            extract_fn_signature(source, name).unwrap_or_else(|| panic!("{name} signature"));
        assert!(
            !signature.contains("LiveRelayUrl"),
            "the tier task must reach apply_tier_change with no relay handle but its \
             publisher's; {name} takes one: {signature}"
        );
    }
    let body = extract_fn_body(NODE_PUBLISHED_STATE_SRC, "apply_tier_change")
        .expect("apply_tier_change body");
    let set = body
        .find("publisher.reserve_push_routing_id(")
        .expect("apply_tier_change must set the relay's live URL handle");
    assert!(
        fn_body_contains(
            NODE_PUBLISHED_STATE_SRC,
            "reserve_push_routing_id",
            "relay.set(url)"
        ),
        "reserve_push_routing_id must set the relay's live URL handle"
    );
    let publish = body
        .find(".publish(")
        .expect("apply_tier_change must publish the document");
    assert!(
        set < publish,
        "apply_tier_change must move the relay handle before it publishes the new URL"
    );
    // PUSH-032 (§10.7.1 "Tier 3 relays"): the node reserves the routing ID of
    // the entry it publishes at startup before it publishes.
    let startup = extract_fn_body(NODE_BUILDER_SRC, "build_no_domain_inner")
        .expect("build_no_domain_inner body");
    // The builder binds the publisher before the startup publish, and
    // `seed_from_startup_publish` reserves on that publisher, then bootstraps
    // the publish-sequence counter, then publishes.
    let reserve = startup
        .find("NodePublisher::new(")
        .expect("build_no_domain_inner must bind the publisher its startup publish reserves on");
    let seed = startup
        .find("seed_from_startup_publish(")
        .expect("build_no_domain_inner must publish through seed_from_startup_publish");
    assert!(
        reserve < seed,
        "build_no_domain_inner must bind its publisher with NodePublisher::new before it calls \
         seed_from_startup_publish, which reserves on that publisher"
    );
    let seed_body = extract_fn_body(NODE_PUBLISHED_STATE_SRC, "seed_from_startup_publish")
        .expect("seed_from_startup_publish body");
    let seed_reserve = seed_body
        .find("reserve_push_routing_id(")
        .expect("seed_from_startup_publish must reserve the startup entry's routing ID");
    let seed_initialize = seed_body
        .find(".initialize_sequence(")
        .expect("seed_from_startup_publish must bootstrap the publish-sequence counter");
    let seed_publish = seed_body
        .find(".publish(")
        .expect("seed_from_startup_publish must publish the document");
    assert!(
        seed_reserve < seed_publish,
        "seed_from_startup_publish must reserve the startup entry's routing ID before it publishes"
    );
    assert!(
        seed_reserve < seed_initialize && seed_initialize < seed_publish,
        "seed_from_startup_publish must reserve, then bootstrap the sequence counter, then publish"
    );
    for builder in ["build_domain_inner", "build_no_domain_inner"] {
        assert!(
            !fn_body_contains(NODE_BUILDER_SRC, builder, "initialize_sequence"),
            "{builder} must leave the sequence bootstrap to seed_from_startup_publish, which runs \
             it after the reservation"
        );
    }
    // PUSH-032 (§10.7.1 "Tier 3 relays"): both callers reserve the node's own
    // entry and every tier 3 entry of the document they publish that carries
    // the node's `bridgeTarget`, built from that document before the
    // reservation, which `seed_from_startup_publish` makes.
    let startup_entries = startup
        .find("PublishedEntries::new(&relay_url, &document, bridge_target)")
        .expect("build_no_domain_inner must reserve every entry of the document it publishes");
    assert!(
        startup_entries < seed,
        "build_no_domain_inner must build the reserved entries before it reserves them"
    );
    let tier_entries = body
        .find("PublishedEntries::new(new_relay_url, &next_document, bridge_target)")
        .expect("apply_tier_change must reserve every entry of the document it publishes");
    assert!(
        tier_entries < set,
        "apply_tier_change must build the reserved entries before it reserves them"
    );
}

// §10.7.1 "Tier 3 relays": every publish of the node's DID document goes
// through a reservation of every entry of that document the node publishes.
// The domain builder reserves before its startup publish, like the no-domain
// builder, and the one `PublishAuthorization` constructor is
// `ReservedDocument::authorize`, whose value only
// `NodePublisher::reserve_push_routing_id` builds.
#[test]
fn every_node_document_publish_reserves_the_published_entries() {
    let domain =
        extract_fn_body(NODE_BUILDER_SRC, "build_domain_inner").expect("build_domain_inner body");
    // The publisher carries the relay handle it reserves on, so the domain
    // builder reserves on the relay config's handle by binding its publisher
    // to that config, and `seed_from_startup_publish` reserves the entries it
    // is given.
    let compact = compact_body(NODE_BUILDER_SRC, "build_domain_inner");
    assert_eq!(
        call_args(&compact, "NodePublisher::new").map(|args| args.trim_end_matches(',')),
        Some("Arc::clone(&did_method),dht_mode,&relay_config"),
        "build_domain_inner must reserve the entries of the document it publishes on the live \
         URL handle of the relay config it runs its relay with"
    );
    let domain_reserve = domain
        .find("NodePublisher::new(")
        .expect("build_domain_inner must bind the publisher its startup publish reserves on");
    let domain_entries = domain
        .find("PublishedEntries::new(&relay, &document, bridge_target)")
        .expect("build_domain_inner must reserve every entry of the document it publishes");
    let domain_seed = domain
        .find("seed_from_startup_publish(&publisher, &identity, &entries)")
        .expect("build_domain_inner must publish the reserved document");
    assert!(
        domain_entries < domain_seed && domain_reserve < domain_seed,
        "build_domain_inner must build the document's entries and bind its publisher before \
         the startup publish reserves and publishes them"
    );
    // Every publish of the node's document needs a `PublishAuthorization`,
    // and the one constructor sits in `ReservedDocument::authorize`, whose
    // value only `reserve_push_routing_id` builds.
    assert_eq!(
        NODE_PUBLISHED_STATE_SRC
            .matches("struct PublishAuthorization(());")
            .count(),
        1,
        "PublishAuthorization must have exactly one definition"
    );
    assert_eq!(
        NODE_PUBLISHED_STATE_SRC
            .matches("PublishAuthorization(())")
            .count(),
        2,
        "PublishAuthorization must have its definition and exactly one constructor"
    );
    assert!(
        fn_body_contains(
            NODE_PUBLISHED_STATE_SRC,
            "authorize",
            "PublishAuthorization(())"
        ),
        "the one PublishAuthorization constructor must be ReservedDocument::authorize"
    );
}

// §10.7.1 "Tier 3 relays": "its relay reserves every one of those IDs before
// the node publishes the entries". The node's `NodePublisher` holds the live
// URL handle of the node's own relay, and only a method on the publisher that
// moves that handle builds a `ReservedDocument`, so no caller can reserve on a
// handle it minted with the public `LiveRelayUrl::new`. Each builder binds its
// publisher to `relay_config.relay_url`, the handle its relay listeners read.
#[test]
fn reserved_document_is_minted_only_by_the_publisher_on_its_own_handle() {
    // A1: the reservation is a method on the publisher and takes no handle.
    let reserve_sig = extract_fn_signature(NODE_PUBLISHED_STATE_SRC, "reserve_push_routing_id")
        .expect("reserve_push_routing_id signature");
    assert!(
        reserve_sig.contains("&self"),
        "reserve_push_routing_id must be a method on NodePublisher, got: {reserve_sig}"
    );
    assert!(
        !reserve_sig.contains("LiveRelayUrl"),
        "reserve_push_routing_id must take no relay handle, got: {reserve_sig}"
    );

    // A2: no publish path takes a handle, and the startup publish takes no
    // reservation made outside it.
    for (src, name) in [
        (NODE_PUBLISHED_STATE_SRC, "seed_from_startup_publish"),
        (NODE_PUBLISHED_STATE_SRC, "apply_tier_change"),
        (NODE_BUILDER_SRC, "spawn_tier_reevaluation"),
    ] {
        let sig = extract_fn_signature(src, name).unwrap_or_else(|| panic!("{name} signature"));
        assert!(
            !sig.contains("LiveRelayUrl"),
            "{name} must take no relay handle; the publisher carries it, got: {sig}"
        );
    }
    let seed_sig = extract_fn_signature(NODE_PUBLISHED_STATE_SRC, "seed_from_startup_publish")
        .expect("seed_from_startup_publish signature");
    assert!(
        !seed_sig.contains("ReservedDocument"),
        "seed_from_startup_publish must reserve inside itself, not take a reservation, \
         got: {seed_sig}"
    );

    // A3: the reservation moves the publisher's own handle, and the module
    // mints no handle of its own.
    assert!(
        fn_body_contains(
            NODE_PUBLISHED_STATE_SRC,
            "reserve_push_routing_id",
            "self.relay.set("
        ),
        "reserve_push_routing_id must move the publisher's own relay handle"
    );
    let published_state_code = strip_non_code(NODE_PUBLISHED_STATE_SRC);
    assert!(
        !published_state_code.contains("LiveRelayUrl::new"),
        "published_state must not mint a relay handle; the builder binds the relay's own"
    );

    // A4: `ReservedDocument` is defined in the `mint` module, whose private
    // fields keep every other module from writing a literal, and the one
    // literal in `mint`, spelled `ReservedDocument` or `Self`, is inside the
    // method.
    let compact_code: String = published_state_code.split_whitespace().collect();
    let mint_at = compact_code
        .find("modmint{")
        .expect("published_state must keep ReservedDocument in a `mint` module");
    let mint = clean_and_extract_braced(&compact_code[mint_at + "modmint".len()..])
        .expect("the mint module's braces balance");
    assert!(
        mint.contains("pubstructReservedDocument{own:RelayService,document:DidDocument,}"),
        "ReservedDocument and its private fields must be defined in the mint module"
    );
    // A type name directly before `{` is a literal unless it names the item a
    // `struct` or `impl` defines or a function's return type.
    let literals = ["ReservedDocument{", "Self{"]
        .iter()
        .flat_map(|needle| mint.match_indices(needle))
        .filter(|(at, _)| {
            let before = &mint[..*at];
            !(before.ends_with("struct") || before.ends_with("impl") || before.ends_with("->"))
        })
        .count();
    assert_eq!(
        literals, 1,
        "ReservedDocument must have exactly one struct literal, in the mint module"
    );
    assert!(
        fn_body_contains(
            NODE_PUBLISHED_STATE_SRC,
            "reserve_push_routing_id",
            "ReservedDocument {"
        ),
        "the one ReservedDocument literal must be in reserve_push_routing_id"
    );

    // A5: each builder binds its publisher to the relay's own handle.
    for builder in ["build_domain_inner", "build_no_domain_inner"] {
        let body =
            extract_fn_body(NODE_BUILDER_SRC, builder).unwrap_or_else(|| panic!("{builder} body"));
        assert_eq!(
            body.matches("NodePublisher::new(").count(),
            1,
            "{builder} must build exactly one publisher"
        );
        let compact = compact_body(NODE_BUILDER_SRC, builder);
        let args = call_args(&compact, "NodePublisher::new")
            .unwrap_or_else(|| panic!("{builder} must build a NodePublisher"));
        assert_eq!(
            top_level_args(args).get(2).map(String::as_str),
            Some("&relay_config"),
            "{builder} must bind its publisher to the relay config it runs its relay with, \
             got arguments {args}"
        );
    }
}

/// The top-level arguments of a call's compact argument text, in order: a
/// comma inside parentheses, braces or brackets does not split.
fn top_level_args(args: &str) -> Vec<String> {
    let mut depth = 0i32;
    let mut positional = vec![String::new()];
    for ch in args.chars() {
        match ch {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                positional.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = positional.last_mut() {
            last.push(ch);
        }
    }
    positional
}

// PUSH-013 (§10.7.1): the push routing-ID query runs
// `Supervisor::push_routing_ids` → `dispatch_push_command` → actor mailbox →
// `handlers::push::dispatch` → `push_helpers::push_routes`.
#[test]
fn push_routing_ids_reach_push_helpers_through_the_actor_mailbox() {
    assert!(
        fn_body_contains(SUPERVISOR_SRC, "push_routing_ids", "dispatch_push_command("),
        "Supervisor::push_routing_ids must ask each actor through dispatch_push_command"
    );
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "push_routing_ids",
            "self.known_context_ids()"
        ),
        "Supervisor::push_routing_ids must enumerate known_context_ids, so a context whose actor is down fails the query"
    );
    assert!(
        fn_body_contains(SUPERVISOR_SRC, "push_routing_ids", "canonical_relay_url("),
        "Supervisor::push_routing_ids must group by the canonical relay URL"
    );
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "dispatch_push_command",
            "dispatch_via_mailbox(&actor, ContextCommand::Push(cmd))"
        ),
        "dispatch_push_command must send ContextCommand::Push through the actor mailbox"
    );
    assert!(
        fn_body_contains(ACTOR_MOD_SRC, "dispatch_state", "handlers::push::dispatch("),
        "the actor's dispatch_state must route ContextCommand::Push to handlers::push::dispatch"
    );
    assert!(
        fn_body_contains(
            HANDLERS_PUSH_SRC,
            "dispatch",
            "push_helpers::push_routes(state)"
        ),
        "handlers::push::dispatch must answer PushCommand::Routes from push_helpers::push_routes"
    );
}

// Spec 17 §17.3 "Event log write failures": a writer outside a context's actor
// (the streaming close sink, the cross-context bridge, the streaming saga's
// seal task and both of its recovery paths) queues its leaves as a pending log
// unit through `Supervisor::send_log_unit` → `dispatch_log_unit_command` →
// actor mailbox → `handlers::log_unit::dispatch`, which enqueues them in a
// persisted commit.
#[test]
fn log_unit_writers_reach_the_pending_queue_through_the_actor_mailbox() {
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "send_log_unit",
            "dispatch_log_unit_command("
        ),
        "Supervisor::send_log_unit must send through dispatch_log_unit_command"
    );
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "dispatch_log_unit_command",
            "dispatch_via_mailbox(&actor, ContextCommand::LogUnit(cmd))"
        ),
        "dispatch_log_unit_command must send ContextCommand::LogUnit through the actor mailbox"
    );
    assert!(
        fn_body_contains(
            ACTOR_MOD_SRC,
            "dispatch_state",
            "handlers::log_unit::dispatch("
        ),
        "the actor's dispatch_state must route ContextCommand::LogUnit to handlers::log_unit::dispatch"
    );
    assert!(
        fn_body_contains(
            HANDLERS_LOG_UNIT_SRC,
            "enqueue",
            "enqueue_counted_log_unit("
        ) && fn_body_contains(HANDLERS_LOG_UNIT_SRC, "dispatch", "enqueue(cell, deps"),
        "handlers::log_unit::dispatch must enqueue the leaves as a pending log unit"
    );
    assert!(
        fn_body_contains(HANDLERS_LOG_UNIT_SRC, "enqueue", "commit_class_s_restore("),
        "handlers::log_unit::dispatch must enqueue inside a persisted Class-S commit"
    );
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "enqueue_streaming_outlet_invoked_unit",
            "self.send_log_unit("
        ),
        "the streaming close record must be queued through send_log_unit"
    );
    for writer in ["send_streaming_saga_a_unit", "send_cross_context_a_unit"] {
        assert!(
            fn_body_contains(OUTLETS_INVOKE_SRC, writer, ".send_log_unit("),
            "{writer} must queue its leaf through send_log_unit"
        );
    }
    assert!(
        fn_body_contains(
            OUTLETS_INVOKE_SRC,
            "run_streaming_saga_seal_task",
            "send_streaming_saga_a_unit("
        ),
        "run_streaming_saga_seal_task must queue the A-side leaf through send_streaming_saga_a_unit"
    );
    for caller in [
        "recover_streaming_saga_truncated_close",
        "recover_streaming_committing_entry",
        "complete_unsettled_streaming_saga",
    ] {
        assert!(
            fn_body_contains(SUPERVISOR_SRC, caller, "send_streaming_saga_a_unit("),
            "{caller} must queue the A-side leaf through send_streaming_saga_a_unit"
        );
    }
    assert!(
        fn_body_contains(
            OUTLETS_INVOKE_SRC,
            "invoke_outlet_cross_context",
            "send_cross_context_a_unit("
        ),
        "the cross-context bridge's close must queue A's record through send_cross_context_a_unit"
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

// Bridge level (ADR-049 Phase 2J joiner handshake): the FFI joiner ops reach
// the Supervisor seam. `reserve_key_package` (step 1) must reach
// `Supervisor::reserve_key_package` — where the single-use MLS KeyPackage is
// minted — and `context_join_from_welcome` (step 2) must reach
// `Supervisor::spawn_actor_from_welcome` — where the Welcome is consumed and
// the per-context actor is spawned. Pinned across BOTH already-landed bridges
// (PyO3 + NAPI) so a future refactor cannot silently sever the joiner path
// from the actor-per-context lifecycle. Additive assertions.
#[test]
fn pyo3_reserve_key_package_reaches_supervisor_seam() {
    assert!(
        fn_body_contains(PYO3_CONTEXT_SRC, "reserve_key_package", "supervisor(")
            && fn_body_contains(
                PYO3_CONTEXT_SRC,
                "reserve_key_package",
                ".reserve_key_package("
            ),
        "PyO3 reserve_key_package must resolve the bridge Supervisor and reach \
         Supervisor::reserve_key_package (mints the single-use MLS KeyPackage)"
    );
}

#[test]
fn pyo3_context_join_from_welcome_reaches_spawn_actor_from_welcome() {
    assert!(
        fn_body_contains(
            PYO3_CONTEXT_SRC,
            "context_join_from_welcome",
            "spawn_actor_from_welcome("
        ),
        "PyO3 context_join_from_welcome must reach Supervisor::spawn_actor_from_welcome \
         (consumes the Welcome + spawns the per-context actor)"
    );
}

#[test]
fn napi_reserve_key_package_reaches_supervisor_seam() {
    assert!(
        fn_body_contains(
            NAPI_CONTEXT_SRC,
            "reserve_key_package_on",
            ".reserve_key_package("
        ),
        "NAPI reserve_key_package_on must reach Supervisor::reserve_key_package \
         (mints the single-use MLS KeyPackage)"
    );
}

#[test]
fn napi_context_join_from_welcome_reaches_spawn_actor_from_welcome() {
    assert!(
        fn_body_contains(
            NAPI_CONTEXT_SRC,
            "context_join_from_welcome_on",
            "spawn_actor_from_welcome("
        ),
        "NAPI context_join_from_welcome_on must reach Supervisor::spawn_actor_from_welcome \
         (consumes the Welcome + spawns the per-context actor)"
    );
}

// Bridge level (ADR-049 Phase 2J / FFI-02 Option A creator-side invite): the
// FFI `invite_member` op reaches `Supervisor::invite_member` — where the MLS
// add is performed and the sealed, signed InvitationBundle (or the deferred
// governance outcome) is produced. Pinned across BOTH landed bridges (PyO3 +
// NAPI, mirroring the reserve/join peers above) so a refactor cannot silently
// sever the creator-side invite path from the Supervisor seam. Additive
// assertions.
#[test]
fn pyo3_invite_member_reaches_supervisor_seam() {
    assert!(
        fn_body_contains(PYO3_CONTEXT_SRC, "invite_member", "supervisor(")
            && fn_body_contains(PYO3_CONTEXT_SRC, "invite_member", ".invite_member("),
        "PyO3 invite_member must resolve the bridge Supervisor and reach \
         Supervisor::invite_member (performs the MLS add + seals the signed \
         InvitationBundle)"
    );
}

#[test]
fn napi_invite_member_reaches_supervisor_seam() {
    assert!(
        fn_body_contains(NAPI_CONTEXT_SRC, "invite_member_on", ".invite_member("),
        "NAPI invite_member_on must reach Supervisor::invite_member \
         (performs the MLS add + seals the signed InvitationBundle)"
    );
}

// Bridge level (ADR-049 Phase 2J / FFI-02 Option A): the UniFFI bridge is the
// THIRD landed bridge for the joiner handshake + creator-side invite. The
// capability matrix + bridge-aliases declare uniffi=true for
// `reserve_key_package` / `context_join_from_welcome` / `invite_member`, so the
// same Supervisor-seam pins that guard the PyO3 + NAPI bodies above MUST also
// guard the UniFFI bodies — otherwise a refactor could sever the UniFFI joiner
// / invite path from the actor-per-context lifecycle while the matrix still
// advertises coverage. `extract_fn_body` excludes the signature, so the
// `.reserve_key_package(` / `.invite_member(` call — even though the UniFFI
// bridge method shares its leaf name with the Supervisor method it calls — is
// the real runtime call (`sup.<method>(`), not a self-satisfying signature
// mention. Additive assertions mirroring the NAPI peers over UNIFFI_BRIDGE_SRC.
#[test]
fn uniffi_reserve_key_package_reaches_supervisor_seam() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "reserve_key_package",
            ".reserve_key_package("
        ),
        "UniFFI reserve_key_package must reach Supervisor::reserve_key_package \
         (mints the single-use MLS KeyPackage)"
    );
}

#[test]
fn uniffi_context_join_from_welcome_reaches_supervisor_seam() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "context_join_from_welcome",
            "spawn_actor_from_welcome("
        ),
        "UniFFI context_join_from_welcome must reach Supervisor::spawn_actor_from_welcome \
         (consumes the Welcome + spawns the per-context actor)"
    );
}

#[test]
fn uniffi_invite_member_reaches_supervisor_seam() {
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "invite_member", ".invite_member("),
        "UniFFI invite_member must reach Supervisor::invite_member \
         (performs the MLS add + seals the signed InvitationBundle)"
    );
}

/// The body of `fn_name` in `source` with every whitespace character
/// removed, so a clause matches whatever line breaks rustfmt chose.
fn compact_body(source: &str, fn_name: &str) -> String {
    extract_fn_body(source, fn_name)
        .unwrap_or_else(|| panic!("fn {fn_name} not found"))
        .split_whitespace()
        .collect()
}

/// The argument text of the first call to `callee` in `compact`, from the
/// opening parenthesis to its balanced close, exclusive.
fn call_args<'a>(compact: &'a str, callee: &str) -> Option<&'a str> {
    let open = compact.find(&format!("{callee}("))? + callee.len();
    let mut depth = 0usize;
    for (offset, ch) in compact[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&compact[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether the comma-separated top-level argument list `args` holds `arg`.
fn has_arg(args: Option<&str>, arg: &str) -> bool {
    args.is_some_and(|args| {
        let mut depth = 0i32;
        let mut start = 0usize;
        let mut found = false;
        for (i, ch) in args.char_indices() {
            match ch {
                '(' | '{' | '[' => depth += 1,
                ')' | '}' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    found |= &args[start..i] == arg;
                    start = i + 1;
                }
                _ => {}
            }
        }
        found || &args[start..] == arg
    })
}

// Spec 05 §5.13.3 rules 1-9: every point where an SCP context group enters a
// member from a caller-supplied description (the Welcome join, import, and
// restore) runs the shared binding check, which also returns the committed
// `creation_timestamp_secs` the member installs as `T0` and as the TTL base.
// The data-flow clauses pin that the returned value is the one installed: a
// call that discards it and keeps the inviter's, snapshot's, or local clock's
// value fails here.
#[test]
fn welcome_import_and_restore_run_the_committed_t0_binding_check() {
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "spawn_actor_from_welcome",
            "verify_scp_context_binding("
        ),
        "Supervisor::spawn_actor_from_welcome must verify the joined group's 0xFF02 \
         extension and take T0 from it"
    );
    for entry in ["import_context", "restore_context"] {
        assert!(
            fn_body_contains(MANAGER_SRC, entry, "verify_scp_context_binding("),
            "lifecycle_helpers::{entry} must verify the rehydrated group's 0xFF02 \
             extension and take T0 from it"
        );
    }

    // Welcome join: the binding check's result is `committed_t0`, which reaches
    // `build_welcome_joiner_state`; there it is the TTL base and the
    // pseudonym-rotation base.
    let welcome = compact_body(SUPERVISOR_SRC, "spawn_actor_from_welcome");
    assert!(
        welcome.contains(
            "letcommitted_t0=crate::context::lifecycle_helpers::verify_scp_context_binding("
        ),
        "spawn_actor_from_welcome must bind the binding check's result as committed_t0"
    );
    assert!(
        has_arg(
            call_args(&welcome, "Self::build_welcome_joiner_state"),
            "committed_t0"
        ),
        "spawn_actor_from_welcome must pass committed_t0 to build_welcome_joiner_state"
    );
    let joiner = compact_body(SUPERVISOR_SRC, "build_welcome_joiner_state");
    assert!(
        joiner.contains("letcreation_timestamp_secs=committed_t0;"),
        "build_welcome_joiner_state must take the TTL base from committed_t0"
    );
    assert!(
        has_arg(
            call_args(&joiner, "PseudonymRotationState::joined"),
            "Some(committed_t0)"
        ),
        "build_welcome_joiner_state must anchor PseudonymRotationState::joined at committed_t0"
    );

    // Import: the TTL base and the rotation anchor come from the check's result.
    let import = compact_body(MANAGER_SRC, "import_context");
    assert!(
        import.contains("letcommitted_t0=match"),
        "import_context must bind the binding check's result as committed_t0"
    );
    assert!(
        import.contains("letttl_base_secs=committed_t0.unwrap_or("),
        "import_context must take its TTL base from committed_t0"
    );
    assert!(
        has_arg(
            call_args(&import, "PseudonymRotationState::anchored"),
            "committed_t0"
        ),
        "import_context must anchor the rotation schedule at committed_t0"
    );

    // Restore: the persisted rotation state is re-anchored at the check's
    // result, and the TTL base comes from it.
    let restore = compact_body(MANAGER_SRC, "restore_context");
    assert!(
        restore.contains("letrestore_committed_t0=match"),
        "restore_context must bind the binding check's result as restore_committed_t0"
    );
    assert!(
        restore.contains(".with_schedule_t0(restore_committed_t0)"),
        "restore_context must re-anchor the restored rotation state at the committed T0"
    );
    assert!(
        restore.contains("letrestore_ttl_base_secs=restore_committed_t0.unwrap_or("),
        "restore_context must take its TTL base from the committed T0"
    );
}

// Spec 17 §17.3 "Merkle event log entries": `restore_context` returns the
// event-log restore's error; a failed load never continues over an empty log.
#[test]
fn restore_context_propagates_the_event_log_restore() {
    let restore = compact_body(LIFECYCLE_HELPERS_SRC, "restore_context");
    assert!(
        restore.contains("restore_event_log_fail_closed(deps,&restored_crypto,context_id).await?;"),
        "restore_context must `?`-propagate restore_event_log_fail_closed"
    );
    let helper = compact_body(LIFECYCLE_HELPERS_SRC, "restore_event_log_fail_closed");
    let call = helper
        .find(".restore_event_log(")
        .expect("restore_event_log_fail_closed must call the provider's restore_event_log");
    let tail = &helper[call..];
    let end = tail
        .find(';')
        .expect("the restore_event_log call ends in a statement");
    let statement = &tail[..end];
    assert!(
        statement.ends_with(")?"),
        "the provider's restore_event_log result must be `?`-propagated, got {statement}"
    );
    for swallow in [".ok()", "unwrap_or", "let_=", "ifletErr("] {
        assert!(
            !helper.contains(swallow),
            "restore_event_log_fail_closed must not swallow the restore error ({swallow})"
        );
    }
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

// ADR-049 PR-6 (read-authority switch) — the Supervisor-owned Class-M floor
// registry is the AUTHORITATIVE home for the Class-M sender-key epoch +
// recv-sequence anti-replay floors; the provider mirrors are deleted. These
// additive structural assertions pin the fail-closed wiring so a regression
// cannot silently reintroduce a log-and-drop seam (fail-OPEN) or re-source the
// durable floors from the deleted provider twins.
#[test]
fn adr049_pr6_read_authority_switch_is_wired_fail_closed() {
    // G1 — the receive seam GATES fail-closed on the registry, never
    // log-and-drops. The recv floor gates in `deliver_incoming` AFTER
    // `verify_and_unwrap`, so a frame whose signature fails never advances the
    // replay floor, and `decrypt_and_dispatch` must not call the recv gate.
    // `decrypt_and_dispatch` gates the remote sender epoch and then installs
    // remote keys via the unchecked wrapper (gate-before-install).
    {
        let body = extract_fn_body(MANAGER_SRC, "deliver_incoming")
            .expect("deliver_incoming body must be extractable");
        let gate = body
            .find("check_and_advance_recv_sequence")
            .expect("deliver_incoming must gate the recv floor on the authoritative registry");
        let verify = body
            .find("verify_and_unwrap(")
            .expect("deliver_incoming must verify the sender signature");
        assert!(
            verify < gate,
            "deliver_incoming must gate the recv floor only after verify_and_unwrap"
        );
    }
    assert!(
        !fn_body_contains(
            MANAGER_SRC,
            "decrypt_and_dispatch",
            "check_and_advance_recv_sequence"
        ),
        "decrypt_and_dispatch must not gate the recv floor before signature verification"
    );
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the KeyResponse install moved off the
    // emptied provider (`deps.crypto.set_sender_key_unchecked`, a no-op on a taken
    // context) onto the actor-owned store (`cs.sender_key_store.set_unchecked`).
    // Track the moved install token; the gate-before-install property is unchanged.
    assert!(
        fn_body_contains(MANAGER_SRC, "decrypt_and_dispatch", "sender_key_store")
            && fn_body_contains(MANAGER_SRC, "decrypt_and_dispatch", "set_unchecked"),
        "the remote-epoch seam must install onto the actor sender_key_store via \
         set_unchecked AFTER gating"
    );
    // P1 (white-hat): the remote-epoch seam-2 D1 gate — the registry epoch gate
    // — must be present AND must precede the key install (gate-BEFORE-install =
    // fail-safe: a rejected epoch never reaches the sender-key store).
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "decrypt_and_dispatch",
            "check_and_advance_sender_epoch"
        ),
        "decrypt_and_dispatch must gate the remote sender epoch on the registry"
    );
    {
        let body = extract_fn_body(MANAGER_SRC, "decrypt_and_dispatch")
            .expect("decrypt_and_dispatch body must be extractable");
        let gate = body
            .find("check_and_advance_sender_epoch")
            .expect("seam-2 gate present");
        // PR-7: the install is now `cs.sender_key_store.set_unchecked` (actor store).
        let install = body
            .find("sender_key_store")
            .expect("seam-2 actor-store install present");
        assert!(
            gate < install,
            "the seam-2 registry epoch gate must PRECEDE the actor sender_key_store \
             install (gate-before-install)"
        );
    }
    assert!(
        !fn_body_contains(MANAGER_SRC, "decrypt_and_dispatch", "non-fatal in PR-4"),
        "decrypt_and_dispatch must NOT log-and-drop the floor advance (fail-open)"
    );
    // The local-rotation mirror-forward gates fail-closed (returns Result, `?`'d
    // by callers); its body calls the registry gate and does not log-and-drop.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "mirror_forward_local_sender_epoch",
            "check_and_advance_sender_epoch"
        ),
        "mirror_forward_local_sender_epoch must gate the local epoch on the registry"
    );
    assert!(
        !fn_body_contains(
            MANAGER_SRC,
            "mirror_forward_local_sender_epoch",
            "non-fatal"
        ),
        "mirror_forward_local_sender_epoch must be fail-closed, not log-and-drop"
    );

    // G2 — every production `export_crypto_state` caller sources the durable
    // floors from the authoritative registry (`deps.supervisor.export_*`). The
    // NEGATIVE (no `deps.crypto.export_*`) is compiler-enforced — the provider
    // twins are DELETED, so such a call would not compile — so only the POSITIVE
    // required clause is asserted here (simplifier E: no redundant weaker
    // re-check of a type-system guarantee).
    assert!(
        MANAGER_SRC.contains("deps.supervisor.export_sender_key_epochs")
            && MANAGER_SRC.contains("deps.supervisor.export_recv_sequence_floors"),
        "export callers must source floors from the authoritative registry"
    );

    // restore-into-registry — the restore/import floor guard merges the snapshot
    // floors INTO the registry sink under ONE cross-axis validating merge
    // (`deps.supervisor.validate_and_merge_all_floors`). The NEGATIVE (no
    // `deps.crypto.validate_and_merge`) is compiler-enforced (provider twins
    // deleted), so only the POSITIVE is asserted.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "restore_crypto_state_with_floor_guard",
            "validate_and_merge_all_floors"
        ) && fn_body_contains(
            MANAGER_SRC,
            "restore_crypto_state_with_floor_guard",
            "deps.supervisor"
        ),
        "the restore guard must merge blob floors INTO the registry sink"
    );
}

// ADR-049 PR-7 (SCP-CRYPTOMOVE-001) §9.16.2 — the steady-state sender-key ANSWER
// half moved off the provider onto the actor. These ADDITIVE structural
// assertions pin the new INBOUND answer wiring so a regression cannot silently
// route a received PULL request back through the emptied provider (a no-op on a
// taken context) or drop the enqueued ephemeral-sealed answer before transmit.
#[test]
fn adr049_pr7_sender_key_answer_is_actor_native_and_enqueued_for_transmit() {
    // A1 — `decrypt_and_dispatch` ANSWERS a received §9.16.2 PULL request on the
    // actor's OWNED crypto state (`cs.handle_sender_key_request`), NOT through the
    // provider. The answer HPKE-seals to the requester's ephemeral wrapping key,
    // so it needs no signing key — a clean receive-side answer.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "decrypt_and_dispatch",
            "handle_sender_key_request"
        ),
        "decrypt_and_dispatch must answer a received sender-key PULL request on the \
         actor's owned crypto state (cs.handle_sender_key_request)"
    );
    // A2 — the ephemeral-sealed answer is ENQUEUED onto the actor's
    // `pending_distributions` for the existing MLS-wrap + transport drain (a blocked
    // requester returns None → nothing enqueued, §9.16.2 silent drop).
    assert!(
        fn_body_contains(MANAGER_SRC, "decrypt_and_dispatch", "pending_distributions"),
        "decrypt_and_dispatch must enqueue the ephemeral-sealed answer onto the \
         actor's pending_distributions for transmit"
    );
    // A3 — the actor answer method (moved off the provider) records its nonce-dedup
    // replay entry on the Class-C crypto cache (`nonce_dedup.record`), NOT the
    // Class-S cross-context `xctx_nonce_dedup` (coalesced persist is sound: a
    // still-fresh replay re-seals the SAME key to the SAME ephemeral pubkey).
    {
        let body = extract_fn_body(STATE_SRC, "handle_sender_key_request")
            .expect("actor ContextCryptoState::handle_sender_key_request body must exist");
        assert!(
            body.contains("nonce_dedup.record"),
            "the actor answer must record its replay nonce on the Class-C crypto \
             nonce_dedup cache"
        );
        assert!(
            !body.contains("xctx_nonce_dedup"),
            "the actor answer must NOT touch the Class-S cross-context xctx_nonce_dedup"
        );
    }
}

// Timer level (ADR-049 Decision-1 / finding A3 — APPROVED enforcement
// retarget): the TTL + governance timers are ACTOR-OWNED arms reconciled
// from owned state inside the actor's own `run()` loop, NOT
// supervisor-driven `task_set` spawns that mailbox a `FireTimer` /
// `EvaluateTimeouts` tick. This assertion REPLACES the two retired
// assertions (`ttl_timer_helpers_call_actor_shape_spawn_not_legacy`,
// `lifecycle_bootstrap_installs_timers_via_mailbox_not_legacy`) that pinned
// the now-superseded supervisor-mailbox timer mechanism. It pins the REAL
// new mechanism (body-scoped, not a dead string-match) so a refactor cannot
// silently regress the arms back to a supervisor-spawned timer task.
#[test]
fn actor_owned_timer_arms_reconcile_from_state() {
    // The run loop reconciles the actor-owned timer arms every turn.
    assert!(
        fn_body_contains(ACTOR_MOD_SRC, "run", "reconcile_timers"),
        "ContextActor::run() must call reconcile_timers() to arm the actor-owned timers"
    );
    // reconcile_timers derives the TTL arm from the convergent deadline and
    // arms BOTH owned timer fields (ttl_timer + governance_timeout).
    assert!(
        fn_body_contains(ACTOR_MOD_SRC, "reconcile_timers", "deadline_unix_secs")
            && fn_body_contains(ACTOR_MOD_SRC, "reconcile_timers", "ttl_timer")
            && fn_body_contains(ACTOR_MOD_SRC, "reconcile_timers", "governance_timeout"),
        "reconcile_timers must arm ttl_timer/governance_timeout from \
         state.ttl.timer.deadline_unix_secs"
    );
    // The TTL tick runs the actor-shape expiry pipeline directly on owned
    // state (no FireTimer mailbox hop).
    assert!(
        fn_body_contains(ACTOR_MOD_SRC, "on_ttl_tick", "handle_ttl_expiry"),
        "on_ttl_tick must run ttl_close_helpers::handle_ttl_expiry on owned state"
    );
    // The governance tick runs the shared sweep directly on owned state (no
    // EvaluateTimeouts mailbox hop).
    assert!(
        fn_body_contains(
            ACTOR_MOD_SRC,
            "on_governance_timeout",
            "evaluate_governance_timeouts"
        ),
        "on_governance_timeout must run handlers::governance::evaluate_governance_timeouts \
         on owned state"
    );
    // No retired supervisor-driven timer residue: the timer helpers no longer
    // spawn onto a shared `task_set` via `tracked_spawn`, and the supervisor
    // no longer exposes the `task_set` accessor.
    assert!(
        !MANAGER_SRC.contains("tracked_spawn"),
        "the retired supervisor-driven timer spawn (tracked_spawn) must be gone from the \
         timer helpers"
    );
    assert!(
        !SUPERVISOR_SRC.contains("task_set_ref"),
        "the supervisor's timer task_set accessor (task_set_ref) must be retired"
    );
}

// Supervisor level (ADR-049): the single startup entry point
// `restore_on_startup` MUST restore contexts BEFORE the saga-journal replay —
// the §17.16.4 restore-then-replay crash-recovery model requires each recovery
// arm (the cross-context caller reversal; a Commit-in-progress re-send) to drive
// a NOW-RESIDENT participant, so context restore must run first.
//
// PRIMARY enforcement is the TYPE SYSTEM: `replay_unresolved_sagas` takes a
// `&RestoredContexts` witness that only `restore_all_contexts` can mint, so a
// reordered "replay first" body does not compile (see the `compile_fail`
// doctest on `Supervisor::replay_unresolved_sagas`). This text gate is
// defense-in-depth — it pins the presence of both calls AND their order in the
// source so the wiring stays legible and a refactor that somehow preserved
// compilation (e.g. by fetching a token elsewhere) is still flagged.
#[test]
fn restore_on_startup_runs_restore_before_replay() {
    let body = extract_fn_body(SUPERVISOR_SRC, "restore_on_startup")
        .expect("Supervisor::restore_on_startup must exist");
    let restore_pos = body
        .find("restore_all_contexts()")
        .expect("restore_on_startup must call restore_all_contexts() — the context-restore sweep");
    // The call now threads the restore witness: `replay_unresolved_sagas(&restored)`.
    // Match the open paren (not `()`), which the witness argument follows.
    let replay_pos = body.find("replay_unresolved_sagas(").expect(
        "restore_on_startup must call replay_unresolved_sagas(&restored) — the §17.16.4 replay sweep",
    );
    assert!(
        restore_pos < replay_pos,
        "restore_on_startup MUST call restore_all_contexts() BEFORE replay_unresolved_sagas() \
         (§17.16.4 restore-then-replay ordering — recovery arms drive now-resident participants); \
         found restore at {restore_pos}, replay at {replay_pos}"
    );
}

// ADR-048 `suspend()` amendment (2026-10-23) and ADR-049 Decision 9: the
// shared bridge `CoreFields::suspend` flushes every context on the tokio
// runtime through the async `flush_all_contexts(`, whose failure reaches the
// caller. The sync `flush_all_contexts_sync(` fails without a runtime on the
// calling thread, so a suspend that called it flushed nothing from an SDK
// thread. The check reads the one `fn suspend(` inside the `impl CoreFields {`
// blocks, so the `BridgeInstanceCore` trait default that delegates to it, or
// any other type's `suspend`, cannot satisfy it.
#[test]
fn bridge_suspend_flushes_on_the_runtime() {
    let body = inherent_method_body(BRIDGE_INSTANCE_SRC, "CoreFields", "suspend");
    assert!(
        body.contains("flush_all_contexts("),
        "CoreFields::suspend must flush every context through the async \
         flush_all_contexts( before it clears transport"
    );
    assert!(
        !body.contains("flush_all_contexts_sync("),
        "CoreFields::suspend must NOT call flush_all_contexts_sync(, which flushes nothing \
         when the calling thread has no tokio runtime"
    );
}

// Bridge level (ADR-049): every production startup/resume path SHOULD
// route through the combined `restore_on_startup` entry point — NOT call the
// bare `restore_all_contexts` — so the saga-journal replay can never be skipped
// on a real process restart. Guards against the "exported but never called from
// the bootstrap path" regression.
//
// **This is a BEST-EFFORT source-order check, NOT the real enforcement.** It is
// best-effort for IN-CRATE callers only: a substring scan cannot soundly
// distinguish "calls the combined entry" from "merely names the token" — an
// in-crate caller could name `restore_all_contexts(&sup)` via UFCS (no
// `.restore_all_contexts()` substring) plus a no-op `restore_on_startup` shadow
// and still pass this gate. Hardening the in-crate locator with more spellings is
// a non-convergent denylist (`.claude/agents/README.md` §Review rules).
//
// `restore_all_contexts` is `pub(crate)`, so no out-of-crate bridge can name the
// bare leg at all — a cross-crate `Supervisor::restore_all_contexts(&sup)` call
// is a compile error (E0624). This source-text gate is therefore retained purely
// as cheap IN-CRATE defense-in-depth against the obvious "names the bare leg"
// regression: it catches an in-crate caller (or a future re-widening of the
// visibility) that names the bare leg and skips the saga-journal replay. It
// covers the shared bridge-instance core AND each of the three FFI exports (PyO3
// / napi / UniFFI), since each exports its own per-instance restore entry
// (`restore_all_contexts` on PyO3/UniFFI, `context_restore_all_on` on napi). Its
// assertions are not weakened.
//
// The REAL enforcement is twofold. The type system enforces it by construction:
// `replay_unresolved_sagas` requires a `RestoredContexts` witness that only
// `restore_all_contexts` can mint, so replay-before-restore does not compile
// (restore-then-replay ORDERING); and `restore_all_contexts` being `pub(crate)`
// makes the bare leg unnameable cross-crate (E0624, above — NO-BARE-RESTORE leg
// coverage, the same fact this source-text gate cheaply backstops in-crate). And
// the behavioral bootstrap integration test
// `bridge_restore_entry_runs_restore_and_replay_legs`
// (`crates/scp-testing/tests/integration/saga_bridge_bootstrap.rs`) is what
// proves BOTH legs run: it drives the shared bridge entry
// `restore_all_persisted_contexts` over a real persistence backend + durable saga
// journal and asserts a persisted context was restored AND a crash-orphaned saga
// was reconciled to terminal.
#[test]
fn bridge_resume_path_routes_through_restore_on_startup() {
    // 1) Shared bridge-instance core: the production startup/resume path.
    assert!(
        fn_body_contains(
            BRIDGE_INSTANCE_SRC,
            "restore_all_persisted_contexts",
            "restore_on_startup()"
        ),
        "CoreFields::restore_all_persisted_contexts (the production startup/resume path) \
         must call Supervisor::restore_on_startup() so the §17.16.4 saga-journal replay runs \
         after context restore on every process restart"
    );
    assert!(
        !fn_body_contains(
            BRIDGE_INSTANCE_SRC,
            "restore_all_persisted_contexts",
            "restore_all_contexts()"
        ),
        "CoreFields::restore_all_persisted_contexts must NOT call the bare \
         restore_all_contexts() — that bypasses the saga-journal replay; route through \
         restore_on_startup() instead"
    );

    // 2) The three FFI exports must each route through `restore_on_startup()` and
    //    NOT call the bare `restore_all_contexts()` on the supervisor.
    //    (PyO3 method `restore_all_contexts`, UniFFI method `restore_all_contexts`,
    //    napi free fn `context_restore_all_on`.)
    for (src, fn_name, bridge) in [
        (PYO3_CONTEXT_SRC, "restore_all_contexts", "PyO3"),
        (UNIFFI_BRIDGE_SRC, "restore_all_contexts", "UniFFI"),
        (NAPI_CONTEXT_SRC, "context_restore_all_on", "napi"),
    ] {
        assert!(
            fn_body_contains(src, fn_name, "restore_on_startup()"),
            "{bridge} export `{fn_name}` must call Supervisor::restore_on_startup() so the \
             §17.16.4 saga-journal replay runs after context restore"
        );
        assert!(
            !fn_body_contains(src, fn_name, ".restore_all_contexts()"),
            "{bridge} export `{fn_name}` must NOT call the bare supervisor \
             `.restore_all_contexts()` — that bypasses the saga-journal replay; route through \
             restore_on_startup() instead"
        );
    }
}

// First-occurrence binding pin for the seal/open crypto-pipeline gates below.
//
// `extract_fn_body` / `extract_fn_signature` bind to the FIRST `fn seal(` /
// `fn open(` in STATE_SRC. STATE_SRC now defines each name TWICE: the
// production `ContextCryptoState::seal`/`open` core (whose bodies call
// `create_outer_envelope` / `encrypt_sender_layer` / `decrypt_sender_layer` /
// `strip_padding`) AND a `#[cfg(test)]` `PerContextState` delegating wrapper
// (whose body only forwards to `crypto.seal(...)` / `crypto.open(...)`). The
// production core is authored first, so first-occurrence binding is correct
// TODAY — but a future impl-block reorder that placed a wrapper first would
// silently rebind the gates below to a delegating body. Pin the assumption by a
// signature token unique to the production core (`aad_sequence` on `seal`; the
// raw `context_id: &[u8; 32]` digest on `open`), absent from the wrappers, so a
// reorder fails HERE loudly instead of masking a downstream regression.
#[test]
fn state_seal_open_first_binding_is_production_core() {
    let seal_sig = extract_fn_signature(STATE_SRC, "seal").expect("STATE_SRC defines a `seal`");
    assert!(
        seal_sig.contains("aad_sequence"),
        "the first `fn seal(` in STATE_SRC must be the production \
         ContextCryptoState core (takes `aad_sequence`), not the #[cfg(test)] \
         PerContextState delegating wrapper — else the seal gates below rebind \
         to the wrapper body"
    );
    let open_sig = extract_fn_signature(STATE_SRC, "open").expect("STATE_SRC defines an `open`");
    assert!(
        open_sig.contains("context_id: &[u8; 32]"),
        "the first `fn open(` in STATE_SRC must be the production \
         ContextCryptoState core (takes the raw `context_id` digest), not the \
         #[cfg(test)] PerContextState delegating wrapper — else the open gates \
         below rebind to the wrapper body"
    );
}

// Actor-state level: `ContextCryptoState::seal` calls encrypt_sender_layer
// (sender key encryption). Repointed from the deleted provider `seal`.
#[test]
fn seal_calls_encrypt_sender_layer() {
    assert!(
        fn_body_contains(STATE_SRC, "seal", "encrypt_sender_layer"),
        "seal (actor ContextCryptoState) must call encrypt_sender_layer"
    );
}

// Actor-state level: `ContextCryptoState::open` calls decrypt_sender_layer.
// Repointed from the deleted provider `open` to its actor home in STATE_SRC.
#[test]
fn open_calls_decrypt_sender_layer() {
    assert!(
        fn_body_contains(STATE_SRC, "open", "decrypt_sender_layer"),
        "open (actor ContextCryptoState) must call decrypt_sender_layer"
    );
}

// ADR-049 PR-7 (SCP-CRYPTOMOVE-001) + #2148 (birth-into-actor): the steady-state
// crypto methods were MOVED off `NodeMlsFactory` onto the actor-owned
// `PerContextState`, and #2148 additionally DELETED the provider's per-context
// birth/restore/teardown seam — the `contexts` / `taken_context_ids` /
// `broadcast_keys` maps and every method that read or wrote them. This asserts
// the provider retains ZERO definitions of any of them: a one-way dissolution
// (no dual-home), so a future refactor cannot silently re-add a provider-resident
// twin that would seal/open/birth behind the actor's back (double-owner,
// divergent sequence, resurrected sender key, #2167-style cross-map TOCTOU).
//
// The RETAINED node-level surface — `create_mls_group_with_context` /
// `install_joined_group` (owned-return birth), `create_bare_group_owned` (test),
// `build_restored_owned`, `process_incoming_sender_key`, `validate_key_package`,
// `wrapping_keypair`(`_snapshot`), `make_credential`, `validate_creator_identity`,
// `local_did`, backends/clock — is deliberately NOT listed (none carry per-context
// state). The listed names are ONLY genuinely-deleted symbols; the checks below
// use `fn NAME(`, which does not match `fn create_mls_group_with_context(` or
// `fn install_joined_group(`. Closed positive list; additive coverage.
#[test]
fn provider_steady_state_crypto_methods_are_deleted() {
    const DELETED_METHODS: &[&str] = &[
        // Steady-state crypto seam relocated onto the actor (PR-7).
        "seal",
        "open",
        "advance_epoch",
        "rotate_sender_key",
        "remove_member",
        "remove_member_sender_key",
        "mls_encrypt_management",
        "local_sender_key_epoch",
        "export_crypto_state",
        "restore_crypto_state",
        "drain_pending_sender_key_messages",
        // #2148 per-context birth/restore/teardown seam DELETED with the maps.
        "take_crypto_state",
        "with_context",
        "context_crypto_present",
        "create_mls_group", // bare; `create_mls_group_with_context` survives (no match)
        "create_group_into_slot",
        "generate_sender_key",
        "init_broadcast_key",
        "destroy_mls_group",
        "destroy_sender_key",
        "add_member", // and add_member_from_bytes — member add mutates the actor group
        "add_member_from_bytes",
        "distribute_sender_key",
        "store_member_sender_key",
        "set_sender_key_unchecked",
        "handle_sender_key_request",
        "group_context_extension", // provider reader deleted; actor twin survives (STATE_SRC)
    ];
    for method in DELETED_METHODS {
        let def = format!("fn {method}(");
        assert!(
            !PROVIDER_SRC.contains(&def),
            "NodeMlsFactory must NOT define `{method}` — the per-context crypto \
             seam is actor-owned (ADR-049 PR-7 + #2148 birth-into-actor); the provider \
             holds no per-context state and no dual-home twin"
        );
    }

    // #2148: the provider holds NO per-context state fields. The three per-context
    // maps are DELETED — removing them closes the #2167 cross-map TOCTOU by
    // construction (there is no check-then-insert to race). Match the FIELD
    // DECLARATION form (`name: Type`) so prose/comment mentions of the retired
    // names do not false-positive.
    for field in [
        "contexts: DashMap",
        "taken_context_ids: DashSet",
        "broadcast_keys: DashMap",
    ] {
        assert!(
            !PROVIDER_SRC.contains(field),
            "NodeMlsFactory must NOT carry the per-context field `{field}` — #2148 \
             (birth-into-actor) dissolves the provider's per-context state; the actor's \
             `PerContextState` is the sole per-context crypto home"
        );
    }
}

// --- Envelope layer (§13) — NOW WIRED ---

/// ADR-002 and spec 23 §23.4.1: a member publish carries one relay-visible
/// `OuterEnvelope` over the serialized MLS message. `seal` serializes the
/// ciphertext and frames nothing; `RelayTransportProvider::send_message`
/// frames it once through the scp-protocol codec; the browser client frames
/// and unframes through the same codec; and the native relay adapter unframes
/// through it.
#[test]
fn every_member_publish_is_framed_once_and_every_receive_unframed_once() {
    const TRANSPORT_PROVIDER_SRC: &str =
        include_str!("../../../../crates/scp-transport/src/provider.rs");
    const CLIENT_SRC: &str = include_str!("../../../../crates/scp-client/src/client.rs");
    const NATIVE_ADAPTER_SRC: &str =
        include_str!("../../../../crates/scp-transport/src/native/adapter.rs");
    let seal = extract_fn_body(STATE_SRC, "seal").expect("actor state.rs must define seal");
    assert!(
        seal.contains("serialize_ciphertext("),
        "seal must return the serialized MLS ciphertext"
    );
    assert!(
        !seal.contains("frame_mls_message") && !seal.contains("create_outer_envelope"),
        "seal must build no envelope; the transport adds the only one"
    );
    let send = extract_fn_body(TRANSPORT_PROVIDER_SRC, "send_message")
        .expect("provider.rs must define send_message");
    assert!(
        send.contains("frame_mls_message("),
        "RelayTransportProvider::send_message must frame through OuterEnvelope::frame_mls_message"
    );
    assert!(
        !send.contains("build_envelope("),
        "RelayTransportProvider::send_message must not build its own envelope"
    );
    let client = strip_non_code(CLIENT_SRC);
    for call in ["frame_mls_message(", "unframe_mls_message("] {
        assert!(
            client.contains(call),
            "the browser client must call OuterEnvelope::{call})"
        );
    }
    assert!(
        strip_non_code(NATIVE_ADAPTER_SRC).contains("unframe_mls_message("),
        "the native relay adapter must unframe through OuterEnvelope::unframe_mls_message"
    );
}

// --- Inner envelope / signatures (§9.8, #1547) — NOW WIRED ---

#[test]
fn encrypt_path_calls_create_inner_envelope() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "create_inner_envelope_signed")
            || fn_body_contains(
                MANAGER_SRC,
                "build_inner_wire",
                "create_inner_envelope_signed"
            ),
        "send path must call create_inner_envelope_signed"
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
            || fn_body_contains(MANAGER_SRC, "build_inner_wire", "wrap_content"),
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
        fn_body_contains(STATE_SRC, "open", "strip_padding")
            || fn_body_contains(MANAGER_SRC, "deliver_incoming", "strip_padding")
            || fn_body_contains(MANAGER_SRC, "verify_and_unwrap", "strip_padding"),
        "receive/decrypt path must call strip_padding"
    );
}

// --- Provenance (#1536) — WIRED (conditional on cross-context source) ---
// attach_provenance is called in the `build_inner_wire` helper when
// source_provenance is Some (cross-context data flow). For intra-context
// direct messages source_provenance is None and attach_provenance is not
// invoked. The pipeline test verifies the code path exists.

#[test]
fn encrypt_path_references_attach_provenance() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "attach_provenance")
            || fn_body_contains(MANAGER_SRC, "build_inner_wire", "attach_provenance"),
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

/// Spec 09 §9.10.4.1, ADR-031: an approved `ModifyPseudonymRotationPolicy`
/// reaches its executor. `execute_governance_action` (the approved-proposal
/// path of propose and vote) calls `dispatch_governance_action`, whose arm for
/// the variant calls `execute_modify_pseudonym_rotation_policy`, which writes
/// the policy through the fail-closed Class-S commit and appends the ADR-011
/// event.
#[test]
fn modify_pseudonym_rotation_policy_reaches_its_executor() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "execute_governance_action",
            "dispatch_governance_action("
        ),
        "execute_governance_action must call dispatch_governance_action"
    );
    let dispatch = extract_fn_body(MANAGER_SRC, "dispatch_governance_action")
        .expect("dispatch_governance_action exists");
    assert!(
        dispatch.contains("GovernanceAction::ModifyPseudonymRotationPolicy")
            && dispatch.contains("execute_modify_pseudonym_rotation_policy("),
        "dispatch_governance_action must route ModifyPseudonymRotationPolicy to \
         execute_modify_pseudonym_rotation_policy"
    );
    let executor = extract_fn_body(MANAGER_SRC, "execute_modify_pseudonym_rotation_policy")
        .expect("execute_modify_pseudonym_rotation_policy exists");
    for step in [
        ".validate()",
        "commit_class_s_keep",
        "set_pseudonym_rotation(",
        "EventType::PseudonymRotationPolicyModified",
    ] {
        assert!(
            executor.contains(step),
            "execute_modify_pseudonym_rotation_policy must contain `{step}`"
        );
    }
}

/// Spec 09 §9.10.4.1: the local member's pseudonym rotation is reachable on
/// its production paths. `Supervisor::rotate_pseudonym` dispatches
/// `MessagingCommand::RotatePseudonym`, the messaging handler calls
/// `messaging_helpers::rotate_pseudonym`, which commits through the
/// fail-closed compensating Class-S commit and then announces through
/// `send_pseudonym_announcement`. `Supervisor::local_routing_ids` dispatches
/// `QueriesCommand::LocalRoutingIds`, answered by
/// `queries_helpers::local_routing_ids`. The actor run loop drives the
/// rotation arm (`on_rotation_tick`, which signals from
/// `PseudonymRotationState::wake`), and `reconcile_timers` re-arms it from
/// state. `record_rotation` puts the routing ID the member left on the
/// query-only list, and the rotated state persists inside the compensating
/// commit.
#[test]
fn local_pseudonym_rotation_reaches_its_helpers() {
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "rotate_pseudonym",
            "MessagingCommand::RotatePseudonym"
        ),
        "Supervisor::rotate_pseudonym must dispatch MessagingCommand::RotatePseudonym"
    );
    let dispatch = extract_fn_body(HANDLERS_MESSAGING_SRC, "dispatch")
        .expect("the messaging handler dispatch exists");
    assert!(
        dispatch.contains("MessagingCommand::RotatePseudonym")
            && dispatch.contains("handle_rotate_pseudonym("),
        "the messaging dispatch must route RotatePseudonym to handle_rotate_pseudonym"
    );
    assert!(
        fn_body_contains(
            HANDLERS_MESSAGING_SRC,
            "handle_rotate_pseudonym",
            "messaging_helpers::rotate_pseudonym("
        ),
        "handle_rotate_pseudonym must call messaging_helpers::rotate_pseudonym"
    );
    let helper = extract_fn_body(MANAGER_SRC, "rotate_pseudonym")
        .expect("messaging_helpers::rotate_pseudonym exists");
    for step in [
        "due_epoch(",
        "commit_class_s_compensating(",
        "record_rotation(",
        "ContextEvent::LocalPseudonymRotated",
        "send_pseudonym_announcement(",
    ] {
        assert!(
            helper.contains(step),
            "messaging_helpers::rotate_pseudonym must contain `{step}`"
        );
    }

    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "local_routing_ids",
            "QueriesCommand::LocalRoutingIds"
        ),
        "Supervisor::local_routing_ids must dispatch QueriesCommand::LocalRoutingIds"
    );
    let queries = extract_fn_body(HANDLERS_QUERIES_SRC, "dispatch")
        .expect("the queries handler dispatch exists");
    assert!(
        queries.contains("QueriesCommand::LocalRoutingIds")
            && queries.contains("queries_helpers::local_routing_ids("),
        "the queries dispatch must answer LocalRoutingIds through \
         queries_helpers::local_routing_ids"
    );

    let run = extract_fn_body(ACTOR_MOD_SRC, "run").expect("ContextActor::run exists");
    assert!(
        run.contains("self.on_rotation_tick()"),
        "the actor run loop must drive the rotation arm"
    );
    assert!(
        fn_body_contains(
            ACTOR_MOD_SRC,
            "reconcile_timers",
            "reconcile_pseudonym_timers("
        ),
        "reconcile_timers must re-arm the pseudonym timers from state"
    );
    assert!(
        fn_body_contains(ACTOR_MOD_SRC, "on_rotation_tick", ".wake("),
        "on_rotation_tick must signal from PseudonymRotationState::wake"
    );

    // §9.10.4.1 "Query-only list": the rotation puts the routing ID it left on
    // the query-only list, and the rotated state reaches the store only
    // through the fail-closed restore-direction commit, whose failure restores
    // the old Class-S state and the old routing ID.
    let record = extract_fn_body(PSEUDONYM_ROTATION_SRC, "record_rotation")
        .expect("PseudonymRotationState::record_rotation exists");
    assert!(
        record.contains("self.query_only.push(QueryOnlyRoutingId")
            && record.contains("routing_id: previous_routing_id"),
        "record_rotation must push the routing ID it left onto query_only"
    );
    let record_at = helper
        .find("record_rotation(")
        .expect("rotate_pseudonym calls record_rotation");
    let commit_at = helper
        .find("commit_class_s_compensating(")
        .expect("rotate_pseudonym persists through commit_class_s_compensating");
    let commit_tail = &helper[commit_at..];
    assert!(
        record_at < commit_at
            && commit_tail.contains("state.class_s.pseudonym_rotation = rotation")
            && commit_tail.contains("set_local_pseudonym(old)"),
        "rotate_pseudonym must record the rotation, then persist the rotated state \
         (query-only list included) inside commit_class_s_compensating, whose \
         compensation restores the old routing ID"
    );
}

/// Spec 09 §9.10.4.1 "Membership trigger" and "Record lifetime": a Commit
/// another member committed reaches the rotation trigger and the registry
/// deletion on the receive path. `Supervisor::deliver_commit_blob` dispatches
/// `MessagingCommand::DeliverIncoming`, the messaging handler calls
/// `deliver_incoming`, which counts the Commit's membership changes by DID with
/// `classify_commit_membership`. The handler then applies them through the
/// fail-closed keep-direction commit to `note_processed_commit`, which deletes
/// each removed DID's registry record and records the trigger through
/// `note_membership_change`, and changes nothing else: the leaf diff is
/// unverified, so membership, role, sender-key and floor state change only
/// from the verified governance leaves of spec 07 §7.3.1.1 step 3. The
/// committed removal and leave keep `remove_member_state` as their teardown,
/// and a reset is one Commit built by `reset_member` (step 1.6). The actor's
/// rotation arm turns the trigger into the `PseudonymRotationDue` signal.
#[test]
fn processed_membership_commit_reaches_rotation_and_registry() {
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "deliver_commit_blob",
            "MessagingCommand::DeliverIncoming"
        ),
        "Supervisor::deliver_commit_blob must dispatch MessagingCommand::DeliverIncoming"
    );
    let dispatch = extract_fn_body(HANDLERS_MESSAGING_SRC, "dispatch")
        .expect("the messaging handler dispatch exists");
    assert!(
        dispatch.contains("MessagingCommand::DeliverIncoming")
            && dispatch.contains("handle_deliver_incoming("),
        "the messaging dispatch must route DeliverIncoming to handle_deliver_incoming"
    );
    let handler = extract_fn_body(HANDLERS_MESSAGING_SRC, "handle_deliver_incoming")
        .expect("handle_deliver_incoming exists");
    for step in [
        "deliver_incoming(",
        "&mut processed_commit",
        "commit_class_s_keep(",
        "note_processed_commit(",
    ] {
        assert!(
            handler.contains(step),
            "handle_deliver_incoming must contain `{step}`"
        );
    }
    assert!(
        !handler.contains(".remove_member_floors("),
        "a processed Commit must not prune floors from an unverified leaf diff"
    );
    let deliver = extract_fn_body(MANAGER_SRC, "deliver_incoming")
        .expect("messaging_helpers::deliver_incoming exists");
    assert!(
        deliver.contains("Dispatched::Commit") && deliver.contains("classify_commit_membership("),
        "deliver_incoming must classify a processed Commit's membership changes by DID"
    );
    let note = extract_fn_body(PSEUDONYM_ROTATION_SRC, "note_processed_commit")
        .expect("note_processed_commit exists");
    assert!(
        note.contains("registry.remove(") && note.contains(".note_membership_change("),
        "note_processed_commit must delete removed DIDs' records and record the trigger"
    );
    for teardown in [
        ".remove_member_state(",
        ".remove_member_sender_key(",
        "floors",
    ] {
        assert!(
            !note.contains(teardown),
            "note_processed_commit must not tear down state from an unverified leaf diff \
             (`{teardown}`)"
        );
    }
    for removal in ["execute_remove_member", "leave_context"] {
        assert!(
            fn_body_contains(MANAGER_SRC, removal, ".remove_member_state("),
            "{removal} must tear down the departed member through remove_member_state"
        );
    }
    let reset =
        extract_fn_body(MANAGER_SRC, "execute_reset_member").expect("execute_reset_member exists");
    assert!(
        reset.contains(".reset_member(")
            && !reset.contains(".remove_member(")
            && !reset.contains("execute_add_member("),
        "execute_reset_member must build its one remove-and-add Commit through reset_member"
    );
    assert!(
        fn_body_contains(
            ACTOR_MOD_SRC,
            "on_rotation_tick",
            "ContextEvent::PseudonymRotationDue"
        ),
        "the rotation arm must turn the trigger into PseudonymRotationDue"
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

// --- Per-DID anti-spam escalation for outlet invocations (§19.7) ---

#[test]
fn invoke_outlet_with_economy_wires_escalation_and_rollback() {
    // ADR-049 actor split: the Phase-1 economy reserve runs on actor-owned
    // state in `reserve_outlet_economy`. It must (a) record the new velocity
    // entry so compute_escalated_cost sees it, (b) thread the per-context
    // velocity_tracker and message_pricing into OutletEconomyContext, and the
    // Phase-3 `rollback_outlet_economy` must roll back the velocity entry on
    // executor failure. The orchestrator `invoke_outlet_with_economy` runs the
    // outlet executor between the two phases.
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_outlet_economy", "record_message"),
        "reserve_outlet_economy must record the invocation for velocity tracking"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_outlet_economy", "velocity_tracker"),
        "reserve_outlet_economy must thread velocity_tracker into OutletEconomyContext"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_outlet_economy", "message_pricing"),
        "reserve_outlet_economy must thread message_pricing into OutletEconomyContext"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "rollback_outlet_economy", ".rollback("),
        "rollback_outlet_economy must roll back the velocity entry on executor failure \
         via the F5 identity-based `rollback(token)` API"
    );
    // The orchestrator runs the outlet executor between reserve and settle.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "invoke_outlet_with_economy",
            "invoke_outlet_execute_and_validate"
        ),
        "invoke_outlet_with_economy must run the executor via invoke_outlet_execute_and_validate \
         between the reserve (Phase 1) and settle (Phase 3) mailbox round-trips"
    );
}

/// D4: the Phase-1 reserve (`reserve_outlet_economy`) must reference the
/// hard rate limit. Enforced structurally so a future refactor cannot
/// silently drop the Matrix Synapse–style defense-in-depth cap on the
/// outlet path.
#[test]
fn invoke_outlet_with_economy_enforces_hard_rate_limit() {
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_outlet_economy", "hard_rate_limit"),
        "reserve_outlet_economy must reference hard_rate_limit so the Matrix Synapse–style \
         defense-in-depth cap is enforced on the outlet path (D4)"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "reserve_outlet_economy", "try_consume"),
        "reserve_outlet_economy must call try_consume on the hard rate limit token bucket \
         before any Phase 1 bookkeeping — mirrors enforce_send_economy at messaging.rs:346"
    );
}

/// D4: every Phase 1 failure branch in `reserve_outlet_economy` MUST refund
/// the hard rate limit token. We expect at least 3 inline refund sites:
/// `economy_pre_check` failure, `record_spend` failure, and
/// `authorize_outlet_payment` failure. Dropping any branch leaks a
/// rate-limit token on failure.
#[test]
fn invoke_outlet_with_economy_refunds_hard_rate_limit_on_every_phase1_failure() {
    let body = extract_fn_body(MANAGER_SRC, "reserve_outlet_economy")
        .expect("reserve_outlet_economy body must exist");
    // The hard-rate-limit token is refunded through the field-granular Class-C
    // governance view (`hard_rate_limit_mut().refund(..)`) on every Phase-1
    // failure branch (ADR-049 §9). Match the accessor form so a renamed bucket
    // access does not silently drop a refund site.
    let refund_sites = body.matches("hard_rate_limit_mut().refund").count();
    assert!(
        refund_sites >= 3,
        "reserve_outlet_economy must have at least 3 inline hard_rate_limit_mut().refund sites \
         (economy_pre_check failure, record_spend failure, authorize_outlet_payment failure); \
         found {refund_sites}. Dropping any branch leaks a rate-limit token on failure."
    );
}

#[test]
fn invoke_outlet_with_economy_releases_lock_before_executor() {
    // ADR-049 actor-split invariant (supersedes the legacy lock_context /
    // relock_context generation-guard mechanism, which is gone with the
    // `contexts` DashMap): the caller-supplied non-Send executor must run
    // OUTSIDE the per-context actor — between the Phase-1 economy reserve and
    // the Phase-3 settle. The economy bookkeeping that mutates per-context
    // state lives entirely in `reserve_outlet_economy` / `settle_outlet_economy`
    // (which run on `&mut PerContextState` inside the actor); the executor
    // never crosses the actor mailbox and never holds per-context state
    // exclusively. A mis-behaving outlet executor blocked every concurrent
    // manager call until the original lock-split landed; the actor split
    // preserves the same off-state-executor guarantee.
    //
    // We assert the orchestrator:
    //   (1) hands the reserve closure to the helper (Phase 1),
    //   (2) hands the settle closure to the helper (Phase 3), and
    //   (3) runs the executor (Phase 2) between them.
    let body = extract_fn_body(MANAGER_SRC, "invoke_outlet_with_economy")
        .expect("invoke_outlet_with_economy body must exist");
    assert!(
        body.contains("reserve()")
            && body.contains("settle(")
            && body.contains("invoke_outlet_execute_and_validate"),
        "invoke_outlet_with_economy must run the reserve (Phase 1) and settle (Phase 3) \
         mailbox round-trips around the off-actor executor (Phase 2) so the non-Send outlet \
         executor never holds per-context state exclusively"
    );
    // Defense in depth: the settle path must cover BOTH the success
    // (Capture) and failure (Rollback) branches.
    assert!(
        body.contains("Capture") && body.contains("Rollback"),
        "invoke_outlet_with_economy must settle via Capture on executor success and Rollback \
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
// Direct-execute governance trust boundary (quorum-bypass fix)
//
// `execute_governance_action` must dispatch the action the *engine* tracked for
// a proposal id — never a caller-supplied proposal/action/status. These
// positive (closed-by-construction) assertions pin the trust boundary at the
// AST level on the native runtime so a future refactor cannot reintroduce the
// bypass by re-accepting caller-trusted governance data.
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
    // The forgery path: `get_proposal(proposal_id)` returns `None` for an id the
    // engine never tracked, and the `ok_or_else(...)?` rejects it with a
    // `PermissionDenied`. We match the CODE construct (`ok_or_else` +
    // `PermissionDenied`) rather than the rejection's error-message STRING, since
    // `extract_fn_body` strips string-literal contents (so a structural assertion
    // cannot false-pass on stringized or commented-out text).
    assert!(
        body.contains("get_proposal(proposal_id)")
            && body.contains("ok_or_else")
            && body.contains("PermissionDenied"),
        "native execute_governance_action must reject a proposal id the engine \
         never tracked — the `get_proposal(proposal_id).ok_or_else(|| ... PermissionDenied ...)?` \
         forgery-rejection path"
    );
}

// C4 (#1606) — Bridge outlet-invoke economy wiring
//
// All 3 FFI bridges (PyO3, NAPI, UniFFI) MUST route outlet
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

// Phase 4 PR 4 (#1549 façade deletion) renamed the PyO3 free function
// `py_outlet_invoke` → `#[pymethods] impl PyScp { pub fn outlet_invoke(&self, ...) }`
// delegating to the private `outlet_invoke_impl` free function that
// carries the real wiring. The assertion targets `outlet_invoke_impl` —
// the implementation body — so a refactor cannot silently regress to a
// bypass path even if the public method signature is preserved.
#[test]
fn c4_pyo3_outlet_invoke_routes_through_invoke_outlet_with_economy() {
    assert!(
        fn_body_contains(
            PYO3_OUTLETS_SRC,
            "outlet_invoke_impl",
            "invoke_outlet_with_economy"
        ),
        "PyO3 outlet_invoke_impl must call ContextManager::invoke_outlet_with_economy \
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
    let body = extract_fn_body(PYO3_OUTLETS_SRC, "outlet_invoke_impl")
        .expect("outlet_invoke_impl body must exist");
    assert!(
        body.contains("spending_ucan"),
        "PyO3 outlet_invoke_impl must accept and forward a spending UCAN argument \
         (PR #1606 / C4). Without it, paid outlet invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "PyO3 outlet_invoke_impl must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_outlet_with_economy."
    );
}

// §5.4.5 streaming-native outlet invocation (SCP-OUT-037, C7). The PyO3
// reference bridge's streaming open MUST (a) validate the invocation UCAN at
// the bridge (the §5.4.5 "UCAN check locus" — validated exactly ONCE at open)
// and (b) drive the runtime pump via `Supervisor::open_outlet_stream`. A
// refactor that skipped either would disable authorization or leave the
// producer unwired for Python streaming clients.
#[test]
fn c7_pyo3_outlet_stream_open_validates_ucan_and_reaches_open_outlet_stream() {
    let body = extract_fn_body(PYO3_OUTLET_STREAM_SRC, "outlet_stream_open_impl")
        .expect("outlet_stream_open_impl body must exist");
    assert!(
        body.contains("validate_outlet_ucan"),
        "PyO3 streaming open must validate the invocation UCAN at the bridge \
         (§5.4.5 UCAN check locus) before opening the stream."
    );
    assert!(
        body.contains("open_outlet_stream"),
        "PyO3 streaming open must reach Supervisor::open_outlet_stream — the \
         runtime reserve → off-mailbox pump → settle orchestrator. Without it the \
         §5.4.5 producer is unwired for Python streaming clients."
    );
}

// The streaming cancel MUST use the runtime-derived cursor: the bridge NEVER
// supplies a `next_seq` (a caller-supplied cursor forges `cancel_ack_seq` to
// zero-out or over-bill delivered chunks — §5.4.5 CRITICAL #3). The bridge
// cancel routes through `apply_outlet_cancel_signed`, which reads the live
// emission cursor and signs internally.
#[test]
fn c7_pyo3_outlet_stream_cancel_uses_runtime_derived_cursor() {
    let body = extract_fn_body(PYO3_OUTLET_STREAM_SRC, "outlet_stream_cancel_impl")
        .expect("outlet_stream_cancel_impl body must exist");
    assert!(
        body.contains("apply_outlet_cancel_signed"),
        "PyO3 streaming cancel must route through apply_outlet_cancel_signed \
         (the runtime signs over its OWN live cursor — §5.4.5 CRITICAL #3). A \
         caller-supplied next_seq would forge cancel_ack_seq."
    );
    assert!(
        !body.contains("next_seq"),
        "PyO3 streaming cancel must NOT construct or pass a next_seq — the cursor \
         is runtime-derived (§5.4.5 CRITICAL #3)."
    );
}

// §5.4.5 / §6.2.4 cross-context streaming saga (SCP-OUT-047 pass 1). The PyO3
// reference bridge's streaming-saga OPEN MUST (a) run the §6.2.4 caller-principal
// binding (`enforce_caller_principal_binding`) BEFORE anything irreversible — so
// the saga never observes an unauthenticated caller and no receiver is handed out
// on a mismatch — and (b) drive the runtime producer
// `start_cross_context_streaming_outlet_invocation_saga`. Its RECOVER export MUST
// reach the key-bearing truncated-close driver.
//
// This is the PyO3-reference assertion and is ENFORCED (not ignored — this file
// forbids stale `#[ignore]`s): the PyO3 impl exists as of SCP-OUT-047 pass 1, so
// the gate is live from day one. Pass 3 ADDS the sibling NAPI/UniFFI assertions
// (mirroring the C7/C8 same-context streaming pattern above) when those bridges
// gain the operation.
#[test]
fn out047_pyo3_streaming_saga_open_binds_caller_and_reaches_start_saga() {
    let body = extract_fn_body(PYO3_OUTLET_STREAM_SRC, "outlet_streaming_saga_open_impl")
        .expect("outlet_streaming_saga_open_impl body must exist");
    assert!(
        body.contains("enforce_caller_principal_binding"),
        "PyO3 streaming-saga open must run the §6.2.4 caller-principal binding \
         BEFORE the saga runs — else an unauthenticated caller could open a \
         cross-context stream (ADR-049 §3a channel-auth)."
    );
    assert!(
        body.contains("start_cross_context_streaming_outlet_invocation_saga"),
        "PyO3 streaming-saga open must reach \
         Supervisor::start_cross_context_streaming_outlet_invocation_saga — the \
         runtime producer that returns the receiver at the Commit-transition. \
         Without it the §5.4.5 cross-context streaming producer is unwired."
    );
}

// SCP-OUT-047 pass 1: the PyO3 recover export MUST reach the key-bearing
// truncated-close recovery driver (which reaches
// `Supervisor::recover_streaming_saga_truncated_close`) and MUST authenticate the
// reconnect caller. ENFORCED (PyO3 impl exists); pass 3 adds the sibling
// assertions.
#[test]
fn out047_pyo3_streaming_saga_recover_reaches_truncated_close() {
    let body = extract_fn_body(
        PYO3_OUTLET_STREAM_SRC,
        "outlet_streaming_saga_recover_truncated_close_impl",
    )
    .expect("outlet_streaming_saga_recover_truncated_close_impl body must exist");
    assert!(
        body.contains("drive_recover_truncated_close"),
        "PyO3 streaming-saga recover must reach the shared \
         drive_recover_truncated_close driver (which reaches \
         Supervisor::recover_streaming_saga_truncated_close) — the key-bearing \
         crash-recovery seal (SCP-OUT-046 #136 AC7)."
    );
    assert!(
        body.contains("identity_registry_contains"),
        "PyO3 streaming-saga recover must AUTHENTICATE the reconnect caller \
         (identity-registry check) before sealing — the caller MUST be the \
         channel-authenticated principal (§6.2.4)."
    );
    assert!(
        body.contains("resolve_context_signer"),
        "PyO3 streaming-saga recover must build the target context's Active \
         Signing Key custody signer per-call (resolve_context_signer) before \
         sealing — the recovery receipt is signed through a custody-resolved \
         signer, NEVER an envelope-asserted key (§6.2.4). Structurally pins the \
         FFI-layer signer resolution, not just the runtime seal."
    );
}

// §5.4.5 streaming-native outlet invocation (SCP-OUT-037, C8a). The NAPI
// bridge's streaming open MUST (a) validate the invocation UCAN at the bridge
// (the §5.4.5 "UCAN check locus" — validated exactly ONCE at open) and (b)
// drive the runtime pump via `Supervisor::open_outlet_stream`. A refactor that
// skipped either would disable authorization or leave the producer unwired for
// Node/Bun streaming clients. Mirrors the PyO3 C7 assertion.
#[test]
fn c8_napi_outlet_stream_open_validates_ucan_and_reaches_open_outlet_stream() {
    let body = extract_fn_body(NAPI_OUTLET_STREAM_SRC, "outlet_stream_open_on")
        .expect("outlet_stream_open_on body must exist");
    assert!(
        body.contains("validate_ucan_for_outlet"),
        "NAPI streaming open must validate the invocation UCAN at the bridge \
         (§5.4.5 UCAN check locus) before opening the stream."
    );
    assert!(
        body.contains("open_outlet_stream"),
        "NAPI streaming open must reach Supervisor::open_outlet_stream — the \
         runtime reserve → off-mailbox pump → settle orchestrator. Without it the \
         §5.4.5 producer is unwired for Node/Bun streaming clients."
    );
}

// The NAPI streaming cancel MUST use the runtime-derived cursor: the bridge
// NEVER supplies a `next_seq` (a caller-supplied cursor forges `cancel_ack_seq`
// to zero-out or over-bill delivered chunks — §5.4.5 CRITICAL #3). It routes
// through `apply_outlet_cancel_signed`, which reads the live emission cursor and
// signs internally. Mirrors the PyO3 C7 assertion.
#[test]
fn c8_napi_outlet_stream_cancel_uses_runtime_derived_cursor() {
    let body = extract_fn_body(NAPI_OUTLET_STREAM_SRC, "outlet_stream_cancel_on")
        .expect("outlet_stream_cancel_on body must exist");
    assert!(
        body.contains("apply_outlet_cancel_signed"),
        "NAPI streaming cancel must route through apply_outlet_cancel_signed \
         (the runtime signs over its OWN live cursor — §5.4.5 CRITICAL #3). A \
         caller-supplied next_seq would forge cancel_ack_seq."
    );
    assert!(
        !body.contains("next_seq"),
        "NAPI streaming cancel must NOT construct or pass a next_seq — the cursor \
         is runtime-derived (§5.4.5 CRITICAL #3)."
    );
}

// §5.4.5 streaming-native outlet invocation (SCP-OUT-037, C8b). The UniFFI
// bridge's streaming open MUST (a) validate the invocation UCAN at the bridge
// (the §5.4.5 "UCAN check locus" — validated exactly ONCE at open) and (b) drive
// the runtime pump via `Supervisor::open_outlet_stream`. A refactor that skipped
// either would disable authorization or leave the producer unwired for
// Swift/Kotlin streaming clients. Mirrors the PyO3 C7 / NAPI C8a assertion.
#[test]
fn c8b_uniffi_outlet_stream_open_validates_ucan_and_reaches_open_outlet_stream() {
    let body = extract_fn_body(UNIFFI_OUTLET_STREAM_SRC, "outlet_stream_open_impl")
        .expect("outlet_stream_open_impl body must exist");
    assert!(
        body.contains("validate_outlet_ucan_uniffi"),
        "UniFFI streaming open must validate the invocation UCAN at the bridge \
         (§5.4.5 UCAN check locus) before opening the stream."
    );
    assert!(
        body.contains("open_outlet_stream"),
        "UniFFI streaming open must reach Supervisor::open_outlet_stream — the \
         runtime reserve → off-mailbox pump → settle orchestrator. Without it the \
         §5.4.5 producer is unwired for Swift/Kotlin streaming clients."
    );
}

// The UniFFI streaming cancel MUST use the runtime-derived cursor: the bridge
// NEVER supplies a `next_seq` (a caller-supplied cursor forges `cancel_ack_seq`
// to zero-out or over-bill delivered chunks — §5.4.5 CRITICAL #3). It routes
// through `apply_outlet_cancel_signed`, which reads the live emission cursor and
// signs internally. Mirrors the PyO3 C7 / NAPI C8a assertion.
#[test]
fn c8b_uniffi_outlet_stream_cancel_uses_runtime_derived_cursor() {
    let body = extract_fn_body(UNIFFI_OUTLET_STREAM_SRC, "outlet_stream_cancel_impl")
        .expect("outlet_stream_cancel_impl body must exist");
    assert!(
        body.contains("apply_outlet_cancel_signed"),
        "UniFFI streaming cancel must route through apply_outlet_cancel_signed \
         (the runtime signs over its OWN live cursor — §5.4.5 CRITICAL #3). A \
         caller-supplied next_seq would forge cancel_ack_seq."
    );
    assert!(
        !body.contains("next_seq"),
        "UniFFI streaming cancel must NOT construct or pass a next_seq — the cursor \
         is runtime-derived (§5.4.5 CRITICAL #3)."
    );
}

// Phase 4 PR 4 moved the NAPI free-function export into
// `impl Scp { pub async fn outlet_invoke(&self, ...) }` that delegates to
// `outlet_invoke_on` in `outlets.rs`. The wiring (spending_ucan_jwt parse +
// `invoke_outlet_with_economy` call) lives on the `outlet_invoke_on` helper,
// so that is the function we assert against.
#[test]
fn c4_napi_outlet_invoke_routes_through_invoke_outlet_with_economy() {
    assert!(
        fn_body_contains(
            NAPI_OUTLETS_SRC,
            "outlet_invoke_on",
            "invoke_outlet_with_economy"
        ),
        "NAPI outlet_invoke_on must call ContextManager::invoke_outlet_with_economy \
         (PR #1606 / C4). The previous bypass path called \
         try_consume_hard_rate_limit against the bridge-owned outlet registry, \
         disabling per-invocation pricing, spending UCAN, velocity tracking, \
         and budget enforcement for Node clients."
    );
}

#[test]
fn c4_napi_outlet_invoke_accepts_spending_ucan() {
    let body = extract_fn_body(NAPI_OUTLETS_SRC, "outlet_invoke_on")
        .expect("NAPI outlet_invoke_on body must exist");
    assert!(
        body.contains("spending_ucan_jwt"),
        "NAPI outlet_invoke_on must accept and forward a spending_ucan_jwt argument \
         (PR #1606 / C4). Without it, paid outlet invocations skip the §19.5 \
         AND-composition check."
    );
    assert!(
        body.contains("parse_ucan"),
        "NAPI outlet_invoke_on must parse the spending UCAN JWT into a UcanToken \
         before passing it to invoke_outlet_with_economy."
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

/// ADR-029 §2 sync-state keys: the three writers of
/// `sync/{context_id}/last_relay_contact`. A full reconnection writes it after
/// it clears `needs_reconnect`, a wake writes it after Phases 2 and 4 fed the
/// context's buffer to the actor, and live delivery writes it after the actor
/// accepts an envelope. napi's live subscription delivers through the shared
/// `deliver_live_envelope`. Every writer goes through `record_relay_contact`.
#[test]
fn last_relay_contact_writers_wired() {
    for (src, caller, callee) in [
        (
            RECONNECT_DRIVER_SRC,
            "reconnect_contexts",
            "clear_and_record_contact(",
        ),
        (
            RECONNECT_DRIVER_SRC,
            "clear_and_record_contact",
            "record_relay_contact(",
        ),
        (
            RECONNECT_DRIVER_SRC,
            "wake_pull_context",
            "record_relay_contact(",
        ),
        (
            RECONNECT_DRIVER_SRC,
            "record_relay_contact",
            "store_last_relay_contact(",
        ),
        (
            NAPI_CONTEXT_SRC,
            "context_subscribe_on",
            "deliver_live_envelope(",
        ),
        (
            RECONNECT_DRIVER_SRC,
            "deliver_live_envelope",
            "record_relay_contact(",
        ),
    ] {
        assert!(
            fn_body_contains(src, caller, callee),
            "{caller} must call {callee} (ADR-029 §2 last_relay_contact writers)"
        );
    }
    // The reconnection writes only after the flag is cleared.
    let body = extract_fn_body(RECONNECT_DRIVER_SRC, "clear_and_record_contact")
        .expect("clear_and_record_contact not found in reconnect.rs");
    let clear = body.find("clear_needs_reconnect(").expect("no clear call");
    let write = body.find("record_relay_contact(").expect("no write call");
    assert!(
        clear < write,
        "clear_and_record_contact must clear needs_reconnect before it writes the contact"
    );
    // A wake writes only after both deliveries, so a context the deadline
    // stops mid-delivery keeps its stored contact.
    let body = extract_fn_body(RECONNECT_DRIVER_SRC, "wake_pull_context")
        .expect("wake_pull_context not found in reconnect.rs");
    let write = body.find("record_relay_contact(").expect("no write call");
    for delivery in ["deliver_commit_blobs_until_steady(", "refeed_buffer("] {
        let at = body
            .find(delivery)
            .unwrap_or_else(|| panic!("wake_pull_context must call {delivery}"));
        assert!(
            at < write,
            "wake_pull_context must call {delivery} before it writes the contact"
        );
    }
}

/// ADR-029 Implementation and ADR-049 Decision 9: create, Welcome join, and
/// import write the context's first `last_relay_contact` through
/// `persist_first_state`, which persists the first snapshot fail-closed, and
/// each calls it before it spawns the actor. Restore writes nothing, so the
/// stored contact keeps measuring the time offline.
#[test]
fn first_relay_contact_written_before_the_actor_spawns() {
    for (src, caller, callee) in [
        (
            LIFECYCLE_HELPERS_SRC,
            "persist_first_state",
            "first_state_writes(",
        ),
        (
            LIFECYCLE_HELPERS_SRC,
            "first_state_writes",
            "write_first_state(",
        ),
        (
            LIFECYCLE_HELPERS_SRC,
            "write_first_state",
            "store_last_relay_contact(",
        ),
        (
            LIFECYCLE_HELPERS_SRC,
            "write_first_state",
            "persist_context(",
        ),
    ] {
        assert!(
            fn_body_contains(src, caller, callee),
            "{caller} must call {callee} (ADR-029 first last_relay_contact)"
        );
    }
    for (src, entry) in [
        (LIFECYCLE_HELPERS_SRC, "create_context"),
        (LIFECYCLE_HELPERS_SRC, "import_context"),
        (SUPERVISOR_SRC, "spawn_actor_from_welcome"),
    ] {
        let body = extract_fn_body(src, entry).unwrap_or_else(|| panic!("{entry} not found"));
        let persist = body
            .find("persist_first_state(")
            .unwrap_or_else(|| panic!("{entry} must call persist_first_state"));
        let spawn = body
            .find("spawn_actor_with_state(")
            .unwrap_or_else(|| panic!("{entry} must call spawn_actor_with_state"));
        assert!(
            persist < spawn,
            "{entry} must persist its first state before it spawns the actor"
        );
    }
    for callee in ["persist_first_state(", "store_last_relay_contact("] {
        assert!(
            !fn_body_contains(LIFECYCLE_HELPERS_SRC, "restore_context", callee),
            "restore_context must not call {callee}"
        );
    }
}

/// ADR-029 Implementation and ADR-049 Decision 9: the first contact is
/// written before the first snapshot, each bootstrap commits its first-state
/// guard only after the actor spawned, and the create arm and the migration
/// refuse a running context's id before they write.
#[test]
fn first_state_is_ordered_guarded_and_refused_over_a_running_context() {
    let body = extract_fn_body(LIFECYCLE_HELPERS_SRC, "write_first_state")
        .expect("write_first_state not found");
    let contact = body
        .find("store_last_relay_contact(")
        .expect("no contact write");
    let snapshot = body.find("persist_context(").expect("no snapshot write");
    assert!(
        contact < snapshot,
        "write_first_state must write the contact before the snapshot"
    );
    for (src, entry) in [
        (LIFECYCLE_HELPERS_SRC, "create_context"),
        (LIFECYCLE_HELPERS_SRC, "import_context"),
        (SUPERVISOR_SRC, "spawn_actor_from_welcome"),
    ] {
        let body = extract_fn_body(src, entry).unwrap_or_else(|| panic!("{entry} not found"));
        let spawn = body
            .find("spawn_actor_with_state(")
            .unwrap_or_else(|| panic!("{entry} must call spawn_actor_with_state"));
        let commit = body
            .find(".commit()")
            .unwrap_or_else(|| panic!("{entry} must commit its first-state guard"));
        assert!(
            spawn < commit,
            "{entry} must commit its first-state guard only after the spawn"
        );
    }
    let body = extract_fn_body(SUPERVISOR_SRC, "dispatch_lifecycle_direct")
        .expect("dispatch_lifecycle_direct not found");
    let refusal = body
        .find("self.lookup(&context_id).is_some()")
        .expect("the create arm must refuse a running context's id");
    let guard = body
        .find("FirstStateRollback::new(")
        .expect("the create arm must build its guard");
    assert!(
        refusal < guard,
        "the create arm must refuse a running id before it builds its guard"
    );
    let body = extract_fn_body(MANAGER_SRC, "execute_propose_context_migration")
        .expect("execute_propose_context_migration not found");
    let lock = body
        .find("guard: bootstrap_guard")
        .expect("the migration must hold the bootstrap guard its executor reserved");
    let transition = body
        .find("transition_to(&ContextState::MigratingOut)")
        .expect("the migration must move its source to MigratingOut");
    assert!(
        lock < transition,
        "the migration must hold bootstrap_spawn_lock before it changes the source"
    );
    assert!(
        !body.contains("try_lock_bootstrap_spawn()") && !body.contains("FirstStateRollback::new("),
        "the migration must not take the lock or the claim itself: its executor reserved both \
         before its first record"
    );
    let lookup = body
        .find("lookup(&destination_context_id)")
        .expect("the migration must look up its destination");
    let create = body
        .find("lifecycle_helpers::create_context(")
        .expect("the migration must create its destination");
    assert!(
        lock < lookup && lookup < create,
        "the migration must check its destination under the lock before it creates"
    );
}

/// ADR-049 Decision 9: a migration's busy `bootstrap_spawn_lock` or
/// destination claim is decided before the propose or vote that executes it
/// records anything. Each path reserves the migration's bootstrap ahead of
/// each record it precedes (the freeze resolution, the proposal and its
/// rate-limit timestamp, the precheck's deadline resolution, or the vote),
/// with no await before the first of them, and hands the reservation to the execution, which drops it when the
/// action does not execute, so a retryable `ActorBusy` leaves nothing
/// behind. The direct-execute path reserves before its replay marker, and
/// the migration takes the reservation as a required argument.
#[test]
fn a_migration_takes_the_bootstrap_lock_before_its_proposal_or_vote_is_recorded() {
    const RESERVE: &str = "MigrationBootstrap::if_executed(";
    let compact = |text: &str| text.split_whitespace().collect::<String>();
    for (entry, reservation, records) in [
        (
            "propose_governance_action_inner",
            0,
            &[
                "check_and_resolve_expired_freezes(cell,",
                ".engine_mut().propose_signed(",
                ".proposal_timestamps_mut()",
            ][..],
        ),
        (
            "vote_on_proposal_inner",
            0,
            &[".engine_mut().precheck_vote("][..],
        ),
        (
            "vote_on_proposal_inner",
            1,
            &[
                "engine.approve_signed(proposal_id,voter_did,&gov_ctx,vote)",
                "engine.reject_signed(proposal_id,voter_did,&gov_ctx,vote)",
            ][..],
        ),
    ] {
        let body = compact(
            &extract_fn_body(MANAGER_SRC, entry).unwrap_or_else(|| panic!("{entry} not found")),
        );
        let reserved = body.match_indices(RESERVE).nth(reservation).map_or_else(
            || panic!("{entry} must reserve the migration's bootstrap"),
            |(at, _)| at,
        );
        let mut first_record = body.len();
        for record in records {
            let recorded = body[reserved..].find(record).map_or_else(
                || panic!("{entry} must record through {record}"),
                |at| reserved + at,
            );
            first_record = first_record.min(recorded);
            assert!(
                !body[..reserved].contains(record),
                "{entry} must reserve the migration's bootstrap before {record}"
            );
        }
        // Held from the reservation on, the guard may span an await after
        // the first record, never one before it.
        assert!(
            !body[reserved..first_record].contains(".await"),
            "{entry} must not await between the reservation and its first record"
        );
        let executed = body[reserved..]
            .find("execute_governance_action(")
            .map_or_else(
                || panic!("{entry} must execute the approved action"),
                |at| reserved + at,
            );
        let call = &body[executed..];
        let call = &call[..call.find(".await").expect("the execute call is awaited")];
        assert!(
            call.contains(",bootstrap,"),
            "{entry} must hand its reservation to the execution"
        );
        assert!(
            body[executed..].contains("drop(bootstrap)"),
            "{entry} must release a reservation the action does not execute with"
        );
    }
    let body = extract_fn_body(MANAGER_SRC, "execute_governance_action")
        .expect("execute_governance_action not found");
    let reserved = body
        .find("MigrationBootstrap::for_migration(")
        .expect("the direct-execute path must reserve a migration's bootstrap");
    let marker = body
        .find("begin_class_s(")
        .expect("execute_governance_action must record its replay marker");
    assert!(
        reserved < marker,
        "the direct-execute path must reserve before its replay marker"
    );
    let body = extract_fn_body(MANAGER_SRC, "reserve").expect("MigrationBootstrap::reserve");
    let lock = body
        .find("try_lock_bootstrap_spawn()")
        .expect("the reservation try-locks bootstrap_spawn_lock");
    let claim = body
        .find("FirstStateRollback::new(")
        .expect("the reservation claims the destination's first state");
    assert!(
        lock < claim && !body.contains(".await"),
        "the reservation is try-locked, never awaited, and claims under the lock"
    );
    let signature = MANAGER_SRC
        .find("pub fn execute_propose_context_migration<")
        .map(|at| &MANAGER_SRC[at..])
        .and_then(|rest| rest.find(") ->").map(|end| &rest[..end]))
        .expect("execute_propose_context_migration signature");
    assert!(
        compact(signature).contains("bootstrap:MigrationBootstrap,"),
        "the migration must take its reservation as a required argument"
    );
}

/// ADR-049 Decision 9 lock order: each bootstrap owns a first-state guard
/// and rolls it back only after it released `bootstrap_spawn_lock`, since the
/// rollback waits for abandoned writes before it retakes the lock; the
/// migration, in an actor turn, rolls back without waiting for the lock.
#[test]
fn every_first_state_owner_rolls_back_after_releasing_the_bootstrap_lock() {
    for (entry, owner, rollback) in [
        (
            "dispatch_lifecycle_direct",
            SUPERVISOR_SRC,
            ".rollback(self.bootstrap_spawn_lock.lock())",
        ),
        (
            "standing_context",
            SUPERVISOR_SRC,
            ".rollback(self.bootstrap_spawn_lock.lock())",
        ),
        (
            "spawn_actor_from_welcome",
            SUPERVISOR_SRC,
            ".rollback(self.bootstrap_spawn_lock.lock())",
        ),
    ] {
        let body = extract_fn_body(owner, entry).unwrap_or_else(|| panic!("{entry} not found"));
        for callee in ["FirstStateRollback::new(", rollback] {
            assert!(
                body.contains(callee),
                "{entry} must own a first-state guard and roll it back ({callee})"
            );
        }
        // Every rollback runs after the owner released `bootstrap_spawn_lock`:
        // the rollback waits for abandoned writes, which can take its whole
        // drain budget, and retakes the lock only for the restores.
        let mut searched = 0;
        while let Some(found) = body[searched..].find(rollback) {
            let at = searched + found;
            let taken = body[..at]
                .rfind("let bootstrap_guard =")
                .unwrap_or_else(|| panic!("{entry} must take bootstrap_spawn_lock"));
            let released = body[..at].rfind("drop(bootstrap_guard)");
            assert!(
                released.is_some_and(|released| released > taken),
                "{entry} must release bootstrap_spawn_lock before it rolls back"
            );
            searched = at + rollback.len();
        }
    }
    // The migration runs in an actor turn under the guard its executor
    // reserved with the destination's claim, and rolls back while holding
    // it, so it never waits for the lock and never returns a busy error
    // after the governance call recorded its proposal or vote.
    let body = extract_fn_body(MANAGER_SRC, "execute_propose_context_migration")
        .expect("execute_propose_context_migration not found");
    let rollback = body
        .find(".rollback_with_guard(bootstrap_guard)")
        .expect("the migration must roll back under its reserved guard");
    assert!(
        !body[..rollback].contains("drop(bootstrap_guard)"),
        "the migration must hold bootstrap_spawn_lock through its rollback"
    );
    assert!(
        extract_fn_body(MANAGER_SRC, "reserve")
            .is_some_and(|reserve| reserve.contains("FirstStateRollback::new(")),
        "the migration's first-state guard is built by its reservation"
    );
}

/// ADR-049 Decision 9 and ADR-029 Implementation: the first-state writes run
/// on a tracked task the rollback waits for before it reads what was touched,
/// a dropped guard undoes under `bootstrap_spawn_lock`, and each bootstrap
/// refreshes its gauges and arms its TTL timer only after it releases that
/// lock.
#[test]
fn first_state_writes_are_drained_and_finalize_runs_after_the_bootstrap_lock() {
    let body = extract_fn_body(LIFECYCLE_HELPERS_SRC, "persist_first_state")
        .expect("persist_first_state not found");
    let busy = body
        .find("writes_idle.send_replace(false)")
        .expect("persist_first_state must mark its writes running");
    let writes = body
        .find("first_state_writes(")
        .expect("persist_first_state must build its writes with first_state_writes");
    let spawn = body
        .find("spawn_tracked(")
        .expect("persist_first_state must run its writes on a tracked task");
    assert!(
        busy < writes && writes < spawn,
        "persist_first_state must mark its writes running before the task can start"
    );
    // The idle guard is built before the future, so a task dropped before its
    // first poll still marks the writes idle, and the writes select on the
    // shutdown token, so a hung write cannot hold shutdown's task drain.
    let body = extract_fn_body(LIFECYCLE_HELPERS_SRC, "first_state_writes")
        .expect("first_state_writes not found");
    let idle_guard = body
        .find("WritesIdleOnDrop(")
        .expect("the writes must mark themselves idle however they end");
    let future = body
        .find("async move")
        .expect("first_state_writes builds a future");
    assert!(
        idle_guard < future,
        "first_state_writes must build its idle guard before the future"
    );
    for step in ["select!", "shutdown.cancelled()", "abandoned"] {
        assert!(
            body[future..].contains(step),
            "the writes must end a bounded time after shutdown begins ({step})"
        );
    }
    for (owner, entry) in [
        (SUPERVISOR_SRC, "dispatch_lifecycle_direct"),
        (SUPERVISOR_SRC, "standing_context"),
        (SUPERVISOR_SRC, "spawn_actor_from_welcome"),
        (MANAGER_SRC, "execute_propose_context_migration"),
    ] {
        let body = extract_fn_body(owner, entry).unwrap_or_else(|| panic!("{entry} not found"));
        let release = body
            .find("drop(bootstrap_guard)")
            .unwrap_or_else(|| panic!("{entry} must release bootstrap_spawn_lock"));
        // Anchored on the `deps` argument: the migration also hashes with
        // a `finalize()` before it takes the lock.
        let finalize = body
            .find(".finalize(&deps")
            .or_else(|| body.find(".finalize(deps"))
            .unwrap_or_else(|| panic!("{entry} must finalize its spawned context"));
        assert!(
            release < finalize,
            "{entry} must finalize only after it releases bootstrap_spawn_lock"
        );
    }
    for (src, entry) in [
        (LIFECYCLE_HELPERS_SRC, "create_context"),
        (LIFECYCLE_HELPERS_SRC, "import_context"),
    ] {
        let body = extract_fn_body(src, entry).unwrap_or_else(|| panic!("{entry} not found"));
        assert!(
            !body.contains("update_context_gauges(") && !body.contains("dispatch_start_ttl_timer("),
            "{entry} must leave the gauge refresh and TTL timer to SpawnedContext::finalize"
        );
    }
}

/// ADR-049 Decision 9: every first-state rollback waits for the writes task
/// before it reads what was touched, with `bootstrap_spawn_lock` released,
/// and undoes under the lock; an in-turn rollback try-locks, and a dropped
/// guard's undo runs on a tracked task that takes the lock.
#[test]
fn first_state_rollbacks_drain_before_they_take_the_bootstrap_lock() {
    for entry in ["rollback", "rollback_with_guard"] {
        let body = extract_fn_body(LIFECYCLE_HELPERS_SRC, entry)
            .unwrap_or_else(|| panic!("{entry} not found"));
        let drain = body
            .find("drain_writes()")
            .unwrap_or_else(|| panic!("{entry} must wait for the writes task"));
        let touched = body
            .find("touched()")
            .unwrap_or_else(|| panic!("{entry} must read what was touched"));
        let undo = body
            .find("undo_locked()")
            .unwrap_or_else(|| panic!("{entry} must undo"));
        assert!(
            drain < touched && touched < undo,
            "{entry} must wait for the writes task before it reads what was touched"
        );
    }
    let body = extract_fn_body(LIFECYCLE_HELPERS_SRC, "rollback").expect("rollback not found");
    let drain = body.find("drain_writes()").expect("rollback drains");
    let relock = body
        .find("relock.await")
        .expect("rollback must retake bootstrap_spawn_lock");
    let undo = body.find("undo_locked()").expect("rollback undoes");
    assert!(
        drain < relock && relock < undo,
        "rollback must drain with the lock released and undo under it"
    );
    let body = extract_fn_body(LIFECYCLE_HELPERS_SRC, "rollback_with_guard")
        .expect("rollback_with_guard not found");
    assert!(
        !body.contains("try_lock_bootstrap_spawn()")
            && !body.contains("spawn_under_bootstrap_spawn_lock(")
            && !body.contains(".lock()"),
        "the in-turn rollback must undo under the guard it was handed, never take the lock"
    );
    let undo = body
        .find("undo_locked()")
        .expect("rollback_with_guard undoes");
    let released = body
        .find("drop(guard)")
        .expect("rollback_with_guard must release its guard");
    let unclaimed = body
        .find("release_claim()")
        .expect("rollback_with_guard must release its claim");
    assert!(
        undo < released && released < unclaimed,
        "the in-turn rollback must undo before it releases the lock, then the claim"
    );
    let guard_drop = LIFECYCLE_HELPERS_SRC
        .find("impl Drop for FirstStateRollback ")
        .expect("FirstStateRollback must implement Drop");
    let body = extract_fn_body(&LIFECYCLE_HELPERS_SRC[guard_drop..], "drop")
        .expect("FirstStateRollback::drop not found");
    let drain = body
        .find("drain_writes()")
        .expect("the dropped guard must wait for its writes");
    let lock = body
        .find("spawn_under_bootstrap_spawn_lock(")
        .expect("the dropped guard's undo must run under bootstrap_spawn_lock");
    let undo = body
        .find("finish_deferred_undo()")
        .expect("the dropped guard must undo");
    assert!(
        drain < lock && lock < undo,
        "the dropped guard must drain before the lock and undo under it"
    );
    let handle_src =
        include_str!("../../../../crates/scp-runtime/src/context/supervisor/handle.rs");
    let body = extract_fn_body(handle_src, "spawn_under_bootstrap_spawn_lock")
        .expect("spawn_under_bootstrap_spawn_lock not found");
    let tracked = body
        .find("spawn_tracked(")
        .expect("the work runs on a tracked task");
    let before = body
        .find("before_lock.await")
        .expect("the pre-lock work runs");
    let lock = body
        .find("lock_owned().await")
        .expect("the task takes the lock");
    let under = body
        .find("under_lock().await")
        .expect("the locked work runs");
    assert!(
        tracked < before && before < lock && lock < under,
        "spawn_under_bootstrap_spawn_lock must run the pre-lock work, then the locked work \
         under the lock, on a tracked task"
    );
}

/// ADR-029 §2 push-wake pull mode step 5: a full reconnection sends the
/// sender-key answers a wake left queued. `reconnect_contexts` passes each
/// context's outcome through `send_queued_answers`, which calls
/// `Supervisor::send_queued_sender_keys`, which dispatches
/// `MessagingCommand::SendQueuedSenderKeys` to the handler that drains the
/// queue.
#[test]
fn full_reconnect_sends_the_queued_sender_key_answers() {
    for (src, caller, callee) in [
        (
            RECONNECT_DRIVER_SRC,
            "reconnect_contexts",
            "send_queued_answers(",
        ),
        (
            RECONNECT_DRIVER_SRC,
            "send_queued_answers",
            ".send_queued_sender_keys(",
        ),
        (
            SUPERVISOR_SRC,
            "send_queued_sender_keys",
            "MessagingCommand::SendQueuedSenderKeys",
        ),
        (
            HANDLERS_MESSAGING_SRC,
            "handle_send_queued_sender_keys",
            "drain_and_deliver_sender_keys(",
        ),
    ] {
        assert!(
            fn_body_contains(src, caller, callee),
            "{caller} must call {callee} (ADR-029 §2 push-wake pull mode step 5)"
        );
    }
}

/// ADR-029 §2 push-wake pull mode step 5: every blob a wake feeds the actor
/// carries `DeliveryMode::PullOnly` from the pull to the handler, and the
/// handler sends queued sender-key answers only in `DeliveryMode::Live`.
/// `wake_pull_context` passes `DeliveryMode::PullOnly` to both feeds, each
/// feed passes its `mode` to `Supervisor::deliver_commit_blob`, which puts it
/// in `MessagingCommand::DeliverIncoming`; the messaging dispatch hands it to
/// `handle_deliver_incoming`, whose `Live` arm alone calls
/// `drain_and_deliver_sender_keys`.
#[test]
fn push_wake_delivers_in_pull_only_mode() {
    let wake = extract_fn_body(RECONNECT_DRIVER_SRC, "wake_pull_context")
        .expect("wake_pull_context not found in reconnect.rs");
    for feed in ["deliver_commit_blobs_until_steady", "refeed_buffer"] {
        let args =
            call_args(&wake, feed).unwrap_or_else(|| panic!("wake_pull_context must call {feed}"));
        assert!(
            args.contains("DeliveryMode::PullOnly") && !args.contains("DeliveryMode::Live"),
            "wake_pull_context must pass DeliveryMode::PullOnly to {feed}: {args}"
        );
    }
    for feed in ["deliver_commit_blobs_until_steady", "refeed_buffer"] {
        let signature = extract_fn_signature(RECONNECT_DRIVER_SRC, feed)
            .unwrap_or_else(|| panic!("{feed} not found in reconnect.rs"));
        assert!(
            signature.contains("mode: DeliveryMode"),
            "{feed} must take the delivery mode: {signature}"
        );
        let body = extract_fn_body(RECONNECT_DRIVER_SRC, feed)
            .unwrap_or_else(|| panic!("{feed} not found in reconnect.rs"));
        let args = call_args(&body, ".deliver_commit_blob")
            .unwrap_or_else(|| panic!("{feed} must call deliver_commit_blob"));
        assert!(
            args.contains("mode") && !args.contains("DeliveryMode::"),
            "{feed} must pass its own mode to deliver_commit_blob: {args}"
        );
    }
    let deliver = extract_fn_body(SUPERVISOR_SRC, "deliver_commit_blob")
        .expect("Supervisor::deliver_commit_blob exists");
    let command = &deliver[deliver
        .find("MessagingCommand::DeliverIncoming")
        .expect("deliver_commit_blob must build DeliverIncoming")..];
    assert!(
        command[..command.find('}').expect("a struct literal")].contains("mode"),
        "Supervisor::deliver_commit_blob must put its mode in DeliverIncoming"
    );
    let dispatch = extract_fn_body(HANDLERS_MESSAGING_SRC, "dispatch")
        .expect("the messaging handler dispatch exists");
    assert!(
        dispatch.contains(
            "handle_deliver_incoming(cell, deps, &context_id, &envelope_bytes, mode, reply)"
        ),
        "the messaging dispatch must hand the command's mode to handle_deliver_incoming"
    );
    let handler = extract_fn_body(HANDLERS_MESSAGING_SRC, "handle_deliver_incoming")
        .expect("handle_deliver_incoming exists");
    assert_eq!(
        handler.matches("drain_and_deliver_sender_keys(").count(),
        1,
        "handle_deliver_incoming must send queued answers on one arm only"
    );
    let live = handler
        .find("DeliveryMode::Live =>")
        .expect("handle_deliver_incoming must match DeliveryMode::Live");
    let drain = handler
        .find("drain_and_deliver_sender_keys(")
        .expect("the Live arm drains");
    let pull_only = handler
        .find("DeliveryMode::PullOnly => {}")
        .expect("the PullOnly arm must do nothing");
    assert!(
        live < drain && drain < pull_only,
        "only the DeliveryMode::Live arm may send queued sender-key answers"
    );
}

/// ADR-029 §2 push-wake pull mode step 4: the wake's targets come from each
/// resident actor. `pull_on_wake` calls `Supervisor::wake_targets`, which sends
/// `PushCommand::WakeTarget` through `dispatch_push_command` to every known
/// context; `handlers::push::dispatch` answers it from
/// `push_helpers::wake_target`.
#[test]
fn push_wake_targets_reach_push_helpers() {
    assert!(
        fn_body_contains(PUSH_WAKE_SRC, "pull_on_wake", ".wake_targets()"),
        "pull_on_wake must list its targets through Supervisor::wake_targets"
    );
    assert!(
        fn_body_contains(
            PUSH_WAKE_SRC,
            "pull_on_wake",
            ".restore_unrestored_contexts()"
        ),
        "pull_on_wake must restore every persisted Active context before it lists targets"
    );
    for step in [
        "self.known_context_ids()",
        ".dispatch_push_command(",
        "PushCommand::WakeTarget",
    ] {
        assert!(
            fn_body_contains(SUPERVISOR_SRC, "wake_targets", step),
            "Supervisor::wake_targets must contain `{step}`"
        );
    }
    assert!(
        fn_body_contains(
            HANDLERS_PUSH_SRC,
            "dispatch",
            "push_helpers::wake_target(state)"
        ),
        "handlers::push::dispatch must answer PushCommand::WakeTarget from push_helpers::wake_target"
    );
    // §9.10.4.1 "Subscription" and ADR-029 §2: a push wake pulls the shared
    // and current routing IDs only. A routing ID the member rotated away from
    // is queried by reconnect catch-up alone, so the wake target reads no
    // rotation state.
    let wake =
        extract_fn_body(PUSH_HELPERS_SRC, "wake_target").expect("push_helpers::wake_target exists");
    for forbidden in ["pseudonym_rotation", "query_only", "previous"] {
        assert!(
            !wake.contains(forbidden),
            "push_helpers::wake_target must read no previous routing ID, found `{forbidden}`"
        );
    }
}

/// ADR-029 §2 push-wake pull mode: a silent push reaches the relay
/// catch-up path (Phase 1 pull, Phase 2 commit replay, Phase 4 re-feed) and
/// nothing that signs or publishes. `handle_wake` → `pull_on_wake` →
/// `wake_pull_contexts` → `wake_pull_context` → `pull_buffered`,
/// `deliver_commit_blobs_until_steady`, `refeed_buffer`; none of the pull
/// functions builds a checkpoint or issues an MLS Update, and neither wake
/// pull signature accepts a `CommandSigner`.
#[test]
fn push_wake_pulls_without_signing() {
    for (src, caller, callee) in [
        (PUSH_WAKE_SRC, "handle_wake", "pull_on_wake("),
        (PUSH_WAKE_SRC, "pull_on_wake", "wake_pull_contexts("),
        (PUSH_WAKE_SRC, "pull_on_wake", "dial_relays("),
        (
            RECONNECT_DRIVER_SRC,
            "wake_pull_contexts",
            "wake_pull_context(",
        ),
        (RECONNECT_DRIVER_SRC, "wake_pull_context", "pull_buffered("),
        (
            RECONNECT_DRIVER_SRC,
            "wake_pull_context",
            "record_relay_contact(",
        ),
        (
            RECONNECT_DRIVER_SRC,
            "wake_pull_context",
            "deliver_commit_blobs_until_steady(",
        ),
        (RECONNECT_DRIVER_SRC, "wake_pull_context", "refeed_buffer("),
        (
            RECONNECT_DRIVER_SRC,
            "deliver_commit_blobs_until_steady",
            ".deliver_commit_blob(",
        ),
        (
            RECONNECT_DRIVER_SRC,
            "refeed_buffer",
            ".deliver_commit_blob(",
        ),
    ] {
        assert!(
            fn_body_contains(src, caller, callee),
            "{caller} must call {callee} (ADR-029 §2 push-wake pull mode)"
        );
    }

    for fn_name in [
        "wake_pull_contexts",
        "wake_pull_context",
        "pull_buffered",
        "deliver_commit_blobs_until_steady",
        "refeed_buffer",
    ] {
        for forbidden in [
            "build_local_checkpoint",
            "issue_mls_update",
            "CommandSigner",
        ] {
            assert!(
                !fn_body_contains(RECONNECT_DRIVER_SRC, fn_name, forbidden),
                "{fn_name} must not reach {forbidden}: a wake pulls and \
                 publishes nothing (ADR-029 §2)"
            );
        }
    }
    for fn_name in ["wake_pull_contexts", "wake_pull_context"] {
        let signature = extract_fn_signature(RECONNECT_DRIVER_SRC, fn_name)
            .unwrap_or_else(|| panic!("{fn_name} not found in reconnect.rs"));
        assert!(
            !signature.contains("CommandSigner"),
            "{fn_name} must take no CommandSigner (ADR-029 §2): {signature}"
        );
    }
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

/// The `Supervisor` `ContextEvent` channel (ADR-049 §12a) must be exposed and
/// enabled on every production bridge. The supervisor exposes the public
/// subscribe surface, and each bridge's production `Supervisor` construction
/// enables the channel, so `subscribe_events()` yields a receiver on every
/// bridge.
#[test]
fn context_event_channel_enabled_on_every_bridge() {
    // The producer seam: after ADR-049 the event channel moved off the deleted
    // ContextManager onto the Supervisor, so the live symbol is
    // `Supervisor::subscribe_events` (the former
    // `ContextManager::with_event_channel` accessor is gone).
    let supervisor_src =
        include_str!("../../../../crates/scp-runtime/src/context/supervisor/supervisor.rs");
    assert!(
        supervisor_src.contains("fn subscribe_events"),
        "Supervisor must expose subscribe_events (otherwise no Rust caller can subscribe)"
    );

    // PyO3 reference bridge.
    let ffi_runtime_src = include_str!("../../../../crates/scp-ffi/src/runtime.rs");
    assert!(
        ffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && ffi_runtime_src.contains("Some(event_tx)"),
        "PyO3 production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None)"
    );

    // NAPI bridge (Node.js/Bun).
    let napi_runtime_src = include_str!("../../../../crates/scp-ffi/napi/src/runtime.rs");
    assert!(
        napi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && napi_runtime_src.contains("Some(event_tx)"),
        "NAPI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None)"
    );

    // UniFFI bridge (Swift/Kotlin).
    let uniffi_runtime_src = include_str!("../../../../crates/scp-ffi/uniffi/src/runtime.rs");
    assert!(
        uniffi_runtime_src.contains("EVENT_CHANNEL_CAPACITY")
            && uniffi_runtime_src.contains("Some(event_tx)"),
        "UniFFI production Supervisor construction must enable the event channel \
         (otherwise subscribe_events yields None)"
    );
}

// ===========================================================================
// MCP resource subscriptions — advertised capability must be backed
// ===========================================================================

/// `resources/subscribe` MUST be backed by a real runtime event source on
/// every bridge.
///
/// The original defect: `McpServer` hard-coded `ResourceServerCapability {
/// subscribe: true }` at `initialize` while `ContextProvider::subscribe_resource`
/// returned `Ok(())` and did nothing on PyO3/UniFFI (NAPI returned `Err`). A
/// client received a successful subscription and then never received a single
/// `notifications/resources/updated` — a false guarantee on a shipped path,
/// plus a three-way divergence between bridges.
///
/// # What the types enforce and what this test checks
///
/// One crate-private `scp-mcp` constructor returns `(McpServer,
/// ContextEventPump)` and is the *only* code that sets the advertisement flag.
/// A server that advertises the capability and a pump that delivers it are one
/// value produced by one call, so:
///
/// - the advertisement cannot be hard-coded — no literal reaches the field;
/// - it cannot be enabled without a receiver — there is no other constructor
///   that sets it;
/// - the pump cannot be separated from the server outside `scp-mcp` — the
///   `McpServerForTransport` bundle is opaque, only a transport can consume it,
///   and the pair constructor `with_event_source` is public only under
///   `scp-mcp`'s `testing` feature, which no shipped artifact resolves.
///
/// The compiler holds those properties, so this test does not restate them as
/// source-text checks. It checks part of what the type system cannot see:
/// that each bridge's `mcp_server_bundle` *sources* its receiver from the
/// Supervisor and passes it to `McpServer::with_optional_event_source`,
/// rather than passing `None` and honestly-but-uselessly advertising nothing,
/// and that the bridge's serve function builds a server through the pinned
/// `mcp_server_bundle` call over the instance its provider reads. It does not
/// check that this server is the one the serve function passes to the
/// transport, and every count it makes covers the bridge's own file only.
#[test]
fn mcp_resource_subscriptions_are_backed_by_a_real_event_source() {
    // Every bridge must obtain the Supervisor receiver and hand it to
    // `McpServer::with_optional_event_source`, the constructor that pairs the
    // flag with the pump. A bridge that passed `None` to that constructor
    // would compile and serve, but would advertise `resources.subscribe:
    // false` forever, and the type system cannot tell that `None` from a
    // Supervisor that has no receiver to give.
    let pyo3_mcp_src = include_str!("../../../../crates/scp-ffi/src/mcp.rs");
    let napi_mcp_src = include_str!("../../../../crates/scp-ffi/napi/src/mcp.rs");
    let uniffi_mcp_src = include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs");
    // Each bridge's accessor for its own instance's Supervisor, called on the
    // `mcp_server_bundle` parameter `bi`: the scrutinee of the `match` that
    // binds the receiver. Then the serve path's pins: the statements that bind
    // the serve function's own instance, build the provider over that
    // instance, and pass that same instance to `mcp_server_bundle`.
    for (bridge, src, serve_fn, supervisor_of_bi, serve_path) in [
        (
            "PyO3",
            pyo3_mcp_src,
            "py_mcp_serve",
            "crate::runtime::supervisor(bi)",
            PYO3_SERVE_PATH,
        ),
        (
            "NAPI",
            napi_mcp_src,
            "mcp_server_create_on",
            "crate::runtime::supervisor(bi)",
            NAPI_SERVE_PATH,
        ),
        (
            "UniFFI",
            uniffi_mcp_src,
            "mcp_server_create",
            "bi.context_manager_or_error()",
            UNIFFI_SERVE_PATH,
        ),
    ] {
        // Search the PRODUCTION code only: every `#[cfg(test)]` `mod tests`
        // removed, with comments and string contents blanked (see
        // `production_code`). Each bridge's unit tests and its comments name
        // the same symbols, so a bare `contains` over the file stayed green
        // after the real call was deleted.
        let code = production_code(src);
        assert!(
            serves_the_supervisor_event_source(&code, serve_fn, supervisor_of_bi, serve_path),
            "{bridge} `{serve_fn}` must build its server with `mcp_server_bundle` over \
             the instance its provider reads (each of {serve_path:?} once), \
             and `mcp_server_bundle` must, as its first statement, obtain the \
             ContextEvent receiver from `{supervisor_of_bi}` (the bridge \
             instance's own Supervisor) and hand THAT receiver to \
             `McpServer::with_optional_event_source`, the file's only call of \
             that constructor; the pinned call must be the file's only call \
             of `mcp_server_bundle`. Passing `None` silently downgrades to \
             resources.subscribe: false. (This gate does not check that the \
             bundle the serve function builds is the one it hands the transport.)"
        );
    }
}

/// Whether `serve_fn` in `code` (from [`production_code`]) builds its server
/// through `mcp_server_bundle` over the instance its provider reads, and
/// `mcp_server_bundle` both obtains the Supervisor's receiver and passes that
/// receiver to `McpServer::with_optional_event_source`, which `code` calls
/// nowhere else, and `code` calls `mcp_server_bundle` nowhere but in the
/// pinned call. It does not read the transport call: whether the `server` the
/// pinned call binds reaches `run_stdio` or `run_sse` is not checked, and a
/// server built in another file of the crate is not seen.
///
/// "The instance its provider reads" is pinned by `serve_path`: each of its
/// pins occurs exactly once in the text of `serve_fn` (the binding of the
/// instance, the provider's `Weak` over it, and the `mcp_server_bundle` call
/// on it), and `let bi` and `let mut bi` together occur exactly as often as
/// the pins bind `bi` or `bi_arc`, so no other `let` rebinds either name
/// before the call. A rebinding through a pattern, closure parameter or
/// `match` arm is not checked, and neither is a rebinding of `provider`: the
/// gate does not check that the `provider` passed to the pinned call is the
/// struct literal carrying the pinned `Weak`, so a `let`, pattern or closure
/// parameter that rebinds `provider` over another instance before the call
/// passes.
///
/// "The Supervisor's receiver" is pinned by the `match` that binds it: its
/// scrutinee is exactly `supervisor_of_bi`, the bridge's accessor for its own
/// instance's Supervisor called on the parameter `bi`; its first arm is
/// `Ok(supervisor) => supervisor.subscribe_events(),`; its only other arm is
/// an `Err` arm whose value is `None`, so a Supervisor that cannot be reached
/// yields no receiver rather than one nothing feeds; and it is the function's
/// first statement, so no earlier statement rebinds `bi`.
///
/// "That receiver" is pinned two ways: the `match` is the whole initializer of
/// `context_events` (the `Err` arm is followed by the `match`'s closing `}`
/// and `;`, so no chained call replaces its value), and every other mention of
/// `context_events` in the body is a read through `.is_none()` or the
/// constructor argument, so no statement rebinds or shadows it between the
/// `match` and the constructor.
fn serves_the_supervisor_event_source(
    code: &str,
    serve_fn: &str,
    supervisor_of_bi: &str,
    serve_path: ServePath,
) -> bool {
    const ARM: &str = "{ Ok(supervisor) => supervisor.subscribe_events(),";
    // The arms allowed after `ARM`, each closing the `match` and ending the
    // statement: with no Supervisor there is no receiver, so the arm's value is
    // `None` (after, at most, the bridges' shared warning, whose message
    // `production_code` blanks). Any other value is a receiver no Supervisor
    // feeds, which would advertise `resources.subscribe: true` over a pump
    // that never fires.
    const ERR_ARMS: [&str; 2] = [
        "Err(_) => None, };",
        "Err(e) => { tracing::warn!(\" \"); None } };",
    ];
    let bind = format!("let context_events = match {supervisor_of_bi} ");
    let bundle_wired = fn_body(code, "mcp_server_bundle").is_some_and(|body| {
        let bi_is_the_parameter = body
            .strip_prefix("fn mcp_server_bundle(")
            .is_some_and(|params| params.trim_start().starts_with("bi: &"));
        let match_is_whole_initializer = body.find(&bind).is_some_and(|at| {
            let before = &body[..at];
            let first_statement =
                before.matches('{').count() == 1 && before.trim_end().ends_with('{');
            let rest = &body[at + bind.len()..];
            first_statement
                && rest.strip_prefix(ARM).is_some_and(|after_ok| {
                    let after_ok = after_ok.trim_start();
                    ERR_ARMS.iter().any(|err_arm| after_ok.starts_with(err_arm))
                })
        });
        let mentions = body.matches("context_events").count();
        let reads = body.matches("context_events.is_none()").count();
        bi_is_the_parameter
            && match_is_whole_initializer
            && mentions == reads + 2
            && body.contains("McpServer::with_optional_event_source(provider, context_events)")
    });
    let serve_uses_bundle = fn_body(code, serve_fn).is_some_and(|body| {
        let (pins, instance_lets) = serve_path;
        pins.iter().all(|pin| body.matches(pin).count() == 1)
            && body.matches("mcp_server_bundle(").count() == 1
            && body.matches("let bi").count() + body.matches("let mut bi").count() == instance_lets
    });
    // The definition and the pinned call are the file's only two mentions, so
    // no other production function serves a bundle over another instance.
    bundle_wired
        && serve_uses_bundle
        && code.matches("mcp_server_bundle(").count() == 2
        && code.matches("with_optional_event_source(").count() == 1
}

/// A serve path's pins (see [`serves_the_supervisor_event_source`]): the
/// statements that must each occur once in the serve function, and how many
/// `let bi` bindings (of `bi` or `bi_arc`, none of them `let mut`) the
/// function holds, all of them among the pins. The function must also call `mcp_server_bundle` only once,
/// in its pinned call.
type ServePath = (&'static [&'static str], usize);

/// `py_mcp_serve` binds `bi` and `bi_arc` from `self.inner`, builds the
/// provider over `bi_arc`, and passes `bi` to `mcp_server_bundle`.
const PYO3_SERVE_PATH: ServePath = (
    &[
        "let bi = &*self.inner;",
        "let bi_arc = Arc::clone(&self.inner);",
        "bi: Arc::downgrade(&bi_arc),",
        "let server = mcp_server_bundle(bi, provider);",
    ],
    2,
);

/// `mcp_server_create_on` takes the instance as its parameter `bi`, builds the
/// provider over it, and passes it to `mcp_server_bundle`.
const NAPI_SERVE_PATH: ServePath = (
    &[
        "fn mcp_server_create_on( bi: &Arc<NapiBridgeInstance>,",
        "bi: Arc::downgrade(bi),",
        "let server = mcp_server_bundle(bi, provider);",
    ],
    0,
);

/// `mcp_server_create` builds the provider over `self.inner` and passes
/// `&self.inner` to `mcp_server_bundle`.
const UNIFFI_SERVE_PATH: ServePath = (
    &[
        "bi: Arc::downgrade(&self.inner),",
        "let server = mcp_server_bundle(&self.inner, provider);",
    ],
    0,
);

/// The serve path of [`WIRED_BUNDLE`], pinned as [`NAPI_SERVE_PATH`] pins
/// NAPI's.
const WIRED_SERVE_PATH: ServePath = (
    &[
        "fn serve(bi: &Arc<Bi>)",
        "bi: Arc::downgrade(bi),",
        "let server = mcp_server_bundle(bi, provider);",
    ],
    0,
);

/// The Supervisor accessor that [`WIRED_BUNDLE`]'s `match` is taken over.
const SUPERVISOR_OF_BI: &str = "crate::runtime::supervisor(bi)";

/// A wired `mcp_server_bundle` and its serve path, as the event-source gate
/// accepts them. The event-source self-tests derive each regression from it.
const WIRED_BUNDLE: &str = "fn mcp_server_bundle(bi: &Bi, provider: P) -> McpServerForTransport<P> {\n    \
                             // `context_events` is `None` only for ...\n    \
                             let context_events = match crate::runtime::supervisor(bi) {\n        \
                             Ok(supervisor) => supervisor.subscribe_events(),\n        Err(_) => None,\n    };\n    \
                             McpServer::with_optional_event_source(provider, context_events)\n}\n\
                             fn serve(bi: &Arc<Bi>) {\n    \
                             let provider = P {\n        bi: Arc::downgrade(bi),\n    };\n    \
                             let server = mcp_server_bundle(bi, provider);\n}\n\
                             #[cfg(test)]\n#[allow(clippy::unwrap_used)]\nmod tests {\n    fn t() { let _ = supervisor.subscribe_events(); }\n}\n";

/// The event-source gate above must go red when the wiring it pins is deleted
/// and only a comment or a `None` receiver remains, when a rebinding or a
/// chained call replaces the receiver before the constructor, or when its
/// pieces survive in a function the serve path does not run. Each case below
/// is the regression the gate exists to catch, written the way a real edit
/// would leave the source.
#[test]
fn mcp_wiring_gate_code_search_ignores_comments_and_none_receivers() {
    let wired = WIRED_BUNDLE;
    // The wired bundle carries a comment line naming `context_events`, which
    // counts as a third mention when comments are searched.
    assert!(serves_the_supervisor_event_source(
        &production_code(wired),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The serve path builds a server with no event source, and the bundle
    // call survives only as a comment line in its place.
    let call_commented_out = wired.replace(
        "    let server = mcp_server_bundle(bi, provider);",
        "    // let server = mcp_server_bundle(bi, provider);\n    \
         let server = McpServer::new(provider);",
    );
    assert_ne!(call_commented_out, wired);
    assert!(!serves_the_supervisor_event_source(
        &production_code(&call_commented_out),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The production bundle is deleted and a wired copy survives only in the
    // test module, after the serve path that calls it.
    let bundle_in_tests = format!(
        "fn serve(bi: &Arc<Bi>) {{\n    let provider = P {{\n        bi: Arc::downgrade(bi),\n    \
         }};\n    let server = mcp_server_bundle(bi, provider);\n}}\n\
         #[cfg(test)]\nmod tests {{\n{}}}\n",
        &wired[..wired.find("fn serve(").unwrap_or(0)]
    );
    assert!(bundle_in_tests.contains("mod tests {\nfn mcp_server_bundle("));
    assert!(!serves_the_supervisor_event_source(
        &production_code(&bundle_in_tests),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));

    // The `Ok` arm no longer yields the Supervisor's receiver.
    let call_deleted = wired.replace(
        "Ok(supervisor) => supervisor.subscribe_events(),",
        "Ok(_) => None,",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&call_deleted),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The constructor gets `None` in place of the receiver.
    let none_passed = wired.replace(
        "with_optional_event_source(provider, context_events)",
        "with_optional_event_source(provider, None)",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&none_passed),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The receiver is obtained, then a `None` rebinding shadows it before the
    // constructor, in the same function.
    let shadowed = wired.replace(
        "McpServer::with_optional_event_source(provider, context_events)",
        "let context_events = None;\n    \
         McpServer::with_optional_event_source(provider, context_events)",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&shadowed),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // A call chained onto the `match` replaces the receiver it produced.
    let chained = wired.replace(
        "Err(_) => None,\n    };",
        "Err(_) => None,\n    }.and(None);",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&chained),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The bundle function stays wired, but the serve path builds its own
    // server over a `None` receiver instead of calling it.
    let serve_builds_its_own = wired.replace(
        "let server = mcp_server_bundle(bi, provider);",
        "let context_events = None;\n    \
         let server = McpServer::with_optional_event_source(provider, context_events);",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&serve_builds_its_own),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The receiver is obtained in one function and the constructor is called
    // over a `None` receiver in another.
    let split = "fn events() {\n    let context_events = match rt.supervisor() {\n        \
                 Ok(supervisor) => supervisor.subscribe_events(),\n        Err(_) => None,\n    };\n}\n\
                 fn mcp_server_bundle(bi: &Bi, provider: P) -> McpServerForTransport<P> {\n    \
                 let context_events = None;\n    \
                 McpServer::with_optional_event_source(provider, context_events)\n}\n\
                 fn serve(bi: &Arc<Bi>) {\n    let provider = P {\n        \
                 bi: Arc::downgrade(bi),\n    };\n    \
                 let server = mcp_server_bundle(bi, provider);\n}\n";
    assert!(!serves_the_supervisor_event_source(
        &production_code(split),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
}

/// The event-source gate must go red when a comment or a string literal holding
/// `mod tests {` sits before a second production function that serves a server
/// over a `None` receiver: the marker must not end the production code early.
#[test]
fn mcp_wiring_gate_reads_past_a_test_module_marker_in_a_comment_or_literal() {
    let wired = WIRED_BUNDLE;
    // A comment or a string literal holding `mod tests {` sits before a second
    // production function that serves a server over a `None` receiver. Both
    // must stay in the production code the gate reads.
    let detached = "fn serve_detached(provider: P) {\n    \
                    let server = McpServer::with_optional_event_source(provider, None);\n}\n";
    for marker in [
        "// mirrors mod tests { fixture }\n",
        "/* mod tests { */\n",
        "const NOTE: &str = \"mod tests {\";\n",
    ] {
        let regression = wired.replacen(
            "#[cfg(test)]",
            &format!("{marker}{detached}#[cfg(test)]"),
            1,
        );
        assert_ne!(regression, wired);
        assert!(
            !serves_the_supervisor_event_source(
                &production_code(&regression),
                "serve",
                SUPERVISOR_OF_BI,
                WIRED_SERVE_PATH
            ),
            "{regression}"
        );
    }
}

/// `production_code` must drop every `#[cfg(test)]` `mod tests`, wherever it
/// sits and whatever attributes follow the `cfg`, and keep everything else:
/// code after a test module, a `mod tests` compiled without `#[cfg(test)]`, and
/// code after a comment or literal that holds `mod tests {`. A `#[cfg(test)]`
/// module with any other name is not dropped (see [`without_test_modules`]).
#[test]
fn production_code_drops_only_cfg_test_modules() {
    let src = "fn a() { one(); }\n\
               // mod tests { in a comment\n\
               fn b() { let _ = \"mod tests {\"; two(); }\n\
               #[cfg(test)]\n#[allow(clippy::unwrap_used, clippy::panic)]\n\
               mod tests {\n    fn t() { if x { hidden_one(); } }\n}\n\
               fn c() { three(); }\n\
               #[cfg(test)] mod tests { fn u() { hidden_two(); } }\n\
               #[allow(dead_code)]\nmod tests { fn v() { shipped(); } }\n\
               fn d() { four(); }\n";
    let code = production_code(src);
    for kept in ["one();", "two();", "three();", "shipped();", "four();"] {
        assert!(code.contains(kept), "{kept} missing from {code}");
    }
    for dropped in ["hidden_one", "hidden_two", "cfg(test)", "clippy::panic"] {
        assert!(!code.contains(dropped), "{dropped} kept in {code}");
    }
    // Each bridge source the MCP gates read keeps its production MCP code and
    // loses its trailing test module.
    for (src, production_fn) in [
        (
            include_str!("../../../../crates/scp-ffi/src/mcp.rs"),
            "fn mcp_server_bundle(",
        ),
        (
            include_str!("../../../../crates/scp-ffi/napi/src/mcp.rs"),
            "fn mcp_server_bundle(",
        ),
        (
            include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs"),
            "fn mcp_server_bundle(",
        ),
    ] {
        let code = production_code(src);
        assert!(code.contains(production_fn));
        assert!(!code.contains("mod tests {"));
    }
}

/// The event-source gate must go red when the serve path hands
/// `mcp_server_bundle` an instance other than the one its provider reads:
/// another instance in the call, the pinned provider literal's `Weak` over
/// another instance, `bi` rebound (by `let` or `let mut`) before the call, or a
/// second call over another instance, in the serve function or in another
/// production function. A `provider` rebound before the call is not checked
/// (see [`serves_the_supervisor_event_source`]).
#[test]
fn mcp_wiring_gate_rejects_a_serve_path_over_another_instance() {
    let wired = WIRED_BUNDLE;
    // The serve path passes another instance to `mcp_server_bundle`, so the
    // pump carries that instance's events while the provider reads `bi`.
    let serve_other_instance = wired.replace(
        "let server = mcp_server_bundle(bi, provider);",
        "let server = mcp_server_bundle(&other_instance, provider);",
    );
    // The provider reads another instance while the bundle subscribes to `bi`.
    let provider_other_instance = wired.replace(
        "bi: Arc::downgrade(bi),",
        "bi: Arc::downgrade(&other_instance),",
    );
    // The pinned call survives, but the serve path rebinds `bi` before it.
    let serve_bi_rebound = wired.replace(
        "    let server = mcp_server_bundle(bi, provider);",
        "    let bi = &other_instance;\n    let server = mcp_server_bundle(bi, provider);",
    );
    // The same rebinding through `let mut`.
    let serve_bi_rebound_mut = wired.replace(
        "    let server = mcp_server_bundle(bi, provider);",
        "    let mut bi = &other_instance;\n    let server = mcp_server_bundle(bi, provider);",
    );
    // The pinned call survives, and a second call over another instance
    // builds the server the serve path runs.
    let second_call = wired.replace(
        "    let server = mcp_server_bundle(bi, provider);",
        "    let server = mcp_server_bundle(bi, provider);\n    \
         let server = mcp_server_bundle(&other_instance, provider);",
    );
    // The serve function keeps its one pinned call, and a second production
    // function serves a bundle over another instance.
    let second_serve_fn = wired.replace(
        "#[cfg(test)]",
        "fn serve_other(bi: &Arc<Bi>, other: &Arc<Bi>) {\n    \
         let provider = P {\n        bi: Arc::downgrade(bi),\n    };\n    \
         let server = mcp_server_bundle(other, provider);\n}\n\
         #[cfg(test)]",
    );
    for regression in [
        serve_other_instance,
        provider_other_instance,
        serve_bi_rebound,
        serve_bi_rebound_mut,
        second_call,
        second_serve_fn,
    ] {
        assert_ne!(regression, wired);
        assert!(
            !serves_the_supervisor_event_source(
                &production_code(&regression),
                "serve",
                SUPERVISOR_OF_BI,
                WIRED_SERVE_PATH
            ),
            "{regression}"
        );
    }
}

/// The event-source gate must go red when the receiver comes from anything
/// but the bridge instance's own Supervisor: a stand-in scrutinee, the
/// accessor called on another instance, `bi` rebound before the `match`, an
/// `Ok` arm that ignores the Supervisor it matched, or an `Err` arm that yields
/// a receiver when there is no Supervisor.
#[test]
fn mcp_wiring_gate_rejects_a_receiver_not_from_the_bridge_instance() {
    let wired = WIRED_BUNDLE;
    // The `match` is taken over a stand-in, not the bridge instance's
    // Supervisor, so it never yields a receiver.
    let stand_in_scrutinee = wired.replace(
        "match crate::runtime::supervisor(bi) {",
        "match Err::<&Supervisor, String>(String::new()) {",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&stand_in_scrutinee),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The accessor is called on an instance other than the parameter `bi`.
    let other_instance = wired.replace(
        "match crate::runtime::supervisor(bi) {",
        "match crate::runtime::supervisor(&detached) {",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&other_instance),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The pinned scrutinee survives, but an earlier statement rebinds `bi` to
    // another instance.
    let bi_rebound = wired.replace(
        "    let context_events = match",
        "    let bi = &detached;\n    let context_events = match",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&bi_rebound),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The `Ok` arm ignores the Supervisor and takes a receiver elsewhere.
    let ok_arm_elsewhere = wired.replace(
        "Ok(supervisor) => supervisor.subscribe_events(),",
        "Ok(_supervisor) => detached.subscribe_events(),",
    );
    assert!(!serves_the_supervisor_event_source(
        &production_code(&ok_arm_elsewhere),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // The bridges' shipped `Err` arm, which warns before yielding `None`, is
    // accepted.
    let warns_then_none = wired.replace(
        "Err(_) => None,\n    };",
        "Err(e) => {\n            \
         tracing::warn!(\"MCP server: no supervisor event source ({e})\");\n            \
         None\n        }\n    };",
    );
    assert!(serves_the_supervisor_event_source(
        &production_code(&warns_then_none),
        "serve",
        SUPERVISOR_OF_BI,
        WIRED_SERVE_PATH
    ));
    // With no Supervisor, the `Err` arm yields a receiver from a channel it
    // creates itself, whose sender is already dropped: subscriptions would be
    // advertised over a pump nothing feeds. Both `Err` arm shapes go red.
    let stand_in_err = wired.replace(
        "Err(_) => None,",
        "Err(_) => Some(tokio::sync::broadcast::channel(1).1),",
    );
    let stand_in_after_warning = warns_then_none.replace(
        "\n            None\n        }",
        "\n            Some(tokio::sync::broadcast::channel(1).1)\n        }",
    );
    for regression in [stand_in_err, stand_in_after_warning] {
        assert!(
            !serves_the_supervisor_event_source(
                &production_code(&regression),
                "serve",
                SUPERVISOR_OF_BI,
                WIRED_SERVE_PATH
            ),
            "{regression}"
        );
    }
}

/// A wired `validate_resource_access`, as the resource-access gate accepts it.
/// The resource-gate self-tests derive each regression from it.
const RESOURCE_BRIDGE: &str = "fn validate_resource_access(&self, context_id: &str, resource: ResourceKind) \
                  -> Result<(), AccessRefusal> {\n    use scp_mcp::server::AccessRefusal;\n    \
                  let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;\n    \
                  let role_state =\n        \
                  gate_role_state(&bi, context_id)?;\n    \
                  let access = resource.check_access(&role_state, &self.agent_did, context_id);\n    \
                  access.map_err(AccessRefusal::Denied)\n}\n\
                  fn context_members(&self) {}\n";

/// A `gate_role_state` that splits an unheld context from a failed read, as the
/// split gate accepts it. The split self-test derives each regression from it.
const SPLIT_GATE: &str = "fn gate_role_state(bi: &Bi, context_id: &str) \
                  -> Result<ContextRoleState, AccessRefusal> {\n    \
                  use scp_mcp::server::AccessRefusal;\n    \
                  match held_role_state(bi, context_id) {\n        \
                  Ok(Some(role_state)) => Ok(role_state),\n        \
                  Ok(None) => Err(AccessRefusal::Denied(format!(\n            \
                  \"context '{context_id}' is not held by the supervisor\"\n        ))),\n        \
                  Err(e) => Err(AccessRefusal::Unreadable(e)),\n    }\n}\n\
                  fn held_role_state(bi: &Bi) {}\n";

/// The split gate must go red when an unheld context is reported as a failed
/// read, which `McpServer` answers with an internal error, when a failed read is
/// reported as a denial, when an unheld context reaches the predicate as a
/// stand-in role state, or when the split survives only in another function.
#[test]
fn mcp_access_gate_rejects_an_unsplit_role_state_read() {
    assert!(splits_absent_context_from_failed_read(&production_code(
        SPLIT_GATE
    )));
    let absent_as_unreadable = SPLIT_GATE.replace(
        "Ok(None) => Err(AccessRefusal::Denied(",
        "Ok(None) => Err(AccessRefusal::Unreadable(",
    );
    assert!(!splits_absent_context_from_failed_read(&production_code(
        &absent_as_unreadable
    )));
    let failed_as_denied = SPLIT_GATE.replace(
        "Err(e) => Err(AccessRefusal::Unreadable(e)),",
        "Err(e) => Err(AccessRefusal::Denied(e)),",
    );
    assert!(!splits_absent_context_from_failed_read(&production_code(
        &failed_as_denied
    )));
    let absent_as_stand_in = SPLIT_GATE.replace(
        "Ok(None) => Err(AccessRefusal::Denied(format!(",
        "Ok(None) => Ok(ContextRoleState::default()), Ok(_) => Err(AccessRefusal::Denied(format!(",
    );
    assert!(!splits_absent_context_from_failed_read(&production_code(
        &absent_as_stand_in
    )));
    let read_elsewhere = SPLIT_GATE.replace(
        "match held_role_state(bi, context_id) {",
        "match cached_role_state(bi, context_id) {",
    );
    assert!(!splits_absent_context_from_failed_read(&production_code(
        &read_elsewhere
    )));
    // A guarded arm between the `Denied` arm and the `Err(e)` arm turns some
    // failed reads into a stand-in role state.
    let guarded_failure = SPLIT_GATE.replace(
        "Err(e) => Err(AccessRefusal::Unreadable(e)),",
        "Err(e) if e.contains(\"busy\") => Ok(ContextRoleState::default()),\n        \
         Err(e) => Err(AccessRefusal::Unreadable(e)),",
    );
    assert!(!splits_absent_context_from_failed_read(&production_code(
        &guarded_failure
    )));
    // A statement after the match discards its answer.
    let after_match = SPLIT_GATE.replace("    }\n}\n", "    };\n    Ok(fallback)\n}\n");
    assert!(!splits_absent_context_from_failed_read(&production_code(
        &after_match
    )));
    let moved = SPLIT_GATE
        .replace("fn gate_role_state(", "fn other_gate(")
        .replace(
            "fn held_role_state(bi: &Bi) {}",
            "fn gate_role_state(bi: &Bi) -> Result<(), AccessRefusal> { Ok(()) }",
        );
    assert!(!splits_absent_context_from_failed_read(&production_code(
        &moved
    )));
}

/// A `gate_role_state` and the read it matches on, as the source gate accepts
/// them. The source self-test derives each regression from it.
const HELD_READ: &str = "fn gate_role_state(bi: &Bi, context_id: &str) -> R {\n    \
                  match held_role_state(bi, context_id) {\n        \
                  Ok(Some(role_state)) => Ok(role_state),\n    }\n}\n\
                  fn held_role_state(bi: &Bi, context_id: &str) -> Result<Option<S>, String> {\n    \
                  let Some(supervisor) = bi.core.try_supervisor() else {\n        \
                  return Ok(\n            \
                  crate::runtime::with_context(bi, context_id, |rt| Ok(rt.role_state.clone())).ok(),\n        \
                  );\n    };\n    \
                  let supervisor = Arc::clone(supervisor);\n    \
                  let id = context_id.to_owned();\n    \
                  block_on(async move { supervisor.get_role_state_checked(&id).await })\n}\n\
                  fn outlet_grant() {}\n";

/// The source gate must go red when the role-state read replaces its pinned
/// no-supervisor branch, drops the `get_role_state_checked` call, calls it on a
/// receiver other than the supervisor it bound from `bi` or with an id other
/// than its `context_id` parameter, rebinds either with a `let`, or spells
/// `Some(`, `Ok(None)` or `default(` outside that branch. Each case below uses
/// one of those spellings; a stand-in spelled some other way stays green.
#[test]
fn mcp_role_state_gate_rejects_a_stand_in_below_gate_role_state() {
    assert!(reads_role_state_from_its_own_source(&production_code(
        HELD_READ
    )));
    let uniffi_form = HELD_READ.replace(
        "return Ok(\n            \
         crate::runtime::with_context(bi, context_id, |rt| Ok(rt.role_state.clone())).ok(),\n        \
         );",
        "return Ok(None);",
    );
    let uniffi_form = uniffi_form
        .replace("Some(supervisor)", "Some(sup)")
        .replace(
            "let supervisor = Arc::clone(supervisor);",
            "let sup = Arc::clone(sup);",
        )
        .replace(
            "{ supervisor.get_role_state_checked",
            "{ sup.get_role_state_checked",
        );
    assert!(reads_role_state_from_its_own_source(&production_code(
        &uniffi_form
    )));
    // The UniFFI form binds `sup`, so a call on `supervisor` there asks a
    // receiver the function never bound from `bi`.
    let uniffi_wrong_receiver = uniffi_form.replace(
        "{ sup.get_role_state_checked",
        "{ supervisor.get_role_state_checked",
    );
    let stand_in_first = HELD_READ.replace(
        "let id =",
        "return Ok(Some(ContextRoleState::default()));\n    let id =",
    );
    let no_supervisor_stand_in = HELD_READ.replace(
        "crate::runtime::with_context(bi, context_id, |rt| Ok(rt.role_state.clone())).ok()",
        "Some(ContextRoleState::default())",
    );
    let cached = HELD_READ.replace("supervisor.get_role_state_checked(&id)", "cached(&id)");
    let fallback = HELD_READ.replace(
        "get_role_state_checked(&id).await",
        "get_role_state_checked(&id).await.map(|held| held.or_else(|| Some(fallback())))",
    );
    let unwrapped = HELD_READ.replace(
        "get_role_state_checked(&id).await",
        "get_role_state_checked(&id).await.or_else(|_| Ok(Some(S::default())))",
    );
    let absent = HELD_READ.replace(
        "block_on(async move",
        "if busy() { return Ok(None); }\n    block_on(async move",
    );
    let unknown_read = HELD_READ.replace(
        "match held_role_state(bi, context_id) {",
        "match cached_role_state(bi, context_id) {",
    );
    let rebound_receiver = HELD_READ.replace(
        "let supervisor = Arc::clone(supervisor);",
        "let supervisor = Arc::clone(&other_instance_supervisor);",
    );
    let rebound_id = HELD_READ.replace(
        "let id = context_id.to_owned();",
        "let id = cached_context_id.clone();",
    );
    let shadowed_receiver = HELD_READ.replace(
        "block_on(async move",
        "let supervisor = other_instance_supervisor();\n    block_on(async move",
    );
    let shadowed_id = HELD_READ.replace(
        "block_on(async move",
        "let id: String = cached_context_id();\n    block_on(async move",
    );
    let other_receiver = HELD_READ.replace(
        "{ supervisor.get_role_state_checked",
        "{ other.supervisor.get_role_state_checked",
    );
    for regression in [
        stand_in_first,
        no_supervisor_stand_in,
        cached,
        fallback,
        unwrapped,
        absent,
        unknown_read,
        uniffi_wrong_receiver,
        rebound_receiver,
        rebound_id,
        shadowed_receiver,
        shadowed_id,
        other_receiver,
    ] {
        assert!(
            !reads_role_state_from_its_own_source(&production_code(&regression)),
            "{regression}"
        );
    }
}

/// A wired `validate_capability`, as the capability gate accepts it.
const CAPABILITY_BRIDGE: &str = "fn validate_capability(&self, context_id: &str, \
                  outlet_name: &str, check: CapabilityCheck) -> Result<(), AccessRefusal> {\n    \
                  use scp_mcp::server::AccessRefusal;\n    \
                  let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;\n    \
                  let role_state = Self::gate_role_state(&bi, context_id)?;\n    \
                  self.outlet_grant(&bi, &role_state, context_id, outlet_name, check)\n}\n\
                  fn invoke_outlet(&self) {}\n";

/// The capability gate must go red when `outlet_grant`'s verdict is discarded
/// or returned only from an inner block, when a stand-in role state reaches it,
/// or when a statement returns before the check.
#[test]
fn mcp_capability_gate_rejects_a_discarded_verdict() {
    assert!(answers_capability_from_live_role_state(
        &production_code(CAPABILITY_BRIDGE),
        false
    ));
    let discarded = CAPABILITY_BRIDGE.replace(
        "outlet_name, check)\n}",
        "outlet_name, check).ok();\n    Ok(())\n}",
    );
    let inner_block = CAPABILITY_BRIDGE.replace(
        "    self.outlet_grant(&bi, &role_state, context_id, outlet_name, check)\n}",
        "    { self.outlet_grant(&bi, &role_state, context_id, outlet_name, check) };\n    Ok(())\n}",
    );
    let stand_in = CAPABILITY_BRIDGE.replace(
        "Self::gate_role_state(&bi, context_id)?",
        "ContextRoleState::default()",
    );
    let early_return = CAPABILITY_BRIDGE.replace(
        "use scp_mcp::server::AccessRefusal;",
        "use scp_mcp::server::AccessRefusal;\n    return Ok(());",
    );
    for regression in [discarded, inner_block, stand_in, early_return] {
        assert!(
            !answers_capability_from_live_role_state(&production_code(&regression), false),
            "{regression}"
        );
    }
}

/// With `lifecycle` true, both MCP access gates accept a body only when
/// `LIFECYCLE_GATE` sits between the role-state read and the tail; with it
/// false, they reject that statement.
#[test]
fn mcp_access_gates_pin_the_lifecycle_statement() {
    let resource = RESOURCE_BRIDGE.replace(
        "?;\n    let access",
        "?;\n    Self::gate_active_lifecycle(&bi, context_id)?;\n    let access",
    );
    let capability = CAPABILITY_BRIDGE.replace(
        "?;\n    self.outlet_grant",
        "?;\n    Self::gate_active_lifecycle(&bi, context_id)?;\n    self.outlet_grant",
    );
    assert_ne!(resource, RESOURCE_BRIDGE);
    assert_ne!(capability, CAPABILITY_BRIDGE);
    assert!(answers_resource_access_from_live_role_state(
        &production_code(&resource),
        true
    ));
    assert!(answers_capability_from_live_role_state(
        &production_code(&capability),
        true
    ));
    // The statement is required when `lifecycle` is true.
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(RESOURCE_BRIDGE),
        true
    ));
    assert!(!answers_capability_from_live_role_state(
        &production_code(CAPABILITY_BRIDGE),
        true
    ));
    // The statement is refused when `lifecycle` is false.
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&resource),
        false
    ));
    assert!(!answers_capability_from_live_role_state(
        &production_code(&capability),
        false
    ));
    // The statement before `bi` is bound, or after the predicate call, does
    // not count, whether it stands alone or beside the statement in the
    // required slot.
    for base in [RESOURCE_BRIDGE, resource.as_str()] {
        let before_bind = base.replace(
            "use scp_mcp::server::AccessRefusal;",
            "use scp_mcp::server::AccessRefusal;\n    Self::gate_active_lifecycle(&bi, context_id)?;",
        );
        let after_check = base.replace(
            "context_id);\n    access.map_err",
            "context_id);\n    Self::gate_active_lifecycle(&bi, context_id)?;\n    access.map_err",
        );
        for misplaced in [before_bind, after_check] {
            assert_ne!(misplaced, base);
            assert!(
                !answers_resource_access_from_live_role_state(&production_code(&misplaced), true),
                "{misplaced}"
            );
        }
    }
    for base in [CAPABILITY_BRIDGE, capability.as_str()] {
        let before_bind = base.replace(
            "use scp_mcp::server::AccessRefusal;",
            "use scp_mcp::server::AccessRefusal;\n    Self::gate_active_lifecycle(&bi, context_id)?;",
        );
        assert_ne!(before_bind, base);
        assert!(
            !answers_capability_from_live_role_state(&production_code(&before_bind), true),
            "{before_bind}"
        );
    }
    // Its refusal discarded does not count.
    let discarded = capability.replace(
        "Self::gate_active_lifecycle(&bi, context_id)?;",
        "let _ = Self::gate_active_lifecycle(&bi, context_id);",
    );
    assert!(!answers_capability_from_live_role_state(
        &production_code(&discarded),
        true
    ));
}

/// The resource-access gate must go red when the live read targets an instance
/// other than the provider's own bridge instance (a stand-in `bi`, or `bi`
/// rebound before the read), or when a statement runs before `bi` is bound.
#[test]
fn mcp_resource_gate_rejects_a_read_not_from_the_bridge_instance() {
    let bridge = RESOURCE_BRIDGE;
    assert!(answers_resource_access_from_live_role_state(
        &production_code(bridge),
        false
    ));
    // The live read survives, but `bi` is a stand-in instance, not the
    // provider's own bridge instance.
    let stand_in_instance = bridge.replace(
        "let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;",
        "let bi = detached.clone();",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&stand_in_instance),
        false
    ));
    // `bi` is bound from the bridge instance, then rebound to another
    // instance before the live read.
    let bi_rebound = bridge.replace(
        "let role_state =\n",
        "let bi = detached.clone();\n    let role_state =\n",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&bi_rebound),
        false
    ));
    // A statement before the `bi` binding answers `Ok(())` early.
    let early_return = bridge.replace(
        "use scp_mcp::server::AccessRefusal;",
        "use scp_mcp::server::AccessRefusal;\n    return Ok(());",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&early_return),
        false
    ));
}

/// The resource-access gate must go red when a comment names the capability
/// check, a stand-in role state reaches the predicate (in place of the live
/// read, chained onto it, or shadowing it), the predicate's verdict is
/// discarded, or the checked pieces survive only in another function.
#[test]
fn mcp_resource_gate_code_search_ignores_comments_and_stand_ins() {
    // The comment holds the exact call the search looks for, so only the
    // blanking of comments keeps it from satisfying the search.
    let doc_only = "/// rt.role_state.member_has_capability(agent_did, &Capability::MessagesRead)\n\
                    fn check() -> bool { rt.role_state.members.contains(agent) }\n";
    assert!(checks_messages_read(doc_only));
    assert!(!checks_messages_read(&production_code(doc_only)));
    let real = "fn check() -> bool {\n    rt.role_state\n        \
                .member_has_capability(agent_did, &Capability::MessagesRead)\n}\n";
    assert!(checks_messages_read(&production_code(real)));

    // The bridge half of the resource gate: `validate_resource_access` must
    // read role state from the live source and pass THAT value to the shared
    // predicate, and return the predicate's verdict.
    let bridge = RESOURCE_BRIDGE;
    assert!(answers_resource_access_from_live_role_state(
        &production_code(bridge),
        false
    ));
    // A stand-in role state reaches the predicate: the live read is gone.
    let stand_in = bridge.replace(
        "gate_role_state(&bi, context_id)?",
        "ContextRoleState::default()",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&stand_in),
        false
    ));
    // The live read survives, but a stand-in shadows it before the predicate.
    let shadowed = bridge.replace(
        "let access = resource",
        "let role_state = ContextRoleState::default();\n    let access = resource",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&shadowed),
        false
    ));
    // The live read survives, but a call chained onto it turns a failed read
    // into a stand-in before the predicate.
    let chained = bridge.replace(
        "?;\n    let access",
        ".or_else(|_| Ok(fallback.clone()))?;\n    let access",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&chained),
        false
    ));
    let unwrapped = bridge.replace(
        "?;\n    let access",
        ".unwrap_or_else(|_| fallback.clone());\n    let access",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&unwrapped),
        false
    ));
    // The predicate call is deleted and the function answers `Ok(())`.
    let unchecked = bridge.replace(
        "resource.check_access(&role_state, &self.agent_did, context_id)",
        "Ok(())",
    );
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&unchecked),
        false
    ));
    // The predicate call survives, but the function discards its verdict and
    // answers `Ok(())`.
    let discarded = bridge
        .replace("let access = resource", "let _access = resource")
        .replace("access.map_err(AccessRefusal::Denied)", "Ok(())");
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&discarded),
        false
    ));
    // The verdict is returned only from an inner block, and the function
    // answers `Ok(())` after it.
    let inner_block = bridge.replace(
        "    let access = resource.check_access(&role_state, &self.agent_did, context_id);\n    \
         access.map_err(AccessRefusal::Denied)\n}",
        "    { let access = resource.check_access(&role_state, &self.agent_did, context_id);\n    \
         access.map_err(AccessRefusal::Denied) };\n    Ok(())\n}",
    );
    assert_ne!(inner_block, bridge);
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(&inner_block),
        false
    ));
    // The live read and the predicate call survive only in ANOTHER function.
    let moved = "fn validate_resource_access(&self) -> Result<(), String> { Ok(()) }\n\
                 fn other(&self) { let role_state = Self::gate_role_state(&bi, context_id)?; \
                 resource.check_access(&role_state, &self.agent_did, context_id) }\n";
    assert!(!answers_resource_access_from_live_role_state(
        &production_code(moved),
        false
    ));
    // The predicate's `messages:read` arm is replaced by a membership check,
    // or the two arms swap their requirements.
    let predicate = CHECK_ACCESS_PREDICATE;
    assert!(arm_checks_messages_read(predicate));
    let membership_only = predicate.replace(
        "member_has_capability(agent, &Capability::MessagesRead)",
        "members.contains(agent)",
    );
    assert!(!arm_checks_messages_read(&membership_only));
    let swapped = predicate
        .replace(
            "Self::Events | Self::Members => role_state.member_has_capability",
            "Self::Tools => role_state.member_has_capability",
        )
        .replace(
            "Self::Tools => role_state.members.contains(agent)",
            "Self::Events | Self::Members => role_state.members.contains(agent)",
        );
    assert!(!arm_checks_messages_read(&swapped));
}

/// A `check_access` whose events/members arm checks `messages:read`, as the
/// predicate gate accepts it.
const CHECK_ACCESS_PREDICATE: &str = "pub fn check_access(self, role_state: &ContextRoleState) \
                  -> bool {\n    match self {\n        Self::Events | Self::Members => \
                  role_state.member_has_capability(agent, &Capability::MessagesRead),\n        \
                  Self::Tools => role_state.members.contains(agent),\n    }\n}\n\
                  const fn display_name(self) {}\n";

/// The predicate gate that [`mcp_resource_access_is_answered_from_real_role_state`]
/// runs on `scp-mcp`'s server, applied to `src`.
fn arm_checks_messages_read(src: &str) -> bool {
    fn_body(&production_code(src), "check_access")
        .and_then(events_and_members_arm)
        .is_some_and(checks_messages_read)
}

/// The predicate gate must go red when the events/members arm checks
/// membership only and keeps the `messages:read` call in a trailing comment,
/// a block comment, or a string literal on the arm's line.
#[test]
fn mcp_predicate_gate_ignores_trailing_comments_and_strings() {
    let predicate = CHECK_ACCESS_PREDICATE;
    assert!(arm_checks_messages_read(predicate));
    for hidden in [
        "members.contains(agent), // member_has_capability(agent, &Capability::MessagesRead)",
        "members.contains(agent) /* member_has_capability(agent, &Capability::MessagesRead) */,",
        "members.contains(agent) || \"member_has_capability(agent, &Capability::MessagesRead)\" \
         .is_empty(),",
    ] {
        let regression = predicate.replace(
            "member_has_capability(agent, &Capability::MessagesRead),",
            hidden,
        );
        assert_ne!(regression, predicate);
        assert!(!arm_checks_messages_read(&regression), "{regression}");
    }
}

/// Every MCP gate reads [`production_code`], which blanks comments and string
/// contents, and [`fn_body`], which ends a function at its closing `}` and
/// refuses a name defined twice. Each case below keeps a pinned statement only
/// in a trailing comment, a block comment or a string literal on a code line,
/// or adds a second function of the pinned name, and must go red; each
/// unaltered fixture must stay green.
#[test]
fn mcp_gates_ignore_trailing_comments_strings_and_second_definitions() {
    // Event-source gate: the serve path's provider and bundle call.
    let serves = |src: &str| {
        serves_the_supervisor_event_source(
            &production_code(src),
            "serve",
            SUPERVISOR_OF_BI,
            WIRED_SERVE_PATH,
        )
    };
    assert!(serves(WIRED_BUNDLE));
    for (pin, hidden) in [
        (
            "bi: Arc::downgrade(bi),",
            "bi: Arc::downgrade(&other), // bi: Arc::downgrade(bi),",
        ),
        (
            "bi: Arc::downgrade(bi),",
            "bi: Arc::downgrade(&other), /* bi: Arc::downgrade(bi), */",
        ),
        (
            "let server = mcp_server_bundle(bi, provider);",
            "let server = serve_detached(provider); // let server = mcp_server_bundle(bi, provider);",
        ),
    ] {
        let regression = WIRED_BUNDLE.replace(pin, hidden);
        assert_ne!(regression, WIRED_BUNDLE);
        assert!(!serves(&regression), "{regression}");
    }

    // Split gate: the role-state `match` itself, and a statement before it.
    let splits = |src: &str| splits_absent_context_from_failed_read(&production_code(src));
    assert!(splits(SPLIT_GATE));
    for (pin, hidden) in [
        (
            "match held_role_state(bi, context_id) {",
            "match cached_role_state(bi, context_id) { // match held_role_state(bi, context_id) {",
        ),
        (
            "use scp_mcp::server::AccessRefusal;\n",
            "use scp_mcp::server::AccessRefusal;\n    \
             if bi.core.try_supervisor().is_none() { return Ok(ContextRoleState::default()); }\n",
        ),
        (
            "use scp_mcp::server::AccessRefusal;\n",
            "use scp_mcp::server::AccessRefusal;\n    let bi = &other_instance;\n",
        ),
    ] {
        let regression = SPLIT_GATE.replace(pin, hidden);
        assert_ne!(regression, SPLIT_GATE);
        assert!(!splits(&regression), "{regression}");
    }
    // A second `gate_role_state` that callers can reach in place of the split one.
    let second = format!(
        "{SPLIT_GATE}fn gate_role_state(bi: &Bi, context_id: &str) -> R {{ \
         Ok(ContextRoleState::default()) }}\n"
    );
    assert!(!splits(&second));

    // Source gate: the supervisor call, and the read `gate_role_state` matches on.
    let reads = |src: &str| reads_role_state_from_its_own_source(&production_code(src));
    assert!(reads(HELD_READ));
    for (pin, hidden) in [
        (
            "block_on(async move { supervisor.get_role_state_checked(&id).await })",
            "block_on(async move { cached(&id).await }) \
             // async move { supervisor.get_role_state_checked(&id).await",
        ),
        (
            "block_on(async move { supervisor.get_role_state_checked(&id).await })",
            "block_on(cached(&id, \"async move { supervisor.get_role_state_checked(&id).await\"))",
        ),
        (
            "match held_role_state(bi, context_id) {",
            "match cached_role_state(bi, context_id) { // match held_role_state(bi, context_id) {",
        ),
    ] {
        let regression = HELD_READ.replace(pin, hidden);
        assert_ne!(regression, HELD_READ);
        assert!(!reads(&regression), "{regression}");
    }
}

/// Returns the text of the function `fn {name}(` in `code` (from
/// [`production_code`]), from that signature to the `}` that closes its body.
///
/// Returns `None` when `code` holds no such function, or more than one, since
/// a gate could then read one function while callers reach another; and when
/// a `;` precedes the body's `{`, since that signature has no body. Braces are
/// counted over `code` as [`production_code`] leaves it, with comments and
/// literals blanked, so a `{` in one of them cannot move the end.
fn fn_body<'a>(code: &'a str, name: &str) -> Option<&'a str> {
    let signature = format!("fn {name}(");
    let mut starts = code.match_indices(&signature).map(|(at, _)| at);
    let start = starts.next()?;
    if starts.next().is_some() {
        return None;
    }
    let rest = &code[start..];
    let open = rest.find('{')?;
    if rest[..open].contains(';') {
        return None;
    }
    let mut depth = 0usize;
    for (at, ch) in rest[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&rest[..=open + at]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The statement `UniFFI`'s MCP access gates run between the `gate_role_state`
/// read and the tail.
const LIFECYCLE_GATE: &str = "Self::gate_active_lifecycle(&bi, context_id)?;";

/// Whether the production `validate_resource_access` in `code` reads the
/// context's role state through the bridge's `gate_role_state` (an associated
/// function on PyO3 and UniFFI, a free function on NAPI) from the provider's
/// own bridge instance, passes that value to `ResourceKind::check_access`, and
/// returns that call's verdict as the function's tail expression.
///
/// The whole body is pinned statement by statement: the `use` of
/// `AccessRefusal`, then `bi` bound from `self.upgrade_bi()`, then the
/// `gate_role_state` read, then the predicate call and its verdict. So no
/// statement can bind `bi` to another instance or return before the check, no
/// later statement can rebind `role_state` to a stand-in, and no call chained
/// onto the read (an `or_else`, an `unwrap_or_else`) can turn a refused read
/// into a stand-in: the pinned read ends in `?`, which returns
/// `gate_role_state`'s refusal. [`splits_absent_context_from_failed_read`]
/// checks which refusal `gate_role_state` returns.
///
/// When `lifecycle` is true, the body must also hold [`LIFECYCLE_GATE`] as its
/// own statement between the `gate_role_state` read and the predicate call;
/// when it is false, nothing may sit there.
fn answers_resource_access_from_live_role_state(code: &str, lifecycle: bool) -> bool {
    const BIND: &str = "use scp_mcp::server::AccessRefusal; \
                        let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;";
    const TAIL: &str = "let access = resource.check_access(&role_state, &self.agent_did, \
                        context_id); access.map_err(AccessRefusal::Denied) }";
    const READS: [&str; 2] = [
        "let role_state = Self::gate_role_state(&bi, context_id)?;",
        "let role_state = gate_role_state(&bi, context_id)?;",
    ];
    fn_body(code, "validate_resource_access").is_some_and(|body| {
        let body = body.trim_end();
        let Some(tail_at) = body.strip_suffix(TAIL).map(str::len) else {
            return false;
        };
        let before_tail = body[..tail_at].trim_end();
        let before_tail = if lifecycle {
            match before_tail
                .strip_suffix(LIFECYCLE_GATE)
                .and_then(|rest| rest.strip_suffix(' '))
            {
                Some(rest) => rest,
                None => return false,
            }
        } else {
            before_tail
        };
        READS.iter().any(|read| {
            before_tail
                .strip_suffix(read)
                .and_then(|rest| rest.strip_suffix(' '))
                .and_then(|rest| rest.strip_suffix(BIND))
                .is_some_and(|signature| {
                    signature.trim_end().ends_with('{') && signature.matches('{').count() == 1
                })
        })
    })
}

/// Whether the `gate_role_state` in `code` (from [`production_code`]) matches
/// on the bridge's live role-state read of `bi` and answers each outcome with
/// its own refusal: a held context yields its role state, a context the actor
/// does not hold yields `AccessRefusal::Denied`, and a failed read yields
/// `AccessRefusal::Unreadable` carrying the read's error.
///
/// `McpServer` omits a denied context from `resources/list` and `tools/list`,
/// and answers `Unreadable` with an internal error. So a bridge that reports
/// an unheld context as `Unreadable` fails a whole list with a server fault
/// where a sibling bridge omits the context, and a bridge that reports a
/// failed read as `Denied` hides the failure as a shorter list.
///
/// The match must have exactly those three arms, in that order, and end the
/// function: the text after the `Denied` arm's closing parentheses must be the
/// `Err(e)` arm, the match's `}` and the function's `}`. So no guarded arm can
/// sit between the `Denied` arm and the `Err(e)` arm and turn some failed
/// reads into a stand-in role state.
///
/// The match must also be the function's first statement after
/// `use scp_mcp::server::AccessRefusal;`: the text before it is the signature,
/// its `{` (the only `{` there) and that `use`. So no earlier statement can
/// return a stand-in role state or rebind `bi` or `context_id`.
fn splits_absent_context_from_failed_read(code: &str) -> bool {
    const PRELUDE: &str = "{ use scp_mcp::server::AccessRefusal;";
    const HELD_THEN_ABSENT: &str =
        " Ok(Some(role_state)) => Ok(role_state), Ok(None) => Err(AccessRefusal::Denied(";
    const FAILED: &str = ", Err(e) => Err(AccessRefusal::Unreadable(e)), } }";
    fn_body(code, "gate_role_state").is_some_and(|body| {
        ROLE_STATE_READS.iter().any(|(read, _)| {
            body.find(read).is_some_and(|at| {
                let first_statement = body[..at]
                    .trim_end()
                    .strip_suffix(PRELUDE)
                    .is_some_and(|signature| !signature.contains('{'));
                first_statement
                    && body[at + read.len()..]
                        .strip_prefix(HELD_THEN_ABSENT)
                        .and_then(after_open_parens::<2>)
                        .is_some_and(|rest| rest.trim_end() == FAILED)
            })
        })
    })
}

/// The `match` on a live role-state read that each bridge's `gate_role_state`
/// opens, paired with the name of the function it reads through.
const ROLE_STATE_READS: [(&str, &str); 3] = [
    (
        "match Self::held_role_state(bi, context_id) {",
        "held_role_state",
    ),
    ("match held_role_state(bi, context_id) {", "held_role_state"),
    (
        "match Self::role_state_of(bi, context_id) {",
        "role_state_of",
    ),
];

/// Returns the text after the parenthesis that closes the `OPEN` parentheses
/// already open at the start of `text`, or `None` when they never close.
fn after_open_parens<const OPEN: usize>(text: &str) -> Option<&str> {
    let mut depth = OPEN;
    for (at, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[at + 1..]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether the function that `gate_role_state` in `code` (from
/// [`production_code`]) matches on has the source shape below. It contains one
/// of three pinned no-supervisor branches, which returns either the bridge's
/// own copy (`rt.role_state` through `crate::runtime::with_context`, on `PyO3`
/// and NAPI, which keep one) or `Ok(None)` (on `UniFFI`, which keeps no copy);
/// after that branch it calls `get_role_state_checked` on the supervisor it
/// bound. The gate does not check whether that call's answer is what the
/// function returns.
///
/// The two statements right after that branch must be `let <name> =
/// Arc::clone(<name>);` and `let id = context_id.to_owned();`, where `<name>`
/// is the supervisor the branch bound from `bi.core.try_supervisor()`. The rest
/// of the function must call `<name>.get_role_state_checked(&id).await` as the
/// first expression of an `async move` block and must not rebind `<name>` or
/// `id` with a `let`. A rebinding through a closure or pattern parameter is
/// not checked.
///
/// Outside that no-supervisor branch the function must not contain `Some(`,
/// `Ok(None)` or `default(`. Those three spellings are indicators of a stand-in
/// role state or a held context reported absent; the gate does not prove the
/// supervisor's answer is returned unaltered by some other spelling.
fn reads_role_state_from_its_own_source(code: &str) -> bool {
    const NO_SUPERVISOR: [(&str, &str); 3] = [
        (
            "letSome(supervisor)=bi.core.try_supervisor()else{returnOk(crate::runtime::\
             with_context(bi,context_id,|rt|{Ok(rt.role_state.clone())}).ok());};",
            "supervisor",
        ),
        (
            "letSome(supervisor)=bi.core.try_supervisor()else{returnOk(crate::runtime::\
             with_context(bi,context_id,|rt|Ok(rt.role_state.clone())).ok(),);};",
            "supervisor",
        ),
        (
            "letSome(sup)=bi.core.try_supervisor()else{returnOk(None);};",
            "sup",
        ),
    ];
    const STAND_INS: [&str; 3] = ["Some(", "Ok(None)", "default("];
    let Some(gate) = fn_body(code, "gate_role_state") else {
        return false;
    };
    ROLE_STATE_READS
        .iter()
        .filter(|(read, _)| gate.contains(read))
        .any(|(_, name)| {
            fn_body(code, name).is_some_and(|body| {
                let body: String = body.split_whitespace().collect();
                NO_SUPERVISOR.iter().any(|(branch, receiver)| {
                    body.split_once(branch).is_some_and(|(before, after)| {
                        let bound = format!(
                            "let{receiver}=Arc::clone({receiver});letid=context_id.to_owned();"
                        );
                        let call =
                            format!("asyncmove{{{receiver}.get_role_state_checked(&id).await");
                        let rebinds = [
                            format!("let{receiver}="),
                            format!("let{receiver}:"),
                            format!("letmut{receiver}"),
                            "letid=".to_owned(),
                            "letid:".to_owned(),
                            "letmutid".to_owned(),
                        ];
                        after.strip_prefix(bound.as_str()).is_some_and(|rest| {
                            rest.contains(call.as_str())
                                && !rebinds.iter().any(|r| rest.contains(r.as_str()))
                        }) && !STAND_INS
                            .iter()
                            .any(|s| before.contains(s) || after.contains(s))
                    })
                })
            })
        })
}

/// Whether the production `validate_capability` in `code` reads the context's
/// role state through `gate_role_state` (an associated function on `PyO3` and
/// `UniFFI`, a free function on NAPI, as in [`answers_resource_access_from_live_role_state`])
/// from the provider's own bridge instance, passes it to `outlet_grant`, and
/// returns that call's verdict as the function's tail expression, pinned
/// statement by statement as [`answers_resource_access_from_live_role_state`]
/// pins `validate_resource_access`, including the [`LIFECYCLE_GATE`]
/// statement between the read and the tail when `lifecycle` is true.
fn answers_capability_from_live_role_state(code: &str, lifecycle: bool) -> bool {
    const BIND: &str = "use scp_mcp::server::AccessRefusal; \
                        let bi = self.upgrade_bi().map_err(AccessRefusal::Unreadable)?;";
    const TAIL: &str = "self.outlet_grant(&bi, &role_state, context_id, outlet_name, check) }";
    const READS: [&str; 2] = [
        "let role_state = Self::gate_role_state(&bi, context_id)?;",
        "let role_state = gate_role_state(&bi, context_id)?;",
    ];
    fn_body(code, "validate_capability").is_some_and(|body| {
        READS.iter().any(|read| {
            let shape = if lifecycle {
                format!("{BIND} {read} {LIFECYCLE_GATE} {TAIL}")
            } else {
                format!("{BIND} {read} {TAIL}")
            };
            body.trim_end()
                .strip_suffix(&shape)
                .is_some_and(|signature| {
                    signature.trim_end().ends_with('{') && signature.matches('{').count() == 1
                })
        })
    })
}

/// Whether the production `invoke_outlet` in `code` (from [`production_code`])
/// is still the SCP-048 stub: its text names `OUTLET_INVOCATION_UNAVAILABLE`,
/// the refusal NAPI's stub returns for every `tools/call`. Any use of that
/// constant counts, not only the stub's exact body, so an `invoke_outlet`
/// that still returns it on some path keeps `validate_capability` refusing.
fn invokes_no_outlet(code: &str) -> bool {
    fn_body(code, "invoke_outlet")
        .is_some_and(|body| body.contains("OUTLET_INVOCATION_UNAVAILABLE"))
}

/// Whether the production `validate_capability` in `code` (from
/// [`production_code`]) answers as the bridge's `invoke_outlet` allows: while
/// `invoke_outlet` is the SCP-048 stub ([`invokes_no_outlet`]), it must refuse
/// every outlet ([`refuses_every_capability_as_unsupported`]), because any
/// grant lists a tool in `tools/list` that every `tools/call` then fails;
/// otherwise it must return `outlet_grant`'s verdict on live role state
/// ([`answers_capability_from_live_role_state`]).
fn answers_capability_as_invoke_outlet_allows(code: &str, lifecycle: bool) -> bool {
    if invokes_no_outlet(code) {
        refuses_every_capability_as_unsupported(code)
    } else {
        answers_capability_from_live_role_state(code, lifecycle)
    }
}

/// Whether the production `validate_capability` in `code` (from
/// [`production_code`]) is the SCP-048 stub whose whole body refuses every
/// outlet as unsupported: after the signature's `{`, the only expression is
/// `Err(scp_mcp::server::AccessRefusal::Unsupported(OUTLET_INVOCATION_UNAVAILABLE.to_owned()))`.
fn refuses_every_capability_as_unsupported(code: &str) -> bool {
    const REFUSAL: &str = "{ Err(scp_mcp::server::AccessRefusal::Unsupported( \
                           OUTLET_INVOCATION_UNAVAILABLE.to_owned(), )) }";
    fn_body(code, "validate_capability").is_some_and(|body| {
        body.trim_end()
            .strip_suffix(REFUSAL)
            .is_some_and(|signature| !signature.contains('{'))
    })
}

/// NAPI's `validate_capability` stub as rustfmt lays it out, as the stub gate
/// accepts it.
const UNSUPPORTED_CAPABILITY_STUB: &str = "fn validate_capability(\n    &self,\n    \
                  _context_id: &str,\n    _outlet_name: &str,\n    \
                  _check: scp_mcp::server::CapabilityCheck,\n) -> Result<(), \
                  scp_mcp::server::AccessRefusal> {\n    // Stub — see SCP-048\n    \
                  Err(scp_mcp::server::AccessRefusal::Unsupported(\n        \
                  OUTLET_INVOCATION_UNAVAILABLE.to_owned(),\n    ))\n}\n\
                  fn invoke_outlet(&self) -> Result<Value, OutletInvokeError> {\n    \
                  // Stub — see SCP-048\n    \
                  Err(OUTLET_INVOCATION_UNAVAILABLE.to_owned().into())\n}\n";

/// The capability gate keys its rule on `invoke_outlet`: while
/// `invoke_outlet` is the SCP-048 stub, only the refusing `validate_capability`
/// passes; once `invoke_outlet` runs outlets, only a `validate_capability`
/// that returns `outlet_grant`'s verdict on live role state passes, with
/// either spelling of the `gate_role_state` read.
#[test]
fn mcp_capability_gate_follows_invoke_outlet() {
    const REAL_INVOKE: &str = "fn invoke_outlet(&self) {}\n";
    let (stub_validate, stub_invoke) = UNSUPPORTED_CAPABILITY_STUB.split_at(
        UNSUPPORTED_CAPABILITY_STUB
            .find("fn invoke_outlet(")
            .unwrap_or(0),
    );
    let (live_validate, _) =
        CAPABILITY_BRIDGE.split_at(CAPABILITY_BRIDGE.find("fn invoke_outlet(").unwrap_or(0));
    let free_read = live_validate.replace(
        "Self::gate_role_state(&bi, context_id)?",
        "gate_role_state(&bi, context_id)?",
    );
    assert_ne!(free_read, live_validate);
    let accepts = |validate: &str, invoke: &str| {
        answers_capability_as_invoke_outlet_allows(
            &production_code(&format!("{validate}{invoke}")),
            false,
        )
    };
    assert!(invokes_no_outlet(&production_code(stub_invoke)));
    assert!(!invokes_no_outlet(&production_code(REAL_INVOKE)));
    // An `invoke_outlet` that runs outlets on one path and still returns the
    // stub's refusal on another counts as the stub.
    let partial_invoke = "fn invoke_outlet(&self) -> Result<Value, OutletInvokeError> {\n    \
                          if ready { run() } else { \
                          Err(OUTLET_INVOCATION_UNAVAILABLE.to_owned().into()) }\n}\n";
    assert!(invokes_no_outlet(&production_code(partial_invoke)));
    assert!(!accepts(live_validate, partial_invoke));
    // The stub pair and the implemented pair pass.
    assert!(accepts(stub_validate, stub_invoke));
    assert!(accepts(live_validate, REAL_INVOKE));
    assert!(accepts(&free_read, REAL_INVOKE));
    // A live grant while `invoke_outlet` is the stub lists tools every call
    // fails; the refusing stub once `invoke_outlet` runs outlets hides them.
    assert!(!accepts(live_validate, stub_invoke));
    assert!(!accepts(&free_read, stub_invoke));
    assert!(!accepts(stub_validate, REAL_INVOKE));
}

/// The stub gate must go red when NAPI's `validate_capability` grants, or runs
/// any statement before its refusal, while `invoke_outlet` is still a stub.
#[test]
fn mcp_capability_stub_gate_rejects_a_grant() {
    const REFUSAL: &str = "Err(scp_mcp::server::AccessRefusal::Unsupported(\n        \
                           OUTLET_INVOCATION_UNAVAILABLE.to_owned(),\n    ))";
    assert!(refuses_every_capability_as_unsupported(&production_code(
        UNSUPPORTED_CAPABILITY_STUB
    )));
    let granted = UNSUPPORTED_CAPABILITY_STUB.replace(REFUSAL, "Ok(())");
    let early_grant = UNSUPPORTED_CAPABILITY_STUB.replace(
        "    // Stub — see SCP-048\n",
        "    if _check.is_read() { return Ok(()); }\n",
    );
    let refusal_in_dead_block = UNSUPPORTED_CAPABILITY_STUB
        .replace(REFUSAL, &format!("Ok(())\n}}\nfn unused() {{ {REFUSAL}"));
    for regression in [granted, early_grant, refusal_in_dead_block] {
        assert_ne!(regression, UNSUPPORTED_CAPABILITY_STUB);
        assert!(
            !refuses_every_capability_as_unsupported(&production_code(&regression)),
            "{regression}"
        );
    }
}

/// Returns the production code of a Rust source file as one whitespace-collapsed
/// line: the file with every comment (a whole-line or trailing `//` comment, a
/// `/* */` block) and the contents of every string and char literal blanked by
/// [`strip_non_code`], the lexer [`extract_fn_body`] uses, and then every
/// `#[cfg(test)]` `mod tests { ... }` removed by [`without_test_modules`]. A
/// string literal keeps its quotes, so `"text"` reads as `" "`.
///
/// Blanking runs first, so a comment or string literal holding `mod tests {`
/// cannot end the production code early, and code after a test module that is
/// not the file's last item stays in. A gate reading this cannot be satisfied
/// by a bridge's own unit tests, by a comment, or by a string literal that
/// names the symbol. Collapsing whitespace lets one pattern match a call
/// rustfmt wraps across lines.
fn production_code(src: &str) -> String {
    without_test_modules(&strip_non_code(src))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Returns `code` (from [`strip_non_code`]) with every `mod tests { ... }`
/// whose outer attributes include `#[cfg(test)]` removed, from its first
/// attribute through its matching `}`. A `mod tests {` without `#[cfg(test)]`
/// is compiled into the shipped crate, so it stays.
fn without_test_modules(code: &str) -> String {
    const MARKER: &str = "mod tests {";
    let mut kept = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(at) = rest.find(MARKER) {
        let open = at + MARKER.len() - 1;
        if let (Some(start), Some(len)) = (
            test_cfg_attrs_start(&rest[..at]),
            matching_brace_end(&rest[open..]),
        ) {
            kept.push_str(&rest[..start]);
            kept.push(' ');
            rest = &rest[open + len..];
        } else {
            kept.push_str(&rest[..=open]);
            rest = &rest[open + 1..];
        }
    }
    kept.push_str(rest);
    kept
}

/// Where the run of outer attributes that ends `head` begins, when one of them
/// is `#[cfg(test)]`; `None` otherwise.
fn test_cfg_attrs_start(head: &str) -> Option<usize> {
    let mut start = head.trim_end().len();
    let mut cfg_test = false;
    while head[..start].ends_with(']') {
        let attr = head[..start].rfind("#[")?;
        cfg_test |= head[attr..start].split_whitespace().collect::<String>() == "#[cfg(test)]";
        start = head[..attr].trim_end().len();
    }
    cfg_test.then_some(start)
}

/// The byte length of `s` up to and including the `}` that balances its
/// leading `{`, counting braces only, because `s` comes from
/// [`strip_non_code`] and holds no comment or literal.
fn matching_brace_end(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Returns the `Self::Events | Self::Members =>` arm of `check_access` in
/// `body` (from [`fn_body`]): the text after that pattern up to the next
/// `Self::` arm, or to the end of `body` when it is the last arm.
fn events_and_members_arm(body: &str) -> Option<&str> {
    const PATTERN: &str = "Self::Events | Self::Members =>";
    let rest = &body[body.find(PATTERN)? + PATTERN.len()..];
    Some(rest.find("Self::").map_or(rest, |end| &rest[..end]))
}

/// Whether `code` (from [`production_code`]) calls `member_has_capability` with
/// `&Capability::MessagesRead` as its capability argument.
fn checks_messages_read(code: &str) -> bool {
    code.match_indices("member_has_capability(").any(|(at, _)| {
        code[at..]
            .find(')')
            .is_some_and(|end| code[at..=at + end].ends_with(", &Capability::MessagesRead)"))
    })
}

/// Resource authorization must run the SAME predicate for `resources/read` and
/// `resources/subscribe`, and every bridge must answer it from real state.
///
/// Two defects motivated this. First, `resources/subscribe` skipped the
/// authorization tier `resources/read` enforced, so a client could hold a live
/// subscription to a resource it could not read and learn from notification
/// timing that denied state was changing. Second, the tier `resources/read` DID
/// enforce named a `resource:{kind}` capability that appears in no ceiling, no
/// role catalogue and no UCAN stem — `Capability::new` resolves it to a
/// `Custom` value no context grants — so it denied every client on every bridge
/// unconditionally, making the whole resource surface dead while
/// `resources/list` kept advertising it.
///
/// `ContextProvider::validate_resource_access` is a required trait method with
/// no default, so a bridge cannot forget to answer it, and it takes the typed
/// `ResourceKind` rather than a string, so no `resource:`-prefixed name can be
/// synthesized again. The rule has one definition,
/// `scp_mcp::server::ResourceKind::check_access`, and each bridge's
/// `validate_resource_access` passes it the role state that bridge read. This
/// test pins the three parts the types cannot see. First, each bridge's
/// `validate_resource_access` passes the predicate the role state its
/// `gate_role_state` read from the provider's own bridge instance, and the
/// function `gate_role_state` reads through has the shape
/// [`reads_role_state_from_its_own_source`] checks: a pinned no-supervisor
/// branch that returns the bridge's own copy (`PyO3`, NAPI) or `Ok(None)`
/// (`UniFFI`, which keeps no copy), then a `get_role_state_checked(&id)` call
/// on the supervisor bound from `bi` over `context_id`, with neither rebound by
/// a `let`, and no `Some(`, `Ok(None)` or `default(` outside that branch. It
/// does not check whether that call's answer is what the function returns.
/// Second, each bridge's `gate_role_state`
/// answers a context the actor does not hold with `AccessRefusal::Denied` and
/// a failed read with `AccessRefusal::Unreadable`, and each bridge's
/// `validate_capability` returns `outlet_grant`'s verdict on role state read
/// through that same `gate_role_state`, except while the bridge's
/// `invoke_outlet` is the stub against SCP-048, the MCP server tool listing
/// and capability filtering story (NAPI's is): then this test pins
/// `validate_capability`'s whole body to the refusal that reports every
/// outlet as unsupported, so it cannot grant a tool the stubbed
/// `invoke_outlet` would then fail. Third, the predicate's
/// `Self::Events | Self::Members =>` arm calls `member_has_capability` with
/// `Capability::MessagesRead`. It does not check
/// how that arm uses the call's result, nor the `Tools` arm, which requires
/// membership only; `scp-mcp`'s unit tests exercise the predicate's decisions.
#[test]
fn mcp_resource_access_is_answered_from_real_role_state() {
    // `ContextProvider::validate_resource_access` takes a typed `ResourceKind`,
    // not a string, so no `resource:{kind}` capability name can be synthesized
    // from it; this test carries no source-text check for that spelling.
    //
    // Search PRODUCTION code with comments and string contents blanked, as the
    // event-source gate above does: each bridge's test module and doc comments
    // name the same symbols, so a whole-file `contains` stayed green after the
    // real call was deleted.
    //
    // `lifecycle` is true for a bridge whose two MCP access gates must run
    // `LIFECYCLE_GATE` between the role-state read and the tail.
    for (bridge, src, lifecycle) in [
        (
            "PyO3",
            include_str!("../../../../crates/scp-ffi/src/mcp.rs"),
            false,
        ),
        (
            "NAPI",
            include_str!("../../../../crates/scp-ffi/napi/src/mcp.rs"),
            false,
        ),
        (
            "UniFFI",
            include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs"),
            true,
        ),
    ] {
        let code = production_code(src);
        assert!(
            answers_resource_access_from_live_role_state(&code, lifecycle),
            "{bridge}'s production `validate_resource_access` must read the context's \
             role state through `gate_role_state` from its own bridge instance and pass that \
             value to `ResourceKind::check_access`; a stand-in role state, a deleted predicate \
             call, or a call in some other function does not count (lifecycle gate required: \
             {lifecycle})"
        );
        assert!(
            splits_absent_context_from_failed_read(&code),
            "{bridge}'s production `gate_role_state` must match on its live role-state read \
             and answer a context the actor does not hold with `AccessRefusal::Denied` and a \
             failed read with `AccessRefusal::Unreadable`, as its sibling bridges do; an unheld \
             context reported as `Unreadable` fails `resources/list` with an internal error"
        );
        assert!(
            reads_role_state_from_its_own_source(&code),
            "{bridge}'s production role-state read behind `gate_role_state` must keep a pinned \
             no-supervisor branch returning the bridge's own copy or `Ok(None)`, then call \
             `get_role_state_checked(&id)` on the supervisor bound from `bi` over `context_id` \
             with neither rebound by a `let`, and spell no `Some(`, `Ok(None)` or `default(` \
             outside that branch"
        );
        assert!(
            answers_capability_as_invoke_outlet_allows(&code, lifecycle),
            "{bridge}'s production `validate_capability` must, while its `invoke_outlet` is the \
             SCP-048 stub (stub: {}), be the stub whose whole body is \
             `Err(AccessRefusal::Unsupported(OUTLET_INVOCATION_UNAVAILABLE))`, since any grant \
             lists tools in `tools/list` that every `tools/call` then fails; otherwise it must \
             read the context's role state through `gate_role_state`, pass it to \
             `outlet_grant`, and return that call's verdict as its tail expression, so \
             `tools/list` omits a context the actor does not hold as `resources/list` does and \
             a discarded verdict grants nothing",
            invokes_no_outlet(&code)
        );
    }

    assert!(
        arm_checks_messages_read(include_str!("../../../../crates/scp-mcp/src/server.rs")),
        "`ResourceKind::check_access` must authorize the events/members resources, \
         in their own `Self::Events | Self::Members =>` arm, \
         against the real capability catalogue (spec §5.5.1, Default Role Set: an observer, whose only \
         permission is `messages:read`, can see all content and membership) on its PRODUCTION path; a \
         test-module occurrence does not count"
    );
}

// ===========================================================================
// Durable saga journal — production supervisor construction (§17.16 / ADR-049)
// ===========================================================================

/// Every production `Supervisor` construction seam (PyO3, NAPI, UniFFI, Node)
/// MUST route through `with_providers_and_journal` and supply a
/// `ProtocolRepositorySagaJournal` built over the SAME chosen `Storage` backend
/// that feeds `mls_storage` — NOT the bare `with_providers` (which hardcodes
/// `NoOpSagaJournal`). Without this, a process restart loads no journal and the
/// §17.16.4 crash-recovery replay can never reconcile a crash-orphaned saga.
///
/// This is a source-text presence gate (defense-in-depth, NOT the primary
/// guarantee — the type system already forces a journal argument on
/// `with_providers_and_journal`). It pins the wiring legible so a refactor that
/// silently reverts a seam to the `NoOpSagaJournal`-hardcoding `with_providers`
/// is flagged. The behavioral proof that BOTH legs run over the real journal is
/// the `saga_bridge_journal_swap` integration test.
#[test]
fn prod_supervisor_construction_wires_durable_saga_journal() {
    // -- PyO3 reference bridge --------------------------------------------
    // `build_supervisor` routes through `with_providers_and_journal`; the
    // journal + mls_storage are derived together by `durable_providers_from_bi`
    // → `DurableProviders::from_handle` over the bridge instance's chosen
    // `StorageProvider`, so they CANNOT diverge to different backends (spec §17.6,
    // construction-enforced — there is no separate journal argument to mis-wire).
    let pyo3_runtime_src = include_str!("../../../../crates/scp-ffi/src/runtime.rs");
    assert!(
        fn_body_contains(
            pyo3_runtime_src,
            "build_supervisor",
            "with_providers_and_journal"
        ),
        "PyO3 build_supervisor must route through with_providers_and_journal (durable saga \
         journal), not the NoOpSagaJournal-hardcoding with_providers"
    );
    assert!(
        fn_body_contains(
            pyo3_runtime_src,
            "build_supervisor",
            "durable_providers_from_bi"
        ),
        "PyO3 build_supervisor must derive the durable providers via durable_providers_from_bi \
         (the single same-backend derivation), not assemble the journal/mls_storage separately"
    );
    assert!(
        fn_body_contains(
            pyo3_runtime_src,
            "durable_providers_from_bi",
            "DurableProviders::from_handle"
        ) && fn_body_contains(
            pyo3_runtime_src,
            "durable_providers_from_bi",
            "STORAGE_8000"
        ),
        "PyO3 durable_providers_from_bi must derive both halves from one handle via \
         DurableProviders::from_handle (same backend by construction, spec §17.6) and preserve \
         the STORAGE_8000 fail-closed check"
    );

    // -- NAPI bridge (Node.js/Bun) ----------------------------------------
    // `build_supervisor_arc` routes through `with_providers_and_journal`; the
    // journal + mls_storage are derived together at the concrete-storage site via
    // `durable_providers_from_handle` → `DurableProviders::from_handle` over ONE
    // `Arc<S>`, so they share one backend by construction (spec §17.6).
    let napi_runtime_src = include_str!("../../../../crates/scp-ffi/napi/src/runtime.rs");
    assert!(
        fn_body_contains(
            napi_runtime_src,
            "build_supervisor_arc",
            "with_providers_and_journal"
        ),
        "NAPI build_supervisor_arc must route through with_providers_and_journal (durable saga \
         journal), not the NoOpSagaJournal-hardcoding with_providers"
    );
    assert!(
        fn_body_contains(
            napi_runtime_src,
            "durable_providers_from_handle",
            "DurableProviders::from_handle"
        ),
        "NAPI durable_providers_from_handle must derive the journal AND mls_storage from one \
         Arc<S> via DurableProviders::from_handle — same backend by construction (spec §17.6)"
    );

    // -- UniFFI bridge (Swift/Kotlin) -------------------------------------
    let uniffi_runtime_src = include_str!("../../../../crates/scp-ffi/uniffi/src/runtime.rs");
    assert!(
        fn_body_contains(
            uniffi_runtime_src,
            "build_supervisor",
            "with_providers_and_journal"
        ),
        "UniFFI build_supervisor must route through with_providers_and_journal (durable saga \
         journal), not the NoOpSagaJournal-hardcoding with_providers"
    );
    assert!(
        fn_body_contains(
            uniffi_runtime_src,
            "durable_providers_from_handle",
            "DurableProviders::from_handle"
        ),
        "UniFFI durable_providers_from_handle must derive the journal AND mls_storage from one \
         Arc<S> via DurableProviders::from_handle — same backend by construction (spec §17.6)"
    );

    // -- Node (self-host loopback supervisor) -----------------------------
    // `connect_loopback_supervisor` routes through `with_providers_and_journal`;
    // `build_host_site_deployer` derives the journal + mls_storage together via
    // `DurableProviders::from_handle` over the SAME `Arc<SqliteStorage>`
    // ({storage_dir}/mls), so they share one backend by construction (spec §17.6).
    let node_self_host_src = include_str!("../../../../crates/scp-node/src/self_host.rs");
    assert!(
        fn_body_contains(
            node_self_host_src,
            "connect_loopback_supervisor",
            "with_providers_and_journal"
        ),
        "Node connect_loopback_supervisor must route through with_providers_and_journal (durable \
         saga journal), not the NoOpSagaJournal-hardcoding with_providers"
    );
    assert!(
        fn_body_contains(
            node_self_host_src,
            "build_host_site_deployer",
            "DurableProviders::from_handle"
        ),
        "Node build_host_site_deployer must derive both halves from the SAME Arc<SqliteStorage> \
         ({{storage_dir}}/mls) via DurableProviders::from_handle — same backend by construction \
         (spec §17.6)"
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

/// The structured `ucan_evaluate` bridge op must route to the shared core
/// `evaluate_ucan` pipeline, not re-implement capability evaluation locally.
///
/// `ucan_evaluate` is the read-only diagnostic counterpart to the throwing
/// `ucan_validate` gate. If the bridge fork-implemented its own evaluation
/// instead of calling core `evaluate_ucan`, the diagnostic could report a
/// token as acceptable that the enforcing pipeline would reject (or vice
/// versa). Pinning the call site keeps both surfaces on one pipeline.
#[test]
fn ucan_evaluate_routes_to_core_evaluate_ucan() {
    assert!(
        fn_body_contains(PYO3_UCAN_SRC, "ucan_evaluate", "evaluate_ucan("),
        "PyO3 ucan_evaluate must call the shared core evaluate_ucan pipeline \
         (it is the read-only diagnostic counterpart to validate_ucan and must \
         not re-implement capability evaluation locally)"
    );
}

/// NAPI's `ucan_evaluate` body lives in the `ucan_evaluate_on` per-instance
/// helper; it must route to the shared core `evaluate_ucan` pipeline. Same
/// rationale as the PyO3 assertion above — keep the diagnostic and the
/// enforcing gate on one pipeline.
#[test]
fn napi_ucan_evaluate_routes_to_core_evaluate_ucan() {
    assert!(
        fn_body_contains(NAPI_UCAN_SRC, "ucan_evaluate_on", "evaluate_ucan("),
        "NAPI ucan_evaluate (ucan_evaluate_on helper) must call the shared core \
         evaluate_ucan pipeline, not re-implement capability evaluation locally"
    );
}

/// UniFFI's `ucan_evaluate` bridge method must route to the shared core
/// `evaluate_ucan` pipeline. Same rationale as the other three bridges.
#[test]
fn uniffi_ucan_evaluate_routes_to_core_evaluate_ucan() {
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "ucan_evaluate", "evaluate_ucan("),
        "UniFFI ucan_evaluate must call the shared core evaluate_ucan pipeline, \
         not re-implement capability evaluation locally"
    );
}

/// The shared `Supervisor::participation_record` method MUST derive the record
/// via the pure-core `compute_participation_record` over the FULL event log —
/// not re-implement participation accounting in the runtime. This is the
/// single source the three bridges route through; if it forked, every binding's
/// participation facts would silently diverge from the protocol definition.
#[test]
fn supervisor_participation_record_routes_to_core_compute() {
    assert!(
        fn_body_contains(
            SUPERVISOR_SRC,
            "participation_record",
            "compute_participation_record("
        ),
        "Supervisor::participation_record must call core compute_participation_record \
         over the full event log, not re-derive participation facts locally"
    );
}

/// The PyO3 `participation_record` bridge op must route to the shared
/// `Supervisor::participation_record`, so Python RECEIVES the flattened facts
/// rather than recomputing them from event-log collections.
#[test]
fn pyo3_participation_record_routes_to_supervisor() {
    assert!(
        fn_body_contains(
            PYO3_TRUST_SRC,
            "participation_record_impl",
            "participation_record_on_pool("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "participation_record_on_pool",
            ".participation_record("
        ),
        "PyO3 participation_record_impl must call Supervisor::participation_record, \
         not re-aggregate participation facts in the bridge"
    );
}

/// The NAPI `participation_record` bridge op (body in `participation_record_on`)
/// must route to the shared `Supervisor::participation_record`.
#[test]
fn napi_participation_record_routes_to_supervisor() {
    assert!(
        fn_body_contains(
            NAPI_TRUST_SRC,
            "participation_record_on",
            ".participation_record("
        ),
        "NAPI participation_record_on must call Supervisor::participation_record, \
         not re-aggregate participation facts in the bridge"
    );
}

/// The UniFFI `participation_record` bridge method must route to the shared
/// `Supervisor::participation_record`.
///
/// The UniFFI bridge method shares its leaf name (`participation_record`) with
/// the supervisor method it calls, so a single `.participation_record(`
/// substring check would be self-satisfying. Pin BOTH the `supervisor` binding
/// (proving the call targets the runtime, not a bridge-local re-aggregation)
/// AND the `.participation_record(` call, so a bare self-mention cannot pass.
#[test]
fn uniffi_participation_record_routes_to_supervisor() {
    assert!(
        fn_body_contains(UNIFFI_BRIDGE_SRC, "participation_record", "supervisor")
            && fn_body_contains(
                UNIFFI_BRIDGE_SRC,
                "participation_record",
                ".participation_record("
            ),
        "UniFFI participation_record must call Supervisor::participation_record, \
         not re-aggregate participation facts in the bridge"
    );
}

// ===========================================================================
// Capability-admission op `check_capability_requirements` (§7.3.4.4, SCP-ACR-008)
// ===========================================================================
//
// The shared `scp_ffi_common::challenge::check_capability_requirements` reads
// the requirements from the context's governance at call time
// (`Supervisor::capability_requirements_checked`), then runs the core
// `scp_protocol::trust::check_capability_requirements` on the blocking pool
// with the instance's DID resolver (`instance_active_key_resolver`), which
// reads each verifier's `#active` key. Each native bridge's export reaches that
// shared body with its own instance's resolver, so no bridge takes the
// requirements from its caller or decides admission itself.

#[test]
fn shared_check_capability_requirements_reads_governance_then_resolves() {
    let body = extract_fn_body(FFI_CHALLENGE_SRC, "check_capability_requirements")
        .expect("scp_ffi_common::challenge::check_capability_requirements must exist");
    let read = body.find("sup.capability_requirements_checked(&context_id)");
    let pool = body.find("run_blocking_resolution(");
    assert!(
        read.is_some()
            && pool.is_some()
            && read < pool
            && body.contains("scp_protocol::trust::check_capability_requirements(")
            && body.contains("instance_active_key_resolver(scope, resolver.as_ref())"),
        "check_capability_requirements must read the context's governed requirements \
         before it runs core check_capability_requirements on the blocking pool with \
         the instance DID resolver"
    );
}

/// The PyO3 `SCP.check_capability_requirements` method reaches the shared
/// operation with the instance's supervisor and DID resolver, without the GIL.
#[test]
fn pyo3_check_capability_requirements_routes_to_core() {
    let reaches =
        |callee| fn_body_contains(PYO3_TRUST_SRC, "check_capability_requirements", callee);
    assert!(
        reaches("scp_ffi_common::challenge::check_capability_requirements(")
            && reaches("crate::runtime::supervisor(bi)")
            && reaches("crate::runtime::did_resolver(bi).cloned()")
            && reaches("crate::actor_wait::block_on_released("),
        "PyO3 check_capability_requirements must reach the shared operation with the \
         instance supervisor and DID resolver, with the GIL released"
    );
}

/// The NAPI `check_capability_requirements` bridge op (body in
/// `check_capability_requirements_on`) reaches the shared operation.
#[test]
fn napi_check_capability_requirements_routes_to_core() {
    assert!(
        fn_body_contains(
            NAPI_SCP_SRC,
            "check_capability_requirements",
            "check_capability_requirements_on("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "check_capability_requirements_on",
            "scp_ffi_common::challenge::check_capability_requirements("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "check_capability_requirements_on",
            "crate::runtime::supervisor(bi)"
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "check_capability_requirements_on",
            "crate::runtime::did_resolver(bi).cloned()"
        ),
        "NAPI check_capability_requirements_on must reach the shared operation with \
         the instance supervisor and DID resolver"
    );
}

/// The UniFFI `Scp::check_capability_requirements` method reaches the shared
/// operation.
#[test]
fn uniffi_check_capability_requirements_routes_to_core() {
    let reaches =
        |callee| fn_body_contains(UNIFFI_BRIDGE_SRC, "check_capability_requirements", callee);
    assert!(
        reaches("scp_ffi_common::challenge::check_capability_requirements(")
            && reaches("self.inner.context_manager_expect()")
            && reaches("self.inner.did_resolver()"),
        "UniFFI check_capability_requirements must reach the shared operation with the \
         instance supervisor and DID resolver"
    );
}

/// Every bridge passes its `capability_requirements` parameter into the
/// common context params, and the common builder parses it through the
/// validating type, so a context created through any bridge holds the
/// requirements its creator set.
#[test]
fn ffi_context_create_reads_capability_requirements() {
    assert!(
        fn_body_contains(
            FFI_CONTEXT_PARAMS_SRC,
            "build_context_params",
            "parse_capability_requirements(params.capability_requirements_json.as_ref())"
        ) && fn_body_contains(
            PYO3_CONTEXT_SRC,
            "build_core_context_params",
            "capability_requirements_json: py_params.capability_requirements.clone()"
        ) && fn_body_contains(
            NAPI_CONTEXT_SRC,
            "parse_context_params",
            "capability_requirements_json,"
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "bridge_params_to_core",
            "capability_requirements_json: params.capability_requirements_json.clone()"
        ),
        "each bridge must pass its capability requirements to the common builder, \
         which must parse them"
    );
}

/// `ModifyCapabilityRequirements` keeps a tightening in force on a persist
/// failure and restores the old list for any other change, so a loosening
/// never takes effect without being durable.
#[test]
fn governance_modify_capability_requirements_chooses_direction_by_delta() {
    let body = extract_fn_body(MANAGER_SRC, "execute_modify_capability_requirements")
        .expect("execute_modify_capability_requirements must exist");
    let tightening = body.find(".is_tightening_of(");
    let keep = body.find(".commit_class_s_keep(");
    let restore = body.find(".commit_class_s_restore(");
    assert!(
        tightening.is_some() && keep.is_some() && restore.is_some() && tightening < keep,
        "execute_modify_capability_requirements must choose commit_class_s_keep for a \
         tightening and commit_class_s_restore otherwise"
    );
}

/// Every bridge exports a `ModifyCapabilityRequirements` proposal entry point
/// that decodes the list through the shared validating builder and proposes
/// the action through the bridge's checked governance path, so governance can
/// change a context's requirements from every SDK.
#[test]
fn every_bridge_exports_modify_capability_requirements() {
    const DECODE: &str = "scp_ffi_common::context_params::modify_capability_requirements_action(";
    let pyo3 = |callee| {
        fn_body_contains(
            PYO3_CONTEXT_SRC,
            "governance_modify_capability_requirements",
            callee,
        )
    };
    let napi = |callee| {
        fn_body_contains(
            NAPI_CONTEXT_SRC,
            "context_governance_modify_capability_requirements_on",
            callee,
        )
    };
    let uniffi = |callee| {
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "governance_modify_capability_requirements",
            callee,
        )
    };
    assert!(
        pyo3(DECODE) && pyo3("propose_governance_action("),
        "PyO3 SCP.governance_modify_capability_requirements must decode the list with \
         modify_capability_requirements_action and propose it"
    );
    assert!(
        fn_body_contains(
            NAPI_SCP_SRC,
            "context_governance_modify_capability_requirements",
            "context_governance_modify_capability_requirements_on("
        ) && napi(DECODE)
            && napi("propose_governance_action_on("),
        "NAPI Scp.contextGovernanceModifyCapabilityRequirements must reach its _on body, \
         which decodes the list with modify_capability_requirements_action and proposes it"
    );
    assert!(
        uniffi(DECODE) && uniffi(".propose_governance_action("),
        "UniFFI Scp::governance_modify_capability_requirements must decode the list with \
         modify_capability_requirements_action and propose it"
    );
}

// ===========================================================================
// Attestation verification reads the revocation list (§7.4.4 step 5)
// ===========================================================================
//
// Each native bridge's `trust_verify_attestation` export MUST verify against
// the instance's revocation list for the caller's context: the export routes
// through its bridge-local `run_verify_attestation`, which builds the trust
// bridge over the instance's repository and calls the shared
// `verify_attestation_in_context`. That helper reads `get_revocation_state` and
// hands `verify_attestation` a `RevocationMapChecker` over it, so no bridge can
// verify with an empty list or a checker that names nothing.

/// The shared helper reads the context's revocation list and verifies with a
/// checker built from it.
#[test]
fn verify_attestation_in_context_reads_the_revocation_list() {
    assert!(
        fn_body_contains(
            FFI_TRUST_STORE_SRC,
            "verify_attestation_in_context",
            ".get_revocation_state("
        ) && fn_body_contains(
            FFI_TRUST_STORE_SRC,
            "verify_attestation_in_context",
            "RevocationMapChecker::new("
        ) && fn_body_contains(
            FFI_TRUST_STORE_SRC,
            "verify_attestation_in_context",
            "verify_attestation("
        ),
        "verify_attestation_in_context must read get_revocation_state and verify \
         with a RevocationMapChecker over that list"
    );
}

/// The PyO3 `trust_verify_attestation` export reaches the shared helper over
/// the instance's storage.
#[test]
fn pyo3_trust_verify_attestation_reads_the_instance_revocation_list() {
    assert!(
        fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_verify_attestation_impl",
            "run_verify_attestation("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "run_verify_attestation",
            "scp_ffi_common::trust_store::verify_attestation_in_context("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "run_verify_attestation",
            "ProtocolRepositoryTrustBridge::new("
        ),
        "PyO3 trust_verify_attestation_impl must verify through \
         verify_attestation_in_context over the instance's storage"
    );
}

/// The NAPI `trust_verify_attestation` export (body in
/// `trust_verify_attestation_on`) reaches the shared helper over the instance's
/// repository.
#[test]
fn napi_trust_verify_attestation_reads_the_instance_revocation_list() {
    assert!(
        fn_body_contains(
            NAPI_TRUST_SRC,
            "trust_verify_attestation_on",
            "run_verify_attestation("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "run_verify_attestation",
            "scp_ffi_common::trust_store::verify_attestation_in_context("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "run_verify_attestation",
            "ProtocolRepositoryTrustBridge::new("
        ),
        "NAPI trust_verify_attestation_on must verify through \
         verify_attestation_in_context over the instance's repository"
    );
}

/// The UniFFI `trust_verify_attestation` method reaches the shared helper over
/// the instance's repository.
#[test]
fn uniffi_trust_verify_attestation_reads_the_instance_revocation_list() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_verify_attestation",
            "let inner = Arc::clone(&self.inner);"
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_verify_attestation",
            "on_resolution_pool("
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_verify_attestation",
            "inner.protocol_repository()"
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_verify_attestation",
            "run_verify_attestation("
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "run_verify_attestation",
            "scp_ffi_common::trust_store::verify_attestation_in_context("
        ),
        "UniFFI trust_verify_attestation must verify through \
         verify_attestation_in_context over the instance's repository"
    );
}

// ===========================================================================
// Challenge operations (spec 07 §7.3.4) — shared bodies, ledger, and bridge routing
// ===========================================================================
//
// The shared `create_challenge` builds the request, checks every `CustomEval`
// evaluator, and records the challenge in the challenger's ledger, which signs
// it. `respond_to_challenge` signs the subject's response through custody.
// `grade_response` looks the challenge up in the ledger before any DID
// resolution, authenticates the response on the blocking pool, takes the ledger
// lease and then a grading permit, grades, commits, and writes the record to the
// bridge's repository. Each supervisor dispatch reaches the challenger ledger's
// mailbox, whose Begin and Commit handlers check the attempt. Each bridge's
// export reaches the shared body, and each bridge grades through the one
// `SharedEvaluatorInvoker` over its own `EvaluatorHost`.

#[test]
fn shared_create_challenge_checks_the_definition_and_signs_in_the_ledger() {
    let reaches = |callee| fn_body_contains(FFI_CHALLENGE_SRC, "create_challenge", callee);
    assert!(
        reaches("challenge_request_unsigned(")
            && reaches(".check_registered(")
            && reaches(".dispatch_challenge_create(")
            && fn_body_contains(LEDGER_SRC, "handle_create", "sign_bounded_ed25519("),
        "create_challenge must build the request, check each evaluator, and record it \
         in the ledger, whose Create handler signs it through sign_bounded_ed25519"
    );
}

#[test]
fn shared_respond_to_challenge_signs_through_custody() {
    let reaches = |callee| fn_body_contains(FFI_CHALLENGE_SRC, "respond_to_challenge", callee);
    assert!(
        reaches("challenge_response_unsigned(")
            && reaches("run_blocking_resolution(")
            && reaches(".sign_bounded_ed25519(&unsigned.signing_digest())"),
        "respond_to_challenge must build the response on the blocking pool and sign \
         its digest through sign_bounded_ed25519"
    );
}

#[test]
fn shared_grade_response_authenticates_then_grades_and_commits() {
    assert!(
        fn_body_contains(
            FFI_CHALLENGE_SRC,
            "grade_response",
            "grade_response_within("
        ),
        "grade_response must run grade_response_within"
    );
    let body = extract_fn_body(FFI_CHALLENGE_SRC, "grade_response_within")
        .expect("grade_response_within must exist");
    let at = |needle: &str| body.find(needle);
    let lookup = at(".dispatch_challenge_lookup(");
    let resolve = at("run_blocking_resolution(");
    let permit = at(".challenge_grading_permit(");
    let begin = at(".dispatch_challenge_begin_grade(");
    let commit = at(".dispatch_challenge_commit(");
    assert!(
        lookup.is_some()
            && resolve.is_some()
            && permit.is_some()
            && begin.is_some()
            && commit.is_some()
            && lookup < resolve
            && resolve < begin
            && begin < permit
            && permit < commit,
        "grade_response_within must look the challenge up, then resolve, then Begin, \
         then take a permit, then Commit, in that order: a stored resubmit takes no permit"
    );
    assert!(
        fn_body_contains(
            FFI_CHALLENGE_SRC,
            "release_lease",
            ".dispatch_challenge_release("
        ) && body.contains("release_lease(")
            && fn_body_contains(LEDGER_SRC, "handle_release", "self.require_lease(")
            && fn_body_contains(LEDGER_SRC, "handle_release", "self.leases.remove("),
        "a capacity refusal in grade_response_within must release the lease through \
         release_lease, whose ledger handler checks and drops the lease"
    );
    assert!(
        body.contains("authenticate_challenge_response(")
            && body.contains(" grade(")
            && body.contains("store_graded(repo, committed)")
            && fn_body_contains(
                FFI_CHALLENGE_SRC,
                "store_graded",
                ".store_trust_challenge_result("
            )
            && body.contains("evaluate_cases(")
            && fn_body_contains(FFI_CHALLENGE_SRC, "evaluate_cases", "schema_case(")
            && fn_body_contains(FFI_CHALLENGE_SRC, "evaluate_cases", "eval_case(")
            && fn_body_contains(FFI_CHALLENGE_SRC, "eval_case", ".invoke(EvaluatorCall {")
            && fn_body_contains(FFI_CHALLENGE_SRC, "schema_case", "SchemaGate::admit("),
        "grade_response_within must authenticate, run each evaluated case (schemas \
         through SchemaGate, evaluators through the invoker), grade, and store the record"
    );
}

/// Begin and Commit both check the attempt in the ledger turn, and Commit signs
/// the record before it persists it.
#[test]
fn ledger_begin_and_commit_check_the_attempt() {
    let commit = extract_fn_body(LEDGER_SRC, "handle_commit").expect("handle_commit");
    let sign = commit.find(".sign_bounded_ed25519(");
    let persist = commit.find("self.persist_entry(");
    assert!(
        fn_body_contains(LEDGER_SRC, "handle_begin", "check_attempt(")
            && commit.contains("check_attempt(")
            && sign.is_some()
            && persist.is_some()
            && sign < persist,
        "the ledger's Begin and Commit handlers must check the attempt, and Commit must \
         sign the record through sign_bounded_ed25519 before it persists the attempt"
    );
}

/// The ledger actor never reaches the synchronous trust store or blocks its
/// turn on a runtime; the graded record is written by the async caller.
#[test]
fn ledger_handler_never_calls_the_sync_trust_store() {
    let code = strip_non_code(LEDGER_SRC);
    for banned in [
        "TrustStore",
        "trust_store",
        "block_on(",
        "store_trust_challenge_result(",
    ] {
        assert!(
            !code.contains(banned),
            "challenger_ledger_actor.rs must not reach `{banned}`"
        );
    }
}

/// Asserts that `Supervisor::{dispatch}` resolves the challenger's ledger and
/// sends `ChallengerLedgerCommand::{command}` to its mailbox.
fn assert_dispatch_reaches_ledger(dispatch: &str, command: &str) {
    let body = extract_fn_body(SUPERVISOR_SRC, dispatch)
        .unwrap_or_else(|| panic!("Supervisor::{dispatch} must exist"));
    assert!(
        body.contains("self.challenger_ledger_for(challenger)")
            && body.contains(".send(|reply| ChallengerLedgerCommand::")
            && body.contains(&format!("ChallengerLedgerCommand::{command} {{")),
        "Supervisor::{dispatch} must send ChallengerLedgerCommand::{command} to the \
         challenger's ledger mailbox"
    );
    let arm = format!("ChallengerLedgerCommand::{command} {{");
    let dispatch_body = extract_fn_body(LEDGER_SRC, "dispatch").expect("ledger dispatch");
    assert!(
        dispatch_body.contains(&arm),
        "the ledger actor's dispatch must handle ChallengerLedgerCommand::{command}"
    );
}

#[test]
fn supervisor_challenge_create_reaches_the_ledger_mailbox() {
    assert_dispatch_reaches_ledger("dispatch_challenge_create", "Create");
}

#[test]
fn supervisor_challenge_lookup_reaches_the_ledger_mailbox() {
    assert_dispatch_reaches_ledger("dispatch_challenge_lookup", "Lookup");
}

#[test]
fn supervisor_challenge_begin_grade_reaches_the_ledger_mailbox() {
    assert_dispatch_reaches_ledger("dispatch_challenge_begin_grade", "BeginGrade");
}

#[test]
fn supervisor_challenge_commit_reaches_the_ledger_mailbox() {
    assert_dispatch_reaches_ledger("dispatch_challenge_commit", "Commit");
}

#[test]
fn supervisor_challenge_fault_reaches_the_ledger_mailbox() {
    assert_dispatch_reaches_ledger("dispatch_challenge_fault", "RecordFault");
}

#[test]
fn pyo3_trust_create_challenge_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_create_challenge",
            "trust_create_challenge_impl("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_create_challenge_impl",
            "scp_ffi_common::challenge::create_challenge("
        ),
        "PyO3 trust_create_challenge must reach scp_ffi_common::challenge::create_challenge"
    );
}

#[test]
fn napi_trust_create_challenge_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            NAPI_SCP_SRC,
            "trust_create_challenge",
            "trust_create_challenge_on("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "trust_create_challenge_on",
            "scp_ffi_common::challenge::create_challenge("
        ),
        "NAPI trustCreateChallenge must reach scp_ffi_common::challenge::create_challenge"
    );
}

#[test]
fn uniffi_trust_create_challenge_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_create_challenge",
            "trust_create_challenge_impl("
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_create_challenge_impl",
            "scp_ffi_common::challenge::create_challenge("
        ),
        "UniFFI trust_create_challenge must reach scp_ffi_common::challenge::create_challenge"
    );
}

#[test]
fn pyo3_trust_respond_to_challenge_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_respond_to_challenge",
            "trust_respond_to_challenge_impl("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_respond_to_challenge_impl",
            "scp_ffi_common::challenge::respond_to_challenge("
        ),
        "PyO3 trust_respond_to_challenge must reach \
         scp_ffi_common::challenge::respond_to_challenge"
    );
}

#[test]
fn napi_trust_respond_to_challenge_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            NAPI_SCP_SRC,
            "trust_respond_to_challenge",
            "trust_respond_to_challenge_on("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "trust_respond_to_challenge_on",
            "scp_ffi_common::challenge::respond_to_challenge("
        ),
        "NAPI trustRespondToChallenge must reach \
         scp_ffi_common::challenge::respond_to_challenge"
    );
}

#[test]
fn uniffi_trust_respond_to_challenge_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_respond_to_challenge",
            "trust_respond_to_challenge_impl("
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_respond_to_challenge_impl",
            "scp_ffi_common::challenge::respond_to_challenge("
        ),
        "UniFFI trust_respond_to_challenge must reach \
         scp_ffi_common::challenge::respond_to_challenge"
    );
}

#[test]
fn pyo3_trust_grade_response_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_grade_response",
            "trust_grade_response_impl("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_grade_response_impl",
            "grade_with_storage("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "grade_with_storage",
            "scp_ffi_common::challenge::grade_response("
        ),
        "PyO3 trust_grade_response must reach scp_ffi_common::challenge::grade_response"
    );
}

#[test]
fn napi_trust_grade_response_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            NAPI_SCP_SRC,
            "trust_grade_response",
            "trust_grade_response_on("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "trust_grade_response_on",
            "scp_ffi_common::challenge::grade_response("
        ),
        "NAPI trustGradeResponse must reach scp_ffi_common::challenge::grade_response"
    );
}

#[test]
fn uniffi_trust_grade_response_reaches_the_shared_operation() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_grade_response",
            "trust_grade_response_impl("
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_grade_response_impl",
            "scp_ffi_common::challenge::grade_response("
        ),
        "UniFFI trust_grade_response must reach scp_ffi_common::challenge::grade_response"
    );
}

/// The PyO3 grade writes the record through a `ProtocolRepository` over the
/// instance's own storage provider.
#[test]
fn pyo3_grade_response_uses_the_bridge_repository() {
    assert!(
        fn_body_contains(
            PYO3_TRUST_SRC,
            "trust_grade_response_impl",
            "crate::runtime::get_storage(bi)"
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "grade_with_storage",
            "ProtocolRepository::new(storage)"
        ),
        "PyO3 trust_grade_response must store through a ProtocolRepository over the \
         instance storage"
    );
}

/// The NAPI grade writes the record through the instance's repository.
#[test]
fn napi_grade_response_uses_the_bridge_repository() {
    assert!(
        fn_body_contains(
            NAPI_TRUST_SRC,
            "trust_grade_response_on",
            "crate::runtime::protocol_repository(bi)"
        ),
        "NAPI trustGradeResponse must store through the instance's protocol repository"
    );
}

/// The UniFFI grade writes the record through the instance's repository.
#[test]
fn uniffi_grade_response_uses_the_bridge_repository() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "trust_grade_response_impl",
            "bi.protocol_repository()"
        ),
        "UniFFI trust_grade_response must store through the instance's protocol repository"
    );
}

/// The shared evaluator call runs the host handler on the blocking pool under
/// the grading permit, inside the outlet economy pipeline, on its own task.
#[test]
fn shared_evaluator_outlet_spawns_blocking_inside_the_economy_pipeline() {
    let reaches = |callee| fn_body_contains(FFI_CHALLENGE_SRC, "invoke_evaluator_outlet", callee);
    assert!(
        reaches("tokio::task::spawn_blocking(")
            && reaches("let _permit = permit;")
            && reaches(".spawn_evaluator_pipeline(")
            && !reaches("tokio::spawn(")
            && fn_body_contains(
                SUPERVISOR_SRC,
                "spawn_evaluator_pipeline",
                "self.spawn_tracked("
            )
            && reaches(".invoke_outlet_with_economy(")
            && reaches("let Some(handler) = handler else")
            && reaches("EvaluatorOutcome::Unavailable("),
        "invoke_evaluator_outlet must refuse without a handler and run it on the \
         blocking pool under the permit inside invoke_outlet_with_economy"
    );
}

/// Returns the source text from `header` to the end of `src`, so a body lookup
/// finds the first `fn` after that impl header rather than an earlier sibling.
fn from_impl<'a>(src: &'a str, header: &str) -> &'a str {
    let at = src
        .find(header)
        .unwrap_or_else(|| panic!("`{header}` must exist"));
    &src[at..]
}

/// Asserts that a bridge grades through the one shared invoker over its own
/// evaluator host. `create_fn` and `grade_fn` must each bind `let host = {host}
/// { bi };` and build `SharedEvaluatorInvoker::new(sup, &host)`, and the host
/// must implement `EvaluatorHost` by reading the bridge's state: `registry`
/// reaches `registry_lookup` and `handler` reaches `handler_lookup`.
/// `SharedEvaluatorInvoker` is a struct, so a bridge cannot supply a check or
/// an invocation of its own; what a bridge can still get wrong is the host it
/// passes, and this pins it.
fn assert_bridge_uses_shared_invoker(
    src: &str,
    host: &str,
    create_fn: &str,
    grade_fn: &str,
    registry_lookup: &str,
    handler_lookup: &str,
) {
    let bind = format!("let host = {host} {{ bi }};");
    let build = "scp_ffi_common::challenge::SharedEvaluatorInvoker::new(sup, &host)";
    for op in [create_fn, grade_fn] {
        assert!(
            fn_body_contains(src, op, &bind) && fn_body_contains(src, op, build),
            "{op} must build SharedEvaluatorInvoker over `{host} {{ bi }}`"
        );
    }
    let host_impl = from_impl(
        src,
        &format!("impl scp_ffi_common::challenge::EvaluatorHost for {host}<'_>"),
    );
    assert!(
        fn_body_contains(host_impl, "registry", registry_lookup)
            && fn_body_contains(host_impl, "handler", handler_lookup),
        "{host} must read the outlet registry through `{registry_lookup}` and the \
         handler through `{handler_lookup}`"
    );
}

#[test]
fn pyo3_grades_through_the_shared_evaluator_invoker() {
    assert_bridge_uses_shared_invoker(
        PYO3_TRUST_SRC,
        "PyEvaluatorHost",
        "trust_create_challenge_impl",
        "trust_grade_response_impl",
        "rt.outlet_registry.clone()",
        "rt.outlet_handlers.get(outlet_id.as_str())",
    );
}

#[test]
fn napi_grades_through_the_shared_evaluator_invoker() {
    assert_bridge_uses_shared_invoker(
        NAPI_TRUST_SRC,
        "NapiEvaluatorHost",
        "trust_create_challenge_on",
        "trust_grade_response_on",
        "rt.outlet_registry.clone()",
        "rt.outlet_handlers.get(outlet_id.as_str())",
    );
}

#[test]
fn uniffi_grades_through_the_shared_evaluator_invoker() {
    assert_bridge_uses_shared_invoker(
        UNIFFI_BRIDGE_SRC,
        "UniffiEvaluatorHost",
        "trust_create_challenge_impl",
        "trust_grade_response_impl",
        ".outlet_registry",
        ".outlet_handlers",
    );
    assert!(
        fn_body_contains(
            from_impl(UNIFFI_BRIDGE_SRC, "impl UniffiEvaluatorHost<'_>"),
            "handle",
            "context_handle_registry(self.bi)"
        ),
        "UniffiEvaluatorHost must find the evaluator context's handle in this \
         instance's context handle registry"
    );
}

// ===========================================================================
// §6.2.4 cross-context outlet-invocation saga — FFI export wiring (ADR-049 §3a)
// ===========================================================================
//
// Each native bridge's `outlet_invoke_cross_context_saga` export MUST, before the
// saga can run:
//   (a) bind the caller principal — `enforce_caller_principal_binding`, which
//       authenticates the hosted caller via `identity_registry_contains` and
//       `is_member` (ADR-049 §3a:94 normative: caller_did/caller_context bound
//       to the authenticated FFI principal, NOT an envelope-asserted value);
//   (b) convert the caller/target id STRING → [u8; 32] through the canonical
//       ADR-056 keying chokepoint `context_id_to_bytes` (a raw re-hash would
//       double-hash a 64-hex id and key a non-existent actor slot); and
//   (c) dispatch to the merged producer
//       `start_cross_context_outlet_invocation_saga`.
//
// These pin the bridge bodies so a refactor cannot silently sever any of the
// three from the export — e.g. drop the principal binding (replay/forgery),
// re-hash the id (spurious ContextNotRegistered), or bypass the saga producer.
// The principal-binding helper that wraps `identity_registry_contains` +
// `is_member` is itself pinned (the export → helper edge), so the named tokens
// cannot be satisfied by an unrelated sibling's substring.

#[test]
fn pyo3_saga_export_wires_binding_chokepoint_and_producer() {
    assert!(
        fn_body_contains(
            PYO3_OUTLETS_SRC,
            "outlet_invoke_cross_context_saga_impl",
            "enforce_caller_principal_binding(",
        ),
        "PyO3 cross-context saga export must bind the caller principal via \
         enforce_caller_principal_binding before invoking the saga (ADR-049 §3a)"
    );
    assert!(
        fn_body_contains(
            PYO3_OUTLETS_SRC,
            "outlet_invoke_cross_context_saga_impl",
            "context_id_to_bytes(",
        ),
        "PyO3 cross-context saga export must convert ids via the ADR-056 \
         context_id_to_bytes keying chokepoint, not re-hash them"
    );
    assert!(
        fn_body_contains(
            PYO3_OUTLETS_SRC,
            "outlet_invoke_cross_context_saga_impl",
            "start_cross_context_outlet_invocation_saga(",
        ),
        "PyO3 cross-context saga export must dispatch to the producer \
         start_cross_context_outlet_invocation_saga"
    );
    // The principal-binding helper itself must authenticate the hosted caller
    // (registry membership + context membership), so the (a) edge is meaningful.
    assert!(
        fn_body_contains(
            PYO3_OUTLETS_SRC,
            "enforce_caller_principal_binding",
            "identity_registry_contains",
        ) && fn_body_contains(
            PYO3_OUTLETS_SRC,
            "enforce_caller_principal_binding",
            "is_member",
        ),
        "PyO3 enforce_caller_principal_binding must check identity_registry_contains \
         AND is_member (authenticated-principal binding, ADR-049 §3a:94)"
    );
}

#[test]
fn napi_saga_export_wires_binding_chokepoint_and_producer() {
    assert!(
        fn_body_contains(
            NAPI_OUTLETS_SRC,
            "outlet_invoke_cross_context_saga_on",
            "enforce_caller_principal_binding(",
        ),
        "NAPI cross-context saga export must bind the caller principal via \
         enforce_caller_principal_binding before invoking the saga (ADR-049 §3a)"
    );
    assert!(
        fn_body_contains(
            NAPI_OUTLETS_SRC,
            "outlet_invoke_cross_context_saga_on",
            "context_id_to_bytes(",
        ),
        "NAPI cross-context saga export must convert ids via the ADR-056 \
         context_id_to_bytes keying chokepoint, not re-hash them"
    );
    assert!(
        fn_body_contains(
            NAPI_OUTLETS_SRC,
            "outlet_invoke_cross_context_saga_on",
            "start_cross_context_outlet_invocation_saga(",
        ),
        "NAPI cross-context saga export must dispatch to the producer \
         start_cross_context_outlet_invocation_saga"
    );
    assert!(
        fn_body_contains(
            NAPI_OUTLETS_SRC,
            "enforce_caller_principal_binding",
            "identity_registry_contains",
        ) && fn_body_contains(
            NAPI_OUTLETS_SRC,
            "enforce_caller_principal_binding",
            "is_member",
        ),
        "NAPI enforce_caller_principal_binding must check identity_registry_contains \
         AND is_member (authenticated-principal binding, ADR-049 §3a:94)"
    );
}

#[test]
fn uniffi_saga_export_wires_binding_chokepoint_and_producer() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "outlet_invoke_cross_context_saga",
            "enforce_caller_principal_binding(",
        ),
        "UniFFI cross-context saga export must bind the caller principal via \
         enforce_caller_principal_binding before invoking the saga (ADR-049 §3a)"
    );
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "outlet_invoke_cross_context_saga",
            "context_id_to_bytes(",
        ),
        "UniFFI cross-context saga export must convert ids via the ADR-056 \
         context_id_to_bytes keying chokepoint, not re-hash them"
    );
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "outlet_invoke_cross_context_saga",
            "start_cross_context_outlet_invocation_saga(",
        ),
        "UniFFI cross-context saga export must dispatch to the producer \
         start_cross_context_outlet_invocation_saga"
    );
    // UniFFI authenticates the hosted caller against the per-instance custody
    // registry (`identity_custody_registry(bi).contains_key`) rather than the
    // PyO3/NAPI `identity_registry_contains` helper — a per-SDK idiom difference,
    // same authenticated-principal property. Both legs (registry presence +
    // context membership via `is_member`) must be present.
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "enforce_caller_principal_binding",
            "identity_custody_registry",
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "enforce_caller_principal_binding",
            "is_member",
        ),
        "UniFFI enforce_caller_principal_binding must check the per-instance \
         identity_custody_registry AND is_member (authenticated-principal \
         binding, ADR-049 §3a:94)"
    );
}

// ===========================================================================
// SCP-OUT-046 streaming saga — AC8 (commit once, no per-chunk 2PC)
// ===========================================================================

/// AC8 (SCP-OUT-046; ADR-061) — the streaming-saga seal COMMITS ONCE over the
/// bounded Merkle root; it performs NO per-chunk two-phase commit. Structural
/// guard on the off-mailbox seal task `run_streaming_saga_seal_task`:
///
/// - the per-chunk pump loop (`while let Some(chunk) = inner_rx.recv().await`)
///   folds each forwarded chunk into B's durable frontier via
///   `StreamCaptureAppend` — an O(log n) durable capture, NOT a commit;
/// - the loop body contains NEITHER `CommitBStreamSettle` NOR `PrepareBStreaming`
///   (no per-chunk commit, no per-chunk prepare);
/// - the SINGLE `CommitBStreamSettle` fires exactly once in the whole task, at
///   stream-close, OUTSIDE the loop.
///
/// This is the rejected-alternative tripwire (ADR-061: per-chunk 2PC is
/// forbidden). Additive assertion — does not weaken any existing pipeline check.
#[test]
fn ac8_streaming_saga_seal_commits_once_no_per_chunk_2pc() {
    // Bound the seal-task function body: from its `fn` to the next item
    // (`send_streaming_saga_a_unit`, which immediately follows it).
    let fn_start = OUTLETS_INVOKE_SRC
        .find("pub(crate) async fn run_streaming_saga_seal_task")
        .expect("run_streaming_saga_seal_task must exist in invoke.rs");
    let after_fn = &OUTLETS_INVOKE_SRC[fn_start..];
    let fn_len = after_fn
        .find("async fn send_streaming_saga_a_unit")
        .expect("send_streaming_saga_a_unit follows the seal task");
    // Strip `//` line comments (doc/rationale references to the message names are
    // not code) before matching — mirrors the gating gate's comment-stripping, so
    // the guard asserts on the actual dispatch code, not prose.
    let seal_fn_owned: String = after_fn[..fn_len]
        .lines()
        .map(|line| line.split("//").next().unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    let seal_fn = seal_fn_owned.as_str();

    // (1) Exactly ONE CommitBStreamSettle dispatch in the whole seal task —
    // commit once over the bounded root (AC8). More than one is a per-chunk 2PC.
    let commit_count = seal_fn
        .matches("SagaPhaseMessage::CommitBStreamSettle")
        .count();
    assert_eq!(
        commit_count, 1,
        "AC8: the seal task must issue CommitBStreamSettle EXACTLY once (commit once over \
         the bounded root); found {commit_count} — a per-chunk two-phase-commit regression"
    );

    // (2) Per-chunk capture is present, and Prepare-B is NOT the seal task's job.
    assert!(
        seal_fn.contains("StreamCaptureAppend"),
        "AC8: the seal task must fold each forwarded chunk via StreamCaptureAppend"
    );
    assert!(
        !seal_fn.contains("PrepareBStreaming"),
        "AC8: the seal task must NOT run Prepare-B (Prepare-B is the driver's one-time job)"
    );

    // (3) Extract the per-chunk pump loop body via brace matching and assert the
    // per-chunk fold is inside it but NEITHER commit NOR prepare is (the single
    // commit fires at stream-close, outside the loop). In-string format
    // placeholders (`{SLUG_…}`) are balanced, so they net-zero the depth count.
    let loop_start = seal_fn
        .find("while let Some(chunk) = inner_rx.recv().await")
        .expect("the seal task must have a per-chunk pump loop");
    let open_rel = seal_fn[loop_start..]
        .find('{')
        .expect("the pump loop opens a block");
    let body_start = loop_start + open_rel + 1;
    let bytes = seal_fn.as_bytes();
    let mut depth = 1usize;
    let mut i = body_start;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    assert_eq!(depth, 0, "AC8: pump loop body braces must balance");
    let loop_body = &seal_fn[body_start..i - 1];

    assert!(
        loop_body.contains("StreamCaptureAppend"),
        "AC8: the per-chunk pump loop must fold each chunk via StreamCaptureAppend"
    );
    assert!(
        !loop_body.contains("CommitBStreamSettle"),
        "AC8: the per-chunk pump loop body must NOT commit per chunk — the single \
         CommitBStreamSettle fires once at stream-close, OUTSIDE the loop"
    );
    assert!(
        !loop_body.contains("PrepareBStreaming"),
        "AC8: the per-chunk pump loop body must NOT run Prepare-B per chunk"
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
    let meta_tests = 3; // this test + agents_md_enforcement_sections_present + no_stale_ignores
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

// ---------------------------------------------------------------------------
// ADR-003 §2 — the node's own DID-record keep-alive
// ---------------------------------------------------------------------------

/// ADR-003 §2 of `.docs/adrs/phase-1.md` states that republishing "starts when
/// an identity is loaded". `Node::start` loads an identity, and every one of its
/// paths ends in `build_domain_inner` (the `Reach::Domain` TLS-success arm) or
/// `build_no_domain_inner` (`Reach::NatTraversal`, `Reach::Tunnel`,
/// `Reach::Local`, and the `Reach::Domain` TLS-failure fall-through). Both must
/// therefore start the cycle.
///
/// Each assertion pins a call with its real arguments: the DHT client comes from
/// the node's own `DidMethod`, and the record source is a live view of the slot
/// the startup publish just seeded. Naming `start_self_did_republishing` without
/// calling it satisfies none of them.
///
/// Against the pre-fix code these assertions fail: the cycle was constructed in
/// `self_host::serve_hosted_site`, so a node the self-hosting serve loop did not
/// wrap — `start_node_in_memory` and `start_node_local`, the FFI bridges' two
/// node front doors — published its DID document once and never re-put it.
/// Mainline DHT nodes expire a BEP44 record that nobody re-puts, so every
/// identity that document names stops resolving.
#[test]
fn every_node_start_path_starts_the_self_did_republish_cycle() {
    for builder in ["build_domain_inner", "build_no_domain_inner"] {
        assert!(
            fn_body_contains(
                NODE_BUILDER_SRC,
                builder,
                "start_node_republish_cycle(&did_method, &live_state)"
            ),
            "{builder} must start this node's self-DID republish cycle over the \
             DID method it just published with and the slot that publish seeded \
             (ADR-003 §2)"
        );
    }
    assert!(
        fn_body_contains(
            NODE_BUILDER_SRC,
            "start_node_republish_cycle",
            "republish::start_self_did_republishing("
        ),
        "start_node_republish_cycle must actually start the cycle, not merely \
         name it"
    );
    assert!(
        fn_body_contains(
            NODE_BUILDER_SRC,
            "start_node_republish_cycle",
            "did_method.dht_client()"
        ),
        "the cycle must keep the record alive through the DHT client the node's \
         own DidMethod published it with, never a second client passed alongside"
    );
    assert!(
        fn_body_contains(
            NODE_BUILDER_SRC,
            "start_node_republish_cycle",
            "live_state.subscribe()"
        ),
        "the cycle must read a LIVE view of the published-record slot, so a NAT \
         tier change re-points both arms at the record it produced instead of \
         leaving them on a superseded sequence"
    );

    // One node, one cycle. Counted rather than pattern-matched: two managers
    // would re-put one BEP44 record under two independently-held sequences, and
    // the lower-seq put loses, so whichever cycle falls behind stops keeping the
    // record alive while still reporting success. `start_self_did_republishing`
    // is `pub` inside its private module, so any module in `scp-node` could call
    // it; the count says how many do.
    let call_sites = NODE_BUILDER_SRC
        .matches("start_self_did_republishing(")
        .count()
        + NODE_SELF_HOST_SRC
            .matches("start_self_did_republishing(")
            .count();
    assert_eq!(
        call_sites, 1,
        "exactly one function may start the cycle, and \
         `start_node_republish_cycle` is it"
    );

    assert!(
        NODE_BUILDER_SRC.contains("republish: Arc<dyn republish::RepublishCycle>,"),
        "ApplicationNode must hold the cycle in a non-optional field, so a node \
         carries exactly one by construction rather than by a caller remembering \
         to start one"
    );
    assert!(
        fn_body_contains(
            NODE_BUILDER_SRC,
            "shutdown",
            "self.republish.stop_and_wait()"
        ),
        "ApplicationNode::shutdown must stop both arms; an arm that outlived \
         shutdown would keep asserting this node's address on the DHT for the \
         life of the process (§10.12.1)"
    );
}

/// Asserts that `steps` occur in `body` in the given order, each after the one
/// before it.
fn assert_steps_in_order(bridge: &str, body: &str, steps: &[&str]) {
    let mut from = 0;
    for step in steps {
        let Some(at) = body[from..].find(step) else {
            panic!("{bridge} node_start_on must run `{step}` after the steps before it");
        };
        from += at + step.len();
    }
}

/// Each bridge's `node_start` delegates to `server::node_start(` and runs its
/// steps in the order construction.md §"Node start — `NodeStartConfig`" and
/// SCP-322 give: the handle check (UniFFI), the config parse or conversion,
/// operator identity resolution, the instance storage, `server::node_start`,
/// `server::register_node`, `auto_wire_context_manager`, and the handle. An
/// unregistered operator identity is `OperatorIdentityUnavailable`.
#[test]
fn every_bridge_node_start_delegates_to_server_node_start_in_order() {
    let pyo3 = extract_fn_body(PYO3_SERVER_SRC, "node_start_on")
        .expect("PyO3 server.rs must define node_start_on");
    assert_steps_in_order(
        "PyO3",
        &pyo3,
        &[
            "NodeStartConfig::from_json(",
            "resolve_operator_identity(",
            "instance_storage(",
            "server::node_start(",
            "server::register_node(",
            "auto_wire_context_manager(",
            "PyNodeHandle {",
        ],
    );
    let napi = extract_fn_body(NAPI_SERVER_SRC, "node_start_on")
        .expect("napi server.rs must define node_start_on");
    assert_steps_in_order(
        "napi-rs",
        &napi,
        &[
            "NodeStartConfig::from_json(",
            "resolve_operator_identity(",
            ".instance_storage()",
            "server::node_start(",
            "server::register_node(",
            "auto_wire_context_manager(",
            "NapiNodeHandle {",
        ],
    );
    let uniffi = extract_fn_body(UNIFFI_SERVER_SRC, "node_start_on")
        .expect("UniFFI server.rs must define node_start_on");
    assert_steps_in_order(
        "UniFFI",
        &uniffi,
        &[
            ".check_handle(",
            "lower_node_start_config(",
            "build_node_identity_from_uniffi(",
            ".instance_storage()",
            "server::node_start(",
            "server::register_node(",
            "auto_wire_context_manager(",
            "NodeHandle {",
        ],
    );

    // The exported entry points reach `node_start_on`.
    assert!(
        fn_body_contains(PYO3_SERVER_SRC, "node_start", "node_start_on("),
        "PyO3 SCP.node_start must delegate to node_start_on"
    );
    assert!(
        fn_body_contains(NAPI_SCP_SRC, "node_start", "crate::server::node_start_on("),
        "napi-rs Scp.nodeStart must delegate to node_start_on"
    );
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "node_start",
            "crate::server::node_start_on("
        ),
        "UniFFI Scp.node_start must delegate to node_start_on"
    );

    // Identity resolution: PyO3 and napi-rs look the DID up in the instance
    // registry, and a miss is `OperatorIdentityUnavailable` (SCP-IDENT-1063).
    for (bridge, src) in [("PyO3", PYO3_SERVER_SRC), ("napi-rs", NAPI_SERVER_SRC)] {
        assert!(
            fn_body_contains(src, "resolve_operator_identity", "build_node_identity("),
            "{bridge} resolve_operator_identity must call build_node_identity"
        );
        assert!(
            fn_body_contains(
                src,
                "build_node_identity",
                "ServerError::OperatorIdentityUnavailable"
            ),
            "{bridge} build_node_identity must map a registry miss to \
             OperatorIdentityUnavailable"
        );
    }
    assert!(
        fn_body_contains(
            UNIFFI_SERVER_SRC,
            "build_node_identity_from_uniffi",
            "ServerError::OperatorIdentityUnavailable"
        ),
        "UniFFI build_node_identity_from_uniffi must map a handle without key \
         material to OperatorIdentityUnavailable"
    );
}

/// Each bridge's node handle `shutdown` and `Drop` stop the node through
/// `server::stop_node(`, which unbinds the instance's `Supervisor` transport
/// from that node (construction.md §"Node start — `NodeStartConfig`"). A path
/// that called only `RunningNode::shutdown` would leave the binding in place,
/// so the instance's sends would go on targeting a stopped relay.
#[test]
fn every_bridge_node_handle_stop_path_calls_server_stop_node() {
    for (bridge, src, handle_impl, drop_impl) in [
        (
            "PyO3",
            PYO3_SERVER_SRC,
            "impl PyNodeHandle {",
            "impl Drop for PyNodeHandle {",
        ),
        (
            "napi-rs",
            NAPI_SERVER_SRC,
            "impl NapiNodeHandle {",
            "impl Drop for NapiNodeHandle {",
        ),
        (
            "UniFFI",
            UNIFFI_SERVER_SRC,
            "impl NodeHandle {",
            "impl Drop for NodeHandle {",
        ),
    ] {
        for (label, header, method) in [
            ("shutdown", handle_impl, "shutdown"),
            ("Drop", drop_impl, "drop"),
        ] {
            let at = src
                .find(header)
                .unwrap_or_else(|| panic!("{bridge} server.rs must contain `{header}`"));
            let body = extract_fn_body(&src[at..], method)
                .unwrap_or_else(|| panic!("{bridge} `{header}` must define fn {method}"));
            assert!(
                body.contains("server::stop_node("),
                "{bridge} node handle {label} must call server::stop_node"
            );
        }
    }
}

/// Verifies that the root AGENTS.md contains the required enforcement sections.
/// These sections instruct agents to check integration wiring before
/// writing code and to never weaken enforcement files.
#[test]
fn agents_md_enforcement_sections_present() {
    let agents_md = include_str!("../../../../AGENTS.md");
    assert!(
        agents_md.contains("Integration checklist (MANDATORY"),
        "AGENTS.md must contain the 'Integration checklist (MANDATORY' section"
    );
    assert!(
        agents_md.contains("NEVER modify enforcement files"),
        "AGENTS.md must contain the 'NEVER modify enforcement files' section"
    );
}

/// Spec 09 §9.7.1: the inviter verifies the invitee `KeyPackage`'s `0xFF03`
/// attestation against the invitee's `#active` key before it seals anything
/// to the `0xFF01` wrapping key that attestation binds.
#[test]
fn invite_member_verifies_the_key_package_attestation_before_sealing() {
    let body = extract_fn_body(SUPERVISOR_SRC, "invite_member")
        .expect("supervisor.rs must define invite_member");
    let verify = body
        .find(".verify_key_package_attestation(")
        .expect("invite_member must call verify_key_package_attestation");
    let seal = body
        .find("envelope_seal::hpke_seal_invitation(")
        .expect("invite_member must seal the invitation");
    assert!(
        verify < seal,
        "invite_member must verify the attestation before it seals the invitation"
    );
}

/// Spec 09 §9.7.1: every bridge's self-join (`context_join`) mints its
/// `KeyPackage` through the supervisor's attested mint, so the leaf carries a
/// `0xFF03` attestation signed by the joiner's `#active` key.
#[test]
fn every_bridge_self_join_mints_an_attested_key_package() {
    for (bridge, src, entry, minter) in [
        (
            "PyO3",
            PYO3_CONTEXT_SRC,
            "context_join",
            "mint_self_join_key_package",
        ),
        (
            "NAPI",
            NAPI_CONTEXT_SRC,
            "context_join_on",
            "mint_self_join_key_package",
        ),
        (
            "UniFFI",
            UNIFFI_BRIDGE_SRC,
            "context_join",
            "mint_self_join_key_package",
        ),
    ] {
        assert!(
            fn_body_contains(src, entry, &format!("{minter}(")),
            "{bridge} {entry} must mint its KeyPackage through {minter}"
        );
        assert!(
            fn_body_contains(src, minter, ".mint_attested_key_package("),
            "{bridge} {minter} must call Supervisor::mint_attested_key_package"
        );
    }
}

/// Spec 09 §9.16.2 Open: the Welcome join loads the joiner's wrapping key,
/// runs the KEM Diffie-Hellman through custody on its handle, and opens the
/// invitation, all before it takes `bootstrap_spawn_lock`, so a slow custody
/// never holds the node-wide bootstrap lock.
#[test]
fn spawn_actor_from_welcome_agrees_through_the_wrapping_key_before_the_bootstrap_lock() {
    let body = extract_fn_body(SUPERVISOR_SRC, "spawn_actor_from_welcome")
        .expect("supervisor.rs must define spawn_actor_from_welcome");
    let mut from = 0;
    for step in [
        ".load_wrapping_key(",
        ".agree(",
        "hpke_open_invitation_with_external_dh(",
        "bootstrap_spawn_lock.lock()",
    ] {
        let Some(at) = body[from..].find(step) else {
            panic!("spawn_actor_from_welcome must run `{step}` after the steps before it");
        };
        from += at + step.len();
    }
}

// --- One relay-visible envelope per member publish (ADR-002, spec 23 §23.4.1) ---

/// `seal` returns the serialized MLS message: it builds no envelope, because
/// the transport adds the only one.
#[test]
fn seal_builds_no_outer_envelope() {
    let body = extract_fn_body(STATE_SRC, "seal").expect("state.rs must define seal");
    assert!(
        !body.contains("create_outer_envelope") && !body.contains("frame_mls_message"),
        "seal must return the MLS message without framing it"
    );
}

/// Every Commit publish goes through `publish_commit`: the first broadcast
/// (`try_broadcast_commit`) and the retry of a queued Commit
/// (`compute_commit_retry_outcomes`).
#[test]
fn commit_publishes_go_through_publish_commit() {
    const GOVERNANCE_HELPERS_SRC: &str =
        include_str!("../../../../crates/scp-runtime/src/context/governance_helpers.rs");
    const HANDLERS_GOVERNANCE_SRC: &str =
        include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/governance.rs");
    assert!(
        fn_body_contains(
            GOVERNANCE_HELPERS_SRC,
            "try_broadcast_commit",
            "publish_commit("
        ),
        "try_broadcast_commit must publish through publish_commit"
    );
    assert!(
        fn_body_contains(
            HANDLERS_GOVERNANCE_SRC,
            "compute_commit_retry_outcomes",
            "publish_commit("
        ),
        "compute_commit_retry_outcomes must publish through publish_commit"
    );
}

/// The Phase 5 Update (spec 23 §23.3) publishes through the Commit retry
/// queue's entry point, so a failed publish is queued, not lost.
#[test]
fn the_phase_5_update_publishes_through_try_broadcast_commit() {
    const HANDLERS_LIFECYCLE_SRC: &str =
        include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/lifecycle.rs");
    let body = extract_fn_body(HANDLERS_LIFECYCLE_SRC, "handle_issue_mls_update_actor")
        .expect("handlers/lifecycle.rs must define handle_issue_mls_update_actor");
    let broadcast = body
        .find("try_broadcast_commit(")
        .expect("the IssueMlsUpdate handler must call try_broadcast_commit");
    assert!(
        body[broadcast..].contains("keep_broadcast_failure("),
        "the IssueMlsUpdate handler must queue a failed publish with keep_broadcast_failure"
    );
}

/// No Commit producer publishes Commit bytes with a direct
/// `send_message(` call; `publish_commit` is the only one.
#[test]
fn no_commit_producer_sends_commit_bytes_directly() {
    const GOVERNANCE_HELPERS_SRC: &str =
        include_str!("../../../../crates/scp-runtime/src/context/governance_helpers.rs");
    const LIFECYCLE_HELPERS_SRC_FULL: &str =
        include_str!("../../../../crates/scp-runtime/src/context/lifecycle_helpers.rs");
    const TRUST_RECOVERY_HELPERS_SRC: &str =
        include_str!("../../../../crates/scp-runtime/src/context/trust_recovery_helpers.rs");
    const HANDLERS_LIFECYCLE_SRC: &str =
        include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/lifecycle.rs");
    let publish_commit = extract_fn_body(GOVERNANCE_HELPERS_SRC, "publish_commit")
        .expect("governance_helpers.rs must define publish_commit");
    let governance = strip_non_code(GOVERNANCE_HELPERS_SRC);
    assert!(
        governance.contains(&publish_commit),
        "the publish_commit body must be found in the stripped source"
    );
    let governance = governance.replacen(&publish_commit, "", 1);
    for (file, code) in [
        ("governance_helpers.rs", governance),
        (
            "lifecycle_helpers.rs",
            strip_non_code(LIFECYCLE_HELPERS_SRC_FULL),
        ),
        (
            "trust_recovery_helpers.rs",
            strip_non_code(TRUST_RECOVERY_HELPERS_SRC),
        ),
        (
            "handlers/lifecycle.rs",
            strip_non_code(HANDLERS_LIFECYCLE_SRC),
        ),
    ] {
        for (at, _) in code.match_indices("send_message(") {
            let args = &code[at..];
            let args = &args[..args.find(')').unwrap_or(args.len())];
            assert!(
                !args.contains("commit"),
                "{file} sends Commit bytes directly ({args}); publish them through publish_commit"
            );
        }
    }
}

/// ADR-029 §2 sync-state keys: `record_relay_contact` is the one writer of
/// `last_relay_contact`, and the live delivery, the push-wake pull and the
/// full reconnection all record their contact through it.
#[test]
fn record_relay_contact_is_the_one_relay_contact_writer() {
    let body = extract_fn_body(RECONNECT_DRIVER_SRC, "record_relay_contact")
        .expect("reconnect.rs must define record_relay_contact");
    assert!(
        body.contains("store_last_relay_contact("),
        "record_relay_contact must write last_relay_contact"
    );
    let code = strip_non_code(RECONNECT_DRIVER_SRC);
    let production = &code[..code.rfind("mod tests").unwrap_or(code.len())];
    assert_eq!(
        production.matches("store_last_relay_contact(").count(),
        1,
        "record_relay_contact must be the only writer of last_relay_contact in reconnect.rs"
    );
    for writer in [
        "deliver_live_envelope",
        "wake_pull_context",
        "clear_and_record_contact",
    ] {
        assert!(
            fn_body_contains(RECONNECT_DRIVER_SRC, writer, "record_relay_contact("),
            "{writer} must record its relay contact through record_relay_contact"
        );
    }
    for (bridge, src) in [
        ("napi", NAPI_CONTEXT_SRC),
        ("pyo3", PYO3_CONTEXT_SRC),
        ("uniffi", UNIFFI_BRIDGE_SRC),
    ] {
        assert!(
            !strip_non_code(src).contains("store_last_relay_contact("),
            "the {bridge} bridge must not write last_relay_contact itself"
        );
    }
}

// ---------------------------------------------------------------------------
// Syntax-tree scans over every production file of a crate directory
// ---------------------------------------------------------------------------

/// Parses the production source of the crates under a directory and records,
/// per function, the names it calls and the names it mentions.
///
/// "Production" follows the module tree from each crate root (`src/lib.rs`,
/// `src/main.rs`, `src/bin/*.rs`, `build.rs`) and skips every item and module
/// gated on `cfg(test)`, so a test module in its own file is skipped as well.
/// Code inside an argument of a task spawn (`spawn`, `spawn_tracked`,
/// `spawn_tracked_on`, `spawn_local`, `spawn_under_bootstrap_spawn_lock`)
/// runs on its own task, so it is attributed to a synthetic caller named
/// `<spawned in fn>` (`FnFacts::spawned`), not to the function that spawns
/// it: a writer scan sees it, and a scan of what a turn waits on can leave
/// it out.
mod syn_scan {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use proc_macro2::{TokenStream, TokenTree};
    use syn::visit::{self, Visit};

    /// The calls whose arguments run on a task of their own.
    const SPAWNS: [&str; 5] = [
        "spawn",
        "spawn_tracked",
        "spawn_tracked_on",
        "spawn_local",
        "spawn_under_bootstrap_spawn_lock",
    ];

    /// One function's calls and mentions, outside spawned-task arguments, or
    /// one spawned-task argument's.
    #[derive(Debug, Default)]
    pub struct FnFacts {
        /// The facts are a spawned task's, named `<spawned in fn>` after the
        /// function that spawns it.
        pub spawned: bool,
        /// The self type of the enclosing `impl`, or empty for a free function.
        pub owner: String,
        pub name: String,
        pub file: PathBuf,
        /// Method and function names called, and `name(` inside macros.
        pub calls: BTreeSet<String>,
        /// The subset of `calls` made through a bare or module path
        /// (`name(..)`, `crate::module::name(..)`): each names a free
        /// function, never a method.
        pub free_calls: BTreeSet<String>,
        /// Field, path and macro-token identifiers.
        pub mentions: BTreeSet<String>,
    }

    /// `true` when a `#[cfg(..)]` in `attrs` holds only under `test`: it names
    /// `test` outside every `not(..)`.
    pub fn gated_on_test(attrs: &[syn::Attribute]) -> bool {
        fn names_test(tokens: TokenStream, under_not: bool) -> bool {
            let mut after_not = false;
            for tree in tokens {
                match tree {
                    TokenTree::Ident(ident) => {
                        if ident == "test" && !under_not {
                            return true;
                        }
                        after_not = ident == "not";
                    }
                    TokenTree::Group(group) => {
                        if names_test(group.stream(), under_not || after_not) {
                            return true;
                        }
                        after_not = false;
                    }
                    TokenTree::Punct(_) | TokenTree::Literal(_) => after_not = false,
                }
            }
            false
        }
        attrs.iter().any(|attr| {
            attr.path().is_ident("cfg")
                && matches!(&attr.meta, syn::Meta::List(list) if names_test(list.tokens.clone(), false))
        })
    }

    /// Every production source file of the crates whose `Cargo.toml` sits in
    /// `dir` or one level below it, parsed.
    ///
    /// # Panics
    ///
    /// When a file cannot be read or parsed, or a declared module has no file:
    /// a scan that skips a file proves nothing about it.
    pub fn production_files(dir: &Path) -> Vec<(PathBuf, syn::File)> {
        let mut crate_dirs = vec![dir.to_path_buf()];
        for entry in std::fs::read_dir(dir).expect("read crate directory") {
            let path = entry.expect("directory entry").path();
            if path.join("Cargo.toml").is_file() {
                crate_dirs.push(path);
            }
        }
        let mut roots = Vec::new();
        for crate_dir in crate_dirs.iter().filter(|d| d.join("Cargo.toml").is_file()) {
            for root in ["src/lib.rs", "src/main.rs", "build.rs"] {
                let path = crate_dir.join(root);
                if path.is_file() {
                    roots.push(path);
                }
            }
            if let Ok(bins) = std::fs::read_dir(crate_dir.join("src/bin")) {
                for bin in bins {
                    let path = bin.expect("bin entry").path();
                    if path.extension().is_some_and(|ext| ext == "rs") {
                        roots.push(path);
                    }
                }
            }
        }
        assert!(!roots.is_empty(), "no crate root under {}", dir.display());
        let mut files = Vec::new();
        let mut pending = roots;
        while let Some(path) = pending.pop() {
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let file =
                syn::parse_file(&src).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            let parent = path.parent().expect("file has a directory").to_path_buf();
            let is_mod_root = path.file_name().is_some_and(|n| {
                n == "mod.rs" || n == "lib.rs" || n == "main.rs" || n == "build.rs"
            }) || parent.ends_with("src/bin");
            let base = if is_mod_root {
                parent.clone()
            } else {
                parent.join(path.file_stem().expect("file stem"))
            };
            declared_modules(&file.items, &parent, &base, &mut pending);
            files.push((path, file));
        }
        files
    }

    /// Pushes the file of every non-test `mod name;` in `items`, descending
    /// into inline non-test modules.
    fn declared_modules(items: &[syn::Item], dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
        for item in items {
            let syn::Item::Mod(module) = item else {
                continue;
            };
            if gated_on_test(&module.attrs) {
                continue;
            }
            let name = module.ident.to_string();
            let explicit = module.attrs.iter().find_map(|attr| match &attr.meta {
                syn::Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) => Some(s.value()),
                    _ => None,
                },
                _ => None,
            });
            if let Some((_, inner)) = &module.content {
                let inner_base = base.join(&name);
                declared_modules(inner, dir, &inner_base, out);
                continue;
            }
            let candidates = explicit.map_or_else(
                || {
                    vec![
                        base.join(format!("{name}.rs")),
                        base.join(&name).join("mod.rs"),
                    ]
                },
                |rel| vec![dir.join(rel)],
            );
            let found = candidates
                .iter()
                .find(|p| p.is_file())
                .unwrap_or_else(|| panic!("module file for {candidates:?}"));
            out.push(found.clone());
        }
    }

    /// Records [`FnFacts`] for every non-test function in a file.
    #[derive(Default)]
    pub struct Collector {
        pub fns: Vec<FnFacts>,
        file: PathBuf,
        stack: Vec<usize>,
        owners: Vec<String>,
    }

    impl Collector {
        pub fn scan(files: &[(PathBuf, syn::File)]) -> Vec<FnFacts> {
            let mut collector = Self::default();
            for (path, file) in files {
                collector.file.clone_from(path);
                collector.visit_file(file);
            }
            collector.fns
        }

        fn enter(&mut self, name: String, spawned: bool) {
            self.fns.push(FnFacts {
                spawned,
                owner: self.owners.last().cloned().unwrap_or_default(),
                name,
                file: self.file.clone(),
                ..FnFacts::default()
            });
            self.stack.push(self.fns.len() - 1);
        }

        fn leave(&mut self) {
            self.stack.pop();
        }

        fn record_free_call(&mut self, name: String) {
            if let Some(&at) = self.stack.last() {
                self.fns[at].free_calls.insert(name);
            }
        }

        fn record(&mut self, call: bool, name: String) {
            if let Some(&at) = self.stack.last() {
                let facts = &mut self.fns[at];
                if call {
                    facts.calls.insert(name);
                } else {
                    facts.mentions.insert(name);
                }
            }
        }

        fn scan_tokens(&mut self, tokens: TokenStream) {
            let trees: Vec<TokenTree> = tokens.into_iter().collect();
            for (at, tree) in trees.iter().enumerate() {
                match tree {
                    TokenTree::Ident(ident) => {
                        let called = matches!(
                            trees.get(at + 1),
                            Some(TokenTree::Group(g))
                                if g.delimiter() == proc_macro2::Delimiter::Parenthesis
                        );
                        if called {
                            self.record(true, ident.to_string());
                        }
                        self.record(false, ident.to_string());
                    }
                    TokenTree::Group(group) => self.scan_tokens(group.stream()),
                    TokenTree::Punct(_) | TokenTree::Literal(_) => {}
                }
            }
        }

        fn visit_spawned_args<'a>(&mut self, args: impl Iterator<Item = &'a syn::Expr>) {
            let spawner = self
                .stack
                .last()
                .map(|&at| self.fns[at].name.clone())
                .unwrap_or_default();
            self.enter(format!("<spawned in {spawner}>"), true);
            for arg in args {
                self.visit_expr(arg);
            }
            self.leave();
        }
    }

    fn type_name(ty: &syn::Type) -> String {
        match ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }

    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if !gated_on_test(&node.attrs) {
                visit::visit_item_mod(self, node);
            }
        }

        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            if gated_on_test(&node.attrs) {
                return;
            }
            self.owners.push(type_name(&node.self_ty));
            visit::visit_item_impl(self, node);
            self.owners.pop();
        }

        fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
            if gated_on_test(&node.attrs) {
                return;
            }
            self.owners.push(node.ident.to_string());
            visit::visit_item_trait(self, node);
            self.owners.pop();
        }

        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            if gated_on_test(&node.attrs) {
                return;
            }
            self.owners.push(String::new());
            self.enter(node.sig.ident.to_string(), false);
            visit::visit_item_fn(self, node);
            self.leave();
            self.owners.pop();
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            if gated_on_test(&node.attrs) {
                return;
            }
            self.enter(node.sig.ident.to_string(), false);
            visit::visit_impl_item_fn(self, node);
            self.leave();
        }

        fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
            if gated_on_test(&node.attrs) {
                return;
            }
            self.enter(node.sig.ident.to_string(), false);
            visit::visit_trait_item_fn(self, node);
            self.leave();
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let method = node.method.to_string();
            self.record(true, method.clone());
            self.visit_expr(&node.receiver);
            if SPAWNS.contains(&method.as_str()) {
                self.visit_spawned_args(node.args.iter());
            } else {
                for arg in &node.args {
                    self.visit_expr(arg);
                }
            }
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            let syn::Expr::Path(path) = &*node.func else {
                visit::visit_expr_call(self, node);
                return;
            };
            let name = path
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            self.record(true, name.clone());
            // A bare or module path names a free function; `Type::name` and
            // `Self::name` may name a method.
            let segments = &path.path.segments;
            let module_path = path.qself.is_none()
                && (segments.len() == 1
                    || segments.iter().nth(segments.len() - 2).is_some_and(|s| {
                        s.ident
                            .to_string()
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_lowercase())
                    }));
            if module_path {
                self.record_free_call(name.clone());
            }
            self.visit_expr_path(path);
            if SPAWNS.contains(&name.as_str()) {
                self.visit_spawned_args(node.args.iter());
            } else {
                for arg in &node.args {
                    self.visit_expr(arg);
                }
            }
        }

        fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
            self.record(false, node.to_string());
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            self.scan_tokens(node.tokens.clone());
        }
    }
}

/// The directory that holds the workspace's crates.
fn crates_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Every caller of `store_last_relay_contact` in `facts`, a spawned task
/// as `<spawned in fn>`, each as `file::caller`.
fn relay_contact_writers(facts: &[syn_scan::FnFacts]) -> Vec<String> {
    facts
        .iter()
        .filter(|f| f.calls.contains("store_last_relay_contact"))
        .map(|f| format!("{}::{}", f.file.display(), f.name))
        .collect()
}

/// Fails unless `writers` is `record_relay_contact` in `reconnect.rs` alone.
fn assert_record_relay_contact_writes_alone(writers: &[String]) {
    assert_eq!(
        writers.len(),
        1,
        "store_last_relay_contact callers: {writers:?}"
    );
    assert!(
        writers[0].ends_with("reconnect.rs::record_relay_contact"),
        "the one caller must be record_relay_contact in reconnect.rs, got {writers:?}"
    );
}

/// ADR-029 §2 sync-state keys: across every production file of the FFI and
/// node crates, `store_last_relay_contact` is called only inside
/// `record_relay_contact`, so no bridge, node path, helper or task they
/// spawn writes the contact around the one writer the reconnection driver
/// owns.
#[test]
fn record_relay_contact_is_the_only_relay_contact_writer_in_ffi_and_node() {
    let mut writers = Vec::new();
    let mut scanned = 0_usize;
    for crate_dir in ["scp-ffi", "scp-node"] {
        let files = syn_scan::production_files(&crates_dir().join(crate_dir));
        scanned += files.len();
        writers.extend(relay_contact_writers(&syn_scan::Collector::scan(&files)));
    }
    assert!(scanned > 50, "the scan read only {scanned} files");
    assert_record_relay_contact_writes_alone(&writers);
}

/// The relay-contact gate fails on a `store_last_relay_contact` call inside
/// a task that a function beside `record_relay_contact` spawns.
#[test]
fn relay_contact_gate_fails_on_a_write_in_a_spawned_task() {
    let file: syn::File = syn::parse_str(
        "fn record_relay_contact() { s.store_last_relay_contact(id, 1); }\n\
         fn reconnect() { tokio::spawn(async move { s.store_last_relay_contact(id, 1).await }); }\n",
    )
    .expect("parse");
    let writers = relay_contact_writers(&syn_scan::Collector::scan(&[(
        std::path::PathBuf::from("reconnect.rs"),
        file,
    )]));
    assert_eq!(
        writers,
        [
            "reconnect.rs::record_relay_contact",
            "reconnect.rs::<spawned in reconnect>",
        ]
    );
    let gate = std::panic::catch_unwind(|| assert_record_relay_contact_writes_alone(&writers));
    assert!(gate.is_err(), "the gate must fail on the spawned writer");
}

/// The writer scan sees a call inside a macro, attributes a call inside a
/// spawned task to `<spawned in fn>`, skips a `cfg(test)` module and a
/// test-gated function, and keeps a `cfg(not(test))` function.
#[test]
fn syn_scan_records_macro_calls_and_skips_test_code() {
    let file: syn::File = syn::parse_str(
        "fn in_macro() { tokio::select! { _ = s.store_last_relay_contact(id, 1) => {} } }\n\
         fn in_task() { tokio::spawn(async move { s.store_last_relay_contact(id, 1).await }); }\n\
         #[cfg(test)] mod tests { fn t() { s.store_last_relay_contact(id, 1); } }\n\
         #[cfg(any(test, feature = \"testing\"))] fn gated() { s.store_last_relay_contact(id, 1); }\n\
         #[cfg(not(test))] fn kept() { s.store_last_relay_contact(id, 1); }\n",
    )
    .expect("parse");
    let facts = syn_scan::Collector::scan(&[(std::path::PathBuf::from("x.rs"), file)]);
    let callers: Vec<(&str, bool)> = facts
        .iter()
        .filter(|f| f.calls.contains("store_last_relay_contact"))
        .map(|f| (f.name.as_str(), f.spawned))
        .collect();
    assert_eq!(
        callers,
        [
            ("in_macro", false),
            ("<spawned in in_task>", true),
            ("kept", false)
        ]
    );
}

/// `true` when `f` awaits `bootstrap_spawn_lock` on its own turn: it is not
/// a spawned task, mentions the lock, and calls `lock` or `lock_owned`.
/// `try_lock` and `try_lock_owned` never wait.
fn awaits_bootstrap_lock(f: &syn_scan::FnFacts) -> bool {
    !f.spawned
        && f.mentions.contains("bootstrap_spawn_lock")
        && (f.calls.contains("lock") || f.calls.contains("lock_owned"))
}

/// The files whose functions an actor turn calls with a `Weak<Supervisor>`
/// in hand, outside `SupervisorHandle`: the outlet stream adapters.
const ACTOR_TURN_ADAPTER_FILES: [&str; 2] =
    ["stream_settlement_adapter.rs", "stream_counter_adapter.rs"];

/// `true` when an actor turn reaches the Supervisor through `f`: a
/// `SupervisorHandle` method, or a function of an outlet stream adapter that
/// holds a `Weak<Supervisor>`. A spawned task runs on its own task.
fn actor_turn_entry(f: &syn_scan::FnFacts) -> bool {
    !f.spawned
        && (f.owner == "SupervisorHandle"
            || f.file
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| ACTOR_TURN_ADAPTER_FILES.contains(&name)))
}

/// Every actor-turn entry in `facts` (`actor_turn_entry`) that awaits
/// `bootstrap_spawn_lock` on its own turn, directly or through the functions
/// it calls, each with the call path that reaches the lock.
///
/// A call through a bare or module path resolves to the free functions of
/// its name; every other call resolves to every function of its name, so a
/// method name shared with a lock taker counts as a call of it: the check
/// over-approximates and never misses a path.
fn handle_paths_to_the_bootstrap_lock(facts: &[syn_scan::FnFacts]) -> Vec<String> {
    // Keyed by (is a free function, name).
    let mut reach: std::collections::BTreeMap<(bool, String), String> = facts
        .iter()
        .filter(|f| !actor_turn_entry(f) && awaits_bootstrap_lock(f))
        .map(|f| ((f.owner.is_empty(), f.name.clone()), f.name.clone()))
        .collect();
    let reached = |reach: &std::collections::BTreeMap<(bool, String), String>,
                   f: &syn_scan::FnFacts| {
        f.calls.iter().find_map(|c| {
            let free = reach.get(&(true, c.clone()));
            if f.free_calls.contains(c) {
                free.cloned()
            } else {
                free.or_else(|| reach.get(&(false, c.clone()))).cloned()
            }
        })
    };
    loop {
        let mut grew = false;
        // A spawned task runs on its own task, never on its spawner's turn.
        for f in facts.iter().filter(|f| !f.spawned && !actor_turn_entry(f)) {
            let key = (f.owner.is_empty(), f.name.clone());
            if reach.contains_key(&key) {
                continue;
            }
            if let Some(path) = reached(&reach, f) {
                reach.insert(key, format!("{} -> {path}", f.name));
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    facts
        .iter()
        .filter(|f| actor_turn_entry(f))
        .filter_map(|f| {
            let entry = if f.owner.is_empty() {
                f.file
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
            } else {
                f.owner.clone()
            };
            if awaits_bootstrap_lock(f) {
                return Some(format!("{entry}::{} awaits the lock", f.name));
            }
            reached(&reach, f).map(|path| format!("{entry}::{} -> {path}", f.name))
        })
        .collect()
}

/// ADR-049 lock order: a holder of `bootstrap_spawn_lock` waits on actor
/// mailboxes, so no actor turn may wait on that lock. An actor turn reaches
/// the Supervisor through `SupervisorHandle` or through an outlet stream
/// adapter holding a `Weak<Supervisor>`, so no method of either may await the
/// lock on its own turn, directly or through any function it calls. A method that needs the lock try-locks it and returns a
/// retryable `ActorBusy`, or hands the work to a task that takes the lock.
#[test]
fn no_actor_turn_waits_on_the_bootstrap_spawn_lock() {
    let files = syn_scan::production_files(&crates_dir().join("scp-runtime"));
    let facts = syn_scan::Collector::scan(&files);
    let handle_fns = facts
        .iter()
        .filter(|f| !f.spawned && f.owner == "SupervisorHandle")
        .count();
    assert!(
        handle_fns > 20,
        "the scan found only {handle_fns} SupervisorHandle methods"
    );
    for adapter in ACTOR_TURN_ADAPTER_FILES {
        let entries = facts
            .iter()
            .filter(|f| actor_turn_entry(f) && f.file.ends_with(adapter))
            .count();
        assert!(
            entries > 2,
            "the scan found only {entries} functions of {adapter}"
        );
    }
    let takers: Vec<&str> = facts
        .iter()
        .filter(|f| awaits_bootstrap_lock(f))
        .map(|f| f.name.as_str())
        .collect();
    assert!(
        takers.contains(&"dispatch_lifecycle_direct"),
        "the scan must see the Supervisor's lifecycle arms await the lock, found {takers:?}"
    );
    for nonblocking in [
        "try_lock_bootstrap_spawn",
        "spawn_under_bootstrap_spawn_lock",
    ] {
        assert!(
            !takers.contains(&nonblocking),
            "{nonblocking} must not wait on bootstrap_spawn_lock on its caller's turn"
        );
    }
    let paths = handle_paths_to_the_bootstrap_lock(&facts);
    assert!(
        paths.is_empty(),
        "actor turns that wait on bootstrap_spawn_lock: {paths:#?}"
    );
}

/// The lock scan flags a handle method, or an outlet stream adapter's
/// function, that awaits the lock directly or through a Supervisor function,
/// and passes a try-lock, a lock taken inside a spawned task, and a
/// module-path call of a free function that shares a lock taker's method
/// name.
#[test]
fn bootstrap_lock_scan_flags_a_waiting_handle_method() {
    let file: syn::File = syn::parse_str(
        "impl SupervisorHandle {\n\
             async fn lock_bootstrap_spawn(&self) { self.upgrade()?.bootstrap_spawn_lock.lock().await; }\n\
             async fn via_supervisor(&self) { self.upgrade()?.respawn_x().await; }\n\
             fn try_it(&self) { self.upgrade()?.bootstrap_spawn_lock.try_lock_owned(); }\n\
             fn spawned(&self) { spawn_tracked(async move { l.bootstrap_spawn_lock.lock().await; }); }\n\
             async fn via_free(&self) { crate::helpers::restore_y().await; }\n\
             async fn via_method(&self) { self.upgrade()?.restore_y().await; }\n\
         }\n\
         impl Supervisor {\n\
             async fn respawn_x(&self) { self.respawn_locked().await; }\n\
             async fn respawn_locked(&self) { let _g = self.bootstrap_spawn_lock.lock().await; }\n\
             async fn restore_y(&self) { let _g = self.bootstrap_spawn_lock.lock().await; }\n\
         }\n\
         async fn restore_y() {}\n",
    )
    .expect("parse");
    let adapter: syn::File = syn::parse_str(
        "impl ActorStreamSettlementSink {\n\
             async fn settle(&self) { self.supervisor.upgrade()?.respawn_x().await; }\n\
             fn queued(&self) { spawn_tracked(async move { s.respawn_x().await; }); }\n\
         }\n\
         async fn dispatch(supervisor: &Weak<Supervisor>) { supervisor.upgrade()?.restore_y().await; }\n",
    )
    .expect("parse");
    let facts = syn_scan::Collector::scan(&[
        (std::path::PathBuf::from("x.rs"), file),
        (
            std::path::PathBuf::from("outlets/stream_settlement_adapter.rs"),
            adapter,
        ),
    ]);
    assert_eq!(
        handle_paths_to_the_bootstrap_lock(&facts),
        [
            "SupervisorHandle::lock_bootstrap_spawn awaits the lock",
            "SupervisorHandle::via_supervisor -> respawn_x -> respawn_locked",
            "SupervisorHandle::via_method -> restore_y",
            "ActorStreamSettlementSink::settle -> respawn_x -> respawn_locked",
            "stream_settlement_adapter.rs::dispatch -> restore_y",
        ]
    );
}

/// PUSH-014 criterion 4 (§10.7.1, ADR-004 **Push registration interception**):
/// `PushRegistrar::register` reaches a relay PUBLISH at the relay's own push
/// routing ID. `register` → `prepare_registration`, which refuses a tier 3
/// relay, signs the preimage from `push_registration_signing_bytes` and
/// addresses the message to `push_routing_id()` → `publish_all` →
/// `PushRelayPublisher::publish` → `TransportPushPublisher::publish` →
/// `publish_raw` at that routing ID. The trigger task reaches `register`
/// through `reconcile`, which reads `push_routing_ids`.
#[test]
fn push_registrar_register_reaches_relay_publish() {
    for (src, caller, callee) in [
        (PUSH_REGISTRAR_SRC, "register", "self.prepare_registration("),
        (PUSH_REGISTRAR_SRC, "register", "self.publish_all("),
        (PUSH_REGISTRAR_SRC, "prepare_registration", "refuse_tier3("),
        (
            PUSH_REGISTRAR_SRC,
            "prepare_registration",
            "push_registration_signing_bytes(",
        ),
        (
            PUSH_REGISTRAR_SRC,
            "prepare_registration",
            ".sign_preimage(",
        ),
        (
            PUSH_REGISTRAR_SRC,
            "prepare_registration",
            "push_routing_id: target.relay.push_routing_id()",
        ),
        (
            PUSH_REGISTRAR_SRC,
            "publish_all",
            ".publish(&relay_url, push_routing_id, blob)",
        ),
        (PUSH_REGISTRAR_SRC, "reconcile", ".push_routing_ids()"),
        (PUSH_REGISTRAR_SRC, "reconcile", "self.register(&changed)"),
        (PUSH_REGISTRAR_SRC, "reconcile_and_log", "self.reconcile("),
        (PUSH_REGISTRAR_SRC, "spawn_trigger", "self.run("),
        (PUSH_PUBLISHER_SRC, "publish", ".publish_raw("),
        (PUSH_PUBLISHER_SRC, "publish", "RoutingId::new(routing_id)"),
    ] {
        assert!(
            fn_body_contains(src, caller, callee),
            "`{caller}` must contain `{callee}`"
        );
    }
}

/// Spec 17 §17.3 "Event log write failures": an actor's shutdown releases its
/// context's in-memory event log and write gate, and never destroys the log.
/// Shutdown is not a deletion; destroying the log there deleted the stored log
/// of every context at every process stop.
#[test]
fn shutdown_releases_the_event_log_and_never_destroys_it() {
    const HANDLERS_LIFECYCLE_SRC: &str =
        include_str!("../../../../crates/scp-runtime/src/context/actor/handlers/lifecycle.rs");
    let code = strip_non_code(HANDLERS_LIFECYCLE_SRC);
    let body = extract_fn_body(&code, "handle_shutdown_self_actor")
        .expect("handlers/lifecycle.rs must define handle_shutdown_self_actor");
    assert!(
        body.contains(".release_event_log("),
        "handle_shutdown_self_actor must release the context's event log"
    );
    assert!(
        !body.contains("destroy_event_log"),
        "handle_shutdown_self_actor must not destroy the context's event log"
    );
}

/// Spec 17 §17.17 (capability classification): an event log with no store is
/// a test construct. `MerkleEventLogProvider::new()` and its `Default` build
/// one, so no shipped source under `crates/` calls either; production builds
/// the provider with `with_persistence`.
///
/// Test code is code the compiler builds only under `test` or a `testing`
/// feature, which the shipped-feature-graph gate keeps out of every shipped
/// artifact:
/// - a `mod` block gated by such a `cfg`;
/// - a file declared by such a gated `mod name;`;
/// - a crate on [`TEST_ONLY_CRATES`], each of which every other workspace
///   manifest reaches only through `[dev-dependencies]` or an optional
///   dependency that only a `testing` feature enables.
///
/// Every other crate is shipped, including one that no manifest names: the
/// bridges and the relay ship as libraries and binaries of their own.
#[test]
fn no_shipped_source_builds_an_event_log_without_a_store() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("scp-testing sits under crates/");
    let mut crate_dirs = Vec::new();
    for krate in std::fs::read_dir(crates)
        .expect("crates/ is readable")
        .flatten()
    {
        let dir = krate.path();
        if dir.join("Cargo.toml").is_file() {
            crate_dirs.push(dir.clone());
        }
        // Nested crates such as `scp-ffi/napi` keep their own manifest.
        if let Ok(nested) = std::fs::read_dir(&dir) {
            for sub in nested.flatten() {
                if sub.path().join("Cargo.toml").is_file() {
                    crate_dirs.push(sub.path());
                }
            }
        }
    }
    let manifests: Vec<String> = crate_dirs
        .iter()
        .map(|dir| std::fs::read_to_string(dir.join("Cargo.toml")).expect("a manifest is readable"))
        .collect();

    let mut files = Vec::new();
    // A crate counts as scanned only when its `src` walk yields a file, so a
    // moved or unreadable source tree fails the must-cover check below
    // instead of passing it with nothing read.
    let mut scanned = std::collections::BTreeMap::new();
    let mut test_only = std::collections::BTreeSet::new();
    for (dir, manifest) in crate_dirs.iter().zip(&manifests) {
        let name = manifest_package_name(manifest).expect("a manifest names its package");
        if TEST_ONLY_CRATES.contains(&name.as_str()) {
            let others = manifests.iter().filter(|m| !std::ptr::eq(*m, manifest));
            assert!(
                reached_only_by_tests(&name, others),
                "{name} is listed as test-only, but a manifest ships it"
            );
            test_only.insert(name);
            continue;
        }
        let before = files.len();
        collect_rust_files(&dir.join("src"), &mut files);
        let found = files.len() - before;
        if found > 0 {
            scanned.insert(name, found);
        }
    }
    assert_eq!(
        test_only,
        TEST_ONLY_CRATES
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        "every test-only crate names a workspace crate"
    );
    for shipped in [
        "scp-ffi",
        "scp-ffi-napi",
        "scp-ffi-uniffi",
        "scp-relay",
        "scp-client-wasm",
    ] {
        let found = scanned.get(shipped).copied().unwrap_or(0);
        assert!(
            found >= 1,
            "the scan must read at least one source file of {shipped}, read {found}: {scanned:?}"
        );
    }
    assert!(
        files.len() > 100,
        "the walk must reach the workspace sources, found {}",
        files.len()
    );

    let sources: Vec<(std::path::PathBuf, String, String)> = files
        .into_iter()
        .map(|file| {
            let src = std::fs::read_to_string(&file).expect("a source file is readable");
            let code = strip_non_code_keeping_cfg(&src);
            (file, src, code)
        })
        .collect();
    let test_files: std::collections::HashSet<std::path::PathBuf> = sources
        .iter()
        .flat_map(|(file, src, code)| test_gated_mod_files(file, src, code))
        .collect();

    let mut offenders = Vec::new();
    for (file, _, code) in &sources {
        if test_files.contains(file) {
            continue;
        }
        offenders.extend(
            store_free_event_log_calls(code)
                .into_iter()
                .map(|call| format!("{}: {call}", file.display())),
        );
    }
    assert!(
        offenders.is_empty(),
        "shipped sources build an event log with no store: {offenders:#?}"
    );
}

/// The workspace crates the store-free scan skips: each is reached only by
/// tests, which the scan asserts.
const TEST_ONLY_CRATES: &[&str] = &["scp-testing", "scp-relay-mock", "scp-ffi-napi-test-stubs"];

/// The scan's own rules: a call in shipped code is reported, and the same
/// call inside a test-gated module is not.
#[test]
fn the_store_free_event_log_scan_reports_shipped_calls_only() {
    let shipped = strip_non_code_keeping_cfg(
        "fn build() -> Box<dyn P> { Box::new(MerkleEventLogProvider::new()) }\n\
         fn other() { let _ = MerkleEventLogProvider::default(); }\n",
    );
    assert_eq!(store_free_event_log_calls(&shipped).len(), 2);
    let gated = strip_non_code_keeping_cfg(
        "fn build() -> Box<dyn P> { Box::new(MerkleEventLogProvider::with_persistence(s)) }\n\
         #[cfg(test)]\nmod shutdown_sweep_tests { fn s() { MerkleEventLogProvider::new(); } }\n\
         #[cfg(all(test, feature = \"testing\"))]\n#[allow(clippy::unwrap_used)]\n\
         mod restore_tests { fn r() { MerkleEventLogProvider::new(); } }\n\
         #[cfg(feature = \"testing\")]\npub mod fixtures { fn f() { MerkleEventLogProvider::new(); } }\n",
    );
    assert!(store_free_event_log_calls(&gated).is_empty());
    let any_cfg = strip_non_code_keeping_cfg(
        "#[cfg(any(test, feature = \"server\"))]\nmod shipped { fn s() { MerkleEventLogProvider::new(); } }\n",
    );
    assert_eq!(
        store_free_event_log_calls(&any_cfg).len(),
        1,
        "a cfg that a shipped feature satisfies does not make a module test code"
    );

    let declaring = std::path::Path::new("/w/crates/c/src/context/mod.rs");
    let raw = "#[cfg(test)]\nmod pipeline_tests;\n\
               #[cfg(test)]\n#[path = \"welcome_tests.rs\"]\nmod welcome;\n\
               mod shipped;\n";
    let found = test_gated_mod_files(declaring, raw, &strip_non_code_keeping_cfg(raw));
    assert!(found.contains(&std::path::PathBuf::from(
        "/w/crates/c/src/context/pipeline_tests.rs"
    )));
    assert!(found.contains(&std::path::PathBuf::from(
        "/w/crates/c/src/context/welcome_tests.rs"
    )));
    assert!(!found.iter().any(|p| p.ends_with("shipped.rs")));

    let manifest_dev =
        "[package]\nname = \"a\"\n[dev-dependencies]\nsupport = { path = \"../s\" }\n";
    let manifest_opt = "[package]\nname = \"b\"\n[features]\ntesting = [\n    \"dep:support\",\n]\n\
                        [dependencies]\nsupport = { path = \"../s\", optional = true }\n";
    let manifest_shipped =
        "[package]\nname = \"c\"\n[dependencies]\nsupport = { path = \"../s\" }\n";
    let manifest_server = "[package]\nname = \"d\"\n[features]\nserver = [\"dep:support\"]\n\
                           [dependencies]\nsupport = { path = \"../s\", optional = true }\n";
    let as_vec = |ms: &[&str]| ms.iter().map(|m| (*m).to_owned()).collect::<Vec<_>>();
    assert!(reached_only_by_tests(
        "support",
        as_vec(&[manifest_dev, manifest_opt]).iter()
    ));
    assert!(!reached_only_by_tests(
        "support",
        as_vec(&[manifest_dev, manifest_shipped]).iter()
    ));
    assert!(!reached_only_by_tests(
        "support",
        as_vec(&[manifest_server]).iter()
    ));
}

/// [`strip_non_code`] with each `#[cfg(...)]` attribute restored from `src`,
/// so a `feature = "testing"` predicate keeps its feature name. The cleaner
/// blanks one char per char, so a char index in its output is the same char
/// index in `src`.
fn strip_non_code_keeping_cfg(src: &str) -> String {
    let raw: Vec<char> = src.chars().collect();
    let mut code: Vec<char> = strip_non_code(src).chars().collect();
    assert_eq!(raw.len(), code.len(), "the cleaner keeps one char per char");
    let opener: Vec<char> = "#[cfg(".chars().collect();
    let mut i = 0;
    while i + opener.len() <= code.len() {
        if code[i..i + opener.len()] != opener[..] {
            i += 1;
            continue;
        }
        // Blanked strings hold no bracket, so depth counting in `code` finds
        // the attribute's closing `]`.
        let mut depth = 0usize;
        let mut end = None;
        for (j, ch) in code.iter().enumerate().skip(i + 1) {
            match ch {
                '[' => depth += 1,
                ']' if depth <= 1 => {
                    end = Some(j);
                    break;
                }
                ']' => depth -= 1,
                _ => {}
            }
        }
        let Some(end) = end else { break };
        code[i..=end].copy_from_slice(&raw[i..=end]);
        i = end + 1;
    }
    code.into_iter().collect()
}

fn collect_rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every store-free event-log construction in `code` (from
/// [`strip_non_code`]) outside a test-gated `mod` block.
fn store_free_event_log_calls(code: &str) -> Vec<&'static str> {
    let shipped: String = without_test_gated_mod_blocks(code)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    [
        "MerkleEventLogProvider::new()",
        "MerkleEventLogProvider::default()",
    ]
    .into_iter()
    .filter(|call| shipped.contains(call))
    .collect()
}

/// Whether a normalized `#[cfg(...)]` attribute holds only when `test` or the
/// `testing` feature is on.
fn cfg_requires_test(attr: &str) -> bool {
    let attr: String = attr.split_whitespace().collect();
    attr == "#[cfg(test)]"
        || attr == "#[cfg(feature=\"testing\")]"
        || attr == "#[cfg(any(test,feature=\"testing\"))]"
        || attr.starts_with("#[cfg(all(test,")
        || attr.starts_with("#[cfg(all(feature=\"testing\",")
}

/// Where the run of outer attributes that ends `head` begins, when one of them
/// requires `test` or the `testing` feature; `None` otherwise.
fn test_gated_attrs_start(head: &str) -> Option<usize> {
    let mut start = head.trim_end().len();
    let mut gated = false;
    while head[..start].ends_with(']') {
        let attr = head[..start].rfind("#[")?;
        gated |= cfg_requires_test(&head[attr..start]);
        start = head[..attr].trim_end().len();
    }
    gated.then_some(start)
}

/// The `mod` items in `code`: (start of the `mod` keyword, its name, the byte
/// just past the name).
fn mod_items(code: &str) -> Vec<(usize, &str, usize)> {
    let mut items = Vec::new();
    let mut from = 0;
    while let Some(rel) = code[from..].find("mod ") {
        let at = from + rel;
        from = at + 4;
        let boundary = code[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        if !boundary {
            continue;
        }
        let rest = &code[at + 4..];
        let len = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        if len > 0 {
            items.push((at, &rest[..len], at + 4 + len));
        }
    }
    items
}

/// The start of the item that owns the `mod` keyword at `at`: the keyword
/// itself, or a visibility (`pub`, `pub(crate)`, ...) before it.
fn item_head_end(code: &str, at: usize) -> usize {
    let head = code[..at].trim_end();
    if let Some(stripped) = head.strip_suffix(')')
        && let Some(open) = stripped.rfind("pub(")
    {
        return open;
    }
    if head.ends_with("pub") {
        return head.len() - 3;
    }
    at
}

/// `code` with every `mod name { ... }` block gated by a test `cfg` removed.
fn without_test_gated_mod_blocks(code: &str) -> String {
    let mut kept = String::with_capacity(code.len());
    let mut cursor = 0;
    for (at, _, name_end) in mod_items(code) {
        if at < cursor {
            continue;
        }
        let after = code[name_end..].trim_start();
        if !after.starts_with('{') {
            continue;
        }
        let open = code.len() - after.len();
        let item = item_head_end(code, at);
        let (Some(start), Some(len)) = (
            test_gated_attrs_start(&code[cursor..item]),
            matching_brace_end(&code[open..]),
        ) else {
            continue;
        };
        kept.push_str(&code[cursor..cursor + start]);
        kept.push(' ');
        cursor = open + len;
    }
    kept.push_str(&code[cursor..]);
    kept
}

/// The files that `file` (raw source `src`, [`strip_non_code`] output `code`)
/// declares through a test-gated `mod name;`, at each path rustc would load:
/// the `#[path = "..."]` value beside the declaring file, or `name.rs` /
/// `name/mod.rs` in the declaring module's directory.
fn test_gated_mod_files(file: &std::path::Path, src: &str, code: &str) -> Vec<std::path::PathBuf> {
    let dir = file.parent().expect("a source file has a directory");
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let module_dir = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    let mut out = Vec::new();
    for (at, name, name_end) in mod_items(code) {
        if !code[name_end..].trim_start().starts_with(';') {
            continue;
        }
        let head = &code[..item_head_end(code, at)];
        let Some(start) = test_gated_attrs_start(head) else {
            continue;
        };
        // `strip_non_code` blanks string contents, so read a `#[path]` value
        // from the raw attribute run before the same declaration.
        if head[start..].contains("#[path") {
            let decl = format!("mod {name};");
            let path = src.find(&decl).and_then(|at| {
                let attrs = &src[..at];
                let value = &attrs[attrs.rfind("#[path")?..];
                let open = value.find('"')? + 1;
                let len = value[open..].find('"')?;
                Some(value[open..open + len].to_owned())
            });
            out.push(dir.join(path.expect("a #[path] attribute names its file")));
        }
        out.push(module_dir.join(format!("{name}.rs")));
        out.push(module_dir.join(name).join("mod.rs"));
    }
    out
}

/// The `name` under a manifest's `[package]`.
fn manifest_package_name(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package && let Some(value) = line.strip_prefix("name") {
            return Some(
                value
                    .trim_start()
                    .strip_prefix('=')?
                    .trim()
                    .trim_matches('"')
                    .to_owned(),
            );
        }
    }
    None
}

/// Whether every manifest in `others` that names crate `name` reaches it only
/// as a dev-dependency or as an optional dependency that only a feature named
/// `testing` enables.
fn reached_only_by_tests<'a>(name: &str, others: impl Iterator<Item = &'a String>) -> bool {
    let dep_key = format!("{name} ");
    let dep_eq = format!("{name}=");
    let enabler = format!("\"dep:{name}\"");
    for manifest in others {
        let mut section = String::new();
        let mut feature = String::new();
        for line in manifest.lines().map(str::trim) {
            if line.starts_with('[') && line.ends_with(']') && !line.contains('"') {
                line.clone_into(&mut section);
                continue;
            }
            if section == "[features]" {
                if let Some(eq) = line.find('=') {
                    line[..eq].trim().clone_into(&mut feature);
                }
                if line.contains(&enabler) && feature != "testing" {
                    return false;
                }
                continue;
            }
            let names_dep = line.starts_with(&dep_key) || line.starts_with(&dep_eq);
            let shipped_section =
                section.ends_with("dependencies]") && !section.ends_with("dev-dependencies]");
            if names_dep && shipped_section && !line.contains("optional = true") {
                return false;
            }
        }
    }
    true
}

/// Methods named `append_*` that write no leaf to a context's event log, with
/// the store each one writes. The scan counts every other `.append_*(` call.
const NON_EVENT_LOG_APPENDS: &[(&str, &str)] = &[
    ("append_journal", "the saga journal store"),
    ("append_block_list_event", "the identity store's block list"),
    (
        "append_log_event",
        "the in-browser client's in-memory context state (ADR-057), not the runtime provider",
    ),
    ("append_log", "the scp-platform syncable change log"),
    ("append_entry", "the scp-platform key custody file"),
    (
        "append_entry_holding_the_write_locks",
        "the scp-platform key custody file",
    ),
    ("append_entry_by_text", "an OpenSSL X.509 name"),
    ("append_own_leaf_node", "the MLS provider's storage"),
];

/// Free functions that write leaves to a context's event log. None exists
/// today: every write goes through a `.append_*(` method call.
const EVENT_LOG_APPEND_FREE_FNS: &[&str] = &[];

/// The byte offset of each call in `code` that writes a leaf to a context's
/// event log: every `.append_<name>(` method call whose name
/// [`NON_EVENT_LOG_APPENDS`] does not list, and every call of a free function
/// on [`EVENT_LOG_APPEND_FREE_FNS`]. A wrapper that forwards to the provider is
/// a writer too, so its callers count.
fn event_log_append_calls(code: &str) -> Vec<usize> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut calls = Vec::new();
    for (at, _) in code.match_indices(".append_") {
        let rest = &code[at + 1..];
        let len = rest.find(|c: char| !ident(c)).unwrap_or(rest.len());
        let name = &rest[..len];
        let called = rest[len..].starts_with('(') || rest[len..].starts_with("::<");
        if called && !NON_EVENT_LOG_APPENDS.iter().any(|(n, _)| *n == name) {
            calls.push(at);
        }
    }
    for free in EVENT_LOG_APPEND_FREE_FNS {
        for (at, _) in code.match_indices(free) {
            let before = code[..at].chars().next_back();
            let after = &code[at + free.len()..];
            let definition = code[..at].trim_end().ends_with("fn");
            if before.is_none_or(|c| !(ident(c) || c == '.'))
                && after.starts_with('(')
                && !definition
            {
                calls.push(at);
            }
        }
    }
    calls
}

/// Each shipped function that may write a leaf to a context's event log, once
/// per call it makes, with the reason it may.
///
/// Spec 17 §17.3 "Event log write failures": a leaf written after an
/// irreversible step goes into a pending log unit in the step's commit, and
/// only the drain writes it. Every other append is either the provider or
/// builder layer the drain and the fail-closed appends go through, or a
/// fail-closed append that runs before its step.
const EVENT_LOG_APPEND_ALLOWLIST: &[(&str, &str, &str)] = &[
    // The drain.
    (
        "scp-runtime/src/context/log_unit_helpers.rs",
        "drain_queue",
        "the pending-unit drain",
    ),
    // The provider and the builder trait.
    (
        "scp-runtime/src/store/event_log.rs",
        "append_event_full",
        "the event-log store",
    ),
    (
        "scp-runtime/src/context/builder.rs",
        "append_unit",
        "the builder trait",
    ),
    (
        "scp-runtime/src/context/builder.rs",
        "append_context_event",
        "the builder trait",
    ),
    (
        "scp-runtime/src/context/builder.rs",
        "append_context_event_with_payload",
        "the builder trait",
    ),
    (
        "scp-runtime/src/context/builder.rs",
        "append_membership_change_leaf",
        "the builder trait",
    ),
    // Fail-closed appends that run before their step.
    (
        "scp-runtime/src/context/builder.rs",
        "create_context",
        "a fail-closed append",
    ),
    (
        "scp-runtime/src/context/builder.rs",
        "create_context",
        "a fail-closed append",
    ),
    (
        "scp-runtime/src/context/builder.rs",
        "create_context",
        "a fail-closed append, the founder's `MemberJoined`",
    ),
    (
        "scp-runtime/src/context/ttl_close_helpers.rs",
        "extend_ttl_deadline_and_record",
        "fail-closed before the step (the bilateral reset)",
    ),
    // A seam that only the `testing` feature compiles.
    (
        "scp-runtime/src/context/supervisor/supervisor.rs",
        "test_append_event_log",
        "a testing-feature seam",
    ),
];

/// Spec 17 §17.3 "Event log write failures": no shipped function writes a
/// leaf to a context's event log unless [`EVENT_LOG_APPEND_ALLOWLIST`] names
/// it, once per call. A call outside the allowlist, a second call in a listed
/// function, and an entry whose call is gone all fail.
///
/// The scan covers each shipped crate's `src` tree, minus test-gated `mod`
/// blocks and the files test-gated `mod` declarations load, and minus the
/// crates on [`TEST_ONLY_CRATES`].
#[test]
fn no_shipped_source_appends_outside_the_allowlist() {
    let sources = shipped_crate_sources();
    let scanned_runtime = sources
        .iter()
        .filter(|(rel, _)| rel.starts_with("scp-runtime/src/"))
        .count();
    assert!(
        scanned_runtime > 100,
        "the scan must read the scp-runtime sources, read {scanned_runtime}"
    );
    let mismatches = event_log_append_mismatches(&sources, EVENT_LOG_APPEND_ALLOWLIST);
    assert!(
        mismatches.is_empty(),
        "shipped event-log appends differ from the allowlist; a leaf written after an \
         irreversible step goes into a pending log unit instead (spec 17 §17.3): {mismatches:#?}"
    );
}

/// The append scan's must-fail companion: a call planted in a temporary copy
/// of the scanned sources fails the scan, in a new function and as a second
/// call in a listed function; the same call in a test-gated module does not.
#[test]
fn the_event_log_append_scan_reports_a_planted_call() {
    let sources = shipped_crate_sources();
    assert!(
        event_log_append_mismatches(&sources, EVENT_LOG_APPEND_ALLOWLIST).is_empty(),
        "the unplanted copy passes"
    );
    let planted_in = "scp-runtime/src/context/messaging_helpers.rs";
    let plant = |extra: &str| -> Vec<(String, String)> {
        let mut copy = sources.clone();
        let entry = copy
            .iter_mut()
            .find(|(rel, _)| rel == planted_in)
            .expect("the scan reads the messaging helpers");
        entry.1.push_str(&strip_non_code_keeping_cfg(extra));
        copy
    };
    // A provider call, a builder wrapper, a supervisor wrapper, and a method
    // no list names yet.
    for call in [
        "log.append_event(a, b)",
        "log.append_unit(a, b)",
        "log.append_membership_change_leaf(a, b)",
        "sup.append_streaming_outlet_invoked_event(a, b)",
        "log.append_some_new_leaf(a)",
    ] {
        let planted = plant(&format!(
            "\nasync fn planted_after_send(log: &L) {{ let _ = {call}.await; }}\n"
        ));
        let found = event_log_append_mismatches(&planted, EVENT_LOG_APPEND_ALLOWLIST);
        assert_eq!(
            found,
            vec![format!(
                "{planted_in}::planted_after_send: 1 call(s), allowlisted 0"
            )],
            "a planted `{call}` call is reported"
        );
    }
    for (name, _) in NON_EVENT_LOG_APPENDS {
        let planted = plant(&format!(
            "\nasync fn planted_other_store(s: &S) {{ let _ = s.{name}(a).await; }}\n"
        ));
        assert!(
            event_log_append_mismatches(&planted, EVENT_LOG_APPEND_ALLOWLIST).is_empty(),
            "`{name}` writes no event-log leaf"
        );
    }
    let gated = plant(
        "\n#[cfg(test)]\nmod planted_tests { async fn t(log: &L) { log.append_event(a).await; } }\n",
    );
    assert!(
        event_log_append_mismatches(&gated, EVENT_LOG_APPEND_ALLOWLIST).is_empty(),
        "a call in a test-gated module is not shipped"
    );

    let mut nested = sources.clone();
    let drain = nested
        .iter_mut()
        .find(|(rel, _)| rel == "scp-runtime/src/context/log_unit_helpers.rs")
        .expect("the scan reads the drain");
    let at = drain
        .1
        .find("fn drain_queue")
        .expect("the drain is defined");
    let open = at + drain.1[at..].find('{').expect("the drain has a body") + 1;
    drain.1.insert_str(open, " log.append_unit(a); ");
    assert_eq!(
        event_log_append_mismatches(&nested, EVENT_LOG_APPEND_ALLOWLIST),
        vec![
            "scp-runtime/src/context/log_unit_helpers.rs::drain_queue: 2 call(s), allowlisted 1"
                .to_owned()
        ],
        "a second call in a listed function is reported"
    );

    let stale: Vec<(&str, &str, &str)> = EVENT_LOG_APPEND_ALLOWLIST
        .iter()
        .copied()
        .chain([("scp-runtime/src/context/ttl.rs", "gone", "a removed site")])
        .collect();
    assert_eq!(
        event_log_append_mismatches(&sources, &stale),
        vec!["scp-runtime/src/context/ttl.rs::gone: 0 call(s), allowlisted 1".to_owned()],
        "an entry whose call is gone is reported"
    );
}

/// Each shipped source file as (path under `crates/`, its
/// [`strip_non_code_keeping_cfg`] output), skipping the crates on
/// [`TEST_ONLY_CRATES`] and the files a test-gated `mod name;` loads.
fn shipped_crate_sources() -> Vec<(String, String)> {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("scp-testing sits under crates/");
    let mut crate_dirs = Vec::new();
    for krate in std::fs::read_dir(crates)
        .expect("crates/ is readable")
        .flatten()
    {
        let dir = krate.path();
        if dir.join("Cargo.toml").is_file() {
            crate_dirs.push(dir.clone());
        }
        if let Ok(nested) = std::fs::read_dir(&dir) {
            for sub in nested.flatten() {
                if sub.path().join("Cargo.toml").is_file() {
                    crate_dirs.push(sub.path());
                }
            }
        }
    }
    let mut files = Vec::new();
    for dir in &crate_dirs {
        let manifest =
            std::fs::read_to_string(dir.join("Cargo.toml")).expect("a manifest is readable");
        let name = manifest_package_name(&manifest).expect("a manifest names its package");
        if !TEST_ONLY_CRATES.contains(&name.as_str()) {
            collect_rust_files(&dir.join("src"), &mut files);
        }
    }
    let read: Vec<(std::path::PathBuf, String, String)> = files
        .into_iter()
        .map(|file| {
            let src = std::fs::read_to_string(&file).expect("a source file is readable");
            let code = strip_non_code_keeping_cfg(&src);
            (file, src, code)
        })
        .collect();
    let test_files: std::collections::HashSet<std::path::PathBuf> = read
        .iter()
        .flat_map(|(file, src, code)| test_gated_mod_files(file, src, code))
        .collect();
    let mut out: Vec<(String, String)> = read
        .into_iter()
        .filter(|(file, _, _)| !test_files.contains(file))
        .map(|(file, _, code)| {
            let rel = file
                .strip_prefix(crates)
                .expect("a source file sits under crates/")
                .to_string_lossy()
                .replace('\\', "/");
            (rel, code)
        })
        .collect();
    out.sort();
    out
}

/// Every (file, function) whose count of [`event_log_append_calls`] in
/// shipped code differs from its count of `allowlist` entries, as
/// `"file::fn: N call(s), allowlisted M"`, sorted. A call outside any
/// function counts against the function name `<item>`.
fn event_log_append_mismatches(
    sources: &[(String, String)],
    allowlist: &[(&str, &str, &str)],
) -> Vec<String> {
    let mut found: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for (rel, code) in sources {
        let shipped = without_test_gated_mod_blocks(code);
        let bodies = fn_bodies(&shipped);
        for at in event_log_append_calls(&shipped) {
            let owner = bodies
                .iter()
                .filter(|(open, end, _)| *open < at && at < *end)
                .max_by_key(|(open, _, _)| *open)
                .map_or("<item>", |(_, _, name)| *name);
            *found.entry((rel.clone(), owner.to_owned())).or_default() += 1;
        }
    }
    let mut allowed: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for (file, func, _) in allowlist {
        *allowed
            .entry(((*file).to_owned(), (*func).to_owned()))
            .or_default() += 1;
    }
    let keys: std::collections::BTreeSet<&(String, String)> =
        found.keys().chain(allowed.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let calls = found.get(key).copied().unwrap_or(0);
            let listed = allowed.get(key).copied().unwrap_or(0);
            (calls != listed).then(|| {
                format!(
                    "{}::{}: {calls} call(s), allowlisted {listed}",
                    key.0, key.1
                )
            })
        })
        .collect()
}

/// Each `fn name` with a body in `code`: (byte of its opening `{`, byte past
/// its closing `}`, name). A declaration that ends in `;` has no body.
fn fn_bodies(code: &str) -> Vec<(usize, usize, &str)> {
    let mut bodies = Vec::new();
    let mut from = 0;
    while let Some(rel) = code[from..].find("fn ") {
        let at = from + rel;
        from = at + 3;
        let boundary = code[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        if !boundary {
            continue;
        }
        let rest = &code[at + 3..];
        let len = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        if len == 0 {
            continue;
        }
        let name = &rest[..len];
        let sig = at + 3 + len;
        // A `;` inside the signature's brackets, as in `&[u8; 32]`, does not
        // end the item.
        let mut depth = 0usize;
        let Some(stop) = code[sig..].find(|c: char| {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth = depth.saturating_sub(1),
                _ => {}
            }
            depth == 0 && (c == '{' || c == ';')
        }) else {
            continue;
        };
        let open = sig + stop;
        if !code[open..].starts_with('{') {
            continue;
        }
        if let Some(body) = matching_brace_end(&code[open..]) {
            bodies.push((open, open + body, name));
        }
    }
    bodies
}
