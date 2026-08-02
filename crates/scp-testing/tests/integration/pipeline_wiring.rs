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

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================
// Raised 46 -> 49 when the `ucan_evaluate` routing assertion was extended from
// PyO3-only to the bridges, adding per-bridge routing tests.
// Raised 49 -> 50 when the production saga-journal swap added
// `prod_supervisor_construction_wires_durable_saga_journal` — pinning that every
// production seam constructs the durable `ProtocolRepositorySagaJournal` rather
// than `NoopSagaJournal` — locking that assertion into the ratchet floor.
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
// core `scp_core::trust::check_capability_requirements` call and the production
// `IdentityDidPublicKeyResolver`. The 2J joiner (+4) and capability-admission
// (+3) additions are disjoint, so the merged floor is 48 + 4 + 3 = 55.
const MIN_ACTIVE_PIPELINE_ASSERTIONS: usize = 55;

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
            depth -= 1;
        }
        cleaned.push(ch);
        if ch == '}' && depth == 0 {
            return Some(cleaned);
        }
        i += 1;
    }

    None // Unbalanced braces
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
    // log-and-drops. `decrypt_and_dispatch` must call the registry recv gate and
    // install remote keys via the unchecked wrapper (gate-before-install), with
    // no "non-fatal" mirror-forward drop.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "decrypt_and_dispatch",
            "check_and_advance_recv_sequence"
        ),
        "decrypt_and_dispatch must gate the recv floor on the authoritative registry"
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
// a non-convergent denylist (CLAUDE.md).
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

// Actor-state level: `ContextCryptoState::seal` calls create_outer_envelope
// (envelope construction). Repointed from the deleted provider `seal` to its
// actor home in `state.rs` (STATE_SRC) — the moved pipeline, not a weakening.
// First-occurrence binding to the production core is pinned by
// `state_seal_open_first_binding_is_production_core` above.
#[test]
fn seal_calls_create_outer_envelope() {
    assert!(
        fn_body_contains(STATE_SRC, "seal", "create_outer_envelope"),
        "seal (actor ContextCryptoState) must call create_outer_envelope"
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

#[test]
fn encrypt_path_calls_create_outer_envelope_or_seal() {
    assert!(
        fn_body_contains(STATE_SRC, "seal", "create_outer_envelope")
            || fn_body_contains(MANAGER_SRC, "send_message", "create_outer_envelope"),
        "send/encrypt path must call create_outer_envelope"
    );
}

// --- Inner envelope / signatures (§9.8, #1547) — NOW WIRED ---

#[test]
fn encrypt_path_calls_create_inner_envelope() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "create_inner_envelope_raw")
            || fn_body_contains(MANAGER_SRC, "build_inner_wire", "create_inner_envelope_raw"),
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
        body.contains("resolve_context_signing_key"),
        "PyO3 streaming-saga recover must SURFACE the target context's Active \
         Signing Key per-call from custody (resolve_context_signing_key) before \
         sealing — the recovery receipt is signed with a custody-resolved key, \
         NEVER an envelope-asserted one (§6.2.4). Structurally pins the \
         FFI-layer key-surfacing, not just the runtime seal."
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

    // Every bridge (PyO3 reference, NAPI, UniFFI) must independently
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
// Durable saga journal — production supervisor construction (§17.16 / ADR-049)
// ===========================================================================

/// Every production `Supervisor` construction seam (PyO3, NAPI, UniFFI, Node)
/// MUST route through `with_providers_and_journal` and supply a
/// `ProtocolRepositorySagaJournal` built over the SAME chosen `Storage` backend
/// that feeds `mls_storage` — NOT the bare `with_providers` (which hardcodes
/// `NoopSagaJournal`). Without this, a process restart loads no journal and the
/// §17.16.4 crash-recovery replay can never reconcile a crash-orphaned saga.
///
/// This is a source-text presence gate (defense-in-depth, NOT the primary
/// guarantee — the type system already forces a journal argument on
/// `with_providers_and_journal`). It pins the wiring legible so a refactor that
/// silently reverts a seam to the `NoopSagaJournal`-hardcoding `with_providers`
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
         journal), not the NoopSagaJournal-hardcoding with_providers"
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
         journal), not the NoopSagaJournal-hardcoding with_providers"
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
         journal), not the NoopSagaJournal-hardcoding with_providers"
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
         saga journal), not the NoopSagaJournal-hardcoding with_providers"
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
// Each native bridge's capability-admission export MUST delegate to the shared
// core `scp_protocol::trust::check_capability_requirements` (re-exported as
// `scp_core::trust::check_capability_requirements`) rather than re-implementing
// the admission decision locally, AND MUST wire the production
// `IdentityDidPublicKeyResolver` so each `ChallengeVerification` is
// signature/subject/context/expiry verified. Pinning the fully-qualified
// `scp_core::trust::check_capability_requirements(` call (not the bare leaf,
// which the bridge fn shares its name with) plus the resolver makes a
// self-satisfying substring impossible.

/// The PyO3 `check_capability_requirements` bridge op must route to core.
#[test]
fn pyo3_check_capability_requirements_routes_to_core() {
    assert!(
        fn_body_contains(
            PYO3_TRUST_SRC,
            "py_check_capability_requirements",
            "scp_core::trust::check_capability_requirements("
        ) && fn_body_contains(
            PYO3_TRUST_SRC,
            "py_check_capability_requirements",
            "IdentityDidPublicKeyResolver"
        ),
        "PyO3 py_check_capability_requirements must call core \
         check_capability_requirements with the production DID resolver"
    );
}

/// The NAPI `check_capability_requirements` bridge op (body in
/// `check_capability_requirements_on`) must route to core.
#[test]
fn napi_check_capability_requirements_routes_to_core() {
    assert!(
        fn_body_contains(
            NAPI_TRUST_SRC,
            "check_capability_requirements_on",
            "scp_core::trust::check_capability_requirements("
        ) && fn_body_contains(
            NAPI_TRUST_SRC,
            "check_capability_requirements_on",
            "IdentityDidPublicKeyResolver"
        ),
        "NAPI check_capability_requirements_on must call core \
         check_capability_requirements with the production DID resolver"
    );
}

/// The UniFFI `check_capability_requirements` bridge op must route to core.
#[test]
fn uniffi_check_capability_requirements_routes_to_core() {
    assert!(
        fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "check_capability_requirements",
            "scp_core::trust::check_capability_requirements("
        ) && fn_body_contains(
            UNIFFI_BRIDGE_SRC,
            "check_capability_requirements",
            "IdentityDidPublicKeyResolver"
        ),
        "UniFFI check_capability_requirements must call core \
         check_capability_requirements with the production DID resolver"
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
    // (`record_streaming_saga_a_event`, which immediately follows it).
    let fn_start = OUTLETS_INVOKE_SRC
        .find("pub(crate) async fn run_streaming_saga_seal_task")
        .expect("run_streaming_saga_seal_task must exist in invoke.rs");
    let after_fn = &OUTLETS_INVOKE_SRC[fn_start..];
    let fn_len = after_fn
        .find("async fn record_streaming_saga_a_event")
        .expect("record_streaming_saga_a_event follows the seal task");
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
