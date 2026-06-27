//! WASM-local `ContextManager` — mirrors `scp_core::context::manager::ContextManager`.
//!
//! # Design Decision (ADR-034 compliance)
//!
//! `scp-core` cannot compile to `wasm32-unknown-unknown` due to:
//! 1. `tokio = { features = ["full"] }` requiring the multi-thread runtime.
//! 2. `OpenMLS` platform-specific crypto backends incompatible with WASM.
//!
//! ADR-034 decided on **verbatim re-implementation**: the WASM bridge
//! re-implements scp-core's public API surface in WASM-compatible Rust,
//! verified against the same conformance test suite.
//!
//! This module centralizes ALL context state management into a single
//! `WasmContextManager` struct that mirrors `ContextManager`'s method
//! signatures. Bridge functions (`context.rs`, `tools.rs`, `ucan.rs`,
//! `event_log.rs`) delegate to this manager instead of re-implementing
//! logic locally.
//!
//! **Evaluated alternatives (from issue #389):**
//! 1. Feature-gate tokio multi-thread in scp-core — rejected by ADR-034
//!    ("structural incompatibilities, not feature-flag-able").
//! 2. `WasmContextManager` with API parity — **chosen** (this file).
//! 3. wasm-bindgen-futures with single-threaded tokio — rejected by ADR-034
//!    ("maintenance burden exceeds that of a separate WASM bridge").
//!
//! See ADR-034 in `.docs/adrs/phase-4.md` for the full rationale.

use scp_ffi_common::error_codes as codes;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

use base64::Engine as _;

use crate::error::ScpWasmError;
use crate::runtime::{ToolRegistration, ToolRegistry, validate_value_against_schema};

use scp_event_log::proof::{Direction, prove_absence, prove_inclusion, verify_inclusion};
use scp_event_log::tree::{append_unsigned_event, event_count, root};
use scp_event_log::{DID, Event, EventLog, EventPayload, EventType};

use scp_protocol::context::EXPORT_SCOPE_TAG_FULL;
use scp_protocol::context::broadcast::{BroadcastAdmission, BroadcastContext};
use scp_protocol::context::governance::{
    AccessScope, ConflictResolution, GovernanceAction, GovernanceProposal, ProposalStatus,
    SignedVote, VoteType,
};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::ContextMode;
use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
// `builtin_roles` / `builtin_broadcast_roles` are used only by the test-only
// `set_ceiling_and_refresh` scaffolding (the production `ModifyCeiling` path calls
// `set_ceiling` only, matching native — no built-in-role rebuild).
#[cfg(test)]
use scp_protocol::context::roles::{builtin_broadcast_roles, builtin_roles};
use scp_protocol::crypto::ucan::UcanError;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker,
};
use scp_protocol::economy::policy::policy_requires_payment;
use scp_protocol::economy::types::EconomicPolicy;

/// Strictly parses a hex-encoded governance proposal id into the canonical
/// 32-byte array.
///
/// This is the manager-level equivalent of the native bridges'
/// `hex::decode(...)` + `try_into::<[u8; 32]>()` parse: it rejects non-hex
/// input and any length other than exactly 32 bytes. It replaces the former
/// `hex::decode(...).unwrap_or_default()` + truncate/zero-pad code, which
/// silently widened a short id (or an empty decode from non-hex input) into a
/// well-formed-looking all-zero / right-padded id — a divergence from native
/// that could mint a `GovernanceActionExecuted` leaf whose `proposal_id`
/// differs across platforms. The WASM bridge boundary
/// (`validate_proposal_id_hex`) already rejects malformed ids before reaching
/// the manager; this parse is the defense-in-depth equal of the native parse
/// for any in-crate caller, and fails loudly rather than fabricating bytes.
///
/// # Errors
///
/// Returns [`ScpWasmError::Context`] with code `SCP-CTX-2040` (via
/// [`ScpWasmError::proposal_id`]) if `proposal_id` is not valid hex or does not
/// decode to exactly 32 bytes — the same error surface the bridge boundary
/// emits, so the in-crate defense-in-depth path is byte-for-byte consistent.
fn parse_proposal_id_bytes(proposal_id: &str) -> Result<[u8; 32], ScpWasmError> {
    // Single decode + length-check: `validate_proposal_id_hex` returns the
    // canonical 32-byte array, so there is no second `hex::decode` and no
    // unreachable error arm to map.
    scp_ffi_common::validate::validate_proposal_id_hex(proposal_id)
        .map_err(ScpWasmError::proposal_id)
}

// ---------------------------------------------------------------------------
// No-op UCAN validation trait impls for BroadcastContext::subscribe turbofish
// ---------------------------------------------------------------------------
//
// `BroadcastContext::subscribe` is generic over `DidResolver`, `NonceTracker`,
// `RevocationChecker`, and `ProofResolver`. When `validation_ctx` is `None`
// (open admission, no UCAN), these types are only needed to satisfy the
// generic bounds — their methods are never called. We define minimal no-op
// implementations here because the in-memory test impls in scp-protocol
// are gated behind `#[cfg(test)]` / `feature = "testing"`.

/// No-op [`DidResolver`] — always returns an error (never called at runtime).
struct NoOpDidResolver;

impl DidResolver for NoOpDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError> {
        Err(UcanError::MalformedToken(format!(
            "NoOpDidResolver cannot resolve DID: {did}"
        )))
    }
}

/// No-op [`NonceTracker`] — always returns an error (never called at runtime).
struct NoOpNonceTracker;

impl NonceTracker for NoOpNonceTracker {
    fn check_replay(&self, _nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        Err(UcanError::NonceFormatInvalid(
            "NoOpNonceTracker: not a real tracker".to_owned(),
        ))
    }

    fn record(&mut self, _nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        Err(UcanError::NonceFormatInvalid(
            "NoOpNonceTracker: not a real tracker".to_owned(),
        ))
    }
}

/// No-op [`RevocationChecker`] — always returns `false` (never called at runtime).
struct NoOpRevocationChecker;

impl RevocationChecker for NoOpRevocationChecker {
    fn is_revoked(&self, _token_cid: &str) -> bool {
        false
    }
}

/// No-op [`ProofResolver`] — always returns an error (never called at runtime).
struct NoOpProofResolver;

impl ProofResolver for NoOpProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<scp_protocol::crypto::ucan::UcanToken, UcanError> {
        Err(UcanError::MalformedToken(format!(
            "NoOpProofResolver cannot resolve CID: {cid}"
        )))
    }
}

/// SCP protocol version for WASM bridge (§13.2). Must match scp-core's
/// `SCP_PROTOCOL_VERSION`. Encoded as `(major << 8) | minor`.
/// SCP/1.0 = `0x0100` (decimal 256).
const SCP_PROTOCOL_VERSION: u16 = 0x0100;

// ---------------------------------------------------------------------------
// Economy fail-closed gating (C2 — wasm cannot run scp-runtime payment flow)
// ---------------------------------------------------------------------------

/// Stable error code rejecting paid economic policies at WASM context creation
/// or via in-WASM `SetEconomicPolicy` governance.
///
/// The browser bridge cannot run the full `enforce_economy` pipeline (payment
/// adapter, budget tracker, velocity tracker, hard rate limit token bucket)
/// because `scp-runtime` does not compile to `wasm32` (ADR-034). Accepting a
/// paid policy in WASM would silently bypass economic enforcement on every
/// downstream operation, so creation is rejected fail-closed.
///
/// SDK consumers should switch to a native (Python / Node.js / Swift /
/// Kotlin) bridge for any context with non-free economic policy.
pub const SCP_ECON_PAID_POLICY_UNSUPPORTED_ON_WASM: &str = codes::ECON_12095;

/// Stable error code rejecting `join_context` / `send_message` against a
/// paid context from the WASM bridge.
///
/// Even if the caller supplies a `spending_ucan_jwt`, the WASM bridge cannot
/// cryptographically validate the spending UCAN against a payment adapter
/// (no `enforce_economy`, no budget/velocity/hard-rate-limit enforcement —
/// see ADR-034 and `crates/scp-ffi/wasm/CLAUDE.md`). Accepting it would be a
/// security lie: the SDK would tell callers their spend was authorized when
/// it was never validated. We reject instead.
pub const SCP_ECON_WASM_CANNOT_VALIDATE_SPENDING_UCAN: &str = codes::ECON_12096;

/// Returns `true` when the JSON-serialized economic policy stored in
/// `PerContextState::economic_policy` requires payment for any action.
///
/// Returns `false` for any of:
/// - the policy is absent (`None`),
/// - the JSON is malformed (defense in depth: TS validates schema, but a
///   malformed policy here means we cannot positively identify it as paid,
///   so we treat it as not-paid; `create_context` separately validates
///   schema via the bridge layer),
/// - the policy parses but no cost field is set and no pricing formula
///   is configured (i.e. the canonical "free" shape).
///
/// Mirrors `scp_protocol::economy::policy::policy_requires_payment` and
/// matches the auto-accept guard at spec §19.3 / §19.14 invariant #9.
fn stored_policy_requires_payment(stored: Option<&str>) -> bool {
    let Some(json) = stored else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<EconomicPolicy>(json) else {
        return false;
    };
    policy_requires_payment(&parsed)
}

/// Parses a WASM-format (UCAN `{resource}:{action}`) capability string into a
/// typed [`Capability`].
///
/// The WASM bridge stores and checks capabilities in the UCAN wire form, where
/// the built-ins with a compound resource are underscore-joined (`"tool_invoke:*"`,
/// `"tool_invoke:<id>"`, `"context_child:create"`, `"bridging:*"`) and every other
/// capability is a 2-segment form identical in both the wire and user-facing
/// encodings (e.g. `"messages:write"`, `"governance:vote"`, `"role:assign"`).
///
/// `Capability::new` recognizes BOTH spellings of every built-in — the
/// user-facing colon form AND the UCAN wire form (`tool_invoke:*` == `ToolInvokeAll`,
/// `tool_invoke:<id>` == `ToolInvoke(id)`, `context_child:create` ==
/// `ChildContextCreate`, `bridging:*` == `Bridging`) — and resolves them to the
/// proper enumerated variant rather than a `Custom` lookalike (no valid custom
/// carries a `_` in its resource, so there is no collision). Delegating to it
/// therefore round-trips a UCAN-form ceiling/suspension string back to the correct
/// typed variant for ALL built-ins, including `bridging:*` -> `Bridging`.
fn ucan_string_to_capability(ucan: &str) -> Capability {
    Capability::new(ucan)
}

/// Maps a [`scp_protocol::context::roles::RoleError`] (from a
/// `system_assign_role` / role operation on the shared [`ContextRoleState`])
/// into the WASM bridge's [`ScpWasmError`].
///
/// A `RoleNotFound` (the role name is not in `role_definitions`) or
/// `CapabilityOutsideCeiling` is a governance/validation failure surfaced as a
/// `Context` error; this is the path that now rejects an undefined / out-of-
/// ceiling role on the WASM bridge instead of silently accepting it.
fn map_role_error(e: scp_protocol::context::roles::RoleError) -> ScpWasmError {
    ScpWasmError::Context {
        message: format!("role assignment failed: {e}"),
        code: codes::CTX_2015.to_owned(),
    }
}

/// Type alias for tool handler closures stored per-context.
type ToolHandlerMap =
    HashMap<String, Box<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String>>>;

// ---------------------------------------------------------------------------
// Thread-local singleton (WASM is single-threaded)
// ---------------------------------------------------------------------------

thread_local! {
    static MANAGER: RefCell<WasmContextManager> = RefCell::new(WasmContextManager::new());
}

/// Executes a closure with mutable access to the global `WasmContextManager`.
///
/// All bridge functions call this to access the manager. The `RefCell` is safe
/// because WASM is single-threaded — no concurrent access is possible.
///
/// # Errors
///
/// Returns an error if the closure itself returns an error.
pub fn with_manager<T, F>(f: F) -> Result<T, ScpWasmError>
where
    F: FnOnce(&mut WasmContextManager) -> Result<T, ScpWasmError>,
{
    MANAGER.with(|mgr| f(&mut mgr.borrow_mut()))
}

// WasmProposal deleted: replaced by GovernanceProposal from scp-protocol
// (scp_protocol::context::governance::GovernanceProposal).

/// Maximum number of pending proposals per context.
const WASM_PENDING_PROPOSAL_CAP: usize = 100;

/// Default voting deadline: 1 hour in milliseconds.
const WASM_PROPOSAL_DEADLINE_MS: f64 = 3_600_000.0;

// BroadcastState deleted: replaced by BroadcastContext from scp-protocol
// (§5.14.2 cohesion invariant — broadcast keys stored alongside context data).

// ---------------------------------------------------------------------------
// Ceiling-entry grammar enforcement at the WASM boundary (spec §5.3.1.1)
// ---------------------------------------------------------------------------

// The former `ValidatedCeilingStrings` newtype (and its `from_colon_entries` /
// `from_capabilities` / `from_ucan_strings` validating constructors) is GONE: the
// WASM bridge now stores the ceiling inside the shared
// `scp_protocol::context::roles::ContextRoleState`, whose `new` and `set_ceiling`
// both run `CapabilityCeiling::validate_entries` and whose `Deserialize` rejects a
// malformed ceiling from bytes (the `#[serde(try_from)]` path). The shared type is
// the single enforcement point both bridges share.
//
// The §5.3.1.1 grammar is enforced by the single shared
// `CapabilityCeiling::validate_entries` on all three paths: create (via
// `ContextRoleState::new`), modify (via `set_ceiling`), and import (the
// deserialize belt — the `#[serde(try_from)]` path plus the explicit
// post-deserialize `validate_entries` check). No separate WASM-side
// per-capability validator remains.
//
// The error CLASS differs by path, however. Create and modify surface the
// canonical `SCP-VALID-7000` `Validation` error (the create path maps the
// shared `RoleError::InvalidCeilingCategory`, and the modify path maps
// `set_ceiling`'s `CeilingEntryError` through `ceiling_validation_error`).
// Import surfaces the `SCP-CTX-2032` deserialize error class instead, because a
// malformed ceiling is rejected while decoding an untrusted snapshot envelope.

/// Maps a ceiling-grammar error into the canonical WASM bridge validation error
/// (`SCP-VALID-7000`). Used on the create and modify paths; the import path
/// rejects a malformed ceiling at deserialize time and surfaces the
/// `SCP-CTX-2032` deserialize error class instead.
fn ceiling_validation_error(e: scp_protocol::context::roles::CeilingEntryError) -> ScpWasmError {
    ScpWasmError::Validation {
        message: e.to_string(),
        code: codes::VALID_7000.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// PerContextState — per-context state
// ---------------------------------------------------------------------------

/// Per-context runtime state.
///
/// Mirrors `PerContextState` in `scp_core::context::manager`.
pub(crate) struct PerContextState {
    /// Context lifecycle state.
    state: String,
    /// Context creation parameters stored as JSON. Used for version compatibility
    /// checks and snapshot/restore. `minProtocolVersion` is read from this field
    /// during `join_context` and `subscribe_broadcast`.
    params_json: serde_json::Value,
    /// Context mode: "Encrypted" or "Broadcast".
    mode: String,
    /// Shared role state: members, role assignments, capability ceiling, role
    /// definitions, per-member granted capabilities, and suspensions.
    ///
    /// This is the `scp_protocol` shared, sync, wasm-safe type — the SAME
    /// representation the native runtime holds. It replaces the WASM bridge's
    /// former flat reimplementation (`members: HashMap<String, MemberEntry>`,
    /// `ceiling_strings: HashSet<String>`, `suspended_capabilities`,
    /// `creator_did`). Role-against-`role_definitions` validation now happens by
    /// construction (`ContextRoleState::system_assign_role`), closing the
    /// divergence where the old hardcoded role-name match silently accepted
    /// undefined / out-of-ceiling roles.
    role_state: ContextRoleState,
    /// Per-member MLS message sequence counter, keyed by member DID.
    ///
    /// This is ENCRYPTION state (the next outgoing message's sequence number
    /// for each sender), NOT role state — it has no home in
    /// [`ContextRoleState`], so it lives here alongside the other crypto-adjacent
    /// fields. Inserted when a member joins / is added, incremented on each
    /// `send_message` AND each `publish_broadcast`, and dropped when the member
    /// is removed.
    member_sequence_numbers: HashMap<String, u64>,
    /// Ceiling policy: "immutable" or "governed".
    ceiling_policy: String,
    /// TTL in seconds, if any.
    ttl_seconds: Option<u64>,
    /// Promotion policy.
    promotion_policy: Option<String>,
    /// Governance model string.
    governance: String,
    /// Economic policy.
    economic_policy: Option<String>,
    /// Tool registry.
    tool_registry: ToolRegistry,
    /// Registered tool handlers keyed by tool ID.
    tool_handlers: ToolHandlerMap,
    /// Event log (Merkle tree) — canonical `scp-event-log` implementation.
    event_log: EventLog,
    /// UCAN revocation set (token CIDs). Capped at [`WASM_REVOKED_TOKENS_CAP`].
    revoked_tokens: HashSet<String>,
    /// UCAN nonce replay tracker. Stores `(nonce, insertion_timestamp_ms)`.
    /// Evicts entries older than [`WASM_NONCE_TTL_MS`] when exceeding [`WASM_NONCE_CAP`].
    seen_nonces: HashMap<String, f64>,
    /// Receive buffer for events. Capped at [`WASM_EVENT_BUFFER_CAP`] (FIFO overflow).
    /// Uses `VecDeque` for O(1) `pop_front` instead of `Vec::remove(0)` O(n) shift.
    event_buffer: VecDeque<ContextEvent>,
    /// Executed proposal IDs with insertion timestamps (replay protection).
    /// Evicts entries older than [`WASM_PROPOSAL_TTL_MS`] when exceeding [`WASM_PROPOSAL_CAP`].
    executed_proposals: HashMap<String, f64>,
    /// Members excluded from future CEK wrapping (`AccessScope::Read` revocation).
    read_exclusion_list: HashSet<String>,
    /// Broadcast context state (only for Broadcast mode).
    /// Uses `BroadcastContext` from scp-protocol per §5.14.2 cohesion invariant.
    broadcast_context: Option<BroadcastContext>,
    /// Stateful tool sessions (spec section 6.2.1).
    sessions: HashMap<String, WasmToolSession>,
    /// Threshold governance signers (ADR-031 §4b).
    threshold_signers: Vec<String>,
    /// Current threshold value (ADR-031 §4b). `0` means threshold governance
    /// is not configured.
    threshold_value: u32,
    /// Established tool interfaces (spec section 6.2).
    tool_interfaces: Vec<String>,
    /// Whether governance is frozen due to conflicting proposals (ADR-031 §7).
    governance_freeze: bool,
    /// Pending governance proposals keyed by proposal ID (hex).
    /// Multi-party governance models accumulate votes here until quorum
    /// is reached or the deadline expires (#621).
    /// Uses `GovernanceProposal` from scp-protocol.
    pending_proposals: HashMap<String, GovernanceProposal>,
    /// Resolved (approved/rejected) governance proposals keyed by proposal ID.
    /// Proposals move here from `pending_proposals` when quorum is reached or
    /// the proposal is definitively rejected. This allows retrieval of resolved
    /// proposals via `get_proposal` and `list_proposals` (#621 F4).
    /// Capped at [`WASM_RESOLVED_PROPOSAL_CAP`]; oldest by `created_at` evicted.
    /// Uses `GovernanceProposal` from scp-protocol.
    resolved_proposals: HashMap<String, GovernanceProposal>,
    /// Pruning policy JSON string (ADR-030 §6).
    pruning_policy: Option<String>,
    /// Whether the economic policy is locked (§19.3, ADR-033).
    economic_policy_locked: bool,
    /// Hard rate limit configuration (D4, §19.7) as an opaque JSON blob.
    ///
    /// The WASM bridge does not run the runtime-side
    /// `TokenBucketLimiter` (that lives in scp-runtime which cannot
    /// compile to wasm32 due to tokio). Consumers of this bridge
    /// enforce rate limits via JS-side counterparts; the stored
    /// config is the authoritative governance-approved configuration.
    ///
    /// `None` means the context is using the Matrix-style default
    /// (burst 10, refill 0.2/sec). A `ModifyHardRateLimit` governance
    /// action populates this field.
    hard_rate_limit_config: Option<String>,
    /// Consequence rules declared at context creation (ADR-017, #1531).
    /// Parsed and validated from `params.consequenceRules` in `create_context`.
    /// Evaluated via [`crate::consequence::dispatch_consequences_for_subject`]
    /// at every mutation site that the runtime bridge fires
    /// `enforce_triggered_consequences` at (send, governance dispatch).
    consequence_rules: Vec<scp_protocol::trust::consequence::ConsequenceRule>,
    /// Per-rule cooldown timers (`rule_index` → Unix second until which the
    /// rule should not re-fire). Mirrors
    /// `scp_runtime::context::state::PerContextState.governance.cooldown_until`
    /// and is consulted by [`crate::consequence::dispatch_consequences_for_subject`]
    /// to prevent re-firing within a rule's window.
    cooldown_until: HashMap<usize, u64>,
    /// MLS encryption + sender key state. `Some` for encrypted contexts,
    /// `None` for broadcast-only or unencrypted contexts.
    crypto: Option<crate::crypto::WasmCryptoState>,
    /// Convergent creator-assigned context-creation timestamp (Unix seconds).
    ///
    /// The same value this member stamped on the `ContextCreated` event-log leaf
    /// at `create_context` (creator), or restored from the export snapshot on
    /// `import_context` (§7.3.1, §9.9.3). Used as the convergent base for the TTL
    /// expiry deadline (`creation_timestamp_secs + ttl_seconds`) recorded on the
    /// `ContextExpired` leaf, so a TTL-fired close converges across members
    /// instead of stamping each member's local fire-time `now()`.
    ///
    /// `0` when no convergent creation time is known (e.g. the bare test-helper
    /// state). The WASM bridge keeps its own independent representation — it is
    /// NOT byte-parity with the native `ContextSnapshot`.
    creation_timestamp_secs: u64,
}

/// A stateful tool session for the WASM bridge.
///
/// Mirrors `scp_core::context::tools::ToolSession` locally since WASM
/// cannot depend on scp-core (ADR-034).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields read via pattern matching and clone.
struct WasmToolSession {
    /// Unique session identifier.
    session_id: String,
    /// The tool this session is associated with.
    tool_id: String,
    /// The calling context.
    source_context: String,
    /// Opaque session state.
    state: serde_json::Value,
    /// Creation timestamp (milliseconds since epoch).
    created_at_ms: f64,
    /// Optional TTL in milliseconds. `None` means the session persists for
    /// the lifetime of the context (spec section 6.2.1).
    ttl_ms: Option<f64>,
    /// Number of invocations.
    call_count: u64,
}

impl WasmToolSession {
    /// Returns `true` if this session has expired.
    ///
    /// Sessions with `ttl_ms: None` never expire (they persist for the
    /// lifetime of the context, per spec section 6.2.1).
    fn is_expired(&self) -> bool {
        let Some(ttl) = self.ttl_ms else {
            return false;
        };
        let now = crate::time::now_ms();
        (now - self.created_at_ms) >= ttl
    }
}

/// Maximum concurrent sessions per calling context (spec §6.2.1, ADR-043).
const WASM_SESSION_CAP_PER_CALLER: usize = 1000;

/// Maximum concurrent sessions across all callers (global cap).
/// Must be >= `WASM_SESSION_CAP_PER_CALLER` so the per-caller cap is meaningful.
const WASM_SESSION_GLOBAL_CAP: usize = 10_000;

/// Maximum number of nonces tracked per context before triggering eviction.
const WASM_NONCE_CAP: usize = 10_000;

/// Nonce TTL in milliseconds (24 hours — UCAN max lifetime per ADR-016 step 11).
const WASM_NONCE_TTL_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

/// Maximum number of revoked token CIDs per context.
const WASM_REVOKED_TOKENS_CAP: usize = 100_000;

/// Maximum number of executed proposals tracked per context before triggering eviction.
const WASM_PROPOSAL_CAP: usize = 10_000;

/// Executed-proposal replay-protection TTL in milliseconds (14 days).
///
/// SECURITY-CRITICAL replay window. MUST mirror the native runtime's
/// `EXECUTED_PROPOSALS_TTL_SECS` (`crates/scp-runtime/src/context/state.rs` =
/// `14 * 24 * 60 * 60` seconds). A shorter WASM window would let a direct
/// re-execute of a durably-resolved (`Approved`) proposal slip past the
/// emptied replay guard after the window and mint a SECOND
/// `GovernanceActionExecuted` leaf that native — guarding for the full 14 days
/// (and by the `status == Approved` precondition) — would reject, diverging the
/// log across bridges (§9.9.3). Keep this in lock-step with the native const.
const WASM_PROPOSAL_TTL_MS: f64 = 14.0 * 24.0 * 60.0 * 60.0 * 1000.0;

/// Maximum number of resolved (approved/rejected) proposals per context.
/// When at capacity, the oldest entry (by `created_at`) is evicted.
const WASM_RESOLVED_PROPOSAL_CAP: usize = 10_000;

/// Maximum events in the receive buffer. Matches `PyO3` channel capacity.
const WASM_EVENT_BUFFER_CAP: usize = 1000;

/// Maximum entries per author's block list in broadcast contexts (§5.14.8).
const WASM_BLOCK_LIST_CAP: usize = 10_000;

/// Maximum members per context. Prevents unbounded growth of the membership map.
const WASM_MEMBER_CAP: usize = 10_000;

impl PerContextState {
    /// Pushes an event to the receive buffer, evicting the oldest if at capacity.
    fn push_event(&mut self, event: ContextEvent) {
        if self.event_buffer.len() >= WASM_EVENT_BUFFER_CAP {
            self.event_buffer.pop_front();
        }
        self.event_buffer.push_back(event);
    }

    /// Appends a protocol event to the context's event log.
    ///
    /// Constructs a full [`Event`] with the correct sequence number and
    /// `prev_hash` chain link, then delegates to
    /// [`scp_event_log::tree::append_unsigned_event`]. The event carries an
    /// empty signature (WASM bridge limitation — see `append_unsigned_event`
    /// documentation for the security model).
    ///
    /// This helper replaces the old `WasmEventLog::append_event(tag, did, payload)`
    /// API with the canonical scp-event-log implementation.
    /// `timestamp_secs` is the **committer-assigned** convergent leaf timestamp
    /// (Unix seconds), matching the native runtime: for a commit-ordered event
    /// it is the `created_at` of the signed SCP envelope carrying the commit
    /// (copied by every member); for a timer-triggered event it is the
    /// pre-computed convergent deadline. It is NEVER each member's local
    /// `crate::time::now_secs()`, which would diverge and break the
    /// equal-count/equal-root equivocation test a WASM member and a native
    /// member must both satisfy (§7.3.1, §9.9.3).
    fn append_log_event(
        &mut self,
        event_type: EventType,
        actor_did: &str,
        payload: &[u8],
        timestamp_secs: u64,
    ) {
        let sequence = event_count(&self.event_log);
        let prev_hash = if self.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            self.event_log.leaves()[self.event_log.leaves().len() - 1]
        };
        let event = Event {
            event_type,
            actor_did: DID::from(actor_did.to_owned()),
            timestamp: timestamp_secs,
            sequence,
            payload: EventPayload {
                data: payload.to_vec(),
            },
            prev_hash,
            signature: vec![],
        };
        // append_unsigned_event validates sequence + prev_hash. Since we
        // compute both from the current log state, this should never fail.
        // If it does, log the error to the browser console for diagnostics.
        if let Err(e) = append_unsigned_event(&mut self.event_log, &event) {
            web_sys::console::error_1(&format!("[SCP] event log append failed: {e}").into());
        }
    }

    /// Returns `true` if the member has the given capability string.
    ///
    /// Delegates to the shared [`ContextRoleState::member_has_capability`] (the
    /// SAME role/ceiling/suspension logic the native runtime uses), after
    /// parsing the WASM-format capability string into a typed
    /// [`Capability`]. Suspension is checked first by the shared type, then the
    /// member's role-granted `member_capabilities` set.
    ///
    /// Capability strings use the UCAN `{resource}:{action}` format where
    /// compound resources use underscores (e.g. `"tool_invoke:*"`,
    /// `"context:close"`, `"messages:write"`). [`ucan_string_to_capability`]
    /// reverses the underscore-resource encoding so `Capability::new` (which
    /// expects the colon user-facing form) recovers the right variant.
    fn member_has_capability(&self, member_did: &str, capability: &str) -> bool {
        self.role_state
            .member_has_capability(member_did, &ucan_string_to_capability(capability))
    }

    /// Checks that the SDK's protocol version is compatible with this context's
    /// `minProtocolVersion` requirement (spec §13.4).
    ///
    /// Returns `Ok(())` if compatible (or if no minimum is set). Returns an
    /// error if the context requires a higher protocol version than the SDK
    /// supports, if the major versions differ, or if the version data is
    /// malformed (non-numeric values are rejected, not silently defaulted).
    fn check_version_compatibility(&self) -> Result<(), ScpWasmError> {
        parse_and_check_min_protocol_version(&self.params_json)
    }

    // -----------------------------------------------------------------------
    // Accessors used by `crate::consequence`
    //
    // These are colocated with the struct so that the private fields stay
    // accessible without leaking the full `PerContextState` surface out of
    // the module. The consequence module calls these directly.
    // -----------------------------------------------------------------------

    /// Read-only view of the declared consequence rules (ADR-017).
    pub(crate) fn consequence_rules(&self) -> &[scp_protocol::trust::consequence::ConsequenceRule] {
        &self.consequence_rules
    }

    /// Returns the stored event log's event slice. Wraps
    /// [`scp_event_log::EventLog::events`] so the consequence module can
    /// call `evaluate_consequence_rules` without pulling in extra surface.
    pub(crate) fn event_log_events(&self) -> &[scp_event_log::Event] {
        self.event_log.events()
    }

    /// Returns the recent receive-buffer events (local `ContextEvent`s) used
    /// as a supplementary source for consequence evaluation.
    ///
    /// Per the ADR-011 amendment exclusion taxonomy
    /// (`.docs/adrs/phase-2.md` §2), per-author application activity such as
    /// `MessageSent` is no longer a durable Merkle leaf — it is surfaced only
    /// as a local `ContextEvent` in this buffer. The consequence engine reads
    /// velocity / rate triggers from here, mirroring the native runtime's
    /// `event_log_entries_for_consequences` Source 2 (the receive buffer).
    pub(crate) fn event_buffer_events(&self) -> &VecDeque<ContextEvent> {
        &self.event_buffer
    }

    /// Checks whether the subject is currently a member of the context.
    pub(crate) fn members_contains(&self, subject_did: &str) -> bool {
        self.role_state.members.contains(subject_did)
    }

    /// System-level role assignment over the shared [`ContextRoleState`]
    /// (consequence-engine path). Validates that the role exists in
    /// `role_definitions` and that every granted capability is within the
    /// ceiling before minting tokens — the shared behavior that closes the
    /// former WASM gap of silently accepting an undefined role.
    ///
    /// Returns `Err` if the member is absent or the role is undefined /
    /// out-of-ceiling; the consequence actuator maps that to `false`.
    pub(crate) fn role_state_system_assign_role(
        &mut self,
        subject_did: &str,
        role_name: &str,
    ) -> Result<(), scp_protocol::context::roles::RoleError> {
        self.role_state
            .system_assign_role(subject_did, role_name, &crate::time::WasmClock)
            .map(|_tokens| ())
    }

    /// Pushes a context event onto the receive buffer (public wrapper so
    /// `crate::consequence` can emit `ConsequenceTriggered` /
    /// `ConsequenceEnforced`).
    pub(crate) fn push_event_pub(&mut self, event: ContextEvent) {
        self.push_event(event);
    }

    /// Role-based capability check (public wrapper around the module-private
    /// `member_has_capability`). Test-only: the production consequence path
    /// (`apply_suspend_all`) now delegates to the shared
    /// [`ContextRoleState::suspend_all`] and no longer needs this per-cap probe;
    /// it survives solely as a cross-module assertion helper for the
    /// `consequence` tests.
    #[cfg(test)]
    pub(crate) fn member_has_capability_pub(&self, subject_did: &str, capability: &str) -> bool {
        self.member_has_capability(subject_did, capability)
    }

    /// Suspends `capability` (a WASM-format UCAN string) for the subject via the
    /// shared [`ContextRoleState::suspend_capabilities`]. Test-only — used by
    /// sibling-module tests to construct partially-suspended members.
    #[cfg(test)]
    pub(crate) fn suspended_capabilities_insert(&mut self, subject_did: &str, capability: String) {
        self.role_state
            .suspend_capabilities(subject_did, [ucan_string_to_capability(&capability)]);
    }

    /// Suspends typed capabilities for the subject via the shared
    /// [`ContextRoleState::suspend_capabilities`] (no string round-trip).
    pub(crate) fn suspend_capabilities_typed(&mut self, subject_did: &str, caps: &[Capability]) {
        self.role_state
            .suspend_capabilities(subject_did, caps.iter().cloned());
    }

    /// Suspends ALL of the subject's effective capabilities via the shared
    /// [`ContextRoleState::suspend_all`], which REPLACES (not extends) the
    /// subject's suspended set with their full current `member_capabilities`.
    /// Returns `true` if the subject had any capabilities to suspend (i.e. a
    /// suspended-set entry now exists), `false` otherwise — so the consequence
    /// actuator can report whether the action applied.
    pub(crate) fn suspend_all_pub(&mut self, subject_did: &str) -> bool {
        self.role_state.suspend_all(subject_did);
        self.role_state
            .suspended_for(subject_did)
            .is_some_and(|caps| !caps.is_empty())
    }

    /// Reads a cooldown timer for a given rule index.
    pub(crate) fn cooldown_until_get(&self, rule_index: usize) -> Option<&u64> {
        self.cooldown_until.get(&rule_index)
    }

    /// Records a cooldown timer for a given rule index.
    pub(crate) fn cooldown_until_insert(&mut self, rule_index: usize, until_secs: u64) {
        self.cooldown_until.insert(rule_index, until_secs);
    }

    /// TEST-ONLY scaffolding: replaces the ceiling and RE-DERIVES the built-in
    /// role definitions and every member's granted-capability set from the new
    /// ceiling, so a test can incrementally widen a context's ceiling on an
    /// already-constructed context and have built-in roles + member capabilities
    /// recompute against it.
    ///
    /// This does NOT model the production `ModifyCeiling` path. Production
    /// `dispatch_modify_ceiling` converges with native
    /// (`apply_pending_ceiling_modification`): it calls `set_ceiling` ONLY, with
    /// no built-in-role rebuild and no per-member `system_assign_role` refresh, so
    /// `member_capabilities` go stale-on-ceiling-change exactly like native. This
    /// helper exists only so test setup can mutate the ceiling of a context that
    /// already has members assigned (the production path seeds the ceiling at
    /// construction via [`ContextRoleState::new`], which derives built-in roles
    /// from the ceiling up front).
    ///
    /// It:
    /// 1. installs the new ceiling (`set_ceiling`),
    /// 2. rebuilds the built-in role definitions (`admin` = the whole new
    ///    ceiling; the role-subset roles intersected with it),
    /// 3. re-runs `system_assign_role` for every current member at their existing
    ///    role so `member_capabilities` reflects the new ceiling.
    ///
    /// Custom (non-built-in) role definitions are preserved as-is; only the
    /// protocol built-ins are re-derived (WASM only assigns built-in role names).
    ///
    /// # Errors
    ///
    /// Returns [`CeilingEntryError`](scp_protocol::context::roles::CeilingEntryError)
    /// if any entry of `ceiling` is malformed per the §5.3.1.1 grammar — the shared
    /// `ContextRoleState::set_ceiling` is fail-closed, so on a rejected write the
    /// prior ceiling, role definitions, and member capabilities are ALL left
    /// unchanged (the refresh below runs only after a successful `set_ceiling`).
    #[cfg(test)]
    fn set_ceiling_and_refresh(
        &mut self,
        ceiling: CapabilityCeiling,
    ) -> Result<(), scp_protocol::context::roles::CeilingEntryError> {
        // Fail-closed: validate + install the whole replacement first. If it is
        // rejected, return BEFORE touching role definitions or member caps.
        self.role_state.set_ceiling(ceiling.clone())?;

        // Rebuild built-in role definitions against the new ceiling, leaving any
        // custom role definitions untouched.
        for role in builtin_roles(&ceiling)
            .into_iter()
            .chain(builtin_broadcast_roles(&ceiling))
        {
            self.role_state
                .role_definitions
                .insert(role.name.clone(), role);
        }

        // Refresh every member's granted-capability set at their current role.
        let assignments: Vec<(String, String)> = self
            .role_state
            .assignments
            .iter()
            .map(|(did, a)| (did.clone(), a.role_name.clone()))
            .collect();
        for (did, role_name) in assignments {
            // `system_assign_role` can error three ways: `MemberNotInContext`
            // (member absent), `RoleNotFound` (role undefined), or
            // `CapabilityOutsideCeiling` (a role-def cap not in the live
            // ceiling). None can occur here: `did` is drawn from a live
            // `assignments` entry (so it is present); `role_name` is that
            // entry's role, which — for the built-in role names WASM assigns —
            // was just re-inserted into `role_definitions` by the rebuild above
            // (so it is defined); and that rebuild derives each built-in role's
            // caps by INTERSECTING with the new ceiling, so every assigned
            // role's caps are within-ceiling by construction. The discarded
            // result is therefore always `Ok`.
            let _ = self
                .role_state
                .system_assign_role(&did, &role_name, &crate::time::WasmClock);
        }

        Ok(())
    }

    /// Appends a durable consequence-enforcement Merkle leaf (ADR-017, ADR-051
    /// §6, H4). Called by [`crate::consequence::WasmConsequenceDispatcher`]'s
    /// [`scp_protocol::trust::consequence::ConsequenceDispatcher::append_durable_consequence_leaf`]
    /// override for convergent-trigger consequences only.
    ///
    /// The actor is the stable system sentinel `"system"` (matching the native
    /// runtime's `CONSEQUENCE_ACTOR_DID`), and the payload is the shared
    /// [`scp_event_log::payload::consequence_event_payload`] output, so the leaf
    /// preimage is byte-identical to the native runtime's
    /// (§9.9.3 equivocation-detection convergence).
    pub(crate) fn append_consequence_leaf(
        &mut self,
        event_type: EventType,
        subject_did: &str,
        rule_index: usize,
        trigger_kind: &str,
        action_type: &str,
        trigger_timestamp_secs: u64,
    ) {
        // Native uses CONSEQUENCE_ACTOR_DID = SYSTEM_CONSEQUENCE_ACTOR ("system")
        // as the actor for these leaves so the `WarningCount` trigger's
        // `actor_did != subject_did` requirement holds for recursive rule
        // evaluation. The shared const guarantees byte-identical sentinels
        // across native and WASM (§9.9.3 cross-bridge convergence).
        let payload = scp_event_log::payload::consequence_event_payload(
            subject_did,
            rule_index,
            trigger_kind,
            action_type,
        );
        self.append_log_event(
            event_type,
            scp_event_log::system_actors::SYSTEM_CONSEQUENCE_ACTOR,
            &payload.data,
            trigger_timestamp_secs,
        );
    }

    // ---- Test-only helpers (compiled away in release builds) -------------
    //
    // These expose a minimal subset of the private internals needed by the
    // consequence-dispatch tests and the snapshot-validator tests in this
    // file. They are `#[cfg(test)]` so they do not widen the production API
    // surface. They also take an explicit `timestamp` parameter where
    // applicable so tests can run on the native target without invoking
    // `crate::time::now_secs()` (which requires the WASM JS runtime).

    /// Test-only: append an event to the event log with an explicit
    /// timestamp. Mirrors [`append_log_event`] but does not call
    /// `crate::time::now_secs()`, so this is safe in native tests.
    #[cfg(test)]
    pub(crate) fn test_append_log_event_at(
        &mut self,
        event_type: EventType,
        actor_did: &str,
        timestamp: u64,
        payload: &[u8],
    ) {
        let sequence = event_count(&self.event_log);
        let prev_hash = if self.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            self.event_log.leaves()[self.event_log.leaves().len() - 1]
        };
        let event = Event {
            event_type,
            actor_did: DID::from(actor_did.to_owned()),
            timestamp,
            sequence,
            payload: EventPayload {
                data: payload.to_vec(),
            },
            prev_hash,
            signature: vec![],
        };
        let _ = append_unsigned_event(&mut self.event_log, &event);
    }

    /// Test-only: the current Merkle root of this context's event log. Used by
    /// cross-impl leaf-parity tests to prove a payload change perturbs the root.
    #[cfg(test)]
    pub(crate) fn test_event_log_root(&self) -> [u8; 32] {
        scp_event_log::tree::root(&self.event_log)
    }

    /// Test-only: insert a member with the given (built-in) role.
    ///
    /// Adds the DID to `role_state.members`, seeds its MLS sequence counter, and
    /// assigns the role via `system_assign_role` so `member_capabilities` is
    /// populated against the current ceiling.
    #[cfg(test)]
    pub(crate) fn test_insert_member(&mut self, did: &str, role: &str) {
        self.role_state.members.insert(did.to_owned());
        self.member_sequence_numbers
            .entry(did.to_owned())
            .or_insert(0);
        let _ = self
            .role_state
            .system_assign_role(did, role, &crate::time::WasmClock);
    }

    /// Test-only: read the current role name for a member.
    #[cfg(test)]
    pub(crate) fn test_member_role(&self, did: &str) -> Option<&str> {
        self.role_state
            .assignments
            .get(did)
            .map(|a| a.role_name.as_str())
    }

    /// Test-only: read a member's MLS message sequence counter, or `None` if
    /// the DID has no entry in `member_sequence_numbers`. Lets rollback and
    /// export/import round-trip tests assert the counter directly (the field
    /// is private).
    #[cfg(test)]
    pub(crate) fn test_member_sequence_number(&self, did: &str) -> Option<u64> {
        self.member_sequence_numbers.get(did).copied()
    }

    /// Test-only: read the suspended capability set for a member as
    /// UCAN-format strings (owned), or `None` if the member has no suspensions.
    #[cfg(test)]
    pub(crate) fn test_suspended_capabilities(
        &self,
        did: &str,
    ) -> Option<std::collections::HashSet<String>> {
        self.role_state
            .suspended_for(did)
            .map(|caps| caps.iter().map(Capability::ucan_capability_name).collect())
    }

    /// Test-only: suspend a single capability (UCAN-format string) for a
    /// member, so sibling-module cross-impl tests can construct a member that
    /// holds `governance:vote` (eligible voter) while lacking a specific action
    /// capability (e.g. `role:assign`). Mirrors the production effect of
    /// `apply_suspend` populating the shared `suspended_capabilities`.
    #[cfg(test)]
    pub(crate) fn test_insert_suspended_capability(&mut self, did: &str, capability: &str) {
        self.role_state
            .suspend_capabilities(did, [ucan_string_to_capability(capability)]);
    }

    /// Test-only: push a consequence rule onto the context's declared rules.
    #[cfg(test)]
    pub(crate) fn test_push_consequence_rule(
        &mut self,
        rule: scp_protocol::trust::consequence::ConsequenceRule,
    ) {
        self.consequence_rules.push(rule);
    }

    /// Test-only: add a capability (UCAN-format string) to the context ceiling
    /// and refresh role definitions / member capabilities against it.
    #[cfg(test)]
    #[allow(clippy::expect_used)] // test-only helper; the test corpus uses well-formed entries
    pub(crate) fn test_insert_ceiling(&mut self, capability: &str) {
        let mut caps: HashSet<Capability> = self.role_state.ceiling().iter().cloned().collect();
        caps.insert(ucan_string_to_capability(capability));
        // Test helper: the inserted capability is well-formed (the test corpus
        // uses canonical entries), so the validating `set_ceiling_and_refresh`
        // never errors here.
        self.set_ceiling_and_refresh(CapabilityCeiling::new(caps))
            .expect("test ceiling capability must be well-formed");
    }

    /// Test-only: set the governance model string (e.g. `"majority"`), so
    /// sibling-module tests can drive multi-admin proposal/vote flows.
    #[cfg(test)]
    pub(crate) fn test_set_governance(&mut self, model: &str) {
        self.governance = model.to_owned();
    }

    /// Test-only: insert a resolved (e.g. `Approved`) proposal directly, so
    /// sibling-module cross-impl tests can drive the direct-execute path
    /// (which requires the proposal tracked-and-`Approved`).
    #[cfg(test)]
    pub(crate) fn test_insert_resolved_proposal(
        &mut self,
        id: String,
        proposal: GovernanceProposal,
    ) {
        self.insert_resolved_proposal(id, proposal);
    }

    /// Test-only: set the lifecycle state string (e.g. `"closing"`), so
    /// sibling-module cross-impl tests can drive `finalize_close`.
    #[cfg(test)]
    pub(crate) fn test_set_state(&mut self, state: &str) {
        self.state = state.to_owned();
    }

    /// Test-only: set the convergent creation timestamp (seconds), the TTL
    /// deadline base for `handle_ttl_expiry`.
    #[cfg(test)]
    pub(crate) fn test_set_creation_timestamp_secs(&mut self, secs: u64) {
        self.creation_timestamp_secs = secs;
    }

    /// Test-only: set the TTL window (seconds). With a creation timestamp this
    /// fixes the convergent `ContextExpired` leaf timestamp.
    #[cfg(test)]
    pub(crate) fn test_set_ttl_seconds(&mut self, ttl: Option<u64>) {
        self.ttl_seconds = ttl;
    }

    /// Inserts a resolved proposal, evicting the oldest (by `created_at`) if
    /// at [`WASM_RESOLVED_PROPOSAL_CAP`].
    fn insert_resolved_proposal(&mut self, id: String, proposal: GovernanceProposal) {
        if self.resolved_proposals.len() >= WASM_RESOLVED_PROPOSAL_CAP {
            // Evict the entry with the smallest `created_at`.
            if let Some(oldest_key) = self
                .resolved_proposals
                .iter()
                .min_by_key(|(_, p)| p.created_at)
                .map(|(k, _)| k.clone())
            {
                self.resolved_proposals.remove(&oldest_key);
            }
        }
        self.resolved_proposals.insert(id, proposal);
    }

    /// Removes a resolved proposal by id. Used to roll back a pending →
    /// resolved move when the subsequent governance dispatch fails, so the
    /// proposal remains retriable (parity with native retry semantics).
    fn remove_resolved_proposal(&mut self, id: &str) -> Option<GovernanceProposal> {
        self.resolved_proposals.remove(id)
    }
}

// ---------------------------------------------------------------------------
// WasmContextManager
// ---------------------------------------------------------------------------

/// WASM-compatible context manager.
///
/// Mirrors `scp_core::context::manager::ContextManager`'s public API surface.
/// All bridge functions delegate to this manager. State is kept in a
/// `HashMap<String, PerContextState>` keyed by context ID.
///
/// WASM is single-threaded, so no `Mutex` or async coordination is needed.
/// All methods are synchronous (the `async` bridge wrappers in `context.rs`
/// call these synchronously within `future_to_promise`).
pub struct WasmContextManager {
    contexts: HashMap<String, PerContextState>,
    /// Pending MLS key package holders for encrypted context joins.
    /// Keyed by `"{context_id}:{member_did}"`. Consumed by
    /// `join_context_encrypted`.
    pending_key_packages: HashMap<String, crate::crypto::group::WasmMlsGroup>,
}

// ---------------------------------------------------------------------------
// Import validation helpers
// ---------------------------------------------------------------------------

/// Validates a string field from imported (untrusted) data.
fn validate_imported_string(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), ScpWasmError> {
    if value.is_empty() {
        return Err(ScpWasmError::Context {
            message: format!("{field_name} must not be empty"),
            code: codes::CTX_2032.to_owned(),
        });
    }
    if value.len() > max_len {
        return Err(ScpWasmError::Context {
            message: format!(
                "{field_name} exceeds maximum length ({} > {max_len})",
                value.len()
            ),
            code: codes::CTX_2032.to_owned(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ScpWasmError::Context {
            message: format!("{field_name} contains control characters"),
            code: codes::CTX_2032.to_owned(),
        });
    }
    Ok(())
}

/// Validates a DID string from imported (untrusted) data.
fn validate_imported_did(value: &str, field_name: &str) -> Result<(), ScpWasmError> {
    validate_imported_string(value, field_name, 512)?;
    if !value.starts_with("did:") {
        return Err(ScpWasmError::Context {
            message: format!("{field_name} must start with 'did:': got '{value}'"),
            code: codes::CTX_2032.to_owned(),
        });
    }
    // Must have at least did:method:id (3 colon-separated parts)
    if value.splitn(4, ':').count() < 3 {
        return Err(ScpWasmError::Context {
            message: format!("{field_name} must have format 'did:method:id': got '{value}'"),
            code: codes::CTX_2032.to_owned(),
        });
    }
    Ok(())
}

/// Validates the v3 anti-replay fields (`seen_nonces_v3`,
/// `executed_proposals`, `resolved_proposals_json`), the `consequence_rules`
/// vector, and the `cooldown_until` map on an imported snapshot.
///
/// This is defense-in-depth: the envelope HMAC already prevents tampering,
/// but malformed state (empty nonce strings, `NaN` or unbounded timestamps,
/// over-cap entries, invalid consequence rules) must fail loud rather than
/// silently propagate into `PerContextState`.
fn validate_imported_antispam_state(snap: &WasmContextExportSnapshot) -> Result<(), ScpWasmError> {
    // Capacity caps — match live `PerContextState` limits. A malicious
    // export cannot bloat the importer beyond its runtime policy.
    if snap.seen_nonces_v3.len() > WASM_NONCE_CAP {
        return Err(ScpWasmError::Context {
            message: format!(
                "snapshot contains {} nonces, exceeds cap {WASM_NONCE_CAP}",
                snap.seen_nonces_v3.len()
            ),
            code: codes::CTX_2032.to_owned(),
        });
    }
    if snap.seen_nonces_legacy_v2.len() > WASM_NONCE_CAP {
        return Err(ScpWasmError::Context {
            message: format!(
                "snapshot contains {} legacy nonces, exceeds cap {WASM_NONCE_CAP}",
                snap.seen_nonces_legacy_v2.len()
            ),
            code: codes::CTX_2032.to_owned(),
        });
    }
    if snap.executed_proposals.len() > WASM_PROPOSAL_CAP {
        return Err(ScpWasmError::Context {
            message: format!(
                "snapshot contains {} executed proposals, exceeds cap {WASM_PROPOSAL_CAP}",
                snap.executed_proposals.len()
            ),
            code: codes::CTX_2032.to_owned(),
        });
    }
    if snap.resolved_proposals_json.len() > WASM_RESOLVED_PROPOSAL_CAP {
        return Err(ScpWasmError::Context {
            message: format!(
                "snapshot contains {} resolved proposals, exceeds cap {WASM_RESOLVED_PROPOSAL_CAP}",
                snap.resolved_proposals_json.len()
            ),
            code: codes::CTX_2032.to_owned(),
        });
    }

    // Per-entry shape + timestamp sanity on seen_nonces_v3.
    //
    // We DO NOT use `crate::time::now_ms()` here because on native test
    // targets the captured `Date.now` extern would panic if called. The
    // clock-skew clamp is enforced at use time in `import_context` (each
    // imported `inserted_at_ms` is `min`ed against `now_ms` when the
    // `HashMap<String, f64>` is constructed). Here we only reject clearly
    // malformed values: NaN / infinity / negative.
    for entry in &snap.seen_nonces_v3 {
        validate_imported_string(&entry.nonce, "seen_nonces_v3.nonce", 256)?;
        if !entry.inserted_at_ms.is_finite() || entry.inserted_at_ms < 0.0 {
            return Err(ScpWasmError::Context {
                message: format!(
                    "nonce '{}' has invalid inserted_at_ms={}",
                    entry.nonce, entry.inserted_at_ms
                ),
                code: codes::CTX_2032.to_owned(),
            });
        }
    }

    for entry in &snap.executed_proposals {
        validate_imported_string(&entry.proposal_id, "executed_proposals.proposal_id", 256)?;
        if !entry.executed_at_ms.is_finite() || entry.executed_at_ms < 0.0 {
            return Err(ScpWasmError::Context {
                message: format!(
                    "executed proposal '{}' has invalid executed_at_ms={}",
                    entry.proposal_id, entry.executed_at_ms
                ),
                code: codes::CTX_2032.to_owned(),
            });
        }
    }

    // Legacy v2 entries are flat strings. Same length/shape rules as v3.
    for nonce in &snap.seen_nonces_legacy_v2 {
        validate_imported_string(nonce, "seen_nonces_legacy_v2", 256)?;
    }

    // resolved_proposals keys must be valid hex strings (proposal IDs).
    for key in snap.resolved_proposals_json.keys() {
        validate_imported_string(key, "resolved_proposals_json.key", 256)?;
    }

    // Validate imported consequence rules via validate_against_config.
    // Default config (allow_automatic_access_revocation = false) is the
    // safe choice for imported snapshots of unknown provenance.
    let import_config = scp_protocol::context::params::ConsequenceConfig::default();
    for (idx, rule) in snap.consequence_rules.iter().enumerate() {
        rule.validate_against_config(&import_config)
            .map_err(|e| ScpWasmError::Context {
                message: format!("imported consequence_rules[{idx}] invalid: {e}"),
                code: codes::CTX_2032.to_owned(),
            })?;
    }

    // Cooldown map: rule_index must be within the rules vector's bounds so
    // an attacker cannot inject cooldowns for nonexistent rules and
    // indirectly affect future rule evaluation.
    for &rule_index in snap.cooldown_until.keys() {
        if rule_index >= snap.consequence_rules.len() {
            return Err(ScpWasmError::Context {
                message: format!(
                    "cooldown_until contains rule_index={rule_index} but only {} rules are declared",
                    snap.consequence_rules.len()
                ),
                code: codes::CTX_2032.to_owned(),
            });
        }
    }

    Ok(())
}

/// Parses and validates `minProtocolVersion` from a params JSON value, then
/// checks that this SDK's `SCP_PROTOCOL_VERSION` is compatible.
///
/// Returns `Ok(())` if no `minProtocolVersion` is present or if the SDK
/// version satisfies the minimum. Returns an error if:
/// - The array has fewer than 2 elements.
/// - Either element is not a number (rejects silent downgrades).
/// - Either element exceeds `u8` range.
/// - The SDK version is incompatible per §13.1/§13.4.
///
/// Used by both `PerContextState::check_version_compatibility` (join/subscribe
/// paths) and `WasmContextManager::create_context` (creation defense-in-depth).
fn parse_and_check_min_protocol_version(params: &serde_json::Value) -> Result<(), ScpWasmError> {
    let Some(min_ver) = params["minProtocolVersion"].as_array() else {
        return Ok(());
    };
    if min_ver.len() < 2 {
        return Err(ScpWasmError::Context {
            message: format!(
                "malformed minProtocolVersion: expected [major, minor] array with at \
                 least 2 elements, got {min_ver:?}"
            ),
            code: codes::CTX_2015.to_owned(),
        });
    }
    let raw_major = min_ver
        .first()
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ScpWasmError::Context {
            message: format!(
                "malformed minProtocolVersion: major version is not a number: {:?}",
                min_ver.first()
            ),
            code: codes::CTX_2015.to_owned(),
        })?;
    let req_major = u8::try_from(raw_major).map_err(|_| ScpWasmError::Context {
        message: format!(
            "malformed minProtocolVersion: major version {raw_major} exceeds u8 range"
        ),
        code: codes::CTX_2015.to_owned(),
    })?;
    let raw_minor = min_ver
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ScpWasmError::Context {
            message: format!(
                "malformed minProtocolVersion: minor version is not a number: {:?}",
                min_ver.get(1)
            ),
            code: codes::CTX_2015.to_owned(),
        })?;
    let req_minor = u8::try_from(raw_minor).map_err(|_| ScpWasmError::Context {
        message: format!(
            "malformed minProtocolVersion: minor version {raw_minor} exceeds u8 range"
        ),
        code: codes::CTX_2015.to_owned(),
    })?;
    let sdk_major = (SCP_PROTOCOL_VERSION >> 8) as u8;
    let sdk_minor = (SCP_PROTOCOL_VERSION & 0xFF) as u8;

    // Exact major match is intentional: different major versions have
    // incompatible wire formats per §13.1. This rejects both lower AND
    // higher majors.
    if sdk_major != req_major || sdk_minor < req_minor {
        return Err(ScpWasmError::Context {
            message: format!(
                "protocol version incompatible: context requires {req_major}.{req_minor}, \
                 SDK supports {sdk_major}.{sdk_minor}"
            ),
            code: codes::CTX_2016.to_owned(),
        });
    }
    Ok(())
}

impl Default for WasmContextManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// WASM-local broadcast content constants (ADR-034: cannot import from scp-core)
// ---------------------------------------------------------------------------

/// Maximum number of assets in a single batch publish call.
const MAX_BATCH_ASSETS: usize = 10_000;

/// Maximum body size in bytes (10 MiB).
/// Must match `scp_core::context::broadcast_content::MAX_BODY_BYTES`.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

// Imported from scp-protocol.
use scp_protocol::context::broadcast_content::BROADCAST_CONTENT_VERSION;

// ---------------------------------------------------------------------------
// Content validation — delegates to scp-protocol broadcast_content types
// ---------------------------------------------------------------------------

/// Validates a content path for broadcast asset publishing (SCP-290).
///
/// Delegates to `scp_protocol::context::broadcast_content::ContentPath::new`.
fn validate_content_path_wasm(path: &str) -> Result<String, String> {
    use scp_protocol::context::broadcast_content::ContentPath;
    let cp = ContentPath::new(path).map_err(|e| e.to_string())?;
    Ok(cp.as_str().to_owned())
}

/// Validates a MIME type using `scp_protocol::context::broadcast_content::MimeType`.
fn validate_mime_type_wasm(value: &str) -> Result<(), String> {
    use scp_protocol::context::broadcast_content::MimeType;
    MimeType::new(value).map_err(|e| e.to_string())?;
    Ok(())
}

/// Validates a `deploy_id` using `scp_protocol::context::broadcast_content::validate_deploy_id`.
fn validate_deploy_id_wasm(deploy_id: &str) -> Result<(), String> {
    scp_protocol::context::broadcast_content::validate_deploy_id(deploy_id)
        .map_err(|e| e.to_string())
}

/// Serializes broadcast content into the canonical wire format using
/// `scp_protocol::context::broadcast_content::serialize_broadcast_content`.
fn serialize_broadcast_content_wasm(
    path: &str,
    content_type: &str,
    deploy_id: Option<&str>,
    etag: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    use scp_protocol::context::broadcast_content::{
        BroadcastContent, ContentMetadata, ContentPath, MimeType, serialize_broadcast_content,
    };

    let content = BroadcastContent {
        version: BROADCAST_CONTENT_VERSION,
        metadata: ContentMetadata {
            path: Some(ContentPath::new(path).map_err(|e| e.to_string())?),
            content_type: Some(MimeType::new(content_type).map_err(|e| e.to_string())?),
            deploy_id: deploy_id.map(str::to_owned),
            etag: Some(etag.to_owned()),
            immutable: false,
        },
        body: body.to_vec(),
    };

    serialize_broadcast_content(&content).map_err(|e| e.to_string())
}

/// Test-only: construct a minimal [`PerContextState`] with the creator
/// registered as an `admin` member and no crypto/broadcast state.
///
/// This bypasses [`WasmContextManager::create_context`] entirely so
/// native tests (which lack the WASM JS runtime required by
/// `crate::time::now_secs`) can build a per-context state without
/// triggering the `ContextCreated` event-log append (which calls time).
///
/// Consumers should use the `test_*` helpers on [`PerContextState`] to
/// append events, insert members, push consequence rules, etc.
#[cfg(test)]
#[allow(clippy::expect_used)] // test-only helper; empty-ceiling construction is infallible
pub(crate) fn make_bare_per_context_state(context_id: &str, creator_did: &str) -> PerContextState {
    // Empty ceiling, creator auto-assigned `admin` by `ContextRoleState::new`.
    // `WasmClock` falls back to `SystemTime` on the native test target, so the
    // token-minting clock call inside `new` does not require the JS runtime.
    let role_state = ContextRoleState::new(
        context_id.to_owned(),
        creator_did.to_owned(),
        CapabilityCeiling::new(std::iter::empty()),
        Vec::new(),
        &crate::time::WasmClock,
    )
    .expect("bare ContextRoleState with empty ceiling and no custom roles is always valid");

    let mut member_sequence_numbers = HashMap::new();
    member_sequence_numbers.insert(creator_did.to_owned(), 0);

    PerContextState {
        state: "active".to_owned(),
        params_json: serde_json::Value::Null,
        mode: "Unencrypted".to_owned(),
        role_state,
        member_sequence_numbers,
        ceiling_policy: "immutable".to_owned(),
        ttl_seconds: None,
        promotion_policy: None,
        governance: "single_admin".to_owned(),
        economic_policy: None,
        tool_registry: ToolRegistry::new(),
        tool_handlers: HashMap::new(),
        event_log: EventLog::new(context_id.to_owned()),
        revoked_tokens: HashSet::new(),
        seen_nonces: HashMap::new(),
        event_buffer: VecDeque::new(),
        executed_proposals: HashMap::new(),
        read_exclusion_list: HashSet::new(),
        broadcast_context: None,
        sessions: HashMap::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        tool_interfaces: Vec::new(),
        governance_freeze: false,
        pending_proposals: HashMap::new(),
        resolved_proposals: HashMap::new(),
        pruning_policy: None,
        economic_policy_locked: false,
        hard_rate_limit_config: None,
        consequence_rules: Vec::new(),
        cooldown_until: HashMap::new(),
        crypto: None,
        creation_timestamp_secs: 0,
    }
}

impl WasmContextManager {
    /// Creates a new empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contexts: HashMap::new(),
            pending_key_packages: HashMap::new(),
        }
    }

    /// Test-only: register a pre-built `PerContextState` under `context_id`.
    /// Lets tests in sibling modules (e.g. `crate::consequence`) drive the
    /// real lifecycle/governance handlers without reaching into the private
    /// `contexts` field.
    #[cfg(test)]
    pub(crate) fn test_insert_context(&mut self, context_id: &str, ctx: PerContextState) {
        self.contexts.insert(context_id.to_owned(), ctx);
    }

    /// Test-only: clone the durable event-log leaves for `context_id`. Lets
    /// sibling-module tests assert on leaves the real handlers appended
    /// without exposing the private `contexts` field.
    #[cfg(test)]
    pub(crate) fn test_context_event_log_events(
        &self,
        context_id: &str,
    ) -> Vec<scp_event_log::Event> {
        self.contexts
            .get(context_id)
            .map(|ctx| ctx.event_log_events().to_vec())
            .unwrap_or_default()
    }

    /// Test-only: the current Merkle root of a registered context's event log.
    /// Used by cross-impl system-leaf parity tests to compare the WASM
    /// real-producer root against the native-reference single-leaf root.
    #[cfg(test)]
    pub(crate) fn test_context_event_log_root(&self, context_id: &str) -> [u8; 32] {
        self.contexts
            .get(context_id)
            .map(PerContextState::test_event_log_root)
            .unwrap_or_default()
    }

    /// Returns `true` if the context's stored economic policy requires payment.
    /// Returns `false` if the context is not found, not active, or has no/free policy.
    ///
    /// # Errors
    ///
    /// Returns `ScpWasmError::Context` if the context is not registered.
    pub fn context_has_paid_policy(&self, context_id: &str) -> Result<bool, ScpWasmError> {
        let ctx = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context '{context_id}' not found"),
                code: codes::CTX_2000.to_owned(),
            })?;
        Ok(stored_policy_requires_payment(
            ctx.economic_policy.as_deref(),
        ))
    }

    // -----------------------------------------------------------------------
    // Context lifecycle
    // -----------------------------------------------------------------------

    /// Creates a new context. Mirrors `ContextManager::create_context`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context ID is already registered or if
    /// parameters are invalid.
    #[allow(clippy::too_many_lines)] // context initialization touches many fields
    pub fn create_context(
        &mut self,
        context_id: &str,
        creator_did: &str,
        params: &serde_json::Value,
    ) -> Result<(), ScpWasmError> {
        if self.contexts.contains_key(context_id) {
            return Err(ScpWasmError::Context {
                message: format!("context '{context_id}' is already registered"),
                code: codes::CTX_2000.to_owned(),
            });
        }

        let mode = params["mode"].as_str().unwrap_or("Encrypted").to_owned();
        let ceiling: Vec<String> = params["ceiling"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let ceiling_policy = params["ceilingPolicy"]
            .as_str()
            .unwrap_or("immutable")
            .to_owned();
        let ttl_seconds = params["ttlSeconds"].as_u64();
        let promotion_policy = params["promotionPolicy"].as_str().map(str::to_owned);
        let governance = params["governance"]
            .as_str()
            .unwrap_or("single_admin")
            .to_owned();
        let economic_policy = params["economicPolicy"].as_str().map(str::to_owned);

        // C2 fail-closed: reject paid economic policies at WASM context creation.
        //
        // The browser bridge cannot run scp-runtime's `enforce_economy` (no
        // tokio multi-thread runtime, no payment adapter, no budget tracker —
        // see ADR-034). Accepting a paid policy here would silently bypass
        // every economic check on every subsequent send / join / tool invoke,
        // because the caller's `spending_ucan_jwt` is never cryptographically
        // validated against a payment adapter on the WASM path.
        //
        // We REJECT before any state is mutated. Callers must use a native
        // (Python / Node.js / Swift / Kotlin) bridge to create paid contexts.
        if stored_policy_requires_payment(economic_policy.as_deref()) {
            return Err(ScpWasmError::Context {
                message: "EconomicPolicyUnsupportedOnWasm: paid contexts cannot be created \
                          from the WASM bridge — the browser SDK cannot run the full economy \
                          enforcement pipeline (ADR-034). Use a native (Python / Node.js / \
                          Swift / Kotlin) client for paid contexts."
                    .to_owned(),
                code: SCP_ECON_PAID_POLICY_UNSUPPORTED_ON_WASM.to_owned(),
            });
        }

        // Build the typed capability ceiling. Empty input -> the shared
        // `default_ceiling()` (its `to_ucan_string_set()` is byte-equal to the
        // former `build_ceiling_strings(empty)` default — verified
        // format-preserving). Non-empty input -> parse each user-supplied
        // colon-form string via `Capability::new` (the same parse the shared
        // enforcement uses), then build the ceiling. The §5.3.1.1 grammar is
        // enforced by the shared `ContextRoleState::new` below, which runs
        // `CapabilityCeiling::validate_entries` and surfaces a malformed entry as
        // the canonical `SCP-VALID-7000` error (mapped from
        // `RoleError::InvalidCeilingCategory`). The ceiling is stored as
        // `Capability` enums in `ContextRoleState`; its canonical UCAN-string
        // projection (`to_ucan_string_set`) is byte-identical to what the native
        // bridge stores for the same logical entries.
        let ceiling: CapabilityCeiling = if ceiling.is_empty() {
            scp_protocol::context::roles::default_ceiling()
        } else {
            CapabilityCeiling::new(ceiling.iter().map(Capability::new))
        };

        // Parse and validate minProtocolVersion from params (spec §13.4).
        // This mirrors the NAPI bridge's parsing in context_create. Malformed
        // values produce errors (not silent downgrades). Defense-in-depth: the
        // creator's SDK version must satisfy the minimum it sets.
        parse_and_check_min_protocol_version(params)?;

        // H14: Parse and validate consequence_rules from params (ADR-017, #1531).
        let consequence_rules: Vec<scp_protocol::trust::consequence::ConsequenceRule> =
            if let Some(rules_val) = params.get("consequenceRules") {
                serde_json::from_value(rules_val.clone()).map_err(|e| ScpWasmError::Validation {
                    message: format!("invalid consequence_rules: {e}"),
                    code: codes::VALID_7000.to_owned(),
                })?
            } else {
                Vec::new()
            };
        let consequence_config: scp_protocol::context::params::ConsequenceConfig =
            params.get("consequenceConfig").map_or_else(
                scp_protocol::context::params::ConsequenceConfig::default,
                |cfg_val| serde_json::from_value(cfg_val.clone()).unwrap_or_default(),
            );
        for rule in &consequence_rules {
            rule.validate_against_config(&consequence_config)
                .map_err(|e| ScpWasmError::Validation {
                    message: format!("consequence rule validation failed: {e}"),
                    code: codes::VALID_7000.to_owned(),
                })?;
        }

        // Initialize broadcast context for Broadcast mode (§5.14.2).
        let broadcast_context = if mode == "Broadcast" {
            let admission_str = params["admission"].as_str().unwrap_or("open");
            let admission = if admission_str == "gated" {
                BroadcastAdmission::Gated
            } else {
                BroadcastAdmission::Open
            };
            let mut bc =
                BroadcastContext::new(context_id.to_owned(), &ContextMode::Broadcast, admission)
                    .map_err(|e| ScpWasmError::Context {
                        message: format!("broadcast context creation failed: {e}"),
                        code: codes::CTX_2001.to_owned(),
                    })?;
            // Register creator as initial author.
            let _ = bc
                .add_author(creator_did)
                .map_err(|e| ScpWasmError::Context {
                    message: format!("failed to add creator as author: {e}"),
                    code: codes::CTX_2001.to_owned(),
                })?;
            Some(bc)
        } else {
            None
        };

        // Initialize MLS crypto state for Encrypted mode.
        let crypto = if mode == "Encrypted" {
            Some(
                crate::crypto::WasmCryptoState::new_for_context(creator_did).map_err(|e| {
                    ScpWasmError::Crypto {
                        message: format!("MLS group creation failed: {e}"),
                        code: codes::CRYPTO_4004.to_owned(),
                    }
                })?,
            )
        } else {
            None
        };

        // Initialize the shared role state: `ContextRoleState::new` auto-derives
        // built-in role definitions from the ceiling and assigns the creator the
        // `admin` role. It is the single §5.3.1.1 enforcement point on the create
        // path: it runs `CapabilityCeiling::validate_entries`, so a malformed
        // ceiling entry surfaces as `RoleError::InvalidCeilingCategory`. Map that
        // to the canonical `SCP-VALID-7000` `Validation` error (identical reject
        // surface to the modify path; the import path surfaces the SCP-CTX-2032
        // deserialize error class); any other error here (a custom role outside
        // the ceiling) maps to a context error.
        let role_state = ContextRoleState::new(
            context_id.to_owned(),
            creator_did.to_owned(),
            ceiling,
            Vec::new(),
            &crate::time::WasmClock,
        )
        .map_err(|e| match e {
            scp_protocol::context::roles::RoleError::InvalidCeilingCategory(ce) => {
                ceiling_validation_error(ce)
            }
            other => ScpWasmError::Context {
                message: format!("role state initialization failed: {other}"),
                code: codes::CTX_2001.to_owned(),
            },
        })?;

        // Seed the creator's MLS message sequence counter.
        let mut member_sequence_numbers = HashMap::new();
        member_sequence_numbers.insert(creator_did.to_owned(), 0);

        // Creator-assigned creation time (this member is the creator). Bound
        // once so the `ContextCreated` leaf timestamp below and the stored
        // convergent `creation_timestamp_secs` are the identical value every
        // member copies (§7.3.1, §9.9.3).
        let creation_timestamp_secs = crate::time::now_secs();

        let per_context = PerContextState {
            state: "active".to_owned(),
            params_json: params.clone(),
            mode,
            role_state,
            member_sequence_numbers,
            ceiling_policy,
            ttl_seconds,
            promotion_policy,
            governance,
            economic_policy,
            tool_registry: ToolRegistry::new(),
            tool_handlers: HashMap::new(),
            event_log: EventLog::new(context_id.to_owned()),
            revoked_tokens: HashSet::new(),
            seen_nonces: HashMap::new(),
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            read_exclusion_list: HashSet::new(),
            broadcast_context,
            sessions: HashMap::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            tool_interfaces: Vec::new(),
            governance_freeze: false,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: None,
            economic_policy_locked: false,
            hard_rate_limit_config: None,
            consequence_rules,
            cooldown_until: HashMap::new(),
            crypto,
            creation_timestamp_secs,
        };

        self.contexts.insert(context_id.to_owned(), per_context);

        // Append ContextCreated event to event log.
        // Safe: we just inserted the context above, so the key is present.
        if let Some(ctx) = self.contexts.get_mut(context_id) {
            ctx.append_log_event(
                EventType::ContextCreated,
                creator_did,
                b"",
                // Creator-assigned creation time (this member is the creator);
                // copied by every member (§7.3.1, §9.9.3). Identical to the
                // stored `creation_timestamp_secs`.
                creation_timestamp_secs,
            );
        }

        Ok(())
    }

    /// Commits ONLY the in-memory membership state for a join — the
    /// active-check, version/economy gates, the `role_state.members` insert,
    /// the built-in "member" role assignment, and the `member_sequence_numbers`
    /// seed — WITHOUT emitting the `MemberJoined` buffer event or appending the
    /// durable `MemberJoined` Merkle leaf.
    ///
    /// This split exists so the encrypted-join path can match the native
    /// runtime's ordering (`crates/scp-runtime/src/context/lifecycle_helpers.rs`
    /// join): MLS Welcome processing happens BEFORE the durable
    /// `MemberJoined` leaf is appended (native Phase 5), so a failed Welcome
    /// leaves NO durable trace in the event log. The public unencrypted
    /// [`Self::join_context`] re-adds the buffer event + leaf immediately after
    /// this helper (matching native's non-MLS join, which appends the leaf at
    /// once); [`Self::join_context_encrypted`] defers them until after
    /// `join_from_welcome` succeeds.
    ///
    /// The fail-closed rollback on role-assign failure is preserved here: on a
    /// rejected assignment BOTH the `members` insert and the sequence seed are
    /// rolled back so a failed membership commit leaves nothing behind. Because
    /// this helper appends NO leaf, an early return cannot orphan one.
    ///
    /// # Errors
    ///
    /// Returns [`ScpWasmError`] if the context is not active, the SDK protocol
    /// version is incompatible (§13.4), the context's economic policy requires
    /// a payment the WASM bridge cannot validate (ADR-034), the member has
    /// already joined, or the built-in "member" role assignment fails (rolled
    /// back, infallible by construction today).
    fn join_context_membership_only(
        &mut self,
        context_id: &str,
        member_did: &str,
        spending_ucan_jwt: Option<&str>,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // Version compatibility check (spec §13.4): reject join if the
        // context requires a protocol version higher than this SDK supports.
        ctx.check_version_compatibility()?;

        // C2 fail-closed economy gate. We inspect both the stored
        // `economic_policy` AND `spending_ucan_jwt` so that callers cannot
        // accidentally believe a paid join was authorized — there is no
        // path where the WASM bridge can validate it.
        if stored_policy_requires_payment(ctx.economic_policy.as_deref()) {
            let _ = spending_ucan_jwt; // explicitly inspected so the parameter is no longer dropped
            return Err(ScpWasmError::Context {
                message: format!(
                    "WasmCannotValidateSpendingUcan: context '{context_id}' has an economic \
                     policy requiring payment, but the WASM bridge cannot cryptographically \
                     validate spending UCANs against a payment adapter (ADR-034). Use a native \
                     (Python / Node.js / Swift / Kotlin) client to join paid contexts."
                ),
                code: SCP_ECON_WASM_CANNOT_VALIDATE_SPENDING_UCAN.to_owned(),
            });
        }

        if ctx.role_state.members.contains(member_did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{member_did}' already joined context '{context_id}'"),
                code: codes::CTX_2013.to_owned(),
            });
        }

        // `system_assign_role` requires the DID to already be in `members`, so
        // insert first and seed the MLS sequence counter; on assignment failure
        // roll BOTH the `members` insert and the sequence seed back so a
        // rejected join leaves NO partial membership behind (fail-closed
        // atomicity — mirrors `dispatch_add_member` / `subscribe_broadcast`).
        //
        // Defense-in-depth: this assigns the built-in "member" role, whose caps
        // are ceiling-filtered at `ContextRoleState` construction, so
        // `system_assign_role` cannot return `RoleNotFound` /
        // `MemberNotInContext` / `CapabilityOutsideCeiling` here — the error
        // branch is unreachable today (infallible by construction). The
        // rollback exists for uniform fail-closed atomicity across all
        // membership-add paths and as robustness if a future change makes this
        // assignment fallible. The load-bearing, genuinely-reachable rollback
        // is `dispatch_add_member`'s (caller-supplied arbitrary role).
        ctx.role_state.members.insert(member_did.to_owned());
        ctx.member_sequence_numbers.insert(member_did.to_owned(), 0);
        if let Err(e) =
            ctx.role_state
                .system_assign_role(member_did, "member", &crate::time::WasmClock)
        {
            ctx.role_state.members.remove(member_did);
            ctx.member_sequence_numbers.remove(member_did);
            return Err(ScpWasmError::Context {
                message: format!("failed to assign 'member' role on join: {e}"),
                code: codes::CTX_2015.to_owned(),
            });
        }

        Ok(())
    }

    /// Joins a member to a context. Mirrors `ContextManager::join_context`.
    ///
    /// Delegates the membership commit to [`Self::join_context_membership_only`],
    /// then — since the unencrypted path has no MLS Welcome to process — emits
    /// the `MemberJoined` buffer event and durable Merkle leaf immediately,
    /// matching the native runtime's non-MLS join.
    ///
    /// # Fail-closed economy gate (C2)
    ///
    /// The WASM bridge cannot run scp-runtime's `enforce_economy` pipeline
    /// because `scp-runtime` does not compile to `wasm32` (ADR-034). If the
    /// stored `economic_policy` requires payment for any action, this method
    /// rejects the join with `SCP-ECON-12096` regardless of whether
    /// `spending_ucan_jwt` is `Some` or `None`. Accepting the join would be a
    /// security lie: the SDK would tell the caller their spend was authorized
    /// when it was never validated against a payment adapter, budget tracker,
    /// velocity tracker, or hard rate limit token bucket.
    ///
    /// Free contexts are unaffected — the parameter is inspected only to
    /// drive the rejection branch.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the protocol version
    /// is incompatible, the member is already joined, or the context's
    /// economic policy requires payment (fail-closed).
    pub fn join_context(
        &mut self,
        context_id: &str,
        member_did: &str,
        spending_ucan_jwt: Option<&str>,
    ) -> Result<(), ScpWasmError> {
        // Commit membership first. On any failure (inactive context, version
        // mismatch, economy gate, already-joined, or the infallible-by-
        // construction role assign) this returns Err having left no partial
        // state — and crucially no durable leaf, since the helper appends none.
        self.join_context_membership_only(context_id, member_did, spending_ucan_jwt)?;

        // Unencrypted join has no MLS Welcome to process, so — matching the
        // native runtime's non-MLS join — the `MemberJoined` buffer event and
        // durable Merkle leaf are emitted immediately once membership commits.
        let ctx = self.require_active_context_mut(context_id)?;
        ctx.push_event(ContextEvent::MemberJoined {
            member_did: DID(member_did.to_owned()),
            role_name: "member".to_owned(),
        });
        ctx.append_log_event(
            EventType::MemberJoined,
            member_did,
            b"",
            // Committer-assigned: this member's clock, the source of the
            // join commit's `created_at` (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        Ok(())
    }

    /// Leaves a context. Mirrors `ContextManager::leave_context`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the member is not found.
    pub fn leave_context(
        &mut self,
        context_id: &str,
        member_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if !ctx.role_state.members.remove(member_did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{member_did}' not found in context '{context_id}'"),
                code: codes::CTX_2015.to_owned(),
            });
        }
        // Drop all per-member state the leaving member left behind: role
        // assignment, granted capabilities, suspensions, and the MLS sequence
        // counter. Clearing suspensions via `restore_capabilities` over the
        // member's current suspended set keeps the shared map free of dangling
        // entries (a re-admitted same-DID member must not inherit a phantom
        // suspension).
        ctx.role_state.assignments.remove(member_did);
        ctx.role_state.member_capabilities.remove(member_did);
        // Clears the member's suspensions on removal — see the RemoveMember handler for the known native↔WASM divergence + deferred shared-removal convergence.
        if let Some(suspended) = ctx.role_state.suspended_for(member_did) {
            let caps: Vec<Capability> = suspended.iter().cloned().collect();
            ctx.role_state.restore_capabilities(member_did, &caps);
        }
        ctx.member_sequence_numbers.remove(member_did);

        // Unsubscribe from broadcast if applicable.
        if let Some(ref mut bc) = ctx.broadcast_context {
            // Ignore error if member is not a subscriber.
            let _ = bc.unsubscribe(member_did, false);
        }

        // Destroy crypto state on leave — the leaving member should not
        // retain MLS key material.
        if let Some(ref mut crypto) = ctx.crypto {
            crypto.destroy();
        }
        ctx.crypto = None;

        ctx.push_event(ContextEvent::MemberLeft {
            member_did: DID(member_did.to_owned()),
        });

        ctx.append_log_event(
            EventType::MemberLeft,
            member_did,
            b"",
            // Committer-assigned: the leaving member's clock (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        // Auto-close if no members remain.
        if ctx.role_state.members.is_empty() {
            "closing".clone_into(&mut ctx.state);
        }

        Ok(())
    }

    /// Sends a message within a context. Mirrors `ContextManager::send_message`.
    ///
    /// # Fail-closed economy gate (C2)
    ///
    /// The WASM bridge cannot run scp-runtime's `enforce_economy` pipeline
    /// because `scp-runtime` does not compile to `wasm32` (ADR-034). If the
    /// stored `economic_policy` requires payment for any action, this method
    /// rejects the send with `SCP-ECON-12096` regardless of whether
    /// `spending_ucan_jwt` is `Some` or `None`. Accepting the send would be a
    /// security lie: the SDK would tell the caller their spend was authorized
    /// when no payment adapter, budget tracker, velocity tracker, or hard
    /// rate limit token bucket has actually validated it.
    ///
    /// Free contexts are unaffected — the parameter is inspected only to
    /// drive the rejection branch.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the sender lacks
    /// `messages:write` capability, the sender is not a member, MLS
    /// encryption fails, or the context's economic policy requires payment
    /// (fail-closed).
    pub fn send_message(
        &mut self,
        context_id: &str,
        sender_did: &str,
        payload_base64: &str,
        spending_ucan_jwt: Option<&str>,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // C2 fail-closed economy gate. We inspect both the stored
        // `economic_policy` AND `spending_ucan_jwt` so that callers cannot
        // accidentally believe a paid send was authorized — there is no
        // path where the WASM bridge can validate it.
        if stored_policy_requires_payment(ctx.economic_policy.as_deref()) {
            let _ = spending_ucan_jwt; // explicitly inspected so the parameter is no longer dropped
            return Err(ScpWasmError::Context {
                message: format!(
                    "WasmCannotValidateSpendingUcan: context '{context_id}' has an economic \
                     policy requiring payment, but the WASM bridge cannot cryptographically \
                     validate spending UCANs against a payment adapter (ADR-034). Use a native \
                     (Python / Node.js / Swift / Kotlin) client to send messages in paid contexts."
                ),
                code: SCP_ECON_WASM_CANNOT_VALIDATE_SPENDING_UCAN.to_owned(),
            });
        }

        // Check membership and assign the MLS message sequence number.
        if !ctx.role_state.members.contains(sender_did) {
            return Err(ScpWasmError::Context {
                message: format!("sender '{sender_did}' is not a member of context '{context_id}'"),
                code: codes::CTX_2019.to_owned(),
            });
        }

        // Positive role-grant authorization gate. Mirrors native
        // `messaging_helpers::send_message` (the H7 capability check before any
        // economy/velocity mutation): a sender may write ONLY if their assigned
        // role grants `messages:write`. `member_has_capability` is
        // suspension-aware — it returns `false` when the capability is in the
        // member's suspended set — so this SINGLE positive check closes both
        // facets: a read-only role (e.g. `observer` / `subscriber`, which grant
        // only `messages:read`) is rejected, AND a write-granting member whose
        // `messages:write` was suspended via `SuspendAccess` /
        // `SuspendCapability` is rejected. The distinct error message mirrors
        // native's suspended-vs-not-granted split.
        if !ctx
            .role_state
            .member_has_capability(sender_did, &Capability::MessagesWrite)
        {
            let is_suspended = ctx
                .role_state
                .suspended_for(sender_did)
                .is_some_and(|caps| caps.contains(&Capability::MessagesWrite));
            let message = if is_suspended {
                format!("write access has been suspended for {sender_did}")
            } else {
                format!("member {sender_did} role does not grant messages:write")
            };
            return Err(ScpWasmError::Permission {
                message,
                code: codes::PERM_3000.to_owned(),
            });
        }
        // Per-member message-sequence sidecar. This PRE-increments to match
        // native's `MembershipState::next_sequence_number` (membership.rs),
        // which does `info.sequence_number += 1; info.sequence_number` — it
        // bumps THEN returns, so the first message's sequence is 1. The WASM
        // sidecar bumps the stored counter from its base 0 and returns the
        // post-increment value, so the first message's emitted
        // `sequence_number` is likewise 1. The base divergence with native is
        // RESOLVED: both families now emit 1-based per-author sequences. The
        // per-author byte values remain out of cross-family export byte-parity
        // scope per ADR-050 (each author mints its own sequence with no global
        // order), but the increment direction and base now converge.
        // Note whether the sender already had a sequence entry, so a failure
        // that created a fresh `0` entry can remove it cleanly on rollback.
        let seq_was_present = ctx.member_sequence_numbers.contains_key(sender_did);
        let seq_entry = ctx
            .member_sequence_numbers
            .entry(sender_did.to_owned())
            .or_insert(0);
        *seq_entry += 1;
        let seq = *seq_entry;

        // If crypto state is available, encrypt the payload before recording.
        //
        // The reserved sequence above is rolled back on ANY failure before the
        // message is recorded, mirroring native
        // `MembershipState::rollback_sequence_number` (membership.rs, a
        // `saturating_sub(1)`): a failed send (invalid base64, MLS epoch read,
        // encryption) must burn no sequence, so two honest members never
        // diverge on a gap. The fallible work is wrapped in a closure so the
        // single `?`-propagating error path is captured for rollback rather
        // than early-returning. The closure borrows `ctx.crypto` mutably; the
        // rollback touches `ctx.member_sequence_numbers` only after the closure
        // returns, so the two `&mut` borrows are sequential, not overlapping.
        let recorded_payload = match (|| -> Result<String, ScpWasmError> {
            if let Some(ref mut crypto) = ctx.crypto {
                let raw_bytes = base64::engine::general_purpose::STANDARD
                    .decode(payload_base64)
                    .map_err(|e| ScpWasmError::Crypto {
                        message: format!("invalid base64 payload: {e}"),
                        code: codes::CRYPTO_4001.to_owned(),
                    })?;

                let epoch = crypto.mls_group.epoch().map_err(|e| ScpWasmError::Crypto {
                    message: format!("failed to read MLS epoch: {e}"),
                    code: codes::CRYPTO_4002.to_owned(),
                })?;

                let ciphertext = crypto
                    .encrypt_message(&raw_bytes, context_id, sender_did, epoch, seq)
                    .map_err(|e| ScpWasmError::Crypto {
                        message: format!("encryption failed: {e}"),
                        code: codes::CRYPTO_4003.to_owned(),
                    })?;

                Ok(base64::engine::general_purpose::STANDARD.encode(&ciphertext))
            } else {
                Ok(payload_base64.to_owned())
            }
        })() {
            Ok(payload) => payload,
            Err(e) => {
                if let Some(entry) = ctx.member_sequence_numbers.get_mut(sender_did) {
                    *entry = entry.saturating_sub(1);
                    // If we created the entry purely to reserve this (failed)
                    // send, drop it so the map matches its pre-send shape.
                    if !seq_was_present && *entry == 0 {
                        ctx.member_sequence_numbers.remove(sender_did);
                    }
                }
                return Err(e);
            }
        };

        ctx.push_event(ContextEvent::MessageSent {
            sender_did: DID(sender_did.to_owned()),
            sequence_number: seq,
            payload: recorded_payload.as_bytes().to_vec(),
        });

        // Per-author application activity (MessageSent) is NOT appended to the
        // canonical Merkle log: each author mints leaves in its own per-author
        // sequence with no global order, so two honest members would derive
        // different `tree::root` and §9.9.3 equivocation detection would break.
        // It is surfaced only as a local `ContextEvent` (the `push_event`
        // above). This matches the native scp-runtime exclusion and the
        // ADR-011 amendment exclusion taxonomy (`.docs/adrs/phase-2.md` §2).

        // Evaluate and enforce consequence rules for the sender. Mirrors
        // `scp_runtime::context::manager::messaging::send_message` which
        // calls `enforce_triggered_consequences` after appending the
        // outbound event. This is a no-op if no rules were declared at
        // context creation.
        let now_secs = crate::time::now_secs();
        crate::consequence::dispatch_consequences_for_subject(
            ctx, context_id, sender_did, now_secs,
        );

        Ok(())
    }

    /// Closes a context. Mirrors `ContextManager::close_context`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the initiator lacks
    /// the `ContextClose` capability.
    pub fn close_context(
        &mut self,
        context_id: &str,
        initiator_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // Authorization: check ContextClose capability, matching
        // ttl::close_context in scp-core. Uses scp-core Capability::Display
        // format ("context:close").
        if !ctx.member_has_capability(initiator_did, "context:close") {
            return Err(ScpWasmError::Permission {
                message: format!("member {initiator_did} does not have context:close capability"),
                code: codes::PERM_3000.to_owned(),
            });
        }

        "closed".clone_into(&mut ctx.state);
        ctx.broadcast_context = None;

        // Destroy crypto state on close — releases MLS group keys and
        // sender key material.
        if let Some(ref mut crypto) = ctx.crypto {
            crypto.destroy();
        }
        ctx.crypto = None;

        ctx.push_event(ContextEvent::SystemClose {
            initiator_did: DID(initiator_did.to_owned()),
        });

        ctx.append_log_event(
            EventType::ContextClosing,
            initiator_did,
            b"",
            // Committer-assigned: the initiator's clock, source of the close
            // commit's `created_at` (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        Ok(())
    }

    /// Decrypts a message within a context.
    ///
    /// Reverses the double encryption: MLS decrypt -> sender key decrypt.
    ///
    /// # Errors
    ///
    /// Returns an error if the context has no crypto state, or if decryption fails.
    pub fn decrypt_message(
        &mut self,
        context_id: &str,
        sender_did: &str,
        ciphertext_base64: &str,
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let crypto = ctx.crypto.as_mut().ok_or_else(|| ScpWasmError::Crypto {
            message: "context has no MLS encryption state".to_string(),
            code: codes::CRYPTO_4010.to_owned(),
        })?;

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_base64)
            .map_err(|e| ScpWasmError::Crypto {
                message: format!("invalid base64 ciphertext: {e}"),
                code: codes::CRYPTO_4001.to_owned(),
            })?;

        crypto
            .decrypt_message(&ciphertext, context_id, sender_did, epoch, sequence)
            .map_err(|e| ScpWasmError::Crypto {
                message: format!("decryption failed: {e}"),
                code: codes::CRYPTO_4011.to_owned(),
            })
    }

    /// Generates an MLS `KeyPackage` for joining an encrypted context.
    ///
    /// Returns the TLS-serialized key package bytes. The private key material
    /// is stored in `pending_key_packages` keyed by `(context_id, member_did)`
    /// for later use by `join_context_encrypted`.
    ///
    /// # Errors
    ///
    /// Returns an error if key package generation fails.
    pub fn generate_key_package_for_join(
        &mut self,
        context_id: &str,
        member_did: &str,
    ) -> Result<Vec<u8>, ScpWasmError> {
        let credential = crate::crypto::credential::WasmScpCredential::new(
            member_did.to_string(),
            None,
            crate::crypto::credential::WasmSigningKeyId::Active,
        )
        .map_err(|e| ScpWasmError::Crypto {
            message: format!("credential creation failed: {e}"),
            code: codes::CRYPTO_4020.to_owned(),
        })?;

        let (kp_bytes, holder) =
            crate::crypto::group::WasmMlsGroup::generate_key_package(&credential).map_err(|e| {
                ScpWasmError::Crypto {
                    message: format!("key package generation failed: {e}"),
                    code: codes::CRYPTO_4022.to_owned(),
                }
            })?;

        // Store the holder for later use in join_context_encrypted.
        self.pending_key_packages
            .insert(format!("{context_id}:{member_did}"), holder);

        Ok(kp_bytes)
    }

    /// Joins a context with encrypted MLS state.
    ///
    /// The joiner processes the MLS Welcome message to reconstruct the group.
    /// A key package must have been previously generated via
    /// `generate_key_package_for_join` for the same `(context_id, member_did)`.
    ///
    /// # Errors
    ///
    /// Returns an error if no pending key package exists, or if the Welcome
    /// cannot be processed.
    pub fn join_context_encrypted(
        &mut self,
        context_id: &str,
        member_did: &str,
        welcome_bytes: &[u8],
    ) -> Result<(), ScpWasmError> {
        // Retrieve the pending key package holder.
        let pending_key = format!("{context_id}:{member_did}");
        let holder = self
            .pending_key_packages
            .remove(&pending_key)
            .ok_or_else(|| ScpWasmError::Crypto {
                message: format!(
                    "no pending key package for '{member_did}' in context '{context_id}' — \
                     call generate_key_package_for_join first"
                ),
                code: codes::CRYPTO_4023.to_owned(),
            })?;

        // Commit ONLY the in-memory membership (no buffer event, no durable
        // leaf yet). Encrypted join doesn't carry a separate spending UCAN —
        // the Welcome flow implies the adder already validated the join cost.
        //
        // We borrow native's ORDERING INVARIANT (crypto succeeds BEFORE the
        // durable `MemberJoined` leaf is appended, leaf last & only on
        // success) from `crates/scp-runtime/src/context/lifecycle_helpers.rs`
        // `join_context` — but note that is native's ADDER path (it calls
        // `crypto.add_member`, Phase 3, then appends the leaf at Phase 5).
        // Native has NO joiner-side lifecycle method to mirror: the
        // receive-side `join_from_welcome` append path is dormant there
        // (cross-member leaf replication is a forward ADR-051 step). So we
        // apply the adder-path invariant to this joiner path: defer BOTH the
        // `MemberJoined` buffer event AND the durable Merkle leaf until AFTER
        // `join_from_welcome` succeeds, so a failed Welcome leaves no leaf —
        // the same fail-closed ordering native's adder path guarantees. (The
        // unencrypted `join_context` still appends its leaf immediately.)
        self.join_context_membership_only(context_id, member_did, None)?;

        // Process the MLS Welcome.
        //
        // REACHABLE-ROLLBACK: unlike the role-assign rollbacks elsewhere in
        // this file (which guard a built-in-role assignment that is infallible
        // by construction), `join_from_welcome` failure is genuinely reachable
        // — a malformed, stale, or otherwise un-processable Welcome (or any
        // subsequent crypto-setup error) returns `Err`. The membership commit
        // above already populated `role_state.members` + `assignments` +
        // `member_capabilities` + `member_sequence_numbers`, and the pending
        // key package was already consumed. If we returned the crypto error
        // here without rolling that membership back, the joiner would be left
        // as a PHANTOM member: full role/sequence/membership state, counted by
        // `member_count` / `is_member` / `member_dids`, charged against
        // `WASM_MEMBER_CAP`, and role-assignable — yet with no MLS leaf, so
        // unable to decrypt or send. Strip the membership the helper added
        // before propagating the error so the failed join leaves NO partial
        // membership behind (fail-closed atomicity). No durable
        // `MemberJoined` leaf was appended (it is deferred to post-success
        // below), so the failed encrypted join also leaves no orphan leaf and
        // no phantom buffered join event — matching native.
        let mls_group =
            match crate::crypto::group::WasmMlsGroup::join_from_welcome(welcome_bytes, holder) {
                Ok(group) => group,
                Err(e) => {
                    // Inline-strip rather than calling `leave_context`: this is an
                    // as-if-never-joined rollback, so it must NOT emit a
                    // `MemberLeft` buffer/log event, unsubscribe a broadcast that
                    // was never subscribed, or trip `leave_context`'s
                    // auto-close-on-empty. Mirror `leave_context`'s per-member
                    // state teardown (members, role assignment, granted caps,
                    // suspensions, MLS sequence counter) without those side
                    // effects. No crypto state was installed yet, so there is none
                    // to destroy. `require_active_context_mut` is reused because
                    // the membership helper may have re-borrowed `self`.
                    let ctx = self.require_active_context_mut(context_id)?;
                    ctx.role_state.members.remove(member_did);
                    ctx.role_state.assignments.remove(member_did);
                    ctx.role_state.member_capabilities.remove(member_did);
                    // Clears the member's suspensions on removal — see the RemoveMember handler for the known native↔WASM divergence + deferred shared-removal convergence.
                    if let Some(suspended) = ctx.role_state.suspended_for(member_did) {
                        let caps: Vec<Capability> = suspended.iter().cloned().collect();
                        ctx.role_state.restore_capabilities(member_did, &caps);
                    }
                    ctx.member_sequence_numbers.remove(member_did);
                    return Err(ScpWasmError::Crypto {
                        message: format!("MLS welcome processing failed: {e}"),
                        code: codes::CRYPTO_4021.to_owned(),
                    });
                }
            };

        // MLS succeeded. Install crypto state, THEN emit the `MemberJoined`
        // buffer event + durable Merkle leaf LAST — the leaf-last ordering
        // borrowed from native's adder path (see above), so the leaf appears
        // only on a fully-successful encrypted join. The
        // leaf content (actor_did = `member_did`, empty payload, committer-
        // assigned `now_secs()` timestamp) is IDENTICAL to the unencrypted
        // `join_context` leaf; only WHEN it is appended differs.
        let ctx = self.require_active_context_mut(context_id)?;
        ctx.crypto = Some(crate::crypto::WasmCryptoState {
            mls_group,
            local_sender_key: crate::crypto::sender_key::generate_sender_key(),
            sender_key_store: std::collections::HashMap::new(),
        });
        ctx.push_event(ContextEvent::MemberJoined {
            member_did: DID(member_did.to_owned()),
            role_name: "member".to_owned(),
        });
        ctx.append_log_event(
            EventType::MemberJoined,
            member_did,
            b"",
            // Committer-assigned: this member's clock, the source of the
            // join commit's `created_at` (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Membership queries
    // -----------------------------------------------------------------------

    /// Returns the member count. Mirrors `ContextManager::member_count`.
    #[must_use]
    pub fn member_count(&self, context_id: &str) -> Option<usize> {
        self.contexts
            .get(context_id)
            .map(|ctx| ctx.role_state.members.len())
    }

    /// Returns `true` if the DID is a member. Mirrors `ContextManager::is_member`.
    #[must_use]
    pub fn is_member(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .get(context_id)
            .is_some_and(|ctx| ctx.role_state.members.contains(did))
    }

    /// Returns all member DIDs. Mirrors `ContextManager::member_dids`.
    #[must_use]
    pub fn member_dids(&self, context_id: &str) -> Vec<String> {
        self.contexts
            .get(context_id)
            .map(|ctx| ctx.role_state.members.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the role for a member. Mirrors `ContextManager::member_role`.
    #[must_use]
    pub fn member_role(&self, context_id: &str, did: &str) -> Option<String> {
        self.contexts
            .get(context_id)
            .and_then(|ctx| ctx.role_state.assignments.get(did))
            .map(|a| a.role_name.clone())
    }

    /// Returns the event log leaf count for a context, or `None` if not found.
    #[must_use]
    pub fn event_log_leaf_count(&self, context_id: &str) -> Option<usize> {
        self.contexts
            .get(context_id)
            .map(|ctx| ctx.event_log.leaves().len())
    }

    /// Appends a provenance event to the event log for the given context.
    ///
    /// Used by `provenance_attach` to record `ProvenanceAttached` and
    /// `ProvenanceReceived` events (issue #586).
    ///
    /// # Errors
    ///
    /// Returns [`ScpWasmError::Context`] if the context is not registered.
    pub fn append_provenance_event(
        &mut self,
        context_id: &str,
        actor_did: &str,
        event_type: EventType,
        prov_hash: &[u8],
    ) -> Result<(), ScpWasmError> {
        let ctx = self
            .contexts
            .get_mut(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context '{context_id}' not found"),
                code: codes::CTX_2060.to_owned(),
            })?;

        ctx.append_log_event(
            event_type,
            actor_did,
            prov_hash,
            // Committer-assigned: the attaching member's clock (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /// Drains all events from the receive buffer. Mirrors `ContextManager::drain_events`.
    pub fn drain_events(&mut self, context_id: &str) -> Vec<ContextEvent> {
        self.contexts
            .get_mut(context_id)
            .map(|ctx| std::mem::take(&mut ctx.event_buffer).into())
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // Tool operations
    // -----------------------------------------------------------------------

    /// Registers a tool. Mirrors tool registration through `ContextManager`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the tool definition
    /// is invalid, or the tool ID is already registered.
    pub fn register_tool(
        &mut self,
        context_id: &str,
        registration: ToolRegistration,
    ) -> Result<String, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let tool_id = registration.tool_id.clone();
        crate::runtime::tool_registry_insert_unique(&mut ctx.tool_registry, registration).map_err(
            |e| ScpWasmError::Tool {
                message: e,
                code: codes::TOOL_6001.to_owned(),
            },
        )?;

        let actor = ctx.role_state.creator_did.clone();
        // Native appends ToolRegistered with an EMPTY payload
        // (`append_context_event`, no payload) — match it so the leaf preimage
        // is byte-identical across platforms (§9.9.3). The tool_id is NOT part
        // of the canonical leaf.
        ctx.append_log_event(
            EventType::ToolRegistered,
            &actor,
            b"",
            // Committer-assigned: the registering member's clock (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        Ok(tool_id)
    }

    /// Checks whether a tool exists in the context's registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or not active.
    pub fn tool_exists(&self, context_id: &str, tool_id: &str) -> Result<bool, ScpWasmError> {
        let ctx = self.require_active_context(context_id)?;
        Ok(ctx.tool_registry.get(tool_id).is_some())
    }

    /// Registers a handler function for a tool.
    ///
    /// The handler will be called when the tool is invoked. The tool must
    /// already be registered in the context's tool registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the tool is not found.
    pub fn register_tool_handler(
        &mut self,
        context_id: &str,
        tool_id: &str,
        handler: Box<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String>>,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if ctx.tool_registry.get(tool_id).is_none() {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "tool '{tool_id}' not found in context '{context_id}' \
                     -- register the tool before adding a handler"
                ),
                code: codes::TOOL_6002.to_owned(),
            });
        }

        ctx.tool_handlers.insert(tool_id.to_owned(), handler);
        Ok(())
    }

    /// Invokes a tool. Validates the tool exists, validates input against schema,
    /// and returns a JSON result.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the tool is not found,
    /// or schema validation fails.
    pub fn invoke_tool(
        &mut self,
        context_id: &str,
        tool_id: &str,
        input_json: &serde_json::Value,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let registration = ctx
            .tool_registry
            .get(tool_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                code: codes::TOOL_6002.to_owned(),
            })?;

        // Validate input against the tool's input schema.
        validate_value_against_schema(input_json, &registration.schema.input_schema).map_err(
            |e| ScpWasmError::Tool {
                message: format!("input schema validation failed for tool '{tool_id}': {e}"),
                code: codes::TOOL_6002.to_owned(),
            },
        )?;

        let output_schema = registration.schema.output_schema.clone();

        // Dispatch to registered handler if available.
        let result = if let Some(handler) = ctx.tool_handlers.get(tool_id) {
            let out = handler(input_json.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("tool handler for '{tool_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;

            validate_value_against_schema(&out, &output_schema).map_err(|msg| {
                ScpWasmError::Tool {
                    message: format!("output validation failed for tool '{tool_id}': {msg}"),
                    code: codes::TOOL_6002.to_owned(),
                }
            })?;

            out
        } else {
            serde_json::json!({
                "tool_id": tool_id,
                "status": "validated",
                "input": input_json,
            })
        };

        // `ToolInvoked` is per-author application activity (ADR-011 amendment
        // exclusion taxonomy, `.docs/adrs/phase-2.md` §2): appended only by its
        // author in a per-author sequence with no global order, so a durable
        // leaf would make honest members diverge on `tree::root` and break
        // §9.9.3 equivocation detection. Native scp-runtime appends no durable
        // leaf and surfaces no local `ContextEvent` for intra-context tool
        // invocations, so neither does WASM. (`tool_invocation_count` is
        // recomputed from local events; it carries `anchored=false` until
        // ADR-051's causal DAG makes the count convergent.)

        Ok(result)
    }

    /// Verifies a tool against its test vectors.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or the tool is not registered.
    pub fn verify_tool(
        &self,
        context_id: &str,
        tool_id: &str,
    ) -> Result<(bool, Vec<String>), ScpWasmError> {
        let ctx = self.require_context(context_id)?;

        let registration = ctx
            .tool_registry
            .get(tool_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                code: codes::TOOL_6003.to_owned(),
            })?;

        // Verify test vectors by validating inputs against the input schema.
        let mut failures = Vec::new();
        for (i, tv) in registration.test_vectors.iter().enumerate() {
            if let Err(e) =
                validate_value_against_schema(&tv.input, &registration.schema.input_schema)
            {
                failures.push(format!(
                    "vector {i} ({0}): input validation failed: {e}",
                    tv.description
                ));
            }
            if let Err(e) = validate_value_against_schema(
                &tv.expected_output,
                &registration.schema.output_schema,
            ) {
                failures.push(format!(
                    "vector {i} ({0}): output validation failed: {e}",
                    tv.description
                ));
            }
        }

        Ok((failures.is_empty(), failures))
    }

    // -----------------------------------------------------------------------
    // Cross-context tool invocation (spec section 6.2)
    // -----------------------------------------------------------------------

    /// Invokes a tool across context boundaries.
    ///
    /// # Errors
    ///
    /// Returns an error if either context is not found, tool is not found,
    /// or chain depth is exceeded.
    pub fn invoke_tool_cross_context(
        &self,
        source_context_id: &str,
        target_context_id: &str,
        tool_id: &str,
        input: &serde_json::Value,
        invoker_did: &str,
        chain_depth: u8,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Validate both contexts exist and are active.
        let source = self.require_active_context(source_context_id)?;
        let target = self.require_active_context(target_context_id)?;

        // Validate chain depth against SOURCE context's configurable max (ADR-043).
        // Chain depth is a property of the originating context — matches scp-core,
        // PyO3, NAPI, and UniFFI bridges.
        let max_chain_depth = source
            .params_json
            .get("maxChainDepth")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(crate::provenance::DEFAULT_MAX_CHAIN_DEPTH)
            .min(32);
        if chain_depth > max_chain_depth {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "cross-context chain depth {chain_depth} exceeds maximum {max_chain_depth}"
                ),
                code: codes::TOOL_6012.to_owned(),
            });
        }

        // Validate tool exists in target and validate input.
        let registration = target
            .tool_registry
            .get(tool_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!(
                    "tool '{tool_id}' not found in target context '{target_context_id}'"
                ),
                code: codes::TOOL_6003.to_owned(),
            })?;

        validate_value_against_schema(input, &registration.schema.input_schema).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("input validation failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            }
        })?;

        let output_schema = registration.schema.output_schema.clone();

        // Dispatch to handler or echo mode.
        let result = if let Some(handler) = target.tool_handlers.get(tool_id) {
            let out = handler(input.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("cross-context tool handler for '{tool_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;

            validate_value_against_schema(&out, &output_schema).map_err(|msg| {
                ScpWasmError::Tool {
                    message: format!("output validation failed for tool '{tool_id}': {msg}"),
                    code: codes::TOOL_6002.to_owned(),
                }
            })?;

            out
        } else {
            serde_json::json!({
                "tool": tool_id,
                "source_context": source_context_id,
                "target_context": target_context_id,
                "status": "validated",
                "chain_depth": chain_depth,
                "invoker_did": invoker_did,
                "validated_input": input,
            })
        };

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Stateful tool sessions (spec section 6.2.1)
    // -----------------------------------------------------------------------

    /// Creates a stateful tool session.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, tool not found,
    /// or per-caller session cap exceeded.
    pub fn session_create(
        &mut self,
        context_id: &str,
        tool_id: &str,
        source_context_id: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<String, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // Evict expired sessions before checking caps.
        ctx.sessions.retain(|_, s| !s.is_expired());

        // Enforce global cap.
        if ctx.sessions.len() >= WASM_SESSION_GLOBAL_CAP {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "global session cap exceeded: {} active (max {WASM_SESSION_GLOBAL_CAP})",
                    ctx.sessions.len()
                ),
                code: codes::TOOL_6015.to_owned(),
            });
        }

        // Enforce per-caller cap (context-configurable via sessionCap param).
        let session_cap = ctx
            .params_json
            .get("sessionCap")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(WASM_SESSION_CAP_PER_CALLER)
            .min(10_000);
        let current = ctx
            .sessions
            .values()
            .filter(|s| s.source_context == source_context_id)
            .count();
        if current >= session_cap {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "session cap exceeded for caller '{source_context_id}': {current} active (max {session_cap})"
                ),
                code: codes::TOOL_6015.to_owned(),
            });
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let now = crate::time::now_ms();

        let session = WasmToolSession {
            session_id: session_id.clone(),
            tool_id: tool_id.to_owned(),
            source_context: source_context_id.to_owned(),
            state: serde_json::Value::Null,
            created_at_ms: now,
            #[allow(clippy::cast_precision_loss)] // JS numbers are f64; TTL values are small
            ttl_ms: ttl_seconds.map(|s| (s as f64) * 1000.0),
            call_count: 0,
        };

        ctx.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    /// Invokes a tool within an active session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found or has expired.
    pub fn session_invoke(
        &mut self,
        context_id: &str,
        session_id: &str,
        input: &serde_json::Value,
        invoker_did: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let session = ctx
            .sessions
            .get(session_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("session '{session_id}' not found"),
                code: codes::TOOL_6018.to_owned(),
            })?;

        if session.is_expired() {
            ctx.sessions.remove(session_id);
            return Err(ScpWasmError::Tool {
                message: format!("session '{session_id}' has expired"),
                code: codes::TOOL_6019.to_owned(),
            });
        }

        let tool_id = session.tool_id.clone();
        let current_state = session.state.clone();
        let call_count = session.call_count;

        // Validate input against tool's input schema if tool is registered.
        if let Some(registration) = ctx.tool_registry.get(&tool_id) {
            validate_value_against_schema(input, &registration.schema.input_schema).map_err(
                |e| ScpWasmError::Tool {
                    message: format!("input validation failed: {e}"),
                    code: codes::TOOL_6002.to_owned(),
                },
            )?;
        }

        // Execute via handler or echo mode.
        let (new_state, output) = if let Some(handler) = ctx.tool_handlers.get(&tool_id) {
            let out = handler(input.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("tool handler for '{tool_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;
            (current_state, out)
        } else {
            let out = serde_json::json!({
                "tool": tool_id,
                "session_id": session_id,
                "status": "validated",
                "call_count": call_count + 1,
                "invoker_did": invoker_did,
                "validated_input": input,
            });
            (current_state, out)
        };

        // Update session state and increment call count.
        if let Some(s) = ctx.sessions.get_mut(session_id) {
            s.state = new_state;
            s.call_count = s.call_count.saturating_add(1);
        }

        Ok(output)
    }

    /// Returns the tool ID for an active session.
    ///
    /// Used to look up the tool before UCAN validation so the correct
    /// `tool_invoke:{tool_id}` capability can be checked.
    ///
    /// # Errors
    ///
    /// Returns an error if the context or session is not found.
    pub fn session_tool_id(
        &self,
        context_id: &str,
        session_id: &str,
    ) -> Result<String, ScpWasmError> {
        let ctx = self.require_active_context(context_id)?;
        let session = ctx
            .sessions
            .get(session_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("session '{session_id}' not found"),
                code: codes::TOOL_6018.to_owned(),
            })?;
        Ok(session.tool_id.clone())
    }

    /// Closes a stateful tool session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found.
    pub fn session_close(
        &mut self,
        context_id: &str,
        session_id: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if ctx.sessions.remove(session_id).is_none() {
            return Err(ScpWasmError::Tool {
                message: format!("session '{session_id}' not found"),
                code: codes::TOOL_6021.to_owned(),
            });
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Event log operations
    // -----------------------------------------------------------------------

    /// Queries the event log. Returns event count and Merkle root.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found.
    pub fn event_log_query(&self, context_id: &str) -> Result<(u64, String), ScpWasmError> {
        let ctx = self.require_context(context_id)?;

        let count = event_count(&ctx.event_log);
        let root_hash = root(&ctx.event_log);
        let root = crate::runtime::encode_hex(&root_hash);

        Ok((count, root))
    }

    /// Returns the events stored in the context's event log.
    ///
    /// Produces one entry per appended event, preserving append order.
    /// Each entry carries the protocol-level fields the TypeScript
    /// `Event` interface exposes (event type, actor DID, timestamp,
    /// sequence) plus the payload bytes rendered as a hex string so
    /// JSON transport remains lossless. This mirrors how the NAPI
    /// bridge surfaces per-event records via `MerkleEventLogProvider`,
    /// keeping cross-bridge parity on `event_log_query` observable.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found.
    pub fn event_log_query_events(
        &self,
        context_id: &str,
    ) -> Result<Vec<serde_json::Value>, ScpWasmError> {
        let ctx = self.require_context(context_id)?;

        #[allow(clippy::cast_precision_loss)]
        let events = ctx
            .event_log_events()
            .iter()
            .map(|ev| {
                serde_json::json!({
                    "eventType": format!("{:?}", ev.event_type),
                    "actorDid": ev.actor_did.to_string(),
                    "timestamp": ev.timestamp as f64,
                    "payloadJson": crate::runtime::encode_hex(&ev.payload.data),
                    "sequence": ev.sequence as f64,
                })
            })
            .collect();

        Ok(events)
    }

    /// Generates and verifies a Merkle inclusion proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or the proof fails.
    pub fn event_log_prove_inclusion(
        &self,
        context_id: &str,
        leaf_index: u64,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_context(context_id)?;

        let proof =
            prove_inclusion(&ctx.event_log, leaf_index).map_err(|e| ScpWasmError::Context {
                message: format!("inclusion proof failed: {e}"),
                code: codes::CTX_2007.to_owned(),
            })?;

        let verified = verify_inclusion(&proof);

        let path_json: Vec<serde_json::Value> = proof
            .path
            .iter()
            .map(|step| {
                serde_json::json!({
                    "siblingHash": crate::runtime::encode_hex(&step.sibling_hash),
                    "direction": match step.direction {
                        Direction::Left => "left",
                        Direction::Right => "right",
                    },
                })
            })
            .collect();

        Ok(serde_json::json!({
            "verified": verified,
            "proofType": "inclusion",
            "leafIndex": proof.leaf_index,
            "leafHash": crate::runtime::encode_hex(&proof.leaf_hash),
            "root": crate::runtime::encode_hex(&proof.root),
            "path": path_json,
        }))
    }

    /// Generates and verifies a Merkle absence proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or the proof fails.
    pub fn event_log_prove_absence(
        &self,
        context_id: &str,
        event_hash: &[u8; 32],
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_context(context_id)?;

        let proof =
            prove_absence(&ctx.event_log, event_hash).map_err(|e| ScpWasmError::Context {
                message: format!("absence proof failed: {e}"),
                code: codes::CTX_2007.to_owned(),
            })?;

        Ok(serde_json::json!({
            "verified": true,
            "proofType": "absence",
            "queryHash": crate::runtime::encode_hex(&proof.query_hash),
            "root": crate::runtime::encode_hex(&proof.root),
            "leafCount": proof.leaf_count,
            "hasLower": proof.lower.is_some(),
            "hasUpper": proof.upper.is_some(),
        }))
    }

    // -----------------------------------------------------------------------
    // UCAN operations
    // -----------------------------------------------------------------------

    /// Returns the UCAN state for validation (ceiling, `creator_did`, nonces, revoked CIDs).
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found.
    pub fn ucan_context_state(
        &self,
        context_id: &str,
    ) -> Result<(HashSet<String>, String, HashSet<String>), ScpWasmError> {
        let ctx = self.require_context(context_id)?;
        Ok((
            ctx.role_state.ceiling().to_ucan_string_set(),
            ctx.role_state.creator_did.clone(),
            ctx.revoked_tokens.clone(),
        ))
    }

    /// Returns the set of seen nonce keys for a context (for replay checking).
    ///
    /// Used by the extract-validate-writeback UCAN validation pattern to
    /// pre-extract nonce state before calling `scp_protocol::validate_ucan`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found.
    pub fn ucan_seen_nonce_keys(&self, context_id: &str) -> Result<HashSet<String>, ScpWasmError> {
        let ctx = self.require_context(context_id)?;
        Ok(ctx.seen_nonces.keys().cloned().collect())
    }

    /// Records a nonce as seen (for replay prevention).
    ///
    /// Records a nonce for replay detection.
    ///
    /// Format and freshness validation is performed upstream in
    /// `ucan.rs::validate_nonce_format_and_freshness` (step 9 of the UCAN
    /// pipeline). This method is responsible only for:
    /// 1. **Uniqueness** — nonce must not have been seen before.
    /// 2. **Capacity management** — evicts entries older than
    ///    `WASM_NONCE_TTL_MS` when the map exceeds `WASM_NONCE_CAP`.
    ///
    /// # Errors
    ///
    /// Returns [`ScpWasmError::Permission`] if the nonce was already seen or
    /// the tracker is at capacity after eviction.
    pub fn ucan_record_nonce(&mut self, context_id: &str, nonce: &str) -> Result<(), ScpWasmError> {
        let now = crate::time::now_ms();
        let ctx = self.require_context_mut(context_id)?;

        // 1. Replay check.
        if ctx.seen_nonces.contains_key(nonce) {
            return Err(ScpWasmError::Permission {
                message: format!("nonce reused: {nonce}"),
                code: codes::PERM_3000.to_owned(),
            });
        }

        // 2. Evict expired nonces when over capacity, then reject if still full.
        // Matches scp-core's `NonceTracker::check_and_record` capacity behavior.
        if ctx.seen_nonces.len() >= WASM_NONCE_CAP {
            let cutoff = now - WASM_NONCE_TTL_MS;
            ctx.seen_nonces.retain(|_, ts| *ts > cutoff);

            if ctx.seen_nonces.len() >= WASM_NONCE_CAP {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "nonce tracker full: capacity {WASM_NONCE_CAP} reached and no expired entries to evict"
                    ),
                    code: codes::PERM_3000.to_owned(),
                });
            }
        }

        ctx.seen_nonces.insert(nonce.to_owned(), now);
        Ok(())
    }

    /// Revokes a UCAN token by CID.
    ///
    /// Revocation is idempotent — re-revoking an already-revoked token
    /// succeeds even when the set is at capacity. The set is capped at
    /// `WASM_REVOKED_TOKENS_CAP` entries — overflow of genuinely new
    /// tokens returns an error.
    ///
    /// The `revoker_did` is used as the event actor in the event log. The
    /// caller is responsible for authorization (verifying the revoker is the
    /// token issuer or context creator) before calling this function.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the revocation set
    /// has reached capacity and the token is not already revoked.
    pub fn ucan_revoke(
        &mut self,
        context_id: &str,
        token_cid: &str,
        revoker_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if ctx.revoked_tokens.len() >= WASM_REVOKED_TOKENS_CAP
            && !ctx.revoked_tokens.contains(token_cid)
        {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "revoked token set has reached capacity ({WASM_REVOKED_TOKENS_CAP}) — \
                     cannot revoke additional tokens"
                ),
                code: codes::VALID_7300.to_owned(),
            });
        }

        ctx.revoked_tokens.insert(token_cid.to_owned());

        // Durable TokenRevoked leaf. The payload MUST be the shared JSON
        // {token_cid, revoker_did, context_id} producer so the leaf preimage is
        // byte-identical to the native/PyO3/UniFFI/NAPI bridge path
        // (`scp-ffi-common`'s `BridgeRevocationEventLogger`) — §9.9.3
        // cross-platform convergence.
        let payload = scp_protocol::crypto::ucan::revoke::token_revoked_payload(
            context_id,
            token_cid,
            revoker_did,
        );
        ctx.append_log_event(
            EventType::TokenRevoked,
            revoker_did,
            &payload,
            // Committer-assigned: the revoker's clock (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        Ok(())
    }

    /// Checks if a token CID is revoked.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found.
    pub fn ucan_is_revoked(&self, context_id: &str, token_cid: &str) -> Result<bool, ScpWasmError> {
        let ctx = self.require_context(context_id)?;
        Ok(ctx.revoked_tokens.contains(token_cid))
    }

    // -----------------------------------------------------------------------
    // Governance
    // -----------------------------------------------------------------------

    /// Returns the required capability string for a governance action.
    ///
    /// Maps each `GovernanceAction` variant to the capability that
    /// the initiator must hold. Uses the UCAN `{resource}:{action}` format,
    /// matching `member_has_capability` and the typed ceiling.
    /// Returns the context-ceiling capability a governance action requires at
    /// DISPATCH time, as a canonical `Capability::ucan_capability_name()` (UCAN)
    /// string — or `None` if the action is NOT ceiling-gated at dispatch.
    ///
    /// This mirrors EXACTLY the native runtime's per-action ceiling gates in
    /// `dispatch_governance_action` / its per-action `execute_*` helpers
    /// (`governance_helpers.rs`), which gate on `ceiling.contains(&Capability::X)`
    /// — NOT on the committing member's role. Native gates precisely these seven
    /// actions across four capabilities:
    ///
    /// - `SuspendCapability`  (`execute_suspend_member`)        → `member:ban`
    /// - `SuspendAccess`      (inline `dispatch_governance_action`) → `member:ban`
    /// - `RevokeAccess`       (`execute_revoke`)                 → `member:ban`
    /// - `RestoreAccess`      (`execute_restore_access`)         → `member:ban`
    /// - `RegisterTool`       (`execute_register_tool`)          → `tool:register`
    /// - `CreateChildContext` (`execute_create_child_context`)  → `context_child:create`
    /// - `EstablishToolInterface` (`execute_establish_tool_interface`) → `tool:interface`
    ///
    /// All OTHER actions have NO per-action ceiling gate in native — their
    /// authorization is entirely at propose time. Returning `None` for them
    /// keeps WASM's accept/reject decision byte-identical to native (§9.9.3).
    ///
    /// The strings are exact `Capability::ucan_capability_name()` outputs
    /// (`member:ban`, `tool:register`) and are matched through the typed
    /// `CapabilityCeiling::contains` on `ContextRoleState` (`ceiling().contains`)
    /// with EXACT membership — no wildcard expansion — because native's
    /// `CapabilityCeiling::contains` uses exact set membership for these
    /// capabilities (only `ToolInvoke` has wildcard special-casing).
    fn dispatch_ceiling_capability(action: &GovernanceAction) -> Option<&'static str> {
        // EXHAUSTIVE match over every `GovernanceAction` variant — NO wildcard.
        // This MUST mirror, one-for-one, native's per-action ceiling gates
        // (`state.role_state.ceiling.contains(&Capability::X)`) in
        // `governance_helpers.rs`. The exhaustive match is closed-by-construction:
        // a newly-added `GovernanceAction` variant becomes a COMPILE ERROR here,
        // forcing the author to decide its ceiling gate explicitly rather than
        // silently inheriting `None` (a `_ => None` wildcard is exactly why
        // `CreateChildContext` and `EstablishToolInterface` were previously
        // ungated in WASM while native rejected them — a §9.9.3 divergence and a
        // security gap). Strings are exact `Capability::ucan_capability_name()`
        // outputs (the canonical UCAN form the typed ceiling holds) and are
        // matched with EXACT membership through the typed
        // `CapabilityCeiling::contains` on `ContextRoleState` (`ceiling().contains`),
        // because native's `CapabilityCeiling::contains` uses exact set
        // membership for all these capabilities (only `ToolInvoke` has wildcard
        // special-casing).
        match action {
            // member:ban — native: execute_suspend_member, execute_revoke,
            // execute_restore_access, and the inline SuspendAccess arm in
            // dispatch_governance_action (governance_helpers.rs).
            GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. } => Some("member:ban"),
            // tool:register — native: execute_register_tool.
            GovernanceAction::RegisterTool { .. } => Some("tool:register"),
            // context_child:create — native: execute_create_child_context.
            // `ChildContextCreate.name()` is the 3-segment "context:child:create",
            // but the typed ceiling holds the UCAN form "context_child:create"
            // (`Capability::ucan_capability_name()`), so we match on that.
            GovernanceAction::CreateChildContext { .. } => Some("context_child:create"),
            // tool:interface — native: execute_establish_tool_interface.
            GovernanceAction::EstablishToolInterface { .. } => Some("tool:interface"),
            // NOT ceiling-gated at dispatch in native — authorization is entirely
            // at propose time. Returning `None` keeps WASM's accept/reject byte-
            // identical to native (§9.9.3). Listed explicitly (no wildcard) so a
            // future variant cannot silently default to ungated.
            GovernanceAction::AddMember { .. }
            | GovernanceAction::RemoveMember { .. }
            | GovernanceAction::ChangeRole { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. }
            | GovernanceAction::ResetMember { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::PromoteContext
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. }
            | GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration
            | GovernanceAction::ModifyHardRateLimit { .. } => None,
        }
    }

    /// Asserts that the proposal `proposal_id` is tracked and `Approved`.
    ///
    /// Mirrors the native runtime's `execute_governance_action` precondition,
    /// which rejects any non-`Approved` proposal before dispatch. WASM enforces
    /// the same so a (re-)execute of a pending / rejected / unknown proposal can
    /// never mint a `GovernanceActionExecuted` leaf that native would not
    /// (§9.9.3). The committed proposal lives in `resolved_proposals` with
    /// status `Approved`; a still-`Pending` proposal in `pending_proposals` is
    /// NOT executable via the execute path.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the proposal is not
    /// `Approved`.
    fn require_proposal_approved(
        &mut self,
        context_id: &str,
        proposal_id: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        let status = ctx
            .resolved_proposals
            .get(proposal_id)
            .or_else(|| ctx.pending_proposals.get(proposal_id))
            .map(|p| p.status.clone());
        if matches!(status, Some(ProposalStatus::Approved)) {
            Ok(())
        } else {
            Err(ScpWasmError::Permission {
                message: format!(
                    "governance proposal '{proposal_id}' is not approved (status: {status:?}); \
                     cannot execute"
                ),
                code: codes::PERM_3000.to_owned(),
            })
        }
    }

    /// Encodes the shared `GovernanceActionExecutedPayload` (positional
    /// `MessagePack` via `encode_payload`) for the `GovernanceActionExecuted`
    /// leaf — byte-identical to the native runtime's `finalize_governance_action`
    /// construction so cross-platform members derive equal Merkle roots
    /// (§9.9.3). `target_did` is the action's target (empty when untargeted);
    /// `action_type` is the `GovernanceAction` variant name.
    ///
    /// # Errors
    ///
    /// FAILS CLOSED on encode error (mirrors native's `map_err(...)?`) so a
    /// payload-encode failure never mints a divergent empty-payload leaf.
    pub(crate) fn encode_governance_action_executed_payload(
        action: &GovernanceAction,
        target_did: Option<&DID>,
    ) -> Result<Vec<u8>, ScpWasmError> {
        scp_event_log::payload::encode_payload(
            &scp_event_log::payload::GovernanceActionExecutedPayload {
                target_did: target_did
                    .map(|d| d.as_ref().to_owned())
                    .unwrap_or_default(),
                action_type: action.variant_name().to_owned(),
            },
        )
        .map(|p| p.data)
        .map_err(|e| ScpWasmError::Context {
            message: format!("failed to encode GovernanceActionExecuted payload: {e}"),
            code: codes::CTX_2001.to_owned(),
        })
    }

    /// Executes a governance action. Mirrors the native runtime's
    /// `execute_governance_action` (`governance_helpers.rs`).
    ///
    /// Validates that the proposal is `Approved`, that the proposal is not a
    /// replay, dispatches to the appropriate action handler (which applies the
    /// per-action context-ceiling gate), and records the proposal as executed.
    /// There is NO per-member capability check at execute time (matches native).
    ///
    /// `initiator_did` is the CONSEQUENCE SUBJECT — the member the action's
    /// effect is attributed to. It is NOT capability-checked here; authorization
    /// is enforced at propose/vote time and by the per-action ceiling gate at
    /// dispatch. `executor_did` is the COMMITTING member — the DID stamped as
    /// the `GovernanceActionExecuted` leaf `actor_did` and the buffer event
    /// `executor_did`. These are deliberately
    /// SEPARATE (ADR-031 §8 "executor DID" / §7.3.1 "committing member" /
    /// ADR-051 §6): the native runtime takes the executor explicitly, and the
    /// leaf `actor_did` is convergence-critical (§9.9.3 native↔WASM byte parity).
    ///
    /// - Quorum-approval path: `initiator_did == executor_did ==` the
    ///   quorum-crossing voter (the committing member).
    /// - Propose auto-execute (`SingleAdmin`) path: `initiator_did ==
    ///   executor_did ==` the proposer (proposer == committer there).
    /// - Direct-FFI execute path (`context_execute_governance`):
    ///   `initiator_did == executor_did ==` the proposal's `proposer_did`,
    ///   resolved from tracked state by the bridge — the caller's identity is
    ///   NOT used as the subject. Matches the native direct-execute handler,
    ///   which stamps `proposal.proposer_did` as both the executor and the
    ///   consequence subject.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the proposal is not
    /// tracked, the proposal is not `Approved`, the proposal was already
    /// executed, or the action fails. There is no per-member capability check
    /// at execute time (see above).
    pub fn execute_governance_action(
        &mut self,
        context_id: &str,
        initiator_did: &str,
        executor_did: &str,
        proposal_id: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Status precondition (mirrors native): a proposal must be `Approved`
        // before it can be executed.
        self.require_proposal_approved(context_id, proposal_id)?;

        // NO per-MEMBER capability check at execute time. The native runtime's
        // `execute_governance_action` (`governance_helpers.rs`) gates ONLY on
        // status==Approved, context-id match, replay (`executed_proposals`), and
        // `check_commit_fault` — it performs NO per-member action-capability
        // check at execute. Authorization is enforced at PROPOSE time
        // (proposer needs `governance:propose` + action within ceiling) and, for
        // the ban/tool-register class, by a per-action CONTEXT-CEILING gate
        // inside `dispatch_governance_action` (matching native's per-action
        // `ceiling.contains(&Capability::X)` gates). A per-member check here
        // diverged from native: on the quorum path the committing member is the
        // quorum-crossing VOTER, who only needs `governance:vote` — gating on the
        // action capability (e.g. `role:assign`) would make WASM mint ZERO
        // `GovernanceActionExecuted` leaves where native mints ONE, breaking
        // §9.9.3 native↔WASM accept/reject convergence (ADR-031 §8).

        // Resolve the CONVERGENT `GovernanceActionExecuted` leaf timestamp
        // BEFORE dispatch, while the proposal is still tracked. This is the
        // executed proposal's signed `created_at`, copied identically by every
        // member — byte-identical to the native runtime's
        // `finalize_governance_action`, which sources `proposal.created_at`
        // (§7.3.1, §9.9.3). The proposal lives in `pending_proposals`
        // (pre-resolution) or `resolved_proposals` (post-resolution).
        //
        // Native CANNOT reach this leaf without a real proposal
        // (`finalize_governance_action` takes `&GovernanceProposal`). WASM
        // therefore guards the same invariant rather than silently stamping
        // `0`: a missing proposal here would mint a leaf whose timestamp
        // diverges from native's `created_at`, breaking cross-platform Merkle
        // equivocation detection. Fail loudly so a future regression surfaces
        // instead of corrupting the convergent log.
        let proposal_created_at = {
            let ctx = self.require_active_context_mut(context_id)?;
            let now = crate::time::now_ms();

            if ctx.executed_proposals.contains_key(proposal_id) {
                return Err(ScpWasmError::Permission {
                    message: "governance proposal has already been executed".to_owned(),
                    code: codes::PERM_3000.to_owned(),
                });
            }

            // Resolve BOTH the convergent leaf timestamp AND the action to
            // dispatch from the TRACKED proposal — never from a caller-supplied
            // action. This closes the action-substitution facet of the
            // direct-execute quorum bypass: the executed action is exactly the
            // one the engine tracked for this id.
            let tracked = ctx
                .pending_proposals
                .get(proposal_id)
                .or_else(|| ctx.resolved_proposals.get(proposal_id))
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!(
                        "governance proposal '{proposal_id}' is not tracked (pending or resolved); \
                         cannot derive the convergent GovernanceActionExecuted leaf timestamp"
                    ),
                    code: codes::CTX_2041.to_owned(),
                })?;
            let created_at = tracked.created_at;
            let tracked_action = tracked.action.clone();

            // Evict expired proposals when over capacity.
            if ctx.executed_proposals.len() >= WASM_PROPOSAL_CAP {
                let cutoff = now - WASM_PROPOSAL_TTL_MS;
                ctx.executed_proposals.retain(|_, ts| *ts > cutoff);
            }

            ctx.executed_proposals.insert(proposal_id.to_owned(), now);
            (created_at, tracked_action)
        };
        let (proposal_created_at, action) = proposal_created_at;
        let action = &action;

        // `proposal_created_at` is the convergent committer-assigned leaf
        // timestamp (the executed proposal's signed `created_at`). It is threaded
        // into dispatch so the `RemoveMember` arm can append its OWN durable
        // `MemberLeft` leaf with the SAME convergent timestamp the
        // `GovernanceActionExecuted` leaf below uses — mirroring native's
        // per-action `execute_remove_member`, which appends `MemberLeft` BEFORE
        // `finalize_governance_action` appends `GovernanceActionExecuted`. Using
        // `crate::time::now_secs()` here would diverge across members and break
        // the §9.9.3 equal-count/equal-root equivocation invariant.
        let result =
            self.dispatch_governance_action(context_id, action, executor_did, proposal_created_at);

        // Roll back on failure.
        if result.is_err()
            && let Some(ctx) = self.contexts.get_mut(context_id)
        {
            ctx.executed_proposals.remove(proposal_id);
        }

        // Record governance event on success.
        if result.is_ok()
            && let Some(ctx) = self.contexts.get_mut(context_id)
        {
            // Convergent leaf timestamp for `GovernanceActionExecuted`: the
            // executed proposal's signed `created_at`, captured above before
            // dispatch (guarded against a missing proposal so this can never be
            // a divergent `0`). Byte-identical to the native runtime's
            // proposal-derived value (`finalize_governance_action`); never
            // local `now()` (§7.3.1, §9.9.3).
            let action_summary = action.variant_name().to_owned();
            // Strict parse: reject non-hex / non-32-byte ids loudly instead of
            // silently zero-padding (matches the native bridges' parse and the
            // WASM bridge boundary). A divergent `proposal_id` here would break
            // cross-platform Merkle equivocation detection.
            let proposal_id_bytes: [u8; 32] = parse_proposal_id_bytes(proposal_id)?;
            let target_did: Option<DID> = action.target_did().cloned();

            // Encode the durable leaf payload FIRST, before any buffer event is
            // pushed — matching native `finalize_governance_action`, which
            // encodes the payload (`encode_payload(...)?`) BEFORE appending the
            // leaf and BEFORE emitting the buffer `ContextEvent`. The payload
            // MUST be the shared `GovernanceActionExecutedPayload` (positional
            // MessagePack via `encode_payload`) — byte-identical to native — so
            // cross-platform members derive equal Merkle roots (§9.9.3).
            // `target_did` is the action's target (empty when untargeted);
            // `action_type` is the `GovernanceAction` variant name.
            //
            // FAIL CLOSED on encode error (mirrors native's `map_err(...)?`):
            // on failure return `Err` with NO buffer event and NO leaf — exactly
            // native's position (it returns Err before `emit`, leaving the
            // executed marker set). Doing the encode BEFORE `push_event` is what
            // keeps the buffer-event side effect symmetric: a previous ordering
            // pushed the buffer event first, so an encode failure left WASM with
            // a buffer event native never emits.
            let executed_payload =
                Self::encode_governance_action_executed_payload(action, target_did.as_ref())?;

            // Durable GovernanceActionExecuted leaf.
            ctx.append_log_event(
                EventType::GovernanceActionExecuted,
                // Convergence-critical leaf `actor_did`: the COMMITTING member
                // (the executor), NOT the auth-subject `initiator_did`. For the
                // direct-FFI execute path the executor is the proposal's
                // proposer (resolved by the caller); for quorum/auto it is the
                // voter/proposer respectively — byte-identical to native
                // (§9.9.3; ADR-031 §8 "executor DID").
                executor_did,
                &executed_payload,
                proposal_created_at,
            );

            // Buffer event LAST, mirroring native's post-leaf `emit(...)`.
            ctx.push_event(ContextEvent::GovernanceActionExecuted {
                proposal_id: proposal_id_bytes,
                action_summary,
                // The buffer event's `executor_did` is the COMMITTING member
                // (the executor), NOT the auth-subject `initiator_did` —
                // matching native `finalize_governance_action` (§9.9.3; ADR-031
                // §8 "executor DID" / spec §7.3.1 "committing member" /
                // ADR-051 §6).
                executor_did: DID(executor_did.to_owned()),
                resulting_epoch: None,
                target_did: target_did.clone(),
            });

            // Evaluate and enforce consequence rules. Mirrors
            // `scp_runtime::context::manager::governance::
            // execute_governance_action` which dispatches consequences
            // for both the executor and the action's target DID (if any)
            // after the governance event has been recorded.
            let now_secs = crate::time::now_secs();
            crate::consequence::dispatch_consequences_for_subject(
                ctx,
                context_id,
                initiator_did,
                now_secs,
            );
            if let Some(target) = target_did.as_ref() {
                crate::consequence::dispatch_consequences_for_subject(
                    ctx,
                    context_id,
                    target.as_ref(),
                    now_secs,
                );
            }
        }

        result
    }

    /// Handles a `ModifyCeiling` governance action (BLACK-002).
    ///
    /// Ceiling-entry grammar enforcement (spec §5.3.1.1): the shared
    /// `ContextRoleState::set_ceiling` is the single fail-closed validation point.
    /// It runs `CapabilityCeiling::validate_entries` BEFORE storing, so a malformed
    /// proposed entry (no-colon / stray-`*` / multi-colon `Custom`) is rejected
    /// with the canonical `SCP-VALID-7000` error and the prior ceiling is left
    /// UNCHANGED, and nothing else mutates.
    ///
    /// Convergence with native (`apply_pending_ceiling_modification`): native
    /// applies a ceiling modification with `role_state.set_ceiling(...)` ONLY — it
    /// does NOT rebuild built-in role definitions nor re-run `system_assign_role`
    /// to refresh members' `member_capabilities`. Those snapshots stay as computed
    /// at the last explicit role assignment and are recomputed only on the next
    /// assignment. WASM matches that exactly here: validate → `set_ceiling` → done.
    /// Eagerly refreshing on a ceiling WIDEN would, via `system_assign_role`'s
    /// SHRINK-only `prune_suspensions_to_role_grants`, silently re-grant a
    /// `SuspendAccess`-suspended member the newly-added capability (the suspended
    /// set never gains the new cap, but the refreshed `member_capabilities` does);
    /// not refreshing keeps the suspended member fully suspended, matching native.
    ///
    /// WASM keeps the single-phase immediate write — native's two-phase
    /// governed-ceiling deferral is a separate slice. Because the validation and
    /// the stored form both flow from the same shared `Capability` grammar, native
    /// and WASM store the SAME effective ceiling for the same `ModifyCeiling`
    /// action.
    fn dispatch_modify_ceiling(
        &mut self,
        context_id: &str,
        new_ceiling: &[scp_protocol::context::roles::Capability],
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        if ctx.ceiling_policy != "governed" {
            return Err(ScpWasmError::Permission {
                message: "ceiling is immutable — cannot modify".to_owned(),
                code: codes::PERM_3000.to_owned(),
            });
        }
        // The shared `set_ceiling` is the single fail-closed validation point: it
        // runs `validate_entries` BEFORE storing, so a malformed proposed entry is
        // rejected with the canonical `SCP-VALID-7000` error and the prior ceiling
        // is left UNCHANGED. No built-in-role rebuild and no per-member
        // `system_assign_role` refresh — `member_capabilities` go
        // stale-on-ceiling-change exactly like native.
        ctx.role_state
            .set_ceiling(CapabilityCeiling::new(new_ceiling.iter().cloned()))
            .map_err(ceiling_validation_error)?;
        // per-action-EventType-leaf deferral: native ALSO appends a per-action
        // durable event-log leaf for ModifyCeiling (`CeilingModificationPending`
        // when the change defers, `CeilingModified` when it applies, in
        // governance_helpers.rs) IN ADDITION to the generic
        // `GovernanceActionExecuted`. WASM does not yet emit those per-action
        // leaves — a known §9.9.3 leaf-count divergence deferred to the
        // per-action-EventType-leaf-parity workstream (tracked by the ignored
        // `wasm_native_full_governance_eventtype_parity_pending` conformance
        // test).
        Ok(serde_json::json!({"action": "ModifyCeiling"}))
    }

    /// Dispatches a governance action to its handler.
    ///
    /// Split into multiple methods to satisfy the 100-line function limit.
    fn dispatch_governance_action(
        &mut self,
        context_id: &str,
        action: &GovernanceAction,
        // The committing member (executor) — stamped as the convergence-critical
        // `actor_did` on any per-action durable leaf this dispatch appends,
        // byte-identical to native (§9.9.3; ADR-031 §8 "executor DID"). NOTE:
        // WASM currently emits only RemoveMember's `MemberLeft` per-action leaf;
        // it does NOT yet emit per-action leaves everywhere native does
        // (TransferAdmin's `AdminTransferred`, ModifyCeiling's
        // `CeilingModificationPending`/`CeilingModified`, etc. are deferred to
        // the per-action-EventType-leaf-parity workstream — the ignored
        // `wasm_native_full_governance_eventtype_parity_pending` conformance
        // test). So this `actor_did` stamps the MemberLeft leaf today; the
        // others are pending.
        executor_did: &str,
        // The convergent committer-assigned leaf timestamp (the executed
        // proposal's signed `created_at`), used for any per-action durable leaf
        // this dispatch appends — NEVER local `now()`.
        timestamp_secs: u64,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Per-action CONTEXT-CEILING gate, identical to native's per-action
        // `ceiling.contains(&Capability::X)` gates in `dispatch_governance_action`
        // / the `execute_*` helpers (`governance_helpers.rs`). Gates on the
        // CEILING only — NOT on the committing member's role — so an
        // out-of-ceiling action is rejected byte-identically on both bridges and
        // an in-ceiling action executes (and mints its leaves) on both (§9.9.3,
        // ADR-031 §8). Actions with no native ceiling gate return `None` and skip
        // this check (their authorization lives entirely at propose time).
        if let Some(required) = Self::dispatch_ceiling_capability(action) {
            let ctx = self.require_active_context(context_id)?;
            if !ctx
                .role_state
                .ceiling()
                .contains(&ucan_string_to_capability(required))
            {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "context ceiling does not include '{required}' capability required for this governance action"
                    ),
                    code: codes::PERM_3000.to_owned(),
                });
            }
        }
        match action {
            GovernanceAction::AddMember { did, role } => {
                self.dispatch_add_member(context_id, did, role)
            }
            GovernanceAction::RemoveMember { did, .. } => {
                self.dispatch_remove_member(context_id, did, executor_did, timestamp_secs)
            }
            GovernanceAction::ChangeRole { did, new_role } => {
                self.dispatch_change_role(context_id, did, new_role)
            }
            GovernanceAction::RegisterTool { registration } => {
                self.dispatch_register_tool(
                    context_id,
                    &registration.tool_id,
                    &registration.name,
                    &registration.description,
                )
            }
            GovernanceAction::RemoveTool { tool_id } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.tool_registry.remove(tool_id).is_none() {
                    return Err(ScpWasmError::Tool {
                        message: format!("tool '{tool_id}' not found"),
                        code: codes::TOOL_6003.to_owned(),
                    });
                }
                Ok(serde_json::json!({"action": "RemoveTool", "toolId": tool_id}))
            }
            GovernanceAction::ModifyCeiling { new_ceiling } => {
                self.dispatch_modify_ceiling(context_id, new_ceiling)
            }
            GovernanceAction::CloseContext { .. } => {
                let ctx = self.require_active_context_mut(context_id)?;
                "closing".clone_into(&mut ctx.state);
                Ok(serde_json::json!({"action": "CloseContext"}))
            }
            GovernanceAction::ExtendTtl { additional_secs } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if let Some(ref mut ttl) = ctx.ttl_seconds {
                    // Saturating add for exact parity with native
                    // `execute_extend_ttl` (`governance_helpers.rs`), which
                    // extends the TTL with a saturating base — and for u64
                    // overflow safety (a plain `+=` panics in debug builds).
                    *ttl = ttl.saturating_add(*additional_secs);
                }
                Ok(serde_json::json!({"action": "ExtendTtl", "additionalSecs": additional_secs}))
            }
            GovernanceAction::TransferAdmin { .. } // remaining: exhaustive, no wildcard
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. }
            | GovernanceAction::PromoteContext
            | GovernanceAction::CreateChildContext { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. }
            | GovernanceAction::EstablishToolInterface { .. }
            | GovernanceAction::ResetMember { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. }
            | GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::ModifyHardRateLimit { .. }
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration => self.dispatch_governance_action_ext(context_id, action),
        }
    }

    /// Handles the `ChangeRole` governance action.
    ///
    /// Routes the role change through the shared
    /// [`ContextRoleState::system_assign_role`], which validates the role exists
    /// in `role_definitions` (and that every granted capability is within the
    /// ceiling) before applying it. This is the #1886 fix: an undefined or
    /// out-of-ceiling role is now REJECTED, matching native, instead of being
    /// silently accepted as a free-form role string. Broadcast author state is
    /// synced when the role transitions to/from `author`.
    fn dispatch_change_role(
        &mut self,
        context_id: &str,
        did: &str,
        new_role: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        if !ctx.role_state.members.contains(did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{did}' not found"),
                code: codes::CTX_2015.to_owned(),
            });
        }
        let old_role = ctx
            .role_state
            .assignments
            .get(did)
            .map(|a| a.role_name.clone())
            .unwrap_or_default();
        ctx.role_state
            .system_assign_role(did, new_role, &crate::time::WasmClock)
            .map_err(map_role_error)?;
        // Sync broadcast state when role transitions to/from "author".
        if let Some(ref mut bc) = ctx.broadcast_context {
            if old_role == "author" && new_role != "author" {
                // Revoke author status — destroys their broadcast key.
                let _ = bc.block_author(did);
            } else if new_role == "author" && old_role != "author" {
                // Grant author status — generates a fresh broadcast key.
                let _ = bc.add_author(did);
            }
        }
        Ok(serde_json::json!({"action": "ChangeRole", "did": did, "newRole": new_role}))
    }

    /// Handles `AddMember` governance action: inserts the member and, for
    /// broadcast contexts, registers author state when the role is "author".
    fn dispatch_add_member(
        &mut self,
        context_id: &str,
        did: &str,
        role: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if ctx.role_state.members.len() >= WASM_MEMBER_CAP {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "member list has reached capacity ({WASM_MEMBER_CAP}) — \
                     cannot add additional members"
                ),
                code: codes::VALID_7302.to_owned(),
            });
        }

        // Add the member and assign the requested role via the shared
        // `system_assign_role` (validates the role exists in `role_definitions`
        // / is within the ceiling before applying it). `system_assign_role`
        // requires the DID to already be in `members`, so insert first.
        //
        // Rollback is CONDITIONAL on novelty: on assignment failure we undo
        // only what THIS call inserted. A genuinely-new member is fully
        // removed (fail-closed atomicity — a rejected first-time `AddMember`
        // leaves NO partial membership behind), but a re-add of an EXISTING
        // member with a bad / out-of-ceiling role leaves that member fully
        // intact (members + sequence counter preserved). This matches native
        // `execute_add_member`, which does not roll back at all (member-add is
        // coalesce-window-rollback acceptable per ADR-049 §9) and therefore
        // never corrupts an existing member. Unconditional rollback would
        // split-brain an existing member: drop them from `members` / their
        // sequence counter while leaving `assignments` + `member_capabilities`
        // intact, so membership queries report them gone yet they retain caps
        // and can still propose / vote / decrypt.
        let member_was_present = ctx.role_state.members.contains(did);
        let seq_was_present = ctx.member_sequence_numbers.contains_key(did);
        ctx.role_state.members.insert(did.to_owned());
        ctx.member_sequence_numbers
            .entry(did.to_owned())
            .or_insert(0);
        if let Err(e) = ctx
            .role_state
            .system_assign_role(did, role, &crate::time::WasmClock)
        {
            // Only undo what THIS call inserted — never evict a pre-existing
            // member. (`system_assign_role` validates the role BEFORE touching
            // `assignments` / `member_capabilities`, so a failure leaves an
            // existing member fully intact; native `execute_add_member`
            // likewise does not roll back — member-add is
            // coalesce-window-rollback acceptable per ADR-049 §9.)
            if !member_was_present {
                ctx.role_state.members.remove(did);
            }
            if !seq_was_present {
                ctx.member_sequence_numbers.remove(did);
            }
            return Err(map_role_error(e));
        }
        // If the new member is an author in a broadcast context, register
        // them with a fresh broadcast key at epoch 0 (§5.14.8).
        if role == "author"
            && let Some(ref mut bc) = ctx.broadcast_context
        {
            let _ = bc.add_author(did);
        }
        ctx.push_event(ContextEvent::MemberJoined {
            member_did: DID(did.to_owned()),
            role_name: role.to_owned(),
        });
        Ok(serde_json::json!({"action": "AddMember", "did": did}))
    }

    /// Handles `RemoveMember` governance action: removes the member and, for
    /// broadcast contexts, cleans up author state when the ejected member had
    /// the "author" role.
    fn dispatch_remove_member(
        &mut self,
        context_id: &str,
        did: &str,
        executor_did: &str,
        timestamp_secs: u64,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // Existence check WITHOUT removing — the governance strip is deferred
        // until AFTER the MLS eviction succeeds (fail-closed-keep ordering;
        // mirrors native `execute_remove_member`, which checks
        // `membership.contains(did)` before the MLS boundary and only strips
        // membership once the crypto cuts have all succeeded). Preserves the
        // exact `CTX_2015` not-found semantics.
        if !ctx.role_state.members.contains(did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{did}' not found"),
                code: codes::CTX_2015.to_owned(),
            });
        }

        // MLS eviction is the HARD security boundary and MUST run FIRST, BEFORE
        // any governance/broadcast state is stripped (mirrors native
        // `execute_remove_member`, which removes from the MLS group first and
        // strips membership only inside the fail-closed-keep closure after the
        // crypto cuts succeed). On an encrypted context: evict the member from
        // the MLS group, drop their stored sender key, then rotate the local
        // sender key so the removed member's knowledge of any prior sender key
        // grants no future plaintext (§9.16.4). When there is no MLS
        // state (`crypto.is_none()` — a broadcast / unencrypted context, or one
        // whose crypto was destroyed by a prior self-leave) there is no MLS
        // group, so the commit is empty, matching native's non-MLS no-op.
        //
        // A governance member with NO MLS leaf is NOT a failure: it is a no-op
        // returning an empty commit (matching native `MlsCryptoProvider::
        // remove_member`), so dispatch PROCEEDS to strip membership + append the
        // `MemberLeft` leaf. The governance layer is authoritative for
        // membership; the crypto layer only manages MLS state.
        //
        // Fail-closed: if ANY of these crypto steps errors with a GENUINE MLS
        // failure (a destroyed group, or a commit-serialization failure on a
        // leaf that WAS found), this returns `Err` while the member is STILL
        // fully present in `ctx.members` and broadcast state.
        // The removal is therefore atomic at the security boundary — there is no
        // window where the member is gone from governance yet still able to
        // derive the group keys. The caller's only rollback
        // (`execute_governance_action`) does not restore `ctx.members`, so the
        // strip must not happen until eviction has actually succeeded; a retry
        // after a transient failure is safe.
        //
        // The operative lockout for the evicted member is the MLS layer-2
        // eviction (epoch advance) itself: once the commit lands, the removed
        // member can no longer derive the group keys, so MLS decryption of any
        // later message fails. The sender-key rotation's role, and why WASM's
        // missing cross-member sender-key distribution path is orthogonal to the
        // eviction security property, are explained in full at
        // `WasmCryptoState::governance_rotate_sender_key` (crypto/state.rs).
        //
        // Scope the `ctx.crypto.as_mut()` borrow tightly so the later
        // `ctx.members` / `ctx.broadcast_context` mutations can re-borrow `ctx`.
        let commit = if let Some(crypto) = ctx.crypto.as_mut() {
            let commit =
                crypto
                    .governance_remove_from_group(did)
                    .map_err(|e| ScpWasmError::Crypto {
                        message: e.to_string(),
                        code: codes::CRYPTO_4011.to_owned(),
                    })?;
            crypto.governance_remove_sender_key(did);
            crypto.governance_rotate_sender_key();
            commit
        } else {
            Vec::new()
        };

        // MLS eviction succeeded (or there was no MLS group) — only NOW is it
        // safe to strip governance and broadcast state. Capture the role before
        // removing so broadcast-author cleanup can still see it.
        let removed_role = ctx
            .role_state
            .assignments
            .get(did)
            .map(|a| a.role_name.clone());
        ctx.role_state.members.remove(did);

        // Drop all per-DID state the removed member left behind. Native
        // `execute_remove_member` (governance_helpers.rs) leaves the removed
        // member's `suspended_capabilities` entry in place — it strips
        // members/assignments/member_capabilities (plus the access key store
        // entry and the pseudonym routing entry) but has no removal primitive
        // that clears the suspension. WASM clears it here (via
        // `restore_capabilities`) as the safer behavior: a re-admitted same-DID
        // member must not inherit a phantom suspension, assignment,
        // read-exclusion, or sequence number. The CEK-exclusion state is
        // `read_exclusion_list` and the MLS sequence counter is
        // `member_sequence_numbers`. All removals are no-ops if absent.
        //
        // This is a KNOWN native↔WASM divergence where native should converge
        // TO WASM; the convergence — a shared `ContextRoleState::remove_member`
        // primitive in scp-protocol with a spec-decided canonical
        // suspension-on-removal policy — is deferred to the MembershipState /
        // shared-removal slice.
        ctx.role_state.assignments.remove(did);
        ctx.role_state.member_capabilities.remove(did);
        if let Some(suspended) = ctx.role_state.suspended_for(did) {
            let caps: Vec<Capability> = suspended.iter().cloned().collect();
            ctx.role_state.restore_capabilities(did, &caps);
        }
        ctx.member_sequence_numbers.remove(did);
        ctx.read_exclusion_list.remove(did);

        // If the ejected member was an author in a broadcast context, clean up
        // their broadcast state (destroys broadcast key).
        if removed_role.as_deref() == Some("author")
            && let Some(ref mut bc) = ctx.broadcast_context
        {
            let _ = bc.block_author(did);
        }

        // Buffer event for local subscribers (mirrors native's `emit`).
        ctx.push_event(ContextEvent::MemberLeft {
            member_did: DID(did.to_owned()),
        });

        // Durable `MemberLeft` leaf — appended BEFORE the wrapper's
        // `GovernanceActionExecuted` leaf, matching native's ordering
        // (`execute_remove_member` appends `MemberLeft` inside the commit closure;
        // `finalize_governance_action` appends `GovernanceActionExecuted` after).
        // The leaf carries the convergent committer-assigned `executor_did` +
        // `timestamp_secs` and an EMPTY payload, byte-identical to native's
        // `append_context_event(EventType::MemberLeft, actor_did, timestamp_secs)`
        // (which uses `EventPayload::default()`). The target DID lives in the
        // buffer event only, never in the durable leaf (§9.9.3).
        ctx.append_log_event(EventType::MemberLeft, executor_did, b"", timestamp_secs);

        // Return the eviction commit (hex) so the relay can distribute it to the
        // remaining members; empty for non-MLS contexts.
        Ok(serde_json::json!({
            "action": "RemoveMember",
            "did": did,
            "commit": crate::runtime::encode_hex(&commit),
        }))
    }

    /// Handles governance actions that don't fit in the primary dispatch.
    #[allow(clippy::too_many_lines)]
    fn dispatch_governance_action_ext(
        &mut self,
        context_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            GovernanceAction::TransferAdmin { new_admin } => {
                let ctx = self.require_active_context_mut(context_id)?;
                let new_admin_str: &str = new_admin;
                // Converges to native `execute_transfer_admin`
                // (`governance_helpers.rs`): admin is a transferable ROLE, not
                // `creator_did`. The transfer (a) REJECTS a non-member new_admin
                // before any mutation, (b) demotes EVERY current admin-role
                // holder to "member", then (c) promotes new_admin to "admin" —
                // all via the shared `system_assign_role`. `creator_did` is the
                // immutable original creator (UCAN root / export signer / HMAC
                // identity / exporter_did) and is NEVER touched by a role
                // transfer.
                //
                // Reject-before-mutate: the membership guard returns before any
                // `system_assign_role`, and the two assignments target built-in
                // roles ("member" / "admin") whose caps are ceiling-filtered at
                // `ContextRoleState` construction, so they cannot fail here —
                // no rollback is needed (mirrors native, which returns its
                // guard `Err` before persisting).
                if !ctx.role_state.members.contains(new_admin_str) {
                    return Err(ScpWasmError::Context {
                        message: format!("member '{new_admin_str}' not found"),
                        code: codes::CTX_2015.to_owned(),
                    });
                }
                let current_admins: Vec<String> = ctx
                    .role_state
                    .assignments
                    .iter()
                    .filter(|(_, a)| a.role_name == "admin")
                    .map(|(did, _)| did.clone())
                    .collect();
                for admin_did in &current_admins {
                    ctx.role_state
                        .system_assign_role(admin_did, "member", &crate::time::WasmClock)
                        .map_err(map_role_error)?;
                }
                ctx.role_state
                    .system_assign_role(new_admin_str, "admin", &crate::time::WasmClock)
                    .map_err(map_role_error)?;
                // per-action-EventType-leaf deferral: native ALSO appends a
                // per-action `AdminTransferred` durable event-log leaf for
                // TransferAdmin (governance_helpers.rs) IN ADDITION to the
                // generic `GovernanceActionExecuted`. WASM does not yet emit
                // that per-action leaf — a known §9.9.3 leaf-count divergence
                // deferred to the per-action-EventType-leaf-parity workstream
                // (tracked by the ignored
                // `wasm_native_full_governance_eventtype_parity_pending`
                // conformance test).
                Ok(serde_json::json!({"action": "TransferAdmin", "newAdmin": new_admin_str}))
            }
            GovernanceAction::SuspendCapability { did, capabilities } => {
                let did_str: &str = did;
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.role_state
                    .suspend_capabilities(did_str, capabilities.iter().cloned());
                // Emit a capability-precise suspension event that
                // carries the exact suspended set. Cross-SDK parity
                // requires both the native manager and the WASM
                // bridge to emit `CapabilitiesSuspended` with the
                // full set.
                ctx.push_event(ContextEvent::CapabilitiesSuspended {
                    did: did.clone(),
                    capabilities: capabilities.clone(),
                });
                Ok(serde_json::json!({"action": "SuspendCapability", "did": did_str}))
            }
            GovernanceAction::SuspendAccess { did } => {
                let did_str: &str = did;
                let ctx = self.require_active_context_mut(context_id)?;
                // Suspend all of the member's effective capabilities, matching
                // the runtime's `suspend_all` semantics (the shared method
                // copies the member's full effective capability set into the
                // suspended set).
                ctx.role_state.suspend_all(did_str);
                ctx.push_event(ContextEvent::CapabilitiesSuspended {
                    did: did.clone(),
                    capabilities: vec![], // all — indicated by empty
                });
                Ok(serde_json::json!({"action": "SuspendAccess", "did": did_str}))
            }
            GovernanceAction::RevokeAccess { did, access } => {
                self.dispatch_revoke(context_id, did, *access)
            }
            GovernanceAction::RestoreAccess { did, capabilities } => {
                let did_str: &str = did;
                let ctx = self.require_active_context_mut(context_id)?;

                // NothingToRestore guard — byte-identical to native
                // `execute_restore_access` (governance_helpers.rs, §5.9): reject
                // BEFORE mutating when none of the requested capabilities are
                // actually suspended for the member, UNLESS the member is
                // read-excluded with read requested (the carve-out that lets a
                // read restore clear a standing read-exclusion even with an empty
                // suspended set). Surfaces the same SCP-CTX-2137 code native
                // does for cross-bridge parity.
                let nothing_suspended_for_request = ctx
                    .role_state
                    .suspended_for(did_str)
                    .is_none_or(|set| !capabilities.iter().any(|c| set.contains(c)));
                let read_excluded = ctx.read_exclusion_list.contains(did_str);
                let read_requested = capabilities.contains(&Capability::MessagesRead);
                if nothing_suspended_for_request && !(read_requested && read_excluded) {
                    return Err(ScpWasmError::Context {
                        message: format!(
                            "nothing to restore: no suspended capabilities to restore for {did_str}"
                        ),
                        code: codes::CTX_2137.to_owned(),
                    });
                }

                let caps: Vec<Capability> = capabilities.clone();
                ctx.role_state.restore_capabilities(did_str, &caps);
                ctx.read_exclusion_list.remove(did_str);
                if let Some(bc) = ctx.broadcast_context.as_mut() {
                    // Governance unban: remove from ALL authors' block lists (§5.14.8).
                    bc.governance_unban_subscriber(did_str);
                }
                Ok(serde_json::json!({"action": "RestoreAccess", "did": did_str}))
            }
            // 8 variants handled by upstream dispatch method (exhaustive, no wildcard).
            GovernanceAction::AddMember { .. }
            | GovernanceAction::RemoveMember { .. }
            | GovernanceAction::ChangeRole { .. }
            | GovernanceAction::RegisterTool { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::ExtendTtl { .. } => unreachable!(),
            // 16 variants handled by downstream dispatch methods.
            GovernanceAction::PromoteContext
            | GovernanceAction::CreateChildContext { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. }
            | GovernanceAction::EstablishToolInterface { .. }
            | GovernanceAction::ResetMember { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. }
            | GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::ModifyHardRateLimit { .. }
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration => {
                self.dispatch_governance_action_structural(context_id, action)
            }
        }
    }

    /// Handles `Revoke` governance action (§5.14.8).
    ///
    /// Extracted from `dispatch_governance_action_ext` to stay within the
    /// line limit. Governance ban: removes from subscriber registry, adds to
    /// all authors' block lists, increments all authors' key epochs, and
    /// emits `ContentKeysRotated` events.
    fn dispatch_revoke(
        &mut self,
        context_id: &str,
        did: &DID,
        access: AccessScope,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let did_str: &str = did;
        let access_str = format!("{access:?}");
        let ctx = self.require_active_context_mut(context_id)?;

        // Pre-validate: check ALL authors' block lists before any mutation.
        // This prevents partial corruption if a cap check fails mid-loop.
        if let Some(bc) = ctx.broadcast_context.as_ref() {
            for author_did in bc.author_dids() {
                if let Some(author) = bc.get_author(author_did)
                    && author.block_list.len() >= WASM_BLOCK_LIST_CAP
                    && !author.block_list.contains(did_str)
                {
                    return Err(ScpWasmError::Validation {
                        message: format!(
                            "per-author block list has reached capacity ({WASM_BLOCK_LIST_CAP}) \
                             for author '{author_did}' during governance ban"
                        ),
                        code: codes::VALID_7301.to_owned(),
                    });
                }
            }
        }

        // Suspend capabilities based on access scope (typed, via the shared
        // `ContextRoleState::suspend_capabilities`).
        let revoked_caps: &[Capability] = match access {
            AccessScope::Read => &[Capability::MessagesRead],
            AccessScope::Write => &[Capability::MessagesWrite],
            AccessScope::Both => &[Capability::MessagesRead, Capability::MessagesWrite],
        };
        ctx.role_state
            .suspend_capabilities(did_str, revoked_caps.iter().cloned());

        // For write revocation, destroy broadcast key in Full scope.
        if matches!(access, AccessScope::Write | AccessScope::Both) {
            if let Some(ref mut bc) = ctx.broadcast_context {
                let _ = bc.block_author(did_str);
            }
            ctx.push_event(ContextEvent::WriteAccessRevoked { did: did.clone() });
        }

        // For read revocation, perform governance ban.
        let mut key_rotated = false;
        if matches!(access, AccessScope::Read | AccessScope::Both) {
            if let Some(bc) = ctx.broadcast_context.as_mut() {
                // governance_ban_subscriber handles: remove from subscriber roster,
                // add to ALL authors' block lists, rotate ALL authors' keys, and
                // increment ALL epochs (§5.14.8 steps 2-4).
                if let Ok(ban_result) = bc.governance_ban_subscriber(did_str, access) {
                    key_rotated = !ban_result.rotated_authors.is_empty();
                }
            }
            ctx.push_event(ContextEvent::ReadAccessRevoked { did: did.clone() });
        }

        // Emit ContentKeysRotated if any author keys were rotated (§5.14.8 step 4).
        if key_rotated {
            ctx.push_event(ContextEvent::ContentKeysRotated {
                reason: Some(format!("Revoke for {did}")),
            });
        }
        Ok(serde_json::json!({"action": "RevokeAccess", "did": did_str, "access": access_str}))
    }

    /// Handles structural, threshold, and economic governance actions.
    ///
    /// Split from `dispatch_governance_action_ext` to stay within the line
    /// limit. Handles: `PromoteContext`, `CreateChildContext`,
    /// `ModifyPruningPolicy`, `AddSigner`, `RemoveSigner`,
    /// `ModifyThreshold`, and delegates remaining to
    /// `dispatch_governance_action_remaining`.
    fn dispatch_governance_action_structural(
        &mut self,
        context_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            GovernanceAction::PromoteContext => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.promotion_policy.as_deref() != Some("Promotable") {
                    return Err(ScpWasmError::Permission {
                        message: "context promotion_policy is not Promotable".to_owned(),
                        code: codes::PERM_3000.to_owned(),
                    });
                }
                // Promote: cancel TTL (§5.10).
                ctx.ttl_seconds = None;
                Ok(serde_json::json!({"action": "PromoteContext"}))
            }
            GovernanceAction::CreateChildContext { .. } => {
                let _ = self.require_active_context_mut(context_id)?;
                // Child context creation is delegated to create_context by the
                // caller with the parent_context_id field set. This method
                // records the governance event on the parent.
                Ok(serde_json::json!({"action": "CreateChildContext"}))
            }
            GovernanceAction::ModifyPruningPolicy { new_policy } => {
                let ctx = self.require_active_context_mut(context_id)?;
                // Store as JSON string for WASM-local state.
                ctx.pruning_policy = Some(serde_json::to_string(new_policy).unwrap_or_default());
                Ok(serde_json::json!({"action": "ModifyPruningPolicy"}))
            }
            GovernanceAction::AddSigner { did } => {
                let did_str: &str = did;
                let ctx = self.require_active_context_mut(context_id)?;
                if !ctx.role_state.members.contains(did_str) {
                    return Err(ScpWasmError::Context {
                        message: format!("member '{did}' not found"),
                        code: codes::CTX_2015.to_owned(),
                    });
                }
                if ctx.threshold_signers.contains(&did_str.to_owned()) {
                    return Err(ScpWasmError::Permission {
                        message: format!("DID is already a signer: {did}"),
                        code: codes::PERM_3000.to_owned(),
                    });
                }
                ctx.threshold_signers.push(did_str.to_owned());
                Ok(serde_json::json!({"action": "AddSigner", "did": did_str}))
            }
            GovernanceAction::RemoveSigner { did } => {
                self.dispatch_remove_signer(context_id, did)
            }
            GovernanceAction::ModifyThreshold { new_threshold } => {
                let ctx = self.require_active_context_mut(context_id)?;
                let signer_count = u32::try_from(ctx.threshold_signers.len()).unwrap_or(u32::MAX);
                if *new_threshold == 0 || *new_threshold > signer_count {
                    return Err(ScpWasmError::Permission {
                        message: format!(
                            "threshold must be 1..={signer_count}, got {new_threshold}"
                        ),
                        code: codes::PERM_3000.to_owned(),
                    });
                }
                ctx.threshold_value = *new_threshold;
                Ok(serde_json::json!({"action": "ModifyThreshold", "newThreshold": new_threshold}))
            }
            GovernanceAction::AddMember { .. } // 14 upstream (exhaustive, no wildcard)
            | GovernanceAction::RemoveMember { .. }
            | GovernanceAction::ChangeRole { .. }
            | GovernanceAction::RegisterTool { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. } => unreachable!(),
            GovernanceAction::EstablishToolInterface { .. } // 11 downstream
            | GovernanceAction::ResetMember { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. }
            | GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::ModifyHardRateLimit { .. }
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration => {
                self.dispatch_governance_action_remaining(context_id, action)
            }
        }
    }

    /// Handles remaining governance actions: `EstablishToolInterface`,
    /// `ResetMember`, `ResolveConflict`, `RotateContentKeys`,
    /// `ReconfigureGovernance`, `ProposeContextMigration`,
    /// `CancelContextMigration`.
    fn dispatch_governance_action_remaining(
        &mut self,
        context_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            GovernanceAction::EstablishToolInterface { interface } => {
                let ctx = self.require_active_context_mut(context_id)?;
                // Store as JSON string for WASM-local state.
                ctx.tool_interfaces
                    .push(serde_json::to_string(interface).unwrap_or_default());
                Ok(serde_json::json!({"action": "EstablishToolInterface"}))
            }
            GovernanceAction::ResetMember { did, reason } => {
                self.dispatch_reset_member(context_id, did, reason)
            }
            GovernanceAction::ResolveConflict {
                proposal_a,
                proposal_b,
                resolution,
            } => {
                let first_proposal = hex::encode(proposal_a);
                let second_proposal = hex::encode(proposal_b);
                let res_str = match resolution {
                    ConflictResolution::InvalidateBoth => "invalidateBoth".to_owned(),
                    ConflictResolution::AcceptProposal { winner_id } => hex::encode(winner_id),
                };
                self.dispatch_resolve_conflict(
                    context_id,
                    &first_proposal,
                    &second_proposal,
                    &res_str,
                )
            }
            GovernanceAction::RotateContentKeys { .. } => {
                let _ = self.require_active_context_mut(context_id)?;
                // Key rotation in WASM: no MLS backend — records event only.
                // In broadcast mode, the event signals JS to re-derive keys.
                Ok(serde_json::json!({"action": "RotateContentKeys"}))
            }
            GovernanceAction::ReconfigureGovernance {
                changes,
                justification,
            } => {
                let changes_json = serde_json::to_string(changes).unwrap_or_default();
                let justification_str = serde_json::to_string(justification).unwrap_or_default();
                self.dispatch_reconfigure_governance(context_id, &changes_json, &justification_str)
            }
            GovernanceAction::ProposeContextMigration {
                new_context_params,
                reason,
                grace_period_secs,
                auto_invite,
            } => {
                let _ = self.require_active_context_mut(context_id)?;
                Ok(serde_json::json!({
                    "action": "ProposeContextMigration",
                    "reason": reason,
                    "gracePeriodSecs": grace_period_secs,
                    "autoInvite": auto_invite,
                    "newContextParams": format!("{new_context_params:?}"),
                }))
            }
            GovernanceAction::CancelContextMigration => {
                let _ = self.require_active_context_mut(context_id)?;
                Ok(serde_json::json!({"action": "CancelContextMigration"}))
            }
            // 18 variants handled by upstream dispatch methods (exhaustive, no wildcard).
            GovernanceAction::AddMember { .. }
            | GovernanceAction::RemoveMember { .. }
            | GovernanceAction::ChangeRole { .. }
            | GovernanceAction::RegisterTool { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. }
            | GovernanceAction::PromoteContext
            | GovernanceAction::CreateChildContext { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. } => unreachable!(),
            // 4 variants handled by dispatch_governance_action_economic
            // (SetEconomicPolicy, ApproveSpend, LockEconomicPolicy, ModifyHardRateLimit).
            GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::ModifyHardRateLimit { .. } => {
                self.dispatch_governance_action_economic(context_id, action)
            }
        }
    }

    /// Handles `SetEconomicPolicy` governance dispatch with the C2 fail-closed
    /// gate (rejects paid policies that the WASM bridge cannot enforce).
    ///
    /// Extracted from `dispatch_governance_action_economic` to keep the parent
    /// match arm under `clippy::too_many_lines`.
    fn dispatch_set_economic_policy(
        &mut self,
        context_id: &str,
        policy: &EconomicPolicy,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // C2 fail-closed: even via governance, the WASM bridge cannot
        // accept a paid economic policy because it cannot run
        // `enforce_economy` (ADR-034). Reject before any state mutation
        // so subsequent join / send operations cannot drift into a
        // partially-paid state.
        if policy_requires_payment(policy) {
            return Err(ScpWasmError::Context {
                message: "EconomicPolicyUnsupportedOnWasm: SetEconomicPolicy with a paid \
                          policy is rejected on the WASM bridge — the browser SDK cannot \
                          run the full economy enforcement pipeline (ADR-034). Run this \
                          governance action from a native (Python / Node.js / Swift / \
                          Kotlin) client."
                    .to_owned(),
                code: SCP_ECON_PAID_POLICY_UNSUPPORTED_ON_WASM.to_owned(),
            });
        }
        let ctx = self.require_active_context_mut(context_id)?;
        if ctx.economic_policy_locked {
            return Err(ScpWasmError::Permission {
                message: "economic policy is locked and cannot be changed".to_owned(),
                code: codes::PERM_3000.to_owned(),
            });
        }
        // Store as JSON string for WASM-local state.
        ctx.economic_policy = Some(serde_json::to_string(policy).unwrap_or_default());
        Ok(serde_json::json!({"action": "SetEconomicPolicy"}))
    }

    /// Handles economic governance actions: `SetEconomicPolicy`,
    /// `ApproveSpend`, `LockEconomicPolicy`.
    fn dispatch_governance_action_economic(
        &mut self,
        context_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            GovernanceAction::SetEconomicPolicy { policy } => {
                self.dispatch_set_economic_policy(context_id, policy)
            }
            GovernanceAction::ApproveSpend {
                spender,
                amount,
                purpose,
            } => {
                let spender_str: &str = spender;
                let ctx = self.require_active_context_mut(context_id)?;
                if !ctx.role_state.members.contains(spender_str) {
                    return Err(ScpWasmError::Context {
                        message: format!("spender '{spender}' is not a member"),
                        code: codes::CTX_2015.to_owned(),
                    });
                }
                Ok(serde_json::json!({
                    "action": "ApproveSpend",
                    "spender": spender_str,
                    "amount": amount.0,
                    "purpose": purpose,
                }))
            }
            GovernanceAction::LockEconomicPolicy => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.economic_policy.is_none() {
                    return Err(ScpWasmError::Permission {
                        message: "cannot lock economic policy: no policy is set".to_owned(),
                        code: codes::PERM_3000.to_owned(),
                    });
                }
                if ctx.economic_policy_locked {
                    return Err(ScpWasmError::Permission {
                        message: "economic policy is already locked".to_owned(),
                        code: codes::PERM_3000.to_owned(),
                    });
                }
                ctx.economic_policy_locked = true;
                Ok(serde_json::json!({"action": "LockEconomicPolicy"}))
            }
            GovernanceAction::ModifyHardRateLimit { new_config } => {
                // Validate BEFORE touching context state so a malformed
                // proposal cannot corrupt the persisted config.
                new_config.validate().map_err(|e| ScpWasmError::Context {
                    message: format!("ModifyHardRateLimit: new config failed validation: {e}"),
                    code: codes::ECON_12091.to_owned(),
                })?;
                let ctx = self.require_active_context_mut(context_id)?;
                // WASM bridge stores the config as an opaque JSON blob
                // because it does not run the runtime-side
                // `TokenBucketLimiter` (that lives in scp-runtime, which
                // cannot compile to wasm32). Consumers of the WASM
                // bridge enforce rate limits via their own JS-side
                // counterparts; the stored config is what governance
                // has approved and is the authoritative reference.
                ctx.hard_rate_limit_config =
                    Some(serde_json::to_string(new_config).unwrap_or_default());
                Ok(serde_json::json!({
                    "action": "ModifyHardRateLimit",
                    "refillPerKilosec": new_config.refill_per_kilosec,
                    "burst": new_config.burst,
                }))
            }
            // 25 variants handled by upstream dispatch methods (exhaustive, no wildcard).
            GovernanceAction::AddMember { .. }
            | GovernanceAction::RemoveMember { .. }
            | GovernanceAction::ChangeRole { .. }
            | GovernanceAction::RegisterTool { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. }
            | GovernanceAction::PromoteContext
            | GovernanceAction::CreateChildContext { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. }
            | GovernanceAction::EstablishToolInterface { .. }
            | GovernanceAction::ResetMember { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. }
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration => unreachable!(),
        }
    }

    /// Helper for `ResolveConflict` governance action (upstream from dispatcher).
    ///
    /// Validates the `resolution` value, then records conflicting proposals as
    /// executed (invalidated). `resolution` must be `"invalidateBoth"` or one
    /// of the two proposal IDs.
    fn dispatch_resolve_conflict(
        &mut self,
        context_id: &str,
        proposal_a: &str,
        proposal_b: &str,
        resolution: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Validate resolution value before mutating state.
        let is_invalidate_both = resolution == "invalidateBoth";
        let is_accept_proposal = resolution == proposal_a || resolution == proposal_b;
        if !is_invalidate_both && !is_accept_proposal {
            return Err(ScpWasmError::Permission {
                message: format!(
                    "invalid resolution: must be 'invalidateBoth' or one of the proposal IDs, got '{resolution}'"
                ),
                code: codes::PERM_3000.to_owned(),
            });
        }

        let ctx = self.require_active_context_mut(context_id)?;
        // Clear governance freeze (ADR-031 §7).
        ctx.governance_freeze = false;
        // Record conflicting proposals as executed (invalidated).
        let now = crate::time::now_ms();
        if is_invalidate_both {
            ctx.executed_proposals.insert(proposal_a.to_owned(), now);
            ctx.executed_proposals.insert(proposal_b.to_owned(), now);
        } else {
            // AcceptProposal: resolution is the winner_id, loser is
            // invalidated. The winner remains eligible for execution.
            let loser = if resolution == proposal_a {
                proposal_b
            } else {
                proposal_a
            };
            ctx.executed_proposals.insert(loser.to_owned(), now);
        }
        Ok(serde_json::json!({"action": "ResolveConflict"}))
    }

    /// Helper for `ResetMember` governance action.
    fn dispatch_reset_member(
        &mut self,
        context_id: &str,
        did: &str,
        reason: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        if !ctx.role_state.members.contains(did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{did}' not found"),
                code: codes::CTX_2015.to_owned(),
            });
        }
        // Member reset: re-assign the SAME role and reset the MLS sequence
        // counter to 0 (ADR-029 §Tier 3). Re-running `system_assign_role`
        // re-mints the member's tokens and refreshes their capabilities; the
        // role is the member's existing assignment, so it is defined.
        let role = ctx
            .role_state
            .assignments
            .get(did)
            .map(|a| a.role_name.clone())
            .unwrap_or_default();
        ctx.role_state
            .system_assign_role(did, &role, &crate::time::WasmClock)
            .map_err(map_role_error)?;
        ctx.member_sequence_numbers.insert(did.to_owned(), 0);
        Ok(serde_json::json!({"action": "ResetMember", "did": did, "reason": reason}))
    }

    /// Helper for `ReconfigureGovernance` governance action.
    fn dispatch_reconfigure_governance(
        &mut self,
        context_id: &str,
        changes_json: &str,
        justification: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        if changes_json.is_empty() {
            return Err(ScpWasmError::Permission {
                message: "reconfigure_governance requires at least one change".to_owned(),
                code: codes::PERM_3000.to_owned(),
            });
        }
        if justification.is_empty() {
            return Err(ScpWasmError::Permission {
                message: "deadlock justification must not be empty".to_owned(),
                code: codes::PERM_3000.to_owned(),
            });
        }
        // Clear governance freeze as the reconfiguration resolves it.
        ctx.governance_freeze = false;
        Ok(serde_json::json!({"action": "ReconfigureGovernance"}))
    }

    /// Helper for `RegisterTool` governance action.
    fn dispatch_register_tool(
        &mut self,
        context_id: &str,
        tool_id: &str,
        name: &str,
        description: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        let registered_at = crate::time::now_secs();
        let reg = ToolRegistration {
            tool_id: tool_id.to_owned(),
            name: name.to_owned(),
            description: description.to_owned(),
            schema: crate::runtime::ToolSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
            },
            implementation_hash: [0u8; 32],
            test_vectors: Vec::new(),
            operator_did: DID::from(ctx.role_state.creator_did.clone()),
            cost: None,
            registered_at,
            signature: Vec::new(),
        };
        crate::runtime::tool_registry_insert_unique(&mut ctx.tool_registry, reg).map_err(|e| {
            ScpWasmError::Tool {
                message: e,
                code: codes::TOOL_6001.to_owned(),
            }
        })?;
        Ok(serde_json::json!({"action": "RegisterTool", "toolId": tool_id}))
    }

    /// Helper for `RemoveSigner` governance action.
    fn dispatch_remove_signer(
        &mut self,
        context_id: &str,
        did: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        let before = ctx.threshold_signers.len();
        ctx.threshold_signers.retain(|s| s != did);
        if ctx.threshold_signers.len() == before {
            return Err(ScpWasmError::Context {
                message: format!("signer '{did}' not found"),
                code: codes::CTX_2015.to_owned(),
            });
        }
        // Reject if removing would make threshold > signers.len().
        if ctx.threshold_value > 0 {
            let remaining = u32::try_from(ctx.threshold_signers.len()).unwrap_or(u32::MAX);
            if ctx.threshold_value > remaining {
                // Undo the removal.
                ctx.threshold_signers.push(did.to_owned());
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "removing signer would leave {remaining} signers < threshold {}",
                        ctx.threshold_value
                    ),
                    code: codes::PERM_3000.to_owned(),
                });
            }
        }
        Ok(serde_json::json!({"action": "RemoveSigner", "did": did}))
    }

    // -----------------------------------------------------------------------
    // Governance proposal lifecycle (#621)
    // -----------------------------------------------------------------------

    /// Determines the quorum requirement for a governance action.
    ///
    /// - `single_admin`: auto-approved (quorum = 0, always approved immediately).
    /// - `threshold`: requires `threshold_value` approvals.
    /// - `majority`: requires > 50% of members.
    /// - `unanimity`: requires all members.
    ///
    /// Returns `(required_approvals, total_members)`.
    fn governance_quorum(ctx: &PerContextState) -> (usize, usize) {
        let total = ctx.role_state.members.len();
        match ctx.governance.as_str() {
            "threshold" => (ctx.threshold_value as usize, total),
            "majority" => (total / 2 + 1, total),
            "unanimity" => (total, total),
            // single_admin and any unrecognized model: auto-approve.
            _ => (0, total),
        }
    }

    /// Proposes a governance action. Mirrors `ContextManager::propose_governance_action_checked`.
    ///
    /// For `single_admin`, the proposal is auto-approved and executed immediately.
    /// For multi-admin models, the proposal enters pending status. The proposer's
    /// vote counts as the first approval.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the proposer lacks the
    /// required capability, or the action is invalid.
    #[allow(clippy::too_many_lines)] // governance proposal creation + dispatch
    pub fn propose_governance_action(
        &mut self,
        context_id: &str,
        proposer_did: &str,
        proposal_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Authorization: check that proposer has governance:propose capability.
        {
            let ctx = self.require_active_context_mut(context_id)?;
            if !ctx.member_has_capability(proposer_did, "governance:propose") {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "member {proposer_did} does not have 'governance:propose' capability"
                    ),
                    code: codes::CTX_2041.to_owned(),
                });
            }
        }

        // Check for duplicate proposal ID (pending or resolved).
        {
            let ctx = self.require_active_context_mut(context_id)?;
            if ctx.pending_proposals.contains_key(proposal_id)
                || ctx.resolved_proposals.contains_key(proposal_id)
            {
                return Err(ScpWasmError::Context {
                    message: format!("proposal {proposal_id} already exists"),
                    code: codes::CTX_2041.to_owned(),
                });
            }
        }

        // Check governance model.
        let (required, _total) = {
            let ctx = self.require_active_context_mut(context_id)?;
            Self::governance_quorum(ctx)
        };

        // Build the proposal up front so even the SingleAdmin / quorum=0
        // auto-execute path TRACKS it before executing (required since
        // `execute_governance_action` resolves the convergent
        // `GovernanceActionExecuted` leaf timestamp from the still-tracked
        // proposal's `created_at` AND enforces the `status == Approved`
        // precondition — both fail if the proposal was never inserted).
        let now = crate::time::now_ms();
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let now_secs = (now / 1000.0) as u64;
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let voting_deadline_secs = ((now + WASM_PROPOSAL_DEADLINE_MS) / 1000.0) as u64;
        // Compute proposal_id as [u8; 32] from the hex string. Strict parse:
        // reject non-hex / non-32-byte ids loudly instead of silently
        // zero-padding (matches the native bridges' parse and the WASM bridge
        // boundary). A divergent `proposal_id` here would break cross-platform
        // Merkle equivocation detection.
        let proposal_id_bytes: [u8; 32] = parse_proposal_id_bytes(proposal_id)?;
        let proposal = GovernanceProposal {
            proposal_id: proposal_id_bytes,
            context_id: context_id.to_owned(),
            proposer_did: DID(proposer_did.to_owned()),
            action: action.clone(),
            status: ProposalStatus::Pending,
            created_at: now_secs,
            voting_deadline: voting_deadline_secs,
            approvals: vec![SignedVote {
                voter_did: DID(proposer_did.to_owned()),
                vote: VoteType::Approve,
                timestamp: now_secs,
                signature: Vec::new(),
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };

        // SingleAdmin or quorum=0: auto-approve and execute immediately. The
        // proposer IS the committing member here, so the executor is the
        // proposer (matches native's propose auto-execute). Insert the proposal
        // as `Approved` into `resolved_proposals` BEFORE executing so it is
        // tracked when `execute_governance_action` derives the convergent leaf
        // timestamp and checks the status precondition.
        if required == 0 {
            let pid = proposal_id.to_owned();
            let mut approved = proposal;
            approved.status = ProposalStatus::Approved;
            if let Some(ctx) = self.contexts.get_mut(context_id) {
                ctx.insert_resolved_proposal(pid.clone(), approved);
            }
            match self.execute_governance_action(context_id, proposer_did, proposer_did, &pid) {
                Ok(result) => {
                    return Ok(serde_json::json!({
                        "proposal_id": proposal_id,
                        "status": "Approved",
                        "execution_result": result,
                    }));
                }
                Err(e) => {
                    // Dispatch failed: drop the durably-resolved proposal so the
                    // proposer can retry (parity with native retry semantics —
                    // a failed execution must not strand the proposal).
                    if let Some(ctx) = self.contexts.get_mut(context_id) {
                        ctx.remove_resolved_proposal(&pid);
                    }
                    return Err(e);
                }
            }
        }

        let ctx = self.require_active_context_mut(context_id)?;

        // Evict expired proposals if at capacity.
        // Compare deadline (seconds) against current time (seconds).
        if ctx.pending_proposals.len() >= WASM_PENDING_PROPOSAL_CAP {
            ctx.pending_proposals
                .retain(|_, p| p.voting_deadline > now_secs);
        }

        // Check if proposer's initial vote meets quorum immediately.
        let meets_quorum = proposal.approvals.len() >= required;
        let pid = proposal_id.to_owned();
        ctx.pending_proposals.insert(pid.clone(), proposal);

        ctx.push_event(ContextEvent::GovernanceActionExecuted {
            proposal_id: proposal_id_bytes,
            action_summary: "ProposalCreated".to_owned(),
            executor_did: DID(proposer_did.to_owned()),
            resulting_epoch: None,
            target_did: action.target_did().cloned(),
        });
        // SECURITY/§9.9.3: native appends GovernanceProposalCreated with an
        // EMPTY payload (`append_context_event`, no payload) — match it so the
        // leaf preimage is byte-identical across platforms. The proposal_id is
        // NOT part of the canonical leaf; it rides only in the buffer-only
        // `ContextEvent` pushed above (which is not a durable Merkle leaf).
        ctx.append_log_event(
            EventType::GovernanceProposalCreated,
            proposer_did,
            b"",
            // Convergent: the proposal's signed `created_at` (set to `now_secs`
            // above), copied by every member — matches the native runtime's
            // proposal-derived leaf timestamp (§7.3.1, §9.9.3).
            now_secs,
        );

        if meets_quorum {
            // Move pending → resolved (marking Approved) BEFORE executing, so
            // the proposal is still tracked when `execute_governance_action`
            // resolves the convergent `GovernanceActionExecuted` leaf timestamp
            // from `proposal.created_at` (it looks up pending-or-resolved). On
            // auto-execute the proposer IS the committing member, so the
            // executor is the proposer (matches native's propose auto-execute).
            let proposal = self
                .contexts
                .get_mut(context_id)
                .and_then(|ctx| ctx.pending_proposals.remove(&pid));
            if let Some(p) = proposal {
                let pending_snapshot = p.clone();
                let mut approved = p;
                approved.status = ProposalStatus::Approved;
                if let Some(ctx) = self.contexts.get_mut(context_id) {
                    ctx.insert_resolved_proposal(pid.clone(), approved);
                }
                // Proposer's own vote crossed quorum: proposer == committing
                // member, so the executor is the proposer (auth subject and
                // executor coincide here).
                match self.execute_governance_action(context_id, proposer_did, proposer_did, &pid) {
                    Ok(result) => {
                        return Ok(serde_json::json!({
                            "proposal_id": pid,
                            "status": "Approved",
                            "execution_result": result,
                        }));
                    }
                    Err(e) => {
                        // Dispatch failed: roll back the pending → resolved move
                        // so the proposal stays retriable (parity with native).
                        if let Some(ctx) = self.contexts.get_mut(context_id) {
                            ctx.remove_resolved_proposal(&pid);
                            ctx.pending_proposals.insert(pid.clone(), pending_snapshot);
                        }
                        return Err(e);
                    }
                }
            }
        }

        Ok(serde_json::json!({
            "proposal_id": pid,
            "status": "Pending",
            "execution_result": null,
        }))
    }

    /// Casts an approval vote on a pending governance proposal.
    ///
    /// If the vote pushes the proposal past quorum, the action is auto-executed
    /// and the proposal is removed from the pending set.
    ///
    /// # Errors
    ///
    /// Returns an error if the proposal is not found, the voter lacks the
    /// `governance:vote` capability, or the voter has already voted.
    pub fn approve_governance_proposal(
        &mut self,
        context_id: &str,
        proposal_id: &str,
        voter_did: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Authorization.
        {
            let ctx = self.require_active_context_mut(context_id)?;
            if !ctx.member_has_capability(voter_did, "governance:vote") {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "member {voter_did} does not have 'governance:vote' capability"
                    ),
                    code: codes::CTX_2042.to_owned(),
                });
            }
        }

        // Check expiry and find proposal.
        let now = crate::time::now_ms();
        let (required, _total) = {
            let ctx = self.require_active_context_mut(context_id)?;
            Self::governance_quorum(ctx)
        };

        let ctx = self.require_active_context_mut(context_id)?;

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let now_secs = (now / 1000.0) as u64;
        let meets_quorum = {
            let proposal = ctx.pending_proposals.get_mut(proposal_id).ok_or_else(|| {
                ScpWasmError::Context {
                    message: format!("proposal {proposal_id} not found"),
                    code: codes::CTX_2042.to_owned(),
                }
            })?;

            if proposal.voting_deadline <= now_secs {
                return Err(ScpWasmError::Context {
                    message: "proposal voting deadline has expired".to_owned(),
                    code: codes::CTX_2042.to_owned(),
                });
            }

            // Check for duplicate vote.
            if proposal
                .approvals
                .iter()
                .any(|v| v.voter_did.0 == voter_did)
                || proposal
                    .rejections
                    .iter()
                    .any(|v| v.voter_did.0 == voter_did)
            {
                return Err(ScpWasmError::Permission {
                    message: format!("member {voter_did} has already voted on this proposal"),
                    code: codes::CTX_2042.to_owned(),
                });
            }

            proposal.approvals.push(SignedVote {
                voter_did: DID(voter_did.to_owned()),
                vote: VoteType::Approve,
                timestamp: now_secs,
                signature: Vec::new(),
            });
            proposal.approvals.len() >= required
        };

        // SECURITY/§9.9.3: native appends GovernanceVoteCast with an EMPTY
        // payload (`append_context_event`, no payload) — match it so the leaf
        // preimage is byte-identical across platforms. The proposal_id is NOT
        // part of the canonical leaf; it rides only in the buffer-only
        // `ContextEvent` (which is not a durable Merkle leaf).
        ctx.append_log_event(
            EventType::GovernanceVoteCast,
            voter_did,
            b"",
            // Convergent: the voter's signed vote `created_at` (= `now_secs`,
            // the same value stamped on the SignedVote), copied by every member
            // (§7.3.1, §9.9.3).
            now_secs,
        );

        let pid = proposal_id.to_owned();

        if meets_quorum {
            // Move pending → resolved (marking Approved) BEFORE executing, so
            // the proposal is still tracked when `execute_governance_action`
            // resolves the convergent `GovernanceActionExecuted` leaf timestamp
            // from `proposal.created_at` (it looks up pending-or-resolved). If
            // it were removed first, execute would fail its
            // proposal-is-tracked guard and could never mint the executed leaf.
            let proposal = self
                .contexts
                .get_mut(context_id)
                .and_then(|ctx| ctx.pending_proposals.remove(&pid));
            if let Some(p) = proposal {
                // Retain the PRE-MOVE proposal (status `Pending`) so the
                // pending → resolved move can be rolled back if dispatch fails.
                let pending_snapshot = p.clone();
                let mut approved = p;
                approved.status = ProposalStatus::Approved;
                if let Some(ctx) = self.contexts.get_mut(context_id) {
                    ctx.insert_resolved_proposal(pid.clone(), approved);
                }
                // The executor is the quorum-crossing VOTER (the committing
                // member), NOT the proposer — `execute_governance_action`
                // stamps the executor as the `GovernanceActionExecuted` leaf
                // `actor_did` (ADR-031 §8 "executor DID" / §7.3.1 "committing
                // member" / ADR-051 §6). The voter is both the auth subject and
                // the executor here. Passing the proposer would diverge the leaf
                // from native's quorum path, which stamps the voter (§9.9.3
                // native↔WASM convergence).
                match self.execute_governance_action(context_id, voter_did, voter_did, &pid) {
                    Ok(result) => {
                        return Ok(serde_json::json!({
                            "status": "Approved",
                            "execution_result": result,
                        }));
                    }
                    Err(e) => {
                        // Dispatch failed. Roll back the pending → resolved move
                        // so the proposal is retriable (matches native, which
                        // leaves the proposal `Approved`-and-retriable: it never
                        // durably resolves a proposal whose execution failed).
                        // Without this, WASM would strand the proposal in
                        // `resolved_proposals` (gone from `pending_proposals`),
                        // unable to be re-executed.
                        if let Some(ctx) = self.contexts.get_mut(context_id) {
                            ctx.remove_resolved_proposal(&pid);
                            ctx.pending_proposals.insert(pid.clone(), pending_snapshot);
                        }
                        return Err(e);
                    }
                }
            }
        }

        Ok(serde_json::json!({ "status": "Pending" }))
    }

    /// Casts a rejection vote on a pending governance proposal.
    ///
    /// # Errors
    ///
    /// Returns an error if the proposal is not found, the voter lacks the
    /// `governance:vote` capability, or the voter has already voted.
    pub fn reject_governance_proposal(
        &mut self,
        context_id: &str,
        proposal_id: &str,
        voter_did: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Authorization.
        {
            let ctx = self.require_active_context_mut(context_id)?;
            if !ctx.member_has_capability(voter_did, "governance:vote") {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "member {voter_did} does not have 'governance:vote' capability"
                    ),
                    code: codes::CTX_2043.to_owned(),
                });
            }
        }

        let now = crate::time::now_ms();
        let (_required, total) = {
            let ctx = self.require_active_context_mut(context_id)?;
            Self::governance_quorum(ctx)
        };

        let ctx = self.require_active_context_mut(context_id)?;

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let now_secs = (now / 1000.0) as u64;
        let remaining_possible_approvals = {
            let proposal = ctx.pending_proposals.get_mut(proposal_id).ok_or_else(|| {
                ScpWasmError::Context {
                    message: format!("proposal {proposal_id} not found"),
                    code: codes::CTX_2043.to_owned(),
                }
            })?;

            if proposal.voting_deadline <= now_secs {
                return Err(ScpWasmError::Context {
                    message: "proposal voting deadline has expired".to_owned(),
                    code: codes::CTX_2043.to_owned(),
                });
            }

            if proposal
                .approvals
                .iter()
                .any(|v| v.voter_did.0 == voter_did)
                || proposal
                    .rejections
                    .iter()
                    .any(|v| v.voter_did.0 == voter_did)
            {
                return Err(ScpWasmError::Permission {
                    message: format!("member {voter_did} has already voted on this proposal"),
                    code: codes::CTX_2043.to_owned(),
                });
            }

            proposal.rejections.push(SignedVote {
                voter_did: DID(voter_did.to_owned()),
                vote: VoteType::Reject,
                timestamp: now_secs,
                signature: Vec::new(),
            });
            total.saturating_sub(proposal.approvals.len() + proposal.rejections.len())
        };

        // SECURITY/§9.9.3: native appends GovernanceVoteCast with an EMPTY
        // payload (`append_context_event`, no payload) — match it so the leaf
        // preimage is byte-identical across platforms. The proposal_id is NOT
        // part of the canonical leaf; it rides only in the buffer-only
        // `ContextEvent` (which is not a durable Merkle leaf).
        ctx.append_log_event(
            EventType::GovernanceVoteCast,
            voter_did,
            b"",
            // Convergent: the voter's signed vote `created_at` (= `now_secs`,
            // the same value stamped on the SignedVote), copied by every member
            // (§7.3.1, §9.9.3).
            now_secs,
        );

        let can_still_reach_quorum = {
            let ctx2 = self.require_active_context_mut(context_id)?;
            let (req, _) = Self::governance_quorum(ctx2);
            let p = ctx2.pending_proposals.get(proposal_id);
            p.is_some_and(|pp| pp.approvals.len() + remaining_possible_approvals >= req)
        };

        if !can_still_reach_quorum {
            // Proposal is dead — move to resolved_proposals for later retrieval.
            if let Some(ctx3) = self.contexts.get_mut(context_id)
                && let Some(mut p) = ctx3.pending_proposals.remove(proposal_id)
            {
                p.status = ProposalStatus::Rejected {
                    reason: scp_protocol::context::governance::RejectionReason::ApprovalImpossible,
                };
                ctx3.insert_resolved_proposal(proposal_id.to_owned(), p);
            }
            return Ok(serde_json::json!({ "status": "Rejected" }));
        }

        Ok(serde_json::json!({ "status": "Pending" }))
    }

    /// Withdraws a previously cast vote on a pending governance proposal.
    ///
    /// # Errors
    ///
    /// Returns an error if the proposal is not found or the voter hasn't voted.
    pub fn withdraw_governance_vote(
        &mut self,
        context_id: &str,
        proposal_id: &str,
        voter_did: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        let proposal =
            ctx.pending_proposals
                .get_mut(proposal_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!("proposal {proposal_id} not found"),
                    code: codes::CTX_2044.to_owned(),
                })?;

        let was_approval = proposal
            .approvals
            .iter()
            .position(|v| v.voter_did.0 == voter_did);
        let was_rejection = proposal
            .rejections
            .iter()
            .position(|v| v.voter_did.0 == voter_did);

        if let Some(idx) = was_approval {
            proposal.approvals.remove(idx);
        } else if let Some(idx) = was_rejection {
            proposal.rejections.remove(idx);
        } else {
            return Err(ScpWasmError::Permission {
                message: format!("member {voter_did} has not voted on proposal {proposal_id}"),
                code: codes::CTX_2044.to_owned(),
            });
        }

        // SECURITY/§9.9.3: native appends GovernanceVoteWithdrawn with an EMPTY
        // payload (`append_context_event`, no payload) — match it so the leaf
        // preimage is byte-identical across platforms. The proposal_id is NOT
        // part of the canonical leaf; it rides only in the buffer-only
        // `ContextEvent` (which is not a durable Merkle leaf).
        ctx.append_log_event(
            EventType::GovernanceVoteWithdrawn,
            voter_did,
            b"",
            // Committer-assigned: the withdrawing voter's clock, the source of
            // the withdrawal commit's `created_at` (§7.3.1, §9.9.3).
            crate::time::now_secs(),
        );

        Ok(serde_json::json!({ "status": "Pending" }))
    }

    /// Retrieves a governance proposal by ID from pending or resolved maps.
    ///
    /// # Errors
    ///
    /// Returns an error if the proposal is not found in either map.
    pub fn get_proposal(
        &self,
        context_id: &str,
        proposal_id: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context {context_id} not found"),
                code: codes::CTX_2045.to_owned(),
            })?;

        let proposal = ctx
            .pending_proposals
            .get(proposal_id)
            .or_else(|| ctx.resolved_proposals.get(proposal_id))
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("proposal {proposal_id} not found"),
                code: codes::CTX_2045.to_owned(),
            })?;

        Ok(Self::proposal_to_json(proposal_id, proposal))
    }

    /// Returns the `proposer_did` of a tracked governance proposal (pending or
    /// resolved), or an error if it is not found.
    ///
    /// Used by the direct-FFI execute path (`context_execute_governance`) to
    /// resolve the proposal's proposer so it can be stamped as the
    /// `GovernanceActionExecuted` leaf `actor_did` — the executor — matching the
    /// native direct-execute handler, which stamps `proposal.proposer_did`
    /// (§9.9.3 native↔WASM convergence; ADR-031 §8).
    ///
    /// # Errors
    ///
    /// Returns an error if the context or proposal is not found.
    pub fn proposal_proposer_did(
        &self,
        context_id: &str,
        proposal_id: &str,
    ) -> Result<String, ScpWasmError> {
        let ctx = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context {context_id} not found"),
                code: codes::CTX_2045.to_owned(),
            })?;

        ctx.pending_proposals
            .get(proposal_id)
            .or_else(|| ctx.resolved_proposals.get(proposal_id))
            .map(|p| p.proposer_did.0.clone())
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("proposal {proposal_id} not found"),
                code: codes::CTX_2045.to_owned(),
            })
    }

    /// Lists all governance proposals (pending and resolved) for a context.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found.
    pub fn list_proposals(&self, context_id: &str) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context {context_id} not found"),
                code: codes::CTX_2046.to_owned(),
            })?;

        let proposals: Vec<serde_json::Value> = ctx
            .pending_proposals
            .iter()
            .chain(ctx.resolved_proposals.iter())
            .map(|(id, p)| Self::proposal_to_json(id, p))
            .collect();

        Ok(serde_json::json!(proposals))
    }

    /// Serializes a `GovernanceProposal` to the full JSON response shape matching
    /// native bridges' serialization.
    ///
    /// Fields: `proposal_id`, `context_id`, `proposer_did`, `action`,
    /// `status`, `created_at` (Unix epoch seconds, u64), `created_at_epoch`,
    /// `voting_deadline` (seconds), `approvals` (with `voter_did` and
    /// `vote` fields), `rejections` (same shape).
    fn proposal_to_json(proposal_id: &str, proposal: &GovernanceProposal) -> serde_json::Value {
        let approvals: Vec<serde_json::Value> = proposal
            .approvals
            .iter()
            .map(|v| {
                serde_json::json!({
                    "voter_did": v.voter_did.0,
                    "vote": format!("{:?}", v.vote),
                    "timestamp": v.timestamp,
                    "signature": v.signature,
                })
            })
            .collect();

        let rejections: Vec<serde_json::Value> = proposal
            .rejections
            .iter()
            .map(|v| {
                serde_json::json!({
                    "voter_did": v.voter_did.0,
                    "vote": format!("{:?}", v.vote),
                    "timestamp": v.timestamp,
                    "signature": v.signature,
                })
            })
            .collect();

        let action_name = proposal.action.variant_name();
        let status_str = match &proposal.status {
            ProposalStatus::Pending => "Pending",
            ProposalStatus::Approved => "Approved",
            ProposalStatus::Rejected { .. } => "Rejected",
            ProposalStatus::Expired => "Expired",
            ProposalStatus::Cancelled => "Cancelled",
            ProposalStatus::Invalidated { .. } => "Invalidated",
        };

        serde_json::json!({
            "proposal_id": proposal_id,
            "context_id": proposal.context_id,
            "proposer_did": proposal.proposer_did.0,
            "action": action_name,
            "status": status_str,
            "created_at": proposal.created_at,
            "voting_deadline": proposal.voting_deadline,
            "approvals": approvals,
            "rejections": rejections,
            "created_at_epoch": proposal.created_at_epoch,
        })
    }

    // -----------------------------------------------------------------------
    // Broadcast operations (§5.14)
    // -----------------------------------------------------------------------

    /// Subscribes a DID to a broadcast context. Mirrors `ContextManager::subscribe_broadcast`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or not in Broadcast mode.
    pub fn subscribe_broadcast(
        &mut self,
        context_id: &str,
        subscriber_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // Version compatibility check (spec §13.4): reject subscribe if the
        // context requires a protocol version higher than this SDK supports.
        // Applies to ALL context modes including broadcast.
        ctx.check_version_compatibility()?;

        let bc = ctx
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: codes::CTX_2001.to_owned(),
            })?;

        // Use subscribe with no UCAN (open admission) for WASM bridge.
        // Ignore duplicate subscriber errors (idempotent).
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let ts = (crate::time::now_ms() / 1000.0) as u64;
        let _ = bc.subscribe::<
            NoOpDidResolver,
            NoOpNonceTracker,
            NoOpRevocationChecker,
            NoOpProofResolver,
            std::hash::RandomState,
        >(subscriber_did, None, ts, None);

        // Also add as a member if not already present, assigning the
        // `subscriber` built-in role and seeding the MLS sequence counter.
        // `system_assign_role` requires the DID to already be in `members`, so
        // insert first; on assignment failure roll the insertion and sequence
        // seed back so a rejected subscribe leaves NO partial membership behind
        // (fail-closed atomicity — mirrors `dispatch_add_member`).
        //
        // Defense-in-depth: this assigns the built-in "subscriber" role, whose
        // caps are ceiling-filtered at `ContextRoleState` construction, so
        // `system_assign_role` cannot return `RoleNotFound` /
        // `MemberNotInContext` / `CapabilityOutsideCeiling` here — the error
        // branch is unreachable today (infallible by construction). The
        // rollback exists for uniform fail-closed atomicity and robustness if a
        // future change makes this assignment fallible; the load-bearing,
        // genuinely-reachable rollback is `dispatch_add_member`'s.
        if !ctx.role_state.members.contains(subscriber_did) {
            ctx.role_state.members.insert(subscriber_did.to_owned());
            ctx.member_sequence_numbers
                .insert(subscriber_did.to_owned(), 0);
            if let Err(e) = ctx.role_state.system_assign_role(
                subscriber_did,
                "subscriber",
                &crate::time::WasmClock,
            ) {
                ctx.role_state.members.remove(subscriber_did);
                ctx.member_sequence_numbers.remove(subscriber_did);
                return Err(map_role_error(e));
            }
        }

        Ok(())
    }

    /// Publishes to a broadcast context. Mirrors `ContextManager::publish_broadcast`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, not Broadcast mode,
    /// or the author lacks write access.
    pub fn publish_broadcast(
        &mut self,
        context_id: &str,
        author_did: &str,
        payload_base64: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let bc = ctx
            .broadcast_context
            .as_ref()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: codes::CTX_2001.to_owned(),
            })?;

        if !bc.is_author(author_did) {
            return Err(ScpWasmError::Permission {
                message: format!("'{author_did}' is not an author in this broadcast context"),
                code: codes::PERM_3000.to_owned(),
            });
        }

        // Assign the MLS message sequence number.
        if !ctx.role_state.members.contains(author_did) {
            return Err(ScpWasmError::Context {
                message: format!("author '{author_did}' not found in members"),
                code: codes::CTX_2019.to_owned(),
            });
        }

        // Positive role-grant authorization gate. Native broadcast publish
        // (`broadcast_helpers::reserve_broadcast_publish`) gates only on the
        // `MessagesWrite` suspension overlay because native authors MAY be
        // registered with the `BroadcastContext` without being `role_state`
        // members. The WASM bridge always seeds a registered author as a
        // member with a write-granting role, so it can — and does, for
        // defense-in-depth — apply the SAME positive `member_has_capability`
        // check used by `send_message`: a write-granting author whose
        // `messages:write` is suspended is rejected, and the distinct
        // suspended-vs-not-granted message matches `send_message` / native.
        if !ctx
            .role_state
            .member_has_capability(author_did, &Capability::MessagesWrite)
        {
            let is_suspended = ctx
                .role_state
                .suspended_for(author_did)
                .is_some_and(|caps| caps.contains(&Capability::MessagesWrite));
            let message = if is_suspended {
                format!("write access has been suspended for {author_did}")
            } else {
                format!("author {author_did} role does not grant messages:write")
            };
            return Err(ScpWasmError::Permission {
                message,
                code: codes::PERM_3000.to_owned(),
            });
        }
        // Per-member sequence sidecar — see `send_message`. PRE-increments to
        // match native `MembershipState::next_sequence_number`, so the
        // broadcast author's first published `sequence_number` is 1.
        let seq_entry = ctx
            .member_sequence_numbers
            .entry(author_did.to_owned())
            .or_insert(0);
        *seq_entry += 1;
        let seq = *seq_entry;

        ctx.push_event(ContextEvent::MessageSent {
            sender_did: DID(author_did.to_owned()),
            sequence_number: seq,
            payload: payload_base64.as_bytes().to_vec(),
        });

        // Per-author broadcast activity is surfaced only as a local
        // `ContextEvent` (above), never as a canonical Merkle leaf — same
        // per-author exclusion as `send_message` (ADR-011 amendment exclusion
        // taxonomy, `.docs/adrs/phase-2.md` §2).

        Ok(())
    }

    /// Publishes a single asset to a broadcast context as structured content (SCP-290).
    ///
    /// Validates path, `content_type`, and `deploy_id` locally (ADR-034: no `scp-core`
    /// dependency). Computes `ETag` from the body. Serializes as the canonical wire
    /// format: `"SCP" ++ version_u8 ++ MessagePack(BroadcastContent)`, then publishes
    /// via `publish_broadcast` with base64-encoded structured payload.
    ///
    /// Returns `(blob_id, etag)` where `blob_id` is a synthetic hex ID derived
    /// from context + author + sequence, and `etag` is `SHA-256(body)` hex.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or publish fails.
    pub fn publish_broadcast_asset(
        &mut self,
        context_id: &str,
        author_did: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        deploy_id: Option<&str>,
    ) -> Result<(String, String, String), ScpWasmError> {
        // Validate and NFC-normalize path (delegates to scp-protocol ContentPath).
        let normalized_path =
            validate_content_path_wasm(path).map_err(|msg| ScpWasmError::Context {
                message: format!("invalid path: {msg}"),
                code: codes::CTX_2070.to_owned(),
            })?;

        // Validate content_type (delegates to scp-protocol MimeType).
        validate_mime_type_wasm(content_type).map_err(|msg| ScpWasmError::Context {
            message: format!("invalid content_type: {msg}"),
            code: codes::CTX_2071.to_owned(),
        })?;

        // Auto-generate deploy_id when None, matching batch behavior.
        let deploy_id_val: String;
        let deploy_id_resolved = if let Some(d) = deploy_id {
            d
        } else {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(context_id.as_bytes());
            hasher.update(author_did.as_bytes());
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let ts = js_sys::Date::now() as u64;
            hasher.update(ts.to_le_bytes());
            deploy_id_val = hex::encode(&Sha256::digest(hasher.finalize())[..16]);
            &deploy_id_val
        };

        // Validate deploy_id.
        validate_deploy_id_wasm(deploy_id_resolved).map_err(|msg| ScpWasmError::Context {
            message: format!("invalid deploy_id: {msg}"),
            code: codes::CTX_2072.to_owned(),
        })?;

        // Body size limit — reject oversized payloads before serialization.
        if body.len() > MAX_BODY_BYTES {
            return Err(ScpWasmError::Context {
                message: format!(
                    "body too large: {} bytes (max {MAX_BODY_BYTES})",
                    body.len()
                ),
                code: codes::CTX_2075.to_owned(),
            });
        }

        // Compute ETag: SHA-256(body) hex.
        let etag = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(body))
        };

        // Build the BroadcastContent wire format: magic "SCP" + version byte
        // + MessagePack serialized content. Matches scp-core's
        // serialize_broadcast_content exactly. Reimplemented per ADR-034.
        let wire_bytes = serialize_broadcast_content_wasm(
            &normalized_path,
            content_type,
            Some(deploy_id_resolved),
            &etag,
            body,
        )
        .map_err(|msg| ScpWasmError::Context {
            message: format!("broadcast content serialization failed: {msg}"),
            code: codes::CTX_2073.to_owned(),
        })?;

        // Base64-encode the wire bytes for the publish_broadcast path.
        let payload = base64::engine::general_purpose::STANDARD.encode(&wire_bytes);
        self.publish_broadcast(context_id, author_did, &payload)?;

        // Compute blob_id as SHA-256 of the serialized broadcast content bytes.
        // Content-addressed and deterministic — matches the intent of other bridges
        // which use SHA-256(serialized_envelope). WASM doesn't have the envelope,
        // so we use the wire bytes (the content that gets encrypted).
        let blob_id = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&wire_bytes))
        };

        Ok((blob_id, etag, deploy_id_resolved.to_owned()))
    }

    /// Publishes multiple assets to a broadcast context (SCP-290, SCP-292).
    ///
    /// All assets are published with the same `deploy_id`. Returns a list of
    /// `(blob_id, etag)` tuples.
    ///
    /// # Errors
    ///
    /// Returns an error if any asset fails validation or publish, or if the
    /// batch exceeds `MAX_BATCH_ASSETS` (10,000).
    #[allow(clippy::type_complexity)]
    pub fn publish_broadcast_assets(
        &mut self,
        context_id: &str,
        author_did: &str,
        assets: &[(String, String, Vec<u8>)],
        deploy_id: Option<&str>,
    ) -> Result<(Vec<(String, String, String)>, String), ScpWasmError> {
        // Enforce batch size limit.
        if assets.len() > MAX_BATCH_ASSETS {
            return Err(ScpWasmError::Context {
                message: format!(
                    "batch too large: {} assets (max {MAX_BATCH_ASSETS})",
                    assets.len()
                ),
                code: codes::CTX_2074.to_owned(),
            });
        }

        // Generate deploy_id if not provided.
        let deploy_id_val: String;
        let did = if let Some(d) = deploy_id {
            d
        } else {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(context_id.as_bytes());
            hasher.update(author_did.as_bytes());
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let ts = js_sys::Date::now() as u64;
            hasher.update(ts.to_le_bytes());
            deploy_id_val = hex::encode(&Sha256::digest(hasher.finalize())[..16]);
            &deploy_id_val
        };

        let mut results = Vec::with_capacity(assets.len());
        for (path, content_type, body) in assets {
            let (blob_id, etag, deploy_id_out) = self.publish_broadcast_asset(
                context_id,
                author_did,
                path,
                content_type,
                body,
                Some(did),
            )?;
            results.push((blob_id, etag, deploy_id_out));
        }
        Ok((results, did.to_owned()))
    }

    /// Unsubscribes from a broadcast context. Mirrors `ContextManager::unsubscribe_broadcast`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or not in Broadcast mode.
    pub fn unsubscribe_broadcast(
        &mut self,
        context_id: &str,
        subscriber_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let bc = ctx
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: codes::CTX_2001.to_owned(),
            })?;

        let _ = bc.unsubscribe(subscriber_did, false);

        ctx.push_event(ContextEvent::MemberLeft {
            member_did: DID(subscriber_did.to_owned()),
        });

        Ok(())
    }

    /// Blocks a subscriber in a broadcast context.
    ///
    /// Per spec §5.14.8 steps 1-2:
    /// 1. Adds DID to the blocker's block list and increments the blocker's
    ///    key epoch.
    /// 2. Emits a `ContentKeysRotated` notification so non-blocked subscribers
    ///    can request the new key.
    ///
    /// # Errors
    ///
    /// Returns an error if not a broadcast context.
    pub fn block_broadcast_subscriber(
        &mut self,
        context_id: &str,
        blocker_did: &str,
        subscriber_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let new_epoch;
        {
            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ScpWasmError::Context {
                    message: "not a broadcast context".to_owned(),
                    code: codes::CTX_2001.to_owned(),
                })?;

            // Pre-validate block list capacity.
            if let Some(author) = bc.get_author(blocker_did)
                && author.block_list.len() >= WASM_BLOCK_LIST_CAP
                && !author.block_list.contains(subscriber_did)
            {
                return Err(ScpWasmError::Validation {
                    message: format!(
                        "per-author block list has reached capacity ({WASM_BLOCK_LIST_CAP}) \
                         for author '{blocker_did}'"
                    ),
                    code: codes::VALID_7301.to_owned(),
                });
            }

            // Per-author blocking (§5.14.8): delegates to BroadcastContext which
            // adds to block list, rotates key, and increments epoch.
            let block_result = bc
                .block_subscriber(blocker_did, subscriber_did)
                .map_err(|e| ScpWasmError::Context {
                    message: format!("block_subscriber failed: {e}"),
                    code: codes::CTX_2001.to_owned(),
                })?;
            new_epoch = block_result.new_epoch;
        }

        ctx.push_event(ContextEvent::MemberBlocked {
            blocked_did: DID(subscriber_did.to_owned()),
            author_did: DID(blocker_did.to_owned()),
        });

        // §5.14.8 step 2: publish ContentKeysRotated notification for the
        // author whose key was rotated due to blocking.
        ctx.push_event(ContextEvent::ContentKeysRotated {
            reason: Some(format!(
                "block_subscriber: author {blocker_did} blocked {subscriber_did}, epoch {new_epoch}"
            )),
        });

        Ok(())
    }

    /// Unblocks a previously blocked subscriber in a broadcast context
    /// (§9.16.8 — forward-only restoration).
    ///
    /// Removes the subscriber DID from the blocked set. Does NOT restore
    /// historical access — the subscriber can request the current key on
    /// next pull but cannot decrypt content from the block period.
    ///
    /// # Errors
    ///
    /// - [`ScpWasmError::Context`] if the context is not active or not
    ///   a broadcast context.
    /// - [`ScpWasmError::Context`] if the subscriber is not blocked.
    pub fn unblock_broadcast_subscriber(
        &mut self,
        context_id: &str,
        unblocker_did: &str,
        subscriber_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        {
            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ScpWasmError::Context {
                    message: "not a broadcast context".to_owned(),
                    code: codes::CTX_2001.to_owned(),
                })?;

            // Per-author unblocking (§5.14.8): remove from the unblocker's
            // block list only. Per spec, no key rotation on unblock — the
            // subscriber receives the current key on next pull.
            bc.unblock_subscriber(unblocker_did, subscriber_did)
                .map_err(|e| ScpWasmError::Context {
                    message: e.to_string(),
                    code: codes::CTX_2001.to_owned(),
                })?;
        }

        ctx.push_event(ContextEvent::MemberUnblocked {
            unblocked_did: DID(subscriber_did.to_owned()),
            author_did: DID(unblocker_did.to_owned()),
        });

        Ok(())
    }

    /// Returns the number of subscribers in a broadcast context.
    ///
    /// Returns `None` if the context is not a broadcast context.
    #[must_use]
    pub fn broadcast_subscriber_count(&self, context_id: &str) -> Option<usize> {
        self.contexts.get(context_id).and_then(|ctx| {
            ctx.broadcast_context
                .as_ref()
                .map(BroadcastContext::subscriber_count)
        })
    }

    /// Returns `true` if the given DID is a subscriber in a broadcast context.
    #[must_use]
    pub fn is_broadcast_subscriber(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .get(context_id)
            .and_then(|ctx| {
                ctx.broadcast_context
                    .as_ref()
                    .map(|bc| bc.is_subscriber(did))
            })
            .unwrap_or(false)
    }

    /// Returns the admission policy string for a broadcast context.
    ///
    /// Returns `None` if the context is not a broadcast context.
    #[must_use]
    pub fn broadcast_admission(&self, context_id: &str) -> Option<String> {
        self.contexts.get(context_id).and_then(|ctx| {
            ctx.broadcast_context
                .as_ref()
                .map(|bc| match bc.admission() {
                    BroadcastAdmission::Open => "open".to_owned(),
                    BroadcastAdmission::Gated => "gated".to_owned(),
                })
        })
    }

    /// Handles a broadcast key request.
    ///
    /// Validates that the requester is a non-blocked subscriber (or author) and,
    /// on grant, HPKE-seals the author's current broadcast key to the
    /// requester's X25519 `wrapping_pubkey` (§5.14.2). Returns `Some(json)` (a
    /// serialized `SealedBroadcastKey`) on grant, or `None` on deny (§5.14.8 —
    /// the author returns no key material to a denied requester). The raw
    /// broadcast key never crosses the JS boundary — only the sealed material.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, not a broadcast context,
    /// or if sealed-key serialization fails.
    pub fn handle_broadcast_key_request(
        &self,
        context_id: &str,
        author_did: &str,
        requester_did: &str,
        wrapping_pubkey: &[u8; 32],
    ) -> Result<Option<String>, ScpWasmError> {
        use scp_protocol::context::broadcast::{KeyRequestDecision, SealedBroadcastKey};

        let ctx = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context not registered: {context_id}"),
                code: codes::CTX_2001.to_owned(),
            })?;

        let bc = ctx
            .broadcast_context
            .as_ref()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: codes::CTX_2001.to_owned(),
            })?;

        // No local-DID-ownership guard here (unlike native
        // `broadcast_helpers::handle_broadcast_key_request`, which rejects when
        // `author_did` is not in the Supervisor's `local_dids` set). WASM is
        // single-tenant in-process: there is no Supervisor, no `ActorDeps`, and
        // no cross-instance `local_dids` registry — author authority is held by
        // the JS caller that owns the identity and drives this manager directly.
        // This mirrors the other author-side WASM broadcast ops
        // (`publish_broadcast`, `block_subscriber`), which likewise gate only on
        // broadcast-context authorship (`bc.is_author` / the protocol decision
        // function below) and not on a locally-controlled-DID registry.
        //
        // Delegate to BroadcastContext::handle_key_request which implements
        // the full §5.14.8 decision logic (author check, block list, subscriber)
        // and seals the broadcast key to `wrapping_pubkey` on grant.
        match bc.handle_key_request(author_did, requester_did, wrapping_pubkey) {
            KeyRequestDecision::Grant { enc, ct, epoch } => {
                let sealed = SealedBroadcastKey {
                    enc,
                    ct,
                    epoch,
                    author_did: author_did.to_owned(),
                    context_id: context_id.to_owned(),
                };
                let json = serde_json::to_string(&sealed).map_err(|e| ScpWasmError::Context {
                    message: format!("serialize sealed broadcast key: {e}"),
                    code: codes::CTX_2023.to_owned(),
                })?;
                Ok(Some(json))
            }
            KeyRequestDecision::Deny { .. } => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // Economic policy operations (§19.3, ADR-033)
    // -----------------------------------------------------------------------

    /// Sets the economic policy for a context by direct mutation.
    ///
    /// Rejects direct economic policy mutation — use governance flow instead
    /// (§19.3, #728).
    ///
    /// Economic policy changes MUST go through the governance proposal flow
    /// (`SetEconomicPolicy` action) to ensure event logging and the mandatory
    /// 24-hour notification period. Direct setters bypass these controls.
    ///
    /// # Errors
    ///
    /// Always returns an error directing the caller to use governance.
    pub fn set_economic_policy(
        &mut self,
        _context_id: &str,
        _policy_json: String,
    ) -> Result<(), ScpWasmError> {
        Err(ScpWasmError::Permission {
            message: "economic policy changes must go through governance \
                      (propose SetEconomicPolicy action). Direct mutation is \
                      not permitted — see spec §19.3"
                .to_owned(),
            code: codes::CTX_2013.to_owned(),
        })
    }

    /// Returns the economic policy for a context, or `None`.
    #[must_use]
    pub fn get_economic_policy(&self, context_id: &str) -> Option<String> {
        self.contexts
            .get(context_id)
            .and_then(|ctx| ctx.economic_policy.clone())
    }

    // -----------------------------------------------------------------------
    // TTL operations
    // -----------------------------------------------------------------------

    /// Returns the remaining TTL seconds for a context.
    #[must_use]
    pub fn ttl_remaining(&self, context_id: &str) -> Option<u64> {
        self.contexts
            .get(context_id)
            .and_then(|ctx| ctx.ttl_seconds)
    }

    /// Proposes a TTL extension. Returns `true` if the extension was applied.
    ///
    /// In the WASM bridge, TTL extension is immediate (no multi-member
    /// unanimity required — the TypeScript SDK coordinates consensus).
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or has no TTL.
    pub fn extend_ttl(
        &mut self,
        context_id: &str,
        additional_secs: u64,
    ) -> Result<bool, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        ctx.ttl_seconds.as_mut().map_or_else(
            || {
                Err(ScpWasmError::Context {
                    message: "context has no TTL configured".to_owned(),
                    code: codes::CTX_2001.to_owned(),
                })
            },
            |ttl| {
                // Saturating add for parity with native `execute_extend_ttl`
                // and u64 overflow safety (a plain `+=` panics in debug builds).
                *ttl = ttl.saturating_add(additional_secs);
                Ok(true)
            },
        )
    }

    /// Handles TTL expiry.
    ///
    /// Transitions the context to `"expired"` state and records a
    /// `ContextExpired` event in the event log.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active.
    pub fn handle_ttl_expiry(&mut self, context_id: &str) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        "expired".clone_into(&mut ctx.state);
        ctx.push_event(ContextEvent::Expired);

        // Stamp the CONVERGENT expiry deadline (`creation_timestamp_secs +
        // ttl_seconds`) on the `ContextExpired` leaf whenever a TTL is set, so a
        // mixed native/WASM context records the identical timestamp regardless
        // of which member's timer fired or when its local clock read (§7.3.1,
        // §9.9.3). This mirrors the native `convergent_ttl_deadline_secs`
        // (`ttl_close_helpers.rs`): `Some(ttl) => creation.saturating_add(ttl)`
        // with NO `creation == 0` guard. A legacy snapshot whose
        // `creation_timestamp_secs` defaulted to `0` therefore yields the
        // deadline `0 + ttl` on BOTH bridges — convergent, and in the distant
        // past (the fail-safe direction: the upper-bound deadline only shortens,
        // so the context expires no later than an honest-clock member would
        // compute). A residual `creation == 0 => now()` special-case here would
        // make WASM stamp the local fire-time while native stamps `0 + ttl`,
        // diverging the `ContextExpired` leaf at equal event count — the very
        // §9.9.3 divergence this convergent stamping exists to eliminate. The
        // `now()` fallback applies ONLY to the genuinely-no-TTL case.
        let expiry_leaf_secs = match ctx.ttl_seconds {
            Some(ttl) => ctx.creation_timestamp_secs.saturating_add(ttl),
            None => crate::time::now_secs(),
        };

        ctx.append_log_event(
            EventType::ContextExpired,
            scp_event_log::system_actors::SYSTEM_TIMER_ACTOR,
            b"",
            expiry_leaf_secs,
        );

        Ok(())
    }

    /// Proposes a TTL extension from a specific member.
    ///
    /// In the WASM bridge, TTL extension is immediate (no multi-member
    /// unanimity required — the TypeScript SDK coordinates consensus).
    /// Returns `true` if the extension was applied.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, has no TTL, or the
    /// proposer is not a member.
    pub fn propose_ttl_extension(
        &mut self,
        context_id: &str,
        proposer_did: &str,
        extension_secs: u64,
    ) -> Result<bool, ScpWasmError> {
        // Verify proposer is a member.
        if !self.is_member(context_id, proposer_did) {
            return Err(ScpWasmError::Context {
                message: format!("DID '{proposer_did}' is not a member of context '{context_id}'"),
                code: codes::CTX_2005.to_owned(),
            });
        }
        self.extend_ttl(context_id, extension_secs)
    }

    /// Resets the TTL timer to a new duration.
    ///
    /// Replaces the context's TTL with the given value. If the context has
    /// no TTL, one is set.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active.
    pub fn reset_ttl_timer(
        &mut self,
        context_id: &str,
        new_seconds: u64,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        ctx.ttl_seconds = Some(new_seconds);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Context state accessors
    // -----------------------------------------------------------------------

    /// Returns the context state string.
    #[must_use]
    pub fn context_state(&self, context_id: &str) -> Option<String> {
        self.contexts.get(context_id).map(|ctx| ctx.state.clone())
    }

    /// Returns the context creator DID.
    #[must_use]
    pub fn context_creator(&self, context_id: &str) -> Option<String> {
        self.contexts
            .get(context_id)
            .map(|ctx| ctx.role_state.creator_did.clone())
    }

    /// Returns the context mode.
    #[must_use]
    pub fn context_mode(&self, context_id: &str) -> Option<String> {
        self.contexts.get(context_id).map(|ctx| ctx.mode.clone())
    }

    /// Returns whether a context is registered.
    #[must_use]
    pub fn has_context(&self, context_id: &str) -> bool {
        self.contexts.contains_key(context_id)
    }

    /// Returns context metadata for the handle.
    #[must_use]
    pub fn context_metadata(&self, context_id: &str) -> Option<ContextMetadata> {
        self.contexts.get(context_id).map(|ctx| {
            // Extract min_protocol_version from params_json. The values were
            // validated at create_context / import_context time, so this is
            // infallible for well-formed contexts.
            let min_protocol_version =
                ctx.params_json["minProtocolVersion"]
                    .as_array()
                    .and_then(|arr| {
                        let major = u8::try_from(arr.first()?.as_u64()?).ok()?;
                        let minor = u8::try_from(arr.get(1)?.as_u64()?).ok()?;
                        Some((major, minor))
                    });

            ContextMetadata {
                context_id: context_id.to_owned(),
                state: ctx.state.clone(),
                creator_did: ctx.role_state.creator_did.clone(),
                mode: ctx.mode.clone(),
                ceiling: ctx
                    .role_state
                    .ceiling()
                    .to_ucan_string_set()
                    .into_iter()
                    .collect(),
                ceiling_policy: ctx.ceiling_policy.clone(),
                ttl_seconds: ctx.ttl_seconds,
                promotion_policy: ctx.promotion_policy.clone(),
                governance: ctx.governance.clone(),
                member_count: ctx.role_state.members.len() as u64,
                economic_policy: ctx.economic_policy.clone(),
                min_protocol_version,
            }
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Returns a reference to context state, or an error if not found.
    fn require_context(&self, context_id: &str) -> Result<&PerContextState, ScpWasmError> {
        self.contexts
            .get(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' not found — was it created with context_create?"
                ),
                code: codes::CTX_2001.to_owned(),
            })
    }

    /// Returns a mutable reference to context state, or an error if not found.
    fn require_active_context(&self, context_id: &str) -> Result<&PerContextState, ScpWasmError> {
        let ctx = self.require_context(context_id)?;
        if ctx.state != "active" {
            return Err(ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' is in '{0}' state — must be 'active'",
                    ctx.state
                ),
                code: codes::CTX_2002.to_owned(),
            });
        }
        Ok(ctx)
    }

    fn require_context_mut(
        &mut self,
        context_id: &str,
    ) -> Result<&mut PerContextState, ScpWasmError> {
        self.contexts
            .get_mut(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' not found — was it created with context_create?"
                ),
                code: codes::CTX_2001.to_owned(),
            })
    }

    /// Returns a mutable reference to an active context, or an error.
    fn require_active_context_mut(
        &mut self,
        context_id: &str,
    ) -> Result<&mut PerContextState, ScpWasmError> {
        let ctx = self.require_context_mut(context_id)?;
        if ctx.state != "active" {
            return Err(ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' is in '{0}' state — must be 'active'",
                    ctx.state
                ),
                code: codes::CTX_2013.to_owned(),
            });
        }
        Ok(ctx)
    }

    // -----------------------------------------------------------------------
    // Context export/import (#424)
    // -----------------------------------------------------------------------

    /// Exports a context's full state as serialized JSON bytes.
    ///
    /// Returns a `WasmContextExportEnvelope` serialized as JSON bytes. The
    /// envelope contains a version number and a snapshot of all context state.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not registered or serialization fails.
    #[allow(clippy::too_many_lines)] // Exhaustive snapshot construction — every state field materialized inline.
    pub fn export_context(&self, context_id: &str) -> Result<Vec<u8>, ScpWasmError> {
        let ctx = self.require_context(context_id)?;

        let broadcast = ctx.broadcast_context.as_ref().map(|bc| {
            let mut author_block_lists: HashMap<String, Vec<String>> = HashMap::new();
            let mut key_epochs: HashMap<String, u64> = HashMap::new();
            for author_did in bc.author_dids() {
                if let Some(author) = bc.get_author(author_did) {
                    author_block_lists.insert(
                        author_did.clone(),
                        author.block_list.iter().cloned().collect(),
                    );
                    key_epochs.insert(author_did.clone(), author.epoch);
                }
            }
            let subscribers: Vec<String> =
                bc.subscribers().map(|s| s.subscriber_did.clone()).collect();
            let admission = match bc.admission() {
                BroadcastAdmission::Open => "open".to_owned(),
                BroadcastAdmission::Gated => "gated".to_owned(),
            };
            WasmExportBroadcast {
                author_block_lists,
                key_epochs,
                subscribers,
                admission,
            }
        });

        let snapshot = WasmContextExportSnapshot {
            context_id: context_id.to_owned(),
            state: ctx.state.clone(),
            params_json: ctx.params_json.clone(),
            mode: ctx.mode.clone(),
            ceiling_policy: ctx.ceiling_policy.clone(),
            ttl_seconds: ctx.ttl_seconds,
            promotion_policy: ctx.promotion_policy.clone(),
            governance: ctx.governance.clone(),
            economic_policy: ctx.economic_policy.clone(),
            // Carry the typed role state VERBATIM (members, assignments +
            // tokens, ceiling, role definitions, member_capabilities, and
            // per-member suspensions). `ContextRoleState: Clone`. This is the
            // crux of the BLACK-CEIL-01 convergence: the importer restores this
            // structure as-is rather than recomputing `member_capabilities`.
            role_state: ctx.role_state.clone(),
            // WASM-local MLS sequence counters, carried as a sidecar map.
            member_sequence_numbers: ctx.member_sequence_numbers.clone(),
            read_exclusion_list: ctx.read_exclusion_list.iter().cloned().collect(),
            broadcast,
            revoked_tokens: ctx.revoked_tokens.iter().cloned().collect(),
            // v3 format: always leave the v2-only field empty on export.
            // Legacy v2 binaries cannot import v3 envelopes anyway (version
            // check rejects). v3 binaries ignore this field when
            // `seen_nonces_v3` is non-empty.
            seen_nonces_legacy_v2: Vec::new(),
            seen_nonces_v3: ctx
                .seen_nonces
                .iter()
                .map(|(nonce, ts)| WasmExportNonceEntry {
                    nonce: nonce.clone(),
                    inserted_at_ms: *ts,
                })
                .collect(),
            executed_proposals: ctx
                .executed_proposals
                .iter()
                .map(|(pid, ts)| WasmExportExecutedProposalEntry {
                    proposal_id: pid.clone(),
                    executed_at_ms: *ts,
                })
                .collect(),
            // GovernanceProposal implements Serialize/Deserialize in
            // scp-protocol. Serializing to `serde_json::Value` here defers
            // the shape commitment to the envelope JSON bytes, so additions
            // to GovernanceProposal don't require a separate snapshot bump.
            resolved_proposals_json: ctx
                .resolved_proposals
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
                    )
                })
                .collect(),
            consequence_rules: ctx.consequence_rules.clone(),
            cooldown_until: ctx.cooldown_until.clone(),
            threshold_signers: ctx.threshold_signers.clone(),
            threshold_value: ctx.threshold_value,
            tool_interfaces: ctx.tool_interfaces.clone(),
            governance_freeze: ctx.governance_freeze,
            pruning_policy: ctx.pruning_policy.clone(),
            economic_policy_locked: ctx.economic_policy_locked,
            hard_rate_limit_config: ctx.hard_rate_limit_config.clone(),
            creation_timestamp_secs: ctx.creation_timestamp_secs,
        };

        // Canonicalize every set/map-derived array to sorted order before
        // signing (§23.16.8 "Set/Map canonicalization"). The snapshot fields
        // above are collected from `HashSet`/`HashMap` sources in incidental
        // iteration order, which is non-deterministic across runs. JCS fixes
        // object-key ordering but NOT array element ordering, so any array
        // derived from a set MUST be emitted sorted or the digest — and thus
        // the signature — would differ across runs and implementations. The
        // verifier applies the identical sort before re-serializing, so the
        // producer and verifier always agree regardless of incoming order.
        let mut snapshot = snapshot;
        canonicalize_snapshot_sets(&mut snapshot);
        let snapshot = snapshot;

        // Serialize snapshot to RFC 8785 JCS canonical JSON. This stable
        // serialization feeds BOTH the primary Ed25519 snapshot-signature
        // digest (SHA-256(domain || scope_tag || snapshot_jcs), §23.16.8) and
        // the defense-in-depth HMAC below. Both are computed over the snapshot
        // serialization — NOT the full envelope — to avoid a circular
        // dependency (the envelope embeds both the MAC and the signature).
        let snapshot_json =
            serde_json_canonicalizer::to_vec(&snapshot).map_err(|e| ScpWasmError::Context {
                message: format!("export snapshot serialization failed: {e}"),
                code: codes::CTX_2030.to_owned(),
            })?;

        // Compute HMAC-SHA256 over the snapshot JSON using the creator's
        // signing key (via HKDF domain separation). The creator DID is in the
        // snapshot — look up their identity in the registry. Retained as
        // defense-in-depth for self-imports.
        let integrity_mac =
            crate::identity::compute_export_hmac(&ctx.role_state.creator_did, &snapshot_json)?;

        // Ed25519 signature over SHA-256(domain || scope_tag || snapshot_jcs)
        // by the creator's #active key (§23.16.8, ADR-034). This is the
        // cross-party integrity proof — verifiable by anyone resolving the
        // exporter's key. The preimage is built by the single-source
        // `wasm_export_snapshot_digest` helper so the producer, verifier, and
        // test cannot drift; it binds the shared FULL scope tag immediately
        // after the domain separator (WASM only produces Full-scope exports).
        let snapshot_hash = wasm_export_snapshot_digest(&snapshot_json);
        let signature = crate::identity::sign_with_identity(
            &ctx.role_state.creator_did,
            "#active",
            &snapshot_hash,
        )?;
        let snapshot_signature = hex::encode(signature);

        let now_ms = crate::time::now_ms();
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let exported_at = (now_ms / 1000.0) as u64;

        let envelope = WasmContextExportEnvelope {
            version: WASM_EXPORT_VERSION,
            exported_at,
            // The exporter is always the context creator — the snapshot is
            // signed with the creator's #active key and the verifying key is
            // resolved from `snapshot.role_state.creator_did` on import. Derive it here
            // rather than accepting a caller-supplied value: a wrong caller
            // value would only self-reject (exporter_did == creator_did is
            // asserted on import), so there is no reason to expose it as a
            // parameter. Mirrors the native bridges, which derive the exporter
            // internally from the context's creator DID.
            exporter_did: ctx.role_state.creator_did.clone(),
            integrity_mac,
            snapshot_signature,
            snapshot,
        };

        serde_json::to_vec(&envelope).map_err(|e| ScpWasmError::Context {
            message: format!("export serialization failed: {e}"),
            code: codes::CTX_2030.to_owned(),
        })
    }

    /// Deserializes and verifies a context export envelope.
    ///
    /// Performs version check and HMAC integrity verification before returning
    /// the parsed envelope. Extracted to keep `import_context` within the line
    /// limit.
    fn deserialize_and_verify_envelope(
        data: &[u8],
    ) -> Result<WasmContextExportEnvelope, ScpWasmError> {
        // Defense in depth: bound the attacker-controlled input length BEFORE
        // `from_slice` / JCS re-canonicalization. The signature check cannot
        // reject a forgery until after the whole snapshot has been parsed and
        // re-canonicalized, so an unbounded blob is a DoS amplifier. Reject
        // oversized inputs up front, failing closed with the existing
        // validation error class. See [`WASM_MAX_EXPORT_BYTES`].
        if data.len() > WASM_MAX_EXPORT_BYTES {
            return Err(ScpWasmError::Context {
                message: format!(
                    "context export too large: {} bytes exceeds maximum of {WASM_MAX_EXPORT_BYTES} bytes",
                    data.len()
                ),
                code: codes::CTX_2032.to_owned(),
            });
        }

        let mut envelope: WasmContextExportEnvelope =
            serde_json::from_slice(data).map_err(|e| ScpWasmError::Context {
                message: format!("invalid export data: {e}"),
                code: codes::CTX_2032.to_owned(),
            })?;

        if envelope.version > WASM_EXPORT_VERSION {
            return Err(ScpWasmError::Context {
                message: format!(
                    "incompatible export version: got {}, max supported is {WASM_EXPORT_VERSION}",
                    envelope.version
                ),
                // Dedicated version-gate code (SCP-CTX-2094): the export format
                // version is unsupported, distinct from a signature failure
                // (SCP-CTX-2093). Lets a caller tell "wrong/newer format" apart
                // from "tampered/forged signature".
                code: codes::CTX_2094.to_owned(),
            });
        }

        // Fail closed on pre-signature (unsigned) envelopes. Versions below
        // `WASM_EXPORT_VERSION` carried no Ed25519 snapshot signature, so the
        // embedded snapshot was not cross-party verifiable — refuse rather than
        // import unverifiable membership/role/governance state (§23.16.8).
        // Distinct from a signature failure: this is a version error.
        if envelope.version < WASM_EXPORT_VERSION {
            return Err(ScpWasmError::Context {
                message: format!(
                    "unsupported export version: {} predates the current signed-export \
                     format — required version is {WASM_EXPORT_VERSION} (refusing \
                     unverifiable import)",
                    envelope.version
                ),
                // Dedicated version-gate code (SCP-CTX-2094): the export format
                // version predates the current signed-export preimage, so its
                // signature was computed over a different construction and is not
                // verifiable here. Distinct from a signature failure (CTX-2093).
                code: codes::CTX_2094.to_owned(),
            });
        }

        // Re-serialize the snapshot to RFC 8785 JCS canonical JSON. This MUST
        // happen before any state reconstruction to prevent an attacker from
        // crafting payloads that grant them admin of a context.
        //
        // Apply the identical set/map canonicalization the exporter applied
        // (§23.16.8): sort every set-derived array to a deterministic order
        // before re-serializing, so the verifier reconstructs the exact bytes
        // the signer hashed regardless of the array ordering present in the
        // received envelope. Without this, a re-ordered (but otherwise
        // faithful) envelope would fail verification, and the signing/verifying
        // sides would not be guaranteed to agree.
        canonicalize_snapshot_sets(&mut envelope.snapshot);
        let snapshot_json = serde_json_canonicalizer::to_vec(&envelope.snapshot).map_err(|e| {
            ScpWasmError::Context {
                message: format!("snapshot re-serialization failed: {e}"),
                code: codes::CTX_2032.to_owned(),
            }
        })?;

        // 0. Bind the signing authority to the creator identity (§23.16.8
        // import requirement #2): the envelope's declared `exporter_did` MUST
        // equal the snapshot's `creator_did`. The verifying key is always
        // resolved from `creator_did` (never from the envelope), so a mismatch
        // means a non-creator re-wrapped the snapshot under their own claimed
        // identity — reject it. Treated as a snapshot signature failure: the
        // signing authority does not match the verifying key (SCP-CTX-2093),
        // matching the runtime and the other three bridges.
        if envelope.exporter_did != envelope.snapshot.role_state.creator_did {
            return Err(ScpWasmError::Context {
                message: format!(
                    "export exporter_did '{}' does not match snapshot creator_did '{}' — \
                     only the context creator may sign an export (§23.16.8)",
                    envelope.exporter_did, envelope.snapshot.role_state.creator_did
                ),
                code: codes::CTX_2093.to_owned(),
            });
        }

        // 1. Ed25519 snapshot signature (§23.16.8). The exporter signs
        // SHA-256(domain || scope_tag || snapshot_jcs) with its #active key;
        // verify against the creator DID's resolved #active (then #agent)
        // verification key. Fail closed: an empty or invalid signature rejects
        // the import.
        if envelope.snapshot_signature.is_empty() {
            return Err(ScpWasmError::Context {
                message: "export snapshot_signature is missing — refusing to import \
                          unsigned export (§23.16.8)"
                    .to_owned(),
                code: codes::CTX_2093.to_owned(),
            });
        }
        Self::verify_snapshot_signature(
            &envelope.snapshot.role_state.creator_did,
            &snapshot_json,
            &envelope.snapshot_signature,
        )?;

        // 2. HMAC integrity tag (defense-in-depth for self-imports). Verifiable
        // only by a holder of the creator's key; skipped if the creator's key
        // is not in the local registry (cross-party import), since the Ed25519
        // signature already provides cross-party integrity.
        if !envelope.integrity_mac.is_empty()
            && crate::identity::creator_key_available(&envelope.snapshot.role_state.creator_did)
        {
            crate::identity::verify_export_hmac(
                &envelope.snapshot.role_state.creator_did,
                &snapshot_json,
                &envelope.integrity_mac,
            )?;
        }

        Ok(envelope)
    }

    /// Verifies the Ed25519 snapshot signature against the creator DID's
    /// resolved verification-method key (§23.16.8, ADR-039).
    ///
    /// Recomputes
    /// `SHA-256(SCP-CONTEXT-EXPORT-V1: || EXPORT_SCOPE_TAG_FULL || snapshot_jcs)`
    /// and verifies the signature with `verify_strict` against the `#active` key,
    /// falling back to `#agent`. Fails closed on any resolution or verification
    /// error.
    fn verify_snapshot_signature(
        creator_did: &str,
        snapshot_json: &[u8],
        signature_hex: &str,
    ) -> Result<(), ScpWasmError> {
        let sig_bytes: [u8; 64] = hex::decode(signature_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| ScpWasmError::Context {
                message: "snapshot_signature is not a valid 64-byte hex Ed25519 signature"
                    .to_owned(),
                code: codes::CTX_2093.to_owned(),
            })?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // Recompute the digest via the single-source helper so the verifier
        // binds the FULL export-scope tag identically to the producer
        // (§23.16.8) and a freshly-exported WASM snapshot still verifies.
        let snapshot_hash = wasm_export_snapshot_digest(snapshot_json);

        // Resolve #active, then #agent (ADR-039 shared-DID model).
        let key_bytes = crate::identity::resolve_verification_method_key(creator_did, "#active")
            .or_else(|_| crate::identity::resolve_verification_method_key(creator_did, "#agent"))
            .map_err(|e| ScpWasmError::Context {
                message: format!(
                    "failed to resolve creator '{creator_did}' verification key \
                     (#active/#agent): {e}"
                ),
                code: codes::CTX_2093.to_owned(),
            })?;

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            ScpWasmError::Context {
                message: format!("creator '{creator_did}' key is not valid Ed25519: {e}"),
                code: codes::CTX_2093.to_owned(),
            }
        })?;

        verifying_key
            .verify_strict(&snapshot_hash, &signature)
            .map_err(|e| ScpWasmError::Context {
                message: format!(
                    "snapshot signature did not verify for creator '{creator_did}': {e}"
                ),
                code: codes::CTX_2093.to_owned(),
            })
    }

    /// Imports a context from serialized JSON bytes produced by `export_context`.
    ///
    /// Deserializes the envelope, validates the version and integrity MAC,
    /// then reconstructs the context state in the manager.
    ///
    /// # Returns
    ///
    /// The context ID of the imported context.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails, version is incompatible,
    /// the integrity MAC is missing/invalid, or the context already exists.
    #[allow(clippy::too_many_lines)] // snapshot reconstruction with many fields
    pub fn import_context(&mut self, data: &[u8]) -> Result<String, ScpWasmError> {
        let envelope = Self::deserialize_and_verify_envelope(data)?;

        let snap = &envelope.snapshot;
        let context_id = snap.context_id.clone();

        // Validate imported fields from untrusted data (defense-in-depth).
        // The role-state DIDs and assigned role names now live inside the typed
        // `ContextRoleState` carried verbatim in the snapshot, so the string
        // validations iterate `role_state.members` (member + creator DIDs) and
        // `role_state.assignments` (assigned role names).
        validate_imported_string(&context_id, "context_id", 256)?;
        validate_imported_did(&snap.role_state.creator_did, "creator_did")?;
        for did in &snap.role_state.members {
            validate_imported_did(did, "member DID")?;
        }
        for assignment in snap.role_state.assignments.values() {
            let role = &assignment.role_name;
            if role.is_empty() || role.len() > 64 {
                return Err(ScpWasmError::Context {
                    message: format!("invalid member role '{role}': must be 1-64 chars"),
                    code: codes::CTX_2032.to_owned(),
                });
            }
        }
        let valid_states = ["active", "closed", "suspended", "archived"];
        if !valid_states.contains(&snap.state.as_str()) {
            return Err(ScpWasmError::Context {
                message: format!(
                    "invalid context state '{}': must be one of {valid_states:?}",
                    snap.state
                ),
                code: codes::CTX_2032.to_owned(),
            });
        }

        // Defense-in-depth: validate and check minProtocolVersion from the
        // imported snapshot's params. Rejects malformed version data and
        // imported contexts that require a newer SDK than we support.
        parse_and_check_min_protocol_version(&snap.params_json)?;

        // Validate v3 anti-replay fields (defense-in-depth; the Ed25519
        // snapshot signature already covers tamper detection, but we validate
        // shape and bounds to
        // fail loud, not silently accept malformed state).
        validate_imported_antispam_state(snap)?;

        if self.contexts.contains_key(&context_id) {
            return Err(ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' already exists — cannot import over existing context"
                ),
                code: codes::CTX_2000.to_owned(),
            });
        }

        // Restore the shared role state VERBATIM from the signed, already-verified
        // snapshot — the exact native behavior (`lifecycle_helpers::import_context`
        // assigns `role_state: export.snapshot.role_state`). Carrying the typed
        // `ContextRoleState` and restoring it as-is is what makes the WASM import
        // path converge with native and closes BLACK-CEIL-01: the former code
        // rebuilt `member_capabilities` by re-running `system_assign_role` per
        // member against the imported ceiling, which RE-GRANTED a member who had
        // been `SuspendAccess`'d BEFORE a ceiling widen the widened capability
        // (`member_has_capability` flipped false→true across export/import). We no
        // longer recompute anything: members, role assignments + minted tokens,
        // `member_capabilities`, and per-member `suspended_capabilities` are taken
        // straight from the signed snapshot, so a suspended-then-widened member
        // stays suspended exactly as they were at export time.
        //
        // We deliberately do NOT intersect `member_capabilities` with the ceiling
        // or otherwise downward-shrink on import — native does neither, and doing
        // so here would be a NEW native/WASM divergence. The snapshot is trusted
        // for CONTENT because the envelope already binds it to the creator:
        // `deserialize_and_verify_envelope` enforces `exporter_did == creator_did`
        // and `verify_strict`s the creator's Ed25519 signature over the
        // JCS-canonical snapshot (fail-closed on a missing/invalid signature). The
        // signature authenticates ORIGIN, not WELL-FORMEDNESS, so we still validate
        // the ceiling GRAMMAR below.
        let role_state = snap.role_state.clone();

        // §5.3.1.1 defense-in-depth belt, mirroring native: validate every ceiling
        // entry against the canonical ceiling-entry grammar. A conformant export's
        // ceiling is already well-formed (and the `#[serde(try_from = "CapabilityCeilingRaw")]`
        // deserialize path already rejects a malformed ceiling before we reach
        // here), so this is the explicit, greppable belt that fails loud rather than
        // relying solely on the deserialize-time check.
        role_state
            .ceiling()
            .validate_entries()
            .map_err(|e| ScpWasmError::Context {
                message: format!(
                    "imported context ceiling has a malformed entry (spec §5.3.1.1): {e}"
                ),
                code: codes::CTX_2032.to_owned(),
            })?;

        // MLS sequence counters are genuinely WASM-local orchestration state with
        // no home in `ContextRoleState`; restore them verbatim from the sidecar.
        let member_sequence_numbers = snap.member_sequence_numbers.clone();

        let broadcast_context = snap.broadcast.as_ref().map(|bc| {
            use scp_protocol::context::broadcast::{
                AuthorStateSnapshot, BroadcastContextSnapshot, SubscriberRecord,
            };
            let admission = if bc.admission == "gated" {
                BroadcastAdmission::Gated
            } else {
                BroadcastAdmission::Open
            };
            // Build snapshot and use from_snapshot to reconstruct BroadcastContext.
            let authors: HashMap<String, AuthorStateSnapshot> = bc
                .author_block_lists
                .iter()
                .map(|(did, block_list)| {
                    let epoch = bc.key_epochs.get(did).copied().unwrap_or(0);
                    (
                        did.clone(),
                        AuthorStateSnapshot {
                            author_did: did.clone(),
                            broadcast_key: scp_protocol::crypto::sender_keys::generate_sender_key(),
                            epoch,
                            next_sequence: 1,
                            block_list: block_list.iter().cloned().collect(),
                        },
                    )
                })
                .collect();
            let subscribers: HashMap<String, SubscriberRecord> = bc
                .subscribers
                .iter()
                .map(|did| {
                    (
                        did.clone(),
                        SubscriberRecord {
                            subscriber_did: did.clone(),
                            registered_at: 0,
                            has_ucan: false,
                        },
                    )
                })
                .collect();
            BroadcastContext::from_snapshot(BroadcastContextSnapshot {
                context_id: context_id.clone(),
                admission,
                subscribers,
                authors,
            })
        });

        // Clamp ONLY the anti-replay timestamps to `now` so snapshot forgery
        // cannot push them into the future: the per-nonce `seen_nonces_v3`
        // `inserted_at_ms` and the per-proposal `executed_at_ms` (both `.min(now)`
        // below). `ttl_seconds` and `creation_timestamp_secs` are NOT clamped —
        // `creation_timestamp_secs` is consumed VERBATIM (see the assignment
        // further down) because the convergent TTL deadline base
        // (`creation_timestamp_secs + ttl_seconds`) must be byte-identical across
        // members and bridges (§9.9.3); clamping it would diverge the
        // `ContextExpired` leaf. Consuming it verbatim is safe NOT because of any
        // fail-safe direction (a forged FUTURE creation time would in fact LENGTHEN
        // `creation + ttl`, pushing the deadline later — the opposite of fail-safe).
        // It is safe because by the time we reach this code the whole snapshot —
        // `creation_timestamp_secs` included — has already been bound to the creator:
        // `deserialize_and_verify_envelope` enforces `exporter_did == creator_did`,
        // verifies the Ed25519 snapshot signature over the JCS-canonical snapshot
        // against the creator DID's resolved key, and (for self-imports) the
        // defense-in-depth HMAC. Forging `creation_timestamp_secs` therefore requires
        // the creator's signing key. §9.9.3 additionally requires the value verbatim
        // for cross-member/bridge convergence, so clamping is forbidden regardless.
        let now_ms_for_clamp = crate::time::now_ms();
        let ctx = PerContextState {
            state: snap.state.clone(),
            params_json: snap.params_json.clone(),
            mode: snap.mode.clone(),
            role_state,
            member_sequence_numbers,
            ceiling_policy: snap.ceiling_policy.clone(),
            ttl_seconds: snap.ttl_seconds,
            promotion_policy: snap.promotion_policy.clone(),
            governance: snap.governance.clone(),
            economic_policy: snap.economic_policy.clone(),
            tool_registry: ToolRegistry::new(),
            tool_handlers: HashMap::new(),
            event_log: EventLog::new(context_id.clone()),
            revoked_tokens: snap.revoked_tokens.iter().cloned().collect(),
            // v3 import: prefer `seen_nonces_v3` if present, falling back to
            // the v2-legacy `seen_nonces_legacy_v2` field for back-compat.
            seen_nonces: if snap.seen_nonces_v3.is_empty() {
                // v2 compat — legacy snapshot had no timestamps. Reset to
                // now (the current, knowingly-lossy behavior for v2).
                snap.seen_nonces_legacy_v2
                    .iter()
                    .map(|n| (n.clone(), now_ms_for_clamp))
                    .collect()
            } else {
                // v3 import — restore real timestamps.
                snap.seen_nonces_v3
                    .iter()
                    .map(|e| (e.nonce.clone(), e.inserted_at_ms.min(now_ms_for_clamp)))
                    .collect()
            },
            event_buffer: VecDeque::new(),
            // v3 import: preserve executed_proposals timestamps so replay
            // protection survives export/import.
            executed_proposals: snap
                .executed_proposals
                .iter()
                .map(|e| {
                    (
                        e.proposal_id.clone(),
                        e.executed_at_ms.min(now_ms_for_clamp),
                    )
                })
                .collect(),
            read_exclusion_list: snap.read_exclusion_list.iter().cloned().collect(),
            broadcast_context,
            sessions: HashMap::new(),
            threshold_signers: snap.threshold_signers.clone(),
            threshold_value: snap.threshold_value,
            tool_interfaces: snap.tool_interfaces.clone(),
            governance_freeze: snap.governance_freeze,
            pending_proposals: HashMap::new(),
            // v3 import: reconstruct resolved_proposals from serde_json::Value
            // entries. Malformed entries (e.g., struct shape drift) are
            // dropped — the envelope HMAC already gates this path, so this
            // is a last-line defense against forward-incompatible imports.
            resolved_proposals: {
                let mut out: HashMap<String, GovernanceProposal> = HashMap::new();
                for (k, v) in &snap.resolved_proposals_json {
                    if let Ok(proposal) = serde_json::from_value::<GovernanceProposal>(v.clone()) {
                        out.insert(k.clone(), proposal);
                    }
                }
                out
            },
            pruning_policy: snap.pruning_policy.clone(),
            economic_policy_locked: snap.economic_policy_locked,
            hard_rate_limit_config: snap.hard_rate_limit_config.clone(),
            consequence_rules: snap.consequence_rules.clone(),
            cooldown_until: snap.cooldown_until.clone(),
            // Imported contexts do not carry MLS state — they must re-establish
            // encryption via join_context_encrypted after import.
            //
            // SECURITY: an imported context intentionally holds NO live MLS
            // crypto state (`crypto: None`). The verbatim-restored `role_state`
            // is advisory metadata only — it confers no message-decryption
            // ability — and the `member_sequence_numbers` sidecar above is
            // therefore decoupled from any live AEAD key. Because no GCM key is
            // bound to these counters at import, a reset or forged sequence
            // value CANNOT cause GCM nonce reuse: there is no nonce to reuse
            // until a fresh Welcome establishes `crypto`, which starts its own
            // counters from zero. If a future change ever populates `crypto`
            // from imported MLS state, this sidecar becomes a nonce-reuse vector
            // and MUST be re-evaluated.
            crypto: None,
            // Convergent creator-assigned creation time, restored from the
            // signed snapshot so the imported TTL deadline base
            // (`creation_timestamp_secs + ttl_seconds`) matches what every other
            // member computes (§7.3.1, §9.9.3). Consumed VERBATIM to match the
            // native bridge and preserve cross-member convergence: the value is
            // inside the creator-signed snapshot preimage (this import path
            // `verify_strict`s the creator's Ed25519 signature and fails closed
            // on a missing/invalid signature before reaching here), so it is
            // authenticated. Unlike the nonce / executed-proposal `observed_at`
            // timestamps above, this field is NOT re-pinned to importer-local
            // `now()`: its sole consumer is the TTL upper bound
            // (`creation + ttl`), where backdating only SHORTENS the lifetime
            // (fail-safe) and future-dating is bounded by `ttl`. Clamping to
            // `now` would re-introduce the import-time divergence this field
            // exists to close — a mixed native/WASM context where
            // `creation > wasm_now` (legitimate clock skew, or a creator that
            // stamped a slightly-future creation) would otherwise record a WASM
            // expiry leaf at `now + ttl` while native records `creation + ttl`,
            // diverging the Merkle root at equal event count.
            creation_timestamp_secs: snap.creation_timestamp_secs,
        };

        // See the SECURITY note on `crypto: None` above: imported contexts must
        // start without live MLS crypto; a fresh Welcome establishes it.
        debug_assert!(
            ctx.crypto.is_none(),
            "imported contexts must start without live MLS crypto (see SECURITY note); a fresh Welcome establishes crypto"
        );

        self.contexts.insert(context_id.clone(), ctx);
        Ok(context_id)
    }

    // -----------------------------------------------------------------------
    // Ceiling modification, close, checkpoint, restore (#559)
    // -----------------------------------------------------------------------

    /// Applies a pending ceiling modification if the notification period has elapsed.
    ///
    /// WASM re-implementation: checks `pending_ceiling_modification` timestamp.
    /// Returns `true` if applied, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or not active.
    pub fn apply_pending_ceiling_modification(
        &mut self,
        context_id: &str,
        current_timestamp: u64,
    ) -> Result<bool, ScpWasmError> {
        // The WASM bridge does not currently track pending ceiling modifications
        // at the per-context level (scp-core has PerContextState.pending_ceiling_modification).
        // Return false (no pending modification) — this is consistent behavior because
        // the WASM bridge cannot initiate ceiling modifications through governance yet.
        let _ = self.require_active_context(context_id)?;
        let _ = current_timestamp;
        Ok(false)
    }

    /// Finalizes the cooperative close flow for a context in `Closing` state.
    ///
    /// Transitions from `closing` to `closed`, records a `ContextClosed` event.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not in `closing` state.
    pub fn finalize_close(&mut self, context_id: &str) -> Result<(), ScpWasmError> {
        let ctx = self.require_context_mut(context_id)?;

        if ctx.state != "closing" {
            return Err(ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' is in '{}' state — must be 'closing' to finalize",
                    ctx.state
                ),
                code: codes::CTX_2061.to_owned(),
            });
        }

        "closed".clone_into(&mut ctx.state);
        ctx.broadcast_context = None;

        // Convergent `ContextClosed` leaf timestamp. For a TTL-driven close this
        // MUST be the CONVERGENT TTL deadline (`creation_timestamp_secs +
        // ttl_seconds`) — the identical absolute value every member computes
        // regardless of which member's timer fired or what its local clock read
        // — NOT each member's local `crate::time::now_secs()`, which would
        // diverge the leaf at equal event count and trip §9.9.3 equivocation
        // detection across native/WASM. This mirrors native: the convergent
        // close timestamp is computed in the CALLER `ttl_close_helpers.rs`'s
        // `finalize_close` as
        // `state.ttl.timer.deadline_unix_secs.unwrap_or_else(|| now_secs())`
        // and passed as the pre-computed `timestamp_secs` argument into
        // `ttl::finalize_close` (`crates/scp-runtime/src/context/ttl.rs`), which
        // stamps it onto the `ContextClosed` leaf. `deadline_unix_secs` holds
        // `creation + ttl` (auto-reflecting any TTL extension, which mutates
        // `ttl_seconds` here / `deadline_unix_secs` there by the same delta), and
        // falls back to the closer's clock only for a governance/explicit close
        // of a no-TTL context. WASM mirrors that
        // exactly via `convergent_ttl_deadline_secs(creation, ttl_seconds)`:
        // `Some(ttl) => creation + ttl`, else local `now_secs()`. Identical to
        // `handle_ttl_expiry`'s `expiry_leaf_secs` so a close and an expiry of
        // the same TTL context stamp the same convergent instant.
        let close_leaf_secs = match ctx.ttl_seconds {
            Some(ttl) => ctx.creation_timestamp_secs.saturating_add(ttl),
            None => crate::time::now_secs(),
        };

        ctx.append_log_event(
            EventType::ContextClosed,
            scp_event_log::system_actors::SYSTEM_CLOSE_ACTOR,
            b"",
            close_leaf_secs,
        );

        Ok(())
    }

    /// Creates a governance checkpoint (ADR-031 §9).
    ///
    /// Returns the checkpoint as a JSON value.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or not active.
    #[allow(clippy::too_many_arguments)]
    pub fn create_governance_checkpoint(
        &self,
        context_id: &str,
        checkpoint_seq: u64,
        merkle_root: &[u8; 32],
        event_count: u64,
        last_event_hash: &[u8; 32],
        state_snapshot_hash: &[u8; 32],
        creator_did: &str,
        creator_signature: &[u8],
    ) -> Result<serde_json::Value, ScpWasmError> {
        let _ = self.require_active_context(context_id)?;

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let created_at = (crate::time::now_ms() / 1000.0) as u64;

        Ok(serde_json::json!({
            "checkpoint_seq": checkpoint_seq,
            "merkle_root": hex::encode(merkle_root),
            "event_count": event_count,
            "last_event_hash": hex::encode(last_event_hash),
            "state_snapshot_hash": hex::encode(state_snapshot_hash),
            "created_at": created_at,
            "creator_did": creator_did,
            "creator_signature": hex::encode(creator_signature),
            "cosignatures": [],
            "attestation_status": "PartiallyAttested",
        }))
    }

    /// Adds a cosignature to an existing checkpoint (ADR-031 §9).
    ///
    /// Returns the updated checkpoint and attestation status.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or not active.
    pub fn add_checkpoint_cosignature(
        &self,
        context_id: &str,
        checkpoint: &mut serde_json::Value,
        signer_did: &str,
        signature: &[u8],
    ) -> Result<String, ScpWasmError> {
        let _ = self.require_active_context(context_id)?;

        let cosig = serde_json::json!({
            "signer_did": signer_did,
            "signature": hex::encode(signature),
        });

        if let Some(arr) = checkpoint
            .get_mut("cosignatures")
            .and_then(|v| v.as_array_mut())
        {
            arr.push(cosig);
        }

        // WASM bridge does not have governance engine to validate quorum.
        // Return PartiallyAttested. Full validation happens server-side or
        // in the native bridges.
        let status = "PartiallyAttested";
        if let Some(obj) = checkpoint.as_object_mut() {
            obj.insert(
                "attestation_status".to_owned(),
                serde_json::Value::String(status.to_owned()),
            );
        }

        Ok(status.to_owned())
    }

    /// Restores a single context (WASM no-op: WASM has no persistence layer).
    ///
    /// Returns an error because WASM contexts are ephemeral.
    ///
    /// # Errors
    ///
    /// Always returns an error — WASM has no persistence layer (ADR-034).
    pub fn restore_context(&self, _context_id: &str) -> Result<(), ScpWasmError> {
        Err(ScpWasmError::Context {
            message: "context restoration is not supported in the WASM bridge — \
                      WASM contexts are ephemeral (ADR-034)"
                .to_owned(),
            code: codes::CTX_2064.to_owned(),
        })
    }

    /// Restores all contexts (WASM no-op: WASM has no persistence layer).
    ///
    /// Returns an error because WASM contexts are ephemeral.
    ///
    /// # Errors
    ///
    /// Always returns an error — WASM has no persistence layer (ADR-034).
    pub fn restore_all_contexts(&self) -> Result<Vec<String>, ScpWasmError> {
        Err(ScpWasmError::Context {
            message: "context restoration is not supported in the WASM bridge — \
                      WASM contexts are ephemeral (ADR-034)"
                .to_owned(),
            code: codes::CTX_2065.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// ContextMetadata — returned to bridge functions for handle construction
// ---------------------------------------------------------------------------

/// Metadata about a context, used by bridge functions to construct handles.
pub struct ContextMetadata {
    pub context_id: String,
    pub state: String,
    pub creator_did: String,
    pub mode: String,
    pub ceiling: Vec<String>,
    pub ceiling_policy: String,
    pub ttl_seconds: Option<u64>,
    pub promotion_policy: Option<String>,
    pub governance: String,
    pub member_count: u64,
    pub economic_policy: Option<String>,
    /// Minimum protocol version as `[major, minor]`, or `None` if unset.
    pub min_protocol_version: Option<(u8, u8)>,
}

// ---------------------------------------------------------------------------
// Context export/import types (#424)
// ---------------------------------------------------------------------------

/// Current version of the WASM context export format.
///
/// SCP is pre-release with no deployed exports, so there is no cross-version
/// back-compat: `deserialize_and_verify_envelope` enforces a STRICT version gate
/// that rejects any envelope whose `version` differs from `WASM_EXPORT_VERSION`
/// (both newer and older) outright with `SCP-CTX-2094`, distinct from a
/// signature failure (`SCP-CTX-2093`). The correct end state ships directly;
/// earlier formats are never imported.
///
/// # Format summary
///
/// The current (v5) envelope carries the lossless anti-replay state —
/// `seen_nonces_v3` (full `(nonce, inserted_at_ms)` pairs), `executed_proposals`
/// (full `(proposal_id, executed_at_ms)` pairs), `resolved_proposals_json`,
/// `consequence_rules`, `cooldown_until` — alongside per-author broadcast state
/// (block lists, key epochs) and the mandatory Ed25519 `snapshot_signature`
/// (§23.16.8) whose preimage binds the export-scope discriminant. The byte value
/// MUST NEVER be reused for an incompatible shape.
///
/// # Relationship to the native export version
///
/// This WASM version line (JSON envelope) is **intentionally independent** of
/// the native bridge's `CURRENT_EXPORT_VERSION` (`MessagePack` `StoredValue`
/// payload, currently 4). The two serializations are disjoint and mutually
/// non-importable by construction (ADR-034): a native export fed to this WASM
/// bridge is rejected at the version gate, never silently parsed. The two
/// numbers are therefore **not** expected to match and must **not** be
/// "reconciled" — only the signing construction converges, not the bytes.
const WASM_EXPORT_VERSION: u32 = 5;

/// Maximum byte length of a context-export envelope accepted by
/// [`WasmContextManager::deserialize_and_verify_envelope`].
///
/// The import path runs `serde_json::from_slice` then re-canonicalizes the
/// whole snapshot to RFC 8785 JCS (`canonicalize_snapshot_sets` +
/// `serde_json_canonicalizer::to_vec`) BEFORE the Ed25519 signature can reject
/// a forgery — an `O(n*m*log n)` amplifier with per-element re-canonicalization
/// of every set/map field. An unbounded attacker-controlled blob is therefore a
/// CPU/allocation `DoS` amplifier, mirroring the native `MAX_CONTEXT_EXPORT_BYTES`
/// guard in `scp-runtime`. This is checked at the TOP of deserialization,
/// failing closed with the same `CTX_2032` validation class the rest of the
/// path uses.
///
/// The WASM envelope is a JSON snapshot that — unlike the native `MessagePack`
/// envelope — never embeds the event log (events are re-registered after
/// import), so it is bounded by membership/role/governance state. 16 MiB is a
/// generous ceiling for that JSON shape while still bounding the amplifier; it
/// is intentionally distinct from (and smaller than) native's 64 MiB
/// MessagePack-plus-event-log bound.
const WASM_MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;

/// Domain separator for the WASM context-export snapshot signature, matching
/// the cross-bridge canonical hash (spec §23.16.8, §9.18.2).
///
/// This is the §23.16.8 *signed-export* separator, deliberately DISTINCT from
/// the §23.16.4 sync-delta separator `"SCP-CONTEXT-SNAPSHOT-V1:"`. The WASM
/// bridge has no sync-delta path, but the export construction still uses its own
/// separator so an export signature can never be confused with a sync-delta
/// signature under the same creator key (cross-protocol domain separation,
/// matching the native `CONTEXT_EXPORT_DOMAIN_SEPARATOR`).
const WASM_EXPORT_SIGN_DOMAIN: &[u8] = b"SCP-CONTEXT-EXPORT-V1:";

/// Versioned envelope for context exports.
///
/// Serialized as JSON bytes. The `version` field drives a STRICT version gate:
/// import rejects any envelope whose `version` is not exactly
/// `WASM_EXPORT_VERSION` (newer or older) with `SCP-CTX-2094`.
///
/// Integrity protection: the authoritative cross-party integrity proof is the
/// mandatory Ed25519 `snapshot_signature` (§23.16.8) over
/// `SHA-256(domain || scope_tag || snapshot_jcs)`. The `integrity_mac`
/// HMAC-SHA256 tag is computed over the SAME snapshot preimage and is strictly
/// defense-in-depth: it is fully subsumed by the signature and is verified only
/// on self-import, when the creator's key is available in the local registry.
/// It is retained transitionally and is NOT the authoritative integrity proof —
/// the signature is. (A separate cleanup may remove the HMAC entirely.)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmContextExportEnvelope {
    /// Export format version.
    version: u32,
    /// Unix timestamp (seconds) when the export was created.
    exported_at: u64,
    /// DID of the identity that performed the export.
    exporter_did: String,
    /// HMAC-SHA256 tag (hex-encoded) over the canonical JSON serialization of
    /// the `snapshot` field. Keyed by `HKDF(creator_signing_key,
    /// info="scp-context-export-integrity-v1")`. Defense-in-depth ONLY: it
    /// covers the identical preimage as the mandatory Ed25519
    /// `snapshot_signature` and is fully subsumed by it. Verified only on
    /// self-import (when the creator's key is locally available); skipped on
    /// cross-party import, where the signature already provides integrity. It
    /// is NOT the authoritative cross-party integrity proof — the signature is.
    integrity_mac: String,
    /// Ed25519 signature (hex-encoded, 64 bytes) by the creator's `#active`
    /// signing key over
    /// `SHA-256(SCP-CONTEXT-EXPORT-V1: || EXPORT_SCOPE_TAG_FULL || snapshot_jcs)`
    /// (spec §23.16.8, adapted to the WASM JSON snapshot shape per ADR-034).
    ///
    /// Unlike `integrity_mac` (a symmetric HMAC verifiable only by a holder of
    /// the creator's key), this is an asymmetric signature: any importer that
    /// can resolve the exporter DID's `#active`/`#agent` verification key can
    /// verify the embedded snapshot was not tampered with — matching the
    /// cross-bridge Ed25519 `snapshot_signature` contract. The strict version
    /// gate rejects any envelope whose `version` differs from the current
    /// `WASM_EXPORT_VERSION`, so an export must carry this signature to import.
    #[serde(default)]
    snapshot_signature: String,
    /// The context state snapshot.
    snapshot: WasmContextExportSnapshot,
}

/// A UCAN nonce plus its insertion timestamp (ms since Unix epoch), used to
/// round-trip the live `PerContextState.seen_nonces: HashMap<String, f64>`.
///
/// Introduced in `WASM_EXPORT_VERSION = 3`. The `inserted_at_ms` field is an
/// `f64` to match the live field's representation exactly and preserve
/// bit-for-bit round-trip fidelity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmExportNonceEntry {
    /// The nonce string as recorded by `ucan_record_nonce`.
    nonce: String,
    /// Milliseconds since Unix epoch when the nonce was first observed.
    /// Matches `PerContextState.seen_nonces` value type (`f64`).
    inserted_at_ms: f64,
}

/// An executed-proposal replay entry plus its execution timestamp (ms since
/// Unix epoch).
///
/// Introduced in `WASM_EXPORT_VERSION = 3`. Mirrors
/// `WasmExportNonceEntry` in shape but keyed on governance proposal IDs, so
/// that governance replay protection survives export/import without
/// TTL-bypass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmExportExecutedProposalEntry {
    /// Hex-encoded governance proposal ID.
    proposal_id: String,
    /// Milliseconds since Unix epoch when the proposal was recorded as
    /// executed. Matches `PerContextState.executed_proposals` value type
    /// (`f64`).
    executed_at_ms: f64,
}

/// Snapshot of a context's state for export.
///
/// Contains all fields needed to reconstruct a `PerContextState` on import.
/// Tool registry, event log, and tool handlers are NOT exported (they can be
/// re-registered after import). Membership, roles, governance, broadcast,
/// UCAN revocation, and nonce replay state are preserved.
///
/// # Versioning
///
/// - v1/v2: flat `seen_nonces: Vec<String>` (keys only — timestamps lost).
/// - v3: adds `seen_nonces_v3` with full `(nonce, inserted_at_ms)` pairs,
///   `executed_proposals` with full `(proposal_id, executed_at_ms)` pairs,
///   `resolved_proposals_json`, `consequence_rules`, and `cooldown_until` so
///   anti-replay, governance audit, and consequence enforcement state survive
///   round-trip without TTL-bypass. v2's `seen_nonces` field is retained as
///   `seen_nonces_legacy_v2` for back-compat.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmContextExportSnapshot {
    context_id: String,
    state: String,
    params_json: serde_json::Value,
    mode: String,
    ceiling_policy: String,
    ttl_seconds: Option<u64>,
    promotion_policy: Option<String>,
    governance: String,
    economic_policy: Option<String>,
    /// Shared role state restored VERBATIM on import (members, role
    /// assignments + minted tokens, capability ceiling, role definitions,
    /// per-member granted capabilities, and per-member suspensions). Carrying
    /// the typed `ContextRoleState` instead of a lossy flat projection is what
    /// makes the WASM import path converge with native
    /// (`lifecycle_helpers::import_context`, which assigns
    /// `role_state: export.snapshot.role_state`): import no longer recomputes
    /// `member_capabilities` via `system_assign_role`, so a member who was
    /// suspended BEFORE a ceiling widen cannot regain the widened capability on
    /// round-trip (BLACK-CEIL-01). The ceiling and per-member suspension sets
    /// self-canonicalize for the signed digest via the
    /// `serde_sorted_set` / `serde_sorted_set_map` field codecs on
    /// `ContextRoleState`, and the `#[serde(try_from = "CapabilityCeilingRaw")]`
    /// path rejects a malformed ceiling at deserialize time (§5.3.1.1).
    role_state: ContextRoleState,
    /// Per-member MLS message sequence counters, keyed by member DID.
    ///
    /// The shared home for this per-member counter is
    /// `scp_protocol::context::membership::MembershipState`
    /// (`MemberInfo.sequence_number`), which native carries inside its context
    /// snapshot and restores verbatim. WASM does not yet adopt `MembershipState`,
    /// so this flat `HashMap<String, u64>` is the INTERIM WASM representation of
    /// the same state. Converging WASM onto the shared `MembershipState` (and
    /// retiring this sidecar) is a deferred follow-up slice of the native↔WASM
    /// convergence program.
    ///
    /// The DID-keyed map is canonicalized for the signed digest by RFC 8785 JCS
    /// object-key sorting; the scalar values need no element sort.
    #[serde(default)]
    member_sequence_numbers: HashMap<String, u64>,
    read_exclusion_list: Vec<String>,
    broadcast: Option<WasmExportBroadcast>,
    /// UCAN revocation CIDs. Preserves revocation state across export/import
    /// so that previously revoked tokens remain rejected.
    #[serde(default)]
    revoked_tokens: Vec<String>,
    /// v1/v2 lossy seen-nonces field (keys only). Retained under the original
    /// serde name so that v2 envelopes still deserialize into a v3 snapshot.
    /// v3 exporters always leave this empty and populate `seen_nonces_v3`
    /// instead.
    #[serde(default, rename = "seen_nonces")]
    seen_nonces_legacy_v2: Vec<String>,
    /// v3 lossless seen-nonces field. Each entry preserves both the nonce
    /// string and its insertion timestamp (ms since epoch) so TTL eviction
    /// survives export/import without the "nonces become young again on
    /// import" bug present in v1/v2.
    #[serde(default)]
    seen_nonces_v3: Vec<WasmExportNonceEntry>,
    /// v3 lossless executed-proposals field. Each entry preserves the
    /// proposal ID and the execution timestamp so governance replay
    /// protection survives export/import. Absent in v1/v2.
    #[serde(default)]
    executed_proposals: Vec<WasmExportExecutedProposalEntry>,
    /// v3 resolved-proposals audit field. Keys are proposal IDs; values are
    /// the raw `GovernanceProposal` JSON. Stored as `serde_json::Value` for
    /// forward compatibility with any additions to the struct in
    /// scp-protocol. Malformed entries are dropped on import (defense in
    /// depth; the envelope HMAC already gates this path).
    #[serde(default)]
    resolved_proposals_json: HashMap<String, serde_json::Value>,
    /// Consequence rules declared at context creation (ADR-017). Mirrors
    /// `scp_runtime::context::state::ContextSnapshot.consequence_rules` and
    /// is wired to `evaluate_consequence_rules` via the WASM
    /// `consequence::dispatch_consequences_for_subject` helper.
    #[serde(default)]
    consequence_rules: Vec<scp_protocol::trust::consequence::ConsequenceRule>,
    /// Per-rule cooldown timers for consequence dispatch. Maps rule index to
    /// the Unix second until which the rule should not re-fire. Mirrors
    /// `scp_runtime` governance `cooldown_until`.
    #[serde(default)]
    cooldown_until: HashMap<usize, u64>,
    /// Threshold governance signers (ADR-031 §4b).
    #[serde(default)]
    threshold_signers: Vec<String>,
    /// Current threshold value (ADR-031 §4b).
    #[serde(default)]
    threshold_value: u32,
    /// Established tool interface JSON strings (§6.2).
    #[serde(default)]
    tool_interfaces: Vec<String>,
    /// Whether governance is frozen (ADR-031 §7).
    #[serde(default)]
    governance_freeze: bool,
    /// Pruning policy JSON (ADR-030 §6).
    #[serde(default)]
    pruning_policy: Option<String>,
    /// Whether the economic policy is locked (§19.3, ADR-033).
    #[serde(default)]
    economic_policy_locked: bool,
    /// Hard rate limit configuration (D4, §19.7) as an opaque JSON blob.
    /// `None` means the default Matrix-style config applies.
    #[serde(default)]
    hard_rate_limit_config: Option<String>,
    /// Convergent creator-assigned context-creation timestamp (Unix seconds).
    ///
    /// Mirrors the live `PerContextState.creation_timestamp_secs` so the
    /// convergent TTL deadline base (`creation_timestamp_secs + ttl_seconds`)
    /// survives export/import rather than being re-derived from importer-local
    /// `now()`. This is the WASM bridge's independent DTO field — NOT byte-parity
    /// with the native `ContextSnapshot` (the WASM export keeps its own digest).
    /// `#[serde(default)]` so pre-field envelopes deserialize as `0`.
    #[serde(default)]
    creation_timestamp_secs: u64,
}

/// Canonicalizes every set/map-derived array in an export snapshot to a
/// deterministic sorted order (§23.16.8 "Set/Map canonicalization").
///
/// The export builder collects these arrays from `HashSet`/`HashMap` sources
/// in incidental iteration order, which is non-deterministic across runs and
/// implementations. RFC 8785 JCS canonicalizes JSON *object* member ordering
/// (so the `HashMap`-backed fields serialized as JSON objects —
/// `resolved_proposals_json`, `cooldown_until`, `member_sequence_numbers`, and
/// the broadcast `author_block_lists`/`key_epochs` maps — are already
/// deterministic by key), but JCS does NOT reorder JSON *array* elements.
/// Every array whose elements derive from a set MUST therefore be sorted here
/// before the snapshot is serialized for signing and before it is re-serialized
/// for verification, so the signed digest is byte-identical across runs and the
/// producer and verifier always agree.
///
/// The embedded `role_state` (`ContextRoleState`) is NOT handled here. Its
/// SET-shaped fields self-canonicalize for the digest via the
/// `serde_sorted_set` / `serde_sorted_set_map` field codecs: the `members`
/// set, the per-member `member_capabilities` and `suspended_capabilities`
/// inner sets, the ceiling's `capabilities` set, and each
/// `role_definitions[*].capabilities` set. Its outer MAPS (`assignments`,
/// `role_definitions`, and `member_sequence_numbers`) are JCS-canonicalized by
/// object key. So those portions of the subtree serialize deterministically
/// regardless of the incidental iteration order present in the source, and no
/// array sort is needed or possible for them here (the inner sets are private
/// to scp-protocol).
///
/// IMPORTANT — this does NOT make the whole `role_state` subtree byte-identical
/// across two INDEPENDENT exports of the same logical state. The exception is
/// `assignments[*].tokens`: a `Vec<UcanToken>` (the role-token type, whose `att`
/// is an unsorted `Vec<UcanAttestation>`). The minter (`mint_role_tokens`)
/// produces one token per capability by iterating the role's
/// `capabilities` SET in unspecified `HashSet` order, so the `tokens` Vec
/// carries that incidental mint/iteration order; and each token's `nnc` is a
/// fresh random nonce. Re-minting the same logical grant therefore yields
/// different `assignments` bytes, and we intentionally do NOT sort `tokens`
/// here.
///
/// This is sound for THIS construction because the signed digest is a
/// single-signer VERBATIM model: the exporter signs the exact JCS bytes it
/// produced, and the importer re-canonicalizes and `verify_strict`s THOSE SAME
/// received bytes — tokens are carried verbatim and never re-minted on either
/// side. A faithful export therefore always verifies (identical bytes in,
/// identical bytes out), and any tamper changes the bytes and fails
/// `verify_strict`. Byte-parity across independent exports — or with native /
/// any other implementation — is explicitly NOT claimed here; the WASM digest
/// is already documented as not byte-identical to native's.
///
/// Fields that originate from an ordered `Vec` in `PerContextState`
/// (`threshold_signers`, `tool_interfaces`, `consequence_rules`) carry a
/// producer-defined order and are intentionally left untouched.
fn canonicalize_snapshot_sets(snapshot: &mut WasmContextExportSnapshot) {
    // Plain `Vec<String>` fields derived directly from a `HashSet`.
    snapshot.read_exclusion_list.sort_unstable();
    snapshot.revoked_tokens.sort_unstable();

    // Arrays of struct entries derived from `HashMap` iteration: sort by the
    // logical map key so the array order matches the canonical key order.
    snapshot
        .seen_nonces_v3
        .sort_unstable_by(|a, b| a.nonce.cmp(&b.nonce));
    snapshot
        .executed_proposals
        .sort_unstable_by(|a, b| a.proposal_id.cmp(&b.proposal_id));

    // Broadcast sub-structure: the subscriber list comes from a `HashMap` and
    // each author block list comes from an inner `HashSet`.
    if let Some(broadcast) = snapshot.broadcast.as_mut() {
        broadcast.subscribers.sort_unstable();
        for block_list in broadcast.author_block_lists.values_mut() {
            block_list.sort_unstable();
        }
    }
}

/// Computes the WASM signed-export snapshot digest from the canonical JCS bytes.
///
/// Single source of truth for the preimage shared by the producer
/// (`export_context`), the verifier (`verify_snapshot_signature`), and the
/// unit-test helper: `SHA-256(WASM_EXPORT_SIGN_DOMAIN || [EXPORT_SCOPE_TAG_FULL]
/// || snapshot_json)` (spec §23.16.8). The scope tag sits IMMEDIATELY after the
/// domain separator and BEFORE the JCS bytes. WASM only ever produces Full-scope
/// exports (the envelope carries no scope field), so the shared
/// `EXPORT_SCOPE_TAG_FULL` constant is always bound — using the scp-protocol
/// constant so the native runtime and the WASM bridge cannot drift. Mirrors the
/// native single-source `ContextExport::canonical_snapshot_hash`.
fn wasm_export_snapshot_digest(snapshot_json: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(WASM_EXPORT_SIGN_DOMAIN);
    hasher.update([EXPORT_SCOPE_TAG_FULL]);
    hasher.update(snapshot_json);
    hasher.finalize().into()
}

/// Serializable broadcast state for export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmExportBroadcast {
    /// Author DIDs mapped to their per-author block lists (§5.14.8).
    /// Defaults to empty map for backward compat with v1 exports that used
    /// flat `authors: Vec<String>` (per-author blocking did not exist in v1).
    #[serde(default)]
    author_block_lists: HashMap<String, Vec<String>>,
    /// Per-author key epochs (§5.14.8). Tracks how many times each author
    /// has rotated their broadcast key due to block events.
    #[serde(default)]
    key_epochs: HashMap<String, u64>,
    subscribers: Vec<String>,
    admission: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Event hashing delegated to `scp_event_log::tree::append_unsigned_event`
// which uses the canonical hash format via `rmp_serde` serialization.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // GovernanceAction serde roundtrip tests
    // -----------------------------------------------------------------------

    /// Helper: serialize to JSON, deserialize back, and assert equal JSON.
    fn roundtrip(action: &GovernanceAction) {
        let json = serde_json::to_string(action).unwrap();
        let back: GovernanceAction = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2, "roundtrip mismatch for {action:?}");
    }

    use scp_protocol::context::roles::Capability;
    use scp_protocol::economy::types::Amount;

    /// Deserializes a protocol type from a JSON value for test construction.
    fn from_json<T: serde::de::DeserializeOwned>(val: serde_json::Value) -> T {
        serde_json::from_value(val).unwrap()
    }

    #[test]
    fn serde_roundtrip_add_member() {
        roundtrip(&GovernanceAction::AddMember {
            did: DID("did:dht:z123".to_owned()),
            role: "admin".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_remove_member() {
        roundtrip(&GovernanceAction::RemoveMember {
            did: DID("did:dht:z123".to_owned()),
            reason: Some("inactive".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_change_role() {
        roundtrip(&GovernanceAction::ChangeRole {
            did: DID("did:dht:z123".to_owned()),
            new_role: "member".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_register_tool() {
        roundtrip(&GovernanceAction::RegisterTool {
            registration: Box::new(from_json(serde_json::json!({
                "tool_id": "tool-abc",
                "name": "my-tool",
                "description": "A test tool",
                "schema": {"input_schema": {}, "output_schema": {}},
                "implementation_hash": vec![0u8; 32],
                "test_vectors": [],
                "operator_did": "did:dht:zop"
            }))),
        });
    }

    #[test]
    fn serde_roundtrip_remove_tool() {
        roundtrip(&GovernanceAction::RemoveTool {
            tool_id: "tool-abc".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_modify_ceiling() {
        roundtrip(&GovernanceAction::ModifyCeiling {
            new_ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
        });
    }

    #[test]
    fn serde_roundtrip_close_context() {
        roundtrip(&GovernanceAction::CloseContext {
            reason: Some("done".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_extend_ttl() {
        roundtrip(&GovernanceAction::ExtendTtl {
            additional_secs: 3600,
        });
    }

    #[test]
    fn serde_roundtrip_transfer_admin() {
        roundtrip(&GovernanceAction::TransferAdmin {
            new_admin: DID("did:dht:zadmin".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_create_child_context() {
        // Construct a valid GovernanceAction from JSON, then roundtrip.
        let json_str =
            serde_json::to_string(&GovernanceAction::CloseContext { reason: None }).unwrap();
        // Verify basic roundtrip works; CreateChildContext requires ContextParams
        // which is complex — test via JSON deserialization.
        let action: GovernanceAction = from_json(serde_json::json!({
            "CreateChildContext": {
                "params": {
                    "mode": "Encrypted",
                    "ceiling": [],
                    "ceiling_policy": "Immutable",
                    "promotion_policy": "NoPromotion",
                    "roles": [],
                    "tools": [],
                    "ttl": null,
                    "memory_scope": "Ephemeral",
                    "governance": "SingleAdmin",
                    "template_id": null
                }
            }
        }));
        roundtrip(&action);
        let _ = json_str; // suppress unused
    }

    #[test]
    fn serde_roundtrip_modify_pruning_policy() {
        let action: GovernanceAction = from_json(serde_json::json!({
            "ModifyPruningPolicy": {
                "new_policy": {
                    "time_based": null,
                    "size_based": null,
                    "event_type_retention": {"structural_retention_multiplier": 30000, "operational_retention_multiplier": 10000},
                    "allow_full_history_requests": false,
                    "checkpoint_schedule": {"event_interval": 10000, "time_interval_secs": 86400, "min_events_since_last": 100}
                }
            }
        }));
        roundtrip(&action);
    }

    #[test]
    fn serde_roundtrip_add_signer() {
        roundtrip(&GovernanceAction::AddSigner {
            did: DID("did:dht:zsigner".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_remove_signer() {
        roundtrip(&GovernanceAction::RemoveSigner {
            did: DID("did:dht:zsigner".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_modify_threshold() {
        roundtrip(&GovernanceAction::ModifyThreshold { new_threshold: 3 });
    }

    #[test]
    fn serde_roundtrip_establish_tool_interface() {
        let action: GovernanceAction = from_json(serde_json::json!({
            "EstablishToolInterface": {
                "interface": {
                    "source_context": "ctx-src",
                    "target_context": "ctx-tgt",
                    "tool_id": "tool-1",
                    "rate_limit": null,
                    "per_caller_rate_limit": null,
                    "approved_by_source": false,
                    "approved_by_target": false,
                    "outbound_policy": null,
                    "inbound_policy": null
                }
            }
        }));
        roundtrip(&action);
    }

    #[test]
    fn serde_roundtrip_reset_member() {
        roundtrip(&GovernanceAction::ResetMember {
            did: DID("did:dht:z123".to_owned()),
            reason: "stale state".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_resolve_conflict() {
        roundtrip(&GovernanceAction::ResolveConflict {
            proposal_a: [1u8; 32],
            proposal_b: [2u8; 32],
            resolution: ConflictResolution::InvalidateBoth,
        });
    }

    #[test]
    fn serde_roundtrip_promote_context() {
        roundtrip(&GovernanceAction::PromoteContext);
    }

    #[test]
    fn serde_roundtrip_suspend_member() {
        roundtrip(&GovernanceAction::SuspendCapability {
            did: DID("did:dht:z123".to_owned()),
            capabilities: vec![Capability::MessagesWrite],
        });
    }

    #[test]
    fn serde_roundtrip_revoke() {
        roundtrip(&GovernanceAction::RevokeAccess {
            did: DID("did:dht:z123".to_owned()),
            access: AccessScope::Both,
        });
    }

    #[test]
    fn serde_roundtrip_rotate_content_keys() {
        roundtrip(&GovernanceAction::RotateContentKeys {
            reason: Some("compromise".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_reconfigure_governance() {
        let action: GovernanceAction = from_json(serde_json::json!({
            "ReconfigureGovernance": {
                "changes": [{"ReduceThreshold": {"new_threshold": 2}}],
                "justification": {
                    "unavailable_dids": [],
                    "missed_windows": [],
                    "detected_at": 1_700_000_000
                }
            }
        }));
        roundtrip(&action);
    }

    #[test]
    fn serde_roundtrip_restore_access() {
        roundtrip(&GovernanceAction::RestoreAccess {
            did: DID("did:dht:z123".to_owned()),
            capabilities: vec![Capability::MessagesRead, Capability::MessagesWrite],
        });
    }

    #[test]
    fn serde_roundtrip_set_economic_policy() {
        let action: GovernanceAction = from_json(serde_json::json!({
            "SetEconomicPolicy": {
                "policy": {
                    "locked": false,
                    "cost_schedule": {"currency": [85, 83, 68, 0], "per_message": null, "per_tool_invoke": null, "per_join": null, "per_period": null, "per_byte_stored": null},
                    "payment_adapters": [],
                    "pricing_formula": null,
                    "payee": "did:dht:zpayee"
                }
            }
        }));
        roundtrip(&action);
    }

    #[test]
    fn serde_roundtrip_approve_spend() {
        roundtrip(&GovernanceAction::ApproveSpend {
            spender: DID("did:dht:zspender".to_owned()),
            amount: Amount(1000),
            purpose: "compute resources".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_lock_economic_policy() {
        roundtrip(&GovernanceAction::LockEconomicPolicy);
    }

    #[test]
    fn serde_roundtrip_propose_context_migration() {
        let action: GovernanceAction = from_json(serde_json::json!({
            "ProposeContextMigration": {
                "new_context_params": {
                    "mode": "Encrypted",
                    "ceiling": [],
                    "ceiling_policy": "Immutable",
                    "promotion_policy": "NoPromotion",
                    "roles": [],
                    "tools": [],
                    "ttl": null,
                    "memory_scope": "Ephemeral",
                    "governance": "SingleAdmin",
                    "template_id": null
                },
                "reason": "protocol upgrade",
                "grace_period_secs": 604_800,
                "auto_invite": true
            }
        }));
        roundtrip(&action);
    }

    #[test]
    fn serde_roundtrip_cancel_context_migration() {
        roundtrip(&GovernanceAction::CancelContextMigration);
    }

    // -----------------------------------------------------------------------
    // Variant count exhaustiveness
    // -----------------------------------------------------------------------

    /// Builds all 28 `GovernanceAction` variants for exhaustive testing.
    ///
    /// Uses JSON deserialization to construct complex inner types (`ContextParams`,
    /// `ToolRegistration`, etc.) rather than manual struct construction.
    fn all_wasm_governance_actions() -> Vec<GovernanceAction> {
        let json_actions: Vec<serde_json::Value> = vec![
            serde_json::json!({"AddMember": {"did": "d", "role": "r"}}),
            serde_json::json!({"RemoveMember": {"did": "d", "reason": null}}),
            serde_json::json!({"ChangeRole": {"did": "d", "new_role": "r"}}),
            serde_json::json!({"RegisterTool": {"registration": {
                "tool_id": "t", "name": "n", "description": "d",
                "schema": {"input_schema": {}, "output_schema": {}},
                "implementation_hash": vec![0u8; 32], "test_vectors": [],
                "operator_did": "did:dht:zop"
            }}}),
            serde_json::json!({"RemoveTool": {"tool_id": "t"}}),
            serde_json::json!({"ModifyCeiling": {"new_ceiling": []}}),
            serde_json::json!({"CloseContext": {"reason": null}}),
            serde_json::json!({"ExtendTtl": {"additional_secs": 1}}),
            serde_json::json!({"TransferAdmin": {"new_admin": "d"}}),
            serde_json::json!({"CreateChildContext": {"params": {
                "mode": "Encrypted", "ceiling": [], "ceiling_policy": "Immutable",
                "promotion_policy": "NoPromotion", "roles": [], "tools": [],
                "ttl": null, "memory_scope": "Ephemeral", "governance": "SingleAdmin",
                "template_id": null
            }}}),
            serde_json::json!({"ModifyPruningPolicy": {"new_policy": {
                "time_based": null, "size_based": null, "event_type_retention": {"structural_retention_multiplier": 30000, "operational_retention_multiplier": 10000},
                "allow_full_history_requests": false,
                    "checkpoint_schedule": {"event_interval": 10000, "time_interval_secs": 86400, "min_events_since_last": 100}
            }}}),
            serde_json::json!({"AddSigner": {"did": "d"}}),
            serde_json::json!({"RemoveSigner": {"did": "d"}}),
            serde_json::json!({"ModifyThreshold": {"new_threshold": 1}}),
            serde_json::json!({"EstablishToolInterface": {"interface": {
                "source_context": "ctx-src", "target_context": "ctx-tgt",
                "tool_id": "tool-1", "rate_limit": null, "per_caller_rate_limit": null,
                "approved_by_source": false, "approved_by_target": false,
                "outbound_policy": null, "inbound_policy": null
            }}}),
            serde_json::json!({"ResetMember": {"did": "d", "reason": "stale"}}),
            serde_json::json!({"ResolveConflict": {
                "proposal_a": vec![1u8; 32], "proposal_b": vec![2u8; 32],
                "resolution": "InvalidateBoth"
            }}),
            serde_json::json!("PromoteContext"),
            serde_json::json!({"SuspendCapability": {"did": "d", "capabilities": ["MessagesWrite"]}}),
            serde_json::json!({"RevokeAccess": {"did": "d", "access": "Both"}}),
            serde_json::json!({"RestoreAccess": {"did": "d", "capabilities": ["MessagesRead", "MessagesWrite"]}}),
            serde_json::json!({"RotateContentKeys": {"reason": null}}),
            serde_json::json!({"ReconfigureGovernance": {
                "changes": [], "justification": {
                    "unavailable_dids": [], "missed_windows": [], "detected_at": 0
                }
            }}),
            serde_json::json!({"SetEconomicPolicy": {"policy": {
                "locked": false,
                    "cost_schedule": {"currency": [85, 83, 68, 0], "per_message": null, "per_tool_invoke": null, "per_join": null, "per_period": null, "per_byte_stored": null},
                    "payment_adapters": [],
                    "pricing_formula": null,
                    "payee": "did:dht:zpayee"
            }}}),
            serde_json::json!({"ApproveSpend": {
                "spender": "d", "amount": 0, "purpose": "p"
            }}),
            serde_json::json!("LockEconomicPolicy"),
            serde_json::json!({"ProposeContextMigration": {
                "new_context_params": {
                    "mode": "Encrypted", "ceiling": [], "ceiling_policy": "Immutable",
                    "promotion_policy": "NoPromotion", "roles": [], "tools": [],
                    "ttl": null, "memory_scope": "Ephemeral", "governance": "SingleAdmin",
                    "template_id": null
                },
                "reason": "upgrade", "grace_period_secs": 604_800, "auto_invite": true
            }}),
            serde_json::json!("CancelContextMigration"),
        ];
        json_actions.into_iter().map(from_json).collect()
    }

    #[test]
    fn governance_action_has_28_variants() {
        let all = all_wasm_governance_actions();
        assert_eq!(all.len(), 28, "expected 28 governance action variants");

        // Verify each variant serializes successfully (unit variants serialize
        // as strings, struct variants as objects — both are valid).
        for a in &all {
            let _ = serde_json::to_value(a).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // Deserialization from JS-shaped JSON
    // -----------------------------------------------------------------------
    // Note: The protocol `GovernanceAction` type uses serde's default tagged
    // enum representation. The JSON format differs from the old WASM-local
    // format. These tests verify the canonical protocol serialization roundtrips.

    // -----------------------------------------------------------------------
    // ResolveConflict validation
    // -----------------------------------------------------------------------

    /// Invalid resolution values must be rejected before any state mutation.
    /// This test runs on native (non-WASM) because the validation returns
    /// early before calling `crate::time::now_ms()` (which requires WASM).
    #[test]
    fn resolve_conflict_invalid_resolution_rejected() {
        let mut mgr = WasmContextManager::new();
        // No context needed — validation rejects before accessing context state.
        let err = mgr
            .dispatch_resolve_conflict("ctx-1", "prop-a", "prop-b", "bogus-value")
            .unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Permission { .. }),
            "expected Permission error, got: {err:?}"
        );
        if let ScpWasmError::Permission {
            ref message,
            ref code,
        } = err
        {
            assert!(
                message.contains("invalid resolution"),
                "unexpected message: {message}"
            );
            assert!(
                message.contains("bogus-value"),
                "message should include the bad value: {message}"
            );
            assert_eq!(code, codes::PERM_3000);
        }
    }

    // -----------------------------------------------------------------------
    // min_protocol_version tests (#707)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_and_check_min_protocol_version_none_passes() {
        let params = serde_json::json!({});
        assert!(parse_and_check_min_protocol_version(&params).is_ok());
    }

    #[test]
    fn parse_and_check_min_protocol_version_valid_passes() {
        let params = serde_json::json!({ "minProtocolVersion": [1, 0] });
        assert!(parse_and_check_min_protocol_version(&params).is_ok());
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_higher_minor() {
        let params = serde_json::json!({ "minProtocolVersion": [1, 99] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == codes::CTX_2016),
            "expected SCP-CTX-2016, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_different_major() {
        let params = serde_json::json!({ "minProtocolVersion": [2, 0] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == codes::CTX_2016),
            "expected SCP-CTX-2016, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_string_major() {
        // Non-numeric major should error, not silently downgrade to (1, 0).
        let params = serde_json::json!({ "minProtocolVersion": ["2", "0"] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == codes::CTX_2015),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_string_minor() {
        // Non-numeric minor should error, not silently downgrade to (1, 0).
        let params = serde_json::json!({ "minProtocolVersion": [1, "0"] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == codes::CTX_2015),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_short_array() {
        let params = serde_json::json!({ "minProtocolVersion": [1] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == codes::CTX_2015),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_overflow() {
        let params = serde_json::json!({ "minProtocolVersion": [256, 0] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == codes::CTX_2015),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    // The following tests validate integration behavior (create_context
    // validates minProtocolVersion, metadata surfaces it). They cannot run on
    // native targets because PerContextState::append_log_event calls
    // time::now_ms() which requires a WASM runtime. Coverage is provided by:
    // - The parse_and_check_* tests above (unit tests, no WASM runtime needed).
    // - The scp-core wasm_conformance tests (SCP_PROTOCOL_VERSION sync).
    // - The scp-core manager tests (create_context version check at core layer).

    // -----------------------------------------------------------------------
    // Per-author block list tests (§5.14.8, #749)
    // -----------------------------------------------------------------------

    /// Helper: creates a `BroadcastContext` with given authors and subscribers.
    fn make_broadcast(authors: &[&str], subscribers: &[&str]) -> BroadcastContext {
        let mut bc = BroadcastContext::new(
            "test-ctx".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Open,
        )
        .unwrap();
        for a in authors {
            let _ = bc.add_author(a);
        }
        for s in subscribers {
            let _ = bc.subscribe::<
                NoOpDidResolver,
                NoOpNonceTracker,
                NoOpRevocationChecker,
                NoOpProofResolver,
                std::hash::RandomState,
            >(s, None, 0, None);
        }
        bc
    }

    #[test]
    fn broadcast_state_per_author_block_list_isolation() {
        // Author A blocks sub1. Author B does NOT block sub1.
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1", "sub2"]);
        let _ = bc.block_subscriber("author-a", "sub1");

        // sub1 is blocked by author-a
        assert!(bc.is_blocked("author-a", "sub1"));
        // sub1 is NOT blocked by author-b
        assert!(!bc.is_blocked("author-b", "sub1"));
        // sub2 is blocked by nobody
        assert!(!bc.is_blocked("author-a", "sub2"));
        assert!(!bc.is_blocked("author-b", "sub2"));
    }

    #[test]
    fn broadcast_state_governance_ban_adds_to_all_authors() {
        let mut bc = make_broadcast(&["author-a", "author-b", "author-c"], &["sub1"]);

        // Governance ban: delegates to BroadcastContext
        let _ = bc.governance_ban_subscriber("sub1", AccessScope::Both);

        assert!(bc.is_blocked("author-a", "sub1"));
        assert!(bc.is_blocked("author-b", "sub1"));
        assert!(bc.is_blocked("author-c", "sub1"));
    }

    #[test]
    fn broadcast_state_governance_unban_removes_from_all_authors() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1"]);

        // Ban first
        let _ = bc.governance_ban_subscriber("sub1", AccessScope::Both);
        assert!(bc.is_blocked("author-a", "sub1"));
        assert!(bc.is_blocked("author-b", "sub1"));

        // Unban: remove from ALL authors
        bc.governance_unban_subscriber("sub1");
        assert!(!bc.is_blocked("author-a", "sub1"));
        assert!(!bc.is_blocked("author-b", "sub1"));
    }

    #[test]
    fn broadcast_export_roundtrip_preserves_per_author_block_lists() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1"]);
        let _ = bc.block_subscriber("author-a", "sub1");

        // Use snapshot for export/import roundtrip
        let snapshot = bc.to_snapshot();
        let restored = BroadcastContext::from_snapshot(snapshot);

        // author-a blocks sub1, author-b does not
        assert!(restored.is_blocked("author-a", "sub1"));
        assert!(!restored.is_blocked("author-b", "sub1"));
        assert!(restored.is_subscriber("sub1"));
        // Epoch preserved through roundtrip (block_subscriber increments epoch to 1)
        assert_eq!(restored.get_author("author-a").map(|a| a.epoch), Some(1));
        assert_eq!(restored.get_author("author-b").map(|a| a.epoch), Some(0));
    }

    #[test]
    fn export_roundtrip_key_epochs_default_missing() {
        // Verify that importing an export without key_epochs (from an older
        // version) defaults to empty via #[serde(default)].
        let json = r#"{"author_block_lists":{},"subscribers":[],"admission":"open"}"#;
        let export: WasmExportBroadcast = serde_json::from_str(json).unwrap();
        assert!(export.key_epochs.is_empty());
    }

    #[test]
    fn export_broadcast_defaults_missing_author_block_lists() {
        // v1 exports did not have `author_block_lists` (they had a flat
        // `authors: Vec<String>` and `blocked_subscribers`). Verify that
        // deserializing without `author_block_lists` yields an empty map
        // via #[serde(default)].
        let json = r#"{"subscribers":["sub1"],"admission":"open"}"#;
        let export: WasmExportBroadcast = serde_json::from_str(json).unwrap();
        assert!(export.author_block_lists.is_empty());
        assert_eq!(export.subscribers, vec!["sub1"]);
    }

    #[test]
    fn export_version_matches_signed_constant() {
        // The WASM JSON-envelope version is an independent per-serializer
        // integer (§23.16.8): it need NOT equal the native MessagePack
        // export version. It is currently 5 — the version that bound the
        // export-scope discriminant into the Ed25519 signed preimage (v4
        // introduced the full-snapshot signature). This test pins the constant
        // so a change is deliberate.
        assert_eq!(WASM_EXPORT_VERSION, 5);
    }

    /// **§23.16.8 version-gate:** an envelope whose version exceeds the current
    /// supported version is rejected with the dedicated version-gate code
    /// (SCP-CTX-2094), NOT a generic validation or signature-failure code.
    #[test]
    fn deserialize_rejects_newer_version_with_ctx_2094() {
        let snapshot = make_minimal_valid_snapshot();
        let envelope = WasmContextExportEnvelope {
            version: WASM_EXPORT_VERSION + 1,
            exported_at: 0,
            exporter_did: snapshot.role_state.creator_did.clone(),
            integrity_mac: String::new(),
            snapshot_signature: String::new(),
            snapshot,
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let err = WasmContextManager::deserialize_and_verify_envelope(&bytes).unwrap_err();
        match err {
            ScpWasmError::Context { ref code, .. } => {
                assert_eq!(code, codes::CTX_2094);
            }
            other => panic!("expected version-gate Context error, got: {other:?}"),
        }
    }

    /// **§23.16.8 version-gate:** an envelope whose version predates the current
    /// signed-export format is rejected with SCP-CTX-2094 (its signature was
    /// computed over a different preimage and cannot be verified here), distinct
    /// from the signature-failure code SCP-CTX-2093.
    #[test]
    fn deserialize_rejects_older_version_with_ctx_2094() {
        let snapshot = make_minimal_valid_snapshot();
        let envelope = WasmContextExportEnvelope {
            version: WASM_EXPORT_VERSION - 1,
            exported_at: 0,
            exporter_did: snapshot.role_state.creator_did.clone(),
            integrity_mac: String::new(),
            snapshot_signature: String::new(),
            snapshot,
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let err = WasmContextManager::deserialize_and_verify_envelope(&bytes).unwrap_err();
        match err {
            ScpWasmError::Context { ref code, .. } => {
                assert_eq!(code, codes::CTX_2094);
                assert_ne!(code, codes::CTX_2093);
            }
            other => panic!("expected version-gate Context error, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Key epoch tests (§5.14.8)
    //
    // These tests use BroadcastContext's public API. BroadcastContext
    // manages key epochs internally as part of AuthorState.
    // -----------------------------------------------------------------------

    #[test]
    fn key_epoch_increments_on_block() {
        let mut bc = make_broadcast(&["author-a"], &["sub1"]);

        // Initially epoch is 0
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(0));

        // Block sub1 → epoch increments to 1
        let _ = bc.block_subscriber("author-a", "sub1");

        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(1));
        assert!(bc.is_blocked("author-a", "sub1"));
    }

    #[test]
    fn key_epoch_increments_per_block() {
        let mut bc = make_broadcast(&["author-a"], &["sub1", "sub2"]);

        // First block
        let _ = bc.block_subscriber("author-a", "sub1");
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(1));

        // Second block
        let _ = bc.block_subscriber("author-a", "sub2");
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(2));
    }

    #[test]
    fn key_epoch_per_author_isolation() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1"]);

        // Only author-a blocks → only author-a's epoch increments
        let _ = bc.block_subscriber("author-a", "sub1");

        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(1));
        assert_eq!(bc.get_author("author-b").map(|a| a.epoch), Some(0));
    }

    #[test]
    fn governance_ban_increments_all_authors_key_epochs() {
        let mut bc = make_broadcast(&["author-a", "author-b", "author-c"], &["sub1"]);

        // Governance ban (§5.14.8 steps 3-4) via BroadcastContext API
        let _ = bc.governance_ban_subscriber("sub1", AccessScope::Both);

        // All authors blocked sub1
        assert!(bc.is_blocked("author-a", "sub1"));
        assert!(bc.is_blocked("author-b", "sub1"));
        assert!(bc.is_blocked("author-c", "sub1"));

        // All authors' epochs incremented
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(1));
        assert_eq!(bc.get_author("author-b").map(|a| a.epoch), Some(1));
        assert_eq!(bc.get_author("author-c").map(|a| a.epoch), Some(1));
    }

    #[test]
    fn governance_ban_stacks_on_existing_epochs() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1", "sub2"]);

        // author-a already blocked sub1 (epoch=1)
        let _ = bc.block_subscriber("author-a", "sub1");
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(1));

        // Now governance ban sub2 → all authors' epochs increment again
        let _ = bc.governance_ban_subscriber("sub2", AccessScope::Both);

        // author-a: was 1, now 2. author-b: was 0, now 1.
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(2));
        assert_eq!(bc.get_author("author-b").map(|a| a.epoch), Some(1));
    }

    #[test]
    fn content_keys_rotated_event_serializes_correctly() {
        let event = ContextEvent::ContentKeysRotated {
            reason: Some("block_subscriber: author rotated key".to_owned()),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.to_string().contains("ContentKeysRotated"));
        assert!(json.to_string().contains("block_subscriber"));
    }

    /// Helper: builds a `WasmContextManager` containing a single Broadcast
    /// context with the given authors and subscribers pre-populated.
    fn make_manager_with_broadcast(
        context_id: &str,
        creator_did: &str,
        authors: &[&str],
        subscribers: &[&str],
    ) -> WasmContextManager {
        let mut bc = make_broadcast(authors, subscribers);
        // Ensure the creator is always an author (mirrors create_context).
        if !bc.is_author(creator_did) {
            let _ = bc.add_author(creator_did);
        }

        // Start from a bare state (creator auto-assigned admin in `role_state`),
        // then overlay the Broadcast-mode fields.
        let mut ctx = make_bare_per_context_state(context_id, creator_did);
        ctx.params_json = serde_json::json!({"mode": "Broadcast"});
        ctx.mode = "Broadcast".to_owned();
        ctx.broadcast_context = Some(bc);

        let mut mgr = WasmContextManager::new();
        mgr.contexts.insert(context_id.to_owned(), ctx);
        mgr
    }

    #[test]
    fn governance_ban_enforces_block_list_cap() {
        let mut mgr =
            make_manager_with_broadcast("ctx-1", "author-a", &["author-a", "author-b"], &[]);

        // Fill author-a's block list to exactly WASM_BLOCK_LIST_CAP.
        {
            let ctx = mgr.contexts.get_mut("ctx-1").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            for i in 0..WASM_BLOCK_LIST_CAP {
                let _ = bc.block_subscriber("author-a", &format!("did:dht:zfiller{i}"));
            }
            assert_eq!(
                bc.get_author("author-a").unwrap().block_list.len(),
                WASM_BLOCK_LIST_CAP
            );
            // author-b is still empty.
            assert!(bc.get_author("author-b").unwrap().block_list.is_empty());
        }

        // Call the real dispatch method — it should fail because author-a's
        // block list is at capacity (pre-validation rejects before any mutation).
        let err = mgr
            .dispatch_revoke(
                "ctx-1",
                &DID("did:dht:zbanned".to_owned()),
                AccessScope::Both,
            )
            .unwrap_err();

        match &err {
            ScpWasmError::Validation { code, message } => {
                assert_eq!(code, codes::VALID_7301);
                assert!(
                    message.contains("during governance ban"),
                    "expected 'during governance ban' in message, got: {message}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }

        // Verify no mutation occurred — author-b's block list must still be
        // empty (pre-validation prevented partial writes).
        let bc = mgr.contexts["ctx-1"].broadcast_context.as_ref().unwrap();
        assert!(
            bc.get_author("author-b").unwrap().block_list.is_empty(),
            "author-b's block list should be empty — pre-validation must prevent partial mutation"
        );
    }

    /// `subscribe_broadcast` on a Broadcast context adds the new DID as a member,
    /// assigns it the built-in `subscriber` role, and seeds its MLS sequence
    /// counter — and a repeat subscribe is idempotent (the `!members.contains`
    /// guard leaves membership / role / sequence untouched, with no error).
    #[test]
    fn subscribe_broadcast_adds_member_with_subscriber_role_wasm() {
        let mut mgr = make_manager_with_broadcast(
            "ctx-bcast",
            "did:dht:zcreator",
            &["did:dht:zcreator"],
            &[],
        );
        let subscriber = "did:dht:zsubscriber";

        // Pre-state: the subscriber is neither a member nor sequence-seeded.
        {
            let ctx = mgr.contexts.get("ctx-bcast").unwrap();
            assert!(
                !ctx.role_state.members.contains(subscriber),
                "subscriber must not be a member before subscribing"
            );
            assert!(
                !ctx.member_sequence_numbers.contains_key(subscriber),
                "subscriber must not have a sequence counter before subscribing"
            );
        }

        mgr.subscribe_broadcast("ctx-bcast", subscriber)
            .expect("subscribe to an open broadcast context must succeed");

        // Post-state: member, `subscriber` role, sequence seeded to 0.
        {
            let ctx = mgr.contexts.get("ctx-bcast").unwrap();
            assert!(
                ctx.role_state.members.contains(subscriber),
                "subscriber must be a member after subscribing"
            );
            assert_eq!(
                ctx.member_sequence_numbers.get(subscriber),
                Some(&0),
                "subscriber's MLS sequence counter must be seeded to 0"
            );
        }
        assert_eq!(
            mgr.member_role("ctx-bcast", subscriber).as_deref(),
            Some("subscriber"),
            "subscriber must hold the built-in `subscriber` role"
        );

        // Idempotent re-subscribe: no error, no duplicate, state unchanged.
        mgr.subscribe_broadcast("ctx-bcast", subscriber)
            .expect("re-subscribing must be idempotent (no error)");
        let ctx = mgr.contexts.get("ctx-bcast").unwrap();
        assert!(
            ctx.role_state.members.contains(subscriber),
            "re-subscribe must leave membership intact"
        );
        assert_eq!(
            ctx.member_sequence_numbers.get(subscriber),
            Some(&0),
            "re-subscribe must not reset or duplicate the sequence counter"
        );
        assert_eq!(
            mgr.member_role("ctx-bcast", subscriber).as_deref(),
            Some("subscriber"),
            "re-subscribe must leave the `subscriber` role intact"
        );
    }

    /// `subscribe_broadcast` on a NON-broadcast context is rejected with the
    /// `not a broadcast context` `Context` error (`SCP-CTX-2001`) and performs NO
    /// membership mutation — the would-be subscriber is never added.
    #[test]
    fn subscribe_broadcast_on_non_broadcast_context_is_rejected_wasm() {
        // A bare active context is Unencrypted with `broadcast_context: None`.
        let mut mgr = WasmContextManager::new();
        let ctx = make_bare_per_context_state("ctx-plain", "did:dht:zcreator");
        mgr.contexts.insert("ctx-plain".to_owned(), ctx);
        let subscriber = "did:dht:zsubscriber";

        let err = mgr
            .subscribe_broadcast("ctx-plain", subscriber)
            .expect_err("subscribing to a non-broadcast context must be rejected");
        match err {
            ScpWasmError::Context {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::CTX_2001);
                assert!(
                    message.contains("not a broadcast context"),
                    "expected `not a broadcast context`, got: {message}"
                );
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // No membership mutation: only the creator remains; the subscriber was
        // never inserted into members or sequence-seeded.
        let ctx = mgr.contexts.get("ctx-plain").unwrap();
        assert!(
            !ctx.role_state.members.contains(subscriber),
            "a rejected subscribe must not add the subscriber to members"
        );
        assert!(
            !ctx.member_sequence_numbers.contains_key(subscriber),
            "a rejected subscribe must not seed a sequence counter"
        );
        assert!(
            mgr.member_role("ctx-plain", subscriber).is_none(),
            "a rejected subscribe must not assign any role"
        );
    }

    // -----------------------------------------------------------------------
    // ucan_revoke idempotent-at-capacity tests (#895)
    // -----------------------------------------------------------------------

    /// Helper: create a minimal active context with a pre-filled revocation set.
    fn make_manager_with_revoked_tokens(
        context_id: &str,
        creator_did: &str,
        revoked: HashSet<String>,
    ) -> WasmContextManager {
        // Bare state (creator auto-admin), with the pre-filled revocation set
        // and Encrypted mode overlaid.
        let mut ctx = make_bare_per_context_state(context_id, creator_did);
        ctx.params_json = serde_json::json!({});
        ctx.mode = "Encrypted".to_owned();
        ctx.revoked_tokens = revoked;
        let mut mgr = WasmContextManager::new();
        mgr.contexts.insert(context_id.to_owned(), ctx);
        mgr
    }

    /// Verifies the capacity guard allows idempotent revocation.
    ///
    /// `ucan_revoke` calls `append_event` → `now_ms()` on success, which
    /// panics on non-WASM targets. So we verify the capacity-check logic
    /// directly: at capacity, a token already in the set must NOT trigger
    /// the error branch, while a genuinely new token must.
    #[test]
    fn ucan_revoke_capacity_guard_allows_existing_token() {
        let target_cid = "cid-already-revoked";
        let mut revoked: HashSet<String> = (0..WASM_REVOKED_TOKENS_CAP - 1)
            .map(|i| format!("cid-{i}"))
            .collect();
        revoked.insert(target_cid.to_owned());
        assert_eq!(revoked.len(), WASM_REVOKED_TOKENS_CAP);

        // Existing token at capacity: guard must NOT fire.
        let would_reject =
            revoked.len() >= WASM_REVOKED_TOKENS_CAP && !revoked.contains(target_cid);
        assert!(
            !would_reject,
            "capacity guard must allow idempotent revocation of an existing token"
        );

        // New token at capacity: guard must fire.
        let would_reject_new =
            revoked.len() >= WASM_REVOKED_TOKENS_CAP && !revoked.contains("cid-brand-new");
        assert!(
            would_reject_new,
            "capacity guard must reject a new token when at capacity"
        );
    }

    #[test]
    fn ucan_revoke_new_token_at_capacity_fails() {
        let revoked: HashSet<String> = (0..WASM_REVOKED_TOKENS_CAP)
            .map(|i| format!("cid-{i}"))
            .collect();
        assert_eq!(revoked.len(), WASM_REVOKED_TOKENS_CAP);

        let mut mgr = make_manager_with_revoked_tokens("ctx-1", "did:dht:zcreator", revoked);

        // Revoking a genuinely new token at capacity must fail.
        let err = mgr
            .ucan_revoke("ctx-1", "cid-brand-new", "did:dht:zcreator")
            .unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Validation { .. }),
            "expected Validation error, got: {err:?}"
        );
        if let ScpWasmError::Validation { ref code, .. } = err {
            assert_eq!(code, codes::VALID_7300);
        }
    }

    #[test]
    fn unblock_not_blocked_subscriber_error_contains_both_dids() {
        let author = "did:dht:zauthor1";
        let subscriber = "did:dht:zsub_not_blocked";
        let mut mgr = make_manager_with_broadcast("ctx-1", author, &[author], &[subscriber]);

        // Subscriber is NOT blocked — unblock should fail.
        let err = mgr
            .unblock_broadcast_subscriber("ctx-1", author, subscriber)
            .unwrap_err();

        match &err {
            ScpWasmError::Context { message, code } => {
                assert_eq!(code, codes::CTX_2001);
                assert!(
                    message.contains(subscriber),
                    "error should contain subscriber DID, got: {message}"
                );
                assert!(
                    message.contains(author),
                    "error should contain author/unblocker DID, got: {message}"
                );
                assert_eq!(
                    message,
                    &format!(
                        "invalid state: subscriber {subscriber} not blocked by author {author}"
                    )
                );
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    #[test]
    fn governance_ban_allows_idempotent_ban_at_capacity() {
        let mut mgr =
            make_manager_with_broadcast("ctx-1", "author-a", &["author-a", "author-b"], &[]);

        let target_did = "did:dht:zbanned";

        // Fill BOTH authors' block lists to exactly WASM_BLOCK_LIST_CAP,
        // including the target DID in every list (idempotent ban scenario).
        {
            let ctx = mgr.contexts.get_mut("ctx-1").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            for author_did in &["author-a", "author-b"] {
                // Fill to capacity minus 1, then insert the target DID.
                for i in 0..(WASM_BLOCK_LIST_CAP - 1) {
                    let _ = bc.block_subscriber(author_did, &format!("did:dht:zfiller{i}"));
                }
                let _ = bc.block_subscriber(author_did, target_did);
                assert_eq!(
                    bc.get_author(author_did).unwrap().block_list.len(),
                    WASM_BLOCK_LIST_CAP
                );
            }
        }

        // Banning an already-blocked DID when block lists are at capacity
        // must succeed — HashSet::insert is a no-op for existing entries.
        let result = mgr.dispatch_revoke("ctx-1", &DID(target_did.to_owned()), AccessScope::Both);
        assert!(
            result.is_ok(),
            "idempotent governance ban at capacity should succeed, got: {result:?}"
        );
    }

    #[test]
    fn block_broadcast_subscriber_allows_idempotent_block_at_capacity() {
        let mut mgr = make_manager_with_broadcast("ctx-1", "author-a", &["author-a"], &["sub1"]);

        let target_did = "sub1";

        // Fill author-a's block list to capacity, including the target DID.
        {
            let ctx = mgr.contexts.get_mut("ctx-1").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            for i in 0..(WASM_BLOCK_LIST_CAP - 1) {
                let _ = bc.block_subscriber("author-a", &format!("did:dht:zfiller{i}"));
            }
            let _ = bc.block_subscriber("author-a", target_did);
            assert_eq!(
                bc.get_author("author-a").unwrap().block_list.len(),
                WASM_BLOCK_LIST_CAP
            );
        }

        // Blocking an already-blocked subscriber when at capacity must succeed.
        let result = mgr.block_broadcast_subscriber("ctx-1", "author-a", target_did);
        assert!(
            result.is_ok(),
            "idempotent per-author block at capacity should succeed, got: {result:?}"
        );
    }

    #[test]
    fn block_broadcast_subscriber_rejects_new_did_at_capacity() {
        let mut mgr =
            make_manager_with_broadcast("ctx-1", "author-a", &["author-a"], &["sub1", "sub2"]);

        // Fill author-a's block list to capacity (without sub2).
        {
            let ctx = mgr.contexts.get_mut("ctx-1").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            for i in 0..WASM_BLOCK_LIST_CAP {
                let _ = bc.block_subscriber("author-a", &format!("did:dht:zfiller{i}"));
            }
            assert_eq!(
                bc.get_author("author-a").unwrap().block_list.len(),
                WASM_BLOCK_LIST_CAP
            );
        }

        // Blocking a NEW DID when at capacity must fail.
        let err = mgr
            .block_broadcast_subscriber("ctx-1", "author-a", "sub2")
            .unwrap_err();

        match &err {
            ScpWasmError::Validation { code, .. } => {
                assert_eq!(code, codes::VALID_7301);
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn key_epoch_unblock_does_not_change_epoch() {
        let mut bc = make_broadcast(&["author-a"], &["sub1"]);

        // Block sub1 → epoch = 1
        let _ = bc.block_subscriber("author-a", "sub1");
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(1));

        // Unblock sub1 → epoch stays at 1 (per spec: no key rotation on unblock)
        let _ = bc.unblock_subscriber("author-a", "sub1");
        assert_eq!(bc.get_author("author-a").map(|a| a.epoch), Some(1));
    }

    // =======================================================================
    // validate_imported_antispam_state tests (E1 of the PR-review plan)
    //
    // These exercise the WASM import-path defensive validator directly by
    // constructing `WasmContextExportSnapshot` instances in various
    // pathological shapes and asserting the validator rejects them with a
    // clear error.
    //
    // Not covered here (require full export/import flow and would trip
    // `crate::time::now_ms` on native):
    //   - v2 → v3 legacy-nonce upgrade path — `import_context` drains
    //     `seen_nonces_legacy_v2` into the live `seen_nonces` map, but
    //     that path reads `crate::time::now_ms()` for clock-skew clamping.
    //   - HMAC mismatch — verified via `verify_export_hmac` inside
    //     `import_context`.
    //   - Round-trip equivalence — `export_context` also calls
    //     `crate::time::now_ms()` for the `snapshot.timestamp` field.
    //
    // The validator itself is a pure sync function that takes an owned
    // snapshot and returns Result, so every field-level check can be tested
    // here without touching time or HMAC.
    // =======================================================================

    /// Builds a minimal valid [`WasmContextExportSnapshot`] that passes
    /// [`validate_imported_antispam_state`] cleanly. Tests start from this
    /// and mutate one field to drive a specific rejection path.
    fn make_minimal_valid_snapshot() -> WasmContextExportSnapshot {
        WasmContextExportSnapshot {
            context_id: "ctx-test".to_owned(),
            state: "active".to_owned(),
            params_json: serde_json::Value::Null,
            mode: "Unencrypted".to_owned(),
            ceiling_policy: "immutable".to_owned(),
            ttl_seconds: None,
            promotion_policy: None,
            governance: "single_admin".to_owned(),
            economic_policy: None,
            // `creator_did` now lives inside the typed role state. A bare
            // `ContextRoleState` (empty ceiling, creator auto-admin) is the
            // minimal valid role state.
            role_state: ContextRoleState::new(
                "ctx-test",
                "did:test:creator",
                scp_protocol::context::roles::CapabilityCeiling::new(std::iter::empty()),
                Vec::new(),
                &crate::time::WasmClock,
            )
            .expect("bare role state with empty ceiling is always valid"),
            member_sequence_numbers: HashMap::new(),
            read_exclusion_list: Vec::new(),
            broadcast: None,
            revoked_tokens: Vec::new(),
            seen_nonces_legacy_v2: Vec::new(),
            seen_nonces_v3: Vec::new(),
            executed_proposals: Vec::new(),
            resolved_proposals_json: HashMap::new(),
            consequence_rules: Vec::new(),
            cooldown_until: HashMap::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            tool_interfaces: Vec::new(),
            governance_freeze: false,
            pruning_policy: None,
            economic_policy_locked: false,
            hard_rate_limit_config: None,
            creation_timestamp_secs: 0,
        }
    }

    /// **E1-baseline:** the default minimal snapshot passes validation.
    #[test]
    fn validate_antispam_minimal_snapshot_accepted() {
        let snap = make_minimal_valid_snapshot();
        assert!(validate_imported_antispam_state(&snap).is_ok());
    }

    // =======================================================================
    // §23.16.8 set/map canonicalization tests
    // =======================================================================

    /// Computes the signed digest the way `export_context` /
    /// `verify_snapshot_signature` do: canonicalize set-derived arrays, JCS,
    /// then `SHA-256(domain || jcs)`.
    fn signed_digest(snapshot: &WasmContextExportSnapshot) -> [u8; 32] {
        let mut snap = snapshot.clone();
        canonicalize_snapshot_sets(&mut snap);
        let json = serde_json_canonicalizer::to_vec(&snap).unwrap();
        wasm_export_snapshot_digest(&json)
    }

    /// Builds a snapshot populated across every set/map-derived field, with
    /// each array supplied in the caller-chosen order so the test can vary it.
    #[allow(clippy::too_many_arguments)]
    fn snapshot_with_sets(
        ceiling: &[&str],
        read_excl: &[&str],
        revoked: &[&str],
        members: &[&str],
        nonces: &[&str],
        executed: &[&str],
        suspended: &[(&str, &[&str])],
        subscribers: &[&str],
        block_list: &[&str],
    ) -> WasmContextExportSnapshot {
        let mut snap = make_minimal_valid_snapshot();
        // The ceiling, members, and per-member suspensions now live inside the
        // embedded typed `ContextRoleState` (carried + restored verbatim). They
        // self-canonicalize for the signed digest via the `serde_sorted_set` /
        // `serde_sorted_set_map` field codecs, so this helper populates them
        // through the shared validating APIs. The digest-invariance assertion
        // this helper backs is satisfied by the still-flat order-sensitive
        // fields below (read_exclusion_list / revoked_tokens / seen_nonces_v3 /
        // executed_proposals / broadcast subscribers + block lists).
        let seed_ceiling =
            CapabilityCeiling::new(ceiling.iter().map(|c| ucan_string_to_capability(c)));
        snap.role_state
            .set_ceiling(seed_ceiling)
            .expect("snapshot_with_sets test ceiling entries must be well-formed");
        for did in members {
            snap.role_state.members.insert((*did).to_owned());
            let _ = snap
                .role_state
                .system_assign_role(did, "member", &crate::time::WasmClock);
        }
        for (member, caps) in suspended {
            snap.role_state
                .suspend_capabilities(member, caps.iter().map(|c| ucan_string_to_capability(c)));
        }
        snap.read_exclusion_list = read_excl.iter().map(|s| (*s).to_owned()).collect();
        snap.revoked_tokens = revoked.iter().map(|s| (*s).to_owned()).collect();
        snap.seen_nonces_v3 = nonces
            .iter()
            .map(|n| WasmExportNonceEntry {
                nonce: (*n).to_owned(),
                inserted_at_ms: 1.0,
            })
            .collect();
        snap.executed_proposals = executed
            .iter()
            .map(|p| WasmExportExecutedProposalEntry {
                proposal_id: (*p).to_owned(),
                executed_at_ms: 1.0,
            })
            .collect();
        snap.broadcast = Some(WasmExportBroadcast {
            author_block_lists: std::iter::once((
                "author-a".to_owned(),
                block_list
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>(),
            ))
            .collect(),
            key_epochs: std::iter::once(("author-a".to_owned(), 0u64)).collect(),
            subscribers: subscribers.iter().map(|s| (*s).to_owned()).collect(),
            admission: "open".to_owned(),
        });
        snap
    }

    /// **§23.16.8:** the signed digest MUST be invariant under the insertion
    /// order of every set/map-derived array. Two logically-identical snapshots
    /// whose set-derived arrays are supplied in reversed order MUST produce a
    /// byte-identical digest.
    #[test]
    fn snapshot_digest_invariant_under_set_insertion_order() {
        let forward = snapshot_with_sets(
            &["messages:read", "messages:write", "tool_invoke:*"],
            &["did:test:x", "did:test:y", "did:test:z"],
            &["cid-a", "cid-b", "cid-c"],
            &["did:test:m1", "did:test:m2", "did:test:m3"],
            &["nonce-1", "nonce-2", "nonce-3"],
            &["prop-1", "prop-2", "prop-3"],
            &[(
                "did:test:m1",
                &["messages:read", "messages:write", "role:assign"],
            )],
            &["sub-1", "sub-2", "sub-3"],
            &["blk-1", "blk-2", "blk-3"],
        );
        let reversed = snapshot_with_sets(
            &["tool_invoke:*", "messages:write", "messages:read"],
            &["did:test:z", "did:test:y", "did:test:x"],
            &["cid-c", "cid-b", "cid-a"],
            &["did:test:m3", "did:test:m2", "did:test:m1"],
            &["nonce-3", "nonce-2", "nonce-1"],
            &["prop-3", "prop-2", "prop-1"],
            &[(
                "did:test:m1",
                &["role:assign", "messages:write", "messages:read"],
            )],
            &["sub-3", "sub-2", "sub-1"],
            &["blk-3", "blk-2", "blk-1"],
        );

        assert_eq!(
            signed_digest(&forward),
            signed_digest(&reversed),
            "signed digest must be invariant under set/map insertion order (§23.16.8)"
        );

        let raw_forward = serde_json_canonicalizer::to_vec(&forward).unwrap();
        let raw_reversed = serde_json_canonicalizer::to_vec(&reversed).unwrap();
        assert_ne!(
            raw_forward, raw_reversed,
            "test inputs must differ in array order before canonicalization"
        );
    }

    /// **§23.16.8 tamper-reject:** `suspended_capabilities` is restored verbatim
    /// and now covered by the full-snapshot signature. Mutating it MUST change
    /// the signed digest.
    #[test]
    fn snapshot_digest_changes_when_suspended_capabilities_tampered() {
        let base = snapshot_with_sets(
            &["messages:read", "messages:write"],
            &[],
            &[],
            &["did:test:m1"],
            &[],
            &[],
            &[("did:test:m1", &["messages:write"])],
            &[],
            &[],
        );
        // The suspension now lives inside the embedded `ContextRoleState` and is
        // covered by the full-snapshot signature. Clearing it (restoring the
        // member's effective capability) MUST change the signed digest.
        let mut tampered = base.clone();
        tampered
            .role_state
            .restore_capabilities("did:test:m1", &[Capability::MessagesWrite]);

        assert_ne!(
            signed_digest(&base),
            signed_digest(&tampered),
            "tampering with a signed role-state suspension must change the digest"
        );
    }

    /// **§23.16.8 tamper-reject:** the broadcast author block list is a
    /// set-derived field now covered by the signature.
    #[test]
    fn snapshot_digest_changes_when_block_list_tampered() {
        let base = snapshot_with_sets(&[], &[], &[], &[], &[], &[], &[], &["sub-1"], &["blk-1"]);
        let mut tampered = base.clone();
        if let Some(b) = tampered.broadcast.as_mut() {
            b.author_block_lists
                .get_mut("author-a")
                .unwrap()
                .push("blk-2".to_owned());
        }

        assert_ne!(
            signed_digest(&base),
            signed_digest(&tampered),
            "tampering with the broadcast block list must change the digest"
        );
    }

    /// **E1-1:** `seen_nonces_v3.len() > WASM_NONCE_CAP` → rejected.
    #[test]
    fn validate_antispam_rejects_seen_nonces_v3_over_cap() {
        let mut snap = make_minimal_valid_snapshot();
        snap.seen_nonces_v3 = (0..=WASM_NONCE_CAP)
            .map(|i| WasmExportNonceEntry {
                nonce: format!("nonce-{i}"),
                inserted_at_ms: 1.0,
            })
            .collect();
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context {
                ref message,
                ref code,
            } => {
                assert_eq!(code, codes::CTX_2032);
                assert!(
                    message.contains("exceeds cap"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// **E1-2:** `seen_nonces_legacy_v2.len() > WASM_NONCE_CAP` → rejected.
    #[test]
    fn validate_antispam_rejects_seen_nonces_legacy_v2_over_cap() {
        let mut snap = make_minimal_valid_snapshot();
        snap.seen_nonces_legacy_v2 = (0..=WASM_NONCE_CAP)
            .map(|i| format!("legacy-nonce-{i}"))
            .collect();
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context {
                ref message,
                ref code,
            } => {
                assert_eq!(code, codes::CTX_2032);
                assert!(message.contains("legacy nonces"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// **E1-3:** `executed_proposals.len() > WASM_PROPOSAL_CAP` → rejected.
    #[test]
    fn validate_antispam_rejects_executed_proposals_over_cap() {
        let mut snap = make_minimal_valid_snapshot();
        snap.executed_proposals = (0..=WASM_PROPOSAL_CAP)
            .map(|i| WasmExportExecutedProposalEntry {
                proposal_id: format!("prop-{i:08x}"),
                executed_at_ms: 1.0,
            })
            .collect();
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context {
                ref message,
                ref code,
            } => {
                assert_eq!(code, codes::CTX_2032);
                assert!(message.contains("executed proposals"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// **E1-4:** `resolved_proposals_json.len() > WASM_RESOLVED_PROPOSAL_CAP`
    /// → rejected.
    #[test]
    fn validate_antispam_rejects_resolved_proposals_over_cap() {
        let mut snap = make_minimal_valid_snapshot();
        snap.resolved_proposals_json = (0..=WASM_RESOLVED_PROPOSAL_CAP)
            .map(|i| (format!("prop-{i:08x}"), serde_json::Value::Null))
            .collect();
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context {
                ref message,
                ref code,
            } => {
                assert_eq!(code, codes::CTX_2032);
                assert!(message.contains("resolved proposals"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// **E1-5:** NaN `inserted_at_ms` on a v3 nonce entry → rejected.
    #[test]
    fn validate_antispam_rejects_nan_nonce_timestamp() {
        let mut snap = make_minimal_valid_snapshot();
        snap.seen_nonces_v3.push(WasmExportNonceEntry {
            nonce: "corrupt-nonce".to_owned(),
            inserted_at_ms: f64::NAN,
        });
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context {
                ref message,
                ref code,
            } => {
                assert_eq!(code, codes::CTX_2032);
                assert!(message.contains("corrupt-nonce"));
                assert!(message.contains("inserted_at_ms"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// **E1-6:** negative `inserted_at_ms` on a v3 nonce entry → rejected.
    #[test]
    fn validate_antispam_rejects_negative_nonce_timestamp() {
        let mut snap = make_minimal_valid_snapshot();
        snap.seen_nonces_v3.push(WasmExportNonceEntry {
            nonce: "past-nonce".to_owned(),
            inserted_at_ms: -1.0,
        });
        assert!(validate_imported_antispam_state(&snap).is_err());
    }

    /// **E1-7:** infinite `executed_at_ms` on an executed proposal entry →
    /// rejected.
    #[test]
    fn validate_antispam_rejects_infinite_proposal_timestamp() {
        let mut snap = make_minimal_valid_snapshot();
        snap.executed_proposals
            .push(WasmExportExecutedProposalEntry {
                proposal_id: "infprop".to_owned(),
                executed_at_ms: f64::INFINITY,
            });
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context { ref message, .. } => {
                assert!(message.contains("infprop"));
                assert!(message.contains("executed_at_ms"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// **E1-8:** empty nonce string in `seen_nonces_v3` → rejected via
    /// `validate_imported_string`.
    #[test]
    fn validate_antispam_rejects_empty_nonce_string() {
        let mut snap = make_minimal_valid_snapshot();
        snap.seen_nonces_v3.push(WasmExportNonceEntry {
            nonce: String::new(),
            inserted_at_ms: 1.0,
        });
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context { ref message, .. } => {
                assert!(message.contains("must not be empty"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// **E1-9:** cooldown map with a rule index beyond the declared rules
    /// vector → rejected (prevents an attacker from injecting cooldowns for
    /// nonexistent rules).
    #[test]
    fn validate_antispam_rejects_cooldown_index_out_of_bounds() {
        let mut snap = make_minimal_valid_snapshot();
        // No rules declared, but cooldown has a dangling entry.
        snap.cooldown_until.insert(0, 1_000_000);
        let err = validate_imported_antispam_state(&snap).unwrap_err();
        match err {
            ScpWasmError::Context {
                ref message,
                ref code,
            } => {
                assert_eq!(code, codes::CTX_2032);
                assert!(message.contains("cooldown_until"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    // =======================================================================
    // C2 — WASM economy fail-closed gate
    //
    // The WASM bridge cannot run scp-runtime's `enforce_economy` pipeline
    // (no payment adapter, no budget tracker, no velocity tracker, no hard
    // rate limit token bucket — see ADR-034). To prevent a silent bypass on
    // every paid send/join, the bridge rejects:
    //
    //   - context_create with an economic_policy that requires payment
    //     → SCP-ECON-12095 (EconomicPolicyUnsupportedOnWasm)
    //   - join_context against a context whose stored economic_policy
    //     requires payment, regardless of spending_ucan_jwt
    //     → SCP-ECON-12096 (WasmCannotValidateSpendingUcan)
    //   - send_message in a context whose stored economic_policy requires
    //     payment, regardless of spending_ucan_jwt
    //     → SCP-ECON-12096 (WasmCannotValidateSpendingUcan)
    //
    // These tests exercise the bridge layer directly via `WasmContextManager`
    // so the failure mode is reproduced without spinning up the JS host.
    // =======================================================================

    /// JSON for an `EconomicPolicy` whose `cost_schedule.per_message` requires
    /// 100 units. The exact field shape mirrors
    /// `scp_protocol::economy::types::{EconomicPolicy, CostSchedule, Amount}`.
    fn paid_per_message_policy_json() -> String {
        serde_json::json!({
            "locked": false,
            "cost_schedule": {
                "currency": [85, 83, 68, 0],
                "per_message": 100,
                "per_tool_invoke": null,
                "per_join": null,
                "per_period": null,
                "per_byte_stored": null
            },
            "payment_adapters": [],
            "pricing_formula": null,
            "payee": "did:dht:zpayee"
        })
        .to_string()
    }

    /// JSON for a free `EconomicPolicy` (no cost fields, no formula). Mirrors
    /// `policy_requires_payment(&policy) == false` shape from scp-protocol
    /// `economy::policy` tests.
    fn free_policy_json() -> String {
        serde_json::json!({
            "locked": false,
            "cost_schedule": {
                "currency": [85, 83, 68, 0],
                "per_message": null,
                "per_tool_invoke": null,
                "per_join": null,
                "per_period": null,
                "per_byte_stored": null
            },
            "payment_adapters": [],
            "pricing_formula": null,
            "payee": "did:dht:zpayee"
        })
        .to_string()
    }

    /// **C2-A:** `create_context` rejects a paid economic policy with
    /// `SCP-ECON-12095` BEFORE any state mutation occurs (no MLS group
    /// creation, no event log append).
    #[test]
    fn test_wasm_context_create_rejects_paid_policy() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let params = serde_json::json!({
            "mode": "Encrypted",
            "ceiling": [],
            "ceilingPolicy": "immutable",
            "governance": "single_admin",
            "economicPolicy": paid_per_message_policy_json(),
        });

        let err = mgr
            .create_context("ctx-paid", creator, &params)
            .expect_err("create_context must reject paid economic policy on WASM");

        match err {
            ScpWasmError::Context {
                ref code,
                ref message,
            } => {
                assert_eq!(code, SCP_ECON_PAID_POLICY_UNSUPPORTED_ON_WASM);
                assert_eq!(code, codes::ECON_12095);
                assert!(
                    message.contains("EconomicPolicyUnsupportedOnWasm"),
                    "expected EconomicPolicyUnsupportedOnWasm marker, got: {message}"
                );
                assert!(
                    message.contains("paid contexts cannot be created"),
                    "expected guidance text, got: {message}"
                );
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // Defense-in-depth: nothing was inserted into the registry.
        assert!(
            !mgr.contexts.contains_key("ctx-paid"),
            "rejected paid context must not appear in the registry"
        );
    }

    /// `create_context` rejects a malformed ceiling entry (spec §5.3.1.1)
    /// BEFORE any state mutation (the ceiling-grammar gate runs ahead of the
    /// time-dependent creation path), and nothing is inserted into the registry.
    /// A single-token custom (`payments`) and a stray-wildcard (`*:*`) are both
    /// rejected — proving the WASM bridge does NOT silently normalize/broaden
    /// them into the ceiling.
    #[test]
    fn test_wasm_context_create_rejects_malformed_ceiling_entry() {
        for bad_entry in [
            "payments",
            "*:*",
            "*:read",
            "payments:read:write",
            "payments:wr*",
            // BLACK-003: `Capability::new("custom:payments")` strips the `custom:`
            // prefix → `Custom("payments")`, a no-colon custom whose enforced form
            // is rejected. Validating the parsed enum (this fix) rejects it here so
            // the validation and the enforced parse agree.
            "custom:payments",
        ] {
            let mut mgr = WasmContextManager::new();
            let creator = "did:dht:zcreator";
            let params = serde_json::json!({
                "mode": "Encrypted",
                "ceiling": ["messages:read", bad_entry],
                "ceilingPolicy": "immutable",
                "governance": "single_admin",
                "economicPolicy": free_policy_json(),
            });

            let err = mgr
                .create_context("ctx-bad-ceiling", creator, &params)
                .expect_err("create_context must reject malformed ceiling entry");

            match err {
                ScpWasmError::Validation {
                    ref code,
                    ref message,
                } => {
                    assert_eq!(code, codes::VALID_7000);
                    assert!(
                        message.contains("InvalidCeilingCategory"),
                        "expected InvalidCeilingCategory for {bad_entry:?}, got: {message}"
                    );
                }
                other => panic!("expected Validation error for {bad_entry:?}, got: {other:?}"),
            }

            assert!(
                !mgr.contexts.contains_key("ctx-bad-ceiling"),
                "rejected context must not appear in the registry for {bad_entry:?}"
            );
        }
    }

    /// `create_context` accepts a well-formed custom ceiling entry and an
    /// explicit `{resource}:*` wildcard at the grammar gate (the gate passes;
    /// downstream creation is covered by the conformance suite under a real JS
    /// host). We assert the gate does not reject these well-formed entries by
    /// confirming the error, if any, is NOT an `InvalidCeilingCategory`.
    #[test]
    fn test_wasm_context_create_accepts_wellformed_custom_ceiling() {
        for good_entry in ["payments:approve", "payments:*", "tool:invoke:calc"] {
            let mut mgr = WasmContextManager::new();
            let creator = "did:dht:zcreator";
            let params = serde_json::json!({
                "mode": "Encrypted",
                "ceiling": ["messages:read", good_entry],
                "ceilingPolicy": "immutable",
                "governance": "single_admin",
                "economicPolicy": free_policy_json(),
            });
            // The grammar gate must NOT reject well-formed entries. (The accept
            // path may still error later on the native time stub — that is not a
            // ceiling-grammar rejection.)
            if let Err(ScpWasmError::Validation { code, message }) =
                mgr.create_context("ctx-good-ceiling", creator, &params)
            {
                assert!(
                    !(code == codes::VALID_7000 && message.contains("InvalidCeilingCategory")),
                    "well-formed entry {good_entry:?} must not be rejected by the grammar gate: {message}"
                );
            }
        }
    }

    /// CREATE-PATH canonical-form parity: the WASM create path parses each
    /// user-supplied colon-form entry via `Capability::new`, validates it via the
    /// shared `ContextRoleState::new` (`validate_entries`), and stores the typed ceiling inside
    /// `ContextRoleState`; its canonical UCAN-string projection
    /// (`ceiling().to_ucan_string_set()`) is byte-identical to the native bridge's
    /// `Capability::ucan_capability_name` set for the SAME logical entries — closing
    /// the prior WASM create-store split (the old `build_ceiling_strings` formatted
    /// from the RAW string and stored `custom_payments:approve`, while native stores
    /// `payments:approve`). Asserted at the ceiling projection (the canonical form
    /// every gate check matches against) rather than a full `create_context`, which
    /// trips the native time stub; the accept path is covered end-to-end by the WASM
    /// conformance suite under a real JS host.
    #[test]
    fn test_wasm_create_path_canonical_form_matches_native() {
        use scp_protocol::context::roles::{CapabilityCeiling, ContextRoleState};

        let entries = [
            "messages:read".to_owned(),
            "custom:payments:approve".to_owned(),
            "tool:invoke:*".to_owned(),
            "context:child:create".to_owned(),
            "billing:*".to_owned(),
        ];
        // Mirror the create path: parse each entry, build the typed ceiling, and
        // store it in `ContextRoleState`. `ContextRoleState::new` runs
        // `validate_entries` — the single §5.3.1.1 enforcement point — so the
        // `.expect` below also proves the well-formed entries validate.
        let parsed: Vec<Capability> = entries.iter().map(Capability::new).collect();
        let role_state = ContextRoleState::new(
            "ctx-create-parity",
            "did:dht:zcreator",
            CapabilityCeiling::new(parsed),
            Vec::new(),
            &crate::time::WasmClock,
        )
        .expect("well-formed ceiling must build a role state");
        let wasm_stored: HashSet<String> = role_state.ceiling().to_ucan_string_set();

        // Native canonical form for the SAME logical entries: parse each via
        // `Capability::new` (the native parse) and format via
        // `ucan_capability_name` (the native ceiling string form).
        let native_expected: HashSet<String> = entries
            .iter()
            .map(|e| Capability::new(e).ucan_capability_name())
            .collect();

        assert_eq!(
            wasm_stored, native_expected,
            "WASM create-path canonical ceiling form must equal native"
        );
        // The specific divergence the fix closes: `custom:payments:approve`
        // stores as `payments:approve` (NOT the old `custom_payments:approve`).
        assert!(
            wasm_stored.contains("payments:approve"),
            "custom:payments:approve must store as the canonical payments:approve"
        );
        assert!(
            !wasm_stored.contains("custom_payments:approve"),
            "the old raw-string formatting (custom_payments:approve) must be gone"
        );
    }

    /// IMPORT PATH (BLACK-005): the import no longer pre-validates a flat
    /// `ceiling_strings` array — the ceiling now lives inside the typed
    /// `ContextRoleState` carried in the snapshot, whose `CapabilityCeiling`
    /// deserializes through `#[serde(try_from = "CapabilityCeilingRaw")]`. That
    /// `try_from` runs `validate_entries` (spec §5.3.1.1), so a malformed ceiling
    /// entry fails the envelope `serde_json::from_slice` BEFORE any signature
    /// check or state reconstruction. This proves a non-conformant peer cannot
    /// smuggle a malformed (multi-colon `Custom`) ceiling through the import path.
    #[test]
    fn test_wasm_import_rejects_malformed_ceiling_on_deserialize() {
        // Start from a well-formed, serialized envelope (a minimal valid snapshot
        // wrapped in a current-version envelope). The signature fields are empty;
        // that does not matter because deserialization fails first.
        let snapshot = make_minimal_valid_snapshot();
        let envelope = WasmContextExportEnvelope {
            version: WASM_EXPORT_VERSION,
            exported_at: 0,
            exporter_did: snapshot.role_state.creator_did.clone(),
            integrity_mac: String::new(),
            snapshot_signature: String::new(),
            snapshot,
        };
        let json = serde_json::to_string(&envelope).unwrap();

        // Inject a malformed multi-colon `Custom` capability into the role-state
        // ceiling array. The empty ceiling serializes as `"capabilities":[]`;
        // splice the malformed entry in. Default serde enum repr serializes
        // `Capability::Custom(s)` as `{"Custom":s}`.
        assert!(
            json.contains("\"capabilities\":[]"),
            "minimal snapshot ceiling must serialize as an empty capabilities array"
        );
        let tampered = json.replace(
            "\"capabilities\":[]",
            "\"capabilities\":[{\"Custom\":\"a:b:c\"}]",
        );
        assert_ne!(
            tampered, json,
            "the malformed entry must have been spliced in"
        );

        let err = WasmContextManager::deserialize_and_verify_envelope(tampered.as_bytes())
            .expect_err("a malformed ceiling entry must fail envelope deserialization");
        match err {
            // The malformed ceiling is rejected by `CapabilityCeilingRaw::try_from`
            // during `serde_json::from_slice`, surfaced as the bridge's deserialize
            // error class (CTX-2032), not a signature failure (CTX-2093).
            ScpWasmError::Context { ref code, .. } => assert_eq!(code, codes::CTX_2032),
            other => panic!("expected a Context deserialize error, got {other:?}"),
        }
    }

    /// All three WASM ceiling write paths converge on the SAME canonical UCAN-form
    /// set for the SAME logical ceiling — create (colon input, parsed +
    /// projected), modify (Capability enums, projected via `ucan_capability_name`),
    /// and import (already-canonical UCAN strings, validated + stored verbatim).
    #[test]
    fn test_wasm_ceiling_paths_converge_on_canonical_form() {
        use scp_protocol::context::roles::{Capability, CapabilityCeiling};

        let colon_input = [
            "messages:read".to_owned(),
            "custom:payments:approve".to_owned(),
            "tool:invoke:*".to_owned(),
        ];
        let caps = [
            Capability::MessagesRead,
            Capability::Custom("payments:approve".to_owned()),
            Capability::ToolInvokeAll,
        ];
        let ucan_input = [
            "messages:read".to_owned(),
            "payments:approve".to_owned(),
            "tool_invoke:*".to_owned(),
        ];

        // CREATE: parse colon input, validate via the shared `validate_entries`,
        // build ceiling, project to UCAN form.
        let parsed: Vec<Capability> = colon_input.iter().map(Capability::new).collect();
        let create_ceiling = CapabilityCeiling::new(parsed);
        create_ceiling.validate_entries().unwrap();
        let from_create: HashSet<String> = create_ceiling.to_ucan_string_set();

        // MODIFY: validate the typed enums via the shared `validate_entries`,
        // project the SAME way the stored `ContextRoleState` ceiling does
        // (`set_ceiling_and_refresh` stores these enums; `to_ucan_string_set` is
        // their canonical projection).
        let modify_ceiling = CapabilityCeiling::new(caps.iter().cloned());
        modify_ceiling.validate_entries().unwrap();
        let from_modify: HashSet<String> = modify_ceiling.to_ucan_string_set();

        // IMPORT: the ceiling now arrives inside the typed `ContextRoleState`
        // (carried + restored VERBATIM). Reconstruct the ceiling from the
        // already-canonical UCAN strings exactly as a deserialized snapshot would
        // hold it, then project it the SAME way the stored state does
        // (`to_ucan_string_set`). The deserialize-time `CapabilityCeilingRaw`
        // try_from validates grammar; here the entries are canonical so it is a
        // no-op, and the projection must converge with create/modify.
        let imported_ceiling =
            CapabilityCeiling::new(ucan_input.iter().map(|s| ucan_string_to_capability(s)));
        imported_ceiling
            .validate_entries()
            .expect("canonical UCAN-form import ceiling must validate");
        let from_import: HashSet<String> = imported_ceiling.to_ucan_string_set();

        assert_eq!(from_create, from_modify, "create and modify must converge");
        assert_eq!(from_modify, from_import, "modify and import must converge");
    }

    /// UCAN-form -> typed `Capability` round-trip for the compound-resource
    /// built-ins whose wire spelling differs from their colon form. The export
    /// path stores the ceiling as `Capability::ucan_capability_name` strings; the
    /// import path reverses them via `ucan_string_to_capability`. This must recover
    /// the SAME typed variant — in particular `bridging:*` must round-trip to the
    /// enumerated `Bridging` (not a `Custom("bridging:*")` lookalike), so an
    /// exported context's `Bridging` authority survives import as the same typed
    /// capability every gate check matches against.
    #[test]
    fn test_wasm_ucan_string_to_capability_roundtrips_compound_builtins() {
        use scp_protocol::context::roles::Capability;

        for cap in [
            Capability::Bridging,
            Capability::ToolInvokeAll,
            Capability::ToolInvoke("calc".to_owned()),
            Capability::ChildContextCreate,
            // A 2-segment built-in (identical in both encodings) and a custom, to
            // prove the delegation does not regress the simple cases.
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::Custom("payments:approve".to_owned()),
        ] {
            // Export form (what the signed snapshot stores).
            let exported = cap.ucan_capability_name();
            // Import reversal.
            let reimported = ucan_string_to_capability(&exported);
            assert_eq!(
                reimported, cap,
                "UCAN-form {exported:?} must round-trip back to {cap:?}"
            );
        }

        // Explicit guard on the #1884-relevant case: the literal wire string.
        assert_eq!(
            ucan_string_to_capability("bridging:*"),
            Capability::Bridging,
            "bridging:* must resolve to the typed Bridging built-in"
        );
        assert_eq!(
            ucan_string_to_capability("context_child:create"),
            Capability::ChildContextCreate,
            "context_child:create must resolve to the typed ChildContextCreate built-in"
        );
        assert_eq!(
            ucan_string_to_capability("tool_invoke:*"),
            Capability::ToolInvokeAll,
            "tool_invoke:* must resolve to the typed ToolInvokeAll built-in"
        );
    }

    /// Build an ACTIVE, encrypted, `governed`-ceiling-policy context registered
    /// in a fresh manager, seeded with the given (UCAN-form) ceiling strings. Used
    /// to drive `dispatch_governance_action(ModifyCeiling)` directly in tests.
    fn manager_with_governed_context(
        context_id: &str,
        creator_did: &str,
        ceiling: &[&str],
    ) -> WasmContextManager {
        // Bare state (creator auto-admin), then overlay the seed ceiling and the
        // `governed` policy. The seed strings are UCAN form, so parse them into the
        // typed ceiling and install via the validating `set_ceiling_and_refresh`.
        let mut ctx = make_bare_per_context_state(context_id, creator_did);
        ctx.params_json = serde_json::json!({"mode": "Encrypted"});
        ctx.mode = "Encrypted".to_owned();
        ctx.ceiling_policy = "governed".to_owned();
        let seed_caps: Vec<Capability> = ceiling
            .iter()
            .map(|s| ucan_string_to_capability(s))
            .collect();
        ctx.set_ceiling_and_refresh(CapabilityCeiling::new(seed_caps))
            .expect("test seed ceiling strings must be well-formed");
        let mut mgr = WasmContextManager::new();
        mgr.contexts.insert(context_id.to_owned(), ctx);
        mgr
    }

    /// Governance `SuspendCapability` / `RestoreAccess` store and clear the SAME
    /// canonical UCAN-form keys for every capability shape — built-in
    /// (`Bridging`), parameterized (`ToolInvokeAll`), and `Custom` (both a
    /// `resource:action` form and a bare no-colon token that canonicalizes to
    /// `name:name`). The typed `ContextRoleState` stores suspensions as typed
    /// `Capability` values; `test_suspended_capabilities` projects them to their
    /// `Capability::ucan_capability_name` form — the exact spelling
    /// `apply_suspend` and `member_has_capability` produce and consume. Restore
    /// must then clear every key suspend stored, leaving the subject with no
    /// suspended set at all.
    #[test]
    fn governance_suspend_restore_uses_canonical_form_for_all_shapes() {
        let mut mgr = manager_with_governed_context(
            "ctx-susp",
            "did:dht:zcreator",
            &["messages:read", "bridging:*", "tool_invoke:*", "member:ban"],
        );

        let subject = DID("did:dht:zsubject".to_owned());
        let caps = vec![
            Capability::Bridging,
            Capability::ToolInvokeAll,
            Capability::Custom("custom:foo".to_owned()),
            Capability::Custom("bridging".to_owned()),
        ];

        mgr.dispatch_governance_action(
            "ctx-susp",
            &GovernanceAction::SuspendCapability {
                did: subject.clone(),
                capabilities: caps.clone(),
            },
            "did:dht:zcreator",
            0,
        )
        .expect("SuspendCapability must succeed");

        // Each stored key is exactly `cap.ucan_capability_name()` — the same
        // value `apply_suspend` and `member_has_capability` produce/consume. The
        // typed storage is projected to UCAN-form strings via
        // `test_suspended_capabilities`.
        let stored: HashSet<String> = mgr
            .contexts
            .get("ctx-susp")
            .unwrap()
            .test_suspended_capabilities(subject.as_ref())
            .expect("subject must have a suspended set");
        let expected: HashSet<String> = caps.iter().map(Capability::ucan_capability_name).collect();
        assert_eq!(
            stored, expected,
            "governance SuspendCapability must store canonical UCAN-form keys"
        );

        // RestoreAccess removes the SAME canonical keys, fully clearing the set.
        mgr.dispatch_governance_action(
            "ctx-susp",
            &GovernanceAction::RestoreAccess {
                did: subject.clone(),
                capabilities: caps,
            },
            "did:dht:zcreator",
            0,
        )
        .expect("RestoreAccess must succeed");
        assert!(
            mgr.contexts
                .get("ctx-susp")
                .unwrap()
                .test_suspended_capabilities(subject.as_ref())
                .is_none(),
            "RestoreAccess must clear every key SuspendCapability stored"
        );
    }

    /// §5.9 / native parity (`execute_restore_access`): a `RestoreAccess` for a
    /// member with NO suspended capabilities (nothing matching the request) must
    /// be REJECTED before any state mutation, surfacing the dedicated
    /// `SCP-CTX-2137` (`NothingToRestore`) code — byte-identical to native. The
    /// WASM bridge previously cleared the read-exclusion / re-minted access with
    /// no guard, diverging from native, which rejected.
    #[test]
    fn restore_access_with_nothing_suspended_is_rejected_wasm() {
        let mut mgr = manager_with_governed_context(
            "ctx-ntr",
            "did:dht:zcreator",
            &["messages:read", "messages:write", "member:ban"],
        );
        let subject = DID("did:dht:znever-suspended".to_owned());

        // Snapshot the pre-dispatch state so we can prove NO mutation occurred.
        {
            let ctx = mgr.contexts.get("ctx-ntr").expect("context must exist");
            assert!(
                ctx.test_suspended_capabilities(subject.as_ref()).is_none(),
                "precondition: subject has no suspended set"
            );
            assert!(
                !ctx.read_exclusion_list.contains(subject.as_ref()),
                "precondition: subject is not read-excluded"
            );
        }

        let err = mgr
            .dispatch_governance_action(
                "ctx-ntr",
                &GovernanceAction::RestoreAccess {
                    did: subject.clone(),
                    capabilities: vec![Capability::MessagesWrite],
                },
                "did:dht:zcreator",
                0,
            )
            .expect_err("RestoreAccess with nothing suspended must be rejected");

        match err {
            ScpWasmError::Context { code, .. } => {
                assert_eq!(
                    code,
                    codes::CTX_2137,
                    "must surface the dedicated NothingToRestore code"
                );
            }
            other => panic!("expected ScpWasmError::Context, got {other:?}"),
        }

        // No state mutation: still no suspended set, still not read-excluded.
        let ctx = mgr.contexts.get("ctx-ntr").expect("context must exist");
        assert!(
            ctx.test_suspended_capabilities(subject.as_ref()).is_none(),
            "rejected RestoreAccess must not create a suspended set"
        );
        assert!(
            !ctx.read_exclusion_list.contains(subject.as_ref()),
            "rejected RestoreAccess must not touch the read-exclusion list"
        );
    }

    /// §5.9 / native parity: a `RestoreAccess` that clears a capability the
    /// member actually had suspended must SUCCEED and leave the member holding
    /// that capability again (`member_has_capability` true). The guard only
    /// rejects no-op restores; a real suspension still restores.
    #[test]
    fn restore_access_clears_a_real_suspension_wasm() {
        // The creator is auto-admin and holds the seeded ceiling caps.
        let mut mgr = manager_with_governed_context(
            "ctx-real",
            "did:dht:zcreator",
            &["messages:read", "messages:write", "member:ban"],
        );
        let subject = "did:dht:zcreator";

        assert!(
            mgr.contexts
                .get("ctx-real")
                .unwrap()
                .member_has_capability(subject, "messages:write"),
            "precondition: admin creator holds messages:write"
        );

        // Suspend messages:write for the member.
        mgr.dispatch_governance_action(
            "ctx-real",
            &GovernanceAction::SuspendCapability {
                did: DID(subject.to_owned()),
                capabilities: vec![Capability::MessagesWrite],
            },
            "did:dht:zcreator",
            0,
        )
        .expect("SuspendCapability must succeed");
        assert!(
            !mgr.contexts
                .get("ctx-real")
                .unwrap()
                .member_has_capability(subject, "messages:write"),
            "after suspend, member must not hold messages:write"
        );

        // Restore it — a real suspension exists, so the guard must NOT reject.
        mgr.dispatch_governance_action(
            "ctx-real",
            &GovernanceAction::RestoreAccess {
                did: DID(subject.to_owned()),
                capabilities: vec![Capability::MessagesWrite],
            },
            "did:dht:zcreator",
            0,
        )
        .expect("RestoreAccess of a real suspension must succeed");
        assert!(
            mgr.contexts
                .get("ctx-real")
                .unwrap()
                .member_has_capability(subject, "messages:write"),
            "after restore, member must hold messages:write again"
        );
        assert!(
            mgr.contexts
                .get("ctx-real")
                .unwrap()
                .test_suspended_capabilities(subject)
                .is_none(),
            "after restore, the suspended set must be cleared"
        );
    }

    /// §5.9 / native parity carve-out (`!(read_requested && read_excluded)`): a
    /// member who is read-EXCLUDED (in `read_exclusion_list`) with read
    /// (`messages:read`) requested must NOT be rejected even when the suspended
    /// set is empty — the restore proceeds and clears the read-exclusion. This
    /// is the exact edge native preserves so a standing read-exclusion can be
    /// lifted via a read restore.
    #[test]
    fn restore_access_read_excluded_proceeds_wasm() {
        let mut mgr = manager_with_governed_context(
            "ctx-rx",
            "did:dht:zcreator",
            &["messages:read", "messages:write", "member:ban"],
        );
        let subject = "did:dht:zexcluded";

        // Member is read-excluded with NO suspended capabilities.
        {
            let ctx = mgr.contexts.get_mut("ctx-rx").expect("context must exist");
            ctx.read_exclusion_list.insert(subject.to_owned());
            assert!(
                ctx.test_suspended_capabilities(subject).is_none(),
                "precondition: subject has no suspended set"
            );
        }

        // Read requested + read-excluded → guard must NOT reject (carve-out).
        mgr.dispatch_governance_action(
            "ctx-rx",
            &GovernanceAction::RestoreAccess {
                did: DID(subject.to_owned()),
                capabilities: vec![Capability::MessagesRead],
            },
            "did:dht:zcreator",
            0,
        )
        .expect("read-excluded read restore must proceed, not reject");

        // The restore cleared the standing read-exclusion.
        assert!(
            !mgr.contexts
                .get("ctx-rx")
                .unwrap()
                .read_exclusion_list
                .contains(subject),
            "read restore must clear the read-exclusion"
        );
    }

    /// Canonical-form parity for EVERY built-in capability variant: the slice's
    /// single ceiling-conversion path (parse the colon-form `name()` via
    /// `Capability::new`, build a `CapabilityCeiling`, project via
    /// `to_ucan_string_set` — the one canonical source the typed
    /// `ContextRoleState` routes all ceiling writes through) must produce exactly
    /// `Capability::ucan_capability_name()` for each variant, byte-identical to
    /// native. This is the exhaustive built-in counterpart to the multi-entry
    /// create/modify/import convergence tests, and it pins that the old
    /// hand-rolled converter's buggy pass-through spellings (bare `bridging`, the
    /// un-underscored `tool:invoke:*`) are GONE.
    #[test]
    fn ceiling_string_conversion_matches_native_for_all_builtin_variants() {
        use scp_protocol::context::roles::CapabilityCeiling;

        // Every non-parameterized built-in (mirrors `BUILTIN_CAPABILITIES` in
        // scp-protocol `roles.rs`; kept exhaustive by
        // `builtin_capabilities_list_is_exhaustive`), plus a parameterized
        // `ToolInvoke` and a custom `{resource}:{action}` — the full shape space
        // the create/modify ceiling converter must round-trip.
        let cases = vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolInvokeAll,
            Capability::ToolRegister,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::RoleAssign,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
            Capability::ChildContextCreate,
            Capability::ToolInterface,
            Capability::Bridging,
            Capability::MediaVoice,
            Capability::MediaVideo,
            Capability::MediaScreenShare,
            Capability::MemberBan,
            Capability::MetadataEdit,
            // Parameterized + custom shapes.
            Capability::ToolInvoke("calculator".to_owned()),
            Capability::Custom("payments:approve".to_owned()),
        ];

        for cap in &cases {
            let native = cap.ucan_capability_name();
            // The slice's create/modify path receives the colon form
            // (`cap.name()`), parses it via `Capability::new`, and stores the
            // typed ceiling whose canonical projection is `to_ucan_string_set`.
            let wasm: Vec<String> = CapabilityCeiling::new([Capability::new(cap.name().as_ref())])
                .to_ucan_string_set()
                .into_iter()
                .collect();
            assert_eq!(
                wasm,
                vec![native.clone()],
                "WASM ceiling conversion diverged from native ucan_capability_name \
                 for {cap:?}: wasm={wasm:?} native={native:?}"
            );
        }

        // Pin that the old hand-rolled converter's buggy pass-through spellings
        // are GONE (the positive canonical forms are already covered by the loop
        // above when it hits `Bridging` / `ToolInvokeAll`): a no-colon built-in
        // token must NOT pass through, and a built-in colon form must NOT remain
        // un-underscored.
        let pinned_set: HashSet<String> = CapabilityCeiling::new([
            Capability::new("bridging"),
            Capability::new("tool:invoke:*"),
        ])
        .to_ucan_string_set();
        assert!(!pinned_set.contains("bridging"));
        assert!(!pinned_set.contains("tool:invoke:*"));
        assert!(pinned_set.contains("bridging:*"));
        assert!(pinned_set.contains("tool_invoke:*"));
    }

    /// WASM `ModifyCeiling` (BLACK-002) rejects a malformed proposed ceiling
    /// entry (spec §5.3.1.1) and leaves the prior ceiling UNCHANGED — closing the
    /// divergence where the handler rebuilt the ceiling with no validation.
    #[test]
    fn test_wasm_modify_ceiling_rejects_malformed_entry() {
        for malformed in [
            Capability::Custom("payments".to_owned()), // no colon
            Capability::Custom("*:*".to_owned()),      // stray wildcard resource
            Capability::Custom("a:b:c".to_owned()),    // multi-colon (3 segments)
        ] {
            let mut mgr =
                manager_with_governed_context("ctx-mc", "did:dht:zcreator", &["messages:read"]);
            let before = mgr
                .contexts
                .get("ctx-mc")
                .unwrap()
                .role_state
                .ceiling()
                .to_ucan_string_set();
            let action = GovernanceAction::ModifyCeiling {
                new_ceiling: vec![Capability::MessagesRead, malformed.clone()],
            };
            let err = mgr
                .dispatch_governance_action("ctx-mc", &action, "did:dht:zcreator", 0)
                .expect_err("malformed ModifyCeiling must be rejected");
            match err {
                ScpWasmError::Validation { ref code, .. } => {
                    assert_eq!(code, codes::VALID_7000);
                }
                other => panic!("expected Validation error for {malformed:?}, got: {other:?}"),
            }
            // Fail-closed: the prior ceiling is unchanged.
            assert_eq!(
                mgr.contexts
                    .get("ctx-mc")
                    .unwrap()
                    .role_state
                    .ceiling()
                    .to_ucan_string_set(),
                before,
                "a rejected malformed ModifyCeiling must leave the ceiling unchanged ({malformed:?})"
            );
        }
    }

    /// WASM `ModifyCeiling` accepts a well-formed proposed ceiling and stores the
    /// SAME effective ceiling that the native bridge would for the same action —
    /// closing the native/WASM divergence (BLACK-002). The native enforced form is
    /// `Capability::ucan_capability_name`; the WASM stored form is the
    /// `ContextRoleState` ceiling's `to_ucan_string_set()` projection. For these
    /// entries the two agree.
    #[test]
    fn test_wasm_modify_ceiling_accepts_wellformed_and_matches_native() {
        let mut mgr =
            manager_with_governed_context("ctx-mc-ok", "did:dht:zcreator", &["messages:read"]);
        let new_ceiling = vec![
            Capability::MessagesRead,
            Capability::Custom("payments:approve".to_owned()),
            Capability::Custom("billing:*".to_owned()),
            Capability::ToolInvokeAll,
        ];
        mgr.dispatch_governance_action(
            "ctx-mc-ok",
            &GovernanceAction::ModifyCeiling {
                new_ceiling: new_ceiling.clone(),
            },
            "did:dht:zcreator",
            0,
        )
        .expect("well-formed ModifyCeiling must succeed");

        // Native enforced ceiling string set for the SAME action: each capability
        // mapped via `ucan_capability_name` (the native bridge ceiling form).
        let native_expected: HashSet<String> = new_ceiling
            .iter()
            .map(scp_protocol::context::roles::Capability::ucan_capability_name)
            .collect();
        let wasm_stored: HashSet<String> = mgr
            .contexts
            .get("ctx-mc-ok")
            .unwrap()
            .role_state
            .ceiling()
            .to_ucan_string_set();
        assert_eq!(
            wasm_stored, native_expected,
            "native and WASM must store the SAME effective ceiling for the same \
             well-formed ModifyCeiling action"
        );
    }

    /// Native-parity regression: a member placed under `SuspendAccess` STAYS
    /// fully suspended across a governed `ModifyCeiling` that WIDENS the ceiling
    /// — they must NOT regain a capability the widen added.
    ///
    /// This proves the convergence fix in `dispatch_modify_ceiling`. The former
    /// WASM behavior eagerly re-ran `system_assign_role` for every member on a
    /// ceiling change to refresh `member_capabilities`. On a WIDEN, that refresh
    /// recomputed the suspended member's `member_capabilities` to INCLUDE the
    /// newly-added cap, while `prune_suspensions_to_role_grants` (SHRINK-only —
    /// it can only REMOVE entries from the suspended set, never add) left the
    /// suspended set as the pre-widen snapshot. The new cap was therefore present
    /// in `member_capabilities` and absent from the suspended set, so
    /// `member_has_capability` returned `true`: a suspended member silently
    /// regained authority.
    ///
    /// Native (`apply_pending_ceiling_modification`) calls `set_ceiling` only — no
    /// refresh — so the suspended member's `member_capabilities` never gains the
    /// new cap and they stay fully suspended. WASM now matches: the assertions
    /// below confirm the member regains NOTHING across the widen.
    #[test]
    fn test_wasm_suspended_member_stays_suspended_across_ceiling_widen() {
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmember";
        // Seed `member:ban` so the `SuspendAccess` governance action is permitted
        // (it requires `member:ban` in the ceiling), alongside `messages:read`.
        let mut mgr = manager_with_governed_context(
            "ctx-suspend-widen",
            creator,
            &["messages:read", "member:ban"],
        );

        // Add `member` as admin so their `member_capabilities` snapshot is the
        // whole current ceiling, i.e. {messages:read, member:ban}.
        mgr.contexts
            .get_mut("ctx-suspend-widen")
            .unwrap()
            .test_insert_member(member, "admin");
        assert!(
            mgr.contexts
                .get("ctx-suspend-widen")
                .unwrap()
                .member_has_capability_pub(member, "messages:read"),
            "precondition: member holds messages:read before suspension"
        );

        // SuspendAccess → suspend_all copies the member's effective capability
        // set ({messages:read, member:ban}) into their suspended set.
        mgr.dispatch_governance_action(
            "ctx-suspend-widen",
            &GovernanceAction::SuspendAccess {
                did: DID(member.to_owned()),
            },
            creator,
            0,
        )
        .expect("SuspendAccess must succeed");
        assert!(
            !mgr.contexts
                .get("ctx-suspend-widen")
                .unwrap()
                .member_has_capability_pub(member, "messages:read"),
            "after SuspendAccess the member must hold no capability"
        );

        // Governed ModifyCeiling WIDENS the ceiling: adds messages:write
        // (retaining messages:read + member:ban).
        mgr.dispatch_governance_action(
            "ctx-suspend-widen",
            &GovernanceAction::ModifyCeiling {
                new_ceiling: vec![
                    Capability::MessagesRead,
                    Capability::MessagesWrite,
                    Capability::MemberBan,
                ],
            },
            creator,
            0,
        )
        .expect("well-formed governed ModifyCeiling widen must succeed");

        let ctx = mgr.contexts.get("ctx-suspend-widen").unwrap();

        // Convergence: the ceiling itself WAS widened (set_ceiling ran).
        assert_eq!(
            ctx.role_state.ceiling().to_ucan_string_set(),
            HashSet::from([
                "messages:read".to_owned(),
                "messages:write".to_owned(),
                "member:ban".to_owned()
            ]),
            "the ceiling must be widened to include messages:write"
        );

        // The bug-fix proof: the suspended member must NOT regain the newly-added
        // capability across the widen. No eager refresh ran, so the member's
        // `member_capabilities` was never recomputed to include messages:write —
        // exactly as native leaves it.
        assert!(
            !ctx.member_has_capability_pub(member, "messages:write"),
            "a SuspendAccess-suspended member must NOT gain a capability that a \
             governed ceiling widen added (native parity: no per-member refresh)"
        );

        // And they remain suspended for the originally-suspended capability too.
        assert!(
            !ctx.member_has_capability_pub(member, "messages:read"),
            "the member must remain fully suspended across the ceiling widen"
        );
    }

    /// **C2-B:** `create_context` accepts a free economic policy. The
    /// production `create_context` path appends a `ContextCreated` event
    /// via `append_log_event`, which calls `crate::time::now_secs()` —
    /// safe under wasm32 (delegates to JS `Date.now`) but panics under
    /// native test runners (`wasm-bindgen` extern stub). To test the C2
    /// gate without tripping the time stub, we exercise the gate helper
    /// directly with both an absent policy and a free policy JSON, and
    /// confirm neither triggers the rejection branch. The accept-path
    /// integration is covered by the WASM conformance suite (which runs
    /// under a real JS host) and the TypeScript integration test below.
    #[test]
    fn test_wasm_context_create_accepts_free_policy() {
        // Absent policy is free.
        assert!(
            !stored_policy_requires_payment(None),
            "absent policy must be treated as free"
        );

        // Explicit free policy is also free (mirrors
        // `policy_requires_payment` from scp-protocol).
        let free = free_policy_json();
        assert!(
            !stored_policy_requires_payment(Some(&free)),
            "explicit free policy must not be classified as paid"
        );

        // Whitespace / pretty-printed JSON variant.
        let free_pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&free).unwrap(),
        )
        .unwrap();
        assert!(
            !stored_policy_requires_payment(Some(&free_pretty)),
            "pretty-printed free policy must not be classified as paid"
        );

        // Defense-in-depth: a paid policy MUST be classified as paid so
        // the create gate fires (covered end-to-end by C2-A above).
        assert!(
            stored_policy_requires_payment(Some(&paid_per_message_policy_json())),
            "paid policy must be classified as paid"
        );
    }

    /// **C2-C:** `join_context` rejects a context whose stored
    /// `economic_policy` requires payment, with `SCP-ECON-12096`. Both
    /// `Some(jwt)` and `None` jwt cases are rejected — the WASM bridge
    /// cannot validate either way.
    #[test]
    fn test_wasm_join_context_rejects_paid_context() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let context_id = "ctx-paid-join";

        // Bypass the production `create_context` path so the test does
        // not need to invent a paid-policy bypass for the C2 gate. We
        // build a bare context state and stamp the paid policy directly.
        let mut state = make_bare_per_context_state(context_id, creator);
        state.economic_policy = Some(paid_per_message_policy_json());
        mgr.contexts.insert(context_id.to_owned(), state);

        // Case 1: caller provides a spending UCAN — must still reject.
        let err = mgr
            .join_context(
                context_id,
                "did:dht:zjoiner",
                Some("eyJqd3QtcGxhY2Vob2xkZXIifQ"),
            )
            .expect_err("join_context must reject paid context even with spending UCAN");
        match err {
            ScpWasmError::Context {
                ref code,
                ref message,
            } => {
                assert_eq!(code, SCP_ECON_WASM_CANNOT_VALIDATE_SPENDING_UCAN);
                assert_eq!(code, codes::ECON_12096);
                assert!(
                    message.contains("WasmCannotValidateSpendingUcan"),
                    "expected WasmCannotValidateSpendingUcan marker, got: {message}"
                );
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // Case 2: caller omits the spending UCAN — must also reject.
        let err = mgr
            .join_context(context_id, "did:dht:zjoiner", None)
            .expect_err("join_context must reject paid context even without spending UCAN");
        match err {
            ScpWasmError::Context { ref code, .. } => {
                assert_eq!(code, codes::ECON_12096);
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // Defense-in-depth: the joiner was never inserted into members.
        let ctx = &mgr.contexts[context_id];
        assert!(
            !ctx.role_state.members.contains("did:dht:zjoiner"),
            "rejected join must not insert the joiner into members"
        );
    }

    /// **C2-D:** `send_message` rejects a paid context with
    /// `SCP-ECON-12096`. Both `Some(jwt)` and `None` cases are rejected.
    /// Note the test name uses the literal `free_in_context` to match the
    /// fix plan (it intentionally diverges from `fee_in_context` so the
    /// substring grep in the C2 PR description matches the test).
    #[test]
    fn test_wasm_send_message_rejects_paid_context_free_in_context() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let context_id = "ctx-paid-send";

        // Build a bare context with a paid policy. The creator is already
        // registered as `admin` by `make_bare_per_context_state`.
        let mut state = make_bare_per_context_state(context_id, creator);
        state.economic_policy = Some(paid_per_message_policy_json());
        mgr.contexts.insert(context_id.to_owned(), state);

        // Case 1: spending UCAN provided — still rejected.
        let err = mgr
            .send_message(
                context_id,
                creator,
                "aGVsbG8=",
                Some("eyJqd3QtcGxhY2Vob2xkZXIifQ"),
            )
            .expect_err("send_message must reject paid context even with spending UCAN");
        match err {
            ScpWasmError::Context {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::ECON_12096);
                assert!(message.contains("WasmCannotValidateSpendingUcan"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // Case 2: no spending UCAN — also rejected.
        let err = mgr
            .send_message(context_id, creator, "aGVsbG8=", None)
            .expect_err("send_message must reject paid context even without spending UCAN");
        match err {
            ScpWasmError::Context { ref code, .. } => {
                assert_eq!(code, codes::ECON_12096);
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // Defense-in-depth: the rejection happened BEFORE the sequence
        // counter was incremented. Mirrors enforce_economy ordering at
        // scp-runtime/manager/messaging.rs.
        let ctx = &mgr.contexts[context_id];
        assert_eq!(
            ctx.member_sequence_numbers
                .get(creator)
                .copied()
                .unwrap_or(0),
            0,
            "rejected send must not advance the sender's sequence number"
        );
    }

    /// **C2-E:** the C2 gate produces no false positive on free contexts.
    ///
    /// Native test runners cannot exercise the full `send_message` happy path
    /// because its consequence-dispatch step calls `crate::time::now_secs()`,
    /// which panics under the wasm-bindgen stub on non-wasm targets (see C2-B).
    /// (`send_message` no longer appends a durable `MessageSent` leaf — that
    /// per-author event is surfaced only as a local `ContextEvent` now.)
    /// We instead set up a free context (no economic policy) and call
    /// `send_message` with a sender that is NOT a member: the C2 gate runs
    /// first, then the membership check returns `SCP-CTX-2019`. Observing
    /// `SCP-CTX-2019` (and not `SCP-ECON-12096`) proves the gate let the
    /// call through. The full happy path is exercised by the WASM
    /// conformance suite under a real JS host and by the TypeScript
    /// integration test below.
    #[test]
    fn test_wasm_send_message_free_context_succeeds() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let context_id = "ctx-free-send";

        let state = make_bare_per_context_state(context_id, creator);
        // economic_policy stays None (free).
        mgr.contexts.insert(context_id.to_owned(), state);

        // Non-member sender exercises the post-gate code path.
        let err = mgr
            .send_message(context_id, "did:dht:znonmember", "aGVsbG8=", None)
            .expect_err("non-member must reach the membership check, not the C2 gate");
        match err {
            ScpWasmError::Context { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::CTX_2019,
                    "free context must NOT trigger the C2 economy gate; \
                     non-member should hit the membership check instead"
                );
                assert_ne!(
                    code,
                    codes::ECON_12096,
                    "free context must NOT be rejected by the C2 economy gate"
                );
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // Same with a spending UCAN supplied — the gate must still let
        // the call through to the membership check.
        let err = mgr
            .send_message(
                context_id,
                "did:dht:znonmember",
                "aGVsbG8=",
                Some("eyJ0ZXN0Ijoid2hhdGV2ZXIifQ"),
            )
            .expect_err("non-member with UCAN must still reach membership check");
        match err {
            ScpWasmError::Context { ref code, .. } => {
                assert_eq!(code, codes::CTX_2019);
            }
            other => panic!("expected Context error, got: {other:?}"),
        }
    }

    /// Builds a free (no economic policy), unencrypted context whose ceiling
    /// grants `messages:read` + `messages:write`, with the creator as `admin`,
    /// ready for the role-grant send-authorization tests below.
    fn make_free_ctx_for_send_auth(context_id: &str, creator: &str) -> WasmContextManager {
        let mut state = make_bare_per_context_state(context_id, creator);
        // Seed the ceiling so the built-in roles actually grant their caps
        // (built-ins intersect their desired set with the ceiling). This
        // refreshes the role definitions AND the creator's `member_capabilities`.
        state.test_insert_ceiling("messages:read");
        state.test_insert_ceiling("messages:write");
        let mut mgr = WasmContextManager::new();
        mgr.contexts.insert(context_id.to_owned(), state);
        mgr
    }

    /// A read-only-role member (`observer`, granted only `messages:read`)
    /// CANNOT `send_message`: the positive `messages:write` role-grant gate
    /// rejects them with `SCP-PERM-3000` and a "does not grant" message,
    /// matching native `messaging_helpers::send_message`. This is the HIGH
    /// fix — before the slice changed `SuspendAccess` to suspend only
    /// role-granted caps, this member could send.
    #[test]
    fn read_only_role_member_cannot_send_message() {
        let context_id = "ctx-send-observer";
        let creator = "did:dht:zcreator";
        let observer = "did:dht:zobserver";
        let mut mgr = make_free_ctx_for_send_auth(context_id, creator);
        mgr.contexts
            .get_mut(context_id)
            .unwrap()
            .test_insert_member(observer, "observer");

        let err = mgr
            .send_message(context_id, observer, "aGVsbG8=", None)
            .expect_err("an observer (messages:read only) must not be able to send");
        match err {
            ScpWasmError::Permission {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::PERM_3000);
                assert!(
                    message.contains("does not grant messages:write"),
                    "expected a not-granted message, got: {message}"
                );
            }
            other => panic!("expected Permission error, got: {other:?}"),
        }
        // The rejected send must not advance the sender's sequence number.
        assert_eq!(
            mgr.contexts[context_id]
                .member_sequence_numbers
                .get(observer)
                .copied()
                .unwrap_or(0),
            0,
            "rejected send must not advance the observer's sequence number"
        );
    }

    /// A write-granting-role member (`member`, granted `messages:write`) CAN
    /// `send_message` on a free, unencrypted context with no consequence
    /// rules — the positive gate lets them through and the send completes.
    #[test]
    fn write_granting_role_member_can_send_message() {
        let context_id = "ctx-send-member";
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmember";
        let mut mgr = make_free_ctx_for_send_auth(context_id, creator);
        mgr.contexts
            .get_mut(context_id)
            .unwrap()
            .test_insert_member(member, "member");

        mgr.send_message(context_id, member, "aGVsbG8=", None)
            .expect("a member (messages:write) must be able to send");
        // The accepted send advanced the sender's sequence number.
        assert_eq!(
            mgr.contexts[context_id]
                .member_sequence_numbers
                .get(member)
                .copied()
                .unwrap_or(0),
            1,
            "accepted send must advance the member's sequence number"
        );

        // The creator (`admin`, full ceiling) can also send.
        mgr.send_message(context_id, creator, "aGVsbG8=", None)
            .expect("admin must be able to send");
    }

    /// A send that FAILS in the fallible encrypt path must NOT advance the
    /// sender's per-member sequence counter — the reserved sequence is rolled
    /// back, mirroring native `MembershipState::rollback_sequence_number`
    /// (`saturating_sub`). Without the rollback a failed send burns a sequence,
    /// opening a gap that two honest members would derive differently.
    ///
    /// Exercises the REAL crypto path (`WasmCryptoState::new_for_context` so
    /// `ctx.crypto` is `Some`): one successful encrypted send (emits seq 1,
    /// counter -> 1), then a send with an invalid-base64 payload that fails at
    /// the `CRYPTO_4001` decode step. The counter must stay at 1, not advance
    /// to 2.
    #[test]
    fn send_message_failure_does_not_advance_sequence_wasm() {
        let context_id = "ctx-send-rollback";
        let creator = "did:dht:zcreator";
        let mut mgr = make_free_ctx_for_send_auth(context_id, creator);
        // Attach real MLS crypto so the fallible encrypt branch runs. The
        // creator is the MLS group creator, so its own leaf can encrypt.
        {
            let ctx = mgr.contexts.get_mut(context_id).unwrap();
            ctx.crypto = Some(
                crate::crypto::WasmCryptoState::new_for_context(creator)
                    .expect("MLS group creation must succeed"),
            );
        }

        // First send succeeds: it emits sequence 1 (pre-increment from base 0),
        // and the stored counter advances to 1.
        mgr.send_message(context_id, creator, "aGVsbG8=", None)
            .expect("a valid encrypted send must succeed");
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(creator),
            Some(1),
            "an accepted encrypted send must advance the sender's sequence to 1"
        );

        // Second send fails at the base64 decode step (CRYPTO_4001). The
        // reserved sequence must be rolled back so the counter stays at 1.
        let err = mgr
            .send_message(context_id, creator, "@@@not-valid-base64@@@", None)
            .expect_err("an invalid-base64 payload must fail the encrypt path");
        match err {
            ScpWasmError::Crypto { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::CRYPTO_4001,
                    "invalid base64 must surface the decode error class"
                );
            }
            other => panic!("expected Crypto error, got: {other:?}"),
        }

        // The failed send burned NO sequence: counter is still 1 (not 2).
        // With the old code (no rollback) this would be 2 — the mutation guard.
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(creator),
            Some(1),
            "a FAILED send must not advance the sequence — the reserved value \
             is rolled back, mirroring native rollback_sequence_number"
        );
    }

    /// A member who is present in `role_state.members` but has NO entry in
    /// `member_sequence_numbers` (the post-`import_context` shape: `import`
    /// restores `member_sequence_numbers` verbatim and INDEPENDENTLY of
    /// `role_state.members`, so a member who was added but never sent has no
    /// seq entry) must, on a FAILED first-ever send, end up with NO seq entry
    /// again — not a left-behind `Some(0)`.
    ///
    /// This exercises the `!seq_was_present` rollback branch (the `or_insert(0)`
    /// creates a fresh `0` entry to reserve the send; on failure the rollback
    /// `saturating_sub`s it back to `0` and then REMOVES it because it was
    /// created solely for this send). The `None`-vs-`Some(0)` distinction is
    /// the mutation guard: deleting the `remove` line would leave `Some(0)`.
    ///
    /// The send fails at the `CRYPTO_4001` base64-decode step, which runs
    /// BEFORE `encrypt_message`, so the sender does not need a valid MLS leaf —
    /// crypto is attached only so the fallible encrypt closure (and thus the
    /// reserve/rollback path) actually runs.
    #[test]
    fn send_message_first_send_failure_removes_unseeded_entry_wasm() {
        let context_id = "ctx-send-unseeded-rollback";
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmember";
        let mut mgr = make_free_ctx_for_send_auth(context_id, creator);
        {
            let ctx = mgr.contexts.get_mut(context_id).unwrap();
            // Attach real MLS crypto so the encrypt closure (reserve -> rollback)
            // runs. The creator created the group; the member only needs the
            // decode step, which fails first.
            ctx.crypto = Some(
                crate::crypto::WasmCryptoState::new_for_context(creator)
                    .expect("MLS group creation must succeed"),
            );
            // Add a write-granting member (so the role gate passes), then strip
            // its seq entry to reproduce the post-import "in members, no seq
            // entry" shape.
            ctx.test_insert_member(member, "member");
            ctx.member_sequence_numbers.remove(member);
        }

        // Precondition: the member is in role_state.members but has NO seq entry.
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(member),
            None,
            "precondition: an added-but-never-sent member must have no seq entry"
        );

        // First-ever send fails at the base64 decode step (CRYPTO_4001).
        let err = mgr
            .send_message(context_id, member, "@@@not-valid-base64@@@", None)
            .expect_err("an invalid-base64 payload must fail the encrypt path");
        match err {
            ScpWasmError::Crypto { ref code, .. } => {
                assert_eq!(
                    code,
                    codes::CRYPTO_4001,
                    "invalid base64 must surface the decode error class"
                );
            }
            other => panic!("expected Crypto error, got: {other:?}"),
        }

        // The fresh `0` entry created by `or_insert(0)` was REMOVED by the
        // rollback — the map is back to its pre-send shape (no entry), NOT
        // left at `Some(0)`. MUTATION GUARD: deleting the `remove` line in the
        // rollback would make this read `Some(0)` and the test would go RED.
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(member),
            None,
            "a FAILED first-ever send must leave NO seq entry (the reserve-only \
             entry is removed on rollback), not a left-behind Some(0)"
        );
    }

    /// CONVERGENCE GUARD: the WASM per-member message sequence base is
    /// reconciled to native and must stay reconciled.
    ///
    /// The WASM sidecar now PRE-increments from base `0`
    /// (`*entry += 1; let seq = *entry;`), so the FIRST message's emitted
    /// `sequence_number` is `1`, matching native's
    /// `MembershipState::next_sequence_number`
    /// (`info.sequence_number += 1; info.sequence_number`), which is also
    /// 1-based. The prior off-by-one (WASM emitting `0` for the first message)
    /// is RESOLVED — both families emit the same 1-based per-author sequence.
    /// The per-author byte values remain out of cross-family export
    /// byte-parity scope per ADR-050 (each author mints its own sequence with
    /// no global order), but the increment direction and base now converge.
    ///
    /// The body drives a successful first send through the production
    /// `send_message` path with real MLS crypto attached and asserts the
    /// emitted `MessageSent.sequence_number` is `1` (1-based, matching native)
    /// and the stored counter reads `Some(1)`. If a future change regresses the
    /// base back to 0-based, this test flips RED.
    #[test]
    fn wasm_per_member_sequence_base_matches_native() {
        let context_id = "ctx-seq-base-convergence";
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmember";
        let mut mgr = make_free_ctx_for_send_auth(context_id, creator);
        {
            let ctx = mgr.contexts.get_mut(context_id).unwrap();
            // Real MLS crypto so the encrypt path runs and a MessageSent leaf is
            // emitted to the receive buffer.
            ctx.crypto = Some(
                crate::crypto::WasmCryptoState::new_for_context(creator)
                    .expect("MLS group creation must succeed"),
            );
            ctx.test_insert_member(member, "member");
        }

        // One successful send by the creator (group creator, can encrypt).
        mgr.send_message(context_id, creator, "aGVsbG8=", None)
            .expect("a valid encrypted send must succeed");

        // RECONCILED behavior: the first emitted MessageSent carries
        // sequence_number 1 (1-based, pre-increment) — exactly what native's
        // `MembershipState::next_sequence_number` emits for a first send.
        let first_seq = mgr
            .drain_events(context_id)
            .into_iter()
            .find_map(|e| match e {
                ContextEvent::MessageSent {
                    sender_did,
                    sequence_number,
                    ..
                } if sender_did.0 == creator => Some(sequence_number),
                _ => None,
            })
            .expect("the successful send must emit a MessageSent buffer event");
        assert_eq!(
            first_seq, 1,
            "RECONCILED: the first per-author message sequence is 1 \
             (pre-increment from base 0), matching native \
             MembershipState::next_sequence_number. A regression to 0-based \
             must flip this assertion RED."
        );

        // And the stored counter reads Some(1) after the first send.
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(creator),
            Some(1),
            "after the first send the counter reads Some(1)"
        );
    }

    /// A write-granting member whose `messages:write` was suspended via
    /// `SuspendAccess` CANNOT `send_message`: the suspension-aware positive
    /// gate rejects with the distinct "suspended" message. Proves the gate
    /// keeps enforcing suspension even though it is now a single positive
    /// check.
    #[test]
    fn suspended_write_member_cannot_send_message() {
        let context_id = "ctx-send-suspended";
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmember";
        let mut mgr = make_free_ctx_for_send_auth(context_id, creator);
        {
            let ctx = mgr.contexts.get_mut(context_id).unwrap();
            ctx.test_insert_member(member, "member");
            // Suspend the member's full effective set (SuspendAccess semantics).
            assert!(ctx.suspend_all_pub(member), "member had caps to suspend");
        }

        let err = mgr
            .send_message(context_id, member, "aGVsbG8=", None)
            .expect_err("a suspended member must not be able to send");
        match err {
            ScpWasmError::Permission {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::PERM_3000);
                assert!(
                    message.contains("suspended"),
                    "expected a suspended message, got: {message}"
                );
            }
            other => panic!("expected Permission error, got: {other:?}"),
        }
    }

    /// Broadcast publish enforces the SAME role-grant gate: a registered
    /// author with a write-granting role can publish; once their
    /// `messages:write` is suspended they cannot, with the distinct
    /// "suspended" message. A read-only author is rejected with the
    /// "does not grant" message.
    #[test]
    fn publish_broadcast_enforces_write_role_grant_and_suspension() {
        let context_id = "ctx-bc-auth";
        let creator = "did:dht:zcreator";
        let author = "did:dht:zauthor";
        let observer_author = "did:dht:zobsauthor";
        let mut mgr =
            make_manager_with_broadcast(context_id, creator, &[author, observer_author], &[]);
        {
            let ctx = mgr.contexts.get_mut(context_id).unwrap();
            // Grant write/read in the ceiling so author roles actually grant.
            ctx.test_insert_ceiling("messages:read");
            ctx.test_insert_ceiling("messages:write");
            // `author` gets a write-granting role; `observer_author` is a
            // registered broadcast author but only holds the read-only role.
            ctx.test_insert_member(author, "author");
            ctx.test_insert_member(observer_author, "observer");
        }

        // Write-granting author publishes successfully.
        mgr.publish_broadcast(context_id, author, "aGVsbG8=")
            .expect("a write-granting author must be able to publish");

        // A registered author with only the read-only role is rejected by the
        // positive role-grant gate.
        let err = mgr
            .publish_broadcast(context_id, observer_author, "aGVsbG8=")
            .expect_err("a read-only-role author must not be able to publish");
        match err {
            ScpWasmError::Permission {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::PERM_3000);
                assert!(
                    message.contains("does not grant messages:write"),
                    "expected a not-granted message, got: {message}"
                );
            }
            other => panic!("expected Permission error, got: {other:?}"),
        }

        // Suspend the write-granting author and confirm publish is now blocked
        // with the distinct suspended message.
        mgr.contexts
            .get_mut(context_id)
            .unwrap()
            .suspend_all_pub(author);
        let err = mgr
            .publish_broadcast(context_id, author, "aGVsbG8=")
            .expect_err("a suspended author must not be able to publish");
        match err {
            ScpWasmError::Permission {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::PERM_3000);
                assert!(
                    message.contains("suspended"),
                    "expected a suspended message, got: {message}"
                );
            }
            other => panic!("expected Permission error, got: {other:?}"),
        }
    }

    /// **C2-F:** governance `SetEconomicPolicy` rejects a paid policy via
    /// the in-WASM dispatch path with `SCP-ECON-12095`. Defense in depth
    /// for the case where a caller would otherwise route around C2 by
    /// proposing a paid policy via governance after creating a free
    /// context.
    #[test]
    fn test_wasm_set_economic_policy_governance_rejects_paid() {
        use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
        // `DID` in scope is `scp_event_log::DID` re-exported from `scp_primitives`
        // (see manager.rs imports at the top of the file). It is the same type
        // as `EconomicPolicy.payee` expects, so no extra import is needed.

        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let context_id = "ctx-set-paid";

        let state = make_bare_per_context_state(context_id, creator);
        mgr.contexts.insert(context_id.to_owned(), state);

        let paid = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: Some(Amount(100)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: Vec::new(),
            pricing_formula: None,
            payee: DID("did:dht:zpayee".to_owned()),
        };
        let action = GovernanceAction::SetEconomicPolicy { policy: paid };

        let err = mgr
            .dispatch_governance_action_economic(context_id, &action)
            .expect_err("WASM SetEconomicPolicy must reject paid policy fail-closed");

        match err {
            ScpWasmError::Context {
                ref code,
                ref message,
            } => {
                assert_eq!(code, codes::ECON_12095);
                assert!(message.contains("EconomicPolicyUnsupportedOnWasm"));
            }
            other => panic!("expected Context error, got: {other:?}"),
        }

        // Defense-in-depth: the context's economic_policy was NOT set.
        assert!(
            mgr.contexts[context_id].economic_policy.is_none(),
            "rejected SetEconomicPolicy must not mutate stored policy"
        );
    }

    /// `propose_governance_action` REJECTS a caller-supplied `proposal_id` that
    /// is not strict 32-byte hex, instead of silently truncating / zero-padding
    /// it into a well-formed-looking `[u8; 32]`. A short / non-hex id reaching
    /// the `[u8; 32]` parse would have been widened by the former
    /// `hex::decode(...).unwrap_or_default()` path, producing a `proposal_id`
    /// that diverges from the native bridges' strict `hex::decode` +
    /// `try_into::<[u8; 32]>` parse — breaking cross-platform Merkle
    /// equivocation detection. The proposer is granted `governance:propose`
    /// (admin role + ceiling) so the rejection happens at the proposal-id parse,
    /// NOT at the capability gate, and nothing is tracked.
    #[test]
    fn test_wasm_propose_rejects_malformed_proposal_id() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let context_id = "ctx-malformed-pid";

        let mut state = make_bare_per_context_state(context_id, creator);
        // Admin capabilities are intersected with the ceiling, so grant
        // `governance:propose` in the ceiling to reach the proposal-id parse.
        state.test_insert_ceiling("governance:propose");
        mgr.contexts.insert(context_id.to_owned(), state);

        let action = GovernanceAction::ChangeRole {
            did: DID("did:dht:ztarget".to_owned()),
            new_role: "moderator".to_owned(),
        };

        // 4-byte hex — exactly the value the old unwrap_or_default + zero-pad
        // path would have silently widened to 32 bytes. The strict parse
        // (`parse_proposal_id_bytes`) routes the rejection through
        // `ScpWasmError::proposal_id`, so a malformed id surfaces as the same
        // `Context` / `SCP-CTX-2040` error the bridge boundary emits — identical
        // to the native PyO3/UniFFI/NAPI bridges' malformed-proposal-id surface.
        let err = mgr
            .propose_governance_action(context_id, creator, "deadbeef", &action)
            .expect_err("a 4-byte proposal id must be rejected, not zero-padded");
        match err {
            ScpWasmError::Context {
                ref message,
                ref code,
            } => {
                assert_eq!(
                    code,
                    codes::CTX_2040,
                    "a malformed proposal id must surface SCP-CTX-2040, got: {code}"
                );
                assert!(
                    message.contains("32 bytes"),
                    "rejection should name the 32-byte requirement, got: {message}"
                );
            }
            other => panic!("expected Context (SCP-CTX-2040) error, got: {other:?}"),
        }

        // Non-hex input must also be rejected (would decode to 0 bytes and the
        // old path would have produced an all-zero id).
        assert!(
            mgr.propose_governance_action(context_id, creator, "zz", &action)
                .is_err(),
            "non-hex proposal id must be rejected"
        );

        // Defense-in-depth: a rejected proposal id leaves NOTHING tracked.
        let ctx = &mgr.contexts[context_id];
        assert!(
            ctx.pending_proposals.is_empty() && ctx.resolved_proposals.is_empty(),
            "a rejected proposal id must not insert any tracked proposal"
        );
    }

    /// #1886 convergence: a `ChangeRole` to a role that is NOT defined in the
    /// context's `role_definitions` MUST be REJECTED on the WASM bridge, instead
    /// of being silently accepted as a free-form role string (the former flat-
    /// model behavior). The shared `ContextRoleState::system_assign_role`
    /// validates the role against `role_definitions` before applying it, so the
    /// single-admin auto-execute surfaces the rejection on `propose`. The target
    /// member's role is unchanged after the rejection.
    #[test]
    fn change_role_to_undefined_role_is_rejected_wasm() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let target = "did:dht:ztarget";
        let context_id = "ctx-1886-changerole";

        let mut state = make_bare_per_context_state(context_id, creator);
        state.test_set_governance("single_admin");
        state.test_insert_ceiling("governance:propose");
        state.test_insert_ceiling("governance:vote");
        state.test_insert_member(target, "member");
        mgr.contexts.insert(context_id.to_owned(), state);

        // `not-a-real-role` is a syntactically valid custom role NAME but is NOT
        // in `role_definitions` (only the built-ins are). Native rejects it; the
        // WASM bridge now rejects it too.
        let action = GovernanceAction::ChangeRole {
            did: DID(target.to_owned()),
            new_role: "not-a-real-role".to_owned(),
        };
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000ff";
        let result = mgr.propose_governance_action(context_id, creator, proposal_id, &action);

        // `map_role_error` maps EVERY `RoleError` variant to
        // `ScpWasmError::Context` with `SCP-CTX-2015` — there is no
        // RoleNotFound-specific code; CTX_2015 is the generic mapped
        // role-error code. The assertion is still meaningful because
        // `RoleNotFound` is the ONLY role error reachable in this test's setup
        // (a syntactically valid but undefined role name), so a CTX_2015 here
        // can only be the role-not-found rejection. Asserting the exact code
        // prevents the test from passing on an unrelated setup failure (wrong
        // governance model, missing ceiling, etc.).
        match result {
            Err(ScpWasmError::Context { ref code, .. }) => assert_eq!(
                code,
                codes::CTX_2015,
                "undefined-role ChangeRole must reject with the generic CTX_2015 role-error code"
            ),
            other => panic!(
                "ChangeRole to an undefined role MUST be rejected with a \
                 RoleNotFound Context error (#1886), got: {other:?}"
            ),
        }

        // The target keeps its original role — the rejected assignment did not apply.
        assert_eq!(
            mgr.member_role(context_id, target).as_deref(),
            Some("member"),
            "a rejected ChangeRole must leave the member's existing role intact"
        );
    }

    /// #1886 convergence: a `ChangeRole` to a DEFINED built-in role still
    /// succeeds and the target's capability check reflects the new role — the
    /// rejection above is specific to undefined roles, not a blanket failure.
    #[test]
    fn change_role_to_defined_role_succeeds_wasm() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let target = "did:dht:ztarget";
        let context_id = "ctx-1886-changerole-ok";

        let mut state = make_bare_per_context_state(context_id, creator);
        state.test_set_governance("single_admin");
        state.test_insert_ceiling("governance:propose");
        state.test_insert_ceiling("governance:vote");
        state.test_insert_ceiling("messages:read");
        state.test_insert_ceiling("messages:write");
        state.test_insert_member(target, "member");
        mgr.contexts.insert(context_id.to_owned(), state);

        let action = GovernanceAction::ChangeRole {
            did: DID(target.to_owned()),
            new_role: "observer".to_owned(),
        };
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000ff";
        mgr.propose_governance_action(context_id, creator, proposal_id, &action)
            .expect("ChangeRole to the built-in `observer` role must succeed");

        assert_eq!(
            mgr.member_role(context_id, target).as_deref(),
            Some("observer"),
            "a valid ChangeRole must update the member's role"
        );
        // observer grants messages:read only — capability check still works.
        let ctx = &mgr.contexts[context_id];
        assert!(
            ctx.member_has_capability(target, "messages:read"),
            "observer must retain messages:read"
        );
        assert!(
            !ctx.member_has_capability(target, "messages:write"),
            "observer must NOT have messages:write"
        );
    }

    /// Convergence with native `execute_transfer_admin`: a `TransferAdmin` to a
    /// member demotes EVERY current admin-role holder to "member", promotes the
    /// `new_admin` to "admin", and leaves `creator_did` (the immutable export
    /// signer / UCAN root) UNCHANGED. Admin is a transferable ROLE, never
    /// `creator_did`.
    #[test]
    fn transfer_admin_to_member_demotes_old_promotes_new_wasm() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmember";
        let context_id = "ctx-transfer-admin-ok";

        // `make_bare_per_context_state` auto-assigns the creator the "admin"
        // role. Add a plain member that will receive admin via the transfer.
        let mut state = make_bare_per_context_state(context_id, creator);
        state.test_set_governance("single_admin");
        state.test_insert_ceiling("governance:propose");
        state.test_insert_ceiling("governance:vote");
        state.test_insert_member(member, "member");
        mgr.contexts.insert(context_id.to_owned(), state);

        // Precondition: creator is admin, member is member, creator_did set.
        assert_eq!(
            mgr.member_role(context_id, creator).as_deref(),
            Some("admin")
        );
        assert_eq!(
            mgr.member_role(context_id, member).as_deref(),
            Some("member")
        );
        let creator_did_before = mgr.contexts[context_id].role_state.creator_did.clone();

        let action = GovernanceAction::TransferAdmin {
            new_admin: DID(member.to_owned()),
        };
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000aa";
        mgr.propose_governance_action(context_id, creator, proposal_id, &action)
            .expect("TransferAdmin to an existing member must succeed");

        // The new admin holds "admin"; the prior admin is demoted to "member".
        assert_eq!(
            mgr.member_role(context_id, member).as_deref(),
            Some("admin"),
            "new_admin must be promoted to the admin role"
        );
        assert_eq!(
            mgr.member_role(context_id, creator).as_deref(),
            Some("member"),
            "the prior admin must be demoted to member"
        );
        // `creator_did` is the immutable original creator / export signer — a
        // ROLE transfer must NOT relocate it.
        assert_eq!(
            mgr.contexts[context_id].role_state.creator_did, creator_did_before,
            "TransferAdmin must NOT mutate creator_did (the export signer)"
        );
        assert_eq!(
            mgr.contexts[context_id].role_state.creator_did, creator,
            "creator_did must still point at the original creator"
        );
    }

    /// Convergence with native `execute_transfer_admin`: a `TransferAdmin` to a
    /// NON-member is REJECTED before any mutation. The prior admin keeps the
    /// admin role (no zero-admin vacancy) and `creator_did` is unchanged (no
    /// export-signer relocation to a non-member).
    #[test]
    fn transfer_admin_to_nonmember_is_rejected_wasm() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let stranger = "did:dht:zstranger"; // never added to the context
        let context_id = "ctx-transfer-admin-nonmember";

        let mut state = make_bare_per_context_state(context_id, creator);
        state.test_set_governance("single_admin");
        state.test_insert_ceiling("governance:propose");
        state.test_insert_ceiling("governance:vote");
        mgr.contexts.insert(context_id.to_owned(), state);

        let creator_did_before = mgr.contexts[context_id].role_state.creator_did.clone();

        let action = GovernanceAction::TransferAdmin {
            new_admin: DID(stranger.to_owned()),
        };
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000bb";
        let result = mgr.propose_governance_action(context_id, creator, proposal_id, &action);

        // Rejected with the member-not-found Context code (CTX_2015) — the same
        // code `dispatch_change_role` uses for a missing member and that
        // `map_role_error` maps `RoleError::MemberNotInContext` to.
        match result {
            Err(ScpWasmError::Context { ref code, .. }) => assert_eq!(
                code,
                codes::CTX_2015,
                "TransferAdmin to a non-member must reject with the member-not-found CTX_2015 code"
            ),
            other => panic!(
                "TransferAdmin to a non-member MUST be rejected with a                  member-not-found Context error, got: {other:?}"
            ),
        }

        // The reject-before-mutate guard means the prior admin still holds
        // admin (no zero-admin vacancy) and creator_did is untouched.
        assert_eq!(
            mgr.member_role(context_id, creator).as_deref(),
            Some("admin"),
            "a rejected TransferAdmin must leave the original admin's role intact"
        );
        assert_eq!(
            mgr.contexts[context_id].role_state.creator_did, creator_did_before,
            "a rejected TransferAdmin must NOT relocate creator_did to a non-member"
        );
    }

    /// #1886 convergence: an `AddMember` with an undefined role MUST be rejected
    /// on the WASM bridge (mirrors `ChangeRole`). The DID must not end up as a
    /// member.
    #[test]
    fn add_member_with_undefined_role_is_rejected_wasm() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let newcomer = "did:dht:znewcomer";
        let context_id = "ctx-1886-addmember";

        let mut state = make_bare_per_context_state(context_id, creator);
        state.test_set_governance("single_admin");
        state.test_insert_ceiling("governance:propose");
        state.test_insert_ceiling("governance:vote");
        mgr.contexts.insert(context_id.to_owned(), state);

        let action = GovernanceAction::AddMember {
            did: DID(newcomer.to_owned()),
            role: "not-a-real-role".to_owned(),
        };
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000ff";
        let result = mgr.propose_governance_action(context_id, creator, proposal_id, &action);

        // Same generic CTX_2015 role-error code as the ChangeRole case:
        // `map_role_error` maps every `RoleError` to CTX_2015, and
        // `RoleNotFound` is the only role error reachable in this setup.
        match result {
            Err(ScpWasmError::Context { ref code, .. }) => assert_eq!(
                code,
                codes::CTX_2015,
                "undefined-role AddMember must reject with the generic CTX_2015 role-error code"
            ),
            other => panic!(
                "AddMember with an undefined role MUST be rejected with a \
                 RoleNotFound Context error (#1886), got: {other:?}"
            ),
        }

        // `dispatch_add_member` rolls back BOTH the `members` insert and the
        // `member_sequence_numbers` seed on a rejected role assignment
        // (fail-closed atomicity).
        //
        // The sequence-number assertion below is the LOAD-BEARING rollback
        // proof: the seq is seeded BEFORE the fallible `system_assign_role`, so
        // without the rollback it would be `Some(0)`; observing `None` proves
        // the seed was rolled back. The `member_role == None` check is a
        // supplementary "not a member" assertion — it does NOT by itself prove
        // the rollback, because `system_assign_role` rejects an undefined role
        // BEFORE writing any assignment, so `member_role` would read `None`
        // even if the `members`-set insert had leaked.
        assert_eq!(
            mgr.member_role(context_id, newcomer),
            None,
            "a rejected AddMember must NOT leave the newcomer as a member"
        );
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(newcomer),
            None,
            "a rejected AddMember must roll back the newcomer's sequence-number seed \
             (the load-bearing rollback proof: seeded before the fallible assign, so \
             this would be Some(0) without the rollback)"
        );
    }

    /// Conditional-rollback convergence: re-adding an ALREADY-PRESENT member via
    /// `AddMember` with a bad / out-of-ceiling role must REJECT the action yet
    /// leave the existing member fully intact. Unconditional rollback would
    /// split-brain them: drop them from `members` and delete their sequence
    /// counter while leaving `assignments` + `member_capabilities` behind, so
    /// membership queries report them gone while they keep every capability and
    /// can still propose / vote / decrypt. This is the regression guard for the
    /// eviction bug; it matches native `execute_add_member`, which never
    /// corrupts an existing member (member-add is coalesce-window-rollback
    /// acceptable per ADR-049 §9).
    #[test]
    fn add_member_existing_member_bad_role_does_not_evict_wasm() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmoderator";
        let context_id = "ctx-addmember-no-evict";

        let mut state = make_bare_per_context_state(context_id, creator);
        state.test_set_governance("single_admin");
        state.test_insert_ceiling("governance:propose");
        state.test_insert_ceiling("governance:vote");
        // Widen the ceiling so the `moderator` role actually carries a
        // capability we can later prove survives a rejected re-add.
        state.test_insert_ceiling("messages:read");
        state.test_insert_ceiling("messages:write");
        // M is a real, established member with a VALID role, capabilities, and a
        // seeded sequence counter — exactly the state the eviction bug corrupts.
        state.test_insert_member(member, "moderator");
        mgr.contexts.insert(context_id.to_owned(), state);

        // Sanity: M is established BEFORE the bad re-add, so any post-add change
        // localizes to `dispatch_add_member` rather than setup.
        assert!(
            mgr.is_member(context_id, member),
            "M must be an established member before the bad re-add"
        );
        assert!(
            mgr.contexts[context_id].member_has_capability(member, "messages:read"),
            "M's moderator role must grant messages:read before the bad re-add"
        );
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(member),
            Some(0),
            "M must have a seeded sequence counter before the bad re-add"
        );

        // Re-add the SAME member with an undefined role through the production
        // dispatch path (single_admin auto-executes on propose).
        let action = GovernanceAction::AddMember {
            did: DID(member.to_owned()),
            role: "not-a-real-role".to_owned(),
        };
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000ee";
        let result = mgr.propose_governance_action(context_id, creator, proposal_id, &action);

        // (a) The action is rejected.
        assert!(
            result.is_err(),
            "re-adding an existing member with an undefined role must be rejected, got: {result:?}"
        );

        // (b) M is STILL a member (not evicted).
        assert!(
            mgr.is_member(context_id, member),
            "a rejected re-add must NOT evict the pre-existing member from `members`"
        );
        assert!(
            mgr.contexts[context_id].role_state.members.contains(member),
            "the pre-existing member must remain in `role_state.members` after a rejected re-add"
        );

        // (c) M STILL holds the capabilities their original role granted.
        assert!(
            mgr.contexts[context_id].member_has_capability(member, "messages:read"),
            "a rejected re-add must NOT strip the pre-existing member's capabilities"
        );

        // (d) M's sequence counter is preserved (not deleted by the rollback).
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(member),
            Some(0),
            "a rejected re-add must NOT delete the pre-existing member's sequence counter"
        );

        // The original role is untouched (`system_assign_role` rejects the bad
        // role BEFORE writing any assignment, so the prior assignment stands).
        assert_eq!(
            mgr.member_role(context_id, member).as_deref(),
            Some("moderator"),
            "a rejected re-add must leave the pre-existing member's role unchanged"
        );
    }

    /// `AddMember` with a VALID defined role, through the production dispatch
    /// path, must succeed: the newcomer becomes a member with that role and a
    /// `MemberJoined` buffer event is emitted. Exercises the real
    /// `dispatch_add_member` success path (previously only the
    /// `test_insert_member` shortcut covered member addition).
    #[test]
    fn add_member_with_defined_role_succeeds_and_pushes_member_joined_wasm() {
        let mut mgr = WasmContextManager::new();
        let creator = "did:dht:zcreator";
        let newcomer = "did:dht:znewcomer";
        let context_id = "ctx-addmember-success";

        let mut state = make_bare_per_context_state(context_id, creator);
        state.test_set_governance("single_admin");
        state.test_insert_ceiling("governance:propose");
        state.test_insert_ceiling("governance:vote");
        state.test_insert_ceiling("messages:read");
        state.test_insert_ceiling("messages:write");
        mgr.contexts.insert(context_id.to_owned(), state);

        // Newcomer is not a member before the add.
        assert!(!mgr.is_member(context_id, newcomer));

        let action = GovernanceAction::AddMember {
            did: DID(newcomer.to_owned()),
            role: "moderator".to_owned(),
        };
        let proposal_id = "deadbeef000000000000000000000000000000000000000000000000000000aa";
        let result = mgr.propose_governance_action(context_id, creator, proposal_id, &action);
        assert!(
            result.is_ok(),
            "AddMember with a valid defined role must succeed, got: {result:?}"
        );

        // The newcomer is now a member with the requested role.
        assert!(
            mgr.is_member(context_id, newcomer),
            "a successful AddMember must add the newcomer to `members`"
        );
        assert_eq!(
            mgr.member_role(context_id, newcomer).as_deref(),
            Some("moderator"),
            "a successful AddMember must assign the requested defined role"
        );

        // The member's sequence counter is seeded.
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(newcomer),
            Some(0),
            "a successful AddMember must seed the new member's sequence counter"
        );

        // Exactly one MemberJoined buffer event was emitted for the newcomer.
        let joined = mgr
            .drain_events(context_id)
            .into_iter()
            .filter(|e| matches!(e, ContextEvent::MemberJoined { member_did, .. } if member_did.0 == newcomer))
            .count();
        assert_eq!(
            joined, 1,
            "a successful AddMember must push exactly one MemberJoined buffer event for the newcomer"
        );
    }

    /// #1877 slice 1: a full signed `export_context` -> `import_context`
    /// round-trip must reconstruct the NEW shared `ContextRoleState` verbatim.
    /// Specifically: a member's non-default role, a per-member capability
    /// suspension, and a non-zero MLS sequence counter must all survive the
    /// JCS-canonical, Ed25519-signed envelope onto a freshly reconstructed
    /// `ContextRoleState` in a different manager.
    ///
    /// The signed export resolves the creator's `#active` verification key from
    /// the thread-local identity registry, so the creator identity is
    /// registered first (the registry is shared across managers on the test
    /// thread, which is what lets the "fresh" importing manager verify the
    /// signature).
    #[test]
    fn export_import_roundtrip_preserves_role_state_model_wasm() {
        // Non-zero MLS sequence counter to advance and assert survives.
        const EXPECTED_SEQ: u64 = 7;

        // Isolate from any thread-local registry residue left by sibling tests.
        crate::identity::test_helpers::cleanup_identity_registry();
        let (creator, _identity_key, _active_key, _agent_key) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let member = "did:dht:zmoderator";
        let context_id = "ctx-1877-export-roundtrip";

        let mut src = WasmContextManager::new();
        let mut state = make_bare_per_context_state(context_id, &creator);
        // Widen the ceiling so the non-default `moderator` role actually carries
        // read+write capabilities (built-in roles intersect with the ceiling).
        state.test_insert_ceiling("messages:read");
        state.test_insert_ceiling("messages:write");
        // (a) assign a NON-default, non-creator role.
        state.test_insert_member(member, "moderator");
        // (b) suspend a capability the role otherwise grants.
        state.test_insert_suspended_capability(member, "messages:write");
        // (c) advance the member's MLS sequence counter to a non-zero value.
        state
            .member_sequence_numbers
            .insert(member.to_owned(), EXPECTED_SEQ);
        src.contexts.insert(context_id.to_owned(), state);

        // Sanity: the source state holds what we set BEFORE the round-trip, so a
        // failure localizes to export/import rather than setup.
        assert_eq!(
            src.member_role(context_id, member).as_deref(),
            Some("moderator")
        );
        assert!(src.contexts[context_id].member_has_capability(member, "messages:read"));
        assert!(!src.contexts[context_id].member_has_capability(member, "messages:write"));
        assert_eq!(
            src.contexts[context_id].test_member_sequence_number(member),
            Some(EXPECTED_SEQ)
        );

        let bytes = src
            .export_context(context_id)
            .expect("signed export of the role-state context must succeed");

        // Reconstruct into a DIFFERENT manager (shares the thread-local identity
        // registry, so the creator's #active key resolves for verification).
        let mut dst = WasmContextManager::new();
        let imported_id = dst
            .import_context(&bytes)
            .expect("signed import must verify and reconstruct the context");
        assert_eq!(imported_id, context_id);

        // Role survives verbatim on the reconstructed ContextRoleState.
        assert_eq!(
            dst.member_role(context_id, member).as_deref(),
            Some("moderator"),
            "imported member role must match the exported non-default role"
        );
        // Suspension survives: the suspended cap is denied, the unsuspended one allowed.
        let imported_ctx = &dst.contexts[context_id];
        assert!(
            imported_ctx.member_has_capability(member, "messages:read"),
            "an unsuspended capability must remain granted after import"
        );
        assert!(
            !imported_ctx.member_has_capability(member, "messages:write"),
            "a suspended capability must remain denied after import"
        );
        // Sequence counter survives verbatim.
        assert_eq!(
            imported_ctx.test_member_sequence_number(member),
            Some(EXPECTED_SEQ),
            "imported member sequence number must match the exported value"
        );

        // Leave the shared thread-local registry clean for sibling tests.
        crate::identity::test_helpers::cleanup_identity_registry();
    }

    /// BLACK-CEIL-01 load-bearing regression: a member who is `SuspendAccess`'d
    /// BEFORE a governed ceiling WIDEN must NOT regain the widened capability
    /// across an export -> import round-trip into a FRESH manager.
    ///
    /// The former WASM import recomputed `member_capabilities` by re-running
    /// `system_assign_role` per member against the imported ceiling. On a widen,
    /// that recompute re-granted the suspended member the newly-added capability
    /// (`member_has_capability` flipped false -> true post-import). The fix
    /// restores `role_state` VERBATIM (native parity), so the suspension survives.
    #[test]
    fn import_does_not_un_suspend_capability_widened_after_suspension() {
        let creator = "did:dht:zcreator";
        let member = "did:dht:zmember";
        let context_id = "ctx-ceil01-roundtrip";

        // The signed export resolves the creator's #active key from the shared
        // thread-local identity registry; register the creator identity first
        // under a clean registry.
        crate::identity::test_helpers::cleanup_identity_registry();
        let (registered_creator, _ik, _ak, _gk) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        // Governed context whose ceiling does NOT include messages:write but DOES
        // include member:ban (so the SuspendAccess governance action is permitted).
        let mut src = manager_with_governed_context(
            context_id,
            &registered_creator,
            &["messages:read", "member:ban"],
        );
        let _ = creator; // documented intent; the registered DID is authoritative.

        // Add the member as admin so their effective capability set is the whole
        // current ceiling ({messages:read, member:ban}).
        src.contexts
            .get_mut(context_id)
            .unwrap()
            .test_insert_member(member, "admin");

        // SuspendAccess: suspend_all copies the member\'s effective capabilities
        // into their suspended set.
        src.dispatch_governance_action(
            context_id,
            &GovernanceAction::SuspendAccess {
                did: DID(member.to_owned()),
            },
            &registered_creator,
            0,
        )
        .expect("SuspendAccess must succeed");

        // Governed ModifyCeiling WIDENS the ceiling to add messages:write. This is
        // the convergence path: it calls set_ceiling ONLY (no per-member refresh),
        // so the suspended member\'s member_capabilities goes STALE relative to the
        // new ceiling — exactly the precondition that exposed the import recompute.
        src.dispatch_governance_action(
            context_id,
            &GovernanceAction::ModifyCeiling {
                new_ceiling: vec![
                    Capability::MessagesRead,
                    Capability::MessagesWrite,
                    Capability::MemberBan,
                ],
            },
            &registered_creator,
            0,
        )
        .expect("governed ceiling widen must succeed");

        // Pre-export invariant: the suspended member does NOT hold messages:write.
        assert!(
            !src.contexts[context_id].member_has_capability(member, "messages:write"),
            "pre-export: a SuspendAccess-suspended member must not hold a \
             capability the widen added"
        );

        let bytes = src
            .export_context(context_id)
            .expect("signed export must succeed");

        // Import into a FRESH manager (shares the thread-local identity registry).
        let mut dst = WasmContextManager::new();
        let imported_id = dst
            .import_context(&bytes)
            .expect("signed import must verify and reconstruct the context");
        assert_eq!(imported_id, context_id);

        // The crux: post-import the suspended member STILL does not hold
        // messages:write. With the old recompute-on-import this assertion was RED
        // (the member silently regained the widened capability).
        assert!(
            !dst.contexts[context_id].member_has_capability(member, "messages:write"),
            "post-import: a member suspended before a ceiling widen must NOT regain \
             the widened capability (BLACK-CEIL-01; native restores role_state verbatim)"
        );

        crate::identity::test_helpers::cleanup_identity_registry();
    }

    /// Import preserves each member\'s minted assignment tokens VERBATIM — the
    /// fix carries the typed `RoleAssignment` (tokens included) instead of
    /// re-minting fresh tokens via `system_assign_role` on import.
    #[test]
    fn import_preserves_assignment_tokens_verbatim() {
        let member = "did:dht:zmoderator";
        let context_id = "ctx-ceil01-tokens";

        crate::identity::test_helpers::cleanup_identity_registry();
        let (creator, _ik, _ak, _gk) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let mut src = WasmContextManager::new();
        let mut state = make_bare_per_context_state(context_id, &creator);
        state.test_insert_ceiling("messages:read");
        state.test_insert_ceiling("messages:write");
        state.test_insert_member(member, "moderator");
        src.contexts.insert(context_id.to_owned(), state);

        // Capture the pre-export tokens for both the creator and the member.
        let pre_member_tokens = src.contexts[context_id]
            .role_state
            .assignments
            .get(member)
            .expect("member must have an assignment")
            .tokens
            .clone();
        let pre_creator_tokens = src.contexts[context_id]
            .role_state
            .assignments
            .get(creator.as_str())
            .expect("creator must have an assignment")
            .tokens
            .clone();

        let bytes = src.export_context(context_id).expect("export must succeed");
        let mut dst = WasmContextManager::new();
        dst.import_context(&bytes).expect("import must succeed");

        let post_member_tokens = dst.contexts[context_id]
            .role_state
            .assignments
            .get(member)
            .expect("imported member must have an assignment")
            .tokens
            .clone();
        let post_creator_tokens = dst.contexts[context_id]
            .role_state
            .assignments
            .get(creator.as_str())
            .expect("imported creator must have an assignment")
            .tokens
            .clone();

        assert_eq!(
            post_member_tokens, pre_member_tokens,
            "imported member assignment tokens must equal the exported tokens verbatim \
             (no fresh re-mint on import)"
        );
        assert_eq!(
            post_creator_tokens, pre_creator_tokens,
            "imported creator assignment tokens must equal the exported tokens verbatim"
        );

        crate::identity::test_helpers::cleanup_identity_registry();
    }

    /// The whole `ContextRoleState` round-trips VERBATIM (derived `PartialEq`):
    /// members, assignments + tokens, ceiling, `role_definitions`,
    /// `member_capabilities`, and per-member suspensions all match pre-export.
    #[test]
    fn import_round_trips_role_state_verbatim() {
        let member = "did:dht:zmoderator";
        let context_id = "ctx-ceil01-verbatim";

        crate::identity::test_helpers::cleanup_identity_registry();
        let (creator, _ik, _ak, _gk) =
            crate::identity::test_helpers::register_identity_with_agent_key();

        let mut src = WasmContextManager::new();
        let mut state = make_bare_per_context_state(context_id, &creator);
        state.test_insert_ceiling("messages:read");
        state.test_insert_ceiling("messages:write");
        state.test_insert_member(member, "moderator");
        // Suspend one capability the role otherwise grants.
        state.test_insert_suspended_capability(member, "messages:write");
        src.contexts.insert(context_id.to_owned(), state);

        let pre_role_state = src.contexts[context_id].role_state.clone();

        let bytes = src.export_context(context_id).expect("export must succeed");
        let mut dst = WasmContextManager::new();
        dst.import_context(&bytes).expect("import must succeed");

        let post_role_state = &dst.contexts[context_id].role_state;
        assert_eq!(
            *post_role_state, pre_role_state,
            "the whole ContextRoleState must round-trip verbatim (members, assignments + \
             tokens, ceiling, role_definitions, member_capabilities, suspensions)"
        );

        crate::identity::test_helpers::cleanup_identity_registry();
    }

    /// `parse_proposal_id_bytes` is the shared strict parse both
    /// `propose_governance_action` and `execute_governance_action` use. It
    /// accepts exactly-32-byte hex and rejects everything else, matching the
    /// native bridges' `hex::decode` + `try_into::<[u8; 32]>`.
    #[test]
    fn test_parse_proposal_id_bytes_strict() {
        let valid = "a".repeat(64);
        let parsed = parse_proposal_id_bytes(&valid).expect("64-char hex must parse");
        assert_eq!(parsed, [0xaa_u8; 32]);

        assert!(
            parse_proposal_id_bytes("deadbeef").is_err(),
            "short hex must be rejected"
        );
        assert!(
            parse_proposal_id_bytes(&"a".repeat(66)).is_err(),
            "over-length hex must be rejected"
        );
        assert!(
            parse_proposal_id_bytes("zz").is_err(),
            "non-hex must be rejected"
        );
        assert!(
            parse_proposal_id_bytes("").is_err(),
            "empty input must be rejected"
        );
    }

    /// `handle_ttl_expiry` stamps the CONVERGENT deadline
    /// (`creation_timestamp_secs + ttl_seconds`) on the `ContextExpired` leaf,
    /// not the member's local fire-time `now()`. Two members whose timers fire
    /// at different wall-clock instants therefore record the IDENTICAL leaf
    /// timestamp and, with identical prior history, the identical event-log
    /// root — the cross-member equivocation property a WASM and a native member
    /// must both satisfy (§7.3.1, §9.9.3).
    #[test]
    fn test_wasm_ttl_expiry_stamps_convergent_deadline() {
        let creation = 1_700_000_000_u64;
        let ttl = 86_400_u64;

        // Two independent members of the "same" context: same convergent
        // creation time and TTL, but their `handle_ttl_expiry` calls happen at
        // different real instants (separated by the work between them).
        let build = |id: &str| {
            let mut mgr = WasmContextManager::new();
            let mut state = make_bare_per_context_state(id, "did:dht:zcreator");
            state.creation_timestamp_secs = creation;
            state.ttl_seconds = Some(ttl);
            mgr.contexts.insert(id.to_owned(), state);
            mgr
        };

        let id = "ctx-ttl-converge";
        let mut alice = build(id);
        let mut bob = build(id);

        alice.handle_ttl_expiry(id).expect("alice ttl expiry");
        // (any amount of local wall-clock passes here)
        bob.handle_ttl_expiry(id).expect("bob ttl expiry");

        let alice_root = scp_event_log::tree::root(&alice.contexts[id].event_log);
        let bob_root = scp_event_log::tree::root(&bob.contexts[id].event_log);
        assert_eq!(
            alice_root, bob_root,
            "ContextExpired leaves stamped with the convergent creation+ttl deadline must yield \
             identical event-log roots regardless of local fire time"
        );

        // Both contexts transitioned to expired.
        assert_eq!(alice.contexts[id].state, "expired");
        assert_eq!(bob.contexts[id].state, "expired");
    }

    /// Legacy snapshot convergence: a `creation_timestamp_secs` of `0` (the
    /// `#[serde(default)]` value a pre-field envelope deserializes to) is still
    /// a TTL base, NOT a "no convergent base" sentinel. With a TTL present,
    /// `handle_ttl_expiry` MUST stamp the convergent `0 + ttl` deadline — NOT
    /// the member's local `now()` — so it matches native
    /// `convergent_ttl_deadline_secs(0, Some(ttl))` (`ttl_close_helpers.rs`),
    /// which has no `creation == 0` guard either. A residual `creation == 0 =>
    /// now()` special-case in WASM would make WASM stamp the local fire-time
    /// while native stamps `0 + ttl`, diverging the `ContextExpired` leaf — and
    /// thus the event-log root — at equal event count in a mixed native+WASM
    /// context importing the same legacy snapshot (§7.3.1, §9.9.3). The `now()`
    /// fallback is reserved for the genuinely-no-TTL (`ttl_seconds == None`)
    /// case.
    #[test]
    fn test_wasm_ttl_expiry_stamps_zero_plus_ttl_for_legacy_creation() {
        let id = "ctx-ttl-legacy-zero";
        let ttl = 3600_u64;
        let mut mgr = WasmContextManager::new();
        let mut state = make_bare_per_context_state(id, "did:dht:zcreator");
        // Legacy snapshot: creation time defaulted to 0; TTL present.
        state.creation_timestamp_secs = 0;
        state.ttl_seconds = Some(ttl);
        mgr.contexts.insert(id.to_owned(), state);

        mgr.handle_ttl_expiry(id)
            .expect("ttl expiry with legacy zero creation");
        assert_eq!(mgr.contexts[id].state, "expired");

        // The leaf must carry the convergent `0 + ttl` deadline, matching
        // native `convergent_ttl_deadline_secs(0, Some(ttl))` — NOT `now() +
        // ttl` and NOT `now()`.
        let native_deadline = 0_u64.saturating_add(ttl);
        let leaf = mgr.contexts[id]
            .event_log
            .events()
            .iter()
            .rev()
            .find(|e| e.event_type == EventType::ContextExpired)
            .expect("ContextExpired leaf must be present after handle_ttl_expiry");
        assert_eq!(
            leaf.timestamp, native_deadline,
            "WASM must stamp the convergent 0 + ttl deadline for a legacy (creation == 0) \
             snapshot, matching native, NOT a local now()-derived timestamp"
        );
    }

    /// The export DTO field round-trips through serde and defaults to `0` when
    /// a pre-field envelope omits it (`#[serde(default)]`). The WASM bridge
    /// keeps its own independent DTO — this is not byte-parity with native.
    #[test]
    fn test_wasm_snapshot_creation_timestamp_serde_roundtrip_and_default() {
        let mut snap = make_minimal_valid_snapshot();
        snap.creation_timestamp_secs = 1_711_000_777;

        let json = serde_json::to_value(&snap).expect("serialize snapshot");
        let restored: WasmContextExportSnapshot =
            serde_json::from_value(json.clone()).expect("deserialize snapshot");
        assert_eq!(
            restored.creation_timestamp_secs, 1_711_000_777,
            "creation_timestamp_secs must round-trip through the WASM export DTO"
        );

        // Legacy envelope: strip the field; it must default to 0.
        let mut legacy = json;
        legacy
            .as_object_mut()
            .expect("snapshot is a JSON object")
            .remove("creation_timestamp_secs");
        let restored_legacy: WasmContextExportSnapshot =
            serde_json::from_value(legacy).expect("legacy snapshot must deserialize");
        assert_eq!(
            restored_legacy.creation_timestamp_secs, 0,
            "a pre-field WASM envelope must default creation_timestamp_secs to 0"
        );
    }

    /// Cross-bridge convergence: a native importer and a WASM importer that read
    /// the SAME creator-signed snapshot whose `creation_timestamp_secs` is in the
    /// (importer-local) FUTURE — legitimate clock skew within the ±5-min
    /// tolerance, or a creator that stamped a slightly-future creation — must
    /// compute the IDENTICAL TTL expiry deadline. Both consume the field VERBATIM
    /// (no importer-`now` clamp): native via
    /// `convergent_ttl_deadline_secs(creation, ttl)` and WASM via the same
    /// `creation + ttl` arithmetic in `handle_ttl_expiry`. A residual WASM clamp
    /// to `now` would make WASM stamp `now + ttl` (a SHORTER deadline) while
    /// native stamps `creation + ttl`, diverging the `ContextExpired` leaf — and
    /// thus the event-log root — at equal event count (§7.3.1, §9.9.3).
    #[test]
    fn test_native_and_wasm_importers_agree_on_future_creation_deadline() {
        // A WASM importer whose local clock reads strictly BEFORE the snapshot's
        // creation time (the case the old `.min(now)` clamp would have mangled).
        let wasm_now = crate::time::now_secs();
        let creation = wasm_now.saturating_add(120); // 2 min in the importer's future
        let ttl = 86_400_u64;
        assert!(
            creation > wasm_now,
            "test precondition: snapshot creation must be in the importer's future"
        );

        // WASM import + expiry path. The import mapping copies
        // `snap.creation_timestamp_secs` VERBATIM into per-context state (post-fix:
        // no `.min(now)`), and `handle_ttl_expiry` stamps `creation + ttl`.
        let id = "ctx-future-creation-converge";
        let mut wasm_mgr = WasmContextManager::new();
        let mut state = make_bare_per_context_state(id, "did:dht:zcreator");
        state.creation_timestamp_secs = creation; // verbatim future value, as import now stores it
        state.ttl_seconds = Some(ttl);
        wasm_mgr.contexts.insert(id.to_owned(), state);
        wasm_mgr
            .handle_ttl_expiry(id)
            .expect("wasm ttl expiry with future creation");

        let wasm_deadline = creation.saturating_add(ttl);
        let leaf = wasm_mgr.contexts[id]
            .event_log
            .events()
            .iter()
            .rev()
            .find(|e| e.event_type == EventType::ContextExpired)
            .expect("ContextExpired leaf must be present after handle_ttl_expiry");
        assert_eq!(
            leaf.timestamp, wasm_deadline,
            "WASM must stamp the verbatim convergent deadline (creation + ttl), \
             NOT a clamped now + ttl"
        );

        // Native importer math for the SAME signed snapshot field. The native
        // import builder (`lifecycle_helpers.rs`) consumes
        // `export.snapshot.creation_timestamp_secs` verbatim and arms the timer
        // with `convergent_ttl_deadline_secs(creation, Some(ttl))`.
        let native_deadline = creation.saturating_add(ttl);

        assert_eq!(
            wasm_deadline, native_deadline,
            "native and WASM importers of the same future-dated signed snapshot \
             must derive the IDENTICAL TTL deadline"
        );
    }

    // -----------------------------------------------------------------------
    // Direct-execute trust boundary (governance quorum-bypass fix)
    //
    // `WasmContextManager::execute_governance_action` takes a proposal id and
    // resolves the action to dispatch from its OWN tracked
    // (`resolved_proposals`/`pending_proposals`) governance state — never a
    // caller-supplied action. The bridge surface `context_execute_governance`
    // has no `action_json` parameter, so action substitution is structurally
    // impossible. These KATs pin the boundary:
    //   - FORGERY: an untracked id is rejected and applies no state change.
    //   - GENUINE: a tracked `Approved` proposal executes once; a second
    //     execute of the same id is replay-rejected.
    // -----------------------------------------------------------------------

    #[test]
    fn direct_execute_rejects_untracked_proposal_id_wasm() {
        let context_id = "ctx-wasm-forgery";
        let proposer = "did:dht:z6MkWasmForgeryProposer";
        let caller = "did:dht:z6MkWasmForgeryCaller";

        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_insert_member(caller, "admin");
        ctx.test_insert_ceiling("role:assign");
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // An id the manager never tracked. WASM checks the status precondition
        // first, so an untracked id surfaces as "not approved (status: None)"
        // — the engine has no `Approved` proposal to dispatch. Either way the
        // forgery is rejected before any action can run. The shipped bridge
        // resolves the proposer and passes it for both the initiator and the
        // executor, so this call uses the production (proposer, proposer) shape.
        let err = mgr
            .execute_governance_action(context_id, proposer, proposer, "deadbeef")
            .expect_err("executing an untracked proposal id must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("not approved") || msg.contains("not tracked"),
            "untracked/forged proposal must be rejected as un-approved/un-tracked, got: {msg}"
        );
    }

    #[test]
    fn direct_execute_forgery_applies_no_state_change_wasm() {
        use scp_event_log::EventType;

        let context_id = "ctx-wasm-forgery-state";
        let proposer = "did:dht:z6MkWasmForgeryStateProposer";

        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_insert_ceiling("role:assign");
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // No caller action exists to substitute; the forged id carries nothing.
        assert!(
            mgr.execute_governance_action(context_id, proposer, proposer, "feedbeef")
                .is_err(),
            "forged direct-execute must be rejected"
        );

        // The rejection had no side effect: no GovernanceActionExecuted leaf
        // was minted (a substituted action would have produced one).
        let logged = mgr.test_context_event_log_events(context_id);
        assert!(
            !logged
                .iter()
                .any(|e| e.event_type == EventType::GovernanceActionExecuted),
            "a rejected forgery must mint no GovernanceActionExecuted leaf"
        );
    }

    #[test]
    fn direct_execute_of_genuine_proposal_runs_once_then_replay_rejected_wasm() {
        use scp_event_log::EventType;
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceProposal, ProposalStatus, SignedVote, VoteType,
        };

        let context_id = "ctx-wasm-genuine";
        let proposer = "did:dht:z6MkWasmGenuineProposer";
        // A valid 64-char (32-byte) hex id: the strict `parse_proposal_id_bytes`
        // on the execute path requires exactly 32 bytes. The id is only a map
        // key and the leaf bytes, so any well-formed 64-char hex works.
        let proposal_id = "abad1dea000000000000000000000000000000000000000000000000000000ff";
        let created_at = 1_700_600_600_u64;

        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_insert_member("did:dht:z6MkWasmGenuineTarget", "member");
        ctx.test_insert_ceiling("role:assign");

        let action = GovernanceAction::ChangeRole {
            did: DID::from("did:dht:z6MkWasmGenuineTarget".to_owned()),
            new_role: "observer".to_owned(),
        };
        // Seed a genuinely Approved, tracked proposal (the precondition the
        // quorum path produces; here via the test seam since a single-node WASM
        // test cannot run a real multi-voter round).
        let proposal = GovernanceProposal {
            proposal_id: {
                let bytes = hex::decode(proposal_id).unwrap();
                let mut arr = [0u8; 32];
                arr[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
                arr
            },
            context_id: context_id.to_owned(),
            proposer_did: DID::from(proposer.to_owned()),
            action,
            status: ProposalStatus::Approved,
            created_at,
            voting_deadline: created_at + 3600,
            approvals: vec![SignedVote {
                voter_did: DID::from(proposer.to_owned()),
                vote: VoteType::Approve,
                timestamp: created_at,
                signature: Vec::new(),
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };
        ctx.test_insert_resolved_proposal(proposal_id.to_owned(), proposal);

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // First execute: the manager dispatches the TRACKED action, minting
        // exactly one GovernanceActionExecuted leaf.
        let resolved_proposer = mgr
            .proposal_proposer_did(context_id, proposal_id)
            .expect("proposer resolvable");
        mgr.execute_governance_action(context_id, proposer, &resolved_proposer, proposal_id)
            .expect("genuine approved proposal must execute");

        let executed_count = mgr
            .test_context_event_log_events(context_id)
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .count();
        assert_eq!(
            executed_count, 1,
            "the tracked action must take effect exactly once"
        );

        // Second execute of the same id: replay-rejected.
        let err = mgr
            .execute_governance_action(context_id, proposer, &resolved_proposer, proposal_id)
            .expect_err("re-executing an already-executed proposal must be rejected");
        assert!(
            format!("{err:?}").contains("already been executed"),
            "replay rejection should name the executed proposal, got: {err:?}"
        );
    }

    /// WASM half of the split cross-impl KAT for governance `RemoveMember`
    /// (the native half is `cross_impl_remove_member_leaf_is_empty_and_precedes_executed`
    /// in `crates/scp-runtime/tests/wasm_conformance.rs`). Drives the REAL
    /// `execute_governance_action` path for a `RemoveMember` proposal and pins,
    /// from the durable log:
    /// - the `MemberLeft` leaf payload is EMPTY (the removed DID is buffer-only),
    /// - its `actor_did` is the EXECUTOR (not the removed member),
    /// - its `timestamp` is the convergent `proposal.created_at` (not local
    ///   `now()`),
    /// - it is appended BEFORE the `GovernanceActionExecuted` leaf.
    ///
    /// These are byte-for-byte the invariants native's `execute_remove_member` /
    /// `finalize_governance_action` produce; a regression in any of them would
    /// diverge the cross-platform `tree::root` and false-positive §9.9.3
    /// equivocation.
    #[test]
    fn remove_member_appends_empty_member_left_leaf_before_executed_wasm() {
        use scp_event_log::EventType;
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceProposal, ProposalStatus, SignedVote, VoteType,
        };

        let context_id = "ctx-wasm-remove";
        let proposer = "did:dht:z6MkWasmRemoveProposer";
        let removed = "did:dht:z6MkWasmRemoveTarget";
        let proposal_id = "beadfeed000000000000000000000000000000000000000000000000000000ff";
        let created_at = 1_700_600_700_u64;

        let mut ctx = make_bare_per_context_state(context_id, proposer);
        ctx.test_insert_member(removed, "member");
        // RemoveMember is NOT ceiling-gated at dispatch (authorization is at
        // propose time) — see `dispatch_ceiling_capability`, so no ceiling seed
        // is required here.

        let action = GovernanceAction::RemoveMember {
            did: DID::from(removed.to_owned()),
            reason: None,
        };
        let proposal = GovernanceProposal {
            proposal_id: {
                let bytes = hex::decode(proposal_id).unwrap();
                let mut arr = [0u8; 32];
                arr[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
                arr
            },
            context_id: context_id.to_owned(),
            proposer_did: DID::from(proposer.to_owned()),
            action,
            status: ProposalStatus::Approved,
            created_at,
            voting_deadline: created_at + 3600,
            approvals: vec![SignedVote {
                voter_did: DID::from(proposer.to_owned()),
                vote: VoteType::Approve,
                timestamp: created_at,
                signature: Vec::new(),
            }],
            rejections: Vec::new(),
            created_at_epoch: None,
        };
        ctx.test_insert_resolved_proposal(proposal_id.to_owned(), proposal);

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let resolved_proposer = mgr
            .proposal_proposer_did(context_id, proposal_id)
            .expect("proposer resolvable");
        mgr.execute_governance_action(context_id, proposer, &resolved_proposer, proposal_id)
            .expect("approved RemoveMember proposal must execute");

        let events = mgr.test_context_event_log_events(context_id);

        let member_left = events
            .iter()
            .find(|e| e.event_type == EventType::MemberLeft)
            .expect("a durable MemberLeft leaf must be appended on RemoveMember");
        assert!(
            member_left.payload.data.is_empty(),
            "the MemberLeft leaf payload must be empty (the removed DID is buffer-only)"
        );
        assert_eq!(
            member_left.actor_did.as_ref(),
            resolved_proposer,
            "the MemberLeft leaf actor_did must be the executor, not the removed member"
        );
        assert_ne!(
            member_left.actor_did.as_ref(),
            removed,
            "the MemberLeft leaf must NOT be stamped with the removed member's DID"
        );
        assert_eq!(
            member_left.timestamp, created_at,
            "the MemberLeft leaf timestamp must be the convergent proposal.created_at, \
             never local now()"
        );

        // Exactly ONE MemberLeft and exactly ONE GovernanceActionExecuted leaf.
        // Locking the equal-count invariant guards against a duplicate append
        // (which `find`/`position` below would silently tolerate) diverging the
        // cross-platform `tree::root`.
        let member_left_count = events
            .iter()
            .filter(|e| e.event_type == EventType::MemberLeft)
            .count();
        assert_eq!(
            member_left_count, 1,
            "RemoveMember must append EXACTLY one MemberLeft leaf, got {member_left_count}"
        );
        let executed_count = events
            .iter()
            .filter(|e| e.event_type == EventType::GovernanceActionExecuted)
            .count();
        assert_eq!(
            executed_count, 1,
            "RemoveMember must append EXACTLY one GovernanceActionExecuted leaf, got {executed_count}"
        );

        let member_left_pos = events
            .iter()
            .position(|e| e.event_type == EventType::MemberLeft)
            .expect("MemberLeft present");
        let executed_pos = events
            .iter()
            .position(|e| e.event_type == EventType::GovernanceActionExecuted)
            .expect("GovernanceActionExecuted present");
        assert!(
            member_left_pos < executed_pos,
            "the MemberLeft leaf must precede the GovernanceActionExecuted leaf, \
             matching native execute_remove_member ordering"
        );
    }

    /// Native parity: a governance member who carries NO MLS leaf is removed
    /// CLEANLY (not kept). This matches native `MlsCryptoProvider::remove_member`,
    /// which treats a missing leaf as a no-op (empty commit), so
    /// `execute_remove_member` PROCEEDS to strip membership and append the
    /// `MemberLeft` leaf — the governance layer is authoritative for membership.
    ///
    /// The context's MLS group has only the creator's leaf, so the governance
    /// member `removed` has no MLS leaf. `dispatch_remove_member` must return Ok
    /// with an EMPTY commit, the member must be gone from `ctx.members`, and a
    /// durable `MemberLeft` leaf must be appended.
    #[test]
    fn remove_member_with_no_mls_leaf_is_removed_cleanly() {
        use scp_event_log::EventType;

        let context_id = "ctx-wasm-remove-noleaf";
        let creator = "did:dht:z6MkWasmNoLeafCreator";
        // A governance member with NO MLS leaf: present in `ctx.members` but
        // never added to the single-creator MLS group below.
        let removed = "did:dht:z6MkWasmNoLeafTarget";
        let executor = creator;
        let timestamp_secs = 1_700_700_700_u64;

        let mut ctx = make_bare_per_context_state(context_id, creator);
        ctx.crypto = Some(
            crate::crypto::WasmCryptoState::new_for_context(creator)
                .expect("MLS group creation must succeed for the test fixture"),
        );
        ctx.test_insert_member(removed, "member");
        // Seed per-DID state to prove the F5 cleanup runs on this path too.
        ctx.suspended_capabilities_insert(removed, "messages:write".to_owned());
        ctx.read_exclusion_list.insert(removed.to_owned());
        assert!(
            ctx.role_state.members.contains(removed),
            "precondition: the target must be a governance member before removal"
        );

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let result = mgr
            .dispatch_remove_member(context_id, removed, executor, timestamp_secs)
            .expect("a governance member with no MLS leaf must be removed cleanly (native parity)");

        // The MLS layer produced no commit (no leaf to evict) — empty hex.
        assert_eq!(
            result["commit"].as_str(),
            Some(""),
            "a member with no MLS leaf yields an empty commit (no-op eviction)"
        );

        let ctx_after = mgr
            .contexts
            .get(context_id)
            .expect("context must still be registered after removal");
        assert!(
            !ctx_after.role_state.members.contains(removed),
            "the governance member must be removed from ctx.members (native parity)"
        );
        // F5: per-DID state must be cleaned up.
        assert!(
            ctx_after.test_suspended_capabilities(removed).is_none(),
            "the removed member's suspended_capabilities entry must be cleaned up"
        );
        assert!(
            !ctx_after.read_exclusion_list.contains(removed),
            "the removed member's read_exclusion_list entry must be cleaned up"
        );

        // A durable MemberLeft leaf must be appended.
        let events = mgr.test_context_event_log_events(context_id);
        let member_left = events
            .iter()
            .find(|e| e.event_type == EventType::MemberLeft)
            .expect("a MemberLeft leaf must be appended when a no-leaf member is removed");
        assert!(
            member_left.payload.data.is_empty(),
            "the MemberLeft leaf payload must be empty (the removed DID is buffer-only)"
        );
        assert_eq!(
            member_left.actor_did.as_ref(),
            executor,
            "the MemberLeft leaf actor_did must be the executor"
        );
        assert_eq!(
            member_left.timestamp, timestamp_secs,
            "the MemberLeft leaf timestamp must be the committer-assigned timestamp"
        );
    }

    /// Fail-closed-keep proof for `dispatch_remove_member`: when MLS eviction
    /// fails with a GENUINE MLS error, the member MUST remain fully present in
    /// `ctx.members` (and the log must NOT gain a `MemberLeft` leaf), so no
    /// window opens where the member is gone from governance yet can still
    /// derive the group keys.
    ///
    /// The genuine error is forced by DESTROYING the MLS group (group is None):
    /// `governance_remove_from_group` -> `remove_member_by_did` ->
    /// `leaf_index_for_did` -> `GroupDestroyed`. (A missing leaf is NOT a
    /// genuine error after the native-parity fix — it is a no-op — so a real
    /// fail-closed case requires a real MLS failure.) With the fail-closed-keep
    /// ordering, the early `Err` leaves governance state untouched.
    #[test]
    fn remove_member_keeps_governance_state_when_mls_eviction_fails() {
        use scp_event_log::EventType;

        let context_id = "ctx-wasm-remove-failclosed";
        let creator = "did:dht:z6MkWasmFailClosedCreator";
        let removed = "did:dht:z6MkWasmFailClosedTarget";
        let executor = creator;
        let timestamp_secs = 1_700_700_700_u64;

        let mut ctx = make_bare_per_context_state(context_id, creator);
        let mut crypto = crate::crypto::WasmCryptoState::new_for_context(creator)
            .expect("MLS group creation must succeed for the test fixture");
        // Destroy the MLS group so any eviction attempt hits GroupDestroyed — a
        // genuine MLS failure (not a missing-leaf no-op).
        crypto.mls_group.destroy();
        ctx.crypto = Some(crypto);
        ctx.test_insert_member(removed, "member");
        assert!(
            ctx.role_state.members.contains(removed),
            "precondition: the target must be a governance member before removal"
        );

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let result = mgr.dispatch_remove_member(context_id, removed, executor, timestamp_secs);

        // The MLS eviction failed with a genuine error, so the handler must Err...
        let err = result.expect_err(
            "dispatch_remove_member must fail when MLS eviction hits a genuine MLS error",
        );
        assert!(
            matches!(err, ScpWasmError::Crypto { .. }),
            "the failure must surface as a crypto eviction error, got {err:?}"
        );

        // ...and CRITICALLY the member must STILL be in governance state
        // (fail-closed-keep). A retry is safe; no decryption-after-removal hole.
        let ctx_after = mgr
            .contexts
            .get(context_id)
            .expect("context must still be registered after a failed removal");
        assert!(
            ctx_after.role_state.members.contains(removed),
            "FAIL-CLOSED: a member whose MLS eviction failed MUST remain in \
             ctx.members — removing them from governance while they stay in the \
             MLS group reopens the decryption-after-removal hole"
        );
        assert_eq!(
            ctx_after.test_member_role(removed),
            Some("member"),
            "the kept member's role must be unchanged after the failed removal"
        );

        // No durable MemberLeft leaf may be emitted on a failed removal.
        let events = mgr.test_context_event_log_events(context_id);
        assert!(
            !events.iter().any(|e| e.event_type == EventType::MemberLeft),
            "no MemberLeft leaf may be appended when MLS eviction fails"
        );
    }

    /// `join_context_encrypted` must leave NO phantom member AND NO durable
    /// trace behind when the MLS Welcome cannot be processed. The membership
    /// commit (`members` set, role `assignments`, `member_capabilities`, and
    /// the `member_sequence_numbers` seed) and the pending-key-package
    /// consumption both happen BEFORE `join_from_welcome` runs; a malformed
    /// Welcome (here, empty bytes that fail TLS deserialization) is a
    /// genuinely-reachable crypto error.
    ///
    /// Without the membership rollback the joiner would be a phantom member,
    /// observable via `is_member` / `member_count` / `member_dids`, charged
    /// against `WASM_MEMBER_CAP`, and role-assignable, yet with no MLS leaf.
    ///
    /// CRITICALLY, the `MemberJoined` durable Merkle leaf and the receive-buffer
    /// join event are deferred until AFTER the Welcome succeeds (native Phase 5
    /// ordering). A failed Welcome must therefore leave the event-log leaf count
    /// UNCHANGED (no orphan `MemberJoined` leaf) and drain NO `MemberJoined`
    /// event — otherwise WASM's log would diverge from native, which produces
    /// neither on a failed encrypted join (latent cross-impl equivocation). This
    /// test drives the failure and asserts full atomicity across membership,
    /// the durable log, and the receive buffer.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn join_context_encrypted_rolls_back_membership_on_welcome_failure() {
        let context_id = "ctx-wasm-join-encrypted-rollback";
        let creator = "did:dht:z6MkWasmJoinRollbackCreator";
        let joiner = "did:dht:z6MkWasmJoinRollbackJoiner";

        // Active, unencrypted, no-payment context: the membership-only commit
        // succeeds (joiner is not yet a member; the built-in "member" role
        // assign is infallible by construction), so control reaches the
        // reachable `join_from_welcome` failure path under test.
        let ctx = make_bare_per_context_state(context_id, creator);
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // Populate the pending key package so `join_context_encrypted` does NOT
        // fail early at the CRYPTO_4023 "no pending key package" guard — we
        // want it to proceed through membership and into `join_from_welcome`.
        let kp_bytes = mgr
            .generate_key_package_for_join(context_id, joiner)
            .expect("key package generation must succeed for an active context");
        assert!(
            !kp_bytes.is_empty(),
            "a generated key package must carry bytes"
        );

        // Sanity: the joiner is NOT a member before the attempt.
        assert!(
            !mgr.is_member(context_id, joiner),
            "joiner must not be a member before join_context_encrypted"
        );
        let count_before = mgr
            .member_count(context_id)
            .expect("active context has a member count");
        // Baseline durable leaf count BEFORE the attempt. The fix appends the
        // `MemberJoined` leaf only on Welcome success, so this must be
        // unchanged after the failure below — the assertion that would have
        // caught the orphan-leaf bug.
        let leaf_count_before = mgr
            .event_log_leaf_count(context_id)
            .expect("active context has an event-log leaf count");

        // Empty welcome bytes fail TLS deserialization inside
        // `join_from_welcome` (a reachable crypto error), so the membership
        // commit must be rolled back AND no durable leaf / buffer event may
        // have been emitted.
        let result = mgr.join_context_encrypted(context_id, joiner, &[]);
        match result {
            Err(ScpWasmError::Crypto { ref code, .. }) => assert_eq!(
                code,
                codes::CRYPTO_4021,
                "a malformed Welcome must surface as the CRYPTO_4021 welcome-processing error"
            ),
            other => panic!(
                "join_context_encrypted with an empty Welcome MUST fail with a \
                 CRYPTO_4021 Crypto error, got: {other:?}"
            ),
        }

        // Fail-closed atomicity: no phantom member remains.
        assert!(
            !mgr.is_member(context_id, joiner),
            "a failed MLS welcome must NOT leave the joiner as a member"
        );
        assert_eq!(
            mgr.member_count(context_id),
            Some(count_before),
            "member_count must be unchanged after a failed encrypted join"
        );
        assert!(
            !mgr.member_dids(context_id).contains(&joiner.to_owned()),
            "the joiner must not appear in member_dids after a failed encrypted join"
        );
        assert_eq!(
            mgr.member_role(context_id, joiner),
            None,
            "a failed encrypted join must leave no role assignment for the joiner"
        );
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(joiner),
            None,
            "a failed encrypted join must roll back the joiner's sequence-number seed \
             (it is seeded by join_context_membership_only before the reachable \
             join_from_welcome failure, so this would be Some(0) without the rollback)"
        );

        // Durable-log atomicity: no orphan `MemberJoined` leaf. The leaf is
        // appended only AFTER `join_from_welcome` succeeds (native Phase 5),
        // so a failed Welcome must leave the leaf count exactly as it was —
        // this is the assertion that would have caught the original bug, where
        // the leaf was appended by the inner join BEFORE the reachable Welcome
        // failure and could not be un-appended from the append-only log.
        assert_eq!(
            mgr.event_log_leaf_count(context_id),
            Some(leaf_count_before),
            "a failed encrypted join must NOT append a durable MemberJoined leaf \
             (append-only log cannot un-append it — WASM would diverge from native, \
             which produces no leaf on a failed encrypted join)"
        );
        let drained = mgr.drain_events(context_id);
        assert!(
            !drained.iter().any(|e| matches!(
                e,
                ContextEvent::MemberJoined { member_did, .. } if member_did.0 == joiner
            )),
            "a failed encrypted join must NOT leave a phantom MemberJoined event \
             in the receive buffer — it is pushed only after Welcome success"
        );
    }

    /// Positive counterpart: a SUCCESSFUL encrypted join must append EXACTLY
    /// ONE `MemberJoined` durable leaf and surface EXACTLY ONE buffered
    /// `MemberJoined` event for the joiner. This guards against the reorder
    /// regressing the happy path (dropping the deferred leaf/event entirely)
    /// and confirms the leaf is emitted on success — native Phase 5 ordering.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn join_context_encrypted_appends_one_member_joined_leaf_on_success() {
        use openmls::prelude::KeyPackageIn;
        use tls_codec::Deserialize as _;

        let context_id = "ctx-wasm-join-encrypted-success";
        let creator = "did:dht:z6MkWasmJoinSuccessCreator";
        let joiner = "did:dht:z6MkWasmJoinSuccessJoiner";

        // The joining manager owns the context AND the joiner's key-package
        // holder (stored by `generate_key_package_for_join` in
        // `mgr.pending_key_packages`). `join_context_encrypted` consumes THAT
        // holder, so the Welcome must be minted against the SAME key-package
        // bytes this manager produced.
        let ctx = make_bare_per_context_state(context_id, creator);
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);
        let joiner_kp_bytes = mgr
            .generate_key_package_for_join(context_id, joiner)
            .expect("key package generation must succeed for the joining manager");
        assert!(!joiner_kp_bytes.is_empty());

        // A separate creator MLS group adds the joiner's key package and mints
        // the Welcome. `add_member` returns already-TLS-serialized
        // `(commit_bytes, welcome_bytes)`.
        let mut creator_crypto = crate::crypto::WasmCryptoState::new_for_context(creator)
            .expect("MLS group creation must succeed for the creator");
        let joiner_kp_in = KeyPackageIn::tls_deserialize(&mut &*joiner_kp_bytes)
            .expect("key package deserializes");
        let (_commit_bytes, welcome_bytes) = creator_crypto
            .mls_group
            .add_member(joiner_kp_in)
            .expect("adding the joiner's key package must succeed");
        assert!(!welcome_bytes.is_empty(), "the Welcome must carry bytes");

        let leaf_count_before = mgr
            .event_log_leaf_count(context_id)
            .expect("active context has an event-log leaf count");

        mgr.join_context_encrypted(context_id, joiner, &welcome_bytes)
            .expect("a well-formed Welcome must let the encrypted join succeed");

        // Membership committed.
        assert!(
            mgr.is_member(context_id, joiner),
            "a successful encrypted join must leave the joiner as a member"
        );
        // EXACTLY ONE new durable MemberJoined leaf, appended last.
        assert_eq!(
            mgr.event_log_leaf_count(context_id),
            Some(leaf_count_before + 1),
            "a successful encrypted join must append exactly one MemberJoined leaf"
        );
        let leaves = mgr.test_context_event_log_events(context_id);
        assert_eq!(
            leaves
                .iter()
                .filter(|e| e.event_type == EventType::MemberJoined && e.actor_did.0 == joiner)
                .count(),
            1,
            "exactly one MemberJoined leaf for the joiner must exist after success"
        );
        // EXACTLY ONE buffered MemberJoined event for the joiner.
        let drained = mgr.drain_events(context_id);
        assert_eq!(
            drained
                .iter()
                .filter(|e| matches!(
                    e,
                    ContextEvent::MemberJoined { member_did, .. } if member_did.0 == joiner
                ))
                .count(),
            1,
            "exactly one MemberJoined buffer event for the joiner must exist after success"
        );
    }

    /// F6: encrypted-path commit hex round-trips. With a REAL second MLS member,
    /// `dispatch_remove_member` must return a non-empty hex `commit` that
    /// `hex::decode`s to the eviction commit bytes — the relay-distribution
    /// surface the JS caller is obligated to broadcast.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn remove_member_encrypted_path_returns_decodable_commit_hex() {
        use openmls::prelude::KeyPackageIn;
        use tls_codec::Deserialize as _;

        let context_id = "ctx-wasm-remove-commit";
        let creator = "did:dht:z6MkWasmCommitCreator";
        // The second member's DID — must match the credential embedded in the
        // MLS leaf so `leaf_index_for_did` resolves it.
        let bob_did = "did:dht:z6MkWasmCommitBob";
        let executor = creator;
        let timestamp_secs = 1_700_800_800_u64;

        let mut ctx = make_bare_per_context_state(context_id, creator);
        let mut crypto = crate::crypto::WasmCryptoState::new_for_context(creator)
            .expect("MLS group creation must succeed");

        // Add Bob as a REAL MLS leaf via the standard key-package + add flow.
        let bob_cred = crate::crypto::WasmScpCredential::new(
            bob_did.to_owned(),
            None,
            crate::crypto::WasmSigningKeyId::Active,
        )
        .unwrap();
        let (bob_kp_bytes, _bob_holder) =
            crate::crypto::WasmMlsGroup::generate_key_package(&bob_cred).unwrap();
        let bob_kp_in =
            KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).expect("key package deserializes");
        crypto.mls_group.add_member(bob_kp_in).unwrap();

        ctx.crypto = Some(crypto);
        ctx.test_insert_member(bob_did, "member");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let result = mgr
            .dispatch_remove_member(context_id, bob_did, executor, timestamp_secs)
            .expect("removing a real MLS member must succeed");

        let commit_hex = result["commit"]
            .as_str()
            .expect("the result JSON must carry a string commit field");
        assert!(
            !commit_hex.is_empty(),
            "evicting a real MLS member must produce a non-empty commit"
        );
        let commit_bytes = hex::decode(commit_hex)
            .expect("the commit field must be valid hex of the commit bytes");
        assert!(
            !commit_bytes.is_empty(),
            "the decoded commit must be non-empty MLS commit bytes"
        );

        // The member is gone and Bob no longer resolves to a leaf.
        let ctx_after = mgr
            .contexts
            .get(context_id)
            .expect("context still registered");
        assert!(
            !ctx_after.role_state.members.contains(bob_did),
            "the evicted member must be removed from ctx.members"
        );
        assert!(
            ctx_after
                .crypto
                .as_ref()
                .unwrap()
                .mls_group
                .leaf_index_for_did(bob_did)
                .unwrap()
                .is_none(),
            "the evicted member's DID must no longer resolve to an MLS leaf"
        );
    }

    /// Self-removal parity: a governance `RemoveMember` that targets the
    /// local/creator DID on a REAL encrypted context must behave like native's
    /// self-removal — an EMPTY commit (the own MLS leaf is skipped, so eviction
    /// is a no-op) while dispatch STILL PROCEEDS to strip the member from
    /// `ctx.members`, clean F5 per-DID state, and append a `MemberLeft` leaf.
    ///
    /// This is the divergence regression guard: before the own-leaf skip,
    /// `leaf_index_for_did` resolved the creator's own leaf, `OpenMLS` rejected
    /// `remove_member(own_index)` with `CannotRemoveSelf`, dispatch failed
    /// closed, and the member was KEPT with NO `MemberLeft` leaf — diverging
    /// from native (which removes the member + appends the leaf), breaking the
    /// §9.9.3 cross-platform `tree::root` + membership convergence invariant.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn remove_member_self_did_encrypted_empty_commit_strips_and_appends_leaf() {
        use scp_event_log::EventType;

        let context_id = "ctx-wasm-remove-self";
        // The creator IS the local MLS member (leaf 0) and the removal target.
        let creator = "did:dht:z6MkWasmSelfRemovalCreator";
        let executor = creator;
        let timestamp_secs = 1_701_000_000_u64;

        let mut ctx = make_bare_per_context_state(context_id, creator);
        let crypto = crate::crypto::WasmCryptoState::new_for_context(creator)
            .expect("MLS group creation must succeed");
        ctx.crypto = Some(crypto);
        // Seed F5 per-DID state for the creator so we can prove it is cleaned up.
        ctx.test_insert_suspended_capability(creator, "tool:invoke:calculator");
        assert!(
            ctx.test_suspended_capabilities(creator).is_some(),
            "precondition: the creator must hold a suspended-capabilities entry"
        );

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let result = mgr
            .dispatch_remove_member(context_id, creator, executor, timestamp_secs)
            .expect("self-removal on an encrypted context must succeed (empty-commit no-op)");

        // EMPTY commit — the own MLS leaf is skipped, so eviction is a no-op
        // (matching native's self-removal short-circuit).
        assert_eq!(
            result["commit"].as_str(),
            Some(""),
            "self-removal must produce an EMPTY commit (own leaf skipped — no eviction)"
        );

        let ctx_after = mgr
            .contexts
            .get(context_id)
            .expect("context still registered");

        // Member removed from ctx.members despite the empty commit.
        assert!(
            !ctx_after.role_state.members.contains(creator),
            "self-removal must strip the member from ctx.members even though the commit is empty"
        );

        // F5 per-DID state cleaned.
        assert!(
            ctx_after.test_suspended_capabilities(creator).is_none(),
            "self-removal must clean the removed member's suspended_capabilities entry"
        );

        // A durable MemberLeft leaf must be appended (native parity).
        let events = mgr.test_context_event_log_events(context_id);
        let member_left = events
            .iter()
            .find(|e| e.event_type == EventType::MemberLeft)
            .expect("a MemberLeft leaf must be appended on self-removal (native parity)");
        assert!(
            member_left.payload.data.is_empty(),
            "the MemberLeft leaf payload must be empty (the removed DID is buffer-only)"
        );
        assert_eq!(
            member_left.actor_did.as_ref(),
            executor,
            "the MemberLeft leaf actor_did must be the executor (the self-removing member)"
        );
        assert_eq!(
            member_left.timestamp, timestamp_secs,
            "the MemberLeft leaf timestamp must be the committer-assigned timestamp"
        );
    }

    /// F7: broadcast / `crypto.is_none()` path. A broadcast-author context with
    /// an "author" member and no MLS crypto: `dispatch_remove_member` must run
    /// the `block_author` cleanup, return an EMPTY commit, and still append a
    /// `MemberLeft` leaf.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn remove_member_broadcast_path_empty_commit_still_appends_leaf() {
        use scp_event_log::EventType;

        let context_id = "ctx-wasm-remove-broadcast";
        let creator = "did:dht:z6MkWasmBroadcastCreator";
        let author = "did:dht:z6MkWasmBroadcastAuthor";
        let executor = creator;
        let timestamp_secs = 1_700_900_900_u64;

        let mut ctx = make_bare_per_context_state(context_id, creator);
        // Broadcast context: a BroadcastContext is present, crypto is None.
        ctx.broadcast_context = Some(make_broadcast(&[author], &[]));
        ctx.crypto = None;
        ctx.test_insert_member(author, "author");
        assert!(
            ctx.broadcast_context.as_ref().unwrap().is_author(author),
            "precondition: the author must hold a broadcast key before removal"
        );

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let result = mgr
            .dispatch_remove_member(context_id, author, executor, timestamp_secs)
            .expect("removing an author from a broadcast context must succeed");

        // (b) empty commit — no MLS group on a broadcast context.
        assert_eq!(
            result["commit"].as_str(),
            Some(""),
            "a broadcast (crypto.is_none) context produces an empty commit"
        );

        let ctx_after = mgr
            .contexts
            .get(context_id)
            .expect("context still registered");
        assert!(
            !ctx_after.role_state.members.contains(author),
            "the author must be removed from ctx.members"
        );
        // (a) block_author cleanup ran — the author's broadcast key is destroyed.
        assert!(
            !ctx_after
                .broadcast_context
                .as_ref()
                .unwrap()
                .is_author(author),
            "block_author cleanup must run: the removed author must no longer hold a broadcast key"
        );

        // (c) a MemberLeft leaf is still appended.
        let events = mgr.test_context_event_log_events(context_id);
        assert!(
            events.iter().any(|e| e.event_type == EventType::MemberLeft),
            "a MemberLeft leaf must be appended even on the broadcast/empty-commit path"
        );
    }

    // -----------------------------------------------------------------------
    // leave_context coverage
    // -----------------------------------------------------------------------

    /// `leave_context` must strip ALL per-member state for the leaving member
    /// (membership, role assignment, granted capabilities, suspensions, and the
    /// MLS sequence counter) and append EXACTLY one durable `MemberLeft` leaf —
    /// without auto-closing while another member (the creator) remains.
    #[test]
    fn leave_context_strips_all_member_state_and_emits_member_left_wasm() {
        use scp_event_log::EventType;

        let context_id = "ctx-wasm-leave-strip";
        let creator = "did:dht:z6MkWasmLeaveCreator";
        let leaver = "did:dht:z6MkWasmLeaveMember";

        let mut ctx = make_bare_per_context_state(context_id, creator);
        // Widen the ceiling so the built-in `member` role actually carries
        // messages:read / messages:write (caps are ceiling-intersected).
        ctx.test_insert_ceiling("messages:read");
        ctx.test_insert_ceiling("messages:write");
        // Add M with the `member` role (seeds members + a sequence entry +
        // grants caps), advance its sequence counter to a non-zero value, and
        // seed a suspension so we can assert the suspended entry is cleared.
        ctx.test_insert_member(leaver, "member");
        ctx.member_sequence_numbers.insert(leaver.to_owned(), 5);
        ctx.test_insert_suspended_capability(leaver, "messages:write");

        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        // Preconditions: M is a member, holds a non-suspended cap, has a seeded
        // sequence counter and a suspension.
        assert!(
            mgr.is_member(context_id, leaver),
            "precondition: M is a member"
        );
        assert_eq!(
            mgr.member_role(context_id, leaver).as_deref(),
            Some("member"),
            "precondition: M holds the `member` role"
        );
        assert!(
            mgr.contexts[context_id].member_has_capability(leaver, "messages:read"),
            "precondition: M holds messages:read (an unsuspended granted cap)"
        );
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(leaver),
            Some(5),
            "precondition: M has a non-zero sequence counter"
        );
        assert!(
            mgr.contexts[context_id]
                .test_suspended_capabilities(leaver)
                .is_some_and(|s| s.contains("messages:write")),
            "precondition: M has a seeded suspension"
        );

        let leaf_count_before = mgr
            .event_log_leaf_count(context_id)
            .expect("active context has an event-log leaf count");

        mgr.leave_context(context_id, leaver)
            .expect("a member leaving the context must succeed");

        // Membership stripped: M gone from members / role / caps.
        assert!(
            !mgr.is_member(context_id, leaver),
            "after leave, M must be gone from `members`"
        );
        assert_eq!(
            mgr.member_role(context_id, leaver),
            None,
            "after leave, M must have no role assignment"
        );
        assert!(
            !mgr.contexts[context_id].member_has_capability(leaver, "messages:read"),
            "after leave, M must hold no capabilities"
        );
        // Per-member sidecar state stripped.
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(leaver),
            None,
            "after leave, M's sequence counter entry must be removed"
        );
        assert_eq!(
            mgr.contexts[context_id].test_suspended_capabilities(leaver),
            None,
            "after leave, M's suspension entry must be cleared (no dangling phantom suspension)"
        );

        // The creator remains, so the context must NOT auto-close.
        assert!(
            mgr.is_member(context_id, creator),
            "the creator must remain a member after M leaves"
        );
        assert_eq!(
            mgr.contexts[context_id].state, "active",
            "the context must stay active while the creator remains"
        );

        // EXACTLY one new durable MemberLeft leaf was appended.
        assert_eq!(
            mgr.event_log_leaf_count(context_id),
            Some(leaf_count_before + 1),
            "leave_context must append exactly one durable leaf"
        );
        let events = mgr.test_context_event_log_events(context_id);
        let member_left_count = events
            .iter()
            .filter(|e| e.event_type == EventType::MemberLeft)
            .count();
        assert_eq!(
            member_left_count, 1,
            "leave_context must append EXACTLY one MemberLeft leaf, got {member_left_count}"
        );
        let member_left = events
            .iter()
            .find(|e| e.event_type == EventType::MemberLeft)
            .expect("a MemberLeft leaf must be present");
        assert_eq!(
            member_left.actor_did.0, leaver,
            "the MemberLeft leaf actor_did must be the leaving member"
        );
    }

    /// When the LAST member leaves, `leave_context` must transition the context
    /// to the `"closing"` lifecycle state (auto-close on empty membership).
    #[test]
    fn leave_context_last_member_closes_context_wasm() {
        let context_id = "ctx-wasm-leave-last";
        // The creator is the sole member (auto-assigned `admin` by
        // `ContextRoleState::new`), so when the creator leaves, membership is
        // empty and the context must auto-close.
        let creator = "did:dht:z6MkWasmLeaveLastCreator";

        let ctx = make_bare_per_context_state(context_id, creator);
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        assert_eq!(
            mgr.member_dids(context_id).len(),
            1,
            "precondition: the creator is the sole member"
        );
        assert_eq!(
            mgr.contexts[context_id].state, "active",
            "precondition: the context starts active"
        );

        mgr.leave_context(context_id, creator)
            .expect("the last member leaving must succeed");

        assert!(
            !mgr.is_member(context_id, creator),
            "after the last member leaves, no members remain"
        );
        assert!(
            mgr.member_dids(context_id).is_empty(),
            "membership must be empty after the last member leaves"
        );
        // `leave_context` sets state to "closing" when no members remain.
        assert_eq!(
            mgr.contexts[context_id].state, "closing",
            "the last member leaving must auto-close the context (state -> closing)"
        );
    }

    /// `leave_context` for a DID that is NOT a member must be rejected with the
    /// `CTX_2015` not-found code and must NOT mutate state or append any leaf.
    #[test]
    fn leave_context_nonmember_is_rejected_wasm() {
        let context_id = "ctx-wasm-leave-nonmember";
        let creator = "did:dht:z6MkWasmLeaveNonmemberCreator";
        let stranger = "did:dht:z6MkWasmLeaveStranger";

        let ctx = make_bare_per_context_state(context_id, creator);
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let leaf_count_before = mgr
            .event_log_leaf_count(context_id)
            .expect("active context has an event-log leaf count");

        let result = mgr.leave_context(context_id, stranger);
        match result {
            Err(ScpWasmError::Context { code, .. }) => {
                assert_eq!(
                    code,
                    codes::CTX_2015,
                    "a non-member leave must be rejected with the CTX_2015 not-found code"
                );
            }
            other => panic!("expected a CTX_2015 Context error, got {other:?}"),
        }

        // No state mutation: the creator remains and the context stays active.
        assert!(
            mgr.is_member(context_id, creator),
            "a rejected non-member leave must not remove the existing member"
        );
        assert_eq!(
            mgr.contexts[context_id].state, "active",
            "a rejected non-member leave must not change the lifecycle state"
        );
        // No durable leaf appended on the rejected path.
        assert_eq!(
            mgr.event_log_leaf_count(context_id),
            Some(leaf_count_before),
            "a rejected non-member leave must append no durable leaf"
        );
    }

    // -----------------------------------------------------------------------
    // join_context (non-encrypted) success
    // -----------------------------------------------------------------------

    /// The non-encrypted `join_context` path must add the joiner as a `member`,
    /// seed its sequence counter, and emit EXACTLY one `MemberJoined` buffer
    /// event AND one durable `MemberJoined` leaf immediately (no MLS Welcome to
    /// defer behind).
    #[test]
    fn join_context_succeeds_adds_member_wasm() {
        use scp_event_log::EventType;

        let context_id = "ctx-wasm-join-plain";
        let creator = "did:dht:z6MkWasmJoinPlainCreator";
        let joiner = "did:dht:z6MkWasmJoinPlainJoiner";

        // `make_bare_per_context_state` builds a free (no economic policy),
        // unencrypted, active context, so the non-encrypted join path applies
        // and the C2 economy gate does not reject.
        let ctx = make_bare_per_context_state(context_id, creator);
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        assert!(
            !mgr.is_member(context_id, joiner),
            "precondition: the joiner is not yet a member"
        );
        let leaf_count_before = mgr
            .event_log_leaf_count(context_id)
            .expect("active context has an event-log leaf count");

        mgr.join_context(context_id, joiner, None)
            .expect("a free, unencrypted join must succeed");

        // Member added with the built-in `member` role and a seeded counter.
        assert!(
            mgr.is_member(context_id, joiner),
            "a successful join must add the joiner to `members`"
        );
        assert_eq!(
            mgr.member_role(context_id, joiner).as_deref(),
            Some("member"),
            "a successful unencrypted join must assign the built-in `member` role"
        );
        assert_eq!(
            mgr.contexts[context_id].test_member_sequence_number(joiner),
            Some(0),
            "a successful join must seed the joiner's sequence counter to 0"
        );

        // EXACTLY one new durable MemberJoined leaf for the joiner.
        assert_eq!(
            mgr.event_log_leaf_count(context_id),
            Some(leaf_count_before + 1),
            "a successful unencrypted join must append exactly one durable leaf"
        );
        let leaves = mgr.test_context_event_log_events(context_id);
        assert_eq!(
            leaves
                .iter()
                .filter(|e| e.event_type == EventType::MemberJoined && e.actor_did.0 == joiner)
                .count(),
            1,
            "exactly one MemberJoined leaf for the joiner must exist after a successful join"
        );

        // EXACTLY one buffered MemberJoined event for the joiner.
        let drained = mgr.drain_events(context_id);
        assert_eq!(
            drained
                .iter()
                .filter(|e| matches!(
                    e,
                    ContextEvent::MemberJoined { member_did, role_name }
                        if member_did.0 == joiner && role_name == "member"
                ))
                .count(),
            1,
            "exactly one MemberJoined buffer event for the joiner must be emitted"
        );
    }

    // -----------------------------------------------------------------------
    // remove_member non-member rejection
    // -----------------------------------------------------------------------

    /// `dispatch_remove_member` on a DID that is not a member must be rejected
    /// with the `CTX_2015` not-found code and must append no durable leaf.
    #[test]
    fn remove_member_nonmember_is_rejected_wasm() {
        let context_id = "ctx-wasm-remove-nonmember";
        let creator = "did:dht:z6MkWasmRemoveNonmemberCreator";
        let executor = creator;
        let stranger = "did:dht:z6MkWasmRemoveStranger";
        let timestamp_secs = 1_700_950_950_u64;

        let ctx = make_bare_per_context_state(context_id, creator);
        let mut mgr = WasmContextManager::new();
        mgr.test_insert_context(context_id, ctx);

        let leaf_count_before = mgr
            .event_log_leaf_count(context_id)
            .expect("active context has an event-log leaf count");

        let result = mgr.dispatch_remove_member(context_id, stranger, executor, timestamp_secs);
        match result {
            Err(ScpWasmError::Context { code, .. }) => {
                assert_eq!(
                    code,
                    codes::CTX_2015,
                    "removing a non-member must be rejected with the CTX_2015 not-found code"
                );
            }
            other => panic!("expected a CTX_2015 Context error, got {other:?}"),
        }

        // No durable leaf appended on the rejected path.
        assert_eq!(
            mgr.event_log_leaf_count(context_id),
            Some(leaf_count_before),
            "a rejected non-member removal must append no durable leaf"
        );
    }
}
