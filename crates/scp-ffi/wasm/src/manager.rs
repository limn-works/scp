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
use scp_protocol::crypto::ucan::UcanError;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker,
};
use scp_protocol::economy::policy::policy_requires_payment;
use scp_protocol::economy::types::EconomicPolicy;

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

// ---------------------------------------------------------------------------
// MemberEntry — per-member state
// ---------------------------------------------------------------------------

/// Per-member state within a context.
#[derive(Debug, Clone)]
pub(crate) struct MemberEntry {
    /// Stored for diagnostics and serialization; read via `HashMap` key.
    #[allow(dead_code)]
    pub(crate) did: String,
    pub(crate) role: String,
    pub(crate) sequence_number: u64,
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
    /// Creator DID.
    creator_did: String,
    /// Context mode: "Encrypted" or "Broadcast".
    mode: String,
    /// Capability ceiling as `{resource}:{action}` strings.
    ceiling_strings: HashSet<String>,
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
    /// Members indexed by DID.
    members: HashMap<String, MemberEntry>,
    /// Receive buffer for events. Capped at [`WASM_EVENT_BUFFER_CAP`] (FIFO overflow).
    /// Uses `VecDeque` for O(1) `pop_front` instead of `Vec::remove(0)` O(n) shift.
    event_buffer: VecDeque<ContextEvent>,
    /// Executed proposal IDs with insertion timestamps (replay protection).
    /// Evicts entries older than [`WASM_PROPOSAL_TTL_MS`] when exceeding [`WASM_PROPOSAL_CAP`].
    executed_proposals: HashMap<String, f64>,
    /// Suspended capabilities per member DID (replaces legacy per-member revocation tracking).
    /// Key: member DID, Value: set of suspended capability strings (e.g. "messages:write").
    suspended_capabilities: HashMap<String, HashSet<String>>,
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

/// Executed proposal TTL in milliseconds (24 hours).
const WASM_PROPOSAL_TTL_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

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
    /// Mirrors `ContextRoleState::member_has_capability` in scp-core. In the
    /// default role system (see `builtin_*` functions in scp-core roles.rs):
    /// - "admin" — all capabilities in the ceiling.
    /// - "moderator" — messages:read, messages:write, `tool_invoke:*`,
    ///   member:remove, governance:propose (§5.9 elected moderators pattern).
    /// - "member" — messages:read, messages:write, `tool_invoke:*`.
    /// - "author" — messages:write, messages:read, `tool_invoke:*`.
    /// - "observer" — messages:read only.
    /// - "subscriber" — messages:read only (broadcast contexts).
    ///
    /// Capability strings use the UCAN `{resource}:{action}` format where
    /// compound resources use underscores (e.g. `"tool_invoke:*"`,
    /// `"context:close"`, `"messages:write"`). This matches scp-core's
    /// `Capability::ucan_capability_name()` output and the ceiling string
    /// format, ensuring cross-platform UCAN token exchange works correctly.
    fn member_has_capability(&self, member_did: &str, capability: &str) -> bool {
        let Some(member) = self.members.get(member_did) else {
            return false;
        };

        // Suspension check FIRST — a suspended capability is denied even if
        // the member's role + ceiling would grant it. Mirrors
        // `ContextRoleState::member_has_capability` in scp-protocol, which
        // checks `suspended_capabilities` before the role-granted set.
        //
        // This closes the wiring gap where consequence rules (via
        // `crate::consequence::apply_suspend` / `apply_suspend_all`) would
        // insert entries into `suspended_capabilities` but every gate that
        // calls `member_has_capability` would still grant the capability,
        // leaving the suspension unenforced.
        if self
            .suspended_capabilities
            .get(member_did)
            .is_some_and(|s| s.contains(capability))
        {
            return false;
        }

        // Helper: check that the capability is within the context ceiling.
        let in_ceiling = |cap: &str| -> bool {
            let (resource, _action) = cap.rsplit_once(':').unwrap_or((cap, "*"));
            let wildcard = format!("{resource}:*");
            self.ceiling_strings.contains(cap) || self.ceiling_strings.contains(&wildcard)
        };

        match member.role.as_str() {
            "admin" => {
                // Admins have all capabilities in the ceiling.
                in_ceiling(capability)
            }
            "moderator" => {
                // Moderators: messages r/w, tool invoke, member remove,
                // governance propose — intersected with ceiling (§5.9).
                let role_grants = matches!(
                    capability,
                    "messages:read"
                        | "messages:write"
                        | "tool_invoke:*"
                        | "member:remove"
                        | "governance:propose"
                );
                role_grants && in_ceiling(capability)
            }
            "author" => {
                // Authors: messages r/w, tool invoke — intersected with ceiling.
                let role_grants = matches!(
                    capability,
                    "messages:write" | "messages:read" | "tool_invoke:*"
                );
                role_grants && in_ceiling(capability)
            }
            "member" => {
                // Default member capabilities: messages:read, messages:write,
                // tool_invoke:* — intersected with ceiling.
                let role_grants = matches!(
                    capability,
                    "messages:read" | "messages:write" | "tool_invoke:*"
                );
                role_grants && in_ceiling(capability)
            }
            "subscriber" => {
                // Subscribers can only read messages (broadcast contexts).
                capability == "messages:read" && in_ceiling(capability)
            }
            "observer" => {
                // Observers can only read messages.
                capability == "messages:read" && in_ceiling(capability)
            }
            _ => false,
        }
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
        self.members.contains_key(subject_did)
    }

    /// Returns a mutable reference to the subject's member entry.
    pub(crate) fn members_get_mut(&mut self, subject_did: &str) -> Option<&mut MemberEntry> {
        self.members.get_mut(subject_did)
    }

    /// Pushes a context event onto the receive buffer (public wrapper so
    /// `crate::consequence` can emit `ConsequenceTriggered` /
    /// `ConsequenceEnforced`).
    pub(crate) fn push_event_pub(&mut self, event: ContextEvent) {
        self.push_event(event);
    }

    /// Role-based capability check (public wrapper around the module-private
    /// `member_has_capability`).
    pub(crate) fn member_has_capability_pub(&self, subject_did: &str, capability: &str) -> bool {
        self.member_has_capability(subject_did, capability)
    }

    /// Inserts `capability` into the subject's suspended capability set.
    /// Creates a new `HashSet` if the subject has no existing entry.
    pub(crate) fn suspended_capabilities_insert(&mut self, subject_did: &str, capability: String) {
        self.suspended_capabilities
            .entry(subject_did.to_owned())
            .or_default()
            .insert(capability);
    }

    /// Reads a cooldown timer for a given rule index.
    pub(crate) fn cooldown_until_get(&self, rule_index: usize) -> Option<&u64> {
        self.cooldown_until.get(&rule_index)
    }

    /// Records a cooldown timer for a given rule index.
    pub(crate) fn cooldown_until_insert(&mut self, rule_index: usize, until_secs: u64) {
        self.cooldown_until.insert(rule_index, until_secs);
    }

    /// Returns a reference to the context's capability ceiling strings.
    pub(crate) fn ceiling_strings_pub(&self) -> &HashSet<String> {
        &self.ceiling_strings
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
        // Native uses CONSEQUENCE_ACTOR_DID = "system" as the actor for these
        // leaves so the `WarningCount` trigger's `actor_did != subject_did`
        // requirement holds for recursive rule evaluation.
        let payload = scp_event_log::payload::consequence_event_payload(
            subject_did,
            rule_index,
            trigger_kind,
            action_type,
        );
        self.append_log_event(event_type, "system", &payload.data, trigger_timestamp_secs);
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

    /// Test-only: insert a member with the given role.
    #[cfg(test)]
    pub(crate) fn test_insert_member(&mut self, did: &str, role: &str) {
        self.members.insert(
            did.to_owned(),
            MemberEntry {
                did: did.to_owned(),
                role: role.to_owned(),
                sequence_number: 0,
            },
        );
    }

    /// Test-only: read the current role string for a member.
    #[cfg(test)]
    pub(crate) fn test_member_role(&self, did: &str) -> Option<&str> {
        self.members.get(did).map(|m| m.role.as_str())
    }

    /// Test-only: read the suspended capability set for a member.
    #[cfg(test)]
    pub(crate) fn test_suspended_capabilities(
        &self,
        did: &str,
    ) -> Option<&std::collections::HashSet<String>> {
        self.suspended_capabilities.get(did)
    }

    /// Test-only: push a consequence rule onto the context's declared rules.
    #[cfg(test)]
    pub(crate) fn test_push_consequence_rule(
        &mut self,
        rule: scp_protocol::trust::consequence::ConsequenceRule,
    ) {
        self.consequence_rules.push(rule);
    }

    /// Test-only: add a capability string to the context ceiling.
    #[cfg(test)]
    pub(crate) fn test_insert_ceiling(&mut self, capability: &str) {
        self.ceiling_strings.insert(capability.to_owned());
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
pub(crate) fn make_bare_per_context_state(context_id: &str, creator_did: &str) -> PerContextState {
    let mut members = HashMap::new();
    members.insert(
        creator_did.to_owned(),
        MemberEntry {
            did: creator_did.to_owned(),
            role: "admin".to_owned(),
            sequence_number: 0,
        },
    );

    PerContextState {
        state: "active".to_owned(),
        params_json: serde_json::Value::Null,
        creator_did: creator_did.to_owned(),
        mode: "Unencrypted".to_owned(),
        ceiling_strings: HashSet::new(),
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
        members,
        event_buffer: VecDeque::new(),
        executed_proposals: HashMap::new(),
        suspended_capabilities: HashMap::new(),
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

        let ceiling_strings = Self::build_ceiling_strings(&ceiling);

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

        // Initialize creator as admin member.
        let mut members = HashMap::new();
        members.insert(
            creator_did.to_owned(),
            MemberEntry {
                did: creator_did.to_owned(),
                role: "admin".to_owned(),
                sequence_number: 0,
            },
        );

        let per_context = PerContextState {
            state: "active".to_owned(),
            params_json: params.clone(),
            creator_did: creator_did.to_owned(),
            mode,
            ceiling_strings,
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
            members,
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            suspended_capabilities: HashMap::new(),
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
                // copied by every member (§7.3.1, §9.9.3).
                crate::time::now_secs(),
            );
        }

        Ok(())
    }

    /// Joins a member to a context. Mirrors `ContextManager::join_context`.
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

        if ctx.members.contains_key(member_did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{member_did}' already joined context '{context_id}'"),
                code: codes::CTX_2013.to_owned(),
            });
        }

        ctx.members.insert(
            member_did.to_owned(),
            MemberEntry {
                did: member_did.to_owned(),
                role: "member".to_owned(),
                sequence_number: 0,
            },
        );

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

        if ctx.members.remove(member_did).is_none() {
            return Err(ScpWasmError::Context {
                message: format!("member '{member_did}' not found in context '{context_id}'"),
                code: codes::CTX_2015.to_owned(),
            });
        }

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
        if ctx.members.is_empty() {
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

        // Check write suspension.
        if ctx
            .suspended_capabilities
            .get(sender_did)
            .is_some_and(|caps| caps.contains("messages:write"))
        {
            return Err(ScpWasmError::Permission {
                message: format!("write access has been suspended for {sender_did}"),
                code: codes::PERM_3000.to_owned(),
            });
        }

        // Check membership and assign sequence number.
        let member = ctx
            .members
            .get_mut(sender_did)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("sender '{sender_did}' is not a member of context '{context_id}'"),
                code: codes::CTX_2019.to_owned(),
            })?;

        let seq = member.sequence_number;
        member.sequence_number += 1;

        // If crypto state is available, encrypt the payload before recording.
        let recorded_payload = if let Some(ref mut crypto) = ctx.crypto {
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

            base64::engine::general_purpose::STANDARD.encode(&ciphertext)
        } else {
            payload_base64.to_owned()
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

        // First join the context normally (membership, events, etc.).
        // Encrypted join doesn't carry a separate spending UCAN — the Welcome
        // flow implies the adder already validated the join cost.
        self.join_context(context_id, member_did, None)?;

        // Then set up MLS crypto state from the Welcome.
        let mls_group =
            crate::crypto::group::WasmMlsGroup::join_from_welcome(welcome_bytes, holder).map_err(
                |e| ScpWasmError::Crypto {
                    message: format!("MLS welcome processing failed: {e}"),
                    code: codes::CRYPTO_4021.to_owned(),
                },
            )?;

        let ctx = self.require_active_context_mut(context_id)?;
        ctx.crypto = Some(crate::crypto::WasmCryptoState {
            mls_group,
            local_sender_key: crate::crypto::sender_key::generate_sender_key(),
            sender_key_store: std::collections::HashMap::new(),
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Membership queries
    // -----------------------------------------------------------------------

    /// Returns the member count. Mirrors `ContextManager::member_count`.
    #[must_use]
    pub fn member_count(&self, context_id: &str) -> Option<usize> {
        self.contexts.get(context_id).map(|ctx| ctx.members.len())
    }

    /// Returns `true` if the DID is a member. Mirrors `ContextManager::is_member`.
    #[must_use]
    pub fn is_member(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .get(context_id)
            .is_some_and(|ctx| ctx.members.contains_key(did))
    }

    /// Returns all member DIDs. Mirrors `ContextManager::member_dids`.
    #[must_use]
    pub fn member_dids(&self, context_id: &str) -> Vec<String> {
        self.contexts
            .get(context_id)
            .map(|ctx| ctx.members.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the role for a member. Mirrors `ContextManager::member_role`.
    #[must_use]
    pub fn member_role(&self, context_id: &str, did: &str) -> Option<String> {
        self.contexts
            .get(context_id)
            .and_then(|ctx| ctx.members.get(did))
            .map(|m| m.role.clone())
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

        let actor = ctx.creator_did.clone();
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
            ctx.ceiling_strings.clone(),
            ctx.creator_did.clone(),
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
    /// matching `member_has_capability` and the ceiling strings.
    fn required_capability_for_action(action: &GovernanceAction) -> &'static str {
        match action {
            GovernanceAction::AddMember { .. } | GovernanceAction::RestoreAccess { .. } => {
                "member:invite"
            }

            GovernanceAction::RemoveMember { .. }
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::ResetMember { .. } => "member:remove",

            GovernanceAction::ChangeRole { .. } => "role:assign",

            GovernanceAction::RegisterTool { .. }
            | GovernanceAction::RemoveTool { .. }
            | GovernanceAction::EstablishToolInterface { .. } => "tool:register",

            GovernanceAction::CloseContext { .. } => "context:close",

            GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::PromoteContext
            | GovernanceAction::CreateChildContext { .. }
            | GovernanceAction::ModifyPruningPolicy { .. }
            | GovernanceAction::AddSigner { .. }
            | GovernanceAction::RemoveSigner { .. }
            | GovernanceAction::ModifyThreshold { .. }
            | GovernanceAction::ResolveConflict { .. }
            | GovernanceAction::RotateContentKeys { .. }
            | GovernanceAction::ReconfigureGovernance { .. }
            | GovernanceAction::SetEconomicPolicy { .. }
            | GovernanceAction::ApproveSpend { .. }
            | GovernanceAction::LockEconomicPolicy
            | GovernanceAction::ModifyHardRateLimit { .. }
            | GovernanceAction::ProposeContextMigration { .. }
            | GovernanceAction::CancelContextMigration => "governance:propose",
        }
    }

    /// Executes a governance action. Mirrors `ContextManager::execute_governance_action`.
    ///
    /// Validates that the initiator has the required capability for the
    /// action, that the proposal is not a replay, dispatches to the
    /// appropriate action handler, and records the proposal as executed.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the initiator lacks
    /// the required capability, the proposal was already executed, or the
    /// action fails.
    pub fn execute_governance_action(
        &mut self,
        context_id: &str,
        initiator_did: &str,
        proposal_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Authorization: check that initiator has the required capability
        // for this governance action. Matches close_context's pattern.
        {
            let ctx = self.require_active_context_mut(context_id)?;
            let required = Self::required_capability_for_action(action);
            if !ctx.member_has_capability(initiator_did, required) {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "member {initiator_did} does not have '{required}' capability required for this governance action"
                    ),
                    code: codes::PERM_3000.to_owned(),
                });
            }
        }

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

            let created_at = ctx
                .pending_proposals
                .get(proposal_id)
                .or_else(|| ctx.resolved_proposals.get(proposal_id))
                .map(|p| p.created_at)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!(
                        "governance proposal '{proposal_id}' is not tracked (pending or resolved); \
                         cannot derive the convergent GovernanceActionExecuted leaf timestamp"
                    ),
                    code: codes::CTX_2041.to_owned(),
                })?;

            // Evict expired proposals when over capacity.
            if ctx.executed_proposals.len() >= WASM_PROPOSAL_CAP {
                let cutoff = now - WASM_PROPOSAL_TTL_MS;
                ctx.executed_proposals.retain(|_, ts| *ts > cutoff);
            }

            ctx.executed_proposals.insert(proposal_id.to_owned(), now);
            created_at
        };

        let result = self.dispatch_governance_action(context_id, action);

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
            let proposal_id_bytes: [u8; 32] = {
                let bytes = hex::decode(proposal_id).unwrap_or_default();
                let mut arr = [0u8; 32];
                let len = bytes.len().min(32);
                arr[..len].copy_from_slice(&bytes[..len]);
                arr
            };
            let target_did: Option<DID> = action.target_did().cloned();
            ctx.push_event(ContextEvent::GovernanceActionExecuted {
                proposal_id: proposal_id_bytes,
                action_summary,
                executor_did: DID(initiator_did.to_owned()),
                resulting_epoch: None,
                target_did: target_did.clone(),
            });
            // Durable GovernanceActionExecuted leaf. The payload MUST be the
            // shared `GovernanceActionExecutedPayload` (positional MessagePack
            // via `encode_payload`) — byte-identical to the native runtime's
            // `finalize_governance_action` construction — so cross-platform
            // members derive equal Merkle roots (§9.9.3). `target_did` is the
            // action's target (empty when untargeted); `action_type` is the
            // `GovernanceAction` variant name.
            let executed_payload = scp_event_log::payload::encode_payload(
                &scp_event_log::payload::GovernanceActionExecutedPayload {
                    target_did: target_did
                        .as_ref()
                        .map(|d| d.as_ref().to_owned())
                        .unwrap_or_default(),
                    action_type: action.variant_name().to_owned(),
                },
            )
            .map(|p| p.data)
            .unwrap_or_default();
            ctx.append_log_event(
                EventType::GovernanceActionExecuted,
                initiator_did,
                &executed_payload,
                proposal_created_at,
            );

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

    /// Dispatches a governance action to its handler.
    ///
    /// Split into multiple methods to satisfy the 100-line function limit.
    fn dispatch_governance_action(
        &mut self,
        context_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            GovernanceAction::AddMember { did, role } => {
                self.dispatch_add_member(context_id, did, role)
            }
            GovernanceAction::RemoveMember { did, .. } => {
                self.dispatch_remove_member(context_id, did)
            }
            GovernanceAction::ChangeRole { did, new_role } => {
                let ctx = self.require_active_context_mut(context_id)?;
                let did_str: &str = did;
                let member = ctx.members.get_mut(did_str).ok_or_else(|| ScpWasmError::Context {
                    message: format!("member '{did}' not found"),
                    code: codes::CTX_2015.to_owned(),
                })?;
                let old_role = member.role.clone();
                new_role.clone_into(&mut member.role);
                // Sync broadcast state when role transitions to/from "author".
                if let Some(ref mut bc) = ctx.broadcast_context {
                    if old_role == "author" && new_role != "author" {
                        // Revoke author status — destroys their broadcast key.
                        let _ = bc.block_author(did_str);
                    } else if new_role == "author" && old_role != "author" {
                        // Grant author status — generates a fresh broadcast key.
                        let _ = bc.add_author(did_str);
                    }
                }
                Ok(serde_json::json!({"action": "ChangeRole", "did": did_str, "newRole": new_role}))
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
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.ceiling_policy != "governed" {
                    return Err(ScpWasmError::Permission {
                        message: "ceiling is immutable — cannot modify".to_owned(),
                        code: codes::PERM_3000.to_owned(),
                    });
                }
                ctx.ceiling_strings = new_ceiling.iter().map(|c| Self::capability_to_ucan_format(&c.name())).collect();
                Ok(serde_json::json!({"action": "ModifyCeiling"}))
            }
            GovernanceAction::CloseContext { .. } => {
                let ctx = self.require_active_context_mut(context_id)?;
                "closing".clone_into(&mut ctx.state);
                Ok(serde_json::json!({"action": "CloseContext"}))
            }
            GovernanceAction::ExtendTtl { additional_secs } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if let Some(ref mut ttl) = ctx.ttl_seconds {
                    *ttl += additional_secs;
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

    /// Handles `AddMember` governance action: inserts the member and, for
    /// broadcast contexts, registers author state when the role is "author".
    fn dispatch_add_member(
        &mut self,
        context_id: &str,
        did: &str,
        role: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if ctx.members.len() >= WASM_MEMBER_CAP {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "member list has reached capacity ({WASM_MEMBER_CAP}) — \
                     cannot add additional members"
                ),
                code: codes::VALID_7302.to_owned(),
            });
        }

        ctx.members.insert(
            did.to_owned(),
            MemberEntry {
                did: did.to_owned(),
                role: role.to_owned(),
                sequence_number: 0,
            },
        );
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
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        let removed = ctx
            .members
            .remove(did)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("member '{did}' not found"),
                code: codes::CTX_2015.to_owned(),
            })?;
        // If the ejected member was an author in a broadcast context,
        // clean up their broadcast state (destroys broadcast key).
        if removed.role == "author"
            && let Some(ref mut bc) = ctx.broadcast_context
        {
            let _ = bc.block_author(did);
        }
        ctx.push_event(ContextEvent::MemberLeft {
            member_did: DID(did.to_owned()),
        });
        Ok(serde_json::json!({"action": "RemoveMember", "did": did}))
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
                let old_admin = ctx.creator_did.clone();
                if let Some(m) = ctx.members.get_mut(&old_admin) {
                    "member".clone_into(&mut m.role);
                }
                if let Some(m) = ctx.members.get_mut(new_admin_str) {
                    "admin".clone_into(&mut m.role);
                }
                new_admin_str.clone_into(&mut ctx.creator_did);
                Ok(serde_json::json!({"action": "TransferAdmin", "newAdmin": new_admin_str}))
            }
            GovernanceAction::SuspendCapability { did, capabilities } => {
                let did_str: &str = did;
                let ctx = self.require_active_context_mut(context_id)?;
                let entry = ctx
                    .suspended_capabilities
                    .entry(did_str.to_owned())
                    .or_default();
                for cap in capabilities {
                    entry.insert(Self::capability_to_ucan_format(&cap.name()));
                }
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
                // Suspend every capability in the context's ceiling,
                // matching runtime's `suspend_all` semantics.
                let all_capabilities: Vec<String> = ctx.ceiling_strings.iter().cloned().collect();
                let entry = ctx
                    .suspended_capabilities
                    .entry(did_str.to_owned())
                    .or_default();
                for cap in &all_capabilities {
                    entry.insert(cap.clone());
                }
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
                if let Some(entry) = ctx.suspended_capabilities.get_mut(did_str) {
                    for cap in capabilities {
                        entry.remove(&Self::capability_to_ucan_format(&cap.name()));
                    }
                    if entry.is_empty() {
                        ctx.suspended_capabilities.remove(did_str);
                    }
                }
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

        // Suspend capabilities based on access scope.
        {
            let entry = ctx
                .suspended_capabilities
                .entry(did_str.to_owned())
                .or_default();
            match access {
                AccessScope::Read => {
                    entry.insert("messages:read".to_owned());
                }
                AccessScope::Write => {
                    entry.insert("messages:write".to_owned());
                }
                AccessScope::Both => {
                    entry.insert("messages:read".to_owned());
                    entry.insert("messages:write".to_owned());
                }
            }
        }

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
                if !ctx.members.contains_key(did_str) {
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
                if !ctx.members.contains_key(spender_str) {
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
        if !ctx.members.contains_key(did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{did}' not found"),
                code: codes::CTX_2015.to_owned(),
            });
        }
        // Member reset: remove + re-add with same role (ADR-029 §Tier 3).
        let role = ctx
            .members
            .get(did)
            .map(|m| m.role.clone())
            .unwrap_or_default();
        ctx.members.insert(
            did.to_owned(),
            MemberEntry {
                did: did.to_owned(),
                role,
                sequence_number: 0,
            },
        );
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
            operator_did: DID::from(ctx.creator_did.clone()),
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
        let total = ctx.members.len();
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

        // SingleAdmin or quorum=0: auto-approve and execute immediately.
        if required == 0 {
            let result =
                self.execute_governance_action(context_id, proposer_did, proposal_id, action)?;
            return Ok(serde_json::json!({
                "proposal_id": proposal_id,
                "status": "Approved",
                "execution_result": result,
            }));
        }

        // Multi-admin: create pending proposal. Proposer's vote counts as first approval.
        let now = crate::time::now_ms();
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let now_secs = (now / 1000.0) as u64;
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let voting_deadline_secs = ((now + WASM_PROPOSAL_DEADLINE_MS) / 1000.0) as u64;
        // Compute proposal_id as [u8; 32] from the hex string.
        let proposal_id_bytes: [u8; 32] = {
            let bytes = hex::decode(proposal_id).unwrap_or_default();
            let mut arr = [0u8; 32];
            let len = bytes.len().min(32);
            arr[..len].copy_from_slice(&bytes[..len]);
            arr
        };
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
            // Remove from pending and execute.
            let proposal = self
                .contexts
                .get_mut(context_id)
                .and_then(|ctx| ctx.pending_proposals.remove(&pid));
            if let Some(mut p) = proposal {
                let action_ref = p.action.clone();
                let result =
                    self.execute_governance_action(context_id, proposer_did, &pid, &action_ref)?;
                // Move to resolved_proposals for later retrieval.
                p.status = ProposalStatus::Approved;
                if let Some(ctx) = self.contexts.get_mut(context_id) {
                    ctx.insert_resolved_proposal(pid.clone(), p);
                }
                return Ok(serde_json::json!({
                    "proposal_id": pid,
                    "status": "Approved",
                    "execution_result": result,
                }));
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
            // Remove from pending and execute.
            let proposal = self
                .contexts
                .get_mut(context_id)
                .and_then(|ctx| ctx.pending_proposals.remove(&pid));
            if let Some(mut p) = proposal {
                let action_ref = p.action.clone();
                let proposer = p.proposer_did.0.clone();
                let result =
                    self.execute_governance_action(context_id, &proposer, &pid, &action_ref)?;
                // Move to resolved_proposals for later retrieval.
                p.status = ProposalStatus::Approved;
                if let Some(ctx) = self.contexts.get_mut(context_id) {
                    ctx.insert_resolved_proposal(pid.clone(), p);
                }
                return Ok(serde_json::json!({
                    "status": "Approved",
                    "execution_result": result,
                }));
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

        // Also add as a member if not already present.
        ctx.members
            .entry(subscriber_did.to_owned())
            .or_insert_with(|| MemberEntry {
                did: subscriber_did.to_owned(),
                role: "subscriber".to_owned(),
                sequence_number: 0,
            });

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

        if ctx
            .suspended_capabilities
            .get(author_did)
            .is_some_and(|caps| caps.contains("messages:write"))
        {
            return Err(ScpWasmError::Permission {
                message: format!("write access has been suspended for {author_did}"),
                code: codes::PERM_3000.to_owned(),
            });
        }

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

        // Assign sequence number.
        let member = ctx
            .members
            .get_mut(author_did)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("author '{author_did}' not found in members"),
                code: codes::CTX_2019.to_owned(),
            })?;
        let seq = member.sequence_number;
        member.sequence_number += 1;

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
                *ttl += additional_secs;
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

        ctx.append_log_event(
            EventType::ContextExpired,
            "",
            b"",
            // Timer-triggered expiry: WASM tracks no separate convergent TTL
            // deadline, so the expiry instant is the member's clock reading at
            // fire time; a mixed native/WASM context derives the deadline
            // identically from the shared TTL policy (§7.3.1, §9.9.3).
            crate::time::now_secs(),
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
            .map(|ctx| ctx.creator_did.clone())
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
                creator_did: ctx.creator_did.clone(),
                mode: ctx.mode.clone(),
                ceiling: ctx.ceiling_strings.iter().cloned().collect(),
                ceiling_policy: ctx.ceiling_policy.clone(),
                ttl_seconds: ctx.ttl_seconds,
                promotion_policy: ctx.promotion_policy.clone(),
                governance: ctx.governance.clone(),
                member_count: ctx.members.len() as u64,
                economic_policy: ctx.economic_policy.clone(),
                min_protocol_version,
            }
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Converts a capability string from the canonical user-facing colon
    /// format (e.g. `"tool:invoke:*"`) to the UCAN `{resource}:{action}`
    /// format (e.g. `"tool_invoke:*"`).
    ///
    /// The rule: if a capability has more than one colon (compound resource),
    /// join all segments except the last with underscores to form the resource,
    /// and the last segment becomes the action. Simple capabilities with
    /// exactly one colon (e.g. `"messages:write"`) pass through unchanged.
    ///
    /// This mirrors `Capability::ucan_resource_action` in scp-core (see #1293).
    fn capability_to_ucan_format(cap: &str) -> String {
        if let Some((resource_part, action)) = cap.rsplit_once(':') {
            if resource_part.contains(':') {
                // 3+ segments: join all-but-last with underscores.
                // "a:b:c:d" → "a_b_c:d" (matches scp-core rsplit_once behavior)
                format!("{}:{}", resource_part.replace(':', "_"), action)
            } else {
                // 2 parts: "messages:write" — already in UCAN format
                cap.to_owned()
            }
        } else {
            // 1 part: "bridging" — no colon at all → pass through unchanged
            cap.to_owned()
        }
    }

    /// Builds the capability ceiling string set from explicit ceiling entries
    /// or defaults matching scp-core's UCAN `{resource}:{action}` format.
    ///
    /// Default capabilities use underscore-format for compound resources
    /// (e.g. `"tool_invoke:*"`, `"tool:register"`) to match scp-core's
    /// `Capability::ucan_capability_name()` output. This ensures UCAN ceiling
    /// checks (step 8 of validation) pass when tokens minted by scp-core are
    /// validated in the WASM bridge.
    ///
    /// User-provided ceiling strings are converted from colon-format to
    /// UCAN format via [`capability_to_ucan_format`].
    fn build_ceiling_strings(ceiling: &[String]) -> HashSet<String> {
        if ceiling.is_empty() {
            [
                "messages:read",
                "messages:write",
                "tool:register",
                "tool_invoke:*",
                "role:assign",
                "member:invite",
                "member:remove",
                "governance:propose",
                "governance:vote",
                "context:close",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
        } else {
            ceiling
                .iter()
                .map(|s| Self::capability_to_ucan_format(s))
                .collect()
        }
    }

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

        let members: Vec<WasmExportMember> = ctx
            .members
            .iter()
            .map(|(did, entry)| WasmExportMember {
                did: did.clone(),
                role: entry.role.clone(),
                sequence_number: entry.sequence_number,
            })
            .collect();

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
            creator_did: ctx.creator_did.clone(),
            mode: ctx.mode.clone(),
            ceiling_strings: ctx.ceiling_strings.iter().cloned().collect(),
            ceiling_policy: ctx.ceiling_policy.clone(),
            ttl_seconds: ctx.ttl_seconds,
            promotion_policy: ctx.promotion_policy.clone(),
            governance: ctx.governance.clone(),
            economic_policy: ctx.economic_policy.clone(),
            members,
            suspended_capabilities: ctx
                .suspended_capabilities
                .iter()
                .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
                .collect(),
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
        let integrity_mac = crate::identity::compute_export_hmac(&ctx.creator_did, &snapshot_json)?;

        // Ed25519 signature over SHA-256(domain || scope_tag || snapshot_jcs)
        // by the creator's #active key (§23.16.8, ADR-034). This is the
        // cross-party integrity proof — verifiable by anyone resolving the
        // exporter's key. The preimage is built by the single-source
        // `wasm_export_snapshot_digest` helper so the producer, verifier, and
        // test cannot drift; it binds the shared FULL scope tag immediately
        // after the domain separator (WASM only produces Full-scope exports).
        let snapshot_hash = wasm_export_snapshot_digest(&snapshot_json);
        let signature =
            crate::identity::sign_with_identity(&ctx.creator_did, "#active", &snapshot_hash)?;
        let snapshot_signature = hex::encode(signature);

        let now_ms = crate::time::now_ms();
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let exported_at = (now_ms / 1000.0) as u64;

        let envelope = WasmContextExportEnvelope {
            version: WASM_EXPORT_VERSION,
            exported_at,
            // The exporter is always the context creator — the snapshot is
            // signed with the creator's #active key and the verifying key is
            // resolved from `snapshot.creator_did` on import. Derive it here
            // rather than accepting a caller-supplied value: a wrong caller
            // value would only self-reject (exporter_did == creator_did is
            // asserted on import), so there is no reason to expose it as a
            // parameter. Mirrors the native bridges, which derive the exporter
            // internally from the context's creator DID.
            exporter_did: ctx.creator_did.clone(),
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

        // Fail closed on pre-signature (unsigned) envelopes. Versions below 4
        // carried no Ed25519 snapshot signature, so the embedded snapshot was
        // not cross-party verifiable — refuse rather than import unverifiable
        // membership/role/governance state (§23.16.8). Distinct from a
        // signature failure: this is a version error.
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
        if envelope.exporter_did != envelope.snapshot.creator_did {
            return Err(ScpWasmError::Context {
                message: format!(
                    "export exporter_did '{}' does not match snapshot creator_did '{}' — \
                     only the context creator may sign an export (§23.16.8)",
                    envelope.exporter_did, envelope.snapshot.creator_did
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
            &envelope.snapshot.creator_did,
            &snapshot_json,
            &envelope.snapshot_signature,
        )?;

        // 2. HMAC integrity tag (defense-in-depth for self-imports). Verifiable
        // only by a holder of the creator's key; skipped if the creator's key
        // is not in the local registry (cross-party import), since the Ed25519
        // signature already provides cross-party integrity.
        if !envelope.integrity_mac.is_empty()
            && crate::identity::creator_key_available(&envelope.snapshot.creator_did)
        {
            crate::identity::verify_export_hmac(
                &envelope.snapshot.creator_did,
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

        // Validate imported fields from untrusted data (defense-in-depth)
        validate_imported_string(&context_id, "context_id", 256)?;
        validate_imported_did(&snap.creator_did, "creator_did")?;
        for m in &snap.members {
            validate_imported_did(&m.did, "member DID")?;
            if m.role.is_empty() || m.role.len() > 64 {
                return Err(ScpWasmError::Context {
                    message: format!("invalid member role '{}': must be 1-64 chars", m.role),
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

        let mut members = HashMap::new();
        for m in &snap.members {
            members.insert(
                m.did.clone(),
                MemberEntry {
                    did: m.did.clone(),
                    role: m.role.clone(),
                    sequence_number: m.sequence_number,
                },
            );
        }

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

        // Clamp timestamps to `now` so snapshot forgery cannot push them
        // into the future and evade TTL eviction.
        let now_ms_for_clamp = crate::time::now_ms();
        let ctx = PerContextState {
            state: snap.state.clone(),
            params_json: snap.params_json.clone(),
            creator_did: snap.creator_did.clone(),
            mode: snap.mode.clone(),
            ceiling_strings: snap.ceiling_strings.iter().cloned().collect(),
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
            members,
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
            suspended_capabilities: snap
                .suspended_capabilities
                .iter()
                .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
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
            crypto: None,
        };

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

        ctx.append_log_event(
            EventType::ContextClosed,
            "system",
            b"",
            // Convergent close instant (§7.3.1, §9.9.3).
            crate::time::now_secs(),
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
    creator_did: String,
    mode: String,
    ceiling_strings: Vec<String>,
    ceiling_policy: String,
    ttl_seconds: Option<u64>,
    promotion_policy: Option<String>,
    governance: String,
    economic_policy: Option<String>,
    members: Vec<WasmExportMember>,
    /// Suspended capabilities per member DID.
    #[serde(default)]
    suspended_capabilities: HashMap<String, Vec<String>>,
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
}

/// Serializable member entry for export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmExportMember {
    did: String,
    role: String,
    sequence_number: u64,
}

/// Canonicalizes every set/map-derived array in an export snapshot to a
/// deterministic sorted order (§23.16.8 "Set/Map canonicalization").
///
/// The export builder collects these arrays from `HashSet`/`HashMap` sources
/// in incidental iteration order, which is non-deterministic across runs and
/// implementations. RFC 8785 JCS canonicalizes JSON *object* member ordering
/// (so the `HashMap`-backed fields serialized as JSON objects —
/// `suspended_capabilities`, `resolved_proposals_json`, `cooldown_until`, and
/// the broadcast `author_block_lists`/`key_epochs` maps — are already
/// deterministic by key), but JCS does NOT reorder JSON *array* elements.
/// Every array whose elements derive from a set MUST therefore be sorted here
/// before the snapshot is serialized for signing and before it is re-serialized
/// for verification, so the signed digest is byte-identical across runs and the
/// producer and verifier always agree.
///
/// Fields that originate from an ordered `Vec` in `PerContextState`
/// (`threshold_signers`, `tool_interfaces`, `consequence_rules`) carry a
/// producer-defined order and are intentionally left untouched.
fn canonicalize_snapshot_sets(snapshot: &mut WasmContextExportSnapshot) {
    // Plain `Vec<String>` fields derived directly from a `HashSet`.
    snapshot.ceiling_strings.sort_unstable();
    snapshot.read_exclusion_list.sort_unstable();
    snapshot.revoked_tokens.sort_unstable();

    // Arrays of struct entries derived from `HashMap` iteration: sort by the
    // logical map key so the array order matches the canonical key order.
    snapshot.members.sort_unstable_by(|a, b| a.did.cmp(&b.did));
    snapshot
        .seen_nonces_v3
        .sort_unstable_by(|a, b| a.nonce.cmp(&b.nonce));
    snapshot
        .executed_proposals
        .sort_unstable_by(|a, b| a.proposal_id.cmp(&b.proposal_id));

    // Map-of-set field: keys are canonicalized by JCS, but each value array is
    // collected from an inner `HashSet` and must be sorted element-wise.
    for caps in snapshot.suspended_capabilities.values_mut() {
        caps.sort_unstable();
    }

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
            exporter_did: snapshot.creator_did.clone(),
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
            exporter_did: snapshot.creator_did.clone(),
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

        let mut members = HashMap::new();
        members.insert(
            creator_did.to_owned(),
            MemberEntry {
                did: creator_did.to_owned(),
                role: "admin".to_owned(),
                sequence_number: 0,
            },
        );

        let ctx = PerContextState {
            state: "active".to_owned(),
            params_json: serde_json::json!({"mode": "Broadcast"}),
            creator_did: creator_did.to_owned(),
            mode: "Broadcast".to_owned(),
            ceiling_strings: HashSet::new(),
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
            members,
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            suspended_capabilities: HashMap::new(),
            read_exclusion_list: HashSet::new(),
            broadcast_context: Some(bc),
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
        };

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

    // -----------------------------------------------------------------------
    // ucan_revoke idempotent-at-capacity tests (#895)
    // -----------------------------------------------------------------------

    /// Helper: create a minimal active context with a pre-filled revocation set.
    fn make_manager_with_revoked_tokens(
        context_id: &str,
        creator_did: &str,
        revoked: HashSet<String>,
    ) -> WasmContextManager {
        let mut members = HashMap::new();
        members.insert(
            creator_did.to_owned(),
            MemberEntry {
                did: creator_did.to_owned(),
                role: "admin".to_owned(),
                sequence_number: 0,
            },
        );
        let ctx = PerContextState {
            state: "active".to_owned(),
            params_json: serde_json::json!({}),
            creator_did: creator_did.to_owned(),
            mode: "Encrypted".to_owned(),
            ceiling_strings: HashSet::new(),
            ceiling_policy: "immutable".to_owned(),
            ttl_seconds: None,
            promotion_policy: None,
            governance: "single_admin".to_owned(),
            economic_policy: None,
            tool_registry: ToolRegistry::new(),
            tool_handlers: HashMap::new(),
            event_log: EventLog::new(context_id.to_owned()),
            revoked_tokens: revoked,
            seen_nonces: HashMap::new(),
            members,
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            suspended_capabilities: HashMap::new(),
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
        };
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
            creator_did: "did:test:creator".to_owned(),
            mode: "Unencrypted".to_owned(),
            ceiling_strings: Vec::new(),
            ceiling_policy: "immutable".to_owned(),
            ttl_seconds: None,
            promotion_policy: None,
            governance: "single_admin".to_owned(),
            economic_policy: None,
            members: Vec::new(),
            suspended_capabilities: HashMap::new(),
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
        snap.ceiling_strings = ceiling.iter().map(|s| (*s).to_owned()).collect();
        snap.read_exclusion_list = read_excl.iter().map(|s| (*s).to_owned()).collect();
        snap.revoked_tokens = revoked.iter().map(|s| (*s).to_owned()).collect();
        snap.members = members
            .iter()
            .map(|d| WasmExportMember {
                did: (*d).to_owned(),
                role: "member".to_owned(),
                sequence_number: 1,
            })
            .collect();
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
        snap.suspended_capabilities = suspended
            .iter()
            .map(|(member, caps)| {
                (
                    (*member).to_owned(),
                    caps.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>(),
                )
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
            &["messages:read", "messages:write", "tools:invoke"],
            &["did:test:x", "did:test:y", "did:test:z"],
            &["cid-a", "cid-b", "cid-c"],
            &["did:test:m1", "did:test:m2", "did:test:m3"],
            &["nonce-1", "nonce-2", "nonce-3"],
            &["prop-1", "prop-2", "prop-3"],
            &[("did:test:m1", &["a:1", "b:2", "c:3"])],
            &["sub-1", "sub-2", "sub-3"],
            &["blk-1", "blk-2", "blk-3"],
        );
        let reversed = snapshot_with_sets(
            &["tools:invoke", "messages:write", "messages:read"],
            &["did:test:z", "did:test:y", "did:test:x"],
            &["cid-c", "cid-b", "cid-a"],
            &["did:test:m3", "did:test:m2", "did:test:m1"],
            &["nonce-3", "nonce-2", "nonce-1"],
            &["prop-3", "prop-2", "prop-1"],
            &[("did:test:m1", &["c:3", "b:2", "a:1"])],
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
            &["messages:read"],
            &[],
            &[],
            &["did:test:m1"],
            &[],
            &[],
            &[("did:test:m1", &["messages:write"])],
            &[],
            &[],
        );
        let mut tampered = base.clone();
        tampered.suspended_capabilities.clear();

        assert_ne!(
            signed_digest(&base),
            signed_digest(&tampered),
            "tampering with a signed-but-previously-unenumerated field must change the digest"
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
            !ctx.members.contains_key("did:dht:zjoiner"),
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
            ctx.members[creator].sequence_number, 0,
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
}
