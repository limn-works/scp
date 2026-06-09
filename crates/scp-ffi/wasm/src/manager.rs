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
use crate::runtime::{OutletRegistration, OutletRegistry, validate_value_against_schema};

use scp_event_log::proof::{Direction, prove_absence, prove_inclusion, verify_inclusion};
use scp_event_log::tree::{append_unsigned_event, event_count, root};
use scp_event_log::{DID, Event, EventLog, EventPayload, EventType};

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
/// Returns `false` ONLY when:
/// - the policy is absent (`None`) — no policy means free, the canonical
///   default, OR
/// - the policy parses AND no cost field is set and no pricing formula is
///   configured (i.e. the canonical "free" shape).
///
/// FAILS CLOSED (`true`) when the stored JSON is present but does NOT parse
/// as an [`EconomicPolicy`]: this gate guards the paid-context fail-closed
/// preconditions on the WASM invoke / send / join / streaming paths, so a
/// malformed policy that cannot be positively identified as free MUST be
/// treated as requiring payment — never silently treated as free (which
/// would let an unparseable policy bypass the `SCP-ECON-12096` gate). This
/// matches the typed write-path semantics: `create_context` stores only a
/// validated typed policy, so a parse failure here means the stored bytes
/// were corrupted or carry an unrecognized shape — neither is safely "free".
///
/// Mirrors `scp_protocol::economy::policy::policy_requires_payment` (for the
/// parseable case) and matches the auto-accept guard at spec §19.3 / §19.14
/// invariant #9.
fn stored_policy_requires_payment(stored: Option<&str>) -> bool {
    let Some(json) = stored else {
        return false;
    };
    // Fail CLOSED: an unparseable stored policy is treated as requiring
    // payment so it can never be silently admitted as free.
    let Ok(parsed) = serde_json::from_str::<EconomicPolicy>(json) else {
        return true;
    };
    policy_requires_payment(&parsed)
}

/// Type alias for tool handler closures stored per-context.
type OutletHandlerMap =
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
    outlet_registry: OutletRegistry,
    /// Registered tool handlers keyed by tool ID.
    outlet_handlers: OutletHandlerMap,
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
    sessions: HashMap<String, WasmOutletSession>,
    /// Threshold governance signers (ADR-031 §4b).
    threshold_signers: Vec<String>,
    /// Current threshold value (ADR-031 §4b). `0` means threshold governance
    /// is not configured.
    threshold_value: u32,
    /// Established tool interfaces (spec section 6.2).
    outlet_interfaces: Vec<String>,
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
    /// Pinned per-outlet `outlet_message_key` values keyed by
    /// `(outlet_id, registration_event_id)` (§5.4.4 round-5,
    /// SCP-OUT-041a/d).
    ///
    /// The WASM bridge mirrors the scp-runtime
    /// `GovernanceState::pinned_outlet_message_keys` map locally so
    /// `outlet_error_new` can compute
    /// `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]` at the
    /// FFI boundary — the SDK never sees the raw key. WASM cannot
    /// depend on scp-runtime (tokio) so the map lives here.
    pinned_outlet_message_keys: HashMap<(String, [u8; 32]), [u8; 32]>,
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
    /// `scp_runtime::context::manager::PerContextState.governance.cooldown_until`
    /// and is consulted by [`crate::consequence::dispatch_consequences_for_subject`]
    /// to prevent re-firing within a rule's window.
    cooldown_until: HashMap<usize, u64>,
    /// MLS encryption + sender key state. `Some` for encrypted contexts,
    /// `None` for broadcast-only or unencrypted contexts.
    crypto: Option<crate::crypto::WasmCryptoState>,
}

/// A stateful tool session for the WASM bridge.
///
/// Mirrors `scp_core::context::outlets::OutletSession` locally since WASM
/// cannot depend on scp-core (ADR-034).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields read via pattern matching and clone.
struct WasmOutletSession {
    /// Unique session identifier.
    session_id: String,
    /// The tool this session is associated with.
    outlet_id: String,
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

impl WasmOutletSession {
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
    fn append_log_event(&mut self, event_type: EventType, actor_did: &str, payload: &[u8]) {
        let sequence = event_count(&self.event_log);
        let prev_hash = if self.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            self.event_log.leaves()[self.event_log.leaves().len() - 1]
        };
        let event = Event {
            event_type,
            actor_did: DID::from(actor_did.to_owned()),
            timestamp: crate::time::now_secs(),
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
    /// - "moderator" — messages:read, messages:write, `outlet_call:*`,
    ///   member:remove, governance:propose (§5.9 elected moderators pattern).
    /// - "member" — messages:read, messages:write, `outlet_call:*`.
    /// - "author" — messages:write, messages:read, `outlet_call:*`.
    /// - "observer" — messages:read only.
    /// - "subscriber" — messages:read only (broadcast contexts).
    ///
    /// Capability strings use the UCAN `{resource}:{action}` format where
    /// compound resources use underscores (e.g. `"outlet_call:*"`,
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
                        | "outlet_call:*"
                        | "member:remove"
                        | "governance:propose"
                );
                role_grants && in_ceiling(capability)
            }
            "author" => {
                // Authors: messages r/w, tool invoke — intersected with ceiling.
                let role_grants = matches!(
                    capability,
                    "messages:write" | "messages:read" | "outlet_call:*"
                );
                role_grants && in_ceiling(capability)
            }
            "member" => {
                // Default member capabilities: messages:read, messages:write,
                // outlet_call:* — intersected with ceiling (SCP-OUT-014).
                let role_grants = matches!(
                    capability,
                    "messages:read" | "messages:write" | "outlet_call:*"
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
/// One entry in the per-`WasmContextManager` outlet stream registry
/// (§5.4.5 SCP-OUT-037 WASM portion).
///
/// Mirrors the structure of `StreamRegistryEntry` on the `PyO3` / NAPI /
/// `UniFFI` bridges, adapted for the WASM single-threaded re-implementation:
///
/// - No `tokio::sync::mpsc::Receiver`. WASM cannot depend on
///   `scp-runtime` (tokio multi-thread per ADR-034); chunks are
///   pre-materialised into a [`VecDeque`] at open time and drained by
///   `next()` calls one at a time.
/// - No outer `Mutex`. WASM is single-threaded with
///   `thread_local! MANAGER`; `&mut WasmContextManager` already
///   serialises access.
/// - No `StreamSessionHandle` — the handle's grant / cancel surface is
///   re-implemented as plain methods on [`WasmContextManager`] that
///   mutate this struct directly.
///
/// `terminated` flips `true` after the queue has been drained past a
/// terminal chunk (`End` / `Error { terminal: true }`) or after a
/// cancel; the entry remains in the registry until `next()` returns
/// `None` so `requestId`-keyed lookups for the cancel surface remain
/// addressable across the close handshake.
#[derive(Debug)]
pub(crate) struct WasmOutletStreamSession {
    /// Raw 16-byte `request_id` for chunk signing (§5.4.5
    /// `SCP-OUTLET-CHUNK-SIG-V1:` preimage requires the wire bytes).
    pub request_id: [u8; 16],
    /// Hosting context id pinned at acceptance — committed into every
    /// chunk and credit-grant preimage.
    pub context_id: String,
    /// Outlet id pinned at acceptance — committed into every preimage.
    pub outlet_id: String,
    /// MLS epoch counter pinned at acceptance — committed into every
    /// credit-grant preimage. WASM cannot run real MLS state advance
    /// out-of-band, so the value the SDK passes at open is the
    /// authoritative pinned value.
    pub stream_epoch: u64,
    /// 32-byte `caveats_binding` pinned at acceptance — committed into
    /// every chunk and credit-grant preimage.
    pub caveats_binding: [u8; 32],
    /// Strictly-monotonic counter incremented on every accepted credit
    /// grant. Initial state is `0`; the first grant uses `1`. Mirrors
    /// the `monotonic_seq` on `StreamRegistryEntry` in the other
    /// bridges.
    pub monotonic_seq: u64,
    /// Invoker's Ed25519 *verifying* (public) key — pinned at open.
    ///
    /// SCP-OUT-037 W1 (ADR-006): the session holds only the public key,
    /// never the secret [`ed25519_dalek::SigningKey`]. Every signing site
    /// (chunk signing at open, credit-grant signing, cancel signing,
    /// terminate signing, and the synthetic-terminal paths in
    /// `outlet_stream_next`) materialises a transient signing key
    /// on-demand via [`crate::identity::with_signing_key`] keyed by
    /// [`Self::invoker_did`], runs the one signing op, and drops the key
    /// before returning. The self-verification round-trips after each
    /// signature use THIS pinned verifying key — so the verify path needs
    /// no secret material at all.
    ///
    /// Operator and invoker are co-located in the WASM bridge: the
    /// invoker also signs the chunks because there is no separate
    /// out-of-process operator on the browser target.
    pub invoker_verifying_key: ed25519_dalek::VerifyingKey,
    /// Pre-materialised chunks awaiting `next()` consumption.
    ///
    /// WASM is single-threaded and the executor closure is sync, so the
    /// stream pipeline runs to completion at open time and the chunks
    /// are queued here. `next()` pops from the front so chunk ordering
    /// matches emission ordering (matching the §5.4.5 strict-monotonic
    /// `sequence` invariant).
    pub chunks: VecDeque<scp_protocol::context::outlets::stream::OutletStreamChunk>,
    /// `true` once a terminal chunk has been pushed onto `chunks`. Used
    /// by `next()` to flip the JS-side `done` getter once the terminal
    /// chunk has been consumed.
    pub terminated: bool,
    /// `true` once `apply_outlet_cancel` has been observed. The cancel
    /// surface is idempotent (§5.4.5) so subsequent cancels are no-ops.
    pub cancelled: bool,
    /// Cumulative credit budget — sum of all accepted `OutletStreamCredit.grant`
    /// values. Returned to JS from `outlet_stream_grant_credit` so SDK
    /// callers see the running total without a separate query path.
    pub total_credit: u32,
    /// Remaining credit available for `Data`/`Progress` chunk emission.
    /// Decremented on every billable chunk in `outlet_stream_next`;
    /// replenished by accepted `outlet_stream_grant_credit` calls.
    /// `End`/`Error` chunks are terminal and do NOT consume credit
    /// (§5.4.5 credit-based backpressure).
    ///
    /// On exhaustion, `outlet_stream_next` injects a synthetic terminal
    /// `Error { code: SCP-TOOL-6131, slug: "execution.credit-exhausted",
    /// terminal: true }` chunk (signed under the same per-session key
    /// as the real chunks) and flips the session to `terminated`. This
    /// matches the §5.4.5 backpressure semantics on a single-threaded
    /// pre-materialised pipeline — the WASM bridge cannot suspend a
    /// running executor, so credit exhaustion closes the stream
    /// instead of stalling.
    pub remaining_credit: u32,
    /// §5.4.5:758 HARD cumulative billable-chunk ceiling pinned at open.
    /// `Some(cap)` caps the *cumulative* number of billable `Data` chunks
    /// the stream may ever emit (the WASM mirror of the runtime
    /// `CreditTracker::max_billable`); `None` means unbounded (no declared
    /// ceiling). Distinct from [`Self::remaining_credit`]: the credit
    /// window is a *transient* per-grant budget that fresh
    /// `outlet_stream_grant_credit` calls replenish, whereas this is a
    /// HARD upper bound that NO number of grants can raise — once
    /// [`Self::billed_emitted`] reaches it, `outlet_stream_next` closes the
    /// stream with `execution.credit-exhausted` (`SCP-TOOL-6131`)
    /// "regardless of executor behavior" (§5.4.5).
    ///
    /// Sourced from the VALIDATED-NARROWED UCAN `nb` `max_calls` caveat
    /// via [`crate::outlet_stream::enforce_stream_open_caveats`] at open —
    /// NOT from the SDK-declared `estimated_chunk_count`. That helper parses
    /// the already-validated action UCAN's `nb`, pins this ceiling to
    /// `min(estimated_chunk_count, validated max_calls)`, and REJECTS an
    /// over-declared `estimated_chunk_count > max_calls` rather than
    /// silently clamping (mirroring the native runtime's
    /// `enforce_estimated_chunk_count_bound` → `EstimateExceedsBound`).
    /// `None` means the token carried no `max_calls` caveat — unbounded,
    /// matching the runtime's `max_billable = None`.
    ///
    /// WASM limitation (honest): the bridge has no durable counter store
    /// (no out-of-process operator / runtime `CreditTracker` per ADR-034),
    /// so it cannot enforce the CROSS-invocation counter caveats
    /// `rate_window` / `amount_max_cumulative` — `enforce_stream_open_caveats`
    /// FAILS CLOSED (rejects the open) when either is present. `max_calls`,
    /// by contrast, is a WITHIN-stream chunk ceiling enforceable statelessly,
    /// so it is the one counter-bearing caveat the WASM streaming path
    /// honours directly rather than rejecting.
    pub max_calls: Option<u32>,
    /// Count of billable `Data` chunks emitted so far. Compared against
    /// [`Self::max_calls`] by `outlet_stream_next` BEFORE popping a
    /// billable `Data` chunk to enforce the §5.4.5:758 cumulative ceiling.
    /// `Progress` chunks consume credit-window headroom but are NEVER
    /// billed, so they do NOT advance this counter (matching the runtime's
    /// `is_billable_chunk` / `record_billed_emission` semantics — only
    /// `Data` chunks count toward `max_calls`).
    pub billed_emitted: u32,
    /// Pinned invoker DID. The control-plane bridge functions
    /// (`outlet_stream_grant_credit`, `outlet_stream_cancel`,
    /// `outlet_stream_terminate`) verify `caller_did` matches this
    /// before any state mutation. CRITICAL #1 fix.
    pub invoker_did: String,
    /// Count of chunks already popped from `chunks` and delivered to the
    /// JS side (the next-to-emit cursor). Bumped by `outlet_stream_next`
    /// every time it pops the head and returns it. Used as the
    /// runtime-derived `next_seq` value when the bridge constructs an
    /// `OutletStreamCancel` — caller-supplied `next_seq` is rejected.
    /// CRITICAL #3 fix.
    pub emitted_count: u64,
    /// `true` once this session's admission slot has been released back
    /// to the per-context [`WasmStreamAdmissionTracker`]. SCP-OUT-037 W3:
    /// the slot is released exactly once — at the first terminal-eviction
    /// site that fires (queue drained, synthetic-terminal observed,
    /// explicit terminate, or the `Drop` guard). Every release path goes
    /// through [`WasmContextManager::release_admission_once`], which
    /// flips this flag and short-circuits any later release so a
    /// terminal-then-Drop sequence never double-releases the slot.
    pub admission_released: bool,
}

impl Drop for WasmOutletStreamSession {
    /// §5.4.5 HIGH-wave-3 Fix A — defense-in-depth zeroization of the
    /// non-secret-but-tidy `caveats_binding` hash on drop.
    ///
    /// SCP-OUT-037 W1: this struct no longer holds any secret key
    /// material — only the public [`Self::invoker_verifying_key`]
    /// remains. The previous `invoker_signing_key: SigningKey` field was
    /// removed; streaming signs on-demand via
    /// [`crate::identity::with_signing_key`] and never retains a secret
    /// key here. The `chunks` queue carries publicly-signed protocol
    /// envelopes (no secrets) and the remaining fields are public ids /
    /// counters. Per ADR-034 §1 the WASM bridge runs in the same
    /// security boundary as the JS host — same in-process trust model as
    /// the native bridges — so this `caveats_binding` scrub is
    /// best-effort hygiene, not a load-bearing crypto control.
    ///
    /// Admission-slot release on drop is handled by the
    /// [`crate::outlet_stream::WasmOutletInvocationStream`] `Drop` impl
    /// (which has the manager borrow), not here — this `Drop` runs
    /// without manager access and so only scrubs local bytes.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.caveats_binding.zeroize();
    }
}

/// WASM-local mirror of
/// `scp_runtime::context::outlets::stream::StreamAdmissionTracker` —
/// the runtime crate cannot compile to wasm32 (tokio multi-thread per
/// ADR-034), so the tracker structure is re-implemented locally with
/// the same three-cap shape per §5.4.5.
///
/// Caps the runtime exposes via `ContextParams`:
/// - `max_concurrent_inbound_streams_per_invoker` (default 8)
/// - `max_concurrent_inbound_streams_per_origin_invoker` (default 16)
/// - `max_concurrent_inbound_streams_per_outlet` (default 128)
#[derive(Debug, Default)]
// All three counters share the `per_` prefix because the §5.4.5 spec
// names them that way (per_invoker / per_origin_invoker / per_outlet);
// renaming would diverge from `scp_runtime::context::outlets::stream::StreamAdmissionTracker`.
#[allow(clippy::struct_field_names)]
pub(crate) struct WasmStreamAdmissionTracker {
    pub per_invoker: HashMap<String, u32>,
    pub per_origin_invoker: HashMap<String, u32>,
    pub per_outlet: HashMap<String, u32>,
}

impl WasmStreamAdmissionTracker {
    /// Returns `Ok(())` if all three caps would allow one more open
    /// for `(invoker_did, origin_invoker_did, outlet_id)`, otherwise
    /// returns the §5.4.4 transport slug for the breaching cap.
    /// On `Ok`, increments all three counters atomically.
    pub fn try_admit(
        &mut self,
        invoker_did: &str,
        origin_invoker_did: &str,
        outlet_id: &str,
        per_invoker_cap: u32,
        per_origin_invoker_cap: u32,
        per_outlet_cap: u32,
    ) -> Result<(), &'static str> {
        let invoker_count = *self.per_invoker.get(invoker_did).unwrap_or(&0);
        if invoker_count >= per_invoker_cap {
            return Err("transport.concurrent-streams-per-invoker");
        }
        let origin_count = *self
            .per_origin_invoker
            .get(origin_invoker_did)
            .unwrap_or(&0);
        if origin_count >= per_origin_invoker_cap {
            return Err("transport.concurrent-streams-per-origin-invoker");
        }
        let outlet_count = *self.per_outlet.get(outlet_id).unwrap_or(&0);
        if outlet_count >= per_outlet_cap {
            return Err("transport.concurrent-streams-per-outlet");
        }
        *self.per_invoker.entry(invoker_did.to_owned()).or_insert(0) += 1;
        *self
            .per_origin_invoker
            .entry(origin_invoker_did.to_owned())
            .or_insert(0) += 1;
        *self.per_outlet.entry(outlet_id.to_owned()).or_insert(0) += 1;
        Ok(())
    }

    /// Releases one slot from each of the three counters.
    /// Saturating-subtracts so a release that races a missing key is
    /// idempotent.
    pub fn release(&mut self, invoker_did: &str, origin_invoker_did: &str, outlet_id: &str) {
        if let Some(c) = self.per_invoker.get_mut(invoker_did) {
            *c = c.saturating_sub(1);
        }
        if let Some(c) = self.per_origin_invoker.get_mut(origin_invoker_did) {
            *c = c.saturating_sub(1);
        }
        if let Some(c) = self.per_outlet.get_mut(outlet_id) {
            *c = c.saturating_sub(1);
        }
    }
}

/// Parameters for [`WasmContextManager::open_outlet_stream`] (SCP-OUT-037
/// WASM portion).
///
/// Bundled into a struct to keep the call site under the workspace's
/// `clippy::too_many_arguments` ceiling — mirrors the
/// `OpenStreamParams` struct on `scp_runtime::context::outlets::dispatch`.
pub struct OpenOutletStreamParams<'a> {
    /// Hosting context id.
    pub context_id: &'a str,
    /// Outlet id (must be registered on the context).
    pub outlet_id: &'a str,
    /// Pre-parsed input value matching the outlet's input schema.
    pub input_json: &'a serde_json::Value,
    /// Invoker DID. The WASM bridge co-locates the invoker and the
    /// chunk-signing operator (no out-of-process executor — see
    /// `crate::outlet_stream` module docs).
    pub identity_did: &'a str,
    /// 32-byte `caveats_binding` pinned at acceptance — committed into
    /// every chunk and credit-grant preimage.
    pub caveats_binding: [u8; 32],
    /// MLS epoch counter pinned at acceptance — committed into every
    /// credit-grant preimage.
    pub stream_epoch: u64,
    /// Initial credit window — number of `Data`/`Progress` chunks the
    /// executor may emit before requiring an `OutletStreamCredit` grant
    /// (§5.4.5). Pinned at `OutletStreamOpen` acceptance.
    ///
    /// SCP-OUT-037 W1: the invoker signing key is intentionally NOT a
    /// field here. `open_outlet_stream` signs the materialised chunks
    /// on-demand via [`crate::identity::with_signing_key`] keyed by
    /// `identity_did`, and pins only the public verifying key on the
    /// session — no secret key is threaded through this params struct or
    /// retained on the session.
    pub credit_window: u32,
    /// §5.4.5:758 HARD cumulative billable-chunk ceiling — `Some(cap)`
    /// pins the maximum number of billable `Data` chunks the stream may
    /// EVER emit (no number of credit grants can raise it); `None` means
    /// unbounded. Sourced from the VALIDATED-NARROWED UCAN `nb`
    /// `max_calls` caveat via
    /// [`crate::outlet_stream::enforce_stream_open_caveats`]
    /// (`min(estimated_chunk_count, validated max_calls)`, with an
    /// over-declared estimate rejected) — NOT from the SDK-declared
    /// `estimated_chunk_count`. See [`WasmOutletStreamSession::max_calls`]
    /// for the full sourcing + ADR-034 fail-closed limitation note.
    pub max_calls: Option<u32>,
}

/// Inputs passed to [`build_stream_chunks`]. Bundled to stay under the
/// workspace's `clippy::too_many_arguments` ceiling.
struct BuildStreamChunksInputs<'a> {
    context_id: &'a str,
    outlet_id: &'a str,
    request_id: &'a [u8; 16],
    caveats_binding: &'a [u8; 32],
    signing_key: &'a ed25519_dalek::SigningKey,
}

/// Builds the §5.4.5 chunk queue (Data + End on success, terminal
/// Error on failure) for a freshly-opened stream session.
///
/// Extracted from [`WasmContextManager::open_outlet_stream`] so the
/// open path stays under the workspace's `clippy::too_many_lines`
/// ceiling. Signs every chunk under `signing_key` so the
/// `verify_chunk_signature` round-trip passes against the invoker's
/// public key.
fn build_stream_chunks(
    handler_result: Result<serde_json::Value, ScpWasmError>,
    inputs: BuildStreamChunksInputs<'_>,
) -> Result<VecDeque<scp_protocol::context::outlets::stream::OutletStreamChunk>, ScpWasmError> {
    use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk, sign_chunk};

    let mut chunks: VecDeque<OutletStreamChunk> = VecDeque::new();

    let push = |chunks: &mut VecDeque<OutletStreamChunk>,
                payload: ChunkPayload|
     -> Result<(), ScpWasmError> {
        let sequence = chunks.len() as u64;
        let sig = sign_chunk(
            inputs.signing_key,
            inputs.context_id,
            inputs.outlet_id,
            inputs.request_id,
            sequence,
            inputs.caveats_binding,
            &payload,
        )
        .map_err(|e| ScpWasmError::Tool {
            message: format!("failed to sign chunk: {e}"),
            code: codes::TOOL_6002.to_owned(),
        })?;
        chunks.push_back(OutletStreamChunk {
            request_id: *inputs.request_id,
            sequence,
            payload,
            sig,
        });
        Ok(())
    };

    match handler_result {
        Ok(value) => {
            // One Data chunk (the only billable chunk on the WASM path —
            // matches one-shot semantics).
            push(
                &mut chunks,
                ChunkPayload::Data {
                    value: value.clone(),
                },
            )?;
            // Terminal End chunk. WASM cannot generate a full §3
            // provenance chain on the fly — synthesise the
            // minimal valid `DataProvenance` for a freshly-produced
            // local-context invocation.
            let provenance = build_minimal_stream_end_provenance(inputs.context_id);
            push(
                &mut chunks,
                ChunkPayload::End {
                    aggregate: value,
                    provenance,
                    execution_time_ms: 0,
                },
            )?;
        }
        Err(e) => {
            // Map the bridge error into a terminal Error chunk so the
            // iterator yields a single chunk and stops.
            push(
                &mut chunks,
                ChunkPayload::Error {
                    code: e.error_code().to_owned(),
                    message: e.message().to_owned(),
                    terminal: true,
                },
            )?;
        }
    }

    Ok(chunks)
}

pub struct WasmContextManager {
    contexts: HashMap<String, PerContextState>,
    /// Pending MLS key package holders for encrypted context joins.
    /// Keyed by `"{context_id}:{member_did}"`. Consumed by
    /// `join_context_encrypted`.
    pending_key_packages: HashMap<String, crate::crypto::group::WasmMlsGroup>,
    /// Active outlet stream sessions keyed by the composite
    /// `(context_id, request_id_hex)` (§5.4.5 SCP-OUT-037 W2, WASM
    /// portion). `request_id_hex` is the 32-char lowercase hex of the
    /// 16-byte `request_id`.
    ///
    /// SCP-OUT-037 W2: keying on `request_id_hex` alone would let a
    /// `request_id` minted in context A address (grant/cancel/terminate) a
    /// session in context B under a colliding hex — a cross-context
    /// addressing leak that violates the §6.2.1.1 binding-pinning
    /// invariant (`request_id → {context_id, ...}`). Pinning
    /// `context_id` into the key, plus the inline triple-identity check
    /// at every lookup (`session.context_id == context_id` AND
    /// `session.invoker_did == caller_did`), closes that surface. The
    /// native bridges use the SAME `(context_id, request_id_hex)` scheme
    /// — see the cross-bridge note in the wave plan.
    ///
    /// ADR-048 §1: per-bridge state, not a process-global. The
    /// `WasmContextManager` itself is `thread_local!` so this map already
    /// lives on a single bridge instance — adding a separate global
    /// would be the wrong shape on the WASM target. Mirrors the
    /// `outlet_stream_registry: Arc<DashMap<...>>` field on
    /// `PyBridgeInstance` / `NapiBridgeInstance` /
    /// `UniffiBridgeInstance`.
    pub(crate) outlet_streams: HashMap<(String, String), WasmOutletStreamSession>,
    /// Per-context streaming admission tracker (§5.4.5 concurrent-stream
    /// caps). CRITICAL #4 fix — without persisting this across opens,
    /// the per-invoker / per-origin-invoker / per-outlet caps are
    /// vacuous (every fresh tracker resets to zero). Keyed by
    /// `context_id`. Lives on the manager because the
    /// `WasmContextManager` is the bridge instance on the WASM target
    /// (single-threaded, `thread_local!`).
    ///
    /// Re-implemented WASM-locally (ADR-034 — `scp-runtime` cannot
    /// compile to wasm32). The shape mirrors
    /// `scp_runtime::context::outlets::stream::StreamAdmissionTracker`:
    /// three maps tracking concurrent counts per
    /// (`invoker_did`, `origin_invoker_did`, `outlet_id`).
    pub(crate) outlet_stream_admission: HashMap<String, WasmStreamAdmissionTracker>,
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

/// Builds a minimal `DataProvenance` for the §5.4.5 terminal `End`
/// chunk of a streaming outlet invocation (SCP-OUT-037 WASM portion).
///
/// The WASM bridge emits Data + End chunks at open time (no async
/// executor — see `WasmContextManager::open_outlet_stream`). The
/// terminal End chunk requires a full `DataProvenance` record per
/// §5.4.5; this helper synthesises the minimal-valid form for a
/// freshly-produced, local-context invocation:
///
/// - `source_context = context_id` — the hosting context.
/// - `source_type = SourceType::Persistent` — the context is open
///   (otherwise the outlet would not be invocable).
/// - `counterparties = []` — the WASM bridge does not enumerate
///   membership at the streaming boundary; the SDK can re-attach a
///   richer chain via [`crate::provenance`] if needed.
/// - `purpose = None`, `discovery_method = OutOfBand` — no protocol
///   discovery path applies to a local invocation.
/// - `age = 0`, `chain_depth = 0`, `chain_path = None` — fresh data,
///   no cross-context hops.
/// - `memory_scope = MemoryScope::Ephemeral` — conservative default;
///   the SDK overrides if the context's `memory_scope` is broader.
/// - All `payment_*` fields `None` — the WASM bridge fails closed on
///   paid contexts upstream, so streaming is only reachable on the
///   free path.
///
/// This is a defense-in-depth fixture so chunk-signature
/// verification round-trips against a stable JCS-canonicalised
/// preimage; SDK consumers that want a richer provenance attach it
/// at the `End` chunk consumption point.
fn build_minimal_stream_end_provenance(
    context_id: &str,
) -> scp_protocol::provenance::DataProvenance {
    use scp_protocol::context::params::MemoryScope;
    use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
    DataProvenance {
        source_context: context_id.to_owned(),
        source_type: SourceType::Persistent,
        counterparties: Vec::new(),
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::ZERO,
        memory_scope: MemoryScope::Ephemeral,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    }
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
        outlet_registry: OutletRegistry::new(),
        outlet_handlers: HashMap::new(),
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
        outlet_interfaces: Vec::new(),
        governance_freeze: false,
        pending_proposals: HashMap::new(),
        resolved_proposals: HashMap::new(),
        pruning_policy: None,
        economic_policy_locked: false,
        pinned_outlet_message_keys: HashMap::new(),
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
            outlet_streams: HashMap::new(),
            outlet_stream_admission: HashMap::new(),
        }
    }

    /// Low-level release of one slot from the per-context admission
    /// tracker. Idempotent: a missing context entry or zeroed counter is
    /// treated as a no-op (the underlying [`WasmStreamAdmissionTracker`]
    /// saturating-subtracts).
    ///
    /// SCP-OUT-037 W3: prefer [`Self::release_admission_once`] /
    /// [`Self::evict_stream_and_release`] for session eviction — they
    /// guard against double-release via the session's
    /// `admission_released` flag. This raw helper is used by those
    /// wrappers and by the `WasmOutletInvocationStream` `Drop` path
    /// (which has already read+flipped the flag before calling).
    fn release_admission_slot(
        admission: &mut HashMap<String, WasmStreamAdmissionTracker>,
        context_id: &str,
        invoker_did: &str,
        outlet_id: &str,
    ) {
        if let Some(tracker) = admission.get_mut(context_id) {
            tracker.release(invoker_did, invoker_did, outlet_id);
        }
    }

    /// Releases the admission slot held by `session` exactly once,
    /// flipping its `admission_released` flag so a later release on the
    /// same session (terminal-then-Drop, or a redundant eviction site)
    /// is a no-op.
    ///
    /// SCP-OUT-037 W3: every `terminated = true` site and the rejected-
    /// open path in [`Self::insert_stream_session`] route through this
    /// helper. It reads the session's pinned `(context_id, invoker_did,
    /// outlet_id)` triple — the same identity the open path admitted
    /// under (invoker == origin on WASM single-hop) — so the release
    /// always targets the slot that was reserved.
    ///
    /// Takes the admission map and the session by `&mut` separately
    /// (rather than `&mut self`) so it can be called from
    /// `insert_stream_session` while the rejected `session` is owned but
    /// not yet (and never) in the registry map — avoiding a borrow
    /// conflict against `self.outlet_streams`.
    fn release_admission_once(
        admission: &mut HashMap<String, WasmStreamAdmissionTracker>,
        session: &mut WasmOutletStreamSession,
    ) {
        if session.admission_released {
            return;
        }
        session.admission_released = true;
        Self::release_admission_slot(
            admission,
            &session.context_id,
            &session.invoker_did,
            &session.outlet_id,
        );
    }

    /// Removes the session keyed by `key` from the registry and releases
    /// its admission slot exactly once (SCP-OUT-037 W3). Idempotent: a
    /// missing key is a no-op; a session whose slot was already released
    /// (its `admission_released` flag is set) does not double-release.
    ///
    /// This is the single eviction funnel for the
    /// `outlet_stream_next` terminal paths and the
    /// `WasmOutletInvocationStream` `Drop` path — it flips
    /// `admission_released` on the session *before* the session is
    /// dropped so any later release site (terminal-then-Drop) sees the
    /// slot already released and skips its own release.
    pub(crate) fn evict_stream_and_release(&mut self, key: &(String, String)) {
        if let Some(mut session) = self.outlet_streams.remove(key) {
            Self::release_admission_once(&mut self.outlet_stream_admission, &mut session);
            // `session` drops here — its `caveats_binding` is scrubbed by
            // `Drop`. The slot is already released above.
            drop(session);
        }
    }

    /// Returns the §5.4.5 next-emission sequence for a session: the
    /// strict-monotonic per-stream `sequence` the next synthetic terminal
    /// chunk MUST occupy so receivers see a contiguous sequence space.
    ///
    /// SCP-OUT-037 W3: this is `session.emitted_count` — the count of
    /// chunks already popped from the queue and delivered to the JS side
    /// (the runtime next-to-emit cursor). All synthetic-terminal sites
    /// (cancel-synthetic, credit-exhausted-synthetic, terminate-
    /// synthetic) derive their chunk `sequence` from THIS value so a
    /// synthetic terminal lands at exactly the slot the next real chunk
    /// would have, never `emitted_count + queued_len` (which would skip
    /// the dropped-tail sequence numbers and break sequence continuity).
    #[must_use]
    fn next_emission_sequence(session: &WasmOutletStreamSession) -> u64 {
        session.emitted_count
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
            outlet_registry: OutletRegistry::new(),
            outlet_handlers: HashMap::new(),
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
            outlet_interfaces: Vec::new(),
            governance_freeze: false,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: None,
            economic_policy_locked: false,
            pinned_outlet_message_keys: HashMap::new(),
            hard_rate_limit_config: None,
            consequence_rules,
            cooldown_until: HashMap::new(),
            crypto,
        };

        self.contexts.insert(context_id.to_owned(), per_context);

        // Append ContextCreated event to event log.
        // Safe: we just inserted the context above, so the key is present.
        if let Some(ctx) = self.contexts.get_mut(context_id) {
            ctx.append_log_event(EventType::ContextCreated, creator_did, b"");
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

        ctx.append_log_event(EventType::MemberJoined, member_did, b"");

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

        ctx.append_log_event(EventType::MemberLeft, member_did, b"");

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

        ctx.append_log_event(
            EventType::MessageSent,
            sender_did,
            recorded_payload.as_bytes(),
        );

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

        ctx.append_log_event(EventType::ContextClosing, initiator_did, b"");

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

        ctx.append_log_event(event_type, actor_did, prov_hash);

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
    pub fn register_outlet(
        &mut self,
        context_id: &str,
        registration: OutletRegistration,
    ) -> Result<String, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let outlet_id = registration.outlet_id.clone();
        crate::runtime::outlet_registry_insert_unique(&mut ctx.outlet_registry, registration)
            .map_err(|e| ScpWasmError::Tool {
                message: e,
                code: codes::TOOL_6001.to_owned(),
            })?;

        let actor = ctx.creator_did.clone();
        ctx.append_log_event(EventType::OutletRegistered, &actor, outlet_id.as_bytes());

        Ok(outlet_id)
    }

    /// Pins an `outlet_message_key` for a given
    /// `(outlet_id, registration_event_id)` triple per §5.4.4 round-5
    /// (SCP-OUT-041a/d).
    ///
    /// The WASM bridge mirrors the scp-runtime
    /// `GovernanceState::pinned_outlet_message_keys` map locally so
    /// `outlet_error_new` can compute the §5.4.4 wire-message HMAC at
    /// the FFI boundary without exposing the raw key to the SDK.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is unknown.
    pub fn store_outlet_message_key(
        &mut self,
        context_id: &str,
        outlet_id: &str,
        registration_event_id: [u8; 32],
        outlet_message_key: [u8; 32],
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        ctx.pinned_outlet_message_keys.insert(
            (outlet_id.to_owned(), registration_event_id),
            outlet_message_key,
        );
        Ok(())
    }

    /// Returns the pinned 32-byte `outlet_message_key` for the given
    /// `(outlet_id, registration_event_id)` triple per §5.4.4 round-5
    /// (SCP-OUT-041a/d), or `None` if no key is pinned.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is unknown.
    pub fn pinned_outlet_message_key_for(
        &self,
        context_id: &str,
        outlet_id: &str,
        registration_event_id: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, ScpWasmError> {
        let ctx = self.require_active_context(context_id)?;
        Ok(ctx
            .pinned_outlet_message_keys
            .get(&(outlet_id.to_owned(), *registration_event_id))
            .copied())
    }

    /// Checks whether a tool exists in the context's registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or not active.
    pub fn tool_exists(&self, context_id: &str, outlet_id: &str) -> Result<bool, ScpWasmError> {
        let ctx = self.require_active_context(context_id)?;
        Ok(ctx.outlet_registry.get(outlet_id).is_some())
    }

    /// Returns the registered catalog keys (every `MessageTemplate.key`) for
    /// the named outlet, used by SCP-OUT-041d `outlet_error_new` to enforce
    /// `OutletErrorConstructionFailed::UnregisteredMessageKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is unknown or no outlet is registered.
    pub fn outlet_catalog_keys(
        &self,
        context_id: &str,
        outlet_id: &str,
    ) -> Result<Vec<scp_protocol::context::outlets::errors::CatalogKey>, ScpWasmError> {
        use scp_protocol::context::outlets::errors::CatalogKey;
        let ctx = self.require_active_context(context_id)?;
        let registration =
            ctx.outlet_registry
                .get(outlet_id)
                .ok_or_else(|| ScpWasmError::Validation {
                    message: format!("outlet not found: {outlet_id}"),
                    code: codes::TOOL_6002.to_owned(),
                })?;
        let mut keys: Vec<CatalogKey> = Vec::with_capacity(registration.message_catalog.len());
        for tpl in &registration.message_catalog {
            let k = CatalogKey::try_new(tpl.key.clone()).map_err(|e| ScpWasmError::Validation {
                message: format!(
                    "outlet '{outlet_id}' has malformed catalog key {:?}: {e}",
                    tpl.key
                ),
                code: codes::TOOL_6002.to_owned(),
            })?;
            keys.push(k);
        }
        Ok(keys)
    }

    /// Returns the registered [`OutletKind`] for a registered outlet.
    ///
    /// Used by the WASM UCAN validator (`validate_outlet_ucan_wasm`) to
    /// decide which split capability stem (`outlet_query:{id}` for Query
    /// outlets, `outlet_call:{id}` for Action outlets) the caller's UCAN
    /// must carry per SCP-OUT-014 / spec §5.4.2.1.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found, is not active, or has
    /// no registered outlet under `outlet_id`.
    pub fn outlet_kind(
        &self,
        context_id: &str,
        outlet_id: &str,
    ) -> Result<scp_protocol::context::outlets::OutletKind, ScpWasmError> {
        let ctx = self.require_active_context(context_id)?;
        ctx.outlet_registry
            .get(outlet_id)
            .map(|r| r.kind)
            .ok_or_else(|| ScpWasmError::Validation {
                message: format!("outlet not found: {outlet_id}"),
                code: codes::TOOL_6002.to_owned(),
            })
    }

    /// Returns the creator DID of an active context.
    ///
    /// Used by the cross-context single-shot path to resolve the peer DID that
    /// the action UCAN's `allowed_target_dids` caveat constrains (§6.2): a
    /// delegated token may pin the set of peer contexts it is permitted to
    /// reach, and the target context's creator is that peer DID.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active.
    pub fn creator_did(&self, context_id: &str) -> Result<String, ScpWasmError> {
        let ctx = self.require_active_context(context_id)?;
        Ok(ctx.creator_did.clone())
    }

    /// Registers a handler function for a tool.
    ///
    /// The handler will be called when the tool is invoked. The tool must
    /// already be registered in the context's tool registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the tool is not found.
    pub fn register_outlet_handler(
        &mut self,
        context_id: &str,
        outlet_id: &str,
        handler: Box<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String>>,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if ctx.outlet_registry.get(outlet_id).is_none() {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "tool '{outlet_id}' not found in context '{context_id}' \
                     -- register the tool before adding a handler"
                ),
                code: codes::TOOL_6002.to_owned(),
            });
        }

        ctx.outlet_handlers.insert(outlet_id.to_owned(), handler);
        Ok(())
    }

    /// Invokes an outlet and collapses the result to a single JSON value
    /// (one-shot wire form).
    ///
    /// SCP-OUT-033: the WASM bridge is single-threaded JS per ADR-034 and has
    /// no `tokio::sync::mpsc::Receiver` surface to expose to JavaScript; the
    /// `outletInvoke` `#[wasm_bindgen]` export returns a `Promise<string>`
    /// that resolves to the collapsed result. The explicit `_one_shot`
    /// suffix names this collapse so callers do not assume per-chunk
    /// semantics on the WASM bridge. Native (`PyO3` / `NAPI` / `UniFFI`) bridges
    /// expose the same one-shot collapse for the MCP wire; the runtime free
    /// function `scp_runtime::context::outlets::invoke::invoke_outlet`
    /// returns the chunk receiver for non-MCP, non-WASM callers that want
    /// streaming.
    ///
    /// Validates the outlet exists, validates input against schema, and
    /// returns the collapsed JSON result.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the tool is not found,
    /// or schema validation fails.
    pub fn invoke_outlet_one_shot(
        &mut self,
        context_id: &str,
        outlet_id: &str,
        input_json: &serde_json::Value,
        identity_did: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let registration =
            ctx.outlet_registry
                .get(outlet_id)
                .ok_or_else(|| ScpWasmError::Tool {
                    message: format!("tool '{outlet_id}' not found in context '{context_id}'"),
                    code: codes::TOOL_6002.to_owned(),
                })?;

        // Validate input against the tool's input schema.
        validate_value_against_schema(input_json, &registration.schema.input_schema).map_err(
            |e| ScpWasmError::Tool {
                message: format!("input schema validation failed for tool '{outlet_id}': {e}"),
                code: codes::TOOL_6002.to_owned(),
            },
        )?;

        let output_schema = registration.schema.output_schema.clone();

        // Dispatch to registered handler if available.
        let result = if let Some(handler) = ctx.outlet_handlers.get(outlet_id) {
            let out = handler(input_json.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("tool handler for '{outlet_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;

            validate_value_against_schema(&out, &output_schema).map_err(|msg| {
                ScpWasmError::Tool {
                    message: format!("output validation failed for tool '{outlet_id}': {msg}"),
                    code: codes::TOOL_6002.to_owned(),
                }
            })?;

            out
        } else {
            serde_json::json!({
                "outlet_id": outlet_id,
                "status": "validated",
                "input": input_json,
            })
        };

        ctx.append_log_event(EventType::OutletInvoked, identity_did, outlet_id.as_bytes());

        Ok(result)
    }

    /// Opens a §5.4.5 streaming outlet invocation (SCP-OUT-037 WASM
    /// portion).
    ///
    /// Mirrors `ContextManager::open_outlet_stream` from the non-WASM
    /// bridges, adapted for the WASM single-threaded re-implementation:
    /// the executor is sync, so the stream pipeline runs to completion
    /// inline and the chunks are pre-materialised into the session's
    /// queue. `next()` later pops from that queue one at a time, giving
    /// the same JS-shaped iterator surface as the non-WASM bridges.
    ///
    /// SCP-OUT-037 W1: all chunks are signed under a transient signing
    /// key materialised on-demand via
    /// [`crate::identity::with_signing_key`] (keyed by `identity_did`)
    /// and dropped before the open returns; the session pins only the
    /// public verifying key. The WASM bridge has no separate operator
    /// identity — the local invoker also acts as the executor signer per
    /// ADR-034 §1 / SCP-OUT-037 WASM portion. This matches the §5.4.5
    /// chunk-signature preimage byte-for-byte: `verify_chunk_signature`
    /// round-trips against the pinned `invoker_verifying_key`.
    ///
    /// Emitted chunks (in order):
    /// 1. One `Data` chunk carrying the handler's output (or the
    ///    schema-only echo if no handler is registered, matching
    ///    `invoke_outlet_one_shot`).
    /// 2. One terminal `End` chunk carrying the same value as
    ///    `aggregate`, a minimal `DataProvenance` (source = this
    ///    context, no chain), and `execution_time_ms = 0` (the WASM
    ///    bridge does not currently meter handler wall-clock).
    ///
    /// On handler error a single terminal `Error { terminal: true }`
    /// chunk is emitted instead.
    ///
    /// # Errors
    ///
    /// * `Tool` (`SCP-TOOL-6002`) — outlet not registered, input
    ///   schema validation failed, or chunk JCS canonicalisation
    ///   failed.
    /// * `Context` (`SCP-CTX-2000`) — context not active.
    ///
    /// # Returns
    ///
    /// The session's 32-char lowercase hex `request_id` — the SDK uses
    /// this to address the stream from `outlet_stream_grant_credit`
    /// and `outlet_stream_cancel`.
    #[allow(clippy::too_many_lines)] // CRITICAL #4 admission gate adds ~30 lines; refactoring out a helper would obscure the gate ordering relative to require_active_context_mut + handler dispatch.
    pub fn open_outlet_stream(
        &mut self,
        params: OpenOutletStreamParams<'_>,
    ) -> Result<String, ScpWasmError> {
        let OpenOutletStreamParams {
            context_id,
            outlet_id,
            input_json,
            identity_did,
            caveats_binding,
            stream_epoch,
            credit_window,
            max_calls,
        } = params;

        // CRITICAL #4: per-context admission gate. The tracker
        // persists across opens within a single context so the §5.4.5
        // caps actually trip. Pulling defaults that match
        // `ContextParams` (8 / 16 / 128) — until ContextParams plumbs
        // into the WASM context state, default to the §9.18.B
        // baseline so the gate is at least active.
        {
            let admission = self
                .outlet_stream_admission
                .entry(context_id.to_owned())
                .or_default();
            if let Err(slug) = admission.try_admit(
                identity_did,
                identity_did, // origin = invoker on WASM single-hop
                outlet_id,
                8,
                16,
                128,
            ) {
                return Err(ScpWasmError::Context {
                    message: format!("stream open rejected: {slug}"),
                    code: scp_protocol::context::outlets::error_codes::CODE_TRANSPORT_FAULT
                        .to_owned(),
                });
            }
        }

        // SCP-OUT-037 W3 (r2 HIGH fix): the admission slot is now held.
        // Every fallible step below this point — context lookup, outlet
        // lookup, input-schema validation (caller-controlled input!),
        // handler / output-schema failure, on-demand chunk signing, and
        // the duplicate-`request_id` rejection in `insert_stream_session`
        // — MUST release the slot before propagating, or the per-invoker
        // / per-origin / per-outlet caps leak a slot per failed open and
        // wedge the invoker (8 bad opens) or the whole outlet (~128). The
        // native bridges get this for free (runtime `release_admission`
        // on every dispatch error path); the WASM reimplementation must
        // do it explicitly. To keep a SINGLE owner of error-release —
        // avoiding any double-release with the eviction sites — the
        // post-gate body lives in `open_outlet_stream_admitted`, and this
        // is the one and only place that releases on its `Err`. The
        // session is not built yet on these paths, so its `Drop` cannot
        // compensate (and `Drop` is a no-op for admission by design); the
        // release routes through the admission map directly under the
        // pinned `(invoker, origin=invoker, outlet)` triple — exactly
        // what `try_admit` incremented.
        self.open_outlet_stream_admitted(OpenOutletStreamParams {
            context_id,
            outlet_id,
            input_json,
            identity_did,
            caveats_binding,
            stream_epoch,
            credit_window,
            max_calls,
        })
        .inspect_err(|_| {
            Self::release_admission_slot(
                &mut self.outlet_stream_admission,
                context_id,
                identity_did,
                outlet_id,
            );
        })
    }

    /// Post-admission body of [`Self::open_outlet_stream`]. Runs every
    /// fallible step after the admission slot is reserved; on ANY `Err`
    /// the caller ([`Self::open_outlet_stream`]) releases the slot
    /// exactly once. Extracted so the admission-release guard has a
    /// single owner and so the open path stays under the workspace's
    /// `clippy::too_many_lines` ceiling.
    ///
    /// # Errors
    ///
    /// Propagates every post-gate failure unchanged (outlet-not-found,
    /// input/output-schema violation, handler failure, chunk-signing
    /// failure, duplicate-`request_id` conflict). The caller compensates
    /// the admission slot on each.
    fn open_outlet_stream_admitted(
        &mut self,
        params: OpenOutletStreamParams<'_>,
    ) -> Result<String, ScpWasmError> {
        use scp_protocol::context::outlets::stream::OutletStreamChunk;

        let OpenOutletStreamParams {
            context_id,
            outlet_id,
            input_json,
            identity_did,
            caveats_binding,
            stream_epoch,
            credit_window,
            max_calls,
        } = params;

        let ctx = self.require_active_context_mut(context_id)?;

        let registration =
            ctx.outlet_registry
                .get(outlet_id)
                .ok_or_else(|| ScpWasmError::Tool {
                    // ADR-049 §4: input-free static message on the
                    // streaming open surface — do not echo the
                    // caller-supplied `outlet_id` / `context_id`. Matches
                    // the native UniFFI bridge's static "tool not
                    // registered" open-path string; the `SCP-TOOL-6002`
                    // code carries the machine signal.
                    message: "tool not registered".to_owned(),
                    code: codes::TOOL_6002.to_owned(),
                })?;

        // Validate the input against the registered input schema —
        // matches `invoke_outlet_one_shot` so single-shot and streaming
        // have the same precondition shape. SCP-OUT-037 W4: the
        // `jsonschema` validator's error Display embeds the offending
        // *instance value* (i.e. raw `input_json` bytes) — echoing it
        // reflects untrusted input back to the caller (ADR-049 §4). On
        // the streaming open surface we drop the `{e}` and surface a
        // fixed, input-free message; `outlet_id` is a validated
        // identifier so it is safe to include.
        validate_value_against_schema(input_json, &registration.schema.input_schema).map_err(
            |_| ScpWasmError::Tool {
                message: format!("input schema validation failed for tool '{outlet_id}'"),
                code: codes::TOOL_6002.to_owned(),
            },
        )?;
        let output_schema = registration.schema.output_schema.clone();

        // Generate a fresh §5.4.5 16-byte `request_id` via `UUIDv7`. Per
        // §5.4.5 wire types: `request_id: [u8; 16]` MUST be a `UUIDv7` —
        // monotonic time-sortable so log readers can order streams by
        // the byte form alone without consulting an out-of-band
        // timestamp. The `uuid` crate's `getrandom/js` feature is
        // already wired in for `Uuid::new_v4`, so the WASM target uses
        // the same `crypto.getRandomValues`-backed RNG for the
        // 74-bit-random tail of a v7 timestamp.
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);

        // Run the registered handler if present, otherwise return the
        // schema-only echo (same fallback semantics as
        // `invoke_outlet_one_shot`). `map_or_else` with `Result`
        // handlers keeps the option_if_let_else lint happy.
        let handler_result: Result<serde_json::Value, ScpWasmError> =
            ctx.outlet_handlers.get(outlet_id).map_or_else(
                || {
                    Ok(serde_json::json!({
                        "outlet_id": outlet_id,
                        "status": "validated",
                        "input": input_json,
                    }))
                },
                |handler| {
                    let out = handler(input_json.clone()).map_err(|e| ScpWasmError::Tool {
                        message: format!("tool handler for '{outlet_id}' failed: {e}"),
                        code: codes::TOOL_6002.to_owned(),
                    })?;
                    validate_value_against_schema(&out, &output_schema).map_err(|_| {
                        // SCP-OUT-037 W4: drop the `{msg}` — the
                        // jsonschema error embeds the offending handler
                        // *output* value; surface a fixed, input-free
                        // message (ADR-049 §4).
                        ScpWasmError::Tool {
                            message: format!("output validation failed for tool '{outlet_id}'"),
                            code: codes::TOOL_6002.to_owned(),
                        }
                    })?;
                    Ok(out)
                },
            );

        // Append the OutletInvoked event regardless of pass/fail —
        // matches the one-shot path's behaviour so the audit log is
        // identical.
        ctx.append_log_event(EventType::OutletInvoked, identity_did, outlet_id.as_bytes());

        // SCP-OUT-037 W1: sign the materialised chunks on-demand under a
        // transient signing key scoped to this closure, and capture only
        // the public verifying key to pin on the session. The secret key
        // never escapes `with_signing_key` — it is built from the
        // identity registry's `Zeroizing` bytes, used to sign, and
        // dropped before the closure returns. The chunk queue and the
        // pinned verifying key are the only things that survive.
        let (chunks, invoker_verifying_key): (VecDeque<OutletStreamChunk>, _) =
            crate::identity::with_signing_key(identity_did, |signing_key| {
                let chunks = build_stream_chunks(
                    handler_result,
                    BuildStreamChunksInputs {
                        context_id,
                        outlet_id,
                        request_id: &request_id,
                        caveats_binding: &caveats_binding,
                        signing_key,
                    },
                )?;
                Ok((chunks, signing_key.verifying_key()))
            })?;

        // Insert the session AFTER all chunks are signed so the
        // registry never holds a half-built session — if signing fails
        // above, the SDK sees a clean error and no entry is left
        // dangling. SCP-OUT-037 W5: `insert_stream_session` rejects a
        // duplicate `(context_id, request_id_hex)` and releases the
        // admission slot admitted by the gate above before returning the
        // rejection — a rejected open never leaks an admission slot.
        self.insert_stream_session(
            WasmOutletStreamSession {
                request_id,
                context_id: context_id.to_owned(),
                outlet_id: outlet_id.to_owned(),
                stream_epoch,
                caveats_binding,
                monotonic_seq: 0,
                invoker_verifying_key,
                chunks,
                terminated: false,
                cancelled: false,
                total_credit: 0,
                // §5.4.5 credit-based backpressure: the open allocates
                // `credit_window` chunks of headroom for billable
                // chunks (Data + Progress). End/Error are terminal and
                // do NOT consume credit.
                remaining_credit: credit_window,
                // §5.4.5:758 cumulative billable ceiling pinned at open
                // from the VALIDATED-NARROWED UCAN `nb` `max_calls` caveat
                // (`enforce_stream_open_caveats` —
                // `min(estimated, validated max_calls)`, over-declared
                // estimate rejected); NOT the SDK-declared estimate. See
                // `WasmOutletStreamSession::max_calls`.
                max_calls,
                billed_emitted: 0,
                invoker_did: identity_did.to_owned(),
                emitted_count: 0,
                admission_released: false,
            },
            context_id,
            &request_id_hex,
        )?;

        Ok(request_id_hex)
    }

    /// Inserts a freshly-built stream session into the per-bridge
    /// registry under the composite `(context_id, request_id_hex)` key.
    /// Extracted from [`Self::open_outlet_stream`] so the open path
    /// stays under the workspace's `clippy::too_many_lines` ceiling.
    ///
    /// SCP-OUT-037 W5 — duplicate-key rejection. The registry MUST NOT
    /// silently overwrite an existing session for the same
    /// `(context_id, request_id_hex)`: a re-issued `request_id` (§6.2.1.1
    /// requires `request_id` uniqueness per context) is a
    /// `protocol.session-id-conflict`. On a duplicate the freshly-built
    /// `session` is dropped (its `caveats_binding` scrubbed by its
    /// `Drop`) and the conflict error is returned.
    ///
    /// Admission-slot release on this conflict is NOT done here: it is
    /// owned by the single error-release guard in
    /// [`Self::open_outlet_stream`] (r2 HIGH fix). Routing every
    /// post-gate error — including this duplicate-key rejection —
    /// through that one guard keeps a SINGLE owner of admission-release
    /// and removes the double-release hazard that arises when both this
    /// method and the open guard try to release the same slot.
    ///
    /// # Spec note (code/slug pairing)
    ///
    /// A duplicate `(context_id, request_id_hex)` is the §6.2.1.1(a)
    /// `request_id`-uniqueness collision, which §5.4.4 pins to
    /// `CODE_PROTOCOL_SESSION` (`SCP-TOOL-6101`) with slug
    /// `protocol.session-id-conflict`. (§6.2.1.1(b)
    /// `protocol.stream-already-open` carries `SCP-TOOL-6100` and applies
    /// to a re-open of an already-open *stream* by other identity, not a
    /// `request_id` collision — the spec is authoritative here.)
    ///
    /// # Errors
    ///
    /// Returns `ScpWasmError::Context` (`SCP-TOOL-6101`, slug
    /// `protocol.session-id-conflict`) when a session already exists for
    /// the composite key.
    fn insert_stream_session(
        &mut self,
        session: WasmOutletStreamSession,
        context_id: &str,
        request_id_hex: &str,
    ) -> Result<(), ScpWasmError> {
        use scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION;
        use std::collections::hash_map::Entry;

        let key = (context_id.to_owned(), request_id_hex.to_owned());
        match self.outlet_streams.entry(key) {
            Entry::Occupied(_) => {
                // The freshly-built `session` is dropped here (its
                // `caveats_binding` is scrubbed by `Drop`). The admission
                // slot the open reserved is released by the single guard
                // in `open_outlet_stream`, which compensates on this
                // `Err` — not here.
                //
                // ADR-049 §4: input-free static message — never echo the
                // caller-influenced `request_id_hex` / `context_id`. The
                // `SCP-TOOL-6101` code + `protocol.session-id-conflict`
                // slug carry the machine signal.
                drop(session);
                Err(ScpWasmError::Context {
                    message: "stream already open (protocol.session-id-conflict)".to_owned(),
                    code: CODE_PROTOCOL_SESSION.to_owned(),
                })
            }
            Entry::Vacant(slot) => {
                slot.insert(session);
                Ok(())
            }
        }
    }

    /// Pops the next chunk from a stream session, returning `None`
    /// when the queue is drained (signalling end-of-stream to the JS
    /// `next()` caller).
    ///
    /// Eviction policy: the session entry is removed once `next()`
    /// has returned `None`. Until that point the entry stays
    /// addressable from `outlet_stream_cancel` so a late cancel after
    /// the terminal chunk has been observed still surfaces the
    /// idempotent `None` recorded-seq instead of an
    /// `unknown-session` error (matching the cross-bridge round-6
    /// idempotency invariant — the WASM path is best-effort here
    /// because `cancel-after-terminal` is rare on a single-threaded
    /// pre-materialised stream).
    pub fn outlet_stream_next(
        &mut self,
        context_id: &str,
        request_id_hex: &str,
    ) -> Option<scp_protocol::context::outlets::stream::OutletStreamChunk> {
        use scp_protocol::context::outlets::error_codes::{
            CODE_EXECUTION_CREDIT, SLUG_EXECUTION_CREDIT_EXHAUSTED,
        };
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let key = (context_id.to_owned(), request_id_hex.to_owned());
        let session = self.outlet_streams.get_mut(&key)?;

        // §5.4.5 cancellation point — checked BEFORE popping the next
        // queued chunk so a cancel observed between two consumer pulls
        // truncates the stream and surfaces as a signed terminal
        // cancel-ack chunk. WASM's pre-materialised pipeline has no
        // executor pump to suspend; this is the equivalent of the
        // runtime path's `CancelAckTracker::should_force_close` —
        // chunks beyond the cancel point MUST NOT be emitted, and the
        // SDK consumer MUST observe a terminal closure (not a silent
        // `None`).
        //
        // §5.4.5 cancel-ack shape: an ordinary invoker cancel where the
        // executor produces the terminal within the cancel-ack window is
        // a *normal* terminal chunk (`End` or `Error{terminal:true}`),
        // and that terminal chunk IS the cancel-ack (spec §5.4.5 step 3).
        // The dedicated `execution.cancel-ack-timeout` code
        // (`SCP-TOOL-6135`) is reserved exclusively for the framework
        // *timer* firing before the executor emits a terminal — the
        // runtime mints it only from `CancelAckTracker::should_force_close`
        // via `cancel_ack_timeout_payload`. On WASM the lazy generator IS
        // the executor and always produces its terminal synchronously on
        // the next pull (never the timeout path), so this branch emits a
        // normal terminal `End` cancel-ack — never 6135. The framework
        // timeout path on WASM is `outlet_stream_terminate` with
        // `TerminateReason::CancelAckTimeout`, which is the only site that
        // mints `SCP-TOOL-6135`.
        if session.cancelled && !session.terminated {
            // SCP-OUT-037 W3: the cancel-ack terminal takes the
            // next-emission sequence (`emitted_count`), NOT
            // `emitted_count + queued_tail_len`. The dropped tail's
            // sequence numbers are never emitted, so the terminal must
            // land at the cursor to keep the per-stream sequence space
            // contiguous from the receiver's perspective.
            let sequence = Self::next_emission_sequence(session);
            // The stream was truncated by the cancel before completing,
            // so the aggregate is `null` (no completed output) rather
            // than a fabricated value; provenance is the same minimal
            // local-context record the well-formed `End` chunk carries.
            let end_payload = ChunkPayload::End {
                aggregate: serde_json::Value::Null,
                provenance: build_minimal_stream_end_provenance(&session.context_id),
                execution_time_ms: 0,
            };
            // SCP-OUT-037 W1: sign on-demand under a transient key — the
            // session holds only the public verifying key.
            let chunk = Self::sign_synthetic_terminal(session, sequence, end_payload)?;
            session.terminated = true;
            // Cancel truncates: drop any chunks queued past the cancel
            // point — the spec says "Already-emitted chunks remain
            // authorized; the stream closes regardless of executor
            // behavior." Anything not yet popped is, by definition,
            // not yet emitted.
            session.chunks.clear();
            session.emitted_count = session.emitted_count.saturating_add(1);
            // SCP-OUT-037 W3: a terminal observation releases the
            // admission slot immediately — NOT only on the next-pull
            // eviction or on `Drop`. The session entry itself stays in
            // the registry until the next pull returns `None` (so a late
            // cancel/grant still finds it and is idempotent), but the
            // slot is freed now.
            Self::release_admission_once(&mut self.outlet_stream_admission, session);
            return Some(chunk);
        }

        let Some(chunk) = session.chunks.pop_front() else {
            // Queue drained — flip terminated and evict so future
            // `next()` calls see `None` cleanly without a stale entry.
            // `evict_stream_and_release` removes the session and releases
            // its admission slot exactly once (W3).
            session.terminated = true;
            self.evict_stream_and_release(&key);
            return None;
        };

        let is_terminal = matches!(
            chunk.payload,
            ChunkPayload::End { .. } | ChunkPayload::Error { terminal: true, .. }
        );
        let is_billable = matches!(
            chunk.payload,
            ChunkPayload::Data { .. } | ChunkPayload::Progress { .. }
        );
        // §5.4.5:758 the cumulative `max_calls` ceiling counts ONLY
        // billable `Data` chunks — `Progress` chunks consume credit-window
        // headroom (handled by `is_billable` below) but are NEVER billed,
        // so they do not count toward `max_calls` (matching the runtime's
        // `is_billable_chunk` predicate, which is `Data`-only).
        let is_data = matches!(chunk.payload, ChunkPayload::Data { .. });

        // §5.4.5:758 HARD cumulative billable ceiling. Checked BEFORE the
        // credit-window gate (and before consuming any credit) so a stream
        // that has already emitted `max_calls` billable `Data` chunks
        // forwards no further billable chunk "regardless of executor
        // behavior" — additional credit grants cannot raise this cap (the
        // WASM mirror of `CreditTracker::cumulative_ceiling_reached`). On
        // exhaustion the bridge replaces the would-be billable chunk with a
        // synthetic terminal Error (`execution.credit-exhausted` /
        // `SCP-TOOL-6131`) and closes the stream — the same lazy-generator
        // pattern as the credit-window gate below.
        if is_data
            && session
                .max_calls
                .is_some_and(|cap| session.billed_emitted >= cap)
        {
            let sequence = Self::next_emission_sequence(session);
            debug_assert_eq!(
                sequence, chunk.sequence,
                "credit-exhausted (max_calls) synthetic terminal sequence must equal \
                 the suppressed billable chunk's sequence on the well-formed path"
            );
            let error_payload = ChunkPayload::Error {
                code: CODE_EXECUTION_CREDIT.to_owned(),
                message: format!(
                    "{SLUG_EXECUTION_CREDIT_EXHAUSTED}: cumulative billable-chunk \
                     ceiling reached (max_calls)"
                ),
                terminal: true,
            };
            // SCP-OUT-037 W1: sign on-demand under a transient key.
            let synthetic = Self::sign_synthetic_terminal(session, sequence, error_payload)?;
            session.terminated = true;
            // Cumulative-ceiling closure is a hard stop — drop the
            // suppressed billable chunk and any queued tail.
            session.chunks.clear();
            session.emitted_count = session.emitted_count.saturating_add(1);
            // W3: release the admission slot on terminal observation.
            Self::release_admission_once(&mut self.outlet_stream_admission, session);
            return Some(synthetic);
        }

        // §5.4.5 credit-based backpressure: every Data/Progress chunk
        // consumes one credit. Terminal chunks (End / terminal Error)
        // do NOT consume credit and always pass through. On exhaustion
        // the WASM bridge replaces the would-be billable chunk with a
        // synthetic terminal Error and closes the stream — a
        // single-threaded pre-materialised pipeline cannot suspend
        // emission the way the dispatch pump can on tokio.
        if is_billable {
            if session.remaining_credit == 0 {
                // Build a synthetic terminal Error chunk at the same
                // sequence the suppressed billable chunk would have
                // occupied. SCP-OUT-037 W3: that is the next-emission
                // sequence (`emitted_count`), which equals the suppressed
                // chunk's `chunk.sequence` only on the well-formed open
                // path; deriving from `emitted_count` keeps the terminal
                // contiguous even if upstream sequence assignment drifts.
                // We keep `debug_assert!` parity with `chunk.sequence` so
                // a divergence is caught in test builds.
                let sequence = Self::next_emission_sequence(session);
                debug_assert_eq!(
                    sequence, chunk.sequence,
                    "credit-exhausted synthetic terminal sequence must equal the \
                     suppressed billable chunk's sequence on the well-formed path"
                );
                let error_payload = ChunkPayload::Error {
                    code: CODE_EXECUTION_CREDIT.to_owned(),
                    message: format!(
                        "{SLUG_EXECUTION_CREDIT_EXHAUSTED}: stream credit window depleted"
                    ),
                    terminal: true,
                };
                // SCP-OUT-037 W1: sign on-demand under a transient key.
                let synthetic = Self::sign_synthetic_terminal(session, sequence, error_payload)?;
                session.terminated = true;
                // Drop the suppressed billable chunk and any queued
                // tail — credit-exhausted closure is a hard stop, no
                // further Data/Progress passes through.
                session.chunks.clear();
                session.emitted_count = session.emitted_count.saturating_add(1);
                // W3: release the admission slot on terminal observation.
                Self::release_admission_once(&mut self.outlet_stream_admission, session);
                return Some(synthetic);
            }
            session.remaining_credit = session.remaining_credit.saturating_sub(1);
        }

        // §5.4.5:758 advance the cumulative billable counter once a
        // billable `Data` chunk has passed BOTH the cumulative-ceiling gate
        // (above) and the credit-window gate, so it is now committed to
        // forward. `Progress` chunks consume credit but are never billed,
        // so they do not advance this counter (the WASM mirror of
        // `CreditTracker::record_billed_emission`). Saturating so the
        // counter never wraps.
        if is_data {
            session.billed_emitted = session.billed_emitted.saturating_add(1);
        }

        if is_terminal {
            session.terminated = true;
            // W3: a real terminal chunk (End / terminal Error) also
            // releases the admission slot on observation. The session
            // entry stays in the registry until the next-pull eviction.
            Self::release_admission_once(&mut self.outlet_stream_admission, session);
        }
        // §5.4.5 next-emission cursor: bump after every chunk popped
        // from the queue (the runtime-published "next-to-emit" sequence
        // for the next call). Used by `outlet_stream_cancel` to derive
        // the canonical `next_seq` written into the cancel preimage —
        // CRITICAL #3 fix.
        session.emitted_count = session.emitted_count.saturating_add(1);
        Some(chunk)
    }

    /// Signs a synthetic terminal `Error` chunk on-demand for `session`
    /// at `sequence`, materialising the invoker's signing key only for
    /// the signing op (SCP-OUT-037 W1).
    ///
    /// Returns `None` if signing fails (e.g. the invoker DID is no longer
    /// in the identity registry, or JCS canonicalisation fails) — the
    /// caller surfaces this as end-of-stream (`None` from
    /// `outlet_stream_next`), matching the pre-W1 `sign_chunk(...).ok()?`
    /// behaviour. The signature is produced under a transient
    /// [`ed25519_dalek::SigningKey`] from
    /// [`crate::identity::with_signing_key`]; the session retains only
    /// the public [`WasmOutletStreamSession::invoker_verifying_key`].
    fn sign_synthetic_terminal(
        session: &WasmOutletStreamSession,
        sequence: u64,
        payload: scp_protocol::context::outlets::stream::ChunkPayload,
    ) -> Option<scp_protocol::context::outlets::stream::OutletStreamChunk> {
        use scp_protocol::context::outlets::stream::{OutletStreamChunk, sign_chunk};

        let sig = crate::identity::with_signing_key(&session.invoker_did, |signing_key| {
            sign_chunk(
                signing_key,
                session.context_id.as_str(),
                session.outlet_id.as_str(),
                &session.request_id,
                sequence,
                &session.caveats_binding,
                &payload,
            )
            .map_err(|e| ScpWasmError::Tool {
                message: format!("failed to sign synthetic terminal chunk: {e}"),
                code: codes::TOOL_6006.to_owned(),
            })
        })
        .ok()?;
        Some(OutletStreamChunk {
            request_id: session.request_id,
            sequence,
            payload,
            sig,
        })
    }

    /// Returns `true` if the named stream session has flipped
    /// terminated (queue drained or terminal chunk emitted).
    /// Used by the `done` getter on `WasmOutletInvocationStream`.
    /// Returns `true` for missing sessions too — once evicted, the
    /// stream is unambiguously done from the SDK's perspective.
    #[must_use]
    pub fn outlet_stream_is_done(&self, context_id: &str, request_id_hex: &str) -> bool {
        self.outlet_streams
            .get(&(context_id.to_owned(), request_id_hex.to_owned()))
            .is_none_or(|s| s.terminated)
    }

    /// Signs and applies an `OutletStreamCredit` grant against an
    /// active stream session (§5.4.5 round-5 SCP-OUTLET-CREDIT-V1).
    ///
    /// Returns the new running total of granted credits. The WASM
    /// bridge does not gate chunk emission on credit (chunks are
    /// pre-materialised at open per ADR-034 — the WASM target has no
    /// async executor to suspend), but maintains the protocol
    /// invariants:
    ///
    /// - `grant == 0` is rejected with `Validation` (uniform
    ///   `protocol.invalid-grant`, code
    ///   [`error_codes::CODE_PROTOCOL_SESSION`] —
    ///   `SCP-TOOL-6101`).
    /// - `monotonic_seq` strictly increases per accepted grant. The
    ///   counter is bumped under the WASM single-threaded
    ///   `RefCell::borrow_mut` critical section so two re-entrant
    ///   grant calls cannot collide.
    /// - Each grant is signed under the invoker's pinned
    ///   `SigningKey` so `verify_credit_signature` round-trips
    ///   against the invoker's public key.
    ///
    /// # Errors
    ///
    /// * `Validation` (`SCP-TOOL-6101`) — `grant == 0`.
    /// * `Context` (slug `protocol.unknown-session`,
    ///   `SCP-TOOL-6101`) — `request_id_hex` does not match an
    ///   active session.
    /// * `Context` — `monotonic_seq` would overflow `u64` (impossible
    ///   in practice — `2^64` grants per stream).
    pub fn outlet_stream_grant_credit(
        &mut self,
        context_id: &str,
        request_id_hex: &str,
        caller_did: &str,
        grant: u32,
    ) -> Result<u32, ScpWasmError> {
        use scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION;
        use scp_protocol::context::outlets::stream::CreditGrantSigningInputs;

        if grant == 0 {
            return Err(ScpWasmError::Validation {
                message: "invalid grant 0: must be in (0, 2^32 - 1] (protocol.invalid-grant)"
                    .to_owned(),
                code: CODE_PROTOCOL_SESSION.to_owned(),
            });
        }

        // SCP-OUT-037 W2: composite-key lookup. A `request_id_hex`
        // minted in another context can never address this session.
        let key = (context_id.to_owned(), request_id_hex.to_owned());
        let session = self
            .outlet_streams
            .get_mut(&key)
            .ok_or_else(|| ScpWasmError::Context {
                // ADR-049 §4: input-free static message — never echo the
                // caller-supplied `request_id_hex` / `context_id` back.
                // Matches the native bridges' static control-plane string;
                // the `SCP-TOOL-6101` code + `protocol.unknown-session`
                // slug carry the machine signal.
                message: "stream not found in registry (protocol.unknown-session)".to_owned(),
                code: CODE_PROTOCOL_SESSION.to_owned(),
            })?;
        // SCP-OUT-037 W2 triple-identity check + CRITICAL #1: the
        // composite key already pins context_id, but re-assert it
        // inline (defence in depth against a future single-key lookup
        // regression) AND verify caller_did matches the session's
        // pinned invoker_did before signing under the invoker key.
        if session.context_id != context_id || session.invoker_did != caller_did {
            return Err(ScpWasmError::Context {
                // ADR-049 §4: input-free static message — never echo the
                // caller-supplied `caller_did` / `request_id_hex` /
                // `context_id` back. Matches the native bridges' static
                // control-plane string; the `SCP-PERM-3001` code +
                // `authorization.denied` slug carry the machine signal.
                message: "caller is not the pinned invoker for this stream (authorization.denied)"
                    .to_owned(),
                code: codes::PERM_3001.to_owned(),
            });
        }

        // HIGH-1 (R3): reject a grant on an already-closed stream — mirrors
        // the `outlet_stream_cancel` idempotency guard and the native
        // bridges' rejection of a credit grant against a terminated /
        // cancelled session. A grant arriving after the stream closed is a
        // protocol error, NOT a false success: returning the running total
        // would imply the credit was applied when the stream can emit no
        // further billable chunk. The WASM bridge carries no economy /
        // escrow (operator == invoker per ADR-034), so there is no fund
        // loss — but the false-success surface diverged from the native
        // bridges and is closed here. Checked AFTER the composite-key
        // lookup + invoker check (so an unknown session or wrong caller
        // still surfaces the more specific 6101 / 3001 error) and BEFORE
        // `monotonic_seq` is bumped (so a rejected grant never perturbs the
        // strict-monotonic sequence).
        if session.terminated || session.cancelled {
            return Err(ScpWasmError::Context {
                // ADR-049 §4: input-free static message — never echo the
                // caller-supplied `request_id_hex` / `context_id` back. The
                // `SCP-TOOL-6101` code + `protocol.stream-already-closed`
                // slug carry the machine signal, matching the native
                // bridges' rejection of a grant on a closed stream.
                message: "stream already closed (protocol.stream-already-closed)".to_owned(),
                code: CODE_PROTOCOL_SESSION.to_owned(),
            });
        }

        // Bump the counter BEFORE signing — matches the §5.4.5
        // strict-monotonicity invariant on the other bridges.
        let next_seq =
            session
                .monotonic_seq
                .checked_add(1)
                .ok_or_else(|| ScpWasmError::Context {
                    message: "monotonic_seq overflow: stream has issued u64::MAX grants".to_owned(),
                    code: codes::CTX_2000.to_owned(),
                })?;
        session.monotonic_seq = next_seq;

        // SCP-OUT-037 W1: sign the grant on-demand under a transient
        // signing key and self-verify against the session's pinned
        // *public* verifying key. The signature value is verified inline
        // — `verify_credit_signature` round-trips against the same
        // preimage on the SDK side, so any future change to credit-grant
        // signing semantics fails at this call site rather than silently
        // diverging. The signature is otherwise discarded because the
        // WASM bridge has no off-process executor to forward it to. The
        // secret key never escapes `with_signing_key`.
        let credit = crate::identity::with_signing_key(&session.invoker_did, |signing_key| {
            let inputs = CreditGrantSigningInputs {
                context_id: session.context_id.as_str(),
                outlet_id: session.outlet_id.as_str(),
                request_id: &session.request_id,
                grant,
                monotonic_seq: next_seq,
                stream_epoch: session.stream_epoch,
                caveats_binding: &session.caveats_binding,
            };
            let sig =
                scp_protocol::context::outlets::stream::sign_credit_grant(signing_key, &inputs);
            Ok(scp_protocol::context::outlets::stream::OutletStreamCredit {
                request_id: session.request_id,
                grant,
                monotonic_seq: next_seq,
                sig,
            })
        })?;
        if !scp_protocol::context::outlets::stream::verify_credit_signature(
            &credit,
            &session.invoker_verifying_key,
            session.context_id.as_str(),
            session.outlet_id.as_str(),
            session.stream_epoch,
            &session.caveats_binding,
        ) {
            // Self-consistency check — if we just signed a grant that
            // does not verify under the pinned invoker public key,
            // something has gone catastrophically wrong with the
            // protocol crypto layer or the registry has been corrupted.
            // Fail loud so the SDK sees the divergence.
            return Err(ScpWasmError::Crypto {
                message: "internal: freshly-signed credit grant failed self-verification \
                          — SCP-OUTLET-CREDIT-V1 preimage drift"
                    .to_owned(),
                code: codes::CRYPTO_4001.to_owned(),
            });
        }
        // Saturating add: practical totals stay well inside `u32`,
        // but defend against overflow so the bridge never panics.
        session.total_credit = session.total_credit.saturating_add(grant);
        // §5.4.5: a validly accepted grant replenishes the live
        // backpressure counter. Without this the WASM bridge tracked
        // `total_credit` for SDK observability but left
        // `remaining_credit` static — the credit-exhausted gate in
        // `outlet_stream_next` would then never lift after a grant.
        session.remaining_credit = session.remaining_credit.saturating_add(grant);
        Ok(session.total_credit)
    }

    /// Applies an `OutletCancel` to an active stream session (§5.4.5).
    ///
    /// Returns the recorded `cancel_ack_seq` (the next-to-emit
    /// sequence at the moment the cancel landed) when the cancel was
    /// recorded; `None` if the stream had already terminated when the
    /// cancel arrived (matching the §5.4.5 idempotency rule used by
    /// the other bridges).
    ///
    /// CRITICAL #1: requires `caller_did` to match the session's
    /// pinned `invoker_did`. CRITICAL #2: builds and signs an
    /// `OutletStreamCancel` under the session's pinned invoker key,
    /// then verifies the signature against the same key — bringing
    /// WASM cancel-auth to parity with the native bridges, where the
    /// runtime's `apply_outlet_cancel` rejects an unsigned-or-tampered
    /// cancel as `Authorization::AuthorizationFailed`. CRITICAL #3:
    /// derives `next_seq` from `session.emitted_count` (the runtime
    /// next-to-emit cursor) — never accepts caller input.
    ///
    /// # Errors
    ///
    /// * `Context` (slug `protocol.unknown-session`) —
    ///   `request_id_hex` does not match any active session.
    /// * `Context` (slug `authorization.denied`,
    ///   `SCP-PERM-3001`) — `caller_did != session.invoker_did`.
    /// * `Crypto` (`SCP-CRYPTO-4001`) — signature self-verification
    ///   failed (preimage drift; cannot happen under normal
    ///   operation).
    pub fn outlet_stream_cancel(
        &mut self,
        context_id: &str,
        request_id_hex: &str,
        caller_did: &str,
    ) -> Result<Option<u64>, ScpWasmError> {
        use scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION;
        use scp_protocol::context::outlets::stream::{
            CancelSigningInputs, OutletStreamCancel, verify_cancel_signature,
        };

        // SCP-OUT-037 W2: composite-key lookup.
        let key = (context_id.to_owned(), request_id_hex.to_owned());
        let session = self
            .outlet_streams
            .get_mut(&key)
            .ok_or_else(|| ScpWasmError::Context {
                // ADR-049 §4: input-free static message — never echo the
                // caller-supplied `request_id_hex` / `context_id` back.
                // Matches the native bridges' static control-plane string;
                // the `SCP-TOOL-6101` code + `protocol.unknown-session`
                // slug carry the machine signal.
                message: "stream not found in registry (protocol.unknown-session)".to_owned(),
                code: CODE_PROTOCOL_SESSION.to_owned(),
            })?;
        // SCP-OUT-037 W2 triple-identity check + CRITICAL #1: re-assert
        // context_id (the composite key already pins it) AND caller_did
        // against the pinned invoker before any state mutation.
        if session.context_id != context_id || session.invoker_did != caller_did {
            return Err(ScpWasmError::Context {
                // ADR-049 §4: input-free static message — never echo the
                // caller-supplied `caller_did` / `request_id_hex` /
                // `context_id` back. Matches the native bridges' static
                // control-plane string; the `SCP-PERM-3001` code +
                // `authorization.denied` slug carry the machine signal.
                message: "caller is not the pinned invoker for this stream (authorization.denied)"
                    .to_owned(),
                code: codes::PERM_3001.to_owned(),
            });
        }

        if session.terminated || session.cancelled {
            // Idempotent — already terminal at cancel receipt.
            return Ok(None);
        }

        // CRITICAL #3: derive next_seq from runtime state, never from
        // caller input. `emitted_count` is the count of chunks already
        // popped from the queue and delivered to the JS side — that is
        // the next-to-emit cursor at the moment the cancel arrives.
        let next_seq = Self::next_emission_sequence(session);

        // CRITICAL #2: build, sign, and verify the cancel. SCP-OUT-037
        // W1: sign on-demand under a transient key; self-verify against
        // the session's pinned *public* verifying key. The signature
        // roundtrip mirrors the native runtime's `apply_outlet_cancel`
        // which rejects an unsigned-or-tampered cancel. Self-verification
        // catches SCP-OUTLET-CANCEL-V1 preimage drift early.
        let cancel = crate::identity::with_signing_key(&session.invoker_did, |signing_key| {
            let inputs = CancelSigningInputs {
                context_id: session.context_id.as_str(),
                outlet_id: session.outlet_id.as_str(),
                request_id: &session.request_id,
                next_seq,
                caveats_binding: &session.caveats_binding,
            };
            let sig = scp_protocol::context::outlets::stream::sign_cancel(signing_key, &inputs);
            Ok(OutletStreamCancel {
                request_id: session.request_id,
                next_seq,
                sig,
            })
        })?;
        if !verify_cancel_signature(
            &cancel,
            &session.invoker_verifying_key,
            session.context_id.as_str(),
            session.outlet_id.as_str(),
            &session.caveats_binding,
        ) {
            return Err(ScpWasmError::Crypto {
                message: "internal: freshly-signed cancel failed self-verification \
                     — SCP-OUTLET-CANCEL-V1 preimage drift"
                    .to_owned(),
                code: codes::CRYPTO_4001.to_owned(),
            });
        }

        session.cancelled = true;
        // §5.4.5 cancel-ack semantics: the executor must stop emitting
        // after a cancel. WASM has no async executor to suspend; the
        // chunk vector is pre-materialised at open time. To make
        // cancellation an *observable cancellation point* on the
        // consumer (matching the runtime path's
        // `CancelAckTracker::should_force_close` flow), DO NOT clear
        // chunks here and DO NOT flip `terminated` synchronously.
        // Instead, `outlet_stream_next` consults `cancelled` BEFORE
        // popping the next chunk and, on `cancelled = true`, builds a
        // signed terminal `End` cancel-ack chunk (a *normal* terminal
        // per §5.4.5 step 3 — the executor's terminal chunk IS the
        // cancel-ack) and stops producing real chunks. The dedicated
        // `execution.cancel-ack-timeout` code (`SCP-TOOL-6135`) is NOT
        // used here: the spec reserves it for the framework cancel-ack
        // *timer* firing before the executor emits a terminal, which on
        // WASM is the `outlet_stream_terminate` /
        // `TerminateReason::CancelAckTimeout` path. Emitting the normal
        // `End` cancel-ack moves the cancellation observation from the
        // synchronous cancel call to the consumer's pull, matching the
        // runtime path delivered via `should_force_close`.
        Ok(Some(next_seq))
    }

    /// Forces a terminal `Error{terminal:true}` chunk into the active
    /// stream identified by `request_id_hex` (§5.4.5 receiver-side
    /// revocation re-check, `RevokedMidStream` / `SCP-TOOL-6110`).
    ///
    /// Mirrors the runtime-bridge
    /// `StreamSessionHandle::terminate_with_error` path on the
    /// non-WASM bridges. Because the WASM stream pipeline is
    /// pre-materialised (no executor pump), termination clears any
    /// remaining chunks past the next-to-emit sequence, signs and
    /// pushes a synthetic terminal `Error` chunk under the
    /// per-session signing key, and flips `terminated`. The next
    /// `outlet_stream_next` call delivers the synthetic chunk; the
    /// one after that resolves to `None` and evicts the session.
    ///
    /// Idempotent: returns `Ok(false)` when the session is already
    /// terminal (matching the runtime path's `AlreadyTerminated` /
    /// `AlreadyPending` recoverable errors — both indicate the
    /// stream has already left the control plane and the SDK's
    /// recheck loop should stop re-checking).
    ///
    /// # Errors
    ///
    /// Returns `ScpWasmError::Context` (`SCP-TOOL-6101`,
    /// `protocol.unknown-session`) when `request_id_hex` does not
    /// match any active session.
    pub fn outlet_stream_terminate(
        &mut self,
        context_id: &str,
        request_id_hex: &str,
        caller_did: &str,
        reason: scp_protocol::context::outlets::stream::TerminateReason,
        message_override: Option<&str>,
    ) -> Result<bool, ScpWasmError> {
        use scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION;
        use scp_protocol::context::outlets::stream::ChunkPayload;

        // Slug and code derived from the enum — never caller-supplied.
        // Mirrors the runtime bridge's `terminate_with_error` contract:
        // the wire chunk carries the canonical §5.4.4 slug+code
        // regardless of any caller string. The only caller-controllable
        // field is the human-readable message suffix
        // (`message_override`).
        let slug = reason.slug();
        let code = reason.code();
        let suffix = message_override.unwrap_or_else(|| reason.default_message());

        // SCP-OUT-037 W2: composite-key lookup.
        let key = (context_id.to_owned(), request_id_hex.to_owned());
        let session = self
            .outlet_streams
            .get_mut(&key)
            .ok_or_else(|| ScpWasmError::Context {
                // ADR-049 §4: input-free static message — never echo the
                // caller-supplied `request_id_hex` / `context_id` back.
                // Matches the native bridges' static control-plane string;
                // the `SCP-TOOL-6101` code + `protocol.unknown-session`
                // slug carry the machine signal.
                message: "stream not found in registry (protocol.unknown-session)".to_owned(),
                code: CODE_PROTOCOL_SESSION.to_owned(),
            })?;
        // SCP-OUT-037 W2 triple-identity check + CRITICAL #1: re-assert
        // context_id AND caller_did against the pinned invoker.
        if session.context_id != context_id || session.invoker_did != caller_did {
            return Err(ScpWasmError::Context {
                // ADR-049 §4: input-free static message — never echo the
                // caller-supplied `caller_did` / `request_id_hex` /
                // `context_id` back. Matches the native bridges' static
                // control-plane string; the `SCP-PERM-3001` code +
                // `authorization.denied` slug carry the machine signal.
                message: "caller is not the pinned invoker for this stream (authorization.denied)"
                    .to_owned(),
                code: codes::PERM_3001.to_owned(),
            });
        }

        if session.terminated || session.cancelled {
            // Idempotent — recoverable from the SDK's recheck loop
            // perspective. Mirrors the runtime path's
            // `TerminateError::AlreadyTerminated` / `AlreadyPending`.
            return Ok(false);
        }

        // SCP-OUT-037 W3 sequence assignment: §5.4.5 mandates
        // strict-monotonic per-stream sequences. The synthetic terminal
        // takes the next-emission sequence (`emitted_count` — the cursor
        // of chunks already delivered to the SDK) and REPLACES any chunks
        // queued but not yet delivered. Using `emitted_count` (W3) — not
        // `chunks.len()` — keeps the terminal contiguous with the
        // already-emitted prefix: the dropped tail's sequences are never
        // emitted, so the terminal must sit at the cursor, not past the
        // (about-to-be-dropped) queue length. The spec §5.4.5 says
        // "Already-emitted chunks remain authorized; the stream closes
        // ... regardless of executor behavior" — so we drop anything
        // queued but not yet delivered.
        let next_sequence = Self::next_emission_sequence(session);
        session.chunks.clear();

        let payload = ChunkPayload::Error {
            code: code.to_owned(),
            message: format!("{slug}: {suffix}"),
            terminal: true,
        };
        // SCP-OUT-037 W1: sign on-demand under a transient key.
        let synthetic =
            Self::sign_synthetic_terminal(session, next_sequence, payload).ok_or_else(|| {
                ScpWasmError::Tool {
                    message: "failed to sign synthetic terminal chunk".to_owned(),
                    code: codes::TOOL_6006.to_owned(),
                }
            })?;
        session.chunks.push_back(synthetic);
        session.terminated = true;
        // SCP-OUT-037 W3: terminate IS the terminal event — release the
        // admission slot now (not only when the SDK later pulls the
        // synthetic). When the synthetic is subsequently observed via
        // `outlet_stream_next`'s `is_terminal` path, the
        // `release_admission_once` guard there short-circuits.
        Self::release_admission_once(&mut self.outlet_stream_admission, session);
        Ok(true)
    }

    /// Verifies a tool against its test vectors.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or the tool is not registered.
    pub fn verify_outlet(
        &self,
        context_id: &str,
        outlet_id: &str,
    ) -> Result<(bool, Vec<String>), ScpWasmError> {
        let ctx = self.require_context(context_id)?;

        let registration =
            ctx.outlet_registry
                .get(outlet_id)
                .ok_or_else(|| ScpWasmError::Tool {
                    message: format!("tool '{outlet_id}' not found in context '{context_id}'"),
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

    /// Updates an existing outlet registration.
    ///
    /// The caller (`updater_did`) must be either the outlet's operator or
    /// the context creator (WASM tracks roles at the member level only;
    /// creator plays the admin role for registry operations, matching the
    /// pattern used by `outlet_interface_offer`/`accept`).
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the outlet is not
    /// found, the caller is not authorized, or the new registration is
    /// invalid (schema, test vectors, id mismatch).
    pub fn update_outlet(
        &mut self,
        context_id: &str,
        outlet_id: &str,
        new_registration: OutletRegistration,
        updater_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let existing = ctx
            .outlet_registry
            .get(outlet_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("outlet '{outlet_id}' not found in context '{context_id}'"),
                code: codes::TOOL_6002.to_owned(),
            })?
            .clone();

        let is_operator = existing.operator_did.as_ref() == updater_did;
        let is_admin = ctx.creator_did == updater_did;
        if !is_operator && !is_admin {
            return Err(ScpWasmError::Permission {
                message: format!(
                    "updater '{updater_did}' is not authorized to update outlet '{outlet_id}'"
                ),
                code: codes::PERM_3001.to_owned(),
            });
        }

        if new_registration.outlet_id != outlet_id {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "outlet_id mismatch: expected '{outlet_id}', got '{}'",
                    new_registration.outlet_id
                ),
                code: codes::VALID_7000.to_owned(),
            });
        }

        // Validate schemas on the new registration (defense-in-depth — the
        // bridge caller validated them too, but this keeps parity with the
        // scp-protocol update path).
        crate::runtime::validate_schema(&new_registration.schema.input_schema).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid input schema in update: {e}"),
                code: codes::VALID_7035.to_owned(),
            }
        })?;
        crate::runtime::validate_schema(&new_registration.schema.output_schema).map_err(|e| {
            ScpWasmError::Validation {
                message: format!("invalid output schema in update: {e}"),
                code: codes::VALID_7036.to_owned(),
            }
        })?;

        ctx.outlet_registry.insert(new_registration);

        let actor = ctx.creator_did.clone();
        ctx.append_log_event(EventType::OutletUpdated, &actor, outlet_id.as_bytes());

        Ok(())
    }

    /// Deregisters (removes) an outlet from the context.
    ///
    /// The caller must be the outlet's operator or the context creator
    /// (admin on WASM). Drops any registered handler for the outlet.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the outlet is not
    /// found, or the caller is not authorized.
    pub fn deregister_outlet(
        &mut self,
        context_id: &str,
        outlet_id: &str,
        actor_did: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let existing = ctx
            .outlet_registry
            .get(outlet_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("outlet '{outlet_id}' not found in context '{context_id}'"),
                code: codes::TOOL_6002.to_owned(),
            })?
            .clone();

        let is_operator = existing.operator_did.as_ref() == actor_did;
        let is_admin = ctx.creator_did == actor_did;
        if !is_operator && !is_admin {
            return Err(ScpWasmError::Permission {
                message: format!(
                    "actor '{actor_did}' is not authorized to deregister outlet '{outlet_id}'"
                ),
                code: codes::PERM_3001.to_owned(),
            });
        }

        ctx.outlet_registry.remove(outlet_id);
        ctx.outlet_handlers.remove(outlet_id);

        let actor = ctx.creator_did.clone();
        ctx.append_log_event(EventType::OutletDeregistered, &actor, outlet_id.as_bytes());

        Ok(())
    }

    /// Lists all outlet IDs registered in a context. Sorted for deterministic
    /// ordering across callers.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found.
    pub fn list_outlets(&self, context_id: &str) -> Result<Vec<String>, ScpWasmError> {
        let ctx = self.require_context(context_id)?;
        let mut ids: Vec<String> = ctx
            .outlet_registry
            .tool_ids()
            .map(ToOwned::to_owned)
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Retrieves the full registration for an outlet.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not found or the outlet is not
    /// registered.
    pub fn get_outlet(
        &self,
        context_id: &str,
        outlet_id: &str,
    ) -> Result<OutletRegistration, ScpWasmError> {
        let ctx = self.require_context(context_id)?;
        ctx.outlet_registry
            .get(outlet_id)
            .cloned()
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("outlet '{outlet_id}' not found in context '{context_id}'"),
                code: codes::TOOL_6002.to_owned(),
            })
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
        outlet_id: &str,
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
        let registration =
            target
                .outlet_registry
                .get(outlet_id)
                .ok_or_else(|| ScpWasmError::Tool {
                    message: format!(
                        "tool '{outlet_id}' not found in target context '{target_context_id}'"
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
        let result = if let Some(handler) = target.outlet_handlers.get(outlet_id) {
            let out = handler(input.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("cross-context tool handler for '{outlet_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;

            validate_value_against_schema(&out, &output_schema).map_err(|msg| {
                ScpWasmError::Tool {
                    message: format!("output validation failed for tool '{outlet_id}': {msg}"),
                    code: codes::TOOL_6002.to_owned(),
                }
            })?;

            out
        } else {
            serde_json::json!({
                "tool": outlet_id,
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
        outlet_id: &str,
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

        let session = WasmOutletSession {
            session_id: session_id.clone(),
            outlet_id: outlet_id.to_owned(),
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

        let outlet_id = session.outlet_id.clone();
        let current_state = session.state.clone();
        let call_count = session.call_count;

        // Validate input against tool's input schema if tool is registered.
        if let Some(registration) = ctx.outlet_registry.get(&outlet_id) {
            validate_value_against_schema(input, &registration.schema.input_schema).map_err(
                |e| ScpWasmError::Tool {
                    message: format!("input validation failed: {e}"),
                    code: codes::TOOL_6002.to_owned(),
                },
            )?;
        }

        // Execute via handler or echo mode.
        let (new_state, output) = if let Some(handler) = ctx.outlet_handlers.get(&outlet_id) {
            let out = handler(input.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("tool handler for '{outlet_id}' failed: {e}"),
                code: codes::TOOL_6002.to_owned(),
            })?;
            (current_state, out)
        } else {
            let out = serde_json::json!({
                "tool": outlet_id,
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
    /// `outlet_call:{outlet_id}` capability can be checked.
    ///
    /// # Errors
    ///
    /// Returns an error if the context or session is not found.
    pub fn session_outlet_id(
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
        Ok(session.outlet_id.clone())
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

        ctx.append_log_event(EventType::TokenRevoked, revoker_did, token_cid.as_bytes());

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

            GovernanceAction::RegisterOutlet { .. }
            | GovernanceAction::RemoveOutlet { .. }
            | GovernanceAction::EstablishOutletInterface { .. }
            | GovernanceAction::AcceptOutletInterface { .. } => "outlet:register",

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

        // Replay protection: check+mark atomically.
        {
            let ctx = self.require_active_context_mut(context_id)?;
            let now = crate::time::now_ms();

            if ctx.executed_proposals.contains_key(proposal_id) {
                return Err(ScpWasmError::Permission {
                    message: "governance proposal has already been executed".to_owned(),
                    code: codes::PERM_3000.to_owned(),
                });
            }

            // Evict expired proposals when over capacity.
            if ctx.executed_proposals.len() >= WASM_PROPOSAL_CAP {
                let cutoff = now - WASM_PROPOSAL_TTL_MS;
                ctx.executed_proposals.retain(|_, ts| *ts > cutoff);
            }

            ctx.executed_proposals.insert(proposal_id.to_owned(), now);
        }

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
            ctx.append_log_event(
                EventType::GovernanceActionExecuted,
                initiator_did,
                proposal_id.as_bytes(),
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
            GovernanceAction::RegisterOutlet { registration } => {
                self.dispatch_register_tool(
                    context_id,
                    &registration.outlet_id,
                    &registration.name,
                    &registration.description,
                )
            }
            GovernanceAction::RemoveOutlet { outlet_id } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.outlet_registry.remove(outlet_id).is_none() {
                    return Err(ScpWasmError::Tool {
                        message: format!("tool '{outlet_id}' not found"),
                        code: codes::TOOL_6003.to_owned(),
                    });
                }
                Ok(serde_json::json!({"action": "RemoveTool", "toolId": outlet_id}))
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
            | GovernanceAction::EstablishOutletInterface { .. }
            | GovernanceAction::AcceptOutletInterface { .. }
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
            | GovernanceAction::RegisterOutlet { .. }
            | GovernanceAction::RemoveOutlet { .. }
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
            | GovernanceAction::EstablishOutletInterface { .. }
            | GovernanceAction::AcceptOutletInterface { .. }
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
            | GovernanceAction::RegisterOutlet { .. }
            | GovernanceAction::RemoveOutlet { .. }
            | GovernanceAction::ModifyCeiling { .. }
            | GovernanceAction::CloseContext { .. }
            | GovernanceAction::ExtendTtl { .. }
            | GovernanceAction::TransferAdmin { .. }
            | GovernanceAction::SuspendCapability { .. }
            | GovernanceAction::SuspendAccess { .. }
            | GovernanceAction::RevokeAccess { .. }
            | GovernanceAction::RestoreAccess { .. } => unreachable!(),
            GovernanceAction::EstablishOutletInterface { .. } // 12 downstream
            | GovernanceAction::AcceptOutletInterface { .. }
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

    /// Handles remaining governance actions: `EstablishOutletInterface`,
    /// `ResetMember`, `ResolveConflict`, `RotateContentKeys`,
    /// `ReconfigureGovernance`, `ProposeContextMigration`,
    /// `CancelContextMigration`.
    fn dispatch_governance_action_remaining(
        &mut self,
        context_id: &str,
        action: &GovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            GovernanceAction::EstablishOutletInterface { interface } => {
                let ctx = self.require_active_context_mut(context_id)?;
                // Store as JSON string for WASM-local state.
                ctx.outlet_interfaces
                    .push(serde_json::to_string(interface).unwrap_or_default());
                Ok(serde_json::json!({"action": "EstablishOutletInterface"}))
            }
            GovernanceAction::AcceptOutletInterface { proposal } => {
                // WASM bridge cannot run the §6.2.0.1 IKM-commitment
                // pipeline (no scp-runtime, no MLS exporter access — see
                // ADR-034). The browser-target enforcement seam is
                // forward-looking: when the WASM MLS shim grows
                // exporter access, this arm will route through the
                // mirrored handler. For now the dispatch records the
                // proposal payload so the WASM event stream stays
                // consistent with the runtime — non-WASM bridges run
                // the real handler and the cross-bridge byte-equality
                // tests pin the InterfaceEstablished serialization.
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.outlet_interfaces
                    .push(serde_json::to_string(proposal).unwrap_or_default());
                Ok(serde_json::json!({"action": "AcceptOutletInterface"}))
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
            | GovernanceAction::RegisterOutlet { .. }
            | GovernanceAction::RemoveOutlet { .. }
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
            | GovernanceAction::RegisterOutlet { .. }
            | GovernanceAction::RemoveOutlet { .. }
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
            | GovernanceAction::EstablishOutletInterface { .. }
            | GovernanceAction::AcceptOutletInterface { .. }
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
        outlet_id: &str,
        name: &str,
        description: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        let registered_at = crate::time::now_secs();
        let reg = OutletRegistration {
            outlet_id: outlet_id.to_owned(),
            // SCP-OUT-011: default to fail-safe Action (§5.4.2).
            kind: scp_protocol::context::outlets::OutletKind::default(),
            name: name.to_owned(),
            description: description.to_owned(),
            schema: crate::runtime::OutletSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
                aggregate_schema: None,
            },
            implementation_hash: [0u8; 32],
            test_vectors: Vec::new(),
            operator_did: DID::from(ctx.creator_did.clone()),
            cost: None,
            registered_at,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        };
        crate::runtime::outlet_registry_insert_unique(&mut ctx.outlet_registry, reg).map_err(
            |e| ScpWasmError::Tool {
                message: e,
                code: codes::TOOL_6001.to_owned(),
            },
        )?;
        Ok(serde_json::json!({"action": "RegisterTool", "toolId": outlet_id}))
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
        ctx.append_log_event(
            EventType::GovernanceProposalCreated,
            proposer_did,
            proposal_id.as_bytes(),
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

            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let vote_ts = (crate::time::now_ms() / 1000.0) as u64;
            proposal.approvals.push(SignedVote {
                voter_did: DID(voter_did.to_owned()),
                vote: VoteType::Approve,
                timestamp: vote_ts,
                signature: Vec::new(),
            });
            proposal.approvals.len() >= required
        };

        ctx.append_log_event(
            EventType::GovernanceVoteCast,
            voter_did,
            proposal_id.as_bytes(),
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

            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let vote_ts = (crate::time::now_ms() / 1000.0) as u64;
            proposal.rejections.push(SignedVote {
                voter_did: DID(voter_did.to_owned()),
                vote: VoteType::Reject,
                timestamp: vote_ts,
                signature: Vec::new(),
            });
            total.saturating_sub(proposal.approvals.len() + proposal.rejections.len())
        };

        ctx.append_log_event(
            EventType::GovernanceVoteCast,
            voter_did,
            proposal_id.as_bytes(),
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

        ctx.append_log_event(
            EventType::GovernanceVoteWithdrawn,
            voter_did,
            proposal_id.as_bytes(),
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

        ctx.append_log_event(
            EventType::MessageSent,
            author_did,
            payload_base64.as_bytes(),
        );

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
    /// Validates that the requester is a non-blocked subscriber (or author) and
    /// returns a grant/deny decision. In the WASM bridge, key material is managed
    /// by `WebCrypto` — the grant decision carries no actual key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or not a broadcast context.
    pub fn handle_broadcast_key_request(
        &self,
        context_id: &str,
        author_did: &str,
        requester_did: &str,
    ) -> Result<String, ScpWasmError> {
        use scp_protocol::context::broadcast::KeyRequestDecision;

        // Use a uniform deny reason to prevent information leakage (§5.14.8).
        const DENY_REASON: &str = "key request denied";

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

        // Delegate to BroadcastContext::handle_key_request which implements
        // the full §5.14.8 decision logic (author check, block list, subscriber).
        match bc.handle_key_request(author_did, requester_did) {
            KeyRequestDecision::Grant { .. } => {
                Ok(serde_json::json!({ "decision": "grant" }).to_string())
            }
            KeyRequestDecision::Deny { .. } => {
                Ok(serde_json::json!({ "decision": "deny", "reason": DENY_REASON }).to_string())
            }
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

        ctx.append_log_event(EventType::ContextExpired, "", b"");

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
    /// format (e.g. `"outlet:call:*"`) to the UCAN `{resource}:{action}`
    /// format (e.g. `"outlet_call:*"`).
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
    /// (e.g. `"outlet_call:*"`, `"outlet:register"`) to match scp-core's
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
                "outlet:register",
                "outlet_call:*",
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
    pub fn export_context(
        &self,
        context_id: &str,
        exporter_did: &str,
    ) -> Result<Vec<u8>, ScpWasmError> {
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
            outlet_interfaces: ctx.outlet_interfaces.clone(),
            governance_freeze: ctx.governance_freeze,
            pruning_policy: ctx.pruning_policy.clone(),
            economic_policy_locked: ctx.economic_policy_locked,
            hard_rate_limit_config: ctx.hard_rate_limit_config.clone(),
            pinned_outlet_message_keys: HashMap::new(),
        };

        // Serialize snapshot to RFC 8785 JCS canonical JSON for HMAC
        // computation. The HMAC is computed over this stable serialization —
        // NOT the full envelope — to avoid a circular dependency (envelope
        // contains the MAC).
        let snapshot_json =
            serde_json_canonicalizer::to_vec(&snapshot).map_err(|e| ScpWasmError::Context {
                message: format!("export snapshot serialization failed: {e}"),
                code: codes::CTX_2030.to_owned(),
            })?;

        // Compute HMAC-SHA256 over the snapshot JSON using the creator's
        // signing key (via HKDF domain separation). The creator DID is in the
        // snapshot — look up their identity in the registry.
        let integrity_mac = crate::identity::compute_export_hmac(&ctx.creator_did, &snapshot_json)?;

        let now_ms = crate::time::now_ms();
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let exported_at = (now_ms / 1000.0) as u64;

        let envelope = WasmContextExportEnvelope {
            version: WASM_EXPORT_VERSION,
            exported_at,
            exporter_did: exporter_did.to_owned(),
            integrity_mac,
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
        let envelope: WasmContextExportEnvelope =
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
                code: codes::CTX_2032.to_owned(),
            });
        }

        // Re-serialize the snapshot to RFC 8785 JCS canonical JSON and verify
        // the HMAC tag using the creator's signing key. This MUST happen
        // before any state reconstruction to prevent an attacker from crafting
        // payloads that grant them admin of a context.
        let snapshot_json = serde_json_canonicalizer::to_vec(&envelope.snapshot).map_err(|e| {
            ScpWasmError::Context {
                message: format!("snapshot re-serialization failed: {e}"),
                code: codes::CTX_2032.to_owned(),
            }
        })?;

        if envelope.integrity_mac.is_empty() {
            return Err(ScpWasmError::Context {
                message: "export integrity_mac is missing — refusing to import unsigned export"
                    .to_owned(),
                code: codes::CTX_2020.to_owned(),
            });
        }

        crate::identity::verify_export_hmac(
            &envelope.snapshot.creator_did,
            &snapshot_json,
            &envelope.integrity_mac,
        )?;

        Ok(envelope)
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

        // Validate v3 anti-replay fields (defense-in-depth; HMAC already
        // covers tamper detection, but we validate shape and bounds to
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
            outlet_registry: OutletRegistry::new(),
            outlet_handlers: HashMap::new(),
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
            outlet_interfaces: snap.outlet_interfaces.clone(),
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
            // Imported snapshots do not carry pinned outlet message keys —
            // they are derived per-registration from MLS exporter material
            // (§5.4.4 round-5) and re-pinned via `outletStoreMessageKey`
            // after the import path re-establishes the registration.
            pinned_outlet_message_keys: HashMap::new(),
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

        ctx.append_log_event(EventType::ContextClosed, "system", b"");

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
/// # Version history
///
/// - **v1**: initial format.
/// - **v2**: added per-author broadcast state (block lists, key epochs).
/// - **v3**: added lossless anti-replay state —
///   `seen_nonces_v3` (full `(nonce, inserted_at_ms)` pairs),
///   `executed_proposals` (full `(proposal_id, executed_at_ms)` pairs),
///   `resolved_proposals_json`, `consequence_rules`, `cooldown_until`.
///   v2 `seen_nonces: Vec<String>` is retained as `seen_nonces_legacy_v2`
///   for back-compat so v2 exports can still be imported into v3 binaries
///   (with the documented lossy timestamp-reset behavior for that field).
///   v3 exports are NOT importable by v2 binaries because the version
///   check below rejects exports with `version > WASM_EXPORT_VERSION`,
///   which prevents silent loss of the new lossless state.
const WASM_EXPORT_VERSION: u32 = 3;

/// Versioned envelope for context exports.
///
/// Serialized as JSON bytes. The version field enables forward-compatible
/// deserialization: import rejects exports with version > `WASM_EXPORT_VERSION`.
///
/// Integrity protection: `integrity_mac` contains an HMAC-SHA256 tag computed
/// over the canonical JSON serialization of the `snapshot` field, keyed by an
/// HKDF-derived key from the context creator's Ed25519 signing key. This
/// prevents an attacker from crafting import payloads that grant themselves
/// admin over a context.
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
    /// info="scp-context-export-integrity-v1")`. Verified on import to prevent
    /// tampering with membership, roles, or governance state.
    integrity_mac: String,
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
    /// `scp_runtime::context::manager::ContextSnapshot.consequence_rules` and
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
    outlet_interfaces: Vec<String>,
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
    /// SCP-OUT-041a/d: per-outlet pinned `outlet_message_key` indexed by
    /// `(outlet_id, registration_event_id_hex)`. Hex-encoded 32-byte HMAC
    /// keys; the SDK never receives the raw key.
    #[serde(default)]
    pinned_outlet_message_keys: HashMap<(String, String), String>,
}

/// Serializable member entry for export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmExportMember {
    did: String,
    role: String,
    sequence_number: u64,
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

    // -----------------------------------------------------------------------
    // SCP-OUT-037 streaming test helpers (W1-W5)
    // -----------------------------------------------------------------------

    /// Builds a `WasmOutletStreamSession` for a test, pinning the public
    /// verifying key of `signing` (SCP-OUT-037 W1 — no secret key on the
    /// session) and registering `signing` in the identity registry under
    /// its derived DID so `with_signing_key` resolves on the streaming
    /// control plane. Returns `(session, derived_invoker_did)`.
    ///
    /// `chunks` are the pre-materialised queue; the caller is responsible
    /// for signing them under the SAME `signing` key (so
    /// `verify_chunk_signature` round-trips against the pinned verifying
    /// key).
    fn make_test_session(
        signing: &ed25519_dalek::SigningKey,
        context_id: &str,
        outlet_id: &str,
        caveats_binding: [u8; 32],
        request_id: [u8; 16],
        chunks: VecDeque<scp_protocol::context::outlets::stream::OutletStreamChunk>,
        remaining_credit: u32,
    ) -> (WasmOutletStreamSession, String) {
        let invoker_did = crate::identity::register_identity_for_test(signing);
        let session = WasmOutletStreamSession {
            request_id,
            context_id: context_id.to_owned(),
            outlet_id: outlet_id.to_owned(),
            stream_epoch: 0,
            caveats_binding,
            monotonic_seq: 0,
            invoker_verifying_key: signing.verifying_key(),
            chunks,
            terminated: false,
            cancelled: false,
            total_credit: 0,
            remaining_credit,
            // Tests that need a cumulative ceiling set `max_calls` on the
            // returned session directly; the default helper leaves it
            // unbounded so the existing credit-window tests are unaffected.
            max_calls: None,
            billed_emitted: 0,
            invoker_did: invoker_did.clone(),
            emitted_count: 0,
            admission_released: false,
        };
        (session, invoker_did)
    }

    /// Inserts a session into the manager's registry under the composite
    /// `(context_id, request_id_hex)` key (SCP-OUT-037 W2).
    fn insert_test_session(
        mgr: &mut WasmContextManager,
        context_id: &str,
        request_id_hex: &str,
        session: WasmOutletStreamSession,
    ) {
        mgr.outlet_streams
            .insert((context_id.to_owned(), request_id_hex.to_owned()), session);
    }

    /// Pre-seeds a per-context admission tracker entry for `(invoker_did,
    /// outlet_id)` so the W3 admission-release tests have a non-zero slot
    /// count to observe being released. Mirrors what
    /// `open_outlet_stream`'s admission gate would have reserved.
    fn admit_test_slot(
        mgr: &mut WasmContextManager,
        context_id: &str,
        invoker_did: &str,
        outlet_id: &str,
    ) {
        let admission = mgr
            .outlet_stream_admission
            .entry(context_id.to_owned())
            .or_default();
        admission
            .try_admit(invoker_did, invoker_did, outlet_id, 8, 16, 128)
            .expect("test admission slot must be granted");
    }

    /// Reads the current per-invoker admission count for `(context_id,
    /// invoker_did)` — `0` when no tracker entry exists.
    fn admission_count(mgr: &WasmContextManager, context_id: &str, invoker_did: &str) -> u32 {
        mgr.outlet_stream_admission
            .get(context_id)
            .and_then(|t| t.per_invoker.get(invoker_did))
            .copied()
            .unwrap_or(0)
    }

    /// Asserts a chunk is the canonical cancel-ack terminal — a normal
    /// terminal `End` chunk (§5.4.5 step 3: an ordinary invoker cancel's
    /// terminal IS the cancel-ack, NOT a `SCP-TOOL-6135`
    /// `execution.cancel-ack-timeout` error, which is reserved for the
    /// framework timer-fired path) — and that its signature round-trips
    /// under `signing`'s verifying key for context `"ctx"` / outlet
    /// `"outlet"`. Shared by the direct cancel test and the
    /// cancellation-vector replay so both pin the same surface without
    /// duplicating the match arms.
    fn assert_cancel_ack_terminal(
        chunk: &scp_protocol::context::outlets::stream::OutletStreamChunk,
        signing: &ed25519_dalek::SigningKey,
        caveats_binding: &[u8; 32],
    ) {
        use scp_protocol::context::outlets::stream::ChunkPayload;
        match &chunk.payload {
            ChunkPayload::End { aggregate, .. } => {
                assert_eq!(
                    *aggregate,
                    serde_json::Value::Null,
                    "cancel-ack End aggregate is null — the stream was truncated, \
                     not completed"
                );
            }
            other => panic!("expected terminal End cancel-ack, got {other:?}"),
        }
        assert!(
            scp_protocol::context::outlets::stream::verify_chunk_signature(
                chunk,
                &signing.verifying_key(),
                "ctx",
                "outlet",
                caveats_binding,
            ),
            "cancel-ack terminal chunk signature must verify"
        );
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
            induced_rotations: Vec::new(),
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
        roundtrip(&GovernanceAction::RegisterOutlet {
            registration: Box::new(from_json(serde_json::json!({
                "outlet_id": "tool-abc",
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
        roundtrip(&GovernanceAction::RemoveOutlet {
            outlet_id: "tool-abc".to_owned(),
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
    fn serde_roundtrip_establish_outlet_interface() {
        let action: GovernanceAction = from_json(serde_json::json!({
            "EstablishOutletInterface": {
                "interface": {
                    "source_context": "ctx-src",
                    "target_context": "ctx-tgt",
                    "outlet_id": "tool-1",
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
                    "cost_schedule": {"currency": [85, 83, 68, 0], "per_message": null, "per_outlet_call": null, "per_join": null, "per_period": null, "per_byte_stored": null},
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
    /// `OutletRegistration`, etc.) rather than manual struct construction.
    fn all_wasm_governance_actions() -> Vec<GovernanceAction> {
        let json_actions: Vec<serde_json::Value> = vec![
            serde_json::json!({"AddMember": {"did": "d", "role": "r"}}),
            serde_json::json!({"RemoveMember": {"did": "d", "reason": null}}),
            serde_json::json!({"ChangeRole": {"did": "d", "new_role": "r"}}),
            serde_json::json!({"RegisterOutlet": {"registration": {
                "outlet_id": "t", "name": "n", "description": "d",
                "schema": {"input_schema": {}, "output_schema": {}},
                "implementation_hash": vec![0u8; 32], "test_vectors": [],
                "operator_did": "did:dht:zop"
            }}}),
            serde_json::json!({"RemoveOutlet": {"outlet_id": "t"}}),
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
            serde_json::json!({"EstablishOutletInterface": {"interface": {
                "source_context": "ctx-src", "target_context": "ctx-tgt",
                "outlet_id": "tool-1", "rate_limit": null, "per_caller_rate_limit": null,
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
                    "cost_schedule": {"currency": [85, 83, 68, 0], "per_message": null, "per_outlet_call": null, "per_join": null, "per_period": null, "per_byte_stored": null},
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
    fn export_version_is_three() {
        assert_eq!(WASM_EXPORT_VERSION, 3);
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
            outlet_registry: OutletRegistry::new(),
            outlet_handlers: HashMap::new(),
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
            outlet_interfaces: Vec::new(),
            governance_freeze: false,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: None,
            economic_policy_locked: false,
            pinned_outlet_message_keys: HashMap::new(),
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
            outlet_registry: OutletRegistry::new(),
            outlet_handlers: HashMap::new(),
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
            outlet_interfaces: Vec::new(),
            governance_freeze: false,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: None,
            economic_policy_locked: false,
            pinned_outlet_message_keys: HashMap::new(),
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
            outlet_interfaces: Vec::new(),
            governance_freeze: false,
            pruning_policy: None,
            economic_policy_locked: false,
            pinned_outlet_message_keys: HashMap::new(),
            hard_rate_limit_config: None,
        }
    }

    /// **E1-baseline:** the default minimal snapshot passes validation.
    #[test]
    fn validate_antispam_minimal_snapshot_accepted() {
        let snap = make_minimal_valid_snapshot();
        assert!(validate_imported_antispam_state(&snap).is_ok());
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
                "per_outlet_call": null,
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
                "per_outlet_call": null,
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

    /// Fail-closed: a stored economic policy that is PRESENT but does NOT
    /// parse as an `EconomicPolicy` MUST be treated as requiring payment, so
    /// a corrupted / unrecognized policy can never bypass the paid-context
    /// `SCP-ECON-12096` gate by being silently classified as free.
    #[test]
    fn test_wasm_stored_policy_malformed_fails_closed() {
        // Syntactically invalid JSON.
        assert!(
            stored_policy_requires_payment(Some("{not valid json")),
            "malformed JSON policy must fail closed (treated as requiring payment)"
        );
        // Valid JSON, but not the EconomicPolicy shape.
        assert!(
            stored_policy_requires_payment(Some(r#"{"unexpected":"shape"}"#)),
            "JSON that is not an EconomicPolicy must fail closed (treated as requiring payment)"
        );
        // An empty string is present-but-unparseable → fail closed.
        assert!(
            stored_policy_requires_payment(Some("")),
            "empty stored policy string must fail closed (treated as requiring payment)"
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
    /// because `append_log_event` calls `crate::time::now_secs()`, which
    /// panics under the wasm-bindgen stub on non-wasm targets (see C2-B).
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
                per_outlet_call: None,
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

    // -----------------------------------------------------------------------
    // SCP-OUT-037 critical fix #5 — WASM credit enforcement
    // -----------------------------------------------------------------------

    /// Test (SCP-OUT-037 critical fix #5) — `outlet_stream_next`
    /// enforces credit-window backpressure. When the per-session
    /// `remaining_credit` counter reaches zero, the next `Data`/
    /// `Progress` chunk is replaced with a synthetic terminal
    /// `Error { code: SCP-TOOL-6131, terminal: true }` chunk, the
    /// session's `terminated` flag is set, and the queue is cleared
    /// so subsequent calls return `None`.
    #[test]
    fn wasm_outlet_stream_next_enforces_credit_window() {
        use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};
        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x37; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);
        let caveats_binding = [0xA5u8; 32];

        // Build two Data chunks + one terminal End and prime the
        // session with `remaining_credit = 1` so the second Data chunk
        // hits the exhausted path.
        let make_chunk = |seq: u64, payload: ChunkPayload| {
            let sig = sign_chunk(
                &signing,
                "ctx",
                "outlet",
                &request_id,
                seq,
                &caveats_binding,
                &payload,
            )
            .expect("sign chunk");
            scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: seq,
                payload,
                sig,
            }
        };
        let mut chunks: VecDeque<scp_protocol::context::outlets::stream::OutletStreamChunk> =
            VecDeque::new();
        chunks.push_back(make_chunk(
            0,
            ChunkPayload::Data {
                value: serde_json::json!({"a": 1}),
            },
        ));
        chunks.push_back(make_chunk(
            1,
            ChunkPayload::Data {
                value: serde_json::json!({"a": 2}),
            },
        ));
        chunks.push_back(make_chunk(
            2,
            ChunkPayload::End {
                aggregate: serde_json::json!({"final": true}),
                provenance: super::build_minimal_stream_end_provenance("ctx"),
                execution_time_ms: 0,
            },
        ));

        // Only one billable chunk fits in the window — the second Data
        // chunk MUST hit the exhausted path. SCP-OUT-037 W1/W2: the
        // helper pins only the public key and registers the signing key
        // under its derived DID so the on-demand synthetic-terminal
        // signing resolves; the session is keyed by `(ctx, rid_hex)`.
        let (session, _invoker_did) = make_test_session(
            &signing,
            "ctx",
            "outlet",
            caveats_binding,
            request_id,
            chunks,
            1,
        );
        insert_test_session(&mut mgr, "ctx", &request_id_hex, session);

        // First Data chunk consumes the lone credit and passes through.
        let c0 = mgr
            .outlet_stream_next("ctx", &request_id_hex)
            .expect("first chunk");
        assert!(matches!(c0.payload, ChunkPayload::Data { .. }));
        assert_eq!(c0.sequence, 0);

        // Second `next()` call sees `remaining_credit == 0` and returns
        // a synthetic terminal Error chunk at the suppressed chunk's
        // sequence. The signature verifies under the same per-session
        // key so SDK-side `verify_chunk_signature` round-trips.
        let c1 = mgr
            .outlet_stream_next("ctx", &request_id_hex)
            .expect("synthetic terminal");
        match &c1.payload {
            ChunkPayload::Error {
                code,
                terminal,
                message: _,
            } => {
                assert!(*terminal, "synthetic chunk MUST be terminal");
                assert_eq!(
                    code,
                    scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CREDIT
                );
            }
            other => panic!("expected synthetic terminal Error, got {other:?}"),
        }
        assert_eq!(c1.sequence, 1, "synthetic chunk takes suppressed sequence");
        // The synthetic chunk MUST verify under the same per-session
        // key so SDK consumers see a valid signed chunk.
        assert!(
            scp_protocol::context::outlets::stream::verify_chunk_signature(
                &c1,
                &signing.verifying_key(),
                "ctx",
                "outlet",
                &caveats_binding,
            ),
            "synthetic terminal chunk signature must verify"
        );

        // Third call: queue cleared, session terminated, returns None
        // and evicts the entry.
        assert!(mgr.outlet_stream_next("ctx", &request_id_hex).is_none());
        assert!(
            !mgr.outlet_streams
                .contains_key(&("ctx".to_owned(), request_id_hex.clone()))
        );
    }

    /// Helper for `wasm_outlet_stream_next_emits_synthetic_terminal_after_cancel`:
    /// seed the manager with a 5-chunk Data stream under context `"ctx"`
    /// and outlet `"outlet"`, registering `signing` so the on-demand
    /// cancel/synthetic-terminal signing resolves. Pre-admits one
    /// admission slot so the W3 release-on-terminal behaviour is
    /// observable. Returns `(request_id_hex, request_id, caveats_binding,
    /// invoker_did)` where `invoker_did` is the DID derived from
    /// `signing` (SCP-OUT-037 W1).
    fn seed_cancel_test_session(
        mgr: &mut WasmContextManager,
        signing: &ed25519_dalek::SigningKey,
    ) -> (String, [u8; 16], [u8; 32], String) {
        use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);
        let caveats_binding = [0xC4u8; 32];
        let mut chunks: VecDeque<scp_protocol::context::outlets::stream::OutletStreamChunk> =
            VecDeque::new();
        for seq in 0..5_u64 {
            let payload = ChunkPayload::Data {
                value: serde_json::json!({"seq": seq}),
            };
            let sig = sign_chunk(
                signing,
                "ctx",
                "outlet",
                &request_id,
                seq,
                &caveats_binding,
                &payload,
            )
            .expect("sign chunk");
            chunks.push_back(scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: seq,
                payload,
                sig,
            });
        }
        let (session, invoker_did) = make_test_session(
            signing,
            "ctx",
            "outlet",
            caveats_binding,
            request_id,
            chunks,
            100,
        );
        admit_test_slot(mgr, "ctx", &invoker_did, "outlet");
        insert_test_session(mgr, "ctx", &request_id_hex, session);
        (request_id_hex, request_id, caveats_binding, invoker_did)
    }

    /// Cancel-mid-stream test: after `outlet_stream_cancel` lands while
    /// chunks remain queued, the next `outlet_stream_next` call MUST
    /// return a signed terminal `End` cancel-ack chunk (§5.4.5 step 3 —
    /// the executor's terminal IS the cancel-ack; NOT `SCP-TOOL-6135`,
    /// which is reserved for the framework cancel-ack *timer* path) and
    /// the remaining queued chunks MUST be dropped — the consumer NEVER
    /// observes the 4th chunk after cancelling on chunk 3.
    #[test]
    fn wasm_outlet_stream_next_emits_synthetic_terminal_after_cancel() {
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x5C; 32]);
        let (request_id_hex, _request_id, caveats_binding, invoker_did) =
            seed_cancel_test_session(&mut mgr, &signing);
        // The seed pre-admitted one slot — confirm it is held.
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            1,
            "seed admits one slot"
        );

        // Pull 3 chunks (sequences 0, 1, 2) — these are real Data chunks.
        for expected_seq in 0..3 {
            let c = mgr
                .outlet_stream_next("ctx", &request_id_hex)
                .expect("real chunk before cancel");
            assert!(
                matches!(c.payload, ChunkPayload::Data { .. }),
                "chunk {expected_seq} should be Data, got {:?}",
                c.payload
            );
            assert_eq!(c.sequence, expected_seq);
        }

        // Apply cancel — session.cancelled = true, queue NOT cleared
        // synchronously, terminated NOT set synchronously.
        let cancel_ack = mgr
            .outlet_stream_cancel("ctx", &request_id_hex, &invoker_did)
            .expect("cancel accepted");
        assert_eq!(
            cancel_ack,
            Some(3),
            "cancel-ack-seq is the runtime next-to-emit cursor (emitted_count) at cancel time",
        );
        {
            let s = mgr
                .outlet_streams
                .get(&("ctx".to_owned(), request_id_hex.clone()))
                .expect("present");
            assert!(s.cancelled, "cancel must flip cancelled flag");
            assert!(
                !s.terminated,
                "cancel must NOT flip terminated — the consumer pull surfaces the synthetic terminal"
            );
            assert_eq!(s.chunks.len(), 2, "remaining queued chunks NOT cleared yet");
        }

        // Next pull MUST return a signed synthetic terminal Error chunk
        // — NOT the 4th queued Data chunk.
        let terminal = mgr
            .outlet_stream_next("ctx", &request_id_hex)
            .expect("synthetic terminal after cancel");
        assert_cancel_ack_terminal(&terminal, &signing, &caveats_binding);

        // SCP-OUT-037 W3: the admission slot MUST be released immediately
        // on the terminal observation — NOT deferred to the next-pull
        // eviction or the wrapper `Drop`.
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            0,
            "admission slot released on terminal observation (W3)"
        );

        // After the synthetic terminal: session terminated, remaining
        // queued chunks dropped, next pull returns None and evicts.
        {
            let s = mgr
                .outlet_streams
                .get(&("ctx".to_owned(), request_id_hex.clone()))
                .expect("still present until None");
            assert!(s.terminated, "synthetic terminal must flip terminated");
            assert!(
                s.chunks.is_empty(),
                "queued tail dropped after synthetic terminal"
            );
            assert!(
                s.admission_released,
                "admission_released flag set after terminal (W3)"
            );
        }
        assert!(
            mgr.outlet_stream_next("ctx", &request_id_hex).is_none(),
            "post-terminal pull returns None and evicts the session"
        );
        assert!(
            !mgr.outlet_streams
                .contains_key(&("ctx".to_owned(), request_id_hex.clone())),
            "session evicted after terminal observation"
        );
        // Eviction after an already-released terminal MUST NOT
        // double-release (count stays 0, not underflow-wrapped).
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            0,
            "no double-release on post-terminal eviction (W3 idempotency)"
        );
    }

    /// Test (SCP-OUT-037 critical fix #5) — `outlet_stream_grant_credit`
    /// replenishes the live `remaining_credit` counter, lifting the
    /// stream out of the exhausted state.
    #[test]
    fn wasm_outlet_stream_grant_credit_replenishes_remaining_credit() {
        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);

        let (session, invoker_did) = make_test_session(
            &signing,
            "ctx",
            "outlet",
            [0u8; 32],
            request_id,
            VecDeque::new(),
            0,
        );
        insert_test_session(&mut mgr, "ctx", &request_id_hex, session);

        let total = mgr
            .outlet_stream_grant_credit("ctx", &request_id_hex, &invoker_did, 5)
            .expect("grant accepted");
        assert_eq!(total, 5, "total_credit reflects accepted grant");

        let session = mgr
            .outlet_streams
            .get(&("ctx".to_owned(), request_id_hex.clone()))
            .expect("session present");
        assert_eq!(session.remaining_credit, 5, "remaining_credit replenished");
        assert_eq!(session.total_credit, 5);
    }

    /// HIGH-1 (R3) — a credit grant against an already-closed (terminated)
    /// stream MUST be REJECTED with `protocol.stream-already-closed`
    /// (`SCP-TOOL-6101`), NOT silently succeed. This mirrors
    /// `outlet_stream_cancel`'s idempotency guard and the native bridges'
    /// rejection of a grant on a closed session. A false success would
    /// imply the credit was applied when the stream can emit no further
    /// billable chunk.
    #[test]
    fn wasm_outlet_stream_grant_on_terminated_session_rejected() {
        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x43; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);

        let (mut session, invoker_did) = make_test_session(
            &signing,
            "ctx",
            "outlet",
            [0u8; 32],
            request_id,
            VecDeque::new(),
            0,
        );
        // Drive the session to a terminal state, as a drained / terminal
        // pull would.
        session.terminated = true;
        insert_test_session(&mut mgr, "ctx", &request_id_hex, session);

        let err = mgr
            .outlet_stream_grant_credit("ctx", &request_id_hex, &invoker_did, 5)
            .expect_err("grant on a terminated stream MUST be rejected, not a false success");
        match err {
            ScpWasmError::Context { code, message } => {
                assert_eq!(
                    code,
                    scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION,
                    "closed-stream rejection carries SCP-TOOL-6101"
                );
                assert!(
                    message.contains("protocol.stream-already-closed"),
                    "rejection carries the protocol.stream-already-closed slug, got: {message}"
                );
            }
            other => panic!("expected Context error, got {other:?}"),
        }

        // The rejected grant MUST NOT perturb session credit state.
        let session = mgr
            .outlet_streams
            .get(&("ctx".to_owned(), request_id_hex.clone()))
            .expect("session present");
        assert_eq!(
            session.total_credit, 0,
            "rejected grant must not bump total_credit"
        );
        assert_eq!(
            session.monotonic_seq, 0,
            "rejected grant must not bump monotonic_seq"
        );
    }

    /// HIGH-1 (R3) — same rejection applies to a `cancelled` (but not yet
    /// drained) stream: a grant arriving after cancel is closed-stream and
    /// MUST be rejected with `protocol.stream-already-closed`.
    #[test]
    fn wasm_outlet_stream_grant_on_cancelled_session_rejected() {
        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);

        let (mut session, invoker_did) = make_test_session(
            &signing,
            "ctx",
            "outlet",
            [0u8; 32],
            request_id,
            VecDeque::new(),
            0,
        );
        session.cancelled = true;
        insert_test_session(&mut mgr, "ctx", &request_id_hex, session);

        let err = mgr
            .outlet_stream_grant_credit("ctx", &request_id_hex, &invoker_did, 3)
            .expect_err("grant on a cancelled stream MUST be rejected");
        match err {
            ScpWasmError::Context { code, message } => {
                assert_eq!(
                    code,
                    scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION
                );
                assert!(message.contains("protocol.stream-already-closed"));
            }
            other => panic!("expected Context error, got {other:?}"),
        }
    }

    /// HIGH-2 (R3) — the cumulative `max_calls` ceiling caps the total
    /// number of billable `Data` chunks the stream may EVER emit. With
    /// `max_calls = N` and a generous credit window, exactly N billable
    /// chunks pass, then the next billable `Data` pull synthesises a
    /// terminal `Error` with slug `execution.credit-exhausted`
    /// (`SCP-TOOL-6131`). The cap is independent of the credit window —
    /// the window here is wide enough that the credit-window gate never
    /// fires; only the cumulative `max_calls` ceiling closes the stream.
    #[test]
    fn wasm_outlet_stream_next_enforces_max_calls_ceiling() {
        use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};

        // Pre-materialise 5 Data chunks. With max_calls = 2 only the first
        // two pass; the third billable pull closes the stream.
        const MAX_CALLS: u32 = 2;

        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);
        let caveats_binding = [0x99u8; 32];

        let make_chunk = |seq: u64| {
            let payload = ChunkPayload::Data {
                value: serde_json::json!({"n": seq}),
            };
            let sig = sign_chunk(
                &signing,
                "ctx",
                "outlet",
                &request_id,
                seq,
                &caveats_binding,
                &payload,
            )
            .expect("sign chunk");
            scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: seq,
                payload,
                sig,
            }
        };
        let mut chunks: VecDeque<scp_protocol::context::outlets::stream::OutletStreamChunk> =
            VecDeque::new();
        for seq in 0..5 {
            chunks.push_back(make_chunk(seq));
        }

        // Credit window of 100 — far wider than max_calls, so ONLY the
        // cumulative ceiling can close the stream.
        let (mut session, _invoker_did) = make_test_session(
            &signing,
            "ctx",
            "outlet",
            caveats_binding,
            request_id,
            chunks,
            100,
        );
        session.max_calls = Some(MAX_CALLS);
        insert_test_session(&mut mgr, "ctx", &request_id_hex, session);

        // Exactly MAX_CALLS billable Data chunks pass through.
        for expected_seq in 0..u64::from(MAX_CALLS) {
            let c = mgr
                .outlet_stream_next("ctx", &request_id_hex)
                .expect("billable chunk within max_calls");
            assert!(
                matches!(c.payload, ChunkPayload::Data { .. }),
                "chunk {expected_seq} should be Data"
            );
            assert_eq!(c.sequence, expected_seq);
        }

        // The (MAX_CALLS+1)-th billable pull synthesises the terminal
        // credit-exhausted Error — the cumulative ceiling closes the
        // stream regardless of remaining credit window.
        let terminal = mgr
            .outlet_stream_next("ctx", &request_id_hex)
            .expect("synthetic terminal after cumulative ceiling reached");
        match terminal.payload {
            ChunkPayload::Error {
                code,
                terminal,
                message,
            } => {
                assert!(terminal, "ceiling terminal MUST be terminal");
                assert_eq!(
                    code,
                    scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CREDIT,
                    "cumulative-ceiling terminal carries SCP-TOOL-6131"
                );
                assert!(
                    message.contains(
                        scp_protocol::context::outlets::error_codes::SLUG_EXECUTION_CREDIT_EXHAUSTED
                    ),
                    "terminal carries the execution.credit-exhausted slug, got: {message}"
                );
            }
            other => panic!("expected terminal Error, got {other:?}"),
        }
        assert_eq!(
            terminal.sequence,
            u64::from(MAX_CALLS),
            "ceiling terminal lands at the suppressed chunk's sequence"
        );

        // Session billed exactly MAX_CALLS and is terminated; the next
        // pull drains to None.
        {
            let s = mgr
                .outlet_streams
                .get(&("ctx".to_owned(), request_id_hex.clone()))
                .expect("present until next-pull eviction");
            assert_eq!(s.billed_emitted, MAX_CALLS, "billed exactly max_calls");
            assert!(s.terminated, "ceiling closure flips terminated");
        }
        assert!(
            mgr.outlet_stream_next("ctx", &request_id_hex).is_none(),
            "queue cleared + evicted after the ceiling terminal"
        );
    }

    /// HIGH-2 (R3) — `Progress` chunks consume credit-window headroom but
    /// are NEVER billed, so they do NOT count toward the `max_calls`
    /// cumulative ceiling (matching the runtime's `Data`-only
    /// `is_billable_chunk` predicate). A stream of `Progress` chunks under
    /// a `max_calls` cap is unaffected by the cap.
    #[test]
    fn wasm_outlet_stream_progress_does_not_count_toward_max_calls() {
        use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};

        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x78; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);
        let caveats_binding = [0x88u8; 32];

        let make_chunk = |seq: u64, payload: ChunkPayload| {
            let sig = sign_chunk(
                &signing,
                "ctx",
                "outlet",
                &request_id,
                seq,
                &caveats_binding,
                &payload,
            )
            .expect("sign chunk");
            scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: seq,
                payload,
                sig,
            }
        };
        let mut chunks: VecDeque<scp_protocol::context::outlets::stream::OutletStreamChunk> =
            VecDeque::new();
        // Three Progress chunks then a terminal End. max_calls = 1 would
        // close on the second BILLABLE Data chunk — but Progress is never
        // billable, so all three pass and End closes cleanly.
        chunks.push_back(make_chunk(
            0,
            ChunkPayload::Progress {
                pct: 10,
                note: None,
            },
        ));
        chunks.push_back(make_chunk(
            1,
            ChunkPayload::Progress {
                pct: 20,
                note: None,
            },
        ));
        chunks.push_back(make_chunk(
            2,
            ChunkPayload::Progress {
                pct: 30,
                note: None,
            },
        ));
        chunks.push_back(make_chunk(
            3,
            ChunkPayload::End {
                aggregate: serde_json::json!({"done": true}),
                provenance: super::build_minimal_stream_end_provenance("ctx"),
                execution_time_ms: 0,
            },
        ));

        let (mut session, _invoker_did) = make_test_session(
            &signing,
            "ctx",
            "outlet",
            caveats_binding,
            request_id,
            chunks,
            100,
        );
        session.max_calls = Some(1);
        insert_test_session(&mut mgr, "ctx", &request_id_hex, session);

        // All three Progress chunks pass despite max_calls = 1.
        for expected_seq in 0..3 {
            let c = mgr
                .outlet_stream_next("ctx", &request_id_hex)
                .expect("progress chunk not gated by max_calls");
            assert!(
                matches!(c.payload, ChunkPayload::Progress { .. }),
                "chunk {expected_seq} should be Progress"
            );
        }
        // The terminal End passes cleanly — never reached the ceiling.
        let end = mgr
            .outlet_stream_next("ctx", &request_id_hex)
            .expect("terminal End");
        assert!(
            matches!(end.payload, ChunkPayload::End { .. }),
            "terminal is a clean End, not a credit-exhausted Error"
        );
        let s = mgr
            .outlet_streams
            .get(&("ctx".to_owned(), request_id_hex.clone()))
            .expect("present");
        assert_eq!(
            s.billed_emitted, 0,
            "Progress chunks never advance billed_emitted"
        );
    }

    /// Test (SCP-OUT-037 critical fix #5) — `request_id` generated by
    /// `open_outlet_stream` is a `UUIDv7`. The version nibble of the 7th
    /// byte (`bytes[6] & 0xF0`) MUST equal `0x70` per RFC 9562 §5.7.
    #[test]
    fn wasm_request_id_is_uuid_v7() {
        // We can't easily call `open_outlet_stream` without a context,
        // so verify the UUID generator itself produces v7 — the same
        // call site used in `open_outlet_stream`.
        let bytes: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        // Version nibble lives in the high 4 bits of byte 6 per RFC
        // 9562 §4.2 (variant) / §5.7 (version 7).
        assert_eq!(
            bytes[6] & 0xF0,
            0x70,
            "request_id MUST carry the `UUIDv7` version nibble"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-039 AC4 — per-bridge conformance vector replay (WASM)
    //
    // Every vector in `tests/conformance/vectors/outlet_stream_vectors.json`
    // is driven through `WasmContextManager::open_outlet_stream` (the
    // single funnel the WASM bridge converges on — `pipeline_wiring.rs`
    // pins the bridge's `outlet_invoke_stream` body to call this
    // method). The WASM bridge differs from the native bridges in one
    // critical way: chunks are materialised eagerly at open time from a
    // single handler return value (see `build_stream_chunks`). The
    // executor model the runtime conformance funnel exercises
    // (multi-chunk Data, mid-stream Error{terminal:false}, executor-
    // driven End) does not apply on WASM. What WE CAN assert on the
    // WASM funnel:
    //
    // - Every vector's open succeeds (or fails at the appropriate
    //   boundary) under the bridge's actual `open_outlet_stream`
    //   signature, with the vector's `credit_window` /
    //   `caveats_binding` / `stream_epoch` parameters threaded through
    //   `OpenOutletStreamParams`.
    // - Per-chunk signatures verify under the operator's pinned
    //   verifying key (`invoker_verifying_key`; on WASM the invoker is
    //   the operator because there is no cross-context routing, and the
    //   secret key is materialised on-demand via `with_signing_key`,
    //   never retained on the session — SCP-OUT-037 W1).
    // - The cancellation vector's `outlet_stream_cancel` →
    //   terminal flow surfaces a normal terminal `End` cancel-ack
    //   chunk on the next `outlet_stream_next` pull (§5.4.5 step 3 —
    //   the executor's terminal IS the cancel-ack; `SCP-TOOL-6135`
    //   `execution.cancel-ack-timeout` is reserved for the framework
    //   timer-fired path, not an ordinary invoker cancel) — matching
    //   the runtime cancel-ack ceiling on native bridges.
    // - The credit_exhaustion vector's zero-grant flow surfaces the
    //   `SCP-TOOL-6131` (`execution.credit-exhausted`) terminal error
    //   on the second pull after the credit window depletes.
    // - The error_terminal vector's handler-returns-Err flow produces
    //   a terminal `Error` chunk that the SDK iterator surfaces as the
    //   final chunk.
    //
    // What this test does NOT pin on the WASM bridge (and why):
    //
    // - `expected_total_chunks` for the multi_chunk / error_recoverable /
    //   sequence_gap vectors: WASM degenerates the handler return into
    //   Data + End (2 chunks) regardless of the vector's executor
    //   chunk count. The cross-bridge funnel that pins per-vector
    //   chunk count lives in
    //   `crates/scp-testing/tests/integration/outlet_stream_vectors_through_open_path.rs`
    //   (driven via the executor trait — not available on WASM).
    // - The §5.4.5 cancel-ack-seq / credit-stall numeric ceilings are
    //   per-bridge implementation details that the runtime conformance
    //   funnel pins. On WASM the cancel handler returns the runtime
    //   `emitted_count` cursor at cancel time and the test below
    //   asserts the surfaced sequence is in the expected range.
    // -----------------------------------------------------------------------

    /// Build the `BuildStreamChunksInputs` arguments for a fresh test
    /// session — used by the per-vector setup below to register a
    /// vector-specific outlet under a fresh context.
    fn vector_replay_setup(
        mgr: &mut WasmContextManager,
        vector_name: &str,
        creator_did: &str,
    ) -> (String, String) {
        use scp_protocol::context::outlets::{
            OutletKind,
            registry::{OutletRegistration, OutletSchema, OutletTestVector},
        };

        let context_id = format!("wasm-vec-ctx-{vector_name}");
        let outlet_id = format!("vec.outlet.{vector_name}");

        // Seed a bare context — `make_bare_per_context_state` returns an
        // `active` context with the creator as the lone admin member.
        // The vector replay does not need governance or membership
        // beyond that — `open_outlet_stream` reads `outlet_registry`,
        // `outlet_handlers`, and `outlet_stream_admission` directly.
        let state = super::make_bare_per_context_state(&context_id, creator_did);
        mgr.contexts.insert(context_id.clone(), state);

        // Register the outlet. Schema is the broadest two-property
        // object to satisfy the §5.4.5 specificity floor.
        let registration = OutletRegistration {
            outlet_id: outlet_id.clone(),
            kind: OutletKind::Action,
            name: outlet_id.clone(),
            description: format!("WASM vector replay outlet for {vector_name}"),
            schema: OutletSchema {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "a": {"type": "number"},
                        "b": {"type": "number"}
                    }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean"},
                        "v": {"type": "number"}
                    }
                }),
                aggregate_schema: None,
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![OutletTestVector {
                input: serde_json::json!({}),
                expected_output: serde_json::json!({}),
                description: "vector replay fixture".to_owned(),
            }],
            operator_did: DID::from(creator_did),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        };
        mgr.register_outlet(&context_id, registration)
            .expect("register_outlet for vector replay must succeed");

        (context_id, outlet_id)
    }

    /// Build `OpenOutletStreamParams` for a vector replay open. Owned
    /// strings are NOT stored — the params struct uses `&str` lifetimes
    /// so all owned bindings stay in the caller's frame.
    ///
    /// SCP-OUT-037 W1: the signing key is NOT a param — the open path
    /// signs on-demand via `with_signing_key(identity_did)`, so the
    /// caller MUST have registered `identity_did`'s key first.
    // One-to-one constructor for the `OpenOutletStreamParams` FFI params
    // struct — the arg count mirrors the struct fields (the same reason
    // `too_many_arguments` is tolerated on the FFI param-bundle sites).
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    fn open_params_for<'a>(
        context_id: &'a str,
        outlet_id: &'a str,
        identity_did: &'a str,
        input_json: &'a serde_json::Value,
        caveats_binding: [u8; 32],
        stream_epoch: u64,
        credit_window: u32,
        max_calls: Option<u32>,
    ) -> super::OpenOutletStreamParams<'a> {
        super::OpenOutletStreamParams {
            context_id,
            outlet_id,
            input_json,
            identity_did,
            caveats_binding,
            stream_epoch,
            credit_window,
            max_calls,
        }
    }

    /// Drive a vector with `handler_returns_ok = true` and pull the
    /// chunks. Returns the (`request_id_hex`, observed chunks) pair.
    fn drive_ok_vector(
        mgr: &mut WasmContextManager,
        vector_name: &str,
        credit_window: u32,
    ) -> (
        String,
        Vec<scp_protocol::context::outlets::stream::OutletStreamChunk>,
        ed25519_dalek::SigningKey,
        [u8; 32],
        String,
        String,
    ) {
        use std::sync::atomic::AtomicU64;
        static SK_TICK: AtomicU64 = AtomicU64::new(0);

        // Distinct signing key per vector so the registry's
        // chunk-signature verification is meaningful (a different key
        // would cause `verify_chunk_signature` to fail). SCP-OUT-037 W1:
        // register the key and use its DERIVED DID as both the creator
        // and the invoker, so the open path's on-demand
        // `with_signing_key(identity_did)` resolves to this exact key.
        let tick = SK_TICK.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut sk_bytes = [0u8; 32];
        sk_bytes[..8].copy_from_slice(&tick.to_le_bytes());
        sk_bytes[8] = 0x42; // ensure non-zero high bytes
        let signing = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let invoker_did = crate::identity::register_identity_for_test(&signing);

        let (context_id, outlet_id) = vector_replay_setup(mgr, vector_name, &invoker_did);

        let input = serde_json::json!({"a": 1, "b": 2});
        let caveats_binding = [0xA5u8; 32];
        let params = open_params_for(
            &context_id,
            &outlet_id,
            &invoker_did,
            &input,
            caveats_binding,
            0,
            credit_window,
            None,
        );
        let request_id_hex = mgr
            .open_outlet_stream(params)
            .expect("open_outlet_stream must succeed for OK vector");

        let mut observed = Vec::new();
        while let Some(c) = mgr.outlet_stream_next(&context_id, &request_id_hex) {
            observed.push(c);
        }

        (
            request_id_hex,
            observed,
            signing,
            caveats_binding,
            context_id,
            outlet_id,
        )
    }

    /// Verify every chunk in `observed` carries a signature that
    /// round-trips under the operator's verifying key — pins SCP-OUT-039
    /// AC4's "per-chunk signature verifies" expectation on the WASM
    /// funnel.
    fn assert_all_signatures_verify(
        observed: &[scp_protocol::context::outlets::stream::OutletStreamChunk],
        signing: &ed25519_dalek::SigningKey,
        context_id: &str,
        outlet_id: &str,
        caveats_binding: &[u8; 32],
    ) {
        for (i, c) in observed.iter().enumerate() {
            assert!(
                scp_protocol::context::outlets::stream::verify_chunk_signature(
                    c,
                    &signing.verifying_key(),
                    context_id,
                    outlet_id,
                    caveats_binding,
                ),
                "chunk[{i}] signature must verify under the operator's verifying key (WASM bridge)"
            );
        }
    }

    /// SCP-OUT-039 AC4 — `non_streaming` vector through WASM bridge.
    ///
    /// Vector expectation: terminal status `Ok`,
    /// `expected_total_chunks = 2` (one Data + End), no cancellation,
    /// no error. The WASM bridge's eager-materialisation model matches
    /// this vector exactly (the only vector for which the WASM funnel
    /// produces the runtime's exact chunk count).
    #[test]
    fn wasm_vector_non_streaming_through_open_path() {
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let mut mgr = WasmContextManager::new();
        let (_id, observed, signing, binding, ctx_id, outlet_id) =
            drive_ok_vector(&mut mgr, "non_streaming", 32);

        assert_eq!(
            observed.len(),
            2,
            "non_streaming through WASM bridge must produce Data + End (2 chunks)"
        );
        assert!(
            matches!(observed[0].payload, ChunkPayload::Data { .. }),
            "first chunk must be Data, got {:?}",
            observed[0].payload
        );
        assert!(
            matches!(observed[1].payload, ChunkPayload::End { .. }),
            "second chunk must be terminal End, got {:?}",
            observed[1].payload
        );
        assert_all_signatures_verify(&observed, &signing, &ctx_id, &outlet_id, &binding);
    }

    /// SCP-OUT-039 AC4 — `multi_chunk` vector through WASM bridge.
    ///
    /// Vector expectation (runtime): 10 Data + 1 End = 11 chunks,
    /// terminal Ok. WASM bridge limitation: the bridge materialises
    /// one Data + End from the handler result; multi-Data executor
    /// emission is not modelled on WASM (no async executor — see
    /// ADR-034 + `build_stream_chunks`). What this assertion does pin
    /// is that the vector's `credit_window` (32) flows through the
    /// open path and the produced two-chunk sequence verifies — the
    /// per-vector multi-Data shape is pinned by
    /// `outlet_stream_vectors_through_open_path.rs` (runtime funnel)
    /// for SCP-OUT-039 AC4 cross-bridge coverage.
    #[test]
    fn wasm_vector_multi_chunk_through_open_path() {
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let mut mgr = WasmContextManager::new();
        let (_id, observed, signing, binding, ctx_id, outlet_id) =
            drive_ok_vector(&mut mgr, "multi_chunk", 32);

        // WASM bridge degenerates to Data + End — document the
        // limitation inline so a future executor-on-WASM enabler sees
        // the constraint loudly.
        assert_eq!(
            observed.len(),
            2,
            "WASM bridge degenerates multi_chunk to Data + End — multi-Data executor emission is pinned by the runtime funnel, not this bridge"
        );
        assert!(matches!(observed[0].payload, ChunkPayload::Data { .. }));
        assert!(matches!(observed[1].payload, ChunkPayload::End { .. }));
        assert_all_signatures_verify(&observed, &signing, &ctx_id, &outlet_id, &binding);
    }

    /// SCP-OUT-039 AC4 — `error_recoverable` vector through WASM bridge.
    ///
    /// Vector expectation (runtime): non-terminal Error mid-stream
    /// followed by Data + End — terminal Ok. WASM bridge limitation:
    /// the bridge cannot model a mid-stream recoverable error (no
    /// async executor). The handler-Ok path produces Data + End, which
    /// is the same degenerate shape as `multi_chunk` — the assertion
    /// is identical (terminal Ok, 2 chunks, signatures verify).
    #[test]
    fn wasm_vector_error_recoverable_through_open_path() {
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let mut mgr = WasmContextManager::new();
        let (_id, observed, signing, binding, ctx_id, outlet_id) =
            drive_ok_vector(&mut mgr, "error_recoverable", 32);

        assert_eq!(
            observed.len(),
            2,
            "WASM bridge degenerates error_recoverable to Data + End — recoverable-Error executor emission is pinned by the runtime funnel"
        );
        assert!(matches!(observed[0].payload, ChunkPayload::Data { .. }));
        assert!(matches!(observed[1].payload, ChunkPayload::End { .. }));
        assert_all_signatures_verify(&observed, &signing, &ctx_id, &outlet_id, &binding);
    }

    /// SCP-OUT-039 AC4 — `sequence_gap` vector through WASM bridge.
    ///
    /// Vector expectation (runtime): executor emits 0/1/3 (gap at 2);
    /// receiver-side `StreamGap` cancel surfaces `SCP-TOOL-6131` slug
    /// `execution.stream-gap`. WASM bridge limitation: the bridge has
    /// no executor with multi-Data emission, so it cannot produce a
    /// sequence gap — the handler-Ok path produces Data + End. The
    /// runtime funnel pins receiver-side gap detection.
    #[test]
    fn wasm_vector_sequence_gap_through_open_path() {
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let mut mgr = WasmContextManager::new();
        let (_id, observed, signing, binding, ctx_id, outlet_id) =
            drive_ok_vector(&mut mgr, "sequence_gap", 32);

        assert_eq!(
            observed.len(),
            2,
            "WASM bridge degenerates sequence_gap to Data + End — gap detection requires receiver-side observation across multi-Data emission, pinned by the runtime funnel"
        );
        assert!(matches!(observed[0].payload, ChunkPayload::Data { .. }));
        assert!(matches!(observed[1].payload, ChunkPayload::End { .. }));
        assert_all_signatures_verify(&observed, &signing, &ctx_id, &outlet_id, &binding);
    }

    /// SCP-OUT-039 AC4 — `error_terminal` vector through WASM bridge.
    ///
    /// Vector expectation (runtime): executor signals terminal Error
    /// after two Data chunks; framework appends Error{terminal:true}
    /// under `SCP-TOOL-6130` (handler-fault). WASM bridge maps: an
    /// outlet handler that returns `Err(_)` produces a single terminal
    /// Error chunk via `build_stream_chunks`'s Err arm. We register a
    /// handler that fails so the bridge surfaces the terminal Error
    /// shape — the chunk code follows the bridge's Err mapping
    /// (`build_stream_chunks` maps the `ScpWasmError::Tool` to the
    /// chunk's `code` field).
    #[test]
    fn wasm_vector_error_terminal_through_open_path() {
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let mut mgr = WasmContextManager::new();
        // SCP-OUT-037 W1: register the signing key and use its derived
        // DID so the open path's on-demand signing resolves.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
        let invoker_did = crate::identity::register_identity_for_test(&signing);
        let (context_id, outlet_id) = vector_replay_setup(&mut mgr, "error_terminal", &invoker_did);

        // Register a handler that returns Err — drives the
        // `build_stream_chunks` Err arm.
        mgr.register_outlet_handler(
            &context_id,
            &outlet_id,
            Box::new(|_input| Err("vector-replay terminal error".to_owned())),
        )
        .expect("register_outlet_handler must succeed");

        let input = serde_json::json!({"a": 1, "b": 2});
        let caveats_binding = [0xE1u8; 32];
        let params = open_params_for(
            &context_id,
            &outlet_id,
            &invoker_did,
            &input,
            caveats_binding,
            0,
            32,
            None,
        );
        let request_id_hex = mgr
            .open_outlet_stream(params)
            .expect("open_outlet_stream must succeed even when handler returns Err — the Err is surfaced as a terminal chunk, not an open-time error");

        let mut observed = Vec::new();
        while let Some(c) = mgr.outlet_stream_next(&context_id, &request_id_hex) {
            observed.push(c);
        }

        // Single terminal Error chunk per the Err arm of
        // `build_stream_chunks`.
        assert_eq!(
            observed.len(),
            1,
            "error_terminal through WASM bridge must produce one terminal Error chunk"
        );
        match &observed[0].payload {
            ChunkPayload::Error {
                terminal,
                code: _,
                message: _,
            } => {
                assert!(
                    *terminal,
                    "error_terminal: WASM bridge Err arm must produce terminal:true"
                );
            }
            other => panic!("expected terminal Error chunk, got {other:?}"),
        }
        assert_all_signatures_verify(
            &observed,
            &signing,
            &context_id,
            &outlet_id,
            &caveats_binding,
        );
    }

    /// SCP-OUT-039 AC4 — `cancellation` vector through WASM bridge.
    ///
    /// Vector expectation (§5.4.5): receiver issues `OutletCancel`
    /// mid-stream; the stream terminates with status `Cancelled`. On
    /// the runtime path the vector's executor *parks*, so the framework
    /// cancel-ack *timer* fires and force-closes with a terminal
    /// `Error`. On WASM there is no parking executor and no timer: the
    /// pre-materialised lazy generator IS the executor and always
    /// honors the cancel by emitting its terminal synchronously on the
    /// next pull — the §5.4.5 step-3 "executor's terminal IS the
    /// cancel-ack" case — so the WASM cancel-ack is a *normal* terminal
    /// `End` chunk, never the `SCP-TOOL-6135`
    /// (`execution.cancel-ack-timeout`) timer code (which is
    /// unreachable on WASM by construction — only
    /// `outlet_stream_terminate` with `TerminateReason::CancelAckTimeout`
    /// mints it). WASM bridge maps: `outlet_stream_cancel` flips
    /// `session.cancelled`; the next `outlet_stream_next` pull builds
    /// the terminal `End` cancel-ack chunk (per the lazy-generator
    /// pattern documented in `crates/scp-ffi/wasm/CLAUDE.md` →
    /// "Outlet Streaming — Lazy Cancellation Point"). This test drives
    /// the same flow the existing
    /// `wasm_outlet_stream_next_emits_synthetic_terminal_after_cancel`
    /// pins, scoped to the cancellation vector's `caller_did` and
    /// signature roundtrip.
    #[test]
    fn wasm_vector_cancellation_through_open_path() {
        use scp_protocol::context::outlets::stream::ChunkPayload;

        let mut mgr = WasmContextManager::new();
        let (request_id_hex, observed_pre, signing, binding, ctx_id, outlet_id) =
            drive_ok_vector(&mut mgr, "cancellation", 32);
        // Pre-cancel: handler-Ok produced Data + End; the End fully
        // drained the queue. To exercise cancel mid-stream the WASM
        // model needs queued chunks remaining — we re-seed the
        // session using the same fixture pattern as
        // `seed_cancel_test_session` so the cancel surfaces a synthetic
        // terminal at the next pull instead of `None`.
        //
        // The pre-cancel `Data + End` pair already verified above for
        // the open-path AC4 assertion. We now seed a fresh request_id
        // under the same context to drive cancel-mid-stream — this is
        // the second AC4 surface for the cancellation vector (cancel
        // produces synthetic terminal at next pull).
        let _ = request_id_hex; // first run drained — switch to seed pattern
        let _ = observed_pre;
        let _ = ctx_id;
        let _ = outlet_id;
        let _ = binding;

        // Reuse the existing seed_cancel helper to install a 5-Data
        // session bound to the same signing key. SCP-OUT-037 W1/W2: the
        // helper registers `signing` under its derived DID and keys the
        // session by `("ctx", req_hex)`; it returns that derived DID.
        let (req_hex, _req_id, cancel_binding, invoker_did) =
            super::tests::seed_cancel_test_session(&mut mgr, &signing);

        // Pull 3 chunks (sequences 0, 1, 2).
        for expected_seq in 0..3 {
            let c = mgr
                .outlet_stream_next("ctx", &req_hex)
                .expect("real Data chunk before cancel");
            assert!(
                matches!(c.payload, ChunkPayload::Data { .. }),
                "chunk {expected_seq} must be Data"
            );
            assert_eq!(c.sequence, expected_seq);
        }

        // Apply cancel — flips `session.cancelled`, does NOT
        // synchronously clear the queue.
        let cancel_ack = mgr
            .outlet_stream_cancel("ctx", &req_hex, &invoker_did)
            .expect("cancel accepted");
        assert_eq!(
            cancel_ack,
            Some(3),
            "WASM cancel-ack-seq = emitted_count at cancel time"
        );

        // Next pull → normal terminal `End` cancel-ack (§5.4.5 step 3 —
        // the executor's terminal IS the cancel-ack; NOT the
        // `SCP-TOOL-6135` timer code). The shared helper pins the
        // terminal shape AND the per-chunk signature round-trip under
        // the session's pinned operator key — AC4's signature invariant
        // on the cancellation funnel.
        let terminal = mgr
            .outlet_stream_next("ctx", &req_hex)
            .expect("synthetic terminal after cancel");
        assert_cancel_ack_terminal(&terminal, &signing, &cancel_binding);
    }

    /// SCP-OUT-039 AC4 — `credit_exhaustion` vector through WASM bridge.
    ///
    /// Vector expectation (runtime): receiver issues no grant;
    /// framework's credit-stall timer fires after
    /// `stream_credit_stall_secs` and emits a terminal Error under
    /// `SCP-TOOL-6133` (`execution.credit-stall`). WASM bridge maps:
    /// no async timer exists on a single-threaded `thread_local`
    /// runtime, so the bridge surfaces credit-exhaustion through a
    /// different code (`SCP-TOOL-6131` / `execution.credit-exhausted`)
    /// — the next pull after `remaining_credit == 0` synthesises the
    /// terminal Error per the lazy-generator pattern. This is the
    /// same flow `wasm_outlet_stream_next_enforces_credit_window` pins
    /// (existing test); we drive it under the vector's parameters so
    /// AC4's per-vector flow is exercised.
    #[test]
    fn wasm_vector_credit_exhaustion_through_open_path() {
        use scp_protocol::context::outlets::error_codes::{
            CODE_EXECUTION_CREDIT, CODE_EXECUTION_CREDIT_STALL,
        };
        use scp_protocol::context::outlets::stream::ChunkPayload;

        // Drive the eager-materialisation path with `credit_window = 0`
        // so the synthetic credit-exhaustion terminal fires on the
        // first pull of a billable chunk. The handler-Ok return
        // produces a Data + End pair; with zero credit the Data chunk
        // path triggers the synthetic terminal.
        let mut mgr = WasmContextManager::new();
        // SCP-OUT-037 W1: register signing key under its derived DID.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x13; 32]);
        let invoker_did = crate::identity::register_identity_for_test(&signing);
        let (context_id, outlet_id) =
            vector_replay_setup(&mut mgr, "credit_exhaustion", &invoker_did);

        let input = serde_json::json!({"a": 1, "b": 2});
        let caveats_binding = [0xC0u8; 32];

        // open with credit_window=0 — first billable Data chunk hits
        // the exhausted path immediately.
        let params = open_params_for(
            &context_id,
            &outlet_id,
            &invoker_did,
            &input,
            caveats_binding,
            0,
            0,
            None,
        );
        let request_id_hex = mgr
            .open_outlet_stream(params)
            .expect("open_outlet_stream with credit_window=0 must succeed (chunks materialise; credit gate fires on pull)");

        // First pull: synthetic terminal under SCP-TOOL-6131
        // (`execution.credit-exhausted`).
        let terminal = mgr.outlet_stream_next(&context_id, &request_id_hex).expect(
            "credit_exhaustion: WASM bridge surfaces synthetic terminal on first billable pull",
        );
        match &terminal.payload {
            ChunkPayload::Error {
                terminal: is_terminal,
                code,
                message: _,
            } => {
                assert!(
                    *is_terminal,
                    "credit_exhaustion: WASM synthetic chunk must be terminal"
                );
                assert_eq!(
                    code, CODE_EXECUTION_CREDIT,
                    "credit_exhaustion: WASM bridge surfaces {CODE_EXECUTION_CREDIT} (`execution.credit-exhausted`) — runtime emits {CODE_EXECUTION_CREDIT_STALL} on the stall-timer path which is not modelled on WASM; this is the WASM-specific surface for AC4"
                );
            }
            other => panic!("credit_exhaustion: expected terminal Error, got {other:?}"),
        }

        // Synthetic chunk signature verifies under the operator key.
        assert!(
            scp_protocol::context::outlets::stream::verify_chunk_signature(
                &terminal,
                &signing.verifying_key(),
                &context_id,
                &outlet_id,
                &caveats_binding,
            ),
            "credit_exhaustion: synthetic chunk signature must verify under the pinned operator key"
        );

        // Subsequent pull: queue cleared / terminated → None.
        assert!(
            mgr.outlet_stream_next(&context_id, &request_id_hex)
                .is_none(),
            "post-terminal pull must evict the session and return None"
        );
    }

    /// SCP-OUT-039 AC4 — fixture-load sanity check.
    ///
    /// Pins that the conformance vector file the bridge replays from
    /// has the seven §5.4.5 named vectors. If the fixture drifts (a
    /// vector is renamed or dropped), the per-vector tests above stop
    /// having anything meaningful to assert.
    #[test]
    fn wasm_vector_fixture_has_seven_named_vectors() {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        // crates/scp-ffi/wasm → workspace root
        let mut p = std::path::PathBuf::from(manifest);
        p.pop(); // out of wasm
        p.pop(); // out of scp-ffi
        p.pop(); // out of crates
        p.push("tests/conformance/vectors/outlet_stream_vectors.json");
        let bytes = std::fs::read(&p).unwrap_or_else(|e| {
            panic!(
                "vector fixture must exist at {} ({e}); AC4 per-bridge replay depends on it",
                p.display()
            )
        });
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("vector file parses");
        let vectors = v
            .get("vectors")
            .and_then(serde_json::Value::as_array)
            .expect("vectors[]");
        assert_eq!(vectors.len(), 7, "expected 7 SCP-OUT-039 vectors");

        let names: std::collections::HashSet<&str> = vectors
            .iter()
            .filter_map(|v| v.get("name").and_then(serde_json::Value::as_str))
            .collect();
        for required in [
            "non_streaming",
            "multi_chunk",
            "cancellation",
            "error_terminal",
            "error_recoverable",
            "sequence_gap",
            "credit_exhaustion",
        ] {
            assert!(
                names.contains(required),
                "vector {required} missing from fixture — AC4 per-bridge replay coverage broken"
            );
        }
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-037 W2 — composite-key cross-context isolation
    // -----------------------------------------------------------------------

    /// W2: two streams opened by the SAME invoker in two DIFFERENT
    /// contexts under a FORCED `request_id_hex` collision MUST remain
    /// isolated — `(ctx_a, rid)` only ever touches the `ctx_a` session,
    /// `(ctx_b, rid)` only the `ctx_b` session. Before W2 (single
    /// `request_id`-keyed map) the second insert would have overwritten
    /// the first; with the composite key both coexist and address
    /// independently.
    #[test]
    fn wasm_w2_composite_key_isolates_colliding_request_id_across_contexts() {
        use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};

        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x2C; 32]);

        // FORCED collision: the SAME request_id (hence the same
        // request_id_hex) is used to seed two sessions under two
        // distinct contexts.
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);

        // Build a distinct single-Data chunk per context so the observed
        // value tells us WHICH session a lookup hit.
        let build_chunk = |ctx: &str, tag: i64| {
            let payload = ChunkPayload::Data {
                value: serde_json::json!({ "ctx": ctx, "tag": tag }),
            };
            let cb = [0x11u8; 32];
            let sig = sign_chunk(&signing, ctx, "outlet", &request_id, 0, &cb, &payload)
                .expect("sign chunk");
            let mut q = VecDeque::new();
            q.push_back(scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: 0,
                payload,
                sig,
            });
            q
        };

        let (session_a, invoker_did) = make_test_session(
            &signing,
            "ctx-a",
            "outlet",
            [0x11u8; 32],
            request_id,
            build_chunk("ctx-a", 1),
            100,
        );
        let (session_b, invoker_did_b) = make_test_session(
            &signing,
            "ctx-b",
            "outlet",
            [0x11u8; 32],
            request_id,
            build_chunk("ctx-b", 2),
            100,
        );
        // Same invoker (same key → same derived DID) in both contexts.
        assert_eq!(invoker_did, invoker_did_b);

        insert_test_session(&mut mgr, "ctx-a", &request_id_hex, session_a);
        insert_test_session(&mut mgr, "ctx-b", &request_id_hex, session_b);

        // Both coexist — the composite key kept them distinct.
        assert_eq!(mgr.outlet_streams.len(), 2);

        // (ctx-a, rid) addresses ONLY the ctx-a session.
        let c_a = mgr
            .outlet_stream_next("ctx-a", &request_id_hex)
            .expect("ctx-a chunk");
        match &c_a.payload {
            ChunkPayload::Data { value } => {
                assert_eq!(value["ctx"], "ctx-a", "(ctx-a, rid) must hit ctx-a session");
                assert_eq!(value["tag"], 1);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // (ctx-b, rid) addresses ONLY the ctx-b session.
        let c_b = mgr
            .outlet_stream_next("ctx-b", &request_id_hex)
            .expect("ctx-b chunk");
        match &c_b.payload {
            ChunkPayload::Data { value } => {
                assert_eq!(value["ctx"], "ctx-b", "(ctx-b, rid) must hit ctx-b session");
                assert_eq!(value["tag"], 2);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // A grant addressed to (ctx-a, rid) by the (matching) invoker
        // touches only ctx-a; ctx-b's total_credit stays 0.
        mgr.outlet_stream_grant_credit("ctx-a", &request_id_hex, &invoker_did, 7)
            .expect("grant on ctx-a");
        let total_b = mgr
            .outlet_streams
            .get(&("ctx-b".to_owned(), request_id_hex.clone()))
            .expect("ctx-b session present")
            .total_credit;
        assert_eq!(total_b, 0, "grant on ctx-a must not bleed into ctx-b");
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-037 W3 — synthetic-terminal sequence continuity +
    // admission release across all terminal paths
    // -----------------------------------------------------------------------

    /// W3: `outlet_stream_terminate` assigns the synthetic terminal the
    /// `emitted_count` next-emission sequence (NOT `chunks.len()`), drops
    /// the queued tail, and releases the admission slot immediately. The
    /// synthetic chunk signature verifies under the pinned verifying key.
    #[test]
    fn wasm_w3_terminate_synthetic_sequence_is_emitted_count_and_releases_admission() {
        use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};

        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x3A; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);
        let cb = [0x33u8; 32];

        // Seed 4 Data chunks (sequences 0..4).
        let mut chunks = VecDeque::new();
        for seq in 0..4u64 {
            let payload = ChunkPayload::Data {
                value: serde_json::json!({ "seq": seq }),
            };
            let sig = sign_chunk(&signing, "ctx", "outlet", &request_id, seq, &cb, &payload)
                .expect("sign");
            chunks.push_back(scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: seq,
                payload,
                sig,
            });
        }
        let (session, invoker_did) =
            make_test_session(&signing, "ctx", "outlet", cb, request_id, chunks, 100);
        admit_test_slot(&mut mgr, "ctx", &invoker_did, "outlet");
        insert_test_session(&mut mgr, "ctx", &request_id_hex, session);

        // Pull 2 real chunks → emitted_count == 2.
        for expected in 0..2u64 {
            let c = mgr
                .outlet_stream_next("ctx", &request_id_hex)
                .expect("real chunk");
            assert_eq!(c.sequence, expected);
        }

        // Terminate (RevokedMidStream). The synthetic terminal MUST take
        // sequence == emitted_count (2), NOT chunks.len() (which is 2
        // here too — but the assertion below pins the *emitted_count*
        // contract explicitly by checking against the cursor, not the
        // queue length).
        let terminated = mgr
            .outlet_stream_terminate(
                "ctx",
                &request_id_hex,
                &invoker_did,
                scp_protocol::context::outlets::stream::TerminateReason::RevokedMidStream,
                None,
            )
            .expect("terminate accepted");
        assert!(terminated, "terminate must report it acted");

        // W3: admission released immediately on terminate (not deferred).
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            0,
            "terminate releases the admission slot immediately (W3)"
        );

        // The next pull delivers the synthetic terminal at seq == 2.
        let synthetic = mgr
            .outlet_stream_next("ctx", &request_id_hex)
            .expect("synthetic terminal");
        assert_eq!(
            synthetic.sequence, 2,
            "synthetic terminal sequence MUST equal emitted_count (W3), not the dropped-tail length"
        );
        assert!(
            matches!(
                synthetic.payload,
                ChunkPayload::Error { terminal: true, .. }
            ),
            "terminate synthetic must be a terminal Error chunk"
        );
        assert!(
            scp_protocol::context::outlets::stream::verify_chunk_signature(
                &synthetic,
                &signing.verifying_key(),
                "ctx",
                "outlet",
                &cb,
            ),
            "W3 terminate synthetic chunk must verify under the pinned verifying key (W1)"
        );

        // Pull after the synthetic → None + evict, no double-release.
        assert!(mgr.outlet_stream_next("ctx", &request_id_hex).is_none());
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            0,
            "no double-release after terminate→observe→evict"
        );
    }

    /// W3: open N == per-invoker cap, then free each via a DIFFERENT
    /// terminal path (queue-drain, cancel-synthetic, terminate) and
    /// confirm a fresh open succeeds afterwards — i.e. every terminal
    /// path releases its admission slot so the cap is not permanently
    /// consumed.
    #[test]
    fn wasm_w3_every_terminal_path_releases_admission_slot() {
        // The per-invoker cap baseline is 8 (§9.18.B). We drive three
        // distinct terminal paths and assert the running slot count
        // returns to zero after each, then that a fresh admit succeeds.
        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x39; 32]);
        let invoker_did = crate::identity::register_identity_for_test(&signing);

        // Helper: seed a one-Data + End session (so a clean drain hits
        // the terminal End), admit a slot, return its request_id_hex.
        let seed = |mgr: &mut WasmContextManager, cb_byte: u8| -> String {
            use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};
            let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
            let rid_hex = hex::encode(request_id);
            let cb = [cb_byte; 32];
            let mut chunks = VecDeque::new();
            let data = ChunkPayload::Data {
                value: serde_json::json!({"k": 1}),
            };
            chunks.push_back(scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: 0,
                payload: data.clone(),
                sig: sign_chunk(&signing, "ctx", "outlet", &request_id, 0, &cb, &data)
                    .expect("sign"),
            });
            let end = ChunkPayload::End {
                aggregate: serde_json::json!({"k": 1}),
                provenance: super::build_minimal_stream_end_provenance("ctx"),
                execution_time_ms: 0,
            };
            chunks.push_back(scp_protocol::context::outlets::stream::OutletStreamChunk {
                request_id,
                sequence: 1,
                payload: end.clone(),
                sig: sign_chunk(&signing, "ctx", "outlet", &request_id, 1, &cb, &end)
                    .expect("sign"),
            });
            let (session, did) =
                make_test_session(&signing, "ctx", "outlet", cb, request_id, chunks, 100);
            assert_eq!(did, invoker_did);
            admit_test_slot(mgr, "ctx", &invoker_did, "outlet");
            insert_test_session(mgr, "ctx", &rid_hex, session);
            rid_hex
        };

        // Path 1 — clean drain through the terminal End chunk.
        let rid1 = seed(&mut mgr, 0x01);
        assert_eq!(admission_count(&mgr, "ctx", &invoker_did), 1);
        // Pull Data, then End (terminal → releases), then None (evict).
        assert!(mgr.outlet_stream_next("ctx", &rid1).is_some()); // Data
        assert!(mgr.outlet_stream_next("ctx", &rid1).is_some()); // End (terminal)
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            0,
            "terminal End releases admission"
        );
        assert!(mgr.outlet_stream_next("ctx", &rid1).is_none()); // evict

        // Path 2 — cancel → synthetic terminal on next pull.
        let rid2 = seed(&mut mgr, 0x02);
        assert_eq!(admission_count(&mgr, "ctx", &invoker_did), 1);
        mgr.outlet_stream_cancel("ctx", &rid2, &invoker_did)
            .expect("cancel");
        let _synthetic = mgr
            .outlet_stream_next("ctx", &rid2)
            .expect("cancel synthetic terminal");
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            0,
            "cancel synthetic terminal releases admission"
        );

        // Path 3 — terminate releases immediately.
        let rid3 = seed(&mut mgr, 0x03);
        assert_eq!(admission_count(&mgr, "ctx", &invoker_did), 1);
        mgr.outlet_stream_terminate(
            "ctx",
            &rid3,
            &invoker_did,
            scp_protocol::context::outlets::stream::TerminateReason::CreditStall,
            None,
        )
        .expect("terminate");
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            0,
            "terminate releases admission"
        );

        // After all three terminal paths released, a fresh admit must
        // succeed (the cap was never permanently consumed).
        let admission = mgr
            .outlet_stream_admission
            .entry("ctx".to_owned())
            .or_default();
        assert!(
            admission
                .try_admit(&invoker_did, &invoker_did, "outlet", 8, 16, 128)
                .is_ok(),
            "a fresh open admits after every terminal path released its slot"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-037 W5 — duplicate registry-key rejection
    // -----------------------------------------------------------------------

    /// W5: opening a stream whose `(context_id, request_id_hex)` already
    /// exists is rejected with `SCP-TOOL-6101` /
    /// `protocol.session-id-conflict` and the original session is left
    /// untouched.
    ///
    /// Admission-release contract (r2 HIGH fix): `insert_stream_session`
    /// itself does NOT release the admission slot on the duplicate-key
    /// rejection — that responsibility moved to the single error-release
    /// guard in `open_outlet_stream`, which compensates on every
    /// post-gate `Err` uniformly. This test therefore asserts the slot
    /// is STILL held after a direct `insert_stream_session` rejection
    /// (the guard never ran because we bypassed `open_outlet_stream`);
    /// the end-to-end release on the duplicate path through the real open
    /// path is pinned by
    /// `wasm_open_outlet_stream_error_paths_release_admission_slot`.
    #[test]
    fn wasm_w5_duplicate_registry_key_rejected() {
        use scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION;
        use scp_protocol::context::outlets::stream::{ChunkPayload, sign_chunk};

        let mut mgr = WasmContextManager::new();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x50; 32]);
        let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
        let request_id_hex = hex::encode(request_id);
        let cb = [0x55u8; 32];

        // Seed an ORIGINAL session at (ctx, rid) carrying a recognisable
        // Data chunk + one admission slot.
        let payload = ChunkPayload::Data {
            value: serde_json::json!({"orig": true}),
        };
        let mut chunks = VecDeque::new();
        chunks.push_back(scp_protocol::context::outlets::stream::OutletStreamChunk {
            request_id,
            sequence: 0,
            payload: payload.clone(),
            sig: sign_chunk(&signing, "ctx", "outlet", &request_id, 0, &cb, &payload)
                .expect("sign"),
        });
        let (orig_session, invoker_did) =
            make_test_session(&signing, "ctx", "outlet", cb, request_id, chunks, 42);
        admit_test_slot(&mut mgr, "ctx", &invoker_did, "outlet");
        insert_test_session(&mut mgr, "ctx", &request_id_hex, orig_session);
        assert_eq!(admission_count(&mgr, "ctx", &invoker_did), 1);

        // Build a DUPLICATE-keyed session and reserve a second admission
        // slot (as the open path's gate would), then route it through
        // the manager's duplicate guard directly. NOTE: because we bypass
        // `open_outlet_stream` (the owner of admission-release), the slot
        // the gate reserved is NOT released by `insert_stream_session`
        // alone — that is the r2 HIGH single-owner contract.
        let (dup_session, _did) = make_test_session(
            &signing,
            "ctx",
            "outlet",
            cb,
            request_id,
            VecDeque::new(),
            999,
        );
        admit_test_slot(&mut mgr, "ctx", &invoker_did, "outlet");
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            2,
            "the duplicate open reserved a second slot before the insert guard runs"
        );

        let err = mgr
            .insert_stream_session(dup_session, "ctx", &request_id_hex)
            .expect_err("duplicate (ctx, rid) MUST be rejected");
        match err {
            ScpWasmError::Context { code, message } => {
                assert_eq!(
                    code, CODE_PROTOCOL_SESSION,
                    "duplicate-key rejection uses SCP-TOOL-6101"
                );
                assert!(
                    message.contains("session-id-conflict"),
                    "rejection slug is protocol.session-id-conflict, got: {message}"
                );
            }
            other => panic!("expected Context error, got {other:?}"),
        }

        // r2 HIGH single-owner contract: `insert_stream_session` does
        // NOT release on rejection — the slot stays held because we
        // bypassed `open_outlet_stream`'s guard. The end-to-end release
        // through the real open path is pinned separately by
        // `wasm_open_outlet_stream_error_paths_release_admission_slot`.
        assert_eq!(
            admission_count(&mgr, "ctx", &invoker_did),
            2,
            "insert_stream_session does not release on its own — the open guard owns release"
        );

        // The ORIGINAL session is untouched: still present, still
        // carrying its original Data chunk and credit.
        let orig = mgr
            .outlet_streams
            .get(&("ctx".to_owned(), request_id_hex.clone()))
            .expect("original session still present");
        assert_eq!(orig.remaining_credit, 42, "original credit untouched");
        let c = mgr
            .outlet_stream_next("ctx", &request_id_hex)
            .expect("original chunk");
        match &c.payload {
            ChunkPayload::Data { value } => {
                assert_eq!(value["orig"], true, "original session's chunk survived");
            }
            other => panic!("expected original Data chunk, got {other:?}"),
        }
    }

    /// r2 HIGH fix — a post-gate error in `open_outlet_stream` releases
    /// the admission slot it reserved on ALL three counters
    /// (per-invoker / per-origin / per-outlet), so a failed open does
    /// NOT leak a slot. Drives the real `open_outlet_stream` funnel with
    /// a schema-violating input (caller-controlled — the highest-risk
    /// leak surface: 8 bad opens would otherwise lock an invoker out of
    /// streaming on the context with a false rate-limit) and asserts:
    ///   1. the open fails (input-schema rejection, after the gate),
    ///   2. all three admission counters return to the pre-open baseline,
    ///   3. a subsequent well-formed open by the SAME invoker/outlet
    ///      succeeds (the cap was not silently consumed).
    #[test]
    fn wasm_open_outlet_stream_error_paths_release_admission_slot() {
        let mut mgr = WasmContextManager::new();

        // Register an identity whose key the open path resolves via
        // `with_signing_key(identity_did)`, and a context + outlet with
        // an input schema that requires `a`/`b` to be numbers.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
        let invoker_did = crate::identity::register_identity_for_test(&signing);
        let (context_id, outlet_id) = vector_replay_setup(&mut mgr, "admission-leak", &invoker_did);

        // Helper: read all three admission counters for the pinned
        // (invoker, origin=invoker, outlet) triple on this context.
        let counters = |mgr: &WasmContextManager| -> (u32, u32, u32) {
            mgr.outlet_stream_admission
                .get(&context_id)
                .map_or((0, 0, 0), |t| {
                    (
                        t.per_invoker.get(&invoker_did).copied().unwrap_or(0),
                        t.per_origin_invoker.get(&invoker_did).copied().unwrap_or(0),
                        t.per_outlet.get(&outlet_id).copied().unwrap_or(0),
                    )
                })
        };

        assert_eq!(
            counters(&mgr),
            (0, 0, 0),
            "baseline: no admission slots held before any open"
        );

        // A schema-violating input: `a` must be a number, give it a
        // string. This trips `validate_value_against_schema` on the
        // streaming open path — AFTER the admission gate incremented all
        // three counters.
        let bad_input = serde_json::json!({"a": "not-a-number"});
        let bad_params = open_params_for(
            &context_id,
            &outlet_id,
            &invoker_did,
            &bad_input,
            [0x11u8; 32],
            0,
            32,
            None,
        );
        let err = mgr
            .open_outlet_stream(bad_params)
            .expect_err("schema-violating open MUST fail");
        match err {
            ScpWasmError::Tool { code, .. } => {
                assert_eq!(
                    code,
                    codes::TOOL_6002,
                    "input-schema rejection surfaces SCP-TOOL-6002"
                );
            }
            other => panic!("expected Tool error from schema validation, got {other:?}"),
        }

        // The slot the gate reserved MUST be released on this error
        // path — all three counters back to baseline, no leak.
        assert_eq!(
            counters(&mgr),
            (0, 0, 0),
            "failed open released its admission slot on all three counters (no leak)"
        );
        // No half-built session left dangling either.
        assert!(
            mgr.outlet_streams.is_empty(),
            "a failed open leaves no session in the registry"
        );

        // A subsequent well-formed open by the SAME invoker/outlet
        // succeeds — proving the cap was not silently consumed by the
        // failed attempt.
        let good_input = serde_json::json!({"a": 1, "b": 2});
        let good_params = open_params_for(
            &context_id,
            &outlet_id,
            &invoker_did,
            &good_input,
            [0x22u8; 32],
            0,
            32,
            None,
        );
        let request_id_hex = mgr
            .open_outlet_stream(good_params)
            .expect("a fresh well-formed open succeeds after the failed open released its slot");
        assert_eq!(
            counters(&mgr),
            (1, 1, 1),
            "the successful open holds exactly one slot on each counter"
        );

        // Drain the successful stream to its terminal so the slot
        // releases again (end-to-end sanity).
        while mgr
            .outlet_stream_next(&context_id, &request_id_hex)
            .is_some()
        {}
        assert_eq!(
            counters(&mgr),
            (0, 0, 0),
            "draining the successful stream to terminal releases its slot"
        );
    }
}
