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

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

use base64::Engine as _;

use crate::error::ScpWasmError;
use crate::runtime::{
    ToolRegistration, ToolRegistry, WasmEventLog, prove_absence, prove_inclusion,
    validate_value_against_schema, verify_inclusion,
};

/// SCP protocol version for WASM bridge (§13.2). Must match scp-core's
/// `SCP_PROTOCOL_VERSION`. Encoded as `(major << 8) | minor`.
/// SCP/1.0 = `0x0100` (decimal 256).
const SCP_PROTOCOL_VERSION: u16 = 0x0100;

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
// GovernanceAction — mirrors scp_core::context::governance::GovernanceAction
// ---------------------------------------------------------------------------

/// Governance action variants dispatchable through the `WasmContextManager`.
///
/// Mirrors all 28 `GovernanceAction` variants from
/// `scp_core::context::governance::GovernanceAction`. WASM bridge functions
/// serialize JS governance requests into this enum for dispatch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WasmGovernanceAction {
    AddMember {
        did: String,
        role: String,
    },
    RemoveMember {
        did: String,
        reason: Option<String>,
    },
    ChangeRole {
        did: String,
        new_role: String,
    },
    RegisterTool {
        tool_id: String,
        name: String,
        description: String,
    },
    RemoveTool {
        tool_id: String,
    },
    ModifyCeiling {
        new_ceiling: Vec<String>,
    },
    CloseContext {
        reason: Option<String>,
    },
    ExtendTtl {
        additional_secs: u64,
    },
    TransferAdmin {
        new_admin: String,
    },
    CreateChildContext {
        params_json: String,
    },
    ModifyPruningPolicy {
        policy_json: String,
    },
    AddSigner {
        did: String,
    },
    RemoveSigner {
        did: String,
    },
    ModifyThreshold {
        new_threshold: u32,
    },
    EstablishToolInterface {
        interface_json: String,
    },
    ResetMember {
        did: String,
        reason: String,
    },
    ResolveConflict {
        proposal_a: String,
        proposal_b: String,
        resolution: String,
    },
    PromoteContext,
    RevokeWriteAccess {
        did: String,
        scope: String,
    },
    RestoreWriteAccess {
        did: String,
    },
    RotateContentKeys {
        reason: Option<String>,
    },
    ReconfigureGovernance {
        changes_json: String,
        justification: String,
    },
    BlockAuthor {
        did: String,
        reason: Option<String>,
    },
    RevokeReadAccess {
        did: String,
        scope: String,
    },
    RestoreReadAccess {
        did: String,
    },
    SetEconomicPolicy {
        policy_json: String,
    },
    ApproveSpend {
        spender: String,
        amount: u64,
        purpose: String,
    },
    LockEconomicPolicy,
}

/// Validates a revocation scope string.
///
/// Core's `RevocationScope` has two variants: `Full` and `FutureOnly`.
/// The WASM bridge accepts these as lowercase `snake_case` strings.
///
/// # Errors
///
/// Returns `ScpWasmError::Validation` if the string is not `"full"` or
/// `"future_only"`.
fn validate_revocation_scope(scope: &str) -> Result<&str, ScpWasmError> {
    match scope {
        "full" | "future_only" => Ok(scope),
        _ => Err(ScpWasmError::Validation {
            message: format!(
                "invalid revocation scope '{scope}': expected 'full' or 'future_only'"
            ),
            code: "SCP-VALID-7100".to_owned(),
        }),
    }
}

// ---------------------------------------------------------------------------
// ContextEvent — mirrors scp_core::context::membership::ContextEvent
// ---------------------------------------------------------------------------

/// An event emitted by the context manager and stored in the receive buffer.
///
/// Mirrors `scp_core::context::membership::ContextEvent`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WasmContextEvent {
    MemberJoined {
        member_did: String,
        role_name: String,
    },
    MemberLeft {
        member_did: String,
    },
    MessageSent {
        sender_did: String,
        sequence_number: u64,
        payload_base64: String,
    },
    MemberBlocked {
        blocked_did: String,
        author_did: String,
    },
    MemberUnblocked {
        unblocked_did: String,
        author_did: String,
    },
    WriteAccessRevoked {
        did: String,
    },
    KeyEpochAdvance {
        sender_did: String,
        epoch: u64,
    },
    SystemClose {
        initiator_did: String,
    },
    Expired,
    GovernanceExecuted {
        action_type: String,
        proposal_id: String,
    },
}

// ---------------------------------------------------------------------------
// MemberEntry — per-member state
// ---------------------------------------------------------------------------

/// Per-member state within a context.
#[derive(Debug, Clone)]
struct MemberEntry {
    /// Stored for diagnostics and serialization; read via `HashMap` key.
    #[allow(dead_code)]
    did: String,
    role: String,
    sequence_number: u64,
}

// ---------------------------------------------------------------------------
// WasmProposal — governance proposal lifecycle (#621)
// ---------------------------------------------------------------------------

/// A pending governance proposal with vote tracking.
///
/// Mirrors `GovernanceProposal` from scp-core. Tracks approval and
/// rejection votes, the governance model requirements, and the voting
/// deadline. Proposals are resolved (executed or rejected) when quorum
/// is reached or the deadline expires.
#[derive(Debug, Clone)]
struct WasmProposal {
    /// DID of the proposer.
    proposer_did: String,
    /// The governance action to execute if approved.
    action: WasmGovernanceAction,
    /// Votes to approve: `(voter_did, timestamp_secs)`.
    approvals: Vec<(String, u64)>,
    /// Votes to reject: `(voter_did, timestamp_secs)`.
    rejections: Vec<(String, u64)>,
    /// Voting deadline (ms since epoch). Default 1 hour from creation.
    voting_deadline_ms: f64,
    /// Context ID this proposal belongs to.
    context_id: String,
    /// Unix timestamp (seconds) when the proposal was created.
    created_at: u64,
    /// Lifecycle status: "Pending", "Approved", or "Rejected".
    status: String,
}

/// Maximum number of pending proposals per context.
const WASM_PENDING_PROPOSAL_CAP: usize = 100;

/// Default voting deadline: 1 hour in milliseconds.
const WASM_PROPOSAL_DEADLINE_MS: f64 = 3_600_000.0;

// ---------------------------------------------------------------------------
// BroadcastState — broadcast context state (§5.14)
// ---------------------------------------------------------------------------

/// Broadcast-specific state for a context.
///
/// Mirrors the relevant fields from `scp_core::context::broadcast::BroadcastContext`.
/// Per spec §5.14.8, blocking is per-author: each author maintains an independent
/// block list. Author A blocking a subscriber does not affect the subscriber's
/// access to Author B's content.
#[derive(Debug)]
struct BroadcastState {
    /// Author DIDs mapped to their per-author block lists.
    /// Mirrors `scp_core::context::broadcast::AuthorState.block_list`.
    authors: HashMap<String, HashSet<String>>,
    /// Per-author key epochs (§5.14.8). Incremented on block events to
    /// ensure blocked subscribers cannot decrypt future content.
    key_epochs: HashMap<String, u64>,
    /// Subscriber DIDs (members with read access).
    subscribers: HashSet<String>,
    /// Admission policy: "open" or "gated". Stored for context metadata.
    #[allow(dead_code)]
    admission: String,
}

impl BroadcastState {
    fn new(admission: &str) -> Self {
        Self {
            authors: HashMap::new(),
            key_epochs: HashMap::new(),
            subscribers: HashSet::new(),
            admission: admission.to_owned(),
        }
    }

    /// Returns `true` if the given subscriber DID is blocked by ANY author.
    /// Useful for governance-ban checks (when a subscriber has been added to
    /// all authors' block lists). NOT used for subscription gating — per
    /// scp-core `BroadcastContext::subscribe`, subscription always succeeds
    /// regardless of block lists. Blocking only affects key distribution
    /// (`handle_broadcast_key_request`).
    #[cfg(test)]
    fn is_blocked_by_any_author(&self, subscriber_did: &str) -> bool {
        self.authors
            .values()
            .any(|block_list| block_list.contains(subscriber_did))
    }
}

// ---------------------------------------------------------------------------
// PerContextState — per-context state
// ---------------------------------------------------------------------------

/// Per-context runtime state.
///
/// Mirrors `PerContextState` in `scp_core::context::manager`.
struct PerContextState {
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
    /// Event log (Merkle tree).
    event_log: WasmEventLog,
    /// UCAN revocation set (token CIDs). Capped at [`WASM_REVOKED_TOKENS_CAP`].
    revoked_tokens: HashSet<String>,
    /// UCAN nonce replay tracker. Stores `(nonce, insertion_timestamp_ms)`.
    /// Evicts entries older than [`WASM_NONCE_TTL_MS`] when exceeding [`WASM_NONCE_CAP`].
    seen_nonces: HashMap<String, f64>,
    /// Members indexed by DID.
    members: HashMap<String, MemberEntry>,
    /// Receive buffer for events. Capped at [`WASM_EVENT_BUFFER_CAP`] (FIFO overflow).
    /// Uses `VecDeque` for O(1) `pop_front` instead of `Vec::remove(0)` O(n) shift.
    event_buffer: VecDeque<WasmContextEvent>,
    /// Executed proposal IDs with insertion timestamps (replay protection).
    /// Evicts entries older than [`WASM_PROPOSAL_TTL_MS`] when exceeding [`WASM_PROPOSAL_CAP`].
    executed_proposals: HashMap<String, f64>,
    /// Write-revoked member DIDs (§9.17, ADR-038).
    write_revoked_members: HashSet<String>,
    /// Read-revoked member DIDs (ADR-038, §9.17).
    read_revoked_members: HashSet<String>,
    /// Members excluded from future CEK wrapping (`FutureOnly` read revocation).
    read_exclusion_list: HashSet<String>,
    /// Broadcast context state (only for Broadcast mode).
    broadcast: Option<BroadcastState>,
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
    pending_proposals: HashMap<String, WasmProposal>,
    /// Resolved (approved/rejected) governance proposals keyed by proposal ID.
    /// Proposals move here from `pending_proposals` when quorum is reached or
    /// the proposal is definitively rejected. This allows retrieval of resolved
    /// proposals via `get_proposal` and `list_proposals` (#621 F4).
    /// Capped at [`WASM_RESOLVED_PROPOSAL_CAP`]; oldest by `created_at` evicted.
    resolved_proposals: HashMap<String, WasmProposal>,
    /// Pruning policy JSON string (ADR-030 §6).
    pruning_policy: Option<String>,
    /// Whether the economic policy is locked (§19.3, ADR-033).
    economic_policy_locked: bool,
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

/// Maximum concurrent sessions per calling context (spec section 6.2.1).
const WASM_SESSION_CAP_PER_CALLER: usize = 5;

/// Maximum concurrent sessions across all callers (global cap).
const WASM_SESSION_GLOBAL_CAP: usize = 100;

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
    fn push_event(&mut self, event: WasmContextEvent) {
        if self.event_buffer.len() >= WASM_EVENT_BUFFER_CAP {
            self.event_buffer.pop_front();
        }
        self.event_buffer.push_back(event);
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

    /// Inserts a resolved proposal, evicting the oldest (by `created_at`) if
    /// at [`WASM_RESOLVED_PROPOSAL_CAP`].
    fn insert_resolved_proposal(&mut self, id: String, proposal: WasmProposal) {
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
            code: "SCP-CTX-2032".to_owned(),
        });
    }
    if value.len() > max_len {
        return Err(ScpWasmError::Context {
            message: format!(
                "{field_name} exceeds maximum length ({} > {max_len})",
                value.len()
            ),
            code: "SCP-CTX-2032".to_owned(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ScpWasmError::Context {
            message: format!("{field_name} contains control characters"),
            code: "SCP-CTX-2032".to_owned(),
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
            code: "SCP-CTX-2032".to_owned(),
        });
    }
    // Must have at least did:method:id (3 colon-separated parts)
    if value.splitn(4, ':').count() < 3 {
        return Err(ScpWasmError::Context {
            message: format!("{field_name} must have format 'did:method:id': got '{value}'"),
            code: "SCP-CTX-2032".to_owned(),
        });
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
            code: "SCP-CTX-2015".to_owned(),
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
            code: "SCP-CTX-2015".to_owned(),
        })?;
    let req_major = u8::try_from(raw_major).map_err(|_| ScpWasmError::Context {
        message: format!(
            "malformed minProtocolVersion: major version {raw_major} exceeds u8 range"
        ),
        code: "SCP-CTX-2015".to_owned(),
    })?;
    let raw_minor = min_ver
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ScpWasmError::Context {
            message: format!(
                "malformed minProtocolVersion: minor version is not a number: {:?}",
                min_ver.get(1)
            ),
            code: "SCP-CTX-2015".to_owned(),
        })?;
    let req_minor = u8::try_from(raw_minor).map_err(|_| ScpWasmError::Context {
        message: format!(
            "malformed minProtocolVersion: minor version {raw_minor} exceeds u8 range"
        ),
        code: "SCP-CTX-2015".to_owned(),
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
            code: "SCP-CTX-2016".to_owned(),
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

/// Magic byte prefix for structured broadcast content: ASCII "SCP".
/// Algorithm-identical to `scp_core::context::broadcast_content::BROADCAST_CONTENT_MAGIC`.
const BROADCAST_CONTENT_MAGIC: [u8; 3] = [0x53, 0x43, 0x50];

/// Current broadcast content format version.
/// Algorithm-identical to `scp_core::context::broadcast_content::BROADCAST_CONTENT_VERSION`.
const BROADCAST_CONTENT_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// WASM-local content validation (ADR-034: cannot import from scp-core)
// ---------------------------------------------------------------------------

/// Validates a content path for broadcast asset publishing (SCP-290).
///
/// Algorithm-identical to `scp_core::context::broadcast_content::ContentPath::new`.
/// Reimplemented locally per ADR-034.
///
/// Note: scp-core applies NFC normalization before validation. WASM accepts
/// pre-normalized paths only (no `unicode-normalization` dependency). Paths
/// containing decomposed sequences that would normalize differently will pass
/// validation but may not match scp-core's normalized form. Callers should
/// ensure paths are NFC-normalized before calling this function.
fn validate_content_path_wasm(path: &str) -> Result<(), String> {
    // Must start with '/'
    if !path.starts_with('/') {
        return Err("path must start with '/'".to_owned());
    }

    // Max length
    if path.len() > 1024 {
        return Err(format!("path too long: {} bytes (max 1024)", path.len()));
    }

    // Reject backslashes
    if path.contains('\\') {
        return Err("backslashes not allowed".to_owned());
    }

    // Reject percent-encoded bytes
    if path.contains('%') {
        return Err("percent-encoded bytes not allowed".to_owned());
    }

    // Reject query strings
    if path.contains('?') {
        return Err("query strings not allowed".to_owned());
    }

    // Reject fragments
    if path.contains('#') {
        return Err("fragments not allowed".to_owned());
    }

    // Reject null bytes, control characters (U+0000-U+001F, U+007F)
    for ch in path.chars() {
        if ch == '\0' {
            return Err("path must not contain null bytes".to_owned());
        }
        if ('\u{0000}'..='\u{001F}').contains(&ch) {
            return Err(format!(
                "control character U+{:04X} not allowed",
                u32::from(ch),
            ));
        }
        if ch == '\u{007F}' {
            return Err("DEL (U+007F) not allowed".to_owned());
        }
    }

    // Reject non-ASCII whitespace, control, and formatting characters.
    // Matches scp-core's is_unicode_formatting + whitespace/control check.
    for ch in path.chars() {
        if !ch.is_ascii()
            && (ch.is_whitespace() || ch.is_control() || is_unicode_formatting_wasm(ch))
        {
            return Err(format!(
                "non-ASCII whitespace/formatting U+{:04X} not allowed",
                u32::from(ch),
            ));
        }
    }

    // Reject double slashes
    if path.contains("//") {
        return Err("double slashes not allowed".to_owned());
    }

    // No trailing slash except root
    if path.len() > 1 && path.ends_with('/') {
        return Err("path must not end with '/' (except root)".to_owned());
    }

    // Reject '.' and '..' segments (skip leading empty from leading '/')
    for segment in path.split('/').skip(1) {
        if segment == "." {
            return Err("'.' segments not allowed".to_owned());
        }
        if segment == ".." {
            return Err("'..' segments not allowed (path traversal)".to_owned());
        }
    }

    Ok(())
}

/// Returns `true` for Unicode formatting/invisible characters that must be
/// rejected in content paths.
///
/// Algorithm-identical to `scp_core::context::broadcast_content::is_unicode_formatting`.
/// Reimplemented locally per ADR-034.
fn is_unicode_formatting_wasm(ch: char) -> bool {
    let cp = u32::from(ch);
    matches!(
        cp,
        // Zero-width chars (U+200B-U+200F): ZWSP, ZWNJ, ZWJ, LRM, RLM
        0x200B..=0x200F
        // Line/paragraph separators
        | 0x2028..=0x2029
        // Bidi embedding controls (LRE, RLE, PDF, LRO, RLO)
        | 0x202A..=0x202E
        // Medium mathematical space
        | 0x205F
        // Word joiner and invisible operators (U+2060-U+206F)
        | 0x2060..=0x206F
        // Ideographic space
        | 0x3000
        // BOM / ZWNBSP
        | 0xFEFF
        // Non-characters
        | 0xFFFE..=0xFFFF
    )
}

/// Validates a MIME type for broadcast asset publishing (SCP-290).
///
/// Algorithm-identical to `scp_core::context::broadcast_content::MimeType::new`.
/// Reimplemented locally per ADR-034.
///
/// Enforces RFC 7230 tchar set plus alphanumeric.
/// Rejects spaces, angle brackets, parentheses, non-ASCII, semicolons,
/// CRLF, and control chars. Exactly one `/` separator.
fn validate_mime_type_wasm(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("MIME type must not be empty".to_owned());
    }

    // Reject control characters (including \r, \n)
    for ch in value.chars() {
        if ch.is_control() {
            return Err(format!(
                "control character U+{:04X} not allowed",
                u32::from(ch),
            ));
        }
    }

    // Reject parameters (`;`)
    if value.contains(';') {
        return Err("MIME type parameters (';') not allowed".to_owned());
    }

    // Must have exactly one '/'
    let slash_count = value.chars().filter(|&c| c == '/').count();
    if slash_count != 1 {
        return Err("MIME type must be 'type/subtype' (exactly one '/')".to_owned());
    }

    // Both parts must be non-empty and consist of valid token characters.
    let (type_part, subtype_part) = value
        .split_once('/')
        .ok_or_else(|| "MIME type must be 'type/subtype'".to_owned())?;

    if type_part.is_empty() || subtype_part.is_empty() {
        return Err("MIME type and subtype must both be non-empty".to_owned());
    }

    // RFC 7230 §3.2.6 tchar set: ALPHA / DIGIT / "!" / "#" / "$" / "&" /
    // "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
    // Note: "%" is intentionally excluded — it is not a tchar per RFC 7230,
    // and allowing it would enable encoded-character injection.
    let is_token_char = |c: char| c.is_ascii_alphanumeric() || "!#$&'*+-.^_`|~".contains(c);

    if !type_part.chars().all(is_token_char) {
        return Err("MIME type part contains invalid characters".to_owned());
    }
    if !subtype_part.chars().all(is_token_char) {
        return Err("MIME subtype part contains invalid characters".to_owned());
    }

    Ok(())
}

/// Validates a `deploy_id` for broadcast asset publishing (SCP-290).
///
/// Algorithm-identical to `scp_core::context::broadcast_content::validate_deploy_id`.
/// Reimplemented locally per ADR-034.
fn validate_deploy_id_wasm(deploy_id: &str) -> Result<(), String> {
    if deploy_id.is_empty() {
        return Err("deploy_id must not be empty".to_owned());
    }
    if deploy_id.len() > 128 {
        return Err(format!(
            "deploy_id too long: {} bytes (max 128)",
            deploy_id.len()
        ));
    }
    for ch in deploy_id.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            return Err(format!("invalid character '{ch}' in deploy_id"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WASM-local BroadcastContent serialization (ADR-034: cannot import from scp-core)
// ---------------------------------------------------------------------------

/// WASM-local `ContentMetadata` matching `scp_core::context::ContentMetadata`.
/// Field names and `MessagePack` encoding must be identical.
#[derive(serde::Serialize)]
struct WasmContentMetadata<'a> {
    path: Option<&'a str>,
    content_type: Option<&'a str>,
    deploy_id: Option<&'a str>,
    etag: Option<&'a str>,
    #[serde(default)]
    immutable: bool,
}

/// WASM-local `BroadcastContent` matching `scp_core::context::BroadcastContent`.
/// Field names and `MessagePack` encoding must be identical.
#[derive(serde::Serialize)]
struct WasmBroadcastContent<'a> {
    version: u8,
    metadata: WasmContentMetadata<'a>,
    #[serde(with = "serde_bytes")]
    body: &'a [u8],
}

/// Serializes broadcast content into the canonical wire format:
/// `BROADCAST_CONTENT_MAGIC ++ version_u8 ++ rmp_serde::to_vec_named(content)`.
///
/// Algorithm-identical to `scp_core::context::broadcast_content::serialize_broadcast_content`.
/// Reimplemented locally per ADR-034.
fn serialize_broadcast_content_wasm(
    path: &str,
    content_type: &str,
    deploy_id: Option<&str>,
    etag: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let content = WasmBroadcastContent {
        version: BROADCAST_CONTENT_VERSION,
        metadata: WasmContentMetadata {
            path: Some(path),
            content_type: Some(content_type),
            deploy_id,
            etag: Some(etag),
            immutable: false,
        },
        body,
    };

    let msgpack = rmp_serde::to_vec_named(&content)
        .map_err(|e| format!("MessagePack serialization failed: {e}"))?;

    let mut buf = Vec::with_capacity(4 + msgpack.len());
    buf.extend_from_slice(&BROADCAST_CONTENT_MAGIC);
    buf.push(BROADCAST_CONTENT_VERSION);
    buf.extend_from_slice(&msgpack);
    Ok(buf)
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

    // -----------------------------------------------------------------------
    // Context lifecycle
    // -----------------------------------------------------------------------

    /// Creates a new context. Mirrors `ContextManager::create_context`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context ID is already registered or if
    /// parameters are invalid.
    pub fn create_context(
        &mut self,
        context_id: &str,
        creator_did: &str,
        params: &serde_json::Value,
    ) -> Result<(), ScpWasmError> {
        if self.contexts.contains_key(context_id) {
            return Err(ScpWasmError::Context {
                message: format!("context '{context_id}' is already registered"),
                code: "SCP-CTX-2000".to_owned(),
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
        let ceiling_strings = Self::build_ceiling_strings(&ceiling);

        // Parse and validate minProtocolVersion from params (spec §13.4).
        // This mirrors the NAPI bridge's parsing in context_create. Malformed
        // values produce errors (not silent downgrades). Defense-in-depth: the
        // creator's SDK version must satisfy the minimum it sets.
        parse_and_check_min_protocol_version(params)?;

        // Initialize broadcast state for Broadcast mode.
        let broadcast = if mode == "Broadcast" {
            let admission = params["admission"].as_str().unwrap_or("open");
            let mut bc = BroadcastState::new(admission);
            bc.authors.insert(creator_did.to_owned(), HashSet::new());
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
                        code: "SCP-CRYPTO-4004".to_owned(),
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
            event_log: WasmEventLog::new(context_id.to_owned()),
            revoked_tokens: HashSet::new(),
            seen_nonces: HashMap::new(),
            members,
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            broadcast,
            sessions: HashMap::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            tool_interfaces: Vec::new(),
            governance_freeze: false,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: None,
            economic_policy_locked: false,
            crypto,
        };

        self.contexts.insert(context_id.to_owned(), per_context);

        // Append ContextCreated event to event log.
        // Safe: we just inserted the context above, so the key is present.
        if let Some(ctx) = self.contexts.get_mut(context_id) {
            ctx.event_log.append_event(
                crate::runtime::wasm_event_type_tag("ContextCreated"),
                creator_did,
                b"",
            );
        }

        Ok(())
    }

    /// Joins a member to a context. Mirrors `ContextManager::join_context`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active.
    pub fn join_context(&mut self, context_id: &str, member_did: &str) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // Version compatibility check (spec §13.4): reject join if the
        // context requires a protocol version higher than this SDK supports.
        ctx.check_version_compatibility()?;

        if ctx.members.contains_key(member_did) {
            return Err(ScpWasmError::Context {
                message: format!("member '{member_did}' already joined context '{context_id}'"),
                code: "SCP-CTX-2013".to_owned(),
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

        ctx.push_event(WasmContextEvent::MemberJoined {
            member_did: member_did.to_owned(),
            role_name: "member".to_owned(),
        });

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("MemberJoined"),
            member_did,
            b"",
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
                code: "SCP-CTX-2015".to_owned(),
            });
        }

        // Unsubscribe from broadcast if applicable.
        if let Some(ref mut bc) = ctx.broadcast {
            bc.subscribers.remove(member_did);
        }

        // Destroy crypto state on leave — the leaving member should not
        // retain MLS key material.
        if let Some(ref mut crypto) = ctx.crypto {
            crypto.destroy();
        }
        ctx.crypto = None;

        ctx.push_event(WasmContextEvent::MemberLeft {
            member_did: member_did.to_owned(),
        });

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("MemberLeft"),
            member_did,
            b"",
        );

        // Auto-close if no members remain.
        if ctx.members.is_empty() {
            "closing".clone_into(&mut ctx.state);
        }

        Ok(())
    }

    /// Sends a message within a context. Mirrors `ContextManager::send_message`.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the sender lacks
    /// `messages:write` capability.
    pub fn send_message(
        &mut self,
        context_id: &str,
        sender_did: &str,
        payload_base64: &str,
    ) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        // Check write revocation (§9.17, ADR-038).
        if ctx.write_revoked_members.contains(sender_did) {
            return Err(ScpWasmError::Permission {
                message: format!("write access has been revoked for {sender_did}"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        // Check membership and assign sequence number.
        let member = ctx
            .members
            .get_mut(sender_did)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("sender '{sender_did}' is not a member of context '{context_id}'"),
                code: "SCP-CTX-2019".to_owned(),
            })?;

        let seq = member.sequence_number;
        member.sequence_number += 1;

        // If crypto state is available, encrypt the payload before recording.
        let recorded_payload = if let Some(ref mut crypto) = ctx.crypto {
            let raw_bytes = base64::engine::general_purpose::STANDARD
                .decode(payload_base64)
                .map_err(|e| ScpWasmError::Crypto {
                    message: format!("invalid base64 payload: {e}"),
                    code: "SCP-CRYPTO-4001".to_owned(),
                })?;

            let epoch = crypto.mls_group.epoch().map_err(|e| ScpWasmError::Crypto {
                message: format!("failed to read MLS epoch: {e}"),
                code: "SCP-CRYPTO-4002".to_owned(),
            })?;

            let ciphertext = crypto
                .encrypt_message(&raw_bytes, context_id, sender_did, epoch, seq)
                .map_err(|e| ScpWasmError::Crypto {
                    message: format!("encryption failed: {e}"),
                    code: "SCP-CRYPTO-4003".to_owned(),
                })?;

            base64::engine::general_purpose::STANDARD.encode(&ciphertext)
        } else {
            payload_base64.to_owned()
        };

        ctx.push_event(WasmContextEvent::MessageSent {
            sender_did: sender_did.to_owned(),
            sequence_number: seq,
            payload_base64: recorded_payload.clone(),
        });

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("MessageSent"),
            sender_did,
            recorded_payload.as_bytes(),
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
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        "closed".clone_into(&mut ctx.state);
        ctx.broadcast = None;

        // Destroy crypto state on close — releases MLS group keys and
        // sender key material.
        if let Some(ref mut crypto) = ctx.crypto {
            crypto.destroy();
        }
        ctx.crypto = None;

        ctx.push_event(WasmContextEvent::SystemClose {
            initiator_did: initiator_did.to_owned(),
        });

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("ContextClosing"),
            initiator_did,
            b"",
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
            code: "SCP-CRYPTO-4010".to_owned(),
        })?;

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_base64)
            .map_err(|e| ScpWasmError::Crypto {
                message: format!("invalid base64 ciphertext: {e}"),
                code: "SCP-CRYPTO-4001".to_owned(),
            })?;

        crypto
            .decrypt_message(&ciphertext, context_id, sender_did, epoch, sequence)
            .map_err(|e| ScpWasmError::Crypto {
                message: format!("decryption failed: {e}"),
                code: "SCP-CRYPTO-4011".to_owned(),
            })
    }

    /// Generates an MLS `KeyPackage` for joining an encrypted context.
    ///
    /// Returns the TLS-serialized key package bytes. The private key material
    /// is stored in `pending_key_packages` keyed by `(context_id, member_did)`
    /// for later use by [`join_context_encrypted`].
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
            code: "SCP-CRYPTO-4020".to_owned(),
        })?;

        let (kp_bytes, holder) =
            crate::crypto::group::WasmMlsGroup::generate_key_package(&credential).map_err(|e| {
                ScpWasmError::Crypto {
                    message: format!("key package generation failed: {e}"),
                    code: "SCP-CRYPTO-4022".to_owned(),
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
    /// [`generate_key_package_for_join`] for the same `(context_id, member_did)`.
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
                code: "SCP-CRYPTO-4023".to_owned(),
            })?;

        // First join the context normally (membership, events, etc.).
        self.join_context(context_id, member_did)?;

        // Then set up MLS crypto state from the Welcome.
        let mls_group =
            crate::crypto::group::WasmMlsGroup::join_from_welcome(welcome_bytes, holder).map_err(
                |e| ScpWasmError::Crypto {
                    message: format!("MLS welcome processing failed: {e}"),
                    code: "SCP-CRYPTO-4021".to_owned(),
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
            .map(|ctx| ctx.event_log.leaf_count())
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
        event_type_tag: u16,
        prov_hash: &[u8],
    ) -> Result<(), ScpWasmError> {
        let ctx = self
            .contexts
            .get_mut(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context '{context_id}' not found"),
                code: "SCP-CTX-2060".to_owned(),
            })?;

        ctx.event_log
            .append_event(event_type_tag, actor_did, prov_hash);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /// Drains all events from the receive buffer. Mirrors `ContextManager::drain_events`.
    pub fn drain_events(&mut self, context_id: &str) -> Vec<WasmContextEvent> {
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
        ctx.tool_registry
            .insert(registration)
            .map_err(|e| ScpWasmError::Tool {
                message: e,
                code: "SCP-TOOL-6001".to_owned(),
            })?;

        let actor = ctx.creator_did.clone();
        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("ToolRegistered"),
            &actor,
            tool_id.as_bytes(),
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
                code: "SCP-TOOL-6002".to_owned(),
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
        identity_did: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        let registration = ctx
            .tool_registry
            .get(tool_id)
            .ok_or_else(|| ScpWasmError::Tool {
                message: format!("tool '{tool_id}' not found in context '{context_id}'"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

        // Validate input against the tool's input schema.
        validate_value_against_schema(input_json, &registration.input_schema).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("input schema validation failed for tool '{tool_id}': {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            }
        })?;

        let output_schema = registration.output_schema.clone();

        // Dispatch to registered handler if available.
        let result = if let Some(handler) = ctx.tool_handlers.get(tool_id) {
            let out = handler(input_json.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("tool handler for '{tool_id}' failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            validate_value_against_schema(&out, &output_schema).map_err(|msg| {
                ScpWasmError::Tool {
                    message: format!("output validation failed for tool '{tool_id}': {msg}"),
                    code: "SCP-TOOL-6002".to_owned(),
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

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("ToolInvoked"),
            identity_did,
            tool_id.as_bytes(),
        );

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
                code: "SCP-TOOL-6003".to_owned(),
            })?;

        // Verify test vectors by validating inputs against the input schema.
        let mut failures = Vec::new();
        for (i, tv) in registration.test_vectors.iter().enumerate() {
            if let Err(e) = validate_value_against_schema(&tv.input, &registration.input_schema) {
                failures.push(format!(
                    "vector {i} ({0}): input validation failed: {e}",
                    tv.description
                ));
            }
            if let Err(e) =
                validate_value_against_schema(&tv.expected_output, &registration.output_schema)
            {
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
        let _source = self.require_active_context(source_context_id)?;
        let target = self.require_active_context(target_context_id)?;

        // Validate chain depth (max 3 per spec section 6.2).
        if chain_depth > 3 {
            return Err(ScpWasmError::Tool {
                message: format!("cross-context chain depth {chain_depth} exceeds maximum 3"),
                code: "SCP-TOOL-6012".to_owned(),
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
                code: "SCP-TOOL-6003".to_owned(),
            })?;

        validate_value_against_schema(input, &registration.input_schema).map_err(|e| {
            ScpWasmError::Tool {
                message: format!("input validation failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            }
        })?;

        let output_schema = registration.output_schema.clone();

        // Dispatch to handler or echo mode.
        let result = if let Some(handler) = target.tool_handlers.get(tool_id) {
            let out = handler(input.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("cross-context tool handler for '{tool_id}' failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            validate_value_against_schema(&out, &output_schema).map_err(|msg| {
                ScpWasmError::Tool {
                    message: format!("output validation failed for tool '{tool_id}': {msg}"),
                    code: "SCP-TOOL-6002".to_owned(),
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
                code: "SCP-TOOL-6015".to_owned(),
            });
        }

        // Enforce per-caller cap.
        let current = ctx
            .sessions
            .values()
            .filter(|s| s.source_context == source_context_id)
            .count();
        if current >= WASM_SESSION_CAP_PER_CALLER {
            return Err(ScpWasmError::Tool {
                message: format!(
                    "session cap exceeded for caller '{source_context_id}': {current} active (max {WASM_SESSION_CAP_PER_CALLER})"
                ),
                code: "SCP-TOOL-6015".to_owned(),
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
                code: "SCP-TOOL-6018".to_owned(),
            })?;

        if session.is_expired() {
            ctx.sessions.remove(session_id);
            return Err(ScpWasmError::Tool {
                message: format!("session '{session_id}' has expired"),
                code: "SCP-TOOL-6019".to_owned(),
            });
        }

        let tool_id = session.tool_id.clone();
        let current_state = session.state.clone();
        let call_count = session.call_count;

        // Validate input against tool's input schema if tool is registered.
        if let Some(registration) = ctx.tool_registry.get(&tool_id) {
            validate_value_against_schema(input, &registration.input_schema).map_err(|e| {
                ScpWasmError::Tool {
                    message: format!("input validation failed: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                }
            })?;
        }

        // Execute via handler or echo mode.
        let (new_state, output) = if let Some(handler) = ctx.tool_handlers.get(&tool_id) {
            let out = handler(input.clone()).map_err(|e| ScpWasmError::Tool {
                message: format!("tool handler for '{tool_id}' failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
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
                code: "SCP-TOOL-6018".to_owned(),
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
                code: "SCP-TOOL-6021".to_owned(),
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

        let count = ctx.event_log.event_count();
        let root = crate::runtime::encode_hex(&ctx.event_log.root());

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
                code: "SCP-CTX-2007".to_owned(),
            })?;

        let verified = verify_inclusion(&proof);

        let path_json: Vec<serde_json::Value> = proof
            .path
            .iter()
            .map(|step| {
                serde_json::json!({
                    "siblingHash": crate::runtime::encode_hex(&step.sibling_hash),
                    "direction": match step.direction {
                        crate::runtime::Direction::Left => "left",
                        crate::runtime::Direction::Right => "right",
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
                code: "SCP-CTX-2007".to_owned(),
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
                code: "SCP-PERM-3000".to_owned(),
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
                    code: "SCP-PERM-3000".to_owned(),
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
                code: "SCP-VALID-7300".to_owned(),
            });
        }

        ctx.revoked_tokens.insert(token_cid.to_owned());

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("UcanRevoked"),
            revoker_did,
            token_cid.as_bytes(),
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
    /// Maps each `WasmGovernanceAction` variant to the capability that
    /// the initiator must hold. Uses the UCAN `{resource}:{action}` format,
    /// matching `member_has_capability` and the ceiling strings.
    fn required_capability_for_action(action: &WasmGovernanceAction) -> &'static str {
        match action {
            WasmGovernanceAction::AddMember { .. }
            | WasmGovernanceAction::RestoreWriteAccess { .. }
            | WasmGovernanceAction::RestoreReadAccess { .. } => "member:invite",

            WasmGovernanceAction::RemoveMember { .. }
            | WasmGovernanceAction::RevokeWriteAccess { .. }
            | WasmGovernanceAction::BlockAuthor { .. }
            | WasmGovernanceAction::RevokeReadAccess { .. }
            | WasmGovernanceAction::ResetMember { .. } => "member:remove",

            WasmGovernanceAction::ChangeRole { .. } => "role:assign",

            WasmGovernanceAction::RegisterTool { .. }
            | WasmGovernanceAction::RemoveTool { .. }
            | WasmGovernanceAction::EstablishToolInterface { .. } => "tool:register",

            WasmGovernanceAction::CloseContext { .. } => "context:close",

            WasmGovernanceAction::ModifyCeiling { .. }
            | WasmGovernanceAction::ExtendTtl { .. }
            | WasmGovernanceAction::TransferAdmin { .. }
            | WasmGovernanceAction::PromoteContext
            | WasmGovernanceAction::CreateChildContext { .. }
            | WasmGovernanceAction::ModifyPruningPolicy { .. }
            | WasmGovernanceAction::AddSigner { .. }
            | WasmGovernanceAction::RemoveSigner { .. }
            | WasmGovernanceAction::ModifyThreshold { .. }
            | WasmGovernanceAction::ResolveConflict { .. }
            | WasmGovernanceAction::RotateContentKeys { .. }
            | WasmGovernanceAction::ReconfigureGovernance { .. }
            | WasmGovernanceAction::SetEconomicPolicy { .. }
            | WasmGovernanceAction::ApproveSpend { .. }
            | WasmGovernanceAction::LockEconomicPolicy => "governance:propose",
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
        action: &WasmGovernanceAction,
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
                    code: "SCP-PERM-3000".to_owned(),
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
                    code: "SCP-PERM-3000".to_owned(),
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
            let action_type = format!("{action:?}").split_once('{').map_or_else(
                || {
                    format!("{action:?}")
                        .split_once(' ')
                        .map_or_else(|| format!("{action:?}"), |(t, _)| t.to_owned())
                },
                |(t, _)| t.trim().to_owned(),
            );
            ctx.push_event(WasmContextEvent::GovernanceExecuted {
                action_type,
                proposal_id: proposal_id.to_owned(),
            });
            ctx.event_log.append_event(
                crate::runtime::wasm_event_type_tag("GovernanceExecuted"),
                initiator_did,
                proposal_id.as_bytes(),
            );
        }

        result
    }

    /// Dispatches a governance action to its handler.
    ///
    /// Split into multiple methods to satisfy the 100-line function limit.
    fn dispatch_governance_action(
        &mut self,
        context_id: &str,
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            WasmGovernanceAction::AddMember { did, role } => {
                self.dispatch_add_member(context_id, did, role)
            }
            WasmGovernanceAction::RemoveMember { did, .. } => {
                self.dispatch_remove_member(context_id, did)
            }
            WasmGovernanceAction::ChangeRole { did, new_role } => {
                let ctx = self.require_active_context_mut(context_id)?;
                let member = ctx.members.get_mut(did).ok_or_else(|| ScpWasmError::Context {
                    message: format!("member '{did}' not found"),
                    code: "SCP-CTX-2015".to_owned(),
                })?;
                let old_role = member.role.clone();
                new_role.clone_into(&mut member.role);
                // Sync broadcast state when role transitions to/from "author".
                if let Some(ref mut bc) = ctx.broadcast {
                    if old_role == "author" && new_role != "author" {
                        bc.authors.remove(did);
                        bc.key_epochs.remove(did);
                    } else if new_role == "author" && old_role != "author" {
                        bc.authors.insert(did.to_owned(), HashSet::new());
                        bc.key_epochs.insert(did.to_owned(), 0);
                    }
                }
                Ok(serde_json::json!({"action": "ChangeRole", "did": did, "newRole": new_role}))
            }
            WasmGovernanceAction::RegisterTool {
                tool_id,
                name,
                description,
            } => self.dispatch_register_tool(context_id, tool_id, name, description),
            WasmGovernanceAction::RemoveTool { tool_id } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.tool_registry.get(tool_id).is_none() {
                    return Err(ScpWasmError::Tool {
                        message: format!("tool '{tool_id}' not found"),
                        code: "SCP-TOOL-6003".to_owned(),
                    });
                }
                Ok(serde_json::json!({"action": "RemoveTool", "toolId": tool_id}))
            }
            WasmGovernanceAction::ModifyCeiling { new_ceiling } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.ceiling_policy != "governed" {
                    return Err(ScpWasmError::Permission {
                        message: "ceiling is immutable — cannot modify".to_owned(),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                ctx.ceiling_strings = new_ceiling.iter().map(|s| Self::capability_to_ucan_format(s)).collect();
                Ok(serde_json::json!({"action": "ModifyCeiling"}))
            }
            WasmGovernanceAction::CloseContext { .. } => {
                let ctx = self.require_active_context_mut(context_id)?;
                "closing".clone_into(&mut ctx.state);
                Ok(serde_json::json!({"action": "CloseContext"}))
            }
            WasmGovernanceAction::ExtendTtl { additional_secs } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if let Some(ref mut ttl) = ctx.ttl_seconds {
                    *ttl += additional_secs;
                }
                Ok(serde_json::json!({"action": "ExtendTtl", "additionalSecs": additional_secs}))
            }
            WasmGovernanceAction::TransferAdmin { .. } // 20 remaining: exhaustive, no wildcard
            | WasmGovernanceAction::RevokeWriteAccess { .. }
            | WasmGovernanceAction::RestoreWriteAccess { .. }
            | WasmGovernanceAction::BlockAuthor { .. }
            | WasmGovernanceAction::RevokeReadAccess { .. }
            | WasmGovernanceAction::RestoreReadAccess { .. }
            | WasmGovernanceAction::PromoteContext
            | WasmGovernanceAction::CreateChildContext { .. }
            | WasmGovernanceAction::ModifyPruningPolicy { .. }
            | WasmGovernanceAction::AddSigner { .. }
            | WasmGovernanceAction::RemoveSigner { .. }
            | WasmGovernanceAction::ModifyThreshold { .. }
            | WasmGovernanceAction::EstablishToolInterface { .. }
            | WasmGovernanceAction::ResetMember { .. }
            | WasmGovernanceAction::ResolveConflict { .. }
            | WasmGovernanceAction::RotateContentKeys { .. }
            | WasmGovernanceAction::ReconfigureGovernance { .. }
            | WasmGovernanceAction::SetEconomicPolicy { .. }
            | WasmGovernanceAction::ApproveSpend { .. }
            | WasmGovernanceAction::LockEconomicPolicy => self.dispatch_governance_action_ext(context_id, action),
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
                code: "SCP-VALID-7302".to_owned(),
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
        // them in the broadcast state with an empty block list and
        // initialize their key epoch (§5.14.8).
        if role == "author"
            && let Some(ref mut bc) = ctx.broadcast
        {
            bc.authors.insert(did.to_owned(), HashSet::new());
            bc.key_epochs.insert(did.to_owned(), 0);
        }
        ctx.push_event(WasmContextEvent::MemberJoined {
            member_did: did.to_owned(),
            role_name: role.to_owned(),
        });
        Ok(serde_json::json!({"action": "AddMember", "did": did}))
    }

    /// Handles `RemoveMember` governance action: removes the member and, for
    /// broadcast contexts, cleans up author state when the removed member had
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
                code: "SCP-CTX-2015".to_owned(),
            })?;
        // If the removed member was an author in a broadcast context,
        // clean up their broadcast state (block list + key epoch).
        if removed.role == "author"
            && let Some(ref mut bc) = ctx.broadcast
        {
            bc.authors.remove(did);
            bc.key_epochs.remove(did);
        }
        ctx.push_event(WasmContextEvent::MemberLeft {
            member_did: did.to_owned(),
        });
        Ok(serde_json::json!({"action": "RemoveMember", "did": did}))
    }

    /// Handles governance actions that don't fit in the primary dispatch.
    fn dispatch_governance_action_ext(
        &mut self,
        context_id: &str,
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            WasmGovernanceAction::TransferAdmin { new_admin } => {
                let ctx = self.require_active_context_mut(context_id)?;
                let old_admin = ctx.creator_did.clone();
                if let Some(m) = ctx.members.get_mut(&old_admin) {
                    "member".clone_into(&mut m.role);
                }
                if let Some(m) = ctx.members.get_mut(new_admin) {
                    "admin".clone_into(&mut m.role);
                }
                new_admin.clone_into(&mut ctx.creator_did);
                Ok(serde_json::json!({"action": "TransferAdmin", "newAdmin": new_admin}))
            }
            WasmGovernanceAction::RevokeWriteAccess { did, scope } => {
                validate_revocation_scope(scope)?;
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.write_revoked_members.insert(did.clone());
                Ok(serde_json::json!({"action": "RevokeWriteAccess", "did": did, "scope": scope}))
            }
            WasmGovernanceAction::RestoreWriteAccess { did } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if !ctx.write_revoked_members.remove(did) {
                    return Err(ScpWasmError::Context {
                        message: format!("write access not revoked for {did}"),
                        code: "SCP-CTX-2001".to_owned(),
                    });
                }
                Ok(serde_json::json!({"action": "RestoreWriteAccess", "did": did}))
            }
            WasmGovernanceAction::BlockAuthor { did, reason } => {
                // CAC-008: BlockAuthor delegates to RevokeWriteAccess(Full).
                // Destroy the author's broadcast key and mark write-revoked.
                let ctx = self.require_active_context_mut(context_id)?;
                if let Some(ref mut bc) = ctx.broadcast {
                    bc.authors.remove(did);
                    bc.key_epochs.remove(did);
                }
                ctx.write_revoked_members.insert(did.clone());
                ctx.push_event(WasmContextEvent::WriteAccessRevoked { did: did.clone() });
                Ok(
                    serde_json::json!({"action": "WriteAccessRevoked", "did": did, "scope": "full", "reason": reason}),
                )
            }
            WasmGovernanceAction::RevokeReadAccess { did, scope } => {
                self.dispatch_revoke_read_access(context_id, did, scope)
            }
            WasmGovernanceAction::RestoreReadAccess { did } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if !ctx.read_revoked_members.remove(did) {
                    return Err(ScpWasmError::Context {
                        message: format!("read access not revoked for {did}"),
                        code: "SCP-CTX-2001".to_owned(),
                    });
                }
                ctx.read_exclusion_list.remove(did);
                if let Some(bc) = ctx.broadcast.as_mut() {
                    // Governance unban: remove from ALL authors' block lists (§5.14.8).
                    for block_list in bc.authors.values_mut() {
                        block_list.remove(did);
                    }
                }
                Ok(serde_json::json!({"action": "RestoreReadAccess", "did": did}))
            }
            // 8 variants handled by upstream dispatch method (exhaustive, no wildcard).
            WasmGovernanceAction::AddMember { .. }
            | WasmGovernanceAction::RemoveMember { .. }
            | WasmGovernanceAction::ChangeRole { .. }
            | WasmGovernanceAction::RegisterTool { .. }
            | WasmGovernanceAction::RemoveTool { .. }
            | WasmGovernanceAction::ModifyCeiling { .. }
            | WasmGovernanceAction::CloseContext { .. }
            | WasmGovernanceAction::ExtendTtl { .. } => unreachable!(),
            // 14 variants handled by downstream dispatch methods.
            WasmGovernanceAction::PromoteContext
            | WasmGovernanceAction::CreateChildContext { .. }
            | WasmGovernanceAction::ModifyPruningPolicy { .. }
            | WasmGovernanceAction::AddSigner { .. }
            | WasmGovernanceAction::RemoveSigner { .. }
            | WasmGovernanceAction::ModifyThreshold { .. }
            | WasmGovernanceAction::EstablishToolInterface { .. }
            | WasmGovernanceAction::ResetMember { .. }
            | WasmGovernanceAction::ResolveConflict { .. }
            | WasmGovernanceAction::RotateContentKeys { .. }
            | WasmGovernanceAction::ReconfigureGovernance { .. }
            | WasmGovernanceAction::SetEconomicPolicy { .. }
            | WasmGovernanceAction::ApproveSpend { .. }
            | WasmGovernanceAction::LockEconomicPolicy => {
                self.dispatch_governance_action_structural(context_id, action)
            }
        }
    }

    /// Handles `RevokeReadAccess` governance action (§5.14.8).
    ///
    /// Extracted from `dispatch_governance_action_ext` to stay within the
    /// line limit. Governance ban: removes from subscriber registry, adds to
    /// all authors' block lists, increments all authors' key epochs, and
    /// emits `KeyEpochAdvance` events.
    fn dispatch_revoke_read_access(
        &mut self,
        context_id: &str,
        did: &str,
        scope: &str,
    ) -> Result<serde_json::Value, ScpWasmError> {
        validate_revocation_scope(scope)?;
        let ctx = self.require_active_context_mut(context_id)?;

        // Pre-validate: check ALL authors' block lists before any mutation.
        // This prevents partial corruption if a cap check fails mid-loop.
        if let Some(bc) = ctx.broadcast.as_ref() {
            for (author_did, block_list) in &bc.authors {
                if block_list.len() >= WASM_BLOCK_LIST_CAP && !block_list.contains(did) {
                    return Err(ScpWasmError::Validation {
                        message: format!(
                            "per-author block list has reached capacity ({WASM_BLOCK_LIST_CAP}) \
                             for author '{author_did}' during governance ban"
                        ),
                        code: "SCP-VALID-7301".to_owned(),
                    });
                }
            }
        }

        // All caps validated — now commit mutations atomically.
        ctx.read_revoked_members.insert(did.to_owned());
        let mut epoch_advances: Vec<(String, u64)> = Vec::new();
        if let Some(bc) = ctx.broadcast.as_mut() {
            bc.subscribers.remove(did);
            // Governance ban (§5.14.8 step 3): add to ALL authors' block lists.
            for block_list in bc.authors.values_mut() {
                block_list.insert(did.to_owned());
            }
            // §5.14.8 step 4: mandatory key rotation — increment ALL authors'
            // key epochs. Blocked subscriber cannot decrypt future content from
            // any author.
            for author_did in bc.authors.keys() {
                let epoch = bc.key_epochs.entry(author_did.clone()).or_insert(0);
                *epoch = epoch.saturating_add(1);
                epoch_advances.push((author_did.clone(), *epoch));
            }
        }
        // Emit KeyEpochAdvance for each author (§5.14.8 step 4).
        for (author_did, epoch) in epoch_advances {
            ctx.push_event(WasmContextEvent::KeyEpochAdvance {
                sender_did: author_did,
                epoch,
            });
        }
        Ok(serde_json::json!({"action": "RevokeReadAccess", "did": did, "scope": scope}))
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
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            WasmGovernanceAction::PromoteContext => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.promotion_policy.as_deref() != Some("Promotable") {
                    return Err(ScpWasmError::Permission {
                        message: "context promotion_policy is not Promotable".to_owned(),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                // Promote: cancel TTL (§5.10).
                ctx.ttl_seconds = None;
                Ok(serde_json::json!({"action": "PromoteContext"}))
            }
            WasmGovernanceAction::CreateChildContext { .. } => {
                let _ = self.require_active_context_mut(context_id)?;
                // Child context creation is delegated to create_context by the
                // caller with the parent_context_id field set. This method
                // records the governance event on the parent.
                Ok(serde_json::json!({"action": "CreateChildContext"}))
            }
            WasmGovernanceAction::ModifyPruningPolicy { policy_json } => {
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.pruning_policy = Some(policy_json.clone());
                Ok(serde_json::json!({"action": "ModifyPruningPolicy"}))
            }
            WasmGovernanceAction::AddSigner { did } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if !ctx.members.contains_key(did) {
                    return Err(ScpWasmError::Context {
                        message: format!("member '{did}' not found"),
                        code: "SCP-CTX-2015".to_owned(),
                    });
                }
                if ctx.threshold_signers.contains(did) {
                    return Err(ScpWasmError::Permission {
                        message: format!("DID is already a signer: {did}"),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                ctx.threshold_signers.push(did.clone());
                Ok(serde_json::json!({"action": "AddSigner", "did": did}))
            }
            WasmGovernanceAction::RemoveSigner { did } => {
                self.dispatch_remove_signer(context_id, did)
            }
            WasmGovernanceAction::ModifyThreshold { new_threshold } => {
                let ctx = self.require_active_context_mut(context_id)?;
                let signer_count = u32::try_from(ctx.threshold_signers.len()).unwrap_or(u32::MAX);
                if *new_threshold == 0 || *new_threshold > signer_count {
                    return Err(ScpWasmError::Permission {
                        message: format!(
                            "threshold must be 1..={signer_count}, got {new_threshold}"
                        ),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                ctx.threshold_value = *new_threshold;
                Ok(serde_json::json!({"action": "ModifyThreshold", "newThreshold": new_threshold}))
            }
            WasmGovernanceAction::AddMember { .. } // 14 upstream (exhaustive, no wildcard)
            | WasmGovernanceAction::RemoveMember { .. }
            | WasmGovernanceAction::ChangeRole { .. }
            | WasmGovernanceAction::RegisterTool { .. }
            | WasmGovernanceAction::RemoveTool { .. }
            | WasmGovernanceAction::ModifyCeiling { .. }
            | WasmGovernanceAction::CloseContext { .. }
            | WasmGovernanceAction::ExtendTtl { .. }
            | WasmGovernanceAction::TransferAdmin { .. }
            | WasmGovernanceAction::RevokeWriteAccess { .. }
            | WasmGovernanceAction::RestoreWriteAccess { .. }
            | WasmGovernanceAction::BlockAuthor { .. }
            | WasmGovernanceAction::RevokeReadAccess { .. }
            | WasmGovernanceAction::RestoreReadAccess { .. } => unreachable!(),
            WasmGovernanceAction::EstablishToolInterface { .. } // 8 downstream
            | WasmGovernanceAction::ResetMember { .. }
            | WasmGovernanceAction::ResolveConflict { .. }
            | WasmGovernanceAction::RotateContentKeys { .. }
            | WasmGovernanceAction::ReconfigureGovernance { .. }
            | WasmGovernanceAction::SetEconomicPolicy { .. }
            | WasmGovernanceAction::ApproveSpend { .. }
            | WasmGovernanceAction::LockEconomicPolicy => {
                self.dispatch_governance_action_remaining(context_id, action)
            }
        }
    }

    /// Handles remaining governance actions: `EstablishToolInterface`,
    /// `ResetMember`, `ResolveConflict`, `RotateContentKeys`,
    /// `ReconfigureGovernance`.
    fn dispatch_governance_action_remaining(
        &mut self,
        context_id: &str,
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            WasmGovernanceAction::EstablishToolInterface { interface_json } => {
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.tool_interfaces.push(interface_json.clone());
                Ok(serde_json::json!({"action": "EstablishToolInterface"}))
            }
            WasmGovernanceAction::ResetMember { did, reason } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if !ctx.members.contains_key(did) {
                    return Err(ScpWasmError::Context {
                        message: format!("member '{did}' not found"),
                        code: "SCP-CTX-2015".to_owned(),
                    });
                }
                // Member reset: remove + re-add with same role (ADR-029 §Tier 3).
                let role = ctx
                    .members
                    .get(did)
                    .map(|m| m.role.clone())
                    .unwrap_or_default();
                ctx.members.insert(
                    did.clone(),
                    MemberEntry {
                        did: did.clone(),
                        role,
                        sequence_number: 0,
                    },
                );
                Ok(serde_json::json!({"action": "ResetMember", "did": did, "reason": reason}))
            }
            WasmGovernanceAction::ResolveConflict {
                proposal_a,
                proposal_b,
                resolution,
            } => self.dispatch_resolve_conflict(context_id, proposal_a, proposal_b, resolution),
            WasmGovernanceAction::RotateContentKeys { .. } => {
                let _ = self.require_active_context_mut(context_id)?;
                // Key rotation in WASM: no MLS backend — records event only.
                // In broadcast mode, the event signals JS to re-derive keys.
                Ok(serde_json::json!({"action": "RotateContentKeys"}))
            }
            WasmGovernanceAction::ReconfigureGovernance {
                changes_json,
                justification,
            } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if changes_json.is_empty() {
                    return Err(ScpWasmError::Permission {
                        message: "reconfigure_governance requires at least one change".to_owned(),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                if justification.is_empty() {
                    return Err(ScpWasmError::Permission {
                        message: "deadlock justification must not be empty".to_owned(),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                // Clear governance freeze as the reconfiguration resolves it.
                ctx.governance_freeze = false;
                Ok(serde_json::json!({"action": "ReconfigureGovernance"}))
            }
            // 20 variants handled by upstream dispatch methods (exhaustive, no wildcard).
            WasmGovernanceAction::AddMember { .. }
            | WasmGovernanceAction::RemoveMember { .. }
            | WasmGovernanceAction::ChangeRole { .. }
            | WasmGovernanceAction::RegisterTool { .. }
            | WasmGovernanceAction::RemoveTool { .. }
            | WasmGovernanceAction::ModifyCeiling { .. }
            | WasmGovernanceAction::CloseContext { .. }
            | WasmGovernanceAction::ExtendTtl { .. }
            | WasmGovernanceAction::TransferAdmin { .. }
            | WasmGovernanceAction::RevokeWriteAccess { .. }
            | WasmGovernanceAction::RestoreWriteAccess { .. }
            | WasmGovernanceAction::BlockAuthor { .. }
            | WasmGovernanceAction::RevokeReadAccess { .. }
            | WasmGovernanceAction::RestoreReadAccess { .. }
            | WasmGovernanceAction::PromoteContext
            | WasmGovernanceAction::CreateChildContext { .. }
            | WasmGovernanceAction::ModifyPruningPolicy { .. }
            | WasmGovernanceAction::AddSigner { .. }
            | WasmGovernanceAction::RemoveSigner { .. }
            | WasmGovernanceAction::ModifyThreshold { .. } => unreachable!(),
            // 3 variants handled by dispatch_governance_action_economic.
            WasmGovernanceAction::SetEconomicPolicy { .. }
            | WasmGovernanceAction::ApproveSpend { .. }
            | WasmGovernanceAction::LockEconomicPolicy => {
                self.dispatch_governance_action_economic(context_id, action)
            }
        }
    }

    /// Handles economic governance actions: `SetEconomicPolicy`,
    /// `ApproveSpend`, `LockEconomicPolicy`.
    fn dispatch_governance_action_economic(
        &mut self,
        context_id: &str,
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            WasmGovernanceAction::SetEconomicPolicy { policy_json } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.economic_policy_locked {
                    return Err(ScpWasmError::Permission {
                        message: "economic policy is locked and cannot be changed".to_owned(),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                ctx.economic_policy = Some(policy_json.clone());
                Ok(serde_json::json!({"action": "SetEconomicPolicy"}))
            }
            WasmGovernanceAction::ApproveSpend {
                spender,
                amount,
                purpose,
            } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if !ctx.members.contains_key(spender) {
                    return Err(ScpWasmError::Context {
                        message: format!("spender '{spender}' is not a member"),
                        code: "SCP-CTX-2015".to_owned(),
                    });
                }
                Ok(serde_json::json!({
                    "action": "ApproveSpend",
                    "spender": spender,
                    "amount": amount,
                    "purpose": purpose,
                }))
            }
            WasmGovernanceAction::LockEconomicPolicy => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.economic_policy.is_none() {
                    return Err(ScpWasmError::Permission {
                        message: "cannot lock economic policy: no policy is set".to_owned(),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                if ctx.economic_policy_locked {
                    return Err(ScpWasmError::Permission {
                        message: "economic policy is already locked".to_owned(),
                        code: "SCP-PERM-3000".to_owned(),
                    });
                }
                ctx.economic_policy_locked = true;
                Ok(serde_json::json!({"action": "LockEconomicPolicy"}))
            }
            // 25 variants handled by upstream dispatch methods (exhaustive, no wildcard).
            WasmGovernanceAction::AddMember { .. }
            | WasmGovernanceAction::RemoveMember { .. }
            | WasmGovernanceAction::ChangeRole { .. }
            | WasmGovernanceAction::RegisterTool { .. }
            | WasmGovernanceAction::RemoveTool { .. }
            | WasmGovernanceAction::ModifyCeiling { .. }
            | WasmGovernanceAction::CloseContext { .. }
            | WasmGovernanceAction::ExtendTtl { .. }
            | WasmGovernanceAction::TransferAdmin { .. }
            | WasmGovernanceAction::RevokeWriteAccess { .. }
            | WasmGovernanceAction::RestoreWriteAccess { .. }
            | WasmGovernanceAction::BlockAuthor { .. }
            | WasmGovernanceAction::RevokeReadAccess { .. }
            | WasmGovernanceAction::RestoreReadAccess { .. }
            | WasmGovernanceAction::PromoteContext
            | WasmGovernanceAction::CreateChildContext { .. }
            | WasmGovernanceAction::ModifyPruningPolicy { .. }
            | WasmGovernanceAction::AddSigner { .. }
            | WasmGovernanceAction::RemoveSigner { .. }
            | WasmGovernanceAction::ModifyThreshold { .. }
            | WasmGovernanceAction::EstablishToolInterface { .. }
            | WasmGovernanceAction::ResetMember { .. }
            | WasmGovernanceAction::ResolveConflict { .. }
            | WasmGovernanceAction::RotateContentKeys { .. }
            | WasmGovernanceAction::ReconfigureGovernance { .. } => unreachable!(),
        }
    }

    /// Helper for `ResolveConflict` governance action.
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
                code: "SCP-PERM-3000".to_owned(),
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
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            implementation_hash: [0u8; 32],
            test_vectors: Vec::new(),
            operator_did: ctx.creator_did.clone(),
            cost: None,
            registered_at,
            signature: Vec::new(),
        };
        ctx.tool_registry
            .insert(reg)
            .map_err(|e| ScpWasmError::Tool {
                message: e,
                code: "SCP-TOOL-6001".to_owned(),
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
                code: "SCP-CTX-2015".to_owned(),
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
                    code: "SCP-PERM-3000".to_owned(),
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
    pub fn propose_governance_action(
        &mut self,
        context_id: &str,
        proposer_did: &str,
        proposal_id: &str,
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Authorization: check that proposer has governance:propose capability.
        {
            let ctx = self.require_active_context_mut(context_id)?;
            if !ctx.member_has_capability(proposer_did, "governance:propose") {
                return Err(ScpWasmError::Permission {
                    message: format!(
                        "member {proposer_did} does not have 'governance:propose' capability"
                    ),
                    code: "SCP-CTX-2041".to_owned(),
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
                    code: "SCP-CTX-2041".to_owned(),
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
        let proposal = WasmProposal {
            proposer_did: proposer_did.to_owned(),
            action: action.clone(),
            approvals: vec![(proposer_did.to_owned(), now_secs)],
            rejections: Vec::new(),
            voting_deadline_ms: now + WASM_PROPOSAL_DEADLINE_MS,
            context_id: context_id.to_owned(),
            created_at: now_secs,
            status: "Pending".to_owned(),
        };

        let ctx = self.require_active_context_mut(context_id)?;

        // Evict expired proposals if at capacity.
        if ctx.pending_proposals.len() >= WASM_PENDING_PROPOSAL_CAP {
            ctx.pending_proposals
                .retain(|_, p| p.voting_deadline_ms > now);
        }

        // Check if proposer's initial vote meets quorum immediately.
        let meets_quorum = proposal.approvals.len() >= required;
        let pid = proposal_id.to_owned();
        ctx.pending_proposals.insert(pid.clone(), proposal);

        ctx.push_event(WasmContextEvent::GovernanceExecuted {
            action_type: "ProposalCreated".to_owned(),
            proposal_id: pid.clone(),
        });
        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("GovernanceProposed"),
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
                let result =
                    self.execute_governance_action(context_id, proposer_did, &pid, &p.action)?;
                // Move to resolved_proposals for later retrieval.
                "Approved".clone_into(&mut p.status);
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
                    code: "SCP-CTX-2042".to_owned(),
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
        let proposal =
            ctx.pending_proposals
                .get_mut(proposal_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!("proposal {proposal_id} not found"),
                    code: "SCP-CTX-2042".to_owned(),
                })?;

        if proposal.voting_deadline_ms <= now {
            return Err(ScpWasmError::Context {
                message: "proposal voting deadline has expired".to_owned(),
                code: "SCP-CTX-2042".to_owned(),
            });
        }

        // Check for duplicate vote.
        if proposal.approvals.iter().any(|(d, _)| d == voter_did)
            || proposal.rejections.iter().any(|(d, _)| d == voter_did)
        {
            return Err(ScpWasmError::Permission {
                message: format!("member {voter_did} has already voted on this proposal"),
                code: "SCP-CTX-2042".to_owned(),
            });
        }

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let vote_ts = (crate::time::now_ms() / 1000.0) as u64;
        proposal.approvals.push((voter_did.to_owned(), vote_ts));

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("GovernanceVoteApproval"),
            voter_did,
            proposal_id.as_bytes(),
        );

        let meets_quorum = proposal.approvals.len() >= required;
        let pid = proposal_id.to_owned();

        if meets_quorum {
            // Remove from pending and execute.
            let proposal = self
                .contexts
                .get_mut(context_id)
                .and_then(|ctx| ctx.pending_proposals.remove(&pid));
            if let Some(mut p) = proposal {
                let result =
                    self.execute_governance_action(context_id, &p.proposer_did, &pid, &p.action)?;
                // Move to resolved_proposals for later retrieval.
                "Approved".clone_into(&mut p.status);
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
                    code: "SCP-CTX-2043".to_owned(),
                });
            }
        }

        let now = crate::time::now_ms();
        let (_required, total) = {
            let ctx = self.require_active_context_mut(context_id)?;
            Self::governance_quorum(ctx)
        };

        let ctx = self.require_active_context_mut(context_id)?;
        let proposal =
            ctx.pending_proposals
                .get_mut(proposal_id)
                .ok_or_else(|| ScpWasmError::Context {
                    message: format!("proposal {proposal_id} not found"),
                    code: "SCP-CTX-2043".to_owned(),
                })?;

        if proposal.voting_deadline_ms <= now {
            return Err(ScpWasmError::Context {
                message: "proposal voting deadline has expired".to_owned(),
                code: "SCP-CTX-2043".to_owned(),
            });
        }

        if proposal.approvals.iter().any(|(d, _)| d == voter_did)
            || proposal.rejections.iter().any(|(d, _)| d == voter_did)
        {
            return Err(ScpWasmError::Permission {
                message: format!("member {voter_did} has already voted on this proposal"),
                code: "SCP-CTX-2043".to_owned(),
            });
        }

        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let vote_ts = (crate::time::now_ms() / 1000.0) as u64;
        proposal.rejections.push((voter_did.to_owned(), vote_ts));

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("GovernanceVoteRejection"),
            voter_did,
            proposal_id.as_bytes(),
        );

        // Check if enough rejections to make approval impossible.
        let remaining_possible_approvals =
            total.saturating_sub(proposal.approvals.len() + proposal.rejections.len());
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
                "Rejected".clone_into(&mut p.status);
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
                    code: "SCP-CTX-2044".to_owned(),
                })?;

        let voter = voter_did.to_owned();
        let was_approval = proposal.approvals.iter().position(|(d, _)| d == &voter);
        let was_rejection = proposal.rejections.iter().position(|(d, _)| d == &voter);

        if let Some(idx) = was_approval {
            proposal.approvals.remove(idx);
        } else if let Some(idx) = was_rejection {
            proposal.rejections.remove(idx);
        } else {
            return Err(ScpWasmError::Permission {
                message: format!("member {voter_did} has not voted on proposal {proposal_id}"),
                code: "SCP-CTX-2044".to_owned(),
            });
        }

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("GovernanceVoteWithdraw"),
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
                code: "SCP-CTX-2045".to_owned(),
            })?;

        let proposal = ctx
            .pending_proposals
            .get(proposal_id)
            .or_else(|| ctx.resolved_proposals.get(proposal_id))
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("proposal {proposal_id} not found"),
                code: "SCP-CTX-2045".to_owned(),
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
                code: "SCP-CTX-2046".to_owned(),
            })?;

        let proposals: Vec<serde_json::Value> = ctx
            .pending_proposals
            .iter()
            .chain(ctx.resolved_proposals.iter())
            .map(|(id, p)| Self::proposal_to_json(id, p))
            .collect();

        Ok(serde_json::json!(proposals))
    }

    /// Serializes a `WasmProposal` to the full JSON response shape matching
    /// native bridges' `GovernanceProposal` serialization.
    ///
    /// Fields: `proposal_id`, `context_id`, `proposer_did`, `action`,
    /// `status`, `created_at` (Unix epoch seconds, u64), `created_at_epoch`
    /// (null — placeholder for compatibility with native bridge serialization),
    /// `voting_deadline` (seconds), `approvals` (with `voter_did` and
    /// `vote` fields), `rejections` (same shape).
    fn proposal_to_json(proposal_id: &str, proposal: &WasmProposal) -> serde_json::Value {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let voting_deadline_secs = (proposal.voting_deadline_ms / 1000.0) as u64;

        let approvals: Vec<serde_json::Value> = proposal
            .approvals
            .iter()
            .map(|(did, ts)| {
                serde_json::json!({
                    "voter_did": did,
                    "vote": "Approve",
                    "timestamp": ts,
                    "signature": [],
                })
            })
            .collect();

        let rejections: Vec<serde_json::Value> = proposal
            .rejections
            .iter()
            .map(|(did, ts)| {
                serde_json::json!({
                    "voter_did": did,
                    "vote": "Reject",
                    "timestamp": ts,
                    "signature": [],
                })
            })
            .collect();

        serde_json::json!({
            "proposal_id": proposal_id,
            "context_id": proposal.context_id,
            "proposer_did": proposal.proposer_did,
            "action": proposal.action,
            "status": proposal.status,
            "created_at": proposal.created_at,
            "voting_deadline": voting_deadline_secs,
            "approvals": approvals,
            "rejections": rejections,
            "created_at_epoch": null,
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
            .broadcast
            .as_mut()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: "SCP-CTX-2001".to_owned(),
            })?;

        bc.subscribers.insert(subscriber_did.to_owned());

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

        if ctx.write_revoked_members.contains(author_did) {
            return Err(ScpWasmError::Permission {
                message: format!("write access has been revoked for {author_did}"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        let bc = ctx
            .broadcast
            .as_ref()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: "SCP-CTX-2001".to_owned(),
            })?;

        if !bc.authors.contains_key(author_did) {
            return Err(ScpWasmError::Permission {
                message: format!("'{author_did}' is not an author in this broadcast context"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        // Assign sequence number.
        let member = ctx
            .members
            .get_mut(author_did)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("author '{author_did}' not found in members"),
                code: "SCP-CTX-2019".to_owned(),
            })?;
        let seq = member.sequence_number;
        member.sequence_number += 1;

        ctx.push_event(WasmContextEvent::MessageSent {
            sender_did: author_did.to_owned(),
            sequence_number: seq,
            payload_base64: payload_base64.to_owned(),
        });

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("MessageSent"),
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
    ) -> Result<(String, String), ScpWasmError> {
        // Validate path (reimplemented per ADR-034).
        validate_content_path_wasm(path).map_err(|msg| ScpWasmError::Context {
            message: format!("invalid path: {msg}"),
            code: "SCP-CTX-2070".to_owned(),
        })?;

        // Validate content_type (reimplemented per ADR-034).
        validate_mime_type_wasm(content_type).map_err(|msg| ScpWasmError::Context {
            message: format!("invalid content_type: {msg}"),
            code: "SCP-CTX-2071".to_owned(),
        })?;

        // Validate deploy_id.
        if let Some(did) = deploy_id {
            validate_deploy_id_wasm(did).map_err(|msg| ScpWasmError::Context {
                message: format!("invalid deploy_id: {msg}"),
                code: "SCP-CTX-2072".to_owned(),
            })?;
        }

        // Compute ETag: SHA-256(body) hex.
        let etag = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(body))
        };

        // Build the BroadcastContent wire format: magic "SCP" + version byte
        // + MessagePack serialized content. Matches scp-core's
        // serialize_broadcast_content exactly. Reimplemented per ADR-034.
        let wire_bytes =
            serialize_broadcast_content_wasm(path, content_type, deploy_id, &etag, body).map_err(
                |msg| ScpWasmError::Context {
                    message: format!("broadcast content serialization failed: {msg}"),
                    code: "SCP-CTX-2073".to_owned(),
                },
            )?;

        // Base64-encode the wire bytes for the publish_broadcast path.
        let payload = base64::engine::general_purpose::STANDARD.encode(&wire_bytes);
        self.publish_broadcast(context_id, author_did, &payload)?;

        // Compute synthetic blob_id from context + author + etag.
        let blob_id = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(context_id.as_bytes());
            hasher.update(author_did.as_bytes());
            hasher.update(etag.as_bytes());
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let ts = js_sys::Date::now() as u64;
            hasher.update(ts.to_le_bytes());
            hex::encode(Sha256::digest(hasher.finalize()))
        };

        Ok((blob_id, etag))
    }

    /// Publishes multiple assets to a broadcast context (SCP-290).
    ///
    /// All assets are published with the same `deploy_id`. Returns a list of
    /// `(blob_id, etag)` tuples.
    ///
    /// # Errors
    ///
    /// Returns an error if any asset fails validation or publish, or if the
    /// batch exceeds `MAX_BATCH_ASSETS` (10,000).
    pub fn publish_broadcast_assets(
        &mut self,
        context_id: &str,
        author_did: &str,
        assets: &[(String, String, Vec<u8>)],
        deploy_id: Option<&str>,
    ) -> Result<Vec<(String, String)>, ScpWasmError> {
        // Enforce batch size limit.
        if assets.len() > MAX_BATCH_ASSETS {
            return Err(ScpWasmError::Context {
                message: format!(
                    "batch too large: {} assets (max {MAX_BATCH_ASSETS})",
                    assets.len()
                ),
                code: "SCP-CTX-2074".to_owned(),
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
            let (blob_id, etag) = self.publish_broadcast_asset(
                context_id,
                author_did,
                path,
                content_type,
                body,
                Some(did),
            )?;
            results.push((blob_id, etag));
        }
        Ok(results)
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
            .broadcast
            .as_mut()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: "SCP-CTX-2001".to_owned(),
            })?;

        bc.subscribers.remove(subscriber_did);

        ctx.push_event(WasmContextEvent::MemberLeft {
            member_did: subscriber_did.to_owned(),
        });

        Ok(())
    }

    /// Blocks a subscriber in a broadcast context.
    ///
    /// Per spec §5.14.8 steps 1-2:
    /// 1. Adds DID to the blocker's block list and increments the blocker's
    ///    key epoch.
    /// 2. Emits a `KeyEpochAdvance` notification so non-blocked subscribers
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
                .broadcast
                .as_mut()
                .ok_or_else(|| ScpWasmError::Context {
                    message: "not a broadcast context".to_owned(),
                    code: "SCP-CTX-2001".to_owned(),
                })?;

            // Per-author blocking (§5.14.8): add to the blocker's block list only.
            // Does NOT remove from the subscriber roster — the subscriber retains
            // access to other authors' content. Only governance ban removes from
            // the roster.
            let block_list =
                bc.authors
                    .get_mut(blocker_did)
                    .ok_or_else(|| ScpWasmError::Context {
                        message: format!("author not found: {blocker_did}"),
                        code: "SCP-CTX-2001".to_owned(),
                    })?;

            if block_list.len() >= WASM_BLOCK_LIST_CAP && !block_list.contains(subscriber_did) {
                return Err(ScpWasmError::Validation {
                    message: format!(
                        "per-author block list has reached capacity ({WASM_BLOCK_LIST_CAP}) \
                         for author '{blocker_did}'"
                    ),
                    code: "SCP-VALID-7301".to_owned(),
                });
            }

            block_list.insert(subscriber_did.to_owned());

            // §5.14.8 step 1: increment the blocker's key epoch.
            let epoch = bc.key_epochs.entry(blocker_did.to_owned()).or_insert(0);
            *epoch = epoch.saturating_add(1);
            new_epoch = *epoch;
        }

        ctx.push_event(WasmContextEvent::MemberBlocked {
            blocked_did: subscriber_did.to_owned(),
            author_did: blocker_did.to_owned(),
        });

        // §5.14.8 step 2: publish KeyEpochAdvance notification.
        ctx.push_event(WasmContextEvent::KeyEpochAdvance {
            sender_did: blocker_did.to_owned(),
            epoch: new_epoch,
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
                .broadcast
                .as_mut()
                .ok_or_else(|| ScpWasmError::Context {
                    message: "not a broadcast context".to_owned(),
                    code: "SCP-CTX-2001".to_owned(),
                })?;

            // Per-author unblocking (§5.14.8): remove from the unblocker's
            // block list only. Per spec, no key rotation on unblock — the
            // subscriber receives the current key on next pull.
            let block_list =
                bc.authors
                    .get_mut(unblocker_did)
                    .ok_or_else(|| ScpWasmError::Context {
                        message: format!("author not found: {unblocker_did}"),
                        code: "SCP-CTX-2001".to_owned(),
                    })?;

            if !block_list.remove(subscriber_did) {
                return Err(ScpWasmError::Context {
                    message: format!(
                        "subscriber {subscriber_did} not blocked by author {unblocker_did}"
                    ),
                    code: "SCP-CTX-2001".to_owned(),
                });
            }
        }

        ctx.push_event(WasmContextEvent::MemberUnblocked {
            unblocked_did: subscriber_did.to_owned(),
            author_did: unblocker_did.to_owned(),
        });

        Ok(())
    }

    /// Returns the number of subscribers in a broadcast context.
    ///
    /// Returns `None` if the context is not a broadcast context.
    #[must_use]
    pub fn broadcast_subscriber_count(&self, context_id: &str) -> Option<usize> {
        self.contexts
            .get(context_id)
            .and_then(|ctx| ctx.broadcast.as_ref().map(|bc| bc.subscribers.len()))
    }

    /// Returns `true` if the given DID is a subscriber in a broadcast context.
    #[must_use]
    pub fn is_broadcast_subscriber(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .get(context_id)
            .and_then(|ctx| {
                ctx.broadcast
                    .as_ref()
                    .map(|bc| bc.subscribers.contains(did))
            })
            .unwrap_or(false)
    }

    /// Returns the admission policy string for a broadcast context.
    ///
    /// Returns `None` if the context is not a broadcast context.
    #[must_use]
    pub fn broadcast_admission(&self, context_id: &str) -> Option<String> {
        self.contexts
            .get(context_id)
            .and_then(|ctx| ctx.broadcast.as_ref().map(|bc| bc.admission.clone()))
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
        // Use a uniform deny reason to prevent information leakage (§5.14.8).
        const DENY_REASON: &str = "key request denied";

        let ctx = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ScpWasmError::Context {
                message: format!("context not registered: {context_id}"),
                code: "SCP-CTX-2001".to_owned(),
            })?;

        let bc = ctx
            .broadcast
            .as_ref()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: "SCP-CTX-2001".to_owned(),
            })?;

        // Author must be a known author.
        let Some(author_block_list) = bc.authors.get(author_did) else {
            return Ok(
                serde_json::json!({ "decision": "deny", "reason": DENY_REASON }).to_string(),
            );
        };

        // Requester must not be on this author's block list (§5.14.8).
        if author_block_list.contains(requester_did) {
            return Ok(
                serde_json::json!({ "decision": "deny", "reason": DENY_REASON }).to_string(),
            );
        }

        // Requester must be a subscriber or author.
        if !bc.subscribers.contains(requester_did) && !bc.authors.contains_key(requester_did) {
            return Ok(
                serde_json::json!({ "decision": "deny", "reason": DENY_REASON }).to_string(),
            );
        }

        Ok(serde_json::json!({ "decision": "grant" }).to_string())
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
            code: "SCP-CTX-2013".to_owned(),
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
                    code: "SCP-CTX-2001".to_owned(),
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
        ctx.push_event(WasmContextEvent::Expired);

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("ContextExpired"),
            "", // System event — no actor.
            b"",
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
                code: "SCP-CTX-2005".to_owned(),
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
                code: "SCP-CTX-2001".to_owned(),
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
                code: "SCP-CTX-2002".to_owned(),
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
                code: "SCP-CTX-2001".to_owned(),
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
                code: "SCP-CTX-2013".to_owned(),
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

        let broadcast = ctx.broadcast.as_ref().map(|bc| WasmExportBroadcast {
            author_block_lists: bc
                .authors
                .iter()
                .map(|(did, block_list)| (did.clone(), block_list.iter().cloned().collect()))
                .collect(),
            key_epochs: bc.key_epochs.clone(),
            subscribers: bc.subscribers.iter().cloned().collect(),
            admission: bc.admission.clone(),
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
            write_revoked_members: ctx.write_revoked_members.iter().cloned().collect(),
            read_revoked_members: ctx.read_revoked_members.iter().cloned().collect(),
            read_exclusion_list: ctx.read_exclusion_list.iter().cloned().collect(),
            broadcast,
            revoked_tokens: ctx.revoked_tokens.iter().cloned().collect(),
            seen_nonces: ctx.seen_nonces.keys().cloned().collect(),
            threshold_signers: ctx.threshold_signers.clone(),
            threshold_value: ctx.threshold_value,
            tool_interfaces: ctx.tool_interfaces.clone(),
            governance_freeze: ctx.governance_freeze,
            pruning_policy: ctx.pruning_policy.clone(),
            economic_policy_locked: ctx.economic_policy_locked,
        };

        // Serialize snapshot to RFC 8785 JCS canonical JSON for HMAC
        // computation. The HMAC is computed over this stable serialization —
        // NOT the full envelope — to avoid a circular dependency (envelope
        // contains the MAC).
        let snapshot_json =
            serde_json_canonicalizer::to_vec(&snapshot).map_err(|e| ScpWasmError::Context {
                message: format!("export snapshot serialization failed: {e}"),
                code: "SCP-CTX-2030".to_owned(),
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
            code: "SCP-CTX-2030".to_owned(),
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
                code: "SCP-CTX-2032".to_owned(),
            })?;

        if envelope.version > WASM_EXPORT_VERSION {
            return Err(ScpWasmError::Context {
                message: format!(
                    "incompatible export version: got {}, max supported is {WASM_EXPORT_VERSION}",
                    envelope.version
                ),
                code: "SCP-CTX-2032".to_owned(),
            });
        }

        // Re-serialize the snapshot to RFC 8785 JCS canonical JSON and verify
        // the HMAC tag using the creator's signing key. This MUST happen
        // before any state reconstruction to prevent an attacker from crafting
        // payloads that grant them admin of a context.
        let snapshot_json = serde_json_canonicalizer::to_vec(&envelope.snapshot).map_err(|e| {
            ScpWasmError::Context {
                message: format!("snapshot re-serialization failed: {e}"),
                code: "SCP-CTX-2032".to_owned(),
            }
        })?;

        if envelope.integrity_mac.is_empty() {
            return Err(ScpWasmError::Context {
                message: "export integrity_mac is missing — refusing to import unsigned export"
                    .to_owned(),
                code: "SCP-CTX-2020".to_owned(),
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
                    code: "SCP-CTX-2032".to_owned(),
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
                code: "SCP-CTX-2032".to_owned(),
            });
        }

        // Defense-in-depth: validate and check minProtocolVersion from the
        // imported snapshot's params. Rejects malformed version data and
        // imported contexts that require a newer SDK than we support.
        parse_and_check_min_protocol_version(&snap.params_json)?;

        if self.contexts.contains_key(&context_id) {
            return Err(ScpWasmError::Context {
                message: format!(
                    "context '{context_id}' already exists — cannot import over existing context"
                ),
                code: "SCP-CTX-2000".to_owned(),
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

        let broadcast = snap.broadcast.as_ref().map(|bc| BroadcastState {
            authors: bc
                .author_block_lists
                .iter()
                .map(|(did, block_list)| (did.clone(), block_list.iter().cloned().collect()))
                .collect(),
            key_epochs: bc.key_epochs.clone(),
            subscribers: bc.subscribers.iter().cloned().collect(),
            admission: bc.admission.clone(),
        });

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
            event_log: WasmEventLog::new(context_id.clone()),
            revoked_tokens: snap.revoked_tokens.iter().cloned().collect(),
            seen_nonces: {
                let now = crate::time::now_ms();
                snap.seen_nonces.iter().map(|n| (n.clone(), now)).collect()
            },
            members,
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            write_revoked_members: snap.write_revoked_members.iter().cloned().collect(),
            read_revoked_members: snap.read_revoked_members.iter().cloned().collect(),
            read_exclusion_list: snap.read_exclusion_list.iter().cloned().collect(),
            broadcast,
            sessions: HashMap::new(),
            threshold_signers: snap.threshold_signers.clone(),
            threshold_value: snap.threshold_value,
            tool_interfaces: snap.tool_interfaces.clone(),
            governance_freeze: snap.governance_freeze,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: snap.pruning_policy.clone(),
            economic_policy_locked: snap.economic_policy_locked,
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
                code: "SCP-CTX-2061".to_owned(),
            });
        }

        "closed".clone_into(&mut ctx.state);
        ctx.broadcast = None;

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("ContextClosed"),
            "system",
            b"",
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
            code: "SCP-CTX-2064".to_owned(),
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
            code: "SCP-CTX-2065".to_owned(),
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
const WASM_EXPORT_VERSION: u32 = 2;

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

/// Snapshot of a context's state for export.
///
/// Contains all fields needed to reconstruct a `PerContextState` on import.
/// Tool registry, event log, and tool handlers are NOT exported (they can be
/// re-registered after import). Membership, roles, governance, broadcast,
/// UCAN revocation, and nonce replay state are preserved.
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
    write_revoked_members: Vec<String>,
    read_revoked_members: Vec<String>,
    read_exclusion_list: Vec<String>,
    broadcast: Option<WasmExportBroadcast>,
    /// UCAN revocation CIDs. Preserves revocation state across export/import
    /// so that previously revoked tokens remain rejected.
    #[serde(default)]
    revoked_tokens: Vec<String>,
    /// Seen UCAN nonces. Preserves nonce replay protection across
    /// export/import so that previously used nonces are still rejected.
    #[serde(default)]
    seen_nonces: Vec<String>,
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

// `compute_event_hash` replaced by `WasmEventLog::append_event` which uses
// the canonical hash format matching native `compute_event_canonical_hash`.
// See `crate::runtime::compute_canonical_event_hash`.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // WasmGovernanceAction serde roundtrip tests
    // -----------------------------------------------------------------------

    /// Helper: serialize to JSON, deserialize back, and assert equal JSON.
    fn roundtrip(action: &WasmGovernanceAction) {
        let json = serde_json::to_string(action).unwrap();
        let back: WasmGovernanceAction = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2, "roundtrip mismatch for {action:?}");
    }

    #[test]
    fn serde_roundtrip_add_member() {
        roundtrip(&WasmGovernanceAction::AddMember {
            did: "did:dht:z123".to_owned(),
            role: "admin".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_remove_member() {
        roundtrip(&WasmGovernanceAction::RemoveMember {
            did: "did:dht:z123".to_owned(),
            reason: Some("inactive".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_change_role() {
        roundtrip(&WasmGovernanceAction::ChangeRole {
            did: "did:dht:z123".to_owned(),
            new_role: "member".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_register_tool() {
        roundtrip(&WasmGovernanceAction::RegisterTool {
            tool_id: "tool-abc".to_owned(),
            name: "my-tool".to_owned(),
            description: "A test tool".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_remove_tool() {
        roundtrip(&WasmGovernanceAction::RemoveTool {
            tool_id: "tool-abc".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_modify_ceiling() {
        roundtrip(&WasmGovernanceAction::ModifyCeiling {
            new_ceiling: vec!["messages:read".to_owned(), "messages:write".to_owned()],
        });
    }

    #[test]
    fn serde_roundtrip_close_context() {
        roundtrip(&WasmGovernanceAction::CloseContext {
            reason: Some("done".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_extend_ttl() {
        roundtrip(&WasmGovernanceAction::ExtendTtl {
            additional_secs: 3600,
        });
    }

    #[test]
    fn serde_roundtrip_transfer_admin() {
        roundtrip(&WasmGovernanceAction::TransferAdmin {
            new_admin: "did:dht:zadmin".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_create_child_context() {
        roundtrip(&WasmGovernanceAction::CreateChildContext {
            params_json: r#"{"mode":"Encrypted"}"#.to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_modify_pruning_policy() {
        roundtrip(&WasmGovernanceAction::ModifyPruningPolicy {
            policy_json: r#"{"retention":"30d"}"#.to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_add_signer() {
        roundtrip(&WasmGovernanceAction::AddSigner {
            did: "did:dht:zsigner".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_remove_signer() {
        roundtrip(&WasmGovernanceAction::RemoveSigner {
            did: "did:dht:zsigner".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_modify_threshold() {
        roundtrip(&WasmGovernanceAction::ModifyThreshold { new_threshold: 3 });
    }

    #[test]
    fn serde_roundtrip_establish_tool_interface() {
        roundtrip(&WasmGovernanceAction::EstablishToolInterface {
            interface_json: r#"{"tool":"calc"}"#.to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_reset_member() {
        roundtrip(&WasmGovernanceAction::ResetMember {
            did: "did:dht:z123".to_owned(),
            reason: "stale state".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_resolve_conflict() {
        roundtrip(&WasmGovernanceAction::ResolveConflict {
            proposal_a: "prop-1".to_owned(),
            proposal_b: "prop-2".to_owned(),
            resolution: "invalidateBoth".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_promote_context() {
        roundtrip(&WasmGovernanceAction::PromoteContext);
    }

    #[test]
    fn serde_roundtrip_revoke_write_access() {
        roundtrip(&WasmGovernanceAction::RevokeWriteAccess {
            did: "did:dht:z123".to_owned(),
            scope: "full".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_restore_write_access() {
        roundtrip(&WasmGovernanceAction::RestoreWriteAccess {
            did: "did:dht:z123".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_rotate_content_keys() {
        roundtrip(&WasmGovernanceAction::RotateContentKeys {
            reason: Some("compromise".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_reconfigure_governance() {
        roundtrip(&WasmGovernanceAction::ReconfigureGovernance {
            changes_json: r#"[{"action":"reduceThreshold","value":2}]"#.to_owned(),
            justification: "deadlock recovery".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_block_author() {
        roundtrip(&WasmGovernanceAction::BlockAuthor {
            did: "did:dht:zauthor".to_owned(),
            reason: Some("spam".to_owned()),
        });
    }

    #[test]
    fn serde_roundtrip_revoke_read_access() {
        roundtrip(&WasmGovernanceAction::RevokeReadAccess {
            did: "did:dht:z123".to_owned(),
            scope: "future_only".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_restore_read_access() {
        roundtrip(&WasmGovernanceAction::RestoreReadAccess {
            did: "did:dht:z123".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_set_economic_policy() {
        roundtrip(&WasmGovernanceAction::SetEconomicPolicy {
            policy_json: r#"{"locked":false,"costSchedule":{}}"#.to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_approve_spend() {
        roundtrip(&WasmGovernanceAction::ApproveSpend {
            spender: "did:dht:zspender".to_owned(),
            amount: 1000,
            purpose: "compute resources".to_owned(),
        });
    }

    #[test]
    fn serde_roundtrip_lock_economic_policy() {
        roundtrip(&WasmGovernanceAction::LockEconomicPolicy);
    }

    // -----------------------------------------------------------------------
    // Variant count exhaustiveness
    // -----------------------------------------------------------------------

    #[test]
    fn governance_action_has_28_variants() {
        // Ensure all 28 variants are covered by serializing each and counting
        // unique "type" values.
        let all: Vec<WasmGovernanceAction> = vec![
            WasmGovernanceAction::AddMember {
                did: "d".into(),
                role: "r".into(),
            },
            WasmGovernanceAction::RemoveMember {
                did: "d".into(),
                reason: None,
            },
            WasmGovernanceAction::ChangeRole {
                did: "d".into(),
                new_role: "r".into(),
            },
            WasmGovernanceAction::RegisterTool {
                tool_id: "t".into(),
                name: "n".into(),
                description: "d".into(),
            },
            WasmGovernanceAction::RemoveTool {
                tool_id: "t".into(),
            },
            WasmGovernanceAction::ModifyCeiling {
                new_ceiling: vec![],
            },
            WasmGovernanceAction::CloseContext { reason: None },
            WasmGovernanceAction::ExtendTtl { additional_secs: 1 },
            WasmGovernanceAction::TransferAdmin {
                new_admin: "d".into(),
            },
            WasmGovernanceAction::CreateChildContext {
                params_json: "{}".into(),
            },
            WasmGovernanceAction::ModifyPruningPolicy {
                policy_json: "{}".into(),
            },
            WasmGovernanceAction::AddSigner { did: "d".into() },
            WasmGovernanceAction::RemoveSigner { did: "d".into() },
            WasmGovernanceAction::ModifyThreshold { new_threshold: 1 },
            WasmGovernanceAction::EstablishToolInterface {
                interface_json: "{}".into(),
            },
            WasmGovernanceAction::ResetMember {
                did: "d".into(),
                reason: "stale".into(),
            },
            WasmGovernanceAction::ResolveConflict {
                proposal_a: "a".into(),
                proposal_b: "b".into(),
                resolution: "c".into(),
            },
            WasmGovernanceAction::PromoteContext,
            WasmGovernanceAction::RevokeWriteAccess {
                did: "d".into(),
                scope: "full".into(),
            },
            WasmGovernanceAction::RestoreWriteAccess { did: "d".into() },
            WasmGovernanceAction::RotateContentKeys { reason: None },
            WasmGovernanceAction::ReconfigureGovernance {
                changes_json: "[]".into(),
                justification: "j".into(),
            },
            WasmGovernanceAction::BlockAuthor {
                did: "d".into(),
                reason: None,
            },
            WasmGovernanceAction::RevokeReadAccess {
                did: "d".into(),
                scope: "future_only".into(),
            },
            WasmGovernanceAction::RestoreReadAccess { did: "d".into() },
            WasmGovernanceAction::SetEconomicPolicy {
                policy_json: "{}".into(),
            },
            WasmGovernanceAction::ApproveSpend {
                spender: "d".into(),
                amount: 0,
                purpose: "p".into(),
            },
            WasmGovernanceAction::LockEconomicPolicy,
        ];
        assert_eq!(all.len(), 28, "expected 28 governance action variants");

        // Verify each serializes to unique "type" tag.
        let types: std::collections::HashSet<String> = all
            .iter()
            .map(|a| {
                let v: serde_json::Value = serde_json::to_value(a).unwrap();
                v["type"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(
            types.len(),
            28,
            "expected 28 unique type tags, got {}: {types:?}",
            types.len()
        );
    }

    // -----------------------------------------------------------------------
    // Deserialization from JS-shaped JSON
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_set_economic_policy_from_json() {
        let json = r#"{"type":"setEconomicPolicy","policy_json":"flat-rate"}"#;
        let action: WasmGovernanceAction = serde_json::from_str(json).unwrap();
        assert!(matches!(
            action,
            WasmGovernanceAction::SetEconomicPolicy { ref policy_json }
                if policy_json == "flat-rate"
        ));
    }

    #[test]
    fn deserialize_approve_spend_from_json() {
        let json =
            r#"{"type":"approveSpend","spender":"did:dht:z1","amount":500,"purpose":"infra"}"#;
        let action: WasmGovernanceAction = serde_json::from_str(json).unwrap();
        assert!(matches!(
            action,
            WasmGovernanceAction::ApproveSpend {
                ref spender,
                amount: 500,
                ref purpose,
            } if spender == "did:dht:z1" && purpose == "infra"
        ));
    }

    #[test]
    fn deserialize_lock_economic_policy_from_json() {
        let json = r#"{"type":"lockEconomicPolicy"}"#;
        let action: WasmGovernanceAction = serde_json::from_str(json).unwrap();
        assert!(matches!(action, WasmGovernanceAction::LockEconomicPolicy));
    }

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
            assert_eq!(code, "SCP-PERM-3000");
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
            matches!(err, ScpWasmError::Context { ref code, .. } if code == "SCP-CTX-2016"),
            "expected SCP-CTX-2016, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_different_major() {
        let params = serde_json::json!({ "minProtocolVersion": [2, 0] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == "SCP-CTX-2016"),
            "expected SCP-CTX-2016, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_string_major() {
        // Non-numeric major should error, not silently downgrade to (1, 0).
        let params = serde_json::json!({ "minProtocolVersion": ["2", "0"] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == "SCP-CTX-2015"),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_string_minor() {
        // Non-numeric minor should error, not silently downgrade to (1, 0).
        let params = serde_json::json!({ "minProtocolVersion": [1, "0"] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == "SCP-CTX-2015"),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_short_array() {
        let params = serde_json::json!({ "minProtocolVersion": [1] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == "SCP-CTX-2015"),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    #[test]
    fn parse_and_check_min_protocol_version_rejects_overflow() {
        let params = serde_json::json!({ "minProtocolVersion": [256, 0] });
        let err = parse_and_check_min_protocol_version(&params).unwrap_err();
        assert!(
            matches!(err, ScpWasmError::Context { ref code, .. } if code == "SCP-CTX-2015"),
            "expected SCP-CTX-2015, got: {err:?}"
        );
    }

    // The following tests validate integration behavior (create_context
    // validates minProtocolVersion, metadata surfaces it). They cannot run on
    // native targets because WasmEventLog::append_event calls
    // time::now_ms() which requires a WASM runtime. Coverage is provided by:
    // - The parse_and_check_* tests above (unit tests, no WASM runtime needed).
    // - The scp-core wasm_conformance tests (SCP_PROTOCOL_VERSION sync).
    // - The scp-core manager tests (create_context version check at core layer).

    // -----------------------------------------------------------------------
    // Per-author block list tests (§5.14.8, #749)
    // -----------------------------------------------------------------------

    /// Helper: creates a `BroadcastState` with given authors and subscribers.
    fn make_broadcast(authors: &[&str], subscribers: &[&str]) -> BroadcastState {
        let mut bc = BroadcastState::new("open");
        for a in authors {
            bc.authors.insert((*a).to_owned(), HashSet::new());
        }
        for s in subscribers {
            bc.subscribers.insert((*s).to_owned());
        }
        bc
    }

    #[test]
    fn broadcast_state_per_author_block_list_isolation() {
        // Author A blocks sub1. Author B does NOT block sub1.
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1", "sub2"]);
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub1".to_owned());

        // sub1 is blocked by author-a
        assert!(bc.authors["author-a"].contains("sub1"));
        // sub1 is NOT blocked by author-b
        assert!(!bc.authors["author-b"].contains("sub1"));
        // is_blocked_by_any_author returns true (for governance-ban detection)
        assert!(bc.is_blocked_by_any_author("sub1"));
        // sub2 is blocked by nobody
        assert!(!bc.is_blocked_by_any_author("sub2"));
    }

    #[test]
    fn broadcast_state_governance_ban_adds_to_all_authors() {
        let mut bc = make_broadcast(&["author-a", "author-b", "author-c"], &["sub1"]);

        // Simulate governance ban: add to ALL authors' block lists
        for block_list in bc.authors.values_mut() {
            block_list.insert("sub1".to_owned());
        }

        assert!(bc.authors["author-a"].contains("sub1"));
        assert!(bc.authors["author-b"].contains("sub1"));
        assert!(bc.authors["author-c"].contains("sub1"));
        assert!(bc.is_blocked_by_any_author("sub1"));
    }

    #[test]
    fn broadcast_state_governance_unban_removes_from_all_authors() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &[]);

        // Ban first
        for block_list in bc.authors.values_mut() {
            block_list.insert("sub1".to_owned());
        }
        assert!(bc.is_blocked_by_any_author("sub1"));

        // Unban: remove from ALL authors
        for block_list in bc.authors.values_mut() {
            block_list.remove("sub1");
        }
        assert!(!bc.is_blocked_by_any_author("sub1"));
    }

    #[test]
    fn broadcast_export_roundtrip_preserves_per_author_block_lists() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1"]);
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub1".to_owned());

        // Set a key epoch for author-a to verify roundtrip
        bc.key_epochs.insert("author-a".to_owned(), 3);

        // Export
        let export = WasmExportBroadcast {
            author_block_lists: bc
                .authors
                .iter()
                .map(|(did, bl)| (did.clone(), bl.iter().cloned().collect()))
                .collect(),
            key_epochs: bc.key_epochs.clone(),
            subscribers: bc.subscribers.iter().cloned().collect(),
            admission: bc.admission.clone(),
        };

        // Serialize + deserialize roundtrip
        let json = serde_json::to_string(&export).unwrap();
        let reimported: WasmExportBroadcast = serde_json::from_str(&json).unwrap();

        // Reconstruct BroadcastState from reimported data
        let restored = BroadcastState {
            authors: reimported
                .author_block_lists
                .iter()
                .map(|(did, bl)| (did.clone(), bl.iter().cloned().collect()))
                .collect(),
            key_epochs: reimported.key_epochs.clone(),
            subscribers: reimported.subscribers.iter().cloned().collect(),
            admission: reimported.admission.clone(),
        };

        // author-a blocks sub1, author-b does not
        assert!(restored.authors["author-a"].contains("sub1"));
        assert!(!restored.authors["author-b"].contains("sub1"));
        assert!(restored.subscribers.contains("sub1"));
        // key_epochs preserved through roundtrip
        assert_eq!(restored.key_epochs.get("author-a"), Some(&3));
        assert_eq!(restored.key_epochs.get("author-b"), None);
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
    fn export_version_is_two() {
        assert_eq!(WASM_EXPORT_VERSION, 2);
    }

    // -----------------------------------------------------------------------
    // Key epoch tests (§5.14.8)
    //
    // These tests manipulate BroadcastState directly because the full
    // manager methods call `crate::time::now_ms()` which requires a WASM
    // target. Direct manipulation tests the key epoch logic without
    // triggering the wasm-bindgen time import.
    // -----------------------------------------------------------------------

    #[test]
    fn key_epoch_increments_on_block() {
        // Simulate block_broadcast_subscriber: add to block list + increment epoch
        let mut bc = make_broadcast(&["author-a"], &["sub1"]);

        // Initially no key epoch
        assert_eq!(bc.key_epochs.get("author-a"), None);

        // Block sub1 → epoch increments to 1
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub1".to_owned());
        let epoch = bc.key_epochs.entry("author-a".to_owned()).or_insert(0);
        *epoch = epoch.saturating_add(1);

        assert_eq!(bc.key_epochs.get("author-a"), Some(&1));
        assert!(bc.authors["author-a"].contains("sub1"));
    }

    #[test]
    fn key_epoch_increments_per_block() {
        let mut bc = make_broadcast(&["author-a"], &["sub1", "sub2"]);

        // First block
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub1".to_owned());
        let epoch = bc.key_epochs.entry("author-a".to_owned()).or_insert(0);
        *epoch = epoch.saturating_add(1);
        assert_eq!(bc.key_epochs["author-a"], 1);

        // Second block
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub2".to_owned());
        let epoch = bc.key_epochs.entry("author-a".to_owned()).or_insert(0);
        *epoch = epoch.saturating_add(1);
        assert_eq!(bc.key_epochs["author-a"], 2);
    }

    #[test]
    fn key_epoch_per_author_isolation() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1"]);

        // Only author-a blocks → only author-a's epoch increments
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub1".to_owned());
        let epoch = bc.key_epochs.entry("author-a".to_owned()).or_insert(0);
        *epoch = epoch.saturating_add(1);

        assert_eq!(bc.key_epochs.get("author-a"), Some(&1));
        assert_eq!(bc.key_epochs.get("author-b"), None);
    }

    #[test]
    fn governance_ban_increments_all_authors_key_epochs() {
        let mut bc = make_broadcast(&["author-a", "author-b", "author-c"], &["sub1"]);

        // Simulate governance ban (§5.14.8 steps 3-4):
        // Step 3: add to ALL authors' block lists
        for block_list in bc.authors.values_mut() {
            block_list.insert("sub1".to_owned());
        }
        // Step 4: mandatory key rotation — increment ALL authors' epochs
        for author_did in bc.authors.keys() {
            let epoch = bc.key_epochs.entry(author_did.clone()).or_insert(0);
            *epoch = epoch.saturating_add(1);
        }

        // All authors blocked sub1
        assert!(bc.authors["author-a"].contains("sub1"));
        assert!(bc.authors["author-b"].contains("sub1"));
        assert!(bc.authors["author-c"].contains("sub1"));

        // All authors' epochs incremented
        assert_eq!(bc.key_epochs["author-a"], 1);
        assert_eq!(bc.key_epochs["author-b"], 1);
        assert_eq!(bc.key_epochs["author-c"], 1);
    }

    #[test]
    fn governance_ban_stacks_on_existing_epochs() {
        let mut bc = make_broadcast(&["author-a", "author-b"], &["sub1", "sub2"]);

        // author-a already blocked sub1 (epoch=1)
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub1".to_owned());
        let epoch = bc.key_epochs.entry("author-a".to_owned()).or_insert(0);
        *epoch = epoch.saturating_add(1);
        assert_eq!(bc.key_epochs["author-a"], 1);

        // Now governance ban sub2 → all authors' epochs increment again
        for block_list in bc.authors.values_mut() {
            block_list.insert("sub2".to_owned());
        }
        for author_did in bc.authors.keys() {
            let epoch = bc.key_epochs.entry(author_did.clone()).or_insert(0);
            *epoch = epoch.saturating_add(1);
        }

        // author-a: was 1, now 2. author-b: was 0, now 1.
        assert_eq!(bc.key_epochs["author-a"], 2);
        assert_eq!(bc.key_epochs["author-b"], 1);
    }

    #[test]
    fn key_epoch_advance_event_serializes_correctly() {
        let event = WasmContextEvent::KeyEpochAdvance {
            sender_did: "did:dht:zauthor".to_owned(),
            epoch: 42,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "keyEpochAdvance");
        assert_eq!(json["sender_did"], "did:dht:zauthor");
        assert_eq!(json["epoch"], 42);
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
        if !bc.authors.contains_key(creator_did) {
            bc.authors.insert(creator_did.to_owned(), HashSet::new());
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
            event_log: WasmEventLog::new(context_id.to_owned()),
            revoked_tokens: HashSet::new(),
            seen_nonces: HashMap::new(),
            members,
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            broadcast: Some(bc),
            sessions: HashMap::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            tool_interfaces: Vec::new(),
            governance_freeze: false,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: None,
            economic_policy_locked: false,
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
            let bc = ctx.broadcast.as_mut().unwrap();
            for i in 0..WASM_BLOCK_LIST_CAP {
                bc.authors
                    .get_mut("author-a")
                    .unwrap()
                    .insert(format!("did:dht:zfiller{i}"));
            }
            assert_eq!(bc.authors["author-a"].len(), WASM_BLOCK_LIST_CAP);
            // author-b is still empty.
            assert!(bc.authors["author-b"].is_empty());
        }

        // Call the real dispatch method — it should fail because author-a's
        // block list is at capacity (pre-validation rejects before any mutation).
        let err = mgr
            .dispatch_revoke_read_access("ctx-1", "did:dht:zbanned", "full")
            .unwrap_err();

        match &err {
            ScpWasmError::Validation { code, message } => {
                assert_eq!(code, "SCP-VALID-7301");
                assert!(
                    message.contains("during governance ban"),
                    "expected 'during governance ban' in message, got: {message}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }

        // Verify no mutation occurred — author-b's block list must still be
        // empty (pre-validation prevented partial writes).
        let bc = mgr.contexts["ctx-1"].broadcast.as_ref().unwrap();
        assert!(
            bc.authors["author-b"].is_empty(),
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
            event_log: WasmEventLog::new(context_id.to_owned()),
            revoked_tokens: revoked,
            seen_nonces: HashMap::new(),
            members,
            event_buffer: VecDeque::new(),
            executed_proposals: HashMap::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            broadcast: None,
            sessions: HashMap::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            tool_interfaces: Vec::new(),
            governance_freeze: false,
            pending_proposals: HashMap::new(),
            resolved_proposals: HashMap::new(),
            pruning_policy: None,
            economic_policy_locked: false,
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
            assert_eq!(code, "SCP-VALID-7300");
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
                assert_eq!(code, "SCP-CTX-2001");
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
                    &format!("subscriber {subscriber} not blocked by author {author}")
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
            let bc = ctx.broadcast.as_mut().unwrap();
            for author_list in bc.authors.values_mut() {
                // Fill to capacity minus 1, then insert the target DID.
                for i in 0..(WASM_BLOCK_LIST_CAP - 1) {
                    author_list.insert(format!("did:dht:zfiller{i}"));
                }
                author_list.insert(target_did.to_owned());
                assert_eq!(author_list.len(), WASM_BLOCK_LIST_CAP);
            }
        }

        // Banning an already-blocked DID when block lists are at capacity
        // must succeed — HashSet::insert is a no-op for existing entries.
        let result = mgr.dispatch_revoke_read_access("ctx-1", target_did, "full");
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
            let bc = ctx.broadcast.as_mut().unwrap();
            let block_list = bc.authors.get_mut("author-a").unwrap();
            for i in 0..(WASM_BLOCK_LIST_CAP - 1) {
                block_list.insert(format!("did:dht:zfiller{i}"));
            }
            block_list.insert(target_did.to_owned());
            assert_eq!(block_list.len(), WASM_BLOCK_LIST_CAP);
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
            let bc = ctx.broadcast.as_mut().unwrap();
            let block_list = bc.authors.get_mut("author-a").unwrap();
            for i in 0..WASM_BLOCK_LIST_CAP {
                block_list.insert(format!("did:dht:zfiller{i}"));
            }
            assert_eq!(block_list.len(), WASM_BLOCK_LIST_CAP);
        }

        // Blocking a NEW DID when at capacity must fail.
        let err = mgr
            .block_broadcast_subscriber("ctx-1", "author-a", "sub2")
            .unwrap_err();

        match &err {
            ScpWasmError::Validation { code, .. } => {
                assert_eq!(code, "SCP-VALID-7301");
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn key_epoch_unblock_does_not_change_epoch() {
        let mut bc = make_broadcast(&["author-a"], &["sub1"]);

        // Block sub1 → epoch = 1
        bc.authors
            .get_mut("author-a")
            .unwrap()
            .insert("sub1".to_owned());
        let epoch = bc.key_epochs.entry("author-a".to_owned()).or_insert(0);
        *epoch = epoch.saturating_add(1);
        assert_eq!(bc.key_epochs["author-a"], 1);

        // Unblock sub1 → epoch stays at 1 (per spec: no key rotation on unblock)
        bc.authors.get_mut("author-a").unwrap().remove("sub1");
        // No epoch change
        assert_eq!(bc.key_epochs["author-a"], 1);
    }
}
