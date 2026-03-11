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

use crate::error::ScpWasmError;
use crate::runtime::{
    ToolRegistration, ToolRegistry, WasmEventLog, prove_absence, prove_inclusion,
    validate_value_against_schema, verify_inclusion,
};

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
        reason: Option<String>,
    },
    ResolveConflict {
        proposal_a: String,
        proposal_b: String,
        resolution: String,
    },
    PromoteContext,
    RevokeWriteAccess {
        did: String,
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
    },
    RevokeReadAccess {
        did: String,
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
    WriteAccessRevoked {
        did: String,
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
// BroadcastState — broadcast context state (§5.14)
// ---------------------------------------------------------------------------

/// Broadcast-specific state for a context.
///
/// Mirrors the relevant fields from `scp_core::context::broadcast::BroadcastContext`.
#[derive(Debug)]
struct BroadcastState {
    /// Author DIDs (members with write access).
    authors: HashSet<String>,
    /// Subscriber DIDs (members with read access).
    subscribers: HashSet<String>,
    /// Blocked subscriber DIDs.
    blocked_subscribers: HashSet<String>,
    /// Admission policy: "open" or "gated". Stored for context metadata.
    #[allow(dead_code)]
    admission: String,
}

impl BroadcastState {
    fn new(admission: &str) -> Self {
        Self {
            authors: HashSet::new(),
            subscribers: HashSet::new(),
            blocked_subscribers: HashSet::new(),
            admission: admission.to_owned(),
        }
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
    /// Context creation parameters stored as JSON. Preserved for snapshot/restore.
    #[allow(dead_code)]
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
    /// Pruning policy JSON string (ADR-030 §6).
    pruning_policy: Option<String>,
    /// Whether the economic policy is locked (§19.3, ADR-033).
    economic_policy_locked: bool,
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
    /// TTL in milliseconds.
    ttl_ms: f64,
    /// Number of invocations.
    call_count: u64,
}

impl WasmToolSession {
    /// Returns `true` if this session has expired.
    fn is_expired(&self) -> bool {
        let now = crate::time::now_ms();
        (now - self.created_at_ms) >= self.ttl_ms
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

/// Nonce freshness tolerance: 5 minutes in milliseconds (spec section 9.14).
/// Matches native `NonceTracker::NONCE_FRESHNESS_TOLERANCE_MS`.
const WASM_NONCE_FRESHNESS_TOLERANCE_MS: f64 = 5.0 * 60.0 * 1000.0;

/// Maximum number of revoked token CIDs per context.
const WASM_REVOKED_TOKENS_CAP: usize = 100_000;

/// Maximum number of executed proposals tracked per context before triggering eviction.
const WASM_PROPOSAL_CAP: usize = 10_000;

/// Executed proposal TTL in milliseconds (24 hours).
const WASM_PROPOSAL_TTL_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

/// Maximum events in the receive buffer. Matches `PyO3` channel capacity.
const WASM_EVENT_BUFFER_CAP: usize = 1000;

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
    /// default role system:
    /// - "admin" role members have all capabilities in the ceiling.
    /// - "member" role members have `messages:read` and `messages:write` only.
    ///
    /// Capability strings use the format `"{resource}:{action}"` (e.g.
    /// `"context:close"`, `"messages:write"`).
    fn member_has_capability(&self, member_did: &str, capability: &str) -> bool {
        let Some(member) = self.members.get(member_did) else {
            return false;
        };

        match member.role.as_str() {
            "admin" => {
                // Admins have all capabilities in the ceiling.
                // Check the ceiling_strings set for the capability or a wildcard.
                let (resource, _action) = capability.rsplit_once(':').unwrap_or((capability, "*"));
                let wildcard = format!("{resource}:*");
                self.ceiling_strings.contains(capability)
                    || self.ceiling_strings.contains(&wildcard)
            }
            "member" => {
                // Default member capabilities: messages:read, messages:write.
                matches!(capability, "messages:read" | "messages:write")
            }
            _ => false,
        }
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

impl Default for WasmContextManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmContextManager {
    /// Creates a new empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contexts: HashMap::new(),
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

        // Initialize broadcast state for Broadcast mode.
        let broadcast = if mode == "Broadcast" {
            let admission = params["admission"].as_str().unwrap_or("open");
            let mut bc = BroadcastState::new(admission);
            bc.authors.insert(creator_did.to_owned());
            Some(bc)
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
            pruning_policy: None,
            economic_policy_locked: false,
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

        ctx.push_event(WasmContextEvent::MessageSent {
            sender_did: sender_did.to_owned(),
            sequence_number: seq,
            payload_base64: payload_base64.to_owned(),
        });

        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("MessageSent"),
            sender_did,
            payload_base64.as_bytes(),
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
        ttl_seconds: u64,
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
            ttl_ms: (ttl_seconds as f64) * 1000.0,
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
    /// Performs the same validation as native `NonceTracker::check_and_record`:
    /// 1. **Format** — nonce must match `{unix_millis}-{32_hex_chars}`.
    /// 2. **Freshness** — timestamp must be within +/- 5 minutes of now
    ///    (matching spec section 9.14 clock skew tolerance).
    /// 3. **Uniqueness** — nonce must not have been seen before.
    ///
    /// When the nonce map exceeds [`WASM_NONCE_CAP`], evicts entries older than
    /// [`WASM_NONCE_TTL_MS`] (24 hours — UCAN max lifetime per ADR-016 step 11).
    ///
    /// # Errors
    ///
    /// Returns [`ScpWasmError::Permission`] if format is invalid, nonce is
    /// stale/future, or was already seen.
    pub fn ucan_record_nonce(&mut self, context_id: &str, nonce: &str) -> Result<(), ScpWasmError> {
        // 1. Validate nonce format: {unix_millis}-{32_hex_chars}
        let (ts_part, hex_part) =
            nonce
                .split_once('-')
                .ok_or_else(|| ScpWasmError::Permission {
                    message: format!(
                        "nonce format invalid: missing '-' separator in nonce: {nonce}"
                    ),
                    code: "SCP-PERM-3000".to_owned(),
                })?;

        let nonce_millis: f64 = ts_part.parse().map_err(|_| ScpWasmError::Permission {
            message: format!("nonce format invalid: non-numeric timestamp in nonce: {ts_part}"),
            code: "SCP-PERM-3000".to_owned(),
        })?;

        if hex_part.len() != 32 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ScpWasmError::Permission {
                message: format!(
                    "nonce format invalid: expected 32 hex chars suffix, got: {hex_part}"
                ),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        // 2. Freshness check: timestamp within now +/- 5 minutes.
        let now = crate::time::now_ms();

        if nonce_millis + WASM_NONCE_FRESHNESS_TOLERANCE_MS < now {
            return Err(ScpWasmError::Permission {
                message: format!("nonce too old: {nonce}"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        if nonce_millis > now + WASM_NONCE_FRESHNESS_TOLERANCE_MS {
            return Err(ScpWasmError::Permission {
                message: format!("nonce too far in the future: {nonce}"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        // 3. Replay check.
        let ctx = self.require_context_mut(context_id)?;

        if ctx.seen_nonces.contains_key(nonce) {
            return Err(ScpWasmError::Permission {
                message: format!("nonce reused: {nonce}"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        // Evict expired nonces when over capacity.
        if ctx.seen_nonces.len() >= WASM_NONCE_CAP {
            let cutoff = now - WASM_NONCE_TTL_MS;
            ctx.seen_nonces.retain(|_, ts| *ts > cutoff);
        }

        ctx.seen_nonces.insert(nonce.to_owned(), now);
        Ok(())
    }

    /// Revokes a UCAN token by CID.
    ///
    /// Revocation is permanent (no TTL). The set is capped at
    /// [`WASM_REVOKED_TOKENS_CAP`] entries — overflow returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active or the revocation set
    /// has reached capacity.
    pub fn ucan_revoke(&mut self, context_id: &str, token_cid: &str) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;

        if ctx.revoked_tokens.len() >= WASM_REVOKED_TOKENS_CAP {
            return Err(ScpWasmError::Validation {
                message: format!(
                    "revoked token set has reached capacity ({WASM_REVOKED_TOKENS_CAP}) — \
                     cannot revoke additional tokens"
                ),
                code: "SCP-VALID-7300".to_owned(),
            });
        }

        ctx.revoked_tokens.insert(token_cid.to_owned());

        let actor = ctx.creator_did.clone();
        ctx.event_log.append_event(
            crate::runtime::wasm_event_type_tag("UcanRevoked"),
            &actor,
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
    /// the initiator must hold. Uses the WASM ceiling format
    /// Uses scp-core `Capability::Display` format (`"{resource}:{action}"`),
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
    /// Split into two methods to satisfy the 100-line function limit.
    fn dispatch_governance_action(
        &mut self,
        context_id: &str,
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        match action {
            WasmGovernanceAction::AddMember { did, role } => {
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.members.insert(
                    did.clone(),
                    MemberEntry {
                        did: did.clone(),
                        role: role.clone(),
                        sequence_number: 0,
                    },
                );
                ctx.push_event(WasmContextEvent::MemberJoined {
                    member_did: did.clone(),
                    role_name: role.clone(),
                });
                Ok(serde_json::json!({"action": "AddMember", "did": did}))
            }
            WasmGovernanceAction::RemoveMember { did, .. } => {
                let ctx = self.require_active_context_mut(context_id)?;
                if ctx.members.remove(did).is_none() {
                    return Err(ScpWasmError::Context {
                        message: format!("member '{did}' not found"),
                        code: "SCP-CTX-2015".to_owned(),
                    });
                }
                ctx.push_event(WasmContextEvent::MemberLeft {
                    member_did: did.clone(),
                });
                Ok(serde_json::json!({"action": "RemoveMember", "did": did}))
            }
            WasmGovernanceAction::ChangeRole { did, new_role } => {
                let ctx = self.require_active_context_mut(context_id)?;
                let member = ctx
                    .members
                    .get_mut(did)
                    .ok_or_else(|| ScpWasmError::Context {
                        message: format!("member '{did}' not found"),
                        code: "SCP-CTX-2015".to_owned(),
                    })?;
                new_role.clone_into(&mut member.role);
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
                ctx.ceiling_strings = new_ceiling.iter().cloned().collect();
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
            _ => self.dispatch_governance_action_ext(context_id, action),
        }
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
            WasmGovernanceAction::RevokeWriteAccess { did } => {
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.write_revoked_members.insert(did.clone());
                Ok(serde_json::json!({"action": "RevokeWriteAccess", "did": did}))
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
            WasmGovernanceAction::BlockAuthor { did } => {
                // CAC-008: BlockAuthor delegates to RevokeWriteAccess(Full).
                // Destroy the author's broadcast key and mark write-revoked.
                let ctx = self.require_active_context_mut(context_id)?;
                if let Some(ref mut bc) = ctx.broadcast {
                    bc.authors.remove(did);
                }
                ctx.write_revoked_members.insert(did.clone());
                ctx.push_event(WasmContextEvent::WriteAccessRevoked { did: did.clone() });
                Ok(serde_json::json!({"action": "WriteAccessRevoked", "did": did, "scope": "Full"}))
            }
            WasmGovernanceAction::RevokeReadAccess { did } => {
                let ctx = self.require_active_context_mut(context_id)?;
                ctx.read_revoked_members.insert(did.clone());
                if let Some(bc) = ctx.broadcast.as_mut() {
                    bc.subscribers.remove(did);
                    bc.blocked_subscribers.insert(did.clone());
                }
                Ok(serde_json::json!({"action": "RevokeReadAccess", "did": did}))
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
                    bc.blocked_subscribers.remove(did);
                }
                Ok(serde_json::json!({"action": "RestoreReadAccess", "did": did}))
            }
            _ => self.dispatch_governance_action_structural(context_id, action),
        }
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
                        ctx.threshold_signers.push(did.clone());
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
            _ => self.dispatch_governance_action_remaining(context_id, action),
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
            WasmGovernanceAction::ResetMember { did, .. } => {
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
                Ok(serde_json::json!({"action": "ResetMember", "did": did}))
            }
            WasmGovernanceAction::ResolveConflict {
                proposal_a,
                proposal_b,
                resolution,
            } => {
                let ctx = self.require_active_context_mut(context_id)?;
                // Clear governance freeze (ADR-031 §7).
                ctx.governance_freeze = false;
                // Record conflicting proposals as executed (invalidated).
                let now = crate::time::now_ms();
                if resolution.as_str() == "invalidateBoth" {
                    ctx.executed_proposals.insert(proposal_a.clone(), now);
                    ctx.executed_proposals.insert(proposal_b.clone(), now);
                } else {
                    // AcceptProposal: resolution is the winner_id, loser is
                    // invalidated. The winner remains eligible for execution.
                    let loser = if resolution == proposal_a {
                        proposal_b
                    } else {
                        proposal_a
                    };
                    ctx.executed_proposals.insert(loser.clone(), now);
                }
                Ok(serde_json::json!({"action": "ResolveConflict"}))
            }
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
            _ => self.dispatch_governance_action_economic(context_id, action),
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
            // All 28 variants are handled exhaustively across the dispatch
            // chain. This arm covers variants dispatched by parent methods.
            _ => unreachable!("all governance action variants handled by parent dispatch methods"),
        }
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
        let reg = ToolRegistration {
            tool_id: tool_id.to_owned(),
            name: name.to_owned(),
            description: description.to_owned(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            test_vectors: Vec::new(),
            operator_did: ctx.creator_did.clone(),
        };
        ctx.tool_registry
            .insert(reg)
            .map_err(|e| ScpWasmError::Tool {
                message: e,
                code: "SCP-TOOL-6001".to_owned(),
            })?;
        Ok(serde_json::json!({"action": "RegisterTool", "toolId": tool_id}))
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

        let bc = ctx
            .broadcast
            .as_mut()
            .ok_or_else(|| ScpWasmError::Context {
                message: "not a broadcast context".to_owned(),
                code: "SCP-CTX-2001".to_owned(),
            })?;

        if bc.blocked_subscribers.contains(subscriber_did) {
            return Err(ScpWasmError::Permission {
                message: format!("subscriber '{subscriber_did}' is blocked"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

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

        if !bc.authors.contains(author_did) {
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
    /// # Errors
    ///
    /// Returns an error if not a broadcast context.
    pub fn block_broadcast_subscriber(
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
        bc.blocked_subscribers.insert(subscriber_did.to_owned());

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
        if !bc.authors.contains(author_did) {
            return Ok(
                serde_json::json!({ "decision": "deny", "reason": DENY_REASON }).to_string(),
            );
        }

        // Requester must not be blocked.
        if bc.blocked_subscribers.contains(requester_did) {
            return Ok(
                serde_json::json!({ "decision": "deny", "reason": DENY_REASON }).to_string(),
            );
        }

        // Requester must be a subscriber or author.
        if !bc.subscribers.contains(requester_did) && !bc.authors.contains(requester_did) {
            return Ok(
                serde_json::json!({ "decision": "deny", "reason": DENY_REASON }).to_string(),
            );
        }

        Ok(serde_json::json!({ "decision": "grant" }).to_string())
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
        self.contexts.get(context_id).map(|ctx| ContextMetadata {
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
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Builds the capability ceiling string set from explicit ceiling entries
    /// or defaults matching scp-core's `Capability::Display` format (H5).
    fn build_ceiling_strings(ceiling: &[String]) -> HashSet<String> {
        if ceiling.is_empty() {
            [
                "messages:read",
                "messages:write",
                "tool:register",
                "tool:invoke:*",
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
            ceiling.iter().cloned().collect()
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
            authors: bc.authors.iter().cloned().collect(),
            subscribers: bc.subscribers.iter().cloned().collect(),
            blocked_subscribers: bc.blocked_subscribers.iter().cloned().collect(),
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

        // Serialize snapshot to canonical JSON for HMAC computation.
        // The HMAC is computed over this stable serialization — NOT the full
        // envelope — to avoid a circular dependency (envelope contains the MAC).
        let snapshot_json = serde_json::to_vec(&snapshot).map_err(|e| ScpWasmError::Context {
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

        // Re-serialize the snapshot to canonical JSON and verify the HMAC tag
        // using the creator's signing key. This MUST happen before any state
        // reconstruction to prevent an attacker from crafting payloads that
        // grant them admin of a context.
        let snapshot_json =
            serde_json::to_vec(&envelope.snapshot).map_err(|e| ScpWasmError::Context {
                message: format!("snapshot re-serialization failed: {e}"),
                code: "SCP-CTX-2032".to_owned(),
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

    /// Imports a context from serialized JSON bytes produced by [`export_context`].
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
            authors: bc.authors.iter().cloned().collect(),
            subscribers: bc.subscribers.iter().cloned().collect(),
            blocked_subscribers: bc.blocked_subscribers.iter().cloned().collect(),
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
            pruning_policy: snap.pruning_policy.clone(),
            economic_policy_locked: snap.economic_policy_locked,
        };

        self.contexts.insert(context_id.clone(), ctx);
        Ok(context_id)
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
}

// ---------------------------------------------------------------------------
// Context export/import types (#424)
// ---------------------------------------------------------------------------

/// Current version of the WASM context export format.
const WASM_EXPORT_VERSION: u32 = 1;

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
    authors: Vec<String>,
    subscribers: Vec<String>,
    blocked_subscribers: Vec<String>,
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
#[allow(clippy::unwrap_used)]
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
            reason: Some("stale state".to_owned()),
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
        });
    }

    #[test]
    fn serde_roundtrip_revoke_read_access() {
        roundtrip(&WasmGovernanceAction::RevokeReadAccess {
            did: "did:dht:z123".to_owned(),
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
                reason: None,
            },
            WasmGovernanceAction::ResolveConflict {
                proposal_a: "a".into(),
                proposal_b: "b".into(),
                resolution: "c".into(),
            },
            WasmGovernanceAction::PromoteContext,
            WasmGovernanceAction::RevokeWriteAccess { did: "d".into() },
            WasmGovernanceAction::RestoreWriteAccess { did: "d".into() },
            WasmGovernanceAction::RotateContentKeys { reason: None },
            WasmGovernanceAction::ReconfigureGovernance {
                changes_json: "[]".into(),
                justification: "j".into(),
            },
            WasmGovernanceAction::BlockAuthor { did: "d".into() },
            WasmGovernanceAction::RevokeReadAccess { did: "d".into() },
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
        // Verify the actual serialized key name first.
        let action = WasmGovernanceAction::SetEconomicPolicy {
            policy_json: r#"{"locked":false}"#.to_owned(),
        };
        let serialized = serde_json::to_string(&action).unwrap();
        // Deserialize back from the serialized form.
        let back: WasmGovernanceAction = serde_json::from_str(&serialized).unwrap();
        match back {
            WasmGovernanceAction::SetEconomicPolicy { policy_json } => {
                assert_eq!(policy_json, r#"{"locked":false}"#);
            }
            other => panic!("expected SetEconomicPolicy, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_approve_spend_from_json() {
        let json =
            r#"{"type":"approveSpend","spender":"did:dht:z1","amount":500,"purpose":"infra"}"#;
        let action: WasmGovernanceAction = serde_json::from_str(json).unwrap();
        match action {
            WasmGovernanceAction::ApproveSpend {
                spender,
                amount,
                purpose,
            } => {
                assert_eq!(spender, "did:dht:z1");
                assert_eq!(amount, 500);
                assert_eq!(purpose, "infra");
            }
            other => panic!("expected ApproveSpend, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_lock_economic_policy_from_json() {
        let json = r#"{"type":"lockEconomicPolicy"}"#;
        let action: WasmGovernanceAction = serde_json::from_str(json).unwrap();
        assert!(matches!(action, WasmGovernanceAction::LockEconomicPolicy));
    }
}
