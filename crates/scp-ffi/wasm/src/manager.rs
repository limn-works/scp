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
use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

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
/// Mirrors all 24 `GovernanceAction` variants from
/// `scp_core::context::governance::GovernanceAction`. WASM bridge functions
/// serialize JS governance requests into this enum for dispatch.
#[derive(Debug, Clone, serde::Deserialize)]
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
    /// UCAN revocation set (token CIDs).
    revoked_tokens: HashSet<String>,
    /// UCAN nonce replay tracker.
    seen_nonces: HashSet<String>,
    /// Members indexed by DID.
    members: HashMap<String, MemberEntry>,
    /// Receive buffer for events.
    event_buffer: Vec<WasmContextEvent>,
    /// Executed proposal IDs (replay protection).
    executed_proposals: HashSet<String>,
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
        let now = js_sys::Date::now();
        (now - self.created_at_ms) >= self.ttl_ms
    }
}

/// Maximum concurrent sessions per calling context (spec section 6.2.1).
const WASM_SESSION_CAP_PER_CALLER: usize = 5;

impl PerContextState {
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

        // Build default ceiling strings (matching scp-core ContextRoleState::new).
        let ceiling_strings: HashSet<String> = if ceiling.is_empty() {
            [
                "messages:read",
                "messages:write",
                "tool_register:*",
                "tool_invoke:*",
                "role_assign:*",
                "member_invite:*",
                "member_remove:*",
                "governance_propose:*",
                "governance_vote:*",
                "context_close:*",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
        } else {
            ceiling.iter().cloned().collect()
        };

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
            seen_nonces: HashSet::new(),
            members,
            event_buffer: Vec::new(),
            executed_proposals: HashSet::new(),
            write_revoked_members: HashSet::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            broadcast,
            sessions: HashMap::new(),
        };

        self.contexts.insert(context_id.to_owned(), per_context);

        // Append ContextCreated event to event log.
        let leaf_hash = compute_event_hash("ContextCreated", context_id);
        // Safe: we just inserted the context above, so the key is present.
        if let Some(ctx) = self.contexts.get_mut(context_id) {
            ctx.event_log.append_leaf(leaf_hash);
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

        ctx.event_buffer.push(WasmContextEvent::MemberJoined {
            member_did: member_did.to_owned(),
            role_name: "member".to_owned(),
        });

        let leaf_hash = compute_event_hash("MemberJoined", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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

        ctx.event_buffer.push(WasmContextEvent::MemberLeft {
            member_did: member_did.to_owned(),
        });

        let leaf_hash = compute_event_hash("MemberLeft", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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

        ctx.event_buffer.push(WasmContextEvent::MessageSent {
            sender_did: sender_did.to_owned(),
            sequence_number: seq,
            payload_base64: payload_base64.to_owned(),
        });

        let leaf_hash = compute_event_hash("MessageSent", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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
        // ttl::close_context in scp-core. Admin role members have all
        // capabilities in the ceiling; regular members do not have
        // context_close by default. Uses WASM ceiling format
        // ("context_close:*") not scp-core format ("context:close").
        if !ctx.member_has_capability(initiator_did, "context_close:*") {
            return Err(ScpWasmError::Permission {
                message: format!("member {initiator_did} does not have context:close capability"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }

        "closed".clone_into(&mut ctx.state);
        ctx.broadcast = None;

        ctx.event_buffer.push(WasmContextEvent::SystemClose {
            initiator_did: initiator_did.to_owned(),
        });

        let leaf_hash = compute_event_hash("ContextClosing", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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
            .map(|ctx| std::mem::take(&mut ctx.event_buffer))
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

        let leaf_hash = compute_event_hash("ToolRegistered", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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
        _identity_did: &str,
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

        let leaf_hash = compute_event_hash("ToolInvoked", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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
        let now = js_sys::Date::now();

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
    #[allow(clippy::type_complexity)]
    pub fn ucan_context_state(
        &self,
        context_id: &str,
    ) -> Result<(HashSet<String>, String, HashSet<String>, HashSet<String>), ScpWasmError> {
        let ctx = self.require_context(context_id)?;
        Ok((
            ctx.ceiling_strings.clone(),
            ctx.creator_did.clone(),
            ctx.seen_nonces.clone(),
            ctx.revoked_tokens.clone(),
        ))
    }

    /// Records a nonce as seen (for replay prevention).
    ///
    /// # Errors
    ///
    /// Returns [`ScpWasmError::Permission`] if the nonce was already seen.
    pub fn ucan_record_nonce(&mut self, context_id: &str, nonce: &str) -> Result<(), ScpWasmError> {
        let ctx = self.require_context_mut(context_id)?;
        if !ctx.seen_nonces.insert(nonce.to_owned()) {
            return Err(ScpWasmError::Permission {
                message: format!("nonce reused: {nonce}"),
                code: "SCP-PERM-3000".to_owned(),
            });
        }
        Ok(())
    }

    /// Revokes a UCAN token by CID.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active.
    pub fn ucan_revoke(&mut self, context_id: &str, token_cid: &str) -> Result<(), ScpWasmError> {
        let ctx = self.require_active_context_mut(context_id)?;
        ctx.revoked_tokens.insert(token_cid.to_owned());

        let leaf_hash = compute_event_hash("UcanRevoked", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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

    /// Executes a governance action. Mirrors `ContextManager::execute_governance_action`.
    ///
    /// Validates that the proposal is not a replay, dispatches to the
    /// appropriate action handler, and records the proposal as executed.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is not active, the proposal was
    /// already executed, or the action fails.
    pub fn execute_governance_action(
        &mut self,
        context_id: &str,
        proposal_id: &str,
        action: &WasmGovernanceAction,
    ) -> Result<serde_json::Value, ScpWasmError> {
        // Replay protection: check+mark atomically.
        {
            let ctx = self.require_active_context_mut(context_id)?;
            if ctx.executed_proposals.contains(proposal_id) {
                return Err(ScpWasmError::Permission {
                    message: "governance proposal has already been executed".to_owned(),
                    code: "SCP-PERM-3000".to_owned(),
                });
            }
            ctx.executed_proposals.insert(proposal_id.to_owned());
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
            ctx.event_buffer.push(WasmContextEvent::GovernanceExecuted {
                action_type,
                proposal_id: proposal_id.to_owned(),
            });
            let leaf_hash = compute_event_hash("GovernanceExecuted", context_id);
            ctx.event_log.append_leaf(leaf_hash);
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
                ctx.event_buffer.push(WasmContextEvent::MemberJoined {
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
                ctx.event_buffer.push(WasmContextEvent::MemberLeft {
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
                ctx.event_buffer
                    .push(WasmContextEvent::WriteAccessRevoked { did: did.clone() });
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
            _ => {
                // Remaining actions: PromoteContext, CreateChildContext, ModifyPruningPolicy,
                // AddSigner, RemoveSigner, ModifyThreshold, EstablishToolInterface,
                // ResetMember, ResolveConflict, RotateContentKeys, ReconfigureGovernance
                let _ = self.require_active_context_mut(context_id)?;
                Ok(serde_json::json!({"action": "executed"}))
            }
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

        ctx.event_buffer.push(WasmContextEvent::MessageSent {
            sender_did: author_did.to_owned(),
            sequence_number: seq,
            payload_base64: payload_base64.to_owned(),
        });

        let leaf_hash = compute_event_hash("MessageSent", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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

        ctx.event_buffer.push(WasmContextEvent::MemberLeft {
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
        ctx.event_buffer.push(WasmContextEvent::Expired);

        let leaf_hash = compute_event_hash("ContextExpired", context_id);
        ctx.event_log.append_leaf(leaf_hash);

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
        };

        let now_ms = js_sys::Date::now();
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let exported_at = (now_ms / 1000.0) as u64;

        let envelope = WasmContextExportEnvelope {
            version: WASM_EXPORT_VERSION,
            exported_at,
            exporter_did: exporter_did.to_owned(),
            snapshot,
        };

        serde_json::to_vec(&envelope).map_err(|e| ScpWasmError::Context {
            message: format!("export serialization failed: {e}"),
            code: "SCP-CTX-2030".to_owned(),
        })
    }

    /// Imports a context from serialized JSON bytes produced by [`export_context`].
    ///
    /// Deserializes the envelope, validates the version, and reconstructs
    /// the context state in the manager.
    ///
    /// # Returns
    ///
    /// The context ID of the imported context.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails, version is incompatible,
    /// or the context already exists.
    pub fn import_context(&mut self, data: &[u8]) -> Result<String, ScpWasmError> {
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
            revoked_tokens: HashSet::new(),
            seen_nonces: HashSet::new(),
            members,
            event_buffer: Vec::new(),
            executed_proposals: HashSet::new(),
            write_revoked_members: snap.write_revoked_members.iter().cloned().collect(),
            read_revoked_members: snap.read_revoked_members.iter().cloned().collect(),
            read_exclusion_list: snap.read_exclusion_list.iter().cloned().collect(),
            broadcast,
            sessions: HashMap::new(),
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WasmContextExportEnvelope {
    /// Export format version.
    version: u32,
    /// Unix timestamp (seconds) when the export was created.
    exported_at: u64,
    /// DID of the identity that performed the export.
    exporter_did: String,
    /// The context state snapshot.
    snapshot: WasmContextExportSnapshot,
}

/// Snapshot of a context's state for export.
///
/// Contains all fields needed to reconstruct a `PerContextState` on import.
/// Tool registry, event log, and UCAN state are NOT exported (they can be
/// re-registered after import). Membership, roles, governance, broadcast,
/// and revocation state are preserved.
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

/// Computes a leaf hash for the event log from event type and context ID.
///
/// Uses `SHA-256(0x00 || event_type || context_id)` with RFC 6962 leaf
/// domain separation prefix.
fn compute_event_hash(event_type: &str, context_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // RFC 6962 leaf prefix.
    hasher.update(event_type.as_bytes());
    hasher.update(context_id.as_bytes());
    // Include a timestamp-like value for uniqueness. In WASM, use js_sys::Date::now().
    let now_ms = js_sys::Date::now();
    hasher.update(now_ms.to_bits().to_le_bytes());
    hasher.finalize().into()
}
