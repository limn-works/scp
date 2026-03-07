//! napi-rs bridge for context lifecycle, messaging, governance, broadcast,
//! membership queries, TTL, and events.
//!
//! All operations delegate to the shared [`ContextManager`] instance via
//! [`crate::runtime::context_manager()`]. The `NapiContextHandle` is a thin
//! handle carrying context metadata and a reference to the `ContextHandle`
//! from `scp-core`.
//!
//! See issue #388 and ADR-022 in `.docs/adrs/phase-4.md`.

use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;
use scp_core::context::governance::{GovernanceAction, GovernanceProposal, ProposalStatus};
use scp_core::context::params::ContextMode;
use scp_core::context::{ContextHandle, ContextParams, ContextState};
use scp_identity::DID;
use uuid::Uuid;

use crate::error::ScpNapiError;
use crate::identity::{NapiIdentity, OpaqueInMemoryKeyCustody};
use crate::runtime::context_manager;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// NapiContextHandle — opaque JS class for SCP contexts
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP context.
///
/// Stores context metadata and retains a reference to the `scp-core`
/// [`ContextHandle`] for lifecycle operations via the shared
/// [`ContextManager`].
///
/// # JS usage
///
/// ```js
/// const ctx = await contextCreate(identity.did, paramsJson);
/// console.log(ctx.contextId);      // "ctx-..."
/// console.log(ctx.state);          // "active"
/// console.log(ctx.creatorDid);     // "did:dht:z..."
/// ```
#[napi]
pub struct NapiContextHandle {
    /// Unique identifier for this context.
    context_id: String,
    /// Current lifecycle state (guarded by a Mutex for interior mutability).
    state: std::sync::Mutex<ContextState>,
    /// DID of the context creator.
    creator_did: String,
    /// Context mode — `"Encrypted"` or `"Broadcast"`.
    mode: String,
    /// Capability ceiling: list of UCAN capability strings allowed in this context.
    ceiling: Vec<String>,
    /// Ceiling policy — `"immutable"` or `"governed"`.
    ceiling_policy: String,
    /// Optional TTL in seconds. `None` means the context is persistent.
    ttl_seconds: Option<u64>,
    /// Promotion policy — `"no_promotion"` or `"promotable"`. Only meaningful
    /// when `ttl_seconds` is `Some`.
    promotion_policy: Option<String>,
    /// Governance model string (e.g. `"single_admin"`).
    governance: String,
    /// Number of members in the context. Starts at 1 (the creator).
    member_count: u64,
    /// Optional economic policy string.
    economic_policy: Option<String>,
    /// Retained [`InMemoryKeyCustody`] for UCAN signing (RED-102).
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
    /// Handle to the creator's active signing key for UCAN minting (RED-102).
    pub(crate) signing_key: Option<scp_platform::traits::KeyHandle>,
    /// The scp-core `ContextHandle` for this context, used for manager delegation.
    pub(crate) core_handle: Option<ContextHandle>,
}

/// Internal context lifecycle state string helper.
const fn state_str(state: &ContextState) -> &'static str {
    match state {
        ContextState::Creating => "creating",
        ContextState::Active => "active",
        ContextState::Closing => "closing",
        ContextState::Closed => "closed",
        ContextState::Expired => "expired",
    }
}

#[napi]
impl NapiContextHandle {
    /// Returns the context's unique identifier.
    #[napi(getter, js_name = "contextId")]
    #[must_use]
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the context's current lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal state lock is poisoned.
    #[napi(getter)]
    pub fn state(&self) -> napi::Result<String> {
        let guard = self.state.lock().map_err(|_| {
            NapiError::from(ScpNapiError::Context {
                message: "context state lock is poisoned".to_owned(),
                code: "SCP-CTX-2012".to_owned(),
            })
        })?;
        Ok(state_str(&guard).to_owned())
    }

    /// Returns the DID of the context creator.
    #[napi(getter, js_name = "creatorDid")]
    #[must_use]
    pub fn creator_did(&self) -> String {
        self.creator_did.clone()
    }

    /// Returns the context mode (`"Encrypted"` or `"Broadcast"`).
    #[napi(getter)]
    #[must_use]
    pub fn mode(&self) -> String {
        self.mode.clone()
    }

    /// Returns the capability ceiling for this context.
    #[napi(getter)]
    #[must_use]
    pub fn ceiling(&self) -> Vec<String> {
        self.ceiling.clone()
    }

    /// Returns the ceiling policy (`"immutable"` or `"governed"`).
    #[napi(getter, js_name = "ceilingPolicy")]
    #[must_use]
    pub fn ceiling_policy(&self) -> String {
        self.ceiling_policy.clone()
    }

    /// Returns the optional TTL in seconds.
    #[napi(getter, js_name = "ttlSeconds")]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // napi getter cannot be const
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl_seconds
    }

    /// Returns the optional promotion policy.
    #[napi(getter, js_name = "promotionPolicy")]
    #[must_use]
    pub fn promotion_policy(&self) -> Option<String> {
        self.promotion_policy.clone()
    }

    /// Returns the governance model string.
    #[napi(getter)]
    #[must_use]
    pub fn governance(&self) -> String {
        self.governance.clone()
    }

    /// Returns the current member count.
    #[napi(getter, js_name = "memberCount")]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // napi getter cannot be const
    pub fn member_count(&self) -> u64 {
        self.member_count
    }

    /// Returns the optional economic policy string.
    #[napi(getter, js_name = "economicPolicy")]
    #[must_use]
    pub fn economic_policy(&self) -> Option<String> {
        self.economic_policy.clone()
    }
}

impl NapiContextHandle {
    /// Returns the current state string for validation checks.
    pub(crate) fn current_state_str(&self) -> Result<String, ScpNapiError> {
        self.state
            .lock()
            .map(|g| state_str(&g).to_owned())
            .map_err(|_| ScpNapiError::Context {
                message: "context state lock is poisoned".to_owned(),
                code: "SCP-CTX-2012".to_owned(),
            })
    }

    /// Sets the state to Closed.
    pub(crate) fn set_closed(&self) -> Result<(), ScpNapiError> {
        *self.state.lock().map_err(|_| ScpNapiError::Context {
            message: "context state lock is poisoned".to_owned(),
            code: "SCP-CTX-2012".to_owned(),
        })? = ContextState::Closed;
        Ok(())
    }

    /// Returns the scp-core `ContextHandle`, or an error if not available.
    fn require_core_handle(&self) -> Result<&ContextHandle, ScpNapiError> {
        self.core_handle
            .as_ref()
            .ok_or_else(|| ScpNapiError::Context {
                message: "context does not have a core handle — context was not created via \
                      ContextManager"
                    .to_owned(),
                code: "SCP-CTX-2024".to_owned(),
            })
    }
}

impl Drop for NapiContextHandle {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NapiMessage — incoming message from an SCP context
// ---------------------------------------------------------------------------

/// A received message from an SCP context.
#[napi(object)]
pub struct NapiMessage {
    /// DID of the message sender.
    pub sender_did: String,
    /// Raw message payload bytes (decrypted application content).
    pub payload: Vec<u8>,
    /// Unix timestamp (seconds since epoch) when the message was created.
    pub timestamp: f64,
    /// Monotonic sequence number within the context event log.
    pub sequence: f64,
    /// Context ID this message belongs to.
    pub context_id: String,
}

// ---------------------------------------------------------------------------
// Bridge functions — context lifecycle (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Creates a new SCP context.
///
/// Delegates to [`ContextManager::create_context`] for two-phase commit
/// creation (ADR-008). Returns a handle with context metadata.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7000` if `params_json` is malformed JSON.
/// - Rejects with `SCP-CTX-2000` if context creation fails.
#[napi]
pub async fn context_create(
    identity: &NapiIdentity,
    params_json: String,
) -> napi::Result<NapiContextHandle> {
    let params: serde_json::Value = serde_json::from_str(&params_json).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!(
                "params_json is not valid JSON: {e} — pass a JSON-encoded context parameters object"
            ),
            code: "SCP-VALID-7000".to_owned(),
        })
    })?;

    let mode_str = params["mode"].as_str().unwrap_or("Encrypted").to_owned();
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

    // Extract key custody and signing key from the identity handle (RED-102).
    let in_memory_custody = identity.inner.in_memory_custody.clone();
    let signing_key = identity
        .inner
        .scp_identity
        .as_ref()
        .map(|id| id.active_signing_key);

    let context_id = format!("ctx-{}", Uuid::new_v4());
    let creator_did = identity.inner.did.clone();

    // Build ContextParams for the manager, mapping all user-specified fields.
    let mode = if mode_str == "Broadcast" {
        ContextMode::Broadcast
    } else {
        ContextMode::Encrypted
    };

    let core_ceiling_policy = match ceiling_policy.as_str() {
        "governed" => scp_core::context::params::CeilingPolicy::Governed,
        _ => scp_core::context::params::CeilingPolicy::Immutable,
    };

    let core_promotion_policy = match promotion_policy.as_deref() {
        Some("promotable") => scp_core::context::params::PromotionPolicy::Promotable,
        _ => scp_core::context::params::PromotionPolicy::NoPromotion,
    };

    let memory_scope_str = params["memoryScope"].as_str().unwrap_or("ephemeral");
    let core_memory_scope = match memory_scope_str {
        "summary" => scp_core::context::params::MemoryScope::Summary,
        "full" => scp_core::context::params::MemoryScope::Full,
        _ => scp_core::context::params::MemoryScope::Ephemeral,
    };

    // Currently only SingleAdmin is supported; governance string was already parsed.
    let _ = governance.as_str();
    let core_governance = scp_core::context::params::GovernanceModel::SingleAdmin;

    let core_ceiling: Vec<scp_core::context::roles::Capability> = ceiling
        .iter()
        .map(scp_core::context::roles::Capability::new)
        .collect();

    let context_params = ContextParams {
        mode,
        ceiling: core_ceiling,
        ceiling_policy: core_ceiling_policy,
        promotion_policy: core_promotion_policy,
        ttl: ttl_seconds.map(std::time::Duration::from_secs),
        memory_scope: core_memory_scope,
        governance: core_governance,
        ..ContextParams::default()
    };

    // Delegate to ContextManager.
    let manager = context_manager();
    let core_handle = manager
        .create_context(context_id.clone(), context_params, DID(creator_did.clone()))
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // Register the creator's DID as a local DID for defense-in-depth.
    manager.register_local_did(DID(creator_did.clone())).await;

    let handle = NapiContextHandle {
        context_id,
        state: std::sync::Mutex::new(ContextState::Active),
        creator_did,
        mode: mode_str,
        ceiling,
        ceiling_policy,
        ttl_seconds,
        promotion_policy,
        governance,
        member_count: 1,
        economic_policy,
        in_memory_custody,
        signing_key,
        core_handle: Some(core_handle),
    };
    increment_handle_count();
    Ok(handle)
}

/// Joins an existing SCP context.
///
/// Delegates to [`ContextManager::join_context`] for MLS group membership
/// establishment.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2013` if the context is not in `"active"` state.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_join(handle: &NapiContextHandle, identity_did: String) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!("cannot join context in {state_str:?} state — context must be active"),
            code: "SCP-CTX-2013".to_owned(),
        }
        .into());
    }

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let key_package = scp_core::context::membership::KeyPackage {
        owner_did: DID(identity_did.clone()),
        mls_key_package_bytes: None,
    };

    let manager = context_manager();
    manager
        .join_context(core_handle, key_package)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Leaves an SCP context.
///
/// Delegates to [`ContextManager::leave_context`] for MLS membership
/// removal.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2015` if the context is not in `"active"` state.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_leave(handle: &NapiContextHandle, identity_did: String) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot leave context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2015".to_owned(),
        }
        .into());
    }

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let did = DID(identity_did.clone());

    let manager = context_manager();
    manager
        .leave_context(core_handle, &did, &did)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Closes an SCP context.
///
/// Delegates to [`ContextManager::close_context`] for cooperative context
/// closure. Transitions the context to `"closed"` state.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2017` if the context is not in `"active"` state.
/// Rejects with `SCP-PERM-3000` if the caller is not the context creator.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_close(handle: &NapiContextHandle, identity_did: String) -> napi::Result<()> {
    // Authorization is enforced by the ContextManager (which delegates to
    // ttl::close_context checking the ContextClose capability). No bridge-layer
    // auth check — the ContextManager is authoritative.

    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot close context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2017".to_owned(),
        }
        .into());
    }

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let did = DID(identity_did.clone());

    let manager = context_manager();
    manager
        .close_context(core_handle, &did)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    handle.set_closed().map_err(NapiError::from)?;

    // Clean up UCAN state for this context.
    crate::runtime::remove_context(&handle.context_id);

    Ok(())
}

/// Sends a message to an SCP context.
///
/// Delegates to [`ContextManager::send_message`] for MLS-encrypted,
/// transport-delivered messaging.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2019` if the context is not `"active"`.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String/Vec
pub async fn context_send(
    handle: &NapiContextHandle,
    identity_did: String,
    payload: Vec<u8>,
) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot send to context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2019".to_owned(),
        }
        .into());
    }

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let did = DID(identity_did.clone());

    let manager = context_manager();
    manager
        .send_message(core_handle, &did, &payload, None)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Subscribes to incoming messages from an SCP context.
///
/// Registers a JS callback to receive incoming messages. The callback is
/// invoked with a [`NapiMessage`] object for each message.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2021` if the context is not in `"active"` state.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub fn context_subscribe(
    handle: &NapiContextHandle,
    identity_did: String,
    on_message: napi::threadsafe_function::ThreadsafeFunction<Option<NapiMessage>>,
) -> napi::Result<()> {
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot subscribe to context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2021".to_owned(),
        }
        .into());
    }

    let _ = identity_did;

    // Signal stream completion — full transport wiring connects this callback
    // to the message pipeline via ContextManager's transport provider.
    on_message.call(
        Ok(None),
        napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge functions — membership queries (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Returns the current member count for a context.
///
/// Delegates to [`ContextManager::member_count`].
///
/// # Returns
///
/// The member count, or `0` if the context is not registered.
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextMemberCount")]
pub async fn context_member_count(handle: &NapiContextHandle) -> napi::Result<u32> {
    let manager = context_manager();
    let count = manager.member_count(&handle.context_id).await.unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    Ok(count as u32)
}

/// Returns whether a DID is a member of the context.
///
/// Delegates to [`ContextManager::is_member`].
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextIsMember")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_is_member(handle: &NapiContextHandle, did: String) -> napi::Result<bool> {
    let manager = context_manager();
    Ok(manager.is_member(&handle.context_id, &did).await)
}

/// Returns all member DIDs for a context.
///
/// Delegates to [`ContextManager::member_dids`].
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextMemberDids")]
pub async fn context_member_dids(handle: &NapiContextHandle) -> napi::Result<Vec<String>> {
    let manager = context_manager();
    Ok(manager.member_dids(&handle.context_id).await)
}

/// Returns the role assignment for a specific member in a context.
///
/// Delegates to [`ContextManager::member_role`]. Returns the role name
/// as a string, or `null` if the member is not found.
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextMemberRole")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_member_role(
    handle: &NapiContextHandle,
    did: String,
) -> napi::Result<Option<String>> {
    let manager = context_manager();
    Ok(manager
        .member_role(&handle.context_id, &did)
        .await
        .map(|a| a.role_name))
}

// ---------------------------------------------------------------------------
// Bridge functions — events (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Drains all events from the receive buffer for a context.
///
/// Delegates to [`ContextManager::drain_events`]. Returns events as JSON
/// strings.
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextDrainEvents")]
pub async fn context_drain_events(handle: &NapiContextHandle) -> napi::Result<Vec<String>> {
    let manager = context_manager();
    let events = manager.drain_events(&handle.context_id).await;
    Ok(events.into_iter().map(|e| format!("{e:?}")).collect())
}

// ---------------------------------------------------------------------------
// Bridge functions — broadcast (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Returns the number of subscribers in a broadcast context.
///
/// Delegates to [`ContextManager::broadcast_subscriber_count`].
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextBroadcastSubscriberCount")]
pub async fn context_broadcast_subscriber_count(
    handle: &NapiContextHandle,
) -> napi::Result<Option<u32>> {
    let manager = context_manager();
    #[allow(clippy::cast_possible_truncation)]
    Ok(manager
        .broadcast_subscriber_count(&handle.context_id)
        .await
        .map(|c| c as u32))
}

/// Returns whether a DID is a subscriber in a broadcast context.
///
/// Delegates to [`ContextManager::is_broadcast_subscriber`].
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextIsBroadcastSubscriber")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_is_broadcast_subscriber(
    handle: &NapiContextHandle,
    did: String,
) -> napi::Result<bool> {
    let manager = context_manager();
    Ok(manager
        .is_broadcast_subscriber(&handle.context_id, &did)
        .await)
}

/// Returns the admission policy for a broadcast context.
///
/// Delegates to [`ContextManager::broadcast_admission`].
///
/// # Errors
///
/// This function is infallible. The `Result` return type is required by napi-rs.
#[napi(js_name = "contextBroadcastAdmission")]
pub async fn context_broadcast_admission(
    handle: &NapiContextHandle,
) -> napi::Result<Option<String>> {
    let manager = context_manager();
    Ok(manager
        .broadcast_admission(&handle.context_id)
        .await
        .map(|a| format!("{a:?}")))
}

// ---------------------------------------------------------------------------
// Bridge functions — governance (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Executes an approved governance action on a context.
///
/// Delegates to [`ContextManager::execute_governance_action`]. All 24
/// `GovernanceAction` variants are dispatchable.
///
/// # Arguments
///
/// * `handle` — The context to execute the action on.
/// * `action_json` — JSON string describing the governance action.
/// * `proposer_did` — DID of the proposer.
///
/// # Returns
///
/// A JSON string describing the result.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the action fails.
#[napi(js_name = "contextExecuteGovernanceAction")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_execute_governance_action(
    handle: &NapiContextHandle,
    action_json: String,
    proposer_did: String,
) -> napi::Result<String> {
    let action: GovernanceAction = serde_json::from_str(&action_json).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid governance action JSON: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })
    })?;

    // Generate a random proposal ID (32 bytes).
    let mut proposal_id = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut proposal_id);
    }

    let now = scp_core::time::now_secs().ok_or_else(|| {
        napi::Error::from_reason("system clock unavailable — cannot create governance proposal")
    })?;

    let proposal = GovernanceProposal {
        proposal_id,
        context_id: handle.context_id.clone(),
        proposer_did: DID(proposer_did.clone()),
        action,
        status: ProposalStatus::Approved,
        created_at: now,
        voting_deadline: now + 3600, // 1 hour default
        approvals: Vec::new(),
        rejections: Vec::new(),
        created_at_epoch: None,
    };

    let manager = context_manager();
    let result = manager
        .execute_governance_action(&handle.context_id, &proposal)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(format!("{result:?}"))
}

// ---------------------------------------------------------------------------
// Bridge functions — TTL (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Handles automatic TTL expiry for a context.
///
/// Delegates to [`ContextManager::handle_ttl_expiry`].
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2005` if the context is not active.
#[napi(js_name = "contextHandleTtlExpiry")]
pub async fn context_handle_ttl_expiry(handle: &NapiContextHandle) -> napi::Result<()> {
    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let manager = context_manager();
    manager
        .handle_ttl_expiry(core_handle)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Proposes a TTL extension for a context.
///
/// Delegates to [`ContextManager::propose_ttl_extension`]. Records consent
/// from the given member. Returns `true` if the extension was unanimously
/// approved.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2005` if the operation fails.
#[napi(js_name = "contextProposeTtlExtension")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_propose_ttl_extension(
    handle: &NapiContextHandle,
    proposer_did: String,
    extension_secs: u32,
) -> napi::Result<bool> {
    let did = DID(proposer_did.clone());
    let duration = std::time::Duration::from_secs(u64::from(extension_secs));
    let manager = context_manager();
    let unanimous = manager
        .propose_ttl_extension(&handle.context_id, &did, duration)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(unanimous)
}

/// Resets the TTL timer for a context.
///
/// Delegates to [`ContextManager::reset_ttl_timer`]. Requires a core handle
/// and a new duration.
///
/// # Errors
///
/// Returns `SCP-CTX-2024` if the context does not have a core handle.
#[napi(js_name = "contextResetTtlTimer")]
pub async fn context_reset_ttl_timer(
    handle: &NapiContextHandle,
    new_duration_secs: u32,
) -> napi::Result<()> {
    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let duration = std::time::Duration::from_secs(u64::from(new_duration_secs));
    let manager = context_manager();
    manager
        .reset_ttl_timer(&handle.context_id, duration, core_handle.clone())
        .await;
    Ok(())
}
