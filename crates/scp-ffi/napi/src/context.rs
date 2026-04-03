//! napi-rs bridge for context lifecycle, messaging, governance, broadcast,
//! membership queries, TTL, and events.
//!
//! All operations delegate to the shared `ContextManager` instance via
//! [`crate::runtime::context_manager()`]. The `NapiContextHandle` is a thin
//! handle carrying context metadata and a reference to the `ContextHandle`
//! from `scp-core`.
//!
//! See issue #388 and ADR-022 in `.docs/adrs/phase-4.md`.

use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;
use scp_core::context::governance::{GovernanceAction, GovernanceProposal, ProposalStatus};
use scp_core::context::manager::GovernanceActionResult;
use scp_core::context::params::ContextMode;
use scp_core::context::{ContextHandle, ContextParams, ContextState};
use scp_identity::DID;
use scp_primitives::Clock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::traits::KeyCustody;

use scp_ffi_common::validate::validate_did;

use crate::error::ScpNapiError;
use crate::identity::NapiIdentity;
#[cfg(feature = "allow_in_memory_custody")]
use crate::identity::OpaqueInMemoryKeyCustody;
use crate::runtime::context_manager;
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// MLS key package generation for context join (#1294)
// ---------------------------------------------------------------------------

/// Generates TLS-serialized MLS key package bytes for a DID.
///
/// Creates an `ScpCredential` from the DID, generates a fresh
/// `KeyPackage` via `scp_core::crypto::mls::group::generate_key_package`,
/// and TLS-serializes it to bytes suitable for
/// `ContextCryptoProvider::validate_key_package` and `add_member`.
///
/// # Errors
///
/// Returns `ScpNapiError::Crypto` if the DID format is invalid (must be
/// `did:dht:z...`), key package generation fails, or TLS serialization
/// fails.
fn generate_mls_key_package_bytes(did: &str) -> Result<Vec<u8>, ScpNapiError> {
    use scp_core::crypto::mls::credential::ScpCredential;
    use scp_core::crypto::mls::group::generate_key_package;
    use tls_codec::Serialize as TlsSerializeTrait;

    let cred = ScpCredential::new(did.to_owned(), None, scp_identity::SigningKeyId::Active)
        .map_err(|e| ScpNapiError::Crypto {
            message: format!("failed to create SCP credential for MLS key package: {e}"),
            code: "SCP-CRYPTO-4010".to_owned(),
        })?;

    let (kp_bundle, _signer, _provider) =
        generate_key_package(&cred).map_err(|e| ScpNapiError::Crypto {
            message: format!("MLS key package generation failed: {e}"),
            code: "SCP-CRYPTO-4011".to_owned(),
        })?;

    kp_bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| ScpNapiError::Crypto {
            message: format!("MLS key package TLS serialization failed: {e}"),
            code: "SCP-CRYPTO-4012".to_owned(),
        })
}

// ---------------------------------------------------------------------------
// NapiContextHandle — opaque JS class for SCP contexts
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP context.
///
/// Stores context metadata and retains a reference to the `scp-core`
/// [`ContextHandle`] for lifecycle operations via the shared
/// `ContextManager`.
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
    /// Optional economic policy string.
    economic_policy: Option<String>,
    /// Retained [`InMemoryKeyCustody`] for UCAN signing (RED-102).
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
    /// Handle to the creator's active signing key for UCAN minting (RED-102).
    pub(crate) signing_key: Option<scp_platform::traits::KeyHandle>,
    /// The scp-core `ContextHandle` for this context, used for manager delegation.
    pub(crate) core_handle: Option<ContextHandle>,
    /// Cancellation token for the subscription task spawned by `context_subscribe`.
    /// Cancelled in `context_leave` and `context_close` to stop the background
    /// relay listener, preventing orphaned tasks. Wrapped in a `Mutex` so that
    /// `context_subscribe` can replace a spent token with a fresh one, enabling
    /// re-subscription after relay disconnect or task termination.
    pub(crate) subscription_cancel: std::sync::Mutex<CancellationToken>,
    /// Guard preventing duplicate `context_subscribe` calls. Set to `true` on
    /// the first successful call; reset to `false` when the spawned task exits,
    /// enabling re-subscription after relay disconnect or task termination.
    pub(crate) subscription_active: Arc<std::sync::atomic::AtomicBool>,
}

/// Internal context lifecycle state string helper.
const fn state_str(state: &ContextState) -> &'static str {
    match state {
        ContextState::Creating => "creating",
        ContextState::Active => "active",
        ContextState::Closing => "closing",
        ContextState::Closed => "closed",
        ContextState::Expired => "expired",
        ContextState::MigratingOut => "migrating_out",
        ContextState::Tombstoned => "tombstoned",
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

    /// Returns the current member count by querying the `ContextManager`.
    ///
    /// This is a live query — the count always reflects the actual
    /// membership state, not a cached snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the `ContextManager` is not initialised.
    #[napi(getter, js_name = "memberCount")]
    pub fn member_count(&self) -> napi::Result<u32> {
        let manager = context_manager()?;
        let count = crate::runtime()
            .block_on(manager.member_count(&self.context_id))
            .unwrap_or(0);
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
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
        if let Ok(token) = self.subscription_cancel.lock() {
            token.cancel();
        }
        decrement_handle_count();
    }
}

#[cfg(test)]
impl NapiContextHandle {
    /// Creates a minimal active handle for cross-module tests.
    ///
    /// The handle is in `Active` state with default parameters and no
    /// `core_handle`. Suitable for testing bridge functions that only need
    /// UCAN state (set up via `ensure_registered`).
    pub(crate) fn test_active(context_id: String, creator_did: String) -> Self {
        increment_handle_count();
        Self {
            context_id,
            state: std::sync::Mutex::new(ContextState::Active),
            creator_did,
            mode: "Encrypted".to_owned(),
            ceiling: vec![],
            ceiling_policy: "immutable".to_owned(),
            ttl_seconds: None,
            promotion_policy: None,
            governance: "single_admin".to_owned(),
            economic_policy: None,
            #[cfg(feature = "allow_in_memory_custody")]
            in_memory_custody: None,
            signing_key: None,
            core_handle: None,
            subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
            subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
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
// Helper — pseudonym derivation (SCP-214 criterion 5)
// ---------------------------------------------------------------------------

/// Derives the context-scoped pseudonym routing ID via the retained
/// `KeyCustody` provider (SCP-214 criterion 5, spec §9.10.4).
///
/// Returns `Ok(())` on success or if no custody/identity is available
/// (graceful no-op). Errors are logged but not propagated.
#[cfg(feature = "allow_in_memory_custody")]
async fn derive_context_pseudonym(identity: &NapiIdentity, context_id: &str) {
    if let (Some(scp_id), Some(custody)) = (
        identity.inner.scp_identity.as_ref(),
        &identity.inner.in_memory_custody,
    ) {
        let _pseudonym = custody
            .0
            .derive_pseudonym(&scp_id.identity_key, context_id.as_bytes())
            .await
            .ok();
    }
}

// ---------------------------------------------------------------------------
// Bridge functions — context lifecycle (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Creates a new SCP context.
///
/// Delegates to `ContextManager::create_context` for two-phase commit
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
    validate_did(&identity.inner.did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

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
    #[cfg(feature = "allow_in_memory_custody")]
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

    // Validate governance model — reject unknown values instead of silently
    // defaulting to SingleAdmin (#1421).
    let core_governance = match governance.as_str() {
        "single_admin" => scp_core::context::params::GovernanceModel::SingleAdmin,
        other => {
            return Err(ScpNapiError::Validation {
                message: format!(
                    "unsupported governance model: {other:?} — \
                     only \"single_admin\" is currently supported"
                ),
                code: "SCP-VALID-7030".to_owned(),
            }
            .into());
        }
    };

    let core_ceiling: Vec<scp_core::context::roles::Capability> = ceiling
        .iter()
        .map(scp_core::context::roles::Capability::new)
        .collect();

    // Parse minProtocolVersion: [major, minor] array or null (spec §13.4).
    let min_protocol_version = params["minProtocolVersion"].as_array().and_then(|arr| {
        let major = u8::try_from(arr.first()?.as_u64()?).ok()?;
        let minor = u8::try_from(arr.get(1)?.as_u64()?).ok()?;
        Some((major, minor))
    });

    // Parse context-configurable limits (ADR-043).
    let max_chain_depth = params["maxChainDepth"]
        .as_u64()
        .and_then(|v| u8::try_from(v).ok());
    let max_nesting_depth = params["maxNestingDepth"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok());
    let session_cap = params["sessionCap"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok());

    // Deserialize economic_policy JSON string to the core struct, if provided.
    let core_economic_policy: Option<scp_core::economy::EconomicPolicy> = economic_policy
        .as_deref()
        .map(|ep_json| {
            serde_json::from_str(ep_json).map_err(|e| {
                NapiError::from(ScpNapiError::Validation {
                    message: format!("invalid economicPolicy JSON: {e}"),
                    code: "SCP-VALID-7000".to_owned(),
                })
            })
        })
        .transpose()?;

    let context_params = ContextParams {
        mode,
        ceiling: core_ceiling,
        ceiling_policy: core_ceiling_policy,
        promotion_policy: core_promotion_policy,
        ttl: ttl_seconds.map(std::time::Duration::from_secs),
        memory_scope: core_memory_scope,
        governance: core_governance,
        min_protocol_version,
        max_chain_depth,
        max_nesting_depth,
        session_cap,
        economic_policy: core_economic_policy,
        ..ContextParams::default()
    };

    // Initialize the ContextManager if not already done (first context_create call).
    // Passes the creator DID to MlsCryptoProvider for real MLS encryption (#1294).
    crate::runtime::init_context_manager(&creator_did);

    // Delegate to ContextManager.
    let manager = context_manager()?;
    let core_handle = manager
        .create_context(context_id.clone(), context_params, DID(creator_did.clone()))
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // Register the creator's DID as a local DID for defense-in-depth.
    manager.register_local_did(DID(creator_did.clone())).await;

    // Derive the context-scoped pseudonym routing ID (SCP-214 criterion 5).
    #[cfg(feature = "allow_in_memory_custody")]
    derive_context_pseudonym(identity, &context_id).await;

    let handle = NapiContextHandle {
        context_id,
        state: std::sync::Mutex::new(ContextState::Active),
        creator_did,
        mode: mode_str,
        ceiling: ceiling
            .iter()
            .map(|s| scp_core::context::roles::Capability::new(s).ucan_capability_name())
            .collect(),
        ceiling_policy,
        ttl_seconds,
        promotion_policy,
        governance,
        economic_policy,
        #[cfg(feature = "allow_in_memory_custody")]
        in_memory_custody,
        signing_key,
        core_handle: Some(core_handle),
        subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
        subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    increment_handle_count();
    Ok(handle)
}

/// Joins an existing SCP context.
///
/// Delegates to `ContextManager::join_context` for MLS group membership
/// establishment.
///
/// # Errors
///
/// Rejects with `SCP-CTX-2013` if the context is not in `"active"` state.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_join(handle: &NapiContextHandle, identity_did: String) -> napi::Result<()> {
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!("cannot join context in {state_str:?} state — context must be active"),
            code: "SCP-CTX-2013".to_owned(),
        }
        .into());
    }

    // Ensure the ContextManager is initialized — context_join is a valid
    // first operation (e.g. a device joining a context without creating one).
    // init_context_manager is idempotent (OnceLock — first call wins). #1073
    // Passes the joiner DID to MlsCryptoProvider for real MLS encryption (#1294).
    crate::runtime::init_context_manager(&identity_did);

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;

    // Generate a real MLS key package for the joining member (#1294).
    // The key package contains the joiner's SCP credential (DID) and is
    // validated by MlsCryptoProvider::validate_key_package before MLS
    // group addition.
    let kp_bytes = generate_mls_key_package_bytes(&identity_did)?;

    let key_package = scp_core::context::membership::KeyPackage {
        owner_did: DID(identity_did.clone()),
        mls_key_package_bytes: Some(kp_bytes),
    };

    let manager = context_manager()?;
    manager
        .join_context(core_handle, key_package, None)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Leaves an SCP context.
///
/// Delegates to `ContextManager::leave_context` for MLS membership
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

    // Cancel the subscription task before leaving so the background relay
    // listener stops promptly.
    if let Ok(token) = handle.subscription_cancel.lock() {
        token.cancel();
    }

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let did = DID(identity_did.clone());

    let manager = context_manager()?;
    manager
        .leave_context(core_handle, &did, &did)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Closes an SCP context.
///
/// Delegates to `ContextManager::close_context` for cooperative context
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

    // Cancel the subscription task before closing so the background relay
    // listener stops promptly.
    if let Ok(token) = handle.subscription_cancel.lock() {
        token.cancel();
    }

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let did = DID(identity_did.clone());

    let manager = context_manager()?;
    manager
        .close_context(core_handle, &did)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    handle.set_closed().map_err(NapiError::from)?;

    // Clean up UCAN state for this context.
    crate::runtime::remove_context(&handle.context_id);

    // Clean up per-context bridge connector state (ShadowRegistry + SenderKeyStore)
    // to prevent unbounded memory growth in long-running processes.
    crate::bridge_connector::remove_bridge_state(&handle.context_id);

    Ok(())
}

/// Sends a message to an SCP context.
///
/// Delegates to `ContextManager::send_message` for MLS-encrypted,
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
    spending_ucan_jwt: Option<String>,
) -> napi::Result<()> {
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

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

    // Validate inner envelope signing via the retained KeyCustody
    // (SCP-214 criterion 6). Ensures the identity's active signing key
    // can produce a valid Ed25519 signature before sending.
    #[cfg(feature = "allow_in_memory_custody")]
    if let (Some(custody), Some(signing_key)) = (&handle.in_memory_custody, handle.signing_key) {
        let context_id = handle.context_id.clone();
        let sender_did_str = identity_did.clone();
        let now_ms = scp_primitives::SystemClock.now_millis();

        let params = scp_core::envelope::InnerEnvelopeParams {
            version: scp_core::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
            context_id: &context_id,
            sender_did: &sender_did_str,
            epoch: 0,
            generation: 0,
            sequence: 0,
            timestamp: now_ms,
            message_type: scp_core::envelope::MessageType::Content,
            payload: &payload,
            provenance: None,
            signing_key_id: scp_identity::SigningKeyId::Active,
        };

        scp_core::envelope::create_inner_envelope(&params, &custody.0, &signing_key)
            .await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Crypto {
                    message: format!("inner envelope signing failed: {e}"),
                    code: "SCP-CRYPTO-4001".to_owned(),
                })
            })?;
    }

    // Resolve the signing key from the handle's retained custody so the
    // ContextManager can produce a valid inner envelope signature. Passing
    // None would cause the encrypted send path to fail with "signing key
    // required".
    #[cfg(feature = "allow_in_memory_custody")]
    let resolved_signing_key = resolve_napi_signing_key(handle).await.ok();

    #[cfg(not(feature = "allow_in_memory_custody"))]
    let resolved_signing_key: Option<ed25519_dalek::SigningKey> = None;

    // Parse optional spending UCAN JWT into a UcanToken for AND-composition.
    let spending_ucan = spending_ucan_jwt
        .as_deref()
        .map(scp_protocol::crypto::ucan::validate::parse_ucan)
        .transpose()
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("invalid spending UCAN: {e}"),
                code: "SCP-ECON-7061".to_owned(),
            })
        })?;

    let manager = context_manager()?;
    manager
        .send_message(
            core_handle,
            &did,
            &payload,
            resolved_signing_key.as_ref(),
            None,
            spending_ucan.as_ref(),
        )
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Subscribes to incoming messages from an SCP context.
///
/// Registers a JS callback to receive incoming messages. The callback is
/// invoked with a `NapiMessage` object for each message received from the
/// relay. When the stream ends (relay disconnect, context close, or error),
/// the callback receives `null` to signal completion.
///
/// Internally, this subscribes to the relay using the context's routing ID
/// (SHA-256 of `context_id`, matching what `context_send` publishes). Incoming
/// envelopes are decrypted via `ContextManager::deliver_incoming` and
/// forwarded to the JS callback.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2021` if the context is not in `"active"` state.
/// - Rejects with `SCP-CTX-2022` if already subscribed.
/// - Rejects with `SCP-TRANS-5010` if no relay connection is available.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub fn context_subscribe(
    handle: &NapiContextHandle,
    identity_did: String,
    on_message: napi::threadsafe_function::ThreadsafeFunction<Option<NapiMessage>>,
) -> napi::Result<()> {
    // Guard: prevent duplicate subscriptions. The AtomicBool is swapped to
    // true on the first call; subsequent calls see `true` and bail.
    // The flag is reset to `false` by the spawned task when it exits,
    // enabling re-subscription after relay disconnect or task termination.
    if handle
        .subscription_active
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return Err(ScpNapiError::Context {
            message: "already subscribed — each context supports a single subscription".to_owned(),
            code: "SCP-CTX-2022".to_owned(),
        }
        .into());
    }

    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        // Reset the guard so the caller can retry after state changes.
        handle
            .subscription_active
            .store(false, std::sync::atomic::Ordering::SeqCst);
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot subscribe to context in {state_str:?} state — context must be active"
            ),
            code: "SCP-CTX-2021".to_owned(),
        }
        .into());
    }

    // `identity_did` is validated at the API boundary for future membership
    // checks but not used in the current subscription path.
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    drop(identity_did);

    let Some(adapter) = crate::transport::get_relay_adapter() else {
        // Reset the guard so the caller can retry after connecting a relay.
        handle
            .subscription_active
            .store(false, std::sync::atomic::Ordering::SeqCst);
        return Err(NapiError::from(ScpNapiError::Transport {
            message: "no relay connection — call transportConnect() before subscribing".to_owned(),
            code: "SCP-TRANS-5010".to_owned(),
        }));
    };

    let context_id = handle.context_id.clone();
    // Both subscribe and send paths use domain-separated
    // SHA-256("scp:context-routing:" || context_id) as the routing ID.
    let routing_id_bytes = scp_core::context::context_routing_id(&context_id);
    let routing_id = scp_transport::RoutingId::new(routing_id_bytes);

    // Replace the cancellation token with a fresh one so a previously
    // cancelled token doesn't immediately cancel the new subscription.
    let cancel_token = {
        let mut guard = handle.subscription_cancel.lock().map_err(|_| {
            handle
                .subscription_active
                .store(false, std::sync::atomic::Ordering::SeqCst);
            NapiError::from(ScpNapiError::Context {
                message: "subscription cancel lock is poisoned".to_owned(),
                code: "SCP-CTX-2012".to_owned(),
            })
        })?;
        *guard = CancellationToken::new();
        guard.clone()
    };

    // Clone the Arc<AtomicBool> so the spawned task can reset it on exit,
    // enabling re-subscription after relay disconnect or task termination.
    let active_flag = Arc::clone(&handle.subscription_active);

    // Spawn a background task that subscribes to the relay and delivers
    // incoming messages through the JS callback. The task terminates when
    // the stream ends OR the cancellation token is triggered.
    //
    // Uses the shared NAPI runtime (not bare `tokio::spawn`) because this
    // is a sync `#[napi]` function — it runs on the Node.js main thread
    // which has no active tokio runtime context.
    crate::runtime().spawn(async move {
        use futures::StreamExt;
        use scp_transport::TransportAdapter;

        let stream_result = adapter.subscribe(&routing_id, None).await;
        let mut stream = match stream_result {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    context_id = %context_id,
                    error = %e,
                    "relay subscription failed"
                );
                // Signal completion on error.
                on_message.call(
                    Ok(None),
                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                );
                // Reset the active flag so re-subscription is possible.
                active_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                return;
            }
        };

        let manager = match context_manager() {
            Ok(m) => m.clone(),
            Err(e) => {
                tracing::error!(error = %e, "ContextManager not initialized");
                on_message.call(
                    Ok(None),
                    napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                );
                // Reset the active flag so re-subscription is possible.
                active_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                return;
            }
        };

        let mut sequence_counter: f64 = 0.0;

        loop {
            // Select between the next stream event and cancellation.
            let event = tokio::select! {
                () = cancel_token.cancelled() => {
                    tracing::info!(
                        context_id = %context_id,
                        "subscription cancelled via token"
                    );
                    break;
                }
                maybe_event = stream.next() => {
                    match maybe_event {
                        Some(e) => e,
                        None => break, // stream exhausted
                    }
                }
            };

            match event {
                scp_transport::TransportEvent::Envelope(envelope) => {
                    // Decrypt via ContextManager.
                    match manager
                        .deliver_incoming(&context_id, &envelope.encrypted_blob)
                        .await
                    {
                        Ok(Some((plaintext, sender_did))) => {
                            sequence_counter += 1.0;
                            #[allow(clippy::cast_precision_loss)]
                            let ts = scp_primitives::SystemClock.now_secs() as f64;
                            let msg = NapiMessage {
                                sender_did,
                                payload: plaintext,
                                timestamp: ts,
                                sequence: sequence_counter,
                                context_id: context_id.clone(),
                            };
                            on_message.call(
                                Ok(Some(msg)),
                                napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        }
                        Ok(None) => {
                            // MLS Commit or Proposal — epoch advanced or proposal
                            // cached, no application payload to deliver.
                            tracing::debug!(
                                context_id = %context_id,
                                "MLS control message processed (Commit/Proposal) — no payload"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                context_id = %context_id,
                                error = %e,
                                "failed to decrypt incoming message — skipping"
                            );
                        }
                    }

                    // Yield to prevent starving other tasks under high message rates.
                    tokio::task::yield_now().await;
                }
                scp_transport::TransportEvent::Terminated { reason } => {
                    tracing::info!(
                        context_id = %context_id,
                        reason = %reason,
                        "relay subscription terminated"
                    );
                    break;
                }
                scp_transport::TransportEvent::Error(e) => {
                    tracing::warn!(
                        context_id = %context_id,
                        error = %e,
                        "transient relay error — continuing"
                    );
                }
                // BackfillComplete, Reconnected, SuppressionDetected — informational.
                _ => {}
            }
        }

        // Signal stream completion.
        on_message.call(
            Ok(None),
            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
        );

        // Reset the active flag so re-subscription is possible after relay
        // disconnect or task termination.
        active_flag.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    Ok(())
}

/// Cancels an active subscription on a context handle.
///
/// Triggers the cancellation token so the background relay listener task
/// terminates.  The background task itself clears `subscription_active` when
/// it exits — clearing it here would race with a new subscription starting
/// before the old task has terminated, allowing duplicate concurrent
/// subscriptions.  Called from the TypeScript `receive()` generator's `finally`
/// block to prevent orphaned tasks when the consumer abandons iteration.
#[napi(js_name = "contextCancelSubscription")]
pub fn context_cancel_subscription(handle: &NapiContextHandle) -> napi::Result<()> {
    if let Ok(token) = handle.subscription_cancel.lock() {
        token.cancel();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge functions — membership queries (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Returns the current member count for a context.
///
/// Delegates to `ContextManager::member_count`.
///
/// # Returns
///
/// The member count, or `0` if the context is not registered.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextMemberCount")]
pub async fn context_member_count(handle: &NapiContextHandle) -> napi::Result<u32> {
    let manager = context_manager()?;
    let count = manager.member_count(&handle.context_id).await.unwrap_or(0);
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Returns whether a DID is a member of the context.
///
/// Delegates to `ContextManager::is_member`.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextIsMember")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_is_member(handle: &NapiContextHandle, did: String) -> napi::Result<bool> {
    let manager = context_manager()?;
    Ok(manager.is_member(&handle.context_id, &did).await)
}

/// Returns all member DIDs for a context.
///
/// Delegates to `ContextManager::member_dids`.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextMemberDids")]
pub async fn context_member_dids(handle: &NapiContextHandle) -> napi::Result<Vec<String>> {
    let manager = context_manager()?;
    Ok(manager.member_dids(&handle.context_id).await)
}

/// Returns the role assignment for a specific member in a context.
///
/// Delegates to `ContextManager::member_role`. Returns the role name
/// as a string, or `null` if the member is not found.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextMemberRole")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_member_role(
    handle: &NapiContextHandle,
    did: String,
) -> napi::Result<Option<String>> {
    let manager = context_manager()?;
    Ok(manager
        .member_role(&handle.context_id, &did)
        .await
        .map(|a| a.role_name))
}

// ---------------------------------------------------------------------------
// Bridge functions — events (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Formats a [`ContextEvent`] as a human-readable string.
///
/// Consequence events (`ConsequenceTriggered`, `ConsequenceEnforced`) are
/// formatted with structured key=value pairs for observability. All other
/// events use their `Debug` representation.
fn format_context_event(event: &scp_core::context::membership::ContextEvent) -> String {
    use scp_core::context::membership::ContextEvent::{ConsequenceEnforced, ConsequenceTriggered};
    match event {
        ConsequenceTriggered {
            context_id,
            member_did,
            rule_index,
            trigger_type,
            action_type,
        } => format!(
            "consequence_triggered:member={member_did},\
             rule={rule_index},trigger={trigger_type},\
             action={action_type},context={context_id}"
        ),
        ConsequenceEnforced {
            context_id,
            member_did,
            action_type,
            success,
        } => format!(
            "consequence_enforced:member={member_did},\
             action={action_type},success={success},\
             context={context_id}"
        ),
        other => html_escape_event_string(&format!("{other:?}")),
    }
}

/// Drains all events from the receive buffer for a context.
///
/// Delegates to `ContextManager::drain_events`. Returns events as JSON
/// strings.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextDrainEvents")]
pub async fn context_drain_events(handle: &NapiContextHandle) -> napi::Result<Vec<String>> {
    let manager = context_manager()?;
    let events = manager.drain_events(&handle.context_id).await;
    Ok(events.iter().map(format_context_event).collect())
}

// ---------------------------------------------------------------------------
// Bridge functions — access key lifecycle (#1529, delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Generates and stores a per-member access key for explicit lifecycle
/// management.
///
/// Delegates to `ContextManager::generate_context_access_key`.
///
/// # Errors
///
/// Returns an error if the context is not registered, the member is not
/// found, or the caller lacks admin capability.
#[napi(js_name = "accessKeyGenerate")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn access_key_generate(
    context_id: String,
    member_did: String,
    caller_did: String,
) -> napi::Result<()> {
    let manager = context_manager()?;
    manager
        .generate_context_access_key(&context_id, &member_did, &caller_did)
        .await
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2070] {e}")))
}

/// Revokes (removes) a member's access key from the context's access key
/// store.
///
/// Delegates to `ContextManager::revoke_context_access_key`.
///
/// # Errors
///
/// Returns an error if the context is not registered, no access key
/// exists for the member, or the caller lacks admin capability.
#[napi(js_name = "accessKeyRevoke")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn access_key_revoke(
    context_id: String,
    member_did: String,
    caller_did: String,
) -> napi::Result<()> {
    let manager = context_manager()?;
    manager
        .revoke_context_access_key(&context_id, &member_did, &caller_did)
        .await
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2071] {e}")))
}

/// Restores a member's access key by generating a new key at the next
/// epoch.
///
/// Delegates to `ContextManager::restore_context_access_key`.
///
/// # Errors
///
/// Returns an error if the context is not registered, the member is
/// not found, or the caller lacks admin capability.
#[napi(js_name = "accessKeyRestore")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn access_key_restore(
    context_id: String,
    member_did: String,
    caller_did: String,
) -> napi::Result<()> {
    let manager = context_manager()?;
    manager
        .restore_context_access_key(&context_id, &member_did, &caller_did)
        .await
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2072] {e}")))
}

// ---------------------------------------------------------------------------
// Bridge functions — broadcast (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Returns the number of subscribers in a broadcast context.
///
/// Delegates to `ContextManager::broadcast_subscriber_count`.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextBroadcastSubscriberCount")]
pub async fn context_broadcast_subscriber_count(
    handle: &NapiContextHandle,
) -> napi::Result<Option<u32>> {
    let manager = context_manager()?;
    #[allow(clippy::cast_possible_truncation)]
    Ok(manager
        .broadcast_subscriber_count(&handle.context_id)
        .await
        .map(|c| c as u32))
}

/// Returns whether a DID is a subscriber in a broadcast context.
///
/// Delegates to `ContextManager::is_broadcast_subscriber`.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextIsBroadcastSubscriber")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn context_is_broadcast_subscriber(
    handle: &NapiContextHandle,
    did: String,
) -> napi::Result<bool> {
    let manager = context_manager()?;
    Ok(manager
        .is_broadcast_subscriber(&handle.context_id, &did)
        .await)
}

/// Returns the admission policy for a broadcast context.
///
/// Delegates to `ContextManager::broadcast_admission`.
///
/// # Errors
///
/// Returns an error if the `ContextManager` is not initialised.
#[napi(js_name = "contextBroadcastAdmission")]
pub async fn context_broadcast_admission(
    handle: &NapiContextHandle,
) -> napi::Result<Option<String>> {
    let manager = context_manager()?;
    Ok(manager
        .broadcast_admission(&handle.context_id)
        .await
        .map(|a| format!("{a:?}")))
}

// ---------------------------------------------------------------------------
// No-op UCAN validation trait stubs for subscribe_broadcast
//
// Minimal implementations satisfying the generic bounds on
// ContextManager::subscribe_broadcast. Broadcast subscription in open mode
// does not require UCAN validation; gated mode validation will be wired
// when the full UCAN pipeline is integrated with the NAPI bridge.
// ---------------------------------------------------------------------------

struct NoOpDidResolver;
impl scp_core::crypto::ucan::validate::DidResolver for NoOpDidResolver {
    fn resolve_public_key(
        &self,
        _did: &str,
    ) -> Result<[u8; 32], scp_core::crypto::ucan::UcanError> {
        Err(scp_core::crypto::ucan::UcanError::MalformedToken(
            "NoOpDidResolver: no DID resolution available".into(),
        ))
    }
}

/// Fail-closed nonce tracker: rejects all nonces when no real tracker is
/// available. Used as a type parameter only — never reached when token is
/// `None`, but rejects by default if accidentally called.
struct RejectAllNonceTracker;
impl scp_core::crypto::ucan::validate::NonceTracker for RejectAllNonceTracker {
    fn check_and_record(
        &mut self,
        nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_core::crypto::ucan::UcanError> {
        // Fail-closed: reject all nonces when no real tracker is available.
        Err(scp_core::crypto::ucan::UcanError::NonceReused(
            nonce.to_owned(),
        ))
    }
}

/// Fail-closed revocation checker: treats all tokens as revoked when no real
/// checker is available. Used as a type parameter only — never reached when
/// token is `None`, but rejects by default if accidentally called.
struct RejectAllRevocationChecker;
impl scp_core::crypto::ucan::validate::RevocationChecker for RejectAllRevocationChecker {
    fn is_revoked(&self, _token_cid: &str) -> bool {
        // Fail-closed: treat all tokens as revoked when no real checker is available.
        true
    }
}

/// Fail-closed proof resolver: rejects all proof lookups. Used as a type
/// parameter only — never reached when token is `None`.
struct RejectAllProofResolver;
impl scp_core::crypto::ucan::validate::ProofResolver for RejectAllProofResolver {
    fn resolve_proof(
        &self,
        cid: &str,
    ) -> Result<scp_core::crypto::ucan::UcanToken, scp_core::crypto::ucan::UcanError> {
        Err(scp_core::crypto::ucan::UcanError::DelegationChainBroken(
            format!("RejectAllProofResolver: no proof available for CID {cid}"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Bridge functions — broadcast mutations (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Subscribes a DID to a broadcast context.
///
/// Delegates to `ContextManager::subscribe_broadcast`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the context is not active or not broadcast.
#[napi(js_name = "broadcastSubscribe")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_subscribe(
    handle: &NapiContextHandle,
    subscriber_did: String,
) -> napi::Result<()> {
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let did: DID = DID(subscriber_did);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    manager
        .subscribe_broadcast::<
            NoOpDidResolver,
            RejectAllNonceTracker,
            RejectAllRevocationChecker,
            RejectAllProofResolver,
            std::hash::RandomState,
        >(&context_id, &did, None, timestamp, None)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Unsubscribes a DID from a broadcast context.
///
/// When `rotate_keys` is `true`, all authors rotate their broadcast keys
/// for forward secrecy.
///
/// Delegates to `ContextManager::unsubscribe_broadcast`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the context is not active or not broadcast.
#[napi(js_name = "broadcastUnsubscribe")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_unsubscribe(
    handle: &NapiContextHandle,
    subscriber_did: String,
    rotate_keys: Option<bool>,
) -> napi::Result<()> {
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let did: DID = DID(subscriber_did);

    manager
        .unsubscribe_broadcast(&context_id, &did, rotate_keys.unwrap_or(false))
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Publishes a message to a broadcast context.
///
/// The payload is encrypted with the author's broadcast key. The author's
/// identity must have been previously created via `identityCreate` so
/// that the key custody provider and signing key handle are available.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the context is not active, not broadcast,
///   or the sender is not an author.
/// - Rejects with `SCP-PERM-3020` if the context has no custody provider.
#[napi(js_name = "broadcastPublish")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_publish(
    handle: &NapiContextHandle,
    author_did: String,
    payload: Vec<u8>,
) -> napi::Result<()> {
    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let author_did = DID(author_did);

    #[cfg(feature = "allow_in_memory_custody")]
    {
        let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
            NapiError::from(ScpNapiError::Permission {
                message: "broadcast publish requires key custody — create the identity with \
                          identityCreate(\"in_memory\")"
                    .to_owned(),
                code: "SCP-PERM-3020".to_owned(),
            })
        })?;
        let signing_key = handle.signing_key.ok_or_else(|| {
            NapiError::from(ScpNapiError::Permission {
                message: "broadcast publish requires a signing key — identity has no active \
                          signing key handle"
                    .to_owned(),
                code: "SCP-PERM-3021".to_owned(),
            })
        })?;

        manager
            .publish_broadcast(&context_id, &author_did, &payload, &custody.0, &signing_key)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    }

    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (manager, context_id, author_did, payload);
        return Err(NapiError::from(ScpNapiError::Permission {
            message: "broadcast publish requires key custody — in_memory custody feature is \
                      not enabled"
                .to_owned(),
            code: "SCP-PERM-3022".to_owned(),
        }));
    }

    #[allow(unreachable_code)]
    Ok(())
}

/// An asset to publish to a broadcast context (SCP-290).
///
/// Typed struct to prevent positional transposition of path/`content_type`/body.
#[napi(object)]
pub struct NapiAssetEntry {
    /// Validated URL path (e.g., `/index.html`, `/styles.css`).
    pub path: String,
    /// Validated MIME type (e.g., `text/html`, `text/css`).
    pub content_type: String,
    /// Raw content bytes.
    pub body: Vec<u8>,
}

/// Result of publishing an asset to a broadcast context (SCP-290, SCP-292).
#[napi(object)]
pub struct NapiPublishResult {
    /// Hex-encoded SHA-256 of the serialized broadcast envelope.
    pub blob_id: String,
    /// Hex-encoded SHA-256 of the asset body.
    pub etag: String,
    /// The deploy ID for this asset (auto-generated or caller-provided).
    pub deploy_id: String,
}

/// Result of publishing multiple assets to a broadcast context (SCP-292).
///
/// Groups per-asset results with the shared deploy ID used across the batch.
#[napi(object)]
pub struct NapiBatchPublishResult {
    /// Per-asset publish results.
    pub results: Vec<NapiPublishResult>,
    /// The shared deploy ID for this batch.
    pub deploy_id: String,
}

/// Publishes a single asset to a broadcast context as structured content (SCP-290).
///
/// Constructs a `BroadcastContent` from the asset entry, computes an `ETag`,
/// and publishes via `ContextManager::publish_broadcast_content`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the context is not active, not broadcast,
///   or the sender is not an author.
/// - Rejects with `SCP-PERM-3020` if the context has no custody provider.
#[napi(js_name = "broadcastPublishAsset")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_publish_asset(
    handle: &NapiContextHandle,
    author_did: String,
    asset: NapiAssetEntry,
    deploy_id: Option<String>,
) -> napi::Result<NapiPublishResult> {
    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let author_did_val = DID(author_did.clone());

    // Auto-generate deploy_id when None, matching batch behavior.
    let deploy_id = Some(deploy_id.unwrap_or_else(|| {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(context_id.as_bytes());
        hasher.update(author_did.as_bytes());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        hasher.update(ts.to_le_bytes());
        hex::encode(&Sha256::digest(hasher.finalize())[..16])
    }));

    // Validate fields.
    let content_path = scp_core::context::ContentPath::new(asset.path).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("invalid path: {e}"),
            code: "SCP-CTX-2040".to_owned(),
        })
    })?;
    let mime_type = scp_core::context::MimeType::new(asset.content_type).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("invalid content_type: {e}"),
            code: "SCP-CTX-2041".to_owned(),
        })
    })?;
    if let Some(ref did_str) = deploy_id {
        scp_core::context::validate_deploy_id(did_str).map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("invalid deploy_id: {e}"),
                code: "SCP-CTX-2042".to_owned(),
            })
        })?;
    }

    let etag = scp_core::context::compute_etag(&asset.body);
    // Capture the deploy_id string before moving into BroadcastContent (SCP-292).
    let deploy_id_str = deploy_id.as_ref().map_or_else(String::new, Clone::clone);
    let content = scp_core::context::BroadcastContent {
        version: scp_core::context::BROADCAST_CONTENT_VERSION,
        metadata: scp_core::context::ContentMetadata {
            path: Some(content_path),
            content_type: Some(mime_type),
            deploy_id,
            etag: Some(etag.clone()),
            immutable: false,
        },
        body: asset.body,
    };

    #[cfg(feature = "allow_in_memory_custody")]
    {
        let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
            NapiError::from(ScpNapiError::Permission {
                message: "broadcast publish asset requires key custody — create the identity with \
                          identityCreate(\"in_memory\")"
                    .to_owned(),
                code: "SCP-PERM-3020".to_owned(),
            })
        })?;
        let signing_key = handle.signing_key.ok_or_else(|| {
            NapiError::from(ScpNapiError::Permission {
                message: "broadcast publish asset requires a signing key — identity has no active \
                          signing key handle"
                    .to_owned(),
                code: "SCP-PERM-3021".to_owned(),
            })
        })?;

        let envelope = manager
            .publish_broadcast_content(
                &context_id,
                &author_did_val,
                content,
                &custody.0,
                &signing_key,
            )
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let envelope_bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("failed to serialize envelope for blob_id: {e}"),
                code: "SCP-CTX-2043".to_owned(),
            })
        })?;
        let blob_id = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&envelope_bytes))
        };

        Ok(NapiPublishResult {
            blob_id,
            etag,
            deploy_id: deploy_id_str,
        })
    }

    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (manager, context_id, author_did_val, content, deploy_id_str);
        Err(NapiError::from(ScpNapiError::Permission {
            message: "broadcast publish asset requires key custody — in_memory custody feature is \
                      not enabled"
                .to_owned(),
            code: "SCP-PERM-3022".to_owned(),
        }))
    }
}

/// Publishes multiple assets to a broadcast context as structured content (SCP-290).
///
/// All assets are published with the same `deploy_id` (auto-generated if not
/// provided). Returns a list of `{ blob_id, etag }` results.
///
/// # Errors
///
/// - Rejects if any asset fails validation or publish.
#[napi(js_name = "broadcastPublishAssets")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_publish_assets(
    handle: &NapiContextHandle,
    author_did: String,
    assets: Vec<NapiAssetEntry>,
    deploy_id: Option<String>,
) -> napi::Result<NapiBatchPublishResult> {
    const MAX_BATCH_ASSETS: usize = 10_000;
    if assets.len() > MAX_BATCH_ASSETS {
        return Err(NapiError::from(ScpNapiError::Context {
            message: format!(
                "batch too large: {} assets (max {MAX_BATCH_ASSETS})",
                assets.len()
            ),
            code: "SCP-CTX-2074".to_owned(),
        }));
    }

    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let author_did_val = DID(author_did.clone());

    // Generate deploy_id if not provided.
    let deploy_id_val = deploy_id.unwrap_or_else(|| {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(context_id.as_bytes());
        hasher.update(author_did.as_bytes());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        hasher.update(ts.to_le_bytes());
        hex::encode(&Sha256::digest(hasher.finalize())[..16])
    });

    scp_core::context::validate_deploy_id(&deploy_id_val).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("invalid deploy_id: {e}"),
            code: "SCP-CTX-2042".to_owned(),
        })
    })?;

    #[cfg(feature = "allow_in_memory_custody")]
    {
        let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
            NapiError::from(ScpNapiError::Permission {
                message: "broadcast publish assets requires key custody".to_owned(),
                code: "SCP-PERM-3020".to_owned(),
            })
        })?;
        let signing_key = handle.signing_key.ok_or_else(|| {
            NapiError::from(ScpNapiError::Permission {
                message: "broadcast publish assets requires a signing key".to_owned(),
                code: "SCP-PERM-3021".to_owned(),
            })
        })?;

        let mut results = Vec::with_capacity(assets.len());
        for asset in assets {
            let content_path = scp_core::context::ContentPath::new(asset.path).map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("invalid path: {e}"),
                    code: "SCP-CTX-2040".to_owned(),
                })
            })?;
            let mime_type = scp_core::context::MimeType::new(asset.content_type).map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("invalid content_type: {e}"),
                    code: "SCP-CTX-2041".to_owned(),
                })
            })?;

            let etag = scp_core::context::compute_etag(&asset.body);
            let content = scp_core::context::BroadcastContent {
                version: scp_core::context::BROADCAST_CONTENT_VERSION,
                metadata: scp_core::context::ContentMetadata {
                    path: Some(content_path),
                    content_type: Some(mime_type),
                    deploy_id: Some(deploy_id_val.clone()),
                    etag: Some(etag.clone()),
                    immutable: false,
                },
                body: asset.body,
            };

            let envelope = manager
                .publish_broadcast_content(
                    &context_id,
                    &author_did_val,
                    content,
                    &custody.0,
                    &signing_key,
                )
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let envelope_bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("failed to serialize envelope for blob_id: {e}"),
                    code: "SCP-CTX-2043".to_owned(),
                })
            })?;
            let blob_id = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&envelope_bytes))
            };

            results.push(NapiPublishResult {
                blob_id,
                etag,
                deploy_id: deploy_id_val.clone(),
            });
        }
        Ok(NapiBatchPublishResult {
            results,
            deploy_id: deploy_id_val,
        })
    }

    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (manager, context_id, author_did_val, deploy_id_val, assets);
        Err(NapiError::from(ScpNapiError::Permission {
            message: "broadcast publish assets requires key custody — in_memory custody feature \
                      is not enabled"
                .to_owned(),
            code: "SCP-PERM-3022".to_owned(),
        }))
    }
}

/// Blocks a subscriber's read access in a broadcast context.
///
/// The subscriber is removed from the registry and added to all authors'
/// block lists; all author keys are rotated.
///
/// Delegates to `ContextManager::block_broadcast_subscriber`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the operation fails.
#[napi(js_name = "broadcastBlockSubscriber")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_block_subscriber(
    handle: &NapiContextHandle,
    subscriber_did: String,
    blocker_did: String,
) -> napi::Result<()> {
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&blocker_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let subscriber: DID = DID(subscriber_did);
    let blocker: DID = DID(blocker_did);

    manager
        .block_broadcast_subscriber(&context_id, &blocker, &subscriber)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Unblocks a previously blocked subscriber in a broadcast context (§9.16.8).
///
/// Forward-only: the unblocked subscriber can request the current key on
/// next pull but cannot decrypt content from the block period.
///
/// Delegates to `ContextManager::unblock_broadcast_subscriber`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the operation fails.
#[napi(js_name = "broadcastUnblockSubscriber")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_unblock_subscriber(
    handle: &NapiContextHandle,
    subscriber_did: String,
    unblocker_did: String,
) -> napi::Result<()> {
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&unblocker_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let subscriber: DID = DID(subscriber_did);
    let unblocker: DID = DID(unblocker_did);

    manager
        .unblock_broadcast_subscriber(&context_id, &unblocker, &subscriber)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Handles a broadcast key request from a subscriber.
///
/// Validates the author DID is locally controlled and processes the key
/// distribution request.
///
/// Delegates to `ContextManager::handle_broadcast_key_request`.
///
/// # Returns
///
/// A debug string describing the key request decision.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2001` if the operation fails.
#[napi(js_name = "broadcastHandleKeyRequest")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub async fn broadcast_handle_key_request(
    handle: &NapiContextHandle,
    author_did: String,
    requester_did: String,
) -> napi::Result<String> {
    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&requester_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let author: DID = DID(author_did);
    let requester: DID = DID(requester_did);

    let decision = manager
        .handle_broadcast_key_request(&context_id, &author, &requester)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(format!("{decision:?}"))
}

// ---------------------------------------------------------------------------
// Bridge functions — governance (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Executes an approved governance action on a context.
///
/// Delegates to `ContextManager::execute_governance_action`. All 24
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

    let action_name = action.variant_name();

    // Generate a random proposal ID (32 bytes).
    let mut proposal_id = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut proposal_id);
    }

    let now = scp_primitives::SystemClock.now_secs();

    // Currently all bridge governance actions are auto-approved (SingleAdmin).
    // Multi-party governance (Threshold/Majority/Unanimity) requires the
    // propose→vote→execute lifecycle exposed via ContextManager::propose_governance_action,
    // which needs signing keys for vote signatures. This will be wired when
    // multi-party governance is exposed through the NAPI bridge (SCP-270).
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

    let manager = context_manager()?;
    let context_id = handle.context_id.clone();
    let result = manager
        .execute_governance_action(&context_id, &proposal)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // Re-sync local UCAN role state cache from ContextManager after any
    // governance action that may have modified roles/membership (#560).
    if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id).await {
        tracing::warn!(
            context_id = %context_id,
            action = action_name,
            error = %e,
            "failed to sync role state after governance action — \
             local capability checks may be stale"
        );
    }

    // Sync FFI handle state for migration transitions (§5.11A).
    match &result {
        GovernanceActionResult::MigrationProposed(_) => {
            if let Ok(mut s) = handle.state.lock() {
                *s = ContextState::MigratingOut;
            }
        }
        GovernanceActionResult::MigrationCancelled => {
            if let Ok(mut s) = handle.state.lock() {
                *s = ContextState::Active;
            }
        }
        GovernanceActionResult::ContextTombstoned => {
            if let Ok(mut s) = handle.state.lock() {
                *s = ContextState::Tombstoned;
            }
        }
        _ => {}
    }

    Ok(format!("{result:?}"))
}

// ---------------------------------------------------------------------------
// Bridge functions — governance proposal lifecycle (#621)
// ---------------------------------------------------------------------------

/// Resolves the raw Ed25519 signing key from the context handle's custody.
///
/// The NAPI handle retains `in_memory_custody` and `signing_key` (`KeyHandle`)
/// from the creating identity. This function exports the raw key bytes.
#[cfg(feature = "allow_in_memory_custody")]
async fn resolve_napi_signing_key(
    handle: &NapiContextHandle,
) -> napi::Result<ed25519_dalek::SigningKey> {
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        NapiError::from(ScpNapiError::Context {
            message: "no custody provider on context handle — governance lifecycle \
                      requires an identity created with custody"
                .to_owned(),
            code: "SCP-CTX-2040".to_owned(),
        })
    })?;
    let key_handle = handle.signing_key.ok_or_else(|| {
        NapiError::from(ScpNapiError::Context {
            message: "no signing key on context handle — governance lifecycle \
                      requires an identity with an active signing key"
                .to_owned(),
            code: "SCP-CTX-2040".to_owned(),
        })
    })?;
    custody
        .0
        .export_ed25519_signing_key(&key_handle)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("failed to export signing key for governance: {e}"),
                code: "SCP-CTX-2040".to_owned(),
            })
        })
}

/// Parses a hex-encoded proposal ID into a 32-byte array.
fn parse_napi_proposal_id(hex_str: &str) -> napi::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid proposal ID hex: {e}"),
            code: "SCP-CTX-2040".to_owned(),
        })
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("proposal ID must be 32 bytes, got {}", v.len()),
            code: "SCP-CTX-2040".to_owned(),
        })
    })?;
    Ok(arr)
}

/// Proposes a governance action for voting.
///
/// Delegates to `ContextManager::propose_governance_action_checked`.
/// For `SingleAdmin` contexts, the proposal is auto-approved and executed.
/// For multi-admin models (Threshold, Majority, Unanimity), the proposal
/// enters `Pending` status.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `action_json` — JSON-encoded governance action.
/// * `proposer_did` — DID of the proposer.
///
/// # Returns
///
/// JSON string: `{ "proposal_id": hex, "status": string, "execution_result": string | null }`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2041` if the proposal fails.
#[napi(js_name = "contextGovernancePropose")]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_governance_propose(
    handle: &NapiContextHandle,
    action_json: String,
    proposer_did: String,
) -> napi::Result<String> {
    let action: GovernanceAction = serde_json::from_str(&action_json).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid governance action JSON: {e}"),
            code: "SCP-CTX-2040".to_owned(),
        })
    })?;

    let action_name = action.variant_name();

    #[cfg(feature = "allow_in_memory_custody")]
    {
        let signing_key = resolve_napi_signing_key(handle).await?;

        let did = DID(proposer_did);
        let manager = context_manager()?;
        let context_id = handle.context_id.clone();

        let outcome = manager
            .propose_governance_action_checked(&context_id, &did, action, &signing_key)
            .await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("governance proposal failed: {e}"),
                    code: "SCP-CTX-2041".to_owned(),
                })
            })?;

        if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id).await {
            tracing::warn!(
                context_id = %context_id,
                action = action_name,
                error = %e,
                "failed to sync role state after governance proposal"
            );
        }

        let result_str = outcome.execution_result.as_ref().map(|r| format!("{r:?}"));

        let response = serde_json::json!({
            "proposal_id": hex::encode(outcome.proposal.proposal_id),
            "status": format!("{:?}", outcome.status),
            "execution_result": result_str,
        });
        return Ok(response.to_string());
    }

    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (handle, action, action_name, proposer_did);
        return Err(NapiError::from(ScpNapiError::Permission {
            message: "governance proposal requires key custody — in_memory custody feature \
                      is not enabled"
                .to_owned(),
            code: "SCP-CTX-2040".to_owned(),
        }));
    }

    #[allow(unreachable_code)]
    Ok(String::new())
}

/// Casts an approval vote on a pending governance proposal.
///
/// Delegates to `ContextManager::approve_governance_proposal`.
/// If the vote pushes the proposal past quorum, the action is auto-executed.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2042` if the vote fails.
#[napi(js_name = "contextGovernanceApprove")]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_governance_approve(
    handle: &NapiContextHandle,
    proposal_id_hex: String,
    voter_did: String,
) -> napi::Result<String> {
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;

    #[cfg(feature = "allow_in_memory_custody")]
    {
        let signing_key = resolve_napi_signing_key(handle).await?;

        let did = DID(voter_did);
        let manager = context_manager()?;
        let context_id = handle.context_id.clone();

        let status = manager
            .approve_governance_proposal(&context_id, &proposal_id, &did, &signing_key)
            .await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("governance approval failed: {e}"),
                    code: "SCP-CTX-2042".to_owned(),
                })
            })?;

        if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id).await {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to sync role state after governance approval"
            );
        }

        return Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string());
    }

    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (handle, proposal_id, voter_did);
        return Err(NapiError::from(ScpNapiError::Permission {
            message: "governance approval requires key custody — in_memory custody feature \
                      is not enabled"
                .to_owned(),
            code: "SCP-CTX-2040".to_owned(),
        }));
    }

    #[allow(unreachable_code)]
    Ok(String::new())
}

/// Casts a rejection vote on a pending governance proposal.
///
/// Delegates to `ContextManager::reject_governance_proposal`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2043` if the vote fails.
#[napi(js_name = "contextGovernanceReject")]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_governance_reject(
    handle: &NapiContextHandle,
    proposal_id_hex: String,
    voter_did: String,
) -> napi::Result<String> {
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;

    #[cfg(feature = "allow_in_memory_custody")]
    {
        let signing_key = resolve_napi_signing_key(handle).await?;

        let did = DID(voter_did);
        let manager = context_manager()?;
        let context_id = handle.context_id.clone();

        let status = manager
            .reject_governance_proposal(&context_id, &proposal_id, &did, &signing_key)
            .await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("governance rejection failed: {e}"),
                    code: "SCP-CTX-2043".to_owned(),
                })
            })?;

        if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id).await {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to sync role state after governance rejection"
            );
        }

        return Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string());
    }

    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (handle, proposal_id, voter_did);
        return Err(NapiError::from(ScpNapiError::Permission {
            message: "governance rejection requires key custody — in_memory custody feature \
                      is not enabled"
                .to_owned(),
            code: "SCP-CTX-2040".to_owned(),
        }));
    }

    #[allow(unreachable_code)]
    Ok(String::new())
}

/// Withdraws a previously cast vote on a pending governance proposal.
///
/// Delegates to `ContextManager::withdraw_governance_vote`. No signing
/// key is required.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2044` if the withdrawal fails.
#[napi(js_name = "contextGovernanceWithdraw")]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_governance_withdraw(
    handle: &NapiContextHandle,
    proposal_id_hex: String,
    voter_did: String,
) -> napi::Result<String> {
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;
    let did = DID(voter_did);
    let manager = context_manager()?;
    let context_id = handle.context_id.clone();

    let status = manager
        .withdraw_governance_vote(&context_id, &proposal_id, &did)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance vote withdrawal failed: {e}"),
                code: "SCP-CTX-2044".to_owned(),
            })
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id).await {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to sync role state after governance withdrawal"
        );
    }

    Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
}

// ---------------------------------------------------------------------------
// Bridge functions — governance queries (#621)
// ---------------------------------------------------------------------------

/// Retrieves a single governance proposal by hex-encoded ID.
///
/// Returns the full proposal as a JSON string, or rejects if not found.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2045` if the proposal is not found.
#[napi(js_name = "contextGovernanceGetProposal")]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_governance_get_proposal(
    handle: &NapiContextHandle,
    proposal_id_hex: String,
) -> napi::Result<String> {
    let context_id = handle.context_id.clone();
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;
    let manager = context_manager()?;

    let proposal = manager
        .get_proposal(&context_id, &proposal_id)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("get proposal failed: {e}"),
                code: "SCP-CTX-2045".to_owned(),
            })
        })?;

    serde_json::to_string(&proposal).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: "SCP-CTX-2045".to_owned(),
        })
    })
}

/// Lists all governance proposals for a context.
///
/// Returns a JSON array of proposals, or an empty array if the context
/// has no pending proposals.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2046` if listing fails.
#[napi(js_name = "contextGovernanceListProposals")]
pub async fn context_governance_list_proposals(handle: &NapiContextHandle) -> napi::Result<String> {
    let context_id = handle.context_id.clone();
    let manager = context_manager()?;

    let proposals = manager.list_proposals(&context_id).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("list proposals failed: {e}"),
            code: "SCP-CTX-2046".to_owned(),
        })
    })?;

    serde_json::to_string(&proposals).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: "SCP-CTX-2046".to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Bridge functions — ceiling modification, close, checkpoint, restore (#559)
// ---------------------------------------------------------------------------

/// Applies a pending ceiling modification if the notification period has elapsed.
///
/// Returns `true` if the modification was applied, `false` otherwise.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2060` if the operation fails.
#[napi(js_name = "contextApplyPendingCeilingModification")]
pub async fn context_apply_pending_ceiling_modification(
    handle: &NapiContextHandle,
    current_timestamp: f64,
) -> napi::Result<bool> {
    let context_id = handle.context_id.clone();
    let manager = context_manager()?;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ts = current_timestamp as u64;

    manager
        .apply_pending_ceiling_modification(&context_id, ts)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("apply_pending_ceiling_modification failed: {e}"),
                code: "SCP-CTX-2060".to_owned(),
            })
        })
}

/// Finalizes the cooperative close flow for a context in `Closing` state.
///
/// Transitions the context from `Closing` to `Closed`, destroys keys per
/// memory scope, and records a `ContextClosed` event.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2061` if the context is not in `Closing` state.
#[napi(js_name = "contextFinalizeClose")]
pub async fn context_finalize_close(handle: &NapiContextHandle) -> napi::Result<()> {
    let manager = context_manager()?;

    // Use the handle's actual core_handle (which carries correct ContextParams
    // including memory_scope) instead of constructing one with default params.
    // memory_scope governs key destruction behavior in finalize_close — using
    // default (Ephemeral) would incorrectly destroy keys for Full-scope contexts.
    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    // Ensure the core handle is in Closing state. If close_context already
    // transitioned it, the transition_to call fails harmlessly (self-transition
    // or invalid source state) and we ignore the error.
    let _ = core_handle.transition_to(&ContextState::Closing).await;

    manager.finalize_close(core_handle).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("finalize_close failed: {e}"),
            code: "SCP-CTX-2061".to_owned(),
        })
    })?;

    // Update FFI handle state to Closed.
    if let Ok(mut s) = handle.state.lock() {
        *s = ContextState::Closed;
    }

    Ok(())
}

/// Creates a governance checkpoint for a context (ADR-031 §9).
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `checkpoint_seq` — Sequence number.
/// * `merkle_root_hex` — Hex-encoded 32-byte Merkle root.
/// * `event_count` — Number of events.
/// * `last_event_hash_hex` — Hex-encoded 32-byte hash.
/// * `state_snapshot_hash_hex` — Hex-encoded 32-byte hash.
/// * `creator_did` — DID of the checkpoint creator.
/// * `creator_signature_hex` — Hex-encoded Ed25519 signature.
///
/// # Returns
///
/// JSON string with the `ContextCheckpoint` object.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2062` if checkpoint creation fails.
#[napi(js_name = "contextCreateGovernanceCheckpoint")]
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub async fn context_create_governance_checkpoint(
    handle: &NapiContextHandle,
    checkpoint_seq: f64,
    merkle_root_hex: String,
    event_count: f64,
    last_event_hash_hex: String,
    state_snapshot_hash_hex: String,
    creator_did: String,
    creator_signature_hex: String,
) -> napi::Result<String> {
    let context_id = handle.context_id.clone();
    let manager = context_manager()?;

    let merkle_root = parse_napi_hex_32(&merkle_root_hex, "merkle_root")?;
    let last_event_hash = parse_napi_hex_32(&last_event_hash_hex, "last_event_hash")?;
    let state_snapshot_hash = parse_napi_hex_32(&state_snapshot_hash_hex, "state_snapshot_hash")?;
    let creator_signature = hex::decode(&creator_signature_hex).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid creator_signature hex: {e}"),
            code: "SCP-CTX-2062".to_owned(),
        })
    })?;
    let did = DID(creator_did);

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let seq = checkpoint_seq as u64;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let count = event_count as u64;

    let checkpoint = manager
        .create_governance_checkpoint(
            &context_id,
            seq,
            merkle_root,
            count,
            last_event_hash,
            state_snapshot_hash,
            &did,
            creator_signature,
        )
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("create_governance_checkpoint failed: {e}"),
                code: "SCP-CTX-2062".to_owned(),
            })
        })?;

    serde_json::to_string(&checkpoint).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: "SCP-CTX-2062".to_owned(),
        })
    })
}

/// Adds a cosignature to an existing governance checkpoint (ADR-031 §9).
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2063` if cosignature validation fails.
#[napi(js_name = "contextAddCheckpointCosignature")]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_add_checkpoint_cosignature(
    handle: &NapiContextHandle,
    checkpoint_json: String,
    signer_did: String,
    signature_hex: String,
) -> napi::Result<String> {
    let context_id = handle.context_id.clone();
    let manager = context_manager()?;

    let mut checkpoint: scp_core::context::governance::ContextCheckpoint =
        serde_json::from_str(&checkpoint_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid checkpoint JSON: {e}"),
                code: "SCP-CTX-2063".to_owned(),
            })
        })?;

    let signature = hex::decode(&signature_hex).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid signature hex: {e}"),
            code: "SCP-CTX-2063".to_owned(),
        })
    })?;

    let cosignature = scp_core::context::governance::CosignedCheckpoint {
        signer_did: DID(signer_did),
        signature,
    };

    let status = manager
        .add_checkpoint_cosignature(&context_id, &mut checkpoint, cosignature)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("add_checkpoint_cosignature failed: {e}"),
                code: "SCP-CTX-2063".to_owned(),
            })
        })?;

    let response = serde_json::json!({
        "attestation_status": format!("{status:?}"),
        "checkpoint": serde_json::to_value(&checkpoint).unwrap_or_default(),
    });
    Ok(response.to_string())
}

/// Restores a single persisted context from storage.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2064` if restoration fails.
#[napi(js_name = "contextRestore")]
#[allow(clippy::needless_pass_by_value)]
pub async fn context_restore(context_id: String) -> napi::Result<()> {
    let manager = context_manager()?;

    // Load the persisted snapshot to obtain the correct ContextParams (including
    // memory_scope). Using ContextParams::default() would give Ephemeral scope,
    // which would cause incorrect key destruction on subsequent finalize_close.
    let (snapshot, _broadcast) =
        manager
            .load_persisted_context_state(&context_id)
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("restore_context: failed to load persisted state: {e}"),
                    code: "SCP-CTX-2064".to_owned(),
                })
            })?;

    let core_handle = ContextHandle::new(context_id.clone(), snapshot.context_params.clone());
    let _ = core_handle.transition_to(&ContextState::Active).await;

    manager
        .restore_context(&context_id, &core_handle)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("restore_context failed: {e}"),
                code: "SCP-CTX-2064".to_owned(),
            })
        })
}

/// Restores all persisted contexts from storage.
///
/// Returns a JSON array of restored context ID strings.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2065` if restoration fails.
#[napi(js_name = "contextRestoreAll")]
pub async fn context_restore_all() -> napi::Result<String> {
    let manager = context_manager()?;

    let restored = manager.restore_all_contexts().await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("restore_all_contexts failed: {e}"),
            code: "SCP-CTX-2065".to_owned(),
        })
    })?;

    serde_json::to_string(&restored).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: "SCP-CTX-2065".to_owned(),
        })
    })
}

/// Parses a hex string into a 32-byte array for NAPI bridge.
fn parse_napi_hex_32(hex_str: &str, field_name: &str) -> napi::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid {field_name} hex: {e}"),
            code: "SCP-CTX-2062".to_owned(),
        })
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("{field_name} must be 32 bytes, got {}", v.len()),
            code: "SCP-CTX-2062".to_owned(),
        })
    })?;
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Bridge functions — context migration (§5.11A, #580)
// ---------------------------------------------------------------------------

/// Tombstones a migrated context after its grace period has expired (§5.11A.5).
///
/// Transitions the context from `MigratingOut` to `Tombstoned`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2050` if the context is not migrating or the
///   grace period has not expired.
#[napi(js_name = "contextTombstoneMigrated")]
pub async fn context_tombstone_migrated(handle: &NapiContextHandle) -> napi::Result<()> {
    let context_id = handle.context_id.clone();
    let manager = context_manager()?;

    manager
        .tombstone_migrated_context(&context_id)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("tombstone_migrated_context failed: {e}"),
                code: "SCP-CTX-2050".to_owned(),
            })
        })?;

    // Sync FFI handle state to Tombstoned (§5.11A.5).
    if let Ok(mut s) = handle.state.lock() {
        *s = ContextState::Tombstoned;
    }

    Ok(())
}

/// Returns the migration state for a context, if any (§5.11A).
///
/// Returns a JSON string with migration state fields, or `null` if the
/// context is not migrating.
#[napi(js_name = "contextMigrationState")]
pub async fn context_migration_state(handle: &NapiContextHandle) -> napi::Result<Option<String>> {
    let context_id = handle.context_id.clone();
    let manager = context_manager()?;

    let state = manager.migration_state(&context_id).await;
    match state {
        Some(ms) => {
            let json = serde_json::json!({
                "destination_context_id": ms.destination_context_id,
                "reason": ms.reason,
                "grace_period_end": ms.grace_period_end,
                "auto_invite": ms.auto_invite,
                "proposal_id": hex::encode(ms.proposal_id),
            });
            Ok(Some(json.to_string()))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Bridge functions — TTL (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Handles automatic TTL expiry for a context.
///
/// Delegates to `ContextManager::handle_ttl_expiry`.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2005` if the context is not active.
#[napi(js_name = "contextHandleTtlExpiry")]
pub async fn context_handle_ttl_expiry(handle: &NapiContextHandle) -> napi::Result<()> {
    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let manager = context_manager()?;
    manager
        .handle_ttl_expiry(core_handle)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Proposes a TTL extension for a context.
///
/// Delegates to `ContextManager::propose_ttl_extension`. Records consent
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
    let manager = context_manager()?;
    let unanimous = manager
        .propose_ttl_extension(&handle.context_id, &did, duration)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(unanimous)
}

/// Resets the TTL timer for a context.
///
/// Delegates to `ContextManager::reset_ttl_timer`. Requires a core handle
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
    let manager = context_manager()?;
    manager
        .reset_ttl_timer(&handle.context_id, duration, core_handle.clone())
        .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Context export/import (#363)
// ---------------------------------------------------------------------------

/// Exports a context's full state as serialized `MessagePack` bytes.
///
/// Returns serialized `StoredValue<ContextExport>` bytes (§17.5) suitable for
/// backup, migration, or transfer to another node.
///
/// # Errors
///
/// Returns NAPI error if the context does not exist, export fails, or
/// serialization fails.
#[napi(js_name = "contextExport")]
pub async fn context_export(handle: &NapiContextHandle) -> napi::Result<Vec<u8>> {
    let exporter_did = scp_identity::DID::from(handle.creator_did.clone());
    let manager = context_manager()?;
    let export = manager
        .export_context(&handle.context_id, exporter_did)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    scp_core::context::export_import::serialize_export(&export).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("export serialization failed: {e}"),
            code: "SCP-CTX-2030".to_owned(),
        })
    })
}

/// Imports a context from serialized `MessagePack` bytes.
///
/// The bytes must be a `StoredValue<ContextExport>` envelope (§17.5), as
/// produced by [`context_export`].
///
/// Returns the context ID of the imported context.
///
/// # Errors
///
/// Returns NAPI error if deserialization, validation, or import fails.
#[napi(js_name = "contextImport")]
pub async fn context_import(data: Vec<u8>) -> napi::Result<String> {
    let export = scp_core::context::export_import::deserialize_export(&data).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("invalid export data: {e}"),
            code: "SCP-CTX-2032".to_owned(),
        })
    })?;
    let context_id = export.snapshot.context_id.clone();

    // Validate the exporter DID before passing to init_context_manager (#1324).
    validate_did(&export.exporter_did.0).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // Ensure the ContextManager is initialized — context_import is a valid
    // first operation (e.g. a device receiving exported context data).
    // init_context_manager is idempotent (OnceLock — first call wins). #1073
    // Passes the exporter DID to MlsCryptoProvider for real MLS encryption (#1294).
    crate::runtime::init_context_manager(&export.exporter_did.0);

    let manager = context_manager()?;
    manager
        .import_context(export)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(context_id)
}

// ---------------------------------------------------------------------------
// Economic policy bridge (§19.3, ADR-033)
// ---------------------------------------------------------------------------

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
#[napi(js_name = "contextSetEconomicPolicy")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub fn context_set_economic_policy(
    _handle: &mut NapiContextHandle,
    _policy_json: String,
) -> napi::Result<()> {
    Err(NapiError::from(ScpNapiError::Permission {
        message: "economic policy changes must go through governance \
                  (propose SetEconomicPolicy action). Direct mutation is \
                  not permitted — see spec §19.3"
            .to_owned(),
        code: "SCP-CTX-2013".to_owned(),
    }))
}

/// Returns the economic policy for a context as a JSON string, or `null`.
#[napi(js_name = "contextGetEconomicPolicy")]
#[must_use]
pub fn context_get_economic_policy(handle: &NapiContextHandle) -> Option<String> {
    handle.economic_policy.clone()
}

// ---------------------------------------------------------------------------
// App Sandboxing (#595, spec §8.4.1, §8.4.2)
// ---------------------------------------------------------------------------

/// Validates a capability declaration JSON string against context ceiling and role.
///
/// Returns a JSON string with fields: `valid` (bool), `grantedCapabilities`
/// (string[]), `error` (string | null), and `appDid` (string).
#[napi]
pub fn validate_capability_declaration(
    declaration_json: String,
    ceiling_capabilities: Vec<String>,
    role_capabilities: Vec<String>,
) -> napi::Result<String> {
    use scp_core::context::app_sandbox::{CapabilityDeclaration, validate_declaration};
    use scp_core::context::roles::Capability;
    use scp_core::context::{ContextHandle, ContextParams};

    let decl: CapabilityDeclaration = serde_json::from_str(&declaration_json)
        .map_err(|e| NapiError::from_reason(format!("invalid declaration JSON: {e}")))?;

    let ceiling: Vec<Capability> = ceiling_capabilities.iter().map(Capability::new).collect();
    let role_caps: Vec<Capability> = role_capabilities.iter().map(Capability::new).collect();

    let handle = ContextHandle::new("validation-context".to_owned(), ContextParams::default());

    let result_json = match validate_declaration(&decl, &ceiling, &role_caps, handle) {
        Ok(scoped) => {
            let granted: Vec<String> = scoped
                .allowed_capabilities()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            serde_json::json!({
                "valid": true,
                "grantedCapabilities": granted,
                "error": null,
                "appDid": decl.app_id.to_string()
            })
        }
        Err(e) => serde_json::json!({
            "valid": false,
            "grantedCapabilities": [],
            "error": e.to_string(),
            "appDid": decl.app_id.to_string()
        }),
    };

    serde_json::to_string(&result_json)
        .map_err(|e| NapiError::from_reason(format!("serialization failed: {e}")))
}

/// Checks whether a given capability is allowed for an app binding.
#[napi]
pub fn check_scoped_capability(
    granted_capabilities: Vec<String>,
    required_capability: String,
) -> bool {
    use scp_core::context::roles::Capability;
    use std::collections::HashSet;

    let granted: HashSet<Capability> = granted_capabilities.iter().map(Capability::new).collect();
    let required = Capability::new(&required_capability);

    if granted.contains(&required) {
        return true;
    }
    if matches!(&required, Capability::ToolInvoke(_))
        && granted.contains(&Capability::ToolInvokeAll)
    {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Invitation evaluation pipeline (#614)
// ---------------------------------------------------------------------------

/// Result of invitation evaluation.
#[napi(object)]
pub struct NapiEvaluationResult {
    /// The decision: `"auto_accept"` or `"prompt_agent"`.
    pub decision: String,
}

/// FFI-concrete implementation of `TrustOracle`.
struct NapiBridgeTrustOracle {
    trusted_dids: Vec<scp_identity::DID>,
}

impl scp_core::context::invitation::TrustOracle for NapiBridgeTrustOracle {
    fn satisfies_trust(
        &self,
        inviter: &scp_identity::DID,
        requirement: &scp_core::context::policy::TrustRequirement,
    ) -> bool {
        match requirement {
            scp_core::context::policy::TrustRequirement::Any => true,
            scp_core::context::policy::TrustRequirement::SharedContext => {
                self.trusted_dids.contains(inviter)
            }
            scp_core::context::policy::TrustRequirement::Explicit(dids) => dids.contains(inviter),
        }
    }
}

/// Evaluates a context invitation through the sequential pipeline.
///
/// Runs the 4-step evaluation pipeline from `scp-core`:
/// 1. Template validation (rejects template spoofing).
/// 2. Economic policy check (rejects insufficient spending capability).
/// 3. Auto-accept evaluation (trust, TTL cap, rate limit).
/// 4. Falls through to prompt-agent if no auto-accept matches.
///
/// @param paramsJson - JSON-serialized `ContextParams` from the invitation.
/// @param inviterDid - DID string of the identity sending the invitation.
/// @param identityDid - DID string of the local identity receiving the invitation.
/// @param policyJson - Optional JSON-serialized `AutoAcceptPolicy`.
/// @param spendingJson - Optional JSON-serialized `SpendingContext`.
/// @param trustedDidsJson - Optional JSON array of trusted DID strings.
/// @returns `NapiEvaluationResult` with the decision.
#[napi]
pub fn evaluate_invitation(
    params_json: String,
    inviter_did: String,
    identity_did: String,
    policy_json: Option<String>,
    spending_json: Option<String>,
    trusted_dids_json: Option<String>,
) -> napi::Result<NapiEvaluationResult> {
    use scp_core::context::invitation::{
        EvaluationDecision, SpendingContext, evaluate_invitation as core_evaluate,
    };
    use scp_core::context::policy::AutoAcceptPolicy;

    validate_did(&inviter_did).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: e.message,
            code: "SCP-VALID-7010".to_owned(),
        })
    })?;
    validate_did(&identity_did).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: e.message,
            code: "SCP-VALID-7010".to_owned(),
        })
    })?;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse context params JSON: {e}"),
                code: "SCP-VALID-7010".to_owned(),
            })
        })?;

    let policy: Option<AutoAcceptPolicy> = match policy_json {
        Some(ref json) => Some(serde_json::from_str(json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse auto-accept policy JSON: {e}"),
                code: "SCP-VALID-7010".to_owned(),
            })
        })?),
        None => None,
    };

    let spending: Option<SpendingContext> = match spending_json {
        Some(ref json) => Some(serde_json::from_str(json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse spending context JSON: {e}"),
                code: "SCP-VALID-7010".to_owned(),
            })
        })?),
        None => None,
    };

    let trusted_dids: Vec<scp_identity::DID> = match trusted_dids_json {
        Some(ref json) => {
            let did_strings: Vec<String> = serde_json::from_str(json).map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("failed to parse trusted DIDs JSON: {e}"),
                    code: "SCP-VALID-7010".to_owned(),
                })
            })?;
            did_strings
                .into_iter()
                .map(scp_identity::DID::from)
                .collect()
        }
        None => Vec::new(),
    };

    let oracle = NapiBridgeTrustOracle { trusted_dids };
    let inviter = scp_identity::DID::from(inviter_did.as_str());

    let decision = crate::runtime::with_rate_limit_tracker(&identity_did, |tracker| {
        core_evaluate(
            &params,
            &inviter,
            policy.as_ref(),
            spending.as_ref(),
            &oracle,
            tracker,
            &scp_core::time::SystemClock,
        )
    });

    match decision {
        Ok(EvaluationDecision::AutoAccept) => Ok(NapiEvaluationResult {
            decision: "auto_accept".to_owned(),
        }),
        Ok(EvaluationDecision::PromptAgent) => Ok(NapiEvaluationResult {
            decision: "prompt_agent".to_owned(),
        }),
        Err(e) => Err(napi::Error::from(ScpNapiError::Context {
            message: format!("invitation evaluation failed: {e}"),
            code: "SCP-CTX-2060".to_owned(),
        })),
    }
}

// ---------------------------------------------------------------------------
// MetadataRecord inspection (§5.7.2, #615)
// ---------------------------------------------------------------------------

/// Serializes a `MetadataRecord` to a JSON string.
///
/// Constructs a `MetadataRecord` from the provided fields and returns its
/// JSON representation. The `signature` field is provided as a hex-encoded
/// string (64 bytes = 128 hex characters).
#[napi]
pub fn metadata_record_to_json(
    context_id: String,
    sequence: u32,
    signer_did: String,
    timestamp: f64,
    structural_json: String,
    operational_json: String,
    signature_hex: String,
) -> napi::Result<String> {
    use scp_core::context::metadata::{MetadataRecord, OperationalMetadata, StructuralMetadata};
    use scp_ffi_common::validate::{validate_context_id, validate_did};

    validate_context_id(&context_id).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: e.to_string(),
            code: "SCP-VALID-7001".to_owned(),
        })
    })?;
    validate_did(&signer_did).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: e.to_string(),
            code: "SCP-VALID-7001".to_owned(),
        })
    })?;

    if sequence == 0 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: "SCP-VALID-7001".to_owned(),
        }));
    }

    let structural: StructuralMetadata = serde_json::from_str(&structural_json).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid structural metadata JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        })
    })?;

    let operational: OperationalMetadata =
        serde_json::from_str(&operational_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid operational metadata JSON: {e}"),
                code: "SCP-VALID-7001".to_owned(),
            })
        })?;

    let signature = hex::decode(&signature_hex).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid signature hex: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        })
    })?;
    if signature.len() != 64 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: format!("signature must be 64 bytes (got {})", signature.len()),
            code: "SCP-VALID-7001".to_owned(),
        }));
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ts = timestamp as u64;
    let record = MetadataRecord {
        context_id,
        sequence: u64::from(sequence),
        signer_did: scp_identity::DID::from(signer_did),
        timestamp: ts,
        structural,
        operational,
        signature,
    };

    serde_json::to_string(&record).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("failed to serialize MetadataRecord: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        })
    })
}

/// Deserializes a `MetadataRecord` from a JSON string.
///
/// Returns the validated and re-serialized JSON.
#[napi]
pub fn metadata_record_from_json(json_str: String) -> napi::Result<String> {
    use scp_core::context::metadata::MetadataRecord;

    let record: MetadataRecord = serde_json::from_str(&json_str).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid MetadataRecord JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        })
    })?;

    // F6: sequence must be >= 1 (spec §5.7.2)
    if record.sequence == 0 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: "SCP-VALID-7001".to_owned(),
        }));
    }

    // F7: signature must be exactly 64 bytes (Ed25519)
    if record.signature.len() != 64 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: format!(
                "signature must be 64 bytes (got {})",
                record.signature.len()
            ),
            code: "SCP-VALID-7001".to_owned(),
        }));
    }

    serde_json::to_string(&record).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("failed to re-serialize MetadataRecord: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Context template inspection (§5.14, #615)
// ---------------------------------------------------------------------------

/// Returns the canonical `ContextParams` for a given template ID as JSON.
#[napi]
pub fn template_get_params(template_id: String) -> napi::Result<String> {
    use scp_core::context::templates::template_params;

    let tid = parse_template_id_napi(&template_id)?;
    let params = template_params(&tid);
    serde_json::to_string(&params).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("failed to serialize template params: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        })
    })
}

/// Validates that a `ContextParams` JSON matches its template definition.
///
/// Returns `null` on success, or a string error message on validation failure.
#[napi]
pub fn validate_against_template(params_json: String) -> napi::Result<Option<String>> {
    use scp_core::context::templates::validate_against_template;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid ContextParams JSON: {e}"),
                code: "SCP-VALID-7001".to_owned(),
            })
        })?;

    match validate_against_template(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Validates cross-field invariants for `ContextParams` regardless of template.
///
/// Returns `null` on success, or a string error message on validation failure.
#[napi]
pub fn validate_context_params(params_json: String) -> napi::Result<Option<String>> {
    use scp_core::context::templates::validate_context_params;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid ContextParams JSON: {e}"),
                code: "SCP-VALID-7001".to_owned(),
            })
        })?;

    match validate_context_params(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Parses a template ID string into a `TemplateId` enum value.
fn parse_template_id_napi(
    template_id: &str,
) -> napi::Result<scp_core::context::params::TemplateId> {
    use scp_core::context::params::TemplateId;

    match template_id {
        "BilateralEphemeral" => Ok(TemplateId::BilateralEphemeral),
        "BilateralPersistent" => Ok(TemplateId::BilateralPersistent),
        "Coordination" => Ok(TemplateId::Coordination),
        "GroupDiscussion" => Ok(TemplateId::GroupDiscussion),
        "PublicBroadcast" => Ok(TemplateId::PublicBroadcast),
        "GatedBroadcast" => Ok(TemplateId::GatedBroadcast),
        "scp:template/tool-interface" | "ToolInterfaceTemplate" => {
            Ok(TemplateId::ToolInterfaceTemplate)
        }
        "PaidService" => Ok(TemplateId::PaidService),
        "PaidBroadcast" => Ok(TemplateId::PaidBroadcast),
        "scp:template/handle-registry"
        | "HandleRegistry"
        | "scp:template/discovery-context"
        | "DiscoveryContext" => Ok(TemplateId::HandleRegistry),
        _ => Err(NapiError::from(ScpNapiError::Validation {
            message: format!(
                "unknown template ID: {template_id:?} — valid values: BilateralEphemeral, \
                 BilateralPersistent, Coordination, GroupDiscussion, PublicBroadcast, \
                 GatedBroadcast, scp:template/tool-interface, PaidService, PaidBroadcast, \
                 HandleRegistry, scp:template/handle-registry, DiscoveryContext, \
                 scp:template/discovery-context"
            ),
            code: "SCP-VALID-7001".to_owned(),
        })),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::runtime::context_manager;
    use scp_core::context::ContextParams;
    use scp_core::context::governance::GovernanceAction;
    use scp_core::context::membership::KeyPackage;
    use scp_core::context::params::Capability;
    use scp_identity::DID;

    use scp_ffi_common::test_helpers::approved_proposal;

    /// Verifies that `ContextManager::member_count` returns the live member
    /// count — not a hardcoded value.  After creation the count is 1 (the
    /// creator); after a join it becomes 2.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn member_count_reflects_actual_membership() {
        crate::runtime::init_context_manager_for_test();
        let manager = context_manager().expect("manager initialized above");
        let ctx_id = format!("test-member-count-{}", uuid::Uuid::new_v4());
        let creator = DID("did:key:z6MkCreator".to_owned());

        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign")],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context(ctx_id.clone(), params, creator)
            .await
            .expect("create_context should succeed");

        let count = manager.member_count(&ctx_id).await.unwrap();
        assert_eq!(
            count, 1,
            "newly created context should have exactly 1 member"
        );

        let kp = KeyPackage::mock(DID("did:key:z6MkJoiner".to_owned()));
        manager
            .join_context(&handle, kp, None)
            .await
            .expect("join_context should succeed");

        let count = manager.member_count(&ctx_id).await.unwrap();
        assert_eq!(count, 2, "after join, context should have 2 members");
    }

    /// Verifies roundtrip set / get for economic policy on `NapiContextHandle`.
    #[test]
    fn set_get_economic_policy_roundtrip() {
        use super::*;
        use std::sync::Mutex;

        let mut handle = NapiContextHandle {
            context_id: "test-ctx-econ".to_owned(),
            state: Mutex::new(ContextState::Active),
            creator_did: "did:key:z6MkTest".to_owned(),
            mode: "Encrypted".to_owned(),
            ceiling: vec![],
            ceiling_policy: "immutable".to_owned(),
            ttl_seconds: None,
            promotion_policy: None,
            governance: "single_admin".to_owned(),
            economic_policy: None,
            #[cfg(feature = "allow_in_memory_custody")]
            in_memory_custody: None,
            signing_key: None,
            core_handle: None,
            subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
            subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // Initially None.
        assert!(context_get_economic_policy(&handle).is_none());

        // Direct set always rejects — must use governance (#728).
        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":null,"per_tool_invoke":100,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkTest"}"#;
        let result = context_set_economic_policy(&mut handle, json.to_owned());
        assert!(
            result.is_err(),
            "direct set must be rejected — use governance"
        );
        // Policy should remain unchanged.
        assert!(context_get_economic_policy(&handle).is_none());
    }

    // -----------------------------------------------------------------------
    // Role state sync after governance (#560)
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn role_state_syncs_after_change_role() {
        crate::runtime::init_context_manager_for_test();
        let manager = context_manager().expect("manager initialized above");
        let ctx_id = format!("napi-sync-role-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkNapiCreator1";
        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign")],
            ..ContextParams::default()
        };
        manager
            .create_context(ctx_id.clone(), params, DID(creator.to_owned()))
            .await
            .unwrap();
        crate::runtime::register_test_context(&ctx_id, creator);
        let new_did = "did:key:z6MkNapiMember1";
        let add = approved_proposal(
            [10u8; 32],
            &ctx_id,
            GovernanceAction::AddMember {
                did: DID(new_did.to_owned()),
                role: "member".to_owned(),
            },
            creator,
        );
        manager
            .execute_governance_action(&ctx_id, &add)
            .await
            .unwrap();
        crate::runtime::sync_role_state_from_manager(&ctx_id)
            .await
            .unwrap();
        let change = approved_proposal(
            [11u8; 32],
            &ctx_id,
            GovernanceAction::ChangeRole {
                did: DID(new_did.to_owned()),
                new_role: "observer".to_owned(),
            },
            creator,
        );
        manager
            .execute_governance_action(&ctx_id, &change)
            .await
            .unwrap();
        crate::runtime::sync_role_state_from_manager(&ctx_id)
            .await
            .unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            let assignment = st
                .role_state
                .assignments
                .get(new_did)
                .expect("member should have an assignment");
            assert_eq!(assignment.role_name, "observer");
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&ctx_id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn role_state_syncs_after_add_member() {
        crate::runtime::init_context_manager_for_test();
        let manager = context_manager().expect("manager initialized above");
        let ctx_id = format!("napi-sync-add-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkNapiCreator2";
        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign")],
            ..ContextParams::default()
        };
        manager
            .create_context(ctx_id.clone(), params, DID(creator.to_owned()))
            .await
            .unwrap();
        crate::runtime::register_test_context(&ctx_id, creator);
        let new_did = "did:key:z6MkNapiAdded1";
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(!st.role_state.members.contains(new_did));
            Ok(())
        })
        .unwrap();
        let add = approved_proposal(
            [12u8; 32],
            &ctx_id,
            GovernanceAction::AddMember {
                did: DID(new_did.to_owned()),
                role: "member".to_owned(),
            },
            creator,
        );
        manager
            .execute_governance_action(&ctx_id, &add)
            .await
            .unwrap();
        crate::runtime::sync_role_state_from_manager(&ctx_id)
            .await
            .unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(st.role_state.members.contains(new_did));
            assert_eq!(
                st.role_state
                    .assignments
                    .get(new_did)
                    .map(|a| a.role_name.as_str()),
                Some("member")
            );
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&ctx_id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn role_state_syncs_after_remove_member() {
        crate::runtime::init_context_manager_for_test();
        let manager = context_manager().expect("manager initialized above");
        let ctx_id = format!("napi-sync-rm-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkNapiCreator3";
        let target = "did:key:z6MkNapiRemTarget";
        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign")],
            ..ContextParams::default()
        };
        manager
            .create_context(ctx_id.clone(), params, DID(creator.to_owned()))
            .await
            .unwrap();
        crate::runtime::register_test_context(&ctx_id, creator);
        let add = approved_proposal(
            [13u8; 32],
            &ctx_id,
            GovernanceAction::AddMember {
                did: DID(target.to_owned()),
                role: "member".to_owned(),
            },
            creator,
        );
        manager
            .execute_governance_action(&ctx_id, &add)
            .await
            .unwrap();
        crate::runtime::sync_role_state_from_manager(&ctx_id)
            .await
            .unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(st.role_state.members.contains(target));
            Ok(())
        })
        .unwrap();
        let rm = approved_proposal(
            [14u8; 32],
            &ctx_id,
            GovernanceAction::Eject {
                did: DID(target.to_owned()),
                reason: Some("test removal".to_owned()),
            },
            creator,
        );
        manager
            .execute_governance_action(&ctx_id, &rm)
            .await
            .unwrap();
        crate::runtime::sync_role_state_from_manager(&ctx_id)
            .await
            .unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(!st.role_state.members.contains(target));
            assert!(!st.role_state.assignments.contains_key(target));
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&ctx_id);
    }

    // -------------------------------------------------------------------
    // Consequence event format tests (#1531, #1593, #1594)
    // -------------------------------------------------------------------

    #[test]
    fn format_consequence_triggered_event() {
        use scp_core::context::membership::ContextEvent;

        let event = ContextEvent::ConsequenceTriggered {
            context_id: "ctx-napi-123".to_owned(),
            member_did: scp_identity::DID("did:dht:z6MkBob".to_owned()),
            rule_index: 1,
            trigger_type: "velocity".to_owned(),
            action_type: "mute".to_owned(),
        };

        let formatted = super::format_context_event(&event);
        assert!(
            formatted.contains("consequence_triggered:"),
            "must contain consequence_triggered prefix"
        );
        assert!(
            formatted.contains("member=did:dht:z6MkBob"),
            "must contain member DID"
        );
        assert!(formatted.contains("rule=1"), "must contain rule index");
        assert!(
            formatted.contains("trigger=velocity"),
            "must contain trigger type"
        );
        assert!(
            formatted.contains("action=mute"),
            "must contain action type"
        );
        assert!(
            formatted.contains("context=ctx-napi-123"),
            "must contain context ID"
        );
    }

    #[test]
    fn format_consequence_enforced_event() {
        use scp_core::context::membership::ContextEvent;

        let event = ContextEvent::ConsequenceEnforced {
            context_id: "ctx-napi-456".to_owned(),
            member_did: scp_identity::DID("did:dht:z6MkAlice".to_owned()),
            action_type: "restrict_write".to_owned(),
            success: false,
        };

        let formatted = super::format_context_event(&event);
        assert!(
            formatted.contains("consequence_enforced:"),
            "must contain consequence_enforced prefix"
        );
        assert!(
            formatted.contains("member=did:dht:z6MkAlice"),
            "must contain member DID"
        );
        assert!(
            formatted.contains("action=restrict_write"),
            "must contain action type"
        );
        assert!(
            formatted.contains("success=false"),
            "must contain success=false"
        );
    }

    /// Verifies that `ContextParams` accepts `consequence_rules` and they
    /// serialize/deserialize correctly for FFI bridge consumption.
    #[test]
    fn consequence_rules_in_context_params() {
        use scp_core::context::ContextParams;

        // Parse a consequence rule from JSON (mirrors what the bridge does).
        let json = r#"[{"trigger":"MessageVelocity","action":"SuspendAll","threshold":10,"window":{"secs":3600,"nanos":0}}]"#;
        let rules: Vec<scp_core::trust::ConsequenceRule> = serde_json::from_str(json).unwrap();

        let params = ContextParams {
            consequence_rules: rules,
            ..ContextParams::default()
        };

        assert_eq!(
            params.consequence_rules.len(),
            1,
            "consequence_rules should carry 1 rule"
        );
    }

    // -------------------------------------------------------------------
    // Spending UCAN parameter acceptance tests (#1537, #1593)
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_invitation_accepts_spending_json() {
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();
        let spending_json =
            r#"{"has_spending_ucan":true,"configured_adapters":["x402"],"available_balance":10000}"#
                .to_owned();

        let result = super::evaluate_invitation(
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            Some(spending_json),
            None,
        );

        // Free context: pipeline reaches prompt_agent regardless of spending.
        assert!(result.is_ok(), "spending_json should be accepted");
        assert_eq!(result.unwrap().decision, "prompt_agent");
    }

    #[test]
    fn evaluate_invitation_rejects_invalid_spending_json() {
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();

        let result = super::evaluate_invitation(
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            Some("not valid json".to_owned()),
            None,
        );

        assert!(result.is_err(), "invalid spending JSON should be rejected");
    }

    #[test]
    fn evaluate_invitation_none_spending_accepted() {
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();

        let result = super::evaluate_invitation(
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            None,
            None,
        );

        assert!(result.is_ok(), "None spending should be accepted");
        assert_eq!(result.unwrap().decision, "prompt_agent");
    }
}
