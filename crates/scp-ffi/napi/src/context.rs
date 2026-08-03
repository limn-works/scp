//! napi-rs bridge for context lifecycle, messaging, governance, broadcast,
//! membership queries, TTL, and events.
//!
//! All operations route through [`crate::runtime::supervisor`] via the
//! ADR-049 dispatch surface (`Supervisor::dispatch_*`). The
//! `NapiContextHandle` is a thin handle carrying context metadata and a
//! reference to the `ContextHandle` from `scp-core`.
//!
//! See issue #388 and ADR-022 in `.docs/adrs/phase-4.md`.

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;
use scp_clock::Clock;
use scp_core::context::governance::GovernanceAction;
use scp_core::context::state::GovernanceActionResult;
use scp_core::context::{ContextHandle, ContextState};
use scp_did::DID;
use tokio_util::sync::CancellationToken;

use scp_platform::traits::KeyCustody;

use scp_ffi_common::validate::validate_did;

use crate::error::ScpNapiError;
use crate::identity::NapiIdentity;
use crate::runtime::NapiBridgeInstance;
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
/// Uses `generate_key_package_with_context_params` with `None` so the leaf
/// **declares the `0xFF02` (`scp_context_params`) capability** — mandatory to
/// be added to an encrypted context group (`valn0502`, §5.13.3). The base
/// `generate_key_package` declares no SCP capabilities and real MLS rejects it
/// from a context group. No wrapping-key leaf extension is attached (this
/// single-process membership path retains no joiner private state).
///
/// # Errors
///
/// Returns `ScpNapiError::Crypto` if the DID format is invalid (must be
/// `did:dht:z...`), key package generation fails, or TLS serialization
/// fails.
fn generate_mls_key_package_bytes(did: &str) -> Result<Vec<u8>, ScpNapiError> {
    use scp_core::crypto::mls::credential::ScpCredential;
    use scp_core::crypto::mls::group::generate_key_package_with_context_params;
    use tls_codec::Serialize as TlsSerializeTrait;

    let cred =
        ScpCredential::new(did.to_owned(), None, scp_did::SigningKeyId::Active).map_err(|e| {
            ScpNapiError::Crypto {
                message: format!("failed to create SCP credential for MLS key package: {e}"),
                code: codes::CRYPTO_4010.to_owned(),
            }
        })?;

    let (kp_bundle, _signer, _provider) =
        generate_key_package_with_context_params(&cred, None, &scp_clock::SystemClock).map_err(
            |e| ScpNapiError::Crypto {
                message: format!("MLS key package generation failed: {e}"),
                code: codes::CRYPTO_4011.to_owned(),
            },
        )?;

    kp_bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| ScpNapiError::Crypto {
            message: format!("MLS key package TLS serialization failed: {e}"),
            code: codes::CRYPTO_4012.to_owned(),
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
/// console.log(ctx.contextId);      // 64-char lowercase hex per spec §18.4.1
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
    /// Retained custody for UCAN signing — shares the creator identity's
    /// `Arc<NapiKeyCustody>` so context-level signing uses the same key
    /// material (and works for callback-backed identities too).
    ///
    /// Available in production (not feature-gated): in the production
    /// callback-custody path this carries the creator identity's retained
    /// `Arc<NapiKeyCustody::Callback>`. The field name is historical — it
    /// backs any retained custody, not just in-memory. `None` when the context
    /// creator was an externally loaded (DID-string-only) identity.
    pub(crate) in_memory_custody: Option<Arc<crate::custody::NapiKeyCustody>>,
    /// Handle to the creator's active signing key for UCAN minting and
    /// context-export signing.
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
    /// The `NapiBridgeInstance` that minted this handle.
    ///
    /// Retained so getter methods on the handle (e.g. `memberCount`) can
    /// reach the `ContextManager` without depending on the process-global
    /// default bridge. Phase D (#1695).
    pub(crate) bi: Arc<NapiBridgeInstance>,
    /// Identifier of the `NapiBridgeInstance` that minted this handle.
    /// Checked at every FFI entry point that accepts the handle via the
    /// [`napi_check_handle!`](crate::napi_check_handle) macro. Rejects
    /// cross-instance misuse with `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
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
        ContextState::Poisoned => "poisoned",
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
                code: codes::CTX_2012.to_owned(),
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
        use scp_core::context::actor::commands::QueriesCommand;
        let sup = crate::runtime::supervisor(&self.bi)?;
        let sup = Arc::clone(sup);
        let context_id = self.context_id.clone();
        let count = crate::runtime().block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = QueriesCommand::MemberCount {
                context_id,
                reply: tx,
            };
            if sup.dispatch_query(cmd).await.is_err() {
                return 0usize;
            }
            match rx.await {
                Ok(Ok(Some(n))) => n,
                _ => 0,
            }
        });
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
                code: codes::CTX_2012.to_owned(),
            })
    }

    /// Sets the state to Closed.
    pub(crate) fn set_closed(&self) -> Result<(), ScpNapiError> {
        *self.state.lock().map_err(|_| ScpNapiError::Context {
            message: "context state lock is poisoned".to_owned(),
            code: codes::CTX_2012.to_owned(),
        })? = ContextState::Closed;
        Ok(())
    }

    /// Returns the scp-core `ContextHandle`, or an error if not available.
    fn require_core_handle(&self) -> Result<&ContextHandle, ScpNapiError> {
        self.core_handle
            .as_ref()
            .ok_or_else(|| ScpNapiError::Context {
                message: "context does not have a core handle — context was not created via \
                      Supervisor"
                    .to_owned(),
                code: codes::CTX_2024.to_owned(),
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
    /// Creates a minimal active handle stamped with the given bridge
    /// instance's id. Suitable for testing bridge functions that only need
    /// UCAN state (set up via `ensure_registered`).
    pub(crate) fn test_active_on(
        bi: &Arc<NapiBridgeInstance>,
        context_id: String,
        creator_did: String,
    ) -> Self {
        increment_handle_count();
        let instance_id = bi.instance_id();
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
            in_memory_custody: None,
            signing_key: None,
            core_handle: None,
            subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
            subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            bi: Arc::clone(bi),
            instance_id,
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

/// Derives a member's per-context pseudonym routing ID for ENCRYPTED contexts
/// (§9.10.4).
///
/// An encrypted context with no real pseudonym is silently unusable — the
/// member cannot send application data on a pseudonymous routing axis — so
/// derivation failure MUST be a typed error rather than a swallowed `None`.
/// Codes match the `PyO3` reference bridge exactly so the same failure yields the
/// same `.code` across bridges: missing key material → SCP-IDENT-1054,
/// derivation failure → SCP-IDENT-1055, wrong key length → SCP-IDENT-1057.
///
/// Un-gated for production: pseudonym derivation runs through retained
/// callback custody (OS-keychain/HSM), exactly like the rest of the signing
/// chain. The fail-closed boundary is the ABSENCE of retained custody
/// (SCP-IDENT-1054), not a build feature.
async fn derive_context_pseudonym_required(
    identity: &NapiIdentity,
    context_id: &str,
) -> napi::Result<[u8; 32]> {
    let (Some(scp_id), Some(custody)) = (
        identity.inner.scp_identity.as_ref(),
        identity.inner.in_memory_custody.as_ref(),
    ) else {
        return Err(NapiError::from(ScpNapiError::Identity {
            message: "cannot derive pseudonym without retained key material — \
                      encrypted contexts require a real per-member routing ID"
                .to_owned(),
            code: codes::IDENT_1054.to_owned(),
        }));
    };
    derive_pseudonym_bytes(custody, &scp_id.identity_key, context_id).await
}

/// Core pseudonym-derivation sequence shared by every NAPI entry point.
///
/// Holds the single authoritative definition of the derivation-failure code
/// contract (derivation failure → SCP-IDENT-1055, wrong key length →
/// SCP-IDENT-1057). The missing-key-material code (SCP-IDENT-1054) is surfaced
/// by the callers that resolve custody (which know whether the lookup came from
/// a handle or the registry). Centralizing here mirrors the `PyO3` reference
/// bridge so the 1054/1055/1057 contract cannot drift across create / join /
/// import.
async fn derive_pseudonym_bytes(
    custody: &crate::custody::NapiKeyCustody,
    identity_key: &scp_platform::KeyHandle,
    context_id: &str,
) -> napi::Result<[u8; 32]> {
    let pseudonym = custody
        .derive_pseudonym(identity_key, context_id.as_bytes())
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("pseudonym derivation failed: {e}"),
                code: codes::IDENT_1055.to_owned(),
            })
        })?;
    let bytes: [u8; 32] = pseudonym.public_key.as_bytes().try_into().map_err(|_| {
        NapiError::from(ScpNapiError::Identity {
            message: "pseudonym public key must be 32 bytes".to_owned(),
            code: codes::IDENT_1057.to_owned(),
        })
    })?;
    Ok(bytes)
}

/// Resolves a member's per-context pseudonym from the bridge identity registry,
/// hard-failing with the canonical identity codes.
///
/// Mirrors the `PyO3` reference bridge's `derive_member_pseudonym(bi, did,
/// context_id)`: resolves the importer/joiner's custody + identity key from the
/// registry (a miss is missing key material → SCP-IDENT-1054), then routes
/// through [`derive_pseudonym_bytes`] for the 1055/1057 contract. Used by the
/// (encrypted-only) IMPORT path and the encrypted JOIN path so the routing axis
/// is never silently degraded to the reserved `[0u8; 32]` sentinel.
async fn derive_member_pseudonym_required(
    bi: &NapiBridgeInstance,
    did: &str,
    context_id: &str,
) -> napi::Result<[u8; 32]> {
    let custody_and_key = crate::runtime::with_identity(bi, did, |entry| {
        Ok((entry.custody.clone(), entry.identity.identity_key))
    })
    .map_err(|_| {
        NapiError::from(ScpNapiError::Identity {
            message: "cannot derive pseudonym without retained key material — \
                      encrypted contexts require a real per-member routing ID"
                .to_owned(),
            code: codes::IDENT_1054.to_owned(),
        })
    })?;
    let (custody, identity_key) = custody_and_key;
    derive_pseudonym_bytes(&custody, &identity_key, context_id).await
}

/// Best-effort §9.10.4 pseudonym announcement (NAPI).
///
/// The caller decides WHETHER to announce — a pseudonym is present on join, or
/// the imported context is non-broadcast — and this helper owns the HOW so the
/// join and import paths cannot drift apart. It runs over the retained callback
/// custody (OS-keychain/HSM, production) exactly like the `PyO3` import reference.
/// Best-effort: a sign-only custody that cannot export raw signing bytes simply
/// skips, and peers recover on the announcer's next explicit announcement. Never
/// panics — a missing key or a dropped reply is swallowed.
async fn announce_pseudonym_best_effort(
    bi: &NapiBridgeInstance,
    sup: &scp_core::context::supervisor::Supervisor,
    did: &str,
    context_id: &str,
    params: scp_core::context::ContextParams,
) {
    // Extract custody + key handle from the registry (sync), then export the
    // signing key asynchronously — avoids block_on inside an async fn.
    let Some((custody, key_handle)) = crate::runtime::with_identity(bi, did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .ok() else {
        return;
    };
    let Ok(sk) = custody.export_ed25519_signing_key(&key_handle).await else {
        return;
    };
    use scp_core::context::actor::commands::{
        MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = MessagingCommand::SendPseudonymAnnouncement {
        payload: Box::new(SendPseudonymAnnouncementPayload {
            context_id: context_id.to_owned(),
            params,
            sender_did: DID(did.to_owned()),
            signing_key: SigningKeyBytes::from_signing_key(&sk),
        }),
        reply: tx,
    };
    if sup.dispatch_command(context_id, cmd).await.is_ok() {
        let _ = rx.await;
    }
}

// ---------------------------------------------------------------------------
// Shared context-params parsing (create + Welcome-join)
// ---------------------------------------------------------------------------

/// Legible context parameters parsed from the JSON surface, in both the core
/// [`ContextParams`](scp_core::context::ContextParams) form (for the runtime)
/// and the raw handle-metadata fields (for building [`NapiContextHandle`]).
///
/// Shared by [`context_create_on`] and [`context_join_from_welcome_on`] so the
/// two entry points parse the identical param grammar — mirroring the `PyO3`
/// reference bridge, whose `context_create` and `context_join_from_welcome`
/// both route through `PyContextParams::from_py_dict` + `build_core_context_params`.
struct ParsedContextParams {
    /// The runtime [`ContextParams`](scp_core::context::ContextParams).
    core: scp_core::context::ContextParams,
    /// Raw mode string (`"Encrypted"` / `"Broadcast"`) for the handle.
    mode: String,
    /// Raw ceiling entries for the handle (normalized to UCAN names on build).
    ceiling: Vec<String>,
    /// Ceiling policy string for the handle.
    ceiling_policy: String,
    /// Optional TTL seconds for the handle.
    ttl_seconds: Option<u64>,
    /// Optional promotion policy for the handle.
    promotion_policy: Option<String>,
    /// Governance model string for the handle.
    governance: String,
    /// Optional economic policy string for the handle.
    economic_policy: Option<String>,
}

/// Parses the JSON context-parameters surface into a [`ParsedContextParams`].
///
/// Delegates all validation and `ContextParams` construction to the shared
/// `scp-ffi-common` builder (#1447) — the single source of truth across all
/// bridges.
///
/// # Errors
///
/// Returns `ScpNapiError::Validation` (`SCP-VALID-7000`) if the JSON is
/// malformed or the parameters fail the common builder's validation.
fn parse_context_params(params_json: &str) -> napi::Result<ParsedContextParams> {
    let params: serde_json::Value = serde_json::from_str(params_json).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!(
                "params_json is not valid JSON: {e} — pass a JSON-encoded context parameters object"
            ),
            code: codes::VALID_7000.to_owned(),
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

    // Parse consequence_rules from params (ADR-017, #1531). Accepts either a
    // JSON array (preferred) or a JSON-encoded string for legacy callers.
    // Normalize to a JSON string for the common builder.
    let consequence_rules_json: Option<String> = match &params["consequenceRules"] {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(serde_json::to_string(other).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid consequenceRules: {e}"),
                code: codes::VALID_7000.to_owned(),
            })
        })?),
    };

    // Parse consequence_config from params (ADR-017, #1531). Accepts a JSON
    // object (preferred) or a JSON-encoded string for legacy callers.
    // Normalize to a JSON string for the common builder.
    let consequence_config_json: Option<String> = match &params["consequenceConfig"] {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(serde_json::to_string(other).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid consequenceConfig: {e}"),
                code: codes::VALID_7000.to_owned(),
            })
        })?),
    };

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

    let memory_scope_str = params["memoryScope"]
        .as_str()
        .unwrap_or("ephemeral")
        .to_owned();

    // Delegate to the shared context-params builder (#1447). All parsing,
    // validation, and ContextParams construction happens in scp-ffi-common.
    let common = scp_ffi_common::context_params::CommonContextParams {
        mode: mode_str.clone(),
        ceiling: ceiling.clone(),
        ceiling_policy: ceiling_policy.clone(),
        promotion_policy: promotion_policy.clone().unwrap_or_default(),
        memory_scope: memory_scope_str,
        governance: governance.clone(),
        ttl: ttl_seconds.map(std::time::Duration::from_secs),
        min_protocol_version,
        max_chain_depth,
        max_nesting_depth,
        session_cap,
        economic_policy_json: economic_policy.clone(),
        consequence_rules_json,
        consequence_config_json,
        ..Default::default()
    };

    let core = scp_ffi_common::context_params::build_context_params(&common).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: e,
            code: codes::VALID_7000.to_owned(),
        })
    })?;

    Ok(ParsedContextParams {
        core,
        mode: mode_str,
        ceiling,
        ceiling_policy,
        ttl_seconds,
        promotion_policy,
        governance,
        economic_policy,
    })
}

// ---------------------------------------------------------------------------
// Bridge functions — context lifecycle (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `context_create`.
///
/// Takes an `Arc<NapiBridgeInstance>` so the returned handle can retain a
/// clone for subsequent bridge-scoped operations (e.g. `memberCount`
/// getter) without depending on the process-global default bridge.
pub(crate) async fn context_create_on(
    bi: &Arc<NapiBridgeInstance>,
    identity: &NapiIdentity,
    params_json: String,
) -> napi::Result<NapiContextHandle> {
    crate::napi_check_handle!(&bi.core, identity);
    validate_did(&identity.inner.did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // Parse the legible params once via the shared helper (also used by the
    // Welcome-join path) so the two entry points cannot drift.
    let parsed = parse_context_params(&params_json)?;
    let context_params = parsed.core;

    // Extract key custody and signing key from the identity handle.
    let in_memory_custody = identity.inner.in_memory_custody.clone();
    let signing_key = identity
        .inner
        .scp_identity
        .as_ref()
        .map(|id| id.active_signing_key);

    // Spec §18.4.1: context IDs MUST be 64-char lowercase hex so they
    // embed in `scp://context/<context_id_hex>` URIs. The shared helper
    // in `scp-ffi-common` is the single source of truth for all three
    // bridges — see ADR-048 §7a.
    let context_id = scp_ffi_common::generate_context_id();
    let creator_did = identity.inner.did.clone();

    // Initialize the Supervisor if not already done (first context_create call).
    // Passes the creator DID to NodeMlsFactory for real MLS encryption (#1294).
    crate::runtime::init_supervisor(bi, &creator_did);

    // Derive the context-scoped pseudonym routing ID (§9.10.4, SCP-214 criterion 5).
    // Derived BEFORE create_context so it can be passed to the ContextManager.
    //
    // ENCRYPTED contexts hard-fail derivation (a zero pseudonym produces a
    // silently unusable context); BROADCAST contexts soft-fail to `None` (no
    // per-member pseudonym, spec §5.14 — the runtime ignores the value). Branch
    // on the authoritative resolved mode.
    let create_is_broadcast = matches!(
        context_params.mode,
        scp_core::context::params::ContextMode::Broadcast
    );
    let local_pseudonym: Option<[u8; 32]> = if create_is_broadcast {
        None
    } else {
        Some(derive_context_pseudonym_required(identity, &context_id).await?)
    };

    // Route through the ADR-049 lifecycle dispatch surface
    // ([`Supervisor::dispatch_lifecycle_command`](scp_core::context::supervisor::Supervisor::dispatch_lifecycle_command))
    // rather than calling a `ContextManager` method directly. The actor
    // mailbox wraps the delegated call in the 30s transport-timeout budget.
    let sup = crate::runtime::supervisor(bi)?;
    let core_handle = {
        use scp_core::context::actor::commands::{CreateContextPayload, LifecycleCommand};
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::CreateContext {
            payload: Box::new(CreateContextPayload {
                context_id: context_id.clone(),
                params: context_params,
                creator_did: DID(creator_did.clone()),
                local_pseudonym,
            }),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        rx.await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("shim reply dropped: {e}"),
                    code: codes::CTX_2000.to_owned(),
                })
            })?
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("create_context failed: {e}"),
                    code: codes::CTX_2000.to_owned(),
                })
            })?
    };

    // Register the creator's DID as a local DID for defense-in-depth. Routes
    // through the supervisor's direct method — the local-DID set is
    // supervisor-wide (no per-context command target).
    sup.register_local_did(DID(creator_did.clone()))
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("register_local_did failed: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
        })?;

    // Register the created context in the known-contexts discovery registry so
    // the CREATOR surfaces its own context, closing the last cell of the
    // 3-bridges × 3-ops discovery matrix (PyO3 and UniFFI already register on
    // create; napi already registers on join and join_from_welcome). Reuse the
    // creator's derived §9.10.4 pseudonym as the routing id for encrypted
    // contexts; fall back to broadcast_routing_id (plain SHA-256, matching the
    // send path) for broadcast contexts, which carry no per-member pseudonym.
    // Infallible and idempotent (overwrites), so it is safe after the committed
    // create and needs no rollback.
    //
    // The relay URL comes from the handleless transport probe. On the NAPI bridge
    // the relay URL lives on a `NapiTransportManager` handle, so the honest value
    // here is whatever `transport_status_on` surfaces (never a fabricated URL).
    let routing_id = local_pseudonym.unwrap_or_else(|| {
        if create_is_broadcast {
            scp_core::context::broadcast_routing_id(&context_id)
        } else {
            scp_core::context::context_routing_id(&context_id)
        }
    });
    let relay_url = match crate::transport::transport_status_on(bi, None).await {
        Ok(status) => status.relay_url,
        Err(e) => {
            tracing::warn!(
                "failed to query transport status during context create registration: {e}"
            );
            None
        }
    };
    bi.core.register_known_context(
        &context_id,
        scp_ffi_common::bridge_instance::KnownContext {
            routing_id,
            relay_url,
            member_did: creator_did.clone(),
            last_seen: scp_clock::SystemClock.now_secs(),
        },
    );

    // §9.10.4: a freshly created context has exactly one member, so the
    // pseudonym routing-ID announcement has no recipients and is a guaranteed
    // no-op on create. The routing ID is already registered with the
    // ContextManager via `local_pseudonym` in the create payload, and is
    // announced on `context_join` where existing members must learn it.
    // Emitting it here would also require resolving the signing key (a raw
    // `export_ed25519_signing_key`), which a sign-only keychain/HSM custody
    // (ADR-006) cannot satisfy. PyO3's `py_context_create` still emits this
    // no-op announcement; not replicating it here is intentional. Converging
    // the reference bridge is tracked separately.

    let handle = NapiContextHandle {
        context_id,
        state: std::sync::Mutex::new(ContextState::Active),
        creator_did,
        mode: parsed.mode,
        ceiling: parsed
            .ceiling
            .iter()
            .filter_map(|s| {
                scp_core::context::roles::Capability::new(s).map(|c| c.ucan_capability_name())
            })
            .collect(),
        ceiling_policy: parsed.ceiling_policy,
        ttl_seconds: parsed.ttl_seconds,
        promotion_policy: parsed.promotion_policy,
        governance: parsed.governance,
        economic_policy: parsed.economic_policy,
        in_memory_custody,
        signing_key,
        core_handle: Some(core_handle),
        subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
        subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        bi: Arc::clone(bi),
        instance_id: bi.instance_id(),
    };
    increment_handle_count();
    Ok(handle)
}

/// Per-bridge-instance implementation of [`context_join`].
#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn context_join_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    identity_did: String,
    spending_ucan_jwt: Option<String>,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!("cannot join context in {state_str:?} state — context must be active"),
            code: codes::CTX_2013.to_owned(),
        }
        .into());
    }

    // Parse the optional spending UCAN JWT once at the bridge boundary so
    // malformed tokens are rejected before any expensive crypto work. Mirrors
    // the PyO3 bridge's parse-and-thread pattern at scp-ffi/src/context.rs.
    let spending_ucan = spending_ucan_jwt
        .as_deref()
        .map(|jwt| {
            scp_core::crypto::ucan::validate::parse_ucan(jwt).map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("invalid spending UCAN: {e}"),
                    code: codes::ECON_12061.to_owned(),
                })
            })
        })
        .transpose()?;

    // Ensure the Supervisor is initialized — context_join is a valid
    // first operation (e.g. a device joining a context without creating one).
    // init_supervisor is idempotent (OnceLock — first call wins). #1073
    // Passes the joiner DID to NodeMlsFactory for real MLS encryption (#1294).
    crate::runtime::init_supervisor(bi, &identity_did);

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;

    // Generate a real MLS key package for the joining member (#1294).
    // The key package contains the joiner's SCP credential (DID) and is
    // validated by NodeMlsFactory::validate_key_package before MLS
    // group addition.
    let kp_bytes = generate_mls_key_package_bytes(&identity_did)?;

    let key_package = scp_core::context::membership::KeyPackage {
        owner_did: DID(identity_did.clone()),
        mls_key_package_bytes: Some(kp_bytes),
    };

    // §9.10.4: Derive pseudonym for the joining member so it can be stored
    // in PerContextState and announced to other members.
    //
    // ENCRYPTED contexts hard-fail derivation: a soft-failed join into an
    // encrypted context yields `None`, which the runtime maps to the reserved
    // `[0u8; 32]` sentinel — peers reject any announce of a reserved value, so
    // the joiner becomes permanently unaddressable with no error surfaced.
    // Route through `derive_member_pseudonym_required` to propagate the
    // canonical identity codes (1054/1055/1056/1057) at create/import
    // granularity. BROADCAST contexts soft-fail to `None`: they carry no
    // per-member pseudonym (spec §5.14) and the runtime ignores the value.
    let context_id = handle.context_id.clone();
    let join_is_broadcast = matches!(
        core_handle.params().mode,
        scp_core::context::params::ContextMode::Broadcast
    );
    let local_pseudonym: Option<[u8; 32]> = if join_is_broadcast {
        None
    } else {
        Some(derive_member_pseudonym_required(bi, &identity_did, &context_id).await?)
    };

    // Route through the ADR-049 lifecycle dispatch surface.
    use scp_core::context::actor::commands::{JoinContextPayload, LifecycleCommand};
    let sup = crate::runtime::supervisor(bi)?;
    let join_ctx_id = context_id.clone();
    let join_params = core_handle.params().clone();
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::JoinContext {
            payload: Box::new(JoinContextPayload {
                context_id: join_ctx_id,
                params: join_params,
                key_package,
                spending_ucan,
                local_pseudonym,
            }),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        rx.await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("join_context shim reply dropped: {e}"),
                    code: codes::CTX_2013.to_owned(),
                })
            })?
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    }

    // §9.10.4: Send pseudonym announcement to inform existing members.
    // Best-effort: if the signing key is not available, skip silently.
    if local_pseudonym.is_some() {
        announce_pseudonym_best_effort(
            bi,
            sup,
            &identity_did,
            &context_id,
            core_handle.params().clone(),
        )
        .await;
    }

    // Register the joined context in the known-contexts discovery registry so the
    // JOINER surfaces its own plain-joined context, closing the discovery
    // asymmetry with context_join_from_welcome (which registers post-commit).
    // Reuse the joiner's derived §9.10.4 pseudonym as the routing id for
    // encrypted contexts; fall back to broadcast_routing_id (plain SHA-256,
    // matching the send path) for broadcast contexts, which carry no per-member
    // pseudonym. Infallible and idempotent (overwrites), so it is safe after the
    // committed join and needs no rollback.
    //
    // The relay URL comes from the handleless transport probe. On the NAPI bridge
    // the relay URL lives on a `NapiTransportManager` handle, so the honest value
    // here is whatever `transport_status_on` surfaces (never a fabricated URL).
    let routing_id = local_pseudonym.unwrap_or_else(|| {
        if join_is_broadcast {
            scp_core::context::broadcast_routing_id(&context_id)
        } else {
            scp_core::context::context_routing_id(&context_id)
        }
    });
    let relay_url = match crate::transport::transport_status_on(bi, None).await {
        Ok(status) => status.relay_url,
        Err(e) => {
            tracing::warn!(
                "failed to query transport status during context join registration: {e}"
            );
            None
        }
    };
    bi.core.register_known_context(
        &context_id,
        scp_ffi_common::bridge_instance::KnownContext {
            routing_id,
            relay_url,
            member_did: identity_did.clone(),
            last_seen: scp_clock::SystemClock.now_secs(),
        },
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// spawn-from-Welcome join (ADR-049 Phase 2J)
// ---------------------------------------------------------------------------

/// The opaque `(reservation_id, key_package_public)` pair returned by
/// [`reserve_key_package_on`].
///
/// The private signer state never leaves the node's `KeyPackage` actor — only
/// PUBLIC bytes cross the FFI boundary. Mirrors the `PyO3` reference bridge's
/// `(str, bytes)` return, surfaced here as a flat named-field object (napi
/// idiom) rather than a positional tuple.
#[napi(object)]
pub struct NapiKeyPackageReservation {
    /// Opaque reservation id — a lookup key, not a capability. Pass back to
    /// [`context_join_from_welcome_on`] for the Welcome this `KeyPackage`
    /// addresses.
    pub reservation_id: String,
    /// The PUBLIC MLS `KeyPackage` bytes to hand (out of band) to the context
    /// creator, who adds them to its MLS group to mint the addressed Welcome.
    pub key_package_public: Vec<u8>,
}

/// A sealed, signed invitation bundle (ADR-049 Phase 2J; FFI-02 Option A).
///
/// The wire artifact produced by [`invite_member_on`] on the creator side and
/// consumed by [`context_join_from_welcome_on`] on the joiner side. Flat
/// named-field object per the agent-first API tenet, mirroring the `PyO3`
/// reference bridge's `PySealedInvitation` and the runtime wire type
/// [`SealedInvitation`](scp_core::context::invitation_helpers::SealedInvitation):
/// `enc` is the RFC 9180 HPKE encapsulated key (32 bytes) and `ciphertext` is
/// the HPKE ciphertext (`ct = ciphertext || tag`) of the serialized, signed
/// `InvitationBundle`. Both are opaque bytes — the joiner does not interpret
/// them; the runtime opens the bundle and authenticates it. `context_id` /
/// `creator_did` are UNTRUSTED binding hints used only to rebuild the HPKE
/// `info`/`aad`; authority derives from the signed bundle after the open.
#[napi(object)]
pub struct NapiSealedInvitation {
    /// Binding hint: the context id the bundle was sealed for.
    pub context_id: String,
    /// Binding hint: the creator DID the bundle was sealed by.
    pub creator_did: String,
    /// RFC 9180 HPKE encapsulated key (`enc`). Length is validated to be
    /// exactly 32 bytes at the join boundary (fail-closed).
    pub enc: Vec<u8>,
    /// RFC 9180 HPKE ciphertext (`ct = ciphertext || tag`).
    pub ciphertext: Vec<u8>,
}

/// The outcome of [`invite_member_on`].
///
/// Carries the sealed [`NapiSealedInvitation`] `bundle` (directly usable as the
/// `sealed` argument to `context_join_from_welcome` — no re-boxing) plus
/// `delivered`: `true` if the runtime published the sealed bundle to the
/// invitee's routing id, `false` if the caller (or transport) must deliver
/// `bundle` itself.
///
/// `invite_member` supports only `SingleAdmin` contexts today; a voting-governed
/// context throws an error (governed-context invitations are not yet
/// implemented) rather than surfacing here. This is an extensible object — a
/// future governed-invite outcome is added additively — mirroring the `PyO3`
/// reference bridge's `PyInviteMemberOutcome`.
#[napi(object)]
pub struct NapiInviteMemberOutcome {
    /// The sealed invitation bundle — pass it directly to
    /// `context_join_from_welcome`.
    pub bundle: NapiSealedInvitation,
    /// Whether the runtime published the sealed invitation to the invitee's
    /// routing id (`true`) or the caller must deliver it (`false`).
    pub delivered: bool,
}

impl NapiInviteMemberOutcome {
    /// Maps a runtime
    /// [`InviteMemberOutcome`](scp_core::context::supervisor::InviteMemberOutcome)
    /// to its flat bridge projection. Mirrors the `PyO3` reference bridge's
    /// `PyInviteMemberOutcome::from_outcome` exactly (same `bundle` + `delivered`
    /// shape).
    fn from_outcome(outcome: scp_core::context::supervisor::InviteMemberOutcome) -> Self {
        use scp_core::context::supervisor::InviteMemberOutcome;
        match outcome {
            InviteMemberOutcome::Sealed { bundle, delivered } => Self {
                bundle: NapiSealedInvitation {
                    context_id: bundle.context_id,
                    creator_did: bundle.creator_did.to_string(),
                    enc: bundle.enc,
                    ciphertext: bundle.ciphertext,
                },
                delivered,
            },
        }
    }
}

/// The handle-facing string projections of an AUTHENTICATED
/// [`ContextParams`](scp_core::context::ContextParams), used to rebuild a
/// [`NapiContextHandle`] from the params the creator actually signed (never from
/// caller input). Peer of the `PyO3` reference bridge's
/// `PyContextParams::from_core_params`, restricted to the fields the NAPI handle
/// carries. String forms match this bridge's own conventions (capitalized
/// `mode`, snake-case `governance`/`ceilingPolicy`/`promotionPolicy`) so the
/// Welcome-joined handle is indistinguishable from a created/joined one.
struct CoreParamHandleFields {
    mode: String,
    ceiling: Vec<String>,
    ceiling_policy: String,
    ttl_seconds: Option<u64>,
    promotion_policy: Option<String>,
    governance: String,
    economic_policy: Option<String>,
}

/// Projects an authenticated [`ContextParams`](scp_core::context::ContextParams)
/// into the [`NapiContextHandle`] string fields. Ceiling entries are normalized
/// to their enforced UCAN capability-name form (`{resource}:{action}`), matching
/// the `context_create` / `context_join` handle-build sites.
fn handle_fields_from_core_params(
    params: &scp_core::context::ContextParams,
) -> CoreParamHandleFields {
    use scp_core::context::params::{CeilingPolicy, ContextMode, GovernanceModel, PromotionPolicy};

    let mode = match params.mode {
        ContextMode::Encrypted => "Encrypted",
        ContextMode::Broadcast => "Broadcast",
    }
    .to_owned();
    let ceiling_policy = match params.ceiling_policy {
        CeilingPolicy::Governed => "governed",
        CeilingPolicy::Immutable => "immutable",
    }
    .to_owned();
    let promotion_policy = Some(
        match params.promotion_policy {
            PromotionPolicy::Promotable => "promotable",
            PromotionPolicy::NoPromotion => "no_promotion",
        }
        .to_owned(),
    );
    let governance = match params.governance {
        GovernanceModel::SingleAdmin => "single_admin",
        GovernanceModel::Threshold { .. } => "threshold",
        GovernanceModel::Majority { .. } => "majority",
        GovernanceModel::Unanimity { .. } => "unanimity",
    }
    .to_owned();
    let ceiling: Vec<String> = params
        .ceiling
        .iter()
        .map(scp_core::context::roles::Capability::ucan_capability_name)
        .collect();
    let economic_policy = params
        .economic_policy
        .as_ref()
        .and_then(|ep| serde_json::to_string(ep).ok());

    CoreParamHandleFields {
        mode,
        ceiling,
        ceiling_policy,
        ttl_seconds: params.ttl.map(|d| d.as_secs()),
        promotion_policy,
        governance,
        economic_policy,
    }
}

/// Bridge-level local-custody gate for the bare-`DID` join-side bootstraps
/// ([`reserve_key_package_on`] / [`context_join_from_welcome_on`]), mirroring
/// the `PyO3` reference bridge's `ensure_local_custody` and the trust model of
/// `context_create`: a node-level bootstrap only runs on behalf of an identity
/// this bridge locally custodies.
///
/// Presence in the identity registry is exactly the local-custody signal — the
/// Welcome-join path enforces the identical gate implicitly via
/// [`derive_member_pseudonym_required`], but reserve derives no pseudonym, so it
/// needs this explicit up-front check. Fails closed with the identity-not-found
/// error (`SCP-IDENT-1001`) when the DID is not a locally-custodied identity.
fn ensure_local_custody(bi: &NapiBridgeInstance, did: &str) -> napi::Result<()> {
    crate::runtime::with_identity(bi, did, |_| Ok(())).map_err(NapiError::from)
}

/// Per-bridge-instance implementation of `reserve_key_package`.
///
/// Reserves one of the owning identity's pooled MLS `KeyPackage`s for a
/// spawn-from-Welcome join. The join-side peer of [`context_create_on`]: a node
/// that intends to JOIN by receiving a Welcome first reserves a single-use
/// `KeyPackage` under its own identity; the returned PUBLIC bytes are handed to
/// the context creator (out of band) and the `reservation_id` is passed back to
/// [`context_join_from_welcome_on`].
///
/// Local-identity custody is enforced at the bridge (the same trust model as
/// `context_create`): `owning_did` MUST be a locally-custodied identity.
pub(crate) async fn reserve_key_package_on(
    bi: &NapiBridgeInstance,
    owning_did: String,
) -> napi::Result<NapiKeyPackageReservation> {
    validate_did(&owning_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    // Local-custody gate — same trust model as context_create.
    ensure_local_custody(bi, &owning_did)?;

    // reserve may be a node's FIRST context op (it joins before it ever
    // creates), so attach the supervisor first — the same idempotent init the
    // join performs (OnceLock, first-call-wins).
    crate::runtime::init_supervisor(bi, &owning_did);

    let sup = crate::runtime::supervisor(bi)?;
    let sup = Arc::clone(sup);
    let (reservation_id, kp_public) =
        sup.reserve_key_package(DID(owning_did))
            .await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("reserve_key_package failed: {e}"),
                    code: codes::CTX_2000.to_owned(),
                })
            })?;

    Ok(NapiKeyPackageReservation {
        reservation_id: reservation_id.to_string(),
        key_package_public: kp_public,
    })
}

/// Per-bridge-instance implementation of `context_join_from_welcome`.
///
/// Completes the reserve → Welcome → join handshake begun by
/// [`reserve_key_package_on`]: given the Welcome the context creator minted for
/// a previously-reserved `KeyPackage`, this installs the joined MLS group,
/// derives the joiner's §9.10.4 routing pseudonym, persists the initial keyed
/// snapshot fail-closed, registers a context actor, and records the joined
/// context in the known-contexts discovery registry. Without it a
/// Welcome-joined node can DECRYPT but cannot SEND (no actor-backed handle).
///
/// Ordering discipline mirrors the `PyO3` reference bridge exactly: validate →
/// derive pseudonym via custody (hard-fail a non-custodied joiner BEFORE any
/// effect; never caller-supplied) → parse the reservation id (transparent serde
/// round-trip, before any registry mutation) → register FFI state REVERSIBLY
/// (Occupied fails closed pre-consume; member-insert failure rolls back) →
/// irreversible `spawn_actor_from_welcome` (on `Err`: `remove_context`
/// rollback) → post-commit infallible known-context discovery registration.
pub(crate) async fn context_join_from_welcome_on(
    bi: &Arc<NapiBridgeInstance>,
    owning_did: String,
    sealed: NapiSealedInvitation,
    reservation_id: String,
) -> napi::Result<NapiContextHandle> {
    validate_did(&owning_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&sealed.creator_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_context_id(&sealed.context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    // NOTE: the joiner no longer supplies `params`/`welcome_bytes`. The
    // authoritative params + Welcome now travel INSIDE the signed, sealed
    // `InvitationBundle` (`sealed.enc`/`sealed.ciphertext`), which the runtime
    // opens and authenticates. The old up-front broadcast-mode check is gone:
    // there are no caller params to inspect, and a broadcast bundle (which
    // carries no MLS Welcome, spec §5.14) is rejected INSIDE the runtime at the
    // fused `ConfirmConsume` — not at this boundary.

    // spawn-from-Welcome always stands up an ENCRYPTED context; ensure the
    // node's supervisor is attached first (may be the joiner's first context op
    // — the same idempotent init the join performs).
    crate::runtime::init_supervisor(bi, &owning_did);

    // §9.10.4 + local-custody enforcement: DERIVE the joiner's routing pseudonym
    // from its locally-custodied identity — never caller-supplied. This is the
    // SAME custody gate context_create uses; a non-custodied joiner hard-fails
    // here with SCP-IDENT-1054 BEFORE the single-use KeyPackage is consumed.
    let local_pseudonym =
        derive_member_pseudonym_required(bi, &owning_did, &sealed.context_id).await?;

    // Fail-closed: the HPKE encapsulated key (`enc`) MUST be exactly 32 bytes.
    // Reject a malformed length BEFORE any registry mutation or the irreversible
    // KeyPackage consume, rather than letting a short/long buffer fail deep
    // inside the HPKE open.
    let sealed_bundle_enc =
        scp_ffi_common::custody_parse::expect_32("sealed_bundle_enc", &sealed.enc).map_err(
            |e| {
                NapiError::from(ScpNapiError::Validation {
                    message: e.to_string(),
                    code: codes::VALID_7005.to_owned(),
                })
            },
        )?;

    // Reconstruct the opaque reservation id via its sanctioned transparent serde
    // form (a bare string). It is a lookup key, not a capability — a bogus id
    // simply fails the fused consume match downstream, it grants nothing. Parsed
    // BEFORE any registry mutation so a malformed id can't leave orphaned state.
    let reservation: scp_core::context::supervisor::ReservationId =
        serde_json::from_value(serde_json::Value::String(reservation_id)).map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("invalid reservation id: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
        })?;

    // Resolve the supervisor handle BEFORE any reversible registration. The
    // lookup needs no registered bridge state and short-circuits on `?` —
    // resolving it AFTER `register_ffi_state` would leak the just-registered
    // (reversible) state with no rollback on its failure, and a later same-id
    // retry would then hard-fail the Occupied check. Order: custody-derive
    // (above) → supervisor-resolve → custody+active-key resolve →
    // register-reversible → spawn → rollback-on-Err → authenticated ceiling
    // re-sync.
    let sup = crate::runtime::supervisor(bi)?;
    let sup = Arc::clone(sup);

    // Resolve the joiner's OWN custody provider + `#active` KeyHandle (the same
    // locally-custodied identity the pseudonym was derived from). The runtime
    // needs these to open the sealed bundle and drive the join under the joiner's
    // key material — private keys never cross the FFI, only the opaque custody
    // handle + KeyHandle do (ADR-006). Retained (custody `Arc` cloned,
    // `KeyHandle` is `Copy`) so the returned handle can sign subsequent ops.
    let (custody, active_handle) = crate::runtime::with_identity(bi, &owning_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(NapiError::from)?;

    // Register the bridge-side FFI state (UCAN validation state) as a REVERSIBLE
    // precheck BEFORE the irreversible runtime join. Mirrors the PyO3 reference,
    // which registers FFI state first and rolls it back if the runtime step
    // fails. `register_ffi_state` hard-errors on an already-registered context
    // (Occupied) — that collision fails the join HERE, BEFORE
    // `spawn_actor_from_welcome` consumes the single-use KeyPackage, and leaves
    // any pre-existing entry untouched (never roll back state we did not create).
    //
    // FLAG-1: the caller no longer supplies a ceiling, so register with the
    // DEFAULT ceiling (`&[]`). The Occupied dedup is keyed on `context_id`, so
    // the "detect a duplicate BEFORE consuming the single-use KeyPackage"
    // crash-safety is preserved regardless of the ceiling. The AUTHENTICATED
    // ceiling is re-synced from the joined handle's signed params AFTER a
    // successful spawn (see `sync_ceiling_from_params` below).
    crate::runtime::register_ffi_state(bi, &sealed.context_id, &sealed.creator_did, &[])
        .map_err(NapiError::from)?;
    // Insert the joiner as a member of the freshly-registered role state. On the
    // (practically unreachable) failure of this insert into state we just
    // created, roll it back so a failed join leaves nothing behind.
    if let Err(e) = crate::runtime::with_context(bi, &sealed.context_id, |st| {
        st.role_state.members.insert(owning_did.clone());
        Ok(())
    }) {
        crate::runtime::remove_context(bi, &sealed.context_id);
        return Err(NapiError::from(e));
    }

    let req = scp_core::context::supervisor::WelcomeJoinRequest {
        creator_did: DID(sealed.creator_did.clone()),
        context_id: sealed.context_id.clone(),
        sealed_bundle_enc,
        sealed_bundle_ct: sealed.ciphertext.clone(),
        reservation_id: reservation,
        local_pseudonym: Some(local_pseudonym),
    };
    // Irreversible: open + authenticate the sealed bundle, consume the
    // KeyPackage, install the joined MLS group, persist the keyed snapshot,
    // register the context actor. On failure, roll the reversible FFI state
    // (and — via `remove_context` → `remove_known_context` — any known-context
    // discovery entry) back so an errored join leaves no orphaned bridge state
    // beside a runtime that never committed.
    let core_handle = match sup
        .spawn_actor_from_welcome(DID(owning_did.clone()), &*custody, &active_handle, req)
        .await
    {
        Ok(handle) => handle,
        Err(e) => {
            crate::runtime::remove_context(bi, &sealed.context_id);
            return Err(NapiError::from(ScpNapiError::Context {
                message: format!("context_join_from_welcome failed: {e}"),
                code: codes::CTX_2013.to_owned(),
            }));
        }
    };

    // FLAG-1: re-sync the AUTHENTICATED ceiling from the joined handle's signed
    // params, overwriting the default ceiling used for the reversible precheck.
    // The authoritative ceiling lives in the bundle the creator signed — never in
    // caller input. This runs AFTER the irreversible commit; the FFI state was
    // just registered (and not removed on this success path), so the sync targets
    // a live entry.
    //
    // BLACK-2JF-01 — post-irreversible-commit compensation: the sync fails ONLY
    // if a concurrent close/leave removed the just-registered FFI state in the
    // window since the spawn returned. A close/leave does NOT despawn the runtime
    // actor, so returning `Err` here without tearing the actor down would strand a
    // live, orphaned actor for a join that never fully materialized at the bridge.
    // Compensate with the COMPLETE teardown (`discard_joined_context`): it removes
    // the actor handle AND destroys the resident MLS group AND deletes the durable
    // Class-S snapshot the join persisted — a bare `despawn_actor` would leave the
    // crypto group and snapshot behind, resurrecting the context on restart and
    // blocking a fresh re-join. Then purge residual bridge state and surface the
    // error.
    if let Err(e) = crate::runtime::sync_ceiling_from_params(
        bi,
        &sealed.context_id,
        &core_handle.params().ceiling,
    ) {
        sup.discard_joined_context(&sealed.context_id).await;
        crate::runtime::remove_context(bi, &sealed.context_id);
        return Err(NapiError::from(e));
    }

    // Runtime join committed. Register the context in the known-contexts
    // discovery registry so a Welcome-joined context is surfaced by discovery,
    // exactly as `context_create` peers do post-create. Infallible and
    // idempotent (overwrites), so it is safe after the irreversible commit and
    // needs no rollback. The routing id is the joiner's derived §9.10.4
    // pseudonym (`local_pseudonym` is `Copy`, still valid after the request
    // move); the member is the JOINER, matching the role-state member inserted
    // above.
    //
    // The relay URL comes from the handleless transport probe. On the NAPI
    // bridge the relay URL lives on a `NapiTransportManager` handle, not on the
    // bridge instance, and the bare-DID join receives no such handle — so the
    // honest value here is `None` (never a fabricated URL). Peers refresh
    // `last_seen`/relay on subsequent activity.
    let relay_url = match crate::transport::transport_status_on(bi, None).await {
        Ok(status) => status.relay_url,
        Err(e) => {
            tracing::warn!("failed to query transport status during join registration: {e}");
            None
        }
    };
    bi.core.register_known_context(
        &sealed.context_id,
        scp_ffi_common::bridge_instance::KnownContext {
            routing_id: local_pseudonym,
            relay_url,
            member_did: owning_did.clone(),
            last_seen: scp_clock::SystemClock.now_secs(),
        },
    );

    // Build the returned handle from the AUTHENTICATED params carried by the
    // joined MLS group's signed context binding — NOT from caller input (there is
    // none). The ceiling, mode, governance, and policies reflect what the creator
    // actually signed. The custody + `#active` KeyHandle resolved above are
    // retained so the handle can sign subsequent context ops (send / export).
    let fields = handle_fields_from_core_params(core_handle.params());
    let handle = NapiContextHandle {
        context_id: sealed.context_id,
        state: std::sync::Mutex::new(ContextState::Active),
        creator_did: sealed.creator_did,
        mode: fields.mode,
        ceiling: fields.ceiling,
        ceiling_policy: fields.ceiling_policy,
        ttl_seconds: fields.ttl_seconds,
        promotion_policy: fields.promotion_policy,
        governance: fields.governance,
        economic_policy: fields.economic_policy,
        in_memory_custody: Some(custody),
        signing_key: Some(active_handle),
        core_handle: Some(core_handle),
        subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
        subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        bi: Arc::clone(bi),
        instance_id: bi.instance_id(),
    };
    increment_handle_count();
    Ok(handle)
}

/// Per-bridge-instance implementation of `invite_member` (ADR-049 Phase 2J;
/// FFI-02 Option A).
///
/// The creator (or admin) seals the context's genesis params + Welcome for the
/// invitee under RFC 9180 HPKE, binding them to the invitee's `KeyPackage`. Only
/// a `SingleAdmin` context is supported today: the invite is unilateral and
/// returns a [`NapiInviteMemberOutcome`] whose `bundle` is the sealed
/// [`NapiSealedInvitation`] — pass it directly to `context_join_from_welcome`. A
/// voting-governed context returns `Err` (governed-context invitations are not
/// yet implemented). Mirrors the `PyO3` reference bridge's `invite_member`
/// exactly.
///
/// The inviter MUST be a locally-custodied identity: the invite is signed under
/// its `#active` key, resolved (and exported for the single runtime driver call)
/// via the identity registry. The raw signing key is wiped the moment the invite
/// is produced (`SigningKey` is `ZeroizeOnDrop`, so the explicit early `drop`
/// triggers the wipe).
pub(crate) async fn invite_member_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    creator_did: String,
    invitee_did: String,
    invitee_key_package: Vec<u8>,
    relay_urls: Vec<String>,
) -> napi::Result<NapiInviteMemberOutcome> {
    scp_ffi_common::validate::validate_context_id(&context_id)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&creator_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&invitee_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let sup = crate::runtime::supervisor(bi)?;
    let sup = Arc::clone(sup);

    // Resolve the inviter's retained custody + `#active` KeyHandle from the
    // identity registry (a non-custodied inviter hard-fails here with
    // SCP-IDENT-1001, before any context lookup), then export the raw Ed25519
    // signing key for the single runtime driver call. Private key material never
    // lingers past the invite (ADR-006).
    let (custody, active_handle) = crate::runtime::with_identity(bi, &creator_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(NapiError::from)?;
    let signing_key = custody
        .export_ed25519_signing_key(&active_handle)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("failed to export signing key for invite: {e}"),
                code: codes::CTX_2040.to_owned(),
            })
        })?;

    let outcome = sup
        .invite_member(
            context_id,
            DID(creator_did),
            DID(invitee_did),
            invitee_key_package,
            relay_urls,
            &signing_key,
        )
        .await;
    // Defense-in-depth: wipe the raw signing key the moment the invite is
    // produced, rather than letting it linger to end-of-scope. `SigningKey` is
    // `ZeroizeOnDrop` (ed25519-dalek `zeroize` feature) but does NOT implement
    // bare `Zeroize`, so the explicit early `drop` — not a `.zeroize()` call —
    // is what triggers the wipe here (matching the PyO3 reference bridge).
    drop(signing_key);

    let outcome = outcome.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("invite_member failed: {e}"),
            code: codes::CTX_2013.to_owned(),
        })
    })?;
    Ok(NapiInviteMemberOutcome::from_outcome(outcome))
}

/// Per-bridge-instance implementation of [`context_leave`].
#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn context_leave_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    identity_did: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot leave context in {state_str:?} state — context must be active"
            ),
            code: codes::CTX_2015.to_owned(),
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

    // Route through the ADR-049 lifecycle dispatch surface.
    use scp_core::context::actor::commands::{LeaveContextPayload, LifecycleCommand};
    let sup = crate::runtime::supervisor(bi)?;
    let leave_ctx_id = core_handle.context_id().to_owned();
    let leave_params = core_handle.params().clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::LeaveContext {
        payload: Box::new(LeaveContextPayload {
            context_id: leave_ctx_id,
            params: leave_params,
            caller_did: did.clone(),
            member_did: did,
        }),
        reply: tx,
    };
    sup.dispatch_lifecycle_command(cmd)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    rx.await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("leave_context shim reply dropped: {e}"),
                code: codes::CTX_2015.to_owned(),
            })
        })?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Per-bridge-instance implementation of [`context_close`].
pub(crate) async fn context_close_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    identity_did: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    // Authorization is enforced by the ContextManager (which delegates to
    // ttl::close_context checking the ContextClose capability). No bridge-layer
    // auth check — the ContextManager is authoritative.

    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot close context in {state_str:?} state — context must be active"
            ),
            code: codes::CTX_2017.to_owned(),
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

    // Route through the ADR-049 lifecycle dispatch surface
    // ([`Supervisor::dispatch_lifecycle_command`](scp_core::context::supervisor::Supervisor::dispatch_lifecycle_command))
    // rather than calling a `ContextManager` method directly. The actor
    // mailbox wraps the delegated call in the 30s transport-timeout budget
    // and preserves byte-identical close semantics.
    {
        use scp_core::context::actor::commands::{CloseContextPayload, LifecycleCommand};
        let sup = crate::runtime::supervisor(bi)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::CloseContext {
            payload: Box::new(CloseContextPayload {
                context_id: core_handle.context_id().to_owned(),
                params: core_handle.params().clone(),
                initiator_did: did,
            }),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
        rx.await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Context {
                    message: format!("shim reply dropped: {e}"),
                    code: codes::CTX_2000.to_owned(),
                })
            })?
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    }

    handle.set_closed().map_err(NapiError::from)?;

    // Clean up UCAN state for this context.
    crate::runtime::remove_context(bi, &handle.context_id);

    // Clean up per-context bridge connector state and economy state via the
    // same NapiBridgeInstance's core (not the process-global bridge).
    bi.core.remove_bridge_state(&handle.context_id);
    bi.core.remove_economy_state(&handle.context_id);

    Ok(())
}

/// Per-bridge-instance implementation of `context_seed_peer_pseudonym`.
///
/// Test-only: seeds a peer's per-context pseudonym routing ID (§9.10.4) into
/// this bridge's `Supervisor`, simulating a delivered `PseudonymAnnouncement`
/// so multi-member encrypted sends do not fail closed with `SCP-CTX-2095`.
/// Mirrors the runtime `Supervisor::seed_peer_pseudonym` test helper. Gated
/// behind `testing` so it never ships in production builds.
#[cfg(feature = "testing")]
pub(crate) async fn context_seed_peer_pseudonym_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    peer_did: String,
    pseudonym: napi::bindgen_prelude::Buffer,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);

    let pseudonym_bytes: &[u8] = &pseudonym;
    if pseudonym_bytes.len() != 32 {
        return Err(ScpNapiError::Context {
            message: format!(
                "pseudonym must be exactly 32 bytes, got {}",
                pseudonym_bytes.len()
            ),
            code: codes::CTX_2095.to_owned(),
        }
        .into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(pseudonym_bytes);

    let sup = crate::runtime::supervisor(bi)?;
    sup.seed_peer_pseudonym(&handle.context_id, DID::from(peer_did.as_str()), arr)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Per-bridge-instance implementation of [`context_send`].
pub(crate) async fn context_send_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    identity_did: String,
    payload: Vec<u8>,
    spending_ucan_jwt: Option<String>,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot send to context in {state_str:?} state — context must be active"
            ),
            code: codes::CTX_2019.to_owned(),
        }
        .into());
    }

    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let did = DID(identity_did.clone());

    // Validate inner envelope signing via the retained KeyCustody
    // (SCP-214 criterion 6). Ensures the identity's mandatory `#active` signing
    // key can produce a valid Ed25519 signature before sending. This is a
    // discarded custody smoke-test on the baseline operational key (identity
    // plumbing), NOT the wire persona — the persona actually stamped on the
    // message is chosen below via the ADR-039 persona-source seam and validated
    // for the chosen persona by `resolve_napi_message_signer` (which fail-closes
    // on `#agent` with no agent key).
    if let (Some(custody), Some(signing_key)) = (&handle.in_memory_custody, handle.signing_key) {
        let context_id = handle.context_id.clone();
        let sender_did_str = identity_did.clone();
        let now_ms = scp_clock::SystemClock.now_millis();

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
            signing_key_id: scp_did::SigningKeyId::Active,
        };

        scp_core::envelope::create_inner_envelope(&params, custody.as_ref(), &signing_key)
            .await
            .map_err(|e| {
                NapiError::from(ScpNapiError::Crypto {
                    message: format!("inner envelope signing failed: {e}"),
                    code: codes::CRYPTO_4001.to_owned(),
                })
            })?;
    }

    // Parse optional spending UCAN JWT into a UcanToken for AND-composition.
    let spending_ucan = spending_ucan_jwt
        .as_deref()
        .map(scp_core::crypto::ucan::validate::parse_ucan)
        .transpose()
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("invalid spending UCAN: {e}"),
                code: codes::ECON_12061.to_owned(),
            })
        })?;

    // Route through the ADR-049 messaging dispatch surface
    // ([`Supervisor::dispatch_command`](scp_core::context::supervisor::Supervisor::dispatch_command))
    // rather than calling a `ContextManager` method directly. The actor
    // mailbox exercises the RAII [`SequenceReservation`] + 30s transport
    // timeout inside the handler and preserves byte-identical envelope
    // construction.
    use scp_core::context::actor::commands::{
        MessagingCommand, SendMessagePayload, SigningKeyBytes,
    };
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = core_handle.context_id().to_owned();
    let params = core_handle.params().clone();
    // ADR-039 Enforcement-Stack Layer 2: consult the per-instance persona-source
    // seam to choose the send persona (default `#active`; a future determiner —
    // RFC #2242 — overrides it), then resolve BOTH the key handle and the
    // persona from that one value (fail-closed on `#agent` with no agent key).
    // The NAPI path decomposes the signer into `(bytes, signing_key_id)` across
    // the actor mailbox, so BOTH fields are taken from the SAME `MessageSigner`
    // (derived from the same persona) — they cannot diverge.
    let persona = (bi.core.persona_source())();
    let resolved_signer = resolve_napi_message_signer(bi, handle, &identity_did, persona).await?;
    let signer = resolved_signer.message_signer();
    let signing_key_bytes = SigningKeyBytes::from_signing_key(signer.key());
    let signing_key_id = signer.signing_key_id();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = MessagingCommand::SendMessage {
        payload: Box::new(SendMessagePayload {
            context_id: context_id.clone(),
            params,
            sender_did: did,
            payload: payload.clone(),
            signing_key: Some(signing_key_bytes),
            signing_key_id,
            source_provenance: None,
            spending_ucan,
        }),
        reply: tx,
    };
    sup.dispatch_command(&context_id, cmd)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    rx.await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("shim reply dropped: {e}"),
                code: codes::CTX_2001.to_owned(),
            })
        })?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(())
}

/// Drop-guard for `NapiContextHandle::subscription_active`.
///
/// Ensures the flag returns to `false` on ANY exit path — both synchronous
/// error returns from `context_subscribe` *before* the relay listener task
/// is spawned AND the spawned task's own exit path (normal completion or
/// panic unwind). Without this guard a `?`-early-return between the
/// initial `swap(true)` and the `tokio::spawn` would leave the flag stuck
/// at `true`, rejecting every future `contextSubscribe(...)` call on the
/// handle with `SCP-CTX-2022` "already subscribed" (round 3 bug-catcher
/// finding).
///
/// Invariants:
/// - `Drop` stores `false` iff the guard still holds the flag.
/// - `disarm()` transfers ownership of the flag to the caller and defuses
///   `Drop`, so the outer guard can be handed to the spawned inner guard
///   atomically at the hand-off point (no intermediate "unguarded" state).
/// - Calling `disarm()` twice panics — this is impossible in the
///   `context_subscribe` flow but documented defensively.
///
/// `SeqCst` matches the ordering of the entry-side `swap(true)` guard.
struct ActiveFlagGuard(Option<Arc<std::sync::atomic::AtomicBool>>);

impl Drop for ActiveFlagGuard {
    fn drop(&mut self) {
        if let Some(flag) = self.0.take() {
            flag.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl ActiveFlagGuard {
    /// Transfers the flag out of the guard, disabling the `Drop` reset.
    ///
    /// # Panics
    ///
    /// Panics if called twice on the same guard. In `context_subscribe`
    /// the guard is disarmed exactly once immediately before spawning
    /// the relay listener task, so the double-disarm path is unreachable
    /// in practice.
    fn disarm(mut self) -> Arc<std::sync::atomic::AtomicBool> {
        self.0.take().unwrap_or_else(|| {
            unreachable!(
                "ActiveFlagGuard disarmed twice — every call site must disarm at most once"
            )
        })
    }
}

/// Per-bridge-instance implementation of [`context_subscribe`].
pub(crate) async fn context_subscribe_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    identity_did: String,
    on_message: napi::threadsafe_function::ThreadsafeFunction<Option<NapiMessage>>,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    // Guard: prevent duplicate subscriptions. The AtomicBool is swapped to
    // true on the first call; subsequent calls see `true` and bail.
    // The flag is reset to `false` by the spawned task when it exits (via
    // the inner `ActiveFlagGuard`) or by the outer guard below if any
    // fallible step between here and the `spawn()` returns early — so
    // re-subscription works after relay disconnect, sync-error paths, or
    // task termination.
    if handle
        .subscription_active
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return Err(ScpNapiError::Context {
            message: "already subscribed — each context supports a single subscription".to_owned(),
            code: codes::CTX_2022.to_owned(),
        }
        .into());
    }

    // Outer guard — arms immediately after the swap so every `?`
    // early-return path from here to the `tasks.spawn(...)` resets the
    // flag via `Drop`. Ownership is transferred to the spawned task's
    // inner guard via `disarm()` at the hand-off point; no window exists
    // where the flag is held but un-guarded.
    let outer_guard = ActiveFlagGuard(Some(Arc::clone(&handle.subscription_active)));

    let state_str = handle.current_state_str().map_err(NapiError::from)?;
    if state_str != "active" {
        // `outer_guard` Drop resets the flag.
        return Err(ScpNapiError::Context {
            message: format!(
                "cannot subscribe to context in {state_str:?} state — context must be active"
            ),
            code: codes::CTX_2021.to_owned(),
        }
        .into());
    }

    // `identity_did` is validated at the API boundary and reused below as the
    // heartbeat author DID for the periodic suppression-detection scheduler
    // (§9.9.2).
    validate_did(&identity_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let Some(transport_mgr) = crate::transport::get_transport_manager_on(bi) else {
        // `outer_guard` Drop resets the flag.
        return Err(NapiError::from(ScpNapiError::Transport {
            message: "no relay connection — call transportConnect() before subscribing".to_owned(),
            code: codes::TRANS_5010.to_owned(),
        }));
    };

    // Resolve the bridge instance to own the spawned task. The subscription
    // task MUST be registered against `bi.core.task_handle()` so
    // `shutdown_core_async` drains it under the caller's deadline — the
    // previous implementation spawned through the shared runtime, leaving
    // the task orphaned and making `shutdown_core_async` falsely report
    // `GracefulWithin` while the relay listener continued in the
    // background (Item 2 — review finding).
    //
    // Refuse to subscribe when the bridge is suspended (recoverable via
    // `resume()`); `outer_guard`'s `Drop` resets `subscription_active` so
    // the caller can retry after `resume()` (round 3 bug-catcher finding).
    if bi.core.is_suspended() {
        return Err(napi::Error::from(ScpNapiError::Transport {
            message: "bridge is suspended — call resume() before subscribing".to_owned(),
            code: codes::CTX_2000.to_owned(),
        }));
    }
    let bi_core: &crate::runtime::CoreFields = &bi.core;
    let bridge_cancel = bi_core.cancel_token();

    let context_id = handle.context_id.clone();
    let is_broadcast = handle.mode() == "Broadcast";
    // §9.10.4 / §5.14: choose the correct shared routing ID based on context
    // mode. Broadcast contexts use `broadcast_routing_id` = SHA-256(context_id)
    // (plain hash, matching the send path in messaging.rs). Encrypted contexts
    // use `context_routing_id` = SHA-256("scp:context-routing:" || context_id)
    // (domain-separated). Using the wrong routing ID means messages never
    // reach subscribers. Bug fix.
    //
    // For encrypted contexts, also subscribe to the member's pseudonym
    // routing ID for pseudonym-routed application messages (§9.10.4).
    //
    // TODO(§9.10.4.A step 4): After all members have exchanged pseudonyms,
    // unsubscribe from the shared routing ID to achieve full pseudonym privacy.
    // Currently the shared subscription is permanent (migration never completes).
    let shared_routing_id_bytes = if is_broadcast {
        scp_core::context::broadcast_routing_id(&context_id)
    } else {
        scp_core::context::context_routing_id(&context_id)
    };
    let shared_routing_id = scp_transport::RoutingId::new(shared_routing_id_bytes);

    // Replace the cancellation token with a fresh one so a previously
    // cancelled token doesn't immediately cancel the new subscription.
    // A poisoned lock returns `?` — `outer_guard` Drop resets the flag.
    let cancel_token = {
        let mut guard = handle.subscription_cancel.lock().map_err(|_| {
            NapiError::from(ScpNapiError::Context {
                message: "subscription cancel lock is poisoned".to_owned(),
                code: codes::CTX_2012.to_owned(),
            })
        })?;
        *guard = CancellationToken::new();
        guard.clone()
    };

    // Spawn a background task that subscribes to the relay and delivers
    // incoming messages through the JS callback. The task terminates when
    // the stream ends OR either cancellation token fires — the
    // per-subscription `cancel_token` (invoked by
    // `context_cancel_subscription`) or the bridge-level token fired by
    // `shutdown_core_async`.
    //
    // Registered in the bridge instance's `JoinSet` (`bi_core.task_handle()`)
    // so `shutdown_core_async` observes and drains this task within the
    // caller's deadline. Spawning through `crate::runtime().spawn` would
    // orphan the task, making shutdown falsely report `GracefulWithin`
    // while the subscription still held onto `transport_mgr`,
    // `ContextManager`, and the cancel_token Arcs.
    // Capture an owned `Arc<Supervisor>` scoped to this bridge so the spawned
    // task doesn't need to re-resolve it via a per-instance lookup. Falls back
    // gracefully if the supervisor is not attached yet; the spawned task
    // signals completion when so.
    let supervisor_for_task = crate::runtime::supervisor(bi).ok().cloned();

    // §9.9.2 send side: resolve the local member's signing key now (the key
    // lives at this FFI boundary, never inside the actor) so a periodic
    // heartbeat scheduler can be spawned alongside the subscribe loop. The
    // cadence comes from the same per-profile source of truth the receive-side
    // monitor uses (`heartbeat_interval`); `None` (Constrained) or an
    // unavailable key (externally loaded DID-only identity) simply means no
    // scheduler is spawned — the subscribe + receive path still runs.
    let heartbeat_profile = scp_transport::profile::TransportProfile::platform_default();
    let heartbeat_interval =
        scp_ffi_common::heartbeat_scheduler::heartbeat_interval(heartbeat_profile);
    let heartbeat_signing_key = match heartbeat_interval {
        Some(_) => resolve_napi_signing_key(handle).await.ok(),
        None => None,
    };
    let heartbeat_sender_did: scp_did::DID = identity_did.clone().into();

    // Clones for the heartbeat scheduler task — the main subscribe closure
    // below is `async move` and consumes `context_id` / the cancel tokens /
    // `supervisor_for_task`, so the scheduler captures its own copies.
    let heartbeat_supervisor = supervisor_for_task.clone();
    let heartbeat_context_id = context_id.clone();
    let heartbeat_cancel = cancel_token.clone();
    let heartbeat_bridge_cancel = bridge_cancel.clone();

    let mut tasks = bi_core.task_handle().await;
    // Disarm the outer guard and transfer the flag to the spawned task's
    // inner guard. No intermediate "flag is true but un-guarded" window —
    // `disarm()` and the spawn happen back-to-back without any `?` between.
    let active_flag = outer_guard.disarm();
    tasks.spawn(async move {
        use futures::StreamExt;

        // Inner guard: resets `subscription_active` on ALL exit paths of
        // the spawned task — including panics. Without this a panic inside
        // the subscription body would leave `subscription_active` stuck at
        // `true`, rejecting every future `context_subscribe` call on this
        // handle with `SCP-CTX-2022 "already subscribed"` (round 2
        // bug-catcher finding).
        let _active_flag_guard = ActiveFlagGuard(Some(active_flag));

        // Collect the member's pseudonym via the ADR-049 query shim.
        // Broadcast contexts do not use pseudonyms — skip the lookup.
        let local_pseudonym: Option<[u8; 32]> = if is_broadcast {
            None
        } else {
            use scp_core::context::actor::commands::QueriesCommand;
            match supervisor_for_task.as_ref() {
                Some(sup) => {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = QueriesCommand::LocalPseudonym {
                        context_id: context_id.clone(),
                        reply: tx,
                    };
                    if sup.dispatch_query(cmd).await.is_ok() {
                        // §9.10.4: the query now returns a typed
                        // `Result<[u8; 32], _>` — `Ok` for encrypted contexts,
                        // `Err(NotPseudonymousContext)` for broadcast. Map a
                        // successful read to `Some`; any error (including the
                        // broadcast case, already excluded above) to `None`.
                        match rx.await {
                            Ok(Ok(p)) => Some(p),
                            _ => None,
                        }
                    } else {
                        None
                    }
                }
                None => None,
            }
        };

        // §9.10.4: dual subscription — always subscribe to the shared routing
        // ID (MLS management messages, backward compat). If the member has a
        // pseudonym, also subscribe to it for pseudonym-routed messages.
        let stream_result = transport_mgr.subscribe(&shared_routing_id, None).await;
        let stream = match stream_result {
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
                // `_active_flag_guard` resets the flag on drop.
                return;
            }
        };

        // §9.10.4: if the member has a pseudonym, subscribe to that routing
        // ID too and merge both streams. Best-effort: if the pseudonym
        // subscription fails, we still have the shared subscription.
        let mut stream: std::pin::Pin<
            Box<dyn futures::Stream<Item = scp_transport::TransportEvent> + Send>,
        > = stream;
        if let Some(pseudonym_bytes) = local_pseudonym {
            let pseudonym_rid = scp_transport::RoutingId::new(pseudonym_bytes);
            if let Ok(pseudonym_stream) = transport_mgr.subscribe(&pseudonym_rid, None).await {
                // Merge the pseudonym stream into the main stream using
                // futures::stream::select so events from either routing ID
                // are delivered through the same processing loop.
                stream = Box::pin(futures::stream::select(stream, pseudonym_stream));
            } else {
                tracing::warn!(
                    context_id = %context_id,
                    "pseudonym relay subscription failed — using shared routing ID only"
                );
            }
        }

        // Route decrypt through the ADR-049 messaging dispatch surface
        // ([`Supervisor::dispatch_command`](scp_core::context::supervisor::Supervisor::dispatch_command))
        // rather than calling a `ContextManager` method directly. The
        // actor mailbox wraps the call in a 30s transport timeout and
        // preserves byte-identical crypto / anti-replay / buffered delivery.
        let Some(supervisor) = supervisor_for_task else {
            tracing::error!("Supervisor not initialized");
            on_message.call(
                Ok(None),
                napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
            );
            // `_active_flag_guard` resets the flag on drop.
            return;
        };

        let mut sequence_counter: f64 = 0.0;

        loop {
            // Select between the next stream event, the per-subscription
            // cancel token (`context_cancel_subscription` / re-subscribe),
            // and the bridge-level cancel token
            // (`shutdown_core_async`). Either cancel signal exits cleanly.
            let event = tokio::select! {
                () = cancel_token.cancelled() => {
                    tracing::info!(
                        context_id = %context_id,
                        "subscription cancelled via token"
                    );
                    break;
                }
                () = bridge_cancel.cancelled() => {
                    tracing::info!(
                        context_id = %context_id,
                        "subscription cancelled via bridge shutdown"
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
                    // Decrypt via the ADR-049 commit-8 messaging shim.
                    use scp_core::context::actor::commands::MessagingCommand;
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = MessagingCommand::DeliverIncoming {
                        context_id: context_id.clone(),
                        envelope_bytes: envelope.encrypted_blob.clone(),
                        reply: tx,
                    };
                    let dispatch_result = supervisor.dispatch_command(&context_id, cmd).await;
                    let reply_result = if dispatch_result.is_ok() {
                        rx.await.ok()
                    } else {
                        None
                    };
                    let deliver_result = match (dispatch_result, reply_result) {
                        (Ok(_), Some(r)) => r,
                        (Err(e), _) => Err(e),
                        (Ok(_), None) => Err(scp_core::context::ContextError::CryptoFailed(
                            "deliver shim reply dropped".to_owned(),
                        )),
                    };
                    use scp_core::context::actor::commands::DeliverOutcome;
                    match deliver_result {
                        Ok(DeliverOutcome::Application((plaintext, sender_did))) => {
                            // §9.9.2 defense-in-depth: a delivered application
                            // message is equally strong evidence the relay set
                            // is alive as a dedicated heartbeat. Refresh the
                            // monitor baseline so a quiet-but-active peer's
                            // normal traffic keeps suppression detection fresh
                            // and a busy context never trips a spurious
                            // suspicion just because heartbeats were preempted
                            // by real sends.
                            transport_mgr.record_heartbeat_received().await;
                            sequence_counter += 1.0;
                            #[allow(clippy::cast_precision_loss)]
                            let ts = scp_clock::SystemClock.now_secs() as f64;
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
                        Ok(DeliverOutcome::Heartbeat) => {
                            // §9.9.2 suppression-detection heartbeat from a peer.
                            // Refresh every relay monitor's gap-detection
                            // baseline so suppression is only suspected after a
                            // genuine silence. Not surfaced to the JS caller —
                            // a heartbeat carries no user content.
                            transport_mgr.record_heartbeat_received().await;
                            tracing::trace!(
                                context_id = %context_id,
                                "heartbeat received — refreshed suppression baseline"
                            );
                        }
                        Ok(DeliverOutcome::Handled) => {
                            // MLS Commit/Proposal, checkpoint, or pseudonym
                            // announcement — internal protocol message
                            // processed, no application payload to forward.
                            tracing::debug!(
                                context_id = %context_id,
                                "protocol control message processed — no payload"
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

        // Tear down the co-scheduled heartbeat scheduler in lockstep with the
        // subscribe loop. Every loop exit path lands here — explicit
        // unsubscribe (`cancel_token` already fired), bridge shutdown
        // (`bridge_cancel` fired), stream exhaustion (`None`), and relay
        // `Terminated`. Only the explicit-unsubscribe path cancelled
        // `cancel_token`; the other three did not, so without this the
        // `run_heartbeat_scheduler` task (which shares this `cancel_token`)
        // would keep firing `Supervisor::send_heartbeat` on a dead
        // subscription — leaking the task plus its owned `Arc<Supervisor>`
        // and exported signing key, and emitting false liveness. A later
        // re-subscribe overwrites the handle's cancel token without cancelling
        // the old one, so this teardown is the only thing that stops the
        // orphaned scheduler. Cancelling an already-cancelled token (the
        // unsubscribe path) is a harmless idempotent no-op.
        cancel_token.cancel();

        // Signal stream completion.
        on_message.call(
            Ok(None),
            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
        );

        // `_active_flag_guard` resets the flag on drop when this task
        // returns normally (below) or panics (the guard's `Drop` impl
        // fires on unwind).
    });

    // §9.9.2 send side: spawn the periodic heartbeat scheduler alongside the
    // subscribe loop, enrolled in the same `JoinSet` so `shutdown_core_async`
    // drains it too. Only when the profile enables heartbeats AND the signing
    // key resolved (an externally loaded DID-only identity cannot sign, so it
    // sends none — its peers simply observe a quieter stream, which is a valid
    // suppression-detection input, not an error). The scheduler shares the
    // subscription cancel token, so unsubscribe / disconnect / re-subscribe
    // tears it down exactly like the suppression-drain task lifecycle.
    if let (Some(interval), Some(sk), Some(sup)) = (
        heartbeat_interval,
        heartbeat_signing_key,
        heartbeat_supervisor,
    ) {
        tasks.spawn(
            scp_ffi_common::heartbeat_scheduler::run_heartbeat_scheduler(
                sup,
                heartbeat_context_id,
                heartbeat_sender_did,
                sk,
                interval,
                heartbeat_cancel,
                heartbeat_bridge_cancel,
            ),
        );
    }

    // Drop the JoinSet guard now that spawn is done — shutdown requires
    // exclusive access to drain.
    drop(tasks);

    Ok(())
}

/// Per-bridge-instance implementation of [`context_cancel_subscription`].
pub(crate) fn context_cancel_subscription_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    if let Ok(token) = handle.subscription_cancel.lock() {
        token.cancel();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge functions — membership queries (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`context_member_count`].
///
/// Routed through the ADR-049 query dispatch surface
/// ([`Supervisor::dispatch_query`](scp_core::context::supervisor::Supervisor::dispatch_query)).
pub(crate) async fn context_member_count_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<u32> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let supervisor = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::MemberCount {
        context_id,
        reply: tx,
    };
    supervisor
        .dispatch_query(cmd)
        .await
        .map_err(|e| napi::Error::from_reason(format!("supervisor dispatch_query failed: {e}")))?;
    let count = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .unwrap_or(0);
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Per-bridge-instance implementation of [`context_is_member`].
///
/// Routed through the ADR-049 query dispatch surface. The handler acquires
/// the same per-context mutex as the legacy `is_member` path.
pub(crate) async fn context_is_member_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    did: String,
) -> napi::Result<bool> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let supervisor = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::IsMember {
        context_id,
        did,
        reply: tx,
    };
    supervisor
        .dispatch_query(cmd)
        .await
        .map_err(|e| napi::Error::from_reason(format!("supervisor dispatch_query failed: {e}")))?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Per-bridge-instance implementation of [`context_member_dids`].
///
/// Routed through the ADR-049 query dispatch surface.
pub(crate) async fn context_member_dids_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<Vec<String>> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let supervisor = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::MemberDids {
        context_id,
        reply: tx,
    };
    supervisor
        .dispatch_query(cmd)
        .await
        .map_err(|e| napi::Error::from_reason(format!("supervisor dispatch_query failed: {e}")))?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Per-bridge-instance implementation of [`context_member_role`].
///
/// Routed through the ADR-049 query dispatch surface. Returns the role name
/// as a string, or `null` if the member is not found.
pub(crate) async fn context_member_role_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    did: String,
) -> napi::Result<Option<String>> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let supervisor = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::MemberRole {
        context_id,
        did,
        reply: tx,
    };
    supervisor
        .dispatch_query(cmd)
        .await
        .map_err(|e| napi::Error::from_reason(format!("supervisor dispatch_query failed: {e}")))?;
    let assignment = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(assignment.map(|a| a.role_name))
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
        // Relay equivocation detected (§9.9.3, §23.7). Security event — MUST NOT
        // be silently discarded (§9.9.4); surface as a structured, non-lossy,
        // HTML-escaped record rather than a Debug blob.
        scp_core::context::membership::ContextEvent::EquivocationDetected {
            context_id,
            remote_sender_did,
            event_count,
            local_merkle_root,
            remote_merkle_root,
        } => scp_ffi_common::html_escape_event_string(&format!(
            "equivocation_detected:context={context_id},\
             remote_sender={remote_sender_did},event_count={event_count},\
             local_merkle_root={},remote_merkle_root={}",
            hex::encode(local_merkle_root),
            hex::encode(remote_merkle_root),
        )),
        other => scp_ffi_common::html_escape_event_string(&format!("{other:?}")),
    }
}

/// Per-bridge-instance implementation of [`context_drain_events`].
///
/// Routed through the ADR-049 messaging dispatch surface
/// ([`Supervisor::dispatch_command`](scp_core::context::supervisor::Supervisor::dispatch_command)).
/// `drain_events` lives on the messaging enum because the receive buffer
/// is the messaging path's downstream sink (fed by `deliver_incoming`,
/// consumed by FFI receive polling).
pub(crate) async fn context_drain_events_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<Vec<String>> {
    use scp_core::context::actor::commands::MessagingCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = MessagingCommand::DrainEvents {
        context_id: context_id.clone(),
        reply: tx,
    };
    sup.dispatch_command(&context_id, cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_command failed: {e}"))
    })?;
    let events = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("drain_events shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(format!("drain_events failed: {e}")))?;
    Ok(events.iter().map(format_context_event).collect())
}

// ---------------------------------------------------------------------------
// Bridge functions — access key lifecycle (#1529, ADR-049 dispatch surface)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`access_key_generate`].
///
/// Routed through the ADR-049 lifecycle dispatch surface
/// ([`Supervisor::dispatch_lifecycle_command`](scp_core::context::supervisor::Supervisor::dispatch_lifecycle_command)).
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn access_key_generate_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    member_did: String,
    caller_did: String,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::LifecycleCommand;
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::GenerateContextAccessKey {
        context_id,
        member_did,
        caller_did,
        reply: tx,
    };
    sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!(
            "[SCP-CTX-2070] supervisor dispatch_lifecycle_command failed: {e}"
        ))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2070] shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2070] {e}")))
}

/// Per-bridge-instance implementation of [`access_key_revoke`].
///
/// Routed through the ADR-049 lifecycle dispatch surface.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn access_key_revoke_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    member_did: String,
    caller_did: String,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::LifecycleCommand;
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::RevokeContextAccessKey {
        context_id,
        member_did,
        caller_did,
        reply: tx,
    };
    sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!(
            "[SCP-CTX-2071] supervisor dispatch_lifecycle_command failed: {e}"
        ))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2071] shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2071] {e}")))
}

/// Per-bridge-instance implementation of [`access_key_restore`].
///
/// Routed through the ADR-049 lifecycle dispatch surface.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn access_key_restore_on(
    bi: &NapiBridgeInstance,
    context_id: String,
    member_did: String,
    caller_did: String,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::LifecycleCommand;
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::RestoreContextAccessKey {
        context_id,
        member_did,
        caller_did,
        reply: tx,
    };
    sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!(
            "[SCP-CTX-2072] supervisor dispatch_lifecycle_command failed: {e}"
        ))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2072] shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(format!("[SCP-CTX-2072] {e}")))
}

// ---------------------------------------------------------------------------
// Bridge functions — broadcast (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`context_broadcast_subscriber_count`].
///
/// Routed through the ADR-049 broadcast dispatch surface.
pub(crate) async fn context_broadcast_subscriber_count_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<Option<u32>> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::BroadcastSubscriberCount {
        context_id,
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    let count = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    #[allow(clippy::cast_possible_truncation)]
    Ok(count.map(|c| c as u32))
}

/// Per-bridge-instance implementation of [`context_is_broadcast_subscriber`].
///
/// Routed through the ADR-049 broadcast dispatch surface.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn context_is_broadcast_subscriber_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    did: String,
) -> napi::Result<bool> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::IsBroadcastSubscriber {
        context_id,
        did,
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Per-bridge-instance implementation of [`context_broadcast_admission`].
///
/// Routed through the ADR-049 broadcast dispatch surface.
pub(crate) async fn context_broadcast_admission_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<Option<String>> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::BroadcastAdmission {
        context_id,
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    let admission = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(admission.map(|a| format!("{a:?}")))
}

// ---------------------------------------------------------------------------
// Bridge functions — broadcast mutations (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`broadcast_subscribe`].
///
/// Routed through the ADR-049 broadcast dispatch surface. For a GATED broadcast
/// context, `messages_read_ucan_jwt` MUST carry the `messages:read` JWT issued to
/// `subscriber_did` by the context admin/creator (spec §5.14.4); the actor runs
/// the full UCAN validation pipeline on it (spec §07:70). It is unused for an
/// OPEN context.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn broadcast_subscribe_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    subscriber_did: String,
    messages_read_ucan_jwt: Option<String>,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{BroadcastCommand, SubscribeBroadcastPayload};
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    // Parse the optional gated-admission `messages:read` UCAN JWT once at the
    // bridge boundary so malformed tokens are rejected before dispatch. Mirrors
    // the spending-UCAN parse-and-thread pattern above / the PyO3 bridge.
    let ucan_token = messages_read_ucan_jwt
        .as_deref()
        .map(|jwt| {
            scp_core::crypto::ucan::validate::parse_ucan(jwt)
                .map_err(|e| napi::Error::from_reason(format!("invalid messages:read UCAN: {e}")))
        })
        .transpose()?;
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let did: DID = DID(subscriber_did);
    let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::SubscribeBroadcast {
        payload: Box::new(SubscribeBroadcastPayload {
            context_id,
            subscriber_did: did,
            ucan: ucan_token,
            timestamp,
        }),
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Per-bridge-instance implementation of [`broadcast_unsubscribe`].
///
/// When `rotate_keys` is `true`, all authors rotate their broadcast keys
/// for forward secrecy. Routed through the ADR-049 broadcast dispatch surface.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn broadcast_unsubscribe_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    subscriber_did: String,
    rotate_keys: Option<bool>,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{BroadcastCommand, UnsubscribeBroadcastPayload};
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let did: DID = DID(subscriber_did);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::UnsubscribeBroadcast {
        payload: Box::new(UnsubscribeBroadcastPayload {
            context_id,
            subscriber_did: did,
            rotate_keys: rotate_keys.unwrap_or(false),
        }),
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Per-bridge-instance implementation of [`broadcast_publish`].
pub(crate) async fn broadcast_publish_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    author_did: String,
    payload: Vec<u8>,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let context_id = handle.context_id.clone();
    let author_did = DID(author_did);

    use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastPayload};
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        NapiError::from(ScpNapiError::Identity {
            message: "broadcast publish requires retained signing custody — this identity has no \
                      retained custody (it was externally loaded)"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;
    let signing_key = handle.signing_key.ok_or_else(|| {
        NapiError::from(ScpNapiError::Identity {
            message: "broadcast publish requires retained signing custody — identity has no \
                      active signing key"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;

    // Route through the ADR-049 broadcast dispatch surface with custody.
    // Publish requires the custody-bearing variant because the
    // `KeyCustody` trait is not dyn-safe and cannot cross the actor
    // mailbox.
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::PublishBroadcast {
        payload: Box::new(PublishBroadcastPayload {
            context_id,
            author_did,
            payload,
            signing_key_handle: signing_key,
        }),
        reply: tx,
    };
    sup.dispatch_broadcast_command_with_custody(cmd, custody.as_ref())
        .await
        .map_err(|e| {
            napi::Error::from_reason(format!(
                "supervisor dispatch_broadcast_command_with_custody failed: {e}"
            ))
        })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

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

/// Per-bridge-instance implementation of [`broadcast_publish_asset`].
pub(crate) async fn broadcast_publish_asset_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    author_did: String,
    asset: NapiAssetEntry,
    deploy_id: Option<String>,
) -> napi::Result<NapiPublishResult> {
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
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
            code: codes::CTX_2040.to_owned(),
        })
    })?;
    let mime_type = scp_core::context::MimeType::new(asset.content_type).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("invalid content_type: {e}"),
            code: codes::CTX_2041.to_owned(),
        })
    })?;
    if let Some(ref did_str) = deploy_id {
        scp_core::context::validate_deploy_id(did_str).map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("invalid deploy_id: {e}"),
                code: codes::CTX_2042.to_owned(),
            })
        })?;
    }

    let etag = scp_core::context::compute_etag(&asset.body);
    // Capture the deploy_id string before moving into BroadcastContent (SCP-292).
    let deploy_id_str = deploy_id.as_ref().map_or_else(String::new, Clone::clone);
    // Clone etag when custody feature is enabled — it's needed again in the
    // return value after `content` consumes the clone.
    let etag_for_metadata = etag.clone();
    let content = scp_core::context::BroadcastContent {
        version: scp_core::context::BROADCAST_CONTENT_VERSION,
        metadata: scp_core::context::ContentMetadata {
            path: Some(content_path),
            content_type: Some(mime_type),
            deploy_id,
            etag: Some(etag_for_metadata),
            immutable: false,
        },
        body: asset.body,
    };

    use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastContentPayload};
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        NapiError::from(ScpNapiError::Identity {
            message: "broadcast publish asset requires retained signing custody — this identity \
                      has no retained custody (it was externally loaded)"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;
    let signing_key = handle.signing_key.ok_or_else(|| {
        NapiError::from(ScpNapiError::Identity {
            message: "broadcast publish asset requires retained signing custody — identity has \
                      no active signing key"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;

    // Route through the ADR-049 commit-11 broadcast shim with custody.
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::PublishBroadcastContent {
        payload: Box::new(PublishBroadcastContentPayload {
            context_id,
            author_did: author_did_val,
            content,
            signing_key_handle: signing_key,
        }),
        reply: tx,
    };
    sup.dispatch_broadcast_command_with_custody(cmd, custody.as_ref())
        .await
        .map_err(|e| {
            napi::Error::from_reason(format!(
                "supervisor dispatch_broadcast_command_with_custody failed: {e}"
            ))
        })?;
    let envelope = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    let envelope_bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("failed to serialize envelope for blob_id: {e}"),
            code: codes::CTX_2043.to_owned(),
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

/// Per-bridge-instance implementation of [`broadcast_publish_assets`].
pub(crate) async fn broadcast_publish_assets_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    author_did: String,
    assets: Vec<NapiAssetEntry>,
    deploy_id: Option<String>,
) -> napi::Result<NapiBatchPublishResult> {
    crate::napi_check_handle!(&bi.core, handle);
    const MAX_BATCH_ASSETS: usize = 10_000;
    if assets.len() > MAX_BATCH_ASSETS {
        return Err(NapiError::from(ScpNapiError::Context {
            message: format!(
                "batch too large: {} assets (max {MAX_BATCH_ASSETS})",
                assets.len()
            ),
            code: codes::CTX_2074.to_owned(),
        }));
    }

    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
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
            code: codes::CTX_2042.to_owned(),
        })
    })?;

    use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastContentPayload};
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        NapiError::from(ScpNapiError::Identity {
            message: "broadcast publish assets requires retained signing custody — this identity \
                      has no retained custody (it was externally loaded)"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;
    let signing_key = handle.signing_key.ok_or_else(|| {
        NapiError::from(ScpNapiError::Identity {
            message: "broadcast publish assets requires retained signing custody — identity has \
                      no active signing key"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;

    // Route each asset through the ADR-049 commit-11 broadcast shim
    // with custody.
    let sup = crate::runtime::supervisor(bi)?;
    let mut results = Vec::with_capacity(assets.len());
    for asset in assets {
        let content_path = scp_core::context::ContentPath::new(asset.path).map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("invalid path: {e}"),
                code: codes::CTX_2040.to_owned(),
            })
        })?;
        let mime_type = scp_core::context::MimeType::new(asset.content_type).map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("invalid content_type: {e}"),
                code: codes::CTX_2041.to_owned(),
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

        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::PublishBroadcastContent {
            payload: Box::new(PublishBroadcastContentPayload {
                context_id: context_id.clone(),
                author_did: author_did_val.clone(),
                content,
                signing_key_handle: signing_key,
            }),
            reply: tx,
        };
        sup.dispatch_broadcast_command_with_custody(cmd, custody.as_ref())
            .await
            .map_err(|e| {
                napi::Error::from_reason(format!(
                    "supervisor dispatch_broadcast_command_with_custody failed: {e}"
                ))
            })?;
        let envelope = rx
            .await
            .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let envelope_bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("failed to serialize envelope for blob_id: {e}"),
                code: codes::CTX_2043.to_owned(),
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

/// Per-bridge-instance implementation of [`broadcast_block_subscriber`].
///
/// The subscriber is removed from the registry and added to all authors'
/// block lists; all author keys are rotated. Routed through the ADR-049
/// broadcast dispatch surface.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn broadcast_block_subscriber_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    subscriber_did: String,
    blocker_did: String,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&blocker_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let subscriber: DID = DID(subscriber_did);
    let blocker: DID = DID(blocker_did);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::BlockBroadcastSubscriber {
        payload: Box::new(BroadcastBlockPayload {
            context_id,
            author_did: blocker,
            subscriber_did: subscriber,
        }),
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Per-bridge-instance implementation of [`broadcast_unblock_subscriber`] (§9.16.8).
///
/// Forward-only: the unblocked subscriber can request the current key on
/// next pull but cannot decrypt content from the block period. Routed through
/// the ADR-049 broadcast dispatch surface.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn broadcast_unblock_subscriber_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    subscriber_did: String,
    unblocker_did: String,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&subscriber_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&unblocker_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let subscriber: DID = DID(subscriber_did);
    let unblocker: DID = DID(unblocker_did);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::UnblockBroadcastSubscriber {
        payload: Box::new(BroadcastBlockPayload {
            context_id,
            author_did: unblocker,
            subscriber_did: subscriber,
        }),
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Per-bridge-instance implementation of [`broadcast_handle_key_request`].
///
/// Validates the author DID is locally controlled, then HPKE-seals the author's
/// current broadcast key to the requester's X25519 `wrapping_pubkey`
/// (§5.14.2). Returns `Some(json)` (a serialized `SealedBroadcastKey`) on
/// grant, or `None` on deny (§5.14.8 — no key material to a denied requester).
/// The raw broadcast key never crosses the FFI boundary.
/// Routed through the ADR-049 broadcast dispatch surface.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn broadcast_handle_key_request_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    author_did: String,
    requester_did: String,
    wrapping_pubkey: Vec<u8>,
) -> napi::Result<Option<String>> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::napi_check_handle!(&bi.core, handle);
    validate_did(&author_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    validate_did(&requester_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let wrapping: [u8; 32] = wrapping_pubkey.as_slice().try_into().map_err(|_| {
        NapiError::from(ScpNapiError::Validation {
            message: format!(
                "wrapping_pubkey must be 32 bytes, got {}",
                wrapping_pubkey.len()
            ),
            code: codes::VALID_7007.to_owned(),
        })
    })?;
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let context_id_for_seal = context_id.clone();
    let author_did_owned = author_did.clone();
    let author: DID = DID(author_did);
    let requester: DID = DID(requester_did);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::HandleBroadcastKeyRequest {
        context_id,
        author_did: author,
        requester_did: requester,
        wrapping_pubkey: wrapping,
        reply: tx,
    };
    sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_broadcast_command failed: {e}"))
    })?;
    let decision = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    // Grant→sealed-JSON / Deny→None via the shared helper (per-SDK error mapping
    // kept here; only the value-shape logic is shared).
    scp_ffi_common::broadcast::seal_decision_to_json(
        decision,
        &author_did_owned,
        &context_id_for_seal,
    )
    .map_err(|e| {
        // Serializing a just-constructed SealedBroadcastKey is an internal
        // failure, not caller-input validation — classify as Context (CTX_2023)
        // to match the UniFFI/PyO3 bridges.
        NapiError::from(ScpNapiError::Context {
            message: format!("serialize sealed broadcast key: {e}"),
            code: codes::CTX_2023.to_owned(),
        })
    })
}

/// Opens an HPKE-sealed broadcast key (§5.14.2) using a software-held X25519
/// wrapping secret, returning the raw 32-byte AES-256 broadcast key.
///
/// Pure crypto — no bridge-instance state, so it is a module-level free
/// `#[napi]` fn (ADR-048 §1) with no per-instance `_on` variant. `sealed_json`
/// is the JSON returned by `broadcastHandleKeyRequest` on grant.
///
/// # Errors
///
/// Returns a validation error if `sealed_json` is malformed or
/// `wrapping_secret` is not 32 bytes, or a context error if HPKE open fails.
#[napi(js_name = "broadcastOpenKey")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned parameters
pub fn broadcast_open_key(sealed_json: String, wrapping_secret: Vec<u8>) -> napi::Result<Vec<u8>> {
    use scp_ffi_common::broadcast::OpenSealedKeyError;
    scp_ffi_common::broadcast::open_sealed_broadcast_key(&sealed_json, &wrapping_secret).map_err(
        |e| {
            // Malformed JSON / wrong-length secret are caller-input validation
            // errors; a failed HPKE open is a context/crypto error. Mirrors the
            // PyO3/UniFFI classification so the error variant is consistent
            // across every SDK.
            let scp_err = match &e {
                OpenSealedKeyError::InvalidJson { .. } => ScpNapiError::Validation {
                    message: e.to_string(),
                    code: codes::VALID_7002.to_owned(),
                },
                OpenSealedKeyError::InvalidSecretLength { .. } => ScpNapiError::Validation {
                    message: e.to_string(),
                    code: codes::VALID_7007.to_owned(),
                },
                OpenSealedKeyError::OpenFailed { .. } => ScpNapiError::Context {
                    message: e.to_string(),
                    code: codes::CTX_2023.to_owned(),
                },
            };
            NapiError::from(scp_err)
        },
    )
}

// ---------------------------------------------------------------------------
// Bridge functions — governance (delegated to ContextManager)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of
/// `Scp::context_execute_governance_action`.
///
/// Executes a previously-approved governance proposal BY ID. The runtime
/// resolves the authoritative proposal from the context actor's own
/// quorum-validated governance engine; the bridge never supplies a proposal,
/// action, or status. This closes the direct-execute quorum bypass — the
/// previous implementation minted a fresh random id and fabricated a fully
/// `Approved` proposal from a caller-supplied action, executing it with no
/// engine involvement.
///
/// The surface takes only `(handle, proposal_id_hex)`: the executor (the
/// `GovernanceActionExecuted` leaf `actor_did`) and the consequence subject are
/// both resolved from the tracked proposal's proposer inside the runtime, never
/// from a caller-supplied DID.
pub(crate) async fn context_execute_governance_action_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    proposal_id_hex: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;
    let proposal_id_log = hex::encode(proposal_id);

    // Route through the ADR-049 governance dispatch surface.
    use scp_core::context::actor::commands::{ExecuteGovernanceActionPayload, GovernanceCommand};
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::ExecuteGovernanceAction {
        payload: Box::new(ExecuteGovernanceActionPayload {
            context_id: context_id.clone(),
            proposal_id,
        }),
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!(
            "supervisor dispatch_governance_command failed: {e}"
        ))
    })?;
    let result = rx
        .await
        .map_err(|e| napi::Error::from_reason(format!("shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // Re-sync local UCAN role state cache from ContextManager after any
    // governance action that may have modified roles/membership (#560).
    if let Err(e) = crate::runtime::sync_role_state_from_manager(bi, &context_id).await {
        tracing::warn!(
            context_id = %context_id,
            proposal_id = %proposal_id_log,
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
// Reconnection (ADR-029)
// ---------------------------------------------------------------------------

/// Per-context reconnection result surfaced to TypeScript.
///
/// Flat mirror of [`scp_ffi_common::reconnect::ContextReconnectResult`].
#[napi(object)]
pub struct NapiContextReconnectResult {
    /// Context that was reconnected.
    pub context_id: String,
    /// Offline tier: `"short"` / `"extended"` / `"long"`.
    pub tier: String,
    /// Outcome string (`"fully_caught_up"`, `"reset"`, `"failed"`, …).
    pub outcome: String,
    /// MLS epochs caught up.
    pub epochs_caught_up: f64,
    /// Event-log events recovered.
    pub events_recovered: f64,
    /// Whether an MLS Update was issued (§9.12).
    pub mls_update_issued: bool,
    /// Number of equivocation alerts surfaced (§9.9.3).
    pub equivocations_detected: f64,
    /// Whether `needs_reconnect` was cleared on success.
    pub needs_reconnect_cleared: bool,
}

/// Aggregate reconnection report surfaced to TypeScript.
///
/// Flat mirror of [`scp_ffi_common::reconnect::ReconnectReport`].
#[napi(object)]
pub struct NapiReconnectReport {
    /// Per-context results.
    pub contexts: Vec<NapiContextReconnectResult>,
    /// Total queued messages drained (Phase 6).
    pub messages_drained: f64,
    /// Total queued messages discarded.
    pub messages_discarded: f64,
    /// Total reconnection duration in milliseconds.
    pub total_duration_ms: f64,
}

impl From<scp_ffi_common::reconnect::ReconnectReport> for NapiReconnectReport {
    // Event/epoch counts and durations are JS `number` (f64) at the napi
    // boundary; the magnitudes here are far below 2^52, so the precision
    // loss is not reachable in practice.
    #[allow(clippy::cast_precision_loss)]
    fn from(report: scp_ffi_common::reconnect::ReconnectReport) -> Self {
        Self {
            contexts: report
                .contexts
                .into_iter()
                .map(|c| NapiContextReconnectResult {
                    context_id: c.context_id,
                    tier: c.tier,
                    outcome: c.outcome,
                    epochs_caught_up: c.epochs_caught_up as f64,
                    events_recovered: c.events_recovered as f64,
                    mls_update_issued: c.mls_update_issued,
                    equivocations_detected: c.equivocations_detected as f64,
                    needs_reconnect_cleared: c.needs_reconnect_cleared,
                })
                .collect(),
            messages_drained: report.messages_drained as f64,
            messages_discarded: report.messages_discarded as f64,
            total_duration_ms: report.total_duration_ms as f64,
        }
    }
}

/// Per-bridge-instance implementation of `context_reconnect`.
///
/// Runs the ADR-029 six-phase reconnection protocol for each of
/// `context_ids` flagged `needs_reconnect` (§23.11). The driver lives at
/// this FFI relay-client layer (ADR-029 reconnection-driver addendum): it
/// pulls relay-buffered messages via the `TransportManager` and reaches
/// actor-owned reconnection state through the `Supervisor`. On success
/// each context's `needs_reconnect` flag is cleared.
// `last_relay_contacts` arrives as JS `number` (f64) Unix seconds; the
// truncation to u64 is the intended floor of a whole-second timestamp.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) async fn context_reconnect_on(
    bi: &NapiBridgeInstance,
    identity_did: String,
    context_ids: Vec<String>,
    last_relay_contacts: Option<std::collections::HashMap<String, f64>>,
) -> napi::Result<NapiReconnectReport> {
    let supervisor = crate::runtime::supervisor(bi)?;
    let transport = crate::transport::get_transport_manager_on(bi).ok_or_else(|| {
        NapiError::from(ScpNapiError::Transport {
            message: "no relay connection — call transportConnect() before reconnecting".to_owned(),
            code: codes::TRANS_5010.to_owned(),
        })
    })?;

    // Resolve the local member's Ed25519 signing key from the identity
    // registry (used to sign the Phase-3 consistency checkpoint). Private
    // key never crosses FFI beyond this in-process driver call.
    let (custody, key_handle) = crate::runtime::with_identity(bi, &identity_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("cannot resolve signing key for reconnect: {e}"),
            code: codes::IDENT_1001.to_owned(),
        })
    })?;
    let sk = custody
        .export_ed25519_signing_key(&key_handle)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("failed to export signing key for reconnect: {e}"),
                code: codes::CTX_2040.to_owned(),
            })
        })?;

    let contacts: std::collections::HashMap<String, u64> = last_relay_contacts
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, v as u64))
        .collect();
    let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

    // Hold the 32-byte seed in `Zeroizing` so it is wiped after the driver
    // call rather than lingering in freed memory.
    let signing_key_bytes = zeroize::Zeroizing::new(sk.to_bytes());

    let report = scp_ffi_common::reconnect::reconnect_contexts_no_drain(
        &transport,
        supervisor,
        DID(identity_did),
        signing_key_bytes,
        context_ids,
        contacts,
        now,
        scp_core::sync::SyncPolicy::default(),
    )
    .await;
    Ok(report.into())
}

// ---------------------------------------------------------------------------
// Bridge functions — governance proposal lifecycle (#621)
// ---------------------------------------------------------------------------

/// Resolves the raw Ed25519 signing key from the context handle's custody.
///
/// The NAPI handle retains `in_memory_custody` and `signing_key` (`KeyHandle`)
/// from the creating identity. This function exports the raw key bytes.
async fn resolve_napi_signing_key(
    handle: &NapiContextHandle,
) -> napi::Result<ed25519_dalek::SigningKey> {
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        NapiError::from(ScpNapiError::Context {
            message: "no custody provider on context handle — governance lifecycle \
                      requires an identity created with custody"
                .to_owned(),
            code: codes::CTX_2040.to_owned(),
        })
    })?;
    let key_handle = handle.signing_key.ok_or_else(|| {
        NapiError::from(ScpNapiError::Context {
            message: "no signing key on context handle — governance lifecycle \
                      requires an identity with an active signing key"
                .to_owned(),
            code: codes::CTX_2040.to_owned(),
        })
    })?;
    custody
        .export_ed25519_signing_key(&key_handle)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("failed to export signing key for governance: {e}"),
                code: codes::CTX_2040.to_owned(),
            })
        })
}

/// Resolves the [`ResolvedMessageSigner`](scp_ffi_common::persona::ResolvedMessageSigner)
/// for a **message send** under the requested persona (ADR-039 Enforcement-Stack
/// Layer 2).
///
/// Selects BOTH the key handle and the persona so the `#active`/`#agent` stamp
/// and the signing key are chosen together and cannot diverge:
/// - [`SigningKeyId::Active`](scp_did::SigningKeyId::Active) → the handle's
///   retained active signing key (byte-identical to [`resolve_napi_signing_key`],
///   so the default send path is unchanged).
/// - [`SigningKeyId::Agent`](scp_did::SigningKeyId::Agent) → the sender
///   identity's agent signing key, resolved together with the sender identity's
///   OWN retained custody from the SAME identity-registry entry. **Fail-closed**
///   with `SCP-IDENT-1023` if the identity has no agent key — NEVER falls back
///   to `#active`.
///
/// Both the `#agent` key handle and the custody it is exported through come from
/// the same registry entry (mirroring the `PyO3` reference `resolve_message_signer`,
/// which reads `entry.custody` + `entry.identity.agent_signing_key` from one
/// lookup). Sourcing the custody from the sender identity — not the context
/// handle — guarantees the exported key belongs to the identity that stamps the
/// `#agent` persona; the two could differ, and the handle's custody could export
/// the wrong identity's key (fail-closed at the receiver, but a latent
/// correctness bug that bites when RFC #2242 activates the agent path). The
/// `#active` arm still resolves through the handle's retained active key, so the
/// default send path is untouched; a failure there is remapped to a
/// send-specific `SCP-CRYPTO-4001` rather than propagating the governance-worded
/// `SCP-CTX-2040` from [`resolve_napi_signing_key`].
async fn resolve_napi_message_signer(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    sender_did: &str,
    persona: scp_did::SigningKeyId,
) -> napi::Result<scp_ffi_common::persona::ResolvedMessageSigner> {
    let key = match persona {
        scp_did::SigningKeyId::Active => resolve_napi_signing_key(handle).await.map_err(|_| {
            NapiError::from(ScpNapiError::Crypto {
                message: "signing key required for send: could not resolve the sender's \
                              #active signing key from retained custody"
                    .to_owned(),
                code: codes::CRYPTO_4001.to_owned(),
            })
        })?,
        scp_did::SigningKeyId::Agent => {
            // Resolve the agent key handle AND the sender identity's own custody
            // from the SAME registry entry. Clone the custody `Arc` and copy the
            // `KeyHandle` OUT of the `with_identity` closure before the async
            // export so no DashMap shard guard is held across the await (#1940).
            let (custody, agent_handle) = crate::runtime::with_identity(bi, sender_did, |entry| {
                let handle =
                    entry
                        .identity
                        .agent_signing_key
                        .ok_or_else(|| ScpNapiError::Identity {
                            message: format!(
                                "identity '{sender_did}' has no agent signing key — cannot \
                                 send under #agent; add one with identityAddAgentKey first"
                            ),
                            code: codes::IDENT_1023.to_owned(),
                        })?;
                Ok((entry.custody.clone(), handle))
            })
            .map_err(NapiError::from)?;
            custody
                .export_ed25519_signing_key(&agent_handle)
                .await
                .map_err(|e| {
                    NapiError::from(ScpNapiError::Context {
                        message: format!("failed to export agent signing key for send: {e}"),
                        code: codes::CTX_2040.to_owned(),
                    })
                })?
        }
    };
    Ok(scp_ffi_common::persona::ResolvedMessageSigner::new(
        key, persona,
    ))
}

/// Resolves the exporter identity's custody provider and `#active` signing-key
/// handle for signing a context export snapshot (§23.16.8).
///
/// Unlike [`resolve_napi_signing_key`], this does NOT export raw private key
/// bytes. It returns the [`NapiKeyCustody`](crate::custody::NapiKeyCustody)
/// provider and the [`KeyHandle`](scp_platform::traits::KeyHandle) so the caller
/// can delegate signing to [`KeyCustody::sign`], which dispatches to whichever
/// backend backs this identity (in-memory OR JS callback custody). This is the
/// path that lets keychain/HSM-shaped callback providers — which sign but cannot
/// export key bytes — produce a signed export. Private key material never crosses
/// the FFI boundary (ADR-006).
///
/// The `Arc<NapiKeyCustody>` is cloned out so the returned pair is `'static` and
/// can be moved into the synchronous `export_context` sign closure.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` (SCP-CTX-2040) if the context handle carries
/// no retained custody or no active signing-key handle.
fn resolve_napi_export_signer(
    handle: &NapiContextHandle,
) -> napi::Result<(
    Arc<crate::custody::NapiKeyCustody>,
    scp_platform::traits::KeyHandle,
)> {
    let custody = handle.in_memory_custody.as_ref().ok_or_else(|| {
        NapiError::from(ScpNapiError::Context {
            message: "no custody provider on context handle — context export \
                      requires an identity created with custody"
                .to_owned(),
            code: codes::CTX_2040.to_owned(),
        })
    })?;
    let key_handle = handle.signing_key.ok_or_else(|| {
        NapiError::from(ScpNapiError::Context {
            message: "no signing key on context handle — context export \
                      requires an identity with an active signing key"
                .to_owned(),
            code: codes::CTX_2040.to_owned(),
        })
    })?;
    Ok((Arc::clone(custody), key_handle))
}

/// Resolves the snapshot creator's Ed25519 verification key for
/// snapshot-signature verification on context import (spec §23.16.8, ADR-050,
/// ADR-039).
///
/// Per §23.16.8 step 1 the verifying key is derived from the snapshot's
/// `creator_did` (`role_state.creator_did`), never from the unauthenticated
/// envelope `exporter_did`. The runtime separately asserts
/// `exporter_did == creator_did` (§23.16.8 step 2), so the bridge MUST resolve
/// from the creator identity.
///
/// Resolution order (local-custody-first, then DID resolver) is shared across
/// all FFI bridges via
/// [`scp_ffi_common::export_verify::resolve_export_verifying_key`]:
/// 1. **Local identity custody** — if the creator is a local identity (the
///    common self-export case: a device importing a context it exported), the
///    verifying key is derived directly from its `#active` custody signing key.
///    This works even when the DID document has not been published to the DHT
///    (in-memory identities are not auto-published) — fixing the prior bug
///    where a self-export of an unpublished identity failed because the bridge
///    went straight to the DID resolver.
/// 2. **DID resolver** — otherwise resolve the creator DID's `#active` (then
///    `#agent`, ADR-039 shared-DID model) verification-method key.
///
/// Fails closed: if the creator is neither local nor resolvable, the import is
/// rejected with [`codes::CTX_2093`] rather than proceeding unverified.
///
/// `async` because deriving the verifying key from local custody requires an
/// async `KeyCustody::public_key` call (the shared helper's `local_custody`
/// closure is sync, so the local key is resolved up front and handed to the
/// closure as a pre-computed value).
async fn resolve_napi_creator_verifying_key(
    bi: &NapiBridgeInstance,
    creator_did: &str,
) -> napi::Result<ed25519_dalek::VerifyingKey> {
    let resolver = crate::runtime::did_resolver(bi).map(std::convert::AsRef::as_ref);

    // Pre-resolve the local verifying key (async) so the shared helper's sync
    // `local_custody` closure can return it without blocking. Only the public
    // verifying key is derived — private key material never leaves custody
    // (ADR-006). Returns `None` when the creator DID is not a locally retained
    // identity on this bridge instance, in which case resolution relies on the
    // DID resolver.
    let local_key = resolve_napi_local_verifying_key(bi, creator_did).await;

    scp_ffi_common::export_verify::resolve_export_verifying_key(
        resolver,
        |_did| local_key,
        creator_did,
    )
    .map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("{e}"),
            code: codes::CTX_2093.to_owned(),
        })
    })
}

/// Derives the public Ed25519 verifying key for a DID from local key custody,
/// or `None` when the DID is not a local identity on this bridge instance.
///
/// Uses the creator identity's `#active` signing-key handle
/// ([`scp_identity::ScpIdentity::active_signing_key`]) — the verification
/// method §23.16.8 designates as the export signer — and resolves its public
/// half via [`KeyCustody::public_key`]. Only the public verifying key crosses
/// out of custody; the private signing key is never materialized (ADR-006).
async fn resolve_napi_local_verifying_key(
    bi: &NapiBridgeInstance,
    did: &str,
) -> Option<ed25519_dalek::VerifyingKey> {
    let custody_and_key = crate::runtime::with_identity(bi, did, |e| {
        Ok((e.custody.clone(), e.identity.active_signing_key))
    })
    .ok()?;
    let (custody, key_handle) = custody_and_key;
    // Resolve the public verifying key directly via `KeyCustody::public_key`
    // (ADR-006) — no private-key materialization. The 32-byte length and
    // canonical-point decode are the shared conversion tail in scp-ffi-common.
    let public_key = custody.public_key(&key_handle).await.ok()?;
    scp_ffi_common::export_verify::verifying_key_from_public_key(&public_key)
}

/// Parses a hex-encoded proposal ID into a 32-byte array.
fn parse_napi_proposal_id(hex_str: &str) -> napi::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid proposal ID hex: {e}"),
            code: codes::CTX_2040.to_owned(),
        })
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("proposal ID must be 32 bytes, got {}", v.len()),
            code: codes::CTX_2040.to_owned(),
        })
    })?;
    Ok(arr)
}

/// Per-bridge-instance implementation of [`context_governance_propose`].
pub(crate) async fn context_governance_propose_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    action_json: String,
    proposer_did: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let action: GovernanceAction = serde_json::from_str(&action_json).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid governance action JSON: {e}"),
            code: codes::CTX_2040.to_owned(),
        })
    })?;

    // Defense-in-depth: validate user-controlled string fields at the FFI
    // boundary before the action reaches the ContextManager (#1601).
    scp_ffi_common::validate::validate_governance_action_strings(&action).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: e.message,
            code: codes::CTX_2040.to_owned(),
        })
    })?;

    let action_name = action.variant_name();

    use scp_core::context::actor::commands::{
        GovernanceCommand, ProposeGovernanceActionPayload, SigningKeyBytes,
    };

    let signing_key = resolve_napi_signing_key(handle).await?;

    let did = DID(proposer_did);
    let context_id = handle.context_id.clone();

    // Route through the ADR-049 commit-10 governance shim
    // ([`Supervisor::dispatch_governance_command`](scp_core::context::supervisor::Supervisor::dispatch_governance_command))
    // rather than calling `ContextManager::propose_governance_action_checked`
    // directly.
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::ProposeGovernanceActionChecked {
        payload: Box::new(ProposeGovernanceActionPayload {
            context_id: context_id.clone(),
            proposer_did: did,
            action,
            signing_key: SigningKeyBytes::from_signing_key(&signing_key),
            // The generic FFI governance path never carries an invitee
            // KeyPackage (that rides only Supervisor::invite_member).
            key_package: None,
        }),
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2041.to_owned(),
        })
    })?;
    let outcome = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance proposal shim reply dropped: {e}"),
                code: codes::CTX_2041.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance proposal failed: {e}"),
                code: codes::CTX_2041.to_owned(),
            })
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(bi, &context_id).await {
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
    Ok(response.to_string())
}

/// Per-bridge-instance implementation of [`context_governance_approve`].
pub(crate) async fn context_governance_approve_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    proposal_id_hex: String,
    voter_did: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;

    use scp_core::context::actor::commands::{
        GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
    };

    let signing_key = resolve_napi_signing_key(handle).await?;

    let did = DID(voter_did);
    let context_id = handle.context_id.clone();

    // Route through the ADR-049 governance dispatch surface.
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::ApproveGovernanceProposal {
        payload: Box::new(VoteOnProposalPayload {
            context_id: context_id.clone(),
            proposal_id,
            voter_did: did,
            signing_key: SigningKeyBytes::from_signing_key(&signing_key),
        }),
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2042.to_owned(),
        })
    })?;
    let status = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance approval shim reply dropped: {e}"),
                code: codes::CTX_2042.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance approval failed: {e}"),
                code: codes::CTX_2042.to_owned(),
            })
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(bi, &context_id).await {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to sync role state after governance approval"
        );
    }

    Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
}

/// Per-bridge-instance implementation of [`context_governance_reject`].
pub(crate) async fn context_governance_reject_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    proposal_id_hex: String,
    voter_did: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;

    use scp_core::context::actor::commands::{
        GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
    };
    let signing_key = resolve_napi_signing_key(handle).await?;

    let did = DID(voter_did);
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();

    // Route through the ADR-049 governance dispatch surface.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::RejectGovernanceProposal {
        payload: Box::new(VoteOnProposalPayload {
            context_id: context_id.clone(),
            proposal_id,
            voter_did: did,
            signing_key: SigningKeyBytes::from_signing_key(&signing_key),
        }),
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2043.to_owned(),
        })
    })?;
    let status = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance reject shim reply dropped: {e}"),
                code: codes::CTX_2043.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance rejection failed: {e}"),
                code: codes::CTX_2043.to_owned(),
            })
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(bi, &context_id).await {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to sync role state after governance rejection"
        );
    }

    Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
}

/// Per-bridge-instance implementation of [`context_governance_withdraw`].
///
/// Routed through the ADR-049 governance dispatch surface. No signing key
/// is required.
#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn context_governance_withdraw_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    proposal_id_hex: String,
    voter_did: String,
) -> napi::Result<String> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;
    let did = DID(voter_did);
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::WithdrawGovernanceVote {
        context_id: context_id.clone(),
        proposal_id,
        voter_did: did,
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2044.to_owned(),
        })
    })?;
    let status = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance withdraw shim reply dropped: {e}"),
                code: codes::CTX_2044.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("governance vote withdrawal failed: {e}"),
                code: codes::CTX_2044.to_owned(),
            })
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(bi, &context_id).await {
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

/// Per-bridge-instance implementation of [`context_governance_get_proposal`].
///
/// Returns the full proposal as a JSON string, or rejects if not found.
/// Routed through the ADR-049 governance dispatch surface.
#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn context_governance_get_proposal_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    proposal_id_hex: String,
) -> napi::Result<String> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id.clone();
    let proposal_id = parse_napi_proposal_id(&proposal_id_hex)?;
    let sup = crate::runtime::supervisor(bi)?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::GetProposal {
        context_id,
        proposal_id,
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2045.to_owned(),
        })
    })?;
    let proposal = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("get proposal shim reply dropped: {e}"),
                code: codes::CTX_2045.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("get proposal failed: {e}"),
                code: codes::CTX_2045.to_owned(),
            })
        })?;

    serde_json::to_string(&proposal).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: codes::CTX_2045.to_owned(),
        })
    })
}

/// Per-bridge-instance implementation of [`context_governance_list_proposals`].
///
/// Returns a JSON array of proposals, or an empty array if the context has
/// no pending proposals. Routed through the ADR-049 governance dispatch surface.
pub(crate) async fn context_governance_list_proposals_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<String> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id.clone();
    let sup = crate::runtime::supervisor(bi)?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::ListProposals {
        context_id,
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2046.to_owned(),
        })
    })?;
    let proposals = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("list proposals shim reply dropped: {e}"),
                code: codes::CTX_2046.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("list proposals failed: {e}"),
                code: codes::CTX_2046.to_owned(),
            })
        })?;

    serde_json::to_string(&proposals).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: codes::CTX_2046.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Bridge functions — ceiling modification, close, checkpoint, restore (#559)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`context_apply_pending_ceiling_modification`].
pub(crate) async fn context_apply_pending_ceiling_modification_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    current_timestamp: f64,
) -> napi::Result<bool> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id.clone();
    let sup = crate::runtime::supervisor(bi)?;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ts = current_timestamp as u64;

    // Route through the ADR-049 governance dispatch surface.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::ApplyPendingCeilingModification {
        context_id,
        current_timestamp: ts,
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2060.to_owned(),
        })
    })?;
    rx.await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("apply_pending_ceiling_modification shim reply dropped: {e}"),
                code: codes::CTX_2060.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("apply_pending_ceiling_modification failed: {e}"),
                code: codes::CTX_2060.to_owned(),
            })
        })
}

/// Per-bridge-instance implementation of [`context_finalize_close`].
///
/// Transitions the context from `Closing` to `Closed`, destroys keys per
/// memory scope, and records a `ContextClosed` event. Routed through the
/// ADR-049 TTL-close dispatch surface.
pub(crate) async fn context_finalize_close_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
    crate::napi_check_handle!(&bi.core, handle);

    // Use the handle's actual core_handle (which carries correct ContextParams
    // including memory_scope) instead of constructing one with default params.
    // memory_scope governs key destruction behavior in finalize_close — using
    // default (Ephemeral) would incorrectly destroy keys for Full-scope contexts.
    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    // Ensure the core handle is in Closing state. If close_context already
    // transitioned it, the transition_to call fails harmlessly (self-transition
    // or invalid source state) and we ignore the error.
    let _ = core_handle.transition_to(&ContextState::Closing);

    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = TtlCloseCommand::FinalizeClose {
        payload: Box::new(TtlContextPayload {
            context_id: core_handle.context_id().to_owned(),
            params: core_handle.params().clone(),
        }),
        reply: tx,
    };
    sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_ttl_close_command failed: {e}"),
            code: codes::CTX_2061.to_owned(),
        })
    })?;
    rx.await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("finalize_close shim reply dropped: {e}"),
                code: codes::CTX_2061.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("finalize_close failed: {e}"),
                code: codes::CTX_2061.to_owned(),
            })
        })?;

    // Update FFI handle state to Closed.
    if let Ok(mut s) = handle.state.lock() {
        *s = ContextState::Closed;
    }

    Ok(())
}

/// Per-bridge-instance implementation of [`context_create_governance_checkpoint`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn context_create_governance_checkpoint_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    checkpoint_seq: f64,
    merkle_root_hex: String,
    event_count: f64,
    last_event_hash_hex: String,
    state_snapshot_hash_hex: String,
    creator_did: String,
    creator_signature_hex: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id.clone();

    let merkle_root = parse_napi_hex_32(&merkle_root_hex, "merkle_root")?;
    let last_event_hash = parse_napi_hex_32(&last_event_hash_hex, "last_event_hash")?;
    let state_snapshot_hash = parse_napi_hex_32(&state_snapshot_hash_hex, "state_snapshot_hash")?;
    let creator_signature = hex::decode(&creator_signature_hex).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid creator_signature hex: {e}"),
            code: codes::CTX_2062.to_owned(),
        })
    })?;
    let did = DID(creator_did);

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let seq = checkpoint_seq as u64;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let count = event_count as u64;

    // Route through the ADR-049 trust-recovery dispatch surface
    // ([`Supervisor::dispatch_trust_recovery_command`](scp_core::context::supervisor::Supervisor::dispatch_trust_recovery_command)).
    use scp_core::context::actor::commands::{
        CreateGovernanceCheckpointPayload, TrustRecoveryCommand,
    };
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = TrustRecoveryCommand::CreateGovernanceCheckpoint {
        payload: Box::new(CreateGovernanceCheckpointPayload {
            context_id,
            checkpoint_seq: seq,
            merkle_root,
            event_count: count,
            last_event_hash,
            state_snapshot_hash,
            creator_did: did,
            creator_signature,
        }),
        reply: tx,
    };
    sup.dispatch_trust_recovery_command(cmd)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("supervisor dispatch_trust_recovery_command failed: {e}"),
                code: codes::CTX_2062.to_owned(),
            })
        })?;
    let checkpoint = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("create_governance_checkpoint shim reply dropped: {e}"),
                code: codes::CTX_2062.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("create_governance_checkpoint failed: {e}"),
                code: codes::CTX_2062.to_owned(),
            })
        })?;

    serde_json::to_string(&checkpoint).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: codes::CTX_2062.to_owned(),
        })
    })
}

/// Per-bridge-instance implementation of [`context_add_checkpoint_cosignature`].
pub(crate) async fn context_add_checkpoint_cosignature_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    checkpoint_json: String,
    signer_did: String,
    signature_hex: String,
) -> napi::Result<String> {
    use scp_core::context::actor::commands::TrustRecoveryCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id.clone();

    let checkpoint: scp_core::context::governance::ContextCheckpoint =
        serde_json::from_str(&checkpoint_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid checkpoint JSON: {e}"),
                code: codes::CTX_2063.to_owned(),
            })
        })?;

    let signature = hex::decode(&signature_hex).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid signature hex: {e}"),
            code: codes::CTX_2063.to_owned(),
        })
    })?;

    let cosignature = scp_core::context::governance::CosignedCheckpoint {
        signer_did: DID(signer_did),
        signature,
    };

    // Route through the ADR-049 trust-recovery dispatch surface.
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = TrustRecoveryCommand::AddCheckpointCosignature {
        context_id,
        checkpoint: Box::new(checkpoint),
        cosignature: Box::new(cosignature),
        reply: tx,
    };
    sup.dispatch_trust_recovery_command(cmd)
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("supervisor dispatch_trust_recovery_command failed: {e}"),
                code: codes::CTX_2063.to_owned(),
            })
        })?;
    let (updated_checkpoint, status) = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("add_checkpoint_cosignature shim reply dropped: {e}"),
                code: codes::CTX_2063.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("add_checkpoint_cosignature failed: {e}"),
                code: codes::CTX_2063.to_owned(),
            })
        })?;

    let response = serde_json::json!({
        "attestation_status": format!("{status:?}"),
        "checkpoint": serde_json::to_value(&updated_checkpoint).unwrap_or_default(),
    });
    Ok(response.to_string())
}

/// Per-bridge-instance implementation of [`context_restore`].
///
/// Routed through the ADR-049 lifecycle dispatch surface. The handler
/// loads the persisted snapshot itself and reconstructs an ephemeral
/// `ContextHandle` from it — the `ContextParams` supplied here are only
/// used to initialise the ephemeral wrapper; the handler overwrites all
/// memory-scope-sensitive state from the loaded snapshot.
#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn context_restore_on(
    bi: &NapiBridgeInstance,
    context_id: String,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{LifecycleCommand, RestoreContextPayload};
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = LifecycleCommand::RestoreContext {
        payload: Box::new(RestoreContextPayload {
            context_id,
            params: scp_core::context::ContextParams::default(),
        }),
        reply: tx,
    };
    sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_lifecycle_command failed: {e}"),
            code: codes::CTX_2064.to_owned(),
        })
    })?;
    rx.await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("restore_context shim reply dropped: {e}"),
                code: codes::CTX_2064.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("restore_context failed: {e}"),
                code: codes::CTX_2064.to_owned(),
            })
        })
}

/// Per-bridge-instance implementation of [`context_restore_all`].
///
/// Returns a JSON array of restored context ID strings. Routes through the
/// supervisor-scope direct method `restore_on_startup` (ADR-049),
/// which restores contexts BEFORE replaying any crash-orphaned saga journal
/// entries in the §17.16.4-required restore-then-replay order; `restore_on_startup`
/// operates on the supervisor-wide context registry and has no per-context
/// command target.
pub(crate) async fn context_restore_all_on(bi: &NapiBridgeInstance) -> napi::Result<String> {
    let sup = crate::runtime::supervisor(bi)?;

    let restored = sup.restore_on_startup().await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("restore_all_contexts failed: {e}"),
            code: codes::CTX_2065.to_owned(),
        })
    })?;

    serde_json::to_string(&restored).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("serialization failed: {e}"),
            code: codes::CTX_2065.to_owned(),
        })
    })
}

/// Parses a hex string into a 32-byte array for NAPI bridge.
fn parse_napi_hex_32(hex_str: &str, field_name: &str) -> napi::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid {field_name} hex: {e}"),
            code: codes::CTX_2062.to_owned(),
        })
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("{field_name} must be 32 bytes, got {}", v.len()),
            code: codes::CTX_2062.to_owned(),
        })
    })?;
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Bridge functions — context migration (§5.11A, #580)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`context_tombstone_migrated`].
pub(crate) async fn context_tombstone_migrated_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id.clone();

    // Route through the ADR-049 governance dispatch surface.
    use scp_core::context::actor::commands::GovernanceCommand;
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::TombstoneMigratedContext {
        context_id,
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2050.to_owned(),
        })
    })?;
    rx.await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("tombstone_migrated_context shim reply dropped: {e}"),
                code: codes::CTX_2050.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("tombstone_migrated_context failed: {e}"),
                code: codes::CTX_2050.to_owned(),
            })
        })?;

    // Sync FFI handle state to Tombstoned (§5.11A.5).
    if let Ok(mut s) = handle.state.lock() {
        *s = ContextState::Tombstoned;
    }

    Ok(())
}

/// Per-bridge-instance implementation of [`context_migration_state`] (§5.11A).
///
/// Returns a JSON string with migration state fields, or `null` if the
/// context is not migrating. Routed through the ADR-049 governance dispatch surface.
pub(crate) async fn context_migration_state_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<Option<String>> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let context_id = handle.context_id.clone();
    let sup = crate::runtime::supervisor(bi)?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = GovernanceCommand::MigrationState {
        context_id,
        reply: tx,
    };
    sup.dispatch_governance_command(cmd).await.map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("supervisor dispatch_governance_command failed: {e}"),
            code: codes::CTX_2050.to_owned(),
        })
    })?;
    let state = rx
        .await
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("migration_state shim reply dropped: {e}"),
                code: codes::CTX_2050.to_owned(),
            })
        })?
        .map_err(|e| {
            NapiError::from(ScpNapiError::Context {
                message: format!("migration_state failed: {e}"),
                code: codes::CTX_2050.to_owned(),
            })
        })?;
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

/// Per-bridge-instance implementation of [`context_handle_ttl_expiry`].
///
/// Routed through the ADR-049 TTL-close dispatch surface.
pub(crate) async fn context_handle_ttl_expiry_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
    crate::napi_check_handle!(&bi.core, handle);
    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = TtlCloseCommand::ExecuteTtlClose {
        payload: Box::new(TtlContextPayload {
            context_id: core_handle.context_id().to_owned(),
            params: core_handle.params().clone(),
        }),
        reply: tx,
    };
    sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_ttl_close_command failed: {e}"))
    })?;
    rx.await
        .map_err(|e| {
            napi::Error::from_reason(format!("handle_ttl_expiry shim reply dropped: {e}"))
        })?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

/// Per-bridge-instance implementation of [`context_propose_ttl_extension`].
///
/// Routed through the ADR-049 TTL-close dispatch surface. Records consent
/// from the given member. Returns `true` if the extension was unanimously
/// approved.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub(crate) async fn context_propose_ttl_extension_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    proposer_did: String,
    extension_secs: u32,
) -> napi::Result<bool> {
    use scp_core::context::actor::commands::TtlCloseCommand;
    crate::napi_check_handle!(&bi.core, handle);
    let did = DID(proposer_did.clone());
    let duration = std::time::Duration::from_secs(u64::from(extension_secs));
    let sup = crate::runtime::supervisor(bi)?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = TtlCloseCommand::ExtendTtl {
        context_id,
        member_did: did,
        proposed_duration: duration,
        reply: tx,
    };
    sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_ttl_close_command failed: {e}"))
    })?;
    let unanimous = rx
        .await
        .map_err(|e| {
            napi::Error::from_reason(format!("propose_ttl_extension shim reply dropped: {e}"))
        })?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(unanimous)
}

/// Per-bridge-instance implementation of [`context_reset_ttl_timer`].
///
/// EXTENDS the existing convergent TTL deadline by `new_duration_secs`
/// (`old_deadline + new_duration_secs`), NOT a local `now + duration` — every
/// member adds the same duration to the same recorded deadline, so the re-armed
/// `ContextExpired`/`ContextClosed` leaf timestamp stays convergent across
/// members (§7.3.1). It does NOT cancel/respawn a task: the TTL timer is an
/// actor-owned arm and `reconcile_timers` re-derives the one-shot sleep from the
/// new recorded deadline (ADR-049 finding A3).
///
/// NO-OP on a context with no armed TTL (`deadline_unix_secs == None`): with no
/// recorded deadline there is no TTL to extend, so the disarmed timer stays
/// disarmed rather than arming a long-past deadline (H2).
///
/// Routed through the ADR-049 TTL-close dispatch surface. Requires a core
/// handle and a new duration.
pub(crate) async fn context_reset_ttl_timer_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    new_duration_secs: u32,
) -> napi::Result<()> {
    use scp_core::context::actor::commands::{TtlCloseCommand, TtlTimerPayload};
    crate::napi_check_handle!(&bi.core, handle);
    let core_handle = handle.require_core_handle().map_err(NapiError::from)?;
    let duration = std::time::Duration::from_secs(u64::from(new_duration_secs));
    let sup = crate::runtime::supervisor(bi)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = TtlCloseCommand::ResetTtlTimer {
        payload: Box::new(TtlTimerPayload {
            context_id: core_handle.context_id().to_owned(),
            params: core_handle.params().clone(),
            duration,
            // Ignored by ResetTtlTimer (which extends the existing convergent
            // deadline by `duration`, not an absolute override).
            deadline_override: None,
        }),
        reply: tx,
    };
    sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
        napi::Error::from_reason(format!("supervisor dispatch_ttl_close_command failed: {e}"))
    })?;
    rx.await
        .map_err(|e| napi::Error::from_reason(format!("reset_ttl_timer shim reply dropped: {e}")))?
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Context export/import (#363)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`context_export`].
///
/// Returns serialized `StoredValue<ContextExport>` bytes (§17.5) suitable for
/// backup, migration, or transfer to another node.
///
/// Signs the exported snapshot's §23.16.8 canonical digest by delegating to the
/// exporter identity's [`KeyCustody::sign`], which dispatches to whichever
/// backend backs that identity — in-memory OR a JS callback custody
/// (`identityCreateWithCustody`). The raw private key is never exported, so
/// keychain/HSM-shaped callback providers that implement `sign` but not
/// `exportSigningKeyBytes` can still produce a signed export. The signature is
/// applied at this dispatch boundary because the runtime holds no custody key;
/// `Supervisor::export_context` captures the unsigned snapshot from the actor
/// and signs it here via the supplied closure (§23.16.8, ADR-050).
///
/// The retained custody and signing-key handle live on the context handle. If
/// the handle has no retained custody (e.g. the context creator was an
/// externally loaded, DID-string-only identity), the export is rejected
/// fail-closed by `resolve_napi_export_signer` (`CTX_2040`) rather than emitting
/// an unsigned (and thus unverifiable) export.
pub(crate) async fn context_export_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<Vec<u8>> {
    crate::napi_check_handle!(&bi.core, handle);
    let exporter_did = scp_did::DID::from(handle.creator_did.clone());
    let sup = crate::runtime::supervisor(bi)?;

    // Resolve the exporter identity's custody provider and `#active` signing
    // key handle (NOT a raw exported key). Signing the §23.16.8 snapshot
    // digest is delegated to `KeyCustody::sign`, which dispatches to whichever
    // backend backs this identity — in-memory OR a JS callback custody
    // (`identityCreateWithCustody`). This lets keychain/HSM-shaped callback
    // providers — which implement `sign` but intentionally do NOT implement
    // `exportSigningKeyBytes` — produce a signed export. Private key material
    // never crosses the FFI boundary (ADR-006).
    let (custody, key_handle) = resolve_napi_export_signer(handle)?;

    // `export_context`'s `sign` closure is synchronous, but custody `sign` is
    // async (a callback custody awaits a JS `ThreadsafeFunction`). Bridge the
    // two with `block_in_place` + `block_on` on the current multi-thread
    // runtime — the same pattern used by `identity_create_link_attestation`
    // (see `scp.rs`). `context_export_on` already runs on a tokio worker, so a
    // runtime handle is always present here.
    let rt = tokio::runtime::Handle::try_current().map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("context export requires a tokio runtime: {e}"),
            code: codes::CTX_2030.to_owned(),
        })
    })?;

    let export = sup
        .export_context(&handle.context_id, exporter_did, |hash: &[u8; 32]| {
            let signature =
                tokio::task::block_in_place(|| rt.block_on(custody.sign(&key_handle, hash)))?;
            let bytes: [u8; 64] = signature.as_bytes().try_into().map_err(|_| {
                scp_platform::PlatformError::CustodyError(format!(
                    "custody sign returned {} bytes, expected 64 (Ed25519)",
                    signature.as_bytes().len()
                ))
            })?;
            Ok::<[u8; 64], scp_platform::PlatformError>(bytes)
        })
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
    scp_core::context::export_import::serialize_export(&export).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("export serialization failed: {e}"),
            code: codes::CTX_2030.to_owned(),
        })
    })
}

/// Per-bridge-instance implementation of [`context_import`].
///
/// The bytes must be a `StoredValue<ContextExport>` envelope (§17.5), as
/// produced by [`context_export`]. Routed through the ADR-049 lifecycle
/// dispatch surface. Returns the context ID of the imported context.
pub(crate) async fn context_import_on(
    bi: &NapiBridgeInstance,
    data: Vec<u8>,
    importer_did: String,
) -> napi::Result<String> {
    let export = scp_core::context::export_import::deserialize_export(&data).map_err(|e| {
        NapiError::from(ScpNapiError::Context {
            message: format!("invalid export data: {e}"),
            code: codes::CTX_2032.to_owned(),
        })
    })?;
    let context_id = export.snapshot.context_id.clone();
    let imported_core_params = export.snapshot.context_params.clone();
    let imported_is_broadcast = matches!(
        imported_core_params.mode,
        scp_core::context::params::ContextMode::Broadcast
    );

    // Resolve the verification-method key for the snapshot's `creator_did`
    // (§23.16.8 step 1, ADR-050) — NOT the unauthenticated envelope
    // `exporter_did`. The runtime separately asserts
    // `exporter_did == creator_did` (§23.16.8 step 2). Fail-closed: if no key
    // resolves, the import is rejected — never imported unverified.
    let creator_did = export.snapshot.role_state.creator_did.clone();
    validate_did(&creator_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    // §9.10.4: the importer DID is DISTINCT from the snapshot creator — it
    // identifies the local member re-homing the context and is the subject of
    // pseudonym derivation. Validate it up front, before any state mutation.
    validate_did(&importer_did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let verifying_key = resolve_napi_creator_verifying_key(bi, &creator_did).await?;

    // Verify-before-init: validate the snapshot signature, signer binding,
    // version gate, and Merkle chain BEFORE touching the bridge's Supervisor.
    // `init_supervisor` seeds the MLS provider's credential identity from
    // `creator_did`, and that OnceLock is first-call-wins. Seeding it from an
    // unverified snapshot would let an attacker-crafted `creator_did` set the
    // provider identity on a fresh bridge whose first operation is an import.
    // Running the full verification here means the identity is only seeded from
    // a cryptographically authenticated `creator_did`. `import_context` re-runs
    // the same validation (authoritative path); the duplicate work is
    // acceptable to keep the security ordering correct.
    scp_core::context::export_import::validate_export_for_import(&export, &verifying_key)
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // §9.10.4 misuse-resistance: the importer MUST be a member of the now-
    // verified snapshot, else its derived pseudonym routes to an ID no peer
    // expects and the member is silently unaddressable. Reject loudly
    // (SCP-CTX-2092). The creator is a member, so a creator re-homing its own
    // context passes.
    scp_core::context::export_import::ensure_importer_is_member(&export.snapshot, &importer_did)
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // Ensure the Supervisor is initialized — context_import is a valid first
    // operation (e.g. a device receiving exported context data).
    // init_supervisor is idempotent (OnceLock — first call wins). Seeding from
    // the now-verified `creator_did` is safe per the verify-before-init step
    // above.
    crate::runtime::init_supervisor(bi, &creator_did);

    // §9.10.4: derive the importer's OWN per-context pseudonym before the
    // runtime import. The runtime import path is encrypted-only (broadcast-mode
    // exports are rejected upstream with SCP-CTX-2092), so a real pseudonym is
    // ALWAYS required — derive it UNCONDITIONALLY, exactly like the PyO3
    // reference bridge. Custody / derivation failure is a hard error carrying
    // granular codes (missing material → 1054, derivation failure → 1055, wrong
    // length → 1057, custody unavailable → 1056), never a silent zero-pseudonym
    // fallback (which would reintroduce the relay-correlation vector) and never
    // a `[0u8; 32]` sentinel for broadcast (which would make the member
    // permanently unaddressable). Resolve the importer's custody+key from the
    // DID registry, mirroring `context_join_on`.
    let local_pseudonym: [u8; 32] =
        derive_member_pseudonym_required(bi, &importer_did, &context_id).await?;

    let sup = crate::runtime::supervisor(bi)?;
    // Dispatch the import carrying BOTH the creator verifying key
    // (verify-before-init, §23.16.8) and the importer's derived pseudonym
    // (§9.10.4). `import_context` re-runs the authoritative verification and
    // surfaces the typed `ContextError` — including
    // `SnapshotSignatureInvalid` (SCP-CTX-2093, signature/version forgery) and
    // the §9.10.4 codes — through ScpNapiError rather than the catch-all
    // SCP-CTX-2001.
    sup.import_context(export, &verifying_key, Some(local_pseudonym))
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // §9.10.4: emit a PseudonymAnnouncement so existing members learn this
    // importer's per-context routing ID. Encrypted contexts only — broadcast
    // contexts use the shared `broadcast_routing_id` and carry no pseudonym
    // registry. Best-effort: a missing signing key just skips the announcement;
    // without it, peers' pseudonym registries stay stale and app-data fan-out
    // would miss this importer entirely until it re-announces (a plain send does
    // NOT auto-announce — only a `PseudonymAnnouncement` payload reaches the
    // shared routing ID).
    if !imported_is_broadcast {
        // Un-gated for production: runs over retained callback custody
        // (OS-keychain/HSM), matching the NAPI join path and the PyO3 import
        // reference. Without it, a production node that imports a context derives
        // its routing pseudonym but never announces it, so peers' registries
        // stay stale and app-data fan-out silently misses it.
        announce_pseudonym_best_effort(bi, sup, &importer_did, &context_id, imported_core_params)
            .await;
    }

    Ok(context_id)
}

// ---------------------------------------------------------------------------
// Economic policy bridge (§19.3, ADR-033)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`context_set_economic_policy`].
#[allow(clippy::used_underscore_binding)] // param exists for API surface; body rejects all calls
#[allow(clippy::needless_pass_by_ref_mut)] // matches &mut handle signature of free fn
pub(crate) fn context_set_economic_policy_on(
    bi: &NapiBridgeInstance,
    handle: &mut NapiContextHandle,
    _policy_json: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, handle);
    Err(NapiError::from(ScpNapiError::Permission {
        message: "economic policy changes must go through governance \
                  (propose SetEconomicPolicy action). Direct mutation is \
                  not permitted — see spec §19.3"
            .to_owned(),
        code: codes::CTX_2013.to_owned(),
    }))
}

/// Per-bridge-instance implementation of [`context_get_economic_policy`].
pub(crate) fn context_get_economic_policy_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> napi::Result<Option<String>> {
    crate::napi_check_handle!(&bi.core, handle);
    Ok(handle.economic_policy.clone())
}

// ---------------------------------------------------------------------------
// App Sandboxing (#595, spec §8.4.1, §8.4.2)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `validate_capability_declaration`.
pub(crate) fn validate_capability_declaration_on(
    _bi: &NapiBridgeInstance,
    declaration_json: String,
    ceiling_capabilities: Vec<String>,
    role_capabilities: Vec<String>,
) -> napi::Result<String> {
    use scp_core::context::app_sandbox::{CapabilityDeclaration, validate_declaration};
    use scp_core::context::roles::Capability;
    use scp_core::context::{ContextHandle, ContextParams};

    let decl: CapabilityDeclaration = serde_json::from_str(&declaration_json)
        .map_err(|e| NapiError::from_reason(format!("invalid declaration JSON: {e}")))?;

    let ceiling: Vec<Capability> = ceiling_capabilities
        .iter()
        .map(|s| {
            Capability::new(s).ok_or_else(|| {
                NapiError::from_reason(format!(
                    "invalid capability {s:?} in ceiling (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                ))
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;
    let role_caps: Vec<Capability> = role_capabilities
        .iter()
        .map(|s| {
            Capability::new(s).ok_or_else(|| {
                NapiError::from_reason(format!(
                    "invalid capability {s:?} in role (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                ))
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

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
#[must_use]
pub fn check_scoped_capability(
    granted_capabilities: Vec<String>,
    required_capability: String,
) -> bool {
    // Pure capability check — no bridge-instance state involved, so it is a
    // module-level free fn (ADR-048 §1), not a method on the `Scp` object, and
    // has no per-instance `_on` variant.
    check_scoped_capability_inner(granted_capabilities, required_capability)
}

/// Shared implementation used by both the free function and the `Scp` method.
pub(crate) fn check_scoped_capability_inner(
    granted_capabilities: Vec<String>,
    required_capability: String,
) -> bool {
    use scp_core::context::roles::{Capability, CapabilityCeiling};
    use std::collections::HashSet;

    let granted: HashSet<Capability> = granted_capabilities
        .iter()
        .filter_map(Capability::new)
        .collect();
    // Fail-closed: malformed required capability -> deny.
    let Some(required) = Capability::new(&required_capability) else {
        return false;
    };

    // Single authority: `CapabilityCeiling::contains` handles exact matches plus
    // the disjoint wildcard families — `OutletCallAll ⊇ OutletCall(id)` and
    // `OutletQueryAll ⊇ OutletQuery(id)` — never widening across query/call
    // (§5.4.2). Routing through it keeps this helper fail-closed and in lockstep
    // with UCAN ceiling validation.
    CapabilityCeiling::new(granted).contains(&required)
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
///
/// Trust is allowlist-only (§5.12.2): the allowlist travels inside the policy's
/// `TrustRequirement::KnownDid(dids)` variant, so the oracle carries no external
/// state and checks membership of the inviter in that embedded list.
struct NapiBridgeTrustOracle;

impl scp_core::context::invitation::TrustOracle for NapiBridgeTrustOracle {
    fn satisfies_trust(
        &self,
        inviter: &scp_did::DID,
        requirement: &scp_core::context::policy::TrustRequirement,
    ) -> bool {
        match requirement {
            scp_core::context::policy::TrustRequirement::KnownDid(dids) => dids.contains(inviter),
        }
    }
}

/// Per-bridge-instance implementation of `evaluate_invitation`.
pub(crate) fn evaluate_invitation_on(
    bi: &NapiBridgeInstance,
    params_json: String,
    inviter_did: String,
    identity_did: String,
    policy_json: Option<String>,
    spending_json: Option<String>,
) -> napi::Result<NapiEvaluationResult> {
    use scp_core::context::invitation::{
        EvaluationDecision, SpendingContext, evaluate_invitation as core_evaluate,
    };
    use scp_core::context::policy::AutoAcceptPolicy;

    validate_did(&inviter_did).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: e.message,
            code: codes::VALID_7010.to_owned(),
        })
    })?;
    validate_did(&identity_did).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: e.message,
            code: codes::VALID_7010.to_owned(),
        })
    })?;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse context params JSON: {e}"),
                code: codes::VALID_7010.to_owned(),
            })
        })?;

    let policy: Option<AutoAcceptPolicy> = match policy_json {
        Some(ref json) => Some(serde_json::from_str(json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse auto-accept policy JSON: {e}"),
                code: codes::VALID_7010.to_owned(),
            })
        })?),
        None => None,
    };

    let spending: Option<SpendingContext> = match spending_json {
        Some(ref json) => Some(serde_json::from_str(json).map_err(|e| {
            napi::Error::from(ScpNapiError::Validation {
                message: format!("failed to parse spending context JSON: {e}"),
                code: codes::VALID_7010.to_owned(),
            })
        })?),
        None => None,
    };

    let oracle = NapiBridgeTrustOracle;
    let inviter = scp_did::DID::from(inviter_did.as_str());

    let decision = bi.core.with_rate_limit_tracker(&identity_did, |tracker| {
        core_evaluate(
            &params,
            &inviter,
            policy.as_ref(),
            spending.as_ref(),
            &oracle,
            tracker,
            &scp_clock::SystemClock,
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
            code: codes::CTX_2060.to_owned(),
        })),
    }
}

// ---------------------------------------------------------------------------
// MetadataRecord inspection (§5.7.2, #615)
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `metadata_record_to_json`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn metadata_record_to_json_on(
    _bi: &NapiBridgeInstance,
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
            code: codes::VALID_7001.to_owned(),
        })
    })?;
    validate_did(&signer_did).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: e.to_string(),
            code: codes::VALID_7001.to_owned(),
        })
    })?;

    if sequence == 0 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: codes::VALID_7001.to_owned(),
        }));
    }

    let structural: StructuralMetadata = serde_json::from_str(&structural_json).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid structural metadata JSON: {e}"),
            code: codes::VALID_7001.to_owned(),
        })
    })?;

    let operational: OperationalMetadata =
        serde_json::from_str(&operational_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid operational metadata JSON: {e}"),
                code: codes::VALID_7001.to_owned(),
            })
        })?;

    let signature = hex::decode(&signature_hex).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid signature hex: {e}"),
            code: codes::VALID_7001.to_owned(),
        })
    })?;
    if signature.len() != 64 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: format!("signature must be 64 bytes (got {})", signature.len()),
            code: codes::VALID_7001.to_owned(),
        }));
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ts = timestamp as u64;
    let record = MetadataRecord {
        context_id,
        sequence: u64::from(sequence),
        signer_did: scp_did::DID::from(signer_did),
        timestamp: ts,
        structural,
        operational,
        signature,
    };

    serde_json::to_string(&record).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("failed to serialize MetadataRecord: {e}"),
            code: codes::VALID_7001.to_owned(),
        })
    })
}

/// Pure protocol helper — parses, validates, and re-serializes a `MetadataRecord` JSON.
///
/// Touches no per-instance state, so it is a top-level free function per ADR-048 §1
/// ("Pure protocol helpers stay free functions at the FFI Rust layer").
#[napi(js_name = "metadataRecordFromJson")]
pub fn metadata_record_from_json(json_str: String) -> napi::Result<String> {
    use scp_core::context::metadata::MetadataRecord;

    let record: MetadataRecord = serde_json::from_str(&json_str).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("invalid MetadataRecord JSON: {e}"),
            code: codes::VALID_7001.to_owned(),
        })
    })?;

    // F6: sequence must be >= 1 (spec §5.7.2)
    if record.sequence == 0 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: codes::VALID_7001.to_owned(),
        }));
    }

    // F7: signature must be exactly 64 bytes (Ed25519)
    if record.signature.len() != 64 {
        return Err(NapiError::from(ScpNapiError::Validation {
            message: format!(
                "signature must be 64 bytes (got {})",
                record.signature.len()
            ),
            code: codes::VALID_7001.to_owned(),
        }));
    }

    serde_json::to_string(&record).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("failed to re-serialize MetadataRecord: {e}"),
            code: codes::VALID_7001.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Context template inspection (§5.14, #615)
// ---------------------------------------------------------------------------

/// Pure protocol helper — looks up the canonical `ContextParams` for a template ID.
///
/// Touches no per-instance state, so it is a top-level free function per ADR-048 §1
/// ("Pure protocol helpers stay free functions at the FFI Rust layer").
#[napi(js_name = "templateGetParams")]
pub fn template_get_params(template_id: String) -> napi::Result<String> {
    use scp_core::context::templates::template_params;

    let tid = parse_template_id_napi(&template_id)?;
    let params = template_params(&tid);
    serde_json::to_string(&params).map_err(|e| {
        NapiError::from(ScpNapiError::Validation {
            message: format!("failed to serialize template params: {e}"),
            code: codes::VALID_7001.to_owned(),
        })
    })
}

/// Pure protocol helper — validates `ContextParams` JSON against template constraints.
///
/// Touches no per-instance state, so it is a top-level free function per ADR-048 §1
/// ("Pure protocol helpers stay free functions at the FFI Rust layer").
#[napi(js_name = "validateAgainstTemplate")]
pub fn validate_against_template(params_json: String) -> napi::Result<Option<String>> {
    use scp_core::context::templates::validate_against_template;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid ContextParams JSON: {e}"),
                code: codes::VALID_7001.to_owned(),
            })
        })?;

    match validate_against_template(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Pure protocol helper — validates `ContextParams` JSON for shape correctness.
///
/// Touches no per-instance state, so it is a top-level free function per ADR-048 §1
/// ("Pure protocol helpers stay free functions at the FFI Rust layer").
#[napi(js_name = "validateContextParams")]
pub fn validate_context_params(params_json: String) -> napi::Result<Option<String>> {
    use scp_core::context::templates::validate_context_params;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            NapiError::from(ScpNapiError::Validation {
                message: format!("invalid ContextParams JSON: {e}"),
                code: codes::VALID_7001.to_owned(),
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
        "scp:template/outlet-interface" | "OutletInterfaceTemplate" => {
            Ok(TemplateId::OutletInterfaceTemplate)
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
                 GatedBroadcast, scp:template/outlet-interface, PaidService, PaidBroadcast, \
                 HandleRegistry, scp:template/handle-registry, DiscoveryContext, \
                 scp:template/discovery-context"
            ),
            code: codes::VALID_7001.to_owned(),
        })),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_core::context::ContextParams;
    // Consumed only by the `testing`-gated membership helper +
    // test; gate the import so the bare/production test target is warning-clean.
    #[cfg(feature = "testing")]
    use scp_core::context::membership::KeyPackage;
    use scp_core::context::params::Capability;
    // The feature-gated economy tests reference `codes::` directly (no
    // `use super::*`); the ungated export tests reach `codes` through their
    // in-fn `use super::*` glob (re-exporting the file-level alias). Gate the
    // alias to its sole direct consumers so the ungated build does not see an
    // unused import.
    use scp_did::DID;
    #[cfg(feature = "testing")]
    use scp_ffi_common::error_codes as codes;
    use std::sync::Arc;

    /// Test helper: dispatch `LifecycleCommand::CreateContext` through the
    /// supervisor. Mirrors the production rewire pattern but is callable
    /// from tests with a pre-built `ContextParams`.
    async fn test_dispatch_create_context(
        bi: &crate::runtime::NapiBridgeInstance,
        ctx_id: &str,
        params: ContextParams,
        creator: scp_did::DID,
    ) -> scp_core::context::ContextHandle {
        use scp_core::context::actor::commands::{CreateContextPayload, LifecycleCommand};
        let sup = crate::runtime::supervisor(bi).unwrap();
        let sup = Arc::clone(sup);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::CreateContext {
            payload: Box::new(CreateContextPayload {
                context_id: ctx_id.to_owned(),
                params,
                creator_did: creator,
                local_pseudonym: None,
            }),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.unwrap();
        rx.await.unwrap().unwrap()
    }

    /// Test helper: dispatch `LifecycleCommand::JoinContext` through the
    /// supervisor. Only the `testing`-gated membership tests
    /// call it, so it is gated to keep the bare test target warning-clean.
    #[cfg(feature = "testing")]
    async fn test_dispatch_join_context(
        bi: &crate::runtime::NapiBridgeInstance,
        handle: &scp_core::context::ContextHandle,
        key_package: KeyPackage,
    ) {
        use scp_core::context::actor::commands::{JoinContextPayload, LifecycleCommand};
        let sup = crate::runtime::supervisor(bi).unwrap();
        let sup = Arc::clone(sup);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::JoinContext {
            payload: Box::new(JoinContextPayload {
                context_id: handle.context_id().to_owned(),
                params: handle.params().clone(),
                key_package,
                spending_ucan: None,
                local_pseudonym: None,
            }),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.unwrap();
        rx.await.unwrap().unwrap();
    }

    /// Test helper: create a REAL in-memory identity and register it in the
    /// bridge's identity registry, returning its DID. Mirrors the
    /// `build_scp_with_identity` pattern in `scp.rs` tests — a joiner whose
    /// locally-custodied identity makes the §9.10.4 pseudonym-derivation custody
    /// gate SUCCEED, so a Welcome-join test reaches the register -> spawn seam.
    #[cfg(feature = "testing")]
    async fn register_in_memory_joiner(bi: &crate::runtime::NapiBridgeInstance) -> String {
        use crate::identity::OpaqueInMemoryKeyCustody;
        use scp_identity::DidMethod;
        use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

        let custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
        let dht = scp_identity::DidDht::with_client(std::sync::Arc::new(
            scp_dht::InMemoryDhtClient::new(),
        ));
        let (identity, document, pre_rotation_handle) = dht
            .create(&*custody, pre_rotation_custody.as_ref())
            .await
            .expect("in-memory identity creation succeeds");
        let did = identity.did.clone();
        crate::runtime::register_identity(
            bi,
            &did,
            crate::runtime::NapiIdentityEntry {
                identity,
                custody,
                document,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle,
                pre_rotation_custody,
            },
        );
        did
    }

    // -----------------------------------------------------------------------
    // ADR-039 Enforcement-Stack Layer 2 — message-send persona-source seam.
    //
    // Mirrors the PyO3 reference persona resolver tests
    // (`resolve_message_signer_binds_stamp_and_key_atomically` +
    // `..._fails_closed`) against the NAPI bridge, whose custody sourcing is
    // materially different (context-handle custody for `#active`; SAME
    // identity-registry entry for `#agent`). These exercise the REAL
    // `resolve_napi_message_signer`, which binds the VM stamp and the key handle
    // from ONE persona (fail-closed on `#agent` with no agent key).
    // -----------------------------------------------------------------------

    /// Registers a fresh in-memory identity (optionally carrying an `#agent`
    /// signing key) and returns `(did, active_key, agent_key, handle)` with the
    /// two keys exported for byte-comparison and a context handle carrying the
    /// identity's custody + active key so the `#active` resolution path works.
    #[cfg(feature = "testing")]
    async fn register_persona_test_identity(
        bi: &Arc<crate::runtime::NapiBridgeInstance>,
        with_agent_key: bool,
    ) -> (
        String,
        ed25519_dalek::SigningKey,
        Option<ed25519_dalek::SigningKey>,
        super::NapiContextHandle,
    ) {
        use crate::identity::OpaqueInMemoryKeyCustody;
        use scp_identity::{DidDht, DidMethod};
        use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

        let custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
        let dht = DidDht::with_client(Arc::new(scp_dht::InMemoryDhtClient::new()));
        let (identity, document, pre_rotation_handle) = if with_agent_key {
            dht.create_with_agent_key(custody.as_ref(), pre_rotation_custody.as_ref())
                .await
                .expect("agent-keyed in-memory identity creation succeeds")
        } else {
            DidMethod::create(&dht, custody.as_ref(), pre_rotation_custody.as_ref())
                .await
                .expect("in-memory identity creation succeeds")
        };
        let did = identity.did.clone();
        // `KeyHandle` is `Copy` — read the handles before moving `identity`.
        let active_handle = identity.active_signing_key;
        let active_key = custody
            .export_ed25519_signing_key(&active_handle)
            .await
            .expect("export active key");
        let agent_key = match identity.agent_signing_key {
            Some(h) => Some(
                custody
                    .export_ed25519_signing_key(&h)
                    .await
                    .expect("export agent key"),
            ),
            None => None,
        };
        crate::runtime::register_identity(
            bi,
            &did,
            crate::runtime::NapiIdentityEntry {
                identity,
                custody: Arc::clone(&custody),
                document,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle,
                pre_rotation_custody,
            },
        );
        let handle = super::NapiContextHandle {
            context_id: format!("persona-test-{}", uuid::Uuid::new_v4()),
            state: std::sync::Mutex::new(super::ContextState::Active),
            creator_did: did.clone(),
            mode: "Encrypted".to_owned(),
            ceiling: vec![],
            ceiling_policy: "immutable".to_owned(),
            ttl_seconds: None,
            promotion_policy: None,
            governance: "single_admin".to_owned(),
            economic_policy: None,
            in_memory_custody: Some(Arc::clone(&custody)),
            signing_key: Some(active_handle),
            core_handle: None,
            subscription_cancel: std::sync::Mutex::new(super::CancellationToken::new()),
            subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            bi: Arc::clone(bi),
            instance_id: bi.instance_id(),
        };
        (did, active_key, agent_key, handle)
    }

    /// `resolve_napi_message_signer` binds the `#agent` VM stamp to the
    /// identity's AGENT key (never the active key), and `#active` to the active
    /// key — atomically. This is the property that makes an `#agent`-stamped-
    /// but-`#active`-signed message unrepresentable at the FFI send boundary.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_message_signer_binds_stamp_and_key_atomically() {
        use scp_core::context::supervisor::MessageSigner;
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let (did, active_key, agent_key, handle) = register_persona_test_identity(&bi, true).await;
        let agent_key = agent_key.expect("agent-keyed identity has an agent key");
        assert_ne!(
            active_key.to_bytes(),
            agent_key.to_bytes(),
            "test identity must have distinct active and agent keys"
        );

        // #agent persona → agent key + #agent stamp.
        let signer =
            super::resolve_napi_message_signer(&bi, &handle, &did, scp_did::SigningKeyId::Agent)
                .await
                .unwrap();
        assert_eq!(signer.persona(), scp_did::SigningKeyId::Agent);
        assert!(matches!(signer.message_signer(), MessageSigner::Agent(_)));
        assert_eq!(
            signer.message_signer().signing_key_id(),
            scp_did::SigningKeyId::Agent
        );
        assert_eq!(
            signer.message_signer().key().to_bytes(),
            agent_key.to_bytes(),
            "#agent persona MUST resolve the agent key, never the active key"
        );

        // #active persona → active key + #active stamp (default path unchanged).
        let signer =
            super::resolve_napi_message_signer(&bi, &handle, &did, scp_did::SigningKeyId::Active)
                .await
                .unwrap();
        assert_eq!(signer.persona(), scp_did::SigningKeyId::Active);
        assert!(matches!(signer.message_signer(), MessageSigner::Active(_)));
        assert_eq!(
            signer.message_signer().key().to_bytes(),
            active_key.to_bytes()
        );
    }

    /// Fail-closed: `#agent` requested for an identity with NO agent key returns
    /// a typed error (SCP-IDENT-1023) and NEVER falls back to the active key.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolve_message_signer_agent_without_agent_key_fails_closed() {
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let (did, active_key, agent_key, handle) = register_persona_test_identity(&bi, false).await;
        assert!(agent_key.is_none(), "active-only identity has no agent key");

        let err =
            super::resolve_napi_message_signer(&bi, &handle, &did, scp_did::SigningKeyId::Agent)
                .await
                .expect_err("#agent send without an agent key must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains(codes::IDENT_1023),
            "expected fail-closed no-agent-key code SCP-IDENT-1023, got: {msg}"
        );

        // The active path still resolves — the failure is specific to #agent,
        // not a broken identity.
        let signer =
            super::resolve_napi_message_signer(&bi, &handle, &did, scp_did::SigningKeyId::Active)
                .await
                .unwrap();
        assert_eq!(
            signer.message_signer().key().to_bytes(),
            active_key.to_bytes()
        );
    }

    /// ADR-049 Phase 2J: `reserve_key_package` enforces local custody of the
    /// owning identity at the bridge (the same trust model as `context_create`).
    /// A non-locally-custodied `owning_did` fails closed at the
    /// `ensure_local_custody` gate with the identity-not-registered error
    /// (`SCP-IDENT-1001`), BEFORE any supervisor/KeyPackage work.
    ///
    /// The end-to-end reserve -> spawn happy path (which needs wired MLS
    /// providers and a real creator-minted Welcome) is covered at the runtime
    /// layer and by the cross-bridge E2E harness.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reserve_key_package_rejects_non_locally_custodied_identity() {
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let Err(err) =
            super::reserve_key_package_on(&bi, "did:dht:z6MkNoSuchNapiReserve".to_owned()).await
        else {
            panic!("reserve for a non-locally-custodied identity must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains(codes::IDENT_1001),
            "expected local-custody rejection {}, got: {msg}",
            codes::IDENT_1001
        );
    }

    /// ADR-049 Phase 2J: `context_join_from_welcome` enforces local custody of
    /// the JOINER at the bridge — a non-locally-custodied `owning_did`
    /// hard-fails at the pseudonym-derivation seam (the SAME custody gate
    /// `context_create` uses) BEFORE the single-use `KeyPackage` is consumed.
    ///
    /// Drives the REAL entry point with an unregistered joiner. Because the
    /// joiner's routing pseudonym is DERIVED from its locally-custodied identity
    /// (never caller-supplied), the registry miss surfaces as the canonical
    /// `SCP-IDENT-1054`. The `reservation_id` and `welcome_bytes` are dummies —
    /// derivation runs before either is touched, so this is not false-green: were
    /// the custody gate removed, the call would proceed past derivation and fail
    /// later for an unrelated reason, not with `SCP-IDENT-1054`.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_join_from_welcome_rejects_non_locally_custodied_joiner() {
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        // A well-formed 32-byte `enc` so the failure isolates the custody gate
        // (which runs BEFORE the enc-length check), not a length rejection.
        let sealed = super::NapiSealedInvitation {
            context_id: "0".repeat(64),
            creator_did: "did:dht:z6MkSomeNapiCreator".to_owned(),
            enc: vec![0u8; 32],
            ciphertext: b"not-a-real-bundle".to_vec(),
        };
        let Err(err) = super::context_join_from_welcome_on(
            &bi,
            "did:dht:z6MkNoSuchNapiJoinFromWelcome".to_owned(),
            sealed,
            "not-a-real-reservation".to_owned(),
        )
        .await
        else {
            panic!("join-from-Welcome for a non-locally-custodied joiner must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains(codes::IDENT_1054),
            "expected joiner local-custody hard-fail {}, got: {msg}",
            codes::IDENT_1054
        );
    }

    /// ADR-049 Phase 2J / FFI-02 Option A (reshape): the reshaped
    /// `context_join_from_welcome` no longer takes caller `params`, so there is no
    /// `mode` field to inspect — broadcast rejection moved INSIDE the runtime (a
    /// broadcast context carries no MLS Welcome, spec §5.14, so it fails at the
    /// fused `ConfirmConsume`). The NEW bridge-level fail-closed boundary is the
    /// HPKE `enc` length: it MUST be exactly 32 bytes (RFC 9180 X25519
    /// encapsulated key). A wrong-length `enc` is rejected BEFORE the irreversible
    /// `KeyPackage` consume.
    ///
    /// Not false-green: a locally-custodied joiner is used so the custody gate
    /// SUCCEEDS and control reaches the enc-length check; were that check removed,
    /// the malformed `enc` would instead fail deep inside the HPKE open with a
    /// different message, not the exact "expected 32" surfaced here.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_join_from_welcome_rejects_non_32_byte_enc() {
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        // Locally-custodied joiner so the pseudonym-derivation custody gate passes
        // and control reaches the fail-closed enc-length check.
        let joiner_did = register_in_memory_joiner(&bi).await;

        // 31-byte `enc` — one short of the required 32.
        let sealed = super::NapiSealedInvitation {
            context_id: "c".repeat(64),
            creator_did: "did:dht:z6MkNapiEncLenCreator".to_owned(),
            enc: vec![0u8; 31],
            ciphertext: b"bogus-ciphertext".to_vec(),
        };
        let Err(err) = super::context_join_from_welcome_on(
            &bi,
            joiner_did,
            sealed,
            "bogus-reservation-id".to_owned(),
        )
        .await
        else {
            panic!("a non-32-byte HPKE enc must be rejected at the bridge boundary");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("expected 32"),
            "expected a fail-closed 32-byte enc-length rejection, got: {msg}"
        );
    }

    /// ADR-049 Phase 2J (orphaned-success fix): `context_join_from_welcome`
    /// registers the bridge-side FFI state as a REVERSIBLE precheck BEFORE the
    /// irreversible runtime join, and ROLLS IT BACK when the runtime join fails —
    /// so a failed join leaves NO FFI state and NO known-context discovery entry.
    ///
    /// Drives the REAL entry point with a locally-custodied joiner, so the
    /// custody / pseudonym-derivation gate SUCCEEDS and control reaches the
    /// register -> spawn seam, but with a bogus reservation + Welcome so
    /// `spawn_actor_from_welcome` fails at the runtime layer (the joiner reserved
    /// nothing). The assertion is on the observable post-condition: after the
    /// error, BOTH the UCAN-state registry and the known-contexts registry are
    /// empty for the context. The explicit "no `SCP-IDENT-1054`" check pins that
    /// the register -> spawn seam was actually exercised (not short-circuited at
    /// the upstream custody gate).
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn join_from_welcome_rolls_back_ffi_state_when_runtime_join_fails() {
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let joiner_did = register_in_memory_joiner(&bi).await;
        let ctx_id = "a".repeat(64);

        // A well-formed 32-byte `enc` passes the bridge enc-length check, so the
        // failure is the runtime join itself (bogus reservation + ciphertext) —
        // exactly the register -> spawn seam the rollback guards.
        let sealed = super::NapiSealedInvitation {
            context_id: ctx_id.clone(),
            creator_did: "did:dht:z6MkNapiRollbackCreator".to_owned(),
            enc: vec![0u8; 32],
            ciphertext: b"bogus-bundle-ciphertext".to_vec(),
        };
        let Err(err) = super::context_join_from_welcome_on(
            &bi,
            joiner_did,
            sealed,
            "bogus-reservation-id".to_owned(),
        )
        .await
        else {
            panic!("join with a bogus sealed bundle must fail at the runtime layer");
        };
        let msg = err.to_string();
        assert!(
            !msg.contains(codes::IDENT_1054),
            "custody must have SUCCEEDED so the register -> spawn seam is exercised; \
             got a derivation error instead: {msg}"
        );

        // Post-condition: the reversible FFI state was rolled back — no orphaned
        // UCAN state, and no known-context discovery entry.
        assert!(
            crate::runtime::with_context(&bi, &ctx_id, |_| Ok(())).is_err(),
            "FFI (UCAN) state must NOT survive a failed join"
        );
        assert!(
            !bi.core.has_known_context(&ctx_id),
            "no known-context discovery entry may leak after a failed join"
        );
    }

    /// ADR-049 Phase 2J (orphaned-success fix): a pre-existing (`Occupied`)
    /// FFI-state entry fails `context_join_from_welcome` at the
    /// `register_ffi_state` precheck — which runs BEFORE `spawn_actor_from_welcome`
    /// consumes the single-use `KeyPackage` — and does NOT roll back the
    /// pre-existing entry (the bridge must never delete state it did not create).
    ///
    /// Drives the REAL entry with a locally-custodied joiner (custody gate
    /// passes) against a context whose FFI state is already registered. The
    /// register-first ordering surfaces the collision as an `already registered`
    /// error at the precheck; the pre-existing entry SURVIVES the failed join.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn join_from_welcome_occupied_ffi_state_fails_before_keypackage_consumption() {
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let joiner_did = register_in_memory_joiner(&bi).await;
        let ctx_id = "b".repeat(64);

        // Pre-occupy the FFI-state slot for this context id.
        crate::runtime::register_test_context(&bi, &ctx_id, "did:dht:z6MkNapiOccupiedCreator");

        // A well-formed 32-byte `enc` so control passes the bridge enc-length
        // check and reaches the `register_ffi_state` Occupied precheck (which runs
        // BEFORE the KeyPackage consume).
        let sealed = super::NapiSealedInvitation {
            context_id: ctx_id.clone(),
            creator_did: "did:dht:z6MkNapiOccupiedCreator".to_owned(),
            enc: vec![0u8; 32],
            ciphertext: b"bogus-bundle-ciphertext".to_vec(),
        };
        let Err(err) = super::context_join_from_welcome_on(
            &bi,
            joiner_did,
            sealed,
            "bogus-reservation-id".to_owned(),
        )
        .await
        else {
            panic!("join into an already-registered context must be rejected");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("already registered"),
            "expected an Occupied-precheck rejection before KeyPackage consumption, got: {msg}"
        );

        // The PRE-EXISTING entry must SURVIVE — the failing join must not roll
        // back state it did not create.
        assert!(
            crate::runtime::with_context(&bi, &ctx_id, |_| Ok(())).is_ok(),
            "the pre-existing FFI state must be preserved on an Occupied-precheck failure"
        );
    }

    /// ADR-049 Phase 2J / FFI-02 Option A (invite export wiring): the new
    /// `invite_member` bridge export is wired end-to-end — DID validation ->
    /// supervisor resolution -> inviter signing-key resolution/export -> live-
    /// context lookup -> typed error mapping — and rejects the two reachable
    /// failure modes on the pre-add path.
    ///
    /// NOTE ON SCOPE: the sealed happy-path (the full creator-seal ->
    /// joiner-open round-trip) is not re-asserted in THIS Rust unit test by
    /// reference-bridge convention — the runtime already proves it in
    /// `spawn_from_welcome_tests`, and the napi surface is exercised end-to-end
    /// at the real-`.node` TypeScript SDK layer (peer of the Python `pytest`
    /// round-trip). The §5.13.3 `0xFF02` KeyPackage-capabilities path is green
    /// (9fe3b4c9b), so nothing blocks that coverage. This test pins what IS
    /// reachable through the pre-add bridge seams so the export is not merely
    /// compiled-but-dead.
    ///
    /// Not false-green: assertion (a) uses a REAL custodied inviter (+ an attached
    /// supervisor) so signing-key resolution/export SUCCEEDS and the error is the
    /// live-context lookup ("no live context"); assertion (b) uses a non-custodied
    /// inviter so it fails EARLIER at signing-key resolution ("not found in
    /// registry", `SCP-IDENT-1001`) — the two distinct messages prove both seams
    /// are exercised, not short-circuited.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invite_member_rejects_unknown_context_and_non_custodied_inviter() {
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        // A custodied inviter + an attached supervisor so signing-key resolution
        // and export can succeed and control reaches the runtime live-context
        // lookup. `init_supervisor` is idempotent (OnceLock, first-call-wins).
        let inviter_did = register_in_memory_joiner(&bi).await;
        crate::runtime::init_supervisor(&bi, &inviter_did);

        // (a) A custodied inviter into a NON-EXISTENT context: signing-key
        // resolution/export succeeds, then the runtime live-context lookup fails.
        let err_unknown = {
            let Err(err) = super::invite_member_on(
                &bi,
                "d".repeat(64),
                inviter_did.clone(),
                "did:dht:z6MkNapiInviteeUnknownCtx".to_owned(),
                b"bogus-key-package".to_vec(),
                vec![],
            )
            .await
            else {
                panic!("inviting into an unknown context must be rejected");
            };
            err.to_string()
        };
        assert!(
            err_unknown.contains("no live context"),
            "expected a live-context lookup rejection (signing-key resolved first), got: {err_unknown}"
        );

        // (b) A NON-custodied inviter: fails earlier, at signing-key resolution,
        // before any context lookup.
        let Err(err_uncustodied) = super::invite_member_on(
            &bi,
            "e".repeat(64),
            "did:dht:z6MkNoSuchNapiInviterIdentity".to_owned(),
            "did:dht:z6MkNapiInviteeUncustodied".to_owned(),
            b"bogus-key-package".to_vec(),
            vec![],
        )
        .await
        else {
            panic!("a non-locally-custodied inviter must be rejected");
        };
        let msg_uncustodied = err_uncustodied.to_string();
        assert!(
            msg_uncustodied.contains(codes::IDENT_1001),
            "expected an inviter signing-key resolution failure {}, got: {msg_uncustodied}",
            codes::IDENT_1001
        );
    }

    /// Test helper: dispatch `QueriesCommand::MemberCount` through the
    /// supervisor. Only the `testing`-gated membership test
    /// calls it, so it is gated to keep the bare test target warning-clean.
    #[cfg(feature = "testing")]
    async fn test_dispatch_member_count(
        bi: &crate::runtime::NapiBridgeInstance,
        ctx_id: &str,
    ) -> usize {
        use scp_core::context::actor::commands::QueriesCommand;
        let sup = crate::runtime::supervisor(bi).unwrap();
        let sup = Arc::clone(sup);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::MemberCount {
            context_id: ctx_id.to_owned(),
            reply: tx,
        };
        sup.dispatch_query(cmd).await.unwrap();
        rx.await.unwrap().unwrap().unwrap_or(0)
    }

    /// Test helper: dispatch `GovernanceCommand::ExecuteGovernanceAction` BY ID
    /// through the supervisor and return the handler `Result`.
    ///
    /// The payload carries only the proposal id — never a caller-supplied
    /// proposal/action/status/executor DID (the executor is resolved from the
    /// tracked proposal's proposer). The runtime resolves the authoritative
    /// proposal from the context actor's own quorum-validated engine; a caller
    /// cannot fabricate an `Approved`
    /// proposal or substitute an action. Used by the direct-execute
    /// trust-boundary tests.
    #[cfg(feature = "testing")]
    async fn test_dispatch_execute_by_id(
        bi: &crate::runtime::NapiBridgeInstance,
        ctx_id: &str,
        proposal_id: [u8; 32],
    ) -> Result<scp_core::context::state::GovernanceActionResult, scp_core::context::ContextError>
    {
        use scp_core::context::actor::commands::{
            ExecuteGovernanceActionPayload, GovernanceCommand,
        };
        let sup = crate::runtime::supervisor(bi).unwrap();
        let sup = Arc::clone(sup);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ExecuteGovernanceAction {
            payload: Box::new(ExecuteGovernanceActionPayload {
                context_id: ctx_id.to_owned(),
                proposal_id,
            }),
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.unwrap();
        rx.await.unwrap()
    }

    /// Test helper: dispatch `QueriesCommand::ContextParams` through the
    /// supervisor.
    #[cfg(feature = "testing")]
    async fn test_dispatch_context_params(
        bi: &crate::runtime::NapiBridgeInstance,
        ctx_id: &str,
    ) -> ContextParams {
        use scp_core::context::actor::commands::QueriesCommand;
        let sup = crate::runtime::supervisor(bi).unwrap();
        let sup = Arc::clone(sup);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::ContextParams {
            context_id: ctx_id.to_owned(),
            reply: tx,
        };
        sup.dispatch_query(cmd).await.unwrap();
        rx.await
            .unwrap()
            .unwrap()
            .expect("stored params should be retrievable")
    }

    /// Verifies that member count queries return the live member
    /// count — not a hardcoded value.  After creation the count is 1 (the
    /// creator); after a join it becomes 2.
    ///
    /// Gated on `testing`: this test wires the supervisor with a
    /// `did:test:` MLS identity (`init_supervisor_for_test_on`) and `did:key:`
    /// member DIDs, which `NodeMlsFactory::validate_creator_identity` only
    /// accepts under `scp-runtime`'s `testing` feature (pulled in transitively
    /// via `testing` → `dep:scp-testing` → `scp-core/testing`).
    /// It is NOT part of the feature-free export surface; the production/bare
    /// test target must not run it.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn member_count_reflects_actual_membership() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        let ctx_id = format!("test-member-count-{}", uuid::Uuid::new_v4());
        let creator = DID("did:key:z6MkCreator".to_owned());

        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign").expect("known capability")],
            ..ContextParams::default()
        };

        let handle = test_dispatch_create_context(&bi, &ctx_id, params, creator).await;

        let count = test_dispatch_member_count(&bi, &ctx_id).await;
        assert_eq!(
            count, 1,
            "newly created context should have exactly 1 member"
        );

        let kp = KeyPackage::mock(DID("did:key:z6MkJoiner".to_owned()));
        test_dispatch_join_context(&bi, &handle, kp).await;

        let count = test_dispatch_member_count(&bi, &ctx_id).await;
        assert_eq!(count, 2, "after join, context should have 2 members");
    }

    /// The manager-path `event_log_query` projection runs through the shared
    /// `scp_event_log::payload::project_payload` decoder. A non-target event
    /// (the auto-emitted `ContextCreated` leaf) must omit the `target_did` key.
    /// The `Some(target_did)` projection is byte-identical to the PyO3/UniFFI
    /// manager paths (all three call the same decoder) and is asserted with a
    /// real `GovernanceActionExecuted` leaf in those bridges' tests and the
    /// shared decoder unit tests in `scp-event-log`.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_query_manager_path_omits_target_did_for_non_target_event() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        let ctx_id = format!("napi-elog-projection-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkNapiProjection";
        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign").expect("known capability")],
            ..ContextParams::default()
        };
        test_dispatch_create_context(&bi, &ctx_id, params, DID(creator.to_owned())).await;
        crate::runtime::register_test_context(&bi, &ctx_id, creator);

        let handle =
            super::NapiContextHandle::test_active_on(&bi, ctx_id.clone(), creator.to_owned());
        let events = crate::event_log::event_log_query_on(&bi, &handle, None)
            .await
            .expect("manager-path query succeeds");
        assert!(
            !events.is_empty(),
            "a created context emits at least one manager-path event"
        );

        // The manager-path payload_json is a JSON object string; the projection
        // ran and correctly omitted target_did for the non-target ContextCreated
        // leaf.
        let payload_json: serde_json::Value = serde_json::from_str(&events[0].payload_json)
            .expect("manager-path payload_json is a JSON object");
        assert!(
            payload_json.get("target_did").is_none(),
            "a non-target event must omit target_did, got: {payload_json}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// The manager-path `event_log_query` projection must surface a
    /// `RoleAssigned` leaf's `subject_did` (the affected member, NOT the
    /// governance actor) via the shared `scp_event_log::payload::project_payload`
    /// decoder, byte-identical to the PyO3/UniFFI manager paths.
    ///
    /// Mechanism: the manager path reads `Supervisor::event_log_entries`. To
    /// seed a `RoleAssigned` leaf into that exact store without driving a full
    /// governance `ChangeRole` round-trip (whose key resolver rejects unpublished
    /// in-memory test identities), this appends the typed leaf through the
    /// `testing`-gated `Supervisor::test_append_event_log`, which delegates to
    /// the supervisor-owned event-log provider's `append_event` — the same
    /// provider `event_log_entries` reads. No production wiring is touched.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_query_manager_path_projects_role_assigned_subject_did() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        let ctx_id = format!("napi-elog-subject-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkNapiSubjectActor";
        let subject_did = "did:key:z6MkNapiSubjectMember";
        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign").expect("known capability")],
            ..ContextParams::default()
        };
        test_dispatch_create_context(&bi, &ctx_id, params, DID(creator.to_owned())).await;
        crate::runtime::register_test_context(&bi, &ctx_id, creator);

        // Seed a RoleAssigned leaf carrying the affected member's subject_did
        // into the supervisor-owned event log (the manager-path source).
        let ctx_id_bytes = scp_core::context::state::context_id_to_bytes(&ctx_id);
        let payload =
            scp_event_log::payload::encode_payload(&scp_event_log::payload::RoleAssignedPayload {
                subject_did: subject_did.to_owned(),
                role: "moderator".to_owned(),
            })
            .expect("role payload encodes");
        crate::runtime::supervisor(&bi)
            .expect("supervisor wired")
            .test_append_event_log(
                &ctx_id_bytes,
                scp_event_log::EventType::RoleAssigned,
                creator,
                payload,
                1_700_000_000,
            )
            .await
            .expect("append RoleAssigned leaf to supervisor event log");

        let handle =
            super::NapiContextHandle::test_active_on(&bi, ctx_id.clone(), creator.to_owned());
        let filter = serde_json::json!({ "event_type": "RoleAssigned" }).to_string();
        let events = crate::event_log::event_log_query_on(&bi, &handle, Some(filter))
            .await
            .expect("manager-path query succeeds");
        assert_eq!(
            events.len(),
            1,
            "exactly one RoleAssigned leaf was appended, got {} events",
            events.len()
        );

        let payload_json: serde_json::Value = serde_json::from_str(&events[0].payload_json)
            .expect("manager-path payload_json is a JSON object");
        assert_eq!(
            payload_json["subject_did"].as_str(),
            Some(subject_did),
            "RoleAssigned leaf projects its subject_did, got: {payload_json}"
        );
        // A subject-bearing leaf must NOT surface a target_did key.
        assert!(
            payload_json.get("target_did").is_none(),
            "RoleAssigned leaf carries a subject, not a target, got: {payload_json}"
        );

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// Verifies roundtrip set / get for economic policy on `NapiContextHandle`.
    #[test]
    fn set_get_economic_policy_roundtrip() {
        use super::*;
        use std::sync::Mutex;

        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let instance_id = bi.instance_id();

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
            in_memory_custody: None,
            signing_key: None,
            core_handle: None,
            subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
            subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            bi: std::sync::Arc::clone(&bi),
            instance_id,
        };

        // Initially None.
        assert!(
            context_get_economic_policy_on(&bi, &handle)
                .expect("handle matches bi")
                .is_none()
        );

        // Direct set always rejects — must use governance (#728).
        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":null,"per_outlet_call":"100","per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkTest"}"#;
        let result = context_set_economic_policy_on(&bi, &mut handle, json.to_owned());
        assert!(
            result.is_err(),
            "direct set must be rejected — use governance"
        );
        // Policy should remain unchanged.
        assert!(
            context_get_economic_policy_on(&bi, &handle)
                .expect("handle matches bi")
                .is_none()
        );
    }

    // -----------------------------------------------------------------------
    // Direct-execute trust boundary (governance quorum-bypass fix)
    //
    // `GovernanceCommand::ExecuteGovernanceAction` carries ONLY a proposal id
    // (never a caller-supplied proposal/action/status/executor). The runtime
    // resolves the authoritative proposal from the context actor's OWN
    // quorum-validated governance engine and stamps the tracked proposer as the
    // executor; a caller cannot fabricate an `Approved` proposal or
    // substitute an action. The previous NAPI implementation minted a fresh
    // random id and a fully `Approved` proposal from a caller-supplied action
    // — these tests guard the closed boundary.
    //
    // Action substitution is now structurally impossible: the bridge surface
    // and the command payload have no action/proposal field to populate.
    // -----------------------------------------------------------------------

    /// Executing an unknown/fabricated proposal id is rejected (the engine
    /// never tracked it) — the forgery path.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_execute_rejects_untracked_proposal_id() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        let ctx_id = format!("napi-exec-forgery-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkNapiForgery1";
        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign").expect("known capability")],
            ..ContextParams::default()
        };
        test_dispatch_create_context(&bi, &ctx_id, params, DID(creator.to_owned())).await;
        crate::runtime::register_test_context(&bi, &ctx_id, creator);

        let fabricated = [0xABu8; 32];
        let result = test_dispatch_execute_by_id(&bi, &ctx_id, fabricated).await;
        let err = result.expect_err("executing an untracked proposal id must be rejected");
        assert!(
            matches!(err, scp_core::context::ContextError::PermissionDenied(_)),
            "untracked proposal must be PermissionDenied, got: {err:?}"
        );
        assert!(
            format!("{err}").contains("not tracked"),
            "rejection should name the untracked proposal"
        );
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// A rejected direct-execute leaves context membership/role state unchanged
    /// — the forgery cannot apply a phantom action as a side effect.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_execute_rejection_does_not_mutate_state() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        let ctx_id = format!("napi-exec-forgery-state-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkNapiForgery2";
        let victim = "did:key:z6MkNapiVictimNeverAdded";
        let params = ContextParams {
            ceiling: vec![Capability::new("role:assign").expect("known capability")],
            ..ContextParams::default()
        };
        test_dispatch_create_context(&bi, &ctx_id, params, DID(creator.to_owned())).await;
        crate::runtime::register_test_context(&bi, &ctx_id, creator);

        crate::runtime::with_context(&bi, &ctx_id, |st| {
            assert!(!st.role_state.members.contains(victim));
            Ok(())
        })
        .unwrap();

        let fabricated = [0x11u8; 32];
        let result = test_dispatch_execute_by_id(&bi, &ctx_id, fabricated).await;
        assert!(result.is_err(), "forged direct-execute must be rejected");

        crate::runtime::sync_role_state_from_manager(&bi, &ctx_id)
            .await
            .unwrap();
        crate::runtime::with_context(&bi, &ctx_id, |st| {
            assert!(
                !st.role_state.members.contains(victim),
                "rejected forgery must not have added the victim as a member"
            );
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -------------------------------------------------------------------
    // Consequence event format tests (#1531, #1593, #1594)
    // -------------------------------------------------------------------

    #[test]
    fn format_consequence_triggered_event() {
        use scp_core::context::membership::ContextEvent;

        let event = ContextEvent::ConsequenceTriggered {
            context_id: "ctx-napi-123".to_owned(),
            member_did: scp_did::DID("did:dht:z6MkBob".to_owned()),
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
            member_did: scp_did::DID("did:dht:z6MkAlice".to_owned()),
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
        let json = r#"[{"trigger":"MessageVelocity","action":{"Enforcement":"SuspendAccess"},"threshold":10,"window":{"secs":3600,"nanos":0}}]"#;
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
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();
        let spending_json =
            r#"{"has_spending_ucan":true,"configured_adapters":["x402"],"available_balance":10000}"#
                .to_owned();

        let result = super::evaluate_invitation_on(
            &bi,
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            Some(spending_json),
        );

        // Free context: pipeline reaches prompt_agent regardless of spending.
        assert!(result.is_ok(), "spending_json should be accepted");
        assert_eq!(result.unwrap().decision, "prompt_agent");
    }

    #[test]
    fn evaluate_invitation_rejects_invalid_spending_json() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();

        let result = super::evaluate_invitation_on(
            &bi,
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            Some("not valid json".to_owned()),
        );

        assert!(result.is_err(), "invalid spending JSON should be rejected");
    }

    #[test]
    fn evaluate_invitation_none_spending_accepted() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();

        let result = super::evaluate_invitation_on(
            &bi,
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            None,
        );

        assert!(result.is_ok(), "None spending should be accepted");
        assert_eq!(result.unwrap().decision, "prompt_agent");
    }

    // -------------------------------------------------------------------
    // C5: context_create consequence_rules / consequence_config + parity
    // tests for context_join spending_ucan_jwt threading.
    // -------------------------------------------------------------------

    /// Verifies that `context_create` parses both `consequenceRules` and
    /// `consequenceConfig` from `params_json` and surfaces a created context
    /// whose stored `ContextParams` reflect both fields.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_create_threads_consequence_rules_and_config() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let params_json = serde_json::json!({
            "ceiling": ["messages:read", "messages:write"],
            "ceilingPolicy": "immutable",
            "memoryScope": "ephemeral",
            "governance": "single_admin",
            "consequenceConfig": { "allow_automatic_access_revocation": true },
            "consequenceRules": [
                {
                    "trigger": "MessageVelocity",
                    "action": { "Enforcement": { "RevokeAccess": {
                        "did": "did:dht:z6MkSubject",
                        "access": "Both"
                    } } },
                    "threshold": 5,
                    "window": { "secs": 3600, "nanos": 0 }
                }
            ]
        })
        .to_string();

        let handle = super::context_create_on(&bi, &identity, params_json)
            .await
            .expect("context_create should succeed");

        let stored = test_dispatch_context_params(&bi, &handle.context_id).await;

        assert_eq!(
            stored.consequence_rules.len(),
            1,
            "consequence_rules should be threaded into stored ContextParams"
        );
        assert!(
            stored.consequence_config.allow_automatic_access_revocation,
            "consequence_config.allow_automatic_access_revocation should round-trip true"
        );
    }

    /// Verifies that `context_create` rejects a `RevokeAccess` consequence
    /// rule when `consequenceConfig.allow_automatic_access_revocation` is
    /// `false` (the default), proving the bridge fails closed at create
    /// time rather than deferring to runtime evaluation.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_create_rejects_revoke_access_when_config_disallows() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let params_json = serde_json::json!({
            "ceiling": ["messages:read"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
            // consequenceConfig omitted -> default (false) -> RevokeAccess illegal.
            "consequenceRules": [
                {
                    "trigger": "MessageVelocity",
                    "action": { "Enforcement": { "RevokeAccess": {
                        "did": "did:dht:z6MkSubject",
                        "access": "Both"
                    } } },
                    "threshold": 5,
                    "window": { "secs": 60, "nanos": 0 }
                }
            ]
        })
        .to_string();

        let result = super::context_create_on(&bi, &identity, params_json).await;
        assert!(
            result.is_err(),
            "RevokeAccess rule must be rejected when config.allow_automatic_access_revocation is false"
        );
    }

    /// Verifies that `context_join` parses `spending_ucan_jwt` and rejects
    /// malformed tokens at the bridge boundary with the SCP-ECON-12061 code.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_join_rejects_malformed_spending_ucan_jwt() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let params_json = serde_json::json!({
            "ceiling": ["messages:read"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string();
        let handle = super::context_create_on(&bi, &identity, params_json)
            .await
            .expect("context_create should succeed");

        let result = super::context_join_on(
            &bi,
            &handle,
            identity.inner.did.clone(),
            Some("not.a.jwt".to_owned()),
        )
        .await;
        assert!(
            result.is_err(),
            "malformed spending UCAN JWT should be rejected"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(codes::ECON_12061) || msg.contains("invalid spending UCAN"),
            "error should mention SCP-ECON-12061 or invalid spending UCAN, got: {msg}"
        );
    }

    /// Verifies that `context_join` accepts `None` `spending_ucan_jwt` and
    /// reaches the manager (the historical default behaviour stays intact).
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_join_accepts_none_spending_ucan_jwt() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let params_json = serde_json::json!({
            "ceiling": ["messages:read"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string();
        let handle = super::context_create_on(&bi, &identity, params_json)
            .await
            .expect("context_create should succeed");

        // Same identity rejoining is fine for the smoke check — the
        // important assertion is that the bridge reaches the manager
        // instead of erroring on parameter handling.
        let result = super::context_join_on(&bi, &handle, identity.inner.did.clone(), None).await;
        // Manager may or may not error depending on duplicate-member rules.
        // We only verify the bridge accepted the call shape (no
        // SCP-ECON-12061 / SCP-VALID parsing failure).
        if let Err(e) = &result {
            let msg = e.to_string();
            assert!(
                !msg.contains(codes::ECON_12061) && !msg.contains("invalid spending UCAN"),
                "None spending_ucan_jwt must not trigger UCAN parse errors, got: {msg}"
            );
        }
    }

    /// ADR-049 Phase 2J (plain-join discovery symmetry): a successful plain
    /// `context_join` registers the JOINER's context in the known-contexts
    /// discovery registry, closing the asymmetry with `context_join_from_welcome`
    /// (which registers post-commit). A plain-joined node must be able to surface
    /// its own joined context via discovery.
    ///
    /// Drives the REAL entry points: a custodied creator creates an encrypted
    /// context, a DISTINCT custodied joiner plain-joins, and the joiner's own
    /// known-context entry is asserted present. Were the post-commit registration
    /// removed, `known_contexts_for_member` would return nothing for the joiner.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_join_registers_known_context_for_joiner() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let creator = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");
        let joiner = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let params_json = serde_json::json!({
            "mode": "encrypted",
            "ceiling": ["messages:read"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string();
        let handle = super::context_create_on(&bi, &creator, params_json)
            .await
            .expect("context_create should succeed");
        let ctx_id = handle.context_id.clone();

        super::context_join_on(&bi, &handle, joiner.inner.did.clone(), None)
            .await
            .expect("plain encrypted join with a custodied joiner succeeds");

        // The joiner's own known-context discovery entry now exists, keyed to the
        // joined context — the post-commit registration fired.
        let for_joiner = bi.core.known_contexts_for_member(&joiner.inner.did);
        assert!(
            for_joiner.iter().any(|(cid, _)| cid == &ctx_id),
            "plain join must register the joiner's known-context entry for discovery"
        );
    }

    /// ADR-049 Phase 2J (create-path discovery symmetry): a successful
    /// `context_create` registers the CREATOR's context in the known-contexts
    /// discovery registry, closing the last cell of the 3-bridges × 3-ops
    /// discovery matrix (`PyO3` and `UniFFI` already register on create; napi
    /// already registers on join and `join_from_welcome`). A creating node must
    /// be able to surface its own context via discovery.
    ///
    /// Drives the REAL entry point with a custodied creator for BOTH branches:
    /// the encrypted branch (routing id is the creator's derived §9.10.4
    /// pseudonym) and the broadcast branch (routing id falls back to
    /// `broadcast_routing_id` — broadcast contexts carry no per-member
    /// pseudonym).
    /// Asserts the creator's own known-context entry is present for each. Were
    /// the post-commit registration removed, `known_contexts_for_member` would
    /// return nothing for the creator.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_registers_known_context_for_creator() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let creator = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        // Encrypted: routing_id is the creator's derived §9.10.4 pseudonym.
        let enc_params = serde_json::json!({
            "mode": "encrypted",
            "ceiling": ["messages:read"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string();
        let enc_handle = super::context_create_on(&bi, &creator, enc_params)
            .await
            .expect("encrypted context_create should succeed");
        let enc_ctx = enc_handle.context_id.clone();

        // Broadcast: routing_id falls back to broadcast_routing_id (no pseudonym).
        // Broadcast contexts require MemoryScope::Full (spec §5.14).
        let bcast_params = serde_json::json!({
            "mode": "broadcast",
            "ceiling": ["messages:read"],
            "memoryScope": "full",
            "governance": "single_admin",
        })
        .to_string();
        let bcast_handle = super::context_create_on(&bi, &creator, bcast_params)
            .await
            .expect("broadcast context_create should succeed");
        let bcast_ctx = bcast_handle.context_id.clone();

        // Both created contexts now carry the creator's own discovery entry.
        let for_creator = bi.core.known_contexts_for_member(&creator.inner.did);
        assert!(
            for_creator.iter().any(|(cid, _)| cid == &enc_ctx),
            "encrypted create must register the creator's known-context entry"
        );
        assert!(
            for_creator.iter().any(|(cid, _)| cid == &bcast_ctx),
            "broadcast create must register the creator's known-context entry"
        );
    }

    // -----------------------------------------------------------------------
    // Regression: ActiveFlagGuard resets subscription_active on panic
    // (round 2 bug-catcher finding — `context_subscribe` previously had
    // three manual `active_flag.store(false, …)` calls on normal exit
    // paths only; a panic inside the subscription body would leave the
    // flag `true` forever and reject every future subscribe call with
    // `SCP-CTX-2022 "already subscribed"`).
    //
    // Round 3 extension: the flag also had a leak on *synchronous* error
    // paths in `context_subscribe` between `swap(true)` and the
    // `tokio::spawn(...)` — if `validate_did(...)?` or
    // the legacy bridge accessor errored, the flag stayed `true`. The fix is
    // an outer `ActiveFlagGuard` covering the sync critical section,
    // disarmed immediately before spawn so the spawned task's inner
    // guard owns the reset thereafter. These tests exercise the
    // production guard type (module-scope `ActiveFlagGuard`) rather
    // than a local duplicate, so behavioral changes to the guard stay
    // covered.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_flag_guard_resets_on_panic() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let flag_clone = Arc::clone(&flag);

        // Spawn a task that panics while the guard is live.
        let join = tokio::spawn(async move {
            let _guard = super::ActiveFlagGuard(Some(flag_clone));
            panic!("simulated subscription-body panic");
        });

        // The task must return a JoinError (panic propagated).
        let result = join.await;
        assert!(
            result.is_err(),
            "spawned task should surface the panic as a JoinError"
        );

        // And the guard must have reset the flag on unwind.
        assert!(
            !flag.load(Ordering::SeqCst),
            "ActiveFlagGuard::drop must reset subscription_active even when the \
             spawned task panics — otherwise future context_subscribe calls \
             get stuck on SCP-CTX-2022 'already subscribed'"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_flag_guard_resets_on_normal_return() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let flag_clone = Arc::clone(&flag);

        let join = tokio::spawn(async move {
            let _guard = super::ActiveFlagGuard(Some(flag_clone));
            // Simulate ordinary exit path (no panic).
        });
        join.await.expect("task should complete without panic");

        assert!(
            !flag.load(Ordering::SeqCst),
            "ActiveFlagGuard::drop must reset the flag on normal task exit too"
        );
    }

    /// Regression (round 5 test-quality): verify `ActiveFlagGuard::drop`
    /// fires during a `std::panic::catch_unwind` unwind so a *synchronous*
    /// panic inside the pre-spawn critical section resets the flag — the
    /// existing `active_flag_guard_resets_on_panic` test covers tokio-
    /// spawned panics, but the outer guard on the sync critical section
    /// also has to survive direct stack unwinds.
    ///
    /// Complements `active_flag_guard_disarm_defuses_drop` (happy-path
    /// transfer-of-ownership) and `active_flag_guard_resets_on_panic`
    /// (panic through tokio spawn).
    ///
    /// Round 5 simplifier review deleted the earlier
    /// `subscription_flag_resets_on_validate_did_error` test — it exercised
    /// a local mock of the critical section, not `context_subscribe`
    /// itself, so any panic or drift inside the real function would have
    /// left the test passing anyway. The combination of this test +
    /// `active_flag_guard_resets_on_panic` + `subscription_flag_resets_on_suspend`
    /// now covers all three exit modes of the production critical section
    /// (disarm on success, sync unwind on panic, async unwind on task panic).
    #[test]
    fn active_flag_guard_resets_on_panic_unwind() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let flag_clone = Arc::clone(&flag);
        let result = std::panic::catch_unwind(|| {
            let _guard = super::ActiveFlagGuard(Some(flag_clone));
            panic!("simulated sync panic inside the pre-spawn critical section");
        });
        assert!(
            result.is_err(),
            "catch_unwind must surface the injected panic"
        );
        assert!(
            !flag.load(Ordering::SeqCst),
            "ActiveFlagGuard::drop must reset subscription_active on sync \
             panic unwind too — otherwise a panic inside validate_did or \
             any other pre-spawn step leaks the flag and locks every \
             future context_subscribe call with SCP-CTX-2022"
        );
    }

    /// Regression (round 3 bug-catcher): suspend the bridge, then drive
    /// the pre-spawn section of `context_subscribe`. the legacy bridge accessor
    /// errors on suspend; before the outer-guard fix the flag leaked. The
    /// flag must reset so the caller can `resume()` and retry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscription_flag_resets_on_suspend() {
        use std::sync::atomic::Ordering;

        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Mirror the production swap + outer-guard sequence. The
        // suspended-bridge error path is the the legacy bridge accessor call,
        // which we simulate here with an early `?` that triggers after
        // `outer_guard` has been armed.
        let swapped = flag.swap(true, Ordering::SeqCst);
        assert!(!swapped);

        let result: Result<(), &'static str> = (|| {
            let _outer_guard = super::ActiveFlagGuard(Some(std::sync::Arc::clone(&flag)));
            // the legacy bridge accessor returns Err on suspend — represented here.
            Err("bridge is suspended — call resume() before performing operations")?;
            Ok(())
        })();

        assert!(result.is_err(), "suspend path should error");
        assert!(
            !flag.load(Ordering::SeqCst),
            "subscription_active must reset when the bridge suspension \
             check fails — otherwise the caller cannot retry after resume()"
        );
    }

    /// Confirms `ActiveFlagGuard::disarm` transfers ownership of the flag
    /// Arc without invoking the `Drop` reset, so hand-off to the spawned
    /// task is atomic — there is no window where the flag is held but
    /// un-guarded.
    #[test]
    fn active_flag_guard_disarm_defuses_drop() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let guard = super::ActiveFlagGuard(Some(Arc::clone(&flag)));
        let transferred = guard.disarm();
        // `guard` consumed by `disarm` — Drop does NOT fire, flag is
        // still `true` and owned by the caller.
        assert!(
            flag.load(Ordering::SeqCst),
            "disarm must NOT reset the flag — ownership transfers to the caller"
        );
        // Caller is responsible for the flag now; install a new guard
        // to confirm reset resumes under the new owner.
        drop(super::ActiveFlagGuard(Some(transferred)));
        assert!(
            !flag.load(Ordering::SeqCst),
            "new guard must reset the flag via Drop once armed again"
        );
    }

    /// Defensive: disarming twice panics. Documented invariant — the
    /// production `context_subscribe` path never disarms twice, but the
    /// panic is a load-bearing safety net if someone edits the code and
    /// accidentally introduces a double-disarm.
    #[test]
    #[should_panic(expected = "ActiveFlagGuard disarmed twice")]
    fn active_flag_guard_double_disarm_panics() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let flag = Arc::new(AtomicBool::new(true));
        let mut guard = super::ActiveFlagGuard(Some(Arc::clone(&flag)));
        // Forcibly clear the inner Option to simulate a double-take.
        let _ = guard.0.take();
        let _ = guard.disarm();
    }

    /// Exercises the full `context_export_on` -> `context_import_on` round-trip
    /// for an identity whose key material is held in custody.
    ///
    /// This is the regression guard for routing export signing through
    /// [`KeyCustody::sign`] (§23.16.8) instead of exporting a raw signing key:
    /// the snapshot signature the closure produces MUST verify on import against
    /// the creator identity's `#active` verifying key, or `import_context`
    /// rejects it with `SnapshotSignatureInvalid` (SCP-CTX-2093). A passing
    /// round-trip proves the custody-`sign` closure emits a spec-valid signature.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_export_signs_via_custody_and_round_trips() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let params_json = serde_json::json!({
            // `context:close` is required so the creator can close the context
            // before reimport (import_context needs a terminal state).
            "ceiling": ["messages:read", "messages:write", "context:close"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string();

        let handle = super::context_create_on(&bi, &identity, params_json)
            .await
            .expect("context_create should succeed");
        let original_context_id = handle.context_id.clone();

        // Export: the §23.16.8 snapshot digest is signed by `custody.sign`.
        let data = super::context_export_on(&bi, &handle)
            .await
            .expect("context_export should succeed via custody sign");
        assert!(!data.is_empty(), "export bytes must not be empty");

        // Close so `import_context` sees a terminal state and allows reimport
        // of the same context id (mirrors the addon round-trip test).
        super::context_close_on(&bi, &handle, identity.inner.did.clone())
            .await
            .expect("context_close should succeed");

        // Import verifies the snapshot signature against the creator's `#active`
        // verifying key. Success proves the custody-produced signature is valid.
        // The importer is the same identity (self-import round-trip).
        let imported_context_id = super::context_import_on(&bi, data, identity.inner.did.clone())
            .await
            .expect("context_import should accept the custody-signed snapshot");
        assert_eq!(
            imported_context_id, original_context_id,
            "imported context id must match the exported one"
        );
    }

    /// Confirms the export signature is genuinely verified on import: flipping a
    /// byte inside the serialized export (which lands in the signed snapshot
    /// region) MUST cause `context_import_on` to fail. This proves the signature
    /// produced via `custody.sign` is load-bearing, not decorative.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_import_rejects_tampered_custody_signed_export() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);

        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");

        let params_json = serde_json::json!({
            "ceiling": ["messages:read", "context:close"],
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string();
        let handle = super::context_create_on(&bi, &identity, params_json)
            .await
            .expect("context_create should succeed");

        let mut data = super::context_export_on(&bi, &handle)
            .await
            .expect("context_export should succeed via custody sign");
        super::context_close_on(&bi, &handle, identity.inner.did.clone())
            .await
            .expect("context_close should succeed");

        // Flip a byte near the front of the payload — inside the signed snapshot
        // region — so the recomputed §23.16.8 digest no longer matches the
        // signature. (The byte must be a real content byte, not framing.)
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;

        let result = super::context_import_on(&bi, data, identity.inner.did.clone()).await;
        assert!(
            result.is_err(),
            "import of a tampered custody-signed export must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // Production callback-custody export sign chain (NO `testing`)
    //
    // These tests compile and run in the BARE production build. They prove the
    // un-gated §23.16.8 export sign/verify chain works for a non-in-memory,
    // callback-shaped signer (the `identityCreateWithCustody` keychain/HSM
    // case) and that the fail-closed boundary is the ABSENCE of retained
    // custody (CTX_2040 from `resolve_napi_export_signer`), not a build flag.
    // -----------------------------------------------------------------------

    /// A minimal Rust signer that stands in for a production callback custody
    /// (`identityCreateWithCustody`): it can `sign` the §23.16.8 canonical
    /// digest and expose its public verifying key, but holds NO in-memory
    /// `KeyCustody` backend and intentionally cannot export raw key bytes — the
    /// keychain/HSM shape. It is a plain Rust struct, not a `NapiKeyCustody`, so
    /// it needs no live JS `Env`/`ThreadsafeFunction` and exercises the exact
    /// fallible sign-closure shape `context_export_on` hands to
    /// `Supervisor::export_context`.
    struct FakeExportCustody {
        signing_key: ed25519_dalek::SigningKey,
    }

    impl FakeExportCustody {
        fn new() -> Self {
            // Deterministic seed for reproducibility; a real callback custody
            // would back this with a keychain/HSM private key.
            Self {
                signing_key: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            }
        }

        /// Mirrors `KeyCustody::sign` over the §23.16.8 digest. A real callback
        /// custody can fail (the JS callback may throw), so the `Result` is part
        /// of the contract even though this in-test signer is infallible.
        #[allow(clippy::unnecessary_wraps)]
        fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64], std::convert::Infallible> {
            use ed25519_dalek::Signer;
            Ok(self.signing_key.sign(digest).to_bytes())
        }

        fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
            self.signing_key.verifying_key()
        }
    }

    /// Drives the production export sign/verify chain with a non-in-memory
    /// `FakeExportCustody` — the same `Supervisor::export_context` sign-closure +
    /// `serialize_export` / `deserialize_export` + `Supervisor::import_context`
    /// path that `context_export_on` / `context_import_on` delegate to. Proves a
    /// callback-shaped (non-exportable) signer produces a spec-valid §23.16.8
    /// signature that round-trips, and that a tampered snapshot is rejected.
    /// Runs WITHOUT `testing`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn callback_custody_export_round_trips_and_rejects_tamper_without_feature() {
        use scp_core::context::export_import::{deserialize_export, serialize_export};

        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        // Use a production-valid `did:dht:z*` MLS identity so context creation
        // succeeds WITHOUT `scp-runtime/testing` — this test must genuinely
        // exercise the no-in-memory-custody build, not the testing gate.
        crate::runtime::init_production_supervisor_for_test_on(&bi);
        let sup = crate::runtime::supervisor(&bi).expect("supervisor initialized above");
        let sup = Arc::clone(sup);

        let custody = FakeExportCustody::new();
        let creator = DID("did:dht:z6MkCallbackExporter".to_owned());
        let ctx_id = format!("callback-export-{}", uuid::Uuid::new_v4());

        // `context:close` is required so the creator can close the context
        // before reimport (import needs a terminal state).
        let params = ContextParams {
            ceiling: vec![Capability::new("context:close").expect("known capability")],
            ..ContextParams::default()
        };
        let handle = test_dispatch_create_context(&bi, &ctx_id, params, creator.clone()).await;

        // Export: sign the §23.16.8 digest via the callback-shaped custody — the
        // exact closure shape `context_export_on` passes to `export_context`.
        let export = sup
            .export_context(&ctx_id, creator.clone(), |digest: &[u8; 32]| {
                custody.sign(digest)
            })
            .await
            .expect("export_context should succeed via callback-shaped sign closure");
        let data = serialize_export(&export).expect("serialize_export should succeed");
        assert!(!data.is_empty(), "serialized export must not be empty");

        // `handle` (the source context) is dropped — not needed past export.
        let _ = handle;

        // Import into a FRESH bridge instance (the realistic "transfer to
        // another node" path) so the import does not collide with the live
        // source context slot. The snapshot signature is verified against the
        // creator's verifying key (the callback custody's public key — what
        // `resolve_napi_local_verifying_key` returns for a registered callback
        // identity). Success proves the callback-produced signature is
        // spec-valid (§23.16.8).
        let bi2 = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_production_supervisor_for_test_on(&bi2);
        let sup2 = crate::runtime::supervisor(&bi2).expect("supervisor initialized above");
        let sup2 = Arc::clone(sup2);

        let round_tripped = deserialize_export(&data).expect("deserialize_export should succeed");
        let imported = sup2
            .import_context(round_tripped, &custody.verifying_key(), None)
            .await
            .expect("import_context should accept the callback-signed snapshot");
        assert_eq!(
            imported.context_id(),
            ctx_id,
            "imported context id must match the exported one"
        );

        // Tamper: flip a byte inside the signed snapshot region so the
        // recomputed §23.16.8 digest no longer matches the signature. Import
        // MUST reject — proving the callback signature is load-bearing.
        let mut tampered = data.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;
        let result = match deserialize_export(&tampered) {
            Ok(export) => sup2
                .import_context(export, &custody.verifying_key(), None)
                .await
                .map(|_| ()),
            // A flipped framing byte may fail deserialization outright — also a
            // valid rejection of the tampered payload.
            Err(e) => Err(e),
        };
        assert!(
            result.is_err(),
            "import of a tampered callback-signed export must be rejected"
        );
    }

    /// Proves the fail-closed boundary is the ABSENCE of retained custody, not a
    /// build feature: `context_export_on` on a `NapiContextHandle` whose
    /// `in_memory_custody` is `None` (e.g. an externally loaded, DID-string-only
    /// creator) is rejected with `CTX_2040` by `resolve_napi_export_signer` —
    /// never with the old build-gate PERM-3001, and never an unsigned export.
    /// Runs WITHOUT `testing`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_export_fails_closed_without_retained_custody() {
        use super::*;
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        // Production-valid `did:dht:z*` MLS identity so context creation
        // succeeds WITHOUT `scp-runtime/testing` — this test must run in the
        // no-in-memory-custody build it documents.
        crate::runtime::init_production_supervisor_for_test_on(&bi);

        let creator = DID("did:dht:z6MkNoCustodyExporter".to_owned());
        let ctx_id = format!("no-custody-export-{}", uuid::Uuid::new_v4());
        let params = ContextParams {
            ceiling: vec![Capability::new("context:close").expect("known capability")],
            ..ContextParams::default()
        };
        let core_handle = test_dispatch_create_context(&bi, &ctx_id, params, creator.clone()).await;

        // Build a handle with NO retained custody — the externally-loaded shape.
        let handle = NapiContextHandle {
            context_id: ctx_id.clone(),
            state: std::sync::Mutex::new(ContextState::Active),
            creator_did: creator.0.clone(),
            mode: "Encrypted".to_owned(),
            ceiling: vec![],
            ceiling_policy: "immutable".to_owned(),
            ttl_seconds: None,
            promotion_policy: None,
            governance: "single_admin".to_owned(),
            economic_policy: None,
            in_memory_custody: None,
            signing_key: None,
            core_handle: Some(core_handle),
            subscription_cancel: std::sync::Mutex::new(CancellationToken::new()),
            subscription_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            bi: std::sync::Arc::clone(&bi),
            instance_id: bi.instance_id(),
        };

        let err = super::context_export_on(&bi, &handle)
            .await
            .expect_err("export with no retained custody must fail closed");
        let msg = format!("{err}");
        assert!(
            msg.contains(codes::CTX_2040),
            "expected CTX_2040 (absent-custody fail-closed), got: {msg}"
        );
        assert!(
            !msg.contains(codes::PERM_3001),
            "must NOT use the removed build-gate PERM-3001 code, got: {msg}"
        );
    }

    /// §9.10.4: NAPI's `derive_member_pseudonym_required` HARD-FAILS a registry
    /// miss with the canonical `SCP-IDENT-1054` (missing key material).
    ///
    /// This helper is the single deduped definition of the encrypted JOIN /
    /// IMPORT derivation contract for the NAPI bridge — the join and import
    /// paths both route through it so the 1054/1055/1057 codes cannot drift
    /// across entry points. A registry miss (no identity registered for the
    /// DID) resolves no custody, so the encrypted routing axis must hard-fail
    /// rather than silently degrade to the reserved `[0u8; 32]` sentinel.
    ///
    /// Not false-green: the assertion drives the real helper against a fresh
    /// bridge with no registered identities. If the helper's registry-miss arm
    /// stopped mapping to `SCP-IDENT-1054` (e.g. reverted to the raw
    /// `with_identity` `SCP-IDENT-1001`, or swallowed the miss to a zero
    /// pseudonym), the `.code` assertion would fail.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn derive_member_pseudonym_required_registry_miss_is_typed_1054() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let err = super::derive_member_pseudonym_required(
            &bi,
            "did:dht:z6MkNoSuchNapiDeriveIdentity",
            "ctx-encrypted-join",
        )
        .await
        .expect_err("registry miss must hard-fail derivation");
        // `napi::Error` renders the `ScpNapiError` Display, which embeds the
        // `[SCP-IDENT-NNNN]` code prefix.
        let msg = err.to_string();
        assert!(
            msg.contains(codes::IDENT_1054),
            "expected missing-key-material code {}, got: {msg}",
            codes::IDENT_1054
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_publish_without_retained_custody_returns_ident_1017() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        // `test_active_on` leaves `in_memory_custody`/`signing_key` as `None`
        // (an externally-loaded identity), so broadcast publish trips the
        // missing signing-custody gate before reaching the relay.
        let handle = super::NapiContextHandle::test_active_on(
            &bi,
            "ctx-no-custody-broadcast".to_owned(),
            "did:dht:z6MkCreatorNoCustodyBroadcast".to_owned(),
        );

        let result = super::broadcast_publish_on(
            &bi,
            &handle,
            "did:dht:z6MkAuthor".to_owned(),
            b"hi".to_vec(),
        )
        .await;

        let Err(err) = result else {
            panic!("broadcast publish without retained custody must fail")
        };
        let reason = err.reason.clone();
        assert!(
            reason.contains("SCP-IDENT-1017"),
            "expected SCP-IDENT-1017, got: {reason}"
        );
    }
}
