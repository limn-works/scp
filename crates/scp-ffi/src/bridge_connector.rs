//! `PyO3` bridge functions for the bridge connector module.
//!
//! Exposes SCP bridge connector operations to Python. Stateful operations are
//! methods on the `SCP` class; pure helpers remain as free `#[pyfunction]` exports.
//!
//! Pure helpers (no bridge state):
//!
//! - [`py_bridge_register`] -- Register a bridge connector with a context.
//! - [`py_bridge_evaluate_trust`] -- Evaluate trust level for a bridge action.
//! - [`py_bridge_claim_shadow`] -- Claim a shadow identity via identity attestation.
//! - [`py_bridge_seal_shadow_envelope`] -- Seal a sender-key-encrypted envelope.
//! - [`py_bridge_open_shadow_envelope`] -- Open a sender-key-encrypted envelope.
//! - [`py_bridge_derive_credential_key`] -- Derive a per-bridge credential encryption key.
//! - [`py_bridge_generate_credential_key`] -- Generate a random bridge credential key.
//! - [`py_bridge_oauth_generate_pkce`] -- Generate a PKCE S256 challenge pair.
//! - [`py_bridge_oauth_build_auth_url`] -- Build an OAuth 2.0 authorization URL.
//! - [`py_bridge_oauth_scopes_for_mode`] -- Get recommended scopes for a bridge mode.
//!
//! `SCP` methods (bridge-state accessors):
//!
//! - [`PyScp::bridge_create_shadow`] -- Create a shadow identity (uses bridge_state).
//! - [`PyScp::bridge_credential_provision`] -- Provision (store) an encrypted credential.
//! - [`PyScp::bridge_credential_retrieve`] -- Retrieve and decrypt a credential.
//! - [`PyScp::bridge_credential_rotate`] -- Rotate (replace) a credential.
//! - [`PyScp::bridge_credential_revoke`] -- Revoke all credentials for a bridge.
//! - [`PyScp::bridge_credential_list`] -- List credential types for a bridge.
//! - [`PyScp::bridge_credential_store_key`] -- Store a bridge credential key.
//! - [`PyScp::bridge_credential_get_key`] -- Retrieve a bridge credential key.
//! - [`PyScp::bridge_credential_delete_key`] -- Delete a bridge credential key.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice E (#1549).
//!
//! See spec section 12 (Bridge System), section 12.11 (Credential Lifecycle),
//! and ADR-023.

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::runtime::PyBridgeInstance;

use scp_core::bridge::claiming::{ClaimRequest, claim_shadow};
use scp_core::bridge::credentials::{
    BridgeCredentialStore, CredentialType, InMemoryCredentialStore, derive_credential_key,
    generate_bridge_credential_key,
};
use scp_core::bridge::envelope::{
    SealShadowEnvelopeParams, open_shadow_envelope, seal_shadow_envelope,
};
use scp_core::bridge::oauth::{
    OAuthConfig, build_authorization_url, generate_pkce, scopes_for_mode,
};
use scp_core::bridge::provenance::{evaluate_trust_level, mark_bridge_provenance};
use scp_core::bridge::registration::{
    BridgeRegistrationMetadata, BridgeRegistrationRequest, BridgeRegistry, approve_registration,
    register_bridge,
};
use scp_core::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow};
use scp_core::bridge::{
    BridgeConnector, BridgeMode, BridgeStatus, ShadowIdentity, ShadowProvenanceStatus,
};
use scp_core::crypto::sender_keys::{SenderKey, SenderKeyStore};
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};
use scp_core::trust::attestation::Attestation;
use scp_ffi_common::bridge_state::BridgeContextState;
use zeroize::Zeroizing;

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Credential store — resolved via explicit PyBridgeInstance
// ---------------------------------------------------------------------------

/// Returns a reference to the given bridge instance's credential store.
///
/// Migrated from a process-global `OnceLock<InMemoryCredentialStore>` onto
/// the typed `credential_store` field on
/// [`crate::runtime::PyBridgeInstance`] in #1549 Phase 4 PR 2 commit 5.
///
/// The returned [`Arc<InMemoryCredentialStore>`] is the same instance the
/// `PyBridgeInstance` holds — `InMemoryCredentialStore` is thread-safe via
/// internal `tokio::sync::RwLock`. Production deployments should replace
/// this with a `Storage`-backed implementation when it lands (spec §12.11.2).
fn credential_store_for(bi: &PyBridgeInstance) -> &Arc<InMemoryCredentialStore> {
    bi.credential_store()
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Registers a new bridge connector with a context.
///
/// Creates a `BridgeRegistry`, submits a registration request, and
/// immediately approves it using the provided governance DID.
///
/// Returns a dict with the bridge registration details.
///
/// # Arguments
///
/// * `context_id` -- Context to register the bridge in.
/// * `operator_did` -- DID of the human operator accountable for the bridge.
/// * `governance_did` -- DID of the governance authority approving the
///   registration.  Must differ from `operator_did` (self-approval is
///   forbidden per ADR-023).
/// * `platform` -- External platform name (e.g., `"discord"`, `"slack"`).
/// * `mode` -- Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
/// * `webhook_url` -- For cooperative mode: the platform's webhook receiver
///   URL (spec §12.2.1). `None` for non-cooperative modes.
/// * `platform_key` -- For cooperative mode: the platform's Ed25519 public
///   key as 32 bytes (spec §12.2.1, §12.10.2). `None` for non-cooperative modes.
/// * `max_shadows` -- Governance-configured shadow limit for this bridge
///   (spec §12.2.1). Defaults to 10,000.
/// * `metadata_display_name` -- Human-readable display name for the bridge.
/// * `metadata_description` -- Free-text description of the bridge.
/// * `metadata_operator_contact` -- Contact information for the bridge operator.
///
/// # Returns
///
/// A dict with `bridge_id`, `operator_did`, `platform`, `mode`, `status`.
///
/// # Errors
///
/// Raises `ValidationError` if `operator_did` or `governance_did` is not a
/// valid DID string (empty, exceeds 512 bytes, missing `did:{method}:{id}`
/// structure, method not lowercase alphanumeric, or contains control
/// characters), or if `mode` is not recognized.
/// Raises `ContextError` if the governance DID matches the operator DID
/// (self-approval) or if registration fails.
#[pyfunction]
#[pyo3(name = "bridge_register")]
#[pyo3(signature = (
    context_id,
    operator_did,
    governance_did,
    platform,
    mode,
    webhook_url=None,
    platform_key=None,
    max_shadows=10_000,
    metadata_display_name="",
    metadata_description="",
    metadata_operator_contact=""
))]
#[allow(clippy::too_many_arguments)]
pub fn py_bridge_register(
    py: Python<'_>,
    context_id: &str,
    operator_did: &str,
    governance_did: &str,
    platform: &str,
    mode: &str,
    webhook_url: Option<&str>,
    platform_key: Option<Vec<u8>>,
    max_shadows: u32,
    metadata_display_name: &str,
    metadata_description: &str,
    metadata_operator_contact: &str,
) -> PyResult<Py<PyDict>> {
    crate::validate::validate_did(operator_did)?;
    crate::validate::validate_did(governance_did)?;

    let bridge_mode = parse_bridge_mode(mode)?;

    let parsed_platform_key = platform_key
        .map(|k| {
            <[u8; 32]>::try_from(k.as_slice()).map_err(|_| ScpPyError::ValidationError {
                message: format!("platform_key must be exactly 32 bytes, got {}", k.len()),
                code: codes::VALID_7052.to_string(),
            })
        })
        .transpose()?;

    let mut registry = BridgeRegistry::new(context_id.to_string());

    // Bridge ID per spec §12.2.1: SHA-256(context_id || operator_did || platform || timestamp).
    let (bridge_id, now_secs) =
        scp_ffi_common::generate_bridge_id(context_id, operator_did, platform);
    let request = BridgeRegistrationRequest {
        bridge_id: bridge_id.clone(),
        operator_did: operator_did.into(),
        platform: platform.to_string(),
        mode: bridge_mode,
        context_id: context_id.to_string(),
        requested_at: now_secs,
        self_hosted: false,
        webhook_url: webhook_url.map(String::from),
        platform_key: parsed_platform_key,
        max_shadows,
        metadata: BridgeRegistrationMetadata {
            display_name: metadata_display_name.to_string(),
            description: metadata_description.to_string(),
            operator_contact: metadata_operator_contact.to_string(),
        },
    };

    let _event = register_bridge(&mut registry, request).map_err(|e| ScpPyError::ContextError {
        message: format!("bridge registration failed: {e}"),
        code: codes::CTX_2100.to_string(),
    })?;

    let approver_did: scp_identity::DID = governance_did.into();
    let (connector, _approval_event) =
        approve_registration(&mut registry, &bridge_id, &approver_did, 0).map_err(|e| {
            ScpPyError::ContextError {
                message: format!("bridge approval failed: {e}"),
                code: codes::CTX_2101.to_string(),
            }
        })?;

    let dict = PyDict::new(py);
    dict.set_item("bridge_id", &connector.bridge_id)?;
    dict.set_item("operator_did", operator_did)?;
    dict.set_item("platform", platform)?;
    dict.set_item("mode", mode)?;
    dict.set_item("status", "active")?;
    dict.set_item("context_id", context_id)?;
    Ok(dict.into())
}

/// Evaluates the trust level for an action based on bridge provenance.
///
/// Returns an integer (0-3) representing the trust tier:
/// - `0` = `ShadowBridged` (weakest)
/// - `1` = `ClaimedBridged`
/// - `2` = `NativeBridged`
/// - `3` = `NativeNative` (strongest)
///
/// # Arguments
///
/// * `is_bridged` -- Whether the action has bridge provenance.
/// * `is_native_transport` -- Whether the transport is native SCP.
/// * `shadow_status` -- `"shadow"` or `"claimed"` (only if `is_bridged`).
///
/// # Returns
///
/// An integer (0-3) representing the trust tier.
///
/// # Errors
///
/// Raises `ValidationError` if `shadow_status` is invalid.
#[pyfunction]
#[pyo3(name = "bridge_evaluate_trust")]
#[pyo3(signature = (is_bridged=false, is_native_transport=true, shadow_status="shadow"))]
pub fn py_bridge_evaluate_trust(
    is_bridged: bool,
    is_native_transport: bool,
    shadow_status: &str,
) -> PyResult<u8> {
    if !is_bridged {
        let level = evaluate_trust_level(None, is_native_transport);
        return Ok(level as u8);
    }

    let status = parse_shadow_status(shadow_status)?;

    // Build minimal bridge provenance for evaluation
    let base = DataProvenance {
        source_context: String::new(),
        source_type: SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_core::context::MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    let connector = BridgeConnector {
        bridge_id: String::new(),
        operator_did: "did:key:unused".into(),
        platform: String::new(),
        mode: BridgeMode::Relay,
        status: BridgeStatus::Active,
        registration_context: String::new(),
        registered_at: 0,
    };

    let shadow = ShadowIdentity {
        shadow_id: String::new(),
        platform_handle: String::new(),
        bridge_id: String::new(),
        attributed_role: "observer".to_string(),
        provenance_status: status,
        created_at: 0,
    };

    let bp = mark_bridge_provenance(base, &connector, &shadow);
    let level = evaluate_trust_level(Some(&bp), is_native_transport);
    Ok(level as u8)
}

/// Creates a shadow identity for an external platform participant.
///
/// Uses the persistent per-context `ShadowRegistry` and `SenderKeyStore`
/// from the process-global bridge state registry, ensuring that shadow
/// identity state and sender keys survive across function calls.
///
/// Returns a dict with the shadow identity details.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge connector ID that owns this shadow.
/// * `platform_handle` -- External platform handle (e.g., `"@user#1234"`).
/// * `bridge_mode` -- Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
/// * `context_id` -- Context the shadow is being created in.
///
/// # Returns
///
/// A dict with `shadow_id`, `platform_handle`, `bridge_id`, `attributed_role`,
/// `provenance_status`.
///
/// # Errors
///
/// Raises `ValidationError` if `bridge_mode` is invalid or shadow creation fails.
fn bridge_create_shadow_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    bridge_id: &str,
    platform_handle: &str,
    bridge_mode: &str,
    context_id: &str,
) -> PyResult<Py<PyDict>> {
    let mode = parse_bridge_mode(bridge_mode)?;

    let shadow_id = format!("shadow-{bridge_id}-{}", platform_handle.replace('@', ""));

    let params = CreateShadowParams {
        shadow_id: &shadow_id,
        bridge_id,
        bridge_mode: mode,
        platform_handle,
        context_member_dids: &[], // no existing context member DIDs for collision check
        timestamp: 0,
    };

    let mut entry = bi
        .core
        .bridge_state()
        .entry(context_id.to_owned())
        .or_insert_with(|| BridgeContextState {
            shadow_registry: ShadowRegistry::new(context_id.to_string()),
            sender_key_store: SenderKeyStore::new(),
        });
    let state = entry.value_mut();

    let (shadow, _event) = create_shadow(
        &mut state.shadow_registry,
        &mut state.sender_key_store,
        &params,
    )
    .map_err(|e| ScpPyError::ContextError {
        message: format!("shadow creation failed: {e}"),
        code: codes::CTX_2102.to_string(),
    })?;

    let dict = PyDict::new(py);
    dict.set_item("shadow_id", &shadow.shadow_id)?;
    dict.set_item("platform_handle", &shadow.platform_handle)?;
    dict.set_item("bridge_id", &shadow.bridge_id)?;
    dict.set_item("attributed_role", &shadow.attributed_role)?;
    dict.set_item(
        "provenance_status",
        format!("{:?}", shadow.provenance_status),
    )?;
    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// Shadow claiming (§12, ADR-023 acceptance criteria 7-8)
// ---------------------------------------------------------------------------

/// Claims a shadow identity by binding it to a DID via identity attestation.
///
/// Verifies the identity attestation, platform handle match, and Ed25519
/// signatures, then transitions the shadow's provenance status from `Shadow`
/// to `Claimed`. Claiming is one-way and irreversible.
///
/// # Arguments
///
/// * `context_id` -- Context the shadow belongs to.
/// * `shadow_id` -- The shadow identity to claim.
/// * `claimant_did` -- DID of the claimant.
/// * `platform_handle` -- External platform handle the claimant asserts ownership of.
/// * `attestation_json` -- JSON-serialized identity attestation (§3.5).
/// * `claim_signature` -- Ed25519 signature over the claim request content (64 bytes).
/// * `timestamp` -- Unix timestamp (seconds) when the claim was created.
/// * `bridge_id` -- The bridge connector that owns this shadow.
/// * `bridge_mode` -- Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
///
/// # Returns
///
/// A dict with the claim event details: `shadow_id`, `claimant_did`,
/// `platform_handle`, `attestation_id`, `context_id`, `timestamp`.
///
/// # Errors
///
/// Raises `ContextError` if the shadow is not found, already claimed,
/// attestation is invalid, handle mismatch, or signature verification fails.
#[pyfunction]
#[pyo3(name = "bridge_claim_shadow")]
#[pyo3(signature = (
    context_id,
    shadow_id,
    claimant_did,
    platform_handle,
    attestation_json,
    claim_signature,
    timestamp,
    bridge_id,
    bridge_mode
))]
#[allow(clippy::too_many_arguments)]
pub fn py_bridge_claim_shadow(
    py: Python<'_>,
    context_id: &str,
    shadow_id: &str,
    claimant_did: &str,
    platform_handle: &str,
    attestation_json: &str,
    claim_signature: Vec<u8>,
    timestamp: u64,
    bridge_id: &str,
    bridge_mode: &str,
) -> PyResult<Py<PyDict>> {
    crate::validate::validate_context_id(context_id)?;
    crate::validate::validate_did(claimant_did)?;

    let mode = parse_bridge_mode(bridge_mode)?;

    // Deserialize the attestation from JSON.
    let attestation: Attestation =
        serde_json::from_str(attestation_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid attestation JSON: {e}"),
            code: codes::VALID_7053.to_string(),
        })?;

    // Build the shadow registry and create the shadow so it can be found.
    let mut shadow_registry = ShadowRegistry::new(context_id.to_string());
    let shadow_params = CreateShadowParams {
        shadow_id,
        bridge_id,
        bridge_mode: mode,
        platform_handle,
        context_member_dids: &[],
        timestamp: 0,
    };
    let mut sender_key_store = scp_core::crypto::sender_keys::SenderKeyStore::new();
    create_shadow(&mut shadow_registry, &mut sender_key_store, &shadow_params).map_err(|e| {
        ScpPyError::ContextError {
            message: format!("shadow setup for claiming failed: {e}"),
            code: codes::CTX_2103.to_string(),
        }
    })?;

    // Build the claim request.
    let request = ClaimRequest {
        shadow_id: shadow_id.to_string(),
        claimant_did: claimant_did.into(),
        platform_handle: platform_handle.to_string(),
        identity_attestation: attestation,
        timestamp,
        signature: claim_signature,
    };

    let event =
        claim_shadow(&mut shadow_registry, &request).map_err(|e| ScpPyError::ContextError {
            message: format!("shadow claim failed: {e}"),
            code: codes::CTX_2104.to_string(),
        })?;

    let dict = PyDict::new(py);
    dict.set_item("shadow_id", &event.shadow_id)?;
    dict.set_item("claimant_did", &*event.claimant_did)?;
    dict.set_item("platform_handle", &event.platform_handle)?;
    dict.set_item("attestation_id", &event.attestation_id)?;
    dict.set_item("context_id", &event.context_id)?;
    dict.set_item("timestamp", event.timestamp)?;
    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// Bridge envelope sealing/opening (§12.6.1, SCP-BCH-012)
// ---------------------------------------------------------------------------

/// Seals a sender-key-encrypted envelope for a shadow identity message.
///
/// Encrypts plaintext with AES-256-GCM using the shadow's sender key,
/// attaches bridge provenance, and returns the complete envelope as JSON.
///
/// # Arguments
///
/// * `shadow_id` -- The shadow identity DID sending the message.
/// * `platform_handle` -- The shadow's external platform handle.
/// * `bridge_id` -- The bridge connector operating this shadow.
/// * `operator_did` -- DID of the bridge operator.
/// * `platform` -- External platform name (e.g., `"discord"`).
/// * `bridge_mode` -- Bridge mode string.
/// * `sender_key_bytes` -- The shadow's 32-byte AES-256-GCM sender key.
/// * `plaintext` -- Message plaintext to encrypt.
/// * `context_id` -- The SCP context identifier (AAD binding).
/// * `epoch` -- The sender key epoch (AAD binding).
/// * `sequence` -- The per-sender monotonic sequence number (AAD binding).
/// * `platform_message_id` -- Optional platform message ID for correlation.
/// * `platform_timestamp` -- Optional platform-reported timestamp.
/// * `attributed_role` -- Optional role for the shadow (defaults to `"observer"`).
/// * `provenance_status` -- Optional provenance status: `"shadow"` or
///   `"claimed"`. Defaults to `"shadow"` (#1166).
///
/// # Returns
///
/// JSON string of the sealed `SenderKeyEnvelope`.
///
/// # Errors
///
/// Raises `CryptoError` if encryption fails.
/// Raises `ValidationError` if `sender_key_bytes` is not 32 bytes.
#[pyfunction]
#[pyo3(name = "bridge_seal_shadow_envelope")]
#[pyo3(signature = (
    shadow_id,
    platform_handle,
    bridge_id,
    operator_did,
    platform,
    bridge_mode,
    sender_key_bytes,
    plaintext,
    context_id,
    epoch,
    sequence,
    platform_message_id=None,
    platform_timestamp=None,
    attributed_role=None,
    provenance_status=None
))]
#[allow(clippy::too_many_arguments)]
pub fn py_bridge_seal_shadow_envelope(
    shadow_id: &str,
    platform_handle: &str,
    bridge_id: &str,
    operator_did: &str,
    platform: &str,
    bridge_mode: &str,
    sender_key_bytes: Vec<u8>,
    plaintext: Vec<u8>,
    context_id: &str,
    epoch: u64,
    sequence: u64,
    platform_message_id: Option<String>,
    platform_timestamp: Option<u64>,
    attributed_role: Option<String>,
    provenance_status: Option<String>,
) -> PyResult<String> {
    crate::validate::validate_context_id(context_id)?;
    crate::validate::validate_did(operator_did)?;

    let mode = parse_bridge_mode(bridge_mode)?;

    // Wrap raw key material in Zeroizing to prevent lingering in freed heap
    // memory after the Vec is dropped (defense-in-depth for FFI boundary).
    let sender_key_bytes = Zeroizing::new(sender_key_bytes);
    let key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(sender_key_bytes.as_slice()).map_err(|_| {
            ScpPyError::ValidationError {
                message: format!(
                    "sender_key_bytes must be exactly 32 bytes, got {}",
                    sender_key_bytes.len()
                ),
                code: codes::VALID_7054.to_string(),
            }
        })?,
    );
    let sender_key = SenderKey::from_bytes(*key_bytes);

    let status = match provenance_status.as_deref() {
        Some(s) => parse_shadow_status(s)?,
        None => ShadowProvenanceStatus::Shadow,
    };

    let shadow = ShadowIdentity {
        shadow_id: shadow_id.to_string(),
        platform_handle: platform_handle.to_string(),
        bridge_id: bridge_id.to_string(),
        attributed_role: attributed_role.unwrap_or_else(|| "observer".to_string()),
        provenance_status: status,
        created_at: 0,
    };

    let connector = BridgeConnector {
        bridge_id: bridge_id.to_string(),
        operator_did: operator_did.into(),
        platform: platform.to_string(),
        mode,
        status: BridgeStatus::Active,
        registration_context: context_id.to_string(),
        registered_at: 0,
    };

    let base_provenance = DataProvenance {
        source_context: context_id.to_string(),
        source_type: SourceType::Persistent,
        counterparties: vec![],
        purpose: Some("bridged message".to_string()),
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_core::context::MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    let params = SealShadowEnvelopeParams {
        shadow: &shadow,
        connector: &connector,
        sender_key: &sender_key,
        plaintext: &plaintext,
        base_provenance,
        platform_message_id,
        platform_timestamp,
        context_id,
        epoch,
        sequence,
    };

    let envelope = seal_shadow_envelope(&params).map_err(|e| ScpPyError::CryptoError {
        message: format!("envelope sealing failed: {e}"),
        code: codes::CRYPTO_4010.to_string(),
    })?;

    Ok(
        serde_json::to_string(&envelope).map_err(|e| ScpPyError::ValidationError {
            message: format!("envelope serialization failed: {e}"),
            code: codes::VALID_7055.to_string(),
        })?,
    )
}

/// Opens a sender-key-encrypted envelope and returns the decrypted plaintext.
///
/// The caller must supply the same AAD fields (`context_id`, `sender_did`,
/// `epoch`, `sequence`) used at seal time.
///
/// # Arguments
///
/// * `envelope_json` -- JSON-serialized `SenderKeyEnvelope`.
/// * `sender_key_bytes` -- The shadow's 32-byte AES-256-GCM sender key.
/// * `context_id` -- The SCP context identifier (AAD binding).
/// * `sender_did` -- The shadow DID (AAD binding).
/// * `epoch` -- The sender key epoch (AAD binding).
/// * `sequence` -- The per-sender sequence number (AAD binding).
///
/// # Returns
///
/// The decrypted plaintext bytes.
///
/// # Errors
///
/// Raises `CryptoError` if decryption or AAD verification fails.
#[pyfunction]
#[pyo3(name = "bridge_open_shadow_envelope")]
#[pyo3(signature = (envelope_json, sender_key_bytes, context_id, sender_did, epoch, sequence))]
pub fn py_bridge_open_shadow_envelope(
    envelope_json: &str,
    sender_key_bytes: Vec<u8>,
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    sequence: u64,
) -> PyResult<Vec<u8>> {
    crate::validate::validate_context_id(context_id)?;

    let envelope: scp_core::bridge::envelope::SenderKeyEnvelope =
        serde_json::from_str(envelope_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid envelope JSON: {e}"),
            code: codes::VALID_7056.to_string(),
        })?;

    // Wrap raw key material in Zeroizing to prevent lingering in freed heap
    // memory after the Vec is dropped (defense-in-depth for FFI boundary).
    let sender_key_bytes = Zeroizing::new(sender_key_bytes);
    let key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(sender_key_bytes.as_slice()).map_err(|_| {
            ScpPyError::ValidationError {
                message: format!(
                    "sender_key_bytes must be exactly 32 bytes, got {}",
                    sender_key_bytes.len()
                ),
                code: codes::VALID_7054.to_string(),
            }
        })?,
    );
    let sender_key = SenderKey::from_bytes(*key_bytes);

    // Evaluate bridge provenance trust level before decryption (§12.5).
    // This ensures all inbound bridge operations have their provenance
    // validated — matching the outbound path where seal_shadow_envelope
    // attaches provenance via mark_bridge_provenance.
    let trust_level = evaluate_trust_level(Some(&envelope.bridge_provenance), false);
    if trust_level == scp_core::bridge::provenance::BridgeTrustLevel::ShadowBridged {
        tracing::warn!(
            trust_level = ?trust_level,
            "opening shadow envelope with lowest trust tier (ShadowBridged)"
        );
    }

    Ok(open_shadow_envelope(
        &envelope,
        &sender_key,
        context_id,
        sender_did,
        epoch,
        sequence,
    )
    .map_err(|e| ScpPyError::CryptoError {
        message: format!("envelope opening failed: {e}"),
        code: codes::CRYPTO_4011.to_string(),
    })?)
}

// ---------------------------------------------------------------------------
// Credential key derivation (§12.11.1)
// ---------------------------------------------------------------------------

/// Derives a 32-byte AES-256-GCM encryption key from a per-bridge credential
/// key using HKDF-SHA256 (spec §12.11.1 Phase 2).
///
/// # Arguments
///
/// * `bridge_credential_key` -- The 32-byte per-bridge random secret.
/// * `bridge_id` -- The bridge instance identifier.
///
/// # Returns
///
/// The derived 32-byte encryption key.
///
/// # Errors
///
/// Raises `CryptoError` if HKDF expansion fails.
/// Raises `ValidationError` if `bridge_credential_key` is not 32 bytes.
#[pyfunction]
#[pyo3(name = "bridge_derive_credential_key")]
pub fn py_bridge_derive_credential_key(
    bridge_credential_key: Vec<u8>,
    bridge_id: &str,
) -> PyResult<Vec<u8>> {
    let bridge_credential_key = Zeroizing::new(bridge_credential_key);
    let key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(bridge_credential_key.as_slice()).map_err(|_| {
            ScpPyError::ValidationError {
                message: format!(
                    "bridge_credential_key must be exactly 32 bytes, got {}",
                    bridge_credential_key.len()
                ),
                code: codes::VALID_7057.to_string(),
            }
        })?,
    );

    let derived =
        derive_credential_key(&key_bytes, bridge_id).map_err(|e| ScpPyError::CryptoError {
            message: format!("credential key derivation failed: {e}"),
            code: codes::CRYPTO_4012.to_string(),
        })?;

    // SAFETY: `.to_vec()` creates an unzeroized copy of the derived key
    // material. This is unavoidable at the FFI boundary — PyO3 requires
    // `Vec<u8>` for bytes returns and Python's GC controls the lifetime.
    // The `Zeroizing<[u8; 32]>` source is zeroized on drop.
    Ok(derived.to_vec())
}

/// Generates a new random 32-byte bridge credential key (CSPRNG).
///
/// Called once at bridge provisioning time. The returned key must be stored
/// via `bridge_credential_store_key`.
///
/// # Returns
///
/// 32 random bytes suitable for use as a bridge credential key.
#[must_use]
#[pyfunction]
#[pyo3(name = "bridge_generate_credential_key")]
pub fn py_bridge_generate_credential_key() -> Vec<u8> {
    let key = generate_bridge_credential_key();
    // SAFETY: `.to_vec()` creates an unzeroized copy of the generated key
    // material. This is unavoidable at the FFI boundary — PyO3 requires
    // `Vec<u8>` for bytes returns and Python's GC controls the lifetime.
    // The `Zeroizing<[u8; 32]>` source is zeroized on drop.
    key.to_vec()
}

// ---------------------------------------------------------------------------
// Credential store operations (§12.11)
// ---------------------------------------------------------------------------

/// Provisions (stores) an encrypted credential for a bridge instance.
///
/// The plaintext is encrypted using a key derived from the per-bridge
/// credential key via HKDF-SHA256, then stored.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
/// * `credential_type` -- One of: `"OAuthAccessToken"`, `"OAuthRefreshToken"`,
///   `"ApiKey"`, `"WebhookSecret"`, or `"Custom:name"`.
/// * `plaintext` -- The credential value to encrypt and store.
/// * `bridge_credential_key` -- The 32-byte per-bridge credential key.
///
/// # Returns
///
/// A dict with credential metadata: `bridge_id`, `credential_type`,
/// `created_at`.
///
/// # Errors
///
/// Raises `ContextError` if a credential of the same type already exists
/// (use rotate to replace).
/// Raises `CryptoError` if encryption fails.
fn bridge_credential_provision_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    bridge_id: &str,
    credential_type: &str,
    plaintext: &[u8],
    bridge_credential_key: &[u8],
) -> PyResult<Py<PyDict>> {
    let ct = parse_credential_type(credential_type)?;
    let key_bytes = parse_credential_key_bytes(bridge_credential_key)?;

    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    let credential = rt
        .block_on(store.provision(bridge_id, ct, plaintext, &key_bytes))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential provision failed: {e}"),
            code: codes::CTX_2105.to_string(),
        })?;

    let dict = PyDict::new(py);
    dict.set_item("bridge_id", &credential.bridge_id)?;
    dict.set_item("credential_type", credential.credential_type.to_string())?;
    dict.set_item("created_at", credential.created_at)?;
    Ok(dict.into())
}

/// Retrieves and decrypts a credential for a bridge instance.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
/// * `credential_type` -- Credential type string (see `bridge_credential_provision`).
/// * `bridge_credential_key` -- The 32-byte per-bridge credential key.
///
/// # Returns
///
/// The decrypted credential plaintext as bytes.
///
/// # Errors
///
/// Raises `ContextError` if the credential is not found or the bridge is
/// suspended.
/// Raises `CryptoError` if decryption fails.
fn bridge_credential_retrieve_impl(
    bi: &PyBridgeInstance,
    bridge_id: &str,
    credential_type: &str,
    bridge_credential_key: &[u8],
) -> PyResult<Vec<u8>> {
    let ct = parse_credential_type(credential_type)?;
    let key_bytes = parse_credential_key_bytes(bridge_credential_key)?;

    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    let plaintext = rt
        .block_on(store.retrieve(bridge_id, &ct, &key_bytes))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential retrieve failed: {e}"),
            code: codes::CTX_2106.to_string(),
        })?;

    Ok(plaintext.to_vec())
}

/// Rotates (replaces) a credential for a bridge instance.
///
/// The old credential data is securely overwritten before replacement.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
/// * `credential_type` -- Credential type string.
/// * `new_plaintext` -- The new credential value.
/// * `bridge_credential_key` -- The 32-byte per-bridge credential key.
///
/// # Returns
///
/// A dict with the rotated credential metadata.
///
/// # Errors
///
/// Raises `ContextError` if the credential is not found.
fn bridge_credential_rotate_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    bridge_id: &str,
    credential_type: &str,
    new_plaintext: &[u8],
    bridge_credential_key: &[u8],
) -> PyResult<Py<PyDict>> {
    let ct = parse_credential_type(credential_type)?;
    let key_bytes = parse_credential_key_bytes(bridge_credential_key)?;

    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    let credential = rt
        .block_on(store.rotate(bridge_id, &ct, new_plaintext, &key_bytes))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential rotate failed: {e}"),
            code: codes::CTX_2107.to_string(),
        })?;

    let dict = PyDict::new(py);
    dict.set_item("bridge_id", &credential.bridge_id)?;
    dict.set_item("credential_type", credential.credential_type.to_string())?;
    dict.set_item("created_at", credential.created_at)?;
    Ok(dict.into())
}

/// Revokes all credentials for a bridge instance.
///
/// Securely overwrites all credential data with zeros, then deletes them.
/// Also destroys the bridge credential key.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
///
/// # Errors
///
/// Raises `ContextError` if the storage backend fails.
fn bridge_credential_revoke_impl(bi: &PyBridgeInstance, bridge_id: &str) -> PyResult<()> {
    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    rt.block_on(store.revoke(bridge_id))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential revoke failed: {e}"),
            code: codes::CTX_2108.to_string(),
        })?;

    Ok(())
}

/// Lists all credential types stored for a bridge instance.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
///
/// # Returns
///
/// A list of credential type strings.
///
/// # Errors
///
/// Raises `ContextError` if the storage backend fails.
fn bridge_credential_list_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    bridge_id: &str,
) -> PyResult<Py<PyList>> {
    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    let types = rt
        .block_on(store.list(bridge_id))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential list failed: {e}"),
            code: codes::CTX_2109.to_string(),
        })?;

    let list =
        PyList::new(py, types.iter().map(std::string::ToString::to_string)).map_err(|e| {
            ScpPyError::ContextError {
                message: format!("failed to build Python list: {e}"),
                code: codes::CTX_2110.to_string(),
            }
        })?;
    Ok(list.into())
}

/// Stores a bridge credential key in the custody boundary.
///
/// Called once at bridge provisioning time with the output of
/// `bridge_generate_credential_key`.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
/// * `key` -- The 32-byte bridge credential key.
///
/// # Errors
///
/// Raises `ContextError` if storage fails.
/// Raises `ValidationError` if `key` is not 32 bytes.
fn bridge_credential_store_key_impl(
    bi: &PyBridgeInstance,
    bridge_id: &str,
    key: &[u8],
) -> PyResult<()> {
    let key_bytes = parse_credential_key_bytes(key)?;

    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    rt.block_on(store.store_bridge_credential_key(bridge_id, Zeroizing::new(key_bytes)))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential key store failed: {e}"),
            code: codes::CTX_2111.to_string(),
        })?;

    Ok(())
}

/// Retrieves a bridge credential key from the custody boundary.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
///
/// # Returns
///
/// The 32-byte bridge credential key.
///
/// # Errors
///
/// Raises `ContextError` if the key is not found.
fn bridge_credential_get_key_impl(bi: &PyBridgeInstance, bridge_id: &str) -> PyResult<Vec<u8>> {
    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    let key = rt
        .block_on(store.get_bridge_credential_key(bridge_id))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential key retrieval failed: {e}"),
            code: codes::CTX_2112.to_string(),
        })?;

    Ok(key.to_vec())
}

/// Deletes and zeroizes a bridge credential key.
///
/// After this call, no credentials can be decrypted for this bridge.
///
/// # Arguments
///
/// * `bridge_id` -- The bridge instance ID.
///
/// # Errors
///
/// Raises `ContextError` if storage fails.
fn bridge_credential_delete_key_impl(bi: &PyBridgeInstance, bridge_id: &str) -> PyResult<()> {
    let rt = crate::runtime()?;
    let store = credential_store_for(bi);

    rt.block_on(store.delete_bridge_credential_key(bridge_id))
        .map_err(|e| ScpPyError::ContextError {
            message: format!("credential key deletion failed: {e}"),
            code: codes::CTX_2113.to_string(),
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// OAuth 2.0 flow (§12.11.3, ADR-023)
// ---------------------------------------------------------------------------

/// Generates a PKCE S256 code verifier and challenge pair.
///
/// Uses CSPRNG for the code verifier (32 random bytes, base64url-encoded).
/// The challenge is `base64url(SHA-256(verifier))`.
///
/// # Returns
///
/// A dict with `code_verifier` and `code_challenge` strings.
#[pyfunction]
#[pyo3(name = "bridge_oauth_generate_pkce")]
pub fn py_bridge_oauth_generate_pkce(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let pkce = generate_pkce();
    let dict = PyDict::new(py);
    dict.set_item("code_verifier", &pkce.code_verifier)?;
    dict.set_item("code_challenge", &pkce.code_challenge)?;
    Ok(dict.into())
}

/// Builds an OAuth 2.0 authorization URL with PKCE.
///
/// Constructs a URL with `response_type=code`, `client_id`, `redirect_uri`,
/// `scope`, `code_challenge`, and `code_challenge_method=S256`.
///
/// # Arguments
///
/// * `authorization_endpoint` -- Platform's authorization endpoint URL.
/// * `client_id` -- OAuth client ID issued by the platform.
/// * `redirect_uri` -- Redirect URI registered with the platform.
/// * `scopes` -- List of OAuth scope strings.
/// * `code_challenge` -- The S256 code challenge from `bridge_oauth_generate_pkce`.
/// * `state` -- Optional state parameter for CSRF protection.
///
/// # Returns
///
/// The complete authorization URL string.
#[must_use]
#[pyfunction]
#[pyo3(name = "bridge_oauth_build_auth_url")]
#[pyo3(signature = (
    authorization_endpoint,
    client_id,
    redirect_uri,
    scopes,
    code_challenge,
    state=None
))]
pub fn py_bridge_oauth_build_auth_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: Vec<String>,
    code_challenge: &str,
    state: Option<&str>,
) -> String {
    let config = OAuthConfig {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        token_endpoint: String::new(), // Not needed for URL building.
        authorization_endpoint: authorization_endpoint.to_string(),
        revocation_endpoint: None,
        scopes,
    };

    let pkce = scp_core::bridge::oauth::PkceChallenge {
        code_verifier: String::new(), // Not included in the URL.
        code_challenge: code_challenge.to_string(),
    };

    build_authorization_url(&config, &pkce, state)
}

/// Returns recommended OAuth scopes for the given bridge mode.
///
/// - `"relay"` -> read-only scopes
/// - `"puppet"` -> read + write scopes
/// - `"api"` / `"cooperative"` -> empty (platform-specific)
///
/// # Arguments
///
/// * `mode` -- Bridge mode string.
///
/// # Returns
///
/// A list of scope strings.
///
/// # Errors
///
/// Raises `ValidationError` if the mode is invalid.
#[pyfunction]
#[pyo3(name = "bridge_oauth_scopes_for_mode")]
pub fn py_bridge_oauth_scopes_for_mode(py: Python<'_>, mode: &str) -> PyResult<Py<PyList>> {
    let bridge_mode = parse_bridge_mode(mode)?;
    let scopes = scopes_for_mode(&bridge_mode);
    let list = PyList::new(py, &scopes).map_err(|e| ScpPyError::ContextError {
        message: format!("failed to build Python list: {e}"),
        code: codes::CTX_2114.to_string(),
    })?;
    Ok(list.into())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_bridge_mode(s: &str) -> PyResult<BridgeMode> {
    match s {
        "relay" => Ok(BridgeMode::Relay),
        "puppet" => Ok(BridgeMode::Puppet),
        "api" => Ok(BridgeMode::Api),
        "cooperative" => Ok(BridgeMode::Cooperative),
        other => Err(ScpPyError::ValidationError {
            message: format!(
                "invalid bridge mode '{other}': expected 'relay', 'puppet', 'api', or 'cooperative'"
            ),
            code: codes::VALID_7050.to_string(),
        }
        .into()),
    }
}

fn parse_credential_type(s: &str) -> PyResult<CredentialType> {
    match s {
        "OAuthAccessToken" => Ok(CredentialType::OAuthAccessToken),
        "OAuthRefreshToken" => Ok(CredentialType::OAuthRefreshToken),
        "ApiKey" => Ok(CredentialType::ApiKey),
        "WebhookSecret" => Ok(CredentialType::WebhookSecret),
        other => other.strip_prefix("Custom:").map_or_else(
            || {
                Err(ScpPyError::ValidationError {
                    message: format!(
                        "invalid credential type '{other}': expected 'OAuthAccessToken', \
                         'OAuthRefreshToken', 'ApiKey', 'WebhookSecret', or 'Custom:<name>'"
                    ),
                    code: codes::VALID_7058.to_string(),
                }
                .into())
            },
            |name| Ok(CredentialType::Custom(name.to_string())),
        ),
    }
}

fn parse_credential_key_bytes(key: &[u8]) -> PyResult<[u8; 32]> {
    <[u8; 32]>::try_from(key).map_err(|_| {
        ScpPyError::ValidationError {
            message: format!(
                "bridge_credential_key must be exactly 32 bytes, got {}",
                key.len()
            ),
            code: codes::VALID_7057.to_string(),
        }
        .into()
    })
}

fn parse_shadow_status(s: &str) -> PyResult<ShadowProvenanceStatus> {
    match s {
        "shadow" => Ok(ShadowProvenanceStatus::Shadow),
        "claimed" => Ok(ShadowProvenanceStatus::Claimed),
        other => Err(ScpPyError::ValidationError {
            message: format!("invalid shadow_status '{other}': expected 'shadow' or 'claimed'"),
            code: codes::VALID_7051.to_string(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Creates a shadow identity for a bridge.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `bridge_mode` is invalid or shadow creation fails.
    #[pyo3(name = "bridge_create_shadow", signature = (bridge_id, platform_handle, bridge_mode, context_id="ctx-shadow"))]
    pub fn bridge_create_shadow(
        &self,
        py: Python<'_>,
        bridge_id: &str,
        platform_handle: &str,
        bridge_mode: &str,
        context_id: &str,
    ) -> PyResult<Py<PyDict>> {
        let bi = &*self.inner;
        bridge_create_shadow_impl(bi, py, bridge_id, platform_handle, bridge_mode, context_id)
    }

    /// Provisions (stores) an encrypted credential for a bridge.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` on storage/encryption failure.
    /// Raises `ValidationError` if `credential_type` or key length is invalid.
    #[pyo3(name = "bridge_credential_provision")]
    pub fn bridge_credential_provision(
        &self,
        py: Python<'_>,
        bridge_id: &str,
        credential_type: &str,
        plaintext: Vec<u8>,
        bridge_credential_key: Vec<u8>,
    ) -> PyResult<Py<PyDict>> {
        let bi = &*self.inner;
        bridge_credential_provision_impl(
            bi,
            py,
            bridge_id,
            credential_type,
            &plaintext,
            &bridge_credential_key,
        )
    }

    /// Retrieves and decrypts a credential for a bridge instance.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the credential is not found or decryption fails.
    #[pyo3(name = "bridge_credential_retrieve")]
    pub fn bridge_credential_retrieve(
        &self,
        bridge_id: &str,
        credential_type: &str,
        bridge_credential_key: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        let bi = &*self.inner;
        bridge_credential_retrieve_impl(bi, bridge_id, credential_type, &bridge_credential_key)
    }

    /// Rotates (replaces) a credential for a bridge instance.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the credential is not found.
    #[pyo3(name = "bridge_credential_rotate")]
    pub fn bridge_credential_rotate(
        &self,
        py: Python<'_>,
        bridge_id: &str,
        credential_type: &str,
        new_plaintext: Vec<u8>,
        bridge_credential_key: Vec<u8>,
    ) -> PyResult<Py<PyDict>> {
        let bi = &*self.inner;
        bridge_credential_rotate_impl(
            bi,
            py,
            bridge_id,
            credential_type,
            &new_plaintext,
            &bridge_credential_key,
        )
    }

    /// Revokes all credentials for a bridge instance.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the storage backend fails.
    #[pyo3(name = "bridge_credential_revoke")]
    pub fn bridge_credential_revoke(&self, bridge_id: &str) -> PyResult<()> {
        let bi = &*self.inner;
        bridge_credential_revoke_impl(bi, bridge_id)
    }

    /// Lists all credential types stored for a bridge instance.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the storage backend fails.
    #[pyo3(name = "bridge_credential_list")]
    pub fn bridge_credential_list(&self, py: Python<'_>, bridge_id: &str) -> PyResult<Py<PyList>> {
        let bi = &*self.inner;
        bridge_credential_list_impl(bi, py, bridge_id)
    }

    /// Stores a bridge credential key in the custody boundary.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if storage fails.
    /// Raises `ValidationError` if `key` is not 32 bytes.
    #[pyo3(name = "bridge_credential_store_key")]
    pub fn bridge_credential_store_key(&self, bridge_id: &str, key: Vec<u8>) -> PyResult<()> {
        let bi = &*self.inner;
        bridge_credential_store_key_impl(bi, bridge_id, &key)
    }

    /// Retrieves a bridge credential key from the custody boundary.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the key is not found.
    #[pyo3(name = "bridge_credential_get_key")]
    pub fn bridge_credential_get_key(&self, bridge_id: &str) -> PyResult<Vec<u8>> {
        let bi = &*self.inner;
        bridge_credential_get_key_impl(bi, bridge_id)
    }

    /// Deletes and zeroizes a bridge credential key.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if storage fails.
    #[pyo3(name = "bridge_credential_delete_key")]
    pub fn bridge_credential_delete_key(&self, bridge_id: &str) -> PyResult<()> {
        let bi = &*self.inner;
        bridge_credential_delete_key_impl(bi, bridge_id)
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers bridge connector free functions on the `_scp_core` module.
///
/// Post-migration (Phase 4 PR 4 sub-slice E), stateful credential and shadow
/// store operations are exposed as methods on `SCP`. Only pure helpers
/// (registration, trust evaluation, shadow claiming, envelope seal/open,
/// credential key derivation/generation, OAuth helpers) remain as free
/// `#[pyfunction]` exports.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_bridge_connector(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Pure helpers only — stateful operations live on `SCP`.
    m.add_function(wrap_pyfunction!(py_bridge_register, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_evaluate_trust, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_claim_shadow, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_seal_shadow_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_open_shadow_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_derive_credential_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_generate_credential_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_oauth_generate_pkce, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_oauth_build_auth_url, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_oauth_scopes_for_mode, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_core::bridge::provenance::BridgeTrustLevel;

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new()
    }

    #[test]
    fn parse_bridge_mode_valid() {
        assert_eq!(parse_bridge_mode("relay").unwrap(), BridgeMode::Relay);
        assert_eq!(parse_bridge_mode("puppet").unwrap(), BridgeMode::Puppet);
        assert_eq!(parse_bridge_mode("api").unwrap(), BridgeMode::Api);
        assert_eq!(
            parse_bridge_mode("cooperative").unwrap(),
            BridgeMode::Cooperative
        );
    }

    #[test]
    fn parse_bridge_mode_invalid() {
        assert!(parse_bridge_mode("invalid").is_err());
    }

    #[test]
    fn parse_shadow_status_valid() {
        assert_eq!(
            parse_shadow_status("shadow").unwrap(),
            ShadowProvenanceStatus::Shadow
        );
        assert_eq!(
            parse_shadow_status("claimed").unwrap(),
            ShadowProvenanceStatus::Claimed
        );
    }

    #[test]
    fn parse_shadow_status_invalid() {
        assert!(parse_shadow_status("invalid").is_err());
    }

    #[test]
    fn evaluate_trust_native_native() {
        let result = py_bridge_evaluate_trust(false, true, "shadow").unwrap();
        assert_eq!(result, BridgeTrustLevel::NativeNative as u8);
    }

    #[test]
    fn evaluate_trust_native_bridged() {
        let result = py_bridge_evaluate_trust(false, false, "shadow").unwrap();
        assert_eq!(result, BridgeTrustLevel::NativeBridged as u8);
    }

    #[test]
    fn evaluate_trust_shadow_bridged() {
        let result = py_bridge_evaluate_trust(true, false, "shadow").unwrap();
        assert_eq!(result, BridgeTrustLevel::ShadowBridged as u8);
    }

    #[test]
    fn evaluate_trust_claimed_bridged() {
        let result = py_bridge_evaluate_trust(true, false, "claimed").unwrap();
        assert_eq!(result, BridgeTrustLevel::ClaimedBridged as u8);
    }

    #[test]
    fn register_bridge_returns_active_with_valid_bridge_id() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_bridge_register(
                py,
                "ctx-test",
                "did:key:operator",
                "did:key:governance",
                "discord",
                "relay",
                None,
                None,
                10_000,
                "",
                "",
                "",
            )
            .unwrap();
            let dict = result.bind(py);
            let status: String = dict.get_item("status").unwrap().unwrap().extract().unwrap();
            assert_eq!(status, "active");
            let bridge_id: String = dict
                .get_item("bridge_id")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            // bridge_id must be a 64-char hex string (SHA-256 output per §12.2.1)
            assert_eq!(bridge_id.len(), 64);
            assert!(bridge_id.chars().all(|c| c.is_ascii_hexdigit()));
        });
    }

    #[test]
    fn register_bridge_rejects_self_approval() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_bridge_register(
                py,
                "ctx-test",
                "did:key:operator",
                "did:key:operator",
                "discord",
                "relay",
                None,
                None,
                10_000,
                "",
                "",
                "",
            );
            assert!(result.is_err());
        });
    }

    #[test]
    fn register_bridge_with_optional_fields() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_bridge_register(
                py,
                "ctx-test",
                "did:key:operator",
                "did:key:governance",
                "discord",
                "cooperative",
                Some("https://example.com/webhook"),
                Some(vec![42u8; 32]),
                500,
                "My Discord Bridge",
                "Bridges #general channel",
                "admin@example.com",
            )
            .unwrap();
            let dict = result.bind(py);
            let status: String = dict.get_item("status").unwrap().unwrap().extract().unwrap();
            assert_eq!(status, "active");
        });
    }

    #[test]
    fn register_bridge_rejects_invalid_platform_key_length() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_bridge_register(
                py,
                "ctx-test",
                "did:key:operator",
                "did:key:governance",
                "discord",
                "cooperative",
                None,
                Some(vec![42u8; 16]), // wrong length
                10_000,
                "",
                "",
                "",
            );
            assert!(result.is_err());
        });
    }

    // -------------------------------------------------------------------
    // Credential type parsing
    // -------------------------------------------------------------------

    #[test]
    fn parse_credential_type_standard_variants() {
        assert!(matches!(
            parse_credential_type("OAuthAccessToken").unwrap(),
            CredentialType::OAuthAccessToken
        ));
        assert!(matches!(
            parse_credential_type("OAuthRefreshToken").unwrap(),
            CredentialType::OAuthRefreshToken
        ));
        assert!(matches!(
            parse_credential_type("ApiKey").unwrap(),
            CredentialType::ApiKey
        ));
        assert!(matches!(
            parse_credential_type("WebhookSecret").unwrap(),
            CredentialType::WebhookSecret
        ));
    }

    #[test]
    fn parse_credential_type_custom() {
        let ct = parse_credential_type("Custom:discord-bot-token").unwrap();
        assert_eq!(ct, CredentialType::Custom("discord-bot-token".to_owned()));
    }

    #[test]
    fn parse_credential_type_invalid() {
        assert!(parse_credential_type("InvalidType").is_err());
    }

    #[test]
    fn parse_credential_key_bytes_valid() {
        let key = [42u8; 32];
        let result = parse_credential_key_bytes(&key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), key);
    }

    #[test]
    fn parse_credential_key_bytes_wrong_length() {
        let key = [42u8; 16];
        assert!(parse_credential_key_bytes(&key).is_err());
    }

    // -------------------------------------------------------------------
    // Credential key derivation
    // -------------------------------------------------------------------

    #[test]
    fn derive_credential_key_returns_32_bytes() {
        let key = vec![42u8; 32];
        let derived = py_bridge_derive_credential_key(key, "bridge-001").unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn derive_credential_key_deterministic() {
        let key = vec![42u8; 32];
        let d1 = py_bridge_derive_credential_key(key.clone(), "bridge-001").unwrap();
        let d2 = py_bridge_derive_credential_key(key, "bridge-001").unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn derive_credential_key_differs_by_bridge_id() {
        let key = vec![42u8; 32];
        let d1 = py_bridge_derive_credential_key(key.clone(), "bridge-001").unwrap();
        let d2 = py_bridge_derive_credential_key(key, "bridge-002").unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn derive_credential_key_rejects_wrong_length() {
        let key = vec![42u8; 16];
        assert!(py_bridge_derive_credential_key(key, "bridge-001").is_err());
    }

    #[test]
    fn generate_credential_key_returns_32_bytes() {
        let key = py_bridge_generate_credential_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_credential_key_unique() {
        let k1 = py_bridge_generate_credential_key();
        let k2 = py_bridge_generate_credential_key();
        assert_ne!(k1, k2, "two CSPRNG keys must differ");
    }

    // -------------------------------------------------------------------
    // Credential store operations (via global InMemoryCredentialStore)
    // -------------------------------------------------------------------

    #[test]
    fn credential_provision_and_retrieve_roundtrip() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = default_scp();
            let bridge_id = "bridge-cred-test-001";
            let key = py_bridge_generate_credential_key();

            // Provision.
            let result = scp.bridge_credential_provision(
                py,
                bridge_id,
                "ApiKey",
                b"my-secret-api-key".to_vec(),
                key.clone(),
            );
            assert!(result.is_ok(), "provision should succeed");

            // Retrieve.
            let plaintext = scp
                .bridge_credential_retrieve(bridge_id, "ApiKey", key)
                .unwrap();
            assert_eq!(plaintext, b"my-secret-api-key");
        });
    }

    #[test]
    fn credential_rotate_replaces_value() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = default_scp();
            let bridge_id = "bridge-cred-test-002";
            let key = py_bridge_generate_credential_key();

            // Provision.
            scp.bridge_credential_provision(
                py,
                bridge_id,
                "OAuthAccessToken",
                b"old-token".to_vec(),
                key.clone(),
            )
            .unwrap();

            // Rotate.
            let result = scp.bridge_credential_rotate(
                py,
                bridge_id,
                "OAuthAccessToken",
                b"new-token".to_vec(),
                key.clone(),
            );
            assert!(result.is_ok());

            // Retrieve should return new value.
            let plaintext = scp
                .bridge_credential_retrieve(bridge_id, "OAuthAccessToken", key)
                .unwrap();
            assert_eq!(plaintext, b"new-token");
        });
    }

    #[test]
    fn credential_list_returns_types() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = default_scp();
            let bridge_id = "bridge-cred-test-003";
            let key = py_bridge_generate_credential_key();

            scp.bridge_credential_provision(
                py,
                bridge_id,
                "ApiKey",
                b"key-val".to_vec(),
                key.clone(),
            )
            .unwrap();

            scp.bridge_credential_provision(
                py,
                bridge_id,
                "WebhookSecret",
                b"secret-val".to_vec(),
                key,
            )
            .unwrap();

            let list = scp.bridge_credential_list(py, bridge_id).unwrap();
            let list_ref = list.bind(py);
            assert_eq!(list_ref.len(), 2);
        });
    }

    #[test]
    fn credential_revoke_destroys_all() {
        crate::init_runtime().ok();
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let scp = default_scp();
            let bridge_id = "bridge-cred-test-004";
            let key = py_bridge_generate_credential_key();

            scp.bridge_credential_provision(
                py,
                bridge_id,
                "ApiKey",
                b"to-be-destroyed".to_vec(),
                key.clone(),
            )
            .unwrap();

            scp.bridge_credential_revoke(bridge_id).unwrap();

            // Retrieve should fail.
            let result = scp.bridge_credential_retrieve(bridge_id, "ApiKey", key);
            assert!(result.is_err());
        });
    }

    #[test]
    fn credential_store_and_get_key_roundtrip() {
        crate::init_runtime().ok();
        let scp = default_scp();
        let bridge_id = "bridge-cred-test-005";
        let key = py_bridge_generate_credential_key();

        scp.bridge_credential_store_key(bridge_id, key.clone())
            .unwrap();

        let retrieved = scp.bridge_credential_get_key(bridge_id).unwrap();
        assert_eq!(retrieved, key);
    }

    #[test]
    fn credential_delete_key_removes_it() {
        crate::init_runtime().ok();
        let scp = default_scp();
        let bridge_id = "bridge-cred-test-006";
        let key = py_bridge_generate_credential_key();

        scp.bridge_credential_store_key(bridge_id, key).unwrap();
        scp.bridge_credential_delete_key(bridge_id).unwrap();

        let result = scp.bridge_credential_get_key(bridge_id);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // OAuth flow helpers
    // -------------------------------------------------------------------

    #[test]
    fn oauth_generate_pkce_returns_verifier_and_challenge() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_bridge_oauth_generate_pkce(py).unwrap();
            let dict = result.bind(py);
            let verifier: String = dict
                .get_item("code_verifier")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            let challenge: String = dict
                .get_item("code_challenge")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();

            assert!(!verifier.is_empty());
            assert!(!challenge.is_empty());
            // Verifier should be base64url-encoded 32 bytes = 43 chars.
            assert_eq!(verifier.len(), 43);
        });
    }

    #[test]
    fn oauth_build_auth_url_contains_required_params() {
        let url = py_bridge_oauth_build_auth_url(
            "https://example.com/authorize",
            "my-client-id",
            "https://example.com/callback",
            vec!["read:messages".to_owned()],
            "test-challenge",
            None,
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client-id"));
        assert!(url.contains("code_challenge=test-challenge"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn oauth_build_auth_url_includes_state_when_provided() {
        let url = py_bridge_oauth_build_auth_url(
            "https://example.com/authorize",
            "my-client-id",
            "https://example.com/callback",
            vec![],
            "challenge",
            Some("csrf-token-123"),
        );
        assert!(url.contains("state=csrf-token-123"));
    }

    #[test]
    fn oauth_scopes_for_relay_mode() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let list = py_bridge_oauth_scopes_for_mode(py, "relay").unwrap();
            let list_ref = list.bind(py);
            assert_eq!(list_ref.len(), 2);
        });
    }

    #[test]
    fn oauth_scopes_for_puppet_mode() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let list = py_bridge_oauth_scopes_for_mode(py, "puppet").unwrap();
            let list_ref = list.bind(py);
            assert_eq!(list_ref.len(), 3);
        });
    }

    #[test]
    fn oauth_scopes_for_api_mode_empty() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let list = py_bridge_oauth_scopes_for_mode(py, "api").unwrap();
            let list_ref = list.bind(py);
            assert_eq!(list_ref.len(), 0);
        });
    }

    #[test]
    fn oauth_scopes_for_invalid_mode_fails() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = py_bridge_oauth_scopes_for_mode(py, "invalid");
            assert!(result.is_err());
        });
    }

    // -------------------------------------------------------------------
    // Envelope seal/open roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn envelope_seal_and_open_roundtrip() {
        let key = scp_core::crypto::sender_keys::generate_sender_key();
        let plaintext = b"Hello from shadow!";

        let envelope_json = py_bridge_seal_shadow_envelope(
            "shadow:bridge-test:alice",
            "@alice#1234",
            "bridge-test-001",
            "did:dht:z6MkOperator",
            "discord",
            "relay",
            key.as_bytes().to_vec(),
            plaintext.to_vec(),
            "ctx-env-test",
            0,
            1,
            Some("msg-001".to_owned()),
            Some(1_700_000_000),
            None, // attributed_role — defaults to "observer"
            None, // provenance_status — defaults to "shadow"
        )
        .unwrap();

        // Verify it's valid JSON.
        assert!(serde_json::from_str::<serde_json::Value>(&envelope_json).is_ok());

        // Open the envelope.
        let decrypted = py_bridge_open_shadow_envelope(
            &envelope_json,
            key.as_bytes().to_vec(),
            "ctx-env-test",
            "shadow:bridge-test:alice",
            0,
            1,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn envelope_open_wrong_key_fails() {
        let key = scp_core::crypto::sender_keys::generate_sender_key();
        let wrong_key = scp_core::crypto::sender_keys::generate_sender_key();

        let envelope_json = py_bridge_seal_shadow_envelope(
            "shadow:test:bob",
            "@bob",
            "bridge-002",
            "did:dht:z6MkOp",
            "slack",
            "relay",
            key.as_bytes().to_vec(),
            b"secret".to_vec(),
            "ctx-env-test-2",
            0,
            1,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let result = py_bridge_open_shadow_envelope(
            &envelope_json,
            wrong_key.as_bytes().to_vec(),
            "ctx-env-test-2",
            "shadow:test:bob",
            0,
            1,
        );
        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn envelope_seal_rejects_invalid_key_length() {
        let result = py_bridge_seal_shadow_envelope(
            "shadow:test:c",
            "@c",
            "bridge-003",
            "did:dht:z6MkOp",
            "discord",
            "relay",
            vec![42u8; 16], // wrong length
            b"msg".to_vec(),
            "ctx-test",
            0,
            1,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }
}
