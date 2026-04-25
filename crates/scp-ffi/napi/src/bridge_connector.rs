//! napi-rs bridge for bridge connector operations.
//!
//! Exposes SCP bridge connector operations to Node.js/Bun:
//!
//! - [`bridge_evaluate_trust`] -- Evaluate trust level for a bridge action.
//! - [`bridge_register`] -- Register a bridge connector with a context.
//! - [`bridge_create_shadow`] -- Create a shadow identity.
//!
//! See spec section 12 (Bridge System) and ADR-023.

use scp_ffi_common::bridge_state::BridgeContextState;
use scp_ffi_common::error_codes as codes;

use napi_derive::napi;

use scp_core::bridge::provenance::{evaluate_trust_level, mark_bridge_provenance};
use scp_core::bridge::registration::{
    BridgeRegistrationMetadata, BridgeRegistrationRequest, BridgeRegistry, approve_registration,
    register_bridge,
};
use scp_core::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow};
use scp_core::bridge::{
    BridgeConnector, BridgeMode, BridgeStatus, ShadowIdentity, ShadowProvenanceStatus,
};
use scp_core::crypto::sender_keys::SenderKeyStore;
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Shadow identity creation result.
#[napi(object)]
pub struct NapiShadowIdentity {
    /// Unique identifier for this shadow identity.
    pub shadow_id: String,
    /// External platform handle.
    pub platform_handle: String,
    /// Bridge connector that created this shadow.
    pub bridge_id: String,
    /// Role attributed to this shadow.
    pub attributed_role: String,
    /// Provenance status: `"Shadow"` or `"Claimed"`.
    pub provenance_status: String,
}

/// Bridge registration result.
#[derive(Debug)]
#[napi(object)]
pub struct NapiBridgeRegistration {
    /// Unique identifier for the registered bridge.
    pub bridge_id: String,
    /// DID of the bridge operator.
    pub operator_did: String,
    /// External platform name.
    pub platform: String,
    /// Bridge operating mode.
    pub mode: String,
    /// Bridge status after registration.
    pub status: String,
    /// Context the bridge is registered in.
    pub context_id: String,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Evaluates the trust level for an action based on bridge provenance.
///
/// Returns an integer (0-3) representing the trust tier.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn bridge_evaluate_trust(
    is_bridged: bool,
    is_native_transport: bool,
    shadow_status: String,
) -> napi::Result<u32> {
    if !is_bridged {
        let level = evaluate_trust_level(None, is_native_transport);
        return Ok(level as u32);
    }

    let status = parse_shadow_status(&shadow_status)?;

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
    Ok(level as u32)
}

/// Registers a new bridge connector with a context.
///
/// Creates a temporary `BridgeRegistry`, submits a registration request,
/// and immediately approves it using the provided governance DID.
///
/// The `governance_did` must differ from `operator_did` — self-approval is
/// forbidden per ADR-023.
///
/// # Errors
///
/// Returns a validation error if `operator_did` or `governance_did` is not a
/// valid DID string (empty, exceeds 512 bytes, missing `did:{method}:{id}`
/// structure, method not lowercase alphanumeric, or contains control
/// characters), or if `mode` is not a recognized bridge mode.
/// Returns a context error if the governance DID matches the operator DID
/// (self-approval) or if registration fails.
#[napi]
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn bridge_register(
    context_id: String,
    operator_did: String,
    governance_did: String,
    platform: String,
    mode: String,
    webhook_url: Option<String>,
    platform_key: Option<Vec<u8>>,
    max_shadows: Option<u32>,
    metadata_display_name: Option<String>,
    metadata_description: Option<String>,
    metadata_operator_contact: Option<String>,
) -> napi::Result<NapiBridgeRegistration> {
    scp_ffi_common::validate::validate_did(&operator_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    scp_ffi_common::validate::validate_did(&governance_did)
        .map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;

    let bridge_mode = parse_bridge_mode(&mode)?;

    let parsed_platform_key = platform_key
        .map(|k| {
            <[u8; 32]>::try_from(k.as_slice()).map_err(|_| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("platform_key must be exactly 32 bytes, got {}", k.len()),
                    code: codes::VALID_7052.to_owned(),
                })
            })
        })
        .transpose()?;

    let mut registry = BridgeRegistry::new(context_id.clone());

    // Bridge ID per spec §12.2.1: SHA-256(context_id || operator_did || platform || timestamp).
    let (bridge_id, now_secs) =
        scp_ffi_common::generate_bridge_id(&context_id, &operator_did, &platform);
    let request = BridgeRegistrationRequest {
        bridge_id: bridge_id.clone(),
        operator_did: operator_did.clone().into(),
        platform: platform.clone(),
        mode: bridge_mode,
        context_id: context_id.clone(),
        requested_at: now_secs,
        self_hosted: false,
        webhook_url,
        platform_key: parsed_platform_key,
        max_shadows: max_shadows.unwrap_or(10_000),
        metadata: BridgeRegistrationMetadata {
            display_name: metadata_display_name.unwrap_or_default(),
            description: metadata_description.unwrap_or_default(),
            operator_contact: metadata_operator_contact.unwrap_or_default(),
        },
    };

    let _event = register_bridge(&mut registry, request).map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("bridge registration failed: {e}"),
            code: codes::CTX_2100.to_owned(),
        })
    })?;

    let approver_did: scp_identity::DID = governance_did.into();
    let (connector, _approval_event) =
        approve_registration(&mut registry, &bridge_id, &approver_did, 0).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("bridge approval failed: {e}"),
                code: codes::CTX_2101.to_owned(),
            })
        })?;

    Ok(NapiBridgeRegistration {
        bridge_id: connector.bridge_id,
        operator_did,
        platform,
        mode,
        status: "active".to_string(),
        context_id,
    })
}

/// Creates a shadow identity for an external platform participant.
///
/// Uses the persistent per-context `ShadowRegistry` and `SenderKeyStore`
/// from the process-global bridge state registry, ensuring that shadow
/// identity state and sender keys survive across function calls.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn bridge_create_shadow(
    bridge_id: String,
    platform_handle: String,
    bridge_mode: String,
    context_id: Option<String>,
) -> napi::Result<NapiShadowIdentity> {
    let mode = parse_bridge_mode(&bridge_mode)?;
    let ctx_id = context_id.unwrap_or_else(|| "ctx-shadow".to_string());

    let shadow_id = format!("shadow-{bridge_id}-{}", platform_handle.replace('@', ""));

    let params = CreateShadowParams {
        shadow_id: &shadow_id,
        bridge_id: &bridge_id,
        bridge_mode: mode,
        platform_handle: &platform_handle,
        context_member_dids: &[],
        timestamp: 0,
    };

    let bi = crate::runtime::bridge_instance()?;
    let mut entry = bi
        .bridge_state()
        .entry(ctx_id.clone())
        .or_insert_with(|| BridgeContextState {
            shadow_registry: ShadowRegistry::new(ctx_id),
            sender_key_store: SenderKeyStore::new(),
        });
    let state = entry.value_mut();

    let (shadow, _event) = create_shadow(
        &mut state.shadow_registry,
        &mut state.sender_key_store,
        &params,
    )
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("shadow creation failed: {e}"),
            code: codes::CTX_2102.to_owned(),
        })
    })?;

    Ok(NapiShadowIdentity {
        shadow_id: shadow.shadow_id,
        platform_handle: shadow.platform_handle,
        bridge_id: shadow.bridge_id,
        attributed_role: shadow.attributed_role,
        provenance_status: format!("{:?}", shadow.provenance_status),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_bridge_mode(s: &str) -> napi::Result<BridgeMode> {
    match s {
        "relay" => Ok(BridgeMode::Relay),
        "puppet" => Ok(BridgeMode::Puppet),
        "api" => Ok(BridgeMode::Api),
        "cooperative" => Ok(BridgeMode::Cooperative),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid bridge mode '{other}': expected 'relay', 'puppet', 'api', or 'cooperative'"
            ),
            code: codes::VALID_7050.to_owned(),
        }
        .into()),
    }
}

fn parse_shadow_status(s: &str) -> napi::Result<ShadowProvenanceStatus> {
    match s {
        "shadow" => Ok(ShadowProvenanceStatus::Shadow),
        "claimed" => Ok(ShadowProvenanceStatus::Claimed),
        other => Err(ScpNapiError::Validation {
            message: format!("invalid shadow_status '{other}': expected 'shadow' or 'claimed'"),
            code: codes::VALID_7051.to_owned(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_core::bridge::provenance::BridgeTrustLevel;

    #[test]
    fn evaluate_trust_native_native() {
        let result = bridge_evaluate_trust(false, true, "shadow".to_owned()).unwrap();
        assert_eq!(result, BridgeTrustLevel::NativeNative as u32);
    }

    #[test]
    fn evaluate_trust_shadow_bridged() {
        let result = bridge_evaluate_trust(true, false, "shadow".to_owned()).unwrap();
        assert_eq!(result, BridgeTrustLevel::ShadowBridged as u32);
    }

    #[test]
    fn evaluate_trust_claimed_bridged() {
        let result = bridge_evaluate_trust(true, false, "claimed".to_owned()).unwrap();
        assert_eq!(result, BridgeTrustLevel::ClaimedBridged as u32);
    }

    #[test]
    fn register_bridge_returns_active() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:governance".to_owned(),
            "discord".to_owned(),
            "relay".to_owned(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(result.status, "active");
        assert_eq!(result.platform, "discord");
        // bridge_id must be a 64-char hex string (SHA-256 output per §12.2.1)
        assert_eq!(result.bridge_id.len(), 64);
        assert!(result.bridge_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn register_bridge_rejects_self_approval() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:operator".to_owned(),
            "discord".to_owned(),
            "relay".to_owned(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("approver cannot be the same"),
            "expected self-approval error, got: {err}"
        );
    }

    #[test]
    fn register_bridge_with_optional_fields() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:governance".to_owned(),
            "discord".to_owned(),
            "cooperative".to_owned(),
            Some("https://example.com/webhook".to_owned()),
            Some(vec![42u8; 32]),
            Some(500),
            Some("My Discord Bridge".to_owned()),
            Some("Bridges #general channel".to_owned()),
            Some("admin@example.com".to_owned()),
        )
        .unwrap();
        assert_eq!(result.status, "active");
    }

    #[test]
    fn register_bridge_rejects_invalid_platform_key_length() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:governance".to_owned(),
            "discord".to_owned(),
            "cooperative".to_owned(),
            None,
            Some(vec![42u8; 16]), // wrong length
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_shadow_returns_observer_role() {
        crate::runtime::init_supervisor_for_test();
        let result = bridge_create_shadow(
            "bridge-1".to_owned(),
            "@user".to_owned(),
            "relay".to_owned(),
            None,
        )
        .unwrap();
        assert_eq!(result.attributed_role, "observer");
    }
}
