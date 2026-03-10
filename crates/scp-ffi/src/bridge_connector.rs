//! `PyO3` bridge functions for the bridge connector module.
//!
//! Exposes SCP bridge connector operations to Python:
//!
//! - [`py_bridge_register`] -- Register a bridge connector with a context.
//! - [`py_bridge_evaluate_trust`] -- Evaluate trust level for a bridge action.
//! - [`py_bridge_create_shadow`] -- Create a shadow identity.
//!
//! See spec section 12 (Bridge System) and ADR-023.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use scp_core::bridge::provenance::{evaluate_trust_level, mark_bridge_provenance};
use scp_core::bridge::registration::{
    BridgeRegistrationRequest, BridgeRegistry, approve_registration, register_bridge,
};
use scp_core::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow};
use scp_core::bridge::{
    BridgeConnector, BridgeMode, BridgeStatus, ShadowIdentity, ShadowProvenanceStatus,
};
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Registers a new bridge connector with a context.
///
/// Creates a `BridgeRegistry`, submits a registration request, and
/// immediately approves it (for FFI demonstration / testing purposes).
///
/// Returns a dict with the bridge registration details.
///
/// # Arguments
///
/// * `context_id` -- Context to register the bridge in.
/// * `operator_did` -- DID of the human operator accountable for the bridge.
/// * `platform` -- External platform name (e.g., `"discord"`, `"slack"`).
/// * `mode` -- Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
///
/// # Returns
///
/// A dict with `bridge_id`, `operator_did`, `platform`, `mode`, `status`.
///
/// # Errors
///
/// Raises `ValidationError` if `mode` is not recognized or registration fails.
#[pyfunction]
#[pyo3(name = "bridge_register")]
pub fn py_bridge_register(
    py: Python<'_>,
    context_id: &str,
    operator_did: &str,
    platform: &str,
    mode: &str,
) -> PyResult<Py<PyDict>> {
    let bridge_mode = parse_bridge_mode(mode)?;

    let mut registry = BridgeRegistry::new(context_id.to_string());

    let bridge_id = format!(
        "bridge-{platform}-{}",
        context_id.chars().take(8).collect::<String>()
    );
    let request = BridgeRegistrationRequest {
        bridge_id: bridge_id.clone(),
        operator_did: operator_did.into(),
        platform: platform.to_string(),
        mode: bridge_mode,
        context_id: context_id.to_string(),
        requested_at: 0,
        self_hosted: false,
    };

    let _event = register_bridge(&mut registry, request).map_err(|e| ScpPyError::ContextError {
        message: format!("bridge registration failed: {e}"),
        code: "SCP-CTX-2100".to_string(),
    })?;

    let governance_did: scp_identity::DID = operator_did.into();
    let (connector, _approval_event) =
        approve_registration(&mut registry, &bridge_id, &governance_did, 0).map_err(|e| {
            ScpPyError::ContextError {
                message: format!("bridge approval failed: {e}"),
                code: "SCP-CTX-2101".to_string(),
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
        discovery_method: DiscoveryMethod::None,
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
/// Creates a temporary `ShadowRegistry` and calls `create_shadow` with
/// the correct parameters.
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
#[pyfunction]
#[pyo3(name = "bridge_create_shadow")]
#[pyo3(signature = (bridge_id, platform_handle, bridge_mode, context_id="ctx-shadow"))]
pub fn py_bridge_create_shadow(
    py: Python<'_>,
    bridge_id: &str,
    platform_handle: &str,
    bridge_mode: &str,
    context_id: &str,
) -> PyResult<Py<PyDict>> {
    let mode = parse_bridge_mode(bridge_mode)?;

    let shadow_id = format!("shadow-{bridge_id}-{}", platform_handle.replace('@', ""));
    let mut shadow_registry = ShadowRegistry::new(context_id.to_string());

    let params = CreateShadowParams {
        shadow_id: &shadow_id,
        bridge_id,
        bridge_mode: mode,
        platform_handle,
        context_member_dids: &[], // no existing context member DIDs for collision check
        timestamp: 0,
    };
    let mut sender_key_store = scp_core::crypto::sender_keys::SenderKeyStore::new();
    let (shadow, _event) = create_shadow(&mut shadow_registry, &mut sender_key_store, &params)
        .map_err(|e| ScpPyError::ContextError {
            message: format!("shadow creation failed: {e}"),
            code: "SCP-CTX-2102".to_string(),
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
            code: "SCP-VALID-7050".to_string(),
        }
        .into()),
    }
}

fn parse_shadow_status(s: &str) -> PyResult<ShadowProvenanceStatus> {
    match s {
        "shadow" => Ok(ShadowProvenanceStatus::Shadow),
        "claimed" => Ok(ShadowProvenanceStatus::Claimed),
        other => Err(ScpPyError::ValidationError {
            message: format!("invalid shadow_status '{other}': expected 'shadow' or 'claimed'"),
            code: "SCP-VALID-7051".to_string(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers bridge connector bridge functions on the `_scp_core` module.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_bridge_connector(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_bridge_register, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_evaluate_trust, m)?)?;
    m.add_function(wrap_pyfunction!(py_bridge_create_shadow, m)?)?;
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
}
