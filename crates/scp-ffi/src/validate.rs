//! Input validation for the `PyO3` FFI bridge boundary.
//!
//! All public `#[pyfunction]` bridge functions validate string inputs before
//! passing them to scp-core. Each validator delegates to the shared
//! implementation in [`scp_ffi_common::validate`] and converts errors to
//! [`ScpPyError`].
//!
//! See GitHub issue #104, #1601, and ADR-013 §3-§7 (bridge function signatures).

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Constants — re-exported from common
// ---------------------------------------------------------------------------

pub use scp_ffi_common::validate::{
    MAX_ATTESTATION_HANDLE_LEN, MAX_ATTESTATION_PLATFORM_LEN, MAX_ATTESTATION_PROOF_LEN,
    MAX_CAPABILITY_URI_LEN, MAX_CONTEXT_DESCRIPTION_LEN, MAX_CONTEXT_ID_LEN, MAX_CONTEXT_NAME_LEN,
    MAX_DEPLOY_ID_LEN, MAX_DID_LEN, MAX_GOVERNANCE_REASON_LEN,
    MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID, MAX_MCP_HANDLE_LEN, MAX_PAYMENT_ADAPTER_REF_LEN,
    MAX_RELAY_URL_LEN, MAX_ROLE_NAME_LEN, MAX_OUTLET_ID_LEN, MAX_OUTLET_NAME_LEN,
    MAX_TRANSPORT_MODE_LEN, MAX_UCAN_TOKEN_LEN,
};

// ---------------------------------------------------------------------------
// Validators — thin delegates to scp-ffi-common with ScpPyError conversion
// ---------------------------------------------------------------------------

/// Validates a context ID string. See [`scp_ffi_common::validate::validate_context_id`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the context ID is invalid.
pub fn validate_context_id(context_id: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_context_id(context_id)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a deploy ID string. See [`scp_ffi_common::validate::validate_deploy_id`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the deploy ID is invalid.
pub fn validate_deploy_id(deploy_id: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_deploy_id(deploy_id)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a DID string. See [`scp_ffi_common::validate::validate_did`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the DID is invalid.
pub fn validate_did(did: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_did(did).map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a outlet name string. See [`scp_ffi_common::validate::validate_outlet_name`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the outlet name is invalid.
pub fn validate_outlet_name(name: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_outlet_name(name)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a outlet ID string. See [`scp_ffi_common::validate::validate_outlet_id`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the outlet ID is invalid.
pub fn validate_outlet_id(outlet_id: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_outlet_id(outlet_id)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a capability URI string. See [`scp_ffi_common::validate::validate_capability_uri`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the capability URI is invalid.
pub fn validate_capability_uri(uri: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_capability_uri(uri)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a UCAN token string. See [`scp_ffi_common::validate::validate_ucan_token`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the UCAN token is invalid.
pub fn validate_ucan_token(token: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_ucan_token(token)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates an MCP handle string. See [`scp_ffi_common::validate::validate_mcp_handle`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the MCP handle is invalid.
pub fn validate_mcp_handle(handle: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_mcp_handle(handle)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a relay URL string. See [`scp_ffi_common::validate::validate_relay_url`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the relay URL is invalid.
pub fn validate_relay_url(url: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_relay_url(url).map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a transport mode string. See [`scp_ffi_common::validate::validate_transport_mode`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the transport mode is invalid.
pub fn validate_transport_mode(mode: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_transport_mode(mode)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a role name. See [`scp_ffi_common::validate::validate_role_name`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the role name is invalid.
pub fn validate_role_name(role: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_role_name(role)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a context name. See [`scp_ffi_common::validate::validate_context_name`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the context name is invalid.
pub fn validate_context_name(name: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_context_name(name)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a context description. See [`scp_ffi_common::validate::validate_context_description`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the context description is invalid.
pub fn validate_context_description(description: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_context_description(description)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a governance reason/purpose. See [`scp_ffi_common::validate::validate_governance_reason`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the reason is invalid.
pub fn validate_governance_reason(reason: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_governance_reason(reason)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates a payment adapter ref. See [`scp_ffi_common::validate::validate_payment_adapter_ref`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if the adapter ref is invalid.
pub fn validate_payment_adapter_ref(adapter_ref: &str) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_payment_adapter_ref(adapter_ref)
        .map_err(|e| ScpPyError::validation(e.message))
}

/// Validates attestation fields. See [`scp_ffi_common::validate::validate_attestation_fields`].
///
/// # Errors
///
/// Returns [`ScpPyError`] if any attestation field is invalid.
pub fn validate_attestation_fields(
    platform: &str,
    handle: &str,
    proof: &str,
) -> Result<(), ScpPyError> {
    scp_ffi_common::validate::validate_attestation_fields(platform, handle, proof)
        .map_err(|e| ScpPyError::validation(format!("attestation field validation failed: {e}")))
}

// ---------------------------------------------------------------------------
// Tests — verify ScpPyError wrapping works for each validator
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn context_id_valid() {
        assert!(validate_context_id("abc123").is_ok());
    }

    #[test]
    fn context_id_empty_rejected() {
        assert!(validate_context_id("").is_err());
    }

    #[test]
    fn context_id_special_chars_rejected() {
        assert!(validate_context_id("abc/def").is_err());
    }

    #[test]
    fn deploy_id_valid() {
        assert!(validate_deploy_id("deploy-abc-123").is_ok());
    }

    #[test]
    fn deploy_id_special_chars_rejected() {
        assert!(validate_deploy_id("deploy/abc").is_err());
    }

    #[test]
    fn did_valid() {
        assert!(validate_did("did:dht:z6Mkabcdef").is_ok());
    }

    #[test]
    fn did_missing_prefix_rejected() {
        assert!(validate_did("not-a-did").is_err());
    }

    #[test]
    fn outlet_name_valid() {
        assert!(validate_outlet_name("my-outlet").is_ok());
    }

    #[test]
    fn outlet_name_braces_rejected() {
        assert!(validate_outlet_name("outlet-{name}").is_err());
    }

    #[test]
    fn outlet_name_html_rejected() {
        assert!(validate_outlet_name("<script>outlet").is_err());
    }

    #[test]
    fn outlet_id_valid() {
        assert!(validate_outlet_id("outlet-my-outlet").is_ok());
    }

    #[test]
    fn outlet_id_uppercase_rejected() {
        assert!(validate_outlet_id("Outlet-Name").is_err());
    }

    #[test]
    fn capability_uri_valid() {
        assert!(validate_capability_uri("messages:write").is_ok());
    }

    #[test]
    fn capability_uri_empty_rejected() {
        assert!(validate_capability_uri("").is_err());
    }

    #[test]
    fn ucan_token_valid() {
        assert!(
            validate_ucan_token("eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6ZGh0Ono2TWsifQ.sig").is_ok()
        );
    }

    #[test]
    fn ucan_token_control_chars_rejected() {
        assert!(validate_ucan_token("token\ninjection").is_err());
    }

    #[test]
    fn mcp_handle_valid() {
        assert!(validate_mcp_handle("mcp-server-a1b2c3d4").is_ok());
    }

    #[test]
    fn relay_url_valid() {
        assert!(validate_relay_url("wss://relay.example.com/scp/v1").is_ok());
    }

    #[test]
    fn relay_url_invalid_scheme_rejected() {
        assert!(validate_relay_url("ftp://relay.example.com").is_err());
    }

    #[test]
    fn transport_mode_valid() {
        assert!(validate_transport_mode("stdio").is_ok());
        assert!(validate_transport_mode("sse").is_ok());
    }

    #[test]
    fn transport_mode_invalid_rejected() {
        assert!(validate_transport_mode("grpc").is_err());
    }

    #[test]
    fn role_name_valid() {
        assert!(validate_role_name("admin").is_ok());
    }

    #[test]
    fn role_name_html_rejected() {
        assert!(validate_role_name("<script>admin").is_err());
    }

    #[test]
    fn context_name_valid() {
        assert!(validate_context_name("My Context").is_ok());
    }

    #[test]
    fn governance_reason_valid() {
        assert!(validate_governance_reason("Member violated guidelines").is_ok());
    }

    #[test]
    fn payment_adapter_ref_valid() {
        assert!(validate_payment_adapter_ref("lightning").is_ok());
    }

    #[test]
    fn attestation_fields_valid() {
        assert!(validate_attestation_fields("github.com", "@alice", r#"{"sig":"abc"}"#).is_ok());
    }

    #[test]
    fn attestation_platform_html_rejected() {
        assert!(validate_attestation_fields("<evil>", "@alice", "proof").is_err());
    }
}
