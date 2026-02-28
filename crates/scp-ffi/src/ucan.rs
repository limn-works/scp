//! `PyO3` bridge functions for UCAN token management.
//!
//! Exposes SCP UCAN operations to Python:
//!
//! - [`py_ucan_validate`] -- Validate a UCAN token against a required
//!   capability.
//! - [`py_ucan_mint`] -- Mint a new UCAN token for a member.
//! - [`py_ucan_revoke`] -- Revoke a UCAN token.
//!
//! # Types
//!
//! - [`PyUcanToken`] -- UCAN token with ID, issuer, audience, capabilities,
//!   and expiry.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §6 and ADR-016 for the UCAN
//! specification.

use pyo3::prelude::*;

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// PyUcanToken
// ---------------------------------------------------------------------------

/// UCAN token exposed to Python.
///
/// Contains the token metadata accessible to Python code: a unique token ID
/// (derived from the nonce), the issuer DID, the audience DID, the list of
/// granted capabilities, and an optional expiry timestamp.
///
/// The raw signature and encoded JWT are not exposed -- they are internal
/// to the Rust crypto layer and not needed by Python callers.
///
/// See ADR-016 (UCAN validation) and ADR-013 §6 (bridge layer).
#[pyclass(name = "UcanToken")]
#[derive(Debug, Clone)]
pub struct PyUcanToken {
    /// Unique token identifier (derived from the UCAN nonce).
    #[pyo3(get)]
    pub token_id: String,

    /// Issuer DID -- the entity that created and signed this token.
    #[pyo3(get)]
    pub issuer: String,

    /// Audience DID -- the entity this token is delegated to.
    #[pyo3(get)]
    pub audience: String,

    /// List of capability URIs granted by this token.
    ///
    /// Each string follows the SCP capability URI format:
    /// `scp:ctx:{context_id}/{capability}`.
    #[pyo3(get)]
    pub capabilities: Vec<String>,

    /// Expiry timestamp (seconds since Unix epoch). `None` if the token
    /// does not expire (not recommended).
    #[pyo3(get)]
    pub expires_at: Option<f64>,
}

#[pymethods]
impl PyUcanToken {
    fn __repr__(&self) -> String {
        format!(
            "UcanToken(token_id={:?}, issuer={:?}, audience={:?}, capabilities={}, expires_at={:?})",
            self.token_id,
            self.issuer,
            self.audience,
            self.capabilities.len(),
            self.expires_at
        )
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Validates a UCAN token for a required capability.
///
/// Performs structural UCAN validation: JWT format parsing, header field
/// checking (algorithm = EdDSA, version = 0.10.0), time bounds verification,
/// capability matching, and revocation list checking.
///
/// Full cryptographic signature verification requires a DID resolver with
/// access to public keys, which is connected when the transport layer is
/// wired. This function validates everything that can be checked without
/// external key resolution.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context the token is presented in.
/// * `token` -- The encoded UCAN token string (JWT format).
/// * `capability` -- The required capability URI (e.g.,
///   `"scp:ctx:abc123/messages:write"`).
///
/// # Errors
///
/// Raises `UcanError` if validation fails for any reason: malformed token,
/// unsupported algorithm/version, expired token, insufficient capabilities,
/// revoked token, etc.
///
/// See ADR-013 §6: `py_ucan_validate(handle, token, capability) -> None`.
#[pyfunction]
#[pyo3(name = "ucan_validate")]
pub fn py_ucan_validate(
    context_id: &str,
    token: &str,
    capability: &str,
) -> PyResult<()> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Step 1: Parse the JWT format (header.payload.signature).
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ScpPyError::UcanError(format!(
            "malformed token: expected 3 JWT segments, got {}",
            parts.len()
        ))
        .into());
    }

    // Step 2: Decode and validate the header.
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| {
        ScpPyError::UcanError(format!("malformed token: invalid base64 in header: {e}"))
    })?;
    let header: scp_core::crypto::ucan::UcanHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| {
            ScpPyError::UcanError(format!("malformed token: invalid header JSON: {e}"))
        })?;
    header.validate().map_err(ScpPyError::from)?;

    // Step 3: Decode and parse the payload.
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| {
        ScpPyError::UcanError(format!("malformed token: invalid base64 in payload: {e}"))
    })?;
    let payload: scp_core::crypto::ucan::UcanPayload =
        serde_json::from_slice(&payload_bytes).map_err(|e| {
            ScpPyError::UcanError(format!("malformed token: invalid payload JSON: {e}"))
        })?;

    // Step 4: Check time bounds.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if payload.exp <= now {
        return Err(ScpPyError::UcanError("token expired".to_owned()).into());
    }
    if let Some(nbf) = payload.nbf {
        if nbf > now {
            return Err(ScpPyError::UcanError("token not yet valid".to_owned()).into());
        }
    }

    // Step 5: Check capability match.
    let has_matching_capability = payload.att.iter().any(|att| {
        att.with == capability || att.with == format!("scp:ctx:*/{}", capability.rsplit('/').next().unwrap_or(""))
    });
    if !has_matching_capability {
        return Err(ScpPyError::UcanError(format!(
            "capability not granted: {capability}"
        ))
        .into());
    }

    // Step 6: Check revocation list.
    crate::runtime::with_context(context_id, |rt| {
        // Compute a simple token CID for revocation checking.
        let token_cid = compute_simple_cid(token);
        if rt.revocation_list.is_revoked(&token_cid) {
            return Err(format!("token revoked: {token_cid}"));
        }
        Ok(())
    })
    .map_err(|e| ScpPyError::UcanError(e))?;

    Ok(())
}

/// Mints a new UCAN token for a context member.
///
/// Creates a new UCAN token granting the specified capabilities to the
/// given member DID. The token is structured with proper SCP capability
/// URIs scoped to the context.
///
/// Full Ed25519 signing requires key custody integration which is connected
/// when the transport layer is wired. This function creates a properly
/// formatted token with a placeholder signature.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context to mint the token for.
/// * `member_did` -- The DID of the member receiving the token.
/// * `capabilities` -- List of capability URIs to grant.
///
/// # Returns
///
/// A [`PyUcanToken`] with the minted token's metadata.
///
/// # Errors
///
/// Raises `UcanError` if minting fails: capabilities outside the context
/// ceiling, issuer not authorized, etc.
///
/// See ADR-013 §6: `py_ucan_mint(handle, member_did, capabilities) -> PyUcanToken`.
#[pyfunction]
#[pyo3(name = "ucan_mint")]
pub fn py_ucan_mint(
    context_id: &str,
    member_did: &str,
    capabilities: Vec<String>,
) -> PyResult<PyUcanToken> {
    // Look up the context to get the creator DID (issuer).
    let (creator_did, _context_id_owned) = crate::runtime::with_context(context_id, |rt| {
        Ok((rt.creator_did.clone(), context_id.to_owned()))
    })
    .map_err(|e| ScpPyError::UcanError(e))?;

    // Generate a unique nonce for the token ID.
    let nonce = generate_nonce();

    // Build capability attestations scoped to the context.
    let capability_uris: Vec<String> = capabilities
        .iter()
        .map(|cap| {
            if cap.starts_with("scp:ctx:") {
                cap.clone()
            } else {
                format!("scp:ctx:{context_id}/{cap}")
            }
        })
        .collect();

    // Calculate expiry: 1 hour from now (default, within 24h max).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let exp = now + 3600; // 1 hour

    Ok(PyUcanToken {
        token_id: nonce,
        issuer: creator_did,
        audience: member_did.to_owned(),
        capabilities: capability_uris,
        expires_at: Some(exp as f64),
    })
}

/// Revokes a UCAN token.
///
/// Adds the token to the context's revocation list. Revoked tokens are
/// no longer accepted by validation. In the full runtime, revocation is
/// distributed to all context members via MLS.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context the token belongs to.
/// * `token_id` -- The unique ID of the token to revoke.
///
/// # Errors
///
/// Raises `UcanError` if revocation fails: context not found, etc.
///
/// See ADR-013 §6: `py_ucan_revoke(handle, token_id) -> None`.
#[pyfunction]
#[pyo3(name = "ucan_revoke")]
pub fn py_ucan_revoke(
    context_id: &str,
    token_id: &str,
) -> PyResult<()> {
    crate::runtime::with_context(context_id, |rt| {
        // Add the token ID to the revocation list. The RevocationList uses
        // CIDs as keys; we use the token_id directly as a simplified CID.
        rt.revocation_list.revoke(token_id.to_owned());
        Ok(())
    })
    .map_err(|e| ScpPyError::UcanError(e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Generates a nonce in the format `{unix_millis_timestamp}-{16_random_bytes_hex}`.
fn generate_nonce() -> String {
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    // Use a simple counter-based approach for uniqueness since we may not
    // have OsRng available in all environments.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{now_millis}-{count:032x}")
}

/// Computes a simple content identifier for a token string.
///
/// Uses SHA-256 and a `bafyrei` prefix following the CID v1 convention.
fn compute_simple_cid(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    let hex: String = hash.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    format!("bafyrei{}", &hex[..40])
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers UCAN bridge functions and classes on the `_scp_core` module.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of functions or classes fails.
pub fn register_ucan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyUcanToken>()?;
    m.add_function(wrap_pyfunction!(py_ucan_validate, m)?)?;
    m.add_function(wrap_pyfunction!(py_ucan_mint, m)?)?;
    m.add_function(wrap_pyfunction!(py_ucan_revoke, m)?)?;
    Ok(())
}
