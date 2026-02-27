//! `PyO3` bridge functions for UCAN token management.
//!
//! Exposes SCP UCAN operations to Python:
//!
//! - [`py_ucan_validate`] — Validate a UCAN token against a required
//!   capability.
//! - [`py_ucan_mint`] — Mint a new UCAN token for a member.
//! - [`py_ucan_revoke`] — Revoke a UCAN token.
//!
//! # Types
//!
//! - [`PyUcanToken`] — UCAN token with ID, issuer, audience, capabilities,
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
/// The raw signature and encoded JWT are not exposed — they are internal
/// to the Rust crypto layer and not needed by Python callers.
///
/// See ADR-016 (UCAN validation) and ADR-013 §6 (bridge layer).
#[pyclass(name = "UcanToken")]
#[derive(Debug, Clone)]
pub struct PyUcanToken {
    /// Unique token identifier (derived from the UCAN nonce).
    #[pyo3(get)]
    pub token_id: String,

    /// Issuer DID — the entity that created and signed this token.
    #[pyo3(get)]
    pub issuer: String,

    /// Audience DID — the entity this token is delegated to.
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
/// Performs full UCAN validation: signature verification, time bounds
/// checking, delegation chain traversal, attenuation enforcement, nonce
/// replay detection, and capability matching.
///
/// # Arguments
///
/// * `context_id` — The ID of the context the token is presented in.
/// * `token` — The encoded UCAN token string (JWT format).
/// * `capability` — The required capability URI (e.g.,
///   `"scp:ctx:abc123/messages:write"`).
///
/// # Errors
///
/// Raises `UcanError` if validation fails for any reason: malformed token,
/// invalid signature, expired token, insufficient capabilities, revoked
/// token, broken delegation chain, etc.
///
/// See ADR-013 §6: `py_ucan_validate(handle, token, capability) -> None`.
#[pyfunction]
#[pyo3(name = "ucan_validate")]
pub fn py_ucan_validate(
    _context_id: &str,
    _token: &str,
    _capability: &str,
) -> PyResult<()> {
    Err(ScpPyError::UcanError(
        "not yet connected to runtime — UCAN validation requires a live context handle"
            .to_owned(),
    )
    .into())
}

/// Mints a new UCAN token for a context member.
///
/// Creates a new UCAN token granting the specified capabilities to the
/// given member DID. The token is signed by the context creator's key
/// (or the delegating member's key in a delegation chain).
///
/// # Arguments
///
/// * `context_id` — The ID of the context to mint the token for.
/// * `member_did` — The DID of the member receiving the token.
/// * `capabilities` — List of capability URIs to grant.
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
    _context_id: &str,
    _member_did: &str,
    _capabilities: Vec<String>,
) -> PyResult<PyUcanToken> {
    Err(ScpPyError::UcanError(
        "not yet connected to runtime — UCAN minting requires a live context handle".to_owned(),
    )
    .into())
}

/// Revokes a UCAN token.
///
/// Adds the token to the context's revocation list. Revoked tokens are
/// no longer accepted by validation. Revocation is distributed to all
/// context members via MLS.
///
/// # Arguments
///
/// * `context_id` — The ID of the context the token belongs to.
/// * `token_id` — The unique ID of the token to revoke.
///
/// # Errors
///
/// Raises `UcanError` if revocation fails: token not found, revoker not
/// authorized (must be the token's issuer or context creator), etc.
///
/// See ADR-013 §6: `py_ucan_revoke(handle, token_id) -> None`.
#[pyfunction]
#[pyo3(name = "ucan_revoke")]
pub fn py_ucan_revoke(
    _context_id: &str,
    _token_id: &str,
) -> PyResult<()> {
    Err(ScpPyError::UcanError(
        "not yet connected to runtime — UCAN revocation requires a live context handle"
            .to_owned(),
    )
    .into())
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
