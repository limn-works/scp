//! Shared Ed25519 signature verification helpers for the event log.
//!
//! This module mirrors the verification functions from `scp-core::crypto::ed25519`
//! to avoid a circular dependency on scp-core.

use ed25519_dalek::Verifier;

/// Verifies an Ed25519 signature against a public key and message bytes.
///
/// # Errors
///
/// Returns `Err(String)` describing the failure if:
/// - `public_key` is not exactly 32 bytes
/// - `signature` is not exactly 64 bytes
/// - The signature does not verify against the message
pub fn verify_ed25519_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", public_key.len()))?;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid public key: {e}"))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| format!("signature must be 64 bytes, got {}", signature.len()))?;

    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message, &sig)
        .map_err(|e| format!("signature verification failed: {e}"))
}
