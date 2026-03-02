//! Shared Ed25519 signature verification helpers.
//!
//! This module is the single source of truth for Ed25519 signature verification
//! in SCP. All module-specific verification functions delegate to the helpers
//! here rather than inlining `VerifyingKey::from_bytes` + `Signature::from_bytes`
//! + `verify` sequences.
//!
//! Two variants are provided:
//! - [`verify_ed25519_signature`] — standard verification (cofactored).
//! - [`verify_ed25519_signature_strict`] — strict verification (cofactorless,
//!   rejects small-order points). Used for UCAN tokens and inner envelopes.
//!
//! See GitHub issue #81.

use ed25519_dalek::Verifier;

/// Verifies an Ed25519 signature against a public key and message bytes.
///
/// This is the primary verification entry point for SCP. Module-specific
/// verification functions should call this (or [`verify_ed25519_signature_strict`])
/// and map the `Err(String)` to their local error type.
///
/// Uses cofactored verification (`verify`), which is the default for most
/// SCP verification paths (event logs, attestations, challenges, sender keys,
/// shadow claiming).
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
    let (verifying_key, sig) = parse_key_and_signature(public_key, signature)?;

    verifying_key
        .verify(message, &sig)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Verifies an Ed25519 signature using strict verification.
///
/// Strict verification (`verify_strict`) additionally rejects signatures
/// involving small-order points, providing stronger guarantees against
/// certain cryptographic attacks. Used for UCAN tokens (ADR-016) and
/// inner envelope verification (ADR-002).
///
/// # Errors
///
/// Returns `Err(String)` describing the failure if:
/// - `public_key` is not exactly 32 bytes
/// - `signature` is not exactly 64 bytes
/// - The signature does not verify against the message
pub fn verify_ed25519_signature_strict(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let (verifying_key, sig) = parse_key_and_signature(public_key, signature)?;

    verifying_key
        .verify_strict(message, &sig)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Parses a public key and signature from raw byte slices into typed values.
///
/// Shared between [`verify_ed25519_signature`] and
/// [`verify_ed25519_signature_strict`] to avoid duplicating the parsing logic.
fn parse_key_and_signature(
    public_key: &[u8],
    signature: &[u8],
) -> Result<(ed25519_dalek::VerifyingKey, ed25519_dalek::Signature), String> {
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", public_key.len()))?;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid public key: {e}"))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| format!("signature must be 64 bytes, got {}", signature.len()))?;

    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    Ok((verifying_key, sig))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use ed25519_dalek::Signer;

    use super::*;

    fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    #[test]
    fn valid_signature_verifies() {
        let (vk, sk) = test_keypair();
        let message = b"hello SCP";
        let sig = sk.sign(message);

        let result = verify_ed25519_signature(vk.as_bytes(), message, &sig.to_bytes());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn valid_signature_verifies_strict() {
        let (vk, sk) = test_keypair();
        let message = b"strict check";
        let sig = sk.sign(message);

        let result = verify_ed25519_signature_strict(vk.as_bytes(), message, &sig.to_bytes());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn tampered_signature_fails() {
        let (vk, sk) = test_keypair();
        let message = b"hello SCP";
        let sig = sk.sign(message);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0xff;

        let result = verify_ed25519_signature(vk.as_bytes(), message, &sig_bytes);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed"),
            "unexpected error message"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let (_, sk) = test_keypair();
        let (other_vk, _) = test_keypair();
        let message = b"hello SCP";
        let sig = sk.sign(message);

        let result = verify_ed25519_signature(other_vk.as_bytes(), message, &sig.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn wrong_message_fails() {
        let (vk, sk) = test_keypair();
        let sig = sk.sign(b"original message");

        let result = verify_ed25519_signature(vk.as_bytes(), b"different message", &sig.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn short_public_key_fails() {
        let result = verify_ed25519_signature(&[0u8; 16], b"msg", &[0u8; 64]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("public key must be 32 bytes"),
            "unexpected error message"
        );
    }

    #[test]
    fn short_signature_fails() {
        let (vk, _) = test_keypair();
        let result = verify_ed25519_signature(vk.as_bytes(), b"msg", &[0u8; 32]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("signature must be 64 bytes"),
            "unexpected error message"
        );
    }

    #[test]
    fn empty_message_works() {
        let (vk, sk) = test_keypair();
        let sig = sk.sign(b"");

        let result = verify_ed25519_signature(vk.as_bytes(), b"", &sig.to_bytes());
        assert!(result.is_ok());
    }
}
