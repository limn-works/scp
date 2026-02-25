//! Per-context pseudonym derivation for SCP envelope routing.
//!
//! Each participant derives a deterministic pseudonym keypair for every context
//! they join. The pseudonym's public key serves as the `routing_id` in outer
//! envelopes. Relays see only pseudonyms — never real DIDs — so they cannot
//! link activity across contexts.
//!
//! The derivation is:
//! 1. `seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`
//! 2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
//!
//! The HMAC computation happens inside the [`KeyCustody`] boundary. This module
//! simply delegates to [`KeyCustody::derive_pseudonym`].
//!
//! See ADR-002 acceptance criterion 1 and ADR-006 for the custody model.

use scp_platform::traits::{KeyCustody, KeyHandle, PseudonymKeypair};

use super::EnvelopeError;

/// Derives a deterministic, context-scoped pseudonym keypair.
///
/// Delegates to [`KeyCustody::derive_pseudonym`], which computes:
/// ```text
/// seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")
/// pseudonym_keypair = Ed25519_keygen(seed[0..32])
/// ```
///
/// The pseudonym keypair's public key is the `routing_id` used in outer
/// envelopes. Same identity key + same `context_id` always produces the same
/// pseudonym. Different `context_id` produces a different, unlinkable
/// pseudonym.
///
/// # Errors
///
/// Returns [`EnvelopeError::PseudonymDerivationFailed`] if the underlying
/// key custody operation fails (e.g., key handle not found, wrong key type).
pub async fn derive_pseudonym(
    key_custody: &impl KeyCustody,
    identity_key_handle: &KeyHandle,
    context_id: &[u8],
) -> Result<PseudonymKeypair, EnvelopeError> {
    key_custody
        .derive_pseudonym(identity_key_handle, context_id)
        .await
        .map_err(|e| EnvelopeError::PseudonymDerivationFailed(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    use super::*;

    #[tokio::test]
    async fn derive_pseudonym_is_deterministic() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context-1";

        let p1 = derive_pseudonym(&custody, &key_handle, context_id)
            .await
            .unwrap();
        let p2 = derive_pseudonym(&custody, &key_handle, context_id)
            .await
            .unwrap();

        assert_eq!(p1.public_key.as_bytes(), p2.public_key.as_bytes());
    }

    #[tokio::test]
    async fn different_context_produces_different_pseudonym() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let p1 = derive_pseudonym(&custody, &key_handle, b"context-a")
            .await
            .unwrap();
        let p2 = derive_pseudonym(&custody, &key_handle, b"context-b")
            .await
            .unwrap();

        assert_ne!(p1.public_key.as_bytes(), p2.public_key.as_bytes());
    }

    #[tokio::test]
    async fn different_identity_key_produces_different_pseudonym() {
        let custody = InMemoryKeyCustody::new();
        let key1 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let key2 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"same-context";

        let p1 = derive_pseudonym(&custody, &key1, context_id).await.unwrap();
        let p2 = derive_pseudonym(&custody, &key2, context_id).await.unwrap();

        assert_ne!(p1.public_key.as_bytes(), p2.public_key.as_bytes());
    }

    #[tokio::test]
    async fn pseudonym_public_key_is_32_bytes() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let p = derive_pseudonym(&custody, &key_handle, b"ctx")
            .await
            .unwrap();

        assert_eq!(
            p.public_key.as_bytes().len(),
            32,
            "Ed25519 public key should be 32 bytes"
        );
    }
}
