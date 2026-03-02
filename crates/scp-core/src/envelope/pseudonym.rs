//! Per-context pseudonym derivation for SCP envelope routing.
//!
//! Each participant derives a deterministic pseudonym keypair for every context
//! they join. The pseudonym's public key serves as the `routing_id` in outer
//! envelopes. Relays see only pseudonyms — never real DIDs — so they cannot
//! link activity across contexts.
//!
//! # Derivation (v1 — epoch 0)
//!
//! 1. `seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`
//! 2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
//!
//! # Rotatable derivation (v2 — epoch > 0)
//!
//! To mitigate relay-side pseudonym correlation (BLACK-001), pseudonyms can
//! be rotated by including a rotation epoch in the HMAC input:
//!
//! 1. `seed = HMAC-SHA256(identity_key_material, context_id || epoch_BE || "scp-pseudonym-v2")`
//! 2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
//!
//! Epoch 0 in v2 derivation produces a DIFFERENT pseudonym than the v1
//! derivation (different domain separator). This is intentional — once a
//! context opts into rotation, all pseudonyms are in the v2 domain.
//!
//! The HMAC computation happens inside the [`KeyCustody`] boundary. This module
//! delegates to [`KeyCustody::derive_pseudonym`] (v1) or
//! [`KeyCustody::derive_rotatable_pseudonym`] (v2).
//!
//! See ADR-002 acceptance criterion 1, ADR-006 for the custody model, and
//! BLACK-001 for the threat model motivating rotation.

use scp_platform::traits::{KeyCustody, KeyHandle, PseudonymKeypair};

use super::EnvelopeError;

/// Derives a deterministic, context-scoped pseudonym keypair (v1, non-rotatable).
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
/// For contexts that support pseudonym rotation, use
/// [`derive_rotatable_pseudonym`] instead.
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

/// Derives a rotatable, epoch-scoped pseudonym keypair (v2).
///
/// Delegates to [`KeyCustody::derive_rotatable_pseudonym`], which computes:
/// ```text
/// seed = HMAC-SHA256(identity_key_material, context_id || epoch_BE || "scp-pseudonym-v2")
/// pseudonym_keypair = Ed25519_keygen(seed[0..32])
/// ```
///
/// Changing `pseudonym_epoch` produces a different, unlinkable pseudonym for
/// the same identity and context. This breaks long-term pseudonym-level traffic
/// analysis by a compromised relay (BLACK-001).
///
/// **Transition protocol:** During a rotation, the client subscribes to BOTH
/// the old and new `routing_id` for a grace period (recommended: 2x the
/// context's blob TTL) to avoid missing messages from peers who have not yet
/// learned the new pseudonym. The sender announces the new `routing_id` to
/// group members via an MLS application message.
///
/// # Errors
///
/// Returns [`EnvelopeError::PseudonymDerivationFailed`] if the underlying
/// key custody operation fails (e.g., key handle not found, wrong key type).
pub async fn derive_rotatable_pseudonym(
    key_custody: &impl KeyCustody,
    identity_key_handle: &KeyHandle,
    context_id: &[u8],
    pseudonym_epoch: u64,
) -> Result<PseudonymKeypair, EnvelopeError> {
    key_custody
        .derive_rotatable_pseudonym(identity_key_handle, context_id, pseudonym_epoch)
        .await
        .map_err(|e| EnvelopeError::PseudonymDerivationFailed(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    use super::*;

    // -----------------------------------------------------------------------
    // v1 (non-rotatable) pseudonym tests
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // v2 (rotatable) pseudonym tests — BLACK-001 mitigation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotatable_pseudonym_is_deterministic() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context-1";

        let p1 = derive_rotatable_pseudonym(&custody, &key_handle, context_id, 5)
            .await
            .unwrap();
        let p2 = derive_rotatable_pseudonym(&custody, &key_handle, context_id, 5)
            .await
            .unwrap();

        assert_eq!(
            p1.public_key.as_bytes(),
            p2.public_key.as_bytes(),
            "same epoch must produce same pseudonym"
        );
    }

    #[tokio::test]
    async fn different_epoch_produces_different_pseudonym() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context-1";

        let p1 = derive_rotatable_pseudonym(&custody, &key_handle, context_id, 0)
            .await
            .unwrap();
        let p2 = derive_rotatable_pseudonym(&custody, &key_handle, context_id, 1)
            .await
            .unwrap();

        assert_ne!(
            p1.public_key.as_bytes(),
            p2.public_key.as_bytes(),
            "different epochs must produce different pseudonyms (BLACK-001)"
        );
    }

    #[tokio::test]
    async fn rotatable_pseudonym_differs_from_v1() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"test-context-1";

        let v1 = derive_pseudonym(&custody, &key_handle, context_id)
            .await
            .unwrap();
        let v2_epoch0 = derive_rotatable_pseudonym(&custody, &key_handle, context_id, 0)
            .await
            .unwrap();

        assert_ne!(
            v1.public_key.as_bytes(),
            v2_epoch0.public_key.as_bytes(),
            "v2 epoch 0 must differ from v1 (different domain separator)"
        );
    }

    #[tokio::test]
    async fn rotatable_pseudonym_different_context_different_key() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let p1 = derive_rotatable_pseudonym(&custody, &key_handle, b"context-a", 0)
            .await
            .unwrap();
        let p2 = derive_rotatable_pseudonym(&custody, &key_handle, b"context-b", 0)
            .await
            .unwrap();

        assert_ne!(
            p1.public_key.as_bytes(),
            p2.public_key.as_bytes(),
            "different contexts must produce different pseudonyms even at same epoch"
        );
    }

    #[tokio::test]
    async fn rotatable_pseudonym_different_identity_different_key() {
        let custody = InMemoryKeyCustody::new();
        let key1 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let key2 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let context_id = b"same-context";

        let p1 = derive_rotatable_pseudonym(&custody, &key1, context_id, 0)
            .await
            .unwrap();
        let p2 = derive_rotatable_pseudonym(&custody, &key2, context_id, 0)
            .await
            .unwrap();

        assert_ne!(
            p1.public_key.as_bytes(),
            p2.public_key.as_bytes(),
            "different identity keys must produce different pseudonyms"
        );
    }

    #[tokio::test]
    async fn rotatable_pseudonym_public_key_is_32_bytes() {
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let p = derive_rotatable_pseudonym(&custody, &key_handle, b"ctx", 42)
            .await
            .unwrap();

        assert_eq!(
            p.public_key.as_bytes().len(),
            32,
            "Ed25519 public key should be 32 bytes"
        );
    }
}
