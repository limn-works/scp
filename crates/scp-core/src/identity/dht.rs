//! `did:dht` DID method implementation.
//!
//! Implements the [`DidMethod`] trait for `did:dht` identities. The `did:dht`
//! method uses the `BitTorrent` Mainline DHT for document publication and
//! resolution. The DID string is self-certifying: it is the z-base-32 encoding
//! of the Ed25519 Identity Key's public key.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyType};

use super::document::DidDocument;
use super::{DidMethod, IdentityError, ScpIdentity};

/// The `did:dht` DID method prefix.
const DID_DHT_PREFIX: &str = "did:dht:";

/// `did:dht` implementation of the [`DidMethod`] trait.
///
/// Creates self-certifying DIDs where the identifier is the z-base-32 encoding
/// of the Ed25519 Identity Key's public key. Verification is a local operation
/// that decodes the DID suffix and compares to the provided public key.
///
/// # Phase 1 Scope
///
/// This story (SCP-006) implements `create` and `verify`. The `publish`,
/// `resolve`, and `rotate` methods are stubbed and will be implemented in
/// SCP-007 and SCP-008.
#[derive(Debug, Clone, Default)]
pub struct DidDht;

impl DidDht {
    /// Creates a new `DidDht` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

// The trait uses RPITIT (`-> impl Future<...> + Send`), so each impl method
// must return a future rather than use `async fn` directly.
#[allow(clippy::manual_async_fn)]
impl DidMethod for DidDht {
    fn create(
        &self,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send {
        async move {
            // Step 1: Generate three Ed25519 keypairs.
            let identity_key = key_custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .map_err(IdentityError::Platform)?;

            let active_signing_key = key_custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .map_err(IdentityError::Platform)?;

            let pre_rotation_key = key_custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .map_err(IdentityError::Platform)?;

            // Step 2: Get public keys.
            let identity_public = key_custody
                .public_key(&identity_key)
                .await
                .map_err(IdentityError::Platform)?;

            let active_public = key_custody
                .public_key(&active_signing_key)
                .await
                .map_err(IdentityError::Platform)?;

            let pre_rotation_public = key_custody
                .public_key(&pre_rotation_key)
                .await
                .map_err(IdentityError::Platform)?;

            // Step 3: Derive the DID string: did:dht:z<z-base-32(identity_public_key)>
            let did = format!(
                "{DID_DHT_PREFIX}z{}",
                zbase32::encode(identity_public.as_bytes())
            );

            // Step 4: Compute pre-rotation commitment: SHA-256(pre_rotation_key.public)
            let mut hasher = Sha256::new();
            hasher.update(pre_rotation_public.as_bytes());
            let commitment_bytes = hasher.finalize();
            let mut pre_rotation_commitment = [0u8; 32];
            pre_rotation_commitment.copy_from_slice(&commitment_bytes);

            // Step 5: Destroy the pre-rotation key handle — the commitment is all
            // we retain. The actual pre-rotation key should be in cold/offline
            // custody. In production, the pre-rotation key is generated on a
            // separate device; here we just record the commitment and discard
            // the handle.
            key_custody
                .destroy_key(&pre_rotation_key)
                .await
                .map_err(IdentityError::Platform)?;

            // Step 6: Build the DID document.
            let document = DidDocument::new(
                &did,
                identity_public.as_bytes(),
                active_public.as_bytes(),
                &pre_rotation_commitment,
            );

            // Step 7: Return the identity and document.
            let identity = ScpIdentity {
                identity_key,
                active_signing_key,
                pre_rotation_commitment,
                did,
            };

            Ok((identity, document))
        }
    }

    fn verify(&self, did_string: &str, public_key: &[u8]) -> bool {
        // Strip the "did:dht:z" prefix to get the z-base-32 encoded key.
        let Some(encoded) = did_string
            .strip_prefix(DID_DHT_PREFIX)
            .and_then(|s| s.strip_prefix('z'))
        else {
            return false;
        };

        // Decode z-base-32.
        let Ok(decoded) = zbase32::decode(encoded) else {
            return false;
        };

        // Compare decoded bytes to provided public key.
        decoded == public_key
    }

    fn publish(
        &self,
        _identity: &ScpIdentity,
        _document: &DidDocument,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        // TODO: Implement in SCP-007 — publishes DID document to Mainline DHT
        // as a BEP44 signed mutable item.
        async move {
            Err(IdentityError::InvalidDidFormat(
                "publish not yet implemented (SCP-007)".to_owned(),
            ))
        }
    }

    fn resolve(
        &self,
        _did_string: &str,
    ) -> impl Future<Output = Result<DidDocument, IdentityError>> + Send {
        // TODO: Implement in SCP-007 — resolves DID via Mainline DHT lookup.
        async move {
            Err(IdentityError::InvalidDidFormat(
                "resolve not yet implemented (SCP-007)".to_owned(),
            ))
        }
    }

    fn rotate(
        &self,
        _identity: &ScpIdentity,
        _key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send {
        // TODO: Implement in SCP-008 — rotates active signing key.
        async move {
            Err(IdentityError::InvalidDidFormat(
                "rotate not yet implemented (SCP-008)".to_owned(),
            ))
        }
    }
}

/// Verifies that a DID string is self-certifying for the given public key.
///
/// This is a convenience function that delegates to [`DidDht::verify`].
/// It is a local operation — no network call required.
///
/// # Arguments
///
/// * `did_string` - A `did:dht:z...` string.
/// * `public_key` - The raw Ed25519 public key bytes (32 bytes).
///
/// # Returns
///
/// `true` if the z-base-32 decoded suffix of the DID matches the public key,
/// `false` otherwise.
///
/// See ADR-003 acceptance criterion 5.
#[must_use]
pub fn verify_did(did_string: &str, public_key: &[u8]) -> bool {
    DidDht.verify(did_string, public_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryKeyCustody;

    #[tokio::test]
    async fn create_identity_produces_valid_did_format() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let (identity, document) = dht.create(&custody).await.unwrap();

        // DID starts with "did:dht:z"
        assert!(identity.did.starts_with("did:dht:z"));

        // Document ID matches identity DID
        assert_eq!(document.id, identity.did);

        // Pre-rotation commitment is non-zero (SHA-256 of a public key)
        assert_ne!(identity.pre_rotation_commitment, [0u8; 32]);
    }

    #[tokio::test]
    async fn create_identity_verify_self_certifying() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let (identity, _document) = dht.create(&custody).await.unwrap();

        // Get the identity public key
        let identity_public = custody.public_key(&identity.identity_key).await.unwrap();

        // verify_did should return true for the matching key
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));
    }

    #[tokio::test]
    async fn verify_did_returns_false_for_mismatched_key() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let (identity, _document) = dht.create(&custody).await.unwrap();

        // Use a different key (the active signing key, not the identity key)
        let active_public = custody
            .public_key(&identity.active_signing_key)
            .await
            .unwrap();

        assert!(!dht.verify(&identity.did, active_public.as_bytes()));
    }

    #[test]
    fn verify_did_returns_false_for_invalid_prefix() {
        let dht = DidDht::new();
        assert!(!dht.verify("did:web:example.com", &[1u8; 32]));
    }

    #[test]
    fn verify_did_returns_false_for_missing_z_prefix() {
        let dht = DidDht::new();
        assert!(!dht.verify("did:dht:notzbased", &[1u8; 32]));
    }

    #[test]
    fn verify_did_convenience_function_works() {
        // Manually construct a valid did:dht
        let key_bytes = [42u8; 32];
        let encoded = zbase32::encode(&key_bytes);
        let did = format!("did:dht:z{encoded}");

        assert!(verify_did(&did, &key_bytes));
        assert!(!verify_did(&did, &[0u8; 32]));
    }

    #[tokio::test]
    async fn document_has_correct_verification_methods() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let (identity, document) = dht.create(&custody).await.unwrap();

        // Should have two verification methods
        assert_eq!(document.verification_method.len(), 2);

        // #0 is the identity key
        let vm0 = document.verification_method_by_fragment("0").unwrap();
        assert_eq!(vm0.id, format!("{}#0", identity.did));

        // #active is the active signing key
        let vm_active = document.verification_method_by_fragment("active").unwrap();
        assert_eq!(vm_active.id, format!("{}#active", identity.did));

        // authentication and assertionMethod reference #active
        assert_eq!(
            document.authentication,
            vec![format!("{}#active", identity.did)]
        );
        assert_eq!(
            document.assertion_method,
            vec![format!("{}#active", identity.did)]
        );
    }

    #[tokio::test]
    async fn document_has_pre_rotation_service() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let (_identity, document) = dht.create(&custody).await.unwrap();

        let svc = document.pre_rotation_service().unwrap();
        assert_eq!(svc.service_type, "PreRotationCommitment");
        assert!(svc.service_endpoint.starts_with("sha256:"));

        // The hex string after "sha256:" should be 64 chars (32 bytes)
        let hex_part = svc.service_endpoint.strip_prefix("sha256:").unwrap();
        assert_eq!(hex_part.len(), 64);
    }

    #[tokio::test]
    async fn create_identity_deterministic_with_seeded_custody() {
        let custody1 = InMemoryKeyCustody::from_seed(42);
        let custody2 = InMemoryKeyCustody::from_seed(42);
        let dht = DidDht::new();

        let (identity1, doc1) = dht.create(&custody1).await.unwrap();
        let (identity2, doc2) = dht.create(&custody2).await.unwrap();

        // Same seed produces the same DID
        assert_eq!(identity1.did, identity2.did);
        assert_eq!(
            identity1.pre_rotation_commitment,
            identity2.pre_rotation_commitment
        );
        assert_eq!(doc1, doc2);
    }

    #[tokio::test]
    async fn document_json_roundtrip_from_create() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let (_identity, document) = dht.create(&custody).await.unwrap();

        let json = document.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        assert_eq!(document, parsed);
    }
}
