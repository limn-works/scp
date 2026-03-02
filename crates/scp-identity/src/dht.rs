//! `did:dht` DID method implementation.
//!
//! Implements the [`DidMethod`] trait for `did:dht` identities. The `did:dht`
//! method uses the `BitTorrent` Mainline DHT for document publication and
//! resolution. The DID string is self-certifying: it is the z-base-32 encoding
//! of the Ed25519 Identity Key's public key.
//!
//! # DHT Publishing
//!
//! DID documents are published to the Mainline DHT as BEP44 signed mutable
//! items. The document is serialized to JSON, then signed with the identity's
//! Ed25519 key. The signature covers a BEP44-style payload that includes the
//! sequence number and value.
//!
//! # Resolution and Caching
//!
//! Resolved DID documents are cached with TTL-based staleness detection.
//! Active contacts use a 24-hour refresh interval; inactive contacts use a
//! 7-day interval. Stale results (not refreshed within the 2h30m republish
//! window) carry a staleness indicator.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyHandle, KeyType};

use super::cache::{Clock, DidCache, DidResolutionResult, Staleness, SystemClock};
use super::dht_client::{DhtClient, InMemoryDhtClient};
use super::document::{DidDocument, DidRotationEvent, MigrationProof, PreRotationProof};
use super::{DidMethod, IdentityError, ScpIdentity};

/// The `did:dht` DID method prefix.
const DID_DHT_PREFIX: &str = "did:dht:";

/// Domain separator for migration proof hashes, preventing cross-protocol
/// signature confusion. See issue #78.
const DOMAIN_MIGRATION_V1: &[u8] = b"SCP-MIGRATION-V1:";

/// Type alias for the signing function stored in `DidDht`.
///
/// Takes a key handle ID and data to sign, returns the 64-byte Ed25519
/// signature. This abstraction allows `DidDht` to sign BEP44 payloads
/// without requiring a generic `KeyCustody` type parameter.
type SignFn = dyn Fn(u64, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, IdentityError>> + Send>>
    + Send
    + Sync;

/// `did:dht` implementation of the [`DidMethod`] trait.
///
/// Creates self-certifying DIDs where the identifier is the z-base-32 encoding
/// of the Ed25519 Identity Key's public key. Verification is a local operation
/// that decodes the DID suffix and compares to the provided public key.
///
/// # Type Parameters
///
/// * `D` — The DHT client implementation. Defaults to [`InMemoryDhtClient`]
///   for testing. Production code should use a pkarr-based client.
/// * `C` — The clock implementation for the cache. Defaults to [`SystemClock`].
///
/// # Construction
///
/// - [`DidDht::new()`] — Creates a default instance with `InMemoryDhtClient`
///   and no signing capability (for backward compatibility with SCP-006 tests).
/// - [`DidDht::with_client()`] — Creates an instance with a specific DHT client.
/// - [`DidDht::with_client_and_custody()`] — Creates a fully-configured instance
///   with DHT client and signing capability.
pub struct DidDht<D: DhtClient = InMemoryDhtClient, C: Clock = SystemClock> {
    /// The DHT client used for publish/resolve operations.
    dht_client: Arc<D>,
    /// Resolution cache for DID documents.
    cache: Arc<DidCache<C>>,
    /// Monotonically increasing BEP44 sequence number.
    sequence: AtomicU64,
    /// Optional signing function for BEP44 publish.
    sign_fn: Option<Arc<SignFn>>,
}

// Manual Debug impl because SignFn can't derive Debug.
impl<D: DhtClient + std::fmt::Debug, C: Clock + std::fmt::Debug> std::fmt::Debug for DidDht<D, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidDht")
            .field("dht_client", &self.dht_client)
            .field("cache", &self.cache)
            .field("sequence", &self.sequence)
            .field("sign_fn", &self.sign_fn.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

impl Default for DidDht<InMemoryDhtClient, SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl DidDht<InMemoryDhtClient, SystemClock> {
    /// Creates a new `DidDht` instance with an in-memory DHT client and no
    /// signing capability.
    ///
    /// This constructor is backward-compatible with SCP-006 tests. The
    /// `publish` method will return an error unless a signing function is
    /// configured via [`DidDht::with_client_and_custody`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            dht_client: Arc::new(InMemoryDhtClient::new()),
            cache: Arc::new(DidCache::new()),
            sequence: AtomicU64::new(0),
            sign_fn: None,
        }
    }
}

impl<D: DhtClient> DidDht<D, SystemClock> {
    /// Creates a new `DidDht` instance with a specific DHT client and system
    /// clock.
    #[must_use]
    pub fn with_client(dht_client: Arc<D>) -> Self {
        Self {
            dht_client,
            cache: Arc::new(DidCache::new()),
            sequence: AtomicU64::new(0),
            sign_fn: None,
        }
    }
}

impl<D: DhtClient, C: Clock> DidDht<D, C> {
    /// Creates a new `DidDht` instance with a specific DHT client, cache, and
    /// signing function.
    ///
    /// The signing function takes a key handle ID and data bytes, returning the
    /// Ed25519 signature bytes. This is typically constructed from a
    /// [`KeyCustody`] implementation.
    #[must_use]
    pub fn with_client_and_signer(
        dht_client: Arc<D>,
        cache: Arc<DidCache<C>>,
        sign_fn: Arc<SignFn>,
    ) -> Self {
        Self {
            dht_client,
            cache,
            sequence: AtomicU64::new(0),
            sign_fn: Some(sign_fn),
        }
    }

    /// Creates a signing function from a [`KeyCustody`] implementation.
    ///
    /// The returned function captures the key custody in an `Arc` and delegates
    /// signing to `KeyCustody::sign`.
    pub fn make_sign_fn<K: KeyCustody + 'static>(key_custody: Arc<K>) -> Arc<SignFn> {
        Arc::new(move |key_id: u64, data: Vec<u8>| {
            let kc = Arc::clone(&key_custody);
            Box::pin(async move {
                let handle = scp_platform::traits::KeyHandle::new(key_id);
                let sig = kc
                    .sign(&handle, &data)
                    .await
                    .map_err(IdentityError::Platform)?;
                Ok(sig.into_bytes())
            })
        })
    }

    /// Returns a reference to the DHT client.
    #[must_use]
    pub const fn dht_client(&self) -> &Arc<D> {
        &self.dht_client
    }

    /// Returns a reference to the DID cache.
    #[must_use]
    pub const fn cache(&self) -> &Arc<DidCache<C>> {
        &self.cache
    }

    /// Returns the current sequence number.
    #[must_use]
    pub fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }

    /// Sets the sequence number (e.g., when loading from persistent storage).
    pub fn set_sequence(&self, seq: u64) {
        self.sequence.store(seq, Ordering::Release);
    }

    /// Constructs the BEP44 signable payload for a value and sequence number.
    ///
    /// Delegates to the standalone [`bep44_signable`] function.
    #[must_use]
    pub fn bep44_signable(value: &[u8], seq: u64) -> Vec<u8> {
        bep44_signable(value, seq)
    }

    /// Verifies a BEP44 Ed25519 signature over the given value and sequence.
    ///
    /// Delegates to the standalone [`verify_bep44_signature`] function.
    fn verify_bep44_signature(
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> Result<(), IdentityError> {
        verify_bep44_signature(public_key, signature, value, seq)
    }

    /// Extracts the 32-byte public key from a `did:dht:z...` string.
    ///
    /// Delegates to the standalone [`extract_public_key`] function.
    fn extract_public_key(did_string: &str) -> Result<[u8; 32], IdentityError> {
        extract_public_key(did_string)
    }

    /// Publishes a DID document to the DHT with the given signing function.
    ///
    /// This is the internal publish implementation used by both
    /// `DidMethod::publish` and the [`RepublishManager`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::DhtPublishFailed`] if the DHT publish fails,
    /// or [`IdentityError::DocumentSerializationError`] if the document cannot
    /// be serialized to JSON.
    pub async fn publish_document(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> Result<(), IdentityError> {
        let sign_fn = self.sign_fn.as_ref().ok_or_else(|| {
            IdentityError::DhtPublishFailed(
                "no signing function configured; use DidDht::with_client_and_signer".to_owned(),
            )
        })?;

        // Serialize the document to JSON.
        let doc_json = document
            .to_json()
            .map_err(|e| IdentityError::DocumentSerializationError(e.to_string()))?;
        let value = doc_json.as_bytes();

        // Increment the sequence number.
        let seq = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;

        // Construct the BEP44 signable payload and sign it.
        let signable = Self::bep44_signable(value, seq);
        let sig_bytes = sign_fn(identity.identity_key.id(), signable).await?;

        // Convert signature to [u8; 64].
        let signature: [u8; 64] = sig_bytes.try_into().map_err(|v: Vec<u8>| {
            IdentityError::DhtPublishFailed(format!(
                "expected 64-byte signature, got {} bytes",
                v.len()
            ))
        })?;

        // Extract the public key from the DID.
        let public_key = Self::extract_public_key(&identity.did)?;

        // Publish to DHT.
        self.dht_client
            .publish(&public_key, &signature, value, seq)
            .await?;

        Ok(())
    }

    /// Publishes a DID document to the DHT with optional relay URLs.
    ///
    /// When `relay_urls` is non-empty, `SCPRelay` service entries are added to
    /// the document before signing and publishing. The BEP44 signature covers
    /// the complete document including relay entries (existing §9.6.3 property).
    ///
    /// This is used during identity creation when the caller knows their relay
    /// URLs upfront (§18.5 bootstrap flow).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidRelayUrl`] if any URL fails validation.
    /// Returns [`IdentityError::DhtPublishFailed`] if the DHT publish fails.
    pub async fn publish_with_relay_urls(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        relay_urls: &[&str],
    ) -> Result<DidDocument, IdentityError> {
        let mut doc = document.clone();
        doc.set_relay_services(relay_urls)?;
        self.publish_document(identity, &doc).await?;
        Ok(doc)
    }

    /// Updates the relay URL list for an already-published identity.
    ///
    /// Replaces all existing `SCPRelay` service entries in the document with the
    /// provided URLs, then publishes the updated document with an incremented
    /// BEP44 sequence number (§9.6.3 monotonicity). The BEP44 signature covers
    /// the complete updated document.
    ///
    /// Callers SHOULD use this method instead of manually modifying the document
    /// and calling `publish_document`, because this method ensures the relay
    /// entries are validated and the sequence number is incremented atomically.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidRelayUrl`] if any URL fails validation.
    /// Returns [`IdentityError::DhtPublishFailed`] if the DHT publish fails.
    pub async fn update_relay_urls(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        relay_urls: &[&str],
    ) -> Result<DidDocument, IdentityError> {
        let mut doc = document.clone();
        doc.set_relay_services(relay_urls)?;
        self.publish_document(identity, &doc).await?;
        Ok(doc)
    }

    /// Resolves a DID document from the DHT with cache and staleness detection.
    ///
    /// # Resolution Steps
    ///
    /// 1. Check the cache. If a fresh entry exists, return it.
    /// 2. Query the DHT for the BEP44 record.
    /// 3. Verify the BEP44 signature.
    /// 4. Deserialize the DID document.
    /// 5. Verify self-certification (z-base-32 decoded DID suffix matches
    ///    the identity key in the document).
    /// 6. Update the cache.
    ///
    /// # Errors
    ///
    /// Returns errors for DHT lookup failures, signature verification failures,
    /// deserialization failures, and self-certification failures.
    pub async fn resolve_did(
        &self,
        did_string: &str,
    ) -> Result<DidResolutionResult, IdentityError> {
        // Step 1: Check cache.
        if let Some(cached) = self.cache.get(did_string).await {
            // If the cache entry is stale, log a warning but still return it.
            // The caller can decide whether to attempt a fresh resolution.
            return Ok(cached);
        }

        // Step 2: Extract public key and query DHT.
        let public_key = Self::extract_public_key(did_string)?;

        let record = self
            .dht_client
            .resolve(&public_key)
            .await?
            .ok_or_else(|| IdentityError::DhtNotFound(did_string.to_owned()))?;

        // Step 3: Verify BEP44 signature.
        Self::verify_bep44_signature(&public_key, &record.signature, &record.value, record.seq)?;

        // Step 4: Deserialize the DID document.
        let doc_json = String::from_utf8(record.value).map_err(|e| {
            IdentityError::DocumentDeserializationError(format!("invalid UTF-8: {e}"))
        })?;
        let document = DidDocument::from_json(&doc_json)
            .map_err(|e| IdentityError::DocumentDeserializationError(e.to_string()))?;

        // Step 5: Verify self-certification.
        // The identity key (#0) in the document must match the public key
        // derived from the DID string.
        Self::verify_self_certification(did_string, &document)?;

        // Step 6: Update cache.
        self.cache
            .insert(did_string, document.clone(), record.seq)
            .await;

        Ok(DidResolutionResult {
            document,
            staleness: Staleness::Fresh,
            sequence: record.seq,
        })
    }

    /// Rotates the active signing key for an identity (Layer 1).
    ///
    /// Generates a new Ed25519 keypair as the new Active Signing Key, updates
    /// the DID document (moves old active key to `#retired-{sequence}`, installs
    /// new key as `#active`), signs the document with the Identity Key, and
    /// publishes to the DHT.
    ///
    /// **The DID string does NOT change. The Identity Key does NOT change.**
    ///
    /// After rotation, the caller MUST issue MLS Update proposals in all active
    /// contexts and revoke/reissue UCAN tokens signed by the old active key.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (will be consumed to produce the
    ///   updated identity).
    /// * `document` - The current DID document (will be mutated in-place).
    /// * `key_custody` - The key custody for generating the new keypair.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Platform`] if key generation fails.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-003 acceptance criterion 4a.
    pub async fn rotate_active_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 1: Generate a new Ed25519 keypair for the new Active Signing Key.
        let new_active_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 2: Get the new key's public key.
        let new_active_public = key_custody
            .public_key(&new_active_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 3: Clone and update the document.
        let mut updated_doc = document.clone();
        let sequence = self.current_sequence().saturating_add(1);
        updated_doc.retire_active_key(new_active_public.as_bytes(), sequence);

        // Step 4: Publish the updated document. The publish_document method
        // signs with the Identity Key via the stored sign_fn.
        self.publish_document(identity, &updated_doc).await?;

        // Step 5: Build the updated identity. DID string and identity key
        // are preserved; only the active signing key changes.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: new_active_key,
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Migrates an identity to a new DID (Layer 2).
    ///
    /// Creates a new DID using the pre-rotation key as the new Identity Key.
    /// Generates a new Active Signing Key and pre-rotation commitment for the
    /// new DID. Updates the old DID document with an `alsoKnownAs` pointing to
    /// the new DID and cryptographic linkage. Publishes both documents.
    ///
    /// **The DID string changes. All per-context references must be migrated
    /// via the returned [`DidRotationEvent`].**
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity being migrated.
    /// * `old_document` - The current DID document for the old identity.
    /// * `pre_rotation_key` - The pre-rotation key handle (must match the
    ///   commitment in the old DID document).
    /// * `key_custody` - The key custody for generating new keypairs.
    /// * `rotated_at` - Unix timestamp for the migration event.
    ///
    /// # Returns
    ///
    /// A tuple of `(new_identity, new_document, rotation_event)`:
    /// - `new_identity` — The new [`ScpIdentity`] with new DID, keys, and
    ///   pre-rotation commitment.
    /// - `new_document` — The DID document for the new identity.
    /// - `rotation_event` — The [`DidRotationEvent`] to distribute to all
    ///   active contexts.
    ///
    /// # Errors
    ///
    /// Returns errors if key generation, signing, or DHT publishing fails.
    ///
    /// See ADR-003 acceptance criterion 4b.
    pub async fn migrate_identity(
        &self,
        identity: &ScpIdentity,
        old_document: &DidDocument,
        pre_rotation_key: &KeyHandle,
        key_custody: &impl KeyCustody,
        rotated_at: u64,
    ) -> Result<(ScpIdentity, DidDocument, DidRotationEvent), IdentityError> {
        // Step 1: The pre-rotation key becomes the new Identity Key.
        let new_identity_public = key_custody
            .public_key(pre_rotation_key)
            .await
            .map_err(IdentityError::Platform)?;

        let new_did = format!(
            "{DID_DHT_PREFIX}z{}",
            zbase32::encode(new_identity_public.as_bytes())
        );

        // Step 2: Generate new keys and build new DID document.
        let (new_active_key, new_pre_rotation_commitment, new_document) =
            Self::create_new_identity_keys(key_custody, &new_did, &new_identity_public).await?;

        // Step 3: Update old DID document with alsoKnownAs forwarding.
        let mut updated_old_doc = old_document.clone();
        updated_old_doc.set_also_known_as(&new_did);

        // Step 4: Create the migration and pre-rotation proofs.
        let migration_proof =
            Self::build_migration_proof(identity, &new_did, rotated_at, key_custody).await?;
        let pre_rotation_proof =
            Self::build_pre_rotation_proof(old_document, &new_identity_public)?;

        // Step 5: Publish both documents.
        self.publish_document(identity, &updated_old_doc).await?;
        let temp_new_identity = ScpIdentity {
            identity_key: *pre_rotation_key,
            active_signing_key: new_active_key,
            pre_rotation_commitment: new_pre_rotation_commitment,
            did: new_did.clone(),
        };
        self.publish_document(&temp_new_identity, &new_document)
            .await?;

        // Step 6: Build and return the rotation event and new identity.
        let rotation_event = DidRotationEvent {
            old_did: identity.did.clone(),
            new_did: new_did.clone(),
            migration_proof,
            pre_rotation_proof,
            rotated_at,
        };

        let new_identity = ScpIdentity {
            identity_key: *pre_rotation_key,
            active_signing_key: new_active_key,
            pre_rotation_commitment: new_pre_rotation_commitment,
            did: new_did,
        };

        Ok((new_identity, new_document, rotation_event))
    }

    /// Generates new active signing key, pre-rotation key, and DID document
    /// for a migrated identity.
    async fn create_new_identity_keys(
        key_custody: &impl KeyCustody,
        new_did: &str,
        new_identity_public: &scp_platform::traits::PublicKey,
    ) -> Result<(KeyHandle, [u8; 32], DidDocument), IdentityError> {
        let new_active_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;
        let new_active_public = key_custody
            .public_key(&new_active_key)
            .await
            .map_err(IdentityError::Platform)?;

        let new_pre_rotation_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;
        let new_pre_rotation_public = key_custody
            .public_key(&new_pre_rotation_key)
            .await
            .map_err(IdentityError::Platform)?;

        let mut hasher = Sha256::new();
        hasher.update(new_pre_rotation_public.as_bytes());
        let commitment_bytes = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&commitment_bytes);

        key_custody
            .destroy_key(&new_pre_rotation_key)
            .await
            .map_err(IdentityError::Platform)?;

        let document = DidDocument::new(
            new_did,
            new_identity_public.as_bytes(),
            new_active_public.as_bytes(),
            &commitment,
        );

        Ok((new_active_key, commitment, document))
    }

    /// Builds a migration proof by signing
    /// `SHA-256("SCP-MIGRATION-V1:" || old_did || new_did || rotated_at)`
    /// with the old Identity Key.
    async fn build_migration_proof(
        identity: &ScpIdentity,
        new_did: &str,
        rotated_at: u64,
        key_custody: &impl KeyCustody,
    ) -> Result<MigrationProof, IdentityError> {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_MIGRATION_V1);
        hasher.update(identity.did.as_bytes());
        hasher.update(new_did.as_bytes());
        hasher.update(rotated_at.to_be_bytes());
        let digest = hasher.finalize();

        let proof_sig = key_custody
            .sign(&identity.identity_key, &digest)
            .await
            .map_err(IdentityError::Platform)?;

        let old_identity_public = key_custody
            .public_key(&identity.identity_key)
            .await
            .map_err(IdentityError::Platform)?;

        let sig_bytes: [u8; 64] = proof_sig.into_bytes().try_into().map_err(|v: Vec<u8>| {
            IdentityError::KeyRotationFailed(format!(
                "expected 64-byte signature, got {} bytes",
                v.len()
            ))
        })?;

        let old_pub_bytes: [u8; 32] =
            old_identity_public
                .into_bytes()
                .try_into()
                .map_err(|v: Vec<u8>| {
                    IdentityError::KeyRotationFailed(format!(
                        "expected 32-byte public key, got {} bytes",
                        v.len()
                    ))
                })?;

        Ok(MigrationProof {
            signature: sig_bytes,
            old_public_key: old_pub_bytes,
        })
    }

    /// Builds a pre-rotation proof from the old document's `PreRotationCommitment`
    /// service, if present.
    fn build_pre_rotation_proof(
        old_document: &DidDocument,
        new_identity_public: &scp_platform::traits::PublicKey,
    ) -> Result<Option<PreRotationProof>, IdentityError> {
        let Some(svc) = old_document.pre_rotation_service() else {
            return Ok(None);
        };
        let Some(hex_str) = svc.service_endpoint.strip_prefix("sha256:") else {
            return Ok(None);
        };

        let commitment_vec = hex::decode(hex_str).map_err(|e| {
            IdentityError::KeyRotationFailed(format!(
                "failed to decode pre-rotation commitment: {e}"
            ))
        })?;
        let commitment: [u8; 32] = commitment_vec.try_into().map_err(|v: Vec<u8>| {
            IdentityError::KeyRotationFailed(format!(
                "pre-rotation commitment must be 32 bytes, got {}",
                v.len()
            ))
        })?;
        let new_identity_bytes: [u8; 32] =
            new_identity_public.as_bytes().try_into().map_err(|_| {
                IdentityError::KeyRotationFailed(
                    "new identity public key is not 32 bytes".to_owned(),
                )
            })?;

        Ok(Some(PreRotationProof {
            commitment,
            revealed_key: new_identity_bytes,
        }))
    }

    /// Verifies that the identity key in the document matches the DID's
    /// z-base-32 encoded public key.
    fn verify_self_certification(
        did_string: &str,
        document: &DidDocument,
    ) -> Result<(), IdentityError> {
        let public_key = Self::extract_public_key(did_string)?;

        // Find the #0 verification method (identity key).
        let vm0 = document
            .verification_method_by_fragment("0")
            .ok_or_else(|| {
                IdentityError::SelfCertificationFailed(
                    "no #0 verification method in document".to_owned(),
                )
            })?;

        // Decode the multibase public key from the document.
        let doc_key_bytes = decode_multibase_key(&vm0.public_key_multibase)?;

        if doc_key_bytes != public_key {
            return Err(IdentityError::SelfCertificationFailed(format!(
                "identity key in document does not match DID suffix for {did_string}"
            )));
        }

        Ok(())
    }
}

/// Decodes a multibase-encoded public key (z-prefix = base58btc).
///
/// # Errors
///
/// Returns [`IdentityError::InvalidDidFormat`] if the key is not properly
/// base58btc encoded.
fn decode_multibase_key(encoded: &str) -> Result<[u8; 32], IdentityError> {
    let b58_str = encoded.strip_prefix('z').ok_or_else(|| {
        IdentityError::InvalidDidFormat("multibase key must start with 'z' (base58btc)".to_owned())
    })?;

    let decoded = base58btc_decode(b58_str)
        .map_err(|e| IdentityError::InvalidDidFormat(format!("base58btc decode failed: {e}")))?;

    decoded.try_into().map_err(|v: Vec<u8>| {
        IdentityError::InvalidDidFormat(format!("expected 32-byte key, got {} bytes", v.len()))
    })
}

/// Base58btc decoding (Bitcoin alphabet) via the `bs58` crate.
///
/// Inverse of the `base58btc_encode` function in `document.rs`.
fn base58btc_decode(input: &str) -> Result<Vec<u8>, String> {
    bs58::decode(input)
        .into_vec()
        .map_err(|e| format!("base58btc decode error: {e}"))
}

// The trait uses RPITIT (`-> impl Future<...> + Send`), so each impl method
// must return a future rather than use `async fn` directly.
#[allow(clippy::manual_async_fn)]
impl<D: DhtClient + 'static, C: Clock + 'static> DidMethod for DidDht<D, C> {
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
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        // Delegate to the internal method that uses the stored signing function.
        self.publish_document(identity, document)
    }

    fn resolve(
        &self,
        did_string: &str,
    ) -> impl Future<Output = Result<DidDocument, IdentityError>> + Send {
        let did_owned = did_string.to_owned();
        async move {
            let result = self.resolve_did(&did_owned).await?;
            Ok(result.document)
        }
    }

    fn rotate(
        &self,
        identity: &ScpIdentity,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send {
        // Resolve the current document, then delegate to rotate_active_key.
        let did_owned = identity.did.clone();
        async move {
            // Resolve the current DID document from the DHT/cache.
            let resolution = self.resolve_did(&did_owned).await.map_err(|e| {
                IdentityError::KeyRotationFailed(format!(
                    "failed to resolve current document for rotation: {e}"
                ))
            })?;

            self.rotate_active_key(identity, &resolution.document, key_custody)
                .await
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
    DidDht::new().verify(did_string, public_key)
}

/// Verifies a DID identity migration (Layer 3).
///
/// Checks the cryptographic proofs that an identity migration from `old_did`
/// to `new_did` was authorized by the old Identity Key owner.
///
/// # Verification Steps
///
/// 1. **Migration proof (MODERATE assurance):** Verifies that the old Identity
///    Key signed `SHA-256("SCP-MIGRATION-V1:" || old_did || new_did || rotated_at)`.
/// 2. **Pre-rotation proof (STRONG assurance, optional):** If present, verifies
///    that `SHA-256(new_identity_key_public) == commitment` from the old DID
///    document's `PreRotationCommitment` service.
///
/// Returns `true` only if all provided proofs verify successfully.
///
/// # Arguments
///
/// * `old_did` - The DID being migrated from.
/// * `new_did` - The DID being migrated to.
/// * `migration_proof` - The migration proof (signature + old public key).
/// * `pre_rotation_proof` - Optional pre-rotation proof for STRONG assurance.
/// * `rotated_at` - The timestamp that was signed in the migration proof.
///
/// # Errors
///
/// Returns [`IdentityError::MigrationVerificationFailed`] if:
/// - The old public key in the migration proof is invalid.
/// - The migration proof signature does not verify.
/// - The pre-rotation proof commitment does not match `SHA-256(revealed_key)`.
///
/// See ADR-003 acceptance criterion 4c.
pub fn verify_migration(
    old_did: &str,
    new_did: &str,
    migration_proof: &MigrationProof,
    pre_rotation_proof: Option<&PreRotationProof>,
    rotated_at: u64,
) -> Result<bool, IdentityError> {
    // Step 1: Verify the migration proof signature.
    // Reconstruct the signed digest: SHA-256(DOMAIN_MIGRATION_V1 || old_did || new_did || rotated_at).
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MIGRATION_V1);
    hasher.update(old_did.as_bytes());
    hasher.update(new_did.as_bytes());
    hasher.update(rotated_at.to_be_bytes());
    let digest = hasher.finalize();

    let verifying_key = VerifyingKey::from_bytes(&migration_proof.old_public_key).map_err(|e| {
        IdentityError::MigrationVerificationFailed(format!("invalid old public key: {e}"))
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&migration_proof.signature);

    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|e| {
            IdentityError::MigrationVerificationFailed(format!(
                "migration proof signature verification failed: {e}"
            ))
        })?;

    // Step 2: Verify the pre-rotation proof if present.
    if let Some(pre_rot) = pre_rotation_proof {
        let mut commitment_hasher = Sha256::new();
        commitment_hasher.update(pre_rot.revealed_key);
        let computed_commitment = commitment_hasher.finalize();

        if computed_commitment.as_slice() != pre_rot.commitment {
            return Err(IdentityError::MigrationVerificationFailed(
                "pre-rotation proof failed: SHA-256(revealed_key) != commitment".to_owned(),
            ));
        }
    }

    Ok(true)
}

/// Decodes a lowercase hexadecimal string to bytes.
///
/// # Errors
///
/// Returns an error if the string length is odd or contains non-hex characters.
fn hex_decode(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }

    let mut result = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])
            .ok_or_else(|| format!("invalid hex character: {}", chunk[0] as char))?;
        let lo = hex_nibble(chunk[1])
            .ok_or_else(|| format!("invalid hex character: {}", chunk[1] as char))?;
        result[i] = (hi << 4) | lo;
    }
    Ok(result)
}

/// Converts a single hex ASCII byte to its numeric value (0-15).
const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// BEP44 utility functions — public for use by relay-based resolution (§3.10.2)
// ---------------------------------------------------------------------------

/// Constructs the BEP44 signable payload for a value and sequence number.
///
/// BEP44 signing payload format (without salt):
/// `"3:seqi" + seq + "e1:v" + val_len + ":" + val`
///
/// This is a standalone function usable from both [`DidDht`] and relay-based
/// resolution (§3.10.2).
#[must_use]
pub fn bep44_signable(value: &[u8], seq: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"3:seqi");
    payload.extend_from_slice(seq.to_string().as_bytes());
    payload.extend_from_slice(b"e1:v");
    payload.extend_from_slice(value.len().to_string().as_bytes());
    payload.extend_from_slice(b":");
    payload.extend_from_slice(value);
    payload
}

/// Verifies a BEP44 Ed25519 signature over the given value and sequence.
///
/// Constructs the BEP44 signable payload, then verifies the Ed25519 signature
/// against `public_key`. Used by both DHT resolution and relay-based resolution
/// (§3.10.2).
///
/// # Errors
///
/// Returns [`IdentityError::Bep44SignatureInvalid`] if the signature does
/// not verify or the public key is invalid.
pub fn verify_bep44_signature(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    value: &[u8],
    seq: u64,
) -> Result<(), IdentityError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| IdentityError::Bep44SignatureInvalid(format!("invalid public key: {e}")))?;

    let sig = ed25519_dalek::Signature::from_bytes(signature);
    let payload = bep44_signable(value, seq);

    verifying_key.verify_strict(&payload, &sig).map_err(|e| {
        IdentityError::Bep44SignatureInvalid(format!("signature verification failed: {e}"))
    })
}

/// Extracts the 32-byte Ed25519 public key from a `did:dht:z...` string.
///
/// Strips the `did:dht:z` prefix and z-base-32 decodes the remainder to recover
/// the 32-byte Identity Key public key. Used by both DHT resolution and
/// relay-based resolution (§3.10.2).
///
/// # Errors
///
/// Returns [`IdentityError::InvalidDidFormat`] if the DID format is wrong
/// or z-base-32 decoding fails, or if the decoded bytes are not 32 bytes.
pub fn extract_public_key(did_string: &str) -> Result<[u8; 32], IdentityError> {
    let encoded = did_string
        .strip_prefix(DID_DHT_PREFIX)
        .and_then(|s| s.strip_prefix('z'))
        .ok_or_else(|| {
            IdentityError::InvalidDidFormat(format!(
                "expected 'did:dht:z...' prefix, got: {did_string}"
            ))
        })?;

    let decoded = zbase32::decode(encoded)
        .map_err(|e| IdentityError::ZBase32DecodeError(format!("z-base-32 decode failed: {e}")))?;

    let key_bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
        IdentityError::InvalidDidFormat(format!(
            "expected 32-byte public key, got {} bytes",
            v.len()
        ))
    })?;

    Ok(key_bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use scp_platform::testing::InMemoryKeyCustody;

    use super::*;
    use crate::cache::TestClock;
    use crate::dht_client::InMemoryDhtClient;

    /// Helper to create a fully-configured `DidDht` for testing.
    fn make_dht_with_custody(
        custody: &Arc<InMemoryKeyCustody>,
    ) -> DidDht<InMemoryDhtClient, Arc<TestClock>> {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    // -----------------------------------------------------------------------
    // Existing SCP-006 tests (preserved, using default DidDht::new())
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // SCP-007 tests — publish, resolve, cache, staleness
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn publish_and_resolve_roundtrip() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        // Publish the document.
        dht.publish_document(&identity, &document).await.unwrap();

        // Resolve the document.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.document, document);
        assert_eq!(result.staleness, Staleness::Fresh);
    }

    #[tokio::test]
    async fn publish_increments_sequence_number() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        assert_eq!(dht.current_sequence(), 0);
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 1);
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 2);
    }

    #[tokio::test]
    async fn resolve_returns_cached_result() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve populates cache.
        let result1 = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result1.staleness, Staleness::Fresh);

        // Second resolve should come from cache (still fresh).
        let result2 = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result2.document, document);
        assert_eq!(result2.staleness, Staleness::Fresh);
    }

    #[tokio::test]
    async fn resolve_verifies_self_certification() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(Arc::clone(&dht_client), cache, sign_fn);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Clear the cache so resolve hits DHT again.
        dht.cache().remove(&identity.did).await;

        // Should succeed because self-certification passes.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.document, document);
    }

    #[tokio::test]
    async fn resolve_rejects_tampered_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(Arc::clone(&dht_client), cache, sign_fn);

        let (identity, _document) = dht.create(&*custody).await.unwrap();

        // Publish a tampered document by directly writing to the DHT client
        // with a different document but same DID. The BEP44 signature won't match.
        let tampered_doc = DidDocument::new(
            &identity.did,
            &[99u8; 32], // different identity key
            &[98u8; 32],
            &[97u8; 32],
        );
        let tampered_json = tampered_doc.to_json().unwrap();
        let public_key =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::extract_public_key(&identity.did).unwrap();
        dht_client
            .publish(&public_key, &[0u8; 64], tampered_json.as_bytes(), 1)
            .await
            .unwrap();

        // Resolve should fail because BEP44 signature is invalid.
        let result = dht.resolve_did(&identity.did).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_returns_not_found_for_unpublished() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, _document) = dht.create(&*custody).await.unwrap();

        // Don't publish. Resolve should return DhtNotFound.
        let result = dht.resolve_did(&identity.did).await;
        assert!(matches!(result, Err(IdentityError::DhtNotFound(_))));
    }

    #[tokio::test]
    async fn publish_without_signer_returns_error() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let (identity, document) = dht.create(&custody).await.unwrap();

        let result = dht.publish_document(&identity, &document).await;
        assert!(matches!(result, Err(IdentityError::DhtPublishFailed(_))));
    }

    #[tokio::test]
    async fn bep44_signable_format_is_correct() {
        let value = b"test";
        let seq = 42;
        let signable = DidDht::<InMemoryDhtClient>::bep44_signable(value, seq);

        // Expected: "3:seqi42e1:v4:test"
        let expected = b"3:seqi42e1:v4:test";
        assert_eq!(signable, expected);
    }

    #[tokio::test]
    async fn resolve_with_staleness_detection() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve: fresh.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.staleness, Staleness::Fresh);

        // Advance past staleness threshold (2h30m + 1s).
        clock.advance(2 * 60 * 60 + 30 * 60 + 1);

        // Resolve again: should return stale from cache.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert!(matches!(result.staleness, Staleness::Stale { .. }));
    }

    #[tokio::test]
    async fn resolve_bypasses_expired_cache() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve populates cache.
        dht.resolve_did(&identity.did).await.unwrap();

        // Advance past inactive TTL (7 days + 1s).
        clock.advance(7 * 24 * 60 * 60 + 1);

        // Cache is expired, resolve goes to DHT again and succeeds.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.document, document);
        assert_eq!(result.staleness, Staleness::Fresh);
    }

    #[tokio::test]
    async fn resolve_active_contact_24h_ttl() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve + mark active.
        dht.resolve_did(&identity.did).await.unwrap();
        dht.cache().mark_active(&identity.did).await;

        // Advance past 24h TTL.
        clock.advance(24 * 60 * 60 + 1);

        // Cache is expired for active contact, resolve goes to DHT.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.staleness, Staleness::Fresh);
    }

    #[test]
    fn base58btc_decode_roundtrip() {
        let original = [42u8; 32];
        // Use the document module's encode (via the multibase_encode path)
        let encoded =
            crate::document::DidDocument::new("did:dht:zTest", &original, &[0u8; 32], &[0u8; 32]);
        let vm = encoded.verification_method_by_fragment("0").unwrap();
        let decoded = decode_multibase_key(&vm.public_key_multibase).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base58btc_decode_known_vector() {
        // "JxF12TrwUP45BMd" is the base58btc encoding of "Hello World".
        let decoded = base58btc_decode("JxF12TrwUP45BMd").unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn base58btc_decode_leading_ones() {
        // Leading '1' characters map to leading zero bytes.
        let decoded = base58btc_decode("112").unwrap();
        assert_eq!(decoded, vec![0x00, 0x00, 0x01]);
    }

    #[test]
    fn base58btc_decode_empty_input() {
        let decoded = base58btc_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base58btc_decode_rejects_invalid_characters() {
        // '0', 'O', 'I', 'l' are not in the Bitcoin base58 alphabet.
        assert!(base58btc_decode("0OIl").is_err());
    }

    #[test]
    fn base58btc_roundtrip_32_byte_key() {
        // Direct roundtrip: encode with bs58, then decode with our function.
        let key = [0xABu8; 32];
        let encoded = bs58::encode(&key).into_string();
        let decoded = base58btc_decode(&encoded).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn extract_public_key_from_valid_did() {
        let key = [42u8; 32];
        let encoded = zbase32::encode(&key);
        let did = format!("did:dht:z{encoded}");

        let extracted = DidDht::<InMemoryDhtClient>::extract_public_key(&did).unwrap();
        assert_eq!(extracted, key);
    }

    #[test]
    fn extract_public_key_rejects_invalid_prefix() {
        let result = DidDht::<InMemoryDhtClient>::extract_public_key("did:web:example.com");
        assert!(result.is_err());
    }

    /// Helper that creates an identity and returns the pre-rotation key handle
    /// alongside the identity and document. The pre-rotation key is NOT destroyed,
    /// which allows testing identity migration.
    async fn create_identity_with_pre_rotation_key(
        custody: &InMemoryKeyCustody,
        dht: &DidDht<InMemoryDhtClient, Arc<TestClock>>,
    ) -> (ScpIdentity, DidDocument, KeyHandle) {
        // Step 1: Generate three Ed25519 keypairs manually.
        let identity_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let active_signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pre_rotation_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        // Step 2: Get public keys.
        let identity_public = custody.public_key(&identity_key).await.unwrap();
        let active_public = custody.public_key(&active_signing_key).await.unwrap();
        let pre_rotation_public = custody.public_key(&pre_rotation_key).await.unwrap();

        // Step 3: Derive the DID string.
        let did = format!("did:dht:z{}", zbase32::encode(identity_public.as_bytes()));

        // Step 4: Compute pre-rotation commitment.
        let mut hasher = Sha256::new();
        hasher.update(pre_rotation_public.as_bytes());
        let commitment_bytes = hasher.finalize();
        let mut pre_rotation_commitment = [0u8; 32];
        pre_rotation_commitment.copy_from_slice(&commitment_bytes);

        // Step 5: Build the DID document.
        let document = DidDocument::new(
            &did,
            identity_public.as_bytes(),
            active_public.as_bytes(),
            &pre_rotation_commitment,
        );

        // Step 6: Build the identity (pre-rotation key NOT destroyed).
        let identity = ScpIdentity {
            identity_key,
            active_signing_key,
            pre_rotation_commitment,
            did,
        };

        // Verify self-certification works.
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));

        (identity, document, pre_rotation_key)
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Layer 1: rotate_active_key
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_active_key_preserves_did_string() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (rotated_identity, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // DID string must NOT change during active key rotation.
        assert_eq!(rotated_identity.did, identity.did);
    }

    #[tokio::test]
    async fn rotate_active_key_changes_active_signing_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let old_active_public = custody
            .public_key(&identity.active_signing_key)
            .await
            .unwrap();

        let (rotated_identity, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        let new_active_public = custody
            .public_key(&rotated_identity.active_signing_key)
            .await
            .unwrap();

        // The active signing key handle must change.
        assert_ne!(old_active_public.as_bytes(), new_active_public.as_bytes());
    }

    #[tokio::test]
    async fn rotate_active_key_preserves_identity_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (rotated_identity, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // The identity key handle must be unchanged.
        assert_eq!(rotated_identity.identity_key, identity.identity_key);
    }

    #[tokio::test]
    async fn rotate_active_key_retires_old_key_in_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (_, rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // The document should have 3 verification methods: #0, #retired-N, #active.
        assert_eq!(rotated_doc.verification_method.len(), 3);

        // #active must exist with a new key.
        let new_active_vm = rotated_doc.verification_method_by_fragment("active");
        assert!(new_active_vm.is_some());

        // A retired key should exist.
        let has_retired = rotated_doc
            .verification_method
            .iter()
            .any(|vm| vm.id.contains("#retired-"));
        assert!(has_retired);

        // #0 (identity key) must still be present.
        let vm0 = rotated_doc.verification_method_by_fragment("0");
        assert!(vm0.is_some());
    }

    #[tokio::test]
    async fn rotate_active_key_updates_auth_and_assertion_refs() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (_, rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // authentication and assertionMethod should reference #active.
        assert_eq!(
            rotated_doc.authentication,
            vec![format!("{}#active", identity.did)]
        );
        assert_eq!(
            rotated_doc.assertion_method,
            vec![format!("{}#active", identity.did)]
        );
    }

    #[tokio::test]
    async fn rotate_active_key_preserves_pre_rotation_commitment() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (rotated_identity, _) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Pre-rotation commitment must be unchanged during active key rotation.
        assert_eq!(
            rotated_identity.pre_rotation_commitment,
            identity.pre_rotation_commitment
        );
    }

    #[tokio::test]
    async fn rotate_active_key_publishes_updated_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let seq_before = dht.current_sequence();

        let (_, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Publishing should have incremented the sequence number.
        assert!(dht.current_sequence() > seq_before);
    }

    #[tokio::test]
    async fn rotate_via_did_method_trait() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Use the trait method which resolves the document internally.
        let (rotated_identity, rotated_doc) =
            <DidDht<InMemoryDhtClient, Arc<TestClock>> as DidMethod>::rotate(
                &dht, &identity, &*custody,
            )
            .await
            .unwrap();

        // DID preserved.
        assert_eq!(rotated_identity.did, identity.did);
        // Document updated.
        assert!(rotated_doc.verification_method.len() >= 3);
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Layer 2: migrate_identity
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn migrate_identity_creates_new_did() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // The new DID must be different from the old DID.
        assert_ne!(new_identity.did, identity.did);
        // The new DID must still be a valid did:dht.
        assert!(new_identity.did.starts_with("did:dht:z"));
    }

    #[tokio::test]
    async fn migrate_identity_new_did_is_self_certifying() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let pre_rot_public = custody.public_key(&pre_rot_key).await.unwrap();
        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // The new DID must be self-certifying for the pre-rotation key.
        assert!(dht.verify(&new_identity.did, pre_rot_public.as_bytes()));
    }

    #[tokio::test]
    async fn migrate_identity_updates_old_document_with_also_known_as() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // Re-resolve the old DID to check alsoKnownAs was published.
        // Clear the cache first to force a fresh DHT read.
        dht.cache().remove(&identity.did).await;
        let old_resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(old_resolved.document.also_known_as, vec![new_identity.did]);
    }

    #[tokio::test]
    async fn migrate_identity_produces_valid_rotation_event() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // The rotation event should reference old and new DIDs.
        assert_eq!(event.old_did, identity.did);
        assert_eq!(event.new_did, new_identity.did);
        assert_eq!(event.rotated_at, rotated_at);

        // The migration proof should have the old public key.
        let old_pub = custody.public_key(&identity.identity_key).await.unwrap();
        assert_eq!(
            event.migration_proof.old_public_key,
            <[u8; 32]>::try_from(old_pub.as_bytes()).unwrap()
        );

        // The signature should be 64 bytes.
        assert_eq!(event.migration_proof.signature.len(), 64);
    }

    #[tokio::test]
    async fn migrate_identity_includes_pre_rotation_proof() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // Pre-rotation proof should be present if the old document had a
        // PreRotationCommitment service.
        assert!(event.pre_rotation_proof.is_some());
        let pre_rot_proof = event.pre_rotation_proof.unwrap();

        // The revealed key should match the pre-rotation key's public key.
        let pre_rot_public = custody.public_key(&pre_rot_key).await.unwrap();
        assert_eq!(
            pre_rot_proof.revealed_key,
            <[u8; 32]>::try_from(pre_rot_public.as_bytes()).unwrap()
        );
    }

    #[tokio::test]
    async fn migrate_identity_publishes_new_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, new_doc, _event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // The new DID should be resolvable from the DHT.
        let resolved = dht.resolve_did(&new_identity.did).await.unwrap();
        assert_eq!(resolved.document.id, new_doc.id);
    }

    #[tokio::test]
    async fn migrate_identity_new_identity_has_fresh_pre_rotation_commitment() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // The new identity should have a non-zero pre-rotation commitment.
        assert_ne!(new_identity.pre_rotation_commitment, [0u8; 32]);
        // It should differ from the old commitment.
        assert_ne!(
            new_identity.pre_rotation_commitment,
            identity.pre_rotation_commitment
        );
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Layer 3: verify_migration
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_migration_accepts_valid_proof() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // Verify the migration proof.
        let result = verify_migration(
            &event.old_did,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
        );
        assert!(result.is_ok(), "verify_migration failed: {result:?}");
        assert!(result.unwrap());

        // Also verify self-certification of the new DID.
        let new_pub = custody
            .public_key(&new_identity.identity_key)
            .await
            .unwrap();
        assert!(dht.verify(&new_identity.did, new_pub.as_bytes()));
    }

    #[tokio::test]
    async fn verify_migration_rejects_tampered_signature() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // Tamper with the signature.
        let mut tampered_proof = event.migration_proof.clone();
        tampered_proof.signature[0] ^= 0xFF;

        let result = verify_migration(
            &event.old_did,
            &event.new_did,
            &tampered_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IdentityError::MigrationVerificationFailed(_))
        ));
    }

    #[tokio::test]
    async fn verify_migration_rejects_wrong_timestamp() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // Use a different timestamp — the digest won't match.
        let result = verify_migration(
            &event.old_did,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            rotated_at + 1,
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_migration_works_without_pre_rotation_proof() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // Verify with no pre-rotation proof (MODERATE assurance only).
        let result = verify_migration(
            &event.old_did,
            &event.new_did,
            &event.migration_proof,
            None,
            event.rotated_at,
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn verify_migration_rejects_invalid_pre_rotation_proof() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rot_key) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event) = dht
            .migrate_identity(&identity, &document, &pre_rot_key, &*custody, rotated_at)
            .await
            .unwrap();

        // Create a tampered pre-rotation proof with wrong revealed_key.
        let tampered_pre_rot = PreRotationProof {
            commitment: event.pre_rotation_proof.as_ref().unwrap().commitment,
            revealed_key: [99u8; 32], // wrong key
        };

        let result = verify_migration(
            &event.old_did,
            &event.new_did,
            &event.migration_proof,
            Some(&tampered_pre_rot),
            event.rotated_at,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IdentityError::MigrationVerificationFailed(_))
        ));
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Document-level rotation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn retire_active_key_renames_and_adds_new() {
        let did = "did:dht:zTestRotation";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let mut rotated_doc = doc;
        rotated_doc.retire_active_key(&[4u8; 32], 1);

        // Should have 3 verification methods now.
        assert_eq!(rotated_doc.verification_method.len(), 3);

        // The retired key should exist.
        let retired = rotated_doc
            .verification_method
            .iter()
            .find(|vm| vm.id.contains("#retired-1"));
        assert!(retired.is_some());

        // The new #active should exist.
        let active = rotated_doc.verification_method_by_fragment("active");
        assert!(active.is_some());

        // #0 should still exist.
        let identity = rotated_doc.verification_method_by_fragment("0");
        assert!(identity.is_some());
    }

    #[test]
    fn set_also_known_as_sets_field() {
        let did = "did:dht:zTestAKA";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert!(doc.also_known_as.is_empty());

        doc.set_also_known_as("did:dht:zNewDid");
        assert_eq!(doc.also_known_as, vec!["did:dht:zNewDid"]);
    }

    #[test]
    fn also_known_as_omitted_from_json_when_empty() {
        let did = "did:dht:zTestJSON";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let json = doc.to_json().unwrap();

        // alsoKnownAs should not appear in the JSON when empty.
        assert!(!json.contains("alsoKnownAs"));
    }

    #[test]
    fn also_known_as_present_in_json_when_set() {
        let did = "did:dht:zTestJSON2";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        doc.set_also_known_as("did:dht:zNewDid");

        let json = doc.to_json().unwrap();
        assert!(json.contains("alsoKnownAs"));
        assert!(json.contains("did:dht:zNewDid"));

        // Roundtrip should preserve alsoKnownAs.
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(parsed.also_known_as, vec!["did:dht:zNewDid"]);
    }

    #[test]
    fn rotation_event_json_roundtrip() {
        let event = DidRotationEvent {
            old_did: "did:dht:zOld".to_owned(),
            new_did: "did:dht:zNew".to_owned(),
            migration_proof: MigrationProof {
                signature: [0xAA; 64],
                old_public_key: [0xBB; 32],
            },
            pre_rotation_proof: Some(PreRotationProof {
                commitment: [0xCC; 32],
                revealed_key: [0xDD; 32],
            }),
            rotated_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: DidRotationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -----------------------------------------------------------------------
    // SCP-141 tests — Relay URL publication in DID publish flow
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn publish_with_relay_urls_includes_scp_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        let relay_urls = &[
            "wss://relay1.example.com/scp/v1",
            "wss://relay2.example.com/scp/v1",
        ];

        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, relay_urls)
            .await
            .unwrap();

        // Published document should include SCPRelay entries.
        let resolved_urls = published_doc.relay_service_urls();
        assert_eq!(resolved_urls.len(), 2);
        assert_eq!(resolved_urls[0], "wss://relay1.example.com/scp/v1");
        assert_eq!(resolved_urls[1], "wss://relay2.example.com/scp/v1");

        // Resolve from DHT and verify relay entries survive roundtrip.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        let resolved_relay_urls = resolved.document.relay_service_urls();
        assert_eq!(resolved_relay_urls.len(), 2);
        assert_eq!(resolved_relay_urls[0], "wss://relay1.example.com/scp/v1");
        assert_eq!(resolved_relay_urls[1], "wss://relay2.example.com/scp/v1");
    }

    #[tokio::test]
    async fn publish_without_relay_urls_has_no_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        // Publish without relay URLs (empty slice).
        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, &[])
            .await
            .unwrap();

        // No SCPRelay entries.
        assert!(published_doc.relay_service_urls().is_empty());

        // Resolve from DHT and verify no relay entries.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.relay_service_urls().is_empty());
    }

    #[tokio::test]
    async fn update_relay_urls_returns_new_urls_and_increments_sequence() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        // Initial publish with one relay URL.
        let initial_doc = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay1.example.com/scp/v1"])
            .await
            .unwrap();

        let seq_after_initial = dht.current_sequence();
        assert_eq!(initial_doc.relay_service_urls().len(), 1);

        // Update to a different set of relay URLs.
        let updated_doc = dht
            .update_relay_urls(
                &identity,
                &initial_doc,
                &[
                    "wss://new-relay1.example.com/scp/v1",
                    "wss://new-relay2.example.com/scp/v1",
                    "wss://new-relay3.example.com/scp/v1",
                ],
            )
            .await
            .unwrap();

        // Sequence number must have incremented.
        let seq_after_update = dht.current_sequence();
        assert!(seq_after_update > seq_after_initial);

        // Updated document should have the new relay URLs.
        let updated_urls = updated_doc.relay_service_urls();
        assert_eq!(updated_urls.len(), 3);
        assert_eq!(updated_urls[0], "wss://new-relay1.example.com/scp/v1");
        assert_eq!(updated_urls[1], "wss://new-relay2.example.com/scp/v1");
        assert_eq!(updated_urls[2], "wss://new-relay3.example.com/scp/v1");

        // Resolve from DHT and verify the updated relay URLs.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        let resolved_urls = resolved.document.relay_service_urls();
        assert_eq!(resolved_urls.len(), 3);
        assert_eq!(resolved_urls[0], "wss://new-relay1.example.com/scp/v1");
        assert_eq!(resolved_urls[1], "wss://new-relay2.example.com/scp/v1");
        assert_eq!(resolved_urls[2], "wss://new-relay3.example.com/scp/v1");
    }

    #[tokio::test]
    async fn publish_with_relay_urls_rejects_invalid_url() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        // Invalid scheme.
        let result = dht
            .publish_with_relay_urls(&identity, &document, &["http://relay.example.com/scp/v1"])
            .await;
        assert!(matches!(result, Err(IdentityError::InvalidRelayUrl(_))));

        // Invalid path.
        let result = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay.example.com/other"])
            .await;
        assert!(matches!(result, Err(IdentityError::InvalidRelayUrl(_))));
    }

    #[tokio::test]
    async fn update_relay_urls_preserves_non_relay_services() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        // Verify the document starts with a PreRotationCommitment service.
        assert!(document.pre_rotation_service().is_some());

        // Publish with relay URLs.
        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay.example.com/scp/v1"])
            .await
            .unwrap();

        // PreRotationCommitment should still be present.
        assert!(published_doc.pre_rotation_service().is_some());
        assert_eq!(published_doc.relay_service_urls().len(), 1);

        // Update relay URLs.
        let updated_doc = dht
            .update_relay_urls(
                &identity,
                &published_doc,
                &["wss://new-relay.example.com/scp/v1"],
            )
            .await
            .unwrap();

        // PreRotationCommitment should still be present after update.
        assert!(updated_doc.pre_rotation_service().is_some());
        assert_eq!(updated_doc.relay_service_urls().len(), 1);
        assert_eq!(
            updated_doc.relay_service_urls()[0],
            "wss://new-relay.example.com/scp/v1"
        );
    }

    #[tokio::test]
    async fn update_relay_urls_to_empty_removes_all_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        // Publish with relay URLs.
        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay.example.com/scp/v1"])
            .await
            .unwrap();
        assert_eq!(published_doc.relay_service_urls().len(), 1);

        // Update to empty relay list.
        let updated_doc = dht
            .update_relay_urls(&identity, &published_doc, &[])
            .await
            .unwrap();

        assert!(updated_doc.relay_service_urls().is_empty());

        // Resolve and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.relay_service_urls().is_empty());
    }

    #[tokio::test]
    async fn bep44_signature_covers_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document) = dht.create(&*custody).await.unwrap();

        let relay_urls = &["wss://relay.example.com/scp/v1"];
        dht.publish_with_relay_urls(&identity, &document, relay_urls)
            .await
            .unwrap();

        // Clear cache and resolve from DHT. The resolve_did method verifies
        // the BEP44 signature, which covers the complete document including
        // relay entries. If the signature didn't cover relay entries, this
        // would fail.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();

        // The resolved document should have the relay entries, proving the
        // BEP44 signature covered them.
        assert_eq!(resolved.document.relay_service_urls().len(), 1);
        assert_eq!(
            resolved.document.relay_service_urls()[0],
            "wss://relay.example.com/scp/v1"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-176 — Concurrent sequence number monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_fetch_add_produces_unique_monotonic_values() {
        use std::sync::atomic::AtomicU64;
        use std::thread;

        let num_threads = 8;
        let increments_per_thread = 1_000;
        let seq = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq = Arc::clone(&seq);
                thread::spawn(move || {
                    let mut values = Vec::with_capacity(increments_per_thread);
                    for _ in 0..increments_per_thread {
                        let v = seq.fetch_add(1, Ordering::AcqRel);
                        values.push(v);
                    }
                    values
                })
            })
            .collect();

        let mut all_values: Vec<u64> = Vec::with_capacity(num_threads * increments_per_thread);
        for handle in handles {
            let thread_values = handle.join().unwrap();
            // Each thread's values must be strictly monotonically increasing.
            for window in thread_values.windows(2) {
                assert!(
                    window[0] < window[1],
                    "per-thread values not monotonic: {} >= {}",
                    window[0],
                    window[1]
                );
            }
            all_values.extend(thread_values);
        }

        // All values across all threads must be unique.
        all_values.sort_unstable();
        all_values.dedup();
        assert_eq!(
            all_values.len(),
            num_threads * increments_per_thread,
            "duplicate sequence values detected across threads"
        );

        // Final counter value must equal total increments.
        assert_eq!(
            seq.load(Ordering::Acquire),
            (num_threads * increments_per_thread) as u64
        );
    }
}
