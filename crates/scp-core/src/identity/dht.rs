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

use ed25519_dalek::{Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyType};

use super::cache::{Clock, DidCache, DidResolutionResult, Staleness, SystemClock};
use super::dht_client::{DhtClient, InMemoryDhtClient};
use super::document::DidDocument;
use super::{DidMethod, IdentityError, ScpIdentity};

/// The `did:dht` DID method prefix.
const DID_DHT_PREFIX: &str = "did:dht:";

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
        self.sequence.load(Ordering::Relaxed)
    }

    /// Sets the sequence number (e.g., when loading from persistent storage).
    pub fn set_sequence(&self, seq: u64) {
        self.sequence.store(seq, Ordering::Relaxed);
    }

    /// Constructs the BEP44 signable payload for a value and sequence number.
    ///
    /// BEP44 signing payload format:
    /// `"4:salt" + salt_len + ":" + salt + "3:seqi" + seq + "e1:v" + val_len + ":" + val`
    ///
    /// For did:dht, salt is not used, so the payload is:
    /// `"3:seqi" + seq + "e1:v" + val_len + ":" + val`
    #[must_use]
    pub fn bep44_signable(value: &[u8], seq: u64) -> Vec<u8> {
        // BEP44 mutable item signable: "3:seqi<seq>e1:v<len>:<val>"
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
    /// # Errors
    ///
    /// Returns [`IdentityError::Bep44SignatureInvalid`] if the signature does
    /// not verify.
    fn verify_bep44_signature(
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> Result<(), IdentityError> {
        let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|e| {
            IdentityError::Bep44SignatureInvalid(format!("invalid public key: {e}"))
        })?;

        let sig = ed25519_dalek::Signature::from_bytes(signature);
        let payload = Self::bep44_signable(value, seq);

        verifying_key.verify(&payload, &sig).map_err(|e| {
            IdentityError::Bep44SignatureInvalid(format!("signature verification failed: {e}"))
        })
    }

    /// Extracts the 32-byte public key from a `did:dht:z...` string.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidDidFormat`] if the DID format is wrong
    /// or z-base-32 decoding fails.
    fn extract_public_key(did_string: &str) -> Result<[u8; 32], IdentityError> {
        let encoded = did_string
            .strip_prefix(DID_DHT_PREFIX)
            .and_then(|s| s.strip_prefix('z'))
            .ok_or_else(|| {
                IdentityError::InvalidDidFormat(format!(
                    "expected 'did:dht:z...' prefix, got: {did_string}"
                ))
            })?;

        let decoded = zbase32::decode(encoded).map_err(|e| {
            IdentityError::ZBase32DecodeError(format!("z-base-32 decode failed: {e}"))
        })?;

        let key_bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            IdentityError::InvalidDidFormat(format!(
                "expected 32-byte public key, got {} bytes",
                v.len()
            ))
        })?;

        Ok(key_bytes)
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
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;

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

/// Base58btc decoding (Bitcoin alphabet).
///
/// Inverse of the `base58btc_encode` function in `document.rs`.
fn base58btc_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Count leading '1' characters (these map to leading zero bytes).
    let zero_count = input.bytes().take_while(|&b| b == b'1').count();

    // Convert from base58 to base256 via repeated division.
    // We use u32 for the carry to avoid usize-to-u8 truncation warnings.
    let mut bytes: Vec<u8> = Vec::new();
    for ch in input.bytes() {
        let Some(val) = ALPHABET.iter().position(|&a| a == ch) else {
            return Err(format!("invalid base58 character: {}", ch as char));
        };
        // val is always < 58, so this cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        let mut carry = val as u32;
        for byte in &mut bytes {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    let mut result = vec![0u8; zero_count];
    result.extend(bytes.into_iter().rev());
    Ok(result)
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
    DidDht::new().verify(did_string, public_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use scp_platform::testing::InMemoryKeyCustody;

    use super::*;
    use crate::identity::cache::TestClock;
    use crate::identity::dht_client::InMemoryDhtClient;

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
        let encoded = crate::identity::document::DidDocument::new(
            "did:dht:zTest",
            &original,
            &[0u8; 32],
            &[0u8; 32],
        );
        let vm = encoded.verification_method_by_fragment("0").unwrap();
        let decoded = decode_multibase_key(&vm.public_key_multibase).unwrap();
        assert_eq!(decoded, original);
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
}
