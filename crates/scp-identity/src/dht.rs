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

use scp_platform::traits::{KeyCustody, KeyType, PreRotationCustody, PreRotationKeyHandle};

use super::cache::{Clock, DidCache, DidResolutionResult, Staleness, SystemClock};
use super::dht_client::{DhtClient, InMemoryDhtClient};
use super::document::{DidDocument, DidRotationEvent, MigrationProof, PreRotationProof};
use super::{DidMethod, IdentityError, ScpIdentity};

/// The `did:dht` DID method prefix.
const DID_DHT_PREFIX: &str = "did:dht:";

// ---------------------------------------------------------------------------
// BEP44 Sequence Persistence (issue #327)
// ---------------------------------------------------------------------------

/// Persistence trait for BEP44 sequence numbers.
///
/// DID document publications to the Mainline DHT use BEP44 signed mutable
/// items with a monotonically increasing sequence number. If the node restarts
/// and begins from 0, previously-published documents with higher sequence
/// numbers will be considered "newer" by DHT peers, enabling replay attacks.
///
/// Implementations persist the last-published sequence number so it can be
/// recovered on restart. The identity crate defines this trait (rather than
/// importing from `scp-core`) to preserve `scp-identity`'s self-contained
/// design.
///
/// See issue #327 and BEP44 §Mutable Items.
pub trait SequenceStore: Send + Sync {
    /// Loads the last-persisted sequence number for the given DID.
    ///
    /// Returns `Ok(None)` if no sequence has been stored (first run).
    fn load(
        &self,
        did: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, IdentityError>> + Send + '_>>;

    /// Persists the sequence number for the given DID.
    ///
    /// Called after every successful DID document publication.
    fn store(
        &self,
        did: &str,
        seq: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send + '_>>;
}

/// In-memory [`SequenceStore`] for testing.
///
/// Stores sequence numbers in a `HashMap` behind a `tokio::sync::Mutex`.
/// Not suitable for production (no persistence across restarts).
#[derive(Debug, Default)]
pub struct InMemorySequenceStore {
    sequences: tokio::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl InMemorySequenceStore {
    /// Creates a new empty in-memory sequence store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sequences: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl SequenceStore for InMemorySequenceStore {
    fn load(
        &self,
        did: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, IdentityError>> + Send + '_>> {
        let did = did.to_owned();
        Box::pin(async move {
            let map = self.sequences.lock().await;
            Ok(map.get(&did).copied())
        })
    }

    fn store(
        &self,
        did: &str,
        seq: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send + '_>> {
        let did = did.to_owned();
        Box::pin(async move {
            self.sequences.lock().await.insert(did, seq);
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Post-resolve hook (TOFU / certificate pinning integration point)
// ---------------------------------------------------------------------------

/// Hook called after every successful DID resolution.
///
/// This is the integration point for TOFU key tracking (spec §9.11) and
/// certificate pinning (spec §9.13). The `scp-core` crate provides an
/// implementation that calls `check_tofu` and persists records via
/// `ProtocolRepository`. The identity crate defines this trait (rather than
/// importing from `scp-core`) to preserve `scp-identity`'s self-contained
/// dependency graph.
///
/// # Rotation authorization on key change
///
/// When TOFU detects a key change (`TofuResult::Changed`), the implementation
/// should verify that the DID document update was properly authorized. For
/// `did:dht`, BEP44 signature verification during resolution already provides
/// this guarantee: the DHT record is signed by the Identity Key (`#0`), so
/// any document update — including key rotations — is cryptographically
/// authorized by the DID controller. The post-resolve hook does NOT need to
/// perform additional rotation authorization checks; it can focus on alerting
/// the user and refusing encrypted operations until the change is accepted.
pub trait PostResolveHook: Send + Sync {
    /// Called after a DID document is successfully resolved and verified.
    ///
    /// The hook receives the DID string and the resolved document. It may
    /// inspect verification method keys, compare against stored records,
    /// and report changes. Errors from this hook are logged but do not
    /// prevent the resolution result from being returned — TOFU is advisory,
    /// not a gate on resolution itself.
    fn on_resolve(
        &self,
        did: &str,
        document: &DidDocument,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send + '_>>;
}

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
/// - `DidDht::with_client_and_custody()` — Creates a fully-configured instance
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
    /// Optional persistence for BEP44 sequence numbers (issue #327).
    ///
    /// When present, the sequence number is persisted after every successful
    /// DID document publication and loaded on startup via
    /// [`initialize_sequence`](Self::initialize_sequence).
    sequence_store: Option<Arc<dyn SequenceStore>>,
    /// Optional post-resolve hook for TOFU key tracking (spec §9.11).
    ///
    /// When present, called after every successful DID resolution. Errors
    /// from the hook are logged but do not prevent resolution from succeeding.
    post_resolve_hook: Option<Arc<dyn PostResolveHook>>,
}

// Manual Debug impl because SignFn and dyn SequenceStore can't derive Debug.
impl<D: DhtClient + std::fmt::Debug, C: Clock + std::fmt::Debug> std::fmt::Debug for DidDht<D, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidDht")
            .field("dht_client", &self.dht_client)
            .field("cache", &self.cache)
            .field("sequence", &self.sequence)
            .field("sign_fn", &self.sign_fn.as_ref().map(|_| "<fn>"))
            .field(
                "sequence_store",
                &self.sequence_store.as_ref().map(|_| "<store>"),
            )
            .field(
                "post_resolve_hook",
                &self.post_resolve_hook.as_ref().map(|_| "<hook>"),
            )
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
    /// configured via `DidDht::with_client_and_custody`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dht_client: Arc::new(InMemoryDhtClient::new()),
            cache: Arc::new(DidCache::new()),
            sequence: AtomicU64::new(0),
            sign_fn: None,
            sequence_store: None,
            post_resolve_hook: None,
        }
    }

    /// Creates a `DidDht` instance with in-memory DHT, cache, and a signing
    /// function derived from the provided [`KeyCustody`].
    ///
    /// This is the recommended constructor for tests and examples that need
    /// to create identities and publish DID documents. Equivalent to manually
    /// constructing an `InMemoryDhtClient`, `DidCache`, calling `make_sign_fn`,
    /// and wiring them together via `with_client_and_signer`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use scp_identity::dht::DidDht;
    /// use scp_identity::DidMethod;
    /// use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let custody = Arc::new(InMemoryKeyCustody::new());
    /// let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
    /// let did_dht = DidDht::with_in_memory_custody(Arc::clone(&custody));
    /// let (identity, document, _pre_rotation_handle) = did_dht
    ///     .create(&*custody, &*pre_rotation_custody)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See issue #530.
    #[must_use]
    pub fn with_in_memory_custody<K: KeyCustody + 'static>(key_custody: Arc<K>) -> Self {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = Self::make_sign_fn(key_custody);
        Self {
            dht_client,
            cache,
            sequence: AtomicU64::new(0),
            sign_fn: Some(sign_fn),
            sequence_store: None,
            post_resolve_hook: None,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl DidDht<InMemoryDhtClient, SystemClock> {
    /// Creates an in-memory identity in a single call.
    ///
    /// Wires up [`InMemoryKeyCustody`](scp_platform::testing::InMemoryKeyCustody),
    /// `InMemoryDhtClient`, `DidCache`, and the signing function, then calls
    /// [`DidMethod::create`] to generate the identity. Returns all components
    /// the caller needs for subsequent operations.
    ///
    /// This replaces the 5-line boilerplate pattern:
    ///
    /// ```text
    /// // Before (5 lines):
    /// let custody = Arc::new(InMemoryKeyCustody::new());
    /// let dht_client = Arc::new(InMemoryDhtClient::new());
    /// let cache = Arc::new(DidCache::new());
    /// let sign_fn = DidDht::make_sign_fn(Arc::clone(&custody));
    /// let did_dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);
    /// let (identity, document) = did_dht.create(&*custody).await?;
    ///
    /// // After (1 line):
    /// let (identity, document, custody, did_dht) = DidDht::create_in_memory().await?;
    /// ```
    ///
    /// See issue #530.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if key generation or identity creation fails
    /// (should not happen with in-memory backends).
    pub async fn create_in_memory() -> Result<
        (
            ScpIdentity,
            DidDocument,
            Arc<scp_platform::testing::InMemoryKeyCustody>,
            Self,
        ),
        IdentityError,
    > {
        use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

        let custody = Arc::new(InMemoryKeyCustody::new());
        let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
        let did_dht = Self::with_in_memory_custody(Arc::clone(&custody));
        let (identity, document, _pre_rotation_handle) =
            did_dht.create(&*custody, &*pre_rotation_custody).await?;
        Ok((identity, document, custody, did_dht))
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
            sequence_store: None,
            post_resolve_hook: None,
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
            sequence_store: None,
            post_resolve_hook: None,
        }
    }

    /// Creates a new `DidDht` instance with DHT client, cache, signing
    /// function, and sequence persistence store (issue #327).
    ///
    /// After construction, call [`initialize_sequence`](Self::initialize_sequence)
    /// to bootstrap the sequence number from the store and/or DHT before
    /// publishing any documents.
    #[must_use]
    pub fn with_client_signer_and_store(
        dht_client: Arc<D>,
        cache: Arc<DidCache<C>>,
        sign_fn: Arc<SignFn>,
        sequence_store: Arc<dyn SequenceStore>,
    ) -> Self {
        Self {
            dht_client,
            cache,
            sequence: AtomicU64::new(0),
            sign_fn: Some(sign_fn),
            sequence_store: Some(sequence_store),
            post_resolve_hook: None,
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

    /// Returns a reference to the sequence store, if configured.
    #[must_use]
    pub fn sequence_store(&self) -> Option<&Arc<dyn SequenceStore>> {
        self.sequence_store.as_ref()
    }

    /// Sets a post-resolve hook for TOFU key tracking (spec §9.11).
    ///
    /// The hook is called after every successful DID resolution. Use this
    /// to integrate TOFU key tracking from `scp-core::crypto::tofu`.
    pub fn set_post_resolve_hook(&mut self, hook: Arc<dyn PostResolveHook>) {
        self.post_resolve_hook = Some(hook);
    }

    /// Returns a reference to the post-resolve hook, if configured.
    #[must_use]
    pub fn post_resolve_hook(&self) -> Option<&Arc<dyn PostResolveHook>> {
        self.post_resolve_hook.as_ref()
    }

    /// Bootstraps the BEP44 sequence number from persistent storage and/or
    /// the DHT (issue #327).
    ///
    /// This method MUST be called after construction and before publishing
    /// any DID documents. It ensures the node never publishes with a sequence
    /// number less than or equal to a previously-published value, even after
    /// restart.
    ///
    /// # Algorithm
    ///
    /// 1. Load the last-persisted sequence from the [`SequenceStore`] (if
    ///    configured).
    /// 2. Best-effort DHT query for the current sequence of the DID's BEP44
    ///    record. If the DHT is unreachable, initialization proceeds with the
    ///    locally-stored value and logs a warning.
    /// 3. Set the local sequence to `max(stored, remote)`. The next publish
    ///    will increment this to `max(stored, remote) + 1`.
    ///
    /// If no store is configured and no DHT record exists, the sequence
    /// remains at its current value (typically 0 for a new identity).
    ///
    /// # Errors
    ///
    /// Store load errors are propagated as-is. DHT query failures are
    /// logged but not propagated (best-effort).
    pub async fn initialize_sequence(&self, did: &str) -> Result<(), IdentityError> {
        // Step 1: Load from persistent store.
        let mut best_seq: u64 = if let Some(store) = &self.sequence_store
            && let Some(stored_seq) = store.load(did).await?
        {
            stored_seq
        } else {
            0
        };

        // Step 2: Best-effort DHT query for the current remote sequence.
        // If the DHT is unreachable we proceed with the locally-stored value
        // rather than failing the entire initialization.
        let public_key = extract_public_key(did)?;
        match self.dht_client.resolve(&public_key).await {
            Ok(Some(record)) => {
                best_seq = best_seq.max(record.seq);
            }
            Ok(None) => {} // No record on DHT — first publish or expired.
            Err(e) => {
                tracing::warn!(
                    did = %did,
                    error = %e,
                    "DHT query failed during sequence initialization, using local value"
                );
            }
        }

        // Step 3: Set to the maximum known sequence.
        // The next publish_document call will fetch_add(1), producing
        // max(stored, remote) + 1.
        if best_seq > 0 {
            self.sequence.store(best_seq, Ordering::Release);
        }

        Ok(())
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
    /// `DidMethod::publish` and the `RepublishManager`.
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

        // Persist the sequence number after successful publish (issue #327).
        if let Some(store) = &self.sequence_store {
            store.store(&identity.did, seq).await?;
        }

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
        verify_self_certification(did_string, &document)?;

        // Step 6: Post-resolve hook (TOFU key tracking, spec §9.11).
        // Errors are logged but do not prevent resolution from succeeding.
        if let Some(hook) = &self.post_resolve_hook
            && let Err(e) = hook.on_resolve(did_string, &document).await
        {
            tracing::warn!(
                did = %did_string,
                error = %e,
                "post-resolve hook failed (TOFU key tracking may be unavailable)"
            );
        }

        // Step 7: Update cache.
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
            agent_signing_key: identity.agent_signing_key,
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Creates a new identity with an agent signing key (ADR-039).
    ///
    /// Like [`DidMethod::create`] but generates a 4th Ed25519 keypair for the
    /// agent key. The agent key is included in the DID document as the `#agent`
    /// verification method and stored in `ScpIdentity::agent_signing_key`.
    ///
    /// # Arguments
    ///
    /// * `key_custody` - The key custody for generating Identity, Active,
    ///   and Agent keypairs (operational keys).
    /// * `pre_rotation_custody` - Cold-storage custody for the pre-rotation
    ///   key (spec §9.7.4.1 §3 — separate substrate from operational
    ///   custody). See [`DidMethod::create`] for the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Platform`] if operational key generation
    /// fails. Returns [`IdentityError::PreRotation`] if the pre-rotation
    /// key cannot be stored in cold custody.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn create_with_agent_key(
        &self,
        key_custody: &impl KeyCustody,
        pre_rotation_custody: &impl PreRotationCustody,
    ) -> Result<(ScpIdentity, DidDocument, PreRotationKeyHandle), IdentityError> {
        // Step 1: Operational keypairs (#0, #active, #agent).
        let identity_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        let active_signing_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 2: Ephemeral pre-rotation seed from the same RNG stream
        // (ADR-046 byte parity). Order matters: identity → active →
        // pre-rotation, MATCHING the seed-byte windows
        // [0..32]/[32..64]/[64..96] that cross-bridge tests pin. The
        // agent key follows after, since pre-the-add-agent-key seed
        // sequence already has agent at byte window [96..128].
        let pre_rotation_seed = key_custody
            .generate_ephemeral_ed25519_seed()
            .await
            .map_err(IdentityError::Platform)?;
        let pre_rotation_signing = ed25519_dalek::SigningKey::from_bytes(&pre_rotation_seed);
        let pre_rotation_public_bytes = pre_rotation_signing.verifying_key().to_bytes();
        drop(pre_rotation_signing);

        // Step 3: Agent keypair (the fourth in the seed window).
        let agent_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 4: Get operational public keys.
        let identity_public = key_custody
            .public_key(&identity_key)
            .await
            .map_err(IdentityError::Platform)?;

        let active_public = key_custody
            .public_key(&active_signing_key)
            .await
            .map_err(IdentityError::Platform)?;

        let agent_public = key_custody
            .public_key(&agent_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 5: Derive the DID string.
        let did = format!(
            "{DID_DHT_PREFIX}z{}",
            zbase32::encode(identity_public.as_bytes())
        );

        // Step 6: Compute pre-rotation commitment.
        let mut hasher = Sha256::new();
        hasher.update(pre_rotation_public_bytes);
        let commitment_bytes = hasher.finalize();
        let mut pre_rotation_commitment = [0u8; 32];
        pre_rotation_commitment.copy_from_slice(&commitment_bytes);

        // Step 7: Hand the pre-rotation seed to cold custody. Operational
        // copy drops here (Zeroizing).
        let pre_rotation_handle = pre_rotation_custody
            .store_committed_pre_rotation_key(&pre_rotation_public_bytes, pre_rotation_seed)
            .await
            .map_err(IdentityError::PreRotation)?;

        // Step 8: Build the DID document with agent key.
        let document = DidDocument::new_with_agent_key(
            &did,
            identity_public.as_bytes(),
            active_public.as_bytes(),
            &pre_rotation_commitment,
            Some(agent_public.as_bytes()),
        );

        // Step 9: Return the identity, document, and pre-rotation handle.
        let identity = ScpIdentity {
            identity_key,
            active_signing_key,
            agent_signing_key: Some(agent_key),
            pre_rotation_commitment,
            did,
        };

        Ok((identity, document, pre_rotation_handle))
    }

    /// Adds an agent signing key to an existing identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair for the agent key, adds it to the DID
    /// document as the `#agent` verification method, signs the document with
    /// the Identity Key, and publishes to the DHT.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (must not already have an agent key).
    /// * `document` - The current DID document.
    /// * `key_custody` - The key custody for generating the agent keypair.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::AgentKeyAlreadyExists`] if `#agent` already exists.
    /// Returns [`IdentityError::Platform`] if key generation fails.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn add_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 1: Check if the document already has an agent key.
        // This must happen BEFORE key generation to avoid leaking key material
        // in the custody provider on the error path.
        if document.has_agent_key() {
            return Err(IdentityError::AgentKeyAlreadyExists);
        }

        // Step 2: Generate a new Ed25519 keypair for the agent key.
        let agent_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 3: Get the agent key's public key.
        let agent_public = key_custody
            .public_key(&agent_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 4: Clone and update the document.
        let mut updated_doc = document.clone();
        updated_doc.add_agent_key(agent_public.as_bytes())?;

        // Step 5: Publish the updated document (signed with Identity Key).
        self.publish_document(identity, &updated_doc).await?;

        // Step 6: Build the updated identity.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: identity.active_signing_key,
            agent_signing_key: Some(agent_key),
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Rotates the agent signing key for an identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair, updates the DID document (moves the old
    /// `#agent` key to `#retired-agent-{sequence}`, installs the new key as
    /// `#agent`), signs the document with the Identity Key, and publishes to
    /// the DHT.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (must have an existing agent key).
    /// * `document` - The current DID document.
    /// * `key_custody` - The key custody for generating the new agent keypair.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::AgentKeyNotFound`] if no `#agent` VM exists.
    /// Returns [`IdentityError::Platform`] if key generation fails.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn rotate_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 0: Verify identity/document consistency — the identity must
        // track an agent key before we attempt rotation.
        if identity.agent_signing_key.is_none() {
            return Err(IdentityError::AgentKeyNotFound);
        }

        // Step 1: Generate a new Ed25519 keypair.
        let new_agent_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 2: Get the new key's public key.
        let new_agent_public = key_custody
            .public_key(&new_agent_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 3: Clone and update the document.
        let mut updated_doc = document.clone();
        let sequence = self.current_sequence().saturating_add(1);
        updated_doc.rotate_agent_key(new_agent_public.as_bytes(), sequence)?;

        // Step 4: Publish the updated document (signed with Identity Key).
        self.publish_document(identity, &updated_doc).await?;

        // Step 5: Build the updated identity. DID, identity key, active key,
        // and pre-rotation commitment are preserved.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: identity.active_signing_key,
            agent_signing_key: Some(new_agent_key),
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Removes the agent signing key from an identity (ADR-039).
    ///
    /// Removes the `#agent` verification method from the DID document, signs
    /// the document with the Identity Key, and publishes to the DHT.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (must have an existing agent key).
    /// * `document` - The current DID document.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::AgentKeyNotFound`] if no `#agent` VM exists.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn remove_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 0: Verify identity/document consistency — the identity must
        // track an agent key before we attempt removal.
        if identity.agent_signing_key.is_none() {
            return Err(IdentityError::AgentKeyNotFound);
        }

        // Step 1: Clone and update the document.
        let mut updated_doc = document.clone();
        updated_doc.remove_agent_key()?;

        // Step 2: Publish the updated document (signed with Identity Key).
        self.publish_document(identity, &updated_doc).await?;

        // Step 3: Build the updated identity with agent_signing_key: None.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: identity.active_signing_key,
            agent_signing_key: None,
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Attaches a device attestation token to a DID document.
    ///
    /// Calls `DeviceAttestation::attest()` to generate a platform-specific
    /// attestation token, then stores it as an `ScpDeviceAttestation` service
    /// entry in the DID document (§9.3). The token is base64-encoded in the
    /// `serviceEndpoint` field. The service entry uses the ID format
    /// `{did}#device-attestation`.
    ///
    /// Device attestation is a Sybil resistance signal -- the protocol carries
    /// the proof but does not prescribe interpretation. Contexts MAY require
    /// device attestation for admission via `ContextParams`.
    ///
    /// When `DeviceAttestation` is not available (e.g., desktop platforms
    /// without hardware attestation), callers should skip this method. The
    /// absence of an `ScpDeviceAttestation` service entry is a valid state.
    ///
    /// # Arguments
    ///
    /// * `document` - The DID document to attach the attestation to.
    /// * `attestation` - A platform `DeviceAttestation` implementation.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Platform`] if the attestation service is
    /// unavailable or attestation generation fails.
    ///
    /// See §9.3, issue #362, BLACK-006.
    pub async fn attach_device_attestation(
        &self,
        document: &DidDocument,
        attestation: &impl scp_platform::traits::DeviceAttestation,
    ) -> Result<DidDocument, IdentityError> {
        let token = attestation
            .attest()
            .await
            .map_err(IdentityError::Platform)?;

        let mut updated_doc = document.clone();
        updated_doc.set_device_attestation_token(token.as_bytes());
        Ok(updated_doc)
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
    /// * `pre_rotation_handle` - Handle returned by [`PreRotationCustody::store_committed_pre_rotation_key`]
    ///   when the identity was created. Resolved against `pre_rotation_custody`
    ///   to recover the public bytes (for `revealed_key`) and consume the
    ///   private bytes (which become the new identity key, ADR-003 §4b).
    /// * `pre_rotation_custody` - The cold-storage custody holding the
    ///   pre-rotation key. Per spec §9.7.4.1 §6, the protocol immediately
    ///   stores a fresh pre-rotation key in this custody before returning.
    /// * `key_custody` - The operational custody for the new identity. The
    ///   migrated `#0` (the old pre-rotation key's private bytes) is
    ///   imported here; the new `#active` is generated here.
    /// * `rotated_at` - Unix timestamp for the migration event.
    ///
    /// # Returns
    ///
    /// `(new_identity, new_document, rotation_event, new_pre_rotation_handle)`:
    /// - `new_identity` — The new [`ScpIdentity`] with new DID and keys.
    /// - `new_document` — The DID document for the new identity.
    /// - `rotation_event` — The [`DidRotationEvent`] to distribute to all
    ///   active contexts (spec §3.2.1 step 4b).
    /// - `new_pre_rotation_handle` — Handle for the freshly-minted
    ///   pre-rotation key in `pre_rotation_custody` (per §9.7.4.1 §6
    ///   "post-rotation key cycling"). Caller persists this for the next
    ///   migration.
    ///
    /// # Errors
    ///
    /// Returns errors if key generation, signing, or DHT publishing fails.
    ///
    /// See ADR-003 acceptance criterion 4b and spec §9.7.4.1 §6.
    pub async fn migrate_identity(
        &self,
        identity: &ScpIdentity,
        old_document: &DidDocument,
        pre_rotation_handle: &PreRotationKeyHandle,
        pre_rotation_custody: &impl PreRotationCustody,
        key_custody: &impl KeyCustody,
        rotated_at: u64,
    ) -> Result<
        (
            ScpIdentity,
            DidDocument,
            DidRotationEvent,
            PreRotationKeyHandle,
        ),
        IdentityError,
    > {
        // Step 1: Reveal the pre-rotation public key. This will become the
        // new identity public key (ADR-003 §4b). The custody verifies its
        // own commitment integrity if it stored one.
        let new_identity_public_bytes = pre_rotation_custody
            .reveal_public_key(pre_rotation_handle)
            .await
            .map_err(IdentityError::PreRotation)?;

        let new_did = format!(
            "{DID_DHT_PREFIX}z{}",
            zbase32::encode(&new_identity_public_bytes)
        );

        // Step 2: Build the migration_proof signed by the OLD identity key
        // and the pre_rotation_proof carrying the revealed public key.
        let migration_proof =
            Self::build_migration_proof(identity, &new_did, rotated_at, key_custody).await?;
        let pre_rotation_proof =
            Self::build_pre_rotation_proof_from_bytes(old_document, &new_identity_public_bytes)?;

        // Step 3: Update the OLD DID document with `alsoKnownAs` and
        // publish — this happens BEFORE we touch operational custody so
        // that any failure leaves the old identity intact.
        let mut updated_old_doc = old_document.clone();
        updated_old_doc.set_also_known_as(&new_did);
        self.publish_document(identity, &updated_old_doc).await?;

        // Step 4: Generate the NEW pre-rotation seed using the operational
        // custody's RNG (ADR-046 byte parity). The new active key follows.
        let new_pre_rotation_seed = key_custody
            .generate_ephemeral_ed25519_seed()
            .await
            .map_err(IdentityError::Platform)?;
        let new_pre_rotation_signing =
            ed25519_dalek::SigningKey::from_bytes(&new_pre_rotation_seed);
        let new_pre_rotation_public_bytes = new_pre_rotation_signing.verifying_key().to_bytes();
        drop(new_pre_rotation_signing);

        let new_active_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;
        let new_active_public = key_custody
            .public_key(&new_active_key)
            .await
            .map_err(IdentityError::Platform)?;

        let mut hasher = Sha256::new();
        hasher.update(new_pre_rotation_public_bytes);
        let new_pre_rotation_commitment_bytes = hasher.finalize();
        let mut new_pre_rotation_commitment = [0u8; 32];
        new_pre_rotation_commitment.copy_from_slice(&new_pre_rotation_commitment_bytes);

        // Step 5: Hand the new pre-rotation seed to cold custody. If this
        // fails, the operational copy zeroizes on drop and we surface the
        // error WITHOUT having consumed the old pre-rotation key.
        let new_pre_rotation_handle = pre_rotation_custody
            .store_committed_pre_rotation_key(&new_pre_rotation_public_bytes, new_pre_rotation_seed)
            .await
            .map_err(IdentityError::PreRotation)?;

        // Step 6: Consume the OLD pre-rotation key from cold custody —
        // returning its private bytes — and import them into operational
        // custody as the new `#0`. Per spec §9.7.4.1 §6, the old
        // pre-rotation key is destroyed after migration completes; here
        // we destroy-and-export atomically (the trait method's
        // documented contract).
        let revealed_private = pre_rotation_custody
            .destroy_after_migration(*pre_rotation_handle)
            .await
            .map_err(IdentityError::PreRotation)?;

        let new_identity_key = key_custody
            .import_ed25519_signing_key(&revealed_private)
            .await
            .map_err(IdentityError::Platform)?;
        // `revealed_private` is `Zeroizing` — drops here.

        // Step 7: Build and publish the new DID document.
        let new_document = DidDocument::new(
            &new_did,
            &new_identity_public_bytes,
            new_active_public.as_bytes(),
            &new_pre_rotation_commitment,
        );

        let new_identity = ScpIdentity {
            identity_key: new_identity_key,
            active_signing_key: new_active_key,
            agent_signing_key: None,
            pre_rotation_commitment: new_pre_rotation_commitment,
            did: new_did.clone(),
        };

        self.publish_document(&new_identity, &new_document).await?;

        // Step 8: Build and return the rotation event.
        let rotation_event = DidRotationEvent {
            old_did: identity.did.clone(),
            new_did,
            migration_proof,
            pre_rotation_proof,
            rotated_at,
        };

        Ok((
            new_identity,
            new_document,
            rotation_event,
            new_pre_rotation_handle,
        ))
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
        let old_len = u32::try_from(identity.did.len()).map_err(|_| {
            IdentityError::InvalidDidFormat("DID too long for length prefix".into())
        })?;
        let new_len = u32::try_from(new_did.len()).map_err(|_| {
            IdentityError::InvalidDidFormat("DID too long for length prefix".into())
        })?;
        hasher.update(old_len.to_be_bytes());
        hasher.update(identity.did.as_bytes());
        hasher.update(new_len.to_be_bytes());
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

    /// Builds a pre-rotation proof from the old document's
    /// `PreRotationCommitment` service, if present, against the revealed
    /// new identity public key (32 bytes).
    fn build_pre_rotation_proof_from_bytes(
        old_document: &DidDocument,
        new_identity_public_bytes: &[u8; 32],
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

        Ok(Some(PreRotationProof {
            commitment,
            revealed_key: *new_identity_public_bytes,
        }))
    }
}

/// Verifies that the identity key in a DID document matches the DID string's
/// z-base-32 encoded public key (self-certification check).
///
/// This is the single, consolidated implementation used by:
/// - `DidDht::resolve_did` (DHT resolution path)
/// - `verify_and_deserialize` in `resolver.rs` (dual-layer resolution path)
/// - `relay_resolve` in `resolution.rs` (relay resolution path)
///
/// # Errors
///
/// Returns [`IdentityError::SelfCertificationFailed`] if the document's identity
/// key (`#0` verification method) does not match the public key encoded in the
/// DID string.
pub fn verify_self_certification(
    did_string: &str,
    document: &DidDocument,
) -> Result<(), IdentityError> {
    let public_key = extract_public_key(did_string)?;

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

/// Decodes a multibase-encoded public key (z-prefix = base58btc).
///
/// # Errors
///
/// Returns [`IdentityError::InvalidDidFormat`] if the key is not properly
/// base58btc encoded.
pub fn decode_multibase_key(encoded: &str) -> Result<[u8; 32], IdentityError> {
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
        pre_rotation_custody: &impl PreRotationCustody,
    ) -> impl Future<
        Output = Result<(ScpIdentity, DidDocument, PreRotationKeyHandle), IdentityError>,
    > + Send {
        async move {
            // Step 1: Generate the operational keypairs in `key_custody`
            // (Identity Key #0, Active Signing Key #active).
            let identity_key = key_custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .map_err(IdentityError::Platform)?;

            let active_signing_key = key_custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .map_err(IdentityError::Platform)?;

            // Step 2: Mint an ephemeral pre-rotation seed using the SAME
            // RNG stream as the operational keypairs. This preserves the
            // ADR-046 cross-bridge byte-parity invariant (seed[0..32] →
            // identity, seed[32..64] → active, seed[64..96] → pre-rotation)
            // while ensuring the private bytes never sit in operational
            // custody (spec §9.7.4.1 §1, §5(a)). For HSM-backed custody
            // that cannot export ephemeral seed bytes, callers must
            // surface the pre-rotation key through a platform-CSPRNG
            // path and route it directly into `pre_rotation_custody`.
            let pre_rotation_seed = key_custody
                .generate_ephemeral_ed25519_seed()
                .await
                .map_err(IdentityError::Platform)?;
            let pre_rotation_signing = ed25519_dalek::SigningKey::from_bytes(&pre_rotation_seed);
            let pre_rotation_public_bytes = pre_rotation_signing.verifying_key().to_bytes();

            // Step 3: Get operational public keys.
            let identity_public = key_custody
                .public_key(&identity_key)
                .await
                .map_err(IdentityError::Platform)?;

            let active_public = key_custody
                .public_key(&active_signing_key)
                .await
                .map_err(IdentityError::Platform)?;

            // Step 4: Derive the DID string: did:dht:z<z-base-32(identity_public_key)>
            let did = format!(
                "{DID_DHT_PREFIX}z{}",
                zbase32::encode(identity_public.as_bytes())
            );

            // Step 5: Compute pre-rotation commitment: SHA-256(pre_rotation_public)
            let mut hasher = Sha256::new();
            hasher.update(pre_rotation_public_bytes);
            let commitment_bytes = hasher.finalize();
            let mut pre_rotation_commitment = [0u8; 32];
            pre_rotation_commitment.copy_from_slice(&commitment_bytes);

            // Step 6: Hand the pre-rotation private bytes to cold custody
            // (spec §9.7.4.1 §3 — separate substrate). The operational
            // copy is ephemeral: `pre_rotation_seed` is a `Zeroizing<[u8;
            // 32]>` and drops here.
            let pre_rotation_handle = pre_rotation_custody
                .store_committed_pre_rotation_key(&pre_rotation_public_bytes, pre_rotation_seed)
                .await
                .map_err(IdentityError::PreRotation)?;
            // The intermediate SigningKey carries its own copy of the
            // private bytes; drop it explicitly so it zeroizes before the
            // function returns.
            drop(pre_rotation_signing);

            // Step 7: Build the DID document. Verifiers see only the
            // commitment hash; the public key is never published until
            // migration, when `revealed_key` is filled by
            // `pre_rotation_custody.reveal_public_key`.
            let document = DidDocument::new(
                &did,
                identity_public.as_bytes(),
                active_public.as_bytes(),
                &pre_rotation_commitment,
            );

            // Step 8: Return the identity, document, and pre-rotation
            // handle. Callers persist all three so that `migrate_identity`
            // can present the handle back to the same `pre_rotation_custody`.
            let identity = ScpIdentity {
                identity_key,
                active_signing_key,
                agent_signing_key: None,
                pre_rotation_commitment,
                did,
            };

            Ok((identity, document, pre_rotation_handle))
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
    // Reconstruct the signed digest:
    //   SHA-256(DOMAIN_MIGRATION_V1 || len(old_did) || old_did || len(new_did) || new_did || rotated_at)
    // Length prefixes (u32 big-endian) prevent concatenation ambiguity between
    // variable-length DID strings.
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MIGRATION_V1);
    let old_len = u32::try_from(old_did.len())
        .map_err(|_| IdentityError::InvalidDidFormat("DID too long for length prefix".into()))?;
    let new_len = u32::try_from(new_did.len())
        .map_err(|_| IdentityError::InvalidDidFormat("DID too long for length prefix".into()))?;
    hasher.update(old_len.to_be_bytes());
    hasher.update(old_did.as_bytes());
    hasher.update(new_len.to_be_bytes());
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

/// Derives the `did:dht:z...` string from a raw Ed25519 public key.
///
/// Encodes the 32-byte public key as z-base-32 and prepends the `did:dht:z`
/// prefix per the did:dht method specification. This is the inverse of
/// [`extract_public_key`].
///
/// Used by bridge authentication (SCP-247) to verify that a claimed
/// `routing_id` corresponds to the DID derived from the provided public key.
#[must_use]
pub fn did_from_ed25519_public_key(public_key: &[u8; 32]) -> String {
    format!("{DID_DHT_PREFIX}z{}", zbase32::encode(public_key))
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        // Get the identity public key
        let identity_public = custody.public_key(&identity.identity_key).await.unwrap();

        // verify_did should return true for the matching key
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));
    }

    #[tokio::test]
    async fn verify_did_returns_false_for_mismatched_key() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        let svc = document.pre_rotation_service().unwrap();
        assert_eq!(svc.service_type, "PreRotationCommitment");
        assert!(svc.service_endpoint.starts_with("sha256:"));

        // The hex string after "sha256:" should be 64 chars (32 bytes)
        let hex_part = svc.service_endpoint.strip_prefix("sha256:").unwrap();
        assert_eq!(hex_part.len(), 64);
    }

    #[tokio::test]
    async fn create_identity_deterministic_with_seeded_custody() {
        let custody1 = InMemoryKeyCustody::from_seed_bytes([42u8; 32]);
        let custody2 = InMemoryKeyCustody::from_seed_bytes([42u8; 32]);
        let dht = DidDht::new();

        let pre_rotation_custody1 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let pre_rotation_custody2 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity1, doc1, _pre_rotation_handle1) = dht
            .create(&custody1, &*pre_rotation_custody1)
            .await
            .unwrap();
        let (identity2, doc2, _pre_rotation_handle2) = dht
            .create(&custody2, &*pre_rotation_custody2)
            .await
            .unwrap();

        // Same seed produces the same DID
        assert_eq!(identity1.did, identity2.did);
        assert_eq!(
            identity1.pre_rotation_commitment,
            identity2.pre_rotation_commitment
        );
        assert_eq!(doc1, doc2);
    }

    /// Prints the DID and verifying-key hex produced under the fixed
    /// parity seed ([0x7b; 32]). Used to regenerate the ground-truth
    /// values committed in `bindings/python/tests/bridge_parity/
    /// seed_operations.py` when the KDF algorithm is intentionally bumped.
    /// Run with: `cargo test -p scp-identity
    /// print_parity_seed_expected_values -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "diagnostic helper — run with --ignored --nocapture"]
    async fn print_parity_seed_expected_values() {
        let custody = InMemoryKeyCustody::from_seed_bytes([0x7bu8; 32]);
        let dht = DidDht::new();
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _doc, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();
        let pk = custody.public_key(&identity.identity_key).await.unwrap();
        println!("EXPECTED_SEEDED_DID = \"{}\"", identity.did);
        println!(
            "EXPECTED_SEEDED_VERIFYING_KEY_HEX = \"{}\"",
            hex::encode(pk.as_bytes())
        );
    }

    #[tokio::test]
    async fn create_identity_deterministic_with_32byte_seed() {
        // ADR-046 cross-bridge parity: a full 32-byte seed must produce the
        // same DID AND the same active verifying key across two custodies.
        // This is the invariant that bridges rely on when plumbing
        // `identity_create(seed: [u8; 32])` through to a seeded
        // `InMemoryKeyCustody`.
        let seed = [0x7Bu8; 32];
        let custody1 = InMemoryKeyCustody::from_seed_bytes(seed);
        let custody2 = InMemoryKeyCustody::from_seed_bytes(seed);
        let dht = DidDht::new();

        let pre_rotation_custody1 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let pre_rotation_custody2 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (id1, doc1, _pre_rotation_handle1) = dht
            .create(&custody1, &*pre_rotation_custody1)
            .await
            .unwrap();
        let (id2, doc2, _pre_rotation_handle2) = dht
            .create(&custody2, &*pre_rotation_custody2)
            .await
            .unwrap();

        assert_eq!(id1.did, id2.did);
        assert_eq!(id1.pre_rotation_commitment, id2.pre_rotation_commitment);
        assert_eq!(doc1, doc2);

        // Active signing key (the #active VM that scpid_sign uses) is also
        // byte-identical.
        let active1 = custody1.public_key(&id1.active_signing_key).await.unwrap();
        let active2 = custody2.public_key(&id2.active_signing_key).await.unwrap();
        assert_eq!(active1.as_bytes(), active2.as_bytes());
    }

    #[tokio::test]
    async fn document_json_roundtrip_from_create() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Don't publish. Resolve should return DhtNotFound.
        let result = dht.resolve_did(&identity.did).await;
        assert!(matches!(result, Err(IdentityError::DhtNotFound(_))));
    }

    #[tokio::test]
    async fn publish_without_signer_returns_error() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

    /// Helper that creates an identity with a fresh
    /// [`InMemoryPreRotationCustody`]. Returns the identity, document, the
    /// pre-rotation handle (so migration tests can present it back), and
    /// the pre-rotation custody (so migration tests can pass the same
    /// instance to `migrate_identity`).
    async fn create_identity_with_pre_rotation_key(
        custody: &InMemoryKeyCustody,
        dht: &DidDht<InMemoryDhtClient, Arc<TestClock>>,
    ) -> (
        ScpIdentity,
        DidDocument,
        PreRotationKeyHandle,
        Arc<scp_platform::testing::InMemoryPreRotationCustody>,
    ) {
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) =
            dht.create(custody, &*pre_rotation_custody).await.unwrap();
        let identity_public = custody.public_key(&identity.identity_key).await.unwrap();
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));
        (
            identity,
            document,
            pre_rotation_handle,
            pre_rotation_custody,
        )
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Layer 1: rotate_active_key
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_active_key_preserves_did_string() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let pre_rot_public_bytes = pre_rotation_custody
            .reveal_public_key(&pre_rotation_handle)
            .await
            .unwrap();
        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // The new DID must be self-certifying for the pre-rotation key.
        assert!(dht.verify(&new_identity.did, &pre_rot_public_bytes));
    }

    #[tokio::test]
    async fn migrate_identity_updates_old_document_with_also_known_as() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        // Snapshot the pre-rotation public BEFORE migrate, since
        // `migrate_identity` consumes the handle (§9.7.4.1 §6 destroys
        // the old pre-rotation key) — calling `reveal_public_key` after
        // would fail with `HandleNotFound`.
        let pre_rot_public_bytes = pre_rotation_custody
            .reveal_public_key(&pre_rotation_handle)
            .await
            .unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Pre-rotation proof should be present if the old document had a
        // PreRotationCommitment service.
        assert!(event.pre_rotation_proof.is_some());
        let pre_rot_proof = event.pre_rotation_proof.unwrap();

        assert_eq!(pre_rot_proof.revealed_key, pre_rot_public_bytes);
    }

    #[tokio::test]
    async fn migrate_identity_publishes_new_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, new_doc, _event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, _event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (new_identity, _new_doc, event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let (_new_identity, _new_doc, event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

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
    // SCP-AB-009 tests — Agent key DHT wiring (ADR-039)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_with_agent_key_produces_four_verification_methods() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();

        // DID format is valid.
        assert!(identity.did.starts_with("did:dht:z"));
        assert_eq!(document.id, identity.did);

        // Should have three verification methods: #0, #active, #agent.
        assert_eq!(document.verification_method.len(), 3);
        assert!(document.verification_method_by_fragment("0").is_some());
        assert!(document.verification_method_by_fragment("active").is_some());
        assert!(document.verification_method_by_fragment("agent").is_some());

        // agent_signing_key should be set.
        assert!(identity.agent_signing_key.is_some());

        // authentication and assertionMethod should reference both #active and #agent.
        assert_eq!(document.authentication.len(), 2);
        assert!(
            document
                .authentication
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            document
                .authentication
                .iter()
                .any(|r| r.ends_with("#agent"))
        );
        assert_eq!(document.assertion_method.len(), 2);
        assert!(
            document
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            document
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#agent"))
        );
    }

    #[tokio::test]
    async fn create_without_agent_key_backward_compat() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Should have two verification methods: #0 and #active.
        assert_eq!(document.verification_method.len(), 2);
        assert!(!document.has_agent_key());

        // agent_signing_key should be None.
        assert!(identity.agent_signing_key.is_none());

        // authentication and assertionMethod should reference only #active.
        assert_eq!(document.authentication.len(), 1);
        assert_eq!(document.assertion_method.len(), 1);
    }

    #[tokio::test]
    async fn create_with_agent_key_self_certifies() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();

        // Self-certification: identity key in document matches DID string.
        let identity_public = custody.public_key(&identity.identity_key).await.unwrap();
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));

        // verify_self_certification should succeed.
        verify_self_certification(&identity.did, &document).unwrap();
    }

    #[tokio::test]
    async fn create_with_agent_key_publish_and_resolve_roundtrip() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Resolve and verify the agent key survives the roundtrip.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(resolved.document, document);
        assert!(resolved.document.has_agent_key());
        assert_eq!(resolved.document.verification_method.len(), 3);
    }

    #[tokio::test]
    async fn add_agent_key_to_existing_identity() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Create identity without agent key.
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();
        assert!(!document.has_agent_key());
        assert!(identity.agent_signing_key.is_none());

        // Add agent key.
        let (updated_identity, updated_doc) = dht
            .add_agent_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Identity should now have an agent key.
        assert!(updated_identity.agent_signing_key.is_some());
        assert!(updated_doc.has_agent_key());

        // DID and identity key preserved.
        assert_eq!(updated_identity.did, identity.did);
        assert_eq!(updated_identity.identity_key, identity.identity_key);
        assert_eq!(
            updated_identity.active_signing_key,
            identity.active_signing_key
        );

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.has_agent_key());
        assert_eq!(resolved.document.verification_method.len(), 3);
    }

    #[tokio::test]
    async fn add_agent_key_fails_if_already_exists() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Trying to add again should fail.
        let result = dht.add_agent_key(&identity, &document, &*custody).await;
        assert!(matches!(result, Err(IdentityError::AgentKeyAlreadyExists)));
    }

    #[tokio::test]
    async fn rotate_agent_key_produces_new_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let old_agent_key = identity.agent_signing_key.unwrap();
        let old_agent_public = custody.public_key(&old_agent_key).await.unwrap();

        // Rotate the agent key.
        let (rotated_identity, rotated_doc) = dht
            .rotate_agent_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // New agent key should be different.
        let new_agent_key = rotated_identity.agent_signing_key.unwrap();
        let new_agent_public = custody.public_key(&new_agent_key).await.unwrap();
        assert_ne!(old_agent_public.as_bytes(), new_agent_public.as_bytes());

        // Document should have #agent with new key.
        assert!(rotated_doc.has_agent_key());
        let agent_vm = rotated_doc
            .verification_method_by_fragment("agent")
            .unwrap();
        assert!(agent_vm.id.ends_with("#agent"));

        // Should have a retired agent key.
        assert!(rotated_doc.retired_agent_key_count() >= 1);

        // DID, identity key, active key preserved.
        assert_eq!(rotated_identity.did, identity.did);
        assert_eq!(rotated_identity.identity_key, identity.identity_key);
        assert_eq!(
            rotated_identity.active_signing_key,
            identity.active_signing_key
        );

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.has_agent_key());
    }

    #[tokio::test]
    async fn rotate_agent_key_fails_without_existing_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let result = dht.rotate_agent_key(&identity, &document, &*custody).await;
        assert!(matches!(result, Err(IdentityError::AgentKeyNotFound)));
    }

    #[tokio::test]
    async fn remove_agent_key_clears_identity_and_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();
        assert!(document.has_agent_key());

        // Remove the agent key.
        let (updated_identity, updated_doc) =
            dht.remove_agent_key(&identity, &document).await.unwrap();

        // Agent key should be gone from identity and document.
        assert!(updated_identity.agent_signing_key.is_none());
        assert!(!updated_doc.has_agent_key());

        // DID, identity key, active key preserved.
        assert_eq!(updated_identity.did, identity.did);
        assert_eq!(updated_identity.identity_key, identity.identity_key);
        assert_eq!(
            updated_identity.active_signing_key,
            identity.active_signing_key
        );

        // authentication and assertionMethod should only reference #active.
        assert_eq!(updated_doc.authentication.len(), 1);
        assert!(updated_doc.authentication[0].ends_with("#active"));
        assert_eq!(updated_doc.assertion_method.len(), 1);
        assert!(updated_doc.assertion_method[0].ends_with("#active"));

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(!resolved.document.has_agent_key());
        assert_eq!(resolved.document.verification_method.len(), 2);
    }

    #[tokio::test]
    async fn remove_agent_key_fails_without_existing_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let result = dht.remove_agent_key(&identity, &document).await;
        assert!(matches!(result, Err(IdentityError::AgentKeyNotFound)));
    }

    #[tokio::test]
    async fn rotate_active_key_preserves_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Create identity with agent key.
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let agent_key = identity.agent_signing_key.unwrap();
        let agent_public = custody.public_key(&agent_key).await.unwrap();

        // Rotate the active key.
        let (rotated_identity, rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Agent key should be preserved in the identity.
        assert_eq!(rotated_identity.agent_signing_key, Some(agent_key));

        // Document should still have #agent.
        assert!(rotated_doc.has_agent_key());
        let agent_vm = rotated_doc
            .verification_method_by_fragment("agent")
            .unwrap();
        let doc_agent_bytes = super::decode_multibase_key(&agent_vm.public_key_multibase).unwrap();
        assert_eq!(
            doc_agent_bytes,
            <[u8; 32]>::try_from(agent_public.as_bytes()).unwrap()
        );

        // authentication and assertionMethod should reference both #active and #agent.
        assert_eq!(rotated_doc.authentication.len(), 2);
        assert!(
            rotated_doc
                .authentication
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            rotated_doc
                .authentication
                .iter()
                .any(|r| r.ends_with("#agent"))
        );
        assert_eq!(rotated_doc.assertion_method.len(), 2);
        assert!(
            rotated_doc
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            rotated_doc
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#agent"))
        );

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.has_agent_key());
    }

    #[tokio::test]
    async fn verify_self_certification_works_with_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Self-certification only checks #0 (identity key), so it should work
        // regardless of how many VMs exist.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        verify_self_certification(&identity.did, &resolved.document).unwrap();
    }

    #[tokio::test]
    async fn migrate_identity_drops_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Create identity with agent key via the production constructor.
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();

        dht.publish_document(&identity, &document).await.unwrap();

        // Migrate the identity.
        let rotated_at = 1_700_000_000u64;
        let (new_identity, new_doc, _event, _new_pre_rotation_handle) = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Migration creates a new identity -- agent key is NOT carried forward.
        // The agent relationship must be re-established with add_agent_key.
        assert!(new_identity.agent_signing_key.is_none());
        assert!(!new_doc.has_agent_key());
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

    // -----------------------------------------------------------------------
    // BEP44 sequence persistence tests (issue #327)
    // -----------------------------------------------------------------------

    /// Helper to create a `DidDht` with a shared DHT client, custody, and
    /// sequence store — simulating restart by creating a new `DidDht` that
    /// shares the same store and DHT.
    fn make_dht_with_store(
        custody: &Arc<InMemoryKeyCustody>,
        dht_client: Arc<InMemoryDhtClient>,
        store: Arc<InMemorySequenceStore>,
    ) -> DidDht<InMemoryDhtClient, Arc<TestClock>> {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_signer_and_store(dht_client, cache, sign_fn, store)
    }

    #[tokio::test]
    async fn publish_persists_sequence_to_store() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish increments and persists.
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 1);

        let stored = store.load(&identity.did).await.unwrap();
        assert_eq!(stored, Some(1));

        // Second publish persists 2.
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 2);

        let stored = store.load(&identity.did).await.unwrap();
        assert_eq!(stored, Some(2));
    }

    #[tokio::test]
    async fn initialize_sequence_from_store() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish 3 times to get sequence to 3.
        for _ in 0..3 {
            dht.publish_document(&identity, &document).await.unwrap();
        }
        assert_eq!(dht.current_sequence(), 3);
        assert_eq!(store.load(&identity.did).await.unwrap(), Some(3));

        // Simulate restart: create a new DidDht with same store and DHT.
        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        assert_eq!(dht2.current_sequence(), 0); // Not yet initialized.

        dht2.initialize_sequence(&identity.did).await.unwrap();
        assert_eq!(dht2.current_sequence(), 3); // Loaded from store.

        // Next publish must be > 3.
        dht2.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht2.current_sequence(), 4);
        assert_eq!(store.load(&identity.did).await.unwrap(), Some(4));
    }

    #[tokio::test]
    async fn initialize_sequence_from_dht_when_no_store() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());

        // First instance: publish with a store.
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        for _ in 0..5 {
            dht.publish_document(&identity, &document).await.unwrap();
        }
        assert_eq!(dht.current_sequence(), 5);

        // Second instance: fresh store (simulating lost storage), but same DHT.
        let fresh_store = Arc::new(InMemorySequenceStore::new());
        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), fresh_store);

        dht2.initialize_sequence(&identity.did).await.unwrap();
        // Should have recovered seq 5 from the DHT record.
        assert_eq!(dht2.current_sequence(), 5);

        // Next publish must be > 5.
        dht2.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht2.current_sequence(), 6);
    }

    #[tokio::test]
    async fn initialize_sequence_uses_max_of_store_and_dht() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());

        // First instance: publish to get DHT seq to 3.
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        for _ in 0..3 {
            dht.publish_document(&identity, &document).await.unwrap();
        }

        // Manually set the store to a higher value (simulating store ahead of DHT).
        store.store(&identity.did, 10).await.unwrap();

        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        dht2.initialize_sequence(&identity.did).await.unwrap();
        // max(10, 3) = 10
        assert_eq!(dht2.current_sequence(), 10);

        // Next publish: 11.
        dht2.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht2.current_sequence(), 11);
    }

    #[tokio::test]
    async fn publish_restart_publish_produces_higher_sequence() {
        // This is the exact acceptance criterion test:
        // "publish -> restart -> publish again -> second publication has higher sequence"
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());

        // First session: create and publish.
        let dht1 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht1
            .create(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht1.publish_document(&identity, &document).await.unwrap();
        let seq_before_restart = dht1.current_sequence();
        assert_eq!(seq_before_restart, 1);

        // Simulate restart: new DidDht, same store + DHT.
        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        dht2.initialize_sequence(&identity.did).await.unwrap();

        // Second session: publish again.
        dht2.publish_document(&identity, &document).await.unwrap();
        let seq_after_restart = dht2.current_sequence();

        // The second publication MUST have a strictly higher sequence.
        assert!(
            seq_after_restart > seq_before_restart,
            "sequence after restart ({seq_after_restart}) must be > sequence before restart ({seq_before_restart})"
        );
        assert_eq!(seq_after_restart, 2);
    }

    #[tokio::test]
    async fn no_store_works_without_persistence() {
        // Backward compatibility: DidDht without a store still works.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 1);
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 2);
    }

    #[tokio::test]
    async fn initialize_sequence_no_store_no_dht_record() {
        // New identity, no store, no DHT record: sequence stays at 0.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.initialize_sequence(&identity.did).await.unwrap();
        assert_eq!(dht.current_sequence(), 0);
    }

    // -----------------------------------------------------------------------
    // Device attestation integration tests (issue #362)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn attach_device_attestation_adds_service_entry() {
        use scp_platform::testing::InMemoryDeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Before attaching: no device attestation service entry.
        assert!(!document.has_device_attestation());
        assert!(document.device_attestation_token().unwrap().is_none());

        // Attach device attestation.
        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // After attaching: device attestation service entry present.
        assert!(updated_doc.has_device_attestation());
        let token = updated_doc.device_attestation_token().unwrap().unwrap();
        assert!(
            token.starts_with(b"scp-test-attestation-v1:"),
            "token should have synthetic prefix"
        );
    }

    #[tokio::test]
    async fn device_attestation_roundtrip_verify() {
        use scp_platform::testing::InMemoryDeviceAttestation;
        use scp_platform::traits::DeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Attach device attestation.
        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Extract token from service entry and verify it.
        let token_bytes = updated_doc.device_attestation_token().unwrap().unwrap();
        let token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
        let verified = attestation.verify(&token).await.unwrap();
        assert!(verified, "roundtrip token should verify successfully");
    }

    #[tokio::test]
    async fn device_attestation_tampered_token_does_not_verify() {
        use scp_platform::testing::InMemoryDeviceAttestation;
        use scp_platform::traits::DeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Attach device attestation.
        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Extract and tamper with the token.
        let mut token_bytes = updated_doc.device_attestation_token().unwrap().unwrap();
        assert!(!token_bytes.is_empty());
        // Bitflip the first byte (in the prefix) so the synthetic prefix check
        // fails. The InMemoryDeviceAttestation verifier checks the prefix, so
        // corrupting a prefix byte produces a verifiable false result.
        token_bytes[0] ^= 0xFF;

        let tampered_token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
        let result = attestation.verify(&tampered_token).await;
        // Should return Ok(false) or an error -- never panic.
        if let Ok(verified) = result {
            assert!(!verified, "tampered token should not verify");
        } // Err is acceptable — tampered token may fail to parse
    }

    #[tokio::test]
    async fn create_without_device_attestation_has_no_service_entry() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // No device attestation service entry when not explicitly attached.
        assert!(!document.has_device_attestation());
        assert!(document.device_attestation_token().unwrap().is_none());
    }

    #[tokio::test]
    async fn device_attestation_service_entry_format() {
        use base64::Engine;
        use scp_platform::testing::InMemoryDeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Find the service entry and verify format.
        let service = updated_doc
            .service
            .iter()
            .find(|s| s.service_type == "ScpDeviceAttestation")
            .expect("ScpDeviceAttestation service entry should exist");

        assert_eq!(
            service.id,
            format!("{}#device-attestation", identity.did),
            "service ID should use {{did}}#device-attestation format"
        );
        assert_eq!(service.service_type, "ScpDeviceAttestation");
        // Endpoint should be valid base64.
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(&service.service_endpoint)
                .is_ok(),
            "service endpoint should be valid base64"
        );
    }

    #[tokio::test]
    async fn device_attestation_json_roundtrip() {
        use scp_platform::testing::InMemoryDeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Serialize to JSON and back.
        let json = updated_doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        assert!(parsed.has_device_attestation());
        let original_token = updated_doc.device_attestation_token().unwrap().unwrap();
        let parsed_token = parsed.device_attestation_token().unwrap().unwrap();
        assert_eq!(original_token, parsed_token);
    }

    // -----------------------------------------------------------------------
    // Convenience constructor tests (issue #530)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn with_in_memory_custody_creates_signing_capable_instance() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = DidDht::with_in_memory_custody(Arc::clone(&custody));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, doc, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // DID is valid.
        assert!(identity.did.starts_with("did:dht:z"));
        assert_eq!(doc.id, identity.did);

        // Publish works (signing is wired up).
        dht.publish(&identity, &doc).await.unwrap();

        // Resolve returns the published document.
        let resolved = dht.resolve(&identity.did).await.unwrap();
        assert_eq!(resolved.id, identity.did);
    }

    #[tokio::test]
    async fn create_in_memory_returns_all_components() {
        let (identity, document, custody, did_dht) = DidDht::create_in_memory().await.unwrap();

        // Identity is valid.
        assert!(identity.did.starts_with("did:dht:z"));
        assert_eq!(document.id, identity.did);

        // Custody is functional — can sign with identity keys.
        let sig = custody
            .sign(&identity.active_signing_key, b"test")
            .await
            .unwrap();
        assert_eq!(sig.as_bytes().len(), 64);

        // DidDht is functional — publish and resolve work.
        did_dht.publish(&identity, &document).await.unwrap();
        let resolved = did_dht.resolve(&identity.did).await.unwrap();
        assert_eq!(resolved.id, identity.did);
    }

    #[tokio::test]
    async fn create_in_memory_produces_unique_identities() {
        let (id1, _, _, _) = DidDht::create_in_memory().await.unwrap();
        let (id2, _, _, _) = DidDht::create_in_memory().await.unwrap();
        assert_ne!(id1.did, id2.did, "each call must produce a unique DID");
    }
}
