//! DID routing ID derivation and relay-based resolution (§3.10.2, §3.10.4).
//!
//! Derives deterministic routing IDs for publishing and resolving DID documents
//! on SCP relays. The routing ID is computed as `SHA-256("scp:did:" || did_string)`.
//! The `"scp:did:"` domain separator prevents collision with other routing ID
//! derivation schemes: encrypted context routing IDs (HKDF, §9.10.4), broadcast
//! context routing IDs (`SHA-256(context_id)`, §5.14), and context metadata
//! routing IDs (`HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")`, §9.10.4.B).
//!
//! # Relay-Based Resolution (SCP-240)
//!
//! Implements the relay layer of the dual-layer resolution protocol (§3.10.4):
//!
//! 1. Compute `did_routing_id = SHA-256("scp:did:" || did_string)`.
//! 2. Extract `public_key` from the DID string (z-base-32 decode).
//! 3. QUERY relay with `routing_id`, `limit: 1`.
//! 4. Parse response as a BEP44-signed DID document.
//! 5. Verify BEP44 signature against `public_key`.
//! 6. Verify `seq >= last_known_seq`.
//! 7. Cache the result (24h active, 7d inactive via [`DidCache`]).
//!
//! The [`RelayQuerier`] trait abstracts relay QUERY operations so that
//! `scp-core` does not depend on `scp-transport`. Production implementations
//! live in `scp-transport`; tests use [`InMemoryRelayQuerier`].

use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::cache::DidCache;
use crate::dht::{extract_public_key, verify_bep44_signature, verify_self_certification};
use crate::document::DidDocument;
use crate::{IdentityError, cache::Clock};

/// Domain separator for DID routing IDs.
///
/// Prevents collision with context routing IDs (HKDF from identity key material,
/// §9.10.4), broadcast routing IDs (`SHA-256(context_id)`, §5.14), and context
/// metadata routing IDs (`HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")`, §9.10.4.B).
const DID_ROUTING_DOMAIN_SEPARATOR: &[u8] = b"scp:did:";

/// Derives the relay routing ID for a DID string.
///
/// Computes `SHA-256("scp:did:" || did_string)` per §3.10.2. This routing ID
/// is used for PUBLISH and QUERY operations on SCP relays to store and retrieve
/// DID documents.
///
/// # Arguments
/// * `did` — The DID string (e.g., `"did:dht:z6Mk..."`)
///
/// # Returns
/// 32-byte SHA-256 hash used as the routing ID.
#[must_use]
pub fn did_routing_id(did: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DID_ROUTING_DOMAIN_SEPARATOR);
    hasher.update(did.as_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Relay-based DID resolution (§3.10.2, SCP-240)
// ---------------------------------------------------------------------------

/// A BEP44-signed blob returned by a relay QUERY operation.
///
/// This is the relay equivalent of [`DhtRecord`](super::dht_client::DhtRecord).
/// The blob contains the JSON-serialized DID document, a BEP44 Ed25519
/// signature, and a monotonically increasing sequence number.
#[derive(Debug, Clone)]
pub struct RelayQueryRecord {
    /// The serialized DID document bytes (JSON).
    pub value: Vec<u8>,
    /// The 64-byte Ed25519 signature over the BEP44 payload.
    pub signature: [u8; 64],
    /// The BEP44 sequence number.
    ///
    /// Deliberately `u64` despite BEP44's signed integer wire format. SCP never
    /// publishes negative sequence numbers; the bencode encoder/decoder handles
    /// `u64` ↔ `i64` transparently for values up to `i64::MAX`.
    pub seq: u64,
}

/// Abstraction over relay QUERY operations for DID document resolution.
///
/// Production implementations (in `scp-transport`) send QUERY messages to SCP
/// relays. Tests use [`InMemoryRelayQuerier`] backed by a `HashMap`.
///
/// This trait is defined in `scp-core` so that the resolution logic does not
/// depend on `scp-transport` (§3.10.12 phase integration).
pub trait RelayQuerier: Send + Sync {
    /// Queries a relay for a blob with the given routing ID.
    ///
    /// Sends `QUERY { routing_id, since: null, limit: 1 }` to the relay.
    ///
    /// # Arguments
    ///
    /// * `relay_url` — The relay endpoint URL.
    /// * `routing_id` — The 32-byte routing ID to query.
    ///
    /// # Returns
    ///
    /// `Ok(Some(record))` if the relay has a matching blob.
    /// `Ok(None)` if the relay has no matching blob.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::RelayQueryFailed`] if the query fails.
    fn query(
        &self,
        relay_url: &str,
        routing_id: &[u8; 32],
    ) -> impl Future<Output = Result<Option<RelayQueryRecord>, IdentityError>> + Send;
}

/// Result of a successful relay-based DID resolution.
#[derive(Debug, Clone)]
pub struct RelayResolveResult {
    /// The verified DID document.
    pub document: DidDocument,
    /// The BEP44 sequence number.
    pub seq: u64,
    /// The relay URL that served this document.
    pub relay_url: String,
}

/// Resolves a DID document from SCP relays (§3.10.2, §3.10.4 step 3a).
///
/// Queries the provided relay URLs in order (known relays first, then bootstrap
/// relays per §3.10.4). Returns the first valid response.
///
/// # Resolution steps
///
/// 1. Compute `did_routing_id`.
/// 2. Extract `public_key` from DID string (z-base-32 decode).
/// 3. For each relay URL, send QUERY and on response:
///    a. Verify BEP44 signature against `public_key`.
///    b. Check `seq >= last_known_seq` from cache.
///    c. Deserialize the DID document.
///    d. Cache the result.
/// 4. Return the first valid result, or `Ok(None)` if no relay has a valid doc.
///
/// # Arguments
///
/// * `did_string` — The DID to resolve (e.g., `"did:dht:z6Mk..."`).
/// * `relay_urls` — Relay URLs to query, in priority order (identity's known
///   relays first, then bootstrap relays).
/// * `querier` — The relay QUERY implementation.
/// * `cache` — The DID resolution cache (for seq checking and result caching).
///
/// # Errors
///
/// Returns `Err` for DID format errors. Relay failures for individual relays
/// are logged and skipped; the function returns `Ok(None)` only when all relays
/// fail or return no result.
pub async fn relay_resolve<Q: RelayQuerier, C: Clock>(
    did_string: &str,
    relay_urls: &[&str],
    querier: &Q,
    cache: &DidCache<C>,
) -> Result<Option<RelayResolveResult>, IdentityError> {
    // Step 1: Compute routing ID.
    let routing_id = did_routing_id(did_string);

    // Step 2: Extract public key from DID string.
    let public_key = extract_public_key(did_string)?;

    // Get last known sequence number from cache for freshness check.
    let last_known_seq = cache.cached_sequence(did_string).await.unwrap_or(0);

    // Step 3: Query relays in order, return first valid response.
    for relay_url in relay_urls {
        let record = match querier.query(relay_url, &routing_id).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                debug!(relay_url, did = did_string, "relay has no matching blob");
                continue;
            }
            Err(e) => {
                warn!(relay_url, did = did_string, error = %e, "relay query failed");
                continue;
            }
        };

        // Step 3a: Verify BEP44 signature.
        if let Err(e) =
            verify_bep44_signature(&public_key, &record.signature, &record.value, record.seq)
        {
            warn!(relay_url, did = did_string, error = %e, "BEP44 signature verification failed");
            continue;
        }

        // Step 3b: Check sequence number freshness.
        if record.seq < last_known_seq {
            debug!(
                relay_url,
                did = did_string,
                record_seq = record.seq,
                last_known_seq,
                "stale document (seq < last known)"
            );
            continue;
        }

        // Step 3c: Deserialize the DID document.
        let Ok(doc_json) = String::from_utf8(record.value) else {
            warn!(relay_url, did = did_string, "relay returned non-UTF8 blob");
            continue;
        };
        let Ok(document) = DidDocument::from_json(&doc_json) else {
            warn!(
                relay_url,
                did = did_string,
                "relay returned invalid DID document JSON"
            );
            continue;
        };

        // Step 3c.1: Verify self-certification — identity key must match DID suffix.
        if let Err(e) = verify_self_certification(did_string, &document) {
            warn!(relay_url, did = did_string, error = %e, "self-certification failed");
            continue;
        }

        // Step 3d: Cache the result.
        cache.insert(did_string, document.clone(), record.seq).await;

        return Ok(Some(RelayResolveResult {
            document,
            seq: record.seq,
            relay_url: (*relay_url).to_owned(),
        }));
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// In-memory test implementation
// ---------------------------------------------------------------------------

/// In-memory relay querier for testing.
///
/// Stores blobs in a `HashMap` keyed by routing ID. Supports configuring
/// per-relay responses for testing relay selection priority.
#[derive(Debug, Default)]
pub struct InMemoryRelayQuerier {
    /// Map from (`relay_url`, `routing_id`) to stored record.
    items: tokio::sync::Mutex<std::collections::HashMap<(String, [u8; 32]), RelayQueryRecord>>,
}

impl InMemoryRelayQuerier {
    /// Creates a new empty in-memory relay querier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Stores a record for a specific relay and routing ID.
    pub async fn insert(&self, relay_url: &str, routing_id: &[u8; 32], record: RelayQueryRecord) {
        let mut items = self.items.lock().await;
        items.insert((relay_url.to_owned(), *routing_id), record);
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl RelayQuerier for InMemoryRelayQuerier {
    fn query(
        &self,
        relay_url: &str,
        routing_id: &[u8; 32],
    ) -> impl Future<Output = Result<Option<RelayQueryRecord>, IdentityError>> + Send {
        async move {
            let record = self
                .items
                .lock()
                .await
                .get(&(relay_url.to_owned(), *routing_id))
                .cloned();
            Ok(record)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use sha2::{Digest, Sha256};

    use super::DID_ROUTING_DOMAIN_SEPARATOR;
    use crate::cache::TestClock;
    use crate::dht::bep44_signable;
    use crate::document::DidDocument;
    use crate::*;

    /// Helper: create an Ed25519 signing keypair and return (`public_key`, `signing_key`).
    fn make_ed25519_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    /// Helper: build a DID string from an Ed25519 public key.
    fn did_from_public_key(public_key: &ed25519_dalek::VerifyingKey) -> String {
        format!("did:dht:z{}", zbase32::encode(public_key.as_bytes()))
    }

    /// Helper: create a BEP44-signed DID document blob for testing.
    fn make_signed_blob(
        did: &str,
        public_key: &[u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        seq: u64,
    ) -> RelayQueryRecord {
        let active_key = [2u8; 32];
        let pre_rotation_key = [3u8; 32];
        let doc = DidDocument::new(did, public_key, &active_key, &pre_rotation_key);
        let value = serde_json::to_vec(&doc).unwrap();

        let payload = bep44_signable(&value, seq);
        let signature: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(signing_key, &payload);

        RelayQueryRecord {
            value,
            signature: signature.to_bytes(),
            seq,
        }
    }

    // ---- Routing ID tests (preserved from original) ----

    /// Golden test vector: `SHA-256("scp:did:" || did_string)`.
    ///
    /// Computed with:
    /// ```python
    /// import hashlib
    /// hashlib.sha256(b"scp:did:did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").hexdigest()
    /// # => "adb80e64a591a04b2ebd6b8dcb71d8df2b55381092f62396db811ed5e25ff71b"
    /// ```
    #[test]
    fn golden_test_vector() {
        let did = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let expected: [u8; 32] = [
            0xad, 0xb8, 0x0e, 0x64, 0xa5, 0x91, 0xa0, 0x4b, 0x2e, 0xbd, 0x6b, 0x8d, 0xcb, 0x71,
            0xd8, 0xdf, 0x2b, 0x55, 0x38, 0x10, 0x92, 0xf6, 0x23, 0x96, 0xdb, 0x81, 0x1e, 0xd5,
            0xe2, 0x5f, 0xf7, 0x1b,
        ];
        assert_eq!(did_routing_id(did), expected);
    }

    /// Same input always produces the same output (determinism).
    #[test]
    fn deterministic_output() {
        let did = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let first = did_routing_id(did);
        let second = did_routing_id(did);
        assert_eq!(first, second);
    }

    /// Different DID strings produce different routing IDs.
    #[test]
    fn different_inputs_differ() {
        let id_a = did_routing_id("did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let id_b = did_routing_id("did:dht:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp7eTafHQ7jQxm");
        assert_ne!(id_a, id_b);
    }

    /// DID routing ID must not collide with broadcast routing ID derivation.
    ///
    /// Broadcast routing IDs use `SHA-256(context_id)` without a domain separator
    /// (§5.14). The "scp:did:" prefix ensures a DID routing ID for any string S
    /// never equals `SHA-256(S)`.
    #[test]
    fn no_collision_with_broadcast_routing_id() {
        let input = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        // DID routing ID: SHA-256("scp:did:" || input)
        let did_rid = did_routing_id(input);

        // Broadcast routing ID: SHA-256(input) — no domain separator
        let broadcast_rid: [u8; 32] = Sha256::digest(input.as_bytes()).into();

        assert_ne!(did_rid, broadcast_rid);
    }

    /// Verify the domain separator constant is exactly "scp:did:".
    #[test]
    fn domain_separator_value() {
        assert_eq!(DID_ROUTING_DOMAIN_SEPARATOR, b"scp:did:");
    }

    // ---- Relay resolution tests (SCP-240) ----

    /// Valid BEP44-signed document is accepted and cached.
    #[tokio::test]
    async fn relay_resolve_valid_document_accepted_and_cached() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        let blob = make_signed_blob(&did, verifying_key.as_bytes(), &signing_key, 1);

        let querier = InMemoryRelayQuerier::new();
        querier
            .insert("wss://relay1.example.com/scp/v1", &routing_id, blob)
            .await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));

        let result = relay_resolve(&did, &["wss://relay1.example.com/scp/v1"], &querier, &cache)
            .await
            .unwrap();

        assert!(result.is_some());
        let resolved = result.unwrap();
        assert_eq!(resolved.seq, 1);
        assert_eq!(resolved.relay_url, "wss://relay1.example.com/scp/v1");

        // Verify the document was cached.
        let cached = cache.get(&did).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().sequence, 1);
    }

    /// Document with invalid BEP44 signature is rejected.
    #[tokio::test]
    async fn relay_resolve_invalid_signature_rejected() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        let mut blob = make_signed_blob(&did, verifying_key.as_bytes(), &signing_key, 1);
        // Corrupt the signature.
        blob.signature[0] ^= 0xFF;

        let querier = InMemoryRelayQuerier::new();
        querier
            .insert("wss://relay1.example.com/scp/v1", &routing_id, blob)
            .await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        let result = relay_resolve(&did, &["wss://relay1.example.com/scp/v1"], &querier, &cache)
            .await
            .unwrap();

        // Invalid signature: no valid result returned.
        assert!(result.is_none());

        // Nothing should be cached.
        assert!(cache.get(&did).await.is_none());
    }

    /// Document with lower sequence number than cached is rejected.
    #[tokio::test]
    async fn relay_resolve_stale_sequence_rejected() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));

        // Pre-populate cache with seq=5.
        let active_key = [2u8; 32];
        let pre_rotation_key = [3u8; 32];
        let cached_doc = DidDocument::new(
            &did,
            verifying_key.as_bytes(),
            &active_key,
            &pre_rotation_key,
        );
        cache.insert(&did, cached_doc, 5).await;

        // Relay returns document with seq=3 (stale).
        let blob = make_signed_blob(&did, verifying_key.as_bytes(), &signing_key, 3);

        let querier = InMemoryRelayQuerier::new();
        querier
            .insert("wss://relay1.example.com/scp/v1", &routing_id, blob)
            .await;

        let result = relay_resolve(&did, &["wss://relay1.example.com/scp/v1"], &querier, &cache)
            .await
            .unwrap();

        // Stale sequence: rejected.
        assert!(result.is_none());

        // Cache still has seq=5, not overwritten.
        let cached = cache.cached_sequence(&did).await;
        assert_eq!(cached, Some(5));
    }

    /// Queries known relays first, then bootstrap relays.
    #[tokio::test]
    async fn relay_resolve_queries_in_priority_order() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        // Only the second relay (bootstrap) has the document.
        let blob = make_signed_blob(&did, verifying_key.as_bytes(), &signing_key, 1);

        let querier = InMemoryRelayQuerier::new();
        // First relay (known) has nothing.
        // Second relay (bootstrap) has the document.
        querier
            .insert("wss://bootstrap.example.com/scp/v1", &routing_id, blob)
            .await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        let result = relay_resolve(
            &did,
            &[
                "wss://known-relay.example.com/scp/v1",
                "wss://bootstrap.example.com/scp/v1",
            ],
            &querier,
            &cache,
        )
        .await
        .unwrap();

        assert!(result.is_some());
        let resolved = result.unwrap();
        assert_eq!(resolved.relay_url, "wss://bootstrap.example.com/scp/v1");
    }

    /// Returns `None` when no relays have the document.
    #[tokio::test]
    async fn relay_resolve_returns_none_when_no_relays_respond() {
        let (verifying_key, _signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);

        let querier = InMemoryRelayQuerier::new();
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        let result = relay_resolve(&did, &["wss://relay1.example.com/scp/v1"], &querier, &cache)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    /// Relay returns malformed (non-UTF8) value — skipped gracefully.
    #[tokio::test]
    async fn relay_resolve_skips_non_utf8_blob() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        // Create a blob with invalid UTF-8 but valid signature.
        let bad_value = vec![0xFF, 0xFE, 0xFD];
        let payload = bep44_signable(&bad_value, 1);
        let signature: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(&signing_key, &payload);

        let blob = RelayQueryRecord {
            value: bad_value,
            signature: signature.to_bytes(),
            seq: 1,
        };

        let querier = InMemoryRelayQuerier::new();
        querier
            .insert("wss://relay1.example.com/scp/v1", &routing_id, blob)
            .await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        let result = relay_resolve(&did, &["wss://relay1.example.com/scp/v1"], &querier, &cache)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    /// Document with equal sequence number to cached is accepted (spec says >=).
    #[tokio::test]
    async fn relay_resolve_equal_sequence_accepted() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));

        // Pre-populate cache with seq=3.
        let active_key = [2u8; 32];
        let pre_rotation_key = [3u8; 32];
        let cached_doc = DidDocument::new(
            &did,
            verifying_key.as_bytes(),
            &active_key,
            &pre_rotation_key,
        );
        cache.insert(&did, cached_doc, 3).await;

        // Relay returns document with seq=3 (equal — accepted per §3.10.7).
        let blob = make_signed_blob(&did, verifying_key.as_bytes(), &signing_key, 3);

        let querier = InMemoryRelayQuerier::new();
        querier
            .insert("wss://relay1.example.com/scp/v1", &routing_id, blob)
            .await;

        // Advance clock so the cache insert takes effect (DidCache rejects same seq
        // unless time advances).
        clock.advance(1);

        let result = relay_resolve(&did, &["wss://relay1.example.com/scp/v1"], &querier, &cache)
            .await
            .unwrap();

        // Equal sequence is >= last_known, so accepted.
        assert!(result.is_some());
        assert_eq!(result.unwrap().seq, 3);
    }

    /// First relay has invalid doc, second has valid — second is returned.
    #[tokio::test]
    async fn relay_resolve_falls_through_on_invalid_to_valid() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        // First relay: corrupted signature.
        let mut bad_blob = make_signed_blob(&did, verifying_key.as_bytes(), &signing_key, 1);
        bad_blob.signature[0] ^= 0xFF;

        // Second relay: valid blob.
        let good_blob = make_signed_blob(&did, verifying_key.as_bytes(), &signing_key, 1);

        let querier = InMemoryRelayQuerier::new();
        querier
            .insert("wss://relay1.example.com/scp/v1", &routing_id, bad_blob)
            .await;
        querier
            .insert("wss://relay2.example.com/scp/v1", &routing_id, good_blob)
            .await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        let result = relay_resolve(
            &did,
            &[
                "wss://relay1.example.com/scp/v1",
                "wss://relay2.example.com/scp/v1",
            ],
            &querier,
            &cache,
        )
        .await
        .unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().relay_url, "wss://relay2.example.com/scp/v1");
    }

    /// Document with mismatched identity key is rejected (self-certification).
    #[tokio::test]
    async fn relay_resolve_rejects_wrong_identity_key() {
        let (verifying_key, signing_key) = make_ed25519_keypair();
        let did = did_from_public_key(&verifying_key);
        let routing_id = did_routing_id(&did);

        // Create a document with a WRONG identity key (different from DID suffix).
        let wrong_identity_key = [0xFFu8; 32];
        let active_key = [2u8; 32];
        let pre_rotation_key = [3u8; 32];
        let doc = DidDocument::new(&did, &wrong_identity_key, &active_key, &pre_rotation_key);
        let value = serde_json::to_vec(&doc).unwrap();

        // Sign it correctly with the real key (BEP44 sig will verify, but
        // self-cert will fail because the doc's #0 key doesn't match the DID).
        let payload = bep44_signable(&value, 1);
        let signature: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(&signing_key, &payload);

        let blob = RelayQueryRecord {
            value,
            signature: signature.to_bytes(),
            seq: 1,
        };

        let querier = InMemoryRelayQuerier::new();
        querier
            .insert("wss://relay1.example.com/scp/v1", &routing_id, blob)
            .await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        let result = relay_resolve(&did, &["wss://relay1.example.com/scp/v1"], &querier, &cache)
            .await
            .unwrap();

        // Self-certification failure: no valid result returned.
        assert!(result.is_none());

        // Nothing should be cached.
        assert!(cache.get(&did).await.is_none());
    }

    /// Invalid DID format returns an error immediately.
    #[tokio::test]
    async fn relay_resolve_rejects_invalid_did_format() {
        let querier = InMemoryRelayQuerier::new();
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        let result = relay_resolve(
            "not-a-valid-did",
            &["wss://relay1.example.com/scp/v1"],
            &querier,
            &cache,
        )
        .await;

        assert!(result.is_err());
    }
}
