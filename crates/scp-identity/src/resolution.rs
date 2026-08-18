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
//! 3. QUERY relay with `routing_id`, receiving ALL decodable candidates
//!    (bounded — see [`RelayQuerier`] and [`crate::relay_querier::RealMultiRelayQuerier`]).
//! 4. For each candidate: verify BEP44 signature + UTF-8/JSON + self-cert
//!    via [`verify_relay_record`].
//! 5. Return the HIGHEST-SEQ valid candidate — iterating every candidate
//!    so neither a bad-signature frame nor a stale-but-valid frame can shadow
//!    the genuine current record (§3.10.8 intra-relay suppression).
//!    Caching and cross-layer seq arbitration are owned by
//!    [`DualLayerResolver`](crate::resolver::DualLayerResolver) (§3.10.4/§3.10.7).
//!
//! The [`RelayQuerier`] trait abstracts relay QUERY operations so that
//! `scp-core` does not depend on `scp-transport`. The production implementation
//! is `scp_transport::native::TransportRelayQuerier`; tests use
//! `InMemoryRelayQuerier`, which this module compiles only under
//! `cfg(any(test, feature = "testing"))`.

use sha2::{Digest, Sha256};

use crate::IdentityError;
use crate::dht::verify_self_certification;
use scp_dht::verify_bep44_signature;
use scp_did::DidDocument;

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
/// This is the relay equivalent of [`DhtRecord`](scp_dht::DhtRecord).
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
/// The production implementation (`scp_transport::native::TransportRelayQuerier`)
/// sends QUERY messages to SCP relays. Tests use `InMemoryRelayQuerier`, backed
/// by a `HashMap` and compiled only under `cfg(any(test, feature = "testing"))`.
///
/// This trait is defined in `scp-identity` so that the resolution logic does not
/// depend on `scp-transport` (§3.10.12 phase integration).
pub trait RelayQuerier: Send + Sync {
    /// Queries a relay for **all** decodable public-record candidates at a
    /// routing ID.
    ///
    /// Returns EVERY SCPR-decodable record stored at `routing_id`, **without**
    /// verification (framing grants no authority, §9.10.12). The caller (the
    /// [`RealMultiRelayQuerier`](crate::relay_querier::RealMultiRelayQuerier)
    /// composer) BEP44-verifies each candidate and selects the **highest-seq
    /// valid one** (§3.10.7).
    ///
    /// Returning a `Vec` — not a single record — is load-bearing: the
    /// composer iterates every candidate and selects the highest-seq-valid
    /// one, defeating both:
    /// - A decodable-but-bad-signature blob co-located before the genuine
    ///   record (an attacker plants a well-framed frame; `verify_relay_record`
    ///   skips it).
    /// - A stale-but-validly-signed blob co-located before the current record
    ///   (an attacker replays an old triple; highest-seq selection skips it,
    ///   since `seq` is inside the BEP44 signed payload and an attacker cannot
    ///   forge a higher seq without the owner's private key).
    ///
    /// Both variants are intra-relay suppression denial-of-service attacks
    /// (§3.10.8). The relay implementation MUST bound the number of candidates
    /// it collects (see `TransportRelayQuerier`).
    ///
    /// # Arguments
    ///
    /// * `relay_url` — The relay endpoint URL.
    /// * `routing_id` — The 32-byte routing ID to query.
    ///
    /// # Returns
    ///
    /// A (possibly empty) vector of every decodable, **unverified** candidate.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::RelayQueryFailed`] if the query itself fails.
    fn query(
        &self,
        relay_url: &str,
        routing_id: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<RelayQueryRecord>, IdentityError>> + Send;
}

/// Verifies a raw relay `(value, signature, seq)` record against a DID and
/// returns the deserialized [`DidDocument`] (§3.10.4/§9.6.1).
///
/// Performs, in order: BEP44 signature verification against the DID's Ed25519
/// key, UTF-8 + JSON deserialization, and the self-certification check (the
/// document's identity key must match the DID suffix). This is the SINGLE shared
/// verify path used by both the relay composer
/// ([`RealMultiRelayQuerier`](crate::relay_querier::RealMultiRelayQuerier)) and
/// the dual-layer resolver ([`crate::resolver::DualLayerResolver`]), so relay
/// and DHT records are validated identically and the logic is not duplicated.
///
/// # Errors
///
/// Returns [`IdentityError`] when the signature does not verify, the bytes are
/// not valid UTF-8/JSON, or self-certification fails.
pub(crate) fn verify_relay_record(
    did: &str,
    public_key: &[u8; 32],
    value: &[u8],
    signature: &[u8; 64],
    seq: u64,
) -> Result<DidDocument, IdentityError> {
    verify_bep44_signature(public_key, signature, value, seq)?;

    let doc_json = std::str::from_utf8(value)
        .map_err(|e| IdentityError::DocumentDeserializationError(format!("invalid UTF-8: {e}")))?;
    let document = DidDocument::from_json(doc_json)
        .map_err(|e| IdentityError::DocumentDeserializationError(e.to_string()))?;

    verify_self_certification(did, &document)?;

    Ok(document)
}

// ---------------------------------------------------------------------------
// In-memory test implementation
// ---------------------------------------------------------------------------

/// In-memory relay querier for testing.
///
/// Stores blobs in a `HashMap` keyed by (`relay_url`, `routing_id`). Supports
/// configuring per-relay responses for testing relay selection priority.
///
/// Multiple records may be stored at the same key (co-located candidates) via
/// repeated `insert` calls; they are returned by `query` in insertion order.
///
/// This type is a test double and the `cfg` below keeps it out of every shipped
/// build: a default-feature compile of `scp-identity` does not contain it, so no
/// production caller can reach it. The relay layer a shipped build resolves
/// through is `scp_transport::native::TransportRelayQuerier`, composed under
/// `RealMultiRelayQuerier` by `scp_ffi_common::build_production_did_resolver`
/// (spec §3.10.4 step 3a).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct InMemoryRelayQuerier {
    /// Map from (`relay_url`, `routing_id`) to the ordered list of stored
    /// records. `insert` appends, so a routing ID can hold multiple co-located
    /// candidates (exercising the shadow-defeating `Vec` query contract).
    #[allow(clippy::type_complexity)]
    items: tokio::sync::Mutex<std::collections::HashMap<(String, [u8; 32]), Vec<RelayQueryRecord>>>,
}

#[cfg(any(test, feature = "testing"))]
impl InMemoryRelayQuerier {
    /// Creates a new empty in-memory relay querier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Appends a record for a specific relay and routing ID. Multiple records
    /// may be stored at the same key (co-located candidates); they are returned
    /// by `query` in insertion order.
    pub async fn insert(&self, relay_url: &str, routing_id: &[u8; 32], record: RelayQueryRecord) {
        let mut items = self.items.lock().await;
        items
            .entry((relay_url.to_owned(), *routing_id))
            .or_default()
            .push(record);
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
#[cfg(any(test, feature = "testing"))]
impl RelayQuerier for InMemoryRelayQuerier {
    fn query(
        &self,
        relay_url: &str,
        routing_id: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<RelayQueryRecord>, IdentityError>> + Send {
        async move {
            let records = self
                .items
                .lock()
                .await
                .get(&(relay_url.to_owned(), *routing_id))
                .cloned()
                .unwrap_or_default();
            Ok(records)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::DID_ROUTING_DOMAIN_SEPARATOR;
    use crate::*;

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

    // ---- InMemoryRelayQuerier Vec-contract tests ----

    /// The querier returns EVERY co-located record at a routing ID (append
    /// semantics), so a caller can see a valid record even when a decodable but
    /// otherwise-bad record was stored first (shadow-defeating `Vec` contract).
    #[tokio::test]
    async fn in_memory_querier_returns_all_colocated_records_in_order() {
        let routing_id = did_routing_id("did:dht:zTest");
        let rec = |seq: u8| RelayQueryRecord {
            value: vec![seq],
            signature: [seq; 64],
            seq: u64::from(seq),
        };

        let querier = InMemoryRelayQuerier::new();
        querier.insert("wss://r/scp/v1", &routing_id, rec(1)).await;
        querier.insert("wss://r/scp/v1", &routing_id, rec(2)).await;

        let out = RelayQuerier::query(&querier, "wss://r/scp/v1", &routing_id)
            .await
            .unwrap();
        assert_eq!(out.len(), 2, "both co-located records returned");
        assert_eq!(out[0].seq, 1);
        assert_eq!(out[1].seq, 2);
    }

    /// An unknown routing ID yields an empty vector (not an error).
    #[tokio::test]
    async fn in_memory_querier_unknown_routing_id_is_empty() {
        let querier = InMemoryRelayQuerier::new();
        let out = RelayQuerier::query(&querier, "wss://r/scp/v1", &[9u8; 32])
            .await
            .unwrap();
        assert!(out.is_empty());
    }
}
