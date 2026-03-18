//! DHT-based context discovery via DID document service endpoints.
//!
//! Implements context discovery per §5.14.11 and §18.2.2: resolving a DID's
//! `SCPBroadcastContext` service entries to discover broadcast contexts
//! published by that identity.
//!
//! This is the DHT-native discovery path: no HTTP, no `.well-known/scp`,
//! no central registry. Any identity can publish discoverable contexts by
//! adding `SCPBroadcastContext` service entries to their DID document.
//!
//! # Discovery Flow
//!
//! 1. Resolve a DID via `did:dht` (Mainline DHT, self-certifying via BEP44).
//! 2. Extract `SCPBroadcastContext` service entries from the resolved document.
//! 3. Parse each entry to get `(context_id, relay_urls)` pairs.
//! 4. Return structured [`ContextDiscoveryResult`] entries.
//!
//! # Publishing Flow
//!
//! When a broadcast context is created with `discoverable: true`:
//! 1. Add an `SCPBroadcastContext` service entry to the creator's DID document.
//! 2. Republish the DID document to the DHT.
//!
//! See §5.14.11 and §18.2.2 for the full specification.

use serde::{Deserialize, Serialize};

use scp_identity::DID;
use scp_identity::dht_client::DhtClient;
use scp_identity::{DidDht, DidMethod};

use super::DiscoveryError;

// ---------------------------------------------------------------------------
// ContextDiscoveryResult
// ---------------------------------------------------------------------------

/// A discovered context entry from a DID document's `SCPBroadcastContext`
/// service endpoints.
///
/// Contains the context ID, relay URLs, the DID of the publisher, and
/// a trust level indicating how the context was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextDiscoveryResult {
    /// Hex-encoded context identifier.
    pub context_id: String,
    /// Relay URLs where the context is reachable.
    pub relay_urls: Vec<String>,
    /// The DID that published this context in their DID document.
    pub publisher_did: DID,
    /// How the context was discovered.
    pub discovery_source: ContextDiscoverySource,
    /// Advisory context mode, if known. Not verified against actual context
    /// metadata -- the consumer must fetch context metadata to confirm.
    pub mode: Option<String>,
    /// Human-readable summary of context metadata (advisory).
    pub metadata_summary: Option<String>,
}

/// The source through which a context was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDiscoverySource {
    /// Discovered via `SCPBroadcastContext` service entry in a DID document
    /// resolved from the DHT.
    DhtDidDocument,
    /// Discovered via `.well-known/scp` document.
    WellKnown,
    /// Discovered via the `agent_search` tool in a context with discovery tools.
    DiscoveryContext {
        /// The context ID.
        context_id: String,
    },
    /// Discovered via an `scp://` URI shared out-of-band.
    ContextUri,
}

// ---------------------------------------------------------------------------
// resolve_contexts_from_did
// ---------------------------------------------------------------------------

/// Resolves discoverable broadcast contexts from a DID's document.
///
/// Fetches the DID document via `did:dht` and extracts all
/// `SCPBroadcastContext` service entries. Each entry produces a
/// [`ContextDiscoveryResult`] with the context ID, relay URLs, and publisher
/// DID.
///
/// # Arguments
///
/// * `did` -- The DID to resolve (e.g., `"did:dht:z6Mk..."`).
/// * `did_dht` -- A configured `DidDht` instance for DID resolution.
///
/// # Errors
///
/// Returns [`DiscoveryError::DidResolutionFailed`] if the DID cannot be
/// resolved.
///
/// See §5.14.11 and §18.2.2.
pub async fn resolve_contexts_from_did<D: DhtClient + 'static>(
    did: &str,
    did_dht: &DidDht<D>,
) -> Result<Vec<ContextDiscoveryResult>, DiscoveryError> {
    // Step 1: Resolve the DID document.
    let document = did_dht
        .resolve(did)
        .await
        .map_err(|e| DiscoveryError::DidResolutionFailed(e.to_string()))?;

    // Step 2: Extract broadcast context entries.
    let entries = document.broadcast_context_entries();

    // Step 3: Convert to ContextDiscoveryResult.
    let results = entries
        .into_iter()
        .map(|(context_id, relay_urls)| ContextDiscoveryResult {
            context_id,
            relay_urls,
            publisher_did: DID::from(did),
            discovery_source: ContextDiscoverySource::DhtDidDocument,
            mode: Some("broadcast".to_owned()),
            metadata_summary: None,
        })
        .collect();

    Ok(results)
}

/// Publishes a broadcast context as discoverable in the creator's DID document.
///
/// Adds an `SCPBroadcastContext` service entry to the DID document. The caller
/// is responsible for republishing the document to the DHT after this call.
///
/// # Privacy Enforcement
///
/// This function enforces that only broadcast contexts may be published.
/// The `is_broadcast` parameter must be `true`; otherwise the function
/// returns an error. Encrypted context IDs MUST NOT appear in DID documents
/// (§9.10 metadata privacy).
///
/// # Arguments
///
/// * `document` -- The DID document to modify (mutable reference).
/// * `context_id` -- Hex-encoded context identifier.
/// * `relay_urls` -- Relay URLs where the context is reachable.
/// * `is_broadcast` -- Whether the context is a broadcast context.
///
/// # Errors
///
/// Returns [`DiscoveryError::InvalidCapabilities`] if `is_broadcast` is
/// `false` (encrypted contexts MUST NOT be published in DID documents).
pub fn publish_context_to_did_document(
    document: &mut scp_identity::document::DidDocument,
    context_id: &str,
    relay_urls: &[String],
    is_broadcast: bool,
) -> Result<(), DiscoveryError> {
    if !is_broadcast {
        return Err(DiscoveryError::InvalidCapabilities(
            "only broadcast contexts may be published in DID documents — \
             encrypted context IDs MUST NOT appear (§9.10 metadata privacy)"
                .to_owned(),
        ));
    }

    document.add_broadcast_context_service(context_id, relay_urls);
    Ok(())
}

/// Removes a broadcast context from the creator's DID document.
///
/// The caller is responsible for republishing the document to the DHT after
/// this call.
///
/// Returns `true` if an entry was removed, `false` if no matching entry existed.
pub fn unpublish_context_from_did_document(
    document: &mut scp_identity::document::DidDocument,
    context_id: &str,
) -> bool {
    document.remove_broadcast_context_service(context_id)
}

// ---------------------------------------------------------------------------
// resolve_context_uri
// ---------------------------------------------------------------------------

/// Resolves an `scp://` context URI into a [`ContextDiscoveryResult`].
///
/// Parses the URI and extracts context ID, relay URLs, and advisory metadata.
/// This does NOT connect to the relay or fetch context metadata -- it is a
/// pure parsing step. The consumer is responsible for connecting to the relay
/// and fetching metadata.
///
/// # Arguments
///
/// * `uri_str` -- The `scp://` URI string.
///
/// # Errors
///
/// Returns [`DiscoveryError::InvalidCapabilities`] if the URI cannot be parsed.
///
/// See §18.4.
pub fn resolve_context_uri(uri_str: &str) -> Result<ContextDiscoveryResult, DiscoveryError> {
    let uri: crate::uri::ScpUri = uri_str.parse().map_err(|e: crate::uri::ScpUriError| {
        DiscoveryError::InvalidCapabilities(format!("invalid scp:// URI: {e}"))
    })?;

    let mode = uri.mode().map(|m| match m {
        crate::context::ContextMode::Encrypted => "encrypted".to_owned(),
        crate::context::ContextMode::Broadcast => "broadcast".to_owned(),
    });

    Ok(ContextDiscoveryResult {
        context_id: uri.context_id().to_owned(),
        relay_urls: uri.relays().to_vec(),
        publisher_did: DID::from(""),
        discovery_source: ContextDiscoverySource::ContextUri,
        mode,
        metadata_summary: uri.name().map(ToOwned::to_owned),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use scp_identity::DidDht;
    use scp_identity::cache::{DidCache, SystemClock};
    use scp_identity::dht_client::InMemoryDhtClient;

    use scp_platform::testing::InMemoryKeyCustody;

    /// Helper: creates a `DidDht` instance with signing capability for tests.
    fn create_test_dht(custody: &Arc<InMemoryKeyCustody>) -> DidDht<InMemoryDhtClient> {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::<SystemClock>::new());
        let sign_fn = DidDht::<InMemoryDhtClient>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    // -- resolve_context_uri -------------------------------------------------

    #[test]
    fn resolve_context_uri_parses_valid_uri() {
        let uri = "scp://context/a1b2c3d4e5f6?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
                   &mode=broadcast&name=Test%20Context";
        let result = resolve_context_uri(uri).unwrap();

        assert_eq!(result.context_id, "a1b2c3d4e5f6");
        assert_eq!(result.relay_urls, vec!["wss://relay.example.com/scp/v1"]);
        assert_eq!(result.discovery_source, ContextDiscoverySource::ContextUri);
        assert_eq!(result.mode, Some("broadcast".to_owned()));
        assert_eq!(result.metadata_summary, Some("Test Context".to_owned()));
    }

    #[test]
    fn resolve_context_uri_rejects_invalid_uri() {
        let err = resolve_context_uri("https://not-an-scp-uri").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
    }

    #[test]
    fn resolve_context_uri_legacy_broadcast_format() {
        let uri = "scp://broadcast/deadbeef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let result = resolve_context_uri(uri).unwrap();

        assert_eq!(result.context_id, "deadbeef");
        assert_eq!(result.mode, Some("broadcast".to_owned()));
    }

    // -- publish_context_to_did_document -------------------------------------

    #[test]
    fn publish_broadcast_context_adds_service_entry() {
        let mut doc = scp_identity::document::DidDocument::new(
            "did:dht:zTest",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        publish_context_to_did_document(
            &mut doc,
            "a1b2c3d4e5f6",
            &["wss://relay.example.com/scp/v1".to_owned()],
            true,
        )
        .unwrap();

        let entries = doc.broadcast_context_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "a1b2c3d4e5f6");
        assert_eq!(entries[0].1, vec!["wss://relay.example.com/scp/v1"]);
    }

    #[test]
    fn publish_encrypted_context_rejected() {
        let mut doc = scp_identity::document::DidDocument::new(
            "did:dht:zTest",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        let err = publish_context_to_did_document(
            &mut doc,
            "deadbeef",
            &["wss://relay.example.com/scp/v1".to_owned()],
            false,
        )
        .unwrap_err();

        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
        assert!(err.to_string().contains("encrypted"));
        assert!(doc.broadcast_context_entries().is_empty());
    }

    #[test]
    fn publish_multiple_broadcast_contexts() {
        let mut doc = scp_identity::document::DidDocument::new(
            "did:dht:zTest",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        publish_context_to_did_document(
            &mut doc,
            "context1",
            &["wss://relay1.example.com/scp/v1".to_owned()],
            true,
        )
        .unwrap();

        publish_context_to_did_document(
            &mut doc,
            "context2",
            &[
                "wss://relay1.example.com/scp/v1".to_owned(),
                "wss://relay2.example.com/scp/v1".to_owned(),
            ],
            true,
        )
        .unwrap();

        let entries = doc.broadcast_context_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn publish_duplicate_context_id_is_noop() {
        let mut doc = scp_identity::document::DidDocument::new(
            "did:dht:zTest",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        publish_context_to_did_document(
            &mut doc,
            "a1b2c3d4",
            &["wss://relay.example.com/scp/v1".to_owned()],
            true,
        )
        .unwrap();

        // Same context ID again -- should be silently ignored.
        publish_context_to_did_document(
            &mut doc,
            "a1b2c3d4",
            &["wss://relay2.example.com/scp/v1".to_owned()],
            true,
        )
        .unwrap();

        let entries = doc.broadcast_context_entries();
        assert_eq!(entries.len(), 1);
    }

    // -- unpublish_context_from_did_document ----------------------------------

    #[test]
    fn unpublish_removes_matching_entry() {
        let mut doc = scp_identity::document::DidDocument::new(
            "did:dht:zTest",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        publish_context_to_did_document(
            &mut doc,
            "a1b2c3d4",
            &["wss://relay.example.com/scp/v1".to_owned()],
            true,
        )
        .unwrap();

        let removed = unpublish_context_from_did_document(&mut doc, "a1b2c3d4");
        assert!(removed);
        assert!(doc.broadcast_context_entries().is_empty());
    }

    #[test]
    fn unpublish_nonexistent_returns_false() {
        let mut doc = scp_identity::document::DidDocument::new(
            "did:dht:zTest",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        let removed = unpublish_context_from_did_document(&mut doc, "nonexistent");
        assert!(!removed);
    }

    // -- privacy enforcement: only discoverable broadcast contexts -----------

    #[test]
    fn privacy_only_discoverable_contexts_get_service_endpoints() {
        let mut doc = scp_identity::document::DidDocument::new(
            "did:dht:zTest",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        // Simulate: broadcast context with discoverable=false -> no publish call
        // (the caller is responsible for not calling publish when discoverable=false)
        assert!(doc.broadcast_context_entries().is_empty());

        // Simulate: broadcast context with discoverable=true -> publish
        publish_context_to_did_document(
            &mut doc,
            "discoverable_ctx",
            &["wss://relay.example.com/scp/v1".to_owned()],
            true,
        )
        .unwrap();

        assert_eq!(doc.broadcast_context_entries().len(), 1);
        assert_eq!(doc.broadcast_context_entries()[0].0, "discoverable_ctx");
    }

    // -- resolve_contexts_from_did (integration) -----------------------------

    #[tokio::test]
    async fn resolve_contexts_from_did_finds_published_contexts() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_dht = create_test_dht(&custody);

        // Create identity.
        let (identity, mut document) = did_dht.create(&*custody).await.unwrap();

        // Publish a broadcast context.
        document.add_broadcast_context_service(
            "a1b2c3d4e5f6",
            &["wss://relay.example.com/scp/v1".to_owned()],
        );
        did_dht.publish(&identity, &document).await.unwrap();

        // Resolve and discover.
        let results = resolve_contexts_from_did(&identity.did, &did_dht)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].context_id, "a1b2c3d4e5f6");
        assert_eq!(
            results[0].relay_urls,
            vec!["wss://relay.example.com/scp/v1"]
        );
        assert_eq!(results[0].publisher_did, identity.did);
        assert_eq!(
            results[0].discovery_source,
            ContextDiscoverySource::DhtDidDocument
        );
        assert_eq!(results[0].mode, Some("broadcast".to_owned()));
    }

    #[tokio::test]
    async fn resolve_contexts_from_did_no_broadcast_contexts() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_dht = create_test_dht(&custody);

        // Create identity without broadcast contexts.
        let (identity, document) = did_dht.create(&*custody).await.unwrap();
        did_dht.publish(&identity, &document).await.unwrap();

        let results = resolve_contexts_from_did(&identity.did, &did_dht)
            .await
            .unwrap();

        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn resolve_contexts_from_did_invalid_did() {
        let did_dht = DidDht::new();

        let err = resolve_contexts_from_did("did:dht:zInvalidDid", &did_dht)
            .await
            .unwrap_err();

        assert!(matches!(err, DiscoveryError::DidResolutionFailed(_)));
    }

    #[tokio::test]
    async fn resolve_contexts_from_did_multiple_contexts() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_dht = create_test_dht(&custody);

        let (identity, mut document) = did_dht.create(&*custody).await.unwrap();

        document.add_broadcast_context_service(
            "context1",
            &["wss://relay1.example.com/scp/v1".to_owned()],
        );
        document.add_broadcast_context_service(
            "context2",
            &[
                "wss://relay1.example.com/scp/v1".to_owned(),
                "wss://relay2.example.com/scp/v1".to_owned(),
            ],
        );
        did_dht.publish(&identity, &document).await.unwrap();

        let results = resolve_contexts_from_did(&identity.did, &did_dht)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);

        let ctx1 = results.iter().find(|r| r.context_id == "context1").unwrap();
        assert_eq!(ctx1.relay_urls, vec!["wss://relay1.example.com/scp/v1"]);

        let ctx2 = results.iter().find(|r| r.context_id == "context2").unwrap();
        assert_eq!(ctx2.relay_urls.len(), 2);
    }

    // -- ContextDiscoveryResult serialization --------------------------------

    #[test]
    fn context_discovery_result_serialization_roundtrip() {
        let result = ContextDiscoveryResult {
            context_id: "a1b2c3d4e5f6".to_owned(),
            relay_urls: vec!["wss://relay.example.com/scp/v1".to_owned()],
            publisher_did: DID::from("did:dht:zPublisher"),
            discovery_source: ContextDiscoverySource::DhtDidDocument,
            mode: Some("broadcast".to_owned()),
            metadata_summary: Some("A test context".to_owned()),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ContextDiscoveryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn context_discovery_source_variants_serialize() {
        let sources = vec![
            ContextDiscoverySource::DhtDidDocument,
            ContextDiscoverySource::WellKnown,
            ContextDiscoverySource::DiscoveryContext {
                context_id: "ctx-disc-1".to_owned(),
            },
            ContextDiscoverySource::ContextUri,
        ];

        for source in &sources {
            let json = serde_json::to_string(source).unwrap();
            let deserialized: ContextDiscoverySource = serde_json::from_str(&json).unwrap();
            assert_eq!(source, &deserialized);
        }
    }
}
