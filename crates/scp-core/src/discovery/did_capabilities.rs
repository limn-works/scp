//! DID document capability resolution.
//!
//! Extracts `SCPCapabilities` service entries from DID documents resolved via
//! `did:dht`. Any agent can publish capabilities in their DID document -- zero
//! setup, zero registration, zero dependency on discovery contexts.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`, acceptance criterion 2.

use serde::{Deserialize, Serialize};

use crate::identity::dht_client::DhtClient;
use crate::identity::document::DidDocument;
use crate::identity::{DidDht, DidMethod};

use super::{DID, DiscoveryError};

/// The service type string for `SCPCapabilities` entries in DID documents.
const SCP_CAPABILITIES_SERVICE_TYPE: &str = "SCPCapabilities";

/// Capability entry extracted from a DID document's `SCPCapabilities` service.
///
/// Represents the capabilities advertised by an agent in their DID document.
/// Resolved by anyone who knows the agent's DID -- no discovery context
/// membership required.
///
/// See ADR-020 acceptance criterion 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEntry {
    /// The DID of the agent whose capabilities were resolved.
    pub did: DID,
    /// The capability strings advertised by this agent.
    pub capabilities: Vec<String>,
    /// Service endpoint URLs from the `SCPCapabilities` service entries.
    pub service_endpoints: Vec<String>,
    /// Unix timestamp (seconds) when the capabilities were resolved.
    pub resolved_at: u64,
}

/// Resolves capabilities from a DID document's `SCPCapabilities` service entries.
///
/// Performs the following steps:
/// 1. Resolves the DID document via `did:dht` using the provided DHT client.
/// 2. Finds all `SCPCapabilities` service entries in the document.
/// 3. Extracts capability strings from the service endpoints.
/// 4. Returns a [`CapabilityEntry`] with the resolved capabilities.
///
/// # Capability Encoding
///
/// Capabilities are encoded in the service endpoint as a comma-separated list
/// prefixed with `scp:capabilities:`. For example:
/// `scp:capabilities:code_review,testing,translation`
///
/// # Arguments
///
/// * `did` -- The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
/// * `did_dht` -- A configured `DidDht` instance for DID resolution.
///
/// # Errors
///
/// Returns [`DiscoveryError::DidResolutionFailed`] if DID resolution fails.
/// Returns [`DiscoveryError::NoCapabilitiesService`] if no `SCPCapabilities`
/// service entry is found.
/// Returns [`DiscoveryError::InvalidCapabilities`] if the service endpoint
/// cannot be parsed as a capability list.
///
/// See ADR-020 acceptance criterion 2.
pub async fn resolve_capabilities<D: DhtClient + 'static>(
    did: &str,
    did_dht: &DidDht<D>,
) -> Result<CapabilityEntry, DiscoveryError> {
    // Step 1: Resolve the DID document.
    let document = did_dht
        .resolve(did)
        .await
        .map_err(|e| DiscoveryError::DidResolutionFailed(e.to_string()))?;

    // Step 2: Extract capabilities from the document.
    extract_capabilities(did, &document)
}

/// Extracts capabilities from a resolved DID document.
///
/// Finds all `SCPCapabilities` service entries and parses the capability
/// strings from each service endpoint. This is a pure function with no I/O.
fn extract_capabilities(
    did: &str,
    document: &DidDocument,
) -> Result<CapabilityEntry, DiscoveryError> {
    let capability_services: Vec<_> = document
        .service
        .iter()
        .filter(|s| s.service_type == SCP_CAPABILITIES_SERVICE_TYPE)
        .collect();

    if capability_services.is_empty() {
        return Err(DiscoveryError::NoCapabilitiesService(did.to_owned()));
    }

    let mut capabilities = Vec::new();
    let mut service_endpoints = Vec::new();

    for service in &capability_services {
        service_endpoints.push(service.service_endpoint.clone());

        let parsed = parse_capability_endpoint(&service.service_endpoint)?;
        capabilities.extend(parsed);
    }

    // Deduplicate capabilities while preserving order.
    let mut seen = std::collections::HashSet::new();
    capabilities.retain(|cap| seen.insert(cap.clone()));

    let now = crate::time::now_secs()?;

    Ok(CapabilityEntry {
        did: did.into(),
        capabilities,
        service_endpoints,
        resolved_at: now,
    })
}

/// Parses capability strings from an `SCPCapabilities` service endpoint.
///
/// The expected format is `scp:capabilities:<comma-separated-list>`.
/// For example: `scp:capabilities:code_review,testing,translation`.
///
/// # Errors
///
/// Returns [`DiscoveryError::InvalidCapabilities`] if the endpoint does not
/// match the expected format or contains no capabilities.
fn parse_capability_endpoint(endpoint: &str) -> Result<Vec<String>, DiscoveryError> {
    const PREFIX: &str = "scp:capabilities:";

    let capability_str = endpoint.strip_prefix(PREFIX).ok_or_else(|| {
        DiscoveryError::InvalidCapabilities(format!(
            "service endpoint must start with '{PREFIX}', got: {endpoint}"
        ))
    })?;

    if capability_str.is_empty() {
        return Err(DiscoveryError::InvalidCapabilities(
            "empty capability list in service endpoint".to_owned(),
        ));
    }

    let caps: Vec<String> = capability_str
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    if caps.is_empty() {
        return Err(DiscoveryError::InvalidCapabilities(
            "no valid capabilities found in service endpoint".to_owned(),
        ));
    }

    Ok(caps)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::identity::cache::{DidCache, SystemClock};
    use crate::identity::dht_client::InMemoryDhtClient;
    use crate::identity::document::DidDocument;
    use crate::identity::{DidDht, DidMethod};

    use scp_platform::testing::InMemoryKeyCustody;

    /// Helper: creates a `DidDht` instance with signing capability for tests.
    fn create_test_dht(custody: &Arc<InMemoryKeyCustody>) -> DidDht<InMemoryDhtClient> {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::<SystemClock>::new());
        let sign_fn = DidDht::<InMemoryDhtClient>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    /// Helper: creates a DID identity and publishes a document with
    /// `SCPCapabilities` service entries.
    async fn create_identity_with_capabilities(
        did_dht: &DidDht<InMemoryDhtClient>,
        key_custody: &InMemoryKeyCustody,
        capabilities: &[&str],
    ) -> (String, DidDocument) {
        let (identity, mut document) = did_dht.create(key_custody).await.unwrap();

        // Add SCPCapabilities service.
        let cap_str = capabilities.join(",");
        let service = crate::identity::document::Service {
            id: format!("{}#scp-capabilities", document.id),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint: format!("scp:capabilities:{cap_str}"),
        };
        document.service.push(service);

        // Publish the updated document.
        did_dht.publish(&identity, &document).await.unwrap();

        (identity.did, document)
    }

    #[test]
    fn parse_capability_endpoint_valid() {
        let caps = parse_capability_endpoint("scp:capabilities:code_review,testing").unwrap();
        assert_eq!(caps, vec!["code_review", "testing"]);
    }

    #[test]
    fn parse_capability_endpoint_single_capability() {
        let caps = parse_capability_endpoint("scp:capabilities:translation").unwrap();
        assert_eq!(caps, vec!["translation"]);
    }

    #[test]
    fn parse_capability_endpoint_trims_whitespace() {
        let caps =
            parse_capability_endpoint("scp:capabilities:code_review , testing , deploy").unwrap();
        assert_eq!(caps, vec!["code_review", "testing", "deploy"]);
    }

    #[test]
    fn parse_capability_endpoint_rejects_missing_prefix() {
        let err = parse_capability_endpoint("code_review,testing").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
        assert!(err.to_string().contains("scp:capabilities:"));
    }

    #[test]
    fn parse_capability_endpoint_rejects_empty_list() {
        let err = parse_capability_endpoint("scp:capabilities:").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
    }

    #[test]
    fn extract_capabilities_no_service_returns_error() {
        let did = "did:dht:zTestDid";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let err = extract_capabilities(did, &doc).unwrap_err();
        assert!(matches!(err, DiscoveryError::NoCapabilitiesService(_)));
    }

    #[test]
    fn extract_capabilities_with_service() {
        let did = "did:dht:zTestDid";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.service.push(crate::identity::document::Service {
            id: format!("{did}#scp-capabilities"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint: "scp:capabilities:code_review,testing".to_owned(),
        });

        let entry = extract_capabilities(did, &doc).unwrap();
        assert_eq!(entry.did, did);
        assert_eq!(entry.capabilities, vec!["code_review", "testing"]);
        assert_eq!(entry.service_endpoints.len(), 1);
    }

    #[test]
    fn extract_capabilities_deduplicates() {
        let did = "did:dht:zTestDid";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        // Two services with overlapping capabilities.
        doc.service.push(crate::identity::document::Service {
            id: format!("{did}#scp-capabilities-1"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint: "scp:capabilities:code_review,testing".to_owned(),
        });
        doc.service.push(crate::identity::document::Service {
            id: format!("{did}#scp-capabilities-2"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint: "scp:capabilities:testing,translation".to_owned(),
        });

        let entry = extract_capabilities(did, &doc).unwrap();
        assert_eq!(
            entry.capabilities,
            vec!["code_review", "testing", "translation"]
        );
        assert_eq!(entry.service_endpoints.len(), 2);
    }

    #[tokio::test]
    async fn resolve_capabilities_end_to_end() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_dht = create_test_dht(&custody);

        let (did, _doc) =
            create_identity_with_capabilities(&did_dht, &custody, &["code_review", "testing"])
                .await;

        let entry = resolve_capabilities(&did, &did_dht).await.unwrap();

        assert_eq!(entry.did, did);
        assert_eq!(entry.capabilities, vec!["code_review", "testing"]);
        assert_eq!(entry.service_endpoints.len(), 1);
        assert!(entry.resolved_at > 0);
    }

    #[tokio::test]
    async fn resolve_capabilities_no_service_returns_error() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let did_dht = create_test_dht(&custody);

        // Create identity without SCPCapabilities service.
        let (identity, document) = did_dht.create(&*custody).await.unwrap();
        did_dht.publish(&identity, &document).await.unwrap();

        let err = resolve_capabilities(&identity.did, &did_dht)
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::NoCapabilitiesService(_)));
    }

    #[tokio::test]
    async fn resolve_capabilities_invalid_did_returns_error() {
        let did_dht = DidDht::new();

        let err = resolve_capabilities("did:dht:zInvalidDid", &did_dht)
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::DidResolutionFailed(_)));
    }
}
