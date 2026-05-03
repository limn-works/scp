//! DID document capability resolution.
//!
//! Extracts `SCPCapabilities` service entries from DID documents resolved via
//! `did:dht`. Any agent can publish capabilities in their DID document -- zero
//! setup, zero registration, zero dependency on contexts with discovery tools.
//!
//! Each individual capability string within an `SCPCapabilities` service
//! endpoint is a validated [`CapabilityUri`] (ADR-041, §7.3.4.1). The
//! `scp:capabilities:` prefix is retained for DID document encoding; individual
//! capability strings within the comma-separated list must parse as valid
//! `CapabilityUri` values.
//!
//! See ADR-020 in `.docs/adrs/phase-4.md`, acceptance criterion 2.
//! See ADR-041 in `.docs/adrs/phase-4.md`, acceptance criterion 4.

use serde::{Deserialize, Serialize};

use scp_identity::dht_client::DhtClient;
use scp_identity::document::DidDocument;
use scp_identity::{DidDht, DidMethod};
use scp_primitives::Clock;

use scp_protocol::trust::CapabilityUri;

use scp_primitives::DID;
use scp_protocol::discovery::DiscoveryError;

/// The service type string for `SCPCapabilities` entries in DID documents.
const SCP_CAPABILITIES_SERVICE_TYPE: &str = "SCPCapabilities";

/// Capability entry extracted from a DID document's `SCPCapabilities` service.
///
/// Represents the capabilities advertised by an agent in their DID document.
/// Resolved by anyone who knows the agent's DID -- no context
/// membership required. Each capability is a validated [`CapabilityUri`]
/// (ADR-041, §7.3.4.1).
///
/// See ADR-020 acceptance criterion 1.
/// See ADR-041 acceptance criterion 4 (SCP-ACR-005).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEntry {
    /// The DID of the agent whose capabilities were resolved.
    pub did: DID,
    /// The validated capability URIs advertised by this agent.
    pub capabilities: Vec<CapabilityUri>,
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
    clock: &dyn Clock,
) -> Result<CapabilityEntry, DiscoveryError> {
    // Step 1: Resolve the DID document.
    let document = did_dht
        .resolve(did)
        .await
        .map_err(|e| DiscoveryError::DidResolutionFailed(e.to_string()))?;

    // Step 2: Extract capabilities from the document.
    extract_capabilities(did, &document, clock)
}

/// Extracts capabilities from a resolved DID document.
///
/// Finds all `SCPCapabilities` service entries and parses the capability
/// strings from each service endpoint. This is a pure function with no I/O.
fn extract_capabilities(
    did: &str,
    document: &DidDocument,
    clock: &dyn Clock,
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

    let now = clock.now_secs();

    Ok(CapabilityEntry {
        did: did.into(),
        capabilities,
        service_endpoints,
        resolved_at: now,
    })
}

/// Parses capability URIs from an `SCPCapabilities` service endpoint.
///
/// The expected format is `scp:capabilities:<comma-separated-capability-uris>`.
/// For example:
/// `scp:capabilities:scp:capability:schema-validation/v1,scp:capability:rate-limit-compliance/v1`.
///
/// Each comma-separated string must parse as a valid [`CapabilityUri`]
/// (ADR-041, §7.3.4.1). Invalid URIs produce
/// [`DiscoveryError::InvalidCapabilities`].
///
/// # Errors
///
/// Returns [`DiscoveryError::InvalidCapabilities`] if the endpoint does not
/// match the expected format, contains no capabilities, or contains an
/// invalid capability URI.
fn parse_capability_endpoint(endpoint: &str) -> Result<Vec<CapabilityUri>, DiscoveryError> {
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

    let raw_caps: Vec<&str> = capability_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if raw_caps.is_empty() {
        return Err(DiscoveryError::InvalidCapabilities(
            "no valid capabilities found in service endpoint".to_owned(),
        ));
    }

    let mut caps = Vec::with_capacity(raw_caps.len());
    for raw in raw_caps {
        let uri: CapabilityUri = raw.parse().map_err(|e| {
            DiscoveryError::InvalidCapabilities(format!("invalid capability URI '{raw}': {e}"))
        })?;
        caps.push(uri);
    }

    Ok(caps)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use scp_identity::cache::{DidCache, SystemClock};
    use scp_identity::dht_client::InMemoryDhtClient;
    use scp_identity::document::DidDocument;
    use scp_identity::{DidDht, DidMethod};

    use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

    /// Helper: creates a `DidDht` instance with signing capability for tests.
    fn create_test_dht(custody: &Arc<InMemoryKeyCustody>) -> DidDht<InMemoryDhtClient> {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::<SystemClock>::new());
        let sign_fn = DidDht::<InMemoryDhtClient>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    /// Helper: creates a DID identity and publishes a document with
    /// `SCPCapabilities` service entries containing valid `CapabilityUri` strings.
    async fn create_identity_with_capabilities(
        did_dht: &DidDht<InMemoryDhtClient>,
        key_custody: &InMemoryKeyCustody,
        pre_rotation_custody: &InMemoryPreRotationCustody,
        capabilities: &[&str],
    ) -> (String, DidDocument) {
        let (identity, mut document, _pre_rotation_handle) = did_dht
            .create(key_custody, pre_rotation_custody)
            .await
            .unwrap();

        // Add SCPCapabilities service.
        let cap_str = capabilities.join(",");
        let service = scp_identity::document::Service {
            id: format!("{}#scp-capabilities", document.id),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint: format!("scp:capabilities:{cap_str}"),
        };
        document.service.push(service);

        // Publish the updated document.
        did_dht.publish(&identity, &document).await.unwrap();

        (identity.did, document)
    }

    /// Helper: parses a string to `CapabilityUri` for test assertions.
    fn cap(s: &str) -> CapabilityUri {
        s.parse().unwrap()
    }

    // -----------------------------------------------------------------
    // AC 2: parse_capability_endpoint with Protocol URIs
    // -----------------------------------------------------------------

    #[test]
    fn parse_capability_endpoint_two_protocol_uris() {
        let caps = parse_capability_endpoint(
            "scp:capabilities:scp:capability:schema-validation/v1,scp:capability:rate-limit-compliance/v1",
        )
        .unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], cap("scp:capability:schema-validation/v1"));
        assert_eq!(caps[1], cap("scp:capability:rate-limit-compliance/v1"));
    }

    // -----------------------------------------------------------------
    // AC 3: parse_capability_endpoint with DID-scoped URI
    // -----------------------------------------------------------------

    #[test]
    fn parse_capability_endpoint_did_scoped_uri() {
        let caps =
            parse_capability_endpoint("scp:capabilities:did:dht:z6Mk123:capability:custom/v1")
                .unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0], cap("did:dht:z6Mk123:capability:custom/v1"));
        assert!(matches!(caps[0], CapabilityUri::DidScoped { .. }));
    }

    // -----------------------------------------------------------------
    // AC 4: parse_capability_endpoint rejects invalid URIs
    // -----------------------------------------------------------------

    #[test]
    fn parse_capability_endpoint_rejects_invalid_uri() {
        let err = parse_capability_endpoint("scp:capabilities:invalid!!").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
    }

    #[test]
    fn parse_capability_endpoint_rejects_bare_string() {
        let err = parse_capability_endpoint("scp:capabilities:code_review").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
    }

    // -----------------------------------------------------------------
    // parse_capability_endpoint: prefix and empty-list checks
    // -----------------------------------------------------------------

    #[test]
    fn parse_capability_endpoint_single_capability() {
        let caps =
            parse_capability_endpoint("scp:capabilities:scp:capability:schema-validation/v1")
                .unwrap();
        assert_eq!(caps, vec![cap("scp:capability:schema-validation/v1")]);
    }

    #[test]
    fn parse_capability_endpoint_trims_whitespace() {
        let caps = parse_capability_endpoint(
            "scp:capabilities:scp:capability:schema-validation/v1 , scp:capability:rate-limit-compliance/v1",
        )
        .unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], cap("scp:capability:schema-validation/v1"));
        assert_eq!(caps[1], cap("scp:capability:rate-limit-compliance/v1"));
    }

    #[test]
    fn parse_capability_endpoint_rejects_missing_prefix() {
        let err = parse_capability_endpoint("scp:capability:schema-validation/v1").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
        assert!(err.to_string().contains("scp:capabilities:"));
    }

    #[test]
    fn parse_capability_endpoint_rejects_empty_list() {
        let err = parse_capability_endpoint("scp:capabilities:").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidCapabilities(_)));
    }

    // -----------------------------------------------------------------
    // AC 5: extract_capabilities deduplicates by CapabilityUri equality
    // -----------------------------------------------------------------

    #[test]
    fn extract_capabilities_deduplicates_by_capability_uri() {
        let did = "did:dht:zTestDid";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        // Two services with overlapping capabilities.
        doc.service.push(scp_identity::document::Service {
            id: format!("{did}#scp-capabilities-1"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint:
                "scp:capabilities:scp:capability:schema-validation/v1,scp:capability:rate-limit-compliance/v1"
                    .to_owned(),
        });
        doc.service.push(scp_identity::document::Service {
            id: format!("{did}#scp-capabilities-2"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint:
                "scp:capabilities:scp:capability:rate-limit-compliance/v1,scp:system:relay-operation"
                    .to_owned(),
        });

        let entry = extract_capabilities(did, &doc, &scp_primitives::SystemClock).unwrap();
        // rate-limit-compliance/v1 appears in both but should be deduplicated.
        assert_eq!(entry.capabilities.len(), 3);
        assert_eq!(
            entry.capabilities,
            vec![
                cap("scp:capability:schema-validation/v1"),
                cap("scp:capability:rate-limit-compliance/v1"),
                cap("scp:system:relay-operation"),
            ]
        );
        assert_eq!(entry.service_endpoints.len(), 2);
    }

    // -----------------------------------------------------------------
    // extract_capabilities: basic cases
    // -----------------------------------------------------------------

    #[test]
    fn extract_capabilities_no_service_returns_error() {
        let did = "did:dht:zTestDid";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let err = extract_capabilities(did, &doc, &scp_primitives::SystemClock).unwrap_err();
        assert!(matches!(err, DiscoveryError::NoCapabilitiesService(_)));
    }

    #[test]
    fn extract_capabilities_with_service() {
        let did = "did:dht:zTestDid";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        doc.service.push(scp_identity::document::Service {
            id: format!("{did}#scp-capabilities"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint:
                "scp:capabilities:scp:capability:schema-validation/v1,scp:capability:rate-limit-compliance/v1"
                    .to_owned(),
        });

        let entry = extract_capabilities(did, &doc, &scp_primitives::SystemClock).unwrap();
        assert_eq!(entry.did, did);
        assert_eq!(entry.capabilities.len(), 2);
        assert_eq!(
            entry.capabilities[0],
            cap("scp:capability:schema-validation/v1")
        );
        assert_eq!(
            entry.capabilities[1],
            cap("scp:capability:rate-limit-compliance/v1")
        );
        assert_eq!(entry.service_endpoints.len(), 1);
    }

    // -----------------------------------------------------------------
    // AC 6: resolve_capabilities returns validated CapabilityUri instances
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn resolve_capabilities_end_to_end() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
        let did_dht = create_test_dht(&custody);

        let (did, _doc) = create_identity_with_capabilities(
            &did_dht,
            &custody,
            &pre_rotation_custody,
            &[
                "scp:capability:schema-validation/v1",
                "scp:capability:rate-limit-compliance/v1",
            ],
        )
        .await;

        let entry = resolve_capabilities(&did, &did_dht, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(entry.did, did);
        assert_eq!(entry.capabilities.len(), 2);
        assert_eq!(
            entry.capabilities[0],
            cap("scp:capability:schema-validation/v1")
        );
        assert_eq!(
            entry.capabilities[1],
            cap("scp:capability:rate-limit-compliance/v1")
        );
        assert_eq!(entry.service_endpoints.len(), 1);
        assert!(entry.resolved_at > 0);
    }

    #[tokio::test]
    async fn resolve_capabilities_no_service_returns_error() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
        let did_dht = create_test_dht(&custody);

        // Create identity without SCPCapabilities service.
        let (identity, document, _pre_rotation_handle) = did_dht
            .create(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        did_dht.publish(&identity, &document).await.unwrap();

        let err = resolve_capabilities(&identity.did, &did_dht, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::NoCapabilitiesService(_)));
    }

    #[tokio::test]
    async fn resolve_capabilities_invalid_did_returns_error() {
        let did_dht = DidDht::new();

        let err = resolve_capabilities(
            "did:dht:zInvalidDid",
            &did_dht,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DiscoveryError::DidResolutionFailed(_)));
    }

    // -----------------------------------------------------------------
    // AC 8: Serialization produces URI strings
    // -----------------------------------------------------------------

    #[test]
    fn capability_entry_serializes_uri_strings() {
        let entry = CapabilityEntry {
            did: "did:dht:zTestDid".into(),
            capabilities: vec![
                cap("scp:capability:schema-validation/v1"),
                cap("did:dht:z6Mk123:capability:custom/v1"),
            ],
            service_endpoints: vec!["scp:capabilities:scp:capability:schema-validation/v1".into()],
            resolved_at: 1_700_000_000,
        };

        let json = serde_json::to_value(&entry).unwrap();
        let caps = json["capabilities"].as_array().unwrap();
        assert_eq!(
            caps[0].as_str().unwrap(),
            "scp:capability:schema-validation/v1"
        );
        assert_eq!(
            caps[1].as_str().unwrap(),
            "did:dht:z6Mk123:capability:custom/v1"
        );

        // Round-trip deserialization.
        let deserialized: CapabilityEntry = serde_json::from_value(json).unwrap();
        assert_eq!(entry, deserialized);
    }

    // -----------------------------------------------------------------
    // Mixed URI types in a single endpoint
    // -----------------------------------------------------------------

    #[test]
    fn parse_capability_endpoint_mixed_types() {
        let caps = parse_capability_endpoint(
            "scp:capabilities:scp:capability:schema-validation/v1,did:dht:z6Mk123:capability:custom/v1,scp:system:relay-operation",
        )
        .unwrap();
        assert_eq!(caps.len(), 3);
        assert!(matches!(caps[0], CapabilityUri::Protocol { .. }));
        assert!(matches!(caps[1], CapabilityUri::DidScoped { .. }));
        assert!(matches!(caps[2], CapabilityUri::System { .. }));
    }

    // -----------------------------------------------------------------
    // SCP-ACR-006: System capability declarations in DID documents
    // -----------------------------------------------------------------

    #[test]
    fn parse_capability_endpoint_system_only() {
        let caps = parse_capability_endpoint(
            "scp:capabilities:scp:system:relay-operation,scp:system:bridge-operation",
        )
        .unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], cap("scp:system:relay-operation"));
        assert_eq!(caps[1], cap("scp:system:bridge-operation"));
        assert!(
            caps.iter()
                .all(scp_protocol::trust::capability_uri::CapabilityUri::is_system)
        );
    }

    #[test]
    fn parse_capability_endpoint_all_system_capabilities() {
        let caps = parse_capability_endpoint(
            "scp:capabilities:scp:system:mls-group-management,scp:system:key-rotation,scp:system:governance-participation,scp:system:relay-operation,scp:system:bridge-operation",
        )
        .unwrap();
        assert_eq!(caps.len(), 5);
        assert_eq!(caps[0], cap("scp:system:mls-group-management"));
        assert_eq!(caps[1], cap("scp:system:key-rotation"));
        assert_eq!(caps[2], cap("scp:system:governance-participation"));
        assert_eq!(caps[3], cap("scp:system:relay-operation"));
        assert_eq!(caps[4], cap("scp:system:bridge-operation"));
    }

    #[test]
    fn extract_capabilities_deduplicates_system_across_services() {
        let did = "did:dht:zTestDid";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        // Two services both advertising relay-operation.
        doc.service.push(scp_identity::document::Service {
            id: format!("{did}#scp-capabilities-1"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint:
                "scp:capabilities:scp:system:relay-operation,scp:capability:schema-validation/v1"
                    .to_owned(),
        });
        doc.service.push(scp_identity::document::Service {
            id: format!("{did}#scp-capabilities-2"),
            service_type: SCP_CAPABILITIES_SERVICE_TYPE.to_owned(),
            service_endpoint: "scp:capabilities:scp:system:relay-operation,scp:system:bridge-operation".to_owned(),
        });

        let entry = extract_capabilities(did, &doc, &scp_primitives::SystemClock).unwrap();
        // relay-operation appears in both but should be deduplicated.
        assert_eq!(entry.capabilities.len(), 3);
        assert_eq!(entry.capabilities[0], cap("scp:system:relay-operation"));
        assert_eq!(
            entry.capabilities[1],
            cap("scp:capability:schema-validation/v1")
        );
        assert_eq!(entry.capabilities[2], cap("scp:system:bridge-operation"));
    }

    #[test]
    fn capability_entry_holds_mixed_variants() {
        let entry = CapabilityEntry {
            did: "did:dht:zTestDid".into(),
            capabilities: vec![
                cap("scp:capability:schema-validation/v1"),
                cap("did:dht:z6Mk123:capability:custom/v1"),
                cap("scp:system:relay-operation"),
            ],
            service_endpoints: vec!["scp:capabilities:test".into()],
            resolved_at: 1_700_000_000,
        };

        assert!(entry.capabilities[0].is_protocol());
        assert!(entry.capabilities[1].is_did_scoped());
        assert!(entry.capabilities[2].is_system());

        // Round-trip serialization preserves all variants.
        let json = serde_json::to_value(&entry).unwrap();
        let deserialized: CapabilityEntry = serde_json::from_value(json).unwrap();
        assert_eq!(entry, deserialized);
    }
}
