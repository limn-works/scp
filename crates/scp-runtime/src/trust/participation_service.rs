//! `ParticipationStatements` DID Document Service Endpoint functions (SCP-BA-006).
//!
//! These functions operate on `scp_did::DidDocument` and are
//! located in scp-runtime (not scp-protocol) to avoid pulling scp-identity
//! (and its tokio dependency) into the pure protocol crate.

use scp_did::{DidDocument, Service};
use scp_protocol::trust::participation::PARTICIPATION_STATEMENTS_SERVICE_TYPE;

/// The fragment identifier for participation statements service entries.
const PARTICIPATION_STATEMENTS_FRAGMENT: &str = "participation-statements";

/// Adds a `ScpParticipationStatements` service entry to a DID document.
///
/// The service entry points to the relay endpoint where the agent's signed
/// participation profiles can be fetched by admitting contexts. If a
/// `ScpParticipationStatements` entry already exists, it is replaced.
///
/// # Arguments
///
/// * `document` — The DID document to modify.
/// * `service_endpoint` — The URL where participation profiles are served
///   (e.g., `https://relay.example.com/v1/scp/participation/did:dht:z6Mk...`).
///
/// See §7.3.2.1.
pub fn add_participation_service(document: &mut DidDocument, service_endpoint: &str) {
    // Remove any existing participation statements entry.
    document
        .service
        .retain(|s| s.service_type != PARTICIPATION_STATEMENTS_SERVICE_TYPE);

    let service = Service {
        id: format!("{}#{PARTICIPATION_STATEMENTS_FRAGMENT}", document.id),
        service_type: PARTICIPATION_STATEMENTS_SERVICE_TYPE.to_owned(),
        service_endpoint: service_endpoint.to_owned(),
    };
    document.service.push(service);
}

/// Removes the `ScpParticipationStatements` service entry from a DID document,
/// if present.
pub fn remove_participation_service(document: &mut DidDocument) {
    document
        .service
        .retain(|s| s.service_type != PARTICIPATION_STATEMENTS_SERVICE_TYPE);
}

/// Extracts the `ScpParticipationStatements` service endpoint URL from a
/// resolved DID document.
///
/// Returns `None` if no `ScpParticipationStatements` service entry is found.
///
/// See §7.3.2.1.
#[must_use]
pub fn extract_participation_service_endpoint(document: &DidDocument) -> Option<&str> {
    document
        .service
        .iter()
        .find(|s| s.service_type == PARTICIPATION_STATEMENTS_SERVICE_TYPE)
        .map(|s| s.service_endpoint.as_str())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_test_document(did: &str) -> DidDocument {
        DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32])
    }

    #[test]
    fn add_participation_service_adds_entry() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);
        let endpoint = "https://relay.example.com/v1/scp/participation/did:dht:zTestDid";

        add_participation_service(&mut doc, endpoint);

        let svc = doc
            .service
            .iter()
            .find(|s| s.service_type == PARTICIPATION_STATEMENTS_SERVICE_TYPE)
            .expect("service entry should exist");
        assert_eq!(svc.id, format!("{did}#participation-statements"));
        assert_eq!(svc.service_type, "ScpParticipationStatements");
        assert_eq!(svc.service_endpoint, endpoint);
    }

    #[test]
    fn add_participation_service_replaces_existing() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);

        add_participation_service(&mut doc, "https://old.example.com/v1/scp/participation/did");
        add_participation_service(&mut doc, "https://new.example.com/v1/scp/participation/did");

        let matching: Vec<_> = doc
            .service
            .iter()
            .filter(|s| s.service_type == PARTICIPATION_STATEMENTS_SERVICE_TYPE)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "should have exactly one entry after replacement"
        );
        assert_eq!(
            matching[0].service_endpoint,
            "https://new.example.com/v1/scp/participation/did"
        );
    }

    #[test]
    fn remove_participation_service_removes_entry() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);

        add_participation_service(
            &mut doc,
            "https://relay.example.com/v1/scp/participation/did",
        );
        assert!(extract_participation_service_endpoint(&doc).is_some());

        remove_participation_service(&mut doc);
        assert!(extract_participation_service_endpoint(&doc).is_none());
    }

    #[test]
    fn extract_participation_service_endpoint_returns_none_when_absent() {
        let doc = make_test_document("did:dht:zTestDid");
        assert!(extract_participation_service_endpoint(&doc).is_none());
    }

    #[test]
    fn extract_participation_service_endpoint_returns_url_when_present() {
        let mut doc = make_test_document("did:dht:zTestDid");
        let endpoint = "https://relay.example.com/v1/scp/participation/did:dht:zTestDid";
        add_participation_service(&mut doc, endpoint);

        let result = extract_participation_service_endpoint(&doc);
        assert_eq!(result, Some(endpoint));
    }

    #[test]
    fn participation_service_serde_roundtrip() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);
        let endpoint = "https://relay.example.com/v1/scp/participation/did:dht:zTestDid";
        add_participation_service(&mut doc, endpoint);

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: DidDocument = serde_json::from_str(&json).unwrap();

        let result = extract_participation_service_endpoint(&deserialized);
        assert_eq!(result, Some(endpoint));
    }

    #[test]
    fn participation_service_does_not_affect_other_services() {
        let did = "did:dht:zTestDid";
        let mut doc = make_test_document(did);

        // Document starts with pre-rotation service.
        let initial_count = doc.service.len();

        add_participation_service(
            &mut doc,
            "https://relay.example.com/v1/scp/participation/did",
        );
        assert_eq!(doc.service.len(), initial_count + 1);

        remove_participation_service(&mut doc);
        assert_eq!(doc.service.len(), initial_count);

        // Original services should still be intact.
        assert!(doc.pre_rotation_service().is_some());
    }
}
