//! Operator-supplied bridge admission records (spec §12.10.6 step 1).
//!
//! Spec §12.2.1 gates bridge registration behind a `RegisterBridge` governance
//! proposal, and §12.10.6 step 1 makes a bridge node store that approval before
//! any platform can reach it. A node holding no such record answers
//! `BRIDGE_NOT_AUTHORIZED` (401) to every request naming that bridge, so
//! admission is what turns an approved registration into a reachable bridge.
//!
//! This module carries that approval across a process boundary. A bridge
//! operator writes what governance approved into a JSON file, points a node at
//! it, and the node admits every record it holds at startup.
//!
//! # What a node trusts here
//!
//! A record is what its operator asserts governance approved. This node runs no
//! Merkle-inclusion check against a context's `BridgeRegistered` event, so an
//! operator who writes a record governance never approved gets a bridge on
//! their own node. Every context member still sees that bridge only if the
//! context's own registry lists it (§12.2.1 step 4), so a fabricated record
//! reaches no context — it reaches one operator's own endpoints.

use std::path::Path;

use scp_core::bridge::registration::{
    ApprovedRegistration, BridgeRegistrationRequest, BridgeRegistry, approve_registration,
    register_bridge,
};
use scp_did::{DID, DidDocument};
use serde::{Deserialize, Serialize};

/// Errors reading or rebuilding an operator-supplied admission record.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionRecordError {
    /// Reading the file failed.
    #[error("cannot read bridge admission file {path}: {source}")]
    Read {
        /// The path a node tried to read.
        path: String,
        /// What the filesystem reported.
        source: std::io::Error,
    },

    /// The file does not parse as a list of admission records.
    #[error("bridge admission file {path} does not parse: {source}")]
    Parse {
        /// The path a node tried to parse.
        path: String,
        /// What the JSON parser reported.
        source: serde_json::Error,
    },

    /// Governance approval failed for a record's own registration payload.
    #[error("bridge admission record for {bridge_id} does not re-approve: {reason}")]
    Approval {
        /// The bridge that record names.
        bridge_id: String,
        /// Why `register_bridge` or `approve_registration` rejected it.
        reason: String,
    },
}

/// One governance-approved registration, as an operator hands it to a node.
///
/// A node rebuilds an [`ApprovedRegistration`] from these fields by running
/// `scp_protocol` `register_bridge` and `approve_registration` over a registry
/// scoped to `request.context_id`, so every §12.2.1 rule those two functions
/// enforce — a derived bridge id, cooperative-mode key material, an approver
/// distinct from an operator — applies to a record before a node stores it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAdmissionRecord {
    /// The `RegisterBridge` payload governance approved (spec §12.2.1).
    pub request: BridgeRegistrationRequest,

    /// The DID of the governance actor that approved it.
    pub governance_did: DID,

    /// Unix timestamp (seconds) of that approval.
    pub approved_at: u64,

    /// The operator's DID document, which §12.10.2 bearer-token verification
    /// resolves a JWT `iss` against.
    pub operator_document: DidDocument,
}

impl BridgeAdmissionRecord {
    /// Rebuilds the [`ApprovedRegistration`] a node admits.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRecordError::Approval`] when `register_bridge` or
    /// `approve_registration` rejects this record's payload.
    pub fn rebuild_approval(&self) -> Result<ApprovedRegistration, AdmissionRecordError> {
        let mut registry = BridgeRegistry::new(self.request.context_id.clone());
        register_bridge(&mut registry, self.request.clone()).map_err(|e| {
            AdmissionRecordError::Approval {
                bridge_id: self.request.bridge_id.clone(),
                reason: e.to_string(),
            }
        })?;
        approve_registration(
            &mut registry,
            &self.request.bridge_id,
            &self.governance_did,
            self.approved_at,
        )
        .map(|(approved, _event)| approved)
        .map_err(|e| AdmissionRecordError::Approval {
            bridge_id: self.request.bridge_id.clone(),
            reason: e.to_string(),
        })
    }
}

/// Reads a JSON array of admission records from `path`.
///
/// # Errors
///
/// Returns [`AdmissionRecordError::Read`] when the file cannot be read and
/// [`AdmissionRecordError::Parse`] when it does not parse.
pub fn load_admission_records(
    path: &Path,
) -> Result<Vec<BridgeAdmissionRecord>, AdmissionRecordError> {
    let text = std::fs::read_to_string(path).map_err(|source| AdmissionRecordError::Read {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| AdmissionRecordError::Parse {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use scp_core::bridge::BridgeMode;
    use scp_core::bridge::registration::{BridgeRegistrationMetadata, derive_bridge_id};
    use scp_did::VerificationMethod;

    fn operator_document(did: &str) -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#active"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_multibase: "z6MkTestKeyMaterial".to_owned(),
            }],
            authentication: vec![format!("{did}#active")],
            assertion_method: vec![format!("{did}#active")],
            service: vec![],
            also_known_as: Vec::new(),
        }
    }

    fn record(operator: &str, context: &str) -> BridgeAdmissionRecord {
        let requested_at = 1_700_000_000;
        BridgeAdmissionRecord {
            request: BridgeRegistrationRequest {
                bridge_id: derive_bridge_id(context, operator, "discord", requested_at),
                operator_did: operator.into(),
                platform: "discord".to_owned(),
                mode: BridgeMode::Cooperative,
                context_id: context.to_owned(),
                requested_at,
                self_hosted: false,
                webhook_url: Some("https://platform.example.com/hooks".to_owned()),
                platform_key: Some([9_u8; 32]),
                platform_key_id: Some("pk-1".to_owned()),
                max_shadows: 50,
                metadata: BridgeRegistrationMetadata::default(),
            },
            governance_did: "did:dht:z6MkGovernance".into(),
            approved_at: 1_700_000_100,
            operator_document: operator_document(operator),
        }
    }

    #[test]
    fn a_record_rebuilds_the_approval_a_node_admits() {
        let rec = record("did:dht:z6MkOperator", "ctx-1");

        let approved = rec.rebuild_approval().unwrap();

        assert_eq!(approved.connector().bridge_id, rec.request.bridge_id);
        assert_eq!(approved.connector().registration_context, "ctx-1");
        assert_eq!(approved.connector().max_shadows, 50);
        assert_eq!(approved.request().platform_key_id.as_deref(), Some("pk-1"));
    }

    #[test]
    fn a_record_whose_governance_did_equals_its_operator_is_rejected() {
        let mut rec = record("did:dht:z6MkOperator", "ctx-1");
        rec.governance_did = rec.request.operator_did.clone();

        let err = rec.rebuild_approval().unwrap_err();

        assert!(
            matches!(err, AdmissionRecordError::Approval { .. }),
            "expected Approval, got {err}"
        );
    }

    #[test]
    fn a_record_carrying_an_underived_bridge_id_is_rejected() {
        let mut rec = record("did:dht:z6MkOperator", "ctx-1");
        rec.request.bridge_id = "bridge-chosen-by-hand".to_owned();

        let err = rec.rebuild_approval().unwrap_err();

        assert!(
            matches!(err, AdmissionRecordError::Approval { ref reason, .. }
                if reason.contains("not derived")),
            "expected a derivation rejection, got {err}"
        );
    }

    #[test]
    fn a_record_round_trips_through_json() {
        let rec = record("did:dht:z6MkOperator", "ctx-1");
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            serde_json::to_string(&vec![rec.clone()]).unwrap(),
        )
        .unwrap();

        let loaded = load_admission_records(file.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].request.bridge_id, rec.request.bridge_id);
        assert_eq!(loaded[0].approved_at, rec.approved_at);
    }

    #[test]
    fn a_missing_file_reports_a_read_failure() {
        let err = load_admission_records(Path::new("/nonexistent/bridges.json")).unwrap_err();

        assert!(
            matches!(err, AdmissionRecordError::Read { .. }),
            "expected Read, got {err}"
        );
    }
}
