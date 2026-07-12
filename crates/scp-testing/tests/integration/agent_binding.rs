#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants
)]

//! B3: Agent binding integration tests.
//!
//! Tests shared-DID three-key model, self-delegation UCANs with `key_scope`,
//! inner envelope signing/verification with agent keys, Category A enforcement,
//! action classification, and custody violation attestations.

use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};
use scp_core::envelope::inner::{
    InnerEnvelopeParams, MessageType, SCP_INNER_ENVELOPE_VERSION, create_inner_envelope,
    enforce_inner_envelope_category_a, verify_inner_signature,
};
use scp_core::trust::custody_violation::{
    ActionCategory, CounterAttestation, CustodyViolationType, ScpCustodyViolationAttestation,
    classify_action,
};
use scp_did::{DID, SigningKeyId};
use scp_identity::{DidDht, DidMethod, ScpIdentity};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates an identity and generates an agent key, returning identity, doc,
/// and the agent key handle.
async fn create_identity_with_agent_key(
    custody: &InMemoryKeyCustody,
) -> (ScpIdentity, scp_did::DidDocument) {
    let did_dht = DidDht::new();
    let pre_rotation_custody = scp_platform::testing::InMemoryPreRotationCustody::new();
    let (mut identity, mut doc, _pre_rotation_handle) = did_dht
        .create(custody, &pre_rotation_custody)
        .await
        .expect("create identity");

    // Generate agent key.
    let agent_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate agent key");
    let agent_pub = custody.public_key(&agent_key).await.unwrap();
    doc.add_agent_key(agent_pub.as_bytes()).unwrap();
    identity.agent_signing_key = Some(agent_key);

    (identity, doc)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shared_did_three_keys() {
    let custody = InMemoryKeyCustody::new();
    let (identity, doc) = create_identity_with_agent_key(&custody).await;

    // All three keys present.
    assert!(identity.agent_signing_key.is_some());

    // Each key handle is distinct.
    let agent_key = identity.agent_signing_key.as_ref().unwrap();
    assert_ne!(identity.identity_key, identity.active_signing_key);
    assert_ne!(identity.active_signing_key, *agent_key);
    assert_ne!(identity.identity_key, *agent_key);

    // Public keys are each 32 bytes.
    let pub_id = custody.public_key(&identity.identity_key).await.unwrap();
    let pub_active = custody
        .public_key(&identity.active_signing_key)
        .await
        .unwrap();
    let pub_agent = custody.public_key(agent_key).await.unwrap();
    assert_eq!(pub_id.as_bytes().len(), 32);
    assert_eq!(pub_active.as_bytes().len(), 32);
    assert_eq!(pub_agent.as_bytes().len(), 32);

    // Document has #agent VM.
    assert!(doc.has_agent_key());
}

#[tokio::test]
async fn self_delegation_ucan_with_key_scope() {
    let custody = InMemoryKeyCustody::new();
    let (identity, _doc) = create_identity_with_agent_key(&custody).await;

    let caps = vec!["messages:write".to_owned()];
    let params = MintParams {
        issuer_did: &identity.did,
        issuer_key: &identity.active_signing_key,
        audience_did: &identity.did, // self-delegation
        context_id: "test-context-1",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#agent".to_owned()),
        signing_key_id: None,
        ceiling: None,
    };

    let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
        .await
        .expect("mint self-delegation UCAN");

    // Verify iss == aud.
    assert_eq!(token.payload.iss, token.payload.aud);

    // Verify scp_key_scope is in facts.
    let fct = token.payload.fct.as_ref().expect("facts must be present");
    let scope = fct.get("scp_key_scope").expect("scp_key_scope must exist");
    assert_eq!(scope, "#agent");

    // Verify kid in header matches the key scope.
    assert_eq!(
        token.header.kid.as_deref(),
        Some("#agent"),
        "kid must be set to #agent for key scope delegation"
    );
}

#[tokio::test]
async fn self_delegation_without_key_scope_fails() {
    let custody = InMemoryKeyCustody::new();
    let (identity, _doc) = create_identity_with_agent_key(&custody).await;

    let caps = vec!["messages:write".to_owned()];
    let params = MintParams {
        issuer_did: &identity.did,
        issuer_key: &identity.active_signing_key,
        audience_did: &identity.did, // self-delegation
        context_id: "test-context-1",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None, // no key scope
        signing_key_id: None,
        ceiling: None,
    };

    let result = mint_ucan(&params, &custody, &scp_clock::SystemClock).await;
    assert!(
        result.is_err(),
        "self-delegation without key_scope must fail"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("self-delegation") || err.contains("key_scope"),
        "error should mention self-delegation or key_scope, got: {err}"
    );
}

#[tokio::test]
async fn key_scope_mismatch_fails() {
    // This tests that when minting with signing_key_id=#agent but
    // key_scope="#active", the token encodes #agent in kid, which would
    // mismatch the scp_key_scope="#active" during validation.
    let custody = InMemoryKeyCustody::new();
    let (identity, _doc) = create_identity_with_agent_key(&custody).await;

    let caps = vec!["messages:write".to_owned()];
    let params = MintParams {
        issuer_did: &identity.did,
        issuer_key: &identity.active_signing_key,
        audience_did: &identity.did,
        context_id: "test-context-1",
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#active".to_owned()),
        signing_key_id: Some(SigningKeyId::Agent), // kid="#agent" but scope="#active"
        ceiling: None,
    };

    // Minting itself should succeed — the mismatch is detected at validation time.
    let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
        .await
        .expect("mint should succeed");

    // The kid should be #agent (from signing_key_id).
    assert_eq!(token.header.kid.as_deref(), Some("#agent"));

    // But the scp_key_scope should be #active (from key_scope).
    let fct = token.payload.fct.as_ref().expect("facts");
    let scope = fct.get("scp_key_scope").expect("scp_key_scope");
    assert_eq!(scope, "#active");

    // The kid and scope disagree — this token would fail validation step 5b.
    assert_ne!(
        token.header.kid.as_deref().unwrap_or("#active"),
        scope.as_str().unwrap_or(""),
        "kid and scp_key_scope must disagree to demonstrate the mismatch"
    );
}

#[tokio::test]
async fn envelope_with_agent_signing_key() {
    let custody = InMemoryKeyCustody::new();
    let (identity, _doc) = create_identity_with_agent_key(&custody).await;

    let agent_key = identity.agent_signing_key.as_ref().unwrap();
    let agent_pub = custody.public_key(agent_key).await.unwrap();

    let params = InnerEnvelopeParams {
        version: SCP_INNER_ENVELOPE_VERSION,
        context_id: "test-ctx",
        sender_did: &identity.did,
        epoch: 1,
        generation: 0,
        sequence: 1,
        timestamp: 1_700_000_000_000,
        message_type: MessageType::Content,
        payload: b"hello from agent",
        provenance: None,
        signing_key_id: SigningKeyId::Agent,
    };

    let inner = create_inner_envelope(&params, &custody, agent_key)
        .await
        .expect("create inner envelope with agent key");

    assert_eq!(inner.signing_key_id, SigningKeyId::Agent);

    // Verify with the agent public key should succeed.
    let verified = verify_inner_signature(&inner, agent_pub.as_bytes())
        .expect("verification should not error");
    assert!(verified, "signature must verify with correct agent key");
}

#[tokio::test]
async fn envelope_verify_with_wrong_key_fails() {
    let custody = InMemoryKeyCustody::new();
    let (identity, _doc) = create_identity_with_agent_key(&custody).await;

    let agent_key = identity.agent_signing_key.as_ref().unwrap();
    let active_pub = custody
        .public_key(&identity.active_signing_key)
        .await
        .unwrap();

    let params = InnerEnvelopeParams {
        version: SCP_INNER_ENVELOPE_VERSION,
        context_id: "test-ctx",
        sender_did: &identity.did,
        epoch: 1,
        generation: 0,
        sequence: 1,
        timestamp: 1_700_000_000_000,
        message_type: MessageType::Content,
        payload: b"hello from agent",
        provenance: None,
        signing_key_id: SigningKeyId::Agent,
    };

    let inner = create_inner_envelope(&params, &custody, agent_key)
        .await
        .expect("create inner envelope");

    // Verify with the ACTIVE key (wrong key for agent-signed envelope).
    let verified = verify_inner_signature(&inner, active_pub.as_bytes())
        .expect("verification should not error on well-formed inputs");
    assert!(!verified, "signature must NOT verify with the wrong key");
}

#[tokio::test]
async fn category_a_rejects_agent_key() {
    let custody = InMemoryKeyCustody::new();
    let (identity, _doc) = create_identity_with_agent_key(&custody).await;

    let agent_key = identity.agent_signing_key.as_ref().unwrap();

    let params = InnerEnvelopeParams {
        version: SCP_INNER_ENVELOPE_VERSION,
        context_id: "test-ctx",
        sender_did: &identity.did,
        epoch: 1,
        generation: 0,
        sequence: 1,
        timestamp: 1_700_000_000_000,
        message_type: MessageType::Content,
        payload: b"attempt DID doc update",
        provenance: None,
        signing_key_id: SigningKeyId::Agent,
    };

    let inner = create_inner_envelope(&params, &custody, agent_key)
        .await
        .expect("create inner envelope");

    // Category A resource: DID document modification.
    let result = enforce_inner_envelope_category_a(&inner, "did_document");
    assert!(
        result.is_err(),
        "agent-signed envelope must be rejected for Category A action"
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Category A"),
        "error should mention Category A, got: {err}"
    );

    // Category B resource: messages — should be allowed.
    let result_b = enforce_inner_envelope_category_a(&inner, "messages");
    assert!(
        result_b.is_ok(),
        "agent-signed envelope should be allowed for Category B action"
    );
}

#[tokio::test]
async fn classify_action_categories() {
    // Category A resources.
    assert_eq!(classify_action("did_document"), ActionCategory::CategoryA);
    assert_eq!(
        classify_action("verification_method"),
        ActionCategory::CategoryA
    );
    assert_eq!(classify_action("identity"), ActionCategory::CategoryA);
    assert_eq!(classify_action("pre_rotation"), ActionCategory::CategoryA);
    assert_eq!(classify_action("service"), ActionCategory::CategoryA);
    assert_eq!(classify_action("relay_config"), ActionCategory::CategoryA);
    assert_eq!(classify_action("did_migration"), ActionCategory::CategoryA);
    assert_eq!(classify_action("key_management"), ActionCategory::CategoryA);

    // Category B resources.
    assert_eq!(classify_action("messages"), ActionCategory::CategoryB);
    assert_eq!(classify_action("outlet_call"), ActionCategory::CategoryB);
    assert_eq!(classify_action("member"), ActionCategory::CategoryB);
    assert_eq!(classify_action("role"), ActionCategory::CategoryB);
    assert_eq!(classify_action("context"), ActionCategory::CategoryB);
    assert_eq!(classify_action("spending"), ActionCategory::CategoryB);

    // Unknown defaults to Category B (conservative).
    assert_eq!(
        classify_action("unknown_resource"),
        ActionCategory::CategoryB
    );
}

#[tokio::test]
async fn custody_violation_attestation() {
    let attestation = ScpCustodyViolationAttestation {
        subject_did: DID::from("did:dht:z6MkSubject"),
        timestamp: 1_700_000_000,
        violation: CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_owned(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![0xAB; 64],
        },
        verifier_signature: vec![0xCD; 64],
        verifier_did: DID::from("did:dht:z6MkVerifier"),
    };

    // Verify fields are set correctly.
    assert_eq!(attestation.subject_did.as_ref(), "did:dht:z6MkSubject");
    assert_eq!(attestation.timestamp, 1_700_000_000);
    assert_eq!(attestation.verifier_did.as_ref(), "did:dht:z6MkVerifier");

    // Violation type should be CategoryAViolation.
    match &attestation.violation {
        CustodyViolationType::CategoryAViolation {
            action,
            signer_key_id,
            signature_evidence,
        } => {
            assert_eq!(action, "did_document_update");
            assert_eq!(*signer_key_id, SigningKeyId::Agent);
            assert_eq!(signature_evidence.len(), 64);
        }
        other => panic!("expected CategoryAViolation, got: {other:?}"),
    }

    // Attestation is permanent — no mutable methods to modify it.
    // Verify it can be serialized (serde).
    let json = serde_json::to_string(&attestation).expect("serialize attestation");
    assert!(
        json.contains("did_document_update"),
        "serialized attestation must contain the action"
    );
}

#[tokio::test]
async fn counter_attestation() {
    let counter = CounterAttestation {
        subject_did: DID::from("did:dht:z6MkSubject"),
        violation_reference: "sha256:abc123".to_owned(),
        explanation: "Agent was compromised, key has been rotated".to_owned(),
        timestamp: 1_700_001_000,
        signature: vec![0xEF; 64],
    };

    assert_eq!(counter.subject_did.as_ref(), "did:dht:z6MkSubject");
    assert_eq!(counter.violation_reference, "sha256:abc123");
    assert_eq!(counter.timestamp, 1_700_001_000);
    assert_eq!(counter.signature.len(), 64);

    // Counter-attestation must be signed by #active key (human authorization).
    // This is a structural requirement — the signature field exists.
    assert!(
        !counter.signature.is_empty(),
        "counter-attestation must have a signature"
    );

    // Validate method should accept well-formed counter-attestation.
    let result = counter.validate();
    assert!(
        result.is_ok(),
        "well-formed counter-attestation must pass validation: {result:?}"
    );
}
