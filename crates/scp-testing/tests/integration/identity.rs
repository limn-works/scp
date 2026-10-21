#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::clone_on_copy,
    clippy::redundant_clone
)]

//! B2: Identity integration tests.
//!
//! Tests DID creation, DID document construction, agent key management,
//! and `SigningKeyId` variants using real
//! `InMemoryKeyCustody` and `InMemoryDhtClient` implementations.

use scp_did::{DidDocument, SigningKeyId};
use scp_identity::{DidDht, DidMethod, ScpIdentity};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates an identity via `DidDht::create` and returns the identity + document.
async fn create_test_identity(custody: &InMemoryKeyCustody) -> (ScpIdentity, DidDocument) {
    let did_dht = DidDht::with_client(std::sync::Arc::new(scp_dht::InMemoryDhtClient::new()));
    let pre_rotation_custody = scp_platform::testing::InMemoryPreRotationCustody::new();
    let (identity, doc, _pre_rotation_handle) = did_dht
        .create(custody, &pre_rotation_custody)
        .await
        .expect("create identity");
    (identity, doc)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn did_creation() {
    let custody = InMemoryKeyCustody::new();
    let (identity, doc) = create_test_identity(&custody).await;

    // DID string must start with "did:dht:"
    assert!(
        identity.did.starts_with("did:dht:"),
        "DID must start with did:dht:, got: {}",
        identity.did
    );

    // Identity and active keys must be distinct handles.
    assert_ne!(
        identity.identity_key, identity.active_signing_key,
        "identity key and active key must be different handles"
    );

    // Document ID must match the DID string.
    assert_eq!(doc.id, identity.did);

    // Document must have at least #0 and #active verification methods.
    assert!(
        doc.verification_method.len() >= 2,
        "document must have at least identity and active VMs"
    );

    // Public keys must be retrievable.
    let id_pub = custody
        .public_key(&identity.identity_key)
        .await
        .expect("identity public key");
    assert_eq!(id_pub.as_bytes().len(), 32);
}

#[tokio::test]
async fn identity_three_key_construction() {
    let custody = InMemoryKeyCustody::new();
    let (mut identity, _doc) = create_test_identity(&custody).await;

    // Initially no agent key.
    assert!(identity.agent_signing_key.is_none());

    // Generate an agent key and attach it.
    let agent_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate agent key");
    identity.agent_signing_key = Some(agent_key.clone());

    // Now all three keys are present.
    assert!(identity.agent_signing_key.is_some());
    assert_ne!(identity.identity_key, identity.active_signing_key);
    assert_ne!(identity.active_signing_key, agent_key);

    // Each key's public bytes are 32 bytes.
    let pub_id = custody.public_key(&identity.identity_key).await.unwrap();
    let pub_active = custody
        .public_key(&identity.active_signing_key)
        .await
        .unwrap();
    let pub_agent = custody.public_key(&agent_key).await.unwrap();
    assert_eq!(pub_id.as_bytes().len(), 32);
    assert_eq!(pub_active.as_bytes().len(), 32);
    assert_eq!(pub_agent.as_bytes().len(), 32);
}

#[tokio::test]
async fn did_document_without_agent_key() {
    let custody = InMemoryKeyCustody::new();
    let (_identity, doc) = create_test_identity(&custody).await;

    assert!(
        !doc.has_agent_key(),
        "newly created doc must not have an agent key"
    );
}

#[tokio::test]
async fn did_document_with_agent_key() {
    let custody = InMemoryKeyCustody::new();
    let (_identity, mut doc) = create_test_identity(&custody).await;

    // Generate a key and add it as an agent key.
    let agent_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate agent key");
    let agent_pub = custody.public_key(&agent_key).await.unwrap();

    doc.add_agent_key(agent_pub.as_bytes())
        .expect("add agent key");

    assert!(doc.has_agent_key(), "doc must have agent key after add");

    // Verify the #agent VM exists.
    let agent_vm = doc.agent_verification_method();
    assert!(agent_vm.is_some(), "agent VM must be present");
    assert!(agent_vm.unwrap().id.ends_with("#agent"));
}

#[tokio::test]
async fn agent_key_rotation() {
    let custody = InMemoryKeyCustody::new();
    let (_identity, mut doc) = create_test_identity(&custody).await;

    // Add initial agent key.
    let agent_key_1 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pub_1 = custody.public_key(&agent_key_1).await.unwrap();
    doc.add_agent_key(pub_1.as_bytes()).unwrap();

    // Get the initial agent VM multibase.
    let initial_multibase = doc
        .agent_verification_method()
        .unwrap()
        .public_key_multibase
        .clone();

    // Rotate to a new agent key.
    let agent_key_2 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pub_2 = custody.public_key(&agent_key_2).await.unwrap();
    doc.rotate_agent_key(pub_2.as_bytes(), 1).unwrap();

    // The current #agent VM should have the new key.
    let new_multibase = doc
        .agent_verification_method()
        .unwrap()
        .public_key_multibase
        .clone();
    assert_ne!(
        initial_multibase, new_multibase,
        "rotated agent key must differ from the original"
    );

    // The old key should be retired.
    assert_eq!(
        doc.retired_agent_key_count(),
        1,
        "one retired agent key expected after rotation"
    );
}

#[tokio::test]
async fn agent_key_max_retired() {
    let custody = InMemoryKeyCustody::new();
    let (_identity, mut doc) = create_test_identity(&custody).await;

    // Add initial agent key.
    let k0 = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pub_0 = custody.public_key(&k0).await.unwrap();
    doc.add_agent_key(pub_0.as_bytes()).unwrap();

    // Rotate 3 times — max retired is 2, so the oldest should be pruned.
    for seq in 1..=3 {
        let k = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pub_k = custody.public_key(&k).await.unwrap();
        doc.rotate_agent_key(pub_k.as_bytes(), seq).unwrap();
    }

    // MAX_RETIRED_AGENT_KEYS = 2
    assert!(
        doc.retired_agent_key_count() <= 2,
        "retired agent key count must not exceed MAX_RETIRED_AGENT_KEYS (2), got: {}",
        doc.retired_agent_key_count()
    );
}

#[tokio::test]
async fn agent_key_removal() {
    let custody = InMemoryKeyCustody::new();
    let (_identity, mut doc) = create_test_identity(&custody).await;

    let agent_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pub_agent = custody.public_key(&agent_key).await.unwrap();
    doc.add_agent_key(pub_agent.as_bytes()).unwrap();
    assert!(doc.has_agent_key());

    doc.remove_agent_key().unwrap();
    assert!(!doc.has_agent_key(), "agent key must be gone after removal");

    // Removing again should error.
    let err = doc.remove_agent_key();
    assert!(err.is_err(), "removing absent agent key must fail");
}

#[tokio::test]
async fn agent_key_validation() {
    let custody = InMemoryKeyCustody::new();
    let (_identity, doc) = create_test_identity(&custody).await;

    // Valid doc (no agent key) passes validation.
    doc.validate_agent_keys().expect("valid doc should pass");

    // Fabricate a doc with two #agent VMs to trigger validation error.
    let mut bad_doc = doc.clone();
    let fake_vm = scp_did::VerificationMethod {
        id: format!("{}#agent", bad_doc.id),
        method_type: "Ed25519VerificationKey2020".to_owned(),
        controller: bad_doc.id.clone(),
        public_key_multibase: "z11111111111111111111111111111111".to_owned(),
    };
    bad_doc.verification_method.push(fake_vm.clone());
    bad_doc
        .verification_method
        .push(scp_did::VerificationMethod {
            id: format!("{}#agent", bad_doc.id),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: bad_doc.id.clone(),
            public_key_multibase: "z22222222222222222222222222222222".to_owned(),
        });

    let err = bad_doc.validate_agent_keys();
    assert!(
        err.is_err(),
        "doc with multiple #agent VMs must fail validation"
    );
}

#[tokio::test]
async fn signing_key_id_variants() {
    assert_eq!(SigningKeyId::Active.as_fragment(), "#active");
    assert_eq!(SigningKeyId::Agent.as_fragment(), "#agent");

    assert_eq!(SigningKeyId::Active.fragment(), "active");
    assert_eq!(SigningKeyId::Agent.fragment(), "agent");

    // Display.
    assert_eq!(format!("{}", SigningKeyId::Active), "#active");
    assert_eq!(format!("{}", SigningKeyId::Agent), "#agent");

    // Default is Active.
    assert_eq!(SigningKeyId::default(), SigningKeyId::Active);
}
