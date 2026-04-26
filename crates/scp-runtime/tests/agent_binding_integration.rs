#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unused_async,
    clippy::redundant_field_names
)]
//! End-to-end integration test for shared-DID agent binding (ADR-039).
//!
//! Exercises the full agent binding flow:
//!
//! 1. Create a shared-DID identity with human (#active) and agent (#agent) keys.
//! 2. Attach a custody attestation declaring key custody models.
//! 3. Mint a scoped UCAN with `#agent` key scope (self-delegation).
//! 4. Create an `ScpCredential` with `SigningKeyId::Agent`.
//! 5. Create and verify an inner envelope signed by the agent key.
//! 6. Enforce Category A restriction (agent key rejected for DID doc mods).
//! 7. Verify Category B actions succeed for agent keys.
//! 8. Construct a counter-attestation for reputation restoration.
//!
//! Story: SCP-AB-021. See ADR-039 in `.docs/adrs/phase-1.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::Signer;

use scp_identity::attestation::{KeyCustodyModel, Platform, ScpKeyCustodyAttestation};
use scp_identity::document::DidDocument;
use scp_identity::{DID, SigningKeyId};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};
use scp_protocol::envelope::inner::{
    InnerEnvelopeParams, MessageType, Provenance, verify_inner_signature,
};
use scp_protocol::trust::{
    ActionCategory, CounterAttestation, CustodyViolationType, ScpCustodyViolationAttestation,
    classify_action, enforce_category_a,
};
use scp_runtime::crypto::mls::credential::ScpCredential;
use scp_runtime::crypto::ucan::mint::{MintParams, mint_ucan};
use scp_runtime::envelope::inner::sign::create_inner_envelope;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates an Ed25519 keypair and returns (`verifying_key`, `signing_key`).
fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key, signing_key)
}

/// Decodes a multibase-encoded public key (z-prefixed base58btc) to raw bytes.
fn decode_multibase_key(multibase: &str) -> Vec<u8> {
    let encoded = multibase
        .strip_prefix('z')
        .expect("multibase key must start with 'z' (base58btc)");
    bs58::decode(encoded)
        .into_vec()
        .expect("valid base58btc encoding")
}

/// Builds a test DID string from a verifying key.
fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    // Use z-base-32 encoding to match did:dht format requirement (starts with "did:dht:z").
    let zbase32 = zbase32::encode(verifying_key.as_bytes());
    format!("did:dht:z{zbase32}")
}

// ---------------------------------------------------------------------------
// Full end-to-end flow
// ---------------------------------------------------------------------------

/// Full agent binding flow: identity creation, attestation, UCAN delegation,
/// credential, inner envelope signing, and Category A enforcement.
#[tokio::test]
async fn test_agent_binding_full_flow() {
    // -----------------------------------------------------------------------
    // Step 1: Create shared-DID identity with human and agent keys
    // -----------------------------------------------------------------------

    let (identity_vk, _identity_sk) = test_keypair();
    let (active_vk, active_sk) = test_keypair();
    let (agent_vk, _agent_sk) = test_keypair();

    let did = did_from_pubkey(&identity_vk);

    // Pre-rotation commitment (SHA-256 of next identity key — use random bytes for test).
    let pre_rotation_commitment: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let (next_vk, _) = test_keypair();
        Sha256::digest(next_vk.as_bytes()).into()
    };

    let mut doc = DidDocument::new_with_agent_key(
        &did,
        identity_vk.as_bytes(),
        active_vk.as_bytes(),
        &pre_rotation_commitment,
        Some(agent_vk.as_bytes()),
    );

    // Verify document has all three verification methods.
    assert!(
        doc.verification_method_by_fragment("0").is_some(),
        "DID document must have #0 (Identity Key)"
    );
    assert!(
        doc.verification_method_by_fragment("active").is_some(),
        "DID document must have #active (Active Signing Key)"
    );
    assert!(
        doc.agent_verification_method().is_some(),
        "DID document must have #agent (Agent Signing Key)"
    );

    // Verify the public keys round-trip correctly through multibase encoding.
    let agent_vm = doc.agent_verification_method().unwrap();
    let decoded_agent_pk = decode_multibase_key(&agent_vm.public_key_multibase);
    assert_eq!(
        decoded_agent_pk,
        agent_vk.as_bytes(),
        "Agent public key must survive multibase round-trip"
    );

    // -----------------------------------------------------------------------
    // Step 2: Attach custody attestation
    // -----------------------------------------------------------------------

    let attestation = ScpKeyCustodyAttestation {
        active_key_custody: KeyCustodyModel::HardwareBiometric,
        agent_key_custody: Some(KeyCustodyModel::Software),
        platform: Platform::Ios,
        platform_attestation: None,
        created_at: 1_700_000_000,
    };

    doc.set_custody_attestation(&attestation)
        .expect("setting custody attestation must succeed");

    // Verify the attestation service entry was added.
    let service = doc
        .service
        .iter()
        .find(|s| s.service_type == "ScpKeyCustodyAttestation")
        .expect("custody attestation service entry must exist");
    assert!(
        !service.service_endpoint.is_empty(),
        "service endpoint must contain serialized attestation"
    );

    // -----------------------------------------------------------------------
    // Step 3: Mint scoped UCAN with #agent key scope (self-delegation)
    // -----------------------------------------------------------------------

    let custody = InMemoryKeyCustody::new();
    let active_handle = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate active keypair");

    // For the UCAN test we use the InMemoryKeyCustody signer.
    // The issuer == audience (self-delegation) with key_scope = "#agent".
    let capabilities = vec![
        "messages:write".to_owned(),
        "outlet_call:assistant".to_owned(),
    ];

    let ucan_token = mint_ucan(
        &MintParams {
            issuer_did: &did,
            issuer_key: &active_handle,
            audience_did: &did, // self-delegation
            context_id: "ctx:test-context-001",
            capabilities: &capabilities,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: Some(SigningKeyId::Active),
            ceiling: None,
            caveats: None,
        },
        &custody,
        &scp_primitives::SystemClock,
    )
    .await
    .expect("minting scoped UCAN must succeed");

    // Verify the token is non-empty and has three JWT segments.
    let jwt_segments: Vec<&str> = ucan_token.encoded.split('.').collect();
    assert_eq!(
        jwt_segments.len(),
        3,
        "UCAN token must have header.payload.signature"
    );

    // Decode the header and verify kid is set.
    let header_json: serde_json::Value = {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header_bytes = URL_SAFE_NO_PAD
            .decode(jwt_segments[0])
            .expect("base64url decode header");
        serde_json::from_slice(&header_bytes).expect("parse header JSON")
    };
    assert_eq!(
        header_json.get("kid").and_then(|v| v.as_str()),
        Some("#active"),
        "JWT header kid must be #active (the signing key)"
    );

    // Decode the payload and verify scp_key_scope fact.
    let payload_json: serde_json::Value = {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(jwt_segments[1])
            .expect("base64url decode payload");
        serde_json::from_slice(&payload_bytes).expect("parse payload JSON")
    };
    assert_eq!(
        payload_json.get("iss").and_then(|v| v.as_str()),
        Some(did.as_str()),
        "issuer must be the shared DID"
    );
    assert_eq!(
        payload_json.get("aud").and_then(|v| v.as_str()),
        Some(did.as_str()),
        "audience must be the same DID (self-delegation)"
    );
    let fct = payload_json
        .get("fct")
        .expect("payload must have fct section");
    assert_eq!(
        fct.get("scp_key_scope").and_then(|v| v.as_str()),
        Some("#agent"),
        "fct.scp_key_scope must be #agent"
    );

    // -----------------------------------------------------------------------
    // Step 4: Create ScpCredential with SigningKeyId::Agent
    // -----------------------------------------------------------------------

    let credential = ScpCredential::new(
        did.clone(),
        Some(ucan_token.encoded.clone()),
        SigningKeyId::Agent,
    )
    .expect("creating ScpCredential with Agent signing key must succeed");

    assert_eq!(credential.did, did);
    assert_eq!(credential.signing_key_id, SigningKeyId::Agent);
    assert!(credential.ucan_token.is_some());

    // Verify MessagePack round-trip preserves signing_key_id.
    let serialized = credential.to_bytes().expect("serialize credential");
    let deserialized = ScpCredential::from_bytes(&serialized).expect("deserialize credential");
    assert_eq!(
        deserialized.signing_key_id,
        SigningKeyId::Agent,
        "signing_key_id must survive MessagePack round-trip"
    );

    // -----------------------------------------------------------------------
    // Step 5: Create and verify inner envelope signed by agent key
    // -----------------------------------------------------------------------

    let agent_handle = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate agent keypair");

    let agent_pubkey = custody
        .public_key(&agent_handle)
        .await
        .expect("get agent public key");

    let payload = b"Hello from agent!";
    let params = InnerEnvelopeParams {
        version: scp_protocol::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
        context_id: "ctx:test-context-001",
        sender_did: &did,
        epoch: 1,
        generation: 0,
        sequence: 42,
        timestamp: 1_700_000_000_000,
        message_type: MessageType::Content,
        payload,
        provenance: Some(Provenance {
            source: "agent-assistant".to_owned(),
            upstream_hash: None,
        }),
        signing_key_id: SigningKeyId::Agent,
    };

    let envelope = create_inner_envelope(&params, &custody, &agent_handle)
        .await
        .expect("creating inner envelope with agent key must succeed");

    // Verify envelope fields.
    assert_eq!(envelope.signing_key_id, SigningKeyId::Agent);
    assert_eq!(envelope.sender_did, did);
    assert_eq!(envelope.context_id, "ctx:test-context-001");
    assert_eq!(envelope.sequence, 42);

    // Verify signature using the agent's public key.
    let sig_valid = verify_inner_signature(&envelope, agent_pubkey.as_bytes())
        .expect("signature verification must not error");
    assert!(
        sig_valid,
        "inner envelope signature must verify with agent public key"
    );

    // Verify signature fails with wrong key (active key).
    let active_pubkey = custody
        .public_key(&active_handle)
        .await
        .expect("get active public key");
    let sig_wrong_key = verify_inner_signature(&envelope, active_pubkey.as_bytes())
        .expect("verification with wrong key must not error");
    assert!(
        !sig_wrong_key,
        "inner envelope must NOT verify with a different key"
    );

    // -----------------------------------------------------------------------
    // Step 6: Category A enforcement — agent key rejected
    // -----------------------------------------------------------------------

    let category = classify_action("did_document");
    assert_eq!(category, ActionCategory::CategoryA);

    let result = enforce_category_a(
        SigningKeyId::Agent,
        category,
        &did,
        "did_document_update",
        &[0u8; 64], // evidence signature placeholder
    );
    assert!(
        result.is_err(),
        "agent key must be rejected for Category A action"
    );

    let violation = result.unwrap_err();
    assert_eq!(violation.signing_key_id, SigningKeyId::Agent);
    assert_eq!(violation.violator_did, did);
    assert!(violation.attempted_action.contains("did_document_update"));

    // Active key must succeed for Category A.
    let active_result = enforce_category_a(
        SigningKeyId::Active,
        category,
        &did,
        "did_document_update",
        &[0u8; 64],
    );
    assert!(
        active_result.is_ok(),
        "active key must be permitted for Category A action"
    );

    // -----------------------------------------------------------------------
    // Step 7: Category B — agent key permitted
    // -----------------------------------------------------------------------

    let category_b = classify_action("messages");
    assert_eq!(category_b, ActionCategory::CategoryB);

    let agent_b_result = enforce_category_a(
        SigningKeyId::Agent,
        category_b,
        &did,
        "messages_write",
        &[0u8; 64],
    );
    assert!(
        agent_b_result.is_ok(),
        "agent key must be permitted for Category B action"
    );

    // -----------------------------------------------------------------------
    // Step 8: Counter-attestation for reputation restoration
    // -----------------------------------------------------------------------

    let counter = CounterAttestation {
        subject_did: DID(did.clone()),
        violation_reference: "sha256:abc123def456".to_owned(),
        explanation: "Agent key was compromised; key has been rotated.".to_owned(),
        timestamp: 1_700_001_000,
        signature: active_sk
            .sign(b"counter-attestation-payload")
            .to_bytes()
            .to_vec(),
    };

    assert!(
        counter.validate().is_ok(),
        "counter-attestation with valid fields must pass validation"
    );
}

// ---------------------------------------------------------------------------
// Permission category tests
// ---------------------------------------------------------------------------

/// Category A actions must be rejected when signed by agent key.
#[test]
fn test_category_a_rejection_all_resources() {
    let did = "did:dht:z6MkTestCategoryA";
    let category_a_resources = [
        "did_document",
        "verification_method",
        "identity",
        "pre_rotation",
        "service",
        "relay_config",
        "did_migration",
        "key_management",
    ];

    for resource in &category_a_resources {
        let category = classify_action(resource);
        assert_eq!(
            category,
            ActionCategory::CategoryA,
            "resource '{resource}' must be classified as Category A"
        );

        let result = enforce_category_a(
            SigningKeyId::Agent,
            category,
            did,
            &format!("{resource}_update"),
            &[0u8; 64],
        );
        assert!(
            result.is_err(),
            "agent key must be rejected for Category A resource '{resource}'"
        );

        let violation = result.unwrap_err();
        assert_eq!(violation.signing_key_id, SigningKeyId::Agent);
        assert_eq!(violation.violator_did, did);
    }
}

/// Category B actions must be accepted for both agent and active keys.
#[test]
fn test_category_b_acceptance_both_keys() {
    let did = "did:dht:z6MkTestCategoryB";
    let category_b_resources = [
        "messages",
        "outlet_call",
        "member",
        "role",
        "context",
        "spending",
        "unknown_resource_type",
    ];

    for resource in &category_b_resources {
        let category = classify_action(resource);
        assert_eq!(
            category,
            ActionCategory::CategoryB,
            "resource '{resource}' must be classified as Category B"
        );

        // Agent key permitted.
        let agent_result = enforce_category_a(
            SigningKeyId::Agent,
            category,
            did,
            &format!("{resource}_action"),
            &[0u8; 64],
        );
        assert!(
            agent_result.is_ok(),
            "agent key must be permitted for Category B resource '{resource}'"
        );

        // Active key also permitted.
        let active_result = enforce_category_a(
            SigningKeyId::Active,
            category,
            did,
            &format!("{resource}_action"),
            &[0u8; 64],
        );
        assert!(
            active_result.is_ok(),
            "active key must be permitted for Category B resource '{resource}'"
        );
    }
}

/// Active key must be permitted for ALL action categories.
#[test]
fn test_active_key_permitted_everywhere() {
    let did = "did:dht:z6MkTestActiveKey";

    // Category A with active key.
    let result_a = enforce_category_a(
        SigningKeyId::Active,
        ActionCategory::CategoryA,
        did,
        "did_document_update",
        &[0u8; 64],
    );
    assert!(result_a.is_ok(), "active key must pass Category A");

    // Category B with active key.
    let result_b = enforce_category_a(
        SigningKeyId::Active,
        ActionCategory::CategoryB,
        did,
        "messages_write",
        &[0u8; 64],
    );
    assert!(result_b.is_ok(), "active key must pass Category B");
}

/// `CustodyViolationResult` contains all relevant information for violation logging.
#[test]
fn test_violation_result_contains_all_fields() {
    let did = "did:dht:z6MkTestViolation";
    let result = enforce_category_a(
        SigningKeyId::Agent,
        ActionCategory::CategoryA,
        did,
        "identity_migration",
        &[0u8; 64],
    );
    let violation = result.unwrap_err();

    assert!(
        !violation.error_message.is_empty(),
        "error_message must be non-empty"
    );
    assert_eq!(violation.violator_did, did);
    assert_eq!(violation.signing_key_id, SigningKeyId::Agent);
    assert_eq!(violation.attempted_action, "identity_migration");
}

/// `ScpCustodyViolationAttestation` can be constructed with violation evidence.
#[test]
fn test_custody_violation_attestation_construction() {
    let subject_did = DID("did:dht:z6MkSubject".to_owned());
    let verifier_did = DID("did:dht:z6MkVerifier".to_owned());

    let (_, verifier_sk) = test_keypair();
    let evidence_sig = verifier_sk.sign(b"violation-evidence").to_bytes().to_vec();
    let verifier_sig = verifier_sk
        .sign(b"violation-attestation-payload")
        .to_bytes()
        .to_vec();

    let attestation = ScpCustodyViolationAttestation {
        subject_did: subject_did.clone(),
        timestamp: 1_700_000_500,
        violation: CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_owned(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: evidence_sig.clone(),
        },
        verifier_signature: verifier_sig,
        verifier_did: verifier_did.clone(),
    };

    assert_eq!(attestation.subject_did, subject_did);
    assert_eq!(attestation.verifier_did, verifier_did);
    assert_eq!(attestation.timestamp, 1_700_000_500);

    // Verify the violation type carries the evidence.
    match &attestation.violation {
        CustodyViolationType::CategoryAViolation {
            action,
            signer_key_id,
            signature_evidence,
        } => {
            assert_eq!(action, "did_document_update");
            assert_eq!(*signer_key_id, SigningKeyId::Agent);
            assert_eq!(*signature_evidence, evidence_sig);
        }
        other @ CustodyViolationType::AttestationMismatch { .. } => {
            panic!("expected CategoryAViolation, got {other:?}")
        }
    }
}

/// `CounterAttestation` validation rejects empty fields.
#[test]
fn test_counter_attestation_validation() {
    let (_, sk) = test_keypair();
    let sig = sk.sign(b"test").to_bytes().to_vec();

    // Valid counter-attestation.
    let valid = CounterAttestation {
        subject_did: DID("did:dht:z6MkTest".to_owned()),
        violation_reference: "sha256:abc".to_owned(),
        explanation: "Key compromised and rotated.".to_owned(),
        timestamp: 1_700_000_000,
        signature: sig,
    };
    assert!(valid.validate().is_ok());

    // Empty violation_reference must fail.
    let empty_ref = CounterAttestation {
        violation_reference: String::new(),
        ..valid.clone()
    };
    assert!(empty_ref.validate().is_err());

    // Empty explanation must fail.
    let empty_expl = CounterAttestation {
        explanation: String::new(),
        ..valid
    };
    assert!(empty_expl.validate().is_err());
}

/// `SigningKeyId` serialization round-trip (JSON).
#[test]
fn test_signing_key_id_serialization() {
    let active = SigningKeyId::Active;
    let agent = SigningKeyId::Agent;

    // JSON serialization produces fragment strings.
    let active_json = serde_json::to_string(&active).expect("serialize Active");
    let agent_json = serde_json::to_string(&agent).expect("serialize Agent");
    assert_eq!(active_json, "\"#active\"");
    assert_eq!(agent_json, "\"#agent\"");

    // Round-trip.
    let active_rt: SigningKeyId = serde_json::from_str(&active_json).expect("deserialize Active");
    let agent_rt: SigningKeyId = serde_json::from_str(&agent_json).expect("deserialize Agent");
    assert_eq!(active_rt, SigningKeyId::Active);
    assert_eq!(agent_rt, SigningKeyId::Agent);

    // Display.
    assert_eq!(format!("{active}"), "#active");
    assert_eq!(format!("{agent}"), "#agent");

    // Default is Active.
    assert_eq!(SigningKeyId::default(), SigningKeyId::Active);
}

/// DID document created without agent key must not have #agent VM.
#[test]
fn test_did_document_without_agent_key() {
    let (identity_vk, _) = test_keypair();
    let (active_vk, _) = test_keypair();
    let pre_rotation: [u8; 32] = [0u8; 32];

    let did = did_from_pubkey(&identity_vk);
    let doc = DidDocument::new_with_agent_key(
        &did,
        identity_vk.as_bytes(),
        active_vk.as_bytes(),
        &pre_rotation,
        None, // no agent key
    );

    assert!(doc.verification_method_by_fragment("0").is_some());
    assert!(doc.verification_method_by_fragment("active").is_some());
    assert!(
        doc.agent_verification_method().is_none(),
        "document without agent key must not have #agent VM"
    );
}

/// Custody attestation without agent key custody field.
#[test]
fn test_custody_attestation_without_agent() {
    let attestation = ScpKeyCustodyAttestation {
        active_key_custody: KeyCustodyModel::Software,
        agent_key_custody: None,
        platform: Platform::Desktop,
        platform_attestation: None,
        created_at: 1_700_000_000,
    };

    // Verify JSON round-trip.
    let json = serde_json::to_string(&attestation).expect("serialize attestation");
    let deserialized: ScpKeyCustodyAttestation =
        serde_json::from_str(&json).expect("deserialize attestation");
    assert_eq!(deserialized.active_key_custody, KeyCustodyModel::Software);
    assert!(deserialized.agent_key_custody.is_none());
    assert_eq!(deserialized.platform, Platform::Desktop);
}
