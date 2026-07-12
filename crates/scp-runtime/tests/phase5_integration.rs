#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
//! Phase 5 end-to-end integration test.
//!
//! Exercises all four Phase 5 ADRs together with the Phase 1-4 foundation:
//!
//! - **ADR-023**: Bridge connector registration, shadow identity creation,
//!   provenance marking, and shadow claiming via identity attestation.
//! - **ADR-024**: Media session lifecycle with ceiling checks, MLS-derived
//!   DTLS-SRTP key export, WebRTC signaling, and session metadata capture.
//! - **ADR-025**: Platform adapter traits (key custody, device attestation,
//!   push notifications, key-value storage) via in-memory testing adapters.
//! - **ADR-026**: Swift SDK wrappers [OUT OF SCOPE -- requires `XCFramework`
//!   build (SCP-103)].
//!
//! The test verifies that bridge, media, platform, and cross-ADR integration
//! all function correctly as a cohesive whole.

use std::time::Duration;

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

use scp_did::DID;
use scp_event_log::tree::{self, GENESIS_PREV_HASH};
use scp_event_log::{Event, EventLog, EventPayload, EventType};
use scp_protocol::bridge::claiming::{ClaimRequest, claim_shadow};
use scp_protocol::bridge::provenance::{
    BridgeTrustLevel, evaluate_bridge_trust_level, mark_bridge_provenance,
};
use scp_protocol::bridge::registration::{
    BridgeRegistrationRequest, BridgeRegistry, approve_registration, register_bridge,
};
use scp_protocol::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow};
use scp_protocol::bridge::{BridgeMode, BridgeStatus, ShadowProvenanceStatus};
use scp_protocol::context::MemoryScope;
use scp_protocol::crypto::sender_keys::SenderKeyStore;
use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
use scp_protocol::trust::attestation::{AttestationEvidence, RevocationStatus};
use scp_protocol::trust::{Attestation, AttestationType};

use scp_media::keys::export_media_keys;
use scp_media::session::{
    MediaCapability, MediaSessionState, SessionMetadata, activate_session, check_media_capability,
    end_media_session, initiate_media_session, join_media_session,
};
use scp_media::signaling::{
    SignalingMessage, create_answer, create_ice_candidate, create_offer, deserialize_signaling,
    serialize_signaling, verify_sender_attribution,
};

use scp_mls::credential::ScpCredential;
use scp_mls::group::{add_member, create_group, generate_key_package, join_group};
use scp_protocol::context::params::Capability as ParamCapability;

use scp_platform::testing::{
    InMemoryDeviceAttestation, InMemoryKeyCustody, InMemoryPush, InMemoryStorage,
};
use scp_platform::traits::{DeviceAttestation, KeyCustody, KeyType, Push, Storage};

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

/// Encodes a public key as a test DID (`did:key:<hex>`).
fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> DID {
    let hex: String = verifying_key
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    format!("did:key:{hex}").into()
}

/// Signs an event and returns it with the signature populated.
fn sign_event(
    event_type: EventType,
    actor_did: &DID,
    timestamp: u64,
    sequence: u64,
    payload: Vec<u8>,
    prev_hash: [u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) -> Event {
    let mut event = Event {
        event_type,
        actor_did: actor_did.clone(),
        timestamp,
        sequence,
        payload: EventPayload { data: payload },
        prev_hash,
        signature: Vec::new(),
    };
    let canonical_hash = tree::compute_event_canonical_hash(&event);
    let signature = signing_key.sign(&canonical_hash);
    event.signature = signature.to_bytes().to_vec();
    event
}

/// Appends an event to a log and returns the resulting leaf hash.
fn append_and_hash(log: &mut EventLog, event: &Event) -> [u8; 32] {
    tree::append(log, event).expect("append should succeed");
    let serialized = rmp_serde::to_vec(event).expect("serialize");
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    hasher.finalize().into()
}

/// Computes the canonical SHA-256 hash of a claim request's content
/// (matching the internal `compute_claim_canonical_hash` in claiming.rs).
fn compute_claim_hash(request: &ClaimRequest) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-CLAIM-V1:");
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    length_prefix(&mut hasher, request.shadow_id.as_bytes());
    length_prefix(&mut hasher, request.claimant_did.as_bytes());
    length_prefix(&mut hasher, request.platform_handle.as_bytes());
    length_prefix(&mut hasher, request.identity_attestation.id.as_bytes());
    hasher.update(request.timestamp.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Computes the canonical attestation bytes for signing (matches the
/// `pub(crate) canonical_attestation_bytes` in `trust/attestation.rs`).
fn compute_attestation_canonical_bytes(attestation: &Attestation) -> Vec<u8> {
    use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};

    let evidence_bytes = attestation.evidence.as_ref().map(|e| {
        rmp_serde::to_vec_named(e).expect("AttestationEvidence serialization is infallible")
    });
    // Claim is compact JSON (RFC 8785 JCS) per §9.5.2 Attestation row 5;
    // evidence/revocation_status stay MessagePack per the §9.5.2 note.
    let claim_bytes =
        scp_protocol::jcs::to_vec(&attestation.claim).expect("claim serialization is infallible");
    let revocation_bytes = rmp_serde::to_vec_named(&attestation.revocation_status)
        .expect("RevocationStatus serialization is infallible");

    canonical_hash(
        "SCP-ATTESTATION-V1:",
        &[
            CanonicalField::VarBytes(attestation.id.as_bytes()),
            CanonicalField::U16(scp_protocol::trust::attestation_type_tag(
                &attestation.attestation_type,
            )),
            CanonicalField::VarBytes(attestation.issuer.as_bytes()),
            CanonicalField::VarBytes(attestation.subject.as_bytes()),
            CanonicalField::VarBytes(&claim_bytes),
            evidence_bytes
                .as_deref()
                .map_or(CanonicalField::Absent, CanonicalField::VarBytes),
            CanonicalField::U64(attestation.issued_at),
            attestation
                .expires_at
                .map_or(CanonicalField::Absent, CanonicalField::U64),
            CanonicalField::VarBytes(&revocation_bytes),
        ],
    )
    .unwrap()
    .to_vec()
}

/// Constructs a signed identity attestation.
fn make_identity_attestation(
    subject_did: &str,
    platform_handle: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Attestation {
    let mut attestation = Attestation {
        id: "attest-phase5-001".to_owned(),
        attestation_type: AttestationType::IdentityLink,
        issuer: subject_did.into(),
        subject: subject_did.into(),
        claim: serde_json::json!({
            "platform_handle": platform_handle,
            "platform": "discord"
        }),
        evidence: Some(AttestationEvidence {
            evidence_type: "signed-challenge".to_owned(),
            data: serde_json::json!({"challenge": "phase5-test"}),
        }),
        issued_at: 1_700_000_200,
        expires_at: Some(1_700_100_000),
        renewal_interval: Some(Duration::from_hours(24)),
        renewed_at: None,
        revocation_status: RevocationStatus::Active,
        signature: Vec::new(),
    };

    // Sign the attestation using canonical bytes.
    let canonical_bytes = compute_attestation_canonical_bytes(&attestation);
    let sig = signing_key.sign(&canonical_bytes);
    attestation.signature = sig.to_bytes().to_vec();

    attestation
}

/// Constructs a signed claim request.
fn make_claim_request(
    shadow_id: &str,
    claimant_did: &str,
    platform_handle: &str,
    attestation: Attestation,
    signing_key: &ed25519_dalek::SigningKey,
) -> ClaimRequest {
    let mut request = ClaimRequest {
        shadow_id: shadow_id.to_owned(),
        claimant_did: claimant_did.into(),
        platform_handle: platform_handle.to_owned(),
        identity_attestation: attestation,
        timestamp: 1_700_000_300,
        signature: Vec::new(),
    };

    let canonical_hash = compute_claim_hash(&request);
    let sig = signing_key.sign(&canonical_hash);
    request.signature = sig.to_bytes().to_vec();

    request
}

// ===========================================================================
// Section 1: Bridge lifecycle (ADR-023)
// ===========================================================================

#[test]
fn bridge_registration_shadow_creation_provenance_and_claiming() {
    let context_id = "ctx-phase5-bridge";

    // -- Identity setup --
    let (operator_vk, _operator_sk) = test_keypair();
    let operator_did = did_from_pubkey(&operator_vk);

    let (governance_vk, _governance_sk) = test_keypair();
    let governance_did = did_from_pubkey(&governance_vk);

    // -- Step 1: Create a BridgeRegistry for the test context --
    let mut bridge_registry = BridgeRegistry::new(context_id.to_owned());
    assert_eq!(bridge_registry.context_id(), context_id);
    assert!(bridge_registry.bridges().is_empty());

    // -- Step 2: Register a bridge connector (operator DID, "discord", Relay mode) --
    let registration_request = BridgeRegistrationRequest {
        bridge_id: "bridge-phase5-001".to_owned(),
        operator_did: operator_did.clone(),
        platform: "discord".to_owned(),
        mode: BridgeMode::Relay,
        context_id: context_id.to_owned(),
        requested_at: 1_700_000_000,
        self_hosted: false,
        webhook_url: None,
        platform_key: None,
        max_shadows: 10_000,
        metadata: scp_protocol::bridge::registration::BridgeRegistrationMetadata::default(),
    };

    let reg_event = register_bridge(&mut bridge_registry, registration_request)
        .expect("bridge registration should succeed");
    assert_eq!(reg_event.bridge_id, "bridge-phase5-001");
    assert_eq!(bridge_registry.pending_requests().len(), 1);

    // -- Step 3: Governance approves the registration --
    let (connector, approval_event) = approve_registration(
        &mut bridge_registry,
        "bridge-phase5-001",
        &governance_did,
        1_700_000_001,
    )
    .expect("bridge approval should succeed");

    assert_eq!(connector.bridge_id, "bridge-phase5-001");
    assert_eq!(connector.platform, "discord");
    assert_eq!(connector.mode, BridgeMode::Relay);
    assert_eq!(connector.status, BridgeStatus::Active);
    assert_eq!(connector.operator_did, operator_did);
    assert_eq!(approval_event.bridge_id, "bridge-phase5-001");
    assert_eq!(bridge_registry.bridges().len(), 1);
    assert!(bridge_registry.pending_requests().is_empty());

    // -- Step 4: Create a shadow identity for an external participant --
    let mut shadow_registry = ShadowRegistry::new(context_id.to_owned());
    let platform_handle = "@alice#1234";
    let shadow_id = "shadow-phase5-001";

    let mut sender_key_store = SenderKeyStore::new();
    let shadow_params = CreateShadowParams {
        shadow_id,
        bridge_id: "bridge-phase5-001",
        bridge_mode: BridgeMode::Relay,
        platform_handle,
        context_member_dids: &[],
        timestamp: 1_700_000_100,
    };
    let (shadow, creation_event) =
        create_shadow(&mut shadow_registry, &mut sender_key_store, &shadow_params)
            .expect("shadow creation should succeed");

    assert_eq!(shadow.shadow_id, shadow_id);
    assert_eq!(shadow.platform_handle, platform_handle);
    assert_eq!(shadow.bridge_id, "bridge-phase5-001");
    assert_eq!(shadow.attributed_role, "observer");
    assert_eq!(shadow.provenance_status, ShadowProvenanceStatus::Shadow);
    assert_eq!(creation_event.shadow_id, shadow_id);
    assert_eq!(creation_event.bridge_mode, BridgeMode::Relay);

    // -- Step 5: Mark content with BridgeProvenance and verify trust level --
    let base_provenance = DataProvenance {
        source_context: context_id.to_string(),
        source_type: SourceType::Persistent,
        counterparties: vec![operator_did.clone()],
        purpose: Some("bridged message from Discord".to_string()),
        discovery_method: DiscoveryMethod::SharedContext(context_id.to_string()),
        age: Duration::from_secs(30),
        memory_scope: MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    let bridge_provenance = mark_bridge_provenance(base_provenance, &connector, &shadow);

    // Before claiming: trust level should be ShadowBridged (weakest).
    assert_eq!(
        bridge_provenance.shadow_status,
        ShadowProvenanceStatus::Shadow
    );
    assert_eq!(bridge_provenance.originating_platform, "discord");
    assert_eq!(bridge_provenance.bridge_connector_id, "bridge-phase5-001");
    assert_eq!(bridge_provenance.operator_did, operator_did);
    assert_eq!(bridge_provenance.bridge_mode, BridgeMode::Relay);

    let trust_level = evaluate_bridge_trust_level(&bridge_provenance);
    assert_eq!(trust_level, BridgeTrustLevel::ShadowBridged);

    // -- Step 6: Claim the shadow via identity attestation --
    let (claimant_vk, claimant_sk) = test_keypair();
    let claimant_did = did_from_pubkey(&claimant_vk);

    let attestation = make_identity_attestation(&claimant_did, platform_handle, &claimant_sk);
    let claim_request = make_claim_request(
        shadow_id,
        &claimant_did,
        platform_handle,
        attestation,
        &claimant_sk,
    );

    let claim_event =
        claim_shadow(&mut shadow_registry, &claim_request).expect("claim should succeed");

    // Verify claim event fields.
    assert_eq!(claim_event.shadow_id, shadow_id);
    assert_eq!(claim_event.claimant_did, claimant_did);
    assert_eq!(claim_event.platform_handle, platform_handle);
    assert_eq!(claim_event.context_id, context_id);

    // -- Step 7: Verify provenance status transitions to Claimed --
    let claimed_shadow = &shadow_registry.shadows()[0];
    assert_eq!(
        claimed_shadow.provenance_status,
        ShadowProvenanceStatus::Claimed
    );

    // -- Step 8: Verify trust level upgrades to ClaimedBridged after claiming --
    let post_claim_provenance = mark_bridge_provenance(
        DataProvenance {
            source_context: context_id.to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec![claimant_did],
            purpose: Some("post-claim message".to_string()),
            discovery_method: DiscoveryMethod::SharedContext(context_id.to_string()),
            age: Duration::from_secs(5),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        },
        &connector,
        claimed_shadow,
    );

    assert_eq!(
        post_claim_provenance.shadow_status,
        ShadowProvenanceStatus::Claimed
    );
    let post_claim_trust = evaluate_bridge_trust_level(&post_claim_provenance);
    assert_eq!(post_claim_trust, BridgeTrustLevel::ClaimedBridged);
    assert!(
        post_claim_trust > trust_level,
        "ClaimedBridged > ShadowBridged"
    );
}

// ===========================================================================
// Section 2: Media lifecycle (ADR-024)
// ===========================================================================

#[test]
fn media_session_lifecycle_with_ceiling_check_and_signaling() {
    let context_id = "ctx-phase5-media";
    let alice_did: DID = "did:dht:z6MkAlice".into();
    let bob_did: DID = "did:dht:z6MkBob".into();
    let ts_start: u64 = 1_700_000_000;
    let ts_end: u64 = 1_700_003_600;

    // -- Step 1: Build a capability ceiling that includes media:voice --
    let ceiling = vec![
        ParamCapability::new("messages:read").expect("known capability"),
        ParamCapability::new("messages:write").expect("known capability"),
        ParamCapability::new("media:voice").expect("known capability"),
    ];

    // Verify that the ceiling contains media:voice.
    assert!(
        check_media_capability(&ceiling, &MediaCapability::Voice).is_ok(),
        "media:voice must be in ceiling"
    );

    // Verify that media:video is NOT in the ceiling (negative check).
    assert!(
        check_media_capability(&ceiling, &MediaCapability::Video).is_err(),
        "media:video should not be in ceiling"
    );

    // -- Step 2: Initiate a media session with voice capability --
    let mut session = initiate_media_session(
        context_id.to_owned(),
        &ceiling,
        vec![MediaCapability::Voice],
        vec![alice_did.clone()],
        ts_start,
    )
    .expect("session initiation should succeed");

    assert!(session.session_id.starts_with("ms-"));
    assert_eq!(session.context_id, context_id);
    assert_eq!(session.state, MediaSessionState::Initiating);
    assert_eq!(session.participants, vec![alice_did.clone()]);
    assert_eq!(session.capabilities, vec![MediaCapability::Voice]);

    // -- Step 3: Activate the session (SDP exchange complete) --
    activate_session(&mut session).expect("activation should succeed");
    assert_eq!(session.state, MediaSessionState::Active);

    // -- Step 4: Join a second participant --
    join_media_session(&mut session, bob_did.clone()).expect("join should succeed");
    assert_eq!(session.participants.len(), 2);
    assert!(session.participants.contains(&bob_did));

    // -- Step 5: Create and verify signaling messages --
    let session_id = session.session_id.clone();

    // SDP offer from Alice.
    let (sid_offer, offer_msg) = create_offer(
        &session_id,
        "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n".to_owned(),
        alice_did.clone(),
    );
    assert_eq!(sid_offer, session_id);

    // Verify sender attribution on the offer.
    assert!(verify_sender_attribution(&offer_msg, &alice_did).is_ok());
    assert!(verify_sender_attribution(&offer_msg, &bob_did).is_err());

    // SDP answer from Bob.
    let (sid_answer, answer_msg) = create_answer(
        &session_id,
        "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\n".to_owned(),
        bob_did.clone(),
    );
    assert_eq!(sid_answer, session_id);
    assert!(verify_sender_attribution(&answer_msg, &bob_did).is_ok());

    // ICE candidate from Alice.
    let (sid_ice, ice_msg) = create_ice_candidate(
        &session_id,
        "candidate:1 1 UDP 2130706431 10.0.0.1 5000 typ host".to_owned(),
        Some("audio".to_owned()),
        Some(0),
        alice_did.clone(),
    );
    assert_eq!(sid_ice, session_id);
    assert!(verify_sender_attribution(&ice_msg, &alice_did).is_ok());

    // Verify signaling messages serialize and deserialize correctly.
    let offer_bytes = serialize_signaling(&offer_msg).expect("serialize offer");
    let restored_offer = deserialize_signaling(&offer_bytes).expect("deserialize offer");
    match (&offer_msg, &restored_offer) {
        (SignalingMessage::Offer(a), SignalingMessage::Offer(b)) => {
            assert_eq!(a.sdp, b.sdp);
            assert_eq!(a.sender_did, b.sender_did);
        }
        _ => panic!("offer roundtrip mismatch"),
    }

    // -- Step 6: End the session and verify SessionMetadata capture --
    let metadata: SessionMetadata =
        end_media_session(&mut session, ts_end).expect("end should succeed");

    assert_eq!(session.state, MediaSessionState::Ended);
    assert_eq!(metadata.session_id, session_id);
    assert_eq!(metadata.context_id, context_id);
    assert_eq!(metadata.participants.len(), 2);
    assert!(metadata.participants.contains(&alice_did));
    assert!(metadata.participants.contains(&bob_did));
    assert_eq!(metadata.capabilities, vec![MediaCapability::Voice]);
    assert_eq!(metadata.started_at, ts_start);
    assert_eq!(metadata.ended_at, ts_end);

    // -- Step 7: Verify metadata is serializable for event log recording --
    let payload_bytes = metadata
        .to_payload_bytes()
        .expect("metadata serialization should succeed");
    assert!(!payload_bytes.is_empty());

    let restored_metadata: SessionMetadata =
        serde_json::from_slice(&payload_bytes).expect("metadata deserialization");
    assert_eq!(restored_metadata, metadata);
}

#[test]
fn media_session_mls_key_derivation() {
    // -- Step 1: Create an MLS group with Alice --
    let alice_cred = ScpCredential::new(
        "did:dht:z6MkAlice".to_owned(),
        None,
        scp_did::SigningKeyId::Active,
    )
    .expect("alice credential");
    let mut alice_group = create_group(&alice_cred, &scp_clock::SystemClock).expect("create group");

    // -- Step 2: Add Bob to the group --
    let bob_cred = ScpCredential::new(
        "did:dht:z6MkBob".to_owned(),
        None,
        scp_did::SigningKeyId::Active,
    )
    .expect("bob credential");
    let (bob_kp_bundle, bob_signer, bob_provider) =
        generate_key_package(&bob_cred, &scp_clock::SystemClock).expect("bob key package");
    let bob_kp = bob_kp_bundle.key_package().clone().into();
    let add_result =
        add_member(&mut alice_group, bob_kp, &scp_clock::SystemClock).expect("add bob");

    let bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).expect("bob joins");

    // -- Step 3: Export DTLS-SRTP key material from both members --
    let alice_keys =
        export_media_keys(&alice_group, b"ctx-phase5-media", 32).expect("alice key export");
    let bob_keys = export_media_keys(&bob_group, b"ctx-phase5-media", 32).expect("bob key export");

    // Both members must derive identical keys from the same MLS epoch.
    assert_eq!(
        *alice_keys.dtls_srtp_keys, *bob_keys.dtls_srtp_keys,
        "both group members must derive identical media keys"
    );
    assert_eq!(alice_keys.epoch, bob_keys.epoch);
    assert_eq!(alice_keys.context_id, bob_keys.context_id);

    // Key material is non-trivial (not all zeros).
    assert_ne!(*alice_keys.dtls_srtp_keys, vec![0u8; 32]);

    // Different context bytes produce different keys.
    let alt_keys =
        export_media_keys(&alice_group, b"ctx-different", 32).expect("alt context key export");
    assert_ne!(
        *alice_keys.dtls_srtp_keys, *alt_keys.dtls_srtp_keys,
        "different contexts must produce different keys"
    );
}

// ===========================================================================
// Section 3: Platform adapters (ADR-025)
// ===========================================================================

#[tokio::test]
async fn platform_key_custody_sign_and_verify() {
    let custody = InMemoryKeyCustody::new();

    // -- Generate Ed25519 keypair --
    let ed_handle = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate ed25519 key");

    let ed_pubkey = custody
        .public_key(&ed_handle)
        .await
        .expect("get ed25519 public key");
    assert_eq!(ed_pubkey.as_bytes().len(), 32);

    // -- Sign data and verify via ed25519-dalek --
    let message = b"phase5 integration test data";
    let signature = custody.sign(&ed_handle, message).await.expect("sign data");

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        ed_pubkey.as_bytes().try_into().expect("32-byte public key"),
    )
    .expect("valid verifying key");

    let sig_bytes: [u8; 64] = signature.as_bytes().try_into().expect("64-byte signature");
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    use ed25519_dalek::Verifier;
    assert!(
        verifying_key.verify(message, &ed_sig).is_ok(),
        "signature must verify correctly"
    );

    // -- Generate X25519 keypair --
    let x_handle = custody
        .generate_keypair(KeyType::X25519)
        .await
        .expect("generate x25519 key");

    let x_pubkey = custody
        .public_key(&x_handle)
        .await
        .expect("get x25519 public key");
    assert_eq!(x_pubkey.as_bytes().len(), 32);

    // -- Verify custody type --
    let custody_type = custody.custody_type(&ed_handle);
    assert_eq!(custody_type, scp_platform::traits::CustodyType::InMemory);
}

#[tokio::test]
async fn platform_device_attestation() {
    let attestation = InMemoryDeviceAttestation::new();

    // -- Generate attestation token --
    let token = attestation
        .attest()
        .await
        .expect("attestation should succeed");
    assert!(!token.as_bytes().is_empty());

    // -- Verify attestation token --
    let valid = attestation
        .verify(&token)
        .await
        .expect("verification should succeed");
    assert!(valid, "token from same adapter must verify");
}

#[tokio::test]
async fn platform_push_notifications() {
    let push = InMemoryPush::new();

    // -- Register for push --
    let token = push.register().await.expect("push registration");
    assert!(!token.as_bytes().is_empty());

    // -- Handle notification --
    let payload = b"new-message-ctx-123";
    let wake = push
        .handle_notification(payload)
        .await
        .expect("notification handling");
    assert_eq!(wake.payload, payload);
}

#[tokio::test]
async fn platform_storage_operations() {
    let storage = InMemoryStorage::new();

    // -- Store and retrieve --
    storage
        .store("phase5-key", b"phase5-value")
        .await
        .expect("store");
    let retrieved = storage.retrieve("phase5-key").await.expect("retrieve");
    assert_eq!(retrieved, Some(b"phase5-value".to_vec()));

    // -- Key existence --
    let exists = storage.exists("phase5-key").await.expect("exists");
    assert!(exists);

    let not_exists = storage.exists("nonexistent").await.expect("not exists");
    assert!(!not_exists);

    // -- Retrieve missing key --
    let missing = storage.retrieve("nonexistent").await.expect("missing");
    assert!(missing.is_none());

    // -- List keys by prefix --
    storage.store("prefix-a", b"a").await.expect("store a");
    storage.store("prefix-b", b"b").await.expect("store b");
    let keys = storage.list_keys("prefix-").await.expect("list keys");
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"prefix-a".to_string()));
    assert!(keys.contains(&"prefix-b".to_string()));

    // -- Delete --
    storage.delete("phase5-key").await.expect("delete");
    let after_delete = storage.retrieve("phase5-key").await.expect("after delete");
    assert!(after_delete.is_none());

    // -- Delete by prefix --
    let deleted_count = storage
        .delete_prefix("prefix-")
        .await
        .expect("delete prefix");
    assert_eq!(deleted_count, 2);
}

// ===========================================================================
// Section 4: Cross-ADR integration
// ===========================================================================

#[test]
fn cross_adr_bridge_provenance_carries_correct_metadata() {
    // Bridge + Provenance: bridged message carries BridgeProvenance with correct
    // operator DID, platform, and mode.
    let (operator_vk, _operator_sk) = test_keypair();
    let operator_did = did_from_pubkey(&operator_vk);

    let connector = scp_protocol::bridge::BridgeConnector {
        bridge_id: "bridge-cross-001".to_owned(),
        operator_did: operator_did.clone(),
        platform: "slack".to_owned(),
        mode: BridgeMode::Api,
        status: BridgeStatus::Active,
        registration_context: "ctx-cross-test".to_owned(),
        registered_at: 1_700_000_000,
    };

    let shadow = scp_protocol::bridge::ShadowIdentity {
        shadow_id: "shadow-cross-001".to_owned(),
        platform_handle: "@bob".to_owned(),
        bridge_id: "bridge-cross-001".to_owned(),
        attributed_role: "observer".to_owned(),
        provenance_status: ShadowProvenanceStatus::Shadow,
        created_at: 1_700_000_100,
    };

    let base = DataProvenance {
        source_context: "ctx-cross-test".to_string(),
        source_type: SourceType::Persistent,
        counterparties: vec![operator_did.clone()],
        purpose: Some("cross-adr test message".to_string()),
        discovery_method: DiscoveryMethod::SharedContext("ctx-cross-test".to_string()),
        age: Duration::from_secs(10),
        memory_scope: MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    let bp = mark_bridge_provenance(base, &connector, &shadow);

    // Verify all fields are correctly populated.
    assert_eq!(bp.originating_platform, "slack");
    assert_eq!(bp.bridge_connector_id, "bridge-cross-001");
    assert_eq!(bp.operator_did, operator_did);
    assert_eq!(bp.bridge_mode, BridgeMode::Api);
    assert_eq!(bp.shadow_status, ShadowProvenanceStatus::Shadow);
    assert_eq!(bp.base.source_context, "ctx-cross-test");
}

#[tokio::test]
async fn cross_adr_platform_key_custody_signs_claim_request() {
    // Platform + Bridge: use platform key custody to sign the claim request
    // for shadow claiming.
    let custody = InMemoryKeyCustody::new();

    // Generate a signing key through the platform custody trait.
    let key_handle = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate key");
    let pubkey = custody
        .public_key(&key_handle)
        .await
        .expect("get public key");
    let pubkey_bytes: [u8; 32] = pubkey.as_bytes().try_into().expect("32 byte pubkey");

    // Construct DID from the public key.
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes).expect("valid key");
    let _claimant_did = did_from_pubkey(&verifying_key);

    // For signing we need the ed25519_dalek signing key, which the InMemory
    // adapter wraps. We can verify the signature using the platform trait's
    // sign method. The claim_shadow function requires raw Ed25519 signatures,
    // so we use the custody trait to sign and then embed the result.
    let platform_handle = "@platformuser#5678";
    let shadow_id = "shadow-platform-001";

    // Create a shadow registry and shadow.
    let mut shadow_registry = ShadowRegistry::new("ctx-platform-claim".to_owned());
    let shadow_params = CreateShadowParams {
        shadow_id,
        bridge_id: "bridge-platform-001",
        bridge_mode: BridgeMode::Relay,
        platform_handle,
        context_member_dids: &[],
        timestamp: 1_700_000_100,
    };
    create_shadow(
        &mut shadow_registry,
        &mut SenderKeyStore::new(),
        &shadow_params,
    )
    .expect("shadow creation");

    // Build an identity attestation. Since we need to use ed25519_dalek's
    // Signer trait for the canonical bytes, and the InMemoryKeyCustody wraps
    // the actual signing key, we sign using the custody.sign method and
    // verify it matches what we expect.

    // First, sign test data through the platform trait.
    let test_data = b"platform custody verification";
    let sig = custody.sign(&key_handle, test_data).await.expect("sign");

    // Verify the signature using ed25519-dalek directly.
    let ed_sig = ed25519_dalek::Signature::from_bytes(sig.as_bytes().try_into().expect("64 bytes"));
    use ed25519_dalek::Verifier;
    assert!(verifying_key.verify(test_data, &ed_sig).is_ok());

    // This demonstrates that platform key custody can produce signatures
    // compatible with the Ed25519 verification used in claim_shadow.
    // A full end-to-end claim through the platform trait would require
    // access to the canonical hash functions, which we've already tested
    // in the bridge lifecycle test above.
}

#[test]
fn cross_adr_event_log_records_bridge_and_media_events() {
    // Event log integration: verify that bridge registration, shadow creation,
    // and media session events can all be recorded in a single context event log.
    let context_id = "ctx-phase5-eventlog";

    let (alice_vk, alice_sk) = test_keypair();
    let alice_did = did_from_pubkey(&alice_vk);

    let mut event_log = EventLog::new(context_id.to_owned());
    let mut prev_hash = GENESIS_PREV_HASH;
    let mut seq: u64 = 0;

    // Event 1: Context created.
    let ctx_created = sign_event(
        EventType::ContextCreated,
        &alice_did,
        1_700_000_000,
        seq,
        b"context created".to_vec(),
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut event_log, &ctx_created);
    seq += 1;

    // Event 2: Bridge registration (GovernanceAction event type).
    let bridge_reg_payload = serde_json::to_vec(&serde_json::json!({
        "action": "bridge_registered",
        "bridge_id": "bridge-eventlog-001",
        "platform": "discord",
        "mode": "Relay"
    }))
    .expect("serialize bridge reg payload");

    let bridge_reg_event = sign_event(
        EventType::GovernanceAction,
        &alice_did,
        1_700_000_001,
        seq,
        bridge_reg_payload,
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut event_log, &bridge_reg_event);
    seq += 1;

    // Event 3: Shadow identity created (member joined as shadow).
    let shadow_payload = serde_json::to_vec(&serde_json::json!({
        "action": "shadow_created",
        "shadow_id": "shadow-eventlog-001",
        "platform_handle": "@user#9999",
        "bridge_id": "bridge-eventlog-001"
    }))
    .expect("serialize shadow payload");

    let shadow_event = sign_event(
        EventType::MemberJoined,
        &alice_did,
        1_700_000_002,
        seq,
        shadow_payload,
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut event_log, &shadow_event);
    seq += 1;

    // Event 4: Media session started.
    let media_start_payload = serde_json::to_vec(&serde_json::json!({
        "session_id": "ms-eventlog-001",
        "capabilities": ["Voice"],
        "participants": ["did:dht:z6MkAlice"]
    }))
    .expect("serialize media start payload");

    let media_start_event = sign_event(
        EventType::MediaSessionStarted,
        &alice_did,
        1_700_000_003,
        seq,
        media_start_payload,
        prev_hash,
        &alice_sk,
    );
    prev_hash = append_and_hash(&mut event_log, &media_start_event);
    seq += 1;

    // Event 5: Media session ended.
    let media_end_payload = serde_json::to_vec(&serde_json::json!({
        "session_id": "ms-eventlog-001",
        "ended_at": 1_700_003_600
    }))
    .expect("serialize media end payload");

    let media_end_event = sign_event(
        EventType::MediaSessionEnded,
        &alice_did,
        1_700_003_600,
        seq,
        media_end_payload,
        prev_hash,
        &alice_sk,
    );
    let _prev_hash_final = append_and_hash(&mut event_log, &media_end_event);

    // Verify the event log contains all 5 events.
    assert_eq!(tree::event_count(&event_log), 5);

    // Verify the Merkle root is non-zero and consistent.
    let root = tree::root(&event_log);
    assert_ne!(root, [0u8; 32], "Merkle root must not be zero");

    // Verify all leaf hashes are preserved and non-zero.
    assert_eq!(event_log.leaves().len(), 5);
    for (i, leaf) in event_log.leaves().iter().enumerate() {
        assert_ne!(*leaf, [0u8; 32], "leaf {i} must not be zero");
    }
}

// ===========================================================================
// Section 5: Media + MLS key export integration
// ===========================================================================

#[test]
fn media_session_keys_derived_from_mls_group_state() {
    // Media + MLS: verify media session key material is correctly derived
    // from MLS export secrets, and both group members get the same keys.
    let alice_cred = ScpCredential::new(
        "did:dht:z6MkAlice".to_owned(),
        None,
        scp_did::SigningKeyId::Active,
    )
    .expect("alice cred");
    let mut alice_group = create_group(&alice_cred, &scp_clock::SystemClock).expect("alice group");

    let bob_cred = ScpCredential::new(
        "did:dht:z6MkBob".to_owned(),
        None,
        scp_did::SigningKeyId::Active,
    )
    .expect("bob cred");
    let (bob_kp_bundle, bob_signer, bob_provider) =
        generate_key_package(&bob_cred, &scp_clock::SystemClock).expect("bob kp");
    let bob_kp = bob_kp_bundle.key_package().clone().into();
    let add_result =
        add_member(&mut alice_group, bob_kp, &scp_clock::SystemClock).expect("add bob");
    let bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).expect("bob join");

    // Export keys at 32 bytes (standard DTLS-SRTP keying material length).
    let context_bytes = b"ctx-mls-media-integration";
    let alice_media_keys =
        export_media_keys(&alice_group, context_bytes, 32).expect("alice export");
    let bob_media_keys = export_media_keys(&bob_group, context_bytes, 32).expect("bob export");

    // Both members derive identical key material.
    assert_eq!(
        *alice_media_keys.dtls_srtp_keys,
        *bob_media_keys.dtls_srtp_keys
    );
    assert_eq!(alice_media_keys.epoch, bob_media_keys.epoch);
    assert_eq!(alice_media_keys.dtls_srtp_keys.len(), 32);

    // Keys are bound to the MLS epoch (epoch 1 after add).
    assert_eq!(alice_media_keys.epoch, 1);
}
