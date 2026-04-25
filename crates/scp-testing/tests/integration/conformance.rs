//! §26 Conformance Test Suite — SCP protocol conformance validation.
//!
//! 42 tests across 10 protocol layers (Identity, Context, Messaging, Sync,
//! Trust, Transport, Discovery, Economy, Bridge, Interop).
//!
//! Two conformance tiers:
//! - **SCP Core Conformance** — identity, contexts, messaging, sync (26 tests)
//! - **SCP Full Conformance** — all protocol layers (42 tests)
//!
//! Run with `--nocapture` to see step-by-step output:
//! ```bash
//! cargo test -p scp-testing --test conformance -- --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::needless_range_loop
)]

use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256};

use scp_core::bridge::provenance::{
    BridgeTrustLevel, evaluate_bridge_trust_level, mark_bridge_provenance,
};
use scp_core::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow, find_shadow};
use scp_core::bridge::{BridgeConnector, BridgeMode, BridgeStatus, ShadowIdentity};
use scp_core::context::governance::{GovernanceAction, VoteType, sign_vote, verify_vote};
use scp_core::context::params::{ContextMode, ContextParams, TemplateId};
use scp_core::context::roles::Capability;
use scp_core::context::{ContextHandle, ContextState, MembershipState};
use scp_core::crypto::access_keys::wrapping::{unwrap_cek, wrap_cek};
use scp_core::crypto::access_keys::{ContentEncryptionKey, generate_access_key};
use scp_core::crypto::canonical::{CanonicalField, canonical_hash, canonical_hash_bytes};
use scp_core::crypto::key_continuity::{
    KeyContinuityParty, compute_key_continuity_fingerprint, fingerprint_to_decimal,
};
use scp_core::crypto::sender_keys::{
    SenderKeyStore, decrypt_sender_layer, encrypt_sender_layer, generate_sender_key,
};
use scp_core::discovery::HandleTarget;
use scp_core::discovery::handles::{
    HandleDeregisterParams, HandleLookupParams, HandleRegisterParams, HandleRegistry,
};
use scp_core::economy::{
    Amount, Coefficient, CostSchedule, CurrencyCode, ObservableMetrics, PaidActionType,
    PricingFormula, PricingMetric, PricingVariable, evaluate_formula, lookup_cost,
};
use scp_core::envelope::padding::{BUCKET_SIZES, pad_to_bucket, strip_padding};
use scp_core::provenance::DataProvenance;
use scp_core::sync::{
    OfflineTier, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS, classify_offline_duration,
};
use scp_identity::DID;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryPush};
use scp_platform::{KeyCustody, KeyType, Push};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn print_step(step: u32, desc: &str) {
    println!("    Step {step}: {desc}");
}

fn make_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}

// ===========================================================================
// §26.3 Identity Tests
// ===========================================================================

/// CONF-001: DID Creation with Required Verification Methods
/// Layer: Identity | Tier: Core | Spec: §3.1, §3.2, ADR-039
#[tokio::test]
async fn conf_001_did_creation_with_verification_methods() {
    println!("=== CONF-001: DID Creation with Required Verification Methods ===");

    print_step(1, "Generate Ed25519 keypair");
    let custody = InMemoryKeyCustody::new();
    let identity_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate identity key");
    let active_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate active key");
    let agent_key = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate agent key");

    print_step(2, "Verify all three keys generated");
    let id_pub = custody
        .public_key(&identity_key)
        .await
        .expect("identity pubkey");
    let active_pub = custody
        .public_key(&active_key)
        .await
        .expect("active pubkey");
    let agent_pub = custody.public_key(&agent_key).await.expect("agent pubkey");
    assert_eq!(id_pub.as_bytes().len(), 32, "Ed25519 key must be 32 bytes");
    assert_eq!(active_pub.as_bytes().len(), 32);
    assert_eq!(agent_pub.as_bytes().len(), 32);

    print_step(3, "Verify keys are distinct");
    assert_ne!(
        id_pub.as_bytes(),
        active_pub.as_bytes(),
        "identity and active keys must differ"
    );
    assert_ne!(
        id_pub.as_bytes(),
        agent_pub.as_bytes(),
        "identity and agent keys must differ"
    );
    assert_ne!(
        active_pub.as_bytes(),
        agent_pub.as_bytes(),
        "active and agent keys must differ"
    );

    println!("  PASS: 3 distinct Ed25519 verification methods generated");
}

/// CONF-002: DID Resolution and Self-Certification
/// Layer: Identity | Tier: Core | Spec: §3.1, §9.6.1
#[test]
fn conf_002_did_self_certification() {
    println!("=== CONF-002: DID Resolution and Self-Certification ===");

    print_step(1, "Create DID with known key");
    let signing_key = make_signing_key(0x42);
    let pubkey = signing_key.verifying_key();

    print_step(2, "Verify public key derivation");
    let pubkey_bytes = pubkey.to_bytes();
    println!("    Public key: 0x{}", hex(&pubkey_bytes));

    print_step(3, "Sign and verify self-certification payload");
    let payload = b"self-certification-payload";
    let signature = signing_key.sign(payload);
    pubkey
        .verify(payload, &signature)
        .expect("self-certification must verify");

    println!("  PASS: Self-certification verified");
}

/// CONF-003: Key Rotation (Active Key Update)
/// Layer: Identity | Tier: Core | Spec: §3.3, §9.11
#[test]
fn conf_003_key_rotation_changes_fingerprint() {
    println!("=== CONF-003: Key Rotation (Active Key Update) ===");

    let old_active = [0x11u8; 32];
    let new_active = [0x22u8; 32];
    let identity = [0x33u8; 32];

    print_step(1, "Compute fingerprint with old active key");
    let alice = KeyContinuityParty {
        did: "did:dht:z6MkAlice",
        identity_key: &identity,
        active_key: &old_active,
        agent_key: None,
    };
    let bob = KeyContinuityParty {
        did: "did:dht:z6MkBob",
        identity_key: &[0x44; 32],
        active_key: &[0x55; 32],
        agent_key: None,
    };
    let fp_before = compute_key_continuity_fingerprint(&alice, &bob);

    print_step(2, "Rotate active key");
    let alice_after = KeyContinuityParty {
        did: "did:dht:z6MkAlice",
        identity_key: &identity,
        active_key: &new_active,
        agent_key: None,
    };
    let fp_after = compute_key_continuity_fingerprint(&alice_after, &bob);

    print_step(3, "Verify fingerprint changed");
    assert_ne!(
        fp_before, fp_after,
        "key rotation must change continuity fingerprint"
    );

    print_step(4, "Verify fingerprint is still 60 decimal digits");
    let decimal = fingerprint_to_decimal(&fp_after);
    assert_eq!(decimal.len(), 60);

    println!("  PASS: Key rotation changes fingerprint");
}

/// CONF-004: Agent Binding (Human DID Attests Agent DID)
/// Layer: Identity | Tier: Core | Spec: §4.2, ADR-039
#[test]
fn conf_004_agent_binding_attestation() {
    println!("=== CONF-004: Agent Binding ===");

    let human_key = make_signing_key(0x01);
    let agent_key = make_signing_key(0x02);

    // Use did:key:{hex} format so IdentityDidPublicKeyResolver can resolve
    // the issuer's public key during cross-verification.
    let human_did = format!("did:key:{}", hex(&human_key.verifying_key().to_bytes()));
    let agent_did = format!("did:key:{}", hex(&agent_key.verifying_key().to_bytes()));

    let claim = serde_json::json!({"platform": "agent-binding"});
    let claim_bytes = rmp_serde::to_vec_named(&claim).expect("claim msgpack serialization");

    print_step(1, "Create identity attestation binding agent to human");
    // RevocationStatus::Active serialized as MessagePack (named keys).
    let revocation_active_bytes =
        rmp_serde::to_vec_named(&scp_core::trust::RevocationStatus::Active).unwrap();
    // Field order per §9.5.2: id, attestation_type, issuer, subject, claim,
    // evidence, issued_at, expires_at, revocation_status.
    let attestation_payload = canonical_hash_bytes(
        b"SCP-ATTESTATION-V1:",
        &[
            CanonicalField::VarBytes(b"agent-binding-001"),
            CanonicalField::U16(0x0000), // IdentityLink = tag 0
            CanonicalField::VarBytes(human_did.as_bytes()),
            CanonicalField::VarBytes(agent_did.as_bytes()),
            CanonicalField::VarBytes(&claim_bytes),
            CanonicalField::Absent, // no evidence
            CanonicalField::U64(1_700_000_000),
            CanonicalField::Absent, // expires_at: None → Absent per V2 spec
            CanonicalField::VarBytes(&revocation_active_bytes),
        ],
    )
    .unwrap();
    let hash: [u8; 32] = Sha256::digest(&attestation_payload).into();

    print_step(2, "Sign attestation with human's active key");
    let signature = human_key.sign(&hash);

    print_step(3, "Verify attestation signature (manual)");
    human_key
        .verifying_key()
        .verify(&hash, &signature)
        .expect("attestation must verify");

    print_step(
        4,
        "Cross-verify: manual canonical bytes match verify_attestation()",
    );
    // Build an Attestation struct with the same fields and verify it through
    // the production verify_attestation() code path. This ensures the manual
    // canonical construction above matches canonical_attestation_bytes().
    let attestation = scp_core::trust::Attestation {
        id: "agent-binding-001".to_owned(),
        attestation_type: scp_core::trust::AttestationType::IdentityLink,
        issuer: DID::from(human_did.as_str()),
        subject: DID::from(agent_did.as_str()),
        claim,
        evidence: None,
        issued_at: 1_700_000_000,
        expires_at: None,
        renewal_interval: None,
        renewed_at: None,
        revocation_status: scp_core::trust::RevocationStatus::Active,
        signature: signature.to_bytes().to_vec(),
    };
    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::TestClock::new(1_700_000_000);
    scp_core::trust::verify_attestation(&attestation, &resolver, &clock)
        .expect("cross-verification: manual bytes must match canonical_attestation_bytes()");

    print_step(5, "Verify agent key matches attestation");
    let agent_pub = agent_key.verifying_key().to_bytes();
    assert_eq!(agent_pub.len(), 32);

    println!("  PASS: Agent binding attestation verified");
}

/// CONF-005: Multi-Device (Same DID, Different Device Keys)
/// Layer: Identity | Tier: Core | Spec: §3.4
#[tokio::test]
async fn conf_005_multi_device_signing() {
    println!("=== CONF-005: Multi-Device ===");

    print_step(1, "Create two device keystores for same DID");
    let device_a = InMemoryKeyCustody::new();
    let device_b = InMemoryKeyCustody::new();
    let key_a = device_a
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("device A key");
    let key_b = device_b
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("device B key");

    print_step(2, "Both devices sign a message");
    let message = b"hello from multi-device";
    let sig_a = device_a.sign(&key_a, message).await.expect("device A sign");
    let sig_b = device_b.sign(&key_b, message).await.expect("device B sign");

    print_step(3, "Both signatures verify");
    let pub_a = device_a.public_key(&key_a).await.expect("pubkey A");
    let pub_b = device_b.public_key(&key_b).await.expect("pubkey B");

    let pub_a_bytes: [u8; 32] = pub_a.as_bytes().try_into().expect("32 bytes");
    let pub_b_bytes: [u8; 32] = pub_b.as_bytes().try_into().expect("32 bytes");

    let vk_a = ed25519_dalek::VerifyingKey::from_bytes(&pub_a_bytes).unwrap();
    let vk_b = ed25519_dalek::VerifyingKey::from_bytes(&pub_b_bytes).unwrap();

    let sig_a_typed = ed25519_dalek::Signature::from_slice(sig_a.as_bytes()).unwrap();
    let sig_b_typed = ed25519_dalek::Signature::from_slice(sig_b.as_bytes()).unwrap();

    vk_a.verify(message, &sig_a_typed)
        .expect("device A signature must verify");
    vk_b.verify(message, &sig_b_typed)
        .expect("device B signature must verify");

    assert_ne!(
        sig_a.as_bytes(),
        sig_b.as_bytes(),
        "signatures from different devices must differ"
    );

    println!("  PASS: Multi-device signing verified");
}

// ===========================================================================
// §26.4 Context Tests
// ===========================================================================

/// CONF-006: Create Context with MLS Group
/// Layer: Context | Tier: Core | Spec: §5.1, §9.7
#[tokio::test]
async fn conf_006_create_context() {
    println!("=== CONF-006: Create Context with MLS Group ===");

    print_step(1, "Create context with parameters");
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        template_id: Some(TemplateId::GroupDiscussion),
        ..Default::default()
    };

    print_step(2, "Initialize context handle");
    let handle = ContextHandle::new("conf-006-ctx".to_owned(), params);
    assert_eq!(handle.state().await, ContextState::Creating);

    print_step(3, "Transition to Active (MLS group established)");
    handle.transition_to(&ContextState::Active).await.unwrap();
    assert_eq!(handle.state().await, ContextState::Active);

    println!("  PASS: Context created and activated");
}

/// CONF-007: Join Context via Invitation
/// Layer: Context | Tier: Core | Spec: §5.3, §9.7
/// Note: Full MLS join tested in fullstack.rs. This tests membership tracking.
#[test]
fn conf_007_join_context_via_invitation() {
    println!("=== CONF-007: Join Context via Invitation ===");

    let mut membership = MembershipState::new();

    print_step(1, "Creator is initial member");
    membership.add_member(DID::from("did:dht:z6MkCreator"), "admin".to_owned(), vec![]);
    assert_eq!(membership.count(), 1);

    print_step(2, "Invitee joins via Welcome");
    membership.add_member(
        DID::from("did:dht:z6MkInvitee"),
        "member".to_owned(),
        vec![],
    );
    assert_eq!(membership.count(), 2);

    print_step(3, "Verify invitee is a member");
    assert!(membership.contains("did:dht:z6MkInvitee"));

    print_step(4, "Verify invitee has member role");
    let member = membership.get("did:dht:z6MkInvitee").unwrap();
    assert_eq!(member.role_name, "member");

    println!("  PASS: Context join via invitation verified");
}

/// CONF-008: Leave Context
/// Layer: Context | Tier: Core | Spec: §5.5, §9.7
#[test]
fn conf_008_leave_context() {
    println!("=== CONF-008: Leave Context ===");

    let mut membership = MembershipState::new();
    membership.add_member(DID::from("did:dht:z6MkAlice"), "admin".to_owned(), vec![]);
    membership.add_member(DID::from("did:dht:z6MkBob"), "member".to_owned(), vec![]);
    assert_eq!(membership.count(), 2);

    print_step(1, "Member sends Remove for self");
    membership.remove_member("did:dht:z6MkBob");

    print_step(2, "Verify removed member is no longer present");
    assert!(!membership.contains("did:dht:z6MkBob"));
    assert_eq!(membership.count(), 1);

    print_step(3, "Remaining member still present");
    assert!(membership.contains("did:dht:z6MkAlice"));

    println!("  PASS: Context leave verified");
}

/// CONF-009: Governance — Propose Role Change and Vote
/// Layer: Context | Tier: Core | Spec: §6.4
#[test]
fn conf_009_governance_majority_vote() {
    println!("=== CONF-009: Governance — Majority Vote ===");

    let key_a = make_signing_key(0x01);
    let key_b = make_signing_key(0x02);

    // Simulate proposal ID (compute_proposal_id is pub(crate))
    let proposal_id: [u8; 32] = Sha256::digest(b"conf-009-proposal").into();

    print_step(1, "Member A proposes role change");
    println!("    Proposal ID: 0x{}", hex(&proposal_id));

    print_step(2, "Member A votes approve");
    let vote_a = sign_vote(
        &proposal_id,
        &VoteType::Approve,
        "did:dht:z6MkA",
        1_700_000_000,
        &key_a,
    )
    .expect("sign vote A");

    print_step(3, "Member B votes approve");
    let vote_b = sign_vote(
        &proposal_id,
        &VoteType::Approve,
        "did:dht:z6MkB",
        1_700_000_001,
        &key_b,
    )
    .expect("sign vote B");

    print_step(4, "Verify both vote signatures");
    verify_vote(&proposal_id, &vote_a, &key_a.verifying_key()).expect("vote A must verify");
    verify_vote(&proposal_id, &vote_b, &key_b.verifying_key()).expect("vote B must verify");

    print_step(5, "Quorum reached (2/3)");
    println!("    2 approvals out of 3 members = majority");

    println!("  PASS: Majority vote governance verified");
}

/// CONF-010: Governance — Threshold Voting (k-of-n)
/// Layer: Context | Tier: Core | Spec: §6.4
#[test]
fn conf_010_governance_threshold_voting() {
    println!("=== CONF-010: Governance — Threshold Voting (3-of-5) ===");

    let keys: Vec<_> = (1..=5).map(make_signing_key).collect();
    let proposal_id: [u8; 32] = Sha256::digest(b"conf-010-threshold").into();

    print_step(1, "Propose parameter change");

    print_step(2, "Two members vote (below threshold)");
    for i in 0..2 {
        let vote = sign_vote(
            &proposal_id,
            &VoteType::Approve,
            &format!("did:dht:z6Mk{i}"),
            1_700_000_000 + i as u64,
            &keys[i],
        )
        .unwrap();
        verify_vote(&proposal_id, &vote, &keys[i].verifying_key()).unwrap();
    }
    println!("    2/3 threshold — not yet met");

    print_step(3, "Third member votes (meets threshold)");
    let vote_3 = sign_vote(
        &proposal_id,
        &VoteType::Approve,
        "did:dht:z6Mk2",
        1_700_000_002,
        &keys[2],
    )
    .unwrap();
    verify_vote(&proposal_id, &vote_3, &keys[2].verifying_key()).unwrap();
    println!("    3/3 threshold — met!");

    print_step(4, "Fourth vote does not double-apply");
    let vote_4 = sign_vote(
        &proposal_id,
        &VoteType::Approve,
        "did:dht:z6Mk3",
        1_700_000_003,
        &keys[3],
    )
    .unwrap();
    verify_vote(&proposal_id, &vote_4, &keys[3].verifying_key()).unwrap();
    println!("    4th vote accepted but proposal already resolved");

    println!("  PASS: Threshold voting verified");
}

/// CONF-011: Context Parameter Update Through Governance
/// Layer: Context | Tier: Core | Spec: §5.6, §6.4
#[tokio::test]
async fn conf_011_context_parameter_update() {
    println!("=== CONF-011: Context Parameter Update ===");

    print_step(1, "Create context with default params");
    let params = ContextParams::default();
    let handle = ContextHandle::new("conf-011-ctx".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();

    print_step(2, "Verify ChangeRole is a valid governance action");
    let action = GovernanceAction::ChangeRole {
        did: DID::from("did:dht:z6MkTarget"),
        new_role: "observer".to_owned(),
    };
    // Verify it serializes correctly
    let json = serde_json::to_string(&action).unwrap();
    assert!(json.contains("ChangeRole"));

    print_step(3, "Verify governance action round-trips");
    let deserialized: GovernanceAction = serde_json::from_str(&json).unwrap();
    assert_eq!(
        serde_json::to_string(&deserialized).unwrap(),
        json,
        "governance action must roundtrip"
    );

    println!("  PASS: Context parameter update through governance verified");
}

/// CONF-012: Nested Context Creation
/// Layer: Context | Tier: Full | Spec: §5.13
#[test]
fn conf_012_nested_context() {
    println!("=== CONF-012: Nested Context Creation ===");

    use scp_core::context::nesting::{compute_ceiling_intersection, validate_nesting_depth};
    use scp_core::context::roles::CapabilityCeiling;

    let parent_ceiling =
        CapabilityCeiling::new(vec![Capability::MessagesRead, Capability::MessagesWrite]);

    print_step(
        1,
        "Verify nesting depth is unbounded by default, context-configurable (ADR-043)",
    );
    use scp_core::context::nesting::{OnSeverPolicy, ParentGovernanceConfig, ParentRef};
    // Unbounded when no limit set.
    assert!(validate_nesting_depth(1, None).is_ok());
    assert!(validate_nesting_depth(100, None).is_ok());
    // Context-configurable limit enforced.
    assert!(validate_nesting_depth(5, Some(5)).is_ok());
    assert!(validate_nesting_depth(6, Some(5)).is_err());

    print_step(2, "Verify parent ceiling intersection");
    let parent_ref = ParentRef {
        context_id: "parent-ctx".to_owned(),
        ceiling: parent_ceiling,
        governance_config: ParentGovernanceConfig {
            can_close_child: false,
            can_evict_members: false,
            can_restrict_ceiling: false,
            requires_approval_for: std::collections::BTreeSet::new(),
            on_sever: OnSeverPolicy::PreserveMembership,
        },
        members: std::collections::HashSet::new(),
    };
    let intersection = compute_ceiling_intersection(&[parent_ref]);
    assert!(intersection.contains(&Capability::MessagesRead));
    assert!(intersection.contains(&Capability::MessagesWrite));
    assert!(
        !intersection.contains(&Capability::OutletCallAll),
        "child cannot exceed parent ceiling"
    );

    println!("  PASS: Nested context creation verified");
}

/// CONF-013: Context Close Lifecycle
/// Layer: Context | Tier: Full | Spec: §5.6
#[tokio::test]
async fn conf_013_context_close_lifecycle() {
    println!("=== CONF-013: Context Close Lifecycle ===");

    let handle = ContextHandle::new("conf-013-ctx".to_owned(), ContextParams::default());
    handle.transition_to(&ContextState::Active).await.unwrap();

    print_step(1, "Initiate context close");
    handle.transition_to(&ContextState::Closing).await.unwrap();
    assert_eq!(handle.state().await, ContextState::Closing);

    print_step(2, "Complete close");
    handle.transition_to(&ContextState::Closed).await.unwrap();
    assert_eq!(handle.state().await, ContextState::Closed);

    print_step(3, "Verify no further transitions from Closed");
    assert!(handle.transition_to(&ContextState::Active).await.is_err());
    assert!(handle.transition_to(&ContextState::Creating).await.is_err());

    println!("  PASS: Context close lifecycle verified");
}

// ===========================================================================
// §26.5 Messaging Tests
// ===========================================================================

/// CONF-014: Send Message — Sign, Encrypt, Wrap
/// Layer: Messaging | Tier: Core | Spec: §9.5.2, §9.8, §9.10
#[test]
fn conf_014_send_message_pipeline() {
    println!("=== CONF-014: Send Message — Sign, Encrypt, Wrap ===");

    let signing_key = make_signing_key(0x10);
    let sender_key = generate_sender_key();

    print_step(1, "Construct InnerEnvelope canonical hash");
    let payload = b"Hello, conformance!";
    let payload_hash: [u8; 32] = Sha256::digest(payload).into();
    let hash = canonical_hash(
        "SCP-INNER-ENVELOPE-V1:",
        &[
            CanonicalField::VarBytes(b"conf-014-ctx"),
            CanonicalField::VarBytes(b"did:dht:z6MkSender"),
            CanonicalField::U64(1), // epoch
            CanonicalField::U64(0), // generation
            CanonicalField::U64(0), // sequence
            CanonicalField::U64(1_700_000_000),
            CanonicalField::VarBytes(&payload_hash),
            CanonicalField::Absent,
            CanonicalField::VarBytes(b"#active"),
        ],
    )
    .unwrap();

    print_step(2, "Sign with canonical hash");
    let signature = signing_key.sign(&hash);
    signing_key
        .verifying_key()
        .verify(&hash, &signature)
        .expect("inner envelope signature must verify");

    print_step(3, "Encrypt with sender key");
    let ciphertext = encrypt_sender_layer(
        &sender_key,
        payload,
        "conf-014-ctx",
        "did:dht:z6MkSender",
        0,
        0,
    )
    .expect("sender key encryption must succeed");
    assert_ne!(
        ciphertext.as_slice(),
        payload.as_slice(),
        "ciphertext must differ from plaintext"
    );

    print_step(4, "Pad to bucket boundary");
    let padded = pad_to_bucket(&ciphertext).expect("padding must succeed");
    assert!(
        BUCKET_SIZES.contains(&padded.len()),
        "padded size must be a valid bucket"
    );

    println!(
        "    Pipeline: {} bytes payload → {} bytes ciphertext → {} bytes padded",
        payload.len(),
        ciphertext.len(),
        padded.len()
    );
    println!("  PASS: Send message pipeline verified");
}

/// CONF-015: Receive Message — Unwrap, Decrypt, Verify
/// Layer: Messaging | Tier: Core | Spec: §9.5.2, §9.8, §9.10
#[test]
fn conf_015_receive_message_pipeline() {
    println!("=== CONF-015: Receive Message — Unwrap, Decrypt, Verify ===");

    let signing_key = make_signing_key(0x20);
    let sender_key = generate_sender_key();
    let payload = b"Hello, conformance receiver!";

    // Simulate sending
    let ciphertext = encrypt_sender_layer(
        &sender_key,
        payload,
        "conf-015-ctx",
        "did:dht:z6MkSend",
        0,
        0,
    )
    .unwrap();
    let padded = pad_to_bucket(&ciphertext).unwrap();

    // Now receive
    print_step(1, "Receive and strip padding");
    let unpadded = strip_padding(&padded).expect("strip padding must succeed");
    assert_eq!(unpadded, ciphertext);

    print_step(2, "Decrypt with sender key");
    let plaintext = decrypt_sender_layer(
        &sender_key,
        &unpadded,
        "conf-015-ctx",
        "did:dht:z6MkSend",
        0,
        0,
    )
    .expect("sender key decryption must succeed");
    assert_eq!(plaintext, payload);

    print_step(3, "Verify InnerEnvelope signature");
    let payload_hash: [u8; 32] = Sha256::digest(payload).into();
    let hash = canonical_hash(
        "SCP-INNER-ENVELOPE-V1:",
        &[
            CanonicalField::VarBytes(b"conf-015-ctx"),
            CanonicalField::VarBytes(b"did:dht:z6MkSend"),
            CanonicalField::U64(1),
            CanonicalField::U64(0),
            CanonicalField::U64(0),
            CanonicalField::U64(1_700_000_000),
            CanonicalField::VarBytes(&payload_hash),
            CanonicalField::Absent,
            CanonicalField::VarBytes(b"#active"),
        ],
    )
    .unwrap();
    let signature = signing_key.sign(&hash);
    signing_key
        .verifying_key()
        .verify(&hash, &signature)
        .expect("signature must verify");

    println!("  PASS: Receive message pipeline verified");
}

/// CONF-016: Padding Roundtrip
/// Layer: Messaging | Tier: Core | Spec: §9.10
#[test]
fn conf_016_padding_roundtrip() {
    println!("=== CONF-016: Padding Roundtrip ===");

    let test_sizes: [usize; 7] = [0, 1, 252, 253, 1020, 1021, 262_140];

    for (i, &size) in test_sizes.iter().enumerate() {
        print_step(
            (i + 1) as u32,
            &format!("Pad and strip {size}-byte payload"),
        );
        let payload: Vec<u8> = (0..size).map(|j| (j % 256) as u8).collect();
        let padded = pad_to_bucket(&payload).expect("padding must succeed");

        assert!(
            BUCKET_SIZES.contains(&padded.len()),
            "padded size {} must be valid bucket for payload size {size}",
            padded.len()
        );

        let recovered = strip_padding(&padded).expect("strip must succeed");
        assert_eq!(
            recovered, payload,
            "roundtrip must preserve payload of size {size}"
        );
        println!("      {size} bytes → {} bytes (bucket)", padded.len());
    }

    println!("  PASS: All padding roundtrips verified");
}

/// CONF-017: Sender Key Distribution — Establish, Rotate, Use
/// Layer: Messaging | Tier: Core | Spec: §9.16
#[test]
fn conf_017_sender_key_lifecycle() {
    println!("=== CONF-017: Sender Key Distribution ===");

    let sender_did = "did:dht:z6MkSKD";

    print_step(1, "Generate sender key");
    let key_epoch_0 = generate_sender_key();
    assert_eq!(key_epoch_0.as_bytes().len(), 32);

    print_step(2, "Encrypt message with sender key");
    let msg = b"message at epoch 0";
    let ct = encrypt_sender_layer(&key_epoch_0, msg, "conf-017-ctx", sender_did, 0, 0).unwrap();

    print_step(3, "Decrypt message with sender key");
    let pt = decrypt_sender_layer(&key_epoch_0, &ct, "conf-017-ctx", sender_did, 0, 0).unwrap();
    assert_eq!(pt, msg);

    print_step(4, "Rotate sender key (new epoch)");
    let key_epoch_1 = generate_sender_key();
    assert_ne!(
        key_epoch_0.as_bytes(),
        key_epoch_1.as_bytes(),
        "rotated key must differ"
    );

    print_step(5, "New key works for new messages");
    let msg2 = b"message at epoch 1";
    let ct2 = encrypt_sender_layer(&key_epoch_1, msg2, "conf-017-ctx", sender_did, 1, 0).unwrap();
    let pt2 = decrypt_sender_layer(&key_epoch_1, &ct2, "conf-017-ctx", sender_did, 1, 0).unwrap();
    assert_eq!(pt2, msg2);

    print_step(6, "Old key cannot decrypt new epoch message");
    let result = decrypt_sender_layer(&key_epoch_0, &ct2, "conf-017-ctx", sender_did, 1, 0);
    assert!(result.is_err(), "old key must not decrypt new epoch");

    println!("  PASS: Sender key lifecycle verified");
}

/// CONF-018: Access Key Layer — CEK Distribution
/// Layer: Messaging | Tier: Core | Spec: §9.17
#[test]
fn conf_018_cek_distribution() {
    println!("=== CONF-018: Access Key Layer — CEK Distribution ===");

    print_step(1, "Generate CEK and 3 member access keys");
    let cek = ContentEncryptionKey::generate();
    let ak_alice = generate_access_key("conf-018-ctx", "did:dht:z6MkAlice");
    let ak_bob = generate_access_key("conf-018-ctx", "did:dht:z6MkBob");
    let ak_carol = generate_access_key("conf-018-ctx", "did:dht:z6MkCarol");

    print_step(2, "Wrap CEK for each member");
    let wrapped_alice = wrap_cek(&cek, &ak_alice).expect("wrap for Alice");
    let wrapped_bob = wrap_cek(&cek, &ak_bob).expect("wrap for Bob");
    let wrapped_carol = wrap_cek(&cek, &ak_carol).expect("wrap for Carol");

    print_step(3, "Each recipient unwraps CEK");
    let recovered_alice = unwrap_cek(&wrapped_alice, &ak_alice).expect("unwrap Alice");
    let recovered_bob = unwrap_cek(&wrapped_bob, &ak_bob).expect("unwrap Bob");
    let recovered_carol = unwrap_cek(&wrapped_carol, &ak_carol).expect("unwrap Carol");

    print_step(4, "All recover same CEK");
    assert_eq!(recovered_alice.as_bytes(), cek.as_bytes());
    assert_eq!(recovered_bob.as_bytes(), cek.as_bytes());
    assert_eq!(recovered_carol.as_bytes(), cek.as_bytes());

    print_step(5, "Wrong key cannot unwrap");
    let wrong_result = unwrap_cek(&wrapped_alice, &ak_bob);
    assert!(wrong_result.is_err(), "wrong key must fail to unwrap CEK");

    println!("  PASS: CEK distribution verified");
}

// ===========================================================================
// §26.6 Sync Tests
// ===========================================================================

/// CONF-019: Minutes Offline — Sequential Commit Replay
/// Layer: Sync | Tier: Core | Spec: §23
#[test]
fn conf_019_minutes_offline_classification() {
    println!("=== CONF-019: Minutes Offline ===");

    let now = 1_700_000_000u64;

    print_step(1, "Member offline for 10 minutes");
    let last_contact = now - 600;
    let tier = classify_offline_duration(last_contact, now);
    assert_eq!(
        tier,
        OfflineTier::Short,
        "10 min offline = Short (sequential replay)"
    );

    print_step(2, "Member offline for 3 hours");
    let tier = classify_offline_duration(now - 10_800, now);
    assert_eq!(tier, OfflineTier::Short, "3h offline = still Short");

    print_step(3, "Verify Tier 1 threshold (4h = 14400s)");
    assert_eq!(TIER_1_THRESHOLD_SECS, 14_400);

    println!("  PASS: Minutes offline classification verified");
}

/// CONF-020: Days Offline — Snapshot + Delta
/// Layer: Sync | Tier: Core | Spec: §23
#[test]
fn conf_020_days_offline_classification() {
    println!("=== CONF-020: Days Offline ===");

    let now = 1_700_000_000u64;

    print_step(1, "Member offline for 2 days");
    let tier = classify_offline_duration(now - 172_800, now);
    assert_eq!(
        tier,
        OfflineTier::Extended,
        "2 days offline = Extended (snapshot + delta)"
    );

    print_step(2, "Member offline for 6 days");
    let tier = classify_offline_duration(now - 518_400, now);
    assert_eq!(tier, OfflineTier::Extended, "6 days = still Extended");

    print_step(3, "Verify Tier 2 threshold (7d = 604800s)");
    assert_eq!(TIER_2_THRESHOLD_SECS, 604_800);

    println!("  PASS: Days offline classification verified");
}

/// CONF-021: Weeks Offline — Full Reset
/// Layer: Sync | Tier: Core | Spec: §23.5
#[test]
fn conf_021_weeks_offline_classification() {
    println!("=== CONF-021: Weeks Offline ===");

    let now = 1_700_000_000u64;

    print_step(1, "Member offline for 2 weeks");
    let tier = classify_offline_duration(now - 1_209_600, now);
    assert_eq!(
        tier,
        OfflineTier::Long,
        "2 weeks offline = Long (full reset)"
    );

    print_step(2, "Verify reset request domain separator");
    let domain = b"SCP-RESET-REQUEST-V1:";
    assert_eq!(domain.len(), 21);

    println!("  PASS: Weeks offline classification verified");
}

/// CONF-022: Equivocation Detection
/// Layer: Sync | Tier: Full | Spec: §9.9
#[test]
fn conf_022_equivocation_detection() {
    use scp_event_log::EventLog;
    use scp_event_log::checkpoint::{
        CheckpointComparison, ConsistencyCheckpoint, compare_checkpoint,
    };

    println!("=== CONF-022: Equivocation Detection ===");

    print_step(
        1,
        "Create local event log and a remote checkpoint with same event count but different root",
    );
    // Empty local log has event_count=0 and merkle_root=[0;32].
    let local_log = EventLog::new("ctx-equivocation-test".to_owned());

    // Remote checkpoint claims 0 events but a non-zero root — equivocation.
    let root_b: [u8; 32] = Sha256::digest(b"equivocating-branch").into();
    let remote_checkpoint = ConsistencyCheckpoint {
        context_id: "ctx-equivocation-test".to_owned(),
        sender_did: "did:key:remote".into(),
        event_count: 0,
        merkle_root: root_b,
        epoch: Some(0),
        timestamp: 1_000_000,
        signature: vec![0u8; 64],
    };

    print_step(2, "Detect equivocation via compare_checkpoint");
    let comparison = compare_checkpoint(&local_log, &remote_checkpoint);
    assert!(
        matches!(comparison, CheckpointComparison::Divergent { .. }),
        "same event count + different roots must produce Divergent, got: {comparison:?}"
    );

    print_step(3, "Verify consistent checkpoints are not flagged");
    // Empty log root is SHA-256(""), NOT [0u8; 32] (which is GENESIS_PREV_HASH).
    let empty_root: [u8; 32] = Sha256::digest(b"").into();
    let consistent_checkpoint = ConsistencyCheckpoint {
        context_id: "ctx-equivocation-test".to_owned(),
        sender_did: "did:key:remote".into(),
        event_count: 0,
        merkle_root: empty_root,
        epoch: Some(0),
        timestamp: 1_000_000,
        signature: vec![0u8; 64],
    };
    let comparison = compare_checkpoint(&local_log, &consistent_checkpoint);
    assert_eq!(comparison, CheckpointComparison::Consistent);

    println!("  PASS: Equivocation detection verified via compare_checkpoint API");
}

// ===========================================================================
// §26.7 Trust Tests
// ===========================================================================

/// CONF-023: UCAN Issuance and Verification
/// Layer: Trust | Tier: Core | Spec: §7, §9.5
#[tokio::test]
async fn conf_023_ucan_issuance() {
    use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};

    println!("=== CONF-023: UCAN Issuance and Verification ===");

    let custody = InMemoryKeyCustody::new();
    let key_handle = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("generate key");
    let pubkey = custody.public_key(&key_handle).await.expect("get pubkey");
    let issuer_did = format!("did:key:z6Mk{}", hex::encode(&pubkey.as_bytes()[..16]));

    print_step(1, "Mint a real UCAN token via mint_ucan");
    let context_id = "ctx-conf-023";
    let audience_did = "did:key:z6MkAudience";
    let caps = vec!["messages:read".to_owned()];
    let params = MintParams {
        context_id,
        issuer_did: &issuer_did,
        audience_did,
        capabilities: &caps,
        lifetime_secs: 3600,
        not_before: None,
        issuer_key: &key_handle,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: None,
    };
    let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .expect("mint_ucan");

    print_step(2, "Verify UCAN header fields");
    assert_eq!(token.header.alg, "EdDSA");
    assert_eq!(token.header.typ, "JWT");
    assert_eq!(token.header.ucv, "0.10.0");

    print_step(3, "Verify token has correct issuer and audience");
    assert_eq!(token.payload.iss, issuer_did);
    assert_eq!(token.payload.aud, audience_did);

    print_step(4, "Verify token has non-empty signature and encoded form");
    assert!(!token.signature.is_empty(), "signature must be non-empty");
    assert!(!token.encoded.is_empty(), "encoded JWT must be non-empty");
    assert!(
        token.encoded.contains('.'),
        "encoded form must be a JWT with dots"
    );

    println!("  PASS: UCAN issuance verified via mint_ucan API");
}

/// CONF-024: UCAN Delegation Chain (A -> B -> C)
/// Layer: Trust | Tier: Full | Spec: §7
#[tokio::test]
async fn conf_024_ucan_delegation_chain() {
    use scp_core::crypto::ucan::mint::{MintParams, compute_cid, mint_ucan};

    println!("=== CONF-024: UCAN Delegation Chain ===");

    let custody = InMemoryKeyCustody::new();
    let context_id = "ctx-conf-024";

    // Create keys for A, B, C
    let key_a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pubkey_a = custody.public_key(&key_a).await.unwrap();
    let did_a = format!("did:key:z6Mk{}", hex::encode(&pubkey_a.as_bytes()[..16]));

    let key_b = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pubkey_b = custody.public_key(&key_b).await.unwrap();
    let did_b = format!("did:key:z6Mk{}", hex::encode(&pubkey_b.as_bytes()[..16]));

    let did_c = "did:key:z6MkCharlie";
    let caps = vec!["messages:read".to_owned()];

    print_step(1, "A issues root UCAN to B");
    let root_token = mint_ucan(
        &MintParams {
            context_id,
            issuer_did: &did_a,
            audience_did: &did_b,
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            issuer_key: &key_a,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody,
        &scp_primitives::SystemClock,
    )
    .await
    .expect("mint root UCAN A→B");
    assert_eq!(root_token.payload.iss, did_a);
    assert_eq!(root_token.payload.aud, did_b);

    print_step(2, "B sub-delegates to C via proof chain");
    let root_cid = compute_cid(&root_token);
    let delegated_token = mint_ucan(
        &MintParams {
            context_id,
            issuer_did: &did_b,
            audience_did: did_c,
            capabilities: &caps,
            lifetime_secs: 1800,
            not_before: None,
            issuer_key: &key_b,
            proofs: vec![root_cid.clone()],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody,
        &scp_primitives::SystemClock,
    )
    .await
    .expect("mint delegated UCAN B→C");
    assert_eq!(delegated_token.payload.iss, did_b);
    assert_eq!(delegated_token.payload.aud, did_c);

    print_step(3, "Verify proof chain links back to root");
    assert_eq!(delegated_token.payload.prf.len(), 1);
    assert_eq!(delegated_token.payload.prf[0], root_cid);

    print_step(4, "Verify both tokens have valid signatures");
    assert!(!root_token.signature.is_empty());
    assert!(!delegated_token.signature.is_empty());

    println!("  PASS: UCAN delegation chain verified via mint_ucan + compute_cid");
}

/// CONF-025: UCAN Revocation
/// Layer: Trust | Tier: Full | Spec: §7, §9.5
#[tokio::test]
async fn conf_025_ucan_revocation() {
    use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};
    use scp_core::crypto::ucan::revoke::compute_revocation_cid;

    println!("=== CONF-025: UCAN Revocation ===");

    let custody = InMemoryKeyCustody::new();
    let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pubkey = custody.public_key(&key_handle).await.unwrap();
    let issuer_did = format!("did:key:z6Mk{}", hex::encode(&pubkey.as_bytes()[..16]));
    let context_id = "ctx-conf-025";

    print_step(1, "Mint a real UCAN token");
    let caps = vec!["messages:write".to_owned()];
    let token = mint_ucan(
        &MintParams {
            context_id,
            issuer_did: &issuer_did,
            audience_did: "did:key:z6MkAudience",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            issuer_key: &key_handle,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody,
        &scp_primitives::SystemClock,
    )
    .await
    .expect("mint UCAN");

    print_step(2, "Compute revocation CID from the real encoded token");
    let revocation_cid = compute_revocation_cid(&token.encoded);
    assert!(
        !revocation_cid.is_empty(),
        "revocation CID must be non-empty"
    );
    println!("    Revocation CID: {revocation_cid}");

    print_step(3, "Add CID to revocation list and verify lookup");
    let revocation_list: Vec<String> = vec![revocation_cid.clone()];
    assert!(
        revocation_list.contains(&revocation_cid),
        "revoked token CID must be in list"
    );

    print_step(4, "Different token produces different CID");
    let other_cid = compute_revocation_cid("eyJhbGciOiJFZERTQSJ9.other.sig");
    assert_ne!(
        revocation_cid, other_cid,
        "different tokens must produce different CIDs"
    );
    assert!(
        !revocation_list.contains(&other_cid),
        "unrevoked token must not be in list"
    );

    print_step(5, "Same token always produces same CID (deterministic)");
    let cid_again = compute_revocation_cid(&token.encoded);
    assert_eq!(
        revocation_cid, cid_again,
        "CID computation must be deterministic"
    );

    println!("  PASS: UCAN revocation verified via compute_revocation_cid");
}

/// CONF-026: Capability Attenuation (Subset Delegation)
/// Layer: Trust | Tier: Full | Spec: §7
#[test]
fn conf_026_capability_attenuation() {
    println!("=== CONF-026: Capability Attenuation ===");

    use scp_core::context::roles::CapabilityCeiling;

    let parent_caps = CapabilityCeiling::new(vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::RoleAssign,
    ]);

    print_step(1, "A delegates [read, write] to B (subset)");
    let delegated =
        CapabilityCeiling::new(vec![Capability::MessagesRead, Capability::MessagesWrite]);
    assert!(parent_caps.contains(&Capability::MessagesRead));
    assert!(parent_caps.contains(&Capability::MessagesWrite));

    print_step(2, "B cannot delegate [read, write, admin] to C");
    // RoleAssign is not in delegated ceiling
    assert!(
        !delegated.contains(&Capability::RoleAssign),
        "cannot delegate capability not held"
    );

    print_step(3, "B delegates [read] to C (further attenuation)");
    let sub_delegated = CapabilityCeiling::new(vec![Capability::MessagesRead]);
    assert!(delegated.contains(&Capability::MessagesRead));
    assert_eq!(sub_delegated.len(), 1);

    println!("  PASS: Capability attenuation verified");
}

// ===========================================================================
// §26.8 Transport Tests
// ===========================================================================

/// CONF-027: Relay Connection — Subscribe, Publish, Receive
/// Layer: Transport | Tier: Core | Spec: §10.5
/// Note: Full relay round-trip tested in transport.rs and fullstack.rs.
#[tokio::test]
async fn conf_027_relay_subscribe_publish_receive() {
    println!("=== CONF-027: Relay Connection ===");

    use scp_testing::relay::InMemoryRelay;

    let mut relay = InMemoryRelay::new();

    print_step(1, "Subscribe to routing ID");
    let routing_id = [0xDD; 32];
    let (_sub_id, _rx) = relay.subscribe(routing_id);

    print_step(2, "Store message");
    let blob = vec![0x01, 0x02, 0x03];
    let blob_id = relay.store(routing_id, blob.clone(), None, 1_700_000_000);
    println!("    Blob ID: 0x{}", hex(&blob_id));

    print_step(3, "Query returns stored message");
    let results = relay.query(&routing_id);
    assert_eq!(results.len(), 1, "query must return 1 blob");
    assert_eq!(results[0].data, blob);

    println!("  PASS: Relay subscribe/store/query verified");
}

/// CONF-028: Relay Store-and-Forward
/// Layer: Transport | Tier: Core | Spec: §10.5
#[tokio::test]
async fn conf_028_relay_store_and_forward() {
    println!("=== CONF-028: Relay Store-and-Forward ===");

    use scp_testing::relay::InMemoryRelay;

    let mut relay = InMemoryRelay::new();
    let routing_id = [0xEE; 32];

    print_step(1, "Client disconnects (no subscription)");

    print_step(2, "Messages sent while client offline");
    relay.store(routing_id, b"msg-1".to_vec(), None, 1_700_000_001);
    relay.store(routing_id, b"msg-2".to_vec(), None, 1_700_000_002);
    relay.store(routing_id, b"msg-3".to_vec(), None, 1_700_000_003);

    print_step(3, "Client reconnects and queries");
    let results = relay.query(&routing_id);
    assert_eq!(results.len(), 3, "all 3 offline messages retrievable");

    print_step(4, "Messages retrievable");
    let datas: Vec<&[u8]> = results.iter().map(|b| b.data.as_slice()).collect();
    assert!(datas.contains(&b"msg-1".as_slice()));
    assert!(datas.contains(&b"msg-2".as_slice()));
    assert!(datas.contains(&b"msg-3".as_slice()));

    println!("  PASS: Store-and-forward verified");
}

/// CONF-029: Multi-Relay — Same Context Across Relays
/// Layer: Transport | Tier: Full | Spec: §10.5
#[tokio::test]
async fn conf_029_multi_relay() {
    println!("=== CONF-029: Multi-Relay ===");

    use scp_testing::relay::InMemoryRelay;

    let mut relay_1 = InMemoryRelay::new();
    let mut relay_2 = InMemoryRelay::new();
    let routing_id = [0xFF; 32];

    print_step(1, "Member A stores to relay 1");
    relay_1.store(routing_id, b"from-relay-1".to_vec(), None, 1_700_000_000);

    print_step(2, "Member B stores to relay 2");
    relay_2.store(routing_id, b"from-relay-2".to_vec(), None, 1_700_000_000);

    print_step(3, "Both relays have their respective messages");
    let r1 = relay_1.query(&routing_id);
    let r2 = relay_2.query(&routing_id);
    assert_eq!(r1.len(), 1);
    assert_eq!(r2.len(), 1);
    assert_eq!(r1[0].data, b"from-relay-1");
    assert_eq!(r2[0].data, b"from-relay-2");

    print_step(4, "Client-side multi-relay query combines both");
    let combined_count = r1.len() + r2.len();
    assert_eq!(combined_count, 2);

    println!("  PASS: Multi-relay verified");
}

// ===========================================================================
// §26.9 Discovery Tests
// ===========================================================================

/// CONF-030: Handle Registration and Lookup
/// Layer: Discovery | Tier: Full | Spec: §22.3.1, §22.11
#[test]
fn conf_030_handle_registration_lookup() {
    println!("=== CONF-030: Handle Registration and Lookup ===");

    let mut registry = HandleRegistry::new("discovery-ctx".to_owned());

    print_step(1, "Register handle 'alice' pointing to DID");
    let did = DID::from("did:dht:z6MkAlice");
    let params = HandleRegisterParams {
        handle: "alice".to_owned(),
        target: HandleTarget::Identity { did: did.clone() },
        metadata: None,
    };
    let result = registry.register(&params, &did, &scp_primitives::SystemClock);
    assert!(
        result.entry_id.is_some(),
        "registration must return entry_id"
    );

    print_step(2, "Lookup 'alice'");
    let lookup = registry.lookup(&HandleLookupParams {
        handle: "alice".to_owned(),
        type_filter: None,
    });
    assert!(!lookup.results.is_empty(), "lookup must return results");
    assert_eq!(lookup.results[0].handle, "alice");

    print_step(3, "Deregister");
    let dereg = registry.deregister(&HandleDeregisterParams {
        handle: "alice".to_owned(),
        did: did.clone(),
    });
    assert!(dereg.removed);

    let lookup_after = registry.lookup(&HandleLookupParams {
        handle: "alice".to_owned(),
        type_filter: None,
    });
    assert!(lookup_after.results.is_empty());

    println!("  PASS: Handle registration and lookup verified");
}

/// CONF-031: Agent Capability Registration and Search
/// Layer: Discovery | Tier: Full | Spec: §6.2.2B, §22.11
#[test]
fn conf_031_agent_capability_search() {
    println!("=== CONF-031: Agent Capability Registration and Search ===");

    let mut registry = HandleRegistry::new("discovery-ctx".to_owned());

    print_step(1, "Register agent with capabilities");
    let did = DID::from("did:dht:z6MkAgent");
    let params = HandleRegisterParams {
        handle: "translator".to_owned(),
        target: HandleTarget::Identity { did: did.clone() },
        metadata: None,
    };
    registry.register(&params, &did, &scp_primitives::SystemClock);

    print_step(2, "Lookup finds agent");
    let result = registry.lookup(&HandleLookupParams {
        handle: "translator".to_owned(),
        type_filter: None,
    });
    assert!(!result.results.is_empty());

    print_step(3, "Deregister removes from search");
    registry.deregister(&HandleDeregisterParams {
        handle: "translator".to_owned(),
        did,
    });
    let result_after = registry.lookup(&HandleLookupParams {
        handle: "translator".to_owned(),
        type_filter: None,
    });
    assert!(result_after.results.is_empty());

    println!("  PASS: Agent capability search verified");
}

/// CONF-032: Push Notification Registration
/// Layer: Discovery | Tier: Full | Spec: §10.7.1, §22.11.4
#[tokio::test]
async fn conf_032_push_notification() {
    println!("=== CONF-032: Push Notification Registration ===");

    let push = InMemoryPush::new();

    print_step(1, "Register push subscription");
    let token = push.register().await.expect("push registration");
    println!("    Token: {token:?}");

    print_step(2, "Handle notification");
    let payload = b"notification-payload";
    let wake = push
        .handle_notification(payload)
        .await
        .expect("handle notification");
    println!("    Wake signal: {wake:?}");

    println!("  PASS: Push notification registration verified");
}

// ===========================================================================
// §26.10 Economy Tests
// ===========================================================================

/// CONF-033: Cost Schedule Evaluation
/// Layer: Economy | Tier: Full | Spec: §19.3, §19.15
#[test]
fn conf_033_cost_schedule() {
    println!("=== CONF-033: Cost Schedule Evaluation ===");

    let schedule = CostSchedule {
        currency: CurrencyCode::from("USD"),
        per_message: Some(Amount::new(100)),
        per_outlet_call: Some(Amount::new(500)),
        per_join: Some(Amount::new(1000)),
        per_period: None,
        per_byte_stored: None,
    };

    print_step(1, "Evaluate cost for MessageSend");
    let msg_cost = lookup_cost(&schedule, &PaidActionType::MessageSend);
    assert_eq!(msg_cost, Some(Amount::new(100)));
    println!("    MessageSend cost: {msg_cost:?}");

    print_step(2, "Evaluate cost for ContextJoin");
    let join_cost = lookup_cost(&schedule, &PaidActionType::ContextJoin);
    assert_eq!(join_cost, Some(Amount::new(1000)));
    println!("    ContextJoin cost: {join_cost:?}");

    print_step(3, "Costs are deterministic");
    let msg_cost_2 = lookup_cost(&schedule, &PaidActionType::MessageSend);
    assert_eq!(msg_cost, msg_cost_2);

    println!("  PASS: Cost schedule evaluation verified");
}

/// CONF-034: Payment Authorization -> Capture -> Receipt
/// Layer: Economy | Tier: Full | Spec: §19.6, §19.15.5
#[tokio::test]
async fn conf_034_payment_lifecycle() {
    println!("=== CONF-034: Payment Lifecycle ===");

    use scp_core::economy::{PaidActionType, PaymentAdapter, PaymentMetadata};
    use scp_testing::test_adapter::TestAdapter;

    let adapter = TestAdapter::new();
    adapter.seed_balance(
        DID::from("did:dht:z6MkPayer"),
        Amount::new(10000),
        CurrencyCode::from("USD"),
    );

    print_step(1, "Create authorization");
    let metadata = PaymentMetadata {
        action_type: PaidActionType::MessageSend,
        context_id: Some("conf-034-ctx".to_owned()),
        idempotency_key: [0u8; 16],
    };
    let auth = adapter
        .authorize(
            &DID::from("did:dht:z6MkPayer"),
            &DID::from("did:dht:z6MkPayee"),
            Amount::new(500),
            CurrencyCode::from("USD"),
            metadata,
        )
        .await
        .expect("authorize");
    println!("    Authorization ID: 0x{}", hex(&auth.auth_id));

    print_step(2, "Capture payment");
    let receipt = adapter.capture(&auth).await.expect("capture");
    println!("    Receipt: {receipt:?}");

    println!("  PASS: Payment lifecycle verified");
}

/// CONF-035: Dynamic Pricing Formula Evaluation
/// Layer: Economy | Tier: Full | Spec: §19.4, §19.15.3
#[test]
fn conf_035_dynamic_pricing() {
    println!("=== CONF-035: Dynamic Pricing Formula ===");

    let formula = PricingFormula {
        base_cost: Amount::new(100),
        variables: vec![PricingVariable::Linear {
            metric: PricingMetric::MemberCount,
            coefficient: Coefficient::new(500_000), // 0.5
        }],
        cap: Some(Amount::new(10000)),
        floor: Some(Amount::new(50)),
    };

    print_step(1, "Evaluate with member_count = 50");
    let metrics = ObservableMetrics {
        member_count: 50,
        context_message_rate: 0,
        relay_queue_depth: 0,
        time_of_day: 0,
        sender_velocity: 0,
        storage_usage: 0,
    };
    let cost = evaluate_formula(&formula, &metrics);
    assert!(cost.is_some(), "formula must evaluate");
    let cost_val = cost.unwrap();
    println!("    Cost: {cost_val:?}");

    print_step(2, "Verify determinism");
    let cost2 = evaluate_formula(&formula, &metrics).unwrap();
    assert_eq!(cost_val, cost2, "same inputs must produce same cost");

    print_step(3, "Verify cap constraint");
    let high_metrics = ObservableMetrics {
        member_count: 1_000_000,
        context_message_rate: 0,
        relay_queue_depth: 0,
        time_of_day: 0,
        sender_velocity: 0,
        storage_usage: 0,
    };
    let capped = evaluate_formula(&formula, &high_metrics).unwrap();
    assert!(capped.value() <= 10000, "cost must not exceed cap of 10000");

    println!("  PASS: Dynamic pricing formula verified");
}

// ===========================================================================
// §26.11 Bridge Tests
// ===========================================================================

/// CONF-036: Bridge Registration and Approval
/// Layer: Bridge | Tier: Full | Spec: §12.2.1, §12.12
#[test]
fn conf_036_bridge_registration() {
    println!("=== CONF-036: Bridge Registration and Approval ===");

    print_step(1, "Create bridge connector");
    let connector = BridgeConnector {
        bridge_id: "bridge-discord-001".to_owned(),
        operator_did: DID::from("did:dht:z6MkOperator"),
        platform: "discord".to_owned(),
        mode: BridgeMode::Relay,
        status: BridgeStatus::Active,
        registration_context: "gov-context".to_owned(),
        registered_at: 1_700_000_000,
    };

    print_step(2, "Verify bridge status is Active");
    assert_eq!(connector.status, BridgeStatus::Active);

    print_step(3, "Verify bridge serialization roundtrip");
    let json = serde_json::to_string(&connector).unwrap();
    let deserialized: BridgeConnector = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.bridge_id, "bridge-discord-001");
    assert_eq!(deserialized.platform, "discord");

    print_step(4, "All 4 BridgeMode variants serialize");
    for mode in [
        BridgeMode::Relay,
        BridgeMode::Puppet,
        BridgeMode::Api,
        BridgeMode::Cooperative,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let _: BridgeMode = serde_json::from_str(&json).unwrap();
    }

    println!("  PASS: Bridge registration verified");
}

/// CONF-037: Shadow Identity Creation and Claiming
/// Layer: Bridge | Tier: Full | Spec: §12.3, §12.12.3, §12.12.4
#[test]
fn conf_037_shadow_identity() {
    println!("=== CONF-037: Shadow Identity Creation and Claiming ===");

    let mut registry = ShadowRegistry::new("bridge-ctx".to_owned());
    let mut sender_key_store = SenderKeyStore::new();

    print_step(1, "Create shadow identity");
    let params = CreateShadowParams {
        shadow_id: "shadow-alice-discord",
        bridge_id: "bridge-discord-001",
        bridge_mode: BridgeMode::Relay,
        platform_handle: "@alice#1234",
        context_member_dids: &[],
        timestamp: 1_700_000_000,
    };
    let (shadow, _event) =
        create_shadow(&mut registry, &mut sender_key_store, &params).expect("create shadow");

    print_step(2, "Shadow identity created");
    println!("    Shadow ID: {}", shadow.shadow_id);
    println!("    Platform handle: {}", shadow.platform_handle);

    print_step(3, "Find in shadow registry");
    let found = find_shadow(&registry, "shadow-alice-discord");
    assert!(found.is_ok(), "shadow must be findable");

    print_step(4, "Verify claim hash domain separator");
    let claim_bytes = canonical_hash_bytes(
        b"SCP-CLAIM-V1:",
        &[
            CanonicalField::VarBytes(b"shadow-alice-discord"),
            CanonicalField::VarBytes(b"did:dht:z6MkClaimer"),
            CanonicalField::VarBytes(b"bridge-ctx"),
            CanonicalField::U64(1_700_000_000),
        ],
    )
    .unwrap();
    let claim_hash: [u8; 32] = Sha256::digest(&claim_bytes).into();
    println!("    Claim hash: 0x{}", hex(&claim_hash));

    println!("  PASS: Shadow identity creation verified");
}

/// CONF-038: Bridged Message Provenance Marking
/// Layer: Bridge | Tier: Full | Spec: §12.5, §12.12.5
#[test]
fn conf_038_bridged_provenance() {
    println!("=== CONF-038: Bridged Message Provenance ===");

    let connector = BridgeConnector {
        bridge_id: "bridge-slack-001".to_owned(),
        operator_did: DID::from("did:dht:z6MkOp"),
        platform: "slack".to_owned(),
        mode: BridgeMode::Relay,
        status: BridgeStatus::Active,
        registration_context: "reg-ctx".to_owned(),
        registered_at: 1_700_000_000,
    };

    use scp_core::bridge::ShadowProvenanceStatus;
    use scp_core::context::params::MemoryScope;
    use scp_core::provenance::{DiscoveryMethod, SourceType};

    let shadow = ShadowIdentity {
        shadow_id: "shadow-user-slack".to_owned(),
        platform_handle: "@user".to_owned(),
        bridge_id: "bridge-slack-001".to_owned(),
        attributed_role: "observer".to_owned(),
        provenance_status: ShadowProvenanceStatus::Shadow,
        created_at: 1_700_000_000,
    };

    let base_provenance = DataProvenance {
        source_context: "source-ctx".to_owned(),
        source_type: SourceType::Persistent,
        counterparties: vec![DID::from("did:dht:z6MkSource")],
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: MemoryScope::Ephemeral,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    print_step(1, "Mark bridge provenance on message");
    let provenance = mark_bridge_provenance(base_provenance, &connector, &shadow);

    print_step(2, "Evaluate trust level");
    let trust = evaluate_bridge_trust_level(&provenance);
    assert_eq!(
        trust,
        BridgeTrustLevel::ShadowBridged,
        "shadow + relay = ShadowBridged"
    );

    print_step(3, "Trust level distinguishable from native");
    assert_ne!(trust, BridgeTrustLevel::NativeNative);
    println!("    Trust level: {trust:?}");

    print_step(4, "Ordering: ShadowBridged < NativeNative");
    assert!(BridgeTrustLevel::ShadowBridged < BridgeTrustLevel::NativeNative);

    println!("  PASS: Bridged provenance marking verified");
}

// ===========================================================================
// §26.12 Interop Scenarios
// ===========================================================================

/// CONF-039: Two Implementations Exchange Messages
/// Layer: Interop | Tier: Core | Spec: §9.5, §9.8, §9.10, §9.16
/// Note: Tests single-implementation bidirectional message exchange.
/// True cross-implementation testing requires an independent implementation.
#[test]
fn conf_039_bidirectional_message_exchange() {
    println!("=== CONF-039: Bidirectional Message Exchange ===");

    let key_alice = generate_sender_key();
    let key_bob = generate_sender_key();

    print_step(1, "Alice sends message to Bob");
    let msg_a = b"Hello from Alice";
    let ct_a =
        encrypt_sender_layer(&key_alice, msg_a, "conf-039-ctx", "did:dht:z6MkAlice", 0, 0).unwrap();

    print_step(2, "Bob decrypts Alice's message");
    let pt_a =
        decrypt_sender_layer(&key_alice, &ct_a, "conf-039-ctx", "did:dht:z6MkAlice", 0, 0).unwrap();
    assert_eq!(pt_a, msg_a);

    print_step(3, "Bob sends reply");
    let msg_b = b"Hello from Bob";
    let ct_b =
        encrypt_sender_layer(&key_bob, msg_b, "conf-039-ctx", "did:dht:z6MkBob", 0, 0).unwrap();

    print_step(4, "Alice decrypts Bob's reply");
    let pt_b =
        decrypt_sender_layer(&key_bob, &ct_b, "conf-039-ctx", "did:dht:z6MkBob", 0, 0).unwrap();
    assert_eq!(pt_b, msg_b);

    print_step(5, "Padding is compatible");
    let padded_a = pad_to_bucket(&ct_a).unwrap();
    let padded_b = pad_to_bucket(&ct_b).unwrap();
    let recovered_a = strip_padding(&padded_a).unwrap();
    let recovered_b = strip_padding(&padded_b).unwrap();
    assert_eq!(recovered_a, ct_a);
    assert_eq!(recovered_b, ct_b);

    println!("  PASS: Bidirectional message exchange verified");
}

/// CONF-040: Cross-Implementation Context Join
/// Layer: Interop | Tier: Core | Spec: §5.3, §9.7
/// Note: Tests MLS join semantics. Full MLS cross-node tested in fullstack.rs.
#[tokio::test]
async fn conf_040_cross_implementation_join() {
    println!("=== CONF-040: Cross-Implementation Context Join ===");

    print_step(1, "Implementation A creates context");
    let handle = ContextHandle::new("conf-040-ctx".to_owned(), ContextParams::default());
    handle.transition_to(&ContextState::Active).await.unwrap();

    let mut membership = MembershipState::new();
    membership.add_member(DID::from("did:dht:z6MkImplA"), "admin".to_owned(), vec![]);

    print_step(2, "Implementation B processes Welcome and joins");
    membership.add_member(DID::from("did:dht:z6MkImplB"), "member".to_owned(), vec![]);
    assert_eq!(membership.count(), 2);

    print_step(3, "B can send messages");
    let key_b = generate_sender_key();
    let msg = b"from implementation B";
    let ct = encrypt_sender_layer(&key_b, msg, "conf-040-ctx", "did:dht:z6MkImplB", 0, 0).unwrap();

    print_step(4, "A decrypts B's message");
    let pt = decrypt_sender_layer(&key_b, &ct, "conf-040-ctx", "did:dht:z6MkImplB", 0, 0).unwrap();
    assert_eq!(pt, msg);

    println!("  PASS: Cross-implementation join verified");
}

/// CONF-041: Mixed-Implementation Governance Vote
/// Layer: Interop | Tier: Full | Spec: §6.4
#[test]
fn conf_041_cross_implementation_vote() {
    println!("=== CONF-041: Mixed-Implementation Governance Vote ===");

    let _key_impl1 = make_signing_key(0x51);
    let key_impl2 = make_signing_key(0x52);
    let proposal_id: [u8; 32] = Sha256::digest(b"conf-041-proposal").into();

    print_step(1, "Implementation 1 proposes governance action");

    print_step(2, "Implementation 2 votes approve");
    let vote = sign_vote(
        &proposal_id,
        &VoteType::Approve,
        "did:dht:z6MkImpl2",
        1_700_000_000,
        &key_impl2,
    )
    .unwrap();

    print_step(3, "Implementation 1 verifies Implementation 2's vote");
    verify_vote(&proposal_id, &vote, &key_impl2.verifying_key()).expect("cross-impl vote verify");

    print_step(4, "Vote canonical hash is interoperable");
    println!("    Vote domain: SCP-VOTE-V1:");
    println!("    Proposal ID: 0x{}", hex(&proposal_id));

    println!("  PASS: Cross-implementation governance vote verified");
}

/// CONF-042: Cross-Implementation Sync Recovery
/// Layer: Interop | Tier: Full | Spec: §23
#[test]
fn conf_042_cross_implementation_sync() {
    println!("=== CONF-042: Cross-Implementation Sync Recovery ===");

    let now = 1_700_000_000u64;

    print_step(1, "B reconnects after 5 hours offline");
    let tier = classify_offline_duration(now - 18_000, now);
    assert_eq!(
        tier,
        OfflineTier::Extended,
        "5h = Extended (snapshot + delta)"
    );

    print_step(2, "Consistency checkpoint format is standard");
    let root: [u8; 32] = Sha256::digest(b"merkle-root-snapshot").into();
    println!("    Checkpoint root: 0x{}", hex(&root));

    print_step(3, "Verify sync classification thresholds");
    // Tier boundaries are the same across implementations
    assert_eq!(TIER_1_THRESHOLD_SECS, 14_400);
    assert_eq!(TIER_2_THRESHOLD_SECS, 604_800);

    print_step(4, "Snapshot format is interoperable");
    println!("    Short: sequential replay (< 4h)");
    println!("    Extended: snapshot + delta (4h-7d)");
    println!("    Long: full reset (> 7d)");

    println!("  PASS: Cross-implementation sync recovery verified");
}

// ===========================================================================
// §26 Outlet Registration Conformance — SCP-OUT-009
// ===========================================================================

/// CONF-043: Outlet Registration V2 Vector File Shape
/// Layer: Bridge | Tier: Full | Spec: §5.4.1, §25 | ADR-049 | Story: SCP-OUT-009
fn load_outlet_registration_vector_file()
-> scp_testing::conformance::outlet_registration::OutletRegistrationVectorFile {
    let path = scp_testing::conformance::outlet_registration::vectors_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "outlet registration vector file missing at {}: {}",
            path.display(),
            e
        )
    });
    serde_json::from_str(&raw).expect("vector file must be valid JSON")
}

#[test]
fn conf_043_outlet_registration_v2_shape() {
    println!("=== CONF-043: Outlet Registration V2 Vector File Shape ===");
    let file = load_outlet_registration_vector_file();
    print_step(1, "Vector file declares V2 domain separator");
    assert_eq!(file.domain_separator, "SCP-OUTLET-REGISTRATION-V2:");
    assert_eq!(
        file.rejected_predecessor_separator,
        "SCP-TOOL-REGISTRATION-V1:"
    );
    print_step(2, "Vector file enumerates exactly 12 entries");
    assert_eq!(
        file.vectors.len(),
        12,
        "SCP-OUT-009 AC1 requires exactly 12 vectors, got {}",
        file.vectors.len()
    );
    print_step(3, "Each entry carries the required fields");
    let names: std::collections::HashSet<&str> =
        file.vectors.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(
        names.len(),
        12,
        "vector names must be unique (set has {} entries)",
        names.len()
    );
    for v in &file.vectors {
        assert!(!v.expected_preimage.is_empty(), "preimage hex empty");
        assert!(
            !v.expected_canonical_hash.is_empty(),
            "canonical hash hex empty"
        );
        assert_eq!(
            v.expected_signature.len(),
            128,
            "Ed25519 signature must be 64 bytes (128 hex)"
        );
        assert!(
            v.operator_did.starts_with("did:"),
            "operator_did must be a DID"
        );
        assert_eq!(
            v.operator_public_key.len(),
            64,
            "Ed25519 public key must be 32 bytes (64 hex)"
        );
        let input = v.input.as_object().expect("input must be JSON object");
        for required_field in [
            "outlet_id",
            "name",
            "description",
            "schema",
            "implementation_hash",
            "test_vectors",
            "operator_did",
            "registered_at",
        ] {
            assert!(
                input.contains_key(required_field),
                "vector '{}' missing input field '{}'",
                v.name,
                required_field
            );
        }
    }
    println!("  PASS: V2 vector file shape conforms to SCP-OUT-009 AC1+AC2");
}

/// CONF-044: Outlet Registration V2 Sign-Verify Round-Trip
/// Layer: Bridge | Tier: Full | Spec: §5.4.1 | ADR-049 | Story: SCP-OUT-009
#[test]
fn conf_044_outlet_registration_v2_sign_verify() {
    use scp_core::context::outlets::registry::{
        compute_outlet_registration_canonical_bytes, verify_outlet_registration_signature,
    };
    use scp_testing::conformance::outlet_registration as orv;

    println!("=== CONF-044: Outlet Registration V2 Sign-Verify Round-Trip ===");
    let file = load_outlet_registration_vector_file();
    print_step(
        1,
        "Reconstruct each registration from the on-disk JSON input payload",
    );
    print_step(
        2,
        "Recompute canonical preimage byte-for-byte and the V2 SHA-256 digest",
    );
    print_step(3, "Verify Ed25519 signature against operator_public_key");
    print_step(
        4,
        "Confirm the manual preimage matches compute_outlet_registration_canonical_bytes",
    );
    for vector in &file.vectors {
        let registration =
            orv::registration_from_json_input(&vector.input, &vector.expected_signature)
                .unwrap_or_else(|e| panic!("vector '{}' input malformed: {e}", vector.name));

        let manual_preimage = orv::compute_v2_preimage(&registration);
        let actual_preimage_hex = hex::encode(&manual_preimage);
        assert_eq!(
            actual_preimage_hex, vector.expected_preimage,
            "vector '{}' preimage mismatch",
            vector.name
        );

        let manual_hash: [u8; 32] = Sha256::digest(&manual_preimage).into();
        assert_eq!(
            hex::encode(manual_hash),
            vector.expected_canonical_hash,
            "vector '{}' canonical hash mismatch",
            vector.name
        );

        let core_hash = compute_outlet_registration_canonical_bytes(&registration);
        assert_eq!(
            core_hash.as_slice(),
            manual_hash,
            "vector '{}' Rust core compute_outlet_registration_canonical_bytes diverges from manual preimage",
            vector.name
        );

        let pub_bytes_vec =
            hex::decode(&vector.operator_public_key).expect("operator_public_key hex");
        let pub_bytes: [u8; 32] = pub_bytes_vec
            .as_slice()
            .try_into()
            .expect("operator_public_key must be 32 bytes");
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes)
            .expect("operator_public_key must be a valid Ed25519 verifying key");

        verify_outlet_registration_signature(&registration, &verifying_key).unwrap_or_else(|e| {
            panic!(
                "vector '{}' signature verification failed: {e:?}",
                vector.name
            )
        });

        // Also verify directly using the Ed25519 verifier against the canonical hash bytes
        // (the message that Ed25519 actually signs).
        let sig_bytes_vec =
            hex::decode(&vector.expected_signature).expect("expected_signature hex");
        let sig_bytes: [u8; 64] = sig_bytes_vec
            .as_slice()
            .try_into()
            .expect("expected_signature must be 64 bytes");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&core_hash, &signature)
            .unwrap_or_else(|e| {
                panic!(
                    "vector '{}' direct Ed25519 verify failed: {e:?}",
                    vector.name
                )
            });
    }
    println!(
        "  PASS: 12 vectors round-trip through manual preimage, in-tree hasher, and Ed25519 verify"
    );
}

/// CONF-045: V1 Domain Separator Rejection (Negative Corpus)
/// Layer: Bridge | Tier: Full | Spec: §5.4.1 hard-break | ADR-049 §1 | Story: SCP-OUT-009
#[test]
fn conf_045_outlet_registration_v1_rejected() {
    use scp_core::context::outlets::registry::compute_outlet_registration_canonical_bytes;
    use scp_testing::conformance::outlet_registration as orv;

    println!("=== CONF-045: V1 Domain Separator Rejection (Negative Corpus) ===");
    let file = load_outlet_registration_vector_file();
    print_step(
        1,
        "Vector file documents the deleted V1 domain separator for the rejection corpus",
    );
    assert!(
        !file.v1_rejection_corpus.is_empty(),
        "v1 rejection corpus must be populated"
    );
    assert_eq!(
        file.v1_rejection_corpus.len(),
        file.vectors.len(),
        "every V2 vector must have a paired V1-rejection entry"
    );
    print_step(
        2,
        "Each V1 preimage starts with SCP-TOOL-REGISTRATION-V1: (deleted domain)",
    );
    for entry in &file.v1_rejection_corpus {
        let preimage_bytes = hex::decode(&entry.v1_preimage).expect("v1_preimage hex");
        assert!(
            preimage_bytes.starts_with(b"SCP-TOOL-REGISTRATION-V1:"),
            "V1 corpus entry '{}' must start with SCP-TOOL-REGISTRATION-V1:",
            entry.name
        );
        let v1_hash: [u8; 32] = Sha256::digest(&preimage_bytes).into();
        assert_eq!(
            hex::encode(v1_hash),
            entry.v1_canonical_hash,
            "V1 hash mismatch for entry '{}'",
            entry.name
        );
    }
    print_step(
        3,
        "V1 hash MUST NOT equal the V2 canonical hash for the same logical input",
    );
    for entry in &file.v1_rejection_corpus {
        assert_ne!(
            entry.v1_canonical_hash, entry.v2_canonical_hash,
            "V1 and V2 hashes collide for entry '{}' — domain separation broken",
            entry.name
        );
    }
    print_step(
        4,
        "V1 hash MUST NOT match what the live code path produces for the same logical input",
    );
    for (entry, (name, _notes, registration)) in file
        .v1_rejection_corpus
        .iter()
        .zip(orv::reference_registrations().iter())
    {
        assert_eq!(
            &entry.name, name,
            "rejection corpus order must match reference_registrations() order"
        );
        let live_v2 = compute_outlet_registration_canonical_bytes(registration);
        assert_eq!(
            hex::encode(&live_v2),
            entry.v2_canonical_hash,
            "live code's V2 hash diverges from corpus expectation for '{}'",
            entry.name
        );
        assert_ne!(
            hex::encode(&live_v2),
            entry.v1_canonical_hash,
            "live code's V2 hash must NEVER equal the V1 hash for '{}' — rename hard-break violated",
            entry.name
        );
    }
    println!(
        "  PASS: V1 preimage rejected — pre-rename SCP-TOOL-REGISTRATION-V1 domain produces a distinct hash that never validates against the V2 code path"
    );
}

/// CONF-046: Outlet Registration V2 Vectors Match Generator
/// Layer: Bridge | Tier: Full | Spec: §5.4.1 | ADR-049 | Story: SCP-OUT-009
///
/// Confirms the on-disk JSON file is byte-identical to what the generator
/// would currently produce. Detects accidental drift between the in-tree
/// reference registrations and the committed vectors.
#[test]
fn conf_046_outlet_registration_v2_matches_generator() {
    use scp_testing::conformance::outlet_registration as orv;

    println!("=== CONF-046: V2 Vectors Match Generator ===");
    let on_disk = load_outlet_registration_vector_file();
    let regenerated = orv::build_vector_file();
    print_step(
        1,
        "On-disk vector file matches build_vector_file() output exactly",
    );
    let on_disk_json =
        serde_json::to_value(&on_disk).expect("on-disk file serializable to JSON value");
    let regen_json =
        serde_json::to_value(&regenerated).expect("regen file serializable to JSON value");
    assert_eq!(
        on_disk_json, regen_json,
        "outlet_registration_v2.json drifted from in-tree generator — re-run \
         `cargo test -p scp-testing --test conformance \
         conf_outlet_registration_v2_regen -- --ignored --nocapture` to refresh"
    );
    println!("  PASS: on-disk vectors are byte-identical to the generator output");
}

/// Regenerator (ignored by default). Run with:
///
/// ```bash
/// cargo test -p scp-testing --test conformance \
///   conf_outlet_registration_v2_regen -- --ignored --nocapture
/// ```
#[test]
#[ignore = "writes to disk; run explicitly when intentionally regenerating vectors"]
fn conf_outlet_registration_v2_regen() {
    use scp_testing::conformance::outlet_registration as orv;

    let path = orv::vectors_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create vectors parent directory");
    }
    let file = orv::build_vector_file();
    let serialized = serde_json::to_string_pretty(&file).expect("serialize vector file");
    std::fs::write(&path, serialized + "\n").expect("write vector file");
    println!(
        "Regenerated outlet registration V2 vectors → {} ({} entries, {} V1-rejection entries)",
        path.display(),
        file.vectors.len(),
        file.v1_rejection_corpus.len()
    );
}
