#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::too_many_arguments,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::doc_markdown,
    clippy::redundant_clone,
    clippy::cloned_ref_to_slice_refs,
    clippy::missing_const_for_fn
)]

//! B12: Trust, sybil resistance, and participation admission integration tests.
//!
//! Exercises the trust engine's four layers: participation records
//! (Layer 2), attestation verification and freshness (Layer 3),
//! challenge-response (Layer 3), and consequence enforcement (Layer 4).
//! Also covers sybil resistance evaluation, capability URIs, custody
//! violation attestations, participation admission, and block list state.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use scp_core::identity::SigningKeyId;
use scp_core::identity::block_list::{BlockListEvent, BlockListState};
use scp_core::trust::challenge::VerificationMethod;
use scp_core::trust::{
    ActionCategory, Attestation, AttestationEvidence, AttestationType, AttestorInfo, CapabilityUri,
    ChallengeResponse, ChallengeSigner, ChallengeType, ConsequenceAction, ConsequenceRule,
    ConsequenceTrigger, ContextSybilPolicy, CounterAttestation, CustodyViolationError,
    CustodyViolationType, EarnedCapacityLevel, FreshnessStatus, FreshnessWeight,
    IdentityDepthAssessment, ParticipationFact, ParticipationInput, ParticipationThreshold,
    RequireParticipation, RevocationStatus, ScpCustodyViolationAttestation, ThresholdRequirement,
    TrustError, TrustSignal, TrustSignalCategory, check_attestation_freshness,
    check_threshold_attestation, classify_action, compute_participation_record, enforce_category_a,
    evaluate_consequence_rules, evaluate_earned_capacity, evaluate_sybil_resistance,
    issue_challenge, produce_participation_profile, verify_attestation, verify_challenge_response,
    verify_participation_requirements,
};
use scp_event_log::{Event, EventPayload, EventType};
use scp_identity::DID;
use scp_platform::testing::InMemoryDeviceAttestation;
use scp_platform::traits::DeviceAttestation;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn did(s: &str) -> DID {
    DID::from(s)
}

fn sk_for(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Test Clock that always returns a fixed timestamp.
struct FixedClock(u64);

impl scp_identity::cache::Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }

    fn now_millis(&self) -> u64 {
        self.0 * 1000
    }
}

/// Test DID public key resolver that maps `did:key:{hex}` to raw bytes.
struct TestKeyResolver {
    keys: HashMap<String, Vec<u8>>,
}

impl TestKeyResolver {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn add(&mut self, did: &str, pk_bytes: Vec<u8>) {
        self.keys.insert(did.to_owned(), pk_bytes);
    }
}

impl scp_core::trust::attestation::DidPublicKeyResolver for TestKeyResolver {
    fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
        self.keys
            .get(did)
            .cloned()
            .ok_or_else(|| TrustError::AttestationSignatureInvalid {
                attestation_id: String::new(),
                reason: format!("unknown DID: {did}"),
            })
    }
}

/// Test ChallengeSigner backed by an ed25519 signing key.
struct TestChallengeSigner(SigningKey);

impl ChallengeSigner for TestChallengeSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TrustError> {
        Ok(self.0.sign(data).to_bytes().to_vec())
    }
}

/// Creates a test event with minimal fields.
fn make_event(
    event_type: EventType,
    actor_did: &str,
    timestamp: u64,
    sequence: u64,
    payload: Vec<u8>,
) -> Event {
    Event {
        event_type,
        actor_did: actor_did.into(),
        timestamp,
        sequence,
        payload: EventPayload { data: payload },
        prev_hash: [0u8; 32],
        signature: vec![0u8; 64],
    }
}

/// Creates a signed attestation using the given signing key.
fn make_signed_attestation(
    id: &str,
    attestation_type: AttestationType,
    issuer_did: &str,
    subject_did: &str,
    sk: &SigningKey,
    issued_at: u64,
    expires_at: Option<u64>,
    renewal_interval: Option<Duration>,
) -> Attestation {
    // Build attestation with empty signature first
    let mut att = Attestation {
        id: id.to_owned(),
        attestation_type,
        issuer: did(issuer_did),
        subject: did(subject_did),
        claim: serde_json::json!({"test": true}),
        evidence: Some(AttestationEvidence {
            evidence_type: "test".to_owned(),
            data: serde_json::json!({"proof": "valid"}),
        }),
        issued_at,
        expires_at,
        renewal_interval,
        renewed_at: None,
        revocation_status: RevocationStatus::Active,
        signature: vec![],
    };

    // Set the issuer to a did:key derived from the signing key so the
    // resolver can map the DID back to the public key.
    let vk = sk.verifying_key();
    let vk_hex = hex::encode(vk.to_bytes());
    let issuer_str = format!("did:key:{vk_hex}");
    att.issuer = did(&issuer_str);

    // Use the actual canonical_hash function to match verify_attestation exactly.
    use scp_core::crypto::canonical::{CanonicalField, canonical_hash};
    use scp_core::trust::attestation_type_tag;

    let claim_bytes = rmp_serde::to_vec_named(&att.claim).unwrap();
    let evidence_bytes = att
        .evidence
        .as_ref()
        .map(|e| rmp_serde::to_vec_named(e).unwrap());
    let att_type_tag = attestation_type_tag(&att.attestation_type);
    let revocation_bytes = rmp_serde::to_vec_named(&att.revocation_status).unwrap();

    let canonical = canonical_hash(
        "SCP-ATTESTATION-V1:",
        &[
            CanonicalField::VarBytes(att.id.as_bytes()),
            CanonicalField::U16(att_type_tag),
            CanonicalField::VarBytes(att.issuer.as_bytes()),
            CanonicalField::VarBytes(att.subject.as_bytes()),
            CanonicalField::VarBytes(&claim_bytes),
            evidence_bytes
                .as_deref()
                .map_or(CanonicalField::Absent, CanonicalField::VarBytes),
            CanonicalField::U64(att.issued_at),
            att.expires_at
                .map_or(CanonicalField::Absent, CanonicalField::U64),
            CanonicalField::VarBytes(&revocation_bytes),
        ],
    );
    let sig = sk.sign(&canonical);
    att.signature = sig.to_bytes().to_vec();

    att
}

fn make_trust_signal(
    category: TrustSignalCategory,
    strength: u64,
    verified_at: u64,
) -> TrustSignal {
    TrustSignal {
        category,
        verified_at,
        strength,
        details: None,
    }
}

// ---------------------------------------------------------------------------
// 1. behavioral_record_computation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn behavioral_record_computation() {
    let alice = "did:dht:z6MkAlice";
    let events = vec![
        make_event(EventType::MessageSent, alice, 1000, 0, vec![]),
        make_event(EventType::MessageSent, alice, 1100, 1, vec![]),
        make_event(
            EventType::ToolInvoked,
            alice,
            1200,
            2,
            b"my-tool\0".to_vec(),
        ),
        make_event(EventType::ContextCreated, alice, 1300, 3, vec![]),
    ];

    let record = compute_participation_record(&events, alice, "ctx-test", [0u8; 32], 2000).unwrap();

    assert_eq!(record.subject_did, did(alice));
    assert_eq!(record.context_id, "ctx-test");
    assert_eq!(record.participation_count, 4);
    assert_eq!(record.participation_duration_seconds, 300); // 1300 - 1000
    assert_eq!(*record.tool_invocations.get("my-tool").unwrap_or(&0), 1);
    assert_eq!(record.context_creation_count, 1);
    assert_eq!(record.computed_at, 2000);
}

// ---------------------------------------------------------------------------
// 2. attestation_verify_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attestation_verify_roundtrip() {
    let sk = sk_for(1);
    let vk = sk.verifying_key();
    let vk_hex = hex::encode(vk.to_bytes());
    let issuer_did = format!("did:key:{vk_hex}");

    let att = make_signed_attestation(
        "att-001",
        AttestationType::Endorsement,
        &issuer_did,
        "did:dht:z6MkSubject",
        &sk,
        1000,
        Some(5000),
        None,
    );

    let mut resolver = TestKeyResolver::new();
    resolver.add(&issuer_did, vk.to_bytes().to_vec());

    let clock = FixedClock(2000);
    let result = verify_attestation(&att, &resolver, &clock);
    assert!(result.is_ok(), "verify_attestation failed: {result:?}");
}

// ---------------------------------------------------------------------------
// 3. attestation_freshness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attestation_freshness() {
    let _sk = sk_for(2);

    // Fresh: within renewal interval
    let att_fresh = Attestation {
        id: "att-fresh".to_owned(),
        attestation_type: AttestationType::Endorsement,
        issuer: did("did:dht:z6MkIssuer"),
        subject: did("did:dht:z6MkSubject"),
        claim: serde_json::json!({}),
        evidence: None,
        issued_at: 1000,
        expires_at: Some(5000),
        renewal_interval: Some(Duration::from_secs(2000)),
        renewed_at: None,
        revocation_status: RevocationStatus::Active,
        signature: vec![0; 64],
    };

    let clock_fresh = FixedClock(2500); // 1500s after issued_at, within 2000s renewal
    assert_eq!(
        check_attestation_freshness(&att_fresh, &clock_fresh),
        FreshnessStatus::Fresh
    );

    // Stale: past renewal interval but not expired
    let clock_stale = FixedClock(3500); // 2500s after issued_at, past 2000s renewal
    let status = check_attestation_freshness(&att_fresh, &clock_stale);
    assert!(
        matches!(status, FreshnessStatus::Stale { .. }),
        "expected Stale, got {status:?}"
    );

    // Expired: past expires_at
    let clock_expired = FixedClock(6000);
    assert_eq!(
        check_attestation_freshness(&att_fresh, &clock_expired),
        FreshnessStatus::Expired
    );
}

// ---------------------------------------------------------------------------
// 4. attestation_threshold
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attestation_threshold() {
    let att_type = AttestationType::Endorsement;

    // Build 3 attestors with endorsement attestations.
    let attestors: Vec<AttestorInfo> = (0..3)
        .map(|i| {
            let att = Attestation {
                id: format!("att-{i}"),
                attestation_type: att_type.clone(),
                issuer: did(&format!("did:dht:z6MkAttestor{i}")),
                subject: did("did:dht:z6MkSubject"),
                claim: serde_json::json!({}),
                evidence: None,
                issued_at: 1000,
                expires_at: None,
                renewal_interval: None,
                renewed_at: None,
                revocation_status: RevocationStatus::Active,
                signature: vec![0; 64],
            };
            AttestorInfo {
                did: did(&format!("did:dht:z6MkAttestor{i}")),
                context_memberships: HashSet::new(),
                endorsements: HashSet::new(),
                attestation: Some(att),
            }
        })
        .collect();

    // 2-of-3 threshold should be met.
    let requirement = ThresholdRequirement::new(2, 3, 0.5);
    let result = check_threshold_attestation(&att_type, &attestors, &requirement);
    assert!(result.met, "2-of-3 threshold should be met");
    assert_eq!(result.valid_count, 3);

    // 4-of-5 threshold should NOT be met (only 3 attestors provided).
    let strict_requirement = ThresholdRequirement::new(4, 5, 0.5);
    let result_strict = check_threshold_attestation(&att_type, &attestors, &strict_requirement);
    assert!(
        !result_strict.met,
        "4-of-5 threshold should not be met with only 3 attestors"
    );
}

// ---------------------------------------------------------------------------
// 5. challenge_request_response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn challenge_request_response() {
    let challenger_sk = sk_for(10);
    let challenger_vk = challenger_sk.verifying_key();
    let challenger_hex = hex::encode(challenger_vk.to_bytes());
    let challenger_did = format!("did:key:{challenger_hex}");

    let subject_sk = sk_for(20);
    let subject_vk = subject_sk.verifying_key();
    let subject_hex = hex::encode(subject_vk.to_bytes());
    let subject_did = format!("did:key:{subject_hex}");

    let signer = TestChallengeSigner(challenger_sk.clone());
    let ct = ChallengeType::prompt_injection_resistance();
    let uri_str = "scp:capability:prompt-injection-resistance/v1".to_owned();

    let request = issue_challenge(
        did(&challenger_did),
        did(&subject_did),
        ct,
        uri_str,
        serde_json::json!(null),
        Duration::from_secs(300),
        &signer,
    )
    .unwrap();

    assert!(!request.challenge_id.is_empty());
    assert_eq!(request.challenger_did, did(&challenger_did));
    assert_eq!(request.subject_did, did(&subject_did));

    // Build a response signed by the subject.
    let _response_signer = TestChallengeSigner(subject_sk.clone());

    // Build canonical response bytes for signing.
    let mut response = ChallengeResponse {
        challenge_id: request.challenge_id.clone(),
        responder_did: did(&subject_did),
        result: serde_json::json!({"passed": true}),
        completed_at: 2000,
        signature: vec![],
    };

    // Sign the response manually using the canonical format.
    // We need to compute the canonical response bytes.
    let response_canonical = {
        let result_bytes = serde_json::to_vec(&response.result).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SCP-CHALLENGE-RESP-V1:");
        // challenge_id
        buf.extend_from_slice(&(response.challenge_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(response.challenge_id.as_bytes());
        // responder_did
        let rdid = response.responder_did.as_bytes();
        buf.extend_from_slice(&(rdid.len() as u32).to_be_bytes());
        buf.extend_from_slice(rdid);
        // result
        buf.extend_from_slice(&(result_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&result_bytes);
        // completed_at
        buf.extend_from_slice(&response.completed_at.to_be_bytes());
        buf
    };
    let response_sig = subject_sk.sign(&response_canonical);
    response.signature = response_sig.to_bytes().to_vec();

    // Verify the response.
    let mut resolver = TestKeyResolver::new();
    resolver.add(&subject_did, subject_vk.to_bytes().to_vec());
    resolver.add(&challenger_did, challenger_vk.to_bytes().to_vec());

    let clock = FixedClock(2000);
    let verifier_signer = TestChallengeSigner(challenger_sk);

    let verification = verify_challenge_response(
        &request,
        &response,
        &resolver,
        &clock,
        &verifier_signer,
        None,
    )
    .unwrap();

    assert!(verification.passed);
    assert_eq!(verification.subject_did, did(&subject_did));
    assert!(matches!(
        verification.verification_method,
        VerificationMethod::ChallengeVerified { .. }
    ));
}

// ---------------------------------------------------------------------------
// 6. consequence_rules_evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consequence_rules_evaluation() {
    let rules = vec![
        ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Suspend {
                capabilities: vec!["messages:write".to_owned()],
            },
            threshold: 3,
            window: Duration::from_secs(60),
        },
        ConsequenceRule {
            trigger: ConsequenceTrigger::ToolRateExceeded,
            action: ConsequenceAction::SuspendAll,
            threshold: 2,
            window: Duration::from_secs(120),
        },
    ];

    let alice = "did:dht:z6MkAlice";
    let events = vec![
        make_event(EventType::MessageSent, alice, 950, 0, vec![]),
        make_event(EventType::MessageSent, alice, 960, 1, vec![]),
        make_event(EventType::MessageSent, alice, 970, 2, vec![]),
        make_event(EventType::ToolInvoked, alice, 980, 3, b"tool-a".to_vec()),
        make_event(EventType::ToolInvoked, alice, 990, 4, b"tool-b".to_vec()),
    ];

    let triggered = evaluate_consequence_rules(&rules, &events, alice, 1000);

    assert_eq!(triggered.len(), 2);
    assert_eq!(triggered[0].rule_index, 0);
    assert_eq!(
        triggered[0].action,
        ConsequenceAction::Suspend {
            capabilities: vec!["messages:write".to_owned()]
        }
    );
    assert_eq!(triggered[0].evidence.len(), 3);

    assert_eq!(triggered[1].rule_index, 1);
    assert_eq!(triggered[1].action, ConsequenceAction::SuspendAll);
    assert_eq!(triggered[1].evidence.len(), 2);
}

// ---------------------------------------------------------------------------
// 7. action_classification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn action_classification() {
    // Category A resources (DID document modifications)
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

    // Category B resources (operational)
    assert_eq!(classify_action("messages"), ActionCategory::CategoryB);
    assert_eq!(classify_action("tool_invoke"), ActionCategory::CategoryB);
    assert_eq!(classify_action("member"), ActionCategory::CategoryB);
    assert_eq!(classify_action("role"), ActionCategory::CategoryB);
    assert_eq!(classify_action("context"), ActionCategory::CategoryB);
    assert_eq!(classify_action("spending"), ActionCategory::CategoryB);
    assert_eq!(
        classify_action("unknown_resource"),
        ActionCategory::CategoryB
    );
}

// ---------------------------------------------------------------------------
// 8. custody_violation_attestation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn custody_violation_attestation() {
    let violation = CustodyViolationType::CategoryAViolation {
        action: "did_document_update".to_owned(),
        signer_key_id: SigningKeyId::Agent,
        signature_evidence: vec![1, 2, 3, 4],
    };

    let attestation = ScpCustodyViolationAttestation::new(
        did("did:dht:z6MkSubject"),
        1000,
        violation,
        vec![5, 6, 7, 8],
        did("did:dht:z6MkVerifier"),
    )
    .unwrap();

    assert_eq!(attestation.subject_did, did("did:dht:z6MkSubject"));
    assert_eq!(attestation.timestamp, 1000);
    assert_eq!(attestation.violation_kind(), "CategoryAViolation");
    assert_eq!(attestation.verifier_did, did("did:dht:z6MkVerifier"));

    // Validation should pass.
    assert!(attestation.validate().is_ok());

    // Empty evidence should fail.
    let bad_violation = CustodyViolationType::CategoryAViolation {
        action: "did_document_update".to_owned(),
        signer_key_id: SigningKeyId::Agent,
        signature_evidence: vec![],
    };
    assert!(bad_violation.validate().is_err());

    // Wrong signer key should fail.
    let wrong_signer = CustodyViolationType::CategoryAViolation {
        action: "did_document_update".to_owned(),
        signer_key_id: SigningKeyId::Active,
        signature_evidence: vec![1, 2, 3],
    };
    assert!(matches!(
        wrong_signer.validate(),
        Err(CustodyViolationError::InvalidCategoryASigner(_))
    ));

    // enforce_category_a: agent key + Category A = violation
    let result = enforce_category_a(
        SigningKeyId::Agent,
        ActionCategory::CategoryA,
        "did:dht:z6MkBad",
        "did_document_update",
        &[1, 2, 3],
    );
    assert!(result.is_err());
    let violation_result = result.unwrap_err();
    assert_eq!(violation_result.violator_did, "did:dht:z6MkBad");

    // enforce_category_a: active key + Category A = ok
    assert!(
        enforce_category_a(
            SigningKeyId::Active,
            ActionCategory::CategoryA,
            "did:dht:z6MkGood",
            "did_document_update",
            &[1, 2, 3],
        )
        .is_ok()
    );

    // enforce_category_a: agent key + Category B = ok
    assert!(
        enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryB,
            "did:dht:z6MkAgent",
            "messages_send",
            &[1, 2, 3],
        )
        .is_ok()
    );
}

// ---------------------------------------------------------------------------
// 9. counter_attestation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn counter_attestation() {
    let sk = sk_for(30);
    let sig = sk.sign(b"counter-claim-data");

    let counter = CounterAttestation::new(
        did("did:dht:z6MkSubject"),
        "violation-ref-001".to_owned(),
        "Key was compromised and rotated".to_owned(),
        2000,
        sig.to_bytes().to_vec(),
    )
    .unwrap();

    assert_eq!(counter.subject_did, did("did:dht:z6MkSubject"));
    assert_eq!(counter.violation_reference, "violation-ref-001");
    assert_eq!(counter.explanation, "Key was compromised and rotated");
    assert_eq!(counter.timestamp, 2000);
    assert!(!counter.signature.is_empty());
    assert!(counter.validate().is_ok());

    // Empty fields should fail.
    assert!(
        CounterAttestation::new(
            did("did:dht:z6MkSubject"),
            String::new(),
            "explanation".to_owned(),
            2000,
            vec![1],
        )
        .is_err()
    );

    assert!(
        CounterAttestation::new(
            did("did:dht:z6MkSubject"),
            "ref".to_owned(),
            String::new(),
            2000,
            vec![1],
        )
        .is_err()
    );

    assert!(
        CounterAttestation::new(
            did("did:dht:z6MkSubject"),
            "ref".to_owned(),
            "explanation".to_owned(),
            2000,
            vec![],
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// 10. device_attestation_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_attestation_roundtrip() {
    let device = InMemoryDeviceAttestation::new();

    let token = device.attest().await.unwrap();
    assert!(!token.as_bytes().is_empty());

    // Own token should verify.
    assert!(device.verify(&token).await.unwrap());

    // Foreign token should not verify.
    let foreign = scp_platform::traits::DeviceAttestationToken::new(b"foreign-token".to_vec());
    assert!(!device.verify(&foreign).await.unwrap());

    // Sequential attestations produce unique tokens.
    let token2 = device.attest().await.unwrap();
    assert_ne!(token.as_bytes(), token2.as_bytes());
}

// ---------------------------------------------------------------------------
// 11. earned_capacity_policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn earned_capacity_policy() {
    let current_time: u64 = 1_768_435_200;

    // New identity: no signals => New tier
    let empty_assessment =
        IdentityDepthAssessment::new(did("did:dht:z6MkNew"), HashMap::new(), current_time);
    let policy = ContextSybilPolicy::standard();
    let (level, capacity) = evaluate_earned_capacity(&empty_assessment, &policy, current_time);
    assert_eq!(level, EarnedCapacityLevel::New);
    assert_eq!(capacity.max_context_creation, 2);
    assert_eq!(capacity.max_participation_slots, 5);

    // Developing identity: 1 signal category, moderate strength, 2 days old
    let mut signals = HashMap::new();
    signals.insert(
        TrustSignalCategory::ParticipationHistory,
        make_trust_signal(
            TrustSignalCategory::ParticipationHistory,
            100,
            current_time - 2 * 86400,
        ),
    );
    let dev_assessment =
        IdentityDepthAssessment::new(did("did:dht:z6MkDev"), signals, current_time);
    let (dev_level, dev_capacity) =
        evaluate_earned_capacity(&dev_assessment, &policy, current_time);
    assert_eq!(dev_level, EarnedCapacityLevel::Developing);
    assert!(dev_capacity.max_context_creation > capacity.max_context_creation);

    // Veteran identity: 4+ categories, high strength, 200+ days old.
    // Strength must be high enough that after freshness decay (half-life = 90 days,
    // so weight at 200 days ~ 0.214), total weighted strength >= 1000.
    // 4 signals * 1500 * 0.214 ~ 1284 > 1000.
    let mut vet_signals = HashMap::new();
    let old_time = current_time - 200 * 86400;
    vet_signals.insert(
        TrustSignalCategory::SocialAttestation,
        make_trust_signal(TrustSignalCategory::SocialAttestation, 1500, old_time),
    );
    vet_signals.insert(
        TrustSignalCategory::ParticipationHistory,
        make_trust_signal(TrustSignalCategory::ParticipationHistory, 1500, old_time),
    );
    vet_signals.insert(
        TrustSignalCategory::ParticipationRecord,
        make_trust_signal(TrustSignalCategory::ParticipationRecord, 1500, old_time),
    );
    vet_signals.insert(
        TrustSignalCategory::Endorsement,
        make_trust_signal(TrustSignalCategory::Endorsement, 1500, old_time),
    );
    let vet_assessment =
        IdentityDepthAssessment::new(did("did:dht:z6MkVet"), vet_signals, current_time);
    let (vet_level, _vet_capacity) =
        evaluate_earned_capacity(&vet_assessment, &policy, current_time);
    assert_eq!(vet_level, EarnedCapacityLevel::Veteran);
}

// ---------------------------------------------------------------------------
// 12. freshness_weight_decay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn freshness_weight_decay() {
    let fw = FreshnessWeight::default_config();
    let current_time: u64 = 1_768_435_200;

    // Fresh signal: weight should be 1.0
    let weight_now = fw.compute(current_time, current_time);
    assert!((weight_now - 1.0).abs() < f64::EPSILON);

    // Signal at exactly one half-life ago: weight ~= 0.5
    let one_half_life = current_time - fw.half_life_secs;
    let weight_half = fw.compute(one_half_life, current_time);
    assert!(
        (weight_half - 0.5).abs() < 0.01,
        "expected ~0.5, got {weight_half}"
    );

    // Signal at two half-lives ago: weight ~= 0.25
    let two_half_lives = current_time - 2 * fw.half_life_secs;
    let weight_quarter = fw.compute(two_half_lives, current_time);
    assert!(
        (weight_quarter - 0.25).abs() < 0.01,
        "expected ~0.25, got {weight_quarter}"
    );

    // Very old signal: should not go below min_weight
    let very_old = current_time - 100 * fw.half_life_secs;
    let weight_floor = fw.compute(very_old, current_time);
    assert!(
        weight_floor >= fw.min_weight,
        "weight {weight_floor} should be >= min_weight {}",
        fw.min_weight
    );
    assert!(
        (weight_floor - fw.min_weight).abs() < 0.001,
        "expected ~{}, got {weight_floor}",
        fw.min_weight
    );

    // Future signal (verified_at >= current_time): weight = 1.0
    let weight_future = fw.compute(current_time + 1000, current_time);
    assert!((weight_future - 1.0).abs() < f64::EPSILON);

    // Zero half-life means no decay
    let no_decay = FreshnessWeight {
        half_life_secs: 0,
        min_weight: 0.0,
    };
    assert!((no_decay.compute(0, current_time) - 1.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// 13. sybil_resistance_evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sybil_resistance_evaluation() {
    let current_time: u64 = 1_768_435_200;

    // Casual policy: passes with no signals.
    let casual = ContextSybilPolicy::casual();
    let empty =
        IdentityDepthAssessment::new(did("did:dht:z6MkEmpty"), HashMap::new(), current_time);
    assert!(evaluate_sybil_resistance(&empty, &casual, current_time, None).is_ok());

    // Standard policy: fails with no signals (min_signal_breadth = 1).
    let standard = ContextSybilPolicy::standard();
    let err = evaluate_sybil_resistance(&empty, &standard, current_time, None).unwrap_err();
    assert!(
        matches!(
            err,
            scp_core::trust::sybil::SybilResistanceError::InsufficientSignalBreadth { .. }
        ),
        "expected InsufficientSignalBreadth, got {err:?}"
    );

    // Standard policy: passes with 1 signal category with sufficient strength.
    let mut signals = HashMap::new();
    signals.insert(
        TrustSignalCategory::SocialAttestation,
        make_trust_signal(
            TrustSignalCategory::SocialAttestation,
            100,
            current_time - 3600,
        ),
    );
    let adequate = IdentityDepthAssessment::new(did("did:dht:z6MkAdequate"), signals, current_time);
    assert!(evaluate_sybil_resistance(&adequate, &standard, current_time, None).is_ok());

    // High-trust policy: requires 3+ categories + specific signals.
    let high = ContextSybilPolicy::high_trust();
    let err2 = evaluate_sybil_resistance(&adequate, &high, current_time, None).unwrap_err();
    assert!(
        matches!(
            err2,
            scp_core::trust::sybil::SybilResistanceError::InsufficientSignalBreadth { .. }
        ),
        "expected InsufficientSignalBreadth, got {err2:?}"
    );

    // Device attestation required: fails without it.
    let device_required = ContextSybilPolicy {
        require_device_attestation: true,
        ..ContextSybilPolicy::casual()
    };
    let err3 =
        evaluate_sybil_resistance(&adequate, &device_required, current_time, None).unwrap_err();
    assert!(matches!(
        err3,
        scp_core::trust::sybil::SybilResistanceError::DeviceAttestationRequired
    ));
}

// ---------------------------------------------------------------------------
// 14. participation_profile_produce_verify
// ---------------------------------------------------------------------------

#[tokio::test]
async fn participation_profile_produce_verify() {
    let alice = "did:dht:z6MkAlice";
    let context_key_material = [42u8; 32];
    let merkle_root = [0u8; 32];

    let events = vec![
        make_event(EventType::MessageSent, alice, 1000, 0, vec![]),
        make_event(EventType::MessageSent, alice, 2000, 1, vec![]),
        make_event(EventType::ToolInvoked, alice, 3000, 2, b"tool-x\0".to_vec()),
    ];

    let profile = produce_participation_profile(
        &context_key_material,
        "ctx-test",
        alice,
        &ParticipationInput {
            events: &events,
            merkle_root,
            is_member: true,
            is_opted_in: true,
            current_time: 4000,
        },
    )
    .unwrap();

    assert_eq!(profile.subject_did, did(alice));
    assert_eq!(profile.participation_duration_secs, 2000); // 3000 - 1000
    assert_eq!(profile.tool_invocation_count, 1);
    assert_eq!(profile.updated_at, 4000);
    assert_ne!(profile.signature, [0u8; 64]);

    // Verify the Ed25519 signature.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&profile.signer_public_key).unwrap();
    let sig = Signature::from_bytes(&profile.signature);
    let signable = profile.signable_bytes();
    assert!(vk.verify(&signable, &sig).is_ok());

    // Not-a-member should fail.
    let err = produce_participation_profile(
        &context_key_material,
        "ctx-test",
        alice,
        &ParticipationInput {
            events: &events,
            merkle_root,
            is_member: false,
            is_opted_in: true,
            current_time: 4000,
        },
    )
    .unwrap_err();
    assert!(matches!(err, TrustError::NotAMember { .. }));

    // Not opted-in should fail.
    let err2 = produce_participation_profile(
        &context_key_material,
        "ctx-test",
        alice,
        &ParticipationInput {
            events: &events,
            merkle_root,
            is_member: true,
            is_opted_in: false,
            current_time: 4000,
        },
    )
    .unwrap_err();
    assert!(matches!(err2, TrustError::NotOptedIn { .. }));
}

// ---------------------------------------------------------------------------
// 15. participation_requirements_check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn participation_requirements_check() {
    let alice = "did:dht:z6MkAlice";
    let context_key_material = [42u8; 32];
    let context_key_material_2 = [99u8; 32];
    let merkle_root = [0u8; 32];
    let current_time: u64 = 5000;

    // Create events that will produce a profile with some participation.
    let events = vec![
        make_event(EventType::MessageSent, alice, 1000, 0, vec![]),
        make_event(EventType::MessageSent, alice, 3000, 1, vec![]),
    ];

    let profile1 = produce_participation_profile(
        &context_key_material,
        "ctx-1",
        alice,
        &ParticipationInput {
            events: &events,
            merkle_root,
            is_member: true,
            is_opted_in: true,
            current_time: 4500,
        },
    )
    .unwrap();

    let profile2 = produce_participation_profile(
        &context_key_material_2,
        "ctx-2",
        alice,
        &ParticipationInput {
            events: &events,
            merkle_root,
            is_member: true,
            is_opted_in: true,
            current_time: 4500,
        },
    )
    .unwrap();

    // Requirement: participation duration >= 1000 seconds, from at least 1 context.
    let requirements = vec![RequireParticipation {
        fact: ParticipationFact::ParticipationDuration,
        threshold: ParticipationThreshold::AtLeast(1000),
        max_age_secs: 3600,
        min_contexts: 1,
    }];

    // Should pass with one profile meeting the threshold.
    let result =
        verify_participation_requirements(current_time, &requirements, &[profile1.clone()]);
    assert!(result.is_ok(), "should pass with valid profile: {result:?}");

    // Requirement needing 2 distinct contexts: passes with 2 profiles.
    let requirements_2ctx = vec![RequireParticipation {
        fact: ParticipationFact::ParticipationDuration,
        threshold: ParticipationThreshold::AtLeast(1000),
        max_age_secs: 3600,
        min_contexts: 2,
    }];

    let result_1 =
        verify_participation_requirements(current_time, &requirements_2ctx, &[profile1.clone()]);
    assert!(result_1.is_err(), "should fail with only 1 context");

    let result_2 =
        verify_participation_requirements(current_time, &requirements_2ctx, &[profile1, profile2]);
    assert!(
        result_2.is_ok(),
        "should pass with 2 distinct contexts: {result_2:?}"
    );

    // Empty requirements always pass.
    assert!(verify_participation_requirements(current_time, &[], &[]).is_ok());
}

// ---------------------------------------------------------------------------
// 16. capability_uri_construction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capability_uri_construction() {
    // Protocol capability: FromStr + Display roundtrip
    let protocol_str = "scp:capability:prompt-injection-resistance/v1";
    let protocol: CapabilityUri = protocol_str.parse().unwrap();
    assert!(protocol.is_protocol());
    assert!(!protocol.is_did_scoped());
    assert!(!protocol.is_system());
    assert_eq!(protocol.name(), "prompt-injection-resistance");
    assert_eq!(protocol.to_string(), protocol_str);

    // DID-scoped capability
    let did_scoped_str = "did:dht:z6Mk123:capability:domain-expertise/v2";
    let did_scoped: CapabilityUri = did_scoped_str.parse().unwrap();
    assert!(did_scoped.is_did_scoped());
    assert_eq!(did_scoped.name(), "domain-expertise");
    assert_eq!(did_scoped.to_string(), did_scoped_str);

    // System capability
    let system_str = "scp:system:relay-operation";
    let system: CapabilityUri = system_str.parse().unwrap();
    assert!(system.is_system());
    assert_eq!(system.name(), "relay-operation");
    assert_eq!(system.to_string(), system_str);

    // Serde roundtrip
    let json = serde_json::to_string(&protocol).unwrap();
    let deserialized: CapabilityUri = serde_json::from_str(&json).unwrap();
    assert_eq!(protocol, deserialized);

    // Error cases
    assert!("".parse::<CapabilityUri>().is_err());
    assert!("scp:capability:UPPER/v1".parse::<CapabilityUri>().is_err());
    assert!("scp:capability:name/v0".parse::<CapabilityUri>().is_err());
    assert!("scp:unknown:name".parse::<CapabilityUri>().is_err());
    assert!("scp:capability:name".parse::<CapabilityUri>().is_err()); // missing version
}

// ---------------------------------------------------------------------------
// 17. capability_matching (variant-based equality and type checks)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capability_matching() {
    // CapabilityUri has no `matches` or `matches_context` methods.
    // Test variant equality, version differentiation, and type classification.
    let v1: CapabilityUri = "scp:capability:test/v1".parse().unwrap();
    let v2: CapabilityUri = "scp:capability:test/v2".parse().unwrap();
    let system: CapabilityUri = "scp:system:test".parse().unwrap();
    let did_scoped: CapabilityUri = "did:dht:z6Mk123:capability:test/v1".parse().unwrap();

    // Same name, different versions are not equal.
    assert_ne!(v1, v2);

    // Different variant types are not equal even with same name.
    assert_ne!(v1, system);
    assert_ne!(v1, did_scoped);

    // Clone equality.
    assert_eq!(v1, v1.clone());

    // Hash set deduplication.
    let mut set = std::collections::HashSet::new();
    set.insert(v1.clone());
    set.insert(v1.clone());
    assert_eq!(set.len(), 1);
    set.insert(v2);
    assert_eq!(set.len(), 2);
}

// ---------------------------------------------------------------------------
// 18. block_list_state_from_events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_list_state_from_events() {
    let dave = did("did:dht:z6MkDave");
    let eve = did("did:dht:z6MkEve");

    let events = vec![
        // Block Dave globally
        BlockListEvent::BlockDID {
            target_did: dave.clone(),
            timestamp: 1000,
        },
        // Block Eve in ctx-1
        BlockListEvent::BlockDIDInContext {
            target_did: eve.clone(),
            context_id: "ctx-1".to_owned(),
            timestamp: 2000,
        },
        // Unblock Dave globally
        BlockListEvent::UnblockDID {
            target_did: dave.clone(),
            timestamp: 3000,
        },
        // Block Eve in ctx-2
        BlockListEvent::BlockDIDInContext {
            target_did: eve.clone(),
            context_id: "ctx-2".to_owned(),
            timestamp: 4000,
        },
    ];

    let state = BlockListState::from_events(&events);

    // Dave was blocked then unblocked globally.
    assert!(!state.is_globally_blocked(&dave));

    // Eve is not globally blocked.
    assert!(!state.is_globally_blocked(&eve));

    // Eve is blocked in ctx-1 and ctx-2.
    assert!(state.is_blocked_in_context(&eve, "ctx-1"));
    assert!(state.is_blocked_in_context(&eve, "ctx-2"));
    assert!(!state.is_blocked_in_context(&eve, "ctx-3"));

    // Dave is not blocked anywhere.
    assert!(!state.is_blocked_in_context(&dave, "ctx-1"));

    // is_identity_blocked combines global and per-context.
    assert!(state.is_identity_blocked(&eve, "ctx-1"));
    assert!(!state.is_identity_blocked(&dave, "ctx-1"));

    // Empty event log produces empty state.
    let empty_state = BlockListState::from_events(&[]);
    assert!(empty_state.global_block_list().is_empty());

    // Unblock in context.
    let events_with_unblock = vec![
        BlockListEvent::BlockDIDInContext {
            target_did: eve.clone(),
            context_id: "ctx-1".to_owned(),
            timestamp: 1000,
        },
        BlockListEvent::UnblockDIDInContext {
            target_did: eve.clone(),
            context_id: "ctx-1".to_owned(),
            timestamp: 2000,
        },
    ];
    let state_unblocked = BlockListState::from_events(&events_with_unblock);
    assert!(!state_unblocked.is_blocked_in_context(&eve, "ctx-1"));
}
