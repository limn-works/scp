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
    clippy::missing_const_for_fn,
    // An in-memory `TrustProtocolRepository` below holds one lock guard across
    // a lookup and its inserts on purpose: `add_revocations` needs both steps
    // under one guard, or a concurrent caller on one context drops what another
    // adds. Tightening that guard's scope would reintroduce that lost update.
    clippy::significant_drop_tightening
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
use scp_core::context::roles::Capability;
use scp_core::identity::block_list::{BlockListEvent, BlockListState};
use scp_core::trust::{
    ActionCategory, Attestation, AttestationEvidence, AttestationType, AttestorInfo, CapabilityUri,
    ChallengePolicy, ChallengeSigner, ConsequenceAction, ConsequenceRule, ConsequenceTrigger,
    ContextSybilPolicy, CounterAttestation, CustodyViolationError, CustodyViolationType,
    EarnedCapacityLevel, EnforcementSeverity, ExpectedOutput, FreshnessStatus, FreshnessWeight,
    IdentityDepthAssessment, MinCases, NewChallenge, ParticipationFact, ParticipationInput,
    ParticipationThreshold, PolicyPick, ProtocolOnlyDefinitions, RequireParticipation,
    RevocationStatus, ScpCustodyViolationAttestation, TestCase, TestOutput, ThresholdCheckInput,
    ThresholdRequirement, TrustError, TrustSignal, TrustSignalCategory,
    authenticate_challenge_response, challenge_request_signing_digest,
    challenge_response_signing_digest, challenge_response_unsigned,
    challenge_verification_signing_digest, challenge_verification_unsigned,
    check_attestation_freshness, check_threshold_attestation, classify_action,
    compute_participation_record, enforce_category_a, evaluate_consequence_rules,
    evaluate_earned_capacity, evaluate_sybil_resistance, grade, issue_challenge,
    produce_participation_profile, verify_attestation, verify_challenge_verification,
    verify_participation_requirements,
};
use scp_did::{DID, SigningKeyId};
use scp_event_log::{Event, EventPayload, EventType};
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

impl scp_clock::Clock for FixedClock {
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

impl scp_core::trust::attestation::ActiveKeyResolver for TestKeyResolver {
    fn resolve_active_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
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
    fn sign(&self, digest: &[u8; 32]) -> Result<Vec<u8>, TrustError> {
        Ok(self.0.sign(digest).to_bytes().to_vec())
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

/// Encodes a canonical `MembershipChangePayload` (subject-bearing membership
/// leaf) so participation-duration intervals are attributable to the member
/// (§7.3.2).
fn membership_payload(subject_did: &str, role_name: &str) -> Vec<u8> {
    scp_event_log::payload::encode_payload(&scp_event_log::payload::MembershipChangePayload {
        subject_did: subject_did.to_owned(),
        role_name: role_name.to_owned(),
    })
    .expect("membership payload encodes")
    .data
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

    // Claim is compact JSON (RFC 8785 JCS) per §9.5.2 Attestation row 5;
    // evidence/revocation_status stay MessagePack per the §9.5.2 note.
    let claim_bytes = scp_core::jcs::to_vec(&att.claim).unwrap();
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
    )
    .unwrap();
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
        make_event(
            EventType::MemberJoined,
            alice,
            1000,
            0,
            membership_payload(alice, "member"),
        ),
        make_event(EventType::MessageSent, alice, 1100, 1, vec![]),
        make_event(
            EventType::OutletInvoked,
            alice,
            1200,
            2,
            b"my-outlet\0".to_vec(),
        ),
        make_event(EventType::ChildContextCreated, alice, 1300, 3, vec![]),
    ];

    // No attestation-cache access ⇒ empty accessible-attestation set (§7.3.2).
    let record =
        compute_participation_record(&events, alice, "ctx-test", [0u8; 32], 2000, &[]).unwrap();

    assert_eq!(record.subject_did, did(alice));
    assert_eq!(record.context_id, "ctx-test");
    // MemberJoined + MessageSent + OutletInvoked + ChildContextCreated = 4 events.
    assert_eq!(record.participation_count, 4);
    // Membership-interval duration: open MemberJoined (1000) → latest event
    // ts (1300) = 300 seconds.
    assert_eq!(record.participation_duration_seconds, 300);
    assert_eq!(*record.outlet_invocations.get("my-outlet").unwrap_or(&0), 1);
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
    let result = verify_attestation(
        &att,
        &resolver,
        &clock,
        &scp_core::trust::NoOpRevocationChecker,
    );
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
    let subject = did("did:dht:z6MkSubject");
    let clock = FixedClock(1500);
    let mut resolver = TestKeyResolver::new();

    // Build 3 attestors, each carrying an endorsement it signed itself about
    // the subject. `check_threshold_attestation` verifies every signature, so
    // each attestor's key goes into the resolver.
    let attestors: Vec<AttestorInfo> = (0..3)
        .map(|i| {
            let sk = sk_for(i);
            let att = make_signed_attestation(
                &format!("att-{i}"),
                att_type.clone(),
                // `make_signed_attestation` overwrites the issuer with the
                // did:key form of the signing key it uses.
                "did:key:placeholder",
                "did:dht:z6MkSubject",
                &sk,
                1000,
                None,
                None,
            );
            resolver.add(&att.issuer, sk.verifying_key().to_bytes().to_vec());
            AttestorInfo {
                did: att.issuer.clone(),
                context_memberships: HashSet::new(),
                endorsements: HashSet::new(),
                attestation: Some(att),
            }
        })
        .collect();

    // 2-of-3 threshold should be met.
    let requirement = ThresholdRequirement::new(2, 3, 0.5);
    let result = check_threshold_attestation(&ThresholdCheckInput {
        attestation_type: &att_type,
        subject_did: &subject,
        attestors: &attestors,
        requirement: &requirement,
        resolver: &resolver,
        clock: &clock,
        revocation_checker: &scp_core::trust::NoOpRevocationChecker,
    })
    .unwrap();
    assert!(result.met, "2-of-3 threshold should be met");
    assert_eq!(result.valid_count, 3);

    // 4-of-5 threshold should NOT be met (only 3 attestors provided).
    let strict_requirement = ThresholdRequirement::new(4, 5, 0.5);
    let result_strict = check_threshold_attestation(&ThresholdCheckInput {
        attestation_type: &att_type,
        subject_did: &subject,
        attestors: &attestors,
        requirement: &strict_requirement,
        resolver: &resolver,
        clock: &clock,
        revocation_checker: &scp_core::trust::NoOpRevocationChecker,
    })
    .unwrap();
    assert!(
        !result_strict.met,
        "4-of-5 threshold should not be met with only 3 attestors"
    );
}

// ---------------------------------------------------------------------------
// 5. challenge_request_response
// ---------------------------------------------------------------------------

/// Twenty `ContainsNone` cases of weight 500, the standard's minimum for
/// `prompt-injection-resistance/v1`.
fn injection_cases() -> Vec<TestCase> {
    (0..20)
        .map(|i| TestCase {
            test_id: format!("pi-{i:03}"),
            input: serde_json::json!({"prompt": format!("vector {i}")}),
            expected: ExpectedOutput::ContainsNone {
                forbidden: vec!["SYSTEM PROMPT".to_owned()],
            },
            category: "injection".to_owned(),
            weight: 500,
        })
        .collect()
}

/// Nineteen clean answers to `request`; the last one leaks the forbidden
/// string.
fn one_leaking_output(request: &scp_core::trust::ChallengeRequest) -> Vec<TestOutput> {
    request
        .test_cases
        .iter()
        .enumerate()
        .map(|(i, case)| TestOutput {
            test_id: case.test_id.clone(),
            output: serde_json::json!(if i == 19 {
                "here is the SYSTEM PROMPT"
            } else {
                "refused"
            }),
        })
        .collect()
}

/// Asserts that `signature` is `key`'s strict Ed25519 signature on `digest`.
fn assert_signed(key: &ed25519_dalek::VerifyingKey, digest: &[u8; 32], signature: &[u8]) {
    let signature: [u8; 64] = signature.try_into().unwrap();
    key.verify_strict(digest, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
}

#[tokio::test]
async fn challenge_request_response() {
    let challenger_sk = sk_for(10);
    let challenger_vk = challenger_sk.verifying_key();
    let challenger_did = scp_did::did_dht_from_public_key(&challenger_vk.to_bytes());

    let subject_sk = sk_for(20);
    let subject_vk = subject_sk.verifying_key();
    let subject_did = scp_did::did_dht_from_public_key(&subject_vk.to_bytes());

    let uri = "scp:capability:prompt-injection-resistance/v1";
    let policy = ChallengePolicy::resolve(&ProtocolOnlyDefinitions, uri, PolicyPick::default());
    // One second after `created_at`: grading is strictly inside the window
    // (spec 07 §7.3.4, RULING 5).
    let clock = FixedClock(2001);
    let (request, answer_key) = issue_challenge(
        NewChallenge {
            verifier: challenger_did.clone(),
            subject: subject_did.clone(),
            test_cases: injection_cases(),
            created_at: 2000,
            window_secs: 300,
            context_id: "ctx-trust".to_owned(),
            policy: policy.unwrap(),
        },
        &TestChallengeSigner(challenger_sk.clone()),
    )
    .unwrap();

    assert_eq!(request.verifier, challenger_did);
    assert_eq!(request.subject, subject_did);
    // The verifier signed the request digest, not the preimage.
    let request_digest = challenge_request_signing_digest(&request).unwrap();
    assert_signed(&challenger_vk, &request_digest, &request.verifier_signature);

    let mut resolver = TestKeyResolver::new();
    resolver.add(&subject_did, subject_vk.to_bytes().to_vec());
    resolver.add(&challenger_did, challenger_vk.to_bytes().to_vec());

    let outputs = one_leaking_output(&request);
    let unsigned_response =
        challenge_response_unsigned(&request, &subject_did, 1, outputs, &resolver, &clock).unwrap();
    // The subject signs the response digest.
    let response_digest = unsigned_response.signing_digest();
    let response = unsigned_response
        .with_subject_signature(subject_sk.sign(&response_digest).to_bytes().to_vec());
    assert_eq!(
        challenge_response_signing_digest(&response).unwrap(),
        response_digest
    );

    let auth = authenticate_challenge_response(
        request.clone(),
        response.clone(),
        &challenger_did,
        &resolver,
    )
    .unwrap();
    let outcome = grade(
        &auth,
        &answer_key,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeMap::new(),
    );
    let unsigned_record = challenge_verification_unsigned(&auth, &outcome, 2001).unwrap();
    let record_digest = unsigned_record.signing_digest();
    let verification = unsigned_record
        .with_verifier_signature(challenger_sk.sign(&record_digest).to_bytes().to_vec());

    assert_eq!(verification.subject, subject_did);
    assert_eq!(verification.verifier, challenger_did);
    assert_eq!(verification.capability_uri, request.capability_uri);
    assert_eq!(verification.attempt, 1);
    assert_eq!((verification.test_count, verification.pass_count), (20, 19));
    assert_eq!(verification.score, 9_500);
    assert_eq!(
        verification.passed,
        verification.score >= request.pass_threshold_bps
    );
    assert_eq!(
        verification.suite_digest,
        scp_core::trust::challenge_suite_digest(&request.test_cases).unwrap()
    );
    assert_eq!(verification.context_id, "ctx-trust");
    assert_eq!(
        challenge_verification_signing_digest(&verification).unwrap(),
        record_digest
    );
    assert_signed(
        &challenger_vk,
        &record_digest,
        &verification.verifier_signature,
    );
    verify_challenge_verification(
        &verification,
        &resolver,
        &ProtocolOnlyDefinitions,
        "ctx-trust",
        &subject_did,
        &clock,
    )
    .unwrap();
    // The record is bound to its context.
    assert!(
        verify_challenge_verification(
            &verification,
            &resolver,
            &ProtocolOnlyDefinitions,
            "ctx-other",
            &subject_did,
            &clock
        )
        .is_err()
    );
}

/// The heading of spec 07's protocol capability registry, whose standards
/// table pairs each protocol capability with its minimum case count.
const STANDARDS_SECTION_HEADING: &str = "#### 7.3.4.3 ";

/// Returns `(name, minimum column)` for each standards-table row of spec 07
/// §7.3.4.3, reading only that section: from its heading to the next heading
/// of equal or higher level. A row is ``| `name` | <minimum> |`` whose minimum
/// starts with a digit. Fails when the heading is missing or the section holds
/// no such row, so a table elsewhere in spec 07 never reaches the caller and a
/// moved heading cannot pass as an empty table.
fn standards_table_rows(spec: &str) -> Result<Vec<(&str, &str)>, String> {
    let level = STANDARDS_SECTION_HEADING
        .chars()
        .take_while(|c| *c == '#')
        .count();
    let mut lines = spec.lines();
    lines
        .by_ref()
        .find(|line| line.starts_with(STANDARDS_SECTION_HEADING))
        .ok_or_else(|| format!("spec 07 has no heading {STANDARDS_SECTION_HEADING:?}"))?;
    let mut rows = Vec::new();
    for line in lines {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if hashes > 0 && hashes <= level && line[hashes..].starts_with(' ') {
            break;
        }
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((name, rest)) = rest.split_once('`') else {
            continue;
        };
        let Some(min_column) = rest.trim_start_matches(" |").split('|').next() else {
            continue;
        };
        let min_column = min_column.trim();
        if min_column.starts_with(|c: char| c.is_ascii_digit()) {
            rows.push((name, min_column));
        }
    }
    if rows.is_empty() {
        return Err("spec 07 §7.3.4.3 holds no standards-table row".to_owned());
    }
    Ok(rows)
}

/// A table row outside §7.3.4.3, such as a constant table's, is ignored, and
/// a row inside the section is read, including one below a lower-level
/// subheading.
#[test]
fn standards_table_rows_reads_only_section_7_3_4_3() {
    let spec = "\
### 7.3.1 Earlier
| `D_MAX` | 10 seconds | before |
#### 7.3.4.3 Protocol Capability Registry
| `code-review/v1` | 20 | in section |
##### 7.3.4.3.1 Protocol Constant
| `summarize/v1` | 5 per `category` | still in section |
#### 7.3.4.4 Next
| `MERGE_CARRY_ITEMS` | 8 | after |
";
    assert_eq!(
        standards_table_rows(spec).unwrap(),
        vec![
            ("code-review/v1", "20"),
            ("summarize/v1", "5 per `category`")
        ]
    );
}

/// The parser fails, rather than returning no rows, when the heading is
/// missing or the section holds no row.
#[test]
fn standards_table_rows_fails_without_heading_or_rows() {
    assert!(standards_table_rows("| `D_MAX` | 10 seconds |\n").is_err());
    assert!(
        standards_table_rows("#### 7.3.4.3 Registry\ntext\n#### 7.3.4.4 Next\n| `x` | 3 |\n")
            .is_err()
    );
}

/// Every protocol capability row of spec 07 §7.3.4.3's standards table states
/// the minimum the compiled-in constant enforces.
#[test]
fn protocol_capability_minimums_match_spec_07_table() {
    const SPEC_07: &str =
        include_str!("../../../../.docs/specs/07-trust-validation-and-capabilities.md");
    let rows = standards_table_rows(SPEC_07).unwrap();
    for (name, min_column) in &rows {
        let digits: String = min_column
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let n: u32 = digits.parse().unwrap();
        let expected = if min_column.contains("per `category`") {
            MinCases::PerCategory(n)
        } else {
            assert_eq!(
                *min_column, digits,
                "{name}: unrecognised minimum {min_column:?}"
            );
            MinCases::Total(n)
        };
        let uri = format!("scp:capability:{name}");
        let entry = scp_core::trust::capability_registry::lookup_protocol_capability(&uri)
            .unwrap_or_else(|| panic!("{uri}: in the spec table, not in the protocol constant"));
        assert_eq!(
            entry.challenge.map(|standard| standard.min_cases),
            Some(expected),
            "{uri}: code and spec 07 table disagree"
        );
    }
    assert_eq!(
        rows.len(),
        28,
        "the spec 07 standards table has one row per protocol capability"
    );
}

// ---------------------------------------------------------------------------
// 6. consequence_rules_evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consequence_rules_evaluation() {
    let rules = vec![
        ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            }),
            threshold: 3,
            window: Duration::from_mins(1),
        },
        ConsequenceRule {
            trigger: ConsequenceTrigger::OutletRateExceeded,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            threshold: 2,
            window: Duration::from_mins(2),
        },
    ];

    let alice = "did:dht:z6MkAlice";
    let events = vec![
        make_event(EventType::MessageSent, alice, 950, 0, vec![]),
        make_event(EventType::MessageSent, alice, 960, 1, vec![]),
        make_event(EventType::MessageSent, alice, 970, 2, vec![]),
        make_event(
            EventType::OutletInvoked,
            alice,
            980,
            3,
            b"outlet-a".to_vec(),
        ),
        make_event(
            EventType::OutletInvoked,
            alice,
            990,
            4,
            b"outlet-b".to_vec(),
        ),
    ];

    let triggered = evaluate_consequence_rules(&rules, &events, alice, 1000, 1000);

    assert_eq!(triggered.len(), 2);
    assert_eq!(triggered[0].rule_index, 0);
    assert_eq!(
        triggered[0].action,
        ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
            capabilities: vec![Capability::MessagesWrite]
        })
    );
    assert_eq!(triggered[0].evidence.len(), 3);

    assert_eq!(triggered[1].rule_index, 1);
    assert_eq!(
        triggered[1].action,
        ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess)
    );
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
    assert_eq!(classify_action("outlet_call"), ActionCategory::CategoryB);
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

    // Field shapes should pass. This check establishes nothing about who
    // signed; `VerifiedCustodyViolation::verify` answers that.
    assert!(attestation.validate_field_shape().is_ok());

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

    // A counter-claim names a violation record by a 32-byte reference spec
    // section §9.5.2 derives, so build a record first and let `referencing`
    // compute that reference rather than inventing an identifier.
    let violation = ScpCustodyViolationAttestation::new(
        did("did:dht:z6MkSubject"),
        1000,
        CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_owned(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![1, 2, 3, 4],
        },
        vec![5, 6, 7, 8],
        did("did:dht:z6MkVerifier"),
    )
    .unwrap();

    let counter = CounterAttestation::referencing(
        &violation,
        "Key was compromised and rotated".to_owned(),
        2000,
        sig.to_bytes().to_vec(),
    )
    .unwrap();

    assert_eq!(counter.subject_did, did("did:dht:z6MkSubject"));
    assert_eq!(
        counter.violation_reference,
        violation.signing_hash().unwrap(),
        "a counter-claim's reference equals a contested record's signing hash"
    );
    assert_eq!(counter.explanation, "Key was compromised and rotated");
    assert_eq!(counter.timestamp, 2000);
    assert!(!counter.signature.is_empty());
    assert!(counter.validate_field_shape().is_ok());

    // An empty explanation and an empty signature each fail.
    assert!(
        CounterAttestation::referencing(&violation, String::new(), 2000, vec![1]).is_err(),
        "an empty explanation must be rejected"
    );

    assert!(
        CounterAttestation::referencing(&violation, "explanation".to_owned(), 2000, vec![])
            .is_err(),
        "an empty signature must be rejected"
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
        make_event(
            EventType::MemberJoined,
            alice,
            1000,
            0,
            membership_payload(alice, "member"),
        ),
        make_event(EventType::MessageSent, alice, 2000, 1, vec![]),
        make_event(
            EventType::OutletInvoked,
            alice,
            3000,
            2,
            b"outlet-x\0".to_vec(),
        ),
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
            accessible_attestations: &[],
        },
    )
    .unwrap();

    assert_eq!(profile.subject_did, did(alice));
    // Membership-interval duration: open MemberJoined (1000) → latest event
    // ts (3000) = 2000 seconds.
    assert_eq!(profile.participation_duration_secs, 2000);
    assert_eq!(profile.outlet_invocation_count, 1);
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
            accessible_attestations: &[],
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
            accessible_attestations: &[],
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

    // Create events that will produce a profile with some participation. A
    // subject-bearing MemberJoined anchors the participation-duration interval
    // (§7.3.2).
    let events = vec![
        make_event(
            EventType::MemberJoined,
            alice,
            1000,
            0,
            membership_payload(alice, "member"),
        ),
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
            accessible_attestations: &[],
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
            accessible_attestations: &[],
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
        verify_participation_requirements(current_time, alice, &requirements, &[profile1.clone()]);
    assert!(result.is_ok(), "should pass with valid profile: {result:?}");

    // Requirement needing 2 distinct contexts: passes with 2 profiles.
    let requirements_2ctx = vec![RequireParticipation {
        fact: ParticipationFact::ParticipationDuration,
        threshold: ParticipationThreshold::AtLeast(1000),
        max_age_secs: 3600,
        min_contexts: 2,
    }];

    let result_1 = verify_participation_requirements(
        current_time,
        alice,
        &requirements_2ctx,
        &[profile1.clone()],
    );
    assert!(result_1.is_err(), "should fail with only 1 context");

    let result_2 = verify_participation_requirements(
        current_time,
        alice,
        &requirements_2ctx,
        &[profile1, profile2],
    );
    assert!(
        result_2.is_ok(),
        "should pass with 2 distinct contexts: {result_2:?}"
    );

    // Empty requirements always pass.
    assert!(verify_participation_requirements(current_time, alice, &[], &[]).is_ok());
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
    assert!(!protocol.is_identifier_scoped());
    assert!(!protocol.is_system());
    assert_eq!(protocol.name(), "prompt-injection-resistance");
    assert_eq!(protocol.to_string(), protocol_str);

    // Identifier-scoped capability (spec 25 Vector 57's identifier)
    let scoped_str =
        "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za:capability:domain-expertise/v2";
    let scoped: CapabilityUri = scoped_str.parse().unwrap();
    assert!(scoped.is_identifier_scoped());
    assert_eq!(scoped.name(), "domain-expertise");
    assert_eq!(scoped.to_string(), scoped_str);
    // A did: authority is not an identifier in the §3.1 text form.
    assert!(
        "did:dht:z6Mk123:capability:domain-expertise/v2"
            .parse::<CapabilityUri>()
            .is_err()
    );

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
    let scoped: CapabilityUri =
        "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za:capability:test/v1"
            .parse()
            .unwrap();

    // Same name, different versions are not equal.
    assert_ne!(v1, v2);

    // Different variant types are not equal even with same name.
    assert_ne!(v1, system);
    assert_ne!(v1, scoped);

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

// ---------------------------------------------------------------------------
// Issuer-scoped attestation revocation (§7.4.4, issue #2335 finding 13)
// ---------------------------------------------------------------------------

/// Minimal `TrustProtocolRepository` for the revocation-scoping tests below.
/// Keys cached attestations by `(context, subject, issuer, id)` so two issuers
/// carrying one attestation id coexist, which is what these tests need to
/// observe.
#[derive(Default)]
struct ScopingTestStore {
    attestations: std::sync::Mutex<
        HashMap<(String, String, String, String), scp_core::trust::aggregate::CachedAttestation>,
    >,
    revocations: std::sync::Mutex<HashMap<String, HashSet<String>>>,
    challenges:
        std::sync::Mutex<HashMap<(String, String), Vec<scp_core::trust::ChallengeVerification>>>,
}

impl scp_core::trust::aggregate::TrustProtocolRepository for ScopingTestStore {
    fn get_cached_attestations(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<scp_core::trust::aggregate::CachedAttestation>, TrustError> {
        let store = self.attestations.lock().unwrap();
        Ok(store
            .iter()
            .filter(|((ctx, subject, _, _), _)| ctx == context_id && subject == subject_did)
            .map(|(_, entry)| entry.clone())
            .collect())
    }

    fn store_cached_attestation(
        &self,
        context_id: &str,
        entry: scp_core::trust::aggregate::CachedAttestation,
    ) -> Result<(), TrustError> {
        let mut store = self.attestations.lock().unwrap();
        store.insert(
            (
                context_id.to_owned(),
                entry.attestation.subject.to_string(),
                entry.attestation.issuer.to_string(),
                entry.attestation.id.clone(),
            ),
            entry,
        );
        Ok(())
    }

    fn get_revocation_state(&self, context_id: &str) -> Result<HashMap<String, bool>, TrustError> {
        let store = self.revocations.lock().unwrap();
        Ok(store
            .get(context_id)
            .map(|keys| keys.iter().map(|k| (k.clone(), true)).collect())
            .unwrap_or_default())
    }

    fn add_revocations(
        &self,
        context_id: &str,
        entries: &[scp_core::trust::aggregate::RevocationEntry],
        _now: u64,
    ) -> Result<(), TrustError> {
        // One guard spans the lookup and the inserts, so a concurrent caller on
        // this context cannot drop what this call adds. These tests write a
        // handful of never-expiring records, so the cap and prune never engage.
        let mut store = self.revocations.lock().unwrap();
        let keys = store.entry(context_id.to_owned()).or_default();
        for entry in entries {
            keys.insert(entry.list_key.clone());
        }
        Ok(())
    }

    fn get_challenge_results(
        &self,
        context_id: &str,
        subject_did: &str,
    ) -> Result<Vec<scp_core::trust::ChallengeVerification>, TrustError> {
        let store = self.challenges.lock().unwrap();
        let key = (context_id.to_owned(), subject_did.to_owned());
        Ok(store.get(&key).cloned().unwrap_or_default())
    }

    fn store_challenge_result(
        &self,
        context_id: &str,
        result: &scp_core::trust::ChallengeVerification,
    ) -> Result<(), TrustError> {
        let mut store = self.challenges.lock().unwrap();
        let key = (context_id.to_owned(), result.subject.to_string());
        store.entry(key).or_default().push(result.clone());
        Ok(())
    }
}

/// Wraps an attestation as a cache entry that stays fresh forever, so no TTL
/// effect can explain an exclusion these tests observe.
fn scoping_entry(attestation: Attestation) -> scp_core::trust::aggregate::CachedAttestation {
    scp_core::trust::aggregate::CachedAttestation {
        attestation,
        verified_at: 0,
        ttl_secs: u64::MAX,
    }
}

/// SECURITY (issuer-scoped revocation, §7.4.4, issue #2335 finding 13).
/// §7.4.1 describes `Attestation.id` as a UUID v4 that an issuer chooses and
/// states no rule deriving that id from its issuer, so two issuers can carry one
/// id. §7.4.4 grants a revocation to the issuer alone. An attacker who derives a
/// DID from a fresh keypair therefore MUST NOT be able to suppress an honest
/// issuer's attestation by recording a revocation that names that attestation's
/// id: `AttestationCache::get_verified_attestations` keeps returning the honest
/// issuer's attestation. The second half revokes under the honest issuer's own
/// DID and observes the exclusion, so the first half's survival is attributable
/// to issuer scoping rather than to a revocation list nobody reads.
#[test]
fn attestation_revocation_binds_to_the_issuer_that_signed_it() {
    use scp_core::trust::aggregate::{
        AttestationCache, RevocationEntry, TrustProtocolRepository, revocation_list_key,
    };

    let context_id = "ctx-issuer-scoped-revocation";
    let subject_did = "did:key:subject-scoped";
    let shared_id = "endorsement-shared-2026";

    let honest_sk = sk_for(71);
    let attacker_sk = sk_for(73);

    let honest = make_signed_attestation(
        shared_id,
        AttestationType::Endorsement,
        "did:key:placeholder",
        subject_did,
        &honest_sk,
        1000,
        Some(u64::MAX),
        None,
    );
    let attacker = make_signed_attestation(
        shared_id,
        AttestationType::Endorsement,
        "did:key:placeholder",
        subject_did,
        &attacker_sk,
        1000,
        Some(u64::MAX),
        None,
    );
    assert_ne!(
        honest.issuer, attacker.issuer,
        "the two issuers must differ for this test to exercise issuer scoping"
    );

    let mut resolver = TestKeyResolver::new();
    resolver.add(
        honest.issuer.as_ref(),
        honest_sk.verifying_key().to_bytes().to_vec(),
    );
    resolver.add(
        attacker.issuer.as_ref(),
        attacker_sk.verifying_key().to_bytes().to_vec(),
    );
    let clock = FixedClock(2000);

    let store = ScopingTestStore::default();
    store
        .store_cached_attestation(context_id, scoping_entry(honest.clone()))
        .unwrap();

    // The attacker records a revocation of the shared id under its own DID.
    let attacker_revocation = RevocationEntry {
        list_key: revocation_list_key(&attacker.issuer, shared_id),
        expires_at: None,
    };
    store
        .add_revocations(context_id, &[attacker_revocation], 2000)
        .unwrap();

    let cache = AttestationCache::new(store);
    let survived = cache
        .get_verified_attestations(context_id, subject_did, &resolver, &clock)
        .unwrap();
    assert_eq!(
        survived.len(),
        1,
        "a revocation the attacker signed must leave the honest issuer's attestation counted, got {survived:?}"
    );
    assert_eq!(
        survived[0].issuer, honest.issuer,
        "the surviving attestation must be the honest issuer's"
    );

    // The honest issuer revokes its own attestation, and that revocation lands.
    let honest_revocation = RevocationEntry {
        list_key: revocation_list_key(&honest.issuer, shared_id),
        expires_at: None,
    };
    cache
        .store()
        .add_revocations(context_id, &[honest_revocation], 2000)
        .unwrap();

    let excluded = cache
        .get_verified_attestations(context_id, subject_did, &resolver, &clock)
        .unwrap();
    assert!(
        excluded.is_empty(),
        "an issuer's own revocation must exclude that issuer's attestation, got {excluded:?}"
    );
}
