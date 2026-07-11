//! Integration test for `Supervisor::participation_record` (Phase 2C-1).
//!
//! Verifies that the runtime Supervisor method gathers the context's FULL
//! event log from its wired event-log provider, threads in the caller-supplied
//! accessible attestations, and delegates to the pure-core
//! `compute_participation_record` — surfacing the typed
//! [`ParticipationRecord`](scp_protocol::trust::ParticipationRecord) and its
//! scalar [`ParticipationFacts`](scp_protocol::trust::ParticipationFacts)
//! projection with every fact correctly derived:
//!
//! - `governance_actions_against` — governance events whose projected
//!   `target_did` is the subject (NOT the executing admin); this is exactly why
//!   the method gathers the UNFILTERED event set.
//! - `governance_actions_by` — governance events the subject executed.
//! - `role_progression_count` — `RoleAssigned` leaves for the subject.
//! - `participation_duration_secs` — `MemberJoined`→`MemberLeft` interval.
//! - `context_creation_count` — `ChildContextCreated` by the subject.
//! - `outlet_invocation_count_anchored == false` (ADR-051 not yet landed).
//! - `attestation_count` — accessible, currently-valid attestations for the
//!   subject (the credential-layer fact, §7.4), filtered to subject + Active.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::sync::Arc;

use scp_event_log::payload::{
    GovernanceActionExecutedPayload, MembershipChangePayload, RoleAssignedPayload, encode_payload,
};
use scp_event_log::{EventPayload, EventType};
use scp_protocol::trust::attestation::{Attestation, RevocationStatus};
use scp_protocol::trust::{AttestationType, ParticipationFacts};
use scp_runtime::context::builder::{ContextEventLogProvider, NotConfiguredTransportProvider};
use scp_runtime::context::providers::MerkleEventLogProvider;
use scp_runtime::context::supervisor::Supervisor;
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;
use scp_runtime::crypto::mls::storage_adapter::{
    OpenMlsStorageAdapter, SpawnBlockingStorageAdapter,
};

const CONTEXT_ID: &str = "ctx-participation-2c1";
const SUBJECT: &str = "did:dht:z6MkBob";
const ADMIN: &str = "did:dht:z6MkAlice";

/// A key resolver that never resolves — the participation path verifies no
/// signatures (the supervisor method gathers events + threads attestations; it
/// does not validate them), so the resolver is never consulted here.
fn mock_key_resolver() -> scp_protocol::context::governance::KeyResolver {
    Arc::new(|_did: &scp_did::DID, _kid: scp_did::SigningKeyId| None)
}

fn test_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        scp_platform::testing::InMemoryStorage::new(),
    )))
}

fn membership_payload(subject_did: &str) -> EventPayload {
    encode_payload(&MembershipChangePayload {
        subject_did: subject_did.to_owned(),
        role_name: "member".to_owned(),
    })
    .expect("membership payload encodes")
}

fn role_payload(subject_did: &str) -> EventPayload {
    encode_payload(&RoleAssignedPayload {
        subject_did: subject_did.to_owned(),
        role: "admin".to_owned(),
    })
    .expect("role payload encodes")
}

fn gov_payload(target_did: &str) -> EventPayload {
    encode_payload(&GovernanceActionExecutedPayload {
        target_did: target_did.to_owned(),
        action_type: "RemoveMember".to_owned(),
    })
    .expect("governance payload encodes")
}

const fn empty_payload() -> EventPayload {
    EventPayload { data: Vec::new() }
}

/// Builds an `Active` attestation for `subject` (dummy signature — the
/// participation path counts by subject + status, it does not verify the
/// signature; signature verification is the caller/bridge's job).
fn active_attestation(id: &str, subject: &str) -> Attestation {
    Attestation {
        id: id.to_owned(),
        attestation_type: AttestationType::Endorsement,
        issuer: ADMIN.into(),
        subject: subject.into(),
        claim: serde_json::json!({"test": true}),
        evidence: None,
        issued_at: 1_000,
        expires_at: None,
        renewal_interval: None,
        renewed_at: None,
        revocation_status: RevocationStatus::Active,
        signature: vec![0u8; 64],
    }
}

/// An `Active` event-log-backed Supervisor with a single context whose log
/// carries a representative spread of subject-bearing and target-bearing leaves.
async fn build_supervisor_with_seeded_log() -> Arc<Supervisor> {
    let provider = MerkleEventLogProvider::new();
    let ctx_bytes = scp_runtime::context::state::context_id_to_bytes(CONTEXT_ID);
    provider.init_event_log(&ctx_bytes).await.expect("init log");

    // Walk the log in timestamp order. Bob joins at t=100, leaves at t=400 →
    // a 300-second participation interval. Bob is assigned a role (role
    // progression). The admin executes a governance action TARGETING Bob
    // (governance_actions_against == 1, attributed to Bob though Alice is the
    // actor). Bob himself executes a governance action (governance_actions_by
    // == 1). Bob creates a child context (context_creation_count == 1).
    let appends: &[(EventType, &str, EventPayload, u64)] = &[
        (
            EventType::MemberJoined,
            ADMIN,
            membership_payload(SUBJECT),
            100,
        ),
        (EventType::RoleAssigned, ADMIN, role_payload(SUBJECT), 150),
        (
            EventType::GovernanceActionExecuted,
            ADMIN,
            gov_payload(SUBJECT),
            200,
        ),
        (
            EventType::GovernanceActionExecuted,
            SUBJECT,
            gov_payload(ADMIN),
            250,
        ),
        (
            EventType::ChildContextCreated,
            SUBJECT,
            empty_payload(),
            300,
        ),
        (
            EventType::MemberLeft,
            ADMIN,
            membership_payload(SUBJECT),
            400,
        ),
    ];
    for (event_type, actor, payload, ts) in appends {
        provider
            .append_event(&ctx_bytes, *event_type, actor, payload.clone(), *ts)
            .await
            .expect("append event");
    }

    Supervisor::with_providers(
        Arc::new(MlsCryptoProvider::new(
            ADMIN.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(NotConfiguredTransportProvider),
        Box::new(provider),
        mock_key_resolver(),
        None,
        None,
        None,
        None,
        test_mls_storage(),
    )
}

#[tokio::test]
async fn participation_record_derives_all_facts_from_full_log() {
    let supervisor = build_supervisor_with_seeded_log().await;

    // Two accessible attestations for Bob (Active) + one for someone else +
    // one Revoked for Bob, to prove the count filters to subject + Active.
    let mut revoked_for_bob = active_attestation("att-revoked", SUBJECT);
    revoked_for_bob.revocation_status = RevocationStatus::Revoked {
        reason: "test".to_owned(),
        revoked_at: 2_000,
        revoked_by: ADMIN.into(),
    };
    let attestations = vec![
        active_attestation("att-1", SUBJECT),
        active_attestation("att-2", SUBJECT),
        active_attestation("att-other", "did:dht:z6MkCarol"),
        revoked_for_bob,
    ];

    let record = supervisor
        .participation_record(CONTEXT_ID, SUBJECT, &attestations)
        .expect("participation_record computes");

    // governance: one action AGAINST Bob (target), one BY Bob (actor).
    assert_eq!(
        record.governance_actions_against.len(),
        1,
        "exactly one governance action targets Bob"
    );
    assert_eq!(
        record.governance_actions_by.len(),
        1,
        "exactly one governance action executed by Bob"
    );

    // role: one RoleAssigned leaf for Bob.
    assert_eq!(record.role_history.len(), 1, "one role transition for Bob");

    // duration: MemberJoined(100) → MemberLeft(400) = 300s.
    assert_eq!(record.participation_duration_seconds, 300);

    // context creation: one ChildContextCreated by Bob.
    assert_eq!(record.context_creation_count, 1);

    // attestation_count: only the two Active attestations whose subject is Bob.
    assert_eq!(
        record.attestation_history.len(),
        2,
        "only Active attestations for Bob are counted"
    );

    // Merkle root must be the provider's real root (non-zero, log non-empty).
    assert_ne!(record.event_log_root, [0u8; 32]);

    // The scalar projection flattens identically; outlet count is not Merkle-
    // anchored (ADR-051 not landed).
    let facts = ParticipationFacts::from(&record);
    assert_eq!(facts.governance_actions_against, 1);
    assert_eq!(facts.governance_actions_by, 1);
    assert_eq!(facts.role_progression_count, 1);
    assert_eq!(facts.participation_duration_secs, 300);
    assert_eq!(facts.context_creation_count, 1);
    assert_eq!(facts.attestation_count, 2);
    assert_eq!(facts.outlet_invocation_count, 0);
    assert!(
        !facts.outlet_invocation_count_anchored,
        "outlet count is not Merkle-anchored until ADR-051"
    );
    assert_eq!(facts.subject_did.as_ref(), SUBJECT);
    assert_eq!(facts.event_log_root, record.event_log_root);
}

#[tokio::test]
async fn participation_record_empty_attestations_yields_zero_count() {
    let supervisor = build_supervisor_with_seeded_log().await;
    let record = supervisor
        .participation_record(CONTEXT_ID, SUBJECT, &[])
        .expect("participation_record computes");
    // No attestation access → count 0 (verifier-relative, §7.3.2 — not a stub).
    assert_eq!(record.attestation_history.len(), 0);
    // Other facts are unaffected by the attestation input.
    assert_eq!(record.governance_actions_against.len(), 1);
}

#[test]
fn participation_record_empty_log_errors() {
    let supervisor = Supervisor::with_providers(
        Arc::new(MlsCryptoProvider::new(
            ADMIN.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(NotConfiguredTransportProvider),
        Box::new(MerkleEventLogProvider::new()),
        mock_key_resolver(),
        None,
        None,
        None,
        None,
        test_mls_storage(),
    );
    // No log for this context → empty event set → core returns EmptyEventLog,
    // surfaced as the DEDICATED, machine-detectable `NoParticipationFacts`
    // variant (Finding 3) so the FFI bridges map it to the stable CTX_2076 code
    // instead of collapsing it with genuine failures — not a panic, not a silent
    // empty record, and NOT the generic InvalidState catch-all.
    let err = supervisor
        .participation_record("ctx-never-created", SUBJECT, &[])
        .expect_err("empty log must error");
    assert!(
        matches!(
            err,
            scp_protocol::context::ContextError::NoParticipationFacts { .. }
        ),
        "expected NoParticipationFacts, got: {err:?}"
    );
    assert!(
        format!("{err}").contains("SCP-CTX-2076"),
        "expected the dedicated SCP-CTX-2076 code in the message, got: {err}"
    );
}

/// SECURITY / isolation (white-hat P2, black-hat). A leaf in context B must NOT
/// contribute to context A's participation record: facts are scoped to the
/// queried context's own log, so cross-context activity cannot inflate (or
/// deflate) a subject's standing in an unrelated context.
#[tokio::test]
async fn participation_record_is_context_isolated() {
    const CONTEXT_B: &str = "ctx-participation-2c1-other";

    let provider = MerkleEventLogProvider::new();
    let a_bytes = scp_runtime::context::state::context_id_to_bytes(CONTEXT_ID);
    let b_bytes = scp_runtime::context::state::context_id_to_bytes(CONTEXT_B);
    provider.init_event_log(&a_bytes).await.expect("init A");
    provider.init_event_log(&b_bytes).await.expect("init B");

    // Context A: exactly ONE role assignment for the subject; nothing else.
    provider
        .append_event(
            &a_bytes,
            EventType::RoleAssigned,
            ADMIN,
            role_payload(SUBJECT),
            100,
        )
        .await
        .expect("append A role");

    // Context B: the SAME subject is far more active — three role assignments and
    // an adverse governance action targeting them. None of this may leak into A.
    for ts in [100u64, 200, 300] {
        provider
            .append_event(
                &b_bytes,
                EventType::RoleAssigned,
                ADMIN,
                role_payload(SUBJECT),
                ts,
            )
            .await
            .expect("append B role");
    }
    provider
        .append_event(
            &b_bytes,
            EventType::GovernanceActionExecuted,
            ADMIN,
            gov_payload(SUBJECT),
            400,
        )
        .await
        .expect("append B gov");

    let supervisor = Supervisor::with_providers(
        Arc::new(MlsCryptoProvider::new(
            ADMIN.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(NotConfiguredTransportProvider),
        Box::new(provider),
        mock_key_resolver(),
        None,
        None,
        None,
        None,
        test_mls_storage(),
    );

    // A sees ONLY A's single role assignment and none of B's activity.
    let facts_a = ParticipationFacts::from(
        &supervisor
            .participation_record(CONTEXT_ID, SUBJECT, &[])
            .expect("A record"),
    );
    assert_eq!(
        facts_a.role_progression_count, 1,
        "context A must count only its own role assignment, not B's"
    );
    assert_eq!(
        facts_a.governance_actions_against, 0,
        "B's governance action against the subject must not leak into A"
    );

    // B sees its own (larger) counts — proving the events exist, just scoped to B.
    let facts_b = ParticipationFacts::from(
        &supervisor
            .participation_record(CONTEXT_B, SUBJECT, &[])
            .expect("B record"),
    );
    assert_eq!(facts_b.role_progression_count, 3);
    assert_eq!(facts_b.governance_actions_against, 1);
}

/// An event-log provider that HAS events but whose Merkle-root retrieval fails —
/// models a transient/partial provider fault on the root path while entries are
/// readable.
struct EventsButNoRootProvider;

#[async_trait::async_trait]
impl ContextEventLogProvider for EventsButNoRootProvider {
    async fn init_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_runtime::context::builder::ContextCreationError> {
        Ok(())
    }

    async fn append_event(
        &self,
        _context_id: &[u8; 32],
        _event_type: EventType,
        _actor_did: &str,
        _payload: EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_runtime::context::builder::ContextCreationError> {
        Ok(())
    }

    async fn destroy_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_runtime::context::builder::ContextCreationError> {
        Ok(())
    }

    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        // A single real event so the log is NON-empty.
        Ok(Some(vec![scp_event_log::Event {
            event_type: EventType::MessageSent,
            actor_did: SUBJECT.into(),
            timestamp: 1000,
            sequence: 0,
            payload: EventPayload::default(),
            prev_hash: [0u8; 32],
            signature: vec![0u8; 64],
        }]))
    }

    fn event_log_merkle_root(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<[u8; 32], scp_protocol::context::ContextError> {
        Err(scp_protocol::context::ContextError::EventLogFailed(
            "simulated root retrieval failure".to_owned(),
        ))
    }
}

/// SECURITY (Finding 4). A NON-empty event log whose Merkle-root retrieval fails
/// must FAIL CLOSED: the supervisor propagates the provider error instead of
/// substituting `[0u8; 32]` and emitting real participation facts bound to a zero
/// root.
#[test]
fn participation_record_fails_closed_on_root_error_with_events() {
    let supervisor = Supervisor::with_providers(
        Arc::new(MlsCryptoProvider::new(
            ADMIN.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(NotConfiguredTransportProvider),
        Box::new(EventsButNoRootProvider),
        mock_key_resolver(),
        None,
        None,
        None,
        None,
        test_mls_storage(),
    );

    let err = supervisor
        .participation_record(CONTEXT_ID, SUBJECT, &[])
        .expect_err("a root-retrieval failure on a non-empty log must error, not zero-fill");
    assert!(
        matches!(err, scp_protocol::context::ContextError::EventLogFailed(_)),
        "expected the provider's EventLogFailed to propagate, got: {err:?}"
    );
}
