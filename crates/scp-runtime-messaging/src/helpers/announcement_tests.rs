//! Tests of the messaging domain moved from `scp-runtime-core`
//! `context::actor` (ADR-070 §6.1): they call a function private to this domain.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_runtime_core::context::actor::*;

// -----------------------------------------------------------------
// ADR-049 §15 — state-carrying `ContextActor::new` tests
// -----------------------------------------------------------------

/// Minimal event log provider for the `ContextActor::new` test.
/// Accepts every call, returns OK for every append, never appends
/// anything to a real log — the ADR-049 §15 actor dispatch does not exercise
/// the event-log path, so the stub is never actually touched.
/// The convergent creation instant the TTL-expiry actor tests use — matches
/// the `1_700_000_000` passed to `new_for_test_encrypted` / the past-deadline
/// helper. Post pass-4e (E1) the create base is the PRUNE-IMMUNE snapshot
/// `creation_timestamp_secs + params.ttl`; the test states set
/// `creation_timestamp_secs` to this value via `new_for_test_encrypted`, so
/// `convergent_ttl_deadline` yields `T0 + params.ttl` (not `None`, which would
/// ABORT the expiry per A3). The seeded genesis leaf below is realistic history
/// but is no longer read for the base.
#[cfg(feature = "testing")]
const TTL_TEST_CREATION_TS: u64 = 1_700_000_000;

/// A genesis `ContextCreated` leaf at [`TTL_TEST_CREATION_TS`], returned by the
/// expiry-test event-log doubles' `event_log_entries`. Post pass-4e the
/// derivation does NOT read this leaf for the base (the base is the prune-immune
/// snapshot `creation_timestamp_secs + params.ttl`); it is retained so the test
/// histories stay realistic.
#[cfg(feature = "testing")]
fn ttl_seed_created_leaf() -> scp_event_log::Event {
    scp_event_log::Event {
        event_type: scp_event_log::EventType::ContextCreated,
        actor_did: scp_did::DID("did:example:ttl-test-creator".to_owned()),
        timestamp: TTL_TEST_CREATION_TS,
        sequence: 0,
        payload: scp_event_log::EventPayload::default(),
        prev_hash: [0u8; 32],
        signature: Vec::new(),
    }
}

struct TestEventLog;
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for TestEventLog {
    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event: scp_event_log::EventType,
        _actor: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    #[cfg(feature = "testing")]
    fn event_log_entries(
        &self,
        _id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(Some(vec![ttl_seed_created_leaf()]))
    }
}

/// Minimal persistence stub for the `ContextActor::new` test.
/// Returns empty reads and silently accepts every write.
struct TestPersistence;
#[async_trait::async_trait]
impl scp_runtime_core::context::persistence::ContextPersistence for TestPersistence {
    async fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    async fn delete_context(
        &self,
        _: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

/// Assemble a supervisor-backed `ActorDeps` bundle shared by the
/// state-bearing actor tests (the four `direct_*` announcement tests
/// and `actor_with_state_answers_read_query`). Extracted so each test
/// function stays below the `too_many_lines` clippy threshold.
async fn new_test_deps() -> deps::ActorDeps {
    new_test_deps_with_persistence(Box::new(TestPersistence)).await
}

/// Same as [`new_test_deps`] but with a caller-supplied persistence
/// backend. Lets a test inject a recording backend and assert that a
/// coalesced Class-C mutation actually reaches durable storage via the
/// run loop's coalesced flush (ADR-049 §Decision 9; see
/// `coalesced_class_c_mutation_is_durable_*`).
async fn new_test_deps_with_persistence(
    persistence: Box<dyn scp_runtime_core::context::persistence::ContextPersistence>,
) -> deps::ActorDeps {
    use scp_did::DID;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_runtime_core::context::supervisor::supervisor::Supervisor;
    use std::sync::Arc;

    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestActorNew".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ),
    );
    let transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider> =
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider);
    let event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider> =
        Box::new(TestEventLog);
    let key_resolver: scp_protocol::context::governance::KeyResolver =
        Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None);
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ),
    );

    let supervisor = Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(persistence),
        None,
        None,
        None,
        mls_storage,
        crate::test_support::test_domain_handlers(),
    );

    // `build_actor_deps` self-sources crypto/transport/event_log/clock/
    // key_resolver/mls_storage/persistence from the supervisor and the
    // MLS/HPKE backends transitively through `crypto`; only the owning
    // DID is supplied (resolves this identity's KeyPackageStoreActor).
    scp_runtime_core::context::supervisor::supervisor::leak_for_test(&supervisor);
    supervisor
        .build_actor_deps_loaded(&DID("did:example:actor-with-state-test".to_owned()))
        .await
        .expect("build_actor_deps")
}

// -----------------------------------------------------------------------
// §9.10.4 direct-ingest-site behavioral tests.
//
// `deliver_message_and_drain_buffered` is the IN-ORDER ingest entry point.
// It delegates the four-step pseudonym-announcement validation to the shared
// `ingest_pseudonym_announcement` core (the same boundary the buffered site
// uses) and maps the outcome to its OWN convention: `Recorded` → `Ok(true)`
// (after advancing the sequence tracker + draining the reorder buffer),
// `Rejected` → `Err(PermissionDenied)`. These tests drive a real
// `PseudonymAnnouncement` through that function against a real
// `PerContextState` + `ActorDeps`, asserting both the registry state and the
// direct-site return convention.
// -----------------------------------------------------------------------

const DIRECT_ALICE: &str = "did:dht:z6MkAliceDirect";
const DIRECT_BOB: &str = "did:dht:z6MkBobDirect";

/// Build an encrypted test state where `member` is a writable context
/// member (so the direct ingest path's membership + capability gates pass)
/// and the handle is `Active` (so `require_active` passes).
fn writable_encrypted_state(ctx_byte: u8, member: &str) -> state::PerContextState {
    use scp_protocol::context::roles::Capability;
    use std::collections::HashSet;

    let st = state::PerContextState::new_for_test_encrypted(
        [ctx_byte; 32],
        1_700_000_000,
        scp_did::DID(member.to_owned()),
    );
    // The in-order ingest path requires the context to be Active.
    st.handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("transition test handle to Active");
    let mut st = st;
    st.membership.add_member(
        scp_did::DID(member.to_owned()),
        "member".to_owned(),
        Vec::new(),
    );
    st.members.insert(scp_did::DID(member.to_owned()));
    st.role_state.members.insert(member.to_owned());
    let mut caps = HashSet::new();
    caps.insert(Capability::MessagesWrite);
    st.role_state
        .member_capabilities
        .insert(member.to_owned(), caps);
    st
}

/// Lowercase-hex of a repeated byte — the context-id string the test state's
/// delivery path uses.
fn ctx_hex(byte: u8) -> String {
    let mut s = String::with_capacity(64);
    for _ in 0..32 {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Minimal `InnerEnvelope` — `deliver_message_and_drain_buffered` reads only
/// `sequence` + `timestamp` off it (the message body is the `plaintext`
/// argument; the signature is verified upstream of this helper). All
/// `InnerEnvelope` fields are `pub`, so a struct literal is the simplest
/// faithful fixture.
fn minimal_inner(
    ctx: &str,
    sender: &str,
    sequence: u64,
) -> scp_protocol::envelope::inner::InnerEnvelope {
    scp_protocol::envelope::inner::InnerEnvelope {
        version: scp_protocol::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
        context_id: ctx.to_owned(),
        sender_did: sender.to_owned(),
        epoch: 0,
        generation: 0,
        sequence,
        timestamp: 1_700_000_000,
        message_type: scp_protocol::envelope::inner::MessageType::Content,
        payload_hash: [0u8; 32],
        payload: Vec::new(),
        provenance: None,
        provenance_hash: [0u8; 32],
        signing_key_id: scp_did::SigningKeyId::Active,
        signature: [0u8; 64],
        extensions: std::collections::HashMap::new(),
    }
}

fn announcement_bytes(member_did: &str, pseudonym: [u8; 32]) -> Vec<u8> {
    use scp_protocol::context::pseudonym::{PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement};
    let ann = PseudonymAnnouncement {
        tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
        member_did: member_did.to_owned(),
        pseudonym,
    };
    rmp_serde::to_vec_named(&ann).expect("serialize announcement")
}

#[tokio::test]
async fn direct_legitimate_announcement_records_and_returns_consumed() {
    let deps = new_test_deps().await;
    let mut state = writable_encrypted_state(0x31, DIRECT_ALICE);
    let ctx = ctx_hex(0x31);
    let ctx_bytes = [0x31u8; 32];
    let pseudonym = [0x42u8; 32];
    let inner = minimal_inner(&ctx, DIRECT_ALICE, 1);

    let mut downward_auth_applied: Option<
        scp_runtime_core::context::actor::class_s::ClassSCommitToken,
    > = None;
    let consumed = crate::helpers::deliver_message_and_drain_buffered(
        &mut scp_runtime_core::context::actor::class_s::ClassCMut::from_state(&mut state),
        &deps,
        &ctx,
        &ctx_bytes,
        DIRECT_ALICE,
        &inner,
        &announcement_bytes(DIRECT_ALICE, pseudonym),
        true,
        &mut downward_auth_applied,
    )
    .await
    .expect("a legitimate announcement is consumed, not an error");
    assert!(consumed, "an announcement is reported as consumed (true)");
    let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
    assert_eq!(
        reg.get(&scp_did::DID(DIRECT_ALICE.to_owned()))
            .map(|r| &r.routing_id),
        Some(&pseudonym)
    );
}

#[tokio::test]
async fn direct_forged_did_announcement_errors_permission_denied() {
    let deps = new_test_deps().await;
    let mut state = writable_encrypted_state(0x32, DIRECT_ALICE);
    let ctx = ctx_hex(0x32);
    let ctx_bytes = [0x32u8; 32];
    // Authenticated sender is ALICE, but the announcement claims BOB.
    let inner = minimal_inner(&ctx, DIRECT_ALICE, 1);

    let mut downward_auth_applied: Option<
        scp_runtime_core::context::actor::class_s::ClassSCommitToken,
    > = None;
    let result = crate::helpers::deliver_message_and_drain_buffered(
        &mut scp_runtime_core::context::actor::class_s::ClassCMut::from_state(&mut state),
        &deps,
        &ctx,
        &ctx_bytes,
        DIRECT_ALICE,
        &inner,
        &announcement_bytes(DIRECT_BOB, [0x42u8; 32]),
        true,
        &mut downward_auth_applied,
    )
    .await;
    assert!(
        matches!(result, Err(ContextError::PermissionDenied(_))),
        "the direct ingest site maps a rejection to PermissionDenied; got {result:?}"
    );
    assert!(
        state
            .routing
            .peer_registry()
            .expect("encrypted ⇒ registry")
            .is_empty(),
        "a rejected announcement must not touch the registry"
    );
}

#[tokio::test]
async fn direct_reserved_value_announcement_errors_permission_denied() {
    let deps = new_test_deps().await;
    let mut state = writable_encrypted_state(0x33, DIRECT_ALICE);
    let ctx = ctx_hex(0x33);
    let ctx_bytes = [0x33u8; 32];
    let inner = minimal_inner(&ctx, DIRECT_ALICE, 1);

    let mut downward_auth_applied: Option<
        scp_runtime_core::context::actor::class_s::ClassSCommitToken,
    > = None;
    let result = crate::helpers::deliver_message_and_drain_buffered(
        &mut scp_runtime_core::context::actor::class_s::ClassCMut::from_state(&mut state),
        &deps,
        &ctx,
        &ctx_bytes,
        DIRECT_ALICE,
        &inner,
        &announcement_bytes(DIRECT_ALICE, [0u8; 32]), // zero sentinel = reserved
        true,
        &mut downward_auth_applied,
    )
    .await;
    assert!(
        matches!(result, Err(ContextError::PermissionDenied(_))),
        "a reserved routing-ID value is rejected on the direct path; got {result:?}"
    );
}

#[tokio::test]
async fn direct_same_did_reannounce_succeeds_and_updates_registry() {
    let deps = new_test_deps().await;
    let mut state = writable_encrypted_state(0x34, DIRECT_ALICE);
    let ctx = ctx_hex(0x34);
    let ctx_bytes = [0x34u8; 32];

    for (seq, rid) in [(1u64, [0x42u8; 32]), (2u64, [0x43u8; 32])] {
        let inner = minimal_inner(&ctx, DIRECT_ALICE, seq);
        let mut downward_auth_applied: Option<
            scp_runtime_core::context::actor::class_s::ClassSCommitToken,
        > = None;
        let consumed = crate::helpers::deliver_message_and_drain_buffered(
            &mut scp_runtime_core::context::actor::class_s::ClassCMut::from_state(&mut state),
            &deps,
            &ctx,
            &ctx_bytes,
            DIRECT_ALICE,
            &inner,
            &announcement_bytes(DIRECT_ALICE, rid),
            true,
            &mut downward_auth_applied,
        )
        .await
        .expect("same-DID re-announce must succeed");
        assert!(consumed);
    }
    let reg = state.routing.peer_registry().expect("encrypted ⇒ registry");
    assert_eq!(
        reg.get(&scp_did::DID(DIRECT_ALICE.to_owned()))
            .map(|r| &r.routing_id),
        Some(&[0x43u8; 32]),
        "a same-DID re-announce updates the registry to the rotated routing ID"
    );
}

// -----------------------------------------------------------------
// ADR-049 §Decision 9 — coalesced Class-C persistence durability.
//
// A `class_c_view()` mutation performs NO persist at the mutation
// site (that is its documented contract; see
// `ClassSCell::class_c_view`) — durability rides ENTIRELY on the run
// loop's coalesced flush (`persist_snapshot`, invoked by the Arm-4
// coalesce tick and the post-loop final drain). These regression
// tests drive a real coalesced Class-C mutation through the mailbox
// and prove the flush actually writes it to durable storage. Before
// `persist_snapshot` was wired, the flush was a no-op and any
// mutation made only via `class_c_view()` was silently lost on
// shutdown/crash.
// -----------------------------------------------------------------

/// Ingests `member`'s v2 announcement at `pseudonym_epoch` through the
/// real in-order ingest path.
async fn ingest_v2_announcement(
    state: &mut state::PerContextState,
    deps: &deps::ActorDeps,
    ctx_byte: u8,
    member: &str,
    sequence: u64,
    pseudonym_epoch: u64,
    routing_id: [u8; 32],
) -> Result<bool, ContextError> {
    use scp_protocol::context::pseudonym::{
        PSEUDONYM_ANNOUNCEMENT_V2_TAG, PseudonymAnnouncementV2,
    };
    let ctx = ctx_hex(ctx_byte);
    let plaintext = rmp_serde::to_vec_named(&PseudonymAnnouncementV2 {
        tag: PSEUDONYM_ANNOUNCEMENT_V2_TAG.to_owned(),
        member_did: member.to_owned(),
        pseudonym_epoch,
        routing_id,
    })
    .expect("serialize v2 announcement");
    let inner = minimal_inner(&ctx, member, sequence);
    let mut downward_auth_applied: Option<
        scp_runtime_core::context::actor::class_s::ClassSCommitToken,
    > = None;
    crate::helpers::deliver_message_and_drain_buffered(
        &mut scp_runtime_core::context::actor::class_s::ClassCMut::from_state(state),
        deps,
        &ctx,
        &[ctx_byte; 32],
        member,
        &inner,
        &plaintext,
        true,
        &mut downward_auth_applied,
    )
    .await
}

/// Spec 09 §9.10.4.1 "Record lifetime": once a member processes a Commit
/// another member committed to remove a DID, that DID's record is gone, so
/// the DID's v2 announcement at a lower epoch than the one recorded before
/// the removal is accepted. Before the removal the same announcement is
/// rejected by the ordering criterion, so the deletion is what admits it.
#[tokio::test]
async fn a_processed_removal_admits_the_rejoiners_lower_epoch_announcement() {
    use scp_protocol::context::pseudonym::CommitMembershipChange;
    use scp_protocol::context::roles::Capability;
    use scp_runtime_core::context::actor::pseudonym_rotation::{
        ProcessedCommit, note_processed_commit,
    };

    const LOCAL: &str = "did:dht:z6MkLocalDirect";
    let deps = new_test_deps().await;
    // DIRECT_BOB is the peer that leaves and rejoins.
    let mut state = writable_encrypted_state(0x35, DIRECT_BOB);
    state.membership.add_member(
        scp_did::DID(LOCAL.to_owned()),
        "member".to_owned(),
        Vec::new(),
    );
    state.members.insert(scp_did::DID(LOCAL.to_owned()));
    state.role_state.members.insert(LOCAL.to_owned());
    state.role_state.member_capabilities.insert(
        LOCAL.to_owned(),
        std::iter::once(Capability::MessagesWrite).collect(),
    );

    assert!(
        ingest_v2_announcement(&mut state, &deps, 0x35, DIRECT_BOB, 1, 1, [0x51; 32])
            .await
            .expect("the epoch-1 announcement is accepted")
    );
    let rejected =
        ingest_v2_announcement(&mut state, &deps, 0x35, DIRECT_BOB, 2, 0, [0x50; 32]).await;
    assert!(
        matches!(rejected, Err(ContextError::PermissionDenied(_))),
        "a lower epoch over a recorded epoch is rejected; got {rejected:?}"
    );

    note_processed_commit(
        &mut state,
        LOCAL,
        &ProcessedCommit {
            committer_did: DIRECT_ALICE.to_owned(),
            change: CommitMembershipChange {
                added_dids: Vec::new(),
                removed_dids: vec![DIRECT_BOB.to_owned()],
            },
        },
    );
    let registry = state.routing.peer_registry().expect("encrypted ⇒ registry");
    assert!(!registry.contains_key(&scp_did::DID(DIRECT_BOB.to_owned())));
    // Spec 07 §7.3.1.1 step 3: the unverified leaf diff leaves the
    // membership and role state alone, so the DID stays a member here
    // and only the record deletion changes what is admitted. This test
    // is therefore no evidence for the rejoin clause of PUSH-030 AC2,
    // which waits on the verified leaves of SCP-330.
    assert!(state.membership.contains(DIRECT_BOB));
    assert!(
        state
            .role_state
            .member_has_capability(DIRECT_BOB, &Capability::MessagesWrite)
    );
    assert!(
        ingest_v2_announcement(&mut state, &deps, 0x35, DIRECT_BOB, 3, 0, [0x52; 32])
            .await
            .expect("the rejoiner's epoch-0 announcement is accepted")
    );
    let record = state
        .routing
        .peer_registry()
        .expect("encrypted ⇒ registry")
        .get(&scp_did::DID(DIRECT_BOB.to_owned()))
        .copied()
        .map(|r| (r.routing_id, r.epoch));
    assert_eq!(record, Some(([0x52; 32], Some(0))));
}
