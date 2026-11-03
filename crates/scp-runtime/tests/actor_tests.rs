//! Tests moved out of `scp-runtime-core` `context::actor` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_runtime_core::context::actor::*;
use tokio::sync::mpsc;

/// Encode a 32-byte context ID as lowercase hex, for test fixtures whose
/// string id is the hex of their hash.
fn hex_encode_context_id(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in id {
        use std::fmt::Write;
        // Infallible for `u8` inputs written into `String`.
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[tokio::test]
async fn actor_exits_on_inbox_close() {
    // Run-loop invariant: when every sender drops, `recv()` yields
    // `None` and the actor exits — no Shutdown command needed. This
    // holds for the (sole) state-owning actor shape.
    let deps = new_test_deps().await;
    let state = state::PerContextState::new_for_test_encrypted(
        [0x11u8; 32],
        1_700_000_000,
        scp_did::DID("did:example:admin".to_owned()),
    );
    let (tx, rx) = mpsc::channel::<ContextCommand>(1);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_handle = tokio::spawn(actor.run());

    // Drop every sender; actor should observe `None` on recv and
    // exit without a Shutdown command.
    drop(tx);

    // Bound the wait so a regression that fails to exit is caught.
    tokio::time::timeout(std::time::Duration::from_secs(2), actor_handle)
        .await
        .expect("actor must exit when every sender drops")
        .unwrap();
}

#[tokio::test]
async fn actor_pause_acks_ok_and_keeps_running() {
    // `Pause` is non-terminal: the actor acks `Ok(())` and keeps
    // running, so a subsequent query is still answered off its owned
    // state.
    let deps = new_test_deps().await;
    let state = state::PerContextState::new_for_test_encrypted(
        [0x12u8; 32],
        1_700_000_000,
        scp_did::DID("did:example:admin".to_owned()),
    );
    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_handle = tokio::spawn(actor.run());

    let handle = ContextActorHandle::from_sender(tx);
    handle.send_pause().await.unwrap();
    // Actor is still running; a subsequent read query answers off
    // owned state (empty test fixture ⇒ exact roster count 0).
    let count = handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::MemberCount {
                context_id: hex_encode_context_id(&[0x12u8; 32]),
                reply,
            })
        })
        .await
        .expect("member-count query round-trips after a Pause");
    assert_eq!(count, Some(0));

    handle.send_shutdown().await.unwrap();
    actor_handle.await.unwrap();
}

#[tokio::test]
async fn actor_shutdown_command_exits_loop_promptly() {
    // `Shutdown` is unconditionally terminal: the run loop breaks
    // after dispatching it. Bound the wait so a regression that fails
    // to exit is caught rather than hanging CI.
    let deps = new_test_deps().await;
    let state = state::PerContextState::new_for_test_encrypted(
        [0x13u8; 32],
        1_700_000_000,
        scp_did::DID("did:example:admin".to_owned()),
    );
    let (tx, rx) = mpsc::channel::<ContextCommand>(1);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_handle = tokio::spawn(actor.run());

    let handle = ContextActorHandle::from_sender(tx);
    handle.send_shutdown().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(2), actor_handle)
        .await
        .expect("actor must exit promptly after Shutdown")
        .unwrap();
}

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
        scp_runtime::domain_handlers(),
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

/// `ContextActor::new` constructs an actor that owns `PerContextState`
/// + `ActorDeps` directly and routes commands through the state-owning
/// `dispatch_state` path. This test asserts the struct is constructible
/// and the run-loop processes commands by round-tripping a read-only
/// member-count query and observing a concrete answer.
///
/// Integration-level coverage of the full
/// `build_actor_deps_from_attached` path lives in
/// `crates/scp-runtime/tests/actor_deps_complete.rs` +
/// `spawn_actor_with_state` unit tests in
/// `crates/scp-runtime/src/context/supervisor/supervisor.rs`; this
/// unit test focuses on the actor struct's constructor + run-loop.
#[tokio::test]
async fn actor_with_state_answers_read_query() {
    let deps = new_test_deps().await;
    let state = state::PerContextState::new_for_test_encrypted(
        [0x42u8; 32],
        1_700_000_000,
        scp_did::DID("did:example:admin".to_owned()),
    );

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());

    let handle = ContextActorHandle::from_sender(tx);
    // The state-owning actor answers a read-only query on owned state,
    // proving the run loop picks commands up from the inbox and routes
    // them through the actor-shape queries handler.
    let count = handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::MemberCount {
                context_id: hex_encode_context_id(&[0x42u8; 32]),
                reply,
            })
        })
        .await
        .expect("member-count query round-trips through the state-owning actor");
    // The test fixture (`new_for_test_encrypted`) seeds the admin DID into
    // `governance`, not into `membership`, so the roster is empty and
    // `MemberCount` (which reads `state.membership.count()`) answers the
    // exact count 0 — not merely "some" count.
    assert_eq!(
        count,
        Some(0),
        "the owning actor answers MemberCount with the exact roster count \
             (empty test fixture ⇒ 0)"
    );

    handle.send_shutdown().await.unwrap();
    actor_task.await.unwrap();
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

/// Persistence that RECORDS every `persist_context` snapshot, so a test
/// can prove a coalesced Class-C mutation reached durable storage
/// (ADR-049 §Decision 9). `load_context` returns the most-recent
/// recorded snapshot, so a respawn/restore reads the coalesced state
/// back. `persisted` fires once per write, letting a test await the
/// coalesce flush deterministically under paused tokio time.
#[cfg(feature = "testing")]
#[derive(Clone)]
struct RecordingPersistence {
    // Lock-free per ADR-049 §Decision 12 (`std::sync`/`tokio::sync` mutexes
    // are banned in this crate): the last-written snapshot lives in an
    // `ArcSwapOption`, swapped on each write and loaded on read.
    last:
        std::sync::Arc<arc_swap::ArcSwapOption<scp_runtime_core::context::state::ContextSnapshot>>,
    /// The key the last snapshot was persisted under.
    last_key: std::sync::Arc<arc_swap::ArcSwapOption<String>>,
    persisted: std::sync::Arc<tokio::sync::Notify>,
    /// When set, every `persist_context` fails and records nothing.
    failing: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Fires once per failed write.
    failed: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(feature = "testing")]
impl RecordingPersistence {
    fn new() -> Self {
        Self {
            last: std::sync::Arc::new(arc_swap::ArcSwapOption::empty()),
            last_key: std::sync::Arc::new(arc_swap::ArcSwapOption::empty()),
            persisted: std::sync::Arc::new(tokio::sync::Notify::new()),
            failing: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            failed: std::sync::Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Makes every later write fail (`true`) or land (`false`).
    fn set_failing(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::SeqCst);
    }

    /// The most-recent persisted snapshot, or `None` if nothing was
    /// written — exactly the bytes a respawn/restore would rehydrate.
    fn last_snapshot(
        &self,
    ) -> Option<std::sync::Arc<scp_runtime_core::context::state::ContextSnapshot>> {
        self.last.load_full()
    }
}

#[cfg(feature = "testing")]
#[async_trait::async_trait]
impl scp_runtime_core::context::persistence::ContextPersistence for RecordingPersistence {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            self.failed.notify_one();
            return Err("the test store refuses the write".into());
        }
        self.last_key
            .store(Some(std::sync::Arc::new(context_id.to_owned())));
        self.last.store(Some(std::sync::Arc::new(snapshot.clone())));
        self.persisted.notify_one();
        Ok(())
    }
    async fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.last_snapshot().map(|s| (*s).clone()))
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
        Ok(self
            .last_snapshot()
            .map(|s| vec![s.context_id.clone()])
            .unwrap_or_default())
    }
}

/// Send a `TestInstallAccessKey` command to `handle` for `(ctx, member)`.
/// The handler mutates the persisted `access_key_store` through
/// `class_c_view()` and reports `Outcome::ok_mutated` — a coalesced
/// Class-C mutation with NO co-located persist, so its durability rides
/// only the run loop's coalesced flush.
#[cfg(feature = "testing")]
async fn install_access_key_via_mailbox(handle: &ContextActorHandle, ctx: &str, member: &str) {
    handle
        .send(|reply| {
            ContextCommand::Messaging(MessagingCommand::TestInstallAccessKey {
                context_id: ctx.to_owned(),
                member_did: member.to_owned(),
                key: scp_protocol::crypto::access_keys::generate_access_key(ctx, member),
                reply,
            })
        })
        .await
        .expect("access-key install round-trips through the state-owning actor");
}

/// The post-loop **final drain** persists a pending coalesced Class-C
/// mutation: after installing an access key (a `class_c_view()` mutation
/// with no co-located persist) and shutting the actor down, the drained
/// snapshot must carry the key, so a respawn/restore reads it back.
/// Regression guard for ADR-049 §Decision 9 — with `persist_snapshot` a
/// no-op, the drain wrote nothing and the mutation was lost on shutdown.
#[cfg(feature = "testing")]
#[tokio::test]
async fn coalesced_class_c_mutation_is_durable_across_final_drain() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    let ctx = ctx_hex(0x51);
    let member = "did:example:coalesced-drain-member";
    let state = writable_encrypted_state(0x51, member);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    install_access_key_via_mailbox(&handle, &ctx, member).await;

    // Shutdown drives the run loop to exit; the post-loop final drain
    // (`if self.dirty { persist_snapshot().await }`) flushes the pending
    // snapshot. Awaiting the actor task guarantees the drain completed.
    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");

    let snapshot = recorder
        .last_snapshot()
        .expect("final drain must have persisted a snapshot (ADR-049 §Decision 9)");
    assert!(
        snapshot.access_key_store.contains(&ctx, member),
        "the coalesced access-key mutation must be durable in the drained snapshot"
    );
}

/// An actor whose context id is not lowercase hex persists its snapshot
/// under that id, the key the supervisor restores from. The 32-byte
/// `state.context_id` of such an id is its SHA-256, so an actor keyed by
/// the hex of those bytes wrote a second snapshot that a restart listed
/// as a persisted context no restore could reach.
#[cfg(feature = "testing")]
#[tokio::test]
async fn an_actor_persists_under_its_handle_id_when_the_id_is_not_hex() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    let name = "named-context";
    let member = "did:example:named-context-member";
    let mut state = writable_encrypted_state(0x53, member);
    state.context_id = scp_runtime_core::context::state::context_id_to_bytes(name);
    state.handle = scp_runtime_core::context::ContextHandle::new(
        name.to_owned(),
        scp_protocol::context::ContextParams::default(),
    );

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);
    // The shutdown handler marks the actor dirty, so the final drain
    // runs the same `persist_snapshot` as the coalesce tick.
    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");

    let key = recorder
        .last_key
        .load_full()
        .expect("the final drain persists a snapshot");
    assert_eq!(key.as_str(), name);
}

/// The run loop's **Arm-4 coalesce tick** (`dirty && deadline reached`)
/// flushes the same pending mutation while the actor is still live —
/// the same `persist_snapshot` the final drain uses, reached on the
/// ≤50 ms `COALESCE_INTERVAL` (ADR-049 §Decision 9). Paused tokio time
/// advances the window deterministically, never racing the wall clock.
#[cfg(feature = "testing")]
#[tokio::test]
async fn coalesced_class_c_mutation_is_durable_across_coalesce_tick() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    // Pause AFTER building deps so `build_actor_deps` runs under real
    // time; the actor's `last_persist_attempt_at` is captured (in
    // `ContextActor::new`) against the now-frozen clock.
    tokio::time::pause();
    let ctx = ctx_hex(0x52);
    let member = "did:example:coalesced-tick-member";
    let state = writable_encrypted_state(0x52, member);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    install_access_key_via_mailbox(&handle, &ctx, member).await;

    // Advance virtual time past the coalescing window so Arm-4 fires while
    // the actor is still running (no Shutdown / drain involved). Determinism
    // comes from tokio's current-thread paused clock auto-advancing to the
    // next timer once both tasks park — NOT from the exact `advance` amount;
    // the `+1ms` only steps strictly past the deadline. `notify_one` stores a
    // permit, so `notified()` below cannot miss the wakeup even if the persist
    // lands during `advance`.
    tokio::time::advance(COALESCE_INTERVAL + std::time::Duration::from_millis(1)).await;
    // Bound the wait so a `persist_snapshot` regression to a no-op (no
    // `notify_one`) fails this test in bounded VIRTUAL time instead of
    // hanging forever (`#[tokio::test]` has no wall-clock timeout): under
    // paused time the timeout auto-advances and returns `Err`, turning the
    // hang into a legible assertion failure.
    tokio::time::timeout(COALESCE_INTERVAL * 20, recorder.persisted.notified())
        .await
        .expect("Arm-4 coalesce tick must persist within the coalesce window");

    let snapshot = recorder
        .last_snapshot()
        .expect("the coalesce tick must have persisted a snapshot (ADR-049 §Decision 9)");
    assert!(
        snapshot.access_key_store.contains(&ctx, member),
        "the coalesced access-key mutation must be durable after the Arm-4 tick"
    );

    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");
}

/// A flush writes the pending mutation and leaves the actor clean: no
/// coalesce tick follows it. Without that, a write of the state as it
/// stood at the flush lands up to `COALESCE_INTERVAL` after the flush
/// returned, over anything written to the store in between.
#[cfg(feature = "testing")]
#[tokio::test]
async fn a_flush_leaves_no_coalesced_write_pending() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    tokio::time::pause();
    let ctx = ctx_hex(0x54);
    let member = "did:example:flush-clean-member";
    let state = writable_encrypted_state(0x54, member);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    install_access_key_via_mailbox(&handle, &ctx, member).await;
    handle
        .send(|reply| {
            ContextCommand::Lifecycle(
                scp_runtime_core::context::actor::commands::LifecycleCommand::FlushSnapshot {
                    reply,
                },
            )
        })
        .await
        .expect("the flush round-trips through the actor");
    tokio::time::timeout(COALESCE_INTERVAL, recorder.persisted.notified())
        .await
        .expect("the flush persists the pending mutation");
    assert!(
        recorder
            .last_snapshot()
            .expect("the flush persisted a snapshot")
            .access_key_store
            .contains(&ctx, member)
    );

    assert!(
        tokio::time::timeout(COALESCE_INTERVAL * 20, recorder.persisted.notified())
            .await
            .is_err(),
        "no coalesce tick may write after a flush"
    );

    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");
}

/// A flush whose write fails replies with the error and leaves the actor
/// dirty, so the next coalesce tick writes the mutation once the store
/// accepts writes again (ADR-049 §Decision 9).
#[cfg(feature = "testing")]
#[tokio::test]
async fn a_failed_flush_replies_with_the_error_and_the_next_tick_retries() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    tokio::time::pause();
    let ctx = ctx_hex(0x55);
    let member = "did:example:flush-fail-member";
    let state = writable_encrypted_state(0x55, member);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    recorder.set_failing(true);
    install_access_key_via_mailbox(&handle, &ctx, member).await;
    let flushed = handle
        .send(|reply| {
            ContextCommand::Lifecycle(
                scp_runtime_core::context::actor::commands::LifecycleCommand::FlushSnapshot {
                    reply,
                },
            )
        })
        .await;
    assert!(
        matches!(flushed, Err(ContextError::PersistenceFailed(_))),
        "a flush whose write failed must say so: {flushed:?}"
    );
    assert!(recorder.last_snapshot().is_none());

    recorder.set_failing(false);
    tokio::time::timeout(COALESCE_INTERVAL * 2, recorder.persisted.notified())
        .await
        .expect("the next coalesce tick writes what the failed flush did not");
    assert!(
        recorder
            .last_snapshot()
            .expect("the tick persisted a snapshot")
            .access_key_store
            .contains(&ctx, member)
    );

    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");
}

/// A coalesced write that fails leaves the actor dirty: later ticks keep
/// writing, one coalescing window apart, until one lands (ADR-049
/// §Decision 9).
#[cfg(feature = "testing")]
#[tokio::test]
async fn a_failed_coalesced_write_stays_dirty_until_a_tick_lands() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    tokio::time::pause();
    let ctx = ctx_hex(0x56);
    let member = "did:example:tick-fail-member";
    let state = writable_encrypted_state(0x56, member);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    recorder.set_failing(true);
    install_access_key_via_mailbox(&handle, &ctx, member).await;
    for attempt in 0..3 {
        tokio::time::timeout(COALESCE_INTERVAL * 2, recorder.failed.notified())
            .await
            .unwrap_or_else(|_| panic!("failed tick {attempt} must be followed by another"));
    }
    assert!(recorder.last_snapshot().is_none());

    recorder.set_failing(false);
    tokio::time::timeout(COALESCE_INTERVAL * 2, recorder.persisted.notified())
        .await
        .expect("a tick lands once the store accepts writes");
    assert!(
        recorder
            .last_snapshot()
            .expect("the tick persisted a snapshot")
            .access_key_store
            .contains(&ctx, member)
    );

    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");
}

/// Regression guard for ADR-049 finding **N1** (PR-2 caller audit): a handler
/// that mutates Class-C via `class_c_view()` but reports `Outcome::ok`
/// (`mutated:false`) leaves `dirty` clear, so the run loop's Arm-4 coalesce
/// tick never fires and the mutation is lost on crash.
///
/// `SeedPeerPseudonym` was exactly such a handler: it records a peer routing
/// pseudonym into the `Pseudonymous` registry through `class_c_view()` (NO
/// co-located persist) and used to return `Outcome::ok`. The PR-2 fix makes it
/// report `Outcome::ok_mutated` on a successful insert.
///
/// This uses the **coalesce-tick** model (like
/// [`coalesced_class_c_mutation_is_durable_across_coalesce_tick`]), NOT a
/// shutdown drain: the drain cannot validate a handler's `mutated` flag,
/// because the `Shutdown` handler ITSELF reports `mutated` and dirties the
/// actor, so the drain fires (persisting the whole live state, which already
/// carries the in-memory insert) regardless of the seed handler's flag. Here
/// the assertion runs while the actor is STILL LIVE, off the Arm-4 tick that
/// fires only when `dirty` is set — so with the pre-fix `Outcome::ok` handler
/// `dirty` stays false, the tick never fires, and `persisted.notified()` times
/// out in bounded virtual time (a genuine failure, empirically verified).
#[cfg(feature = "testing")]
#[tokio::test]
async fn coalesced_seed_peer_pseudonym_is_durable_across_coalesce_tick() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    // Pause AFTER building deps so `build_actor_deps` runs under real time and
    // the actor's `last_persist_attempt_at` is captured against the now-frozen clock.
    tokio::time::pause();
    let ctx = ctx_hex(0x53);
    let member = "did:example:coalesced-seed-peer-member";
    let pseudonym = [0x77u8; 32];
    let state = writable_encrypted_state(0x53, member);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    // Record a peer pseudonym — a coalesced Class-C mutation with NO co-located
    // persist (routes through `class_c_view`). Awaiting the reply also proves
    // the live in-memory insert succeeded.
    handle
        .send(|reply| {
            ContextCommand::Messaging(MessagingCommand::SeedPeerPseudonym {
                context_id: ctx.clone(),
                member_did: scp_did::DID(member.to_owned()),
                pseudonym,
                reply,
            })
        })
        .await
        .expect("seed-peer-pseudonym round-trips through the state-owning actor");

    // Advance past the coalescing window so Arm-4 fires while the actor is still
    // running (NO shutdown/drain). With the pre-fix `Outcome::ok` handler
    // `dirty` stays false, Arm-4 never fires, and this `notified()` times out.
    tokio::time::advance(COALESCE_INTERVAL + std::time::Duration::from_millis(1)).await;
    tokio::time::timeout(COALESCE_INTERVAL * 20, recorder.persisted.notified())
        .await
        .expect("Arm-4 coalesce tick must persist the seeded pseudonym within the window");

    let snapshot = recorder
        .last_snapshot()
        .expect("the coalesce tick must have persisted a snapshot (ADR-049 §Decision 9 / N1)");
    let registry = snapshot
        .routing
        .peer_registry()
        .expect("the encrypted test context must persist a Pseudonymous peer registry");
    assert_eq!(
        registry
            .get(&scp_did::DID(member.to_owned()))
            .map(|r| &r.routing_id),
        Some(&pseudonym),
        "the coalesced peer-pseudonym mutation must be durable after the Arm-4 tick",
    );

    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");
}

/// Regression guard for ADR-049 finding **N1** (PR-2): `TestInsertMember`
/// records a member — roster insert, `system_assign_role`, and membership add —
/// through `class_c_view()` with NO co-located persist, and used to return
/// `Outcome::ok` (`mutated:false`), so a `<=50ms` crash silently lost the
/// member. The PR-2 fix reports `Outcome::ok_mutated` on a successful insert.
///
/// Same **coalesce-tick** model as the sibling pseudonym test (the assertion
/// runs while the actor is live, so the shutdown drain cannot mask a false
/// flag): with the pre-fix `Outcome::ok` handler `dirty` stays false, Arm-4
/// never fires, and `persisted.notified()` times out (empirically verified).
#[cfg(feature = "testing")]
#[tokio::test]
async fn coalesced_test_insert_member_is_durable_across_coalesce_tick() {
    use scp_protocol::context::roles::{builtin_roles, default_ceiling};

    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_persistence(Box::new(recorder.clone())).await;
    tokio::time::pause();
    let ctx = ctx_hex(0x54);
    let admin = "did:example:coalesced-insert-admin";
    let new_member = "did:example:coalesced-insert-member";
    let mut state = writable_encrypted_state(0x54, admin);
    // `TestInsertMember` calls `system_assign_role("member")`, which requires
    // that role to be DEFINED within the context ceiling. The bare test fixture
    // starts with an empty ceiling / no role definitions, so seed the standard
    // ceiling + built-in roles (the same "member" role a real `create_context`
    // installs) before driving the insert.
    let ceiling = default_ceiling();
    state
        .role_state
        .set_ceiling(ceiling.clone())
        .expect("seed the default ceiling for the member role definition");
    for role in builtin_roles(&ceiling) {
        state
            .role_state
            .role_definitions
            .insert(role.name.clone(), role);
    }

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    // Insert a second member — a coalesced Class-C structural mutation with NO
    // co-located persist. Awaiting the reply proves the live insert succeeded.
    handle
        .send(|reply| {
            ContextCommand::Messaging(MessagingCommand::TestInsertMember {
                context_id: ctx.clone(),
                member_did: scp_did::DID(new_member.to_owned()),
                role: "member".to_owned(),
                reply,
            })
        })
        .await
        .expect("test-insert-member round-trips through the state-owning actor");

    tokio::time::advance(COALESCE_INTERVAL + std::time::Duration::from_millis(1)).await;
    tokio::time::timeout(COALESCE_INTERVAL * 20, recorder.persisted.notified())
        .await
        .expect("Arm-4 coalesce tick must persist the inserted member within the window");

    let snapshot = recorder
        .last_snapshot()
        .expect("the coalesce tick must have persisted a snapshot (ADR-049 §Decision 9 / N1)");
    assert!(
        snapshot.role_state.members.contains(new_member),
        "the coalesced role-state member insert must be durable after the Arm-4 tick",
    );
    assert!(
        snapshot.membership.contains(new_member),
        "the coalesced membership add must be durable after the Arm-4 tick",
    );

    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");
}

// -----------------------------------------------------------------
// SEC-1 / ADR-049 §9 amendment — fail-closed TTL expiry before teardown.
//
// These drive the actor's real run loop through a TTL fire and assert the
// SEC-1 properties: the terminal `Expired` state is persisted FAIL-CLOSED
// OUTSIDE the relay/event-log transport timeout (so a hostile-relay stall
// cannot cancel the durable transition and re-open a resurrection window),
// and an INCOMPLETE expiry keeps the actor alive to retry (carrying the
// completed-steps bitmask) rather than despawning with unfinished cleanup.
// -----------------------------------------------------------------

/// Build `ActorDeps` with caller-supplied transport + event-log providers
/// (the SEC-1 tests inject a stalling / flaky event log) plus persistence.
/// Mirrors [`new_test_deps_with_persistence`].
#[cfg(feature = "testing")]
async fn new_test_deps_with_providers(
    persistence: Box<dyn scp_runtime_core::context::persistence::ContextPersistence>,
    transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider>,
    event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
) -> deps::ActorDeps {
    use scp_did::DID;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_runtime_core::context::supervisor::supervisor::Supervisor;
    use std::sync::Arc;

    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestSec1Ttl".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ),
    );
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
        scp_runtime::domain_handlers(),
    );

    scp_runtime_core::context::supervisor::supervisor::leak_for_test(&supervisor);
    supervisor
        .build_actor_deps_loaded(&DID("did:example:sec1-ttl-test".to_owned()))
        .await
        .expect("build_actor_deps")
}

/// Event log whose `append_event` STALLS forever — models a hostile relay /
/// wedged event-log sink that a `timeout(HANDLER_TIMEOUT)` must bound.
#[cfg(feature = "testing")]
struct StallingEventLog;
#[cfg(feature = "testing")]
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for StallingEventLog {
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
        std::future::pending::<()>().await;
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    // Reading is fast (a seeded genesis leaf) even though `append` stalls; the
    // deadline base comes from the prune-immune snapshot so expiry proceeds
    // (A3). The STALL is exercised on `append_event`, the op under test.
    fn event_log_entries(
        &self,
        _id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(Some(vec![ttl_seed_created_leaf()]))
    }
}

/// Event log whose `append_event` FAILS on the first attempt then succeeds —
/// a transient cleanup-step failure the actor must retry. (Key destruction
/// itself is not independently injectable: `NodeMlsFactory::destroy_*`
/// are inherent `DashMap` ops that always return `Ok`; a transient event-log
/// failure exercises the IDENTICAL incomplete-cleanup → keep-alive → retry
/// path SEC-1ii guards.)
#[cfg(feature = "testing")]
#[derive(Clone, Default)]
struct FlakyEventLog {
    // `Arc`-shared so the test keeps a handle to read the counters while the
    // deps own a `Box<dyn …>` clone.
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    successes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
#[cfg(feature = "testing")]
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for FlakyEventLog {
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
        use std::sync::atomic::Ordering;
        let n = self.attempts.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            return Err(
                scp_protocol::context::builder::ContextCreationError::EventLogFailed(
                    "fixture: transient event-log append failure (first attempt)".to_owned(),
                ),
            );
        }
        self.successes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    // Reading returns a seeded genesis leaf (realistic history); the deadline
    // base comes from the prune-immune snapshot so expiry proceeds (A3). The
    // transient FAILURE under test is on `append_event`, not the read.
    fn event_log_entries(
        &self,
        _id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(Some(vec![ttl_seed_created_leaf()]))
    }
}

/// Build an `Active` encrypted test state with the TTL deadline already in
/// the past, so `reconcile_timers` arms a `sleep(0)` that fires the TTL
/// expiry on the actor's first loop turn (no `advance` needed to fire it).
#[cfg(feature = "testing")]
fn active_state_with_past_ttl(ctx_byte: u8, now_secs: u64) -> state::PerContextState {
    let context_id_hex = hex_encode_context_id(&[ctx_byte; 32]);
    let mut state = state::PerContextState::new_for_test_encrypted(
        [ctx_byte; 32],
        TTL_TEST_CREATION_TS,
        scp_did::DID("did:example:sec1-admin".to_owned()),
    );
    // A finite params.ttl so the single-source `convergent_ttl_deadline`
    // (prune-immune snapshot `creation_timestamp_secs + params.ttl`) yields a
    // real base. Without
    // a finite ttl AND a genesis leaf the derivation is `None` and
    // `handle_ttl_expiry` ABORTS (A3), so the scalar-armed expiry never fires.
    state.handle = scp_runtime_core::context::ContextHandle::new(
        context_id_hex,
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_hours(1)),
            ..Default::default()
        },
    );
    state
        .handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("transition test handle to Active");
    // Deadline in the past ⇒ `reconcile_timers` derives `remaining = 0`.
    state.ttl.timer.deadline_unix_secs = Some(now_secs.saturating_sub(1));
    state
}

/// SEC-1i (MUST FAIL pre-fix): with the event-log I/O stalling past
/// `HANDLER_TIMEOUT`, the terminal `Expired` state is persisted FAIL-CLOSED
/// BEFORE the actor could tear down, and the actor stays alive to retry the
/// unfinished cleanup. Pre-fix, the terminal persist was best-effort AFTER
/// the timed-out I/O (so a relay stall cancelled it, leaving only a
/// post-despawn coalesce drain to record `Expired` — a resurrection window)
/// AND the actor despawned unconditionally on `Expired` (mailbox closed).
#[cfg(feature = "testing")]
#[tokio::test]
async fn ttl_expiry_persists_before_despawn_with_stalling_transport() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_providers(
        Box::new(recorder.clone()),
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider),
        Box::new(StallingEventLog),
    )
    .await;
    tokio::time::pause();

    let now = deps.clock.now_secs();
    let state = active_state_with_past_ttl(0x71, now);
    let ctx = hex_encode_context_id(&[0x71u8; 32]);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    // The fail-closed Phase-1 persist runs BEFORE (and outside) the stalling
    // I/O, so it lands without any `advance`. A bounded virtual guard turns a
    // regression (no fail-closed persist) into a legible failure, not a hang.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        recorder.persisted.notified(),
    )
    .await
    .expect("the terminal Expired state must be persisted fail-closed (SEC-1)");

    let snap = recorder
        .last_snapshot()
        .expect("fail-closed persist recorded a snapshot");
    assert_eq!(
        snap.state,
        scp_protocol::context::ContextState::Expired,
        "the durable snapshot must be Expired BEFORE any teardown — anti-resurrection \
             keys off this (a stale Active snapshot would resurrect on respawn)"
    );

    // Advance past the I/O transport budget so the stalled event-log append
    // times out. Post-fix: cleanup is incomplete ⇒ the actor keeps itself
    // alive and re-arms a retry (it does NOT despawn). Pre-fix: the actor
    // despawned here (mailbox closed).
    tokio::time::advance(HANDLER_TIMEOUT + std::time::Duration::from_secs(1)).await;

    let state_after = handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::ReadContextState {
                context_id: ctx.clone(),
                reply,
            })
        })
        .await
        .expect("actor is still alive after an INCOMPLETE expiry (SEC-1 keep-alive)");
    assert_eq!(
        state_after,
        scp_protocol::context::ContextState::Expired,
        "the still-alive actor reports the terminal Expired state"
    );

    drop(handle);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), actor_task).await;
}

/// SEC-1ii (MUST FAIL pre-fix): an INCOMPLETE cleanup (a transient event-log
/// append failure) keeps the actor alive; a bounded retry re-runs ONLY the
/// failed step (carrying `prior_completed`) until the expiry is complete and
/// durable, and only THEN despawns. Pre-fix, `on_ttl_tick` discarded the
/// inner error and despawned on `Expired` after ONE attempt — the append
/// never succeeded (0 successful appends).
#[cfg(feature = "testing")]
#[tokio::test]
async fn incomplete_cleanup_keeps_actor_alive_and_retries() {
    use std::sync::atomic::Ordering;

    let recorder = RecordingPersistence::new();
    // `FlakyEventLog` is `Arc`-shared internally, so a clone handed to the
    // deps and the clone kept here observe the SAME counters.
    let flaky = FlakyEventLog::default();
    let deps = new_test_deps_with_providers(
        Box::new(recorder.clone()),
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider),
        Box::new(flaky.clone()),
    )
    .await;
    tokio::time::pause();

    let now = deps.clock.now_secs();
    let state = active_state_with_past_ttl(0x72, now);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    // First attempt fires immediately: transition Expired + fail-closed
    // persist land, but the event-log append fails ⇒ incomplete ⇒ retry
    // armed, actor stays alive.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        recorder.persisted.notified(),
    )
    .await
    .expect("first attempt persists the terminal state fail-closed");

    // Drive the bounded retry: it re-runs ONLY the failed event-log append
    // (transition + key destruction were carried in `prior_completed`), which
    // now succeeds ⇒ complete + durable ⇒ despawn. The handle is held across
    // this so the actor does NOT exit early via inbox-close (a dropped handle
    // makes `biased` Arm 1 `recv()→None→break` win over the retry arm); the
    // retry's own despawn is what ends the task.
    // The FIRST retry uses the base backoff (`ttl_expiry_retry_backoff(1)`).
    tokio::time::advance(ttl_expiry_retry_backoff(1) + std::time::Duration::from_secs(1)).await;

    // The actor despawns once the retry completes — its task joins.
    tokio::time::timeout(std::time::Duration::from_secs(2), actor_task)
        .await
        .expect("the actor task exits after a COMPLETE + durable expiry")
        .expect("actor task joins cleanly");
    drop(handle);

    assert_eq!(
        flaky.successes.load(Ordering::SeqCst),
        1,
        "the failed event-log append must be RETRIED to exactly one success \
             (SEC-1ii); pre-fix the actor despawned after the first failure (0 successes)"
    );
    assert_eq!(
        flaky.attempts.load(Ordering::SeqCst),
        2,
        "exactly two append attempts: the transient failure + the single retry \
             (retry re-runs ONLY the failed step)"
    );
}

/// B10 (MUST FAIL pre-fix): the FFI `ExecuteTtlClose` path must transition
/// and FAIL-CLOSED persist the ACTOR's OWN state to `Expired`. Pre-fix,
/// `handle_execute_ttl_close` built a THROWAWAY `ContextHandle`, transitioned
/// IT, and left the actor's real `cell.handle` (and persisted snapshot)
/// `Active`.
#[cfg(feature = "testing")]
#[tokio::test]
async fn execute_ttl_close_transitions_real_context_state() {
    let recorder = RecordingPersistence::new();
    let deps = new_test_deps_with_providers(
        Box::new(recorder.clone()),
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider),
        Box::new(TestEventLog),
    )
    .await;

    let ctx = hex_encode_context_id(&[0x74u8; 32]);
    let mut state = state::PerContextState::new_for_test_encrypted(
        [0x74u8; 32],
        TTL_TEST_CREATION_TS,
        scp_did::DID("did:example:sec1-admin".to_owned()),
    );
    // Finite params.ttl so the single-source `convergent_ttl_deadline`
    // (prune-immune snapshot `creation_timestamp_secs + ttl`) yields a real
    // deadline; otherwise `handle_ttl_expiry` ABORTS (A3) and the FFI
    // ExecuteTtlClose would no-op instead of transitioning to Expired.
    state.handle = scp_runtime_core::context::ContextHandle::new(
        ctx.clone(),
        scp_protocol::context::params::ContextParams {
            ttl: Some(std::time::Duration::from_hours(1)),
            ..Default::default()
        },
    );
    state
        .handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("transition to Active");

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    handle
        .send(|reply| {
            ContextCommand::TtlClose(
                scp_runtime_core::context::actor::commands::TtlCloseCommand::ExecuteTtlClose {
                    payload: Box::new(
                        scp_runtime_core::context::actor::commands::TtlContextPayload {
                            context_id: ctx.clone(),
                            params: scp_protocol::context::params::ContextParams::default(),
                        },
                    ),
                    reply,
                },
            )
        })
        .await
        .expect("ExecuteTtlClose replies Ok on the real handle");

    // The actor's REAL lifecycle state is now Expired (pre-fix: still Active,
    // because only a throwaway handle was transitioned).
    let live_state = handle
        .send(|reply| {
            ContextCommand::Queries(QueriesCommand::ReadContextState {
                context_id: ctx.clone(),
                reply,
            })
        })
        .await
        .expect("read the actor's real lifecycle state");
    assert_eq!(
        live_state,
        scp_protocol::context::ContextState::Expired,
        "ExecuteTtlClose must transition the ACTOR's real handle to Expired (B10)"
    );

    // ...and the fail-closed persist recorded that Expired state durably.
    let snap = recorder
        .last_snapshot()
        .expect("ExecuteTtlClose fail-closed persist recorded a snapshot");
    assert_eq!(
        snap.state,
        scp_protocol::context::ContextState::Expired,
        "ExecuteTtlClose must FAIL-CLOSED persist the actor's Expired state (B10 + SEC-1)"
    );

    handle.send_shutdown().await.expect("shutdown acks");
    actor_task.await.expect("actor task joins");
}

/// Persistence double that FAILS the FIRST fail-closed persist of a terminal
/// `Expired` snapshot, then succeeds — so a test can exercise the Phase-1
/// persist-failure branch of `handle_ttl_expiry` (L1). Non-`Expired`
/// persists (e.g. any coalesced pre-expiry write) always succeed, so the
/// injected failure targets exactly the terminal fail-closed persist.
#[cfg(feature = "testing")]
#[derive(Clone, Default)]
struct FailFirstExpiredPersist {
    expired_attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    first_fail_observed: std::sync::Arc<tokio::sync::Notify>,
    last:
        std::sync::Arc<arc_swap::ArcSwapOption<scp_runtime_core::context::state::ContextSnapshot>>,
}
#[cfg(feature = "testing")]
#[async_trait::async_trait]
impl scp_runtime_core::context::persistence::ContextPersistence for FailFirstExpiredPersist {
    async fn persist_context(
        &self,
        _context_id: &str,
        snapshot: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::sync::atomic::Ordering;
        if snapshot.state == scp_protocol::context::ContextState::Expired {
            let n = self.expired_attempts.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // The FIRST terminal Expired persist fails fail-closed.
                self.first_fail_observed.notify_one();
                return Err("fixture: first terminal Expired persist fails".into());
            }
        }
        self.last.store(Some(std::sync::Arc::new(snapshot.clone())));
        Ok(())
    }
    async fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.last.load_full().map(|s| (*s).clone()))
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
        Ok(self
            .last
            .load_full()
            .map(|s| vec![s.context_id.clone()])
            .unwrap_or_default())
    }
}

/// Event-log double that always succeeds and COUNTS `ContextExpired` append
/// attempts — the observable leaf whose gating L1 asserts.
#[cfg(feature = "testing")]
#[derive(Clone, Default)]
struct ContextExpiredAppendCounter {
    context_expired_appends: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
#[cfg(feature = "testing")]
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for ContextExpiredAppendCounter {
    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        event_type: scp_event_log::EventType,
        _actor: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        if event_type == scp_event_log::EventType::ContextExpired {
            self.context_expired_appends
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    // Seed a genesis leaf (realistic history); the deadline base comes from the
    // prune-immune snapshot so expiry proceeds (A3) rather than aborting — the
    // L1 gating under test is the persist→leaf ordering, not the derivation.
    fn event_log_entries(
        &self,
        _id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(Some(vec![ttl_seed_created_leaf()]))
    }
}

/// L1 (leaf append gated on the fail-closed persist succeeding): a Phase-1
/// terminal-`Expired` persist FAILURE must NOT append the observable
/// `ContextExpired` leaf that round — the leaf must announce only a DURABLE
/// terminal state. The actor stays alive (keep-direction) and the bounded
/// retry re-runs persist + append; once the persist succeeds the leaf appears
/// exactly once. Pre-fix, Phase 2 ran unconditionally, so the leaf was
/// appended ahead of the durable terminal snapshot.
#[cfg(feature = "testing")]
#[tokio::test]
async fn phase1_persist_failure_defers_leaf_append_until_durable() {
    use std::sync::atomic::Ordering;

    let persistence = FailFirstExpiredPersist::default();
    let counter = ContextExpiredAppendCounter::default();
    let deps = new_test_deps_with_providers(
        Box::new(persistence.clone()),
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider),
        Box::new(counter.clone()),
    )
    .await;
    tokio::time::pause();

    let now = deps.clock.now_secs();
    let state = active_state_with_past_ttl(0x77, now);

    let (tx, rx) = mpsc::channel::<ContextCommand>(4);
    let actor = ContextActor::new(state, deps, rx, handle::ExitRecord::default());
    let actor_task = tokio::spawn(actor.run());
    let handle = ContextActorHandle::from_sender(tx);

    // First attempt fires immediately: transition Expired + key destruction
    // land, but the fail-closed Expired persist FAILS ⇒ Phase 2 (leaf append)
    // is skipped this round ⇒ actor stays alive with a retry armed.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        persistence.first_fail_observed.notified(),
    )
    .await
    .expect("the first terminal Expired persist is attempted (and fails)");

    assert_eq!(
        counter.context_expired_appends.load(Ordering::SeqCst),
        0,
        "no ContextExpired leaf may be appended while the terminal Expired \
             persist is not durable (L1)"
    );

    // Drive the bounded retry: the persist now succeeds ⇒ Phase 2 runs ⇒ the
    // leaf appends (exactly once) ⇒ complete + durable ⇒ despawn.
    tokio::time::advance(ttl_expiry_retry_backoff(1) + std::time::Duration::from_secs(1)).await;

    tokio::time::timeout(std::time::Duration::from_secs(2), actor_task)
        .await
        .expect("the actor task exits after a COMPLETE + durable expiry")
        .expect("actor task joins cleanly");
    drop(handle);

    assert_eq!(
        counter.context_expired_appends.load(Ordering::SeqCst),
        1,
        "the ContextExpired leaf must appear EXACTLY ONCE, only after a retry \
             whose fail-closed persist succeeded (L1)"
    );
    assert!(
        persistence.expired_attempts.load(Ordering::SeqCst) >= 2,
        "the terminal Expired persist must have been retried after its first \
             failure (L1)"
    );
}
