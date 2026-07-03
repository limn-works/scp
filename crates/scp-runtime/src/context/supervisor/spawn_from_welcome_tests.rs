//! Tests for [`Supervisor::spawn_actor_from_welcome`] (ADR-049 Phase 2J,
//! spawn-from-Welcome; Deferred Work #1).
//!
//! These exercise the REAL end-to-end join path — the joiner reserves a
//! `KeyPackage` from its own `KeyPackageStoreActor`, a creator adds that KP and
//! emits a Welcome, and the joiner spawns a per-context actor from that Welcome
//! through the fused `ConfirmConsume` → `install_joined_group` →
//! persist-before-ack → spawn ladder. The pre-2J gap (a Welcome-joined node
//! could DECRYPT but had no actor-backed send `ContextHandle`, so any send
//! failed closed with "context not found in node's handles") is closed here:
//! after `spawn_actor_from_welcome` the joiner is a registered, send-capable
//! participant (`member_count` returns `Some`, not the unregistered `None`),
//! its installed MLS group processes creator traffic AND encrypts joiner
//! traffic the creator decrypts, and the initial keyed snapshot is persisted
//! fail-closed BEFORE the actor is reachable (a persist failure leaves NO live
//! half-keyed actor — Decision 1/8/9).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// `spawn_actor_from_welcome` returns a deliberately large state-building future
// (~16 KB — the Welcome-derived `PerContextState`); production callers `Box::pin`
// it at the `SupervisorHandle` seam. These tests await it directly, so allow the
// large-future lint module-wide rather than box every call site.
#![allow(clippy::large_futures)]
// The `FailingPersistence` double is stateless; the `RecordingPersistence` double
// (durable first-writer-wins test) backs its in-memory store with a lock-free
// `DashMap`/`DashSet` (matching the `CapturingPersistence` pattern), so it needs
// no `Mutex` and holds no guard across an `.await`.

use std::sync::Arc;

use scp_did::{DID, SigningKeyId};
use scp_platform::testing::InMemoryStorage;
use scp_protocol::context::builder::OpenResult;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::roles::Capability;
use scp_protocol::context::{ContextMode, ContextParams};

use super::key_package_actor::KeyPackageCommand;
use super::{Supervisor, WelcomeJoinRequest};
use crate::context::builder::{
    ContextEventLogProvider, ContextTransportProvider, NotConfiguredTransportProvider,
};
use crate::context::persistence::ContextPersistence;
use crate::context::providers::event_log::MerkleEventLogProvider;
use crate::context::state::context_id_to_bytes;
use crate::crypto::mls::provider::MlsCryptoProvider;
use crate::crypto::mls::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};

const ALICE_DID: &str = "did:dht:z6MkAliceSpawnFromWelcomeCreator";
const BOB_DID: &str = "did:dht:z6MkBobSpawnFromWelcomeJoiner";

/// A trivial key resolver — the default `SingleAdmin` governance model needs no
/// signer keys to build, so an always-`None` resolver suffices.
fn trivial_resolver() -> KeyResolver {
    Arc::new(|_: &DID, _: SigningKeyId| None)
}

/// A 64-hex canonical context id (ADR-056 decodes it to its 32-byte digest).
fn ctx_hex(seed: u8) -> String {
    let byte = format!("{seed:02x}");
    byte.repeat(32)
}

/// A REAL §9.10.4 local pseudonym (a distinctive non-`[0u8; 32]` constant). The
/// spawn-from-Welcome entrypoint rejects `None` for the encrypted join surface
/// (BLACK-2J-04), so every valid join fixture must supply one. Returns the
/// `Option` shape the request field / create path take directly.
#[allow(clippy::unnecessary_wraps)]
fn some_pseudonym() -> Option<[u8; 32]> {
    Some([0x5a; 32])
}

/// The joiner's legible context parameters (encrypted, single-admin).
fn joiner_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ],
        ..ContextParams::default()
    }
}

fn fresh_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )))
}

/// Builds Bob's real joiner `Supervisor` (real MLS crypto, not-configured
/// transport, in-memory event log + MLS storage). Returns the supervisor and a
/// clone of Bob's crypto provider (so a test can assert on the installed group).
///
/// `persistence` is threaded straight through: pass `None` for the happy path
/// (a `NoopContextPersistence` default that always succeeds) or a failing
/// double for the crash-safety test.
fn bob_supervisor(
    persistence: Option<Box<dyn ContextPersistence>>,
) -> (Arc<Supervisor>, Arc<MlsCryptoProvider>) {
    let crypto = Arc::new(MlsCryptoProvider::new(BOB_DID.to_owned()));
    let transport: Box<dyn ContextTransportProvider> = Box::new(NotConfiguredTransportProvider);
    let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
    let sup = Supervisor::with_providers(
        Arc::clone(&crypto),
        transport,
        event_log,
        trivial_resolver(),
        persistence,
        None,
        None,
        None,
        fresh_mls_storage(),
    );
    (sup, crypto)
}

/// Reserves one `KeyPackage` from Bob's own `KeyPackageStoreActor` and returns the
/// `(reservation_id, public_kp_bytes)` pair. The store's startup replenish fills
/// the pool before any command is served; the extra explicit `Replenish` is a
/// deterministic barrier (not a sleep) proving the pool is non-empty.
async fn reserve_bob_kp(
    sup: &Arc<Supervisor>,
    bob: &DID,
) -> (super::key_package_actor::ReservationId, Vec<u8>) {
    let store = sup
        .key_package_store_for(bob)
        .await
        .expect("bob's key-package store spawns");
    store
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("replenish barrier");
    let pooled = store
        .send(|reply| KeyPackageCommand::ListPooled { reply })
        .await
        .expect("list pooled KPs");
    let (kp_ref, _public) = pooled
        .into_iter()
        .next()
        .expect("the auto-replenished pool holds at least one KP");
    store
        .send(|reply| KeyPackageCommand::Reserve { kp_ref, reply })
        .await
        .expect("reserve a pooled KP for join")
}

/// The joiner-side outcome of the shared bootstrap: everything a test needs to
/// assert on the spawned joiner and drive MLS traffic through its group.
struct Joined {
    sup: Arc<Supervisor>,
    bob_crypto: Arc<MlsCryptoProvider>,
    alice_crypto: Arc<MlsCryptoProvider>,
    ctx_id: String,
    ctx_bytes: [u8; 32],
}

/// Runs the full reserve → creator-add → Welcome → `spawn_actor_from_welcome`
/// ladder against a Bob supervisor built with `persistence`, returning the spawn
/// result plus the pieces needed to assert on it. The Welcome is produced by a
/// bare creator provider (Alice) adding Bob's RESERVED KP — the same bytes Bob's
/// store holds the private signer-state for, so the fused `ConfirmConsume` join
/// matches.
async fn join_bob(
    seed: u8,
    persistence: Option<Box<dyn ContextPersistence>>,
) -> (
    Result<crate::context::ContextHandle, crate::context::ContextError>,
    Joined,
) {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(seed);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(persistence);

    // Bob reserves a real KP from his own store (private signer-state stays in
    // the actor; only the reservation id + public bytes come back).
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;

    // Alice (bare creator provider) creates the group and adds Bob's reserved
    // KP, producing the real Welcome addressed to that KP's init key.
    let alice_crypto = Arc::new(MlsCryptoProvider::new(ALICE_DID.to_owned()));
    alice_crypto
        .create_mls_group(&ctx_bytes)
        .expect("alice creates the MLS group");
    let add_output = alice_crypto
        .add_member(&ctx_bytes, BOB_DID, Some(&kp_public_bytes))
        .expect("alice adds bob's reserved key package");

    let req = WelcomeJoinRequest {
        creator_did: DID::from(ALICE_DID),
        context_id: ctx_id.clone(),
        params: joiner_params(),
        reservation_id,
        welcome_bytes: add_output.welcome_bytes,
        local_pseudonym: some_pseudonym(),
    };

    let result = sup.spawn_actor_from_welcome(bob, req).await;
    (
        result,
        Joined {
            sup,
            bob_crypto,
            alice_crypto,
            ctx_id,
            ctx_bytes,
        },
    )
}

// ---------------------------------------------------------------------------
// Test A — joiner-spawn happy path (Deferred Work #1 landing signal).
// ---------------------------------------------------------------------------

/// A Welcome-joined node becomes a LIVE, send-capable participant: the spawn
/// registers a context actor whose mailbox serves queries (`member_count`
/// returns `Some`, the exact discriminator against the pre-2J unregistered
/// `None`), the joiner is a `member` and the creator the `admin`, and the joined
/// MLS group is installed in the provider.
///
/// # Event-log wiring (test-quality AC1)
///
/// The joiner's event-log provider is WIRED (the supervisor's shared
/// `MerkleEventLogProvider` is reachable for the spawned context, i.e.
/// `event_log_entries` answers `Ok`, not `Err(NotInitialized)`). The joiner
/// entrypoint appends NO local join event — `MemberJoined` is a creator-side
/// leaf — so the joiner-local log legitimately starts EMPTY and CONVERGES via
/// cross-member event-log leaf replication (the follow-on that Phase 2J
/// unblocks). This test therefore asserts the provider is wired AND that the
/// joiner-local log is absent/empty, not a joiner-local entry that the spec does
/// not have this entrypoint emit.
#[tokio::test]
async fn spawn_from_welcome_yields_a_live_send_capable_actor() {
    let (result, j) = join_bob(0x11, None).await;
    let handle = result.expect("spawn_actor_from_welcome succeeds on a valid Welcome");
    assert_eq!(handle.context_id(), j.ctx_id);

    // The live-actor discriminator: an UNREGISTERED context yields `None`
    // (the pre-2J joiner had no actor at all); a live registered actor answers
    // its membership through the mailbox. This is the working send-handle proof.
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        Some(2),
        "the joiner's actor is registered and serves its mailbox (send handle live)"
    );
    assert!(
        j.sup.lookup(&j.ctx_id).is_some(),
        "a context actor handle is registered for the joiner"
    );

    let members = j.sup.member_dids(&j.ctx_id).await;
    assert!(
        members.contains(&ALICE_DID.to_owned()),
        "the creator is tracked as a member (admin)"
    );
    assert!(
        members.contains(&BOB_DID.to_owned()),
        "the joiner is tracked as a member"
    );

    // The joined MLS group is resident in the joiner's crypto provider.
    // `export_crypto_state` returns a NON-EMPTY serialized snapshot for an
    // installed group and an EMPTY vec when the context is absent, so the
    // non-emptiness is the presence discriminator.
    assert!(
        !j.bob_crypto
            .export_crypto_state(&j.ctx_bytes)
            .expect("export never errors")
            .is_empty(),
        "the joined MLS group is installed in the provider"
    );

    // Event-log provider WIRED (AC1) AND joiner-local log EMPTY: the spawned
    // context resolves against the supervisor's shared event-log provider (an
    // unwired supervisor answers `Err(NotInitialized)`, so `.expect` catches an
    // unwired provider), and the joiner appends NO local join leaf — the log is
    // absent/empty here and converges via cross-member event-log leaf
    // replication. `event_log_entries` returns `None` for an untouched context,
    // so `is_none_or(is_empty)` is the accurate "no local leaf" shape; a
    // regression that starts emitting a spurious local join event fails it.
    assert!(
        j.sup
            .event_log_entries(&j.ctx_bytes)
            .expect("event-log provider is wired")
            .is_none_or(|v| v.is_empty()),
        "joiner emits no local join leaf; the log converges via cross-member \
         event-log leaf replication"
    );
}

// ---------------------------------------------------------------------------
// Test A2 — the joiner seeds its ABSOLUTE MLS epoch from the joined group.
// ---------------------------------------------------------------------------

/// The joiner's `EpochState.mls_epoch` is the REAL absolute epoch of the group
/// it joined — NOT a `0` placeholder. In the fixture the creator builds the
/// group at epoch 0, then adds the joiner via a Commit that advances it to
/// epoch 1; the Welcome is FOR epoch 1, so the joiner must come up at epoch 1.
/// A wrong seed (the old `0`, or any other value) would stamp the wrong epoch
/// into checkpoints (§9.9.3), recovery envelopes, and governance events.
///
/// Non-vacuity: `local_mls_epoch` returns `Some(state.epoch.mls_epoch)`, so the
/// `Some(1)` assertion fails under both the pre-fix `mls_epoch: 0` seed and any
/// mutated constant (`999`) — it pins the read-the-joined-group-epoch behavior.
#[tokio::test]
async fn spawn_from_welcome_seeds_the_real_joined_group_epoch() {
    let (result, j) = join_bob(0x55, None).await;
    result.expect("spawn_actor_from_welcome succeeds");

    assert_eq!(
        j.sup.local_mls_epoch(&j.ctx_id).await,
        Some(1),
        "the joiner comes up at the joined group's real absolute epoch (1), not a \
         0 placeholder"
    );
}

// ---------------------------------------------------------------------------
// Test B — bidirectional MLS round-trip through the entrypoint-installed group.
// ---------------------------------------------------------------------------

/// The entrypoint-installed group is BIDIRECTIONALLY functional: the creator
/// encrypts a management message the joiner decrypts (creator → joiner), and the
/// joiner encrypts a management message the creator decrypts (joiner → creator).
/// The joiner-send direction is the landing signal — pre-2J the joiner had no
/// send handle at all; here its group produces valid ciphertext the creator
/// opens, and its actor is registered (`member_count` is `Some`).
#[tokio::test]
async fn spawn_from_welcome_group_round_trips_both_directions() {
    let (result, j) = join_bob(0x22, None).await;
    result.expect("spawn_actor_from_welcome succeeds");

    let routing_id = scp_protocol::context::context_routing_id(&hex::encode(j.ctx_bytes));

    // Creator -> joiner: Alice encrypts, Bob's installed group decrypts.
    let from_alice = b"management-payload-from-alice";
    let wrapped_alice = j
        .alice_crypto
        .mls_encrypt_management(&j.ctx_bytes, from_alice, &routing_id, 3600)
        .expect("alice encrypts a management message");
    let opened_alice = j
        .bob_crypto
        .open(&j.ctx_bytes, &j.ctx_id, &wrapped_alice)
        .expect("bob opens alice's message");
    assert!(
        matches!(
            &opened_alice,
            OpenResult::Management { payload, .. } if payload.as_slice() == from_alice.as_slice()
        ),
        "joiner decrypts creator traffic through the installed group; \
         expected Management({from_alice:?}), got {opened_alice:?}"
    );

    // Joiner -> creator: Bob encrypts through his installed group, Alice decrypts.
    // Pre-2J this direction was impossible (the joiner had no send-capable group
    // wired into an actor). Both the actor handle AND the group now exist.
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        Some(2),
        "joiner send handle is live"
    );
    let from_bob = b"management-payload-from-bob";
    let wrapped_bob = j
        .bob_crypto
        .mls_encrypt_management(&j.ctx_bytes, from_bob, &routing_id, 3600)
        .expect("bob encrypts a management message through the joined group");
    let opened_bob = j
        .alice_crypto
        .open(&j.ctx_bytes, &j.ctx_id, &wrapped_bob)
        .expect("alice opens bob's message");
    assert!(
        matches!(
            &opened_bob,
            OpenResult::Management { payload, .. } if payload.as_slice() == from_bob.as_slice()
        ),
        "creator decrypts joiner traffic — bidirectional round-trip closed; \
         expected Management({from_bob:?}), got {opened_bob:?}"
    );
}

// ---------------------------------------------------------------------------
// Test C — key-injection crash-safety (Decision 1/8/9), non-vacuous.
// ---------------------------------------------------------------------------

/// A failing persistence double: `persist_context` always errors, every other
/// method is a benign success. Models a crash/storage-fault at the fail-closed
/// snapshot write BETWEEN key-injection and durable persist.
struct FailingPersistence;

impl ContextPersistence for FailingPersistence {
    fn persist_context(
        &self,
        _context_id: &str,
        _snapshot: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("induced persist failure at the fail-closed snapshot write".into())
    }
    fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn delete_context(
        &self,
        _context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

/// When the fail-closed initial-snapshot persist fails, the spawn returns
/// `Err(PersistenceFailed)` and leaves NO live half-keyed actor: the just-
/// installed group is torn back out of the provider and no actor handle is
/// registered. A respawn therefore finds a fully-keyed snapshot OR none — never
/// a half-keyed actor that can decrypt but has no durable key state.
///
/// # Non-vacuity (mutation argument)
///
/// The persist here happens BEFORE the spawn is acked and the group is rolled
/// back on failure. If the entrypoint were mutated to persist best-effort
/// (swallow the error) or to persist AFTER `spawn_actor_with_state`, then on
/// this induced failure the group would REMAIN installed (`with_context` would
/// be `Ok`) and the actor WOULD be registered (`member_count` would be `Some`).
/// Both assertions below would then fail — so the test is non-vacuous with
/// respect to the persist-before-ack + fail-closed-rollback ordering.
#[tokio::test]
async fn persist_failure_leaves_no_half_keyed_actor() {
    let (result, j) = join_bob(0x33, Some(Box::new(FailingPersistence))).await;

    let err = result.expect_err("a fail-closed persist failure rejects the spawn");
    assert!(
        matches!(err, crate::context::ContextError::PersistenceFailed(_)),
        "expected PersistenceFailed, got {err:?}"
    );

    // The installed group was rolled back — no half-keyed crypto is resident.
    // (An absent context exports an EMPTY snapshot; an installed one is
    // non-empty — see the happy-path test.)
    assert!(
        j.bob_crypto
            .export_crypto_state(&j.ctx_bytes)
            .expect("export never errors")
            .is_empty(),
        "the just-installed group must be torn back out on a persist failure"
    );

    // No live actor is registered — the context is unreachable, not half-keyed.
    assert!(
        j.sup.lookup(&j.ctx_id).is_none(),
        "no actor handle may be registered after a fail-closed rejection"
    );
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        None,
        "an unregistered context answers the unregistered default, not a live count"
    );
}

// ---------------------------------------------------------------------------
// Test D — single-use holds across the entrypoint (two-anchor backstop).
// ---------------------------------------------------------------------------

/// A second spawn reusing the SAME reservation (its `KeyPackage` already durably
/// consumed by the first successful join) is rejected by the reservation-journal
/// anchor — the fused `ConfirmConsume` finds no live reservation and replies a
/// typed error. Single-use is preserved: the first live actor is untouched and a
/// replayed Welcome can NOT stand up a second context.
///
/// The replay targets a DIFFERENT context id from the first join, so the
/// up-front actor-registry precheck (Fix 1a) does NOT short-circuit it — the
/// replay reaches the `ConfirmConsume` reservation-journal anchor, which is the
/// single-use property this test exercises. (The same-id replay is covered by
/// the collision precheck test; here we prove the journal anchor holds even for
/// a fresh context id.)
#[tokio::test]
async fn second_spawn_reusing_a_consumed_reservation_is_rejected() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x44);
    let ctx_bytes = context_id_to_bytes(&ctx_id);
    // A distinct id for the replay so it clears the up-front registry precheck
    // and actually hits the reservation-journal anchor.
    let replay_ctx_id = ctx_hex(0x4a);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;

    let alice_crypto = Arc::new(MlsCryptoProvider::new(ALICE_DID.to_owned()));
    alice_crypto.create_mls_group(&ctx_bytes).unwrap();
    let add_output = alice_crypto
        .add_member(&ctx_bytes, BOB_DID, Some(&kp_public_bytes))
        .unwrap();
    let welcome = add_output.welcome_bytes;

    let make_req = |context_id: String, welcome_bytes: Vec<u8>| WelcomeJoinRequest {
        creator_did: DID::from(ALICE_DID),
        context_id,
        params: joiner_params(),
        reservation_id: reservation_id.clone(),
        welcome_bytes,
        local_pseudonym: some_pseudonym(),
    };

    // First join succeeds and consumes the reservation's single-use KP.
    sup.spawn_actor_from_welcome(bob.clone(), make_req(ctx_id.clone(), welcome.clone()))
        .await
        .expect("first spawn-from-Welcome succeeds");
    assert_eq!(sup.member_count(&ctx_id).await, Some(2));

    // Second spawn (fresh context id) reusing the SAME (now-consumed) reservation
    // is rejected at the fused ConfirmConsume — the reservation journal no longer
    // holds it.
    let replay = sup
        .spawn_actor_from_welcome(bob, make_req(replay_ctx_id.clone(), welcome))
        .await
        .expect_err("a consumed reservation must not spawn a second actor");
    assert!(
        matches!(replay, crate::context::ContextError::InvalidState(_)),
        "expected InvalidState for a consumed reservation, got {replay:?}"
    );
    assert!(
        sup.lookup(&replay_ctx_id).is_none(),
        "the replay to a fresh context id must not stand up an actor"
    );

    // The first live actor and its group are untouched by the rejected replay.
    assert_eq!(
        sup.member_count(&ctx_id).await,
        Some(2),
        "the first join's live actor survives the rejected replay"
    );
    assert!(
        !bob_crypto
            .export_crypto_state(&ctx_bytes)
            .expect("export never errors")
            .is_empty(),
        "the first join's installed group is intact"
    );
}

// ---------------------------------------------------------------------------
// Shared setup for the reversible-precheck tests (Fix 1a / Fix 6).
// ---------------------------------------------------------------------------

/// Alice (a bare creator provider) creates the group under `ctx_bytes` and adds
/// Bob's RESERVED public KP, returning `(alice_crypto, welcome_bytes)`.
fn alice_welcome_for(
    ctx_bytes: &[u8; 32],
    kp_public_bytes: &[u8],
) -> (Arc<MlsCryptoProvider>, Vec<u8>) {
    let alice_crypto = Arc::new(MlsCryptoProvider::new(ALICE_DID.to_owned()));
    alice_crypto
        .create_mls_group(ctx_bytes)
        .expect("alice creates the MLS group");
    let add_output = alice_crypto
        .add_member(ctx_bytes, BOB_DID, Some(kp_public_bytes))
        .expect("alice adds bob's reserved key package");
    (alice_crypto, add_output.welcome_bytes)
}

// ---------------------------------------------------------------------------
// Test E — a missing local pseudonym is rejected BEFORE the KP consume (Fix 6).
// ---------------------------------------------------------------------------

/// spawn-from-Welcome always stands up an ENCRYPTED context, so a `None`
/// `local_pseudonym` must be rejected (no silent `[0u8; 32]` sentinel — a
/// linkable constant). The reject is a REVERSIBLE precheck: it fires BEFORE the
/// irreversible `ConfirmConsume`, so the single-use `KeyPackage` is NOT burned.
///
/// Non-vacuity: the SAME reservation + Welcome, retried with a REAL pseudonym,
/// then succeeds — proving the rejected attempt neither consumed the KP nor
/// stood up any context.
#[tokio::test]
async fn missing_pseudonym_is_rejected_before_the_kp_consume() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x66);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_bytes, &kp_public_bytes);

    let make_req = |pseudonym: Option<[u8; 32]>| WelcomeJoinRequest {
        creator_did: DID::from(ALICE_DID),
        context_id: ctx_id.clone(),
        params: joiner_params(),
        reservation_id: reservation_id.clone(),
        welcome_bytes: welcome.clone(),
        local_pseudonym: pseudonym,
    };

    // `None` is rejected up front (CreationFailed), no context stands up.
    let err = sup
        .spawn_actor_from_welcome(bob.clone(), make_req(None))
        .await
        .expect_err("a None pseudonym must be rejected on the encrypted join surface");
    assert!(
        matches!(err, crate::context::ContextError::CreationFailed(_)),
        "expected CreationFailed for a missing pseudonym, got {err:?}"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a pseudonym rejection"
    );
    assert!(
        bob_crypto
            .export_crypto_state(&ctx_bytes)
            .expect("export never errors")
            .is_empty(),
        "no group may be installed after a pseudonym rejection"
    );

    // KP NOT burned: the same reservation + Welcome now succeed WITH a real
    // pseudonym — the reject happened before `ConfirmConsume`.
    sup.spawn_actor_from_welcome(bob, make_req(some_pseudonym()))
        .await
        .expect("the retry with a real pseudonym succeeds — the KP was never burned");
    assert_eq!(
        sup.member_count(&ctx_id).await,
        Some(2),
        "the retry stands up the live joiner actor"
    );
}

// ---------------------------------------------------------------------------
// Test F — a colliding context id is rejected UP FRONT, before the KP consume
// (Fix 1a — broadcast split-registry clobber). BLACK-2J-01.
// ---------------------------------------------------------------------------

/// A join whose `context_id` collides with an EXISTING broadcast context is
/// rejected by the up-front actor-registry check, BEFORE the irreversible
/// `ConfirmConsume`. This is the split-registry case the step-2
/// `install_joined_group` Vacant guard alone would MISS: a broadcast context's
/// crypto lives in `broadcast_keys`, so the `contexts` map slot the install
/// guard checks is VACANT — only the registry check catches the collision.
///
/// The test proves all three: (1) the join is rejected (`CreationFailed`), (2) the
/// broadcast context SURVIVES intact (still registered, its snapshot never
/// clobbered), and (3) the single-use `KeyPackage` is NOT burned (a join to a
/// fresh, non-colliding context id reusing the SAME reservation + Welcome then
/// succeeds).
#[tokio::test]
async fn colliding_broadcast_context_id_is_rejected_before_the_kp_consume() {
    let bob = DID::from(BOB_DID);
    let collide_id = ctx_hex(0x77);
    let collide_bytes = context_id_to_bytes(&collide_id);

    let (sup, bob_crypto) = bob_supervisor(None);

    // Bob pre-creates a BROADCAST context under `collide_id`: this registers an
    // actor (so `lookup` is `Some`) while the encrypted `contexts` crypto slot
    // stays VACANT (broadcast keys live in `broadcast_keys`).
    let broadcast_params = ContextParams {
        mode: ContextMode::Broadcast,
        // Broadcast contexts only support `MemoryScope::Full`.
        memory_scope: scp_protocol::context::params::MemoryScope::Full,
        ..ContextParams::default()
    };
    sup.create_context(
        collide_id.clone(),
        broadcast_params,
        bob.clone(),
        some_pseudonym(),
    )
    .await
    .expect("bob creates the colliding broadcast context");
    assert!(
        sup.lookup(&collide_id).is_some(),
        "the broadcast context registered an actor"
    );
    assert!(
        bob_crypto
            .export_crypto_state(&collide_bytes)
            .expect("export never errors")
            .is_empty(),
        "the broadcast context's ENCRYPTED crypto slot is vacant (split registry) \
         — the install Vacant guard alone could not catch this collision"
    );

    // Bob reserves a KP; Alice builds a Welcome addressed to it for `collide_id`.
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&collide_bytes, &kp_public_bytes);

    // The colliding join is rejected UP FRONT — before the consume.
    let colliding_req = WelcomeJoinRequest {
        creator_did: DID::from(ALICE_DID),
        context_id: collide_id.clone(),
        params: joiner_params(),
        reservation_id: reservation_id.clone(),
        welcome_bytes: welcome.clone(),
        local_pseudonym: some_pseudonym(),
    };
    let err = sup
        .spawn_actor_from_welcome(bob.clone(), colliding_req)
        .await
        .expect_err("a join colliding with a live context id must be rejected");
    assert!(
        matches!(err, crate::context::ContextError::CreationFailed(_)),
        "expected CreationFailed for a colliding context id, got {err:?}"
    );

    // The broadcast context SURVIVES intact — not clobbered.
    assert!(
        sup.lookup(&collide_id).is_some(),
        "the pre-existing broadcast context survives the rejected colliding join"
    );
    assert_eq!(
        sup.local_mls_epoch(&collide_id).await,
        None,
        "the survivor is still the broadcast context (broadcast reports no MLS epoch)"
    );

    // KP NOT burned: the same reservation + Welcome now stand up a join to a
    // FRESH, non-colliding context id — proving the collision reject happened
    // before `ConfirmConsume`.
    let fresh_id = ctx_hex(0x78);
    let fresh_req = WelcomeJoinRequest {
        creator_did: DID::from(ALICE_DID),
        context_id: fresh_id.clone(),
        params: joiner_params(),
        reservation_id,
        welcome_bytes: welcome,
        local_pseudonym: some_pseudonym(),
    };
    sup.spawn_actor_from_welcome(bob, fresh_req)
        .await
        .expect("the fresh-id retry succeeds — the KP was never burned by the collision");
    assert_eq!(
        sup.member_count(&fresh_id).await,
        Some(2),
        "the fresh-id join stands up a live joiner actor"
    );
}

// ---------------------------------------------------------------------------
// Test G — the entrypoint-level crypto fail-closed predicate (Fix 4).
// ---------------------------------------------------------------------------

/// The spawn-from-Welcome entrypoint gates on
/// [`welcome_snapshot_crypto_is_durable`] AFTER the fail-closed persist: an
/// EMPTY or ERRORED crypto export (which `build_snapshot_for_persist` would turn
/// into a keyless `needs_reconnect` snapshot that persists SUCCESSFULLY) is
/// fatal for a JOINER, which cannot reconnect-derive.
///
/// The concrete `MlsCryptoProvider` always returns a NON-EMPTY export for a
/// just-installed group, so the export-failure branch cannot be induced through
/// the full entrypoint with the real provider (install guarantees a live group).
/// This unit test therefore pins the fail-closed DECISION directly on the pure
/// predicate: an empty blob and an errored export both read as NOT durable
/// (→ the entrypoint rolls back + fails closed), while a populated blob reads as
/// durable (→ the spawn proceeds). Mutating the predicate to a constant `true`
/// (fail-open) fails the first two assertions.
#[test]
fn welcome_snapshot_crypto_durability_predicate_fails_closed_on_empty_or_error() {
    use crate::context::messaging_helpers::welcome_snapshot_crypto_is_durable;

    // A populated crypto blob is durable — the spawn may proceed.
    assert!(
        welcome_snapshot_crypto_is_durable(&Ok(vec![0x01, 0x02, 0x03])),
        "a non-empty crypto export is durable"
    );
    // An EMPTY blob is the keyless-snapshot signal — NOT durable, fail closed.
    assert!(
        !welcome_snapshot_crypto_is_durable(&Ok(Vec::new())),
        "an empty crypto export must fail closed (a joiner cannot reconnect-derive)"
    );
    // An ERRORED export is likewise not durable — fail closed.
    assert!(
        !welcome_snapshot_crypto_is_durable(&Err(crate::context::ContextError::CryptoFailed(
            "induced export failure".to_owned()
        ))),
        "an errored crypto export must fail closed"
    );
}

// ---------------------------------------------------------------------------
// Test H — the crypto-durability fail-closed branch, driven END-TO-END (Item B).
// ---------------------------------------------------------------------------

/// The entrypoint's crypto-durability gate (step 3b) fails the spawn CLOSED when
/// the joined group produces a non-durable crypto export — WITHOUT persisting a
/// keyless snapshot and WITHOUT standing up an actor. The real `MlsCryptoProvider`
/// always exports a non-empty blob for a just-installed group, so this branch is
/// otherwise unreachable through the full entrypoint; a one-shot test seam
/// (`arm_export_failure_once`) forces the NEXT export to fail so the WIRING —
/// predicate on the live export → on non-durable, roll back (destroy) + `Err`,
/// never spawn — is exercised, not just the pure predicate (Test G).
///
/// The seam fires at the step-3b durability read (the first export call, BEFORE
/// the persist), so the rollback path runs with nothing persisted. Post-rollback
/// the seam has cleared and the destroyed group exports empty.
#[tokio::test]
async fn non_durable_crypto_export_fails_closed_without_standing_up_an_actor() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x9a);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_bytes, &kp_public_bytes);

    // Arm the one-shot seam: the step-3b durability check reads the live export
    // FIRST, so the seam fires there → the export reads non-durable.
    bob_crypto.arm_export_failure_once();

    let err = sup
        .spawn_actor_from_welcome(
            bob,
            WelcomeJoinRequest {
                creator_did: DID::from(ALICE_DID),
                context_id: ctx_id.clone(),
                params: joiner_params(),
                reservation_id,
                welcome_bytes: welcome,
                local_pseudonym: some_pseudonym(),
            },
        )
        .await
        .expect_err("a non-durable crypto export must fail the spawn closed");
    assert!(
        matches!(err, crate::context::ContextError::PersistenceFailed(_)),
        "expected PersistenceFailed for a non-durable export, got {err:?}"
    );

    // Rollback fired: the just-installed group was destroyed. The one-shot seam
    // has cleared, so this export reads normally → empty for the now-absent group.
    assert!(
        bob_crypto
            .export_crypto_state(&ctx_bytes)
            .expect("export never errors once the one-shot seam has cleared")
            .is_empty(),
        "the installed group must be rolled back on a non-durable export"
    );
    // No actor registered — the keyless joiner never became reachable, and the
    // fail-closed branch ran BEFORE the persist (nothing durable to resurrect).
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a fail-closed non-durable export"
    );
    assert_eq!(
        sup.member_count(&ctx_id).await,
        None,
        "an unregistered context answers the unregistered default, not a live count"
    );
}

// ---------------------------------------------------------------------------
// Test I — durable first-writer-wins (BLACK-2J-06): a persisted-but-UNSPAWNED
// same-id snapshot rejects the join without clobbering it or burning the KP.
// ---------------------------------------------------------------------------

/// A recording persistence double: stores what it persists, returns it on load,
/// and records deletes. `Arc`-shared so a test can seed ONE supervisor's real
/// snapshot and then read it back through a SECOND, independent supervisor that
/// shares the store but has NO live actor for the id — the exact
/// persisted-but-unspawned window Precheck A (`lookup`, live registry only)
/// cannot see and durable Precheck D must catch.
#[derive(Clone, Default)]
struct RecordingPersistence {
    store: Arc<dashmap::DashMap<String, crate::context::state::ContextSnapshot>>,
    deletes: Arc<dashmap::DashSet<String>>,
}

impl ContextPersistence for RecordingPersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store.insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }
    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.store.get(context_id).map(|e| e.value().clone()))
    }
    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.deletes.insert(context_id.to_owned());
        self.store.remove(context_id);
        Ok(())
    }
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store.iter().map(|e| e.key().clone()).collect())
    }
}

/// spawn-from-Welcome is the FIRST join for a NEW context, so an EXISTING durable
/// snapshot for the same id means either a griefing victim or the joiner's own
/// stale/prior context — which must be recovered via restore/reconnect, not
/// re-joined. The join is rejected by the durable first-writer-wins precheck
/// (Precheck D), which — unlike the live-registry Precheck A — sees a
/// persisted-but-unspawned snapshot. The victim snapshot is NOT clobbered or
/// deleted, and because the reject fires BEFORE `ConfirmConsume`, the single-use
/// `KeyPackage` is NOT burned (a retry after the snapshot is cleared succeeds).
#[tokio::test]
async fn durable_snapshot_collision_is_rejected_without_clobbering_or_burning_kp() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x99);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let rec = RecordingPersistence::default();

    // --- Seed: a first supervisor persists a REAL snapshot for `ctx_id` via a
    //     successful join. It shares the recording store; the spawn persists the
    //     joiner's initial Class-S snapshot under `ctx_id`.
    let (seed_sup, _seed_crypto) = bob_supervisor(Some(Box::new(rec.clone())));
    let (seed_res, seed_kp) = reserve_bob_kp(&seed_sup, &bob).await;
    let (_seed_alice, seed_welcome) = alice_welcome_for(&ctx_bytes, &seed_kp);
    seed_sup
        .spawn_actor_from_welcome(
            bob.clone(),
            WelcomeJoinRequest {
                creator_did: DID::from(ALICE_DID),
                context_id: ctx_id.clone(),
                params: joiner_params(),
                reservation_id: seed_res,
                welcome_bytes: seed_welcome,
                local_pseudonym: some_pseudonym(),
            },
        )
        .await
        .expect("the seed join persists a real snapshot for ctx_id");
    let seeded = rec
        .store
        .get(&ctx_id)
        .map(|e| e.value().clone())
        .expect("the seed join persisted a snapshot for ctx_id");

    // --- Target: a SECOND, independent supervisor sharing the SAME store. It has
    //     NO live actor for `ctx_id`, so Precheck A `lookup` misses and only the
    //     durable Precheck D can catch the collision.
    let (target_sup, target_crypto) = bob_supervisor(Some(Box::new(rec.clone())));
    assert!(
        target_sup.lookup(&ctx_id).is_none(),
        "the target supervisor has no live actor for the id (only durable state exists)"
    );

    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&target_sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_bytes, &kp_public_bytes);
    let make_req =
        |context_id: String, reservation_id, welcome_bytes: Vec<u8>| WelcomeJoinRequest {
            creator_did: DID::from(ALICE_DID),
            context_id,
            params: joiner_params(),
            reservation_id,
            welcome_bytes,
            local_pseudonym: some_pseudonym(),
        };

    let err = target_sup
        .spawn_actor_from_welcome(
            bob.clone(),
            make_req(ctx_id.clone(), reservation_id.clone(), welcome.clone()),
        )
        .await
        .expect_err("a durable same-id snapshot must reject the first-join");
    assert!(
        matches!(err, crate::context::ContextError::CreationFailed(_)),
        "expected CreationFailed for a durable-snapshot collision, got {err:?}"
    );

    // The victim snapshot is INTACT — neither clobbered nor deleted.
    assert!(
        !rec.deletes.contains(&ctx_id),
        "the victim durable snapshot must not be deleted by the rejected join"
    );
    let after = rec
        .store
        .get(&ctx_id)
        .map(|e| e.value().clone())
        .expect("the victim snapshot is still present after the reject");
    assert_eq!(
        after.context_id, seeded.context_id,
        "the victim snapshot's identity is unchanged"
    );
    assert_eq!(
        after.state, seeded.state,
        "the victim snapshot's lifecycle state is unchanged (not overwritten)"
    );
    // No actor stood up and no group was installed on the target.
    assert!(
        target_sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a durable-collision reject"
    );
    assert!(
        target_crypto
            .export_crypto_state(&ctx_bytes)
            .expect("export never errors")
            .is_empty(),
        "no group may be installed after a durable-collision reject"
    );

    // KP NOT burned: clear the durable snapshot (as a recover/reconnect would)
    // and retry the SAME reservation + Welcome to the SAME id — it now succeeds,
    // proving the durable-collision reject fired BEFORE `ConfirmConsume`.
    rec.store.remove(&ctx_id);
    rec.deletes.clear();
    target_sup
        .spawn_actor_from_welcome(bob, make_req(ctx_id.clone(), reservation_id, welcome))
        .await
        .expect("the retry after clearing the snapshot succeeds — the KP was never burned");
    assert_eq!(
        target_sup.member_count(&ctx_id).await,
        Some(2),
        "the retry stands up the live joiner actor"
    );
}

// ---------------------------------------------------------------------------
// Test J — a locked region that exceeds LIFECYCLE_TIMEOUT fails the join closed,
// rolls back, and RELEASES the global bootstrap lock (BLACK-2J-07 global-lock
// DoS). The step-1 `ConfirmConsume` send blocks on MLS processing of
// attacker-supplied `welcome_bytes` with no reply timeout; the entrypoint's
// `timeout(LIFECYCLE_TIMEOUT, ...)` wrap bounds that unbounded wait so a slow or
// crafted Welcome can no longer pin the single global `bootstrap_spawn_lock` and
// wedge every other bootstrap node-wide.
// ---------------------------------------------------------------------------

/// A join whose locked region (step-1 `ConfirmConsume`) never completes within
/// `LIFECYCLE_TIMEOUT` returns a typed `TransportTimeout`, rolls back (no group
/// installed, no snapshot persisted, no actor registered), and — critically —
/// RELEASES the global `bootstrap_spawn_lock`, so a subsequent bootstrap for a
/// DIFFERENT context id proceeds promptly instead of deadlocking.
///
/// The `ConfirmConsume` wait is bounded ONLY by the entrypoint's
/// `timeout(LIFECYCLE_TIMEOUT, ...)` (the `KeyPackageStoreHandle::send` reply
/// await itself has no timeout), so this is the exact path a slow/crafted
/// Welcome would take. A fake key-package store injected for Bob receives the
/// `ConfirmConsume` and holds its reply channel open while sleeping far past
/// `LIFECYCLE_TIMEOUT`; under `start_paused` the runtime auto-advances virtual
/// time to the earliest timer, so the entrypoint's timeout fires FIRST and the
/// elapse is deterministic and instant (no wall-clock wait).
///
/// Non-vacuity: without the `LIFECYCLE_TIMEOUT` wrap, `spawn_actor_from_welcome`
/// would await the never-answered reply forever while holding
/// `bootstrap_spawn_lock`; the first `.await` would hang (the join never returns)
/// and, even if it did, the follow-up `create_context` would deadlock acquiring
/// the still-held global lock. Both the `TransportTimeout` result and the prompt
/// follow-up create therefore pin the timeout-bound-and-release behavior.
#[tokio::test(start_paused = true)]
async fn slow_confirm_consume_times_out_rolls_back_and_releases_the_lock() {
    use std::time::Duration;

    use super::key_package_actor::{KeyPackageStoreHandle, ReservationId};

    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0xa5);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);

    // Inject a fake key-package store for Bob whose `ConfirmConsume` handler
    // holds the reply channel open and sleeps far past `LIFECYCLE_TIMEOUT`
    // without answering — modelling a slow/crafted Welcome whose MLS processing
    // does not return. `key_package_store_for` returns this pre-inserted handle
    // (get-or-spawn: it never spawns a real actor when one is already present),
    // so `build_actor_deps` threads it into `deps.key_package_store` and step 1
    // sends `ConfirmConsume` here.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<KeyPackageCommand>(8);
    let fake_actor = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            if let KeyPackageCommand::ConfirmConsume { reply, .. } = cmd {
                // Keep `reply` alive (so the caller's reply await stays pending,
                // not an immediate channel-closed error) but never answer within
                // the join's budget — the entrypoint timeout wins first.
                tokio::time::sleep(Duration::from_hours(1)).await;
                drop(reply);
            }
        }
    });
    sup.key_package_stores
        .insert(bob.clone(), KeyPackageStoreHandle::from_sender(tx));

    // A well-formed request: the fake store ignores `reservation_id` /
    // `welcome_bytes`, so they need not name a real reserved KP. The reversible
    // prechecks (A live-registry miss, B pseudonym, C legible params, D durable
    // first-writer-wins) all PASS, so control reaches the timed region and blocks
    // in the step-1 `ConfirmConsume`.
    let req = WelcomeJoinRequest {
        creator_did: DID::from(ALICE_DID),
        context_id: ctx_id.clone(),
        params: joiner_params(),
        reservation_id: ReservationId::new_random(),
        welcome_bytes: vec![0u8; 4],
        local_pseudonym: some_pseudonym(),
    };

    let err = sup
        .spawn_actor_from_welcome(bob.clone(), req)
        .await
        .expect_err("a ConfirmConsume exceeding LIFECYCLE_TIMEOUT must fail the join closed");
    assert!(
        matches!(err, crate::context::ContextError::TransportTimeout(_)),
        "expected TransportTimeout on the LIFECYCLE_TIMEOUT elapse, got {err:?}"
    );

    // Rollback fired on the elapse: no MLS group is installed and no actor stood
    // up. (The consume never completed, so there was nothing installed yet; the
    // unconditional teardown on `Elapsed` is still safe — the idempotent
    // `destroy_mls_group` / `delete_context` no-op.)
    assert!(
        bob_crypto
            .export_crypto_state(&ctx_bytes)
            .expect("export never errors")
            .is_empty(),
        "no MLS group may be installed after a timed-out join"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a timed-out join"
    );
    assert_eq!(
        sup.member_count(&ctx_id).await,
        None,
        "an unregistered context answers the unregistered default, not a live count"
    );

    // CRITICAL — the global `bootstrap_spawn_lock` was RELEASED: a subsequent
    // bootstrap for a DIFFERENT context id completes promptly. If the timed-out
    // join had pinned the lock, this create would deadlock acquiring it.
    // `create_context` builds a fresh group and never sends `ConfirmConsume`, so
    // it does not touch the still-sleeping fake store.
    let other_id = ctx_hex(0xa6);
    sup.create_context(
        other_id.clone(),
        joiner_params(),
        bob.clone(),
        some_pseudonym(),
    )
    .await
    .expect("a later bootstrap for a different id proceeds — the global lock was released");
    assert!(
        sup.lookup(&other_id).is_some(),
        "the follow-up create stood up its own live actor (the global lock was not pinned)"
    );
    assert!(
        sup.member_count(&other_id).await.is_some(),
        "the follow-up context's actor serves its mailbox — the lock is free"
    );

    fake_actor.abort();
}
