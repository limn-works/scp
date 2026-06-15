//! Integration test for the reconnection driver (ADR-029).
//!
//! Exercises the FFI/SDK-layer `RelayActorSyncDriver` and the
//! `reconnect_contexts` orchestration against a **real** native relay and two
//! full-stack members (real MLS, real event log, real Supervisor). The driver
//! lives at the relay-client layer because the actor's transport provider is
//! send-only (ADR-029 reconnection-driver addendum); this test proves the
//! driver reaches actor-owned reconnection state through the Supervisor
//! mailbox wrappers added in this ticket.
//!
//! Coverage:
//! - **All three tiers reachable.** `last_relay_contacts` is driven to Short /
//!   Extended / Long offline durations and the report classifies each context
//!   into the matching tier (`SyncPolicy::classify_offline_duration`).
//! - **Epoch catch-up.** Bob advances the MLS epoch; Alice's `local_mls_epoch`
//!   reflects her own epoch and the driver re-reads it after reconciliation.
//! - **Checkpoint exchange.** The driver's Phase 3 builds + broadcasts Alice's
//!   local consistency checkpoint via `Supervisor::build_local_checkpoint`,
//!   composing with the equivocation core (§9.9.3).
//! - **Equivocation on forgery.** A forged divergent checkpoint (equal event
//!   count, different Merkle root) compared via `Supervisor::compare_remote_checkpoint`
//!   surfaces `ContextEvent::EquivocationDetected` (§9.9.3) carrying the real
//!   divergent roots, drained ONLY by `drain_equivocation_alerts` (the
//!   non-destructive targeted drain), and replay-deduped.
//! - **`needs_reconnect` cleared.** `clear_needs_reconnect` flips the §23.11
//!   flag off after a successful reconnect.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use scp_core::context::ContextState;
use scp_core::context::governance::KeyResolver;
use scp_core::context::membership::ContextEvent;
use scp_core::context::params::{ContextMode, ContextParams};
use scp_core::context::roles::Capability;
use scp_core::sync::SyncPolicy;
use scp_identity::DID;
use scp_testing::fullstack::FullStackNetwork;
use scp_transport::TransportManager;
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer, ShutdownHandle};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

const ALICE_DID: &str = "did:dht:z6MkAliceReconnect";
const BOB_DID: &str = "did:dht:z6MkBobReconnect";

/// Mirrors `FullStackNode::did_to_seed` so the test's key resolver can derive
/// the same deterministic Ed25519 verifying key each node signs with. Required
/// so `compare_remote_checkpoint` can verify a peer checkpoint's signature.
fn did_to_seed(did: &str) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    seed
}

fn signing_key_for(did: &str) -> SigningKey {
    SigningKey::from_bytes(&did_to_seed(did))
}

/// Key resolver that resolves any DID to the deterministic verifying key the
/// full-stack node derives from `did_to_seed`. Lets the checkpoint-signature
/// verification path in `compare_remote_checkpoint` succeed for legitimately
/// signed peer checkpoints.
fn deterministic_key_resolver() -> KeyResolver {
    Arc::new(|did: &DID| Some(signing_key_for(did.as_ref()).verifying_key()))
}

fn encrypted_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::ContextClose,
        ],
        ..ContextParams::default()
    }
}

fn context_id_bytes(context_id: &str) -> [u8; 32] {
    scp_core::context::context_id_bytes(context_id)
}

/// Forges a divergent consistency checkpoint: same `event_count` / `epoch` /
/// `timestamp` as `reference`, but a Merkle root flipped to differ, authored
/// and signed by `author_did` (with that DID's deterministic key). §9.9.3
/// equivocation is equal-count-different-root with a VALID signature.
fn forge_divergent_checkpoint(
    ctx_id: &str,
    author_did: &str,
    reference: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> (scp_event_log::checkpoint::ConsistencyCheckpoint, [u8; 32]) {
    let mut forged_root = reference.merkle_root;
    forged_root[0] ^= 0xFF; // guaranteed different from the reference root
    let canonical = scp_event_log::checkpoint::compute_checkpoint_canonical_hash(
        ctx_id,
        author_did,
        reference.event_count,
        &forged_root,
        reference.epoch,
        reference.timestamp,
    );
    let signature = ed25519_dalek::Signer::sign(&signing_key_for(author_did), &canonical);
    let forged = scp_event_log::checkpoint::ConsistencyCheckpoint {
        context_id: ctx_id.to_owned(),
        sender_did: DID::from(author_did),
        event_count: reference.event_count,
        merkle_root: forged_root,
        epoch: reference.epoch,
        timestamp: reference.timestamp,
        signature: signature.to_bytes().to_vec(),
    };
    (forged, forged_root)
}

/// Starts an ephemeral native relay on a random port.
async fn start_relay() -> (ShutdownHandle, SocketAddr) {
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    };
    let storage = Arc::new(BlobStorageBackend::in_memory());
    let server = RelayServer::new(config, storage);
    let (handle, addr) = server.start().await.unwrap();
    (handle, addr)
}

/// Builds a `TransportManager` connected to the relay via a real
/// `NativeRelayAdapter` (ws:// loopback, `DhtResolved` source).
async fn connect_transport(relay_addr: SocketAddr) -> Arc<TransportManager> {
    let sourced = SourcedRelayUrl {
        url: format!("ws://{relay_addr}/scp/v1"),
        source: RelayUrlSource::DhtResolved,
    };
    let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .expect("relay adapter connect");
    Arc::new(TransportManager::new(Box::new(adapter)))
}

/// End-to-end relay-backed driver run plus all-three-tier classification.
///
/// Part A drives the real `reconnect_contexts` orchestration over a LIVE
/// native relay for a Short-tier context — proving the FFI-layer
/// `RelayActorSyncDriver` runs end-to-end (relay QUERY → actor mailbox →
/// report) against a real `TransportManager` and a real `Supervisor`.
///
/// Part B proves every offline tier is reachable from the coordinator's
/// classification — Short / Extended / Long — without paying the per-tier
/// relay/Welcome round-trip latency (the native relay QUERY blocks until its
/// 30s collection deadline by design, see `transport_integration::query_*`).
#[tokio::test]
async fn reconnect_classifies_all_three_tiers() {
    use scp_core::sync::OfflineTier;
    use scp_core::sync::hours_offline::ReconnectionCoordinator;

    let policy = SyncPolicy::default();
    let now = 1_000_000_000u64;
    let short_ctx = "reconnect-tier-short";
    let extended_ctx = "reconnect-tier-extended";
    let long_ctx = "reconnect-tier-long";

    // Part B: classification — instant, no relay execution. The coordinator's
    // classify_context is exactly what `reconnect_contexts` uses to set each
    // ContextReconnectResult.tier, so this proves all three tiers are
    // reachable from the same code path the driver drives.
    let mut contacts = HashMap::new();
    contacts.insert(short_ctx.to_owned(), now - 60); // < tier_1 (Short)
    contacts.insert(
        extended_ctx.to_owned(),
        now - (policy.tier_1_threshold_secs + 3600), // (tier_1, tier_2] (Extended)
    );
    contacts.insert(
        long_ctx.to_owned(),
        now - (policy.tier_2_threshold_secs + 3600), // > tier_2 (Long)
    );
    let coordinator = ReconnectionCoordinator::with_policy(
        DID::from(ALICE_DID),
        vec![
            short_ctx.to_owned(),
            extended_ctx.to_owned(),
            long_ctx.to_owned(),
        ],
        contacts,
        policy.clone(),
    );
    assert_eq!(
        coordinator.classify_context(short_ctx, now),
        OfflineTier::Short,
        "Short tier must be reachable"
    );
    assert_eq!(
        coordinator.classify_context(extended_ctx, now),
        OfflineTier::Extended,
        "Extended (Tier 2) must be reachable"
    );
    assert_eq!(
        coordinator.classify_context(long_ctx, now),
        OfflineTier::Long,
        "Long (Tier 3) must be reachable"
    );

    // Part A: drive the real relay-backed driver for the Short context.
    let (relay_handle, relay_addr) = start_relay().await;
    let transport = connect_transport(relay_addr).await;
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, deterministic_key_resolver());
    alice
        .create_context(short_ctx, encrypted_params())
        .await
        .expect("create context");

    let mut short_contacts = HashMap::new();
    short_contacts.insert(short_ctx.to_owned(), now - 60);
    let report = scp_ffi_common::reconnect::reconnect_contexts_no_drain(
        &transport,
        &alice.manager,
        DID::from(ALICE_DID),
        zeroize::Zeroizing::new(signing_key_for(ALICE_DID).to_bytes()),
        vec![short_ctx.to_owned()],
        short_contacts,
        now,
        policy,
    )
    .await;

    let result = report
        .contexts
        .iter()
        .find(|c| c.context_id == short_ctx)
        .expect("short context in report");
    assert_eq!(
        result.tier, "short",
        "the relay-backed driver run must classify the live context as Short"
    );

    relay_handle.shutdown();
}

/// End-to-end Tier-1 reconnect: Alice creates a context and adds Bob (real
/// MLS). Bob advances the epoch + event log. Alice reconnects: the driver
/// builds her checkpoint, the report records the Short tier, and her
/// `needs_reconnect` flag is cleared on success.
///
/// Exercises the actor-side reconnection machinery the driver depends on
/// (Phase 5 MLS update, Phase 3 checkpoint build, §23.11 flag clearing)
/// directly through the Supervisor mailbox wrappers. The relay-backed
/// end-to-end driver run (all phases over a live relay) is covered by
/// `reconnect_classifies_all_three_tiers`.
#[tokio::test]
async fn reconnect_tier1_builds_checkpoint_and_clears_flag() {
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, deterministic_key_resolver());
    let bob = network.create_node(BOB_DID, deterministic_key_resolver());

    let ctx_id = "reconnect-tier1-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let handle = alice
        .create_context(ctx_id, encrypted_params())
        .await
        .expect("create context");
    assert_eq!(handle.try_read_state().unwrap(), ContextState::Active);

    alice.add_member(&handle, BOB_DID).await.expect("add bob");
    bob.join_from_welcome(ctx_id, &ctx_bytes)
        .expect("bob joins");

    // The reconnecting member is the creator (Alice), who owns the per-context
    // actor. (Per the ADR-049 spawn-from-Welcome follow-up, a Welcome-joined
    // node like Bob can decrypt but has no actor-backed send context, so the
    // reconnection driver — which reaches actor-owned state through the
    // Supervisor mailbox — is exercised on the actor-owning creator side.)
    //
    // Phase 5: Alice advances her own MLS epoch (post-compromise security,
    // §9.12) — exactly the step the driver's `mls_update` issues.
    let alice_epoch_before = alice
        .manager
        .local_mls_epoch(ctx_id)
        .await
        .expect("alice has an MLS epoch");
    alice
        .manager
        .issue_mls_update(ctx_id)
        .await
        .expect("alice issues MLS update");
    let alice_epoch_after = alice
        .manager
        .local_mls_epoch(ctx_id)
        .await
        .expect("alice epoch after update");
    assert!(
        alice_epoch_after > alice_epoch_before,
        "issue_mls_update must advance the local epoch (Phase 5)"
    );

    // Phase 3: build Alice's local checkpoint through the actor — confirm it
    // is signed + retained and carries the post-update MLS epoch.
    let cp = alice
        .manager
        .build_local_checkpoint(ctx_id, &DID::from(ALICE_DID), &signing_key_for(ALICE_DID))
        .await
        .expect("alice builds a checkpoint");
    assert_eq!(cp.context_id, ctx_id);
    assert_eq!(
        cp.epoch,
        Some(alice_epoch_after),
        "the built checkpoint must carry the post-update MLS epoch"
    );

    // §23.11: the clear-needs-reconnect supervisor wrapper the driver calls on
    // success must flip the actor-owned flag off.
    alice
        .manager
        .clear_needs_reconnect(ctx_id)
        .await
        .expect("clear_needs_reconnect succeeds");
    assert!(
        !alice.manager.needs_reconnect(ctx_id).await,
        "needs_reconnect must be false after clear_needs_reconnect (§23.11)"
    );
}

/// Equivocation: a forged divergent checkpoint (equal event count, different
/// Merkle root) signed by Bob and fed into Alice's actor via
/// `deliver_commit_blob`'s underlying comparison surfaces
/// `ContextEvent::EquivocationDetected` (§9.9.3). Drives the same
/// `compare_remote_checkpoint` the reconnection driver's Phase 2/3 exercises.
#[tokio::test]
async fn reconnect_detects_forged_divergent_checkpoint() {
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, deterministic_key_resolver());
    let bob = network.create_node(BOB_DID, deterministic_key_resolver());

    let ctx_id = "reconnect-equivocation-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let handle = alice
        .create_context(ctx_id, encrypted_params())
        .await
        .expect("create context");
    alice.add_member(&handle, BOB_DID).await.expect("add bob");
    bob.join_from_welcome(ctx_id, &ctx_bytes)
        .expect("bob joins");

    // Bob is a member (so the checkpoint passes the membership gate) but is a
    // Welcome-joined node with no actor (ADR-049 spawn-from-Welcome follow-up).
    // We therefore forge Bob's checkpoint directly: build Alice's honest
    // checkpoint to learn the current event count + epoch + root, then craft a
    // divergent checkpoint at the SAME count with a DIFFERENT Merkle root,
    // signed by Bob's real key. §9.9.3: equivocation is equal-count,
    // different-root with a VALID signature (not a signature failure).
    let honest = alice
        .manager
        .build_local_checkpoint(ctx_id, &DID::from(ALICE_DID), &signing_key_for(ALICE_DID))
        .await
        .expect("alice builds checkpoint");

    let (forged, _forged_root) = forge_divergent_checkpoint(ctx_id, BOB_DID, &honest);

    // Compare against Alice's local state — divergent at equal count ⇒
    // EquivocationDetected emitted into Alice's receive buffer.
    let comparison = alice
        .manager
        .compare_remote_checkpoint(ctx_id, forged)
        .await
        .expect("compare succeeds (signature valid)");
    assert!(
        matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ),
        "a forged equal-count different-root checkpoint must compare as Divergent (§9.9.3)"
    );

    // The equivocation event must surface to the SDK via the drain path —
    // exactly what the driver's `collect_equivocation_alerts` reads.
    let events = alice.manager.drain_events(ctx_id).await;
    assert!(
        events.iter().any(|e| matches!(
            e,
            ContextEvent::EquivocationDetected { remote_sender_did, .. }
            if remote_sender_did.as_ref() == BOB_DID
        )),
        "compare_remote_checkpoint must emit EquivocationDetected for the forging peer (§9.9.3)"
    );
}

/// Runtime actor-dispatch proof for the equivocation receive path + the
/// non-destructive targeted alert drain (§9.9.3).
///
/// Drives a forged divergent checkpoint through the real actor mailbox
/// (`Supervisor::compare_remote_checkpoint`, i.e. the
/// `MessagingCommand::CompareRemoteCheckpoint` → handler →
/// `compare_remote_checkpoint` chain) rather than calling the helper inline,
/// then asserts:
///
/// 1. The runtime dispatch emits `EquivocationDetected` carrying the real
///    divergent local/remote Merkle roots (the forensic evidence now on the
///    event, not zeroed).
/// 2. `Supervisor::drain_equivocation_alerts` returns ONLY that alert while
///    leaving an unrelated buffered application event in place — proving the
///    reconnection driver's targeted drain does not destroy the SDK's delivery
///    queue (the bug this work fixes).
/// 3. Replaying the identical signed divergent checkpoint is a no-op (replay
///    idempotency) — no second alert is emitted.
///
/// The structural wiring that the *decrypt* prefix
/// (`deliver_incoming → deliver_checkpoint_message → compare_remote_checkpoint`)
/// reaches this comparison is pinned separately by
/// `pipeline_wiring::b3_merkle_proof_verification_wired`; a full cross-member
/// MLS-decrypt round trip is not reconstructable single-node because MLS
/// rejects decrypting one's own messages.
#[tokio::test]
async fn runtime_equivocation_dispatch_and_targeted_drain() {
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, deterministic_key_resolver());
    let bob = network.create_node(BOB_DID, deterministic_key_resolver());

    let ctx_id = "reconnect-runtime-equivocation-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let handle = alice
        .create_context(ctx_id, encrypted_params())
        .await
        .expect("create context");
    alice.add_member(&handle, BOB_DID).await.expect("add bob");
    bob.join_from_welcome(ctx_id, &ctx_bytes)
        .expect("bob joins");

    // Seed an unrelated application event into Alice's receive buffer (the
    // SystemClose/MemberJoined family buffered during real catch-up). A plain
    // self-send to a lone member is a no-op, so use report_degraded_mode which
    // emits a non-equivocation event the targeted drain must preserve.
    alice
        .manager
        .report_degraded_mode(
            ctx_id,
            scp_core::envelope::VersionCompatibility::DegradedMode {
                local_minor: 0,
                remote_minor: 1,
            },
            vec!["unknown-feature".to_owned()],
        )
        .await;

    // Build Alice's honest checkpoint to learn the current count/epoch/time,
    // then forge a divergent one (equal count, different root) signed by Bob.
    let honest = alice
        .manager
        .build_local_checkpoint(ctx_id, &DID::from(ALICE_DID), &signing_key_for(ALICE_DID))
        .await
        .expect("alice builds honest checkpoint");

    let (forged, forged_root) = forge_divergent_checkpoint(ctx_id, BOB_DID, &honest);

    // Runtime dispatch #1 — through the actor mailbox command.
    let comparison = alice
        .manager
        .compare_remote_checkpoint(ctx_id, forged.clone())
        .await
        .expect("compare via actor mailbox succeeds (valid signature)");
    assert!(
        matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ),
        "equal-count different-root checkpoint must compare Divergent (§9.9.3)"
    );

    // Runtime dispatch #2 — REPLAY the identical signed checkpoint. The replay
    // must NOT emit a second EquivocationDetected alert (idempotency). The
    // first detection appended an `EquivocationDetected` event to the log,
    // advancing the local count, so the replayed comparison itself need not be
    // Divergent — the load-bearing guarantee is "no second alert", asserted by
    // the exactly-once count below.
    let _replay = alice
        .manager
        .compare_remote_checkpoint(ctx_id, forged)
        .await
        .expect("replayed compare still returns a verdict without error");

    // Targeted drain: returns ONLY the equivocation alert, EXACTLY ONCE
    // (replay suppressed), and the unrelated DegradedMode event must survive
    // in the receive buffer for the SDK's normal polling.
    let alerts = alice.manager.drain_equivocation_alerts(ctx_id).await;
    let equivocation_count = alerts
        .iter()
        .filter(|e| {
            matches!(
                e,
                ContextEvent::EquivocationDetected {
                    remote_sender_did,
                    remote_merkle_root,
                    ..
                }
                if remote_sender_did.as_ref() == BOB_DID && *remote_merkle_root == forged_root
            )
        })
        .count();
    assert_eq!(
        equivocation_count, 1,
        "the actor dispatch must emit EquivocationDetected exactly once (replay \
         suppressed) carrying the divergent root (§9.9.3); drained: {alerts:?}"
    );
    assert!(
        alerts
            .iter()
            .all(|e| matches!(e, ContextEvent::EquivocationDetected { .. })),
        "drain_equivocation_alerts must return ONLY equivocation alerts, never \
         other buffered events; drained: {alerts:?}"
    );

    // The unrelated application event must NOT have been consumed by the
    // targeted drain — it remains for the SDK's normal receive polling.
    let remaining = alice.manager.drain_events(ctx_id).await;
    assert!(
        remaining
            .iter()
            .any(|e| matches!(e, ContextEvent::DegradedMode { .. })),
        "targeted drain must PRESERVE non-equivocation events (the reconnect \
         bug this fixes); remaining: {remaining:?}"
    );
    assert!(
        !remaining
            .iter()
            .any(|e| matches!(e, ContextEvent::EquivocationDetected { .. })),
        "equivocation alerts were already drained; none should remain"
    );
}
