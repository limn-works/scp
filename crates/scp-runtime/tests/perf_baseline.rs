//! ADR-049 Decision 14 — performance **baseline** harness.
//!
//! Provenance: `.docs/adrs/ADR-049-actor-per-context.md`
//! - `### 14. Performance regression as a rollback trigger`
//! - `## Consequences` §Performance
//!
//! The ADR mandates a `cargo test -p scp-runtime --test perf_baseline` target
//! that measures SIX operations at N = 1 / 4 / 16 (concurrency) and treats a
//! **> 15 % regression on any (operation, N) pair** as rollback trigger #4.
//! The six operations, and the two workload classes the ADR names:
//!
//! | operation             | driver                                                    | class                    |
//! |-----------------------|-----------------------------------------------------------|--------------------------|
//! | `handshake`           | real MLS welcome + keypackage + `add_member`              | crypto-dominated         |
//! | `send_message`        | `Supervisor::send_message` (encrypt + fan-out)            | mixed                    |
//! | `deliver_incoming`    | `Supervisor::deliver_commit_blob` (actor decrypt + merge) | mixed (read fast path)   |
//! | `governance_propose`  | `Supervisor::propose_governance_action`                   | mixed (write slow path)  |
//! | `broadcast_publish`   | `Supervisor::dispatch_broadcast_command_with_custody`     | overhead-dominated (mailbox) |
//! | `broadcast_subscribe` | `Supervisor::dispatch_broadcast_command`                  | overhead-dominated (mailbox) |
//!
//! # Why the `scp-testing` `FullStackNetwork` harness
//!
//! `deliver_incoming` requires a genuine SECOND MLS member whose group state can
//! decrypt an inbound envelope. Producing that (real Welcome / keypackage /
//! sender-key / access-key exchange across two `Supervisor`s) is exactly what
//! `scp_testing::fullstack::FullStackNetwork` already drives. Per ADR guidance
//! ("do not hand-roll protocol setup if a harness exists") this target reuses it
//! via a **dev-only** dependency (see the note in `crates/scp-runtime/Cargo.toml`).
//! The harness is used only for untimed SETUP; every timed region calls the raw
//! `Supervisor` operation directly, so the measurement is sensitive to a
//! regression in the operation itself rather than diluted by harness overhead.
//!
//! # Methodology and the pass/fail gate
//!
//! For each (operation, N): spin up `N` independent contexts (each its own
//! per-context actor — the unit the ADR-049 refactor makes concurrent), run
//! `WARMUP` un-recorded rounds then `ROUNDS` recorded rounds, and in every round
//! launch the operation on all `N` contexts CONCURRENTLY (real `JoinSet` tasks
//! on a multi-thread runtime). Each individual operation's wall-clock is a
//! sample; the recorded statistic is the **p50 (median)** over all samples —
//! robust to CI scheduler jitter in a way a mean or p99 is not.
//!
//! Record-only by default; the gate is opt-in. The pass/fail comparison, when
//! it runs, is **purely relative to a recorded baseline — never an absolute time
//! threshold** (an absolute-timing assertion would flake in CI and is worthless):
//!
//! - **Default run** (no env vars): measure all pairs, (over)write the p50s to
//!   `tests/perf_baseline.json`, print them, and always PASS — no assertion. This
//!   is a per-environment reference artifact that can never flake on any hardware,
//!   which is exactly why the JSON is git-ignored, not committed (committing one
//!   machine's numbers is the machine-specific false-positive we avoid).
//! - **Opt-in gate** (`SCP_PERF_GATE=1`): the deliberate same-environment
//!   before/after comparison (Decision 14's intent). Baseline ABSENT → error,
//!   telling the operator to record first. Baseline PRESENT → for every (op, N)
//!   in it, assert `measured_p50 <= baseline_p50 * 1.15`. A measured pair absent
//!   from the baseline (a newly added op vs a stale baseline) is skipped; a fresh
//!   default run re-records. The gate never writes the baseline.
//!
//! Typical loop: run the default target to record a `before` baseline, apply the
//! change under test, then run `SCP_PERF_GATE=1` on the same box to assert.
//!
//! A `NOISE_FLOOR_MICROS` guard suppresses the relative check when BOTH the
//! baseline and the measurement sit below the floor: at tens-of-microseconds a
//! 15 % band is pure scheduler noise, so gating it would be a false-positive
//! machine. The check still fires the moment EITHER side crosses the floor, so a
//! real regression (e.g. a mailbox op ballooning from 40 µs to 2 ms) is caught.
//! This is a noise gate on the relative comparison, NOT an absolute-time gate:
//! sub-floor pairs always pass.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::large_futures
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use scp_did::DID;
use scp_platform::KeyHandle;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::context::context_id_bytes;
use scp_protocol::context::governance::GovernanceAction;
use scp_protocol::context::params::{
    Capability, ContextMode, ContextParams, GovernanceModel, MemoryScope,
};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::actor::commands::{
    BroadcastCommand, PublishBroadcastPayload, SubscribeBroadcastPayload,
};
use scp_runtime::context::supervisor::Supervisor;
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};

// ---------------------------------------------------------------------------
// Tuning constants — kept modest so the whole matrix runs in reasonable CI time.
// ---------------------------------------------------------------------------

/// Concurrency levels mandated by ADR-049 Decision 14.
const CONCURRENCY_LEVELS: [usize; 3] = [1, 4, 16];
/// Un-recorded rounds run before measurement to warm caches / JIT allocation.
const WARMUP: usize = 2;
/// Recorded rounds. Samples per (op, N) = `N * ROUNDS`.
///
/// Bounded by the protocol's per-sender hard anti-spam limiter (Matrix defaults:
/// burst 10, 0.2 msg/s refill — `HardRateLimitConfig::default`, not
/// param-configurable). Any principal that repeats a message-bearing op is
/// capped at ~10 invocations inside the test's short wall-clock window, so the
/// heaviest per-principal path (`deliver_incoming` setup = `WARMUP + ROUNDS + 1`
/// Alice sends) must stay under that burst. `ROUNDS = 6` keeps every principal
/// at ≤ 9 invocations with margin.
const ROUNDS: usize = 6;
/// Regression tolerance: a pair fails if `measured > baseline * TOLERANCE`.
const TOLERANCE: f64 = 1.15;
/// Below this (in microseconds) a 15 % band is scheduler noise; the relative
/// check is suppressed while BOTH sides are sub-floor. See module docs. Set just
/// under the overhead-dominated `broadcast_publish` p50 (~190 µs) so that path IS
/// gated (the ADR names it as a mandatory workload class), while the deep
/// sub-floor `broadcast_subscribe` (~65 µs, where a 15 % band is ~10 µs of pure
/// scheduler noise) is measured + recorded but not relative-gated until a real
/// regression pushes it across the floor.
const NOISE_FLOOR_MICROS: f64 = 150.0;
/// Fixed application payload used by send / deliver / broadcast measurements.
const PAYLOAD: &[u8] = b"scp-adr049-perf-baseline-payload";

// ---------------------------------------------------------------------------
// Deterministic key derivation — MUST mirror `FullStackNode::did_to_seed` so a
// custody key we mint for a broadcast author verifies against the network's
// deterministic `#active` resolver.
// ---------------------------------------------------------------------------

fn did_to_seed(did: &DID) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.as_ref().hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    seed
}

/// Builds a well-formed, unique `did:dht:` identifier from stable components.
fn make_did(kind: &str, instance: usize, slot: usize) -> String {
    format!("did:dht:z6MkPerf{kind}i{instance}s{slot}")
}

// ---------------------------------------------------------------------------
// Context parameter builders.
// ---------------------------------------------------------------------------

fn encrypted_ceiling() -> Vec<Capability> {
    vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::RoleAssign,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::GovernancePropose,
        Capability::GovernanceVote,
        Capability::ContextClose,
    ]
}

/// Encrypted, single-admin context (handshake / send / deliver).
fn encrypted_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: encrypted_ceiling(),
        ..ContextParams::default()
    }
}

/// Encrypted context under a 2-of-2 threshold model so a lone proposer records a
/// proposal WITHOUT crossing quorum (measures propose, never execute).
fn governance_params(alice: &DID, bob: &DID) -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: encrypted_ceiling(),
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice.clone(), bob.clone()],
        },
        ..ContextParams::default()
    }
}

/// Open broadcast context. `MemoryScope::Full` is mandatory for broadcast
/// (`validate_memory_scope_for_broadcast` rejects Ephemeral / Summary).
fn broadcast_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
        ..ContextParams::default()
    }
}

// ---------------------------------------------------------------------------
// Concurrency runner — the shared warmup/round/join scaffold.
// ---------------------------------------------------------------------------

/// Runs `WARMUP + ROUNDS` rounds; each round launches `op` on every instance
/// concurrently as a spawned task and awaits all. Returns the per-operation
/// wall-clock samples (microseconds) from the recorded rounds only.
async fn run_measure<I, F, Fut>(instances: Vec<Arc<I>>, op: F) -> Vec<f64>
where
    I: Send + Sync + 'static,
    F: Fn(Arc<I>, usize) -> Fut + Copy + Send + 'static,
    Fut: std::future::Future<Output = Duration> + Send + 'static,
{
    let mut samples = Vec::with_capacity(instances.len() * ROUNDS);
    for round in 0..(WARMUP + ROUNDS) {
        let mut set = tokio::task::JoinSet::new();
        for inst in &instances {
            let inst = Arc::clone(inst);
            set.spawn(op(inst, round));
        }
        let mut durations = Vec::with_capacity(instances.len());
        while let Some(joined) = set.join_next().await {
            durations.push(joined.expect("perf op task panicked"));
        }
        if round >= WARMUP {
            samples.extend(durations.into_iter().map(|d| d.as_secs_f64() * 1e6));
        }
    }
    samples
}

/// p50 (median) of a sample set, in whatever unit the samples carry.
fn p50(mut samples: Vec<f64>) -> f64 {
    assert!(!samples.is_empty(), "no samples collected");
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

// ---------------------------------------------------------------------------
// Per-operation instances + drivers.
//
// Each instance keeps its `FullStackNetwork` alive (it owns the shared key
// exchange + node registry the harness routes through).
// ---------------------------------------------------------------------------

// -- handshake -------------------------------------------------------------

struct HandshakeInst {
    _network: FullStackNetwork,
    creator: FullStackNode,
    handle: ContextHandle,
    joiner_dids: Vec<String>,
}

async fn setup_handshake(n: usize) -> Vec<Arc<HandshakeInst>> {
    let mut instances = Vec::with_capacity(n);
    for i in 0..n {
        let network = FullStackNetwork::new();
        let creator = network.create_node(&make_did("HsC", i, 0));
        let handle = creator
            .create_context(&format!("perf-handshake-{i}"), encrypted_params())
            .await
            .expect("create handshake context");
        // One fresh joiner per round (an add cannot be replayed). Each joiner is
        // registered in the network so the creator can mint its key package.
        let mut joiner_dids = Vec::with_capacity(WARMUP + ROUNDS);
        for r in 0..(WARMUP + ROUNDS) {
            let did = make_did("HsJ", i, r);
            let _joiner = network.create_node(&did);
            joiner_dids.push(did);
        }
        instances.push(Arc::new(HandshakeInst {
            _network: network,
            creator,
            handle,
            joiner_dids,
        }));
    }
    instances
}

async fn op_handshake(inst: Arc<HandshakeInst>, round: usize) -> Duration {
    let joiner = inst.joiner_dids[round].clone();
    let start = Instant::now();
    inst.creator
        .add_member(&inst.handle, &joiner)
        .await
        .expect("handshake add_member");
    start.elapsed()
}

// -- send_message ----------------------------------------------------------

struct SendInst {
    _network: FullStackNetwork,
    alice: FullStackNode,
    handle: ContextHandle,
}

/// Builds a live two-member encrypted context (Alice + Bob joined) so sends
/// have a real recipient to fan out to.
async fn build_pair(
    tag: &str,
    i: usize,
) -> (
    FullStackNetwork,
    FullStackNode,
    FullStackNode,
    ContextHandle,
    String,
) {
    let network = FullStackNetwork::new();
    let alice = network.create_node(&make_did(&format!("{tag}A"), i, 0));
    let bob = network.create_node(&make_did(&format!("{tag}B"), i, 0));
    let ctx_id = format!("perf-{tag}-{i}");
    let handle = alice
        .create_context(&ctx_id, encrypted_params())
        .await
        .expect("create pair context");
    let bob_did = bob.did.as_ref().to_owned();
    alice
        .add_member(&handle, &bob_did)
        .await
        .expect("pair add_member");
    bob.join_from_welcome(&ctx_id, &context_id_bytes(&ctx_id))
        .await
        .expect("bob joins pair");
    // §9.10.4: seed Bob's per-member pseudonym routing ID into Alice's manager
    // (production: Bob announces it). Without this an encrypted multi-member
    // send fails closed with `PseudonymRegistryEmpty`.
    alice
        .manager
        .seed_peer_pseudonym(&ctx_id, bob.did.clone(), [0x42u8; 32])
        .await
        .expect("seed bob pseudonym");
    // The actor `deliver_incoming` path resolves the receiving member by
    // intersecting context membership with the supervisor's registered local
    // DIDs. The full-stack harness never registers one (its own receive tests
    // decrypt at the crypto layer), so register Bob here for the actor path.
    bob.manager
        .register_local_did(bob.did.clone())
        .await
        .expect("register bob as local did");
    (network, alice, bob, handle, ctx_id)
}

async fn setup_send(n: usize) -> Vec<Arc<SendInst>> {
    let mut instances = Vec::with_capacity(n);
    for i in 0..n {
        let (network, alice, _bob, handle, _ctx) = build_pair("send", i).await;
        instances.push(Arc::new(SendInst {
            _network: network,
            alice,
            handle,
        }));
    }
    instances
}

async fn op_send(inst: Arc<SendInst>, _round: usize) -> Duration {
    let start = Instant::now();
    inst.alice
        .send_message(&inst.handle, PAYLOAD)
        .await
        .expect("send_message");
    start.elapsed()
}

// -- deliver_incoming ------------------------------------------------------

struct DeliverInst {
    _network: FullStackNetwork,
    bob: Arc<Supervisor>,
    ctx_id: String,
    envelopes: Vec<Vec<u8>>,
}

async fn setup_deliver(n: usize) -> Vec<Arc<DeliverInst>> {
    let mut instances = Vec::with_capacity(n);
    for i in 0..n {
        let (network, alice, bob, handle, ctx_id) = build_pair("deliver", i).await;
        let ctx_bytes = context_id_bytes(&ctx_id);

        // Pre-generate one probe envelope + WARMUP+ROUNDS measured envelopes.
        // Each Alice send yields exactly one captured ciphertext (single peer);
        // delivering them in send order keeps the per-sender sequence monotonic.
        let total = WARMUP + ROUNDS + 1;
        let mut envelopes = Vec::with_capacity(total);
        for _ in 0..total {
            alice
                .send_message(&handle, PAYLOAD)
                .await
                .expect("deliver setup: alice send");
            let mut captured = alice.take_sent_ciphertexts();
            assert_eq!(
                captured.len(),
                1,
                "a single-peer encrypted send must capture exactly one ciphertext"
            );
            envelopes.push(captured.remove(0).1);
        }
        // Resolve Alice's sender key on Bob's shared provider before delivery.
        bob.pickup_sender_keys(&ctx_id, &ctx_bytes)
            .expect("bob picks up alice sender keys");

        // Correctness probe (untimed): the actor deliver path must return real
        // application content for a genuine inbound message.
        let probe = envelopes.remove(0);
        let delivered = bob
            .manager
            .deliver_commit_blob(&ctx_id, probe)
            .await
            .expect("probe deliver_commit_blob");
        assert!(
            matches!(delivered, Some((ref pt, _)) if pt.as_slice() == PAYLOAD),
            "deliver_incoming must yield the real application payload; got {delivered:?}"
        );

        instances.push(Arc::new(DeliverInst {
            _network: network,
            bob: Arc::clone(&bob.manager),
            ctx_id,
            envelopes,
        }));
    }
    instances
}

async fn op_deliver(inst: Arc<DeliverInst>, round: usize) -> Duration {
    let envelope = inst.envelopes[round].clone();
    let start = Instant::now();
    inst.bob
        .deliver_commit_blob(&inst.ctx_id, envelope)
        .await
        .expect("deliver_commit_blob");
    start.elapsed()
}

// -- governance_propose ----------------------------------------------------

struct ProposeInst {
    _network: FullStackNetwork,
    alice: FullStackNode,
    ctx_id: String,
    instance: usize,
}

async fn setup_propose(n: usize) -> Vec<Arc<ProposeInst>> {
    let mut instances = Vec::with_capacity(n);
    for i in 0..n {
        let network = FullStackNetwork::new();
        let alice = network.create_node(&make_did("GovA", i, 0));
        let bob = network.create_node(&make_did("GovB", i, 0));
        let ctx_id = format!("perf-propose-{i}");
        alice
            .create_context(&ctx_id, governance_params(&alice.did, &bob.did))
            .await
            .expect("create governance context");
        instances.push(Arc::new(ProposeInst {
            _network: network,
            alice,
            ctx_id,
            instance: i,
        }));
    }
    instances
}

async fn op_propose(inst: Arc<ProposeInst>, round: usize) -> Duration {
    // A fresh target per round → a distinct pending proposal each time.
    let action = GovernanceAction::AddMember {
        did: DID::from(make_did("GovT", inst.instance, round)),
        role: "member".to_owned(),
    };
    let start = Instant::now();
    inst.alice
        .propose_governance(&inst.ctx_id, action)
        .await
        .expect("propose_governance_action");
    start.elapsed()
}

// -- broadcast_subscribe ---------------------------------------------------

struct SubscribeInst {
    _network: FullStackNetwork,
    sup: Arc<Supervisor>,
    ctx_id: String,
    instance: usize,
}

async fn setup_broadcast(tag: &str, n: usize) -> Vec<(FullStackNetwork, FullStackNode, String)> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let network = FullStackNetwork::new();
        let creator = network.create_node(&make_did(tag, i, 0));
        let ctx_id = format!("perf-{tag}-{i}");
        creator
            .create_context(&ctx_id, broadcast_params())
            .await
            .expect("create broadcast context");
        out.push((network, creator, ctx_id));
    }
    out
}

async fn setup_subscribe(n: usize) -> Vec<Arc<SubscribeInst>> {
    let mut instances = Vec::with_capacity(n);
    for (i, (network, creator, ctx_id)) in setup_broadcast("BSub", n).await.into_iter().enumerate()
    {
        instances.push(Arc::new(SubscribeInst {
            sup: Arc::clone(&creator.manager),
            _network: network,
            ctx_id,
            instance: i,
        }));
    }
    instances
}

async fn op_subscribe(inst: Arc<SubscribeInst>, round: usize) -> Duration {
    // A fresh subscriber each round → no idempotent-dedup short-circuit.
    let subscriber = DID::from(make_did("BSubR", inst.instance, round));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::SubscribeBroadcast {
        payload: Box::new(SubscribeBroadcastPayload {
            context_id: inst.ctx_id.clone(),
            subscriber_did: subscriber,
            ucan: None,
            timestamp: 1_700_000_000 + round as u64,
        }),
        reply: tx,
    };
    let start = Instant::now();
    inst.sup
        .dispatch_broadcast_command(cmd)
        .await
        .expect("dispatch subscribe");
    rx.await
        .expect("subscribe reply channel")
        .expect("subscribe succeeds");
    start.elapsed()
}

// -- broadcast_publish -----------------------------------------------------

struct PublishInst {
    _network: FullStackNetwork,
    sup: Arc<Supervisor>,
    ctx_id: String,
    author: DID,
    custody: InMemoryKeyCustody,
    key: KeyHandle,
}

async fn setup_publish(n: usize) -> Vec<Arc<PublishInst>> {
    let mut instances = Vec::with_capacity(n);
    for (network, creator, ctx_id) in setup_broadcast("BPub", n).await {
        // The creator is auto-registered as the broadcast author on create. Mint
        // a custody key seeded to match the network resolver so the publish
        // signature verifies.
        let custody = InMemoryKeyCustody::new();
        let key = custody.import_ed25519_key(&did_to_seed(&creator.did)).await;
        instances.push(Arc::new(PublishInst {
            author: creator.did.clone(),
            sup: Arc::clone(&creator.manager),
            _network: network,
            ctx_id,
            custody,
            key,
        }));
    }
    instances
}

async fn op_publish(inst: Arc<PublishInst>, _round: usize) -> Duration {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::PublishBroadcast {
        payload: Box::new(PublishBroadcastPayload {
            context_id: inst.ctx_id.clone(),
            author_did: inst.author.clone(),
            payload: PAYLOAD.to_vec(),
            signing_key_handle: inst.key,
        }),
        reply: tx,
    };
    let start = Instant::now();
    inst.sup
        .dispatch_broadcast_command_with_custody(cmd, &inst.custody)
        .await
        .expect("dispatch publish");
    rx.await
        .expect("publish reply channel")
        .expect("publish succeeds");
    start.elapsed()
}

// ---------------------------------------------------------------------------
// Baseline persistence + gate.
// ---------------------------------------------------------------------------

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/perf_baseline.json")
}

fn key(op: &str, n: usize) -> String {
    format!("{op}/N{n}")
}

/// Writes the baseline map as stable, pretty JSON (`BTreeMap` → sorted keys).
fn write_baseline(map: &BTreeMap<String, f64>) {
    let json = serde_json::to_string_pretty(map).expect("serialize baseline");
    std::fs::write(baseline_path(), format!("{json}\n")).expect("write baseline");
}

fn read_baseline() -> Option<BTreeMap<String, f64>> {
    let bytes = std::fs::read(baseline_path()).ok()?;
    Some(serde_json::from_slice(&bytes).expect("parse existing perf_baseline.json"))
}

// ---------------------------------------------------------------------------
// The mandated target.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn perf_baseline() {
    // Measure every (operation, N) pair, recording p50 microseconds.
    let mut measured: BTreeMap<String, f64> = BTreeMap::new();

    for &n in &CONCURRENCY_LEVELS {
        measured.insert(
            key("handshake", n),
            p50(run_measure(setup_handshake(n).await, op_handshake).await),
        );
        measured.insert(
            key("send_message", n),
            p50(run_measure(setup_send(n).await, op_send).await),
        );
        measured.insert(
            key("deliver_incoming", n),
            p50(run_measure(setup_deliver(n).await, op_deliver).await),
        );
        measured.insert(
            key("governance_propose", n),
            p50(run_measure(setup_propose(n).await, op_propose).await),
        );
        measured.insert(
            key("broadcast_publish", n),
            p50(run_measure(setup_publish(n).await, op_publish).await),
        );
        measured.insert(
            key("broadcast_subscribe", n),
            p50(run_measure(setup_subscribe(n).await, op_subscribe).await),
        );
    }

    // Emit the measured table for operator visibility (visible with --nocapture).
    println!("\nADR-049 perf_baseline — p50 wall-clock per (operation, N):");
    for (k, v) in &measured {
        println!("  {k:<26} {v:>12.1} µs");
    }

    // DEFAULT (no env): record the measured p50s and always PASS. This is a
    // per-environment reference artifact, never an absolute-time assertion, so
    // it can never flake on any hardware. The opt-in gate below is the deliberate
    // same-environment before/after comparison (Decision 14's intent).
    if std::env::var("SCP_PERF_GATE").is_err() {
        write_baseline(&measured);
        println!(
            "\nRecorded {} (op, N) p50s to {} — record-only run, PASS.\n\
             Set SCP_PERF_GATE=1 (after a record on this machine) to assert the \
             >{:.0}% regression gate.",
            measured.len(),
            baseline_path().display(),
            (TOLERANCE - 1.0) * 100.0,
        );
        return;
    }

    // OPT-IN GATE (`SCP_PERF_GATE=1`): compare against the previously recorded
    // baseline on THIS machine. Absent baseline is an operator error, not a pass.
    let baseline = read_baseline().unwrap_or_else(|| {
        panic!(
            "SCP_PERF_GATE=1 but no baseline at {} — run the default target once with no \
             env vars to record it, then re-run with SCP_PERF_GATE=1 for the same-environment \
             before/after comparison.",
            baseline_path().display(),
        )
    });

    let mut regressions: Vec<String> = Vec::new();
    for (k, &m) in &measured {
        // A measured pair absent from the baseline means the baseline is stale
        // (a new op was added) — skip it here; a fresh default run re-records.
        if let Some(&b) = baseline.get(k) {
            // Suppress the relative check only while BOTH sides are sub-noise-floor
            // (a 15% band at tens of µs is pure scheduler noise); fire it the
            // instant either side crosses the floor.
            if b.max(m) >= NOISE_FLOOR_MICROS && m > b * TOLERANCE {
                regressions.push(format!(
                    "  {k:<26} baseline {b:.1} µs → measured {m:.1} µs \
                     ({:.1}% over, limit +{:.0}%)",
                    (m / b - 1.0) * 100.0,
                    (TOLERANCE - 1.0) * 100.0,
                ));
            }
        }
    }

    assert!(
        regressions.is_empty(),
        "ADR-049 Decision 14 rollback trigger #4 — >{:.0}% perf regression on \
         {} (operation, N) pair(s):\n{}\n\nIf this reflects an intentional change, \
         re-record with a default (no-env) run.",
        (TOLERANCE - 1.0) * 100.0,
        regressions.len(),
        regressions.join("\n"),
    );
    println!(
        "\nSCP_PERF_GATE — all (operation, N) pairs within +{:.0}% of the recorded baseline — PASSED.",
        (TOLERANCE - 1.0) * 100.0
    );
}
