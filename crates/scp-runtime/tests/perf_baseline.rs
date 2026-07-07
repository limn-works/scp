#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_futures,
    // Test-only recording transport: the trait methods are `async` but the
    // captured-blob buffer is never held across `.await`, so a plain
    // `std::sync::Mutex` is correct. The runtime's actor path bans it
    // (ADR-049); test fixtures are explicitly exempt. See clippy.toml.
    clippy::disallowed_types
)]
//! ADR-049 Decision 14 — actor-per-context performance-baseline harness.
//!
//! This is a **measurement-recording** harness, not a threshold test. It drives
//! the six operations named in ADR-049 §Decision 14 —
//!
//! 1. `handshake`            (welcome + `key_package` + `add_member`)
//! 2. `send_message`
//! 3. `deliver_incoming`
//! 4. `governance_propose`
//! 5. `broadcast_publish`
//! 6. `broadcast_subscribe`
//!
//! — at `N ∈ {1, 4, 16}` (18 measurement points total), through the **real
//! actor command surface** ([`Supervisor`] mailbox dispatch), measures each with
//! [`std::time::Instant`], prints a per-point line, and `assert!`s only
//! smoke-level success (each op completes with its expected outcome). It uses
//! **no** `criterion` dependency (not in the tree) and commits **no** absolute
//! baseline numbers.
//!
//! # Why no committed baseline / no hardcoded thresholds
//!
//! ADR-049 §Decision 14 makes a **>15% regression on any (operation, N) pair**
//! trigger the §Rollback-strategy gate. That gate is a **same-environment
//! pre-merge-vs-post-merge diff on one machine** — not an absolute bound.
//! Wall-clock numbers are meaningless across machines (CPU, allocator, load), so
//! committing a baseline or asserting `elapsed < X` would be noise that fails
//! spuriously on other hardware. Instead this harness *emits* the numbers a
//! human or CI job compares before vs after a change on the **same box**: run it
//! on `main`, run it on the branch, diff the `mean/op` column, and block the
//! merge if any pair regressed >15%. The only thing asserted here is that the
//! path still *works* (smoke), so the harness itself stays green as a normal
//! `cargo test` while remaining the data source for the manual/CI gate.
//!
//! # What `N` means here
//!
//! ADR-049's thesis is **one actor per context**; the performance risk it guards
//! is per-context actor overhead (mailbox, spawn, per-actor MLS/crypto state)
//! scaling with the number of live contexts. So `N` is the **number of
//! independent per-context actors** exercised: each measurement builds `N`
//! distinct contexts inside one [`Supervisor`] and drives the op once per
//! context. The `N` contexts are driven **sequentially** and the wall-clock is
//! summed, which isolates per-context actor cost from tokio-scheduler noise and
//! keeps the pre/post diff reproducible; `mean/op = total / N` is the
//! per-operation figure the 15% gate compares. Per-context setup (context
//! creation, member add, pseudonym seeding, custody keygen) is **excluded** from
//! the timed region — only the named operation is measured.
//!
//! # Faithfulness of each driven op (single-crate constraint)
//!
//! Every op is driven through the genuine actor command surface. Two ops cannot
//! reach a clean cross-node `Ok` from a **single** `scp-runtime` test — a real
//! second party's MLS/crypto state only exists in the two-node fullstack
//! `KeyExchange` harness, which lives in `scp-testing` and therefore cannot be a
//! dependency of a `scp-runtime` test (that would be a dependency cycle). For
//! those two the closest faithfully-drivable proxy is measured and the
//! limitation is documented at the call site — no measurement is faked:
//!
//! - **`handshake`** — driven via the real [`Supervisor::join_context`] path
//!   (welcome + `key_package` + `add_member`). The concrete `MlsCryptoProvider`'s
//!   `cfg(test)` accommodation accepts a `None` key-package (ADR-049
//!   §Consequences), so the local MLS add, Welcome generation, and access-key
//!   minting all run; only the joiner-side Welcome *consumption* (a second node)
//!   is absent.
//! - **`deliver_incoming`** — driven via the real
//!   [`Supervisor::deliver_commit_blob`] (`DeliverIncoming` actor command) fed a
//!   **real captured application ciphertext** produced by a live
//!   [`Supervisor::send_message`]. Single-node the receive pipeline runs in full
//!   — actor mailbox dispatch, local-member resolution, MLS open attempt — and
//!   terminates at the MLS layer with the deterministic
//!   `CryptoFailed("Cannot decrypt own messages.")`, because the only ciphertext
//!   available is one this node authored. A cross-node-decryptable blob needs
//!   the two-node harness. The measured cost still covers the whole
//!   mailbox+receive-dispatch+decrypt-attempt path — exactly the overhead the
//!   rollback gate compares.
//!
//! The remaining four (`send_message`, `governance_propose`,
//! `broadcast_publish`, `broadcast_subscribe`) drive the real command surface to
//! a clean `Ok`.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use scp_did::DID;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::{GovernanceAction, KeyResolver};
use scp_protocol::context::membership::KeyPackage;
use scp_protocol::context::params::{
    Capability, ContextMode, ContextParams, GovernanceModel, MemoryScope,
};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::actor::commands::{
    BroadcastCommand, PublishBroadcastPayload, SubscribeBroadcastPayload,
};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::supervisor::{MessageSigner, Supervisor};
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

const ALICE: &str = "did:dht:z6MkAlicePerfBaseline";
const BOB: &str = "did:dht:z6MkBobPerfBaseline";

/// The `N` fan-out breadths ADR-049 §Decision 14 mandates.
const N_VALUES: [usize; 3] = [1, 4, 16];

fn alice() -> DID {
    DID::from(ALICE)
}
fn bob() -> DID {
    DID::from(BOB)
}

// ---------------------------------------------------------------------------
// Fixtures — the standard single-node `Supervisor` wiring shared by the
// runtime integration tests (concrete `MlsCryptoProvider`, in-memory MLS
// storage, recording transport, mock event log, seed-derived key resolver).
// ---------------------------------------------------------------------------

/// Recording transport — captures every `(routing_id, ciphertext)` a send fans
/// out so `deliver_incoming` can replay a real captured blob.
#[derive(Default)]
struct RecordingTransport {
    connected: AtomicBool,
    blobs: Mutex<Vec<([u8; 32], Vec<u8>)>>,
}
impl RecordingTransport {
    const fn connected() -> Self {
        Self {
            connected: AtomicBool::new(true),
            blobs: Mutex::new(Vec::new()),
        }
    }
    fn take_blobs(&self) -> Vec<([u8; 32], Vec<u8>)> {
        std::mem::take(&mut self.blobs.lock().expect("blob lock"))
    }
}
#[async_trait::async_trait]
impl ContextTransportProvider for RecordingTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    async fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn send_message(&self, id: &[u8; 32], payload: &[u8]) -> Result<(), ContextError> {
        self.blobs
            .lock()
            .expect("blob lock")
            .push((*id, payload.to_vec()));
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog;
#[async_trait::async_trait]
impl ContextEventLogProvider for MockEventLog {
    async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}
fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did, _kid: scp_did::SigningKeyId| {
        Some(ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did)).verifying_key())
    })
}
fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}
fn ceiling() -> Vec<Capability> {
    vec![
        Capability::new("messages:read"),
        Capability::new("messages:write"),
        Capability::new("governance:propose"),
        Capability::new("governance:vote"),
        Capability::new("role:assign"),
    ]
}

/// A fresh `Supervisor` wired with the recording transport (so each
/// measurement is independent). Returns the transport handle for blob capture.
fn supervisor() -> (Arc<Supervisor>, Arc<RecordingTransport>) {
    let transport = Arc::new(RecordingTransport::connected());
    let supervisor = scp_runtime::context::test_supervisor(
        Arc::new(MlsCryptoProvider::new(
            ALICE.to_owned(),
            Arc::new(scp_clock::SystemClock),
        )),
        Box::new(TransportShim(Arc::clone(&transport))),
        Box::new(MockEventLog),
        mock_key_resolver(),
    );
    (supervisor, transport)
}

/// Forwards the transport trait to the shared `Arc<RecordingTransport>` so the
/// measurement can inspect captured ciphertexts.
struct TransportShim(Arc<RecordingTransport>);
#[async_trait::async_trait]
impl ContextTransportProvider for TransportShim {
    fn is_connected(&self) -> bool {
        self.0.is_connected()
    }
    async fn publish_context(
        &self,
        id: &[u8; 32],
        params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        self.0.publish_context(id, params).await
    }
    async fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.delete_published(id).await
    }
    async fn send_message(&self, id: &[u8; 32], payload: &[u8]) -> Result<(), ContextError> {
        self.0.send_message(id, payload).await
    }
}

fn encrypted_params() -> ContextParams {
    ContextParams {
        ceiling: ceiling(),
        mode: ContextMode::Encrypted,
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice(), bob()],
        },
        ..ContextParams::default()
    }
}
fn broadcast_params() -> ContextParams {
    ContextParams {
        ceiling: ceiling(),
        mode: ContextMode::Broadcast,
        // Broadcast contexts only support full memory scope (no MLS group).
        memory_scope: MemoryScope::Full,
        ..ContextParams::default()
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Emits one measurement line. This is the data the >15% same-environment
/// rollback gate diffs before vs after a change.
fn report(op: &str, n: usize, elapsed: Duration) {
    let mean = elapsed / u32::try_from(n).expect("N fits u32");
    println!("perf_baseline op={op:<20} N={n:<2} total={elapsed:>12.3?} mean/op={mean:>12.3?}");
}

// ---------------------------------------------------------------------------
// Per-context setup helpers (NOT timed)
// ---------------------------------------------------------------------------

/// Creates an encrypted context whose only member is the creator.
async fn create_encrypted(m: &Arc<Supervisor>, id: &str) -> ContextHandle {
    m.create_context(id.to_owned(), encrypted_params(), alice(), None)
        .await
        .expect("create encrypted context")
}

/// Creates an encrypted context, adds `bob` through the real governance
/// `AddMember` path (propose + threshold vote), and seeds bob's pseudonym so an
/// encrypted send has a real fan-out target. Returns the creator's handle.
async fn create_two_member(m: &Arc<Supervisor>, id: &str) -> ContextHandle {
    let handle = create_encrypted(m, id).await;
    let sk_a = signing_key_for_did(&alice());
    let sk_b = signing_key_for_did(&bob());
    let (proposal, _events, _) = m
        .propose_governance_action(
            id,
            &alice(),
            GovernanceAction::AddMember {
                did: bob(),
                role: "member".into(),
            },
            &sk_a,
        )
        .await
        .expect("propose AddMember");
    m.vote_on_proposal(id, &proposal.proposal_id, &bob(), true, &sk_b)
        .await
        .expect("bob votes to reach threshold");
    m.seed_peer_pseudonym(id, bob(), [0x42u8; 32])
        .await
        .expect("seed bob pseudonym");
    handle
}

// ---------------------------------------------------------------------------
// Measurements — one per ADR-049 §Decision 14 operation.
// ---------------------------------------------------------------------------

/// `handshake` = welcome + `key_package` + `add_member`, via the real
/// `join_context` actor path. Setup (context creation) is untimed; the
/// `join_context` call is timed.
async fn measure_handshake(n: usize) {
    let (m, _t) = supervisor();
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        handles.push(create_encrypted(&m, &format!("perf-handshake-{n}-{i}")).await);
    }

    let start = Instant::now();
    for handle in &handles {
        let key_package = KeyPackage {
            owner_did: bob(),
            // Concrete-provider `cfg(test)` accommodation (ADR-049 §Consequences).
            mls_key_package_bytes: None,
        };
        m.join_context(handle, key_package, None, None)
            .await
            .expect("handshake (join_context) must succeed");
    }
    report("handshake", n, start.elapsed());
}

/// `send_message` — real encrypted send with a real fan-out target.
async fn measure_send_message(n: usize) {
    let (m, _t) = supervisor();
    m.register_local_did(alice())
        .await
        .expect("register local did");
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        handles.push(create_two_member(&m, &format!("perf-send-{n}-{i}")).await);
    }
    let sk_a = signing_key_for_did(&alice());

    let start = Instant::now();
    for handle in &handles {
        m.send_message(
            handle,
            &alice(),
            b"perf-baseline-payload",
            MessageSigner::Active(&sk_a),
            None,
            None,
        )
        .await
        .expect("send_message must succeed");
    }
    report("send_message", n, start.elapsed());
}

/// `deliver_incoming` — real `DeliverIncoming` actor command on a real captured
/// ciphertext. See the module docs: single-node this exercises the entire
/// receive pipeline and terminates at the MLS layer with the deterministic
/// own-message error (a cross-node-decryptable blob needs the two-node harness).
async fn measure_deliver_incoming(n: usize) {
    let (m, t) = supervisor();
    m.register_local_did(alice())
        .await
        .expect("register local did");
    // Build N contexts and capture one real ciphertext per context (setup).
    let sk_a = signing_key_for_did(&alice());
    let mut blobs = Vec::with_capacity(n);
    for i in 0..n {
        let id = format!("perf-deliver-{n}-{i}");
        let handle = create_two_member(&m, &id).await;
        t.take_blobs(); // discard any setup-phase sends
        m.send_message(
            &handle,
            &alice(),
            b"perf-baseline-inbound",
            MessageSigner::Active(&sk_a),
            None,
            None,
        )
        .await
        .expect("prime a real ciphertext to deliver");
        let (_routing, blob) = t
            .take_blobs()
            .into_iter()
            .next()
            .expect("send captured exactly one ciphertext");
        blobs.push((id, blob));
    }

    let start = Instant::now();
    for (id, blob) in &blobs {
        let outcome = m.deliver_commit_blob(id, blob.clone()).await;
        // The full receive pipeline (mailbox + local-member resolution + MLS
        // open attempt) ran. Single-node it deterministically reaches the MLS
        // layer's own-message rejection; a clean `Ok` requires a cross-node
        // ciphertext (two-node fullstack harness — unavailable here). Either
        // way the mailbox+receive-dispatch cost — what the rollback gate
        // compares — was measured. Anything other than a completed pipeline
        // (e.g. `ContextNotRegistered`) would mean the command surface broke.
        assert!(
            outcome.is_ok() || matches!(outcome, Err(ContextError::CryptoFailed(_))),
            "deliver_incoming pipeline must complete (Ok or the single-node \
             own-message CryptoFailed); got {outcome:?}"
        );
    }
    report("deliver_incoming", n, start.elapsed());
}

/// `governance_propose` — real `propose_governance_action` actor path.
async fn measure_governance_propose(n: usize) {
    let (m, _t) = supervisor();
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let id = format!("perf-gov-{n}-{i}");
        create_encrypted(&m, &id).await;
        ids.push(id);
    }
    let sk_a = signing_key_for_did(&alice());

    let start = Instant::now();
    for id in &ids {
        m.propose_governance_action(
            id,
            &alice(),
            GovernanceAction::AddMember {
                did: bob(),
                role: "member".into(),
            },
            &sk_a,
        )
        .await
        .expect("governance_propose must succeed");
    }
    report("governance_propose", n, start.elapsed());
}

/// `broadcast_publish` — real `PublishBroadcast` actor command through the
/// custody-generic dispatch shim.
async fn measure_broadcast_publish(n: usize) {
    let (m, _t) = supervisor();
    let custody = InMemoryKeyCustody::new();
    let key_handle = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("author signing key");
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let id = format!("perf-bcpub-{n}-{i}");
        m.create_context(id.clone(), broadcast_params(), alice(), None)
            .await
            .expect("create broadcast context");
        ids.push(id);
    }

    let start = Instant::now();
    for id in &ids {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::PublishBroadcast {
            payload: Box::new(PublishBroadcastPayload {
                context_id: id.clone(),
                author_did: alice(),
                payload: b"perf-baseline-broadcast".to_vec(),
                signing_key_handle: key_handle,
            }),
            reply: reply_tx,
        };
        m.dispatch_broadcast_command_with_custody(cmd, &custody)
            .await
            .expect("publish dispatch");
        reply_rx
            .await
            .expect("publish reply channel")
            .expect("broadcast_publish must succeed");
    }
    report("broadcast_publish", n, start.elapsed());
}

/// `broadcast_subscribe` — real `SubscribeBroadcast` actor command.
async fn measure_broadcast_subscribe(n: usize) {
    let (m, _t) = supervisor();
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let id = format!("perf-bcsub-{n}-{i}");
        m.create_context(id.clone(), broadcast_params(), alice(), None)
            .await
            .expect("create broadcast context");
        ids.push(id);
    }

    let start = Instant::now();
    for id in &ids {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::SubscribeBroadcast {
            payload: Box::new(SubscribeBroadcastPayload {
                context_id: id.clone(),
                subscriber_did: bob(),
                ucan: None,
                timestamp: 1_700_000_000,
            }),
            reply: reply_tx,
        };
        m.dispatch_broadcast_command(cmd)
            .await
            .expect("subscribe dispatch");
        reply_rx
            .await
            .expect("subscribe reply channel")
            .expect("broadcast_subscribe must succeed");
    }
    report("broadcast_subscribe", n, start.elapsed());
}

// ---------------------------------------------------------------------------
// Entry point — 6 operations × N∈{1,4,16} = 18 measurement points.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn perf_baseline() {
    println!(
        "\n=== ADR-049 Decision 14 perf baseline (6 ops × N{{1,4,16}} = 18 points) ===\n\
         Compare mean/op before vs after a change on the SAME machine; \
         a >15% regression on any (op, N) pair trips the rollback gate.\n"
    );
    for &n in &N_VALUES {
        measure_handshake(n).await;
    }
    for &n in &N_VALUES {
        measure_send_message(n).await;
    }
    for &n in &N_VALUES {
        measure_deliver_incoming(n).await;
    }
    for &n in &N_VALUES {
        measure_governance_propose(n).await;
    }
    for &n in &N_VALUES {
        measure_broadcast_publish(n).await;
    }
    for &n in &N_VALUES {
        measure_broadcast_subscribe(n).await;
    }
    println!("\n=== perf baseline complete: 18 points emitted ===\n");
}
