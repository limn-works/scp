# 16. Test Infrastructure

## 16.1 Overview

SCP's distributed protocol behavior — suppression detection, equivocation, multi-relay consistency, partitions, TTL enforcement, reorder buffers — requires testing under conditions that cannot be reproduced with unit tests or simple two-party integration tests. This section specifies a network simulation harness: the `scp-testing` crate, a workspace-level dev-dependency that provides in-process, deterministic, zero-I/O simulation of N relays, N identities, and M contexts with configurable topology, fault injection, and time control.

**Design principle: real protocol logic, simulated I/O.** The simulator uses real `scp-core` (MLS, envelopes, contexts, event logs), real `scp-transport::TransportManager`, and real `scp-platform` trait implementations (in-memory, from ADR-006). Only the transport adapters and clock are replaced with simulation-aware implementations. This tests actual protocol behavior, not mocked behavior.

**Determinism.** All randomness (key generation, fault injection, delay distribution) uses a `StdRng` from a single seed. Failing tests print their seed. Test logs record the seed for reproducibility across iterations.

## 16.2 Crate: `scp-testing`

New workspace member. Dev-dependency for all other SCP crates.

```
crates/
  scp-testing/
    Cargo.toml
    src/
      lib.rs
      clock.rs              # SimulatedClock, SimulatedTimerService
      relay/                 # InMemoryRelay, BlobStore, BehaviorMode
        mod.rs
        blob_store.rs        # BlobStore trait + InMemoryBlobStore
        behavior.rs          # BehaviorMode enum and fault injection
        subscription.rs      # SubscriptionRegistry
      transport.rs           # InMemoryTransport (implements TransportAdapter)
      simulator/             # NetworkSimulator, topology, fault injection
        mod.rs
        identity.rs          # SimulatedIdentity
        topology.rs          # NetworkTopology, LinkConfig, partition/heal
      builder.rs             # ScenarioBuilder
      assertions/            # Distributed invariant checks
        mod.rs
        merkle.rs            # assert_consistent_merkle_roots
        delivery.rs          # assert_complete_delivery
        suppression.rs       # assert_suppression_detected
        ordering.rs          # assert_correct_ordering
        privacy.rs           # assert_pseudonym_unlinkability
        blocking.rs          # assert_block_enforced
        epoch.rs             # assert_epoch_consistency
      presets.rs             # Canned scenarios
      conformance/           # Trait conformance test generators (macros)
        mod.rs
        transport.rs         # transport_conformance!()
        storage.rs           # storage_conformance!()
        key_custody.rs       # key_custody_conformance!()
        attestation.rs       # attestation_conformance!()
        push.rs              # push_conformance!()
        blob_store.rs        # blob_store_conformance!()
```

### Dependencies

```toml
[dependencies]
scp-core = { path = "../scp-core" }
scp-transport = { path = "../scp-transport" }
scp-platform = { path = "../scp-platform" }
tokio = { workspace = true }
futures = { workspace = true }
rand = { workspace = true }
serde = { workspace = true }
tracing = { workspace = true }
```

`scp-testing` depends on core, transport, and platform crates. It is never a non-dev dependency — no production code imports it.

## 16.3 Clock Trait

Defined in `scp-core`, not `scp-testing`. All time-dependent protocol components accept `Arc<dyn Clock>`.

```rust
/// scp-core/src/clock.rs

/// Monotonic wall clock abstraction.
/// Production: SystemClock (delegates to std::time).
/// Testing: SimulatedClock (manual advance, deterministic).
pub trait Clock: Send + Sync {
    /// Current wall-clock time as a Unix timestamp (seconds since epoch).
    fn now(&self) -> u64;

    /// Current wall-clock time with sub-second precision.
    fn now_millis(&self) -> u64;

    /// Register a callback to fire when the clock reaches `at` (Unix timestamp seconds).
    /// Returns a handle that can be used to cancel the timer.
    fn register_timer(&self, at: u64, callback: Box<dyn FnOnce() + Send>) -> TimerHandle;

    /// Cancel a previously registered timer.
    fn cancel_timer(&self, handle: TimerHandle);
}

/// Opaque handle for a registered timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerHandle(pub u64);
```

### SystemClock (production)

```rust
/// scp-core/src/clock.rs

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn register_timer(&self, at: u64, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        // Spawns a tokio::time::sleep_until task.
        // Production timers are real async tasks.
        // Implementation detail: uses tokio::spawn internally.
        todo!()
    }

    fn cancel_timer(&self, handle: TimerHandle) {
        // Cancels the tokio task associated with the handle.
        todo!()
    }
}
```

### SimulatedClock (testing)

```rust
/// scp-testing/src/clock.rs

pub struct SimulatedClock {
    current: AtomicU64,
    current_millis: AtomicU64,
    timers: Mutex<BTreeMap<u64, Vec<(TimerHandle, Box<dyn FnOnce() + Send>)>>>,
    next_handle: AtomicU64,
}

impl SimulatedClock {
    /// Create a new simulated clock starting at the given Unix timestamp.
    pub fn new(start: u64) -> Self;

    /// Advance the clock by `delta` seconds.
    /// Fires all registered timer callbacks whose `at` <= new current time,
    /// in chronological order. Callbacks registered by other callbacks during
    /// this advance are fired if their `at` <= new current time.
    pub fn advance(&self, delta: u64);

    /// Advance the clock by `delta` milliseconds.
    pub fn advance_millis(&self, delta: u64);

    /// Advance the clock to exactly the given timestamp.
    /// Fires all timers between current and target.
    pub fn advance_to(&self, target: u64);

    /// Return the number of pending (unfired) timers.
    pub fn pending_timers(&self) -> usize;
}

impl Clock for SimulatedClock { /* delegates to internal state */ }
```

**Usage.** All time-dependent components — TTL expiry, checkpoint intervals, gap timeouts (§9.8.5), cover traffic scheduling (§9.10.6), heartbeat intervals (§9.9.2), PCS update intervals (§9.7.3) — use the `Clock` trait. In tests, `SimulatedClock::advance(3600)` instantly fast-forwards one hour, firing all callbacks deterministically without waiting.

## 16.4 InMemoryRelay

Full ADR-004 relay protocol implemented in-memory. No WebSocket, no network I/O. Stores blobs by `routing_id`, manages subscriptions, enforces TTL, delivers to subscribers. Backed by a `BlobStore` trait for swappable storage.

### 16.4.1 BlobStore Trait

Defined in `scp-transport/native/` (not `scp-testing`), so the relay server can swap between backends without changing relay logic.

```rust
/// scp-transport/src/native/blob_store.rs

/// Storage backend for relay blobs.
/// Implementations: InMemoryBlobStore (testing/dev), SqliteBlobStore (small deployments),
/// RedbBlobStore (medium relays), and other backends (PostgreSQL, S3) without changing relay logic.
/// See §17.7 for the full first-party adapter roster.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Store a blob. Returns the blob_id (SHA-256 of blob content).
    /// `expires_at` is the Unix timestamp when this blob should be deleted.
    async fn store(
        &self,
        routing_id: &[u8; 32],
        blob: &[u8],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        expires_at: u64,
    ) -> Result<[u8; 32], BlobStoreError>;

    /// Retrieve a blob by routing_id and blob_id.
    async fn get(
        &self,
        routing_id: &[u8; 32],
        blob_id: &[u8; 32],
    ) -> Result<Option<StoredBlob>, BlobStoreError>;

    /// List blobs for a routing_id, optionally filtered by `since` timestamp.
    /// Returns blobs in ascending `stored_at` order (oldest first, per ADR-004 backfill ordering).
    async fn list(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: Option<u32>,
    ) -> Result<Vec<StoredBlob>, BlobStoreError>;

    /// Delete a specific blob. Returns true if the blob existed.
    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, BlobStoreError>;

    /// Delete all blobs whose `expires_at` <= `now`. Returns count deleted.
    async fn expire(&self, now: u64) -> Result<u64, BlobStoreError>;
}

/// A blob stored in the relay.
pub struct StoredBlob {
    pub routing_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub recipient_hint: Option<[u8; 32]>,
    pub blob_ttl: u32,
    pub stored_at: u64,
    pub expires_at: u64,
    pub blob: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum BlobStoreError {
    #[error("storage full")]
    StorageFull,
    #[error("blob too large: {size} bytes (max {max})")]
    BlobTooLarge { size: usize, max: usize },
    #[error("internal error: {0}")]
    Internal(String),
}
```

### 16.4.2 InMemoryBlobStore

Reference `BlobStore` implementation in `scp-testing`. HashMap-backed, no persistence. Used by `InMemoryRelay` and as the reference for `blob_store_conformance!()`.

```rust
/// scp-testing/src/relay/blob_store.rs

pub struct InMemoryBlobStore {
    /// Blobs keyed by blob_id, with routing_id index.
    blobs: RwLock<HashMap<[u8; 32], StoredBlob>>,
    /// Secondary index: routing_id -> Vec<blob_id>, ordered by stored_at.
    routing_index: RwLock<HashMap<[u8; 32], Vec<[u8; 32]>>>,
    /// Clock for timestamping.
    clock: Arc<dyn Clock>,
}

impl InMemoryBlobStore {
    pub fn new(clock: Arc<dyn Clock>) -> Self;
}
```

### 16.4.3 InMemoryRelay

```rust
/// scp-testing/src/relay/mod.rs

pub struct InMemoryRelay {
    store: Arc<dyn BlobStore>,
    subscriptions: SubscriptionRegistry,
    behavior: RwLock<BehaviorMode>,
    clock: Arc<dyn Clock>,
    rng: Mutex<StdRng>,
}

impl InMemoryRelay {
    pub fn new(clock: Arc<dyn Clock>, seed: u64) -> Self;
    pub fn with_behavior(clock: Arc<dyn Clock>, behavior: BehaviorMode, seed: u64) -> Self;

    /// Change behavior at runtime (simulate evolving adversarial conditions).
    pub fn set_behavior(&self, behavior: BehaviorMode);

    /// Current behavior mode.
    pub fn behavior(&self) -> BehaviorMode;

    /// Process a client message per ADR-004 protocol.
    /// Returns the relay response(s).
    pub async fn handle(&self, sender: SubscriberId, msg: ClientMessage) -> Vec<RelayMessage>;

    /// Run TTL expiry using the current clock time.
    pub async fn expire_blobs(&self) -> u64;

    /// Number of stored blobs (for assertions).
    pub async fn blob_count(&self) -> usize;

    /// Number of active subscriptions.
    pub fn subscription_count(&self) -> usize;
}
```

### 16.4.4 BehaviorMode

Each variant maps 1:1 to a relay threat from §9.9.1. Modes can be changed at runtime.

```rust
/// scp-testing/src/relay/behavior.rs

/// Relay fault injection modes mapped to §9.9.1 threat model.
#[derive(Debug, Clone)]
pub enum BehaviorMode {
    /// Honest relay. No faults.
    Normal,

    /// §9.9.1 "Drop messages (suppression)."
    /// Drops messages matching a predicate.
    Suppressing(SuppressionConfig),

    /// §9.9.1 "Equivocate: show different message histories to different members."
    /// Delivers different subsets of blobs to different subscribers.
    Equivocating(EquivocationConfig),

    /// §9.9.1 "Delay messages."
    /// Configurable latency before delivery.
    Delayed(DelayConfig),

    /// §9.9.1 "Replay messages."
    /// Re-delivers previously seen blobs.
    Replaying(ReplayConfig),

    /// §9.9.4 "Suppress MLS Commits."
    /// Targeted suppression of MLS Commit messages.
    /// Identified by a caller-provided predicate on blob content hash patterns.
    CommitSuppressing(CommitSuppressionConfig),

    /// ADR-004 DELETE is best-effort. This mode ignores DELETE requests,
    /// simulating a non-compliant relay.
    DeletionNonCompliant,

    /// Combine multiple modes. Applied in order; each mode's transform
    /// feeds into the next.
    Composite(Vec<BehaviorMode>),
}

/// Configures which messages are suppressed.
#[derive(Debug, Clone)]
pub struct SuppressionConfig {
    /// Drop messages to/from specific routing_ids.
    pub by_routing_id: Vec<[u8; 32]>,
    /// Drop messages to/from specific subscriber IDs.
    pub by_subscriber: Vec<SubscriberId>,
    /// Drop every Nth message (0 = disabled).
    pub every_nth: u32,
    /// Drop messages randomly with this probability (0.0-1.0).
    pub random_drop_rate: f64,
}

/// Configures equivocation behavior.
#[derive(Debug, Clone)]
pub struct EquivocationConfig {
    /// Map from subscriber ID to the set of routing_ids whose blobs are hidden from them.
    /// Subscribers not in this map see all blobs.
    pub hidden_from: HashMap<SubscriberId, Vec<[u8; 32]>>,
}

/// Configures delivery delay.
#[derive(Debug, Clone)]
pub struct DelayConfig {
    /// Minimum delay in milliseconds.
    pub min_ms: u64,
    /// Maximum delay in milliseconds.
    pub max_ms: u64,
    // Jitter is derived from the relay's seeded RNG.
}

/// Configures message replay.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Probability of replaying a previously delivered blob on each delivery (0.0-1.0).
    pub replay_probability: f64,
    /// Maximum number of times a single blob can be replayed.
    pub max_replays_per_blob: u32,
}

/// Configures selective MLS Commit suppression (§9.9.4).
#[derive(Debug, Clone)]
pub struct CommitSuppressionConfig {
    /// Predicate: suppress blobs from these routing_ids that match
    /// the commit blob size heuristic (Commits tend to be larger than
    /// application messages due to tree update path).
    pub target_routing_ids: Vec<[u8; 32]>,
    /// Suppress only delivery to these specific subscribers.
    /// If empty, suppress delivery to all subscribers.
    pub suppress_for: Vec<SubscriberId>,
}

/// Unique identifier for a subscriber connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberId(pub u64);
```

### 16.4.5 SubscriptionRegistry

```rust
/// scp-testing/src/relay/subscription.rs

/// Tracks active subscriptions and delivers blobs to subscribers.
pub struct SubscriptionRegistry {
    /// Map from routing_id to set of (SubscriberId, Sender<RelayMessage>).
    subscriptions: RwLock<HashMap<[u8; 32], Vec<(SubscriberId, mpsc::UnboundedSender<RelayMessage>)>>>,
    next_id: AtomicU64,
}

impl SubscriptionRegistry {
    pub fn new() -> Self;

    /// Register a new subscriber, returning their ID and a receiver stream.
    pub fn register(&self) -> (SubscriberId, mpsc::UnboundedReceiver<RelayMessage>);

    /// Subscribe a subscriber to a routing_id.
    pub fn subscribe(&self, subscriber: SubscriberId, routing_id: [u8; 32]);

    /// Unsubscribe a subscriber from a routing_id.
    pub fn unsubscribe(&self, subscriber: SubscriberId, routing_id: &[u8; 32]);

    /// Deliver a blob to all subscribers of a routing_id.
    /// Returns the number of subscribers delivered to.
    pub async fn deliver(&self, routing_id: &[u8; 32], message: RelayMessage) -> usize;

    /// Deliver a blob to a specific subscriber (directed delivery via recipient_hint).
    pub async fn deliver_to(
        &self,
        subscriber: SubscriberId,
        message: RelayMessage,
    ) -> bool;

    /// Number of active subscriptions across all routing_ids.
    pub fn count(&self) -> usize;

    /// Remove a subscriber entirely (disconnect).
    pub fn disconnect(&self, subscriber: SubscriberId);
}
```

## 16.5 InMemoryTransport

Implements `TransportAdapter` (ADR-005) backed by `Arc<InMemoryRelay>`. No WebSocket. Used by `SimulatedIdentity` instances to communicate through in-memory relays.

```rust
/// scp-testing/src/transport.rs

pub struct InMemoryTransport {
    relay: Arc<InMemoryRelay>,
    subscriber_id: SubscriberId,
    receiver: Mutex<Option<mpsc::UnboundedReceiver<RelayMessage>>>,
}

impl InMemoryTransport {
    /// Create a transport connected to the given in-memory relay.
    pub fn new(relay: Arc<InMemoryRelay>) -> Self;
}

#[async_trait]
impl TransportAdapter for InMemoryTransport {
    async fn send(&self, envelope: &OuterEnvelope) -> Result<BlobId, TransportError> {
        // Translate OuterEnvelope to ClientMessage::Publish, call relay.handle().
    }

    async fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<Pin<Box<dyn Stream<Item = TransportEvent> + Send>>, TransportError> {
        // Register subscription with relay, return stream that filters
        // RelayMessage::Blob for the given routing_id, wraps in TransportEvent, and deserializes.
    }

    async fn unsubscribe(&self, routing_id: &RoutingId) -> Result<(), TransportError> {
        // Unsubscribe from relay.
    }

    async fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<Vec<TransportEvent>, TransportError> {
        // Translate to ClientMessage::Query, collect results as TransportEvent.
    }

    async fn delete(&self, blob_id: &BlobId) -> Result<(), TransportError> {
        // Translate to ClientMessage::Delete.
    }
}
```

## 16.6 SimulatedIdentity

Wraps a real `Identity` (ADR-003) with in-memory platform adapters (ADR-006) and `InMemoryTransport` instances. Represents a single participant in the simulation.

```rust
/// scp-testing/src/simulator/identity.rs

pub struct SimulatedIdentity {
    /// The real SCP identity (DID, keys, document).
    pub identity: Identity,
    /// In-memory key custody (ADR-006).
    pub key_custody: Arc<InMemoryKeyCustody>,
    /// In-memory storage (ADR-006). Retained for direct conformance testing
    /// via `storage_conformance!()`.
    pub storage: Arc<InMemoryStorage>,
    /// Protocol-layer storage (§17.4). Wraps `self.storage` and provides typed
    /// domain methods for context state, membership, event logs, nonces, tools,
    /// sender keys, and all other protocol-level persistence.
    /// Used by protocol-level tests (§16.13.7, §16.13.8).
    pub protocol_store: Arc<ProtocolStore>,
    /// Transport manager with InMemoryTransport instances.
    pub transport: TransportManager,
    /// Clock shared with the simulator.
    pub clock: Arc<SimulatedClock>,
    /// Map from relay name to the InMemoryTransport connected to it.
    pub relay_transports: HashMap<String, Arc<InMemoryTransport>>,
}

impl SimulatedIdentity {
    /// DID string for this identity.
    pub fn did(&self) -> &str;

    /// Send a message in a context.
    pub async fn send(
        &self,
        context_id: &ContextId,
        payload: &[u8],
    ) -> Result<(), SimulationError>;

    /// Receive the next message from a context.
    /// Returns None if no message is available.
    pub async fn recv(
        &self,
        context_id: &ContextId,
    ) -> Result<Option<ReceivedMessage>, SimulationError>;

    /// Drain all pending messages from a context.
    pub async fn drain(
        &self,
        context_id: &ContextId,
    ) -> Result<Vec<ReceivedMessage>, SimulationError>;

    /// Access the event log for a context.
    pub fn event_log(&self, context_id: &ContextId) -> Option<&EventLog>;

    /// Access MLS group state for a context (for assertions).
    pub fn mls_epoch(&self, context_id: &ContextId) -> Option<u64>;
}
```

## 16.7 NetworkTopology

Maps identities to reachable relays. Supports dynamic partitioning and per-link configuration.

```rust
/// scp-testing/src/simulator/topology.rs

/// Network topology configuration.
pub struct NetworkTopology {
    /// Map from identity DID to set of reachable relay names.
    reachability: RwLock<HashMap<String, HashSet<String>>>,
    /// Per-link configuration (identity, relay) -> LinkConfig.
    link_configs: RwLock<HashMap<(String, String), LinkConfig>>,
}

/// Configuration for a single network link (identity <-> relay).
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Additional latency in milliseconds (on top of relay's DelayConfig).
    pub latency_ms: u64,
    /// Packet loss probability (0.0-1.0). Independent of relay's SuppressionConfig.
    pub packet_loss: f64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        LinkConfig { latency_ms: 0, packet_loss: 0.0 }
    }
}

impl NetworkTopology {
    pub fn new() -> Self;

    /// Connect an identity to a relay (bidirectional).
    pub fn connect(&self, identity_did: &str, relay_name: &str);

    /// Connect an identity to a relay with specific link configuration.
    pub fn connect_with(&self, identity_did: &str, relay_name: &str, config: LinkConfig);

    /// Disconnect an identity from a relay (partition).
    pub fn partition(&self, identity_did: &str, relay_name: &str);

    /// Disconnect an identity from ALL relays (full isolation).
    pub fn isolate(&self, identity_did: &str);

    /// Restore an identity's connection to a relay.
    pub fn heal(&self, identity_did: &str, relay_name: &str);

    /// Restore an identity's connections to all relays.
    pub fn heal_all(&self, identity_did: &str);

    /// Check if an identity can reach a relay.
    pub fn can_reach(&self, identity_did: &str, relay_name: &str) -> bool;

    /// Get the set of relays reachable by an identity.
    pub fn reachable_relays(&self, identity_did: &str) -> HashSet<String>;

    /// Get the link config for a specific (identity, relay) pair.
    pub fn link_config(&self, identity_did: &str, relay_name: &str) -> LinkConfig;
}
```

## 16.8 NetworkSimulator

Orchestrator. Owns relays, identities, topology, and clock. Provides the entry point for running simulated scenarios.

```rust
/// scp-testing/src/simulator/mod.rs

pub struct NetworkSimulator {
    /// Shared simulated clock.
    pub clock: Arc<SimulatedClock>,
    /// Named relays.
    pub relays: HashMap<String, Arc<InMemoryRelay>>,
    /// Simulated identities, keyed by DID.
    pub identities: HashMap<String, SimulatedIdentity>,
    /// Network topology.
    pub topology: NetworkTopology,
    /// RNG seed used to create this simulator.
    pub seed: u64,
}

impl NetworkSimulator {
    /// Advance the simulated clock by `delta` seconds.
    /// Fires timers, processes delayed deliveries, runs TTL expiry.
    pub async fn advance_time(&self, delta: u64);

    /// Advance the simulated clock by `delta` milliseconds.
    pub async fn advance_time_millis(&self, delta: u64);

    /// Get a relay by name.
    pub fn relay(&self, name: &str) -> Option<&Arc<InMemoryRelay>>;

    /// Get a simulated identity by DID.
    pub fn identity(&self, did: &str) -> Option<&SimulatedIdentity>;

    /// Get a mutable reference to a simulated identity.
    pub fn identity_mut(&mut self, did: &str) -> Option<&mut SimulatedIdentity>;

    /// Run TTL expiry on all relays.
    pub async fn expire_all(&self) -> u64;

    /// Change a relay's behavior mode at runtime.
    pub fn set_relay_behavior(&self, relay_name: &str, behavior: BehaviorMode);

    /// Partition an identity from a relay.
    pub fn partition(&self, identity_did: &str, relay_name: &str);

    /// Heal a partition.
    pub fn heal(&self, identity_did: &str, relay_name: &str);

    /// Total blobs across all relays (for assertions).
    pub async fn total_blobs(&self) -> usize;
}
```

## 16.9 ScenarioBuilder

Fluent builder API for constructing fully initialized simulations. `build()` returns a `NetworkSimulator` with identities created, contexts formed, MLS groups established, and sender keys distributed.

```rust
/// scp-testing/src/builder.rs

pub struct ScenarioBuilder {
    seed: u64,
    clock_start: u64,
    relays: Vec<RelaySpec>,
    identities: Vec<IdentitySpec>,
    contexts: Vec<ContextSpec>,
    topology: Vec<(String, String)>,  // (identity_name, relay_name) connections
}

/// Specification for a relay in the scenario.
#[derive(Debug, Clone)]
pub struct RelaySpec {
    pub name: String,
    pub behavior: BehaviorMode,
}

/// Specification for an identity in the scenario.
#[derive(Debug, Clone)]
pub struct IdentitySpec {
    pub name: String,
}

/// Specification for a context in the scenario.
#[derive(Debug, Clone)]
pub struct ContextSpec {
    pub name: String,
    /// Identity names of context members. First is the creator.
    pub members: Vec<String>,
    /// Capability ceiling.
    pub ceiling: Vec<String>,
    /// TTL in seconds (0 = no expiry).
    pub ttl: u32,
}

impl ScenarioBuilder {
    /// Create a new builder with a deterministic seed.
    pub fn new(seed: u64) -> Self;

    /// Set the simulated clock start time (Unix timestamp).
    /// Default: 1_700_000_000 (Nov 2023, arbitrary fixed point).
    pub fn clock_start(mut self, start: u64) -> Self;

    /// Add a relay with default (Normal) behavior.
    pub fn relay(mut self, name: &str) -> Self;

    /// Add a relay with specific behavior.
    pub fn relay_with(mut self, name: &str, behavior: BehaviorMode) -> Self;

    /// Add an identity.
    pub fn identity(mut self, name: &str) -> Self;

    /// Add a context with the given members.
    /// The first member is the creator.
    pub fn context(mut self, name: &str, members: &[&str]) -> Self;

    /// Add a context with full configuration.
    pub fn context_with(mut self, spec: ContextSpec) -> Self;

    /// Connect an identity to a relay.
    pub fn connect(mut self, identity: &str, relay: &str) -> Self;

    /// Connect all identities to all relays (full mesh).
    pub fn full_mesh(mut self) -> Self;

    /// Build the simulator.
    ///
    /// This performs all setup:
    /// 1. Creates the SimulatedClock at clock_start.
    /// 2. Creates InMemoryRelay instances with specified behaviors.
    /// 3. Creates SimulatedIdentity instances with InMemoryKeyCustody, InMemoryStorage,
    ///    ProtocolStore (wrapping InMemoryStorage, §17.4), and InMemoryTransport
    ///    instances connected to reachable relays.
    /// 4. Creates MLS groups for each context.
    /// 5. Adds members to MLS groups (Welcome + Commit flow).
    /// 6. Distributes sender keys to all members.
    /// 7. Configures the NetworkTopology.
    ///
    /// Returns a fully initialized NetworkSimulator ready for test assertions.
    pub async fn build(self) -> Result<NetworkSimulator, SimulationError>;
}
```

**Example usage:**

```rust
#[tokio::test]
async fn test_suppression_detection() {
    let sim = ScenarioBuilder::new(42)
        .relay("honest")
        .relay_with("evil", BehaviorMode::Suppressing(SuppressionConfig {
            by_routing_id: vec![],
            by_subscriber: vec![],
            every_nth: 3,      // drop every 3rd message
            random_drop_rate: 0.0,
        }))
        .identity("alice")
        .identity("bob")
        .context("chat", &["alice", "bob"])
        .connect("alice", "honest")
        .connect("alice", "evil")
        .connect("bob", "honest")
        .connect("bob", "evil")
        .build()
        .await
        .unwrap();

    let alice = sim.identity("alice").unwrap();
    let bob = sim.identity("bob").unwrap();

    // Alice sends 10 messages
    for i in 0..10 {
        alice.send(&ctx_id, format!("msg {i}").as_bytes()).await.unwrap();
    }

    // Bob should detect gaps from the evil relay
    let messages = bob.drain(&ctx_id).await.unwrap();
    assert_suppression_detected(&sim, "bob", "evil").await;
}
```

## 16.10 Assertion Library

Distributed invariant checks that verify protocol correctness across multiple identities, relays, and contexts.

### 16.10.1 Merkle Consistency

```rust
/// scp-testing/src/assertions/merkle.rs

/// Verify that all members of a context have identical Merkle event log roots.
/// Tolerance: allows `max_drift` events of difference (for in-flight messages).
///
/// Maps to: §9.9.3 Relay Consistency Protocol — checkpoint comparison.
pub async fn assert_consistent_merkle_roots(
    sim: &NetworkSimulator,
    context_id: &ContextId,
    max_drift: u64,
) -> Result<(), AssertionError>;
```

### 16.10.2 Complete Delivery

```rust
/// scp-testing/src/assertions/delivery.rs

/// Verify that all messages sent in a context were received by all members.
/// Accounts for suppression (records gaps) but verifies that the protocol's
/// multi-relay fallback or suppression detection compensated.
///
/// Maps to: §9.9.2 Suppression Detection — multi-relay cross-check.
pub async fn assert_complete_delivery(
    sim: &NetworkSimulator,
    context_id: &ContextId,
) -> Result<(), AssertionError>;

/// Verify that a specific sender's messages were all received by a specific recipient.
pub async fn assert_delivery_between(
    sim: &NetworkSimulator,
    context_id: &ContextId,
    sender_did: &str,
    recipient_did: &str,
) -> Result<(), AssertionError>;
```

### 16.10.3 Suppression Detection

```rust
/// scp-testing/src/assertions/suppression.rs

/// Verify that the given identity detected suppression from the given relay.
/// Checks the identity's suppression alert log.
///
/// Maps to: §9.8.5 gap timeout → suppression alert, §9.9.2 multi-relay cross-check.
pub async fn assert_suppression_detected(
    sim: &NetworkSimulator,
    identity_did: &str,
    relay_name: &str,
) -> Result<(), AssertionError>;

/// Verify that NO suppression was detected by any identity (for honest relay tests).
pub async fn assert_no_suppression_detected(
    sim: &NetworkSimulator,
    context_id: &ContextId,
) -> Result<(), AssertionError>;
```

### 16.10.4 Correct Ordering

```rust
/// scp-testing/src/assertions/ordering.rs

/// Verify that messages were delivered to the application layer in correct
/// (epoch, generation, timestamp) order per §9.8.3.
/// Checks that the reorder buffer (§9.8.5) produced the correct sequence.
///
/// Maps to: §9.8.3 Message Ordering, §9.8.5 Reorder Buffer.
pub async fn assert_correct_ordering(
    sim: &NetworkSimulator,
    context_id: &ContextId,
    recipient_did: &str,
) -> Result<(), AssertionError>;
```

### 16.10.5 Pseudonym Unlinkability

```rust
/// scp-testing/src/assertions/privacy.rs

/// Verify that the routing_ids used by an identity across different contexts
/// are cryptographically unlinkable. Checks that no two routing_ids share
/// a derivable relationship without the identity's private key.
///
/// Maps to: ADR-002 pseudonym derivation, §9.10.4 per-context pseudonyms.
pub async fn assert_pseudonym_unlinkability(
    sim: &NetworkSimulator,
    identity_did: &str,
    context_ids: &[ContextId],
) -> Result<(), AssertionError>;
```

### 16.10.6 Block Enforcement

```rust
/// scp-testing/src/assertions/blocking.rs

/// Verify that after identity A blocks identity B in a context:
/// 1. B cannot decrypt A's new messages (sender key rotated, §9.16 / ADR-007).
/// 2. A cannot decrypt B's new messages (mutual block notification processed).
/// 3. Other members can still decrypt messages from both A and B.
///
/// Maps to: ADR-007 sender-side key layer, §9.16 blocking protocol.
pub async fn assert_block_enforced(
    sim: &NetworkSimulator,
    context_id: &ContextId,
    blocker_did: &str,
    blocked_did: &str,
) -> Result<(), AssertionError>;
```

### 16.10.7 Epoch Consistency

```rust
/// scp-testing/src/assertions/epoch.rs

/// Verify that all members of a context are on the same MLS epoch.
/// Tolerance: allows `max_behind` epochs of difference (for in-flight Commits).
///
/// Maps to: §9.9.3 checkpoint comparison — epoch field, §9.9.4 Commit suppression.
pub async fn assert_epoch_consistency(
    sim: &NetworkSimulator,
    context_id: &ContextId,
    max_behind: u64,
) -> Result<(), AssertionError>;
```

### 16.10.8 Error Type

```rust
/// scp-testing/src/assertions/mod.rs

#[derive(Debug, thiserror::Error)]
pub enum AssertionError {
    #[error("Merkle root mismatch: {member_a} has root {root_a:?} (events: {count_a}), {member_b} has root {root_b:?} (events: {count_b})")]
    MerkleRootMismatch {
        member_a: String, root_a: [u8; 32], count_a: u64,
        member_b: String, root_b: [u8; 32], count_b: u64,
    },

    #[error("Incomplete delivery: {sender} sent {sent} messages, {recipient} received {received}")]
    IncompleteDelivery { sender: String, recipient: String, sent: u64, received: u64 },

    #[error("Expected suppression detection by {identity} from relay {relay}, but none recorded")]
    SuppressionNotDetected { identity: String, relay: String },

    #[error("Unexpected suppression detected by {identity} from relay {relay}")]
    UnexpectedSuppression { identity: String, relay: String },

    #[error("Ordering violation: {recipient} received message seq {received_seq} before {expected_seq} from {sender}")]
    OrderingViolation { recipient: String, sender: String, expected_seq: u64, received_seq: u64 },

    #[error("Pseudonym linkability: routing_ids for {identity} in contexts {ctx_a} and {ctx_b} are linkable")]
    PseudonymLinkable { identity: String, ctx_a: String, ctx_b: String },

    #[error("Block not enforced: {blocked} can still decrypt messages from {blocker} in context {context}")]
    BlockNotEnforced { blocker: String, blocked: String, context: String },

    #[error("Epoch inconsistency: {member_a} is on epoch {epoch_a}, {member_b} is on epoch {epoch_b}")]
    EpochInconsistency { member_a: String, epoch_a: u64, member_b: String, epoch_b: u64 },

    #[error("Simulation error: {0}")]
    Simulation(#[from] SimulationError),
}
```

## 16.11 Preset Scenarios

One-liner factory functions that return fully configured `NetworkSimulator` instances for common test patterns.

```rust
/// scp-testing/src/presets.rs

/// Two identities, one relay, one context.
/// The baseline scenario. Everything should work perfectly.
pub async fn two_party_basic(seed: u64) -> NetworkSimulator;

/// Five identities, one relay, one context.
/// Tests group operations (add/remove), epoch management, sender key distribution.
pub async fn five_party_group(seed: u64) -> NetworkSimulator;

/// Two identities, two relays (one honest, one suppressing every 3rd message),
/// one context. Both identities connected to both relays.
/// Tests: suppression detection (§9.9.2), multi-relay cross-check.
pub async fn suppression_scenario(seed: u64) -> NetworkSimulator;

/// Three identities, two relays (one honest, one equivocating),
/// one context. All identities connected to both relays.
/// Tests: equivocation detection (§9.9.3), Merkle root comparison.
pub async fn equivocation_scenario(seed: u64) -> NetworkSimulator;

/// Three identities, two relays, one context.
/// Identity C is connected only to relay 2, identities A and B only to relay 1.
/// Tests: partition behavior, message loss, reconnection.
pub async fn relay_partitioned(seed: u64) -> NetworkSimulator;

/// Two identities, one relay, one context with TTL = 300 seconds.
/// Tests: TTL expiry, SimulatedClock::advance, blob deletion.
pub async fn ephemeral_ttl(seed: u64) -> NetworkSimulator;

/// Three identities, one relay, one context.
/// Identity A blocks identity B.
/// Tests: sender key rotation, mutual block notification, block enforcement (ADR-007).
pub async fn blocking_scenario(seed: u64) -> NetworkSimulator;

/// Two identities, one relay with Delayed behavior (100-500ms jitter),
/// one context.
/// Tests: reorder buffer (§9.8.5), correct ordering after reorder.
pub async fn reorder_scenario(seed: u64) -> NetworkSimulator;
```

## 16.12 Trait Conformance Test Generators

Reusable test suites for each core trait, ensuring every implementation satisfies the same contract. Each generator is a Rust macro that takes an implementation constructor and expands into a `#[cfg(test)] mod` with all tests.

The in-memory implementations are the reference — they pass the conformance suite first. Every production adapter must also pass.

### 16.12.1 `transport_conformance!()`

```rust
/// scp-testing/src/conformance/transport.rs

/// Generates a test module verifying TransportAdapter (ADR-005) contract.
///
/// Usage:
/// ```rust
/// #[cfg(test)]
/// transport_conformance!(|| InMemoryTransport::new_test_instance());
/// ```
#[macro_export]
macro_rules! transport_conformance {
    ($constructor:expr) => {
        #[cfg(test)]
        mod transport_conformance {
            use super::*;

            #[tokio::test]
            async fn send_subscribe_roundtrip() {
                // Send an envelope, subscribe to its routing_id,
                // verify the envelope is delivered.
            }

            #[tokio::test]
            async fn backfill_with_since() {
                // Store 3 envelopes, subscribe with since = timestamp of 2nd,
                // verify only 2nd and 3rd are backfilled.
            }

            #[tokio::test]
            async fn unsubscribe_stops_delivery() {
                // Subscribe, unsubscribe, send another envelope,
                // verify it is NOT delivered to the unsubscribed stream.
            }

            #[tokio::test]
            async fn query_returns_stored() {
                // Store envelopes, query, verify results match.
            }

            #[tokio::test]
            async fn delete_removes_blob() {
                // Store, delete, query, verify blob is gone.
            }

            #[tokio::test]
            async fn deduplication_by_blob_id() {
                // Send the same envelope twice, subscribe,
                // verify only one delivery (or two — transport layer
                // may not dedup; higher layers handle it per §9.8.2(b)).
                // This test documents the transport's dedup behavior.
            }
        }
    };
}
```

### 16.12.2 `storage_conformance!()`

```rust
/// scp-testing/src/conformance/storage.rs

/// Generates a test module verifying the `Storage` trait contract
/// (ADR-006, expanded with `delete_prefix` and `exists` in §17.2).
///
/// Usage:
/// ```rust
/// #[cfg(test)]
/// storage_conformance!(|| InMemoryStorage::new());
/// ```
#[macro_export]
macro_rules! storage_conformance {
    ($constructor:expr) => {
        #[cfg(test)]
        mod storage_conformance {
            use super::*;

            #[tokio::test]
            async fn store_retrieve_roundtrip() {
                // Store bytes under a key, retrieve, verify match.
            }

            #[tokio::test]
            async fn retrieve_missing_returns_none() {
                // Retrieve a key that was never stored, verify None.
            }

            #[tokio::test]
            async fn delete_removes() {
                // Store, delete, retrieve, verify None.
            }

            #[tokio::test]
            async fn list_keys_with_prefix() {
                // Store "ctx/a", "ctx/b", "other/c",
                // list_keys("ctx/"), verify ["ctx/a", "ctx/b"].
            }

            #[tokio::test]
            async fn delete_prefix_removes_matching() {
                // Store "ctx/a/1", "ctx/a/2", "ctx/b/1", "other/x".
                // delete_prefix("ctx/a/") -> returns 2.
                // Verify "ctx/a/1" and "ctx/a/2" are gone.
                // Verify "ctx/b/1" and "other/x" still exist.
            }

            #[tokio::test]
            async fn delete_prefix_returns_zero_for_no_match() {
                // delete_prefix("nonexistent/") -> returns 0.
            }

            #[tokio::test]
            async fn exists_returns_true_for_stored() {
                // Store "key", exists("key") -> true.
            }

            #[tokio::test]
            async fn exists_returns_false_for_missing() {
                // exists("missing") -> false.
            }

            #[tokio::test]
            async fn exists_returns_false_after_delete() {
                // Store "key", delete "key", exists("key") -> false.
            }

            #[tokio::test]
            async fn list_keys_returns_sorted() {
                // Store keys "c", "a", "b".
                // list_keys("") -> ["a", "b", "c"].
            }

            #[tokio::test]
            async fn list_keys_prefix_returns_sorted() {
                // Store "ctx/z", "ctx/a", "ctx/m", "other/x".
                // list_keys("ctx/") -> ["ctx/a", "ctx/m", "ctx/z"].
            }

            #[tokio::test]
            async fn concurrent_access() {
                // Spawn 10 tasks that store/retrieve concurrently.
                // Verify no panics and all operations complete.
            }
        }
    };
}
```

### 16.12.3 `key_custody_conformance!()`

```rust
/// scp-testing/src/conformance/key_custody.rs

/// Generates a test module verifying KeyCustody (ADR-006) contract.
///
/// Usage:
/// ```rust
/// #[cfg(test)]
/// key_custody_conformance!(|| InMemoryKeyCustody::new());
/// ```
#[macro_export]
macro_rules! key_custody_conformance {
    ($constructor:expr) => {
        #[cfg(test)]
        mod key_custody_conformance {
            use super::*;

            #[tokio::test]
            async fn generate_sign_verify_roundtrip() {
                // Generate keypair, sign data, verify signature with public key.
            }

            #[tokio::test]
            async fn destroy_prevents_sign() {
                // Generate keypair, destroy, attempt sign, verify error.
            }

            #[tokio::test]
            async fn distinct_handles_for_distinct_keys() {
                // Generate two keypairs, verify handles are different,
                // verify public keys are different.
            }

            #[tokio::test]
            async fn sign_with_invalid_handle_errors() {
                // Attempt sign with a fabricated handle, verify error.
            }
        }
    };
}
```

### 16.12.4 `attestation_conformance!()`

```rust
/// scp-testing/src/conformance/attestation.rs

/// Generates a test module verifying DeviceAttestation (ADR-006) contract.
///
/// Usage:
/// ```rust
/// #[cfg(test)]
/// attestation_conformance!(|| InMemoryDeviceAttestation::new());
/// ```
#[macro_export]
macro_rules! attestation_conformance {
    ($constructor:expr) => {
        #[cfg(test)]
        mod attestation_conformance {
            use super::*;

            #[tokio::test]
            async fn attest_verify_roundtrip() {
                // Attest, verify, assert true.
            }

            #[tokio::test]
            async fn invalid_token_rejected() {
                // Create a fabricated token, verify, assert false.
            }
        }
    };
}
```

### 16.12.5 `push_conformance!()`

```rust
/// scp-testing/src/conformance/push.rs

/// Generates a test module verifying Push (ADR-006) contract.
///
/// Usage:
/// ```rust
/// #[cfg(test)]
/// push_conformance!(|| InMemoryPush::new());
/// ```
#[macro_export]
macro_rules! push_conformance {
    ($constructor:expr) => {
        #[cfg(test)]
        mod push_conformance {
            use super::*;

            #[tokio::test]
            async fn register_returns_token() {
                // Register, verify token is non-empty.
            }

            #[tokio::test]
            async fn handle_notification_returns_wake() {
                // Register, handle_notification with test payload,
                // verify WakeSignal is returned.
            }
        }
    };
}
```

### 16.12.6 `blob_store_conformance!()`

```rust
/// scp-testing/src/conformance/blob_store.rs

/// Generates a test module verifying the `BlobStore` trait contract
/// (§16.4.1; see §17.7 for the full first-party adapter roster).
///
/// Usage:
/// ```rust
/// #[cfg(test)]
/// blob_store_conformance!(|| InMemoryBlobStore::new(clock.clone()));
/// ```
#[macro_export]
macro_rules! blob_store_conformance {
    ($constructor:expr) => {
        #[cfg(test)]
        mod blob_store_conformance {
            use super::*;

            #[tokio::test]
            async fn store_retrieve_roundtrip() {
                // Store a blob, retrieve by (routing_id, blob_id), verify match.
            }

            #[tokio::test]
            async fn retrieve_missing_returns_none() {
                // Retrieve a blob_id that was never stored, verify None.
            }

            #[tokio::test]
            async fn ttl_expiry() {
                // Store a blob with TTL=60, advance clock past expiry,
                // call expire(), verify blob is gone.
            }

            #[tokio::test]
            async fn list_by_routing_id() {
                // Store 3 blobs with same routing_id, 1 with different,
                // list by routing_id, verify 3 returned in stored_at order.
            }

            #[tokio::test]
            async fn list_with_since_filter() {
                // Store 3 blobs at different times, list with since,
                // verify only blobs after since are returned.
            }

            #[tokio::test]
            async fn delete_removes_blob() {
                // Store, delete, retrieve, verify None.
                // Also verify list no longer includes it.
            }

            #[tokio::test]
            async fn store_returns_sha256_blob_id() {
                // Store a blob, verify returned blob_id == SHA-256(blob content).
            }

            #[tokio::test]
            async fn concurrent_store_and_expire() {
                // Spawn concurrent store and expire operations,
                // verify no panics and consistency.
            }
        }
    };
}
```

## 16.13 Acceptance Criteria for the Harness Itself

Meta-tests that verify the simulation framework is correct before trusting it for protocol tests.

### 16.13.1 InMemoryRelay Correctness

| Test | Verifies |
|------|----------|
| `relay_stores_and_delivers` | PUBLISH stores blob, subscriber receives it |
| `relay_respects_ttl` | Blob is retrievable before TTL, gone after `expire_blobs()` with advanced clock |
| `relay_subscribe_backfill` | SUBSCRIBE with `since` delivers stored blobs newer than `since` in ascending order |
| `relay_unsubscribe_stops_delivery` | UNSUBSCRIBE prevents further deliveries |
| `relay_query_returns_stored` | QUERY returns matching blobs without creating a subscription |
| `relay_delete_removes` | DELETE removes a blob from storage |
| `relay_suppression_mode` | Suppressing relay drops messages per configured predicate |
| `relay_equivocation_mode` | Equivocating relay shows different histories to different subscribers |
| `relay_delay_mode` | Delayed relay adds latency before delivery |
| `relay_replay_mode` | Replaying relay re-delivers blobs per configured probability |
| `relay_commit_suppression_mode` | CommitSuppressing relay drops blobs matching target routing_ids |
| `relay_deletion_noncompliant_mode` | DeletionNonCompliant relay ignores DELETE |
| `relay_composite_mode` | Composite mode applies multiple behaviors in sequence |
| `relay_behavior_change_at_runtime` | `set_behavior()` changes relay behavior for subsequent operations |

### 16.13.2 InMemoryTransport Correctness

| Test | Verifies |
|------|----------|
| `transport_implements_adapter_trait` | InMemoryTransport satisfies `TransportAdapter` — passes `transport_conformance!()` |
| `transport_routes_to_relay` | Envelopes sent via transport arrive at the backing relay |
| `transport_streams_subscriptions` | Subscription stream yields envelopes as relay delivers them |

### 16.13.3 SimulatedClock Correctness

| Test | Verifies |
|------|----------|
| `clock_advance_fires_timers` | Registering a timer at T+60, advancing by 60, fires the callback |
| `clock_advance_fires_multiple_in_order` | Timers at T+10, T+20, T+30 fire in order when advancing by 30 |
| `clock_timer_registered_during_advance` | A timer registered by a callback during `advance()` fires if its `at` <= target |
| `clock_cancel_timer` | Cancelled timer does not fire |
| `clock_advance_to` | `advance_to(target)` fires all timers between current and target |

### 16.13.4 NetworkTopology Correctness

| Test | Verifies |
|------|----------|
| `topology_connect_and_reach` | Connected identity can reach relay |
| `topology_partition_blocks` | Partitioned identity cannot reach relay |
| `topology_isolate_blocks_all` | Isolated identity cannot reach any relay |
| `topology_heal_restores` | Healed partition restores reachability |

### 16.13.5 ScenarioBuilder Correctness

| Test | Verifies |
|------|----------|
| `builder_creates_identities` | All specified identities exist in the simulator |
| `builder_creates_relays` | All specified relays exist with correct behaviors |
| `builder_creates_contexts` | All specified contexts have MLS groups with correct members |
| `builder_distributes_sender_keys` | All context members have sender keys for all other members |
| `builder_full_mesh_connects_all` | `full_mesh()` connects every identity to every relay |
| `builder_deterministic_with_same_seed` | Same seed produces identical simulator state (DID strings, key material) |

### 16.13.6 Determinism

| Test | Verifies |
|------|----------|
| `same_seed_same_results` | Running an identical scenario with the same seed produces identical outcomes (messages, ordering, fault injection decisions) |
| `different_seed_different_faults` | Different seeds produce different fault injection patterns |
| `seed_printed_on_failure` | Test failure output includes the seed for reproduction |

### 16.13.7 ProtocolStore Correctness

Tests that verify the protocol layer's typed domain methods (§17.4) correctly persist and retrieve state through the `Storage` trait. These exercise key conventions (§17.3), serialization (§17.5), and the `ProtocolStore` domain API — not the storage adapters themselves. Run against `InMemoryStorage` (fast, deterministic); also gated against `SqliteStorage` in Phase 2.

| Test | Verifies |
|------|----------|
| `context_lifecycle_persists` | Create context, store state, reload from storage, verify state matches |
| `context_delete_removes_all` | Create context with members, events, tools. `delete_context` removes everything. Verify no keys with context prefix remain |
| `event_log_range_query` | Append 100 events, load range 50-75, verify correct events in order |
| `nonce_replay_rejected` | Record nonce, attempt same nonce again, verify rejection |
| `nonce_pruning` | Record nonce with short expiry, advance clock, prune, verify nonce is gone |
| `membership_roundtrip` | Store membership, load, verify role matches |
| `sender_key_roundtrip` | Store sender key, load, verify key matches |
| `did_cache_roundtrip` | Cache DID document, load, verify matches |
| `relay_score_list` | Store scores for 3 relays, list all, verify all returned |

### 16.13.8 MlsStorageBridge Correctness

Tests that verify OpenMLS group state persists correctly through the `MlsStorageBridge` → `ProtocolStore` → `Storage` chain (§17.9). These confirm that the bridge's key prefix mapping and serialization produce correct roundtrips for MLS-internal state.

| Test | Verifies |
|------|----------|
| `mls_group_state_roundtrip` | Create MLS group, persist via bridge, reload, verify group state matches |
| `mls_state_isolated_per_context` | Two contexts with MLS groups, verify state does not leak between them |

### 16.13.9 Assertion Library Meta-Tests

The assertion functions (§16.10) are trusted by all protocol tests — a bug in an assertion could silently mask protocol failures. Each assertion function is independently verified with crafted simulator state: one test where the invariant holds (assertion passes) and one where it is violated (assertion returns the correct error variant).

| Test | Verifies |
|------|----------|
| `merkle_assertion_passes_on_consistent` | `assert_consistent_merkle_roots` passes when all members share the same root |
| `merkle_assertion_fails_on_divergent` | `assert_consistent_merkle_roots` returns `MerkleRootMismatch` when roots differ beyond `max_drift` |
| `delivery_assertion_passes_on_complete` | `assert_complete_delivery` passes when all sent messages are received |
| `delivery_assertion_fails_on_missing` | `assert_complete_delivery` returns `IncompleteDelivery` when messages are lost |
| `suppression_assertion_passes_on_detected` | `assert_suppression_detected` passes when identity has a suppression alert for the relay |
| `suppression_assertion_fails_on_undetected` | `assert_suppression_detected` returns `SuppressionNotDetected` when no alert exists |
| `no_suppression_assertion_fails_on_unexpected` | `assert_no_suppression_detected` returns `UnexpectedSuppression` when an alert exists |
| `ordering_assertion_passes_on_correct` | `assert_correct_ordering` passes when messages are in (epoch, generation, timestamp) order |
| `ordering_assertion_fails_on_reorder` | `assert_correct_ordering` returns `OrderingViolation` when messages are misordered |
| `pseudonym_assertion_passes_on_unlinkable` | `assert_pseudonym_unlinkability` passes when routing IDs are derived independently |
| `pseudonym_assertion_fails_on_linkable` | `assert_pseudonym_unlinkability` returns `PseudonymLinkable` when routing IDs share a derivable relationship |
| `block_assertion_passes_on_enforced` | `assert_block_enforced` passes when blocked identity cannot decrypt |
| `block_assertion_fails_on_unenforced` | `assert_block_enforced` returns `BlockNotEnforced` when blocked identity can still decrypt |
| `epoch_assertion_passes_on_consistent` | `assert_epoch_consistency` passes when members are within `max_behind` epochs |
| `epoch_assertion_fails_on_divergent` | `assert_epoch_consistency` returns `EpochInconsistency` when epoch gap exceeds tolerance |

### 16.13.10 Preset Scenarios

All preset scenarios (§16.11) are meta-tested: each builds successfully, produces a valid `NetworkSimulator`, and is deterministic with fixed seeds.

| Test | Verifies |
|------|----------|
| `preset_two_party_basic_builds` | `two_party_basic` returns a simulator with 2 identities, 1 relay, 1 context |
| `preset_five_party_group_builds` | `five_party_group` returns a simulator with 5 identities, correct MLS epoch |
| `preset_suppression_scenario_builds` | `suppression_scenario` returns a simulator with suppressing relay behavior |
| `preset_equivocation_scenario_builds` | `equivocation_scenario` returns a simulator with equivocating relay behavior |
| `preset_scenarios_deterministic` | Each preset called twice with same seed produces identical DID strings and relay state |

## 16.14 Cross-Reference Map

Every simulation component maps to a specific protocol mechanism or threat:

| Component | Protocol reference | What it tests |
|---|---|---|
| `BehaviorMode::Normal` | §9.9.1 honest relay | Baseline correctness |
| `BehaviorMode::Suppressing` | §9.9.1 "Drop messages" | §9.8.5 gap timeout, §9.9.2 suppression detection |
| `BehaviorMode::Equivocating` | §9.9.1 "Show different histories" | §9.9.3 Relay Consistency Protocol |
| `BehaviorMode::Delayed` | §9.9.1 "Delay messages" | §9.8.5 reorder buffer, §9.8.3 ordering |
| `BehaviorMode::Replaying` | §9.9.1 "Replay messages" | §9.8.2 three-layer replay prevention |
| `BehaviorMode::CommitSuppressing` | §9.9.4 selective Commit suppression | Epoch divergence detection |
| `BehaviorMode::DeletionNonCompliant` | ADR-004 DELETE best-effort | Relay non-compliance handling |
| `SimulatedClock` | §9.7.3 PCS update interval, §9.8.5 gap timeout, §9.9.2 heartbeat | Timer-driven protocol behavior |
| `NetworkTopology::partition` | Network partition | Multi-relay failover, relay switching |
| `assert_consistent_merkle_roots` | §9.9.3 checkpoint comparison | Event log integrity |
| `assert_complete_delivery` | §9.9.2 multi-relay cross-check | Suppression recovery |
| `assert_suppression_detected` | §9.8.5 + §9.9.2 | Suppression alerting |
| `assert_correct_ordering` | §9.8.3 + §9.8.5 | Reorder buffer correctness |
| `assert_pseudonym_unlinkability` | §9.10.4 + ADR-002 | Metadata privacy |
| `assert_block_enforced` | ADR-007 + §9.16 | Sender key rotation |
| `assert_epoch_consistency` | §9.9.3 + §9.9.4 | MLS epoch synchronization |
| `transport_conformance!()` | ADR-005 | TransportAdapter contract |
| `storage_conformance!()` | ADR-006, §17.2 | Storage contract (6 methods, ordering guarantee) |
| `key_custody_conformance!()` | ADR-006 | KeyCustody contract |
| `attestation_conformance!()` | ADR-006 | DeviceAttestation contract |
| `push_conformance!()` | ADR-006 | Push contract |
| `blob_store_conformance!()` | §16.4.1, §17.7 | BlobStore contract (5 methods, TTL, concurrent access) |
| ProtocolStore integration tests | §17.4, §17.13 | Protocol-layer persistence correctness |
| MlsStorageBridge tests | §17.9 | OpenMLS state persistence through ProtocolStore |
| Assertion library meta-tests | §16.10, §16.13.9 | Assertion functions detect violations correctly |
| Preset scenario meta-tests | §16.11, §16.13.10 | Preset factories produce valid, deterministic simulators |

## 16.15 CI Integration

The `scp-testing` harness tests are organized into three CI tiers with increasing scope and duration. Each tier subsumes the previous one. For Rust-specific CI commands and the full job matrix, see `.docs/standards/rust.md`. For cross-language SDK CI, see `.docs/standards/sdk-common.md`.

### 16.15.1 Tier 1 — PR Checks

**Trigger:** Every push to a PR branch.
**Target:** < 3 minutes.
**Purpose:** Fast feedback. Must pass before review.

Tier 1 runs standard quality gates (format, lint, build, deny, docs) plus unit tests and conformance macro suites. Conformance macros (`transport_conformance!()`, `storage_conformance!()`, `key_custody_conformance!()`, `attestation_conformance!()`, `push_conformance!()`, `blob_store_conformance!()`) expand into `#[cfg(test)]` modules that run as part of the normal `cargo nextest run --workspace` invocation. They exercise in-memory implementations only and complete in milliseconds.

No §16.13 meta-tests run at this tier — they exercise the simulation harness itself, which is more expensive than unit-level conformance checks.

### 16.15.2 Tier 2 — Merge Gate

**Trigger:** Merge queue entry or push to `main`.
**Target:** < 10 minutes.
**Purpose:** Required to merge. Exercises the harness and protocol integration.

Tier 2 includes all Tier 1 checks plus the `scp-testing` harness meta-tests and protocol integration tests. These verify that the simulation framework is correct (meta-tests) and that the protocol works end-to-end (integration tests).

**§16.13 subsections assigned to Tier 2:**

| Subsection | Tests | Rationale |
|---|---|---|
| §16.13.1 | InMemoryRelay correctness (14 tests) | Validates the relay simulator before trusting it |
| §16.13.2 | InMemoryTransport correctness (3 tests) | Validates transport adapter simulation |
| §16.13.3 | SimulatedClock correctness (5 tests) | Validates time control |
| §16.13.4 | NetworkTopology correctness (4 tests) | Validates partition/heal simulation |
| §16.13.5 | ScenarioBuilder correctness (6 tests) | Validates builder produces valid simulators |
| §16.13.6 | Determinism (3 tests) | Validates seed-based reproducibility |
| §16.13.7 | ProtocolStore correctness (9 tests) | Validates protocol-layer persistence against InMemoryStorage |
| §16.13.8 | MlsStorageBridge correctness (2 tests) | Validates OpenMLS state persistence chain |
| §16.13.9 | Assertion library meta-tests (15 tests) | Validates assertion functions before trusting them |
| §16.13.10 | Preset scenario meta-tests (5 tests) | Validates preset factories |

**Phase integration test:** Tier 2 always includes the current phase's end-to-end integration test. In Phase 1, this is the P1 integration test (identity creation → context creation → MLS group formation → message send/receive → event log verification). Each subsequent phase adds its own integration test; all previous phase tests continue to run.

### 16.15.3 Tier 3 — Nightly / Pre-Release

**Trigger:** Scheduled (nightly) or manual (pre-release).
**Target:** Uncapped duration.
**Purpose:** Extended coverage. Failures create issues but do not block merges.

| Test suite | Phase available | Description |
|---|---|---|
| proptest extended | Phase 1+ | All property-based tests with extended case counts (crypto roundtrips, serialization, Merkle proofs, UCAN chains, bucket padding) |
| Full N-party simulation | Phase 1+ | All preset scenarios (§16.11) × 10 seeds each. Exercises suppression detection, equivocation, partitions, blocking, TTL, reordering across varied random conditions |
| Adapter conformance (persistent backends) | Phase 2+ | `storage_conformance!()` and `blob_store_conformance!()` against SqliteStorage, SqliteBlobStore, RedbBlobStore |
| WasmSqliteStorage conformance | Phase 4+ | `storage_conformance!()` via `wasm-pack test` against WasmSqliteStorage |
| Load testing | Phase 6 | 1000 `SimulatedIdentity` instances, stress-tests on context membership churn, relay throughput, MLS epoch management |

### 16.15.4 Test Marker Convention

Tests are selected by tier using cargo nextest filter expressions and `#[cfg]` feature flags.

**Tier selection:**

- **Tier 1:** `cargo nextest run --workspace` — runs all `#[test]` and `#[tokio::test]` functions. Conformance macros expand into standard test modules.
- **Tier 2:** `cargo nextest run --workspace --features scp-testing/ci-tier2` — the `ci-tier2` feature flag gates §16.13 meta-tests and phase integration tests behind `#[cfg(feature = "ci-tier2")]`.
- **Tier 3:** `cargo nextest run --workspace --features scp-testing/ci-tier3` — the `ci-tier3` feature flag gates extended property tests and multi-seed scenario runs. `ci-tier3` implies `ci-tier2`.

**Feature flag definition in `scp-testing/Cargo.toml`:**

```toml
[features]
ci-tier2 = []
ci-tier3 = ["ci-tier2"]
```

**Usage in test code:**

```rust
// §16.13.1 meta-test — runs only in Tier 2+
#[cfg(feature = "ci-tier2")]
#[tokio::test]
async fn relay_stores_and_delivers() {
    // ...
}

// Extended preset scenario run — runs only in Tier 3
#[cfg(feature = "ci-tier3")]
#[tokio::test]
async fn preset_suppression_all_seeds() {
    for seed in 0..10 {
        let sim = suppression_scenario(seed).await;
        assert_suppression_detected(&sim, /* ... */).await.unwrap();
    }
}
```

### 16.15.5 Tier Assignment Completeness

Every §16.13 subsection is assigned to exactly one tier. No test is unassigned.

| §16.13 subsection | Tier | Feature gate |
|---|---|---|
| §16.13.1 InMemoryRelay | 2 | `ci-tier2` |
| §16.13.2 InMemoryTransport | 2 | `ci-tier2` |
| §16.13.3 SimulatedClock | 2 | `ci-tier2` |
| §16.13.4 NetworkTopology | 2 | `ci-tier2` |
| §16.13.5 ScenarioBuilder | 2 | `ci-tier2` |
| §16.13.6 Determinism | 2 | `ci-tier2` |
| §16.13.7 ProtocolStore | 2 | `ci-tier2` |
| §16.13.8 MlsStorageBridge | 2 | `ci-tier2` |
| §16.13.9 Assertion library | 2 | `ci-tier2` |
| §16.13.10 Preset scenarios | 2 | `ci-tier2` |
| Preset scenarios × 10 seeds | 3 | `ci-tier3` |
| Persistent backend conformance | 3 | `ci-tier3` |
| Wasm conformance | 3 | `ci-tier3` |
| Load testing | 3 | `ci-tier3` |
