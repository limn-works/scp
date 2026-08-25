//! Bridge-agnostic core state for FFI bridges.
//!
//! [`CoreFields`] holds the state every FFI bridge needs
//! (`ContextManager`, transport, known contexts, rate limiters, economy
//! trackers, bridge connector state, DID resolver, lifecycle flags,
//! persistence, relay URL, shutdown hooks). Per-bridge concrete structs
//! (`PyBridgeInstance`, `NapiBridgeInstance`, `UniffiBridgeInstance`) embed
//! one `CoreFields` and add their own typed fields for bridge-specific
//! registries (identity, UCAN, MCP, custody, etc.). They implement the
//! [`BridgeInstanceCore`] trait so shared helpers can operate on
//! `&dyn BridgeInstanceCore`.
//!
//! This is the Phase 4 refactor of the former `BridgeInstance` type
//! (see #1549 Phase 4 remainder plan). The prior `Box<dyn Any>` slots
//! for `identity_registry`/`ucan_registry`/`storage_provider`/
//! `protocol_repository` are gone — each bridge now owns concrete typed
//! fields. The transitional `pub type BridgeInstance = CoreFields;`
//! alias was deleted in PR 1 post-review; callers reference
//! [`CoreFields`] directly.
//!
//! # No local DID on the container
//!
//! Per spec §12.2.3, the FFI bridge instance is *infrastructure*, not a
//! protocol entity. It has NO DID requirement — the authoritative local DID
//! lives inside the `ContextManager`'s `NodeMlsFactory`. An SDK consumer
//! may hold a bridge instance purely to resolve DIDs or verify attestations
//! without ever creating a local identity.
//!
//! # Owned state (bridge-agnostic, in [`CoreFields`])
//!
//! - `ContextManager` — context lifecycle (MLS, membership, governance, broadcast)
//! - Transport manager — relay connections
//! - Known contexts — context discovery registry
//! - Rate limiters — invitation auto-accept
//! - Economy budgets + antispam — economic governance trackers
//! - Bridge connector state — per-context shadow registries + sender key stores
//! - DID resolver — production identity-backed resolver
//! - `instance_id: u64` — monotonic counter used for runtime handle-affinity
//!   checks so a handle created against instance A is rejected on instance B
//! - [`CancellationToken`] — flipped during shutdown; long-running tasks
//!   spawned under the instance's `JoinSet` can cooperatively exit
//! - [`tokio::task::JoinSet`] — owns in-flight async tasks; shutdown awaits
//!   graceful completion up to a deadline, then aborts the rest
//! - MCP stdio allowlist — per-instance subprocess-spawn policy for
//!   `mcp_client_connect_stdio`. Migrated from a process-global
//!   `OnceLock<Mutex<…>>` in `scp-mcp::allowlist`; one bridge unrestricting
//!   no longer leaks into another (closes the realm-local RCE-pivot per
//!   ADR-048 §1).
//!
//! # Thread Safety
//!
//! [`CoreFields`] is `Send + Sync`. The `ContextManager` is behind `Arc`
//! (interior `RwLock`/`DashMap`). Lifecycle flags (`shutdown`, `suspended`)
//! use `AtomicBool` with `Ordering::SeqCst` for cross-thread visibility.
//! Transport uses `std::sync::RwLock` for infrequent writes (connect/
//! disconnect) and concurrent reads (probe/query). Known contexts and rate
//! limiters use `DashMap` for lock-free concurrent access. The `JoinSet`
//! is wrapped in `tokio::sync::Mutex` because accesses happen across
//! `.await` points.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::PoisonError;
use std::sync::RwLock;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use scp_core::context::ContextPersistence;
use scp_core::context::supervisor::Supervisor;
use scp_core::discovery::handles::HandleRegistry;
use scp_core::discovery::petnames::PetnameMap;
use scp_core::discovery::scope::ScopeRegistry;
use scp_protocol::context::invitation::RateLimitTracker;
use scp_protocol::economy::antispam::SenderVelocityTracker;
use scp_protocol::economy::budget::MemberBudgetTracker;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Per-URL timeout for the parallel relay reconnect pass in
/// [`CoreFields::reconnect_transport_if_pending`]. Bounds the worst case
/// when a single slow (or attacker-controlled) relay would otherwise
/// stall the entire reconnect. 5 seconds accommodates real-world TLS +
/// relay handshake overhead while still failing fast on an unresponsive
/// peer. See red-hat RED-1003.
const RECONNECT_PER_URL_TIMEOUT: Duration = Duration::from_secs(5);

use crate::IdentityBackedDidResolver;
use crate::bridge_state::BridgeContextState;

/// Monotonic counter for [`CoreFields::instance_id`].
///
/// Starts at 1. The value `0` is reserved as "unset" so handle types that
/// default-initialize the affinity id never accidentally match a live
/// instance.
static INSTANCE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Reserved instance id meaning "no instance bound yet."
///
/// Handles constructed before they are attached to a bridge instance should
/// carry `UNSET_INSTANCE_ID`; [`CoreFields::check_handle`] treats this as a
/// mismatch, forcing callers to attach the handle explicitly.
pub const UNSET_INSTANCE_ID: u64 = 0;

/// Allocates the next monotonically increasing instance id.
///
/// Each call returns a fresh `u64`. Wraparound would require 2^64 calls and
/// is not defended against; it is not reachable in practice.
#[must_use]
fn next_instance_id() -> u64 {
    INSTANCE_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// A live component a bridge instance started, which borrows a resource that
/// same instance owns and releases at shutdown.
///
/// # Why an instance tracks its borrowers
///
/// A bridge instance owns exactly one storage backend, chosen at construction
/// (`SCP.with_storage({...})`). `start_node_local` hands a node a clone of that
/// backend's `Arc`, so an instance and a node write through one handle.
/// Each bridge's `bridge_specific_shutdown` then calls
/// `ProtocolRepoVariant::close`, which reaches
/// [`scp_platform::sqlite::SqliteStorage::close`] and drops an advisory
/// `flock(2)` on `{dir}/scp.db.lock`. That lock is what stops a second process
/// from opening one `SQLCipher` database while a first writer still holds it,
/// so releasing it while a node keeps writing invites split-brain writes and
/// WAL corruption (red-hat RED-1002).
///
/// [`CoreFields`] therefore records every borrower a node-start path produced,
/// and [`CoreFields::stop_borrowers`] signals each live one to stop before any
/// bridge releases anything. `scp_ffi_common::server::RunningNode` implements
/// this trait; `scp_ffi_common::server::register_node` is a single canonical
/// path that wraps a started node and registers it in one call.
///
/// # Weak references only
///
/// [`CoreFields`] stores [`Weak`], never [`Arc`], so a registry entry never
/// keeps a node alive past its handle and a dropped node leaves nothing to
/// leak. `stop_borrowers` skips whichever entries already died.
pub trait InstanceBorrower: Send + Sync {
    /// Signals this borrower to stop writing through whatever it borrowed.
    ///
    /// Must be idempotent, because a caller can invoke shutdown twice and a
    /// borrower can also stop on its own.
    fn stop(&self);

    /// Reports whether this borrower already stopped.
    fn stopped(&self) -> bool;
}

/// Registry backing [`CoreFields::register_borrower`] and
/// [`CoreFields::stop_borrowers`].
///
/// `closed` turns a register-versus-shutdown race into a decided outcome
/// instead of a lost registration: once [`CoreFields::stop_borrowers`] sets it,
/// a later [`CoreFields::register_borrower`] stops its argument immediately
/// rather than filing a `Weak` nothing will ever read.
#[derive(Default)]
struct BorrowerRegistry {
    /// Set by [`CoreFields::stop_borrowers`]. Never cleared: shutdown is a
    /// terminal transition.
    closed: bool,
    /// Live borrowers, pruned on every registration so an instance that starts
    /// many nodes over its lifetime does not grow this vector without bound.
    entries: Vec<Weak<dyn InstanceBorrower>>,
}

/// Maximum number of known contexts that can be registered in the discovery
/// registry. When this limit is reached, the oldest entry (by `last_seen`)
/// is evicted to make room for the new one. 10,000 is well beyond any
/// realistic per-device usage while preventing unbounded memory growth from
/// a misbehaving caller.
const MAX_KNOWN_CONTEXTS: usize = 10_000;

/// Maximum number of rate limit trackers. When this limit is reached, the
/// least-recently-inserted tracker is evicted to make room for the new one.
/// 1,000 concurrent identity DIDs per bridge instance is generous for any
/// single-process deployment.
const MAX_RATE_LIMITERS: usize = 1_000;

/// Maximum number of economy budget tracker entries. Budget trackers are
/// 1:1 with contexts and are bounded by context membership, so growth is
/// inherently limited in practice. This constant provides a hard ceiling
/// against any pathological caller. When at capacity and a new context ID
/// is requested, an ephemeral (non-persisted) tracker is used and a warning
/// is logged.
const MAX_ECONOMY_CONTEXTS: usize = 10_000;

// Note: bridge connector state entries are 1:1 with contexts managed through
// the `ContextManager`. No separate capacity constant is needed because
// `ContextManager` itself enforces membership bounds, and bridge state entries
// are removed via `remove_bridge_state` during context cleanup.

/// Default sliding window duration for antispam velocity tracking (seconds).
/// Matches the spec section 19.7 example.
const ANTISPAM_DEFAULT_WINDOW_SECS: u64 = 60;

/// Metadata about a known context's relay presence.
///
/// Stored in the per-bridge [`CoreFields`]'s known-contexts registry so that context
/// discovery can probe relays for context activity. The relay is a dumb blob
/// store with no identity-to-context mapping, so the client must track which
/// routing IDs correspond to which contexts.
///
/// See SCP-213 and ADR-015 in `.docs/adrs/phase-3.md`.
#[derive(Debug, Clone)]
pub struct KnownContext {
    /// The context's routing ID (32-byte pseudonym for relay routing).
    pub routing_id: [u8; 32],
    /// The relay URL where this context's blobs are stored. `None` if no relay
    /// was connected at registration time.
    pub relay_url: Option<String>,
    /// The DID of the member who registered this known context.
    pub member_did: String,
    /// Unix timestamp (seconds) when this context was last seen active.
    pub last_seen: u64,
}

/// Bridge-agnostic core state shared by every FFI bridge.
///
/// Per-bridge concrete structs (`PyBridgeInstance`, `NapiBridgeInstance`,
/// `UniffiBridgeInstance`) embed one `CoreFields` and expose their own
/// bridge-specific fields (identity registry, UCAN registry, MCP registries,
/// custody registries, etc.). They implement the [`BridgeInstanceCore`]
/// trait so shared helpers can operate on `&dyn BridgeInstanceCore`.
///
/// The transitional `pub type BridgeInstance = CoreFields;` alias has been
/// deleted; per-bridge code references `CoreFields` directly via the
/// embedded `core` field on the concrete struct.
///
/// # No local DID on the container
///
/// Per spec §12.2.3, `CoreFields` is infrastructure, not a protocol entity.
/// The authoritative local DID lives inside the `ContextManager`'s
/// `NodeMlsFactory`. `CoreFields` carries no DID of its own — it may
/// exist before any identity is created (to service DID resolution or
/// attestation verification for remote DIDs).
///
/// # Lifecycle
///
/// - Construction via [`CoreFields::new`] or [`CoreFields::with_persistence`]
///   allocates a fresh [`CoreFields::instance_id`], a fresh
///   [`CancellationToken`], and an empty [`JoinSet`].
/// - [`CoreFields::suspend`] disconnects transport and flushes snapshots but
///   leaves the instance alive for [`CoreFields::resume`].
/// - [`CoreFields::shutdown`] is a sync, infallible terminal operation
///   preserved for existing bridge call sites. For tasks that need a
///   bounded graceful shutdown, use
///   [`CoreFields::shutdown_core_async`]; it fires the cancellation token,
///   drains the `JoinSet` within the caller's deadline, aborts the rest,
///   and reports the outcome via [`ShutdownOutcome`].
///
/// # Invariants
///
/// - Once shut down, [`CoreFields::is_shutdown`] returns `true` permanently.
///   All bridge operations should check this flag and fail fast.
/// - The `Supervisor` reference is shared (`Arc`) and may outlive this
///   instance if cloned elsewhere. Shutdown does NOT drop or invalidate
///   the `Supervisor` — it is a signal to the bridge layer only.
pub struct CoreFields {
    /// Shared per-instance `Supervisor` — actor registry, saga
    /// coordinator, and query dispatcher.
    ///
    /// Stored in a `OnceLock` so that the per-bridge [`CoreFields`] (and
    /// thus the DID resolver slot it owns) can exist BEFORE the
    /// supervisor is constructed. The supervisor's underlying
    /// `ContextManager` (during the ADR-049 transition window) needs
    /// the real DID at construction time, but the DID is only known
    /// after `DidDht::create()` runs inside `identity_create`. Deferring
    /// the supervisor resolves this ordering.
    ///
    /// Accessors that expect a ready supervisor call
    /// [`supervisor`](Self::supervisor) / [`try_supervisor`](Self::try_supervisor)
    /// which return `None` when the supervisor hasn't been set yet.
    /// During steady-state operation, callers go through bridge
    /// functions that ensure `init_supervisor(real_did)` has been called
    /// first.
    ///
    /// ADR-049 commit 12c.9g.3 — replaces the previous twin
    /// `(context_manager: OnceLock<Arc<ContextManager>>, supervisor:
    /// Arc<Supervisor>)` slot pair with a single OnceLock-managed
    /// supervisor. The `ContextManager` (when constructed by the FFI
    /// layer) is attached internally by the supervisor builder before
    /// the supervisor reaches this slot; bridges no longer hold a
    /// distinct `Arc<ContextManager>`.
    supervisor: OnceLock<Arc<Supervisor>>,

    /// Whether this instance has been shut down permanently.
    ///
    /// Uses `SeqCst` ordering for cross-thread visibility. Once set to `true`,
    /// all subsequent bridge operations should return an error immediately.
    /// A shut-down instance cannot be resumed.
    shutdown: AtomicBool,

    /// Whether this instance is currently suspended.
    ///
    /// Suspended instances have disconnected transport but retain their
    /// context state. `resume()` clears this flag — the caller must
    /// re-establish transport via `set_transport`. Suspension is intended
    /// for mobile app backgrounding.
    suspended: AtomicBool,

    // -----------------------------------------------------------------
    // Shared state — previously per-bridge OnceLock singletons
    // -----------------------------------------------------------------
    /// Transport manager for multi-relay support.
    ///
    /// Stores the real [`scp_transport::TransportManager`] with multi-relay
    /// fanout, per-context relay set assignment, suppression detection, and
    /// reliability scoring. Uses `RwLock` for infrequent writes (connect) and
    /// concurrent reads (probe/query). Wrapped in `Arc` so that NAPI bridge
    /// subscription tasks (which run in spawned async tasks) can hold a
    /// `Send`-compatible reference without keeping the `RwLock` guard alive
    /// across `.await` points.
    transport: RwLock<Option<Arc<scp_transport::TransportManager>>>,

    /// Instance-scoped transport selector (transparent QUIC↔WebSocket
    /// selection, spec §10.14.3 item 4; ADR-037).
    ///
    /// Owned per bridge instance (no globals) so its per-relay caches survive
    /// across connects: a QUIC-suppression set (a dead/blocked QUIC port is not
    /// re-probed every reconnect) and a `.well-known/scp` transports cache (the
    /// relay's advertised transports are fetched once per relay, not on every
    /// dial). Connect sites route through this selector's
    /// `select_and_connect_discovering*` methods so connect-time discovery
    /// feeds the QUIC-vs-WebSocket decision (spec §10.5.1) — closing the gap
    /// where a `None` advertised list always degraded to WebSocket.
    transport_selector: Arc<scp_transport::TransportSelector>,

    /// Known context-to-relay mappings for discovery (SCP-213).
    ///
    /// Tracks contexts that have been created/joined locally, along with their
    /// routing IDs and relay URLs. This allows context discovery to probe
    /// relays for context activity even across process restarts (when combined
    /// with persistence, a future story). Uses `DashMap` for lock-free
    /// concurrent access.
    known_contexts: DashMap<String, KnownContext>,

    /// Rate limit tracker registry for invitation auto-accept, keyed by
    /// identity DID.
    ///
    /// Each identity has its own [`RateLimitTracker`] that persists across
    /// invitation evaluations. The tracker enforces the rate limit specified
    /// in the auto-accept policy. Uses `DashMap` for lock-free concurrent
    /// access.
    rate_limiters: DashMap<String, RateLimitTracker>,

    // -----------------------------------------------------------------
    // Economy state — previously per-bridge OnceLock singletons
    // -----------------------------------------------------------------
    /// Per-context member budget trackers for economic governance.
    ///
    /// Keyed by context ID. Created lazily on first access via
    /// [`with_economy_budget`] / [`with_economy_budget_mut`]. Budget trackers
    /// are NOT removed automatically when contexts are closed -- call
    /// [`Self::remove_economy_state`] for cleanup in long-running processes.
    economy_budgets: DashMap<String, MemberBudgetTracker>,

    /// Per-context antispam velocity trackers for economic governance.
    ///
    /// Keyed by context ID. Created lazily on first access with a default
    /// 60-second sliding window. The window duration matches the spec
    /// section 19.7 example.
    economy_antispam: DashMap<String, SenderVelocityTracker>,

    // -----------------------------------------------------------------
    // Bridge connector state — previously in bridge_state.rs OnceLock
    // -----------------------------------------------------------------
    /// Per-context bridge connector state (shadow registries and sender key
    /// stores).
    ///
    /// Keyed by context ID. See [`BridgeContextState`] for contents.
    /// Previously in `scp_ffi_common::bridge_state::BRIDGE_STATE`.
    bridge_state: DashMap<String, BridgeContextState>,

    // -----------------------------------------------------------------
    // DID resolver — previously per-bridge OnceLock
    // -----------------------------------------------------------------
    /// Production DID resolver that delegates to
    /// `scp_identity::resolver::DidResolver` for full DID document validation
    /// (BEP44 signature verification, self-certification, sequence number
    /// tracking, caching).
    ///
    /// Initialized by [`set_did_resolver`] when the identity layer is first
    /// set up. `None` until `identity_create` initializes it.
    ///
    /// See #311 for the unification design.
    did_resolver: OnceLock<Arc<IdentityBackedDidResolver>>,

    /// Shared DHT client backing the production DID resolver.
    ///
    /// Retained on the instance so that `identity_create` publishes freshly
    /// minted DID documents into the *same* [`FfiDhtClient`] the resolver reads
    /// from. Without this, an identity's document is only registered in the local
    /// identity registry and is never resolvable via the resolver — so any code
    /// path that resolves the DID to verify a signature (UCAN validation,
    /// governance vote verification) fails with "unknown voter: cannot resolve
    /// public key for DID".
    ///
    /// Set by the same idempotent resolver-initialization path that calls
    /// [`set_did_resolver`]; the resolver and this client are the same `Arc`.
    /// `None` until the identity layer is first set up.
    ///
    /// The shipped [`FfiDhtClient`] is the real Mainline `PkarrDhtClient`; the
    /// in-memory arm exists only under `testing` (ADR-062 §Decision 1).
    dht_client: OnceLock<Arc<crate::dht::FfiDhtClient>>,

    /// The DID-resolution cache shared with the production DID resolver.
    ///
    /// Stored alongside [`dht_client`] and the resolver itself (the SAME
    /// `Arc<DidCache>` the `DualLayerResolver` was built over). The resolver
    /// caches resolved documents with a multi-day TTL; when a locally held
    /// identity is mutated (key rotation, agent-key add/rotate/remove,
    /// migration) and its higher-sequence document is re-published into
    /// [`dht_client`], the matching cache entry must be invalidated so the
    /// next resolution re-reads the fresh document instead of serving the
    /// stale, pre-mutation one. `None` until the identity layer is first set
    /// up.
    resolver_cache: OnceLock<Arc<scp_identity::cache::DidCache>>,

    /// Registered shutdown hooks for bridge-specific state cleanup.
    ///
    /// During the Phase 4 transition, each FFI bridge registers hooks that
    /// clear bridge-specific singletons (`PyO3` `FFI_BRIDGE_STATE`, MCP
    /// registries, etc.). Per-bridge concrete structs taking over in the
    /// follow-up commits replace most hooks with typed fields dropped in
    /// [`BridgeInstanceCore::bridge_specific_shutdown`].
    ///
    /// Hooks are called exactly once during `shutdown()` and then discarded.
    /// The `Mutex` is only locked during `shutdown()` and
    /// `register_shutdown_hook()` — no contention on the hot path.
    shutdown_hooks: Mutex<Vec<Box<dyn FnOnce() + Send>>>,

    // -----------------------------------------------------------------
    // Persistence — optional context state persistence provider
    // -----------------------------------------------------------------
    /// Optional persistence provider, forwarded from the `ContextManager`.
    ///
    /// When `Some`, `suspend()` and `shutdown()` call
    /// `ContextManager::flush_all_contexts_sync` to persist context state
    /// before tearing down transport or destroying MLS groups. The provider
    /// reference is retained here so the bridge layer can pass it through
    /// `with_persistence()` at construction time and expose it via the
    /// [`persistence`](Self::persistence) accessor for bridge-specific
    /// restore logic.
    ///
    /// `Arc<dyn ...>` (rather than `Box<dyn ...>`) so the bridge layer can
    /// hand the same provider instance to both this mirror and the
    /// `ContextManager::with_persistence` constructor — SQLite-backed
    /// storage cannot open a second connection to the same database file
    /// at the same time, so we need to clone an `Arc`, not a `Box`.
    /// [`persistence_arc_clone`](Self::persistence_arc_clone) returns the
    /// clone.
    ///
    /// This is logically a mirror of the persistence configured on the
    /// `ContextManager` — the `ContextManager` owns the canonical reference;
    /// this field allows the bridge layer to use the same provider for
    /// bridge-level suspend/resume coordination without separate storage.
    persistence: Option<Arc<dyn ContextPersistence + Send + Sync>>,

    // -----------------------------------------------------------------
    // Relay URLs — for resume after suspend (multi-URL since #1678)
    // -----------------------------------------------------------------
    /// Every relay URL currently registered for reconnection after resume.
    ///
    /// Bridges may connect to more than one relay simultaneously
    /// (`TransportManager` already supports multi-adapter routing). The
    /// `BridgeInstanceCore::resume` default body walks this set and reconnects
    /// each URL individually, so the set is the source of truth for "which
    /// relays does this bridge intend to be connected to".
    ///
    /// Populated via [`Self::add_relay_url`]. Entries removed via
    /// [`remove_relay_url`] (explicit disconnect). Retrieved as a
    /// deduplicated snapshot via [`Self::pending_relay_urls`]. Preserved across
    /// `suspend()` / `resume()` cycles so callers can reconnect.
    /// Cleared in full by [`shutdown()`] and [`clear_relay_urls`].
    relay_urls: Mutex<HashSet<String>>,

    // -----------------------------------------------------------------
    // Identity + async lifecycle
    // -----------------------------------------------------------------
    /// Monotonic per-instance identifier used for runtime handle-affinity
    /// checks. Allocated via [`next_instance_id`] at construction time.
    /// Never zero — [`UNSET_INSTANCE_ID`] marks "not attached to any
    /// instance" for handles constructed independently.
    instance_id: u64,

    /// Shutdown signal for async tasks owned by this instance.
    ///
    /// Fired by [`CoreFields::shutdown_core_async`] before draining the
    /// `JoinSet`. Tasks that want to exit cleanly `select!` on
    /// `cancel.cancelled()` alongside their usual work.
    cancel: CancellationToken,

    /// Cancellation signal scoped to the **current reconnect generation**
    /// — fired on [`suspend`] and [`shutdown`] so any in-flight
    /// [`reconnect_transport_if_pending`] dial can drop its
    /// half-connected socket instead of completing against a torn-down
    /// instance (#1696).
    ///
    /// Rotated (old one cancelled, fresh one installed) on each
    /// `suspend()`. [`reconnect_transport_if_pending`] clones the token
    /// once at entry and races each `NativeRelayAdapter::connect_sourced`
    /// against `token.cancelled()`. If suspend fires mid-dial, the
    /// `.await` resolves with the cancellation branch and the pending
    /// adapter future is dropped — the TCP/TLS socket teardown happens
    /// inside the adapter's own state machine rather than leaking out as
    /// an unowned `NativeRelayAdapter`.
    ///
    /// Wrapped in `Mutex` (not `RwLock`) because writes dominate the
    /// access pattern during `suspend()` and reads are cheap (a
    /// single `clone()` at the top of `reconnect_transport_if_pending`).
    reconnect_cancel: Mutex<CancellationToken>,

    /// In-flight async tasks owned by this instance. Accessed from async
    /// contexts, so wrapped in [`tokio::sync::Mutex`] rather than
    /// [`std::sync::Mutex`] (guards cross `.await` points during shutdown
    /// drain).
    tasks: AsyncMutex<JoinSet<()>>,

    // -----------------------------------------------------------------
    // Petname / handle / scope — #1549 Phase 4 PR 2 commit 2 (additive)
    // -----------------------------------------------------------------
    //
    // These three maps replace the global `OnceLock<Mutex<HashMap<...>>>`
    // singletons in `scp_ffi_common::petname_helpers`. The petname helpers
    // are migrated to use these fields in commit 7 (not this slice). Until
    // then the fields sit empty — adding them here (commit 1/2) establishes
    // the slot so downstream commits can migrate callers without re-touching
    // this struct.
    /// Per-identity petname maps. Keyed by owner DID (spec §3.7 — petnames
    /// are per-identity private state).
    petname_maps: Mutex<HashMap<String, PetnameMap>>,

    /// Per-context handle registries. Keyed by context ID (spec §22.3.1).
    handle_registries: Mutex<HashMap<String, HandleRegistry>>,

    /// Per-context scope registries. Keyed by context ID (spec §22.3.5,
    /// ADR-043). Separate from handle registries — scope entries and handle
    /// entries never share storage.
    scope_registries: Mutex<HashMap<String, ScopeRegistry>>,

    // -----------------------------------------------------------------
    // MCP stdio allowlist — per-instance
    // -----------------------------------------------------------------
    /// Per-instance MCP stdio command allowlist.
    ///
    /// Each `CoreFields` owns its own [`scp_mcp::allowlist::StdioAllowlist`]
    /// guarded by a `Mutex`. Migrated from a `OnceLock<Mutex<…>>` process
    /// singleton in `scp-mcp::allowlist` so that one bridge disabling
    /// enforcement (or extending the allow set) does not leak into another
    /// bridge's policy decisions (ADR-048 multi-instance neutrality).
    ///
    /// Lock-ordering rule: callers must NOT hold this guard while acquiring
    /// any other `CoreFields` lock. The allowlist guard is short-lived and
    /// only wraps the `validate_command` / `configure` / `disable_enforcement`
    /// / `reset` / `snapshot` calls — there is never a reason to nest.
    mcp_allowlist: Mutex<scp_mcp::allowlist::StdioAllowlist>,

    // -----------------------------------------------------------------
    // Persona-source seam — ADR-039 Enforcement-Stack Layer 2
    // -----------------------------------------------------------------
    /// Per-send message signing persona source (ADR-039 Enforcement-Stack
    /// Layer 2).
    ///
    /// Consulted at every message-send site across the three native bridges
    /// (`PyO3`, NAPI, `UniFFI`) to choose the `#active`/`#agent` signing persona.
    /// Defaults to [`crate::persona::default_persona_source`] — always
    /// `#active`, the permanent conservative fail-safe (persona-uncertain ⇒
    /// attribute to the human). Held in a `RwLock` so a future determiner
    /// (RFC #2242, <https://github.com/limn-works/scp/discussions/2242>) can
    /// install a real per-instance source once the persona *selection* policy
    /// and Layer-1 custody enforcement exist. There is intentionally **no**
    /// production setter today (the SDK exposes no lie-able per-call persona
    /// flag); only the test seam ([`Self::set_persona_source_for_test`])
    /// overrides the default. Reads clone the `Arc` (cheap) so the lock is
    /// never held across the send.
    persona_source: RwLock<crate::persona::PersonaSource>,

    // -----------------------------------------------------------------
    // Storage borrowers — shutdown ordering (red-hat RED-1002)
    // -----------------------------------------------------------------
    /// Live components this instance started that borrow a resource this
    /// instance owns — today, every node a bridge's `node_start_*` path
    /// produced.
    ///
    /// [`BridgeInstanceCore::shutdown`] calls
    /// [`stop_borrowers`](Self::stop_borrowers) before
    /// [`BridgeInstanceCore::bridge_specific_shutdown`], so a node stops
    /// writing before a bridge closes its `SQLCipher` handle and drops an
    /// advisory `flock(2)`. See [`InstanceBorrower`] for why that order
    /// matters.
    borrowers: Mutex<BorrowerRegistry>,
}

impl Default for CoreFields {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreFields {
    /// Creates a new `CoreFields` without a `Supervisor`.
    ///
    /// Initializes all shared state registries (transport, known contexts,
    /// rate limiters) as empty. Allocates a fresh [`CoreFields::instance_id`],
    /// a fresh [`CancellationToken`], and an empty [`JoinSet`]. The
    /// per-instance `Supervisor` is **unbound** — call
    /// [`set_supervisor`](Self::set_supervisor) once the identity has
    /// been created and the supervisor constructed with its providers
    /// (whose `NodeMlsFactory` carries the real local DID).
    ///
    /// Decoupling the supervisor from construction lets the FFI bridge
    /// initialize the DID resolver slot BEFORE any identity is known.
    /// That resolves the chicken-and-egg where the DID resolver lives
    /// inside `CoreFields` but the DID itself is generated by
    /// `DidDht::create()` which runs later. `CoreFields` itself never
    /// stores or tracks the DID — that is the `NodeMlsFactory`'s job
    /// (spec §12.2.3).
    #[must_use]
    pub fn new() -> Self {
        Self {
            supervisor: OnceLock::new(),
            shutdown: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            transport: RwLock::new(None),
            transport_selector: Arc::new(scp_transport::TransportSelector::new()),
            known_contexts: DashMap::new(),
            rate_limiters: DashMap::new(),
            economy_budgets: DashMap::new(),
            economy_antispam: DashMap::new(),
            bridge_state: DashMap::new(),
            did_resolver: OnceLock::new(),
            dht_client: OnceLock::new(),
            resolver_cache: OnceLock::new(),
            shutdown_hooks: Mutex::new(Vec::new()),
            persistence: None,
            relay_urls: Mutex::new(HashSet::new()),
            instance_id: next_instance_id(),
            cancel: CancellationToken::new(),
            reconnect_cancel: Mutex::new(CancellationToken::new()),
            tasks: AsyncMutex::new(JoinSet::new()),
            petname_maps: Mutex::new(HashMap::new()),
            handle_registries: Mutex::new(HashMap::new()),
            scope_registries: Mutex::new(HashMap::new()),
            mcp_allowlist: Mutex::new(scp_mcp::allowlist::StdioAllowlist::new_with_defaults()),
            persona_source: RwLock::new(crate::persona::default_persona_source()),
            borrowers: Mutex::new(BorrowerRegistry::default()),
        }
    }

    /// Creates a new `CoreFields` pre-populated with a `Supervisor`.
    ///
    /// Convenience constructor for callers that already have a
    /// `Supervisor` (e.g., test fixtures, the NAPI/UniFFI
    /// `ensure_bridge_instance` helpers that lazily construct one with
    /// placeholder providers). Equivalent to [`new`](Self::new) followed
    /// by [`set_supervisor`](Self::set_supervisor).
    #[must_use]
    pub fn with_supervisor(supervisor: Arc<Supervisor>) -> Self {
        let instance = Self::new();
        instance.set_supervisor(supervisor);
        instance
    }

    /// Creates a new `CoreFields` with a persistence provider but no
    /// `Supervisor`.
    ///
    /// Attaches a [`ContextPersistence`] provider. When provided,
    /// [`suspend`](Self::suspend) and [`shutdown`](Self::shutdown) will
    /// flush all context snapshots via
    /// [`Supervisor::flush_all_contexts_sync`](scp_core::context::supervisor::Supervisor::flush_all_contexts_sync)
    /// before tearing down transport or destroying MLS groups — but only
    /// after the supervisor itself has been set via
    /// [`set_supervisor`](Self::set_supervisor).
    ///
    /// The persistence provider should be the same one configured on the
    /// eventual `ContextManager` (typically constructed via
    /// `ContextManager::with_persistence` or the builder `.storage()` method).
    ///
    /// # Arguments
    ///
    /// - `persistence` — the persistence provider for bridge-level flush on
    ///   suspend/shutdown. Accepts `Box` for ergonomic call-site parity
    ///   with `ContextManager::with_persistence`; the box is upgraded to
    ///   `Arc` internally so
    ///   [`persistence_arc_clone`](Self::persistence_arc_clone) can hand
    ///   the same provider to downstream consumers.
    #[must_use]
    pub fn with_persistence(persistence: Box<dyn ContextPersistence + Send + Sync>) -> Self {
        Self::with_persistence_arc(Arc::from(persistence))
    }

    /// Creates a new `CoreFields` with a shared persistence provider.
    ///
    /// Variant of [`with_persistence`](Self::with_persistence) that accepts
    /// `Arc<dyn ContextPersistence + Send + Sync>` directly. Callers that
    /// need to hand the exact same provider to both this mirror and
    /// `ContextManager::with_persistence` must use this constructor to
    /// avoid opening two separate `SQLite` connections (one connection per
    /// `Box`) to the same database file.
    ///
    /// # Arguments
    ///
    /// - `persistence` — shared persistence provider.
    #[must_use]
    pub fn with_persistence_arc(persistence: Arc<dyn ContextPersistence + Send + Sync>) -> Self {
        Self {
            supervisor: OnceLock::new(),
            shutdown: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            transport: RwLock::new(None),
            transport_selector: Arc::new(scp_transport::TransportSelector::new()),
            known_contexts: DashMap::new(),
            rate_limiters: DashMap::new(),
            economy_budgets: DashMap::new(),
            economy_antispam: DashMap::new(),
            bridge_state: DashMap::new(),
            did_resolver: OnceLock::new(),
            dht_client: OnceLock::new(),
            resolver_cache: OnceLock::new(),
            shutdown_hooks: Mutex::new(Vec::new()),
            persistence: Some(persistence),
            relay_urls: Mutex::new(HashSet::new()),
            instance_id: next_instance_id(),
            cancel: CancellationToken::new(),
            reconnect_cancel: Mutex::new(CancellationToken::new()),
            tasks: AsyncMutex::new(JoinSet::new()),
            petname_maps: Mutex::new(HashMap::new()),
            handle_registries: Mutex::new(HashMap::new()),
            scope_registries: Mutex::new(HashMap::new()),
            mcp_allowlist: Mutex::new(scp_mcp::allowlist::StdioAllowlist::new_with_defaults()),
            persona_source: RwLock::new(crate::persona::default_persona_source()),
            borrowers: Mutex::new(BorrowerRegistry::default()),
        }
    }

    /// Returns the monotonic identifier assigned to this instance at
    /// construction time.
    ///
    /// Handle types (`ContextHandle`, `Identity`, `TransportManager`, etc.)
    /// store this value and pass it to [`check_handle`](Self::check_handle)
    /// on entry so handles from a different instance are rejected with
    /// [`HandleAffinityError`].
    #[must_use]
    pub const fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// Returns a clone of the instance's [`CancellationToken`].
    ///
    /// Cheap: `CancellationToken` is an `Arc`-based cooperative signal.
    /// Long-running tasks spawned under this instance should select on
    /// the returned token alongside their normal work so
    /// [`shutdown_core_async`](Self::shutdown_core_async) can wake them
    /// before the deadline.
    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Locks and returns the `JoinSet` owning this instance's async tasks.
    ///
    /// Callers should spawn new tasks with `set.spawn(...)`. The lock is
    /// async because shutdown holds it across a `.await` while draining.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut tasks = core.task_handle().await;
    /// tasks.spawn(async move { /* ... */ });
    /// ```
    pub async fn task_handle(&self) -> tokio::sync::MutexGuard<'_, JoinSet<()>> {
        self.tasks.lock().await
    }

    /// Emergency, non-blocking task cancellation for use from `Drop`.
    ///
    /// Drop must never block or `.await`, so the graceful
    /// [`shutdown_core_async`] path is unavailable. This helper does the
    /// minimum safe cleanup:
    ///
    /// 1. Fires [`CancellationToken::cancel`] so any task `select!`ing on
    ///    `cancel_token()` exits cooperatively.
    /// 2. Attempts `JoinSet::abort_all` via a non-blocking `try_lock`. If
    ///    the lock is contended (some caller is mid-shutdown holding the
    ///    `JoinSet`), the abort is skipped — that caller will abort
    ///    anything outstanding itself, so there is nothing to do here.
    ///
    /// This is intentionally a best-effort emergency path. Callers that
    /// need deterministic, awaited shutdown MUST still call
    /// [`BridgeInstanceCore::shutdown`] with a timeout; `Drop` only catches
    /// the case where a caller dropped the bridge without ever awaiting
    /// `shutdown(timeout)` and would otherwise leak subscriptions, timers,
    /// and their captured `Arc<BridgeInstance>` references forever.
    ///
    /// # Cancellation propagation
    ///
    /// Tasks that hold a cloned `Arc<BridgeInstanceCore>` (or a concrete
    /// `Arc<NapiBridgeInstance>`, etc.) via capture will NOT be freed by
    /// token cancellation alone — the capture itself is what keeps the
    /// `Arc` live. They must honour the token by dropping their state
    /// once cancellation fires. `JoinSet::abort_all` is the hard guarantee:
    /// it cancels the task at the next `.await` point regardless of
    /// cooperation, which drops the captured `Arc` and permits the
    /// instance's final `Drop` to complete. Missing the lock here means
    /// we fall back to cooperative-only cancellation, which is strictly
    /// better than doing nothing.
    ///
    /// See ADR-048 (multi-instance SCP) for the full lifecycle contract.
    pub fn emergency_cancel_tasks(&self) {
        // Step 1: cooperative signal. Cheap, always safe.
        self.cancel.cancel();
        // Also cancel the reconnect-generation token so any in-flight
        // dial drops its half-open socket instead of completing against
        // a torn-down instance (mirrors the sync `shutdown()` path).
        if let Ok(guard) = self.reconnect_cancel.lock() {
            guard.cancel();
        }
        // Step 2: hard signal. `try_lock` is non-blocking — if another
        // caller holds the JoinSet mid-shutdown, skip the abort rather
        // than risk deadlocking `Drop`. `abort_all` itself is a no-op
        // when the set is empty or every task has already finished.
        if let Ok(mut set) = self.tasks.try_lock() {
            set.abort_all();
        }
    }

    /// Checks that the supplied handle was issued by this instance.
    ///
    /// Handle types carry [`CoreFields::instance_id`] of the instance they
    /// belong to. At every FFI entry point that consumes a handle, the
    /// bridge layer calls `check_handle(handle.instance_id)` to reject
    /// cross-instance misuse (e.g., a handle created on `SCP` A being
    /// passed into `SCP` B).
    ///
    /// # Errors
    ///
    /// Returns [`HandleAffinityError`] if `handle_instance_id` does not
    /// equal [`CoreFields::instance_id`].
    pub const fn check_handle(&self, handle_instance_id: u64) -> Result<(), HandleAffinityError> {
        if handle_instance_id == self.instance_id {
            Ok(())
        } else {
            Err(HandleAffinityError::new(
                handle_instance_id,
                self.instance_id,
            ))
        }
    }

    /// Stores the shared `Supervisor` for this instance.
    ///
    /// Called by the FFI bridge's `init_supervisor*` family once the
    /// supervisor has been constructed (with the real DID passed
    /// directly into its `NodeMlsFactory` — the bridge
    /// [`CoreFields`] itself does not carry a DID). Subsequent calls
    /// are ignored with a warning (`OnceLock` guarantees single
    /// initialization).
    pub fn set_supervisor(&self, supervisor: Arc<Supervisor>) {
        if self.supervisor.set(supervisor).is_err() {
            tracing::warn!("set_supervisor called but Supervisor already set — ignoring");
        }
    }

    /// Returns the shared per-instance `Supervisor`, or `None` if not
    /// yet set.
    ///
    /// FFI query call sites route through
    /// [`Supervisor::dispatch_query`](scp_core::context::supervisor::Supervisor::dispatch_query)
    /// on the returned reference. Callers that need the supervisor must
    /// surface a typed error at the FFI boundary when this returns
    /// `None` (matches the `try_supervisor` lifecycle contract).
    #[must_use]
    pub fn supervisor(&self) -> Option<&Arc<Supervisor>> {
        self.supervisor.get()
    }

    /// Returns a reference to the persistence provider, if configured.
    ///
    /// `None` if this instance was created without persistence (via
    /// [`new`](Self::new)).
    #[must_use]
    pub fn persistence(&self) -> Option<&(dyn ContextPersistence + Send + Sync)> {
        // `Arc::as_ref` returns `&(dyn ContextPersistence + Send + Sync)`
        // directly — no intermediate Box/Deref.
        self.persistence.as_deref()
    }

    /// Returns a clone of the persistence `Arc`, if configured.
    ///
    /// Used by bridge constructors that want to hand the same provider
    /// instance to both this mirror and
    /// `ContextManager::with_persistence` — critical when the underlying
    /// backend (e.g. `SqliteStorage`) cannot tolerate multiple concurrent
    /// connections to the same database file.
    ///
    /// `None` if this instance was created without persistence.
    #[must_use]
    pub fn persistence_arc_clone(&self) -> Option<Arc<dyn ContextPersistence + Send + Sync>> {
        self.persistence.clone()
    }

    /// Returns a reference to the shared `Supervisor`, or `None` if
    /// not yet set.
    ///
    /// All callers must handle the `None` case explicitly — returning
    /// an appropriate lifecycle error at the FFI boundary (typically
    /// `CTX_2000` / "`Supervisor` not yet attached"). Callers that only
    /// touch [`CoreFields`]-owned state (transport, DID resolver, known
    /// contexts) can proceed without the supervisor.
    ///
    /// There is intentionally no panic-variant accessor: a missing
    /// `Supervisor` is a normal lifecycle state (bridge created for DID
    /// resolution before any identity exists; bridge after shutdown)
    /// and must not crash the host process.
    #[must_use]
    pub fn try_supervisor(&self) -> Option<&Arc<Supervisor>> {
        self.supervisor.get()
    }

    /// Returns whether a `Supervisor` has been set on this instance.
    #[must_use]
    pub fn has_supervisor(&self) -> bool {
        self.supervisor.get().is_some()
    }

    /// Returns a reference to the per-identity petname maps registry.
    ///
    /// Keyed by owner DID — each identity has its own [`PetnameMap`]
    /// (spec §3.7, petnames are per-identity private state). Used by the
    /// shared `petname_helpers` module to resolve address queries. Migrated
    /// from a process-global `OnceLock<Mutex<HashMap<...>>>` singleton in
    /// #1549 Phase 4 PR 2 commit 7.
    #[must_use]
    pub const fn petname_maps(&self) -> &Mutex<HashMap<String, PetnameMap>> {
        &self.petname_maps
    }

    /// Returns a reference to the per-context handle registries registry.
    ///
    /// Keyed by context ID (spec §22.3.1). Used by the shared
    /// `petname_helpers` module to resolve handle queries. Migrated from a
    /// process-global `OnceLock<Mutex<HashMap<...>>>` singleton in #1549
    /// Phase 4 PR 2 commit 7.
    #[must_use]
    pub const fn handle_registries(&self) -> &Mutex<HashMap<String, HandleRegistry>> {
        &self.handle_registries
    }

    /// Returns a reference to the per-context scope registries registry.
    ///
    /// Keyed by context ID (spec §22.3.5, ADR-043). Used by the shared
    /// `petname_helpers` module to resolve scope queries. Migrated from a
    /// process-global `OnceLock<Mutex<HashMap<...>>>` singleton in #1549
    /// Phase 4 PR 2 commit 7.
    #[must_use]
    pub const fn scope_registries(&self) -> &Mutex<HashMap<String, ScopeRegistry>> {
        &self.scope_registries
    }

    /// Returns a reference to the per-instance MCP stdio allowlist.
    ///
    /// Each `CoreFields` owns its own [`scp_mcp::allowlist::StdioAllowlist`]
    /// guarded by a `Mutex`. Bridge MCP transports must lock this mutex,
    /// call [`scp_mcp::allowlist::StdioAllowlist::validate_command`], and
    /// drop the guard before invoking `Command::new`. The bridge layer maps
    /// `PoisonError` to its own typed transport error.
    ///
    /// # Lock ordering
    ///
    /// Do NOT call any other `CoreFields` locking method (e.g.
    /// `petname_maps()`, `handle_registries()`, `with_transport`) while
    /// holding the allowlist guard — the guard is short-lived (one allowlist
    /// op only) and there is never a reason to nest.
    #[must_use]
    pub const fn mcp_allowlist(&self) -> &Mutex<scp_mcp::allowlist::StdioAllowlist> {
        &self.mcp_allowlist
    }

    /// Run a closure against the per-instance MCP stdio allowlist with the
    /// guard held for the duration of the call, then drop it.
    ///
    /// Bridges should prefer this helper to manual `mcp_allowlist().lock()`
    /// at every callsite — it centralizes the `PoisonError` handling and
    /// removes any chance of forgetting to drop the guard before doing
    /// non-allowlist work (FFI conversions, error mapping, etc.).
    ///
    /// Mirrors the typed-error shape of [`CoreFields::with_transport`]
    /// rather than the generic `Result<R, E>` form, so the helper composes
    /// uniformly across `CoreFields` and bridges map the typed error at the
    /// callsite via `?` and a small wrapper.
    ///
    /// Not on the [`BridgeInstanceCore`] trait because adding a generic
    /// method would break `dyn BridgeInstanceCore` — call as
    /// `self.core().with_mcp_allowlist(...)`.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistGuardError::Poisoned`] if the underlying mutex
    /// is poisoned. The closure is invoked exactly once when the lock
    /// acquires successfully.
    ///
    /// # Lock ordering
    ///
    /// Do NOT call any other `CoreFields` locking method while holding
    /// the allowlist guard — the guard is intended to be short-lived (one
    /// allowlist op only). See [`CoreFields::mcp_allowlist`].
    pub fn with_mcp_allowlist<T>(
        &self,
        f: impl FnOnce(&mut scp_mcp::allowlist::StdioAllowlist) -> T,
    ) -> Result<T, AllowlistGuardError> {
        let mut guard = self
            .mcp_allowlist
            .lock()
            .map_err(|_| AllowlistGuardError::Poisoned)?;
        Ok(f(&mut guard))
    }

    /// Whether this instance has been shut down permanently.
    ///
    /// Bridge operations should check this before proceeding and return
    /// an appropriate error if `true`.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Whether this instance is currently suspended (backgrounded).
    ///
    /// Suspended instances have disconnected transport but retain context
    /// state. Bridge operations that require transport should check this
    /// and return an appropriate error.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    /// Checks that the bridge instance is ready to service operations.
    ///
    /// Rejects both permanently shut-down and suspended instances. This is
    /// the single gatekeeper that all bridge `bridge_instance()` functions
    /// should call to enforce lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::AlreadyShutDown`] if the instance has been
    /// permanently shut down, or [`LifecycleError::Suspended`] if the
    /// instance is currently suspended.
    pub fn check_ready(&self) -> Result<(), LifecycleError> {
        if self.is_shutdown() {
            return Err(LifecycleError::AlreadyShutDown);
        }
        if self.is_suspended() {
            return Err(LifecycleError::Suspended);
        }
        Ok(())
    }

    /// Registers a shutdown hook for bridge-specific state cleanup.
    ///
    /// The hook is called exactly once during [`shutdown`](Self::shutdown)
    /// and then discarded. Hooks run in registration order after all
    /// `CoreFields`-owned state has been cleared.
    ///
    /// Intended for bridge-specific singletons that cannot be migrated into
    /// `CoreFields` due to crate dependency boundaries (e.g., `PyO3`
    /// `FFI_BRIDGE_STATE`, MCP server/client registries). Per-bridge
    /// concrete structs introduced in the follow-up commits of this PR
    /// should prefer owning those registries as typed fields and dropping
    /// them in [`BridgeInstanceCore::bridge_specific_shutdown`].
    ///
    /// If the internal `Mutex` is poisoned (a previous hook registration
    /// panicked while holding the lock), the hook is silently dropped and
    /// an error is logged.
    pub fn register_shutdown_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        if self.is_shutdown() {
            // Already shut down — run the hook immediately since shutdown()
            // won't be called again. Wrap in catch_unwind for consistency
            // with shutdown()'s hook execution.
            tracing::warn!("hook registered after shutdown — running immediately");
            if let Err(_payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook)) {
                tracing::error!(
                    "post-shutdown hook panicked — bridge-specific cleanup may be incomplete"
                );
            }
            return;
        }
        // Re-check `is_shutdown` after acquiring the lock to close the
        // TOCTOU window between the check above and the push below. Without
        // this, a concurrent shutdown could drain and clear the hook vec
        // (inside `shutdown_core_async`) after we saw `is_shutdown() ==
        // false` but before our push, leaving the hook registered in a
        // vec that `shutdown()` has already finished with — so the hook
        // would never run. When that race happens, run the hook inline,
        // consistent with the fast-path above.
        match self.shutdown_hooks.lock() {
            Ok(mut hooks) => {
                if self.is_shutdown() {
                    drop(hooks);
                    tracing::warn!(
                        "shutdown raced with hook registration — running hook immediately"
                    );
                    if let Err(_payload) =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook))
                    {
                        tracing::error!(
                            "post-shutdown hook panicked — bridge-specific cleanup \
                             may be incomplete"
                        );
                    }
                } else {
                    hooks.push(hook);
                }
            }
            Err(_) => {
                tracing::error!(
                    "shutdown_hooks mutex poisoned — hook not registered; \
                     bridge-specific cleanup may be incomplete on shutdown"
                );
            }
        }
    }

    /// Records `borrower` as a live user of a resource this instance owns.
    ///
    /// Every bridge node-start path registers whatever node it produced, so
    /// [`stop_borrowers`](Self::stop_borrowers) can stop that node before any
    /// bridge releases a `SQLCipher` handle. [`InstanceBorrower`] states why
    /// releasing first corrupts a database.
    ///
    /// Registration stores [`Weak`], so this call adds no ownership: a caller
    /// that drops its node handle leaves a dead entry, which a later
    /// registration prunes and which `stop_borrowers` skips.
    ///
    /// When [`stop_borrowers`](Self::stop_borrowers) already ran, this call
    /// stops `borrower` immediately instead of filing an entry nothing will
    /// read. That decides a race between a thread starting a node and a thread
    /// shutting an instance down: whichever order those two take, `borrower`
    /// ends up stopped.
    ///
    /// A poisoned registry `Mutex` is recovered via
    /// [`PoisonError::into_inner`], matching
    /// [`stop_borrowers`](Self::stop_borrowers): both critical sections only
    /// push to, prune, or take a `Vec`, so a poisoned guard still protects an
    /// intact registry, and skipping a registration would leave a node no
    /// shutdown can reach.
    pub fn register_borrower<B: InstanceBorrower + 'static>(&self, borrower: &Arc<B>) {
        let closed = {
            let mut registry = self
                .borrowers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if registry.closed {
                true
            } else {
                registry.entries.retain(|entry| entry.strong_count() > 0);
                registry
                    .entries
                    .push(Arc::downgrade(borrower) as Weak<dyn InstanceBorrower>);
                false
            }
        };
        if closed {
            borrower.stop();
        }
    }

    /// Stops every live borrower this instance recorded, and refuses later
    /// registrations by stopping them on arrival.
    ///
    /// [`BridgeInstanceCore::shutdown`] calls this first, so a node stops
    /// writing before [`BridgeInstanceCore::bridge_specific_shutdown`] closes
    /// a `SQLCipher` handle and drops an advisory `flock(2)`.
    ///
    /// Idempotent: a second call finds an empty entry list and stops nothing.
    /// Logs how many borrowers a caller had left running, which tells an
    /// operator whether `SCP.shutdown()` had nodes to stop or found them
    /// already stopped.
    /// Infallible: a poisoned `Mutex` is recovered via
    /// [`PoisonError::into_inner`], because a shutdown that skipped this step
    /// would leave a node writing to a closed database.
    pub fn stop_borrowers(&self) {
        let entries = {
            let mut registry = self
                .borrowers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            registry.closed = true;
            std::mem::take(&mut registry.entries)
        };
        let mut still_running = 0usize;
        for entry in entries {
            if let Some(borrower) = entry.upgrade() {
                if !borrower.stopped() {
                    still_running += 1;
                }
                borrower.stop();
            }
        }
        if still_running > 0 {
            tracing::info!(
                count = still_running,
                "shutdown stopped borrowers that a caller left running, before \
                 releasing what those borrowers write through"
            );
        }
    }

    /// Suspends the bridge instance.
    ///
    /// - Disconnects the relay (clears transport)
    /// - Keeps the instance alive but inactive (context state is preserved)
    /// - Intended for mobile app backgrounding
    ///
    /// After suspension, `is_suspended()` returns `true` and transport-dependent
    /// operations will fail. Call `resume()` to clear the suspended flag, then
    /// re-establish transport via `set_transport`.
    ///
    /// No-op if already shut down.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the transport `RwLock` is poisoned.
    pub fn suspend(&self) -> Result<(), TransportLockError> {
        if self.is_shutdown() {
            return Ok(());
        }
        // Set flag FIRST to prevent new operations from starting between
        // flag check and transport teardown.
        self.suspended.store(true, Ordering::SeqCst);
        // #1696: cancel the current reconnect-generation token so any
        // in-flight `reconnect_transport_if_pending` dial wakes on the
        // cancellation branch and drops its half-connected adapter
        // instead of completing against a torn-down instance. Rotate to
        // a fresh token so a later `resume()` gets a clean cancellation
        // scope rather than inheriting the already-cancelled one.
        self.rotate_reconnect_cancel();
        // Flush all context snapshots before disconnecting transport.
        // Best-effort: errors are logged inside flush_all_contexts_sync and do
        // not prevent suspension from completing. Skipped if the
        // Supervisor hasn't been set yet (i.e., suspend before any
        // context operation has run) — in that case there is no
        // supervisor to invoke and the call is a no-op. When set, the
        // supervisor's forwarder may itself report
        // `Err(ContextError::NotInitialized)` if no manager is
        // attached; we discard that to preserve the prior silent-skip
        // behavior.
        if let Some(supervisor) = self.supervisor.get() {
            let _ = supervisor.flush_all_contexts_sync();
        }
        if let Err(e) = self.clear_transport() {
            // Revert the suspended flag — the instance is not cleanly
            // suspended if transport wasn't cleared.
            self.suspended.store(false, Ordering::SeqCst);
            return Err(e);
        }
        tracing::debug!("bridge instance suspended");
        Ok(())
    }

    /// Cancels the current reconnect-generation token and installs a
    /// fresh one in its place (#1696).
    ///
    /// Lock is held only briefly — the cancellation itself is
    /// non-blocking (`CancellationToken::cancel()` is a relaxed
    /// `AtomicUsize` flip plus waker notification) and `take` +
    /// assignment are cheap.
    fn rotate_reconnect_cancel(&self) {
        let Ok(mut guard) = self.reconnect_cancel.lock() else {
            // Poisoned mutex — the previous holder panicked. Log and
            // move on; the stale token will still be cancelled (we can
            // still signal cancellation through a poisoned lock via
            // `PoisonError::into_inner`), but rotation is best-effort.
            tracing::warn!(
                "reconnect_cancel mutex poisoned — the stale token will remain; \
                 a subsequent resume() will fire against it"
            );
            return;
        };
        let old = std::mem::replace(&mut *guard, CancellationToken::new());
        old.cancel();
    }

    /// Returns a clone of the current reconnect-generation cancellation
    /// token (#1696). Callers select on this alongside their dial future
    /// so `suspend()` / `shutdown()` can drop half-connected sockets.
    #[must_use]
    pub fn reconnect_cancel_token(&self) -> CancellationToken {
        self.reconnect_cancel.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |guard| guard.clone(),
        )
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag so bridge operations can proceed.
    ///
    /// `resume` is `async` so the `BridgeInstanceCore::resume` default body can
    /// chain async work — reconnecting transport from pending relay URLs,
    /// rehydrating persisted context state — after the core flag flip. The
    /// core-only body below is `.await`-free and remains cheap.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the instance has been permanently shut down.
    //
    // The body is currently `.await`-free, but the `async` keyword is the
    // contract — the `BridgeInstanceCore::resume` trait method is async
    // (default impl delegates to this method), and per-bridge overrides
    // chain async transport reconnect and persisted-context restoration on
    // top. Making the core method sync would force awkward `.await`ing of
    // a non-future in every override.
    #[allow(clippy::unused_async)]
    pub async fn resume(&self) -> Result<(), LifecycleError> {
        if self.is_shutdown() {
            return Err(LifecycleError::AlreadyShutDown);
        }
        self.suspended.store(false, Ordering::SeqCst);
        tracing::debug!("bridge instance resumed");
        Ok(())
    }

    /// Shuts down the bridge instance permanently.
    ///
    /// - Clears transport (disconnects relay)
    /// - Clears all registries (known contexts, rate limiters)
    /// - Runs all registered shutdown hooks (bridge-specific cleanup)
    /// - Marks instance as shut down (all subsequent operations fail)
    ///
    /// Idempotent: calling `shutdown()` on an already-shut-down instance is
    /// a no-op. Hooks are drained on the first call and will not run again.
    ///
    /// Bridge-specific singleton registries (identity registry, UCAN
    /// registry, MCP registries, custody store, etc.) are the responsibility
    /// of the per-bridge concrete struct implementing [`BridgeInstanceCore`];
    /// they should be cleaned up in
    /// [`BridgeInstanceCore::bridge_specific_shutdown`] or by calling the
    /// async [`shutdown_core_async`](Self::shutdown_core_async) variant.
    ///
    /// # Hook execution
    ///
    /// Shutdown hooks are called in registration order after all
    /// `CoreFields`-owned state has been cleared (registries, economy
    /// trackers). Hooks handle bridge-specific singletons that cannot be
    /// owned by `CoreFields` (FFI bridge state, MCP registries). Together,
    /// these steps release key material held by custody providers
    /// (zeroized via `Drop` when `Arc` refcount reaches zero).
    ///
    /// This function is infallible. Transport lock failures are logged and
    /// cleanup continues. Shutdown must always complete regardless of
    /// intermediate failures.
    pub fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return; // Already shut down
        }
        // Stop borrowers first, so every terminal transition of `CoreFields`
        // ends borrowed writes — not only whichever transition
        // [`BridgeInstanceCore::shutdown`] drives. This path clears registries
        // and flushes persistence below, and a node writing through this
        // instance's storage during that flush would race it.
        self.stop_borrowers();
        // Fire the cancellation token so any tasks spawned under this
        // instance can exit cooperatively. Pending tasks inside `self.tasks`
        // are not drained here — the sync variant cannot await. Callers
        // that need a bounded wait use `shutdown_core_async`.
        self.cancel.cancel();
        // #1696: also cancel any in-flight reconnect dial so its socket
        // teardown fires before the instance is considered dropped.
        // Rotation is unnecessary during shutdown (no resume will
        // follow), so a plain cancel is enough.
        if let Ok(guard) = self.reconnect_cancel.lock() {
            guard.cancel();
        }
        self.blocking_run_shutdown_side_effects();
    }

    // -----------------------------------------------------------------
    // Transport accessors
    // -----------------------------------------------------------------

    /// Stores a pre-built `Arc<TransportManager>` (called after relay
    /// connect).
    ///
    /// The `Arc` allows async tasks (e.g., NAPI subscription) to clone the
    /// reference without keeping the `RwLock` guard alive across `.await`
    /// points.
    ///
    /// Replaces any previous transport manager.
    ///
    /// If the instance is shut down, logs a warning but still sets the
    /// transport — matching the `bridge_instance()` / `context_manager()`
    /// pattern where shutdown operations fail naturally at the MLS/transport
    /// layer rather than being hard-rejected.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the `RwLock` is poisoned, or if the instance is
    /// suspended (lifecycle violation — call `resume()` first).
    #[allow(clippy::significant_drop_tightening)]
    pub fn set_transport(
        &self,
        manager: Arc<scp_transport::TransportManager>,
    ) -> Result<(), TransportLockError> {
        // Shutdown: warn only — matches bridge_instance()/context_manager()
        // behavior where shutdown is a terminal state and operations fail
        // naturally at the MLS/transport layer. This avoids hard failures
        // in test teardown when afterAll calls shutdown() and a later test
        // file tries to set transport.
        if self.is_shutdown() {
            tracing::warn!("set_transport called after shutdown — transport will not be usable");
        }
        if self.is_suspended() {
            return Err(TransportLockError::Rejected(
                "bridge instance is suspended — call resume() before setting transport".to_owned(),
            ));
        }
        let mut guard = self
            .transport
            .write()
            .map_err(|_| TransportLockError::Poisoned)?;
        *guard = Some(manager);
        Ok(())
    }

    /// Clears the transport manager (called on disconnect or suspend).
    ///
    /// Does **not** clear the stored relay URL — the URL is preserved so
    /// that callers can retrieve it after [`Self::resume`] and reconnect to the
    /// same relay. The relay URL is only cleared explicitly in
    /// [`Self::shutdown`] (after flush) or by the caller via an explicit
    /// disconnect flow.
    ///
    /// After this, relay-based operations will fail until a new transport
    /// manager is set.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the `RwLock` is poisoned.
    #[allow(clippy::significant_drop_tightening)]
    pub fn clear_transport(&self) -> Result<(), TransportLockError> {
        let mut guard = self
            .transport
            .write()
            .map_err(|_| TransportLockError::Poisoned)?;
        *guard = None;
        Ok(())
    }

    /// Returns `true` if a transport manager has been set.
    #[must_use]
    pub fn has_transport(&self) -> bool {
        self.transport.read().is_ok_and(|guard| guard.is_some())
    }

    /// Returns this instance's transport selector for connect-time transparent
    /// QUIC↔WebSocket selection (spec §10.14.3 item 4; ADR-037).
    ///
    /// Connect sites route through the returned selector's
    /// `select_and_connect_discovering*` methods so the relay's advertised
    /// transports (`.well-known/scp`, spec §10.5.1) drive the QUIC-vs-WebSocket
    /// decision, and so the per-relay QUIC-suppression and well-known caches
    /// persist across connects/reconnects to the same relay.
    #[must_use]
    pub fn transport_selector(&self) -> Arc<scp_transport::TransportSelector> {
        Arc::clone(&self.transport_selector)
    }

    /// Registers `url` as a relay that this bridge intends to stay
    /// connected to.
    ///
    /// Callers (bridge `transport_connect` functions) call this immediately
    /// after [`Self::set_transport`] so that [`Self::pending_relay_urls`] returns the
    /// URL in subsequent reconnect attempts after [`Self::resume`]. Duplicate
    /// calls are idempotent because the underlying set deduplicates.
    ///
    /// No-op after [`Self::shutdown`] — [`Self::pending_relay_urls`] is cleared on
    /// shutdown and we must not resurrect it by admitting a late writer.
    /// Without this guard, a concurrent `add_relay_url` racing with a
    /// shutdown-triggered `relay_urls.clear()` could leave a stale URL in
    /// the set that a subsequent `resume` would try to dial. The
    /// `is_shutdown()` check is performed twice — once fast-path before
    /// acquiring the lock, and once after — to close the TOCTOU window
    /// between the first check and the insert (symmetric with
    /// [`register_shutdown_hook`]).
    ///
    /// If the `relay_urls` mutex is poisoned (a previous caller panicked
    /// while holding it), the URL is silently dropped and a warning is
    /// logged — a lost relay URL on resume is recoverable by the caller.
    pub fn add_relay_url(&self, url: String) {
        if self.is_shutdown() {
            return;
        }
        match self.relay_urls.lock() {
            Ok(mut guard) => {
                // Re-check `is_shutdown` after acquiring the lock to close
                // the TOCTOU window between the check above and the insert
                // below. Without this, a concurrent `shutdown()` could drain
                // and clear the `relay_urls` set (inside
                // `shutdown_core_async`) after we saw `is_shutdown() ==
                // false` but before our insert, leaving a stale URL in a
                // set that a subsequent `resume()` would try to dial.
                // Matches the symmetric re-check pattern in
                // [`register_shutdown_hook`].
                if self.is_shutdown() {
                    drop(guard);
                    return;
                }
                guard.insert(url);
            }
            Err(_) => {
                tracing::warn!("relay_urls mutex poisoned — relay URL not stored");
            }
        }
    }

    /// Removes a single relay URL from the pending-reconnect set.
    ///
    /// Called by explicit transport disconnect paths (`transport_disconnect`)
    /// so that a subsequent `resume()` does not re-open a URL the caller
    /// intentionally walked away from.
    ///
    /// Silently no-ops if the URL is not registered or if the mutex is
    /// poisoned.
    pub fn remove_relay_url(&self, url: &str) {
        match self.relay_urls.lock() {
            Ok(mut guard) => {
                guard.remove(url);
            }
            Err(_) => {
                tracing::warn!("relay_urls mutex poisoned — relay URL not removed");
            }
        }
    }

    /// Returns a snapshot of every relay URL registered via
    /// [`Self::add_relay_url`] and not yet removed.
    ///
    /// After [`Self::suspend`] the set is preserved so the
    /// `BridgeInstanceCore::resume` default body can reconnect each relay. After
    /// [`Self::shutdown`] the set is empty.
    ///
    /// Returns an empty set if no URLs have been stored, if the instance
    /// has been shut down, or if the internal mutex is poisoned.
    #[must_use]
    pub fn pending_relay_urls(&self) -> HashSet<String> {
        self.relay_urls
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Returns `true` if any relay URL is currently registered.
    #[must_use]
    pub fn has_pending_relay_urls(&self) -> bool {
        self.relay_urls.lock().is_ok_and(|guard| !guard.is_empty())
    }

    /// Reconnects every pending relay URL registered via [`Self::add_relay_url`].
    ///
    /// Iterates the deduplicated snapshot from [`Self::pending_relay_urls`], calls
    /// `NativeRelayAdapter::connect_sourced` (source = `Explicit`) for each
    /// URL, wraps the adapter in a [`scp_transport::TransportManager`], and
    /// stores it via [`Self::set_transport`]. Called from the
    /// `BridgeInstanceCore::resume` default body after the core flag flip.
    ///
    /// Collects every failure and returns the first as
    /// [`LifecycleError::ReconnectFailed`] so the caller sees a real error.
    /// Successfully-reconnected URLs remain in the pending set — the caller
    /// is free to retry a failing URL directly via `transport_connect`.
    ///
    /// No-ops when the pending set is empty (e.g. a bridge that never
    /// connected a relay in the first place, or a test-only resume cycle).
    /// No-ops when the instance is shut down.
    ///
    /// Each reconnect uses the platform-default transport profile so that
    /// cover traffic, heartbeat, and suppression monitoring auto-start with
    /// matching behaviour to the original `transport_connect` call.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::ReconnectFailed`] carrying the first URL
    /// that failed plus a redacted reason. Shutdown state short-circuits
    /// with [`LifecycleError::AlreadyShutDown`] rather than attempting
    /// reconnects against a torn-down instance.
    ///
    /// When reconnect was cancelled by a concurrent `suspend()` /
    /// `shutdown()`, the `reason` field explicitly states "suspended
    /// during reconnect" (empty `url`) so callers can distinguish a
    /// suspend race from a dial / TLS / handshake failure. Non-cancel
    /// failures carry the underlying connect error verbatim.
    // Line-count waiver: dial spawn + cancel-aware collect + deterministic
    // install phase form a single atomic operation. Splitting it across
    // helpers (simplifier #1) lost the linear reading of the suspend/cancel
    // invariants — keep it inline instead.
    #[allow(clippy::too_many_lines)]
    pub async fn reconnect_transport_if_pending(&self) -> Result<(), LifecycleError> {
        if self.is_shutdown() {
            return Err(LifecycleError::AlreadyShutDown);
        }
        let urls = self.pending_relay_urls();
        if urls.is_empty() {
            return Ok(());
        }
        // #1696: snapshot the current reconnect-generation cancellation
        // token once, at entry, and race every dial against it. If
        // `suspend()` fires mid-dial, `token.cancelled()` wakes and we
        // abort the whole reconnect — any in-flight
        // `NativeRelayAdapter::connect_sourced` future is dropped, so
        // its socket teardown happens before we return instead of
        // leaking an unowned adapter.
        let cancel = self.reconnect_cancel_token();
        let profile = scp_transport::profile::TransportProfile::platform_default();
        // Build ONE TransportManager and register every successful adapter
        // in it. `TransportManager::new(adapter)` creates a manager with a
        // single adapter, so calling it in a loop and set_transport'ing each
        // time would keep only the last URL's adapter. Using `builder()` +
        // `add_adapter` preserves multi-relay semantics.
        //
        // Dial every URL in parallel with a per-URL timeout. A serial loop
        // would let a single slow (or attacker-controlled) relay stall
        // reconnect against every remaining relay in the pending set —
        // reducing the multi-relay tolerance the caller paid for to the
        // slowest link. A 5s ceiling per URL bounds the worst case while
        // still accommodating real-world TLS + relay handshake overhead.
        // See red-hat RED-1003.
        let mut join_set: tokio::task::JoinSet<(
            String,
            Result<scp_transport::native::adapter::NativeRelayAdapter, String>,
        )> = tokio::task::JoinSet::new();
        for url in urls {
            let sourced = scp_transport::relay::connection::SourcedRelayUrl {
                url: url.clone(),
                source: scp_transport::relay::connection::RelayUrlSource::Explicit,
            };
            let profile_for_task = profile; // TransportProfile is Copy
            let url_for_task = url.clone();
            join_set.spawn(async move {
                let outcome = match tokio::time::timeout(
                    RECONNECT_PER_URL_TIMEOUT,
                    scp_transport::native::adapter::NativeRelayAdapter::connect_sourced(
                        &sourced,
                        Some(&profile_for_task),
                    ),
                )
                .await
                {
                    Ok(Ok(adapter)) => Ok(adapter),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_elapsed) => Err(format!(
                        "connect timeout after {}s",
                        RECONNECT_PER_URL_TIMEOUT.as_secs()
                    )),
                };
                (url_for_task, outcome)
            });
        }
        // Collect every result, racing against the reconnect-generation
        // cancel token. If `suspend()` / `shutdown()` fires while dials are
        // outstanding, abort the whole set so in-flight
        // `NativeRelayAdapter::connect_sourced` futures are dropped and
        // their partial sockets torn down (#1696) rather than ending up
        // as unowned `NativeRelayAdapter` instances.
        let mut results: Vec<(String, Result<_, _>)> = Vec::new();
        // Track the first panic so callers don't see a silent success when
        // every spawned dial task panicked (leaving `results` empty).
        // Without this, the install phase below would return `Ok(())`
        // despite no adapters being installed — a split-brain where
        // `resume()` reports success but transport is broken.
        let mut first_panic_failure: Option<LifecycleError> = None;
        // Separate boolean so the partial-success log emission downstream
        // can flag `panicked = true` without having to parse
        // `first_failure`'s reason string. Used for log-based alerting
        // (bug-catcher L1): a panic inside a `tokio::spawn` is a defect,
        // not an expected dial failure, and should page.
        let mut any_task_panicked = false;
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    tracing::debug!(
                        "reconnect_transport_if_pending: cancelled mid-dial — aborting in-flight connects"
                    );
                    join_set.abort_all();
                    while join_set.join_next().await.is_some() {}
                    return Err(LifecycleError::ReconnectFailed {
                        url: String::new(),
                        reason:
                            "reconnect suspended during reconnect — caller invoked suspend()/shutdown() while dials were in flight"
                                .to_owned(),
                    });
                }
                next = join_set.join_next() => {
                    match next {
                        None => break,
                        Some(Ok(pair)) => results.push(pair),
                        Some(Err(join_err)) => {
                            any_task_panicked = true;
                            tracing::warn!(
                                error = %join_err,
                                "reconnect_transport_if_pending: spawned task panicked — \
                                 ignoring this URL for this reconnect cycle"
                            );
                            if first_panic_failure.is_none() {
                                first_panic_failure = Some(LifecycleError::ReconnectFailed {
                                    url: String::new(),
                                    reason: format!(
                                        "spawned reconnect task panicked: {join_err}"
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        // --- install phase (re-inlined from the previous
        // `install_reconnected_adapters` helper so the suspend/cancel
        // invariants read linearly alongside the dial phase) ---
        //
        // Sort by URL before registering adapters so the adapter ordering
        // inside `TransportManager` is deterministic regardless of
        // network-timing jitter across the spawned tasks.
        results.sort_by(|a, b| a.0.cmp(&b.0));
        let mut manager = scp_transport::TransportManager::builder();
        // Seed `first_failure` with any panic the outer loop captured so
        // a silent-success path can't swallow the case where every
        // spawned task panicked (empty `results`, no per-URL failure).
        let mut first_failure: Option<LifecycleError> = first_panic_failure;
        let mut connected_count = 0_usize;
        for (url, outcome) in results {
            match outcome {
                Ok(adapter) => {
                    // `add_adapter` may return an `EvictionOutcome` if we hit the
                    // connection budget; we don't surface it here because the
                    // caller's reconnect intent is best-effort multi-relay.
                    let _eviction = manager.add_adapter(Box::new(adapter));
                    connected_count += 1;
                }
                Err(reason) => {
                    tracing::warn!(
                        url = %url,
                        error = %reason,
                        "reconnect_transport_if_pending: relay reconnect failed — leaving URL in pending set for retry"
                    );
                    if first_failure.is_none() {
                        first_failure = Some(LifecycleError::ReconnectFailed {
                            url: url.clone(),
                            reason,
                        });
                    }
                }
            }
        }
        // #1696: one more cancellation check between the dial loop and
        // `set_transport`. If suspend fired *after* the last successful
        // dial but *before* we install the manager, installing it now
        // would immediately fail the suspended-state guard — but more
        // importantly, the adapters we just connected belong to a
        // cancelled generation and should be dropped rather than
        // installed.
        if cancel.is_cancelled() {
            tracing::debug!(
                "reconnect_transport_if_pending: cancelled before set_transport — dropping {connected_count} connected adapter(s)"
            );
            // `manager` (and its adapters) are dropped at the end of
            // this block. Each adapter's Drop fires `cover_traffic_cancel`
            // and `heartbeat_cancel`, and the relay client's background
            // tasks exit — so the socket closes cleanly rather than
            // leaking.
            drop(manager);
            return Err(LifecycleError::ReconnectFailed {
                url: String::new(),
                reason:
                    "reconnect suspended during reconnect — caller invoked suspend()/shutdown() before install"
                        .to_owned(),
            });
        }
        // Only install the manager if at least one adapter is registered —
        // installing an empty manager would make later relay operations fail
        // with a confusing "no adapters" error instead of the clearer
        // "reconnect failed" we surface below.
        let install_failed = if connected_count > 0 {
            if let Err(e) = self.set_transport(Arc::new(manager)) {
                tracing::warn!(
                    error = %e,
                    "reconnect_transport_if_pending: set_transport failed after successful reconnects"
                );
                if first_failure.is_none() {
                    first_failure = Some(LifecycleError::ReconnectFailed {
                        url: String::new(),
                        reason: e.to_string(),
                    });
                }
                true
            } else {
                false
            }
        } else {
            // No adapters connected — nothing installed, no install failure
            // to distinguish from dial/panic failures.
            false
        };
        // If at least one adapter actually landed in the transport manager,
        // report success: the caller would otherwise see `Err` but observe
        // a working transport, and a retry would duplicate the already-open
        // sockets. A panic inside a spawned reconnect task is a real defect
        // (uncaught `unwrap`, assertion failure, OOM) and is promoted to
        // `tracing::error!` with a structured `panicked` field so log-based
        // alerting can page on it. Plain per-URL dial failures (network
        // refused, timeout) stay at `tracing::warn!` — those are routine
        // and recoverable on the next reconnect cycle. If `set_transport`
        // itself failed, we keep the error so the caller can distinguish
        // "nothing landed" from "transport live with some losses".
        if connected_count > 0 && !install_failed {
            if let Some(err) = first_failure.as_ref() {
                if any_task_panicked {
                    tracing::error!(
                        error = %err,
                        connected_count,
                        panicked = true,
                        "reconnect_transport_if_pending: partial success — transport installed \
                         with {connected_count} adapter(s); at least one reconnect task \
                         PANICKED — investigate the backtrace, the bridge is usable but a \
                         reconnect path is throwing"
                    );
                } else {
                    tracing::warn!(
                        error = %err,
                        connected_count,
                        panicked = false,
                        "reconnect_transport_if_pending: partial success — transport installed \
                         with {connected_count} adapter(s); some dials failed but the bridge \
                         is usable"
                    );
                }
            }
            return Ok(());
        }
        first_failure.map_or(Ok(()), Err)
    }

    /// Rehydrates every context that was persisted before the most recent
    /// `suspend()`/`shutdown()` cycle — see
    /// `Supervisor::restore_all_contexts`.
    ///
    /// Called from the `BridgeInstanceCore::resume` default body after
    /// [`Self::reconnect_transport_if_pending`] (concrete bridges MUST NOT
    /// override `resume`). No-ops silently when:
    /// - No `ContextManager` is attached yet (the bridge hasn't seen its
    ///   first `identity_create` / `context_create`).
    /// - The attached `ContextManager` was built without persistence
    ///   (ephemeral test / in-memory path).
    ///
    /// Routes through `Supervisor::restore_on_startup` (ADR-049),
    /// which restores contexts BEFORE the durable saga-journal replay in the
    /// §17.16.4-required restore-then-replay order — so a process restart
    /// rehydrates contexts and then reconciles any crash-orphaned saga journal
    /// entries on the same startup pass, with each recovery arm driving a
    /// now-resident participant (the cross-context caller reversal is delivered
    /// and the journal reaches terminal-`Aborted` with the refund applied).
    ///
    /// Errors from the manager itself are logged but not propagated —
    /// restore is a best-effort rehydration. A caller that needs failure
    /// visibility calls `Supervisor::restore_on_startup` directly.
    pub async fn restore_all_persisted_contexts(&self) {
        // Supervisor restores contexts and then replays the saga journal when a
        // manager is attached, and returns `Err(ContextError::NotInitialized)`
        // otherwise. Both the no-supervisor path (instance has no supervisor
        // wired yet) and the "no persistence provider configured" path are
        // expected for ephemeral bridges and log at debug; a genuine
        // saga-journal load failure after a successful restore is a real fault
        // and logs at warn.
        let Some(supervisor) = self.supervisor.get() else {
            tracing::debug!("restore_all_persisted_contexts: skipped (no Supervisor attached yet)");
            return;
        };
        match supervisor.restore_on_startup().await {
            Ok(restored) => {
                tracing::debug!(
                    count = restored.len(),
                    "restore_all_persisted_contexts: rehydrated contexts after resume"
                );
            }
            Err(
                e @ (scp_core::context::ContextError::NotInitialized(_)
                | scp_core::context::ContextError::PersistenceFailed(_)),
            ) => {
                // `no persistence provider configured` (`PersistenceFailed`) is
                // the expected path for ephemeral bridges; `NotInitialized` (no
                // ContextManager attached to the supervisor) is likewise an
                // expected no-op — the bridge hasn't seen its first
                // identity_create / context_create. Log at debug.
                tracing::debug!(
                    error = %e,
                    "restore_all_persisted_contexts: skipped (no-op is expected when persistence is not configured or no supervisor is attached)"
                );
            }
            Err(e) => {
                // A genuine recovery failure (e.g. a saga-journal load error
                // surfaced by the replay leg after a successful restore) is a
                // real fault, not an expected ephemeral no-op — surface it at
                // warn so operators see it.
                tracing::warn!(
                    error = %e,
                    "restore_all_persisted_contexts: startup recovery failed (saga-journal replay or context restore error)"
                );
            }
        }
    }

    /// Returns an `Arc` clone of the current transport manager, if one exists.
    ///
    /// Used by NAPI `context_subscribe` which needs to move the manager
    /// reference into an async task that outlives any lock guard.
    ///
    /// # Errors
    ///
    /// Returns `TransportLockError::Poisoned` if the lock is poisoned.
    pub fn get_transport_arc(
        &self,
    ) -> Result<Option<Arc<scp_transport::TransportManager>>, TransportLockError> {
        let guard = self
            .transport
            .read()
            .map_err(|_| TransportLockError::Poisoned)?;
        Ok(guard.clone())
    }

    /// Executes a closure with a read reference to the `TransportManager`.
    ///
    /// # Errors
    ///
    /// Returns `TransportLockError::Poisoned` if the lock is poisoned,
    /// or `TransportLockError::NotInitialized` if no transport manager has
    /// been set.
    #[allow(clippy::significant_drop_tightening)]
    pub fn with_transport<T>(
        &self,
        f: impl FnOnce(&scp_transport::TransportManager) -> T,
    ) -> Result<T, TransportLockError> {
        let guard = self.transport.read().map_err(|_| {
            tracing::debug!("transport RwLock poisoned (a writer panicked)");
            TransportLockError::Poisoned
        })?;
        let manager = guard.as_deref().ok_or_else(|| {
            tracing::debug!("transport slot is empty — no transport_connect call");
            TransportLockError::NotInitialized
        })?;
        Ok(f(manager))
    }

    /// Executes a closure with a mutable reference to the `TransportManager`.
    ///
    /// Requires exclusive access to the `Arc` (refcount == 1). If subscription
    /// tasks hold cloned `Arc` references, this will return
    /// [`TransportLockError::InUse`].
    ///
    /// # Errors
    ///
    /// Returns `TransportLockError::Poisoned` if the lock is poisoned,
    /// `TransportLockError::NotInitialized` if no transport manager has been
    /// set, or `TransportLockError::InUse` if the `Arc` has other holders.
    #[allow(clippy::significant_drop_tightening)]
    pub fn with_transport_mut<T>(
        &self,
        f: impl FnOnce(&mut scp_transport::TransportManager) -> T,
    ) -> Result<T, TransportLockError> {
        let mut guard = self.transport.write().map_err(|_| {
            tracing::debug!("transport RwLock poisoned (a writer panicked)");
            TransportLockError::Poisoned
        })?;
        let arc = guard.as_mut().ok_or_else(|| {
            tracing::debug!("transport slot is empty — no transport_connect call");
            TransportLockError::NotInitialized
        })?;
        // Capture strong count before the mutable borrow attempt (can't borrow
        // arc immutably inside the ok_or_else closure while get_mut borrows it).
        let strong_count = Arc::strong_count(arc);
        let manager = Arc::get_mut(arc).ok_or_else(|| {
            tracing::debug!(
                strong_count,
                "transport Arc has multiple holders — subscription task(s) holding references",
            );
            TransportLockError::InUse
        })?;
        Ok(f(manager))
    }

    // -----------------------------------------------------------------
    // Known contexts accessors
    // -----------------------------------------------------------------

    /// Returns a reference to the known-contexts `DashMap`.
    ///
    /// **Prefer the typed accessors** ([`Self::register_known_context`],
    /// [`Self::remove_known_context`], [`Self::all_known_contexts`],
    /// [`Self::known_contexts_for_member`], [`Self::known_context_count`],
    /// [`Self::has_known_context`]) which enforce capacity limits. Direct
    /// mutation via this reference bypasses capacity enforcement.
    #[must_use]
    pub const fn known_contexts(&self) -> &DashMap<String, KnownContext> {
        &self.known_contexts
    }

    /// Returns the number of known contexts in the discovery registry.
    #[must_use]
    pub fn known_context_count(&self) -> usize {
        self.known_contexts.len()
    }

    /// Returns whether the given context ID is in the discovery registry.
    #[must_use]
    pub fn has_known_context(&self, context_id: &str) -> bool {
        self.known_contexts.contains_key(context_id)
    }

    /// Registers a known context in the discovery registry.
    ///
    /// Overwrites any existing entry for the same context ID (idempotent).
    /// When the registry is at capacity ([`MAX_KNOWN_CONTEXTS`]), evicts the
    /// oldest entry (by `last_seen` timestamp) before inserting.
    ///
    /// Note: Under concurrent registration, the cap may be temporarily exceeded
    /// by up to `num_threads - 1` entries. This is bounded and benign.
    pub fn register_known_context(&self, context_id: &str, known: KnownContext) {
        // If this context_id already exists, it's an overwrite — no eviction needed.
        if !self.known_contexts.contains_key(context_id)
            && self.known_contexts.len() >= MAX_KNOWN_CONTEXTS
        {
            // Find the entry with the smallest (oldest) last_seen timestamp.
            if let Some(oldest) = self
                .known_contexts
                .iter()
                .min_by_key(|entry| entry.value().last_seen)
            {
                let oldest_key = oldest.key().clone();
                drop(oldest);
                self.known_contexts.remove(&oldest_key);
                tracing::debug!(
                    evicted_context_id = %oldest_key,
                    capacity = MAX_KNOWN_CONTEXTS,
                    "evicted oldest known context to make room for new registration"
                );
            }
        }
        self.known_contexts.insert(context_id.to_owned(), known);
    }

    /// Removes a known context from the discovery registry.
    pub fn remove_known_context(&self, context_id: &str) {
        self.known_contexts.remove(context_id);
    }

    /// Returns all known contexts from the discovery registry.
    #[must_use]
    pub fn all_known_contexts(&self) -> Vec<(String, KnownContext)> {
        self.known_contexts
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Returns known contexts where the given DID is the registered member.
    #[must_use]
    pub fn known_contexts_for_member(&self, member_did: &str) -> Vec<(String, KnownContext)> {
        self.known_contexts
            .iter()
            .filter(|entry| entry.value().member_did == member_did)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    // -----------------------------------------------------------------
    // Rate limiter accessors
    // -----------------------------------------------------------------

    /// Returns a reference to the rate-limiters `DashMap`.
    ///
    /// **Prefer [`Self::with_rate_limit_tracker`]** which enforces capacity limits.
    /// Direct mutation via this reference bypasses capacity enforcement.
    #[must_use]
    pub const fn rate_limiters(&self) -> &DashMap<String, RateLimitTracker> {
        &self.rate_limiters
    }

    /// Returns the number of rate limit trackers in the registry.
    #[must_use]
    pub fn rate_limiter_count(&self) -> usize {
        self.rate_limiters.len()
    }

    /// Executes a closure with a mutable reference to the rate limit tracker
    /// for the given identity DID, creating a default tracker if none exists.
    ///
    /// When the registry is at capacity ([`MAX_RATE_LIMITERS`]) and the
    /// requested DID does not already have a tracker, the oldest (first)
    /// entry is evicted to make room. This ensures rate limiting always has
    /// persistent history — an evicted tracker loses its window state, but
    /// rate limit bypass requires evicting and re-creating the same DID
    /// repeatedly, which is itself a detectable attack pattern.
    ///
    /// Note: Under concurrent creation, the cap may be temporarily exceeded
    /// by up to `num_threads - 1` entries. This is bounded and benign.
    pub fn with_rate_limit_tracker<F, T>(&self, identity_did: &str, f: F) -> T
    where
        F: FnOnce(&mut RateLimitTracker) -> T,
    {
        // If the entry already exists, serve it regardless of capacity.
        if let Some(mut entry) = self.rate_limiters.get_mut(identity_did) {
            return f(entry.value_mut());
        }
        // New entry: evict oldest if at capacity.
        if self.rate_limiters.len() >= MAX_RATE_LIMITERS {
            // Move the iterator result out before entering the remove call to
            // avoid holding the DashMap shard lock across the remove (which
            // would deadlock on the same shard).
            let oldest_key = self
                .rate_limiters
                .iter()
                .next()
                .map(|entry| entry.key().clone());
            if let Some(oldest_key) = oldest_key {
                self.rate_limiters.remove(&oldest_key);
                tracing::debug!(
                    evicted_did = %oldest_key,
                    capacity = MAX_RATE_LIMITERS,
                    "evicted oldest rate limiter entry to make room for new DID"
                );
            }
        }
        let mut entry = self
            .rate_limiters
            .entry(identity_did.to_owned())
            .or_default();
        f(entry.value_mut())
    }

    // -----------------------------------------------------------------
    // Economy accessors
    // -----------------------------------------------------------------

    /// Reads the budget tracker for a context, creating one if it doesn't exist.
    ///
    /// The closure receives an immutable reference to the tracker.
    ///
    /// When the registry is at capacity ([`MAX_ECONOMY_CONTEXTS`]) and the
    /// requested context ID does not already have a tracker, an ephemeral
    /// (non-persisted) default tracker is used and a warning is logged.
    /// Budget trackers are 1:1 with contexts, so the cap should never be
    /// reached unless [`Self::remove_economy_state`] is not called on context cleanup.
    ///
    /// After shutdown, returns an ephemeral tracker to avoid re-populating
    /// the cleared `DashMap`.
    pub fn with_economy_budget<T, F>(&self, context_id: &str, f: F) -> T
    where
        F: FnOnce(&MemberBudgetTracker) -> T,
    {
        if self.is_shutdown() {
            // Post-shutdown: use ephemeral tracker, don't re-populate cleared map
            let ephemeral = MemberBudgetTracker::default();
            return f(&ephemeral);
        }
        if let Some(entry) = self.economy_budgets.get(context_id) {
            return f(entry.value());
        }
        if self.economy_budgets.len() >= MAX_ECONOMY_CONTEXTS {
            tracing::warn!(
                context_id = %context_id,
                capacity = MAX_ECONOMY_CONTEXTS,
                "economy budget registry at capacity — using ephemeral tracker; \
                 call remove_economy_state during context cleanup"
            );
            let ephemeral = MemberBudgetTracker::default();
            return f(&ephemeral);
        }
        let entry = self
            .economy_budgets
            .entry(context_id.to_owned())
            .or_default();
        f(entry.value())
    }

    /// Mutably accesses the budget tracker for a context, creating one if needed.
    ///
    /// The closure receives a mutable reference to the tracker.
    ///
    /// When the registry is at capacity ([`MAX_ECONOMY_CONTEXTS`]) and the
    /// requested context ID does not already have a tracker, an ephemeral
    /// (non-persisted) default tracker is used and a warning is logged.
    ///
    /// After shutdown, returns an ephemeral tracker to avoid re-populating
    /// the cleared `DashMap`.
    pub fn with_economy_budget_mut<T, F>(&self, context_id: &str, f: F) -> T
    where
        F: FnOnce(&mut MemberBudgetTracker) -> T,
    {
        if self.is_shutdown() {
            // Post-shutdown: use ephemeral tracker, don't re-populate cleared map
            let mut ephemeral = MemberBudgetTracker::default();
            return f(&mut ephemeral);
        }
        if let Some(mut entry) = self.economy_budgets.get_mut(context_id) {
            return f(entry.value_mut());
        }
        if self.economy_budgets.len() >= MAX_ECONOMY_CONTEXTS {
            tracing::warn!(
                context_id = %context_id,
                capacity = MAX_ECONOMY_CONTEXTS,
                "economy budget registry at capacity — using ephemeral tracker; \
                 call remove_economy_state during context cleanup"
            );
            let mut ephemeral = MemberBudgetTracker::default();
            return f(&mut ephemeral);
        }
        let mut entry = self
            .economy_budgets
            .entry(context_id.to_owned())
            .or_default();
        f(entry.value_mut())
    }

    /// Accesses the antispam velocity tracker for a context, creating one if
    /// needed.
    ///
    /// The closure receives a reference to the tracker (which is internally
    /// `Mutex`-protected, so `&self` methods like `record_message` and
    /// `get_velocity` work without `&mut`).
    ///
    /// When the registry is at capacity ([`MAX_ECONOMY_CONTEXTS`]) and the
    /// requested context ID does not already have a tracker, an ephemeral
    /// (non-persisted) tracker is used and a warning is logged.
    ///
    /// After shutdown, returns an ephemeral tracker to avoid re-populating
    /// the cleared `DashMap`.
    pub fn with_economy_antispam<T, F>(&self, context_id: &str, f: F) -> T
    where
        F: FnOnce(&SenderVelocityTracker) -> T,
    {
        if self.is_shutdown() {
            // Post-shutdown: use ephemeral tracker, don't re-populate cleared map
            let ephemeral = SenderVelocityTracker::new(ANTISPAM_DEFAULT_WINDOW_SECS);
            return f(&ephemeral);
        }
        if let Some(entry) = self.economy_antispam.get(context_id) {
            return f(entry.value());
        }
        if self.economy_antispam.len() >= MAX_ECONOMY_CONTEXTS {
            tracing::warn!(
                context_id = %context_id,
                capacity = MAX_ECONOMY_CONTEXTS,
                "economy antispam registry at capacity — using ephemeral tracker; \
                 call remove_economy_state during context cleanup"
            );
            let ephemeral = SenderVelocityTracker::new(ANTISPAM_DEFAULT_WINDOW_SECS);
            return f(&ephemeral);
        }
        let entry = self
            .economy_antispam
            .entry(context_id.to_owned())
            .or_insert_with(|| SenderVelocityTracker::new(ANTISPAM_DEFAULT_WINDOW_SECS));
        f(entry.value())
    }

    /// Removes economy state (budget tracker and antispam tracker) for a context.
    ///
    /// Should be called during context cleanup for long-running processes.
    pub fn remove_economy_state(&self, context_id: &str) {
        self.economy_budgets.remove(context_id);
        self.economy_antispam.remove(context_id);
    }

    // -----------------------------------------------------------------
    // Bridge connector state accessors
    // -----------------------------------------------------------------

    /// Returns a reference to the bridge connector state `DashMap`.
    ///
    /// Keyed by context ID. Each entry holds a [`BridgeContextState`] with
    /// the shadow registry and sender key store for that context.
    #[must_use]
    pub const fn bridge_state(&self) -> &DashMap<String, BridgeContextState> {
        &self.bridge_state
    }

    /// Removes per-context bridge connector state on context close, preventing
    /// unbounded memory growth in long-running processes.
    pub fn remove_bridge_state(&self, context_id: &str) {
        self.bridge_state.remove(context_id);
    }

    /// Clears all bridge connector state entries. Called during shutdown.
    pub fn clear_bridge_state(&self) {
        self.bridge_state.clear();
    }

    // -----------------------------------------------------------------
    // Persona-source seam accessors (ADR-039 Enforcement-Stack Layer 2)
    // -----------------------------------------------------------------

    /// Returns a clone of the current message-send persona source (ADR-039
    /// Enforcement-Stack Layer 2).
    ///
    /// Consulted once per message-send at each native bridge's send site to
    /// choose the `#active`/`#agent` signing persona. Cloning the `Arc` (cheap)
    /// means the send never holds the lock. Defaults to `#active` (the
    /// permanent conservative fail-safe) until a determiner (RFC #2242) installs
    /// a real source.
    #[must_use]
    pub fn persona_source(&self) -> crate::persona::PersonaSource {
        self.persona_source
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Installs a message-send persona source. **Test-only.**
    ///
    /// Production has no persona-source setter: the *determiner* that would
    /// install a non-default (`#agent`-capable) source is owned by RFC #2242
    /// (<https://github.com/limn-works/scp/discussions/2242>), together with the
    /// Layer-1 custody enforcement that makes a persona claim non-forgeable.
    /// Gating this behind `test`/`testing` keeps every shipped production path
    /// pinned to the `#active` fail-safe until that determiner lands, so the
    /// seam cannot silently attribute a send to `#agent` before the enforcement
    /// exists.
    #[cfg(any(test, feature = "testing"))]
    pub fn set_persona_source_for_test(&self, source: crate::persona::PersonaSource) {
        *self
            .persona_source
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = source;
    }

    // -----------------------------------------------------------------
    // DID resolver accessors
    // -----------------------------------------------------------------

    /// Returns the production DID resolver, if initialized.
    #[must_use]
    pub fn did_resolver(&self) -> Option<&Arc<IdentityBackedDidResolver>> {
        self.did_resolver.get()
    }

    /// Stores the production DID resolver.
    ///
    /// Called once during identity system setup. Subsequent calls are no-ops
    /// (`OnceLock` guarantees single initialization).
    pub fn set_did_resolver(&self, resolver: Arc<IdentityBackedDidResolver>) {
        if self.did_resolver.set(resolver).is_err() {
            tracing::warn!("set_did_resolver called but resolver already initialized — ignoring");
        }
    }

    /// Returns the shared DHT client backing the DID resolver, if initialized.
    ///
    /// Used by `identity_create` to publish freshly minted DID documents into
    /// the same [`FfiDhtClient`] the resolver reads from, so the DID is
    /// resolvable for signature verification.
    #[must_use]
    pub fn dht_client(&self) -> Option<&Arc<crate::dht::FfiDhtClient>> {
        self.dht_client.get()
    }

    /// Stores the shared DHT client backing the DID resolver.
    ///
    /// Called once during identity system setup, alongside [`set_did_resolver`],
    /// with the SAME [`FfiDhtClient`] `Arc` the resolver was built over.
    /// Subsequent calls are no-ops (`OnceLock` guarantees single
    /// initialization).
    pub fn set_dht_client(&self, client: Arc<crate::dht::FfiDhtClient>) {
        if self.dht_client.set(client).is_err() {
            tracing::warn!("set_dht_client called but client already initialized — ignoring");
        }
    }

    /// Returns the DID-resolution cache shared with the production resolver, if
    /// initialized.
    ///
    /// Used to invalidate a DID's cached document after a higher-sequence
    /// re-publish (key rotation / agent-key / migration) so the resolver does
    /// not keep serving the stale, pre-mutation document for the cache's
    /// multi-day TTL.
    #[must_use]
    pub fn resolver_cache(&self) -> Option<&Arc<scp_identity::cache::DidCache>> {
        self.resolver_cache.get()
    }

    /// Stores the DID-resolution cache backing the DID resolver.
    ///
    /// Called once during identity system setup, alongside [`set_did_resolver`]
    /// and [`set_dht_client`], with the SAME `Arc<DidCache>` the resolver was
    /// built over. Subsequent calls are no-ops (`OnceLock` guarantees single
    /// initialization).
    pub fn set_resolver_cache(&self, cache: Arc<scp_identity::cache::DidCache>) {
        if self.resolver_cache.set(cache).is_err() {
            tracing::warn!("set_resolver_cache called but cache already initialized — ignoring");
        }
    }

    /// Drops the DID resolver's cached document for `did` after a higher-sequence
    /// re-publish (key rotation, agent-key add/rotate/remove, migration).
    ///
    /// The per-instance `DualLayerResolver` caches resolved documents with a
    /// multi-day TTL and short-circuits on a cached hit without re-querying the
    /// DHT. Without this invalidation a freshly rotated identity keeps resolving
    /// to its pre-rotation document — and pre-rotation `#active` key — until the
    /// TTL expires, defeating rotation's revocation purpose. The rotation
    /// re-publish (higher BEP44 `seq`) has already landed in the shared DHT
    /// client; this drops the resolver's stale copy so the next resolve reads the
    /// fresh document. Best-effort: a no-op when no resolver cache is wired on
    /// this instance.
    ///
    /// Shared by all three FFI bridges (`PyO3` wraps it in `block_on`; napi-rs
    /// and `UniFFI` `.await` it) — the single implementation of the body.
    pub async fn invalidate_resolver_cache(&self, did: &str) {
        if let Some(cache) = self.resolver_cache() {
            cache.remove(did).await;
        }
    }

    // -----------------------------------------------------------------
    // Async shutdown with deadline
    // -----------------------------------------------------------------

    /// Shuts down the instance with a graceful deadline for in-flight tasks.
    ///
    /// Behaves as follows:
    ///
    /// 1. Idempotency: if `shutdown` has already been called (sync or async),
    ///    returns [`ShutdownError::AlreadyShutDown`] without side effects.
    /// 2. Fires [`CancellationToken::cancel`] so cooperating tasks can exit.
    /// 3. Drains the task `JoinSet` inside `tokio::time::timeout(remaining, …)`.
    ///    Tasks that finish within the deadline report
    ///    [`ShutdownOutcome::GracefulWithin`] with the elapsed time.
    /// 4. On timeout, calls `JoinSet::abort_all` and returns
    ///    [`ShutdownOutcome::TimedOut`] with the number of tasks aborted and
    ///    the number that panicked.
    /// 5. Runs the bridge-agnostic cleanup (flush persistence, drop MLS
    ///    groups, clear registries, run shutdown hooks, clear transport)
    ///    regardless of graceful/timeout outcome — these side effects must
    ///    happen on *every* shutdown. The persistence flush
    ///    (`ContextManager::flush_all_contexts_sync`) is executed
    ///    inside the remaining timeout budget so the caller's deadline is
    ///    honored end-to-end; if it exceeds the budget, flush is abandoned
    ///    and a warning is logged.
    ///
    /// # Errors
    ///
    /// - [`ShutdownError::AlreadyShutDown`] — the instance has already been
    ///   shut down. The caller is expected to treat this as a harmless
    ///   lifecycle observation (no additional work to do).
    pub async fn shutdown_core_async(
        &self,
        timeout: Duration,
    ) -> Result<ShutdownOutcome, ShutdownError> {
        // Idempotent terminal transition. The sync `shutdown()` path also
        // swaps this flag; whichever call wins is the one that runs
        // cleanup.
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return Err(ShutdownError::AlreadyShutDown);
        }

        // Signal cooperating tasks to exit. Cheap and idempotent.
        self.cancel.cancel();
        // #1696: cancel any in-flight reconnect dial so its socket
        // teardown fires before shutdown completes. Matches the sync
        // `shutdown()` path.
        if let Ok(guard) = self.reconnect_cancel.lock() {
            guard.cancel();
        }

        let start = std::time::Instant::now();
        let outcome = drain_under_deadline(&self.tasks, timeout, start).await;

        // Run the sync cleanup side effects inside the remaining budget so
        // callers get a true end-to-end deadline on shutdown (including the
        // synchronous flush step). `run_shutdown_side_effects` mirrors the
        // body of the sync `shutdown()` path but without the AtomicBool
        // swap (we already performed it above). Calling it is safe: it
        // checks `is_shutdown()` for the one internal guard that matters
        // (economy accessors), which is already true.
        let elapsed = start.elapsed();
        let remaining = timeout.saturating_sub(elapsed);
        self.run_shutdown_side_effects(remaining).await;

        Ok(outcome)
    }

    /// Shared cleanup body executed by both the sync [`shutdown`](Self::shutdown)
    /// and the async [`shutdown_core_async`](Self::shutdown_core_async) paths.
    ///
    /// Must only be called after `self.shutdown` has been swapped to `true`.
    /// Clears transport, flushes persistence (inside `flush_budget` when
    /// called from the async path, or with no bound from the sync path
    /// via [`blocking_run_shutdown_side_effects`]), drops MLS groups +
    /// sender keys, clears bridge-owned registries, and runs any registered
    /// shutdown hooks. Infallible: lock poisoning, hook panics, and flush
    /// timeouts are logged and cleanup continues — shutdown must finish
    /// regardless.
    async fn run_shutdown_side_effects(&self, flush_budget: Duration) {
        if let Err(e) = self.clear_transport() {
            tracing::error!("failed to clear transport during shutdown: {e} — continuing cleanup");
        }
        if let Ok(mut urls) = self.relay_urls.lock() {
            urls.clear();
        }

        if let Some(supervisor) = self.supervisor.get() {
            // Persistence flush must honor the caller-supplied deadline.
            // The flush is now natively async (per-context bounded
            // `Mutex::lock` with a 250ms budget and degraded-snapshot
            // fallback for wedged contexts); wrap in `tokio::time::timeout`
            // so aggregate storage latency cannot push us past the caller's
            // shutdown budget. Zero budget falls through to a best-effort
            // inline flush (matches the sync shutdown path's contract).
            //
            // Supervisor::flush_all_contexts/shutdown_all_contexts are thin
            // forwarders over the infallible ContextManager methods; the only
            // reachable error is `NotInitialized` (no manager attached to
            // the supervisor). Any error returned here we log rather than
            // panic since shutdown must finish.
            if flush_budget.is_zero() {
                tracing::warn!(
                    "shutdown flush budget exhausted before flush_all_contexts — \
                     context state may not be persisted"
                );
            } else {
                match tokio::time::timeout(flush_budget, supervisor.flush_all_contexts()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            "flush_all_contexts returned an error during shutdown \
                             (likely supervisor providers detached mid-flight) — \
                             context state may not be persisted"
                        );
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            budget_ms = flush_budget.as_millis(),
                            "flush_all_contexts exceeded shutdown budget — \
                             context state may not be persisted"
                        );
                    }
                }
            }
            if let Err(e) = supervisor.shutdown_all_contexts().await {
                tracing::warn!(
                    error = %e,
                    "shutdown_all_contexts returned an error during shutdown \
                     (likely supervisor providers detached mid-flight)"
                );
            }
        }

        self.finish_shutdown_cleanup();
    }

    /// Non-async sibling of [`run_shutdown_side_effects`] used by the sync
    /// [`shutdown`](Self::shutdown) path.
    ///
    /// The sync path has no deadline — it is a terminal, infallible
    /// operation called from destructors and atexit hooks. It therefore
    /// runs the flush inline without a timeout. The async variant is
    /// preferred; callers that can `.await` should use it.
    fn blocking_run_shutdown_side_effects(&self) {
        if let Err(e) = self.clear_transport() {
            tracing::error!("failed to clear transport during shutdown: {e} — continuing cleanup");
        }
        if let Ok(mut urls) = self.relay_urls.lock() {
            urls.clear();
        }

        if let Some(supervisor) = self.supervisor.get() {
            // Supervisor::flush_all_contexts_sync and shutdown_all_contexts
            // are thin forwarders over the infallible ContextManager methods.
            // Any non-Ok return indicates the manager was detached
            // mid-flight (or never attached), which we log since sync
            // shutdown must finish regardless.
            if let Err(e) = supervisor.flush_all_contexts_sync() {
                tracing::warn!(
                    error = %e,
                    "flush_all_contexts_sync returned an error during shutdown \
                     (likely supervisor providers detached mid-flight) — \
                     context state may not be persisted"
                );
            }
            if let Err(e) = supervisor.shutdown_all_contexts_sync() {
                tracing::warn!(
                    error = %e,
                    "shutdown_all_contexts_sync returned an error during shutdown \
                     (likely supervisor providers detached mid-flight)"
                );
            }
        }

        self.finish_shutdown_cleanup();
    }

    /// Shared tail of both shutdown paths — registry clears, hook run,
    /// suspension reset. Split out so the sync and async variants only
    /// differ where they actually need to (flush handling).
    fn finish_shutdown_cleanup(&self) {
        self.known_contexts.clear();
        self.rate_limiters.clear();
        self.economy_budgets.clear();
        self.economy_antispam.clear();
        self.bridge_state.clear();

        if let Ok(mut hooks) = self.shutdown_hooks.lock() {
            for hook in hooks.drain(..) {
                if let Err(_payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook))
                {
                    tracing::error!(
                        "shutdown hook panicked — bridge-specific cleanup may be incomplete"
                    );
                }
            }
        } else {
            tracing::error!("shutdown_hooks mutex poisoned — bridge-specific cleanup skipped");
        }

        // Shutdown supersedes suspension.
        self.suspended.store(false, Ordering::SeqCst);

        tracing::debug!("bridge instance shut down");
    }
}

/// Locks the `JoinSet` long enough to drain outstanding tasks with a
/// deadline. On graceful drain, returns [`ShutdownOutcome::GracefulWithin`]
/// with the elapsed time since `start` and the count of tasks that
/// panicked. On timeout, aborts the remaining tasks, counts both
/// aborted and panicked tasks, and returns [`ShutdownOutcome::TimedOut`].
///
/// The helper exists so the lock guard's scope is obvious and clippy's
/// `significant_drop_tightening` check is satisfied (the guard cannot be
/// released earlier without pulling the `JoinSet` out from under the
/// abort path).
#[allow(clippy::significant_drop_tightening)]
async fn drain_under_deadline(
    tasks: &AsyncMutex<JoinSet<()>>,
    timeout: Duration,
    start: std::time::Instant,
) -> ShutdownOutcome {
    // The `JoinSet` lock is held for the full drain — `abort_all` +
    // `join_next` below all need exclusive access to the same set.
    // Clippy's `significant_drop_tightening` flags the wide scope, but
    // there is no earlier release point that keeps the invariant of
    // draining the exact set we aborted.
    let mut guard = tasks.lock().await;
    let mut panicked: usize = 0;
    if tokio::time::timeout(timeout, drain_tasks(&mut guard, &mut panicked))
        .await
        .is_ok()
    {
        return ShutdownOutcome::GracefulWithin {
            elapsed: start.elapsed(),
            panicked_tasks: panicked,
        };
    }
    // Deadline expired: abort remaining tasks and count how many we cut
    // versus how many panicked on the abort path. `abort_all` is a no-op
    // for finished tasks.
    guard.abort_all();
    let (aborted, abort_panicked) = count_and_drain_aborted(&mut guard).await;
    ShutdownOutcome::TimedOut {
        aborted_tasks: aborted,
        panicked_tasks: panicked + abort_panicked,
    }
}

/// Drains `set` until every task has completed. Panics inside tasks are
/// logged AND counted via `panicked_out`; non-panic join errors (cancellation)
/// are ignored — abort is the caller's signal.
async fn drain_tasks(set: &mut JoinSet<()>, panicked_out: &mut usize) {
    while let Some(joined) = set.join_next().await {
        if let Err(e) = joined
            && e.is_panic()
        {
            *panicked_out += 1;
            tracing::error!("task panicked during shutdown drain: {e}");
        }
    }
}

/// After `abort_all`, drains the set to completion and returns the pair
/// `(aborted, panicked)`: the count of tasks cancelled on the abort path
/// versus tasks that panicked while being aborted.
async fn count_and_drain_aborted(set: &mut JoinSet<()>) -> (usize, usize) {
    let mut aborted = 0usize;
    let mut panicked = 0usize;
    while let Some(joined) = set.join_next().await {
        if let Err(e) = joined {
            if e.is_cancelled() {
                aborted += 1;
            } else if e.is_panic() {
                panicked += 1;
                tracing::error!("task panicked during abort drain: {e}");
            }
        }
    }
    (aborted, panicked)
}

/// Bridge-agnostic trait implemented by every per-bridge concrete struct.
///
/// Each `PyBridgeInstance` / `NapiBridgeInstance` / `UniffiBridgeInstance`
/// embeds a [`CoreFields`] and returns it from [`BridgeInstanceCore::core`].
/// Default implementations delegate common lifecycle accessors to the
/// embedded core, so per-bridge impls only need to override
/// [`BridgeInstanceCore::shutdown`] (to also clean up their bridge-specific
/// typed fields) and optionally [`BridgeInstanceCore::bridge_specific_shutdown`].
///
/// The trait is `Send + Sync`: shared helpers may take `&dyn BridgeInstanceCore`
/// and pass it across threads or `.await` points.
#[async_trait::async_trait]
pub trait BridgeInstanceCore: Send + Sync {
    /// Returns a reference to the embedded bridge-agnostic core state.
    fn core(&self) -> &CoreFields;

    /// Returns the monotonic identifier assigned to this instance.
    fn instance_id(&self) -> u64 {
        self.core().instance_id()
    }

    /// Runtime handle-affinity check.
    ///
    /// # Errors
    ///
    /// Returns [`HandleAffinityError`] if the handle was issued by a
    /// different bridge instance.
    fn check_handle(&self, handle_instance_id: u64) -> Result<(), HandleAffinityError> {
        self.core().check_handle(handle_instance_id)
    }

    /// Suspends the instance — see [`CoreFields::suspend`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportLockError`] if the transport lock is poisoned.
    fn suspend(&self) -> Result<(), TransportLockError> {
        self.core().suspend()
    }

    /// Resumes the instance — see [`CoreFields::resume`].
    ///
    /// Default implementation (extended in commit 6 of the actor-per-context
    /// refactor, ADR-049 §11):
    ///
    /// 1. Flip the suspended flag via [`CoreFields::resume`].
    /// 2. Reconnect transport if a relay URL was retained via
    ///    [`CoreFields::reconnect_transport_if_pending`] — the reconnect
    ///    MUST precede persisted-context rehydration so restored
    ///    subscriptions attach to a live relay connection.
    /// 3. Rehydrate persisted contexts via
    ///    [`CoreFields::restore_all_persisted_contexts`].
    ///
    /// Per-bridge concrete structs (`PyBridgeInstance`,
    /// `NapiBridgeInstance`, `UniffiBridgeInstance`) MUST NOT override
    /// this default. The CI gate
    /// `scripts/check-bridge-instance-lifecycle.py` enforces the ban.
    /// Bridges that need additional resume-time work add a
    /// `post_resume_hook` (future extension; not yet defined because
    /// no bridge currently requires one).
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::AlreadyShutDown`] if the instance has
    /// been permanently shut down, or [`LifecycleError::ReconnectFailed`]
    /// if transport reconnect raced to failure.
    async fn resume(&self) -> Result<(), LifecycleError> {
        self.core().resume().await?;
        self.core().reconnect_transport_if_pending().await?;
        self.core().restore_all_persisted_contexts().await;
        Ok(())
    }

    /// Async shutdown with a graceful deadline.
    ///
    /// Default implementation (landed in commit 6 of the actor-per-context
    /// refactor, ADR-049 §11) stops every registered borrower, drains the
    /// core's async tasks under the supplied timeout, then delegates to
    /// [`BridgeInstanceCore::bridge_specific_shutdown`] so per-bridge
    /// concrete structs can drop their typed registries (MCP registries,
    /// identity custody, etc.).
    ///
    /// # Borrower-stop runs first
    ///
    /// [`CoreFields::stop_borrowers`] runs before anything else, and this
    /// ordering lives here rather than in each bridge so no bridge can drift
    /// out of it. A node that `start_node_local` started writes through a
    /// clone of this instance's storage `Arc`, while
    /// `bridge_specific_shutdown` closes that same `SQLCipher` handle and
    /// drops an advisory `flock(2)` on `{dir}/scp.db.lock`. Releasing that
    /// lock while a node still writes invites split-brain writes and WAL
    /// corruption (red-hat RED-1002), so every borrower stops first. See
    /// [`InstanceBorrower`].
    ///
    /// `bridge_specific_shutdown` runs UNCONDITIONALLY — even when
    /// [`CoreFields::shutdown_core_async`] returns
    /// [`ShutdownError::AlreadyShutDown`]. That variant signals a race
    /// between this call and a prior sync `shutdown()` / prior async call;
    /// without invoking the bridge-specific cleanup, typed registries
    /// would leak key material past shutdown.
    ///
    /// Per-bridge concrete structs (`PyBridgeInstance`,
    /// `NapiBridgeInstance`, `UniffiBridgeInstance`) MUST NOT override
    /// this default. Override `bridge_specific_shutdown` (and the
    /// `pre_*_hook` / `post_*_hook` extension points) instead. The CI
    /// gate `scripts/check-bridge-instance-lifecycle.py` enforces this.
    ///
    /// # Errors
    ///
    /// Returns [`ShutdownError::AlreadyShutDown`] on a second call.
    async fn shutdown(&self, timeout: Duration) -> Result<ShutdownOutcome, ShutdownError> {
        // Stop every borrower BEFORE any release: `bridge_specific_shutdown`
        // closes this instance's `SQLCipher` handle, and a node started on
        // that handle must not still be writing when it does.
        self.core().stop_borrowers();
        let result = self.core().shutdown_core_async(timeout).await;
        self.bridge_specific_shutdown();
        result
    }

    /// Override hook for per-bridge concrete structs to drop their
    /// bridge-specific typed fields (MCP registries, custody store, etc.).
    /// The default implementation is a no-op.
    ///
    /// Called by [`BridgeInstanceCore::shutdown`] implementations after
    /// the bridge-agnostic cleanup finishes, so bridge-specific state is
    /// dropped last (after hooks run and transport is gone).
    fn bridge_specific_shutdown(&self) {}

    // The MCP stdio allowlist is reached via `self.core().mcp_allowlist()` and
    // `self.core().with_mcp_allowlist(...)` directly. A trait-level forwarder
    // would break `dyn BridgeInstanceCore` (the helper is generic) and offers
    // no value because every bridge already touches `core` directly.
}

/// Error from [`CoreFields::with_mcp_allowlist`].
///
/// Mirrors [`TransportLockError`]'s typed-error pattern so bridges map
/// poisoning to their own transport-error variant via a small `From`
/// or `match` at the callsite. The single-variant enum keeps the door
/// open for additional reasons (e.g. acquisition timeout) without
/// breaking match arms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllowlistGuardError {
    /// The allowlist `Mutex` was poisoned (a holder panicked).
    Poisoned,
}

impl std::fmt::Display for AllowlistGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Sanitized: do not leak internal lock-state to callers. Detailed
            // diagnostics belong in `tracing` events at the poisoning site.
            Self::Poisoned => write!(f, "stdio allowlist lock poisoned"),
        }
    }
}

// `std::error::Error` impl mirrors `TransportLockError` so downstream code
// that builds `From<E: std::error::Error>` adapters (or composes via
// `Box<dyn std::error::Error>`) can carry this error uniformly.
impl std::error::Error for AllowlistGuardError {}

/// Error type for transport lock operations.
///
/// Used by [`CoreFields`] transport accessor methods. Bridge layers map
/// this to their own error types (`ScpPyError`, napi `Error`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportLockError {
    /// The transport `RwLock` was poisoned (a writer panicked while holding it).
    Poisoned,
    /// No transport manager has been set (call `set_transport` first).
    NotInitialized,
    /// The transport manager `Arc` is in use by an active subscription task.
    /// Mutable access requires exclusive ownership (refcount == 1).
    InUse,
    /// The operation was rejected due to a lifecycle violation — the bridge
    /// instance is shut down or suspended and cannot accept transport changes.
    Rejected(String),
}

impl std::fmt::Display for TransportLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sanitized messages: no internal architecture details (lock types,
        // Arc refcounts, etc.) leak to callers. Debug-level logging at the
        // creation site provides the detailed reason for operators.
        match self {
            Self::Poisoned => write!(f, "transport operation failed — internal error"),
            Self::NotInitialized => {
                write!(
                    f,
                    "transport not initialized — call transport_connect first"
                )
            }
            Self::InUse => write!(f, "transport is busy — try again later"),
            Self::Rejected(msg) => write!(f, "transport operation rejected: {msg}"),
        }
    }
}

impl std::error::Error for TransportLockError {}

/// Error type for lifecycle operations (`resume`, `check_ready`).
///
/// Used by [`CoreFields::resume`] and related lifecycle accessors.
/// Bridge layers map this to their own error types (`ScpPyError`, napi `Error`,
/// etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// The instance has been permanently shut down and cannot be resumed.
    AlreadyShutDown,
    /// The instance is currently suspended (backgrounded). Transport-dependent
    /// operations are unavailable. Call `resume()` to re-activate.
    Suspended,
    /// Transport reconnect failed during `resume()`.
    ///
    /// Carries the URL that failed to reconnect and a redacted reason
    /// suitable for logging / surfacing to SDK callers. The suspended flag
    /// has already been cleared by the time this error is produced — the
    /// caller can retry the connect (e.g. via `transport_connect`) without
    /// having to call `suspend()` + `resume()` again.
    ReconnectFailed {
        /// The relay URL that failed to reconnect.
        url: String,
        /// Redacted failure reason (no internal architecture leaks).
        reason: String,
    },
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyShutDown => {
                write!(f, "bridge instance has been permanently shut down")
            }
            Self::Suspended => write!(
                f,
                "bridge is suspended — call resume() before performing operations"
            ),
            Self::ReconnectFailed { url, reason } => {
                write!(f, "resume transport reconnect failed for {url}: {reason}")
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Error produced when a handle is used on the wrong bridge instance.
///
/// Every handle type (`ContextHandle`, `Identity`, `TransportManager`, etc.)
/// stores the [`CoreFields::instance_id`] of the bridge instance that
/// issued it. FFI entry points call [`CoreFields::check_handle`] before
/// doing any work; a mismatch produces this error, which maps to error
/// code [`crate::error_codes::PERM_3030`] at the bridge layer.
///
/// The error carries both ids (redacted in `Display` but preserved in
/// `Debug`) so operators can correlate logs without exposing internals to
/// attackers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleAffinityError {
    /// The instance id carried by the offending handle.
    handle_instance_id: u64,
    /// The instance id of the bridge instance the handle was passed to.
    expected_instance_id: u64,
}

impl HandleAffinityError {
    /// Constructs a new affinity error from the observed / expected pair.
    #[must_use]
    pub const fn new(handle_instance_id: u64, expected_instance_id: u64) -> Self {
        Self {
            handle_instance_id,
            expected_instance_id,
        }
    }

    /// The instance id carried by the offending handle.
    #[must_use]
    pub const fn handle_instance_id(self) -> u64 {
        self.handle_instance_id
    }

    /// The instance id of the bridge that rejected the handle.
    #[must_use]
    pub const fn expected_instance_id(self) -> u64 {
        self.expected_instance_id
    }
}

impl std::fmt::Display for HandleAffinityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sanitized message: internal ids stay out of the user-visible
        // string (they are preserved in `Debug` for operator correlation).
        // The recovery hint points the caller at the mechanical fix —
        // use the SCP instance that minted the handle, or mint a fresh
        // handle from the SCP instance the caller intends to operate on.
        // See PR #1690 retro api-design MAJOR.
        write!(
            f,
            "handle belongs to a different SCP instance — use the SCP \
             instance that created this handle (check \
             scp.instance_id matches handle.instance_id)"
        )
    }
}

impl std::error::Error for HandleAffinityError {}

/// Outcome of an async bridge shutdown — see
/// [`CoreFields::shutdown_core_async`].
///
/// Both variants surface `panicked_tasks` so callers can detect task-level
/// panics that previously drowned in tracing errors. A nonzero count means
/// at least one spawned task unwound during the drain — the bridge cleaned
/// up, but there is a real bug upstream worth investigating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// All outstanding tasks completed before the deadline.
    GracefulWithin {
        /// Elapsed wall-clock time from the first cancellation signal to the
        /// last task joining (or panicking). Reported so callers can log
        /// shutdown latency.
        elapsed: Duration,
        /// Number of tasks that panicked during the graceful drain.
        /// Panics are logged at `tracing::error!` level; shutdown continues
        /// regardless.
        panicked_tasks: usize,
    },
    /// The deadline expired before all tasks finished; the `JoinSet` was
    /// aborted.
    TimedOut {
        /// Number of tasks that were aborted because the shutdown deadline
        /// was reached (tasks that had already completed before the deadline
        /// are not counted).
        aborted_tasks: usize,
        /// Number of tasks that panicked during the abort drain. A nonzero
        /// count indicates a task unwound on the abort path — typically a
        /// secondary failure mode when the primary shutdown path races with
        /// a panicking task.
        panicked_tasks: usize,
    },
}

/// Error produced by [`CoreFields::shutdown_core_async`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ShutdownError {
    /// The instance has already been shut down; a second call is a no-op
    /// from the caller's perspective but is surfaced so the caller can
    /// distinguish "I did the work" from "someone else already did."
    #[error("bridge instance has already been shut down")]
    AlreadyShutDown,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_core::context::LocalTransportProvider;
    use scp_core::context::builder::{ContextCreationError, ContextEventLogProvider};
    use scp_core::crypto::mls::provider::NodeMlsFactory;
    use scp_core::crypto::mls::storage_adapter::{
        OpenMlsStorageAdapter, SpawnBlockingStorageAdapter,
    };
    use std::pin::Pin;

    /// Test-only in-memory `OpenMLS` storage adapter for the required
    /// `mls_storage` arg of `Supervisor::with_providers`. The runtime never
    /// defaults storage; tests supply this explicit dev affordance.
    fn test_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
        Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )))
    }

    use scp_core::envelope::outer::OuterEnvelope;
    use scp_transport::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportError};

    // Minimal no-op event-log provider for constructing a ContextManager in
    // tests. Crypto now uses the real `NodeMlsFactory` directly —
    // `ContextCryptoProvider` was deleted in commit 12c.9e of ADR-049.

    struct NoOpEventLog;
    // The async methods carry no `.await`: this test double just returns `Ok`.
    // `ContextEventLogProvider` is an `#[async_trait]` (ADR-049 Decision 7),
    // so the signatures must stay `async fn` to satisfy the trait; the
    // `unused_async` lint is expected and allowed here.
    #[async_trait::async_trait]
    impl ContextEventLogProvider for NoOpEventLog {
        #[allow(
            clippy::unused_async,
            reason = "async fn required by the ContextEventLogProvider async_trait; body has no await"
        )]
        async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        #[allow(
            clippy::unused_async,
            reason = "async fn required by the ContextEventLogProvider async_trait; body has no await"
        )]
        async fn append_event(
            &self,
            _: &[u8; 32],
            _: scp_event_log::EventType,
            _: &str,
            _: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        #[allow(
            clippy::unused_async,
            reason = "async fn required by the ContextEventLogProvider async_trait; body has no await"
        )]
        async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// Builds a per-instance Supervisor with test-friendly providers.
    /// Mirrors the FFI bridges' `init_supervisor*` path:
    /// `Supervisor::with_providers` constructs the supervisor and
    /// populates the lifted-provider slots expected by every
    /// `Supervisor::*` passthrough method (ADR-049 commit 12c.9g.3.6 —
    /// the FFI layer no longer touches `ContextManager` directly).
    fn test_supervisor() -> Arc<Supervisor> {
        // Use LocalTransportProvider (silently succeeds) for tests.
        // Key resolver returns None — no signature verification in tests.
        let key_resolver: scp_core::context::governance::KeyResolver =
            Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None);
        let test_did = "did:test:bridge-instance-test".to_owned();
        Supervisor::with_providers(
            Arc::new(NodeMlsFactory::new(
                test_did,
                std::sync::Arc::new(scp_clock::SystemClock),
            )),
            Box::new(LocalTransportProvider),
            Box::new(NoOpEventLog),
            key_resolver,
            None,
            None,
            None,
            None,
            test_mls_storage(),
        )
    }

    /// Minimal no-op transport adapter for lifecycle tests.
    struct NoOpAdapter;

    type BoxFut<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    impl TransportAdapter for NoOpAdapter {
        fn send(&self, _: &OuterEnvelope) -> BoxFut<'_, Result<BlobId, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn subscribe(
            &self,
            _: &RoutingId,
            _: Option<u64>,
        ) -> BoxFut<'_, Result<SubscriptionStream, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn unsubscribe(&self, _: &RoutingId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
        fn query(
            &self,
            _: &RoutingId,
            _: Option<u64>,
        ) -> BoxFut<'_, Result<Vec<OuterEnvelope>, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn delete(&self, _: &BlobId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn test_transport_manager() -> scp_transport::TransportManager {
        scp_transport::TransportManager::new(Box::new(NoOpAdapter))
    }

    #[test]
    fn new_creates_instance_with_expected_state() {
        let sup = test_supervisor();
        let instance = CoreFields::with_supervisor(Arc::clone(&sup));

        assert!(!instance.is_shutdown());
        // Verify the Supervisor pointer is the same Arc
        assert!(Arc::ptr_eq(instance.try_supervisor().unwrap(), &sup));
        // Shared state starts empty
        assert!(!instance.has_transport());
        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());
    }

    #[test]
    fn new_creates_instance_without_supervisor() {
        // Per spec §12.2.3, BridgeInstance is infrastructure and has no DID
        // requirement — it can exist before any identity is created.
        let instance = CoreFields::new();

        assert!(!instance.has_supervisor());
        assert!(instance.try_supervisor().is_none());
        assert!(!instance.is_shutdown());
    }

    #[test]
    fn set_supervisor_is_idempotent_once_set() {
        let instance = CoreFields::new();
        let sup1 = test_supervisor();
        instance.set_supervisor(Arc::clone(&sup1));
        assert!(Arc::ptr_eq(instance.try_supervisor().unwrap(), &sup1));

        // Second set is a silent no-op (OnceLock).
        let sup2 = test_supervisor();
        instance.set_supervisor(Arc::clone(&sup2));
        assert!(
            Arc::ptr_eq(instance.try_supervisor().unwrap(), &sup1),
            "set_supervisor must not replace the existing Supervisor"
        );
    }

    #[test]
    fn shutdown_without_supervisor_is_safe() {
        // Simulates the case where the bridge was partially initialized
        // (BridgeInstance exists but identity_create / init_supervisor
        // never ran) and then shutdown is called.
        let instance = CoreFields::new();
        assert!(!instance.has_supervisor());
        instance.shutdown();
        assert!(instance.is_shutdown());
    }

    #[test]
    fn shutdown_transitions_flag_permanently() {
        let instance = CoreFields::with_supervisor(test_supervisor());

        assert!(!instance.is_shutdown());
        instance.shutdown();
        assert!(instance.is_shutdown());

        // Calling shutdown again is a no-op — still true
        instance.shutdown();
        assert!(instance.is_shutdown());
    }

    #[test]
    fn supervisor_returns_shared_reference() {
        let sup = test_supervisor();
        let instance = CoreFields::with_supervisor(Arc::clone(&sup));

        // Both should point to the same Supervisor allocation
        assert!(Arc::ptr_eq(instance.try_supervisor().unwrap(), &sup));
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CoreFields>();
    }

    // -----------------------------------------------------------------
    // Transport tests
    // -----------------------------------------------------------------

    #[test]
    fn transport_starts_empty() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(!instance.has_transport());
        assert_eq!(
            instance.with_transport(|_| ()).unwrap_err(),
            TransportLockError::NotInitialized
        );
    }

    #[test]
    fn clear_transport_when_empty_is_ok() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(instance.clear_transport().is_ok());
        assert!(!instance.has_transport());
    }

    // -----------------------------------------------------------------
    // Known context tests
    // -----------------------------------------------------------------

    #[test]
    fn register_and_retrieve_known_context() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let known = KnownContext {
            routing_id: [42u8; 32],
            relay_url: Some("wss://relay.example.com".to_owned()),
            member_did: "did:dht:zalice".to_owned(),
            last_seen: 1_700_000_000,
        };
        instance.register_known_context("ctx-1", known);
        assert_eq!(instance.known_contexts().len(), 1);

        let all = instance.all_known_contexts();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "ctx-1");
        assert_eq!(all[0].1.routing_id, [42u8; 32]);
        assert_eq!(all[0].1.member_did, "did:dht:zalice");
    }

    #[test]
    fn known_contexts_for_member_filters() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.register_known_context(
            "ctx-alice",
            KnownContext {
                routing_id: [1u8; 32],
                relay_url: None,
                member_did: "did:dht:zalice".to_owned(),
                last_seen: 100,
            },
        );
        instance.register_known_context(
            "ctx-bob",
            KnownContext {
                routing_id: [2u8; 32],
                relay_url: None,
                member_did: "did:dht:zbob".to_owned(),
                last_seen: 200,
            },
        );

        let alice_contexts = instance.known_contexts_for_member("did:dht:zalice");
        assert_eq!(alice_contexts.len(), 1);
        assert_eq!(alice_contexts[0].0, "ctx-alice");

        let bob_contexts = instance.known_contexts_for_member("did:dht:zbob");
        assert_eq!(bob_contexts.len(), 1);
        assert_eq!(bob_contexts[0].0, "ctx-bob");

        let nobody_contexts = instance.known_contexts_for_member("did:dht:znobody");
        assert!(nobody_contexts.is_empty());
    }

    #[test]
    fn remove_known_context_works() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.register_known_context(
            "ctx-1",
            KnownContext {
                routing_id: [0u8; 32],
                relay_url: None,
                member_did: "did:dht:ztest".to_owned(),
                last_seen: 0,
            },
        );
        assert_eq!(instance.known_contexts().len(), 1);
        instance.remove_known_context("ctx-1");
        assert!(instance.known_contexts().is_empty());
    }

    // -----------------------------------------------------------------
    // Rate limiter tests
    // -----------------------------------------------------------------

    #[test]
    fn rate_limiter_creates_default_on_first_access() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(instance.rate_limiters().is_empty());

        // Accessing a non-existent tracker creates a default one
        instance.with_rate_limit_tracker("did:dht:zalice", |_tracker| {});
        assert_eq!(instance.rate_limiters().len(), 1);
    }

    // -----------------------------------------------------------------
    // TransportLockError tests
    // -----------------------------------------------------------------

    #[test]
    fn transport_lock_error_display() {
        assert_eq!(
            TransportLockError::Poisoned.to_string(),
            "transport operation failed \u{2014} internal error"
        );
        assert_eq!(
            TransportLockError::NotInitialized.to_string(),
            "transport not initialized \u{2014} call transport_connect first"
        );
        assert_eq!(
            TransportLockError::InUse.to_string(),
            "transport is busy \u{2014} try again later"
        );
        assert_eq!(
            TransportLockError::Rejected("bridge is shut down".to_owned()).to_string(),
            "transport operation rejected: bridge is shut down"
        );
    }

    // -----------------------------------------------------------------
    // Lifecycle tests (suspend / resume / shutdown)
    // -----------------------------------------------------------------

    #[test]
    fn suspend_clears_transport() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        assert!(instance.has_transport());

        instance.suspend().unwrap();

        assert!(!instance.has_transport());
        assert!(instance.is_suspended());
    }

    #[test]
    fn suspend_is_noop_when_shutdown() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.shutdown();

        // Suspending an already-shutdown instance is a no-op (not an error)
        instance.suspend().unwrap();
        assert!(instance.is_shutdown());
        assert!(!instance.is_suspended());
    }

    #[tokio::test]
    async fn resume_clears_suspended_flag() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.suspend().unwrap();
        assert!(instance.is_suspended());

        instance.resume().await.unwrap();
        assert!(!instance.is_suspended());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_fails_after_shutdown() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.shutdown();

        let err = instance.resume().await.unwrap_err();
        assert_eq!(err, LifecycleError::AlreadyShutDown);
        assert_eq!(
            err.to_string(),
            "bridge instance has been permanently shut down"
        );
    }

    #[test]
    fn shutdown_is_idempotent() {
        let instance = CoreFields::with_supervisor(test_supervisor());

        // Register some state
        instance.register_known_context(
            "ctx-1",
            KnownContext {
                routing_id: [0u8; 32],
                relay_url: None,
                member_did: "did:dht:ztest".to_owned(),
                last_seen: 0,
            },
        );
        instance.with_rate_limit_tracker("did:dht:ztest", |_| {});

        instance.shutdown();
        assert!(instance.is_shutdown());
        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());

        // Second call is a no-op
        instance.shutdown();
        assert!(instance.is_shutdown());
    }

    #[test]
    fn shutdown_clears_registries() {
        let instance = CoreFields::with_supervisor(test_supervisor());

        // Populate registries
        instance.register_known_context(
            "ctx-a",
            KnownContext {
                routing_id: [1u8; 32],
                relay_url: Some("wss://r.example.com".to_owned()),
                member_did: "did:dht:zalice".to_owned(),
                last_seen: 100,
            },
        );
        instance.register_known_context(
            "ctx-b",
            KnownContext {
                routing_id: [2u8; 32],
                relay_url: None,
                member_did: "did:dht:zbob".to_owned(),
                last_seen: 200,
            },
        );
        instance.with_rate_limit_tracker("did:dht:zalice", |_| {});
        instance.with_rate_limit_tracker("did:dht:zbob", |_| {});

        assert_eq!(instance.known_contexts().len(), 2);
        assert_eq!(instance.rate_limiters().len(), 2);

        instance.shutdown();

        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());
    }

    #[test]
    fn shutdown_clears_suspended_flag() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.suspend().unwrap();
        assert!(instance.is_suspended());

        instance.shutdown();
        assert!(instance.is_shutdown());
        // Shutdown supersedes suspension
        assert!(!instance.is_suspended());
    }

    #[test]
    fn new_instance_is_not_suspended() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(!instance.is_suspended());
    }

    #[test]
    fn lifecycle_error_display() {
        assert_eq!(
            LifecycleError::AlreadyShutDown.to_string(),
            "bridge instance has been permanently shut down"
        );
        assert_eq!(
            LifecycleError::Suspended.to_string(),
            "bridge is suspended \u{2014} call resume() before performing operations"
        );
    }

    #[test]
    fn check_ready_passes_when_active() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(instance.check_ready().is_ok());
    }

    #[test]
    fn check_ready_fails_when_shutdown() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.shutdown();
        let err = instance.check_ready().unwrap_err();
        assert_eq!(err, LifecycleError::AlreadyShutDown);
    }

    #[test]
    fn check_ready_fails_when_suspended() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.suspend().unwrap();
        let err = instance.check_ready().unwrap_err();
        assert_eq!(err, LifecycleError::Suspended);
    }

    #[tokio::test]
    async fn check_ready_passes_after_resume() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.suspend().unwrap();
        assert!(instance.check_ready().is_err());
        instance.resume().await.unwrap();
        assert!(instance.check_ready().is_ok());
    }

    #[test]
    fn known_contexts_cap_evicts_oldest() {
        let instance = CoreFields::with_supervisor(test_supervisor());

        // Register MAX_KNOWN_CONTEXTS entries.
        for i in 0..MAX_KNOWN_CONTEXTS {
            instance.register_known_context(
                &format!("ctx-{i}"),
                KnownContext {
                    routing_id: [0u8; 32],
                    relay_url: None,
                    member_did: "did:dht:ztest".to_owned(),
                    last_seen: i as u64,
                },
            );
        }
        assert_eq!(instance.known_contexts().len(), MAX_KNOWN_CONTEXTS);

        // Register one more — should evict ctx-0 (smallest last_seen = 0).
        instance.register_known_context(
            "ctx-new",
            KnownContext {
                routing_id: [0u8; 32],
                relay_url: None,
                member_did: "did:dht:ztest".to_owned(),
                last_seen: MAX_KNOWN_CONTEXTS as u64,
            },
        );
        assert_eq!(instance.known_contexts().len(), MAX_KNOWN_CONTEXTS);
        assert!(instance.known_contexts().get("ctx-new").is_some());
        assert!(instance.known_contexts().get("ctx-0").is_none());
    }

    #[test]
    fn rate_limiter_cap_evicts_oldest() {
        let instance = CoreFields::with_supervisor(test_supervisor());

        // Fill up to capacity.
        for i in 0..MAX_RATE_LIMITERS {
            instance.with_rate_limit_tracker(&format!("did:dht:z{i}"), |_| {});
        }
        assert_eq!(instance.rate_limiters().len(), MAX_RATE_LIMITERS);

        // Next new DID evicts an oldest entry and persists the new one.
        let result = instance.with_rate_limit_tracker("did:dht:znew", |_| 42);
        assert_eq!(result, 42);
        // Registry remains at capacity (one evicted, one added).
        assert_eq!(instance.rate_limiters().len(), MAX_RATE_LIMITERS);
        // The new DID is now persisted.
        assert!(
            instance.rate_limiters().contains_key("did:dht:znew"),
            "new DID should be persisted after eviction"
        );
    }

    // -----------------------------------------------------------------
    // Shutdown hook tests
    // -----------------------------------------------------------------

    #[test]
    fn shutdown_hooks_are_called_on_shutdown() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let instance = CoreFields::with_supervisor(test_supervisor());

        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::clone(&counter);
        let c2 = Arc::clone(&counter);

        instance.register_shutdown_hook(Box::new(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        }));
        instance.register_shutdown_hook(Box::new(move || {
            c2.fetch_add(10, Ordering::SeqCst);
        }));

        // Before shutdown: hooks haven't run
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        instance.shutdown();

        // Both hooks ran
        assert_eq!(counter.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn shutdown_hooks_run_only_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let instance = CoreFields::with_supervisor(test_supervisor());

        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        instance.register_shutdown_hook(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));

        instance.shutdown();
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second shutdown is idempotent — hooks don't run again
        instance.shutdown();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn register_hook_after_shutdown_runs_immediately() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let instance = CoreFields::with_supervisor(test_supervisor());

        instance.shutdown();

        let ran = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&ran);

        // Registering after shutdown runs the hook immediately — shutdown()
        // already drained the hook Vec, so a late registration must fire
        // eagerly to guarantee cleanup.
        instance.register_shutdown_hook(Box::new(move || {
            r.store(true, Ordering::SeqCst);
        }));

        assert!(
            ran.load(Ordering::SeqCst),
            "hook registered after shutdown must run immediately"
        );
    }

    // -----------------------------------------------------------------
    // set_transport lifecycle guard tests
    // -----------------------------------------------------------------

    #[test]
    fn set_transport_warns_after_shutdown() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.shutdown();

        // set_transport after shutdown warns but does not error — matches
        // the bridge_instance()/context_manager() pattern where shutdown
        // is a terminal state and operations fail naturally at the
        // MLS/transport layer.
        assert!(
            instance
                .set_transport(Arc::new(test_transport_manager()))
                .is_ok(),
            "set_transport should warn, not reject, after shutdown"
        );
    }

    #[test]
    fn set_transport_rejects_when_suspended() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.suspend().unwrap();

        let err = instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap_err();
        assert!(
            matches!(err, TransportLockError::Rejected(_)),
            "expected Rejected, got {err:?}"
        );
        assert!(err.to_string().contains("suspended"));
    }

    #[tokio::test]
    async fn set_transport_accepts_after_resume() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.suspend().unwrap();
        instance.resume().await.unwrap();

        assert!(
            instance
                .set_transport(Arc::new(test_transport_manager()))
                .is_ok()
        );
        assert!(instance.has_transport());
    }

    // -----------------------------------------------------------------
    // Post-shutdown hook panic safety
    // -----------------------------------------------------------------

    #[test]
    #[allow(clippy::panic)]
    fn register_hook_after_shutdown_catches_panic() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.shutdown();

        // A panicking hook registered after shutdown must not propagate.
        instance.register_shutdown_hook(Box::new(|| {
            panic!("deliberate panic in post-shutdown hook test");
        }));

        // If we got here, the panic was caught.
        assert!(instance.is_shutdown());
    }

    #[test]
    fn register_hook_race_with_shutdown_never_drops_hook() {
        // Stress test for the TOCTOU race between `is_shutdown()` and the
        // `shutdown_hooks.lock()` acquisition in `register_shutdown_hook`.
        //
        // Before the double-check fix, a hook registered on thread B
        // between the first `is_shutdown()` check (false) and the push
        // after lock acquisition could land in a hook vec that
        // `shutdown()` had already drained on thread A — silently losing
        // the hook. The fix rechecks `is_shutdown()` under the lock and
        // runs the hook inline when shutdown raced us.
        //
        // This test verifies the contract: every hook registered must
        // either run (inline or during shutdown()) or not be registered
        // at all. It cannot be forgotten.
        use std::sync::atomic::{AtomicUsize, Ordering};

        for _ in 0..50 {
            let instance = Arc::new(CoreFields::with_supervisor(test_supervisor()));
            let fired = Arc::new(AtomicUsize::new(0));

            // Thread B: register several hooks concurrently with shutdown.
            let inst_b = Arc::clone(&instance);
            let fired_b = Arc::clone(&fired);
            let b = std::thread::spawn(move || {
                for _ in 0..100 {
                    let f = Arc::clone(&fired_b);
                    inst_b.register_shutdown_hook(Box::new(move || {
                        f.fetch_add(1, Ordering::SeqCst);
                    }));
                }
            });

            // Thread A: trigger shutdown while B is still registering.
            let inst_a = Arc::clone(&instance);
            let a = std::thread::spawn(move || {
                inst_a.shutdown();
            });

            a.join().unwrap();
            b.join().unwrap();

            // Every one of the 100 hooks must have fired — none may be
            // silently dropped. They either ran during shutdown() or ran
            // immediately on the late-registration path.
            assert_eq!(
                fired.load(Ordering::SeqCst),
                100,
                "every registered hook must run; race must not drop any"
            );
        }
    }

    // -----------------------------------------------------------------
    // Shutdown hook: hooks run exactly once, modify external state
    // -----------------------------------------------------------------

    #[test]
    fn shutdown_hook_modifies_external_state() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let instance = CoreFields::with_supervisor(test_supervisor());
        let state = Arc::new(AtomicBool::new(false));
        let state2 = Arc::clone(&state);

        instance.register_shutdown_hook(Box::new(move || {
            state2.store(true, Ordering::SeqCst);
        }));

        // Hook has not run yet.
        assert!(
            !state.load(Ordering::SeqCst),
            "hook must not run before shutdown"
        );

        instance.shutdown();

        assert!(
            state.load(Ordering::SeqCst),
            "hook must have modified external state during shutdown"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn multiple_hooks_all_run_even_if_one_panics() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let instance = CoreFields::with_supervisor(test_supervisor());
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::clone(&counter);
        let c3 = Arc::clone(&counter);

        // Hook 1: increments counter.
        instance.register_shutdown_hook(Box::new(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        }));
        // Hook 2: panics — must not prevent hook 3 from running.
        instance.register_shutdown_hook(Box::new(|| {
            panic!("deliberate panic to test isolation between hooks");
        }));
        // Hook 3: increments counter.
        instance.register_shutdown_hook(Box::new(move || {
            c3.fetch_add(1, Ordering::SeqCst);
        }));

        instance.shutdown();

        // Hooks 1 and 3 both ran despite hook 2 panicking.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "hooks 1 and 3 must both run even when hook 2 panics"
        );
    }

    // -----------------------------------------------------------------
    // Economy tests
    // -----------------------------------------------------------------

    #[test]
    fn economy_budget_creates_default_on_first_access() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let remaining = instance.with_economy_budget("ctx-1", |tracker| {
            tracker.remaining(&scp_did::DID::from("did:dht:zalice"))
        });
        assert_eq!(remaining.value(), 0);
    }

    #[test]
    fn economy_budget_mut_grants_and_reads() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let did = scp_did::DID::from("did:dht:zalice");
        instance.with_economy_budget_mut("ctx-eco", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(500));
        });
        let remaining = instance.with_economy_budget("ctx-eco", |tracker| tracker.remaining(&did));
        assert_eq!(remaining.value(), 500);
    }

    #[test]
    fn economy_antispam_creates_default_on_first_access() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let did = scp_did::DID::from("did:dht:zbob");
        let velocity =
            instance.with_economy_antispam("ctx-spam", |tracker| tracker.get_velocity(&did, 1000));
        assert_eq!(velocity, 0);
    }

    #[test]
    fn remove_economy_state_clears_both() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let did = scp_did::DID::from("did:dht:zalice");
        instance.with_economy_budget_mut("ctx-rm", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(100));
        });
        instance.with_economy_antispam("ctx-rm", |tracker| {
            tracker.record_message(&did, 1000);
        });

        instance.remove_economy_state("ctx-rm");

        // Budget should be fresh (zero) after removal.
        let remaining = instance.with_economy_budget("ctx-rm", |tracker| tracker.remaining(&did));
        assert_eq!(remaining.value(), 0);
    }

    #[test]
    fn economy_existing_context_id_bypasses_capacity_check() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let did = scp_did::DID::from("did:dht:zalice");

        // Create one entry.
        instance.with_economy_budget_mut("ctx-exist", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(777));
        });

        // Reading the same context ID when the map is non-empty uses the
        // existing entry (not ephemeral).
        let remaining =
            instance.with_economy_budget("ctx-exist", |tracker| tracker.remaining(&did));
        assert_eq!(
            remaining.value(),
            777,
            "existing entry must be served, not an ephemeral default"
        );
    }

    #[test]
    fn economy_accessors_use_ephemeral_after_shutdown() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let did = scp_did::DID::from("did:dht:zalice");

        // Grant a budget before shutdown.
        instance.with_economy_budget_mut("ctx-sd", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(500));
        });

        instance.shutdown();

        // Post-shutdown: budget should be empty (ephemeral), NOT re-populate the map.
        let remaining = instance.with_economy_budget("ctx-sd", |tracker| tracker.remaining(&did));
        assert_eq!(
            remaining.value(),
            0,
            "post-shutdown economy_budget must use ephemeral tracker"
        );

        // The DashMap must remain empty — economy_budget must NOT re-insert.
        assert!(
            instance.economy_budgets.is_empty(),
            "economy_budgets must not be re-populated after shutdown"
        );

        // with_economy_budget_mut also returns ephemeral.
        instance.with_economy_budget_mut("ctx-sd2", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(100));
        });
        assert!(
            instance.economy_budgets.is_empty(),
            "economy_budgets must not be re-populated after shutdown via _mut"
        );

        // with_economy_antispam also returns ephemeral.
        instance.with_economy_antispam("ctx-sd3", |tracker| {
            tracker.record_message(&did, 1000);
        });
        assert!(
            instance.economy_antispam.is_empty(),
            "economy_antispam must not be re-populated after shutdown"
        );
    }

    // -----------------------------------------------------------------
    // Bridge state tests
    // -----------------------------------------------------------------

    #[test]
    fn bridge_state_starts_empty() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(instance.bridge_state().is_empty());
    }

    #[test]
    fn bridge_state_insert_and_remove() {
        use scp_protocol::bridge::shadow::ShadowRegistry;
        use scp_protocol::crypto::sender_keys::SenderKeyStore;

        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.bridge_state().insert(
            "ctx-bs".to_owned(),
            BridgeContextState {
                shadow_registry: ShadowRegistry::new("ctx-bs".to_owned()),
                sender_key_store: SenderKeyStore::new(),
            },
        );
        assert_eq!(instance.bridge_state().len(), 1);

        instance.remove_bridge_state("ctx-bs");
        assert!(instance.bridge_state().is_empty());
    }

    // -----------------------------------------------------------------
    // DID resolver tests
    // -----------------------------------------------------------------

    #[test]
    fn did_resolver_starts_none() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(instance.did_resolver().is_none());
    }

    // -----------------------------------------------------------------
    // Shutdown clears new registries
    // -----------------------------------------------------------------

    #[test]
    fn shutdown_clears_economy_and_bridge_state() {
        use scp_protocol::bridge::shadow::ShadowRegistry;
        use scp_protocol::crypto::sender_keys::SenderKeyStore;

        let instance = CoreFields::with_supervisor(test_supervisor());

        // Populate economy
        let did = scp_did::DID::from("did:dht:zalice");
        instance.with_economy_budget_mut("ctx-sd", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(100));
        });
        instance.with_economy_antispam("ctx-sd", |_| {});

        // Populate bridge state
        instance.bridge_state().insert(
            "ctx-sd".to_owned(),
            BridgeContextState {
                shadow_registry: ShadowRegistry::new("ctx-sd".to_owned()),
                sender_key_store: SenderKeyStore::new(),
            },
        );

        instance.shutdown();

        assert!(instance.bridge_state().is_empty());
        // Economy DashMaps should be cleared
        assert!(instance.economy_budgets.is_empty());
        assert!(instance.economy_antispam.is_empty());
    }

    // -----------------------------------------------------------------
    // AC 2: persistence field and accessor
    // -----------------------------------------------------------------

    #[test]
    fn new_instance_has_no_persistence() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(
            instance.persistence().is_none(),
            "new() must not have a persistence provider"
        );
    }

    #[test]
    fn with_persistence_sets_provider() {
        use scp_core::context::providers::InMemoryPersistence;

        let persistence = Box::new(InMemoryPersistence::new());
        let instance = CoreFields::with_persistence(persistence);
        instance.set_supervisor(test_supervisor());
        assert!(
            instance.persistence().is_some(),
            "with_persistence() must set the persistence provider"
        );
    }

    // -----------------------------------------------------------------
    // AC 4: relay URL tracking (multi-URL since #1678)
    // -----------------------------------------------------------------

    #[test]
    fn pending_relay_urls_is_empty_by_default() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        assert!(instance.pending_relay_urls().is_empty());
        assert!(!instance.has_pending_relay_urls());
    }

    #[test]
    fn add_relay_url_stores_urls() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.add_relay_url("wss://relay1.example.com".to_owned());
        instance.add_relay_url("wss://relay2.example.com".to_owned());
        let urls = instance.pending_relay_urls();
        assert_eq!(urls.len(), 2);
        assert!(urls.contains("wss://relay1.example.com"));
        assert!(urls.contains("wss://relay2.example.com"));
    }

    #[test]
    fn add_relay_url_deduplicates() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.add_relay_url("wss://relay.example.com".to_owned());
        instance.add_relay_url("wss://relay.example.com".to_owned());
        assert_eq!(instance.pending_relay_urls().len(), 1);
    }

    #[test]
    fn remove_relay_url_drops_entry() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.add_relay_url("wss://relay1.example.com".to_owned());
        instance.add_relay_url("wss://relay2.example.com".to_owned());
        instance.remove_relay_url("wss://relay1.example.com");
        let urls = instance.pending_relay_urls();
        assert_eq!(urls.len(), 1);
        assert!(urls.contains("wss://relay2.example.com"));
    }

    #[test]
    fn add_relay_url_after_shutdown_is_noop() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.shutdown();
        instance.add_relay_url("wss://relay.example.com".to_owned());
        assert!(
            instance.pending_relay_urls().is_empty(),
            "add_relay_url must not resurrect the relay_urls set after shutdown \
             cleared it — that would leak a URL into a subsequent resume attempt"
        );
        assert!(!instance.has_pending_relay_urls());
    }

    #[test]
    fn add_relay_url_race_with_shutdown_never_leaks_urls() {
        // Regression: if `add_relay_url`'s `is_shutdown()` check happens
        // outside the lock, a concurrent shutdown can clear the URL set
        // between the check and the insert. The post-condition of a
        // completed shutdown is that `pending_relay_urls()` is empty; if
        // the race leaves any URL behind, a subsequent `resume()` would
        // dial a relay the caller already walked away from.
        //
        // Run 50 trials × 100 concurrent URL adds racing against shutdown.
        // Each trial constructs a fresh instance, launches a writer thread
        // pushing 100 distinct URLs, concurrently shuts the instance down,
        // joins both, and asserts the post-shutdown URL set is empty.
        use std::thread;
        for trial in 0..50 {
            let instance = Arc::new(CoreFields::with_supervisor(test_supervisor()));
            let writer_instance = Arc::clone(&instance);
            let writer = thread::spawn(move || {
                for i in 0..100 {
                    writer_instance.add_relay_url(format!("wss://relay{i}.example.com"));
                }
            });
            let shutdown_instance = Arc::clone(&instance);
            let shutter = thread::spawn(move || {
                shutdown_instance.shutdown();
            });
            writer.join().unwrap();
            shutter.join().unwrap();
            assert!(
                instance.pending_relay_urls().is_empty(),
                "trial {trial}: relay URLs leaked past shutdown — \
                 add_relay_url admitted a writer after shutdown cleared the set"
            );
            assert!(!instance.has_pending_relay_urls());
        }
    }

    #[test]
    fn clear_transport_preserves_relay_urls() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        instance.add_relay_url("wss://relay.example.com".to_owned());
        assert!(instance.has_pending_relay_urls());

        instance.clear_transport().unwrap();
        assert!(
            instance
                .pending_relay_urls()
                .contains("wss://relay.example.com"),
            "clear_transport must preserve relay URLs so callers can reconnect"
        );
    }

    #[test]
    fn suspend_preserves_relay_urls() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        instance.add_relay_url("wss://relay.example.com".to_owned());

        instance.suspend().unwrap();
        assert!(
            instance
                .pending_relay_urls()
                .contains("wss://relay.example.com"),
            "suspend must preserve relay URLs so callers can reconnect after resume"
        );
    }

    #[tokio::test]
    async fn reconnect_transport_if_pending_is_noop_when_empty() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        // No URLs registered — should return Ok(()) without touching
        // the transport.
        assert!(
            instance.reconnect_transport_if_pending().await.is_ok(),
            "reconnect must succeed when no URLs are pending"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_transport_if_pending_rejects_after_shutdown() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.add_relay_url("wss://relay.example.com".to_owned());
        instance.shutdown();
        let result = instance.reconnect_transport_if_pending().await;
        assert!(
            matches!(result, Err(LifecycleError::AlreadyShutDown)),
            "shutdown must short-circuit with AlreadyShutDown, got {result:?}"
        );
    }

    #[tokio::test]
    async fn suspend_cancels_in_flight_reconnect_dial() {
        // #1696 regression: a `suspend()` firing while
        // `reconnect_transport_if_pending` is mid-dial must cancel the
        // reconnect so the half-connected adapter is dropped before
        // `NativeRelayAdapter` construction completes — preventing the
        // socket leak that motivated #1696. We can't directly observe
        // an OS-level socket handle in a unit test, but we can prove
        // the cancellation path fires and aborts the loop: the dial
        // target is unreachable so the future is "in-flight" until
        // connect timeout, giving us a window to cancel.
        use std::time::Duration;

        let instance = std::sync::Arc::new(CoreFields::with_supervisor(test_supervisor()));
        // Reserved TEST-NET-1 address (RFC 5737) with a closed port —
        // `connect_sourced` stalls until the profile's handshake timeout.
        let unreachable = "ws://192.0.2.1:1/".to_owned();
        instance.add_relay_url(unreachable.clone());

        let instance_clone = std::sync::Arc::clone(&instance);
        let reconnect_handle =
            tokio::spawn(async move { instance_clone.reconnect_transport_if_pending().await });

        // Give the reconnect a moment to enter the dial. Spawn order
        // does not guarantee the future has polled through `.await`
        // yet, so sleep a short tick before firing suspend.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fire suspend — rotates the reconnect-cancel token and
        // cancels the in-flight dial.
        instance.suspend().unwrap();

        // The reconnect must wake on cancellation promptly — with a
        // generous upper bound to tolerate slow CI runners. The
        // production handshake timeout would be on the order of
        // seconds, so anything inside ~1s proves the cancellation
        // actually fired rather than the dial naturally timing out.
        let reconnect_result = tokio::time::timeout(Duration::from_secs(2), reconnect_handle)
            .await
            .unwrap()
            .unwrap();

        assert!(
            matches!(
                reconnect_result,
                Err(LifecycleError::ReconnectFailed { .. })
            ),
            "cancelled reconnect must surface as ReconnectFailed, got {reconnect_result:?}"
        );
        assert!(
            !instance.has_transport(),
            "suspend must leave transport cleared after the cancelled reconnect"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_cancels_in_flight_reconnect_dial() {
        // #1696: `shutdown()` must also cancel a pending reconnect.
        // Same dynamics as the suspend variant — uses the same TEST-NET-1
        // unreachable target to keep the dial in-flight.
        use std::time::Duration;

        let instance = std::sync::Arc::new(CoreFields::with_supervisor(test_supervisor()));
        let unreachable = "ws://192.0.2.1:1/".to_owned();
        instance.add_relay_url(unreachable);

        let instance_clone = std::sync::Arc::clone(&instance);
        let reconnect_handle =
            tokio::spawn(async move { instance_clone.reconnect_transport_if_pending().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        instance.shutdown();

        let reconnect_result = tokio::time::timeout(Duration::from_secs(2), reconnect_handle)
            .await
            .unwrap()
            .unwrap();

        assert!(
            matches!(
                reconnect_result,
                Err(LifecycleError::ReconnectFailed { .. })
            ),
            "cancelled reconnect must surface as ReconnectFailed, got {reconnect_result:?}"
        );
    }

    #[tokio::test]
    async fn suspend_rotates_reconnect_cancel_token() {
        // #1696: the reconnect-cancel token must be rotated on every
        // suspend so subsequent resume cycles get a fresh cancellation
        // scope rather than inheriting an already-cancelled one. Without
        // rotation, every reconnect after the first suspend would short-
        // circuit on the cancellation branch.
        let instance = CoreFields::with_supervisor(test_supervisor());
        let token_before = instance.reconnect_cancel_token();
        assert!(!token_before.is_cancelled());

        instance.suspend().unwrap();

        // Old token must be cancelled — any in-flight reconnect sees it.
        assert!(
            token_before.is_cancelled(),
            "suspend must cancel the previous reconnect token"
        );
        // New token must be fresh — future reconnects aren't pre-cancelled.
        let token_after = instance.reconnect_cancel_token();
        assert!(
            !token_after.is_cancelled(),
            "suspend must install a fresh reconnect-cancel token"
        );
    }

    #[tokio::test]
    async fn reconnect_transport_if_pending_reports_unreachable_urls() {
        // All pending URLs point at unreachable hosts. The function must
        // return a ReconnectFailed error (not panic, not silently succeed)
        // and the URL must remain in the pending set so callers can retry.
        let instance = CoreFields::with_supervisor(test_supervisor());
        // Reserved TEST-NET-1 address (RFC 5737) with a closed port.
        let unreachable = "ws://192.0.2.1:1/".to_owned();
        instance.add_relay_url(unreachable.clone());
        let result = instance.reconnect_transport_if_pending().await;
        assert!(
            matches!(result, Err(LifecycleError::ReconnectFailed { .. })),
            "unreachable URL must surface as ReconnectFailed, got {result:?}"
        );
        assert!(
            instance.pending_relay_urls().contains(&unreachable),
            "failing URL must remain in pending set for retry"
        );
    }

    // Red-hat RED-1003: multi-relay reconnect must dial in parallel with
    // per-URL timeouts, so one slow relay cannot serialize behind itself
    // the dials for every other pending relay. With the serial-loop
    // implementation, three unreachable hosts would take roughly
    // 3 × (full TCP connect timeout) seconds; with the parallel
    // implementation + 5s per-URL timeout, they complete in ~5s.
    //
    // We assert only that the total elapsed time is bounded well below
    // the serial worst case — we do not assert an exact parallel lower
    // bound because `NativeRelayAdapter::connect_sourced` may surface
    // DNS or route-unreachable errors faster than the 5s ceiling. The
    // test is a regression guard: if someone reintroduces the serial
    // loop, this deadline trips.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reconnect_transport_if_pending_dials_urls_in_parallel() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        // Three reserved TEST-NET-1 addresses, different ports — each
        // unroutable and distinct, so the OS cannot coalesce.
        for port in [10_000_u16, 10_001, 10_002] {
            instance.add_relay_url(format!("ws://192.0.2.1:{port}/"));
        }

        let start = std::time::Instant::now();
        let result = instance.reconnect_transport_if_pending().await;
        let elapsed = start.elapsed();

        // Must surface a ReconnectFailed rather than succeed.
        assert!(
            matches!(result, Err(LifecycleError::ReconnectFailed { .. })),
            "unreachable URLs must surface as ReconnectFailed, got {result:?}"
        );
        // Parallel + 5s-per-URL timeout: upper bound ~5s + scheduling
        // slack. Serial 3-URL loop with a per-URL ceiling >= 5s would
        // exceed 15s. Use a generous 10s ceiling to avoid CI flakes from
        // slow runners while still tripping on a regression to a serial
        // loop that lets the per-URL ceiling accumulate.
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "3 unreachable URLs must complete in under 10s with parallel \
             dials — got {elapsed:?}. A serial loop would compound each \
             URL's 5s timeout."
        );
    }

    #[tokio::test]
    async fn relay_urls_survive_suspend_resume_cycle() {
        // Multiple relay URLs must survive suspend/resume so callers can
        // reconnect to every one of them after resume.
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        instance.add_relay_url("wss://relay1.example.com".to_owned());
        instance.add_relay_url("wss://relay2.example.com".to_owned());
        instance.suspend().unwrap();
        assert_eq!(
            instance.pending_relay_urls().len(),
            2,
            "relay URLs must survive suspend"
        );
        instance.resume().await.unwrap();
        assert_eq!(
            instance.pending_relay_urls().len(),
            2,
            "relay URLs must survive resume — caller uses them to reconnect"
        );
    }

    #[test]
    fn shutdown_clears_relay_urls() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.add_relay_url("wss://relay.example.com".to_owned());
        assert!(instance.has_pending_relay_urls());

        instance.shutdown();
        assert!(
            instance.pending_relay_urls().is_empty(),
            "shutdown must clear relay URLs"
        );
    }

    // -----------------------------------------------------------------
    // AC 6: two-instance independence
    // -----------------------------------------------------------------

    #[test]
    fn two_instances_are_independent() {
        // BridgeInstances are containers — they carry no DID of their own
        // (spec §12.2.3). The DID belongs to the `NodeMlsFactory` inside
        // each `Supervisor`'s attached manager. Two instances with distinct
        // supervisors must be independently shut-down-able.
        let sup1 = test_supervisor();
        let sup2 = test_supervisor();
        let bi1 = CoreFields::with_supervisor(Arc::clone(&sup1));
        let bi2 = CoreFields::with_supervisor(Arc::clone(&sup2));

        // Their Supervisor allocations are distinct.
        assert!(!Arc::ptr_eq(
            bi1.try_supervisor().unwrap(),
            bi2.try_supervisor().unwrap()
        ));

        // Shutting down one does not affect the other.
        bi1.shutdown();
        assert!(bi1.is_shutdown());
        assert!(!bi2.is_shutdown());

        // bi2 is still ready to service operations.
        assert!(bi2.check_ready().is_ok());
    }

    // -----------------------------------------------------------------
    // AC 8: suspend/resume with persistence
    // -----------------------------------------------------------------

    // Must run on the multi-thread runtime: `CoreFields::suspend` synchronously
    // invokes `ContextManager::flush_all_contexts_sync`, which uses
    // `tokio::task::block_in_place`. `block_in_place` panics on the default
    // single-thread `#[tokio::test]` runtime ("can call blocking only when
    // running on the multi-threaded runtime"). Commit 12 of #1549 PR 2
    // introduced the `block_in_place` path without updating this test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn suspend_flushes_contexts_to_persistence() {
        use scp_core::context::providers::InMemoryPersistence;
        use std::sync::Arc;

        let persistence = Arc::new(InMemoryPersistence::new());
        let persistence_for_supervisor: Box<dyn ContextPersistence> =
            Box::new(InMemoryPersistence::new());
        let persistence_for_instance: Box<dyn ContextPersistence + Send + Sync> =
            Box::new(InMemoryPersistence::new());

        // Build the Supervisor directly through `with_providers` (ADR-049
        // commit 12c.9g.3.6 — the FFI layer no longer touches
        // `ContextManager`). The supervisor populates its lifted-
        // provider slots and the manager attachment internally.
        let key_resolver: scp_core::context::governance::KeyResolver =
            Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None);
        let supervisor = Supervisor::with_providers(
            Arc::new(NodeMlsFactory::new(
                "did:test:suspend-flush".to_owned(),
                std::sync::Arc::new(scp_clock::SystemClock),
            )),
            Box::new(scp_core::context::LocalTransportProvider),
            Box::new(NoOpEventLog),
            key_resolver,
            Some(persistence_for_supervisor),
            None,
            None,
            None,
            test_mls_storage(),
        );

        let instance = CoreFields::with_persistence(persistence_for_instance);
        instance.set_supervisor(supervisor);

        // Verify the persistence accessor returns Some.
        assert!(instance.persistence().is_some());

        // Suspend should complete without errors (flush is best-effort).
        instance.suspend().unwrap();
        assert!(instance.is_suspended());

        // No relay URLs were registered, so pending_relay_urls is empty.
        assert!(instance.pending_relay_urls().is_empty());

        // Resume clears the suspended flag.
        instance.resume().await.unwrap();
        assert!(!instance.is_suspended());

        // Instance is ready again.
        assert!(instance.check_ready().is_ok());

        // Suppress the unused `persistence` warning — it was only used to
        // verify the Arc::new pattern compiles; the real persistence is
        // owned by the Supervisor through the manager it holds internally.
        let _ = persistence;
    }

    // -----------------------------------------------------------------
    // AC 9: two instances operate concurrently (independent state)
    // -----------------------------------------------------------------

    #[test]
    fn two_instances_operate_concurrently() {
        let sup1 = test_supervisor();
        let sup2 = test_supervisor();
        let bi1 = CoreFields::with_supervisor(Arc::clone(&sup1));
        let bi2 = CoreFields::with_supervisor(Arc::clone(&sup2));

        // Register known contexts independently.
        bi1.register_known_context(
            "ctx-1",
            KnownContext {
                routing_id: [1u8; 32],
                relay_url: None,
                member_did: "did:dht:alice".to_owned(),
                last_seen: 100,
            },
        );
        bi2.register_known_context(
            "ctx-2",
            KnownContext {
                routing_id: [2u8; 32],
                relay_url: None,
                member_did: "did:dht:bob".to_owned(),
                last_seen: 200,
            },
        );

        // Each instance only knows about its own context.
        assert_eq!(bi1.known_context_count(), 1);
        assert!(bi1.has_known_context("ctx-1"));
        assert!(!bi1.has_known_context("ctx-2"));

        assert_eq!(bi2.known_context_count(), 1);
        assert!(bi2.has_known_context("ctx-2"));
        assert!(!bi2.has_known_context("ctx-1"));

        // Set relay URLs independently.
        bi1.add_relay_url("wss://relay1.example.com".to_owned());
        bi2.add_relay_url("wss://relay2.example.com".to_owned());
        assert!(
            bi1.pending_relay_urls()
                .contains("wss://relay1.example.com")
        );
        assert!(
            bi2.pending_relay_urls()
                .contains("wss://relay2.example.com")
        );

        // Shutdown of bi1 does not affect bi2's state.
        bi1.shutdown();
        assert!(bi1.is_shutdown());
        assert!(!bi2.is_shutdown());
        assert_eq!(bi2.known_context_count(), 1);
        assert!(
            bi2.pending_relay_urls()
                .contains("wss://relay2.example.com")
        );
    }

    // -----------------------------------------------------------------
    // Commit 1: instance_id + handle affinity
    // -----------------------------------------------------------------

    #[test]
    fn instance_id_is_unique_across_instances() {
        let a = CoreFields::new();
        let b = CoreFields::new();
        assert_ne!(
            a.instance_id(),
            b.instance_id(),
            "two fresh instances must carry distinct instance_ids"
        );
    }

    #[test]
    fn instance_id_is_monotonic() {
        let a = CoreFields::new();
        let b = CoreFields::new();
        let c = CoreFields::new();
        assert!(
            a.instance_id() < b.instance_id() && b.instance_id() < c.instance_id(),
            "instance_id allocation must be monotonically increasing: {} < {} < {}",
            a.instance_id(),
            b.instance_id(),
            c.instance_id()
        );
    }

    #[test]
    fn instance_id_is_never_zero() {
        // Zero is reserved as UNSET_INSTANCE_ID — live instances must never
        // collide with a handle whose id has not been assigned.
        let a = CoreFields::new();
        assert_ne!(a.instance_id(), UNSET_INSTANCE_ID);
    }

    #[test]
    fn handle_affinity_accepts_same_instance() {
        let instance = CoreFields::new();
        assert!(instance.check_handle(instance.instance_id()).is_ok());
    }

    #[test]
    fn handle_affinity_rejects_cross_instance() {
        let a = CoreFields::new();
        let b = CoreFields::new();
        // Handle minted against `a`, presented to `b`.
        let err = b.check_handle(a.instance_id()).unwrap_err();
        assert_eq!(err.handle_instance_id(), a.instance_id());
        assert_eq!(err.expected_instance_id(), b.instance_id());
    }

    #[test]
    fn handle_affinity_rejects_unset_id() {
        // A handle that forgot to attach itself to an instance carries the
        // reserved `UNSET_INSTANCE_ID` — the live instance must reject it.
        let instance = CoreFields::new();
        assert!(instance.check_handle(UNSET_INSTANCE_ID).is_err());
    }

    #[test]
    fn handle_affinity_error_display_is_sanitized() {
        let err = HandleAffinityError::new(7, 11);
        let msg = err.to_string();
        // Ids must not leak into the display — operators read them from
        // Debug/log fields, users see the sanitized message.
        assert!(!msg.contains('7'));
        assert!(!msg.contains("11"));
        assert!(msg.contains("handle"));
    }

    // -----------------------------------------------------------------
    // with_mcp_allowlist helper
    // -----------------------------------------------------------------

    #[test]
    fn with_mcp_allowlist_runs_closure_and_returns_ok() {
        let core = CoreFields::new();
        let len = core
            .with_mcp_allowlist(|a| a.snapshot().allowed.len())
            .unwrap();
        assert!(len > 0, "default allowlist must be non-empty");
    }

    #[test]
    fn with_mcp_allowlist_returns_closure_value_unchanged() {
        // Helper must surface the closure's return value verbatim; only
        // poisoning is converted into the typed `AllowlistGuardError`.
        let core = CoreFields::new();
        let inner_err: Result<(), &'static str> = core
            .with_mcp_allowlist(|_a| Err::<(), &'static str>("inner-err"))
            .unwrap();
        assert_eq!(inner_err.unwrap_err(), "inner-err");
    }

    #[test]
    fn with_mcp_allowlist_drops_guard_before_returning() {
        // Two back-to-back calls must each acquire the lock cleanly — proving
        // the first call's guard dropped before the second call started.
        let core = CoreFields::new();
        core.with_mcp_allowlist(|a| a.disable_enforcement(0))
            .unwrap();
        let unrestricted = core
            .with_mcp_allowlist(|a| a.snapshot().unrestricted)
            .unwrap();
        assert!(unrestricted, "first call's mutation must be visible");
    }

    #[test]
    fn with_mcp_allowlist_isolates_per_instance() {
        // Helper-mediated mutations on instance A must not affect instance B.
        let a = CoreFields::new();
        let b = CoreFields::new();
        a.with_mcp_allowlist(|x| x.disable_enforcement(0)).unwrap();
        let b_unrestricted = b.with_mcp_allowlist(|x| x.snapshot().unrestricted).unwrap();
        assert!(!b_unrestricted, "instance b must remain restricted");
    }

    // -----------------------------------------------------------------
    // Commit 1: shutdown_core_async
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn shutdown_core_async_graceful_when_no_tasks() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let outcome = instance
            .shutdown_core_async(Duration::from_secs(1))
            .await
            .unwrap();
        let ShutdownOutcome::GracefulWithin {
            elapsed,
            panicked_tasks,
        } = outcome
        else {
            unreachable!("expected GracefulWithin, got {outcome:?}");
        };
        assert!(elapsed < Duration::from_secs(1));
        assert_eq!(panicked_tasks, 0);
        assert!(instance.is_shutdown());
    }

    #[tokio::test]
    async fn shutdown_core_async_times_out_with_long_task() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        {
            let mut tasks = instance.task_handle().await;
            tasks.spawn(async move {
                // Sleep far beyond the shutdown deadline below.
                tokio::time::sleep(Duration::from_mins(1)).await;
            });
        }
        // Review feedback (test-quality, review-round-N): the original
        // 100 ms budget was flaky on slow CI runners — `drain_under_deadline`
        // uses `std::time::Instant::now()` (wall-clock), so
        // `tokio::time::pause()` would not help here. Raising the budget
        // to 500 ms keeps the test's intent (a sub-second deadline on a
        // task that sleeps for a full minute) while tolerating scheduler
        // jitter. If CI flakiness recurs, bump further — the test's
        // correctness signal is the `TimedOut` outcome, not the wall-
        // clock bound.
        let outcome = instance
            .shutdown_core_async(Duration::from_millis(500))
            .await
            .unwrap();
        let ShutdownOutcome::TimedOut {
            aborted_tasks,
            panicked_tasks,
        } = outcome
        else {
            unreachable!("expected TimedOut, got {outcome:?}");
        };
        assert_eq!(aborted_tasks, 1);
        assert_eq!(panicked_tasks, 0);
        assert!(instance.is_shutdown());
    }

    #[tokio::test]
    async fn shutdown_core_async_fires_cancellation_token() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let instance = CoreFields::with_supervisor(test_supervisor());
        let observed = Arc::new(AtomicBool::new(false));
        let observed_clone = Arc::clone(&observed);
        let token = instance.cancel_token();
        {
            let mut tasks = instance.task_handle().await;
            tasks.spawn(async move {
                token.cancelled().await;
                observed_clone.store(true, Ordering::SeqCst);
            });
        }
        let outcome = instance
            .shutdown_core_async(Duration::from_secs(2))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ShutdownOutcome::GracefulWithin { .. }),
            "task observing cancel_token should exit gracefully, got {outcome:?}"
        );
        assert!(
            observed.load(Ordering::SeqCst),
            "spawned task must have observed the cancellation signal"
        );
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn shutdown_core_async_counts_panicked_tasks() {
        // Spawn a task that panics quickly — the drain should observe it
        // and surface the count in `GracefulWithin.panicked_tasks`.
        let instance = CoreFields::with_supervisor(test_supervisor());
        {
            let mut tasks = instance.task_handle().await;
            tasks.spawn(async move {
                panic!("intentional panic — shutdown_core_async_counts_panicked_tasks");
            });
            tasks.spawn(async move {
                panic!("intentional panic #2");
            });
            tasks.spawn(async move {
                // This one exits cleanly — must not be counted as panicked.
                //
                // Uses `yield_now()` (one scheduler round-trip, then a clean
                // exit) rather than a real-time `sleep`. A `sleep` here made
                // the test flaky: the clean task then had to wait on the timer
                // wheel to complete, and `drain_under_deadline` gates the
                // outcome on a wall-clock deadline. Under CI scheduler
                // starvation the drain could lose that race, flipping the
                // outcome from `GracefulWithin` to `TimedOut` and blowing the
                // `unreachable!` below — even though the panicked count itself
                // is always correct. `yield_now()` completes without ever
                // touching the timer wheel, so the drain finishes in a couple
                // of poll cycles and never approaches the (generous) deadline,
                // making the `GracefulWithin` outcome deterministic while still
                // exercising a genuine clean-exit task the drain must not count.
                tokio::task::yield_now().await;
            });
        }
        let outcome = instance
            .shutdown_core_async(Duration::from_secs(2))
            .await
            .unwrap();
        let ShutdownOutcome::GracefulWithin { panicked_tasks, .. } = outcome else {
            unreachable!("expected GracefulWithin, got {outcome:?}");
        };
        assert_eq!(
            panicked_tasks, 2,
            "two panicking tasks must be counted, got {panicked_tasks}"
        );
    }

    #[tokio::test]
    async fn shutdown_core_async_runs_hooks_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let instance = CoreFields::with_supervisor(test_supervisor());
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        instance.register_shutdown_hook(Box::new(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }));

        instance
            .shutdown_core_async(Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_core_async_is_idempotent() {
        let instance = CoreFields::with_supervisor(test_supervisor());
        let first = instance
            .shutdown_core_async(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(first, ShutdownOutcome::GracefulWithin { .. }));

        let err = instance
            .shutdown_core_async(Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(err, ShutdownError::AlreadyShutDown);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_core_async_after_sync_shutdown_errors() {
        // The sync `shutdown()` path also flips the idempotent flag, so the
        // async variant must report AlreadyShutDown afterwards — callers
        // get a single source of truth for "is already terminated?"
        let instance = CoreFields::with_supervisor(test_supervisor());
        instance.shutdown();
        let err = instance
            .shutdown_core_async(Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(err, ShutdownError::AlreadyShutDown);
    }

    // -----------------------------------------------------------------
    // Commit 2: BridgeInstanceCore trait behaves via &dyn
    // -----------------------------------------------------------------

    /// Minimal trait implementation used to exercise default `BridgeInstanceCore`
    /// methods without pulling in a concrete per-bridge struct (those land in
    /// commits 3–5). Holds a `CoreFields` and delegates the trait.
    struct TestBridge {
        core: CoreFields,
    }

    #[async_trait::async_trait]
    impl BridgeInstanceCore for TestBridge {
        fn core(&self) -> &CoreFields {
            &self.core
        }
        // `shutdown` inherits the trait default (landed in commit 6 of
        // ADR-049): `self.core().shutdown_core_async(timeout).await +
        // self.bridge_specific_shutdown()`. Overriding it here would
        // diverge from production behavior and be caught by the
        // cross-bridge consistency gate.
    }

    #[test]
    fn trait_default_check_handle_rejects_cross_instance() {
        let a: Box<dyn BridgeInstanceCore> = Box::new(TestBridge {
            core: CoreFields::new(),
        });
        let b: Box<dyn BridgeInstanceCore> = Box::new(TestBridge {
            core: CoreFields::new(),
        });
        assert!(b.check_handle(a.instance_id()).is_err());
        assert!(a.check_handle(a.instance_id()).is_ok());
    }

    #[tokio::test]
    async fn trait_shutdown_delegates_to_core() {
        let bridge = TestBridge {
            core: CoreFields::with_supervisor(test_supervisor()),
        };
        let outcome = bridge.shutdown(Duration::from_secs(1)).await.unwrap();
        assert!(matches!(outcome, ShutdownOutcome::GracefulWithin { .. }));
        assert!(bridge.core().is_shutdown());
    }
}
