//! `ActorDeps` — the non-state resources a `ContextActor` holds.
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Per ADR-049 §5 and plan §"ActorDeps and SupervisorHandle", `ActorDeps`
//! is capability-reduced: it carries the transport, persistence, event
//! log, MLS/HPKE backends, and a **`SupervisorHandle`** rather than an
//! `Arc<Supervisor>`. Handler code can only reach the supervisor through
//! the handle's narrow API (`start_saga`, read-only accessors); it
//! cannot obtain a sibling actor's handle.
//!
//! This is the mechanical contract that makes "actor A cannot send to
//! actor B directly" a compile-time property. Cross-actor atomicity is
//! saga-only, enforced through the `start_saga` shape.
//!
//! # Commit 12a.5 expansion
//!
//! Commit 12a.5 of ADR-049 (pre-work for handler body migration)
//! extends the bundle with every cross-cutting collaborator the legacy
//! `ContextManager` handler submodules reach via `self.X`:
//!
//! - `clock` — wall-clock source. Legacy: `ContextManager::clock`.
//! - `event_tx` — optional fan-out channel for external `ContextEvent`
//!   subscribers (webhook dispatcher in `scp-node`). Legacy:
//!   `ContextManager::event_tx`. `Option` because not every embedder
//!   wires a subscriber; legacy treats `None` as "drop silently."
//! - `key_resolver` — DID → Ed25519 verifying-key map used by UCAN /
//!   governance vote verification. Legacy: `ContextManager::key_resolver`.
//! - `payment_adapter` — optional economy adapter for the 9-step paid
//!   action flow (spec §19.2.2). Legacy:
//!   `ContextManager::payment_adapter`. `Option` because "free context"
//!   is a valid configuration.
//!
//! # Commit 12b.2a expansion
//!
//! Commit 12b.2a of ADR-049 (actor-owned-state infrastructure) adds one
//! additional cross-cutting collaborator that handler bodies need once
//! they stop delegating to `ContextManager`:
//!
//! - `local_dids` — `Arc<ArcSwap<HashSet<DID>>>`. Legacy:
//!   `ContextManager::local_dids` (`RwLock<HashSet<DID>>`). Rewritten to
//!   `ArcSwap` here because the read path is on the hot path of every
//!   `deliver_incoming` (resolve local member for sender-key layer) —
//!   `ArcSwap::load` is lock-free. Supervisor-scoped on the post-
//!   refactor side; wired at actor-spawn time by the supervisor cloning
//!   its own `Arc`.
//!
//! # `storage` is NOT on the bundle
//!
//! The [`scp_platform::Storage`] trait uses `impl Future` in its
//! associated methods, so it is not dyn-compatible — `Arc<dyn Storage>`
//! fails to compile. Every production carrier of `Storage` is generic
//! over `S: Storage` (see `ProtocolRepositorySagaJournal<S>`,
//! `ProtocolRepository<S>`). Embedding a generic in `ActorDeps` would
//! require parameterizing every handler signature over `S`, which is a
//! non-additive restructure out of scope for commit 12b.2a.
//!
//! Handler bodies that need raw byte-blob storage (saga evidence, KP
//! store blobs) reach it through the specific bridge that already
//! owns a concrete `Arc<S>` — e.g. [`Self::persistence`] (typed
//! `ContextSnapshot` persistence), or the
//! [`KeyPackageStoreHandle`](crate::context::supervisor::key_package_actor::KeyPackageStoreHandle)
//! inside the bundle. No handler currently needs `dyn Storage`
//! directly; if one ever does, the path is a focused generic
//! parameterization, not a dyn-trait field here.
//!
//! Fields explicitly **not** added here:
//!
//! - `standing_contexts` — supervisor-scoped state reachable through
//!   `SupervisorHandle::standing_peer()` per ADR §2.
//! - `contexts` / `contexts_arc` — cross-actor reads are banned by the
//!   capability contract (ADR §2: "Never ContextActor → ContextActor
//!   directly"). Cross-context work goes through
//!   `SupervisorHandle::start_saga`.
//! - `task_set` / `next_generation` — supervisor-scoped lifecycle
//!   state that migrates with the actor run-loop in commit 12b/c.
//! - `consequence_rules` — per-context state stored in `PerContextState`,
//!   not a cross-cutting dep.
//!
//! The new fields are wired on the supervisor side at actor-spawn time
//! (shim wiring lives behind the `testing` feature until the legacy
//! manager is deleted in commit 12). Handler bodies do not yet read the
//! new fields — 12b+ performs the mechanical migration from
//! `view.manager().foo` → `deps.foo`.

use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;

use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::persistence::ContextPersistence;
use crate::context::supervisor::handle::SupervisorHandle;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::crypto::hpke_backend::HpkeBackend;
use crate::crypto::mls::backend::MlsBackend;
use crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter;
use crate::economy::adapter::PaymentAdapterDyn;

// ---------------------------------------------------------------------------
// ActorDeps
// ---------------------------------------------------------------------------

/// Non-state resources held by a `ContextActor`. Moved into the actor
/// task at spawn time; never re-exposed outside the actor's scope.
///
/// Construction is delegated to `Supervisor::spawn_actor` which assembles
/// a `SupervisorHandle` and KP-store handle scoped to the actor's owning
/// identity before handing the bundle to the actor task.
///
/// **Non-clone.** The bundle is passed by value into `tokio::spawn`; it
/// cannot be cloned because [`KeyPackageStoreHandle`] is clone but the
/// overall ownership discipline treats `ActorDeps` as single-owner. If a
/// handler ever needs to re-dispatch through the handle set it should
/// hold its own clones of the individual handles.
pub struct ActorDeps {
    /// Transport provider (relay, subscription, publish).
    pub transport: Arc<dyn ContextTransportProvider>,
    /// Context snapshot persistence backend.
    pub persistence: Arc<dyn ContextPersistence>,
    /// Merkle event log backend.
    pub event_log: Arc<dyn ContextEventLogProvider>,
    /// Capability-reduced supervisor view. No `ContextActorHandle`
    /// accessor — cross-context work goes through
    /// [`SupervisorHandle::start_saga`].
    pub supervisor: SupervisorHandle,
    /// This actor's owning identity's `KeyPackageStoreActor` handle.
    /// `pub` because `handlers/lifecycle.rs` will call its reserve /
    /// confirm API at Welcome-processing time.
    pub key_package_store: KeyPackageStoreHandle,
    /// MLS primitives backend (stateless).
    pub mls: Arc<dyn MlsBackend>,
    /// HPKE + wrapping-key primitives backend (stateless).
    pub hpke: Arc<dyn HpkeBackend>,
    /// OpenMLS `StorageProvider` adapter (shared across actors; each
    /// actor's `OpenMlsBackend` is per-actor but reads/writes the same
    /// underlying KV via this adapter).
    pub mls_storage: Arc<dyn OpenMlsStorageAdapter>,
    /// Wall-clock source. Legacy: `ContextManager::clock`
    /// (`Arc<dyn scp_primitives::Clock>`, default
    /// [`scp_primitives::SystemClock`]). Every handler that computes
    /// pricing windows, velocity tracking, TTL comparisons, UCAN expiry
    /// checks, or rate-limit buckets reads the clock — concentrating it
    /// in `ActorDeps` removes the per-handler plumbing required if each
    /// callsite re-derived it from the supervisor.
    pub clock: Arc<dyn Clock>,
    /// Optional fan-out channel for `(context_id, ContextEvent)` pairs
    /// sent to external subscribers (the webhook dispatcher in
    /// `scp-node`, SDK event streams). Legacy:
    /// `ContextManager::event_tx`. `None` in embedders that do not
    /// subscribe to context events — handlers check `Option::is_some`
    /// before sending and drop silently otherwise, matching legacy.
    ///
    /// Lagging receivers lose events (bounded channel) — delivery is
    /// best-effort.
    pub event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
    /// DID → Ed25519 verifying-key resolver used by governance vote
    /// verification (spec §5.9, ADR-031) and UCAN proof validation.
    /// Legacy: `ContextManager::key_resolver` (typealias
    /// `Arc<dyn Fn(&DID) -> Option<VerifyingKey> + Send + Sync>`).
    pub key_resolver: KeyResolver,
    /// Optional economy adapter for the 9-step paid action flow
    /// (spec §19.2.2). Legacy: `ContextManager::payment_adapter`.
    /// `None` for "free context" configurations — handlers skip the
    /// escrow path and fall through to budget-only enforcement.
    pub payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
    /// DIDs controlled by the local node/SDK. `ArcSwap` for lock-free
    /// reads on every `deliver_incoming` (resolve local member). Legacy:
    /// [`crate::context::manager::ContextManager::local_dids`]
    /// (`RwLock<HashSet<DID>>`). The actor model hoists this to the
    /// supervisor so every actor shares the same snapshot without each
    /// one carrying its own `RwLock` — the `Arc<ArcSwap<_>>` is
    /// clone-cheap and every actor gets a snapshot reference at spawn
    /// time.
    ///
    /// Added in commit 12b.2a of ADR-049. Read by the messaging
    /// handler's `deliver_incoming` body (landing 12b.2b) to resolve
    /// which local DID the incoming envelope addresses.
    pub local_dids: Arc<ArcSwap<HashSet<DID>>>,
}

// Compile-time witness that `ActorDeps` is `Send + Sync` — the bundle
// is moved into a `tokio::spawn`'d task.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ActorDeps>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn actor_deps_is_send_sync() {
        // Compile-time only; the const fn above asserts this. Test is
        // kept as a documentation anchor — if this ever fails to
        // compile, `ActorDeps` has gained a non-Send field and the
        // actor-per-context contract is broken.
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ActorDeps>();
    }
}
