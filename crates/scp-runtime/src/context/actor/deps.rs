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
//! Fields explicitly **not** added here:
//!
//! - `local_dids`, `standing_contexts` — supervisor-scoped state already
//!   reachable through `SupervisorHandle::local_dids()` /
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

use std::sync::Arc;

use scp_primitives::Clock;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;

use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::manager::ContextPersistence;
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
