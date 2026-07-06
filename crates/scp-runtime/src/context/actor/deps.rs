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
//! extended the bundle with every cross-cutting collaborator the
//! deleted `ContextManager` handler submodules reached via `self.X`:
//!
//! - `clock` — wall-clock source. Formerly `ContextManager::clock`.
//! - `event_tx` — optional fan-out channel for external `ContextEvent`
//!   subscribers (webhook dispatcher in `scp-node`). Formerly
//!   `ContextManager::event_tx`. `Option` because not every embedder
//!   wires a subscriber; the legacy handler treated `None` as "drop silently."
//! - `key_resolver` — DID → Ed25519 verifying-key map used by UCAN /
//!   governance vote verification. Formerly `ContextManager::key_resolver`.
//! - `payment_adapter` — optional economy adapter for the 9-step paid
//!   action flow (spec §19.2.2). Formerly
//!   `ContextManager::payment_adapter`. `Option` because "free context"
//!   is a valid configuration.
//!
//! # Commit 12b.2a expansion
//!
//! Commit 12b.2a of ADR-049 (actor-owned-state infrastructure) adds one
//! additional cross-cutting collaborator that handler bodies needed once
//! they stopped delegating to the legacy manager:
//!
//! - `local_dids` — `Arc<ArcSwap<HashSet<DID>>>`. Formerly
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
//! owns a concrete `Arc<S>` — e.g. [`ActorDeps::persistence`] (typed
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
//! - `contexts` — cross-actor reads are banned by the
//!   capability contract (ADR §2: "Never ContextActor → ContextActor
//!   directly"). Cross-context work goes through
//!   `SupervisorHandle::start_saga`.
//! - `task_set` — supervisor-scoped lifecycle state, held on the
//!   supervisor side.
//! - `consequence_rules` — per-context state stored in `PerContextState`,
//!   not a cross-cutting dep.
//!
//! These `ActorDeps` fields are wired on the supervisor side at
//! actor-spawn time and read directly by the handler bodies — e.g.
//! `deps.event_tx` in governance, `deps.payment_adapter` in saga, and
//! `deps.local_dids` in queries. The former `view.manager().foo`
//! indirection and the legacy manager it reached through are gone.

use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;

use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::persistence::ContextPersistence;
use crate::context::supervisor::handle::SupervisorHandle;
use crate::context::supervisor::identity_capability::OwnedIdentityDid;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::crypto::hpke_backend::HpkeBackend;
use crate::crypto::mls::backend::MlsBackend;
use crate::crypto::mls::provider::MlsCryptoProvider;
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
    /// MLS crypto provider — owns the per-context MLS group + sender-key
    /// state map. Formerly `ContextManager::crypto`. Held on
    /// [`Supervisor`](crate::context::supervisor::Supervisor) directly
    /// during the helper-migration window; cloned into each actor's
    /// `ActorDeps` at spawn time so handler bodies can call
    /// [`MlsCryptoProvider::seal`] / `open` / `advance_epoch` without
    /// reaching back through `&Supervisor`.
    ///
    /// Added in Phase 2A.1 of ADR-049 (trust_recovery domain migration)
    /// — first migrated handler that needs MLS provider state. Will
    /// remain populated through the rest of Phase 2A; eventually the
    /// `MlsCryptoProvider` dissolves (plan §"MlsCryptoProvider
    /// dissolution") and per-context crypto state moves entirely onto
    /// [`crate::context::actor::state::ContextCryptoState`] inside
    /// [`crate::context::actor::state::PerContextState`].
    pub crypto: Arc<MlsCryptoProvider>,
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
    /// Wall-clock source. Formerly `ContextManager::clock`
    /// (`Arc<dyn scp_clock::Clock>`, default
    /// [`scp_clock::SystemClock`]). Every handler that computes
    /// pricing windows, velocity tracking, TTL comparisons, UCAN expiry
    /// checks, or rate-limit buckets reads the clock — concentrating it
    /// in `ActorDeps` removes the per-handler plumbing required if each
    /// callsite re-derived it from the supervisor.
    pub clock: Arc<dyn Clock>,
    /// Optional fan-out channel for `(context_id, ContextEvent)` pairs
    /// sent to external subscribers (the webhook dispatcher in
    /// `scp-node`, SDK event streams). Formerly
    /// `ContextManager::event_tx`. `None` in embedders that do not
    /// subscribe to context events — handlers check `Option::is_some`
    /// before sending and drop silently otherwise, matching the legacy behavior.
    ///
    /// Lagging receivers lose events (bounded channel) — delivery is
    /// best-effort.
    pub event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
    /// DID → Ed25519 verifying-key resolver used by governance vote
    /// verification (spec §5.9, ADR-031) and UCAN proof validation.
    /// Formerly `ContextManager::key_resolver` (typealias
    /// `Arc<dyn Fn(&DID) -> Option<VerifyingKey> + Send + Sync>`).
    pub key_resolver: KeyResolver,
    /// Optional economy adapter for the 9-step paid action flow
    /// (spec §19.2.2). Formerly `ContextManager::payment_adapter`.
    /// `None` for "free context" configurations — handlers skip the
    /// escrow path and fall through to budget-only enforcement.
    pub payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
    /// DIDs controlled by the local node/SDK. `ArcSwap` for lock-free
    /// reads on every `deliver_incoming` (resolve local member).
    /// Sourced from
    /// [`crate::context::supervisor::Supervisor::local_dids`]: the
    /// actor model hoists this set to the supervisor (it was a
    /// per-manager `RwLock<HashSet<DID>>` before the actor refactor)
    /// so every actor shares the same snapshot without each one
    /// carrying its own lock — the `Arc<ArcSwap<_>>` is clone-cheap
    /// and every actor gets a snapshot reference at spawn time.
    ///
    /// Added in commit 12b.2a of ADR-049. Read by the messaging
    /// handler's `deliver_incoming` body to resolve which local DID
    /// the incoming envelope addresses.
    pub local_dids: Arc<ArcSwap<HashSet<DID>>>,
    /// Unforgeable capability token proving which identity owns this
    /// actor (ADR-049 §5). Minted fresh per-actor at spawn time in
    /// [`Supervisor::build_actor_deps`](crate::context::supervisor::Supervisor::build_actor_deps)
    /// via `OwnedIdentityDid::issue_for_actor(owning_did)`, so each
    /// actor's token is for ITS OWN owning identity — never a shared or
    /// wrong-owner token.
    ///
    /// `pub(in crate::context)` — held here so per-identity
    /// `SupervisorHandle` methods can take `&OwnedIdentityDid` (the only
    /// identity an actor can read is the one that owns it). This is the
    /// NARROWEST visibility that lets the supervisor build site populate
    /// the field and `crate::context` handlers borrow it; it is NOT
    /// `pub`, because `OwnedIdentityDid` itself is `pub(in crate::context)`
    /// and the capability must not escape the `context` module tree.
    pub(in crate::context) owned_identity: OwnedIdentityDid,
}

impl ActorDeps {
    /// Build a fresh [`ActorDeps`] bundle by cloning every field of
    /// `self` (ADR-049 Phase 2A finalization bootstrap dual-write).
    ///
    /// The bundle is intentionally not `Clone` (single-owner ownership
    /// discipline — see the type-level doc) but every field is an
    /// `Arc`-like clone-cheap handle. The lifecycle bootstrap calls
    /// this when it needs to keep its own `&ActorDeps` borrow while
    /// also handing an owned `ActorDeps` to the actor task spawned for
    /// the freshly-registered context.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — only lifecycle bootstrap calls this.
    /// External crates and FFI bridges never construct or duplicate
    /// `ActorDeps`.
    #[must_use]
    #[allow(dead_code)] // first production caller lands with the bootstrap wiring in this PR
    pub(in crate::context) fn clone_for_spawn(&self) -> Self {
        Self {
            crypto: Arc::clone(&self.crypto),
            transport: Arc::clone(&self.transport),
            persistence: Arc::clone(&self.persistence),
            event_log: Arc::clone(&self.event_log),
            supervisor: self.supervisor.clone(),
            key_package_store: self.key_package_store.clone(),
            mls: Arc::clone(&self.mls),
            hpke: Arc::clone(&self.hpke),
            mls_storage: Arc::clone(&self.mls_storage),
            clock: Arc::clone(&self.clock),
            event_tx: self.event_tx.clone(),
            key_resolver: Arc::clone(&self.key_resolver),
            payment_adapter: self.payment_adapter.as_ref().map(Arc::clone),
            local_dids: Arc::clone(&self.local_dids),
            // Reissue the capability token for the SAME owning identity.
            // `clone_for_spawn` holds only `&self` — a token already
            // minted by the supervisor for this context's owner — so it
            // cannot (and must not) re-derive from a raw `DID`. `reissue`
            // clones the held DID; it is not a forgery vector because it
            // takes no `DID` parameter and possession of `&self` already
            // proves supervisor attestation. See `OwnedIdentityDid::reissue`.
            owned_identity: self.owned_identity.reissue(),
        }
    }
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
