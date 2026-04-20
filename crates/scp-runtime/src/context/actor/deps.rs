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

use std::sync::Arc;

use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::manager::ContextPersistence;
use crate::context::supervisor::handle::SupervisorHandle;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::crypto::hpke_backend::HpkeBackend;
use crate::crypto::mls::backend::MlsBackend;
use crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter;

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
