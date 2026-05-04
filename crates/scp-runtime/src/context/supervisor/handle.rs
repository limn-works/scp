//! `SupervisorHandle` — capability-reduced supervisor surface held by
//! actors via [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Per ADR-049 §5 and plan §"ActorDeps and SupervisorHandle" the handle
//! must **not** expose any method that returns a
//! [`ContextActorHandle`](crate::context::actor::handle::ContextActorHandle).
//! Actors cannot reach sibling actors; cross-context work goes through
//! [`SupervisorHandle::start_saga`]. This is the capability-reduction mechanism:
//! the inner `Arc<Supervisor>` is private and no accessor exposes it.
//!
//! # `&OwnedIdentityDid` parameters
//!
//! Methods that touch per-identity state take `&OwnedIdentityDid`, not
//! `&DID`. [`OwnedIdentityDid`](super::identity_capability::OwnedIdentityDid)
//! is `pub(super)` inside the `supervisor/` module — this file is inside
//! that module so it CAN name the type. Handler code in
//! `actor/handlers/` cannot reach the type's constructor path and
//! therefore cannot call these methods with a fabricated token. See
//! plan §"`OwnedIdentityDid` capability tag".

use std::collections::HashSet;
use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;

use crate::context::supervisor::identity_capability::OwnedIdentityDid;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::context::supervisor::supervisor::{SagaInput, SagaOutput, Supervisor};

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Capability-reduced view of `Supervisor` held by actors. Cloned into
/// each actor's `ActorDeps` and never exposed outside `crate::context::`.
///
/// **No `ContextActorHandle` accessor.** This is the mechanical contract
/// that makes "actors cannot reach sibling actors" a type-system
/// property. The inner `Arc<Supervisor>` field is private; no public
/// method returns it. Cross-context work MUST go through
/// [`Self::start_saga`].
#[derive(Clone)]
pub struct SupervisorHandle {
    supervisor: Arc<Supervisor>,
}

impl SupervisorHandle {
    /// Wrap an `Arc<Supervisor>`. Visible only to supervisor-module
    /// code; the bridge instance constructs one at actor spawn time
    /// (commit 11 wires this through), and handlers receive the handle
    /// via `ActorDeps` at dispatch time.
    ///
    /// `dead_code` allow: commit 6 lands the constructor; the first
    /// production caller lands with the `BridgeInstance` integration
    /// in commit 11. The allow is removed then.
    #[must_use]
    #[allow(dead_code)]
    pub(in crate::context::supervisor) const fn wrap(supervisor: Arc<Supervisor>) -> Self {
        Self { supervisor }
    }

    /// Start a cross-context saga. The ONLY way for an actor to affect
    /// state in another context.
    ///
    /// # Errors
    ///
    /// See `Supervisor::start_saga`. Commit 6: always
    /// [`ContextError::NotImplemented`].
    pub async fn start_saga(&self, input: SagaInput) -> Result<SagaOutput, ContextError> {
        self.supervisor.start_saga(input).await
    }

    /// Snapshot the local-DIDs set. Returned as an `Arc` so callers read
    /// without copying; the snapshot is stable for its lifetime even if
    /// the supervisor rotates the underlying `ArcSwap` mid-read.
    #[must_use]
    pub fn local_dids(&self) -> Arc<HashSet<DID>> {
        self.supervisor.local_dids.load_full()
    }

    /// Find the first context where both `member_a` and `member_b` are
    /// members. Returns `None` if no such context exists.
    ///
    /// Cross-context read used by trust-recovery's `notify_contact`
    /// path (spec §9.12 step 5): the recovering DID's actor must
    /// dispatch a recovery notification through any context shared
    /// with the contact DID. The supervisor performs this enumeration
    /// because no individual actor sees its peers' membership state —
    /// it is the only legal cross-context membership read in the
    /// post-actor-model dispatch.
    ///
    /// # Implementation
    ///
    /// During Phase 2A migration the per-context `Mutex<PerContextState>`
    /// map is the authoritative membership store. Once Phase 2A
    /// finalization deletes the map and replaces it with one
    /// `ContextActor` per context, this method becomes a fan-out over
    /// the actor map asking each actor's mailbox for membership state
    /// (or reads a supervisor-scoped membership index maintained by
    /// the actors). The signature here is stable across that
    /// transition.
    ///
    /// # Lock discipline
    ///
    /// Collects `(key, Arc)` pairs under DashMap's shard locks first,
    /// then drops the shard locks before locking individual per-context
    /// `Mutex`es. Holding a DashMap `Ref` across `.await` would deadlock
    /// any concurrent shard access.
    pub async fn find_shared_context(&self, member_a: &str, member_b: &str) -> Option<String> {
        let entries: Vec<(
            String,
            Arc<tokio::sync::Mutex<crate::context::state::PerContextState>>,
        )> = self
            .supervisor
            .contexts_arc()
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();
        for (context_id, arc) in entries {
            let ctx = arc.lock().await;
            if ctx.membership.contains(member_a) && ctx.membership.contains(member_b) {
                return Some(context_id);
            }
        }
        None
    }

    /// Dispatch a `TrustRecoveryCommand::RecoverySendNotification`
    /// through the supervisor's mailbox routing — used by
    /// trust-recovery's cross-context `notify_contact` path after the
    /// shared context has been found via [`Self::find_shared_context`].
    ///
    /// Routes through
    /// [`Supervisor::dispatch_trust_recovery_command`](crate::context::supervisor::Supervisor::dispatch_trust_recovery_command),
    /// which dispatches via the per-context actor mailbox when one is
    /// registered or falls through to the legacy lock-shaped fallback
    /// otherwise. The reply is awaited inline so the caller observes
    /// the full per-actor outcome.
    ///
    /// # Errors
    ///
    /// - Any [`ContextError`] surfaced through the dispatched
    ///   [`Supervisor::dispatch_trust_recovery_command`](crate::context::supervisor::Supervisor::dispatch_trust_recovery_command)
    ///   call (e.g. [`ContextError::NotInitialized`] if no providers
    ///   attached).
    /// - Any [`ContextError`] surfaced via the per-actor reply on the
    ///   embedded oneshot channel.
    /// - [`ContextError::TransportFailed`] if the reply channel is
    ///   closed before a response arrives (actor panicked or shut down
    ///   between dispatch and reply).
    pub async fn dispatch_recovery_send_notification(
        &self,
        payload: crate::context::actor::commands::RecoverySendNotificationPayload,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::TrustRecoveryCommand;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = TrustRecoveryCommand::RecoverySendNotification {
            payload: Box::new(payload),
            reply: reply_tx,
        };
        self.supervisor.dispatch_trust_recovery_command(cmd).await?;
        reply_rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "dispatch_recovery_send_notification: oneshot reply channel closed".to_owned(),
            )
        })?
    }

    /// Look up the registered standing-context peer DID for `peer_did`.
    /// Returns `None` if the peer has no registered standing context.
    ///
    /// Phase 1 fix-up of ADR-049 (post-review-round-1): the prior
    /// signature took `ctx_id: &str` but the underlying
    /// `standing_contexts: ArcSwap<HashMap<String, DID>>` is keyed by
    /// the peer DID's `to_string()` form (see `standing_helpers.rs`
    /// lines 161/230/291). Querying by context ID always returned
    /// `None`. The renamed parameter matches the actual key shape; the
    /// lookup is now correct.
    #[must_use]
    pub fn standing_peer(&self, peer_did: &DID) -> Option<DID> {
        self.supervisor
            .standing_contexts
            .load()
            .get(peer_did.as_ref())
            .cloned()
    }

    /// Return or create the standing context for `local_did` and `peer_did`.
    ///
    /// Transitional Phase 2A surface for the standing actor handler:
    /// the helper can route through the capability-reduced handle
    /// without receiving `&Supervisor` directly. The implementation
    /// delegates to the legacy lock-shaped helper until standing-pair
    /// creation is decomposed into a saga in Phase 2C.
    pub(crate) async fn standing_context(
        &self,
        local_did: &DID,
        peer_did: &DID,
    ) -> Result<String, ContextError> {
        let expected_context_id =
            crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did);
        let context_id = crate::context::standing_helpers_legacy::standing_context_legacy(
            &self.supervisor,
            local_did,
            peer_did,
        )
        .await?;
        debug_assert_eq!(context_id, expected_context_id);
        Ok(context_id)
    }

    /// Number of supervisor-tracked standing peers.
    #[must_use]
    pub(crate) fn standing_context_count(&self) -> usize {
        self.supervisor.standing_contexts.load().len()
    }

    /// Whether `peer_did` is registered as a standing peer.
    #[must_use]
    pub(crate) fn has_standing_context(&self, peer_did: &DID) -> bool {
        self.supervisor
            .standing_contexts
            .load()
            .contains_key(peer_did.as_ref())
    }

    /// Register `peer_did` in the supervisor standing-context index.
    pub(crate) async fn register_standing_context(&self, peer_did: DID) {
        let _guard = self.supervisor.write_lock.lock().await;
        let snapshot = self.supervisor.standing_contexts.load_full();
        let mut updated: std::collections::HashMap<String, DID> = (*snapshot).clone();
        updated.insert(peer_did.to_string(), peer_did);
        self.supervisor
            .standing_contexts
            .store(std::sync::Arc::new(updated));
    }

    /// Reconnect all standing contexts through the supervisor fallback.
    ///
    /// Transitional Phase 2A surface; the legacy helper still scans the
    /// supervisor context map because standing commands are not keyed to
    /// a single actor until the standing-pair saga lands.
    pub(crate) async fn reconnect_all_standing(&self) -> Result<usize, ContextError> {
        crate::context::standing_helpers_legacy::reconnect_all_standing_legacy(&self.supervisor)
            .await
    }

    /// Look up this identity's wrapping public key. Returns `None` if
    /// the identity has not set a wrapping keypair yet.
    ///
    /// Takes `&OwnedIdentityDid` — not `&DID` — so the caller must hold
    /// the capability proof that they are the actor for this identity.
    /// The token is constructed only in `supervisor/` code
    /// (`pub(super)` constructor); handler code cannot fabricate it.
    ///
    /// Visibility is `pub(in crate::context)` rather than `pub` because
    /// `OwnedIdentityDid` is `pub(super)` inside `supervisor/`.
    /// The narrower visibility scopes call-site reachability to handler
    /// code under `crate::context::actor::handlers/`.
    ///
    /// `private_interfaces` is allowed: the deliberate-by-design
    /// asymmetry (the type is more private than the method) is the
    /// capability discipline. Handlers receive `&OwnedIdentityDid`
    /// references through `ActorDeps`; they cannot construct one
    /// because `OwnedIdentityDid::issue_for_actor` is `pub(super)`
    /// inside `supervisor/`.
    #[must_use]
    #[allow(private_interfaces, dead_code)]
    pub(in crate::context) fn my_wrapping_public_key(
        &self,
        identity: &OwnedIdentityDid,
    ) -> Option<Arc<Vec<u8>>> {
        let did = identity.as_did();
        self.supervisor
            .wrapping_keys
            .get(did)
            .map(|entry| Arc::new(entry.value().load_full().public.to_vec()))
    }

    /// Look up this identity's `KeyPackageStoreActor` handle. Returns
    /// `None` if no KeyPackage actor has been spawned for the identity.
    ///
    /// Same capability discipline as [`Self::my_wrapping_public_key`].
    /// Visibility is `pub(in crate::context)` for the same reason.
    /// `private_interfaces` is allowed for the same deliberate
    /// asymmetry documented there.
    #[must_use]
    #[allow(private_interfaces, dead_code)]
    pub(in crate::context) fn my_key_package_store(
        &self,
        identity: &OwnedIdentityDid,
    ) -> Option<KeyPackageStoreHandle> {
        let did = identity.as_did();
        self.supervisor
            .key_package_stores
            .get(did)
            .map(|r| r.value().clone())
    }

    // -----------------------------------------------------------------
    // Lifecycle bootstrap surface (Phase 2A.9).
    //
    // These methods wrap the supervisor's contexts-map operations
    // through a capability-reduced interface so the actor-shape
    // bootstrap entry points in
    // [`crate::context::lifecycle_helpers`] (`create_context`,
    // `restore_context`, `import_context`) can register fresh
    // `PerContextState` without holding `&Supervisor` directly.
    // -----------------------------------------------------------------

    /// Insert a fresh `PerContextState` into the supervisor's contexts
    /// map. Stamps the generation counter atomically.
    ///
    /// Capability-reduced wrapper around
    /// [`crate::context::manager_methods::insert_context`] so actor
    /// bootstrap helpers do not need to hold `&Supervisor` directly.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`ContextCreationError::CreationFailed`](scp_protocol::context::builder::ContextCreationError::CreationFailed)
    /// if `context_id` is already registered.
    #[allow(private_interfaces)]
    pub(crate) fn insert_context(
        &self,
        context_id: String,
        state: crate::context::state::PerContextState,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        crate::context::manager_methods::insert_context(&self.supervisor, context_id, state)
    }

    /// Initialize a `BroadcastContext` (SCP-227) and persist its
    /// initial state if persistence is configured. Capability-reduced
    /// wrapper around
    /// [`crate::context::manager_methods::init_broadcast_context`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::CreationFailed`](scp_protocol::context::builder::ContextCreationError::CreationFailed)
    /// if the broadcast context construction or initial author
    /// registration fails.
    pub(crate) fn init_broadcast_context(
        &self,
        context_id: &str,
        params: &scp_protocol::context::ContextParams,
        creator_did: &DID,
    ) -> Result<
        Option<scp_protocol::context::broadcast::BroadcastContext>,
        scp_protocol::context::builder::ContextCreationError,
    > {
        crate::context::manager_methods::init_broadcast_context(
            &self.supervisor,
            context_id,
            params,
            creator_did,
        )
    }

    /// Update operational gauges (active contexts, buffer occupancy).
    /// Best-effort: skipped if no metrics recorder is installed.
    pub(crate) fn update_context_gauges(&self) {
        crate::context::manager_methods::update_context_gauges(&self.supervisor);
    }

    /// Persist the per-context state and broadcast snapshot for
    /// `context_id` if persistence is configured. Best-effort —
    /// errors are logged, not propagated.
    pub(crate) async fn persist_context_and_broadcast(&self, context_id: &str) {
        crate::context::manager_methods::persist_context_and_broadcast(
            &self.supervisor,
            context_id,
        )
        .await;
    }

    /// `true` if the supervisor's contexts map currently registers
    /// `context_id`. Used by the import path to distinguish the
    /// no-existing-context branch from the replace-existing branch.
    #[must_use]
    pub(crate) fn has_context(&self, context_id: &str) -> bool {
        self.supervisor.contexts_ref().contains_key(context_id)
    }

    /// Run `f` against the per-context state for an existing context if
    /// one is registered, with the supervisor's write-lock held across
    /// the callback. Used by the import path to perform the
    /// replaceability gate + crypto cleanup atomically — the
    /// write-lock prevents a concurrent caller from inserting an
    /// Active context after the gate.
    ///
    /// If no context is registered for `context_id`, `f` is not
    /// invoked and `Ok(())` is returned.
    ///
    /// # Errors
    ///
    /// Returns whatever error `f` returns. Propagates the per-context
    /// lookup failure mode as `Ok(())` because the no-existing branch
    /// is the legitimate "fresh slot" path the caller must handle on
    /// its own.
    #[allow(private_interfaces)]
    pub(crate) async fn with_existing_context_for_import<F>(
        &self,
        context_id: &str,
        f: F,
    ) -> Result<(), ContextError>
    where
        F: FnOnce(&crate::context::state::PerContextState) -> Result<(), ContextError>,
    {
        let _write_guard = self.supervisor.write_lock.lock().await;
        if let Ok(ctx_arc) =
            crate::context::manager_methods::get_context_arc(&self.supervisor, context_id)
        {
            let guard = ctx_arc.lock().await;
            return f(&guard);
        }
        Ok(())
    }

    /// Replace an existing context in the contexts map atomically
    /// under the supervisor's `write_lock`. Used by the import path's
    /// step 7 to swap in the freshly-built `PerContextState` after
    /// the replaceability gate has already passed.
    ///
    /// If the context does not exist, this is equivalent to a fresh
    /// insert. If it does exist, the existing entry is removed and
    /// replaced — the per-context lock on the prior entry is dropped
    /// inside the swap (the write-lock keeps the remove+insert
    /// atomic with respect to other writers).
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::CreationFailed`](scp_protocol::context::builder::ContextCreationError::CreationFailed)
    /// if the insert fails after the remove (only possible under a
    /// hostile concurrent insert — `write_lock` makes this impossible
    /// in normal operation).
    #[allow(private_interfaces)]
    pub(crate) async fn replace_context(
        &self,
        context_id: String,
        state: crate::context::state::PerContextState,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        let _write_guard = self.supervisor.write_lock.lock().await;
        crate::context::manager_methods::remove_context(&self.supervisor, &context_id);
        crate::context::manager_methods::insert_context(&self.supervisor, context_id, state)
    }

    /// **TRANSITIONAL — shim dispatch period only.** Returns the inner
    /// `Arc<Supervisor>` so the actor's `run()` loop can route commands
    /// through the legacy `dispatch_from_shim` handler entry points
    /// during the Phase 2A → 2I migration window. Removed when handlers
    /// are migrated to the `(&mut PerContextState, &ActorDeps)`
    /// signature in the per-domain rows of Phase 2.
    ///
    /// Visibility is `pub(in crate::context)` so only code within the
    /// `context` module tree (the actor's run loop) can call this.
    /// Handler bodies under `actor/handlers/` MUST NOT call this — they
    /// receive the supervisor via the explicit `&Supervisor` parameter
    /// of their `dispatch_from_shim` entry point.
    #[must_use]
    #[allow(dead_code)]
    pub(in crate::context) fn shim_supervisor(&self) -> Arc<Supervisor> {
        Arc::clone(&self.supervisor)
    }

    /// Spawn a per-context [`ContextActor`](crate::context::actor::ContextActor)
    /// task that owns the supplied
    /// [`PerContextState`](crate::context::actor::state::PerContextState) +
    /// [`ActorDeps`](crate::context::actor::deps::ActorDeps) bundle and
    /// register the resulting handle in the supervisor's actor registry.
    ///
    /// Capability-reduced wrapper around
    /// [`Supervisor::spawn_actor_with_state`](crate::context::supervisor::Supervisor::spawn_actor_with_state).
    /// Phase 2A finalization keystone: lifecycle bootstrap entry points
    /// in [`crate::context::lifecycle_helpers`] (`create_context`,
    /// `restore_context`, `import_context`) call this after building the
    /// actor-shape state so production paths populate
    /// `Supervisor::actors` instead of going through the legacy
    /// contexts-map insert. Subsequent finalization commits delete the
    /// legacy DashMap once every consumer is ported.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — only lifecycle bootstrap callers
    /// (`crate::context::lifecycle_helpers`) reach this. The
    /// `private_interfaces` allow mirrors the discipline used by
    /// [`Self::insert_context`] / [`Self::replace_context`]:
    /// `PerContextState` and `ActorDeps` are `pub(crate)` while the
    /// method itself is reachable from inside the `context` module
    /// tree.
    #[allow(private_interfaces, dead_code)]
    pub(in crate::context) async fn spawn_actor_with_state(
        &self,
        state: crate::context::actor::state::PerContextState,
        deps: crate::context::actor::deps::ActorDeps,
        mailbox_capacity: Option<usize>,
    ) -> crate::context::actor::handle::ContextActorHandle {
        self.supervisor
            .spawn_actor_with_state(state, deps, mailbox_capacity)
            .await
    }

    /// Despawn the actor registered for `context_id`, removing the
    /// entry from `Supervisor::actors` under the supervisor's
    /// `write_lock` so concurrent registrations cannot race.
    ///
    /// Used by [`crate::context::lifecycle_helpers::import_context`] —
    /// import overwrites an existing context, so the prior actor's
    /// mailbox is shut down before the fresh actor is spawned. The
    /// handle's [`Drop`](crate::context::actor::handle::ContextActorHandle)
    /// closes the underlying `mpsc::Sender`, which causes the actor
    /// task's `run()` loop to exit on the next inbox-empty poll.
    ///
    /// Returns `true` if a handle was registered and removed,
    /// `false` if no entry existed for `context_id`.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — the import-bootstrap path is the
    /// only caller. Removed when the actor map is the sole context
    /// registry and `Supervisor::contexts` is deleted.
    #[allow(dead_code)]
    pub(in crate::context) async fn despawn_actor(&self, context_id: &str) -> bool {
        self.supervisor.despawn_actor(context_id).await
    }
}

// Explicit non-exposure check: ensure no public method returns
// `ContextActorHandle` or `Arc<Supervisor>`. This is enforced by the
// methods above (none do), but the file-level contract is documented
// here so future edits see the rule.
//
// Any method added to this impl that returns `ContextActorHandle`,
// `Arc<Supervisor>`, `&Supervisor`, or `&mut Supervisor` breaks the
// capability-reduction contract. Plan §"Mechanical enforcement" adds a
// CI grep-ban against those return types in this file in commit 12.

// ---------------------------------------------------------------------------
// Forbidden trait impls — compile-time checklist
// ---------------------------------------------------------------------------

// Do NOT impl:
// - `Deref<Target = Supervisor>` — would leak `&Supervisor` via auto-deref.
// - `AsRef<Supervisor>` — would leak `&Supervisor`.
// - `From<SupervisorHandle> for Arc<Supervisor>` — would smuggle the
//   Arc out past the capability boundary.
//
// These are documentation, not static assertions — Rust has no
// "forbid impl of trait X" attribute. The CI grep-ban landing in
// commit 12 is the mechanical enforcement.

// Compile-time witness that `SupervisorHandle` is `Send + Sync` — the
// handle rides inside `ActorDeps`, which is moved into `tokio::spawn`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SupervisorHandle>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::actor::state::WrappingKeyPair;
    use crate::context::supervisor::key_package_actor::KeyPackageStoreActor;
    use crate::context::supervisor::saga_journal::{ProtocolRepositorySagaJournal, SagaJournal};
    use crate::context::supervisor::supervisor::SupervisorConfig;
    use arc_swap::ArcSwap;
    use scp_platform::testing::InMemoryStorage;
    use zeroize::Zeroizing;

    struct TestPersistence;
    impl crate::context::persistence::ContextPersistence for TestPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn persist_broadcast(
            &self,
            _: &str,
            _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _: &str,
        ) -> Result<
            Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    fn test_handle() -> (Arc<Supervisor>, SupervisorHandle) {
        let persistence: Arc<dyn crate::context::persistence::ContextPersistence> =
            Arc::new(TestPersistence);
        let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
            InMemoryStorage::new(),
        )));
        let sup = Arc::new(Supervisor::new(
            persistence,
            journal,
            SupervisorConfig::default(),
        ));
        let handle = SupervisorHandle::wrap(Arc::clone(&sup));
        (sup, handle)
    }

    #[tokio::test]
    async fn local_dids_returns_empty_snapshot_on_fresh_supervisor() {
        let (_sup, handle) = test_handle();
        assert!(handle.local_dids().is_empty());
    }

    #[tokio::test]
    async fn standing_peer_returns_none_when_unknown() {
        let (_sup, handle) = test_handle();
        let unknown = DID("did:example:never-registered".to_owned());
        assert!(handle.standing_peer(&unknown).is_none());
    }

    #[tokio::test]
    async fn start_saga_propagates_not_implemented() {
        let (_sup, handle) = test_handle();
        let err = handle
            .start_saga(SagaInput::StandingPairCreate {
                local_did: DID("did:example:a".to_owned()),
                peer_did: DID("did:example:b".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn my_wrapping_public_key_returns_none_when_unset() {
        let (_sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let token = OwnedIdentityDid::issue_for_actor(did);
        assert!(handle.my_wrapping_public_key(&token).is_none());
    }

    #[tokio::test]
    async fn my_wrapping_public_key_reads_registered_value() {
        let (sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let kp = WrappingKeyPair {
            public: [0x42; 32],
            secret: Zeroizing::new([0u8; 32]),
        };
        sup.wrapping_keys
            .insert(did.clone(), ArcSwap::new(Arc::new(kp)));
        let token = OwnedIdentityDid::issue_for_actor(did);
        let got = handle.my_wrapping_public_key(&token).unwrap();
        assert_eq!(&*got, &vec![0x42u8; 32]);
    }

    #[tokio::test]
    async fn my_key_package_store_returns_none_when_unset() {
        let (_sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let token = OwnedIdentityDid::issue_for_actor(did);
        assert!(handle.my_key_package_store(&token).is_none());
    }

    #[tokio::test]
    async fn my_key_package_store_returns_registered_handle() {
        let (sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let kp_handle = KeyPackageStoreActor::spawn(did.clone());
        sup.key_package_stores.insert(did.clone(), kp_handle);
        let token = OwnedIdentityDid::issue_for_actor(did);
        let got = handle.my_key_package_store(&token);
        assert!(got.is_some());
        if let Some(h) = got {
            h.send_shutdown().await.unwrap();
        }
    }

    #[test]
    fn handle_is_clone_send_sync() {
        const fn assert_send_sync<T: Send + Sync + Clone>() {}
        assert_send_sync::<SupervisorHandle>();
    }
}
