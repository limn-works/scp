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
//! is `pub(in crate::context)` — the SAME name-visibility as these
//! methods — so naming the type is not what gates these calls. The mint
//! guarantee rides on two narrower mechanisms: the `pub(super)`
//! constructor `issue_for_actor` (only supervisor-module code can mint a
//! token from a raw `DID`) and the private `did` field (no struct-literal
//! construction outside `identity_capability`). Handlers in
//! `actor/handlers/` receive `&OwnedIdentityDid` references through
//! [`ActorDeps`](crate::context::actor::deps::ActorDeps) and can call
//! these methods, but they cannot CONSTRUCT a token — so they cannot
//! fabricate one for an identity they do not own. See ADR-049 §5
//! (`OwnedIdentityDid`: unforgeable by constructor visibility + private
//! field).

use std::collections::HashSet;
use std::sync::Arc;

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ReceiveFloor;
use scp_protocol::crypto::sender_keys::MergePolicy;

use crate::context::supervisor::floors::FloorAdvanceError;
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
    // AXIS: actor-internal (ADR-049 §5 placement invariant). Every
    // PER-IDENTITY method on this handle takes `&OwnedIdentityDid`, never a
    // bare `&DID` — an actor reaches only the identity that owns it, even for
    // PUBLIC reads (`my_wrapping_public_key` returns public data yet is
    // token-gated, because the discriminator is caller-isolation, not
    // data-sensitivity). A per-identity op callable by the FFI/bridge
    // orchestrator does NOT belong here: add a bare-`DID` `pub fn` on
    // `Supervisor` instead (see `Supervisor::create_context`). The
    // non-per-identity methods below (registry fan-out, saga dispatch,
    // lifecycle bootstrap) are unaffected by this rule.

    /// Wrap an `Arc<Supervisor>`. Visible only to supervisor-module
    /// code; the supervisor constructs one in
    /// [`Supervisor::build_actor_deps`](crate::context::supervisor::Supervisor)
    /// at actor-spawn time, and handlers receive the handle via
    /// `ActorDeps` at dispatch time.
    #[must_use]
    pub(in crate::context::supervisor) const fn wrap(supervisor: Arc<Supervisor>) -> Self {
        Self { supervisor }
    }

    // -----------------------------------------------------------------------
    // ADR-049 (read-authority switch) — supervisor-owned floor registry fan-out.
    //
    // These accessors are PER-CONTEXT (they take `&[u8; 32]`, NOT
    // `&OwnedIdentityDid` and NOT `&DID`): they are registry fan-out, which the
    // AXIS comment above explicitly exempts from the per-identity token rule.
    // They forward to the same-named `Supervisor` primitives on
    // `Supervisor.floors`. NONE returns (or exposes) a `ContextActorHandle`, so
    // Invariant 3 (actors cannot reach sibling actors) is preserved.
    //
    // Single-writer / security separation (inquisitor-sharpened, verbatim — it
    // SEPARATES structural security from liveness): SECURITY — "never accept a
    // key below the floor" — is STRUCTURAL and caller-topology-independent: the
    // single-`entry()`-guard body (atomic read → reject-`<=` → reject-overshoot
    // → write, all under one guard) plus the fail-safe gate-then-key-insert
    // ordering make key-below-floor impossible no matter who calls. The
    // per-context single-writer actor (`ContextActor::run()` serializes
    // gate-then-insert) preserves only LIVENESS (avoids spurious rejects). If
    // `check_and_advance` were ever called for a LIVE context from OUTSIDE its
    // owning actor, the gate→insert window would open but stays FAIL-SAFE — it
    // degrades liveness (a spurious reject / retry), NEVER fail-open. Do NOT
    // read this as "security depends on single-writer"; security is the
    // structural gate, single-writer is a liveness convention. PR-6 made the
    // call: NO separate structural guard is warranted — the single-`entry()`
    // gate + fail-safe ordering is sufficient now that the gate RESULT is
    // security-enforced (fail-closed at the seams); co-locating the gate with the
    // key insert is deferred to PR-7's key-move, which co-serializes it for free.

    /// Advance a per-sender epoch floor in the authoritative registry, FAIL-CLOSED.
    /// See [`Supervisor::check_and_advance_sender_epoch`].
    ///
    /// # Errors
    ///
    /// Propagates [`FloorAdvanceError`] on a non-monotonic or overshooting epoch;
    /// the live receive seams surface it via `?` and abort the operation (it is
    /// NEVER log-and-dropped).
    pub(in crate::context) fn check_and_advance_sender_epoch(
        &self,
        ctx: &[u8; 32],
        did: &str,
        epoch: u64,
        max_advance: u64,
    ) -> Result<(), FloorAdvanceError> {
        self.supervisor
            .check_and_advance_sender_epoch(ctx, did, epoch, max_advance)
    }

    /// Advance a per-sender receive-sequence floor in the authoritative registry,
    /// FAIL-CLOSED. See [`Supervisor::check_and_advance_recv_sequence`].
    ///
    /// # Errors
    ///
    /// Propagates [`FloorAdvanceError`] on a non-monotonic or overshooting
    /// `(epoch, sequence)`; the recv seam surfaces it via `?` (never dropped).
    pub(in crate::context) fn check_and_advance_recv_sequence(
        &self,
        ctx: &[u8; 32],
        did: &str,
        next: ReceiveFloor,
        max_advance: u64,
    ) -> Result<(), FloorAdvanceError> {
        self.supervisor
            .check_and_advance_recv_sequence(ctx, did, next, max_advance)
    }

    /// Read the registry's per-sender epoch floors for `ctx`. See
    /// [`Supervisor::export_sender_key_epochs`].
    ///
    /// ADR-049 PR-6: the authoritative durable-blob export source (the 6
    /// production `export_crypto_state` callers).
    #[must_use]
    pub(in crate::context) fn export_sender_key_epochs(
        &self,
        ctx: &[u8; 32],
    ) -> Vec<(String, u64)> {
        self.supervisor.export_sender_key_epochs(ctx)
    }

    /// Read the registry's per-sender receive-sequence floors for `ctx`. See
    /// [`Supervisor::export_recv_sequence_floors`].
    ///
    /// ADR-049 PR-6: the authoritative durable-blob export source (the 6
    /// production `export_crypto_state` callers).
    #[must_use]
    pub(in crate::context) fn export_recv_sequence_floors(
        &self,
        ctx: &[u8; 32],
    ) -> Vec<(String, ReceiveFloor)> {
        self.supervisor.export_recv_sequence_floors(ctx)
    }

    /// Atomically merge BOTH the per-sender epoch floors AND the receive-sequence
    /// floors into the registry under one guard (the restore/import sink). See
    /// [`Supervisor::validate_and_merge_all_floors`].
    ///
    /// # Errors
    ///
    /// Propagates [`FloorAdvanceError`] on an Inv-3 regression
    /// ([`MergePolicy::RejectRegression`]) or an overshoot (RejectRegression only).
    pub(in crate::context) fn validate_and_merge_all_floors(
        &self,
        ctx: &[u8; 32],
        epochs: Vec<(String, u64)>,
        recv: Vec<(String, ReceiveFloor)>,
        max_advance: u64,
        policy: MergePolicy,
    ) -> Result<(), FloorAdvanceError> {
        self.supervisor
            .validate_and_merge_all_floors(ctx, epochs, recv, max_advance, policy)
    }

    /// Create-seed the floor registry for `ctx` (insert-if-absent). See
    /// [`Supervisor::seed_context_floors`].
    pub(in crate::context) fn seed_context_floors(&self, ctx: &[u8; 32]) {
        self.supervisor.seed_context_floors(ctx);
    }

    /// Permanent-teardown prune of the floor registry entry for `ctx`. See
    /// [`Supervisor::remove_context_floors`] — including the permanent-vs-
    /// transient safety argument. Callers (the terminal close / TTL-expiry /
    /// shutdown paths) invoke this only when the context is permanently gone.
    pub(in crate::context) fn remove_context_floors(&self, ctx: &[u8; 32]) {
        self.supervisor.remove_context_floors(ctx);
    }

    /// Member-granular floor prune of `did` from `ctx`'s registry entry. See
    /// [`Supervisor::remove_member_floors`] — the member-granular twin of
    /// `remove_context_floors` (keeps siblings + the local scalar; drops only the
    /// departed member's floors under one guard). ADR-049 PR-6: called from every
    /// member-removal seam.
    pub(in crate::context) fn remove_member_floors(&self, ctx: &[u8; 32], did: &str) {
        self.supervisor.remove_member_floors(ctx, did);
    }

    /// Permanent-teardown drop of the per-context outlet-stream admission
    /// registry entry for `context_id` (spec §5.4.5) — the streaming twin of
    /// [`Self::remove_context_floors`]. See
    /// [`Supervisor::reap_stream_admission`] for the live-Arc safety
    /// argument. Callers (the terminal close / TTL-expiry paths) invoke this
    /// only when the context is permanently gone.
    pub(in crate::context) fn reap_stream_admission(&self, context_id: &str) {
        self.supervisor.reap_stream_admission(context_id);
    }

    /// Start a cross-context saga. The ONLY way for an actor to affect
    /// state in another context.
    ///
    /// # Errors
    ///
    /// Errors propagate from `Supervisor::start_saga` — the saga
    /// terminal/abort mapping.
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
    /// Fan-out over the actor registry: [`Supervisor::actor_ids`] yields
    /// a lock-free snapshot of every registered context id, and for each
    /// id the membership predicate is read through the per-context actor
    /// mailbox via [`Supervisor::is_member`]. The first context where
    /// BOTH members are present wins; `None` if none qualifies. No
    /// `per-context-state Mutex` lock and no `contexts` DashMap access —
    /// the actor that owns each context is the sole authority for its
    /// membership.
    ///
    /// # Ordering
    ///
    /// `actor_ids()` rebuilds its snapshot per call, so the iteration
    /// order is the registry's shard order — unspecified but stable for
    /// the duration of a single call. The legacy DashMap iteration was
    /// likewise order-unspecified, so "first shared context" carries the
    /// same (non-deterministic across registry mutations) semantics it
    /// always did.
    pub async fn find_shared_context(&self, member_a: &str, member_b: &str) -> Option<String> {
        for context_id in self.supervisor.actor_ids() {
            if self.supervisor.is_member(&context_id, member_a).await
                && self.supervisor.is_member(&context_id, member_b).await
            {
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

    /// Read-only lifecycle-state probe for `context_id`. Returns `None`
    /// if no per-context actor is registered (close / TTL does not
    /// despawn the actor, so `Some(state)` reflects the live lifecycle
    /// state — `Active` / `Creating` vs a terminal state — and `None`
    /// means the actor genuinely does not exist).
    ///
    /// Capability-reduced surface over
    /// [`Supervisor::read_context_state`](crate::context::supervisor::supervisor::Supervisor::read_context_state):
    /// handler / standing-domain code can probe lifecycle state without
    /// receiving `&Supervisor` directly.
    // First in-tree caller is the actor-native standing get-or-create
    // rewrite in the immediately-following commit; `Supervisor::read_context_state`
    // (the body this wraps) is already exercised by the supervisor's
    // `pub` surface and the bridge passthroughs.
    #[allow(dead_code)]
    pub(crate) async fn read_context_state(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::ContextState> {
        self.supervisor.read_context_state(context_id).await
    }

    // No `SupervisorHandle::standing_context` get-or-create wrapper: that
    // operation is supervisor-scoped (it may CREATE the target per-context
    // actor) and is dispatched supervisor-direct through
    // [`Supervisor::dispatch_standing_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_standing_command)
    // → `Supervisor::standing_context`. Exposing it on the
    // capability-reduced handle (reachable from the per-context actor's
    // `run()` loop) would invite the non-`Send` actor-spawns-actor
    // recursion the routing in `Supervisor::standing_command_context_id`
    // explicitly avoids.

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

    /// Reconnect all standing contexts.
    ///
    /// Capability-reduced surface over the actor-native
    /// [`Supervisor::reconnect_all_standing`](crate::context::supervisor::supervisor::Supervisor::reconnect_all_standing),
    /// which resolves per-context lifecycle + params through the actor
    /// registry + mailbox (no `contexts` DashMap, no
    /// `per-context-state Mutex`).
    pub(crate) async fn reconnect_all_standing(&self) -> Result<usize, ContextError> {
        self.supervisor.reconnect_all_standing().await
    }

    /// Look up this identity's wrapping public key. Returns `None` if
    /// the identity has not set a wrapping keypair yet.
    ///
    /// Takes `&OwnedIdentityDid` — not `&DID` — so the caller must hold
    /// the capability proof that they are the actor for this identity.
    /// The token is minted only in `supervisor/` code (the `pub(super)`
    /// `issue_for_actor` constructor) and its `did` field is private;
    /// handler code can hold and pass a token but cannot fabricate one.
    ///
    /// Visibility is `pub(in crate::context)` — the SAME visibility as
    /// `OwnedIdentityDid` itself. The token-by-value lives in
    /// `ActorDeps`; this method is reachable from handler code under
    /// `crate::context::actor::handlers/` that holds an `&OwnedIdentityDid`
    /// borrow. Because the type and the method share visibility, there is
    /// no `private_interfaces` asymmetry to allow — the mint guarantee is
    /// carried entirely by the `pub(super)` constructor and the private
    /// field, not by any visibility gap here.
    #[must_use]
    #[allow(dead_code)]
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
    /// Same capability discipline as [`Self::my_wrapping_public_key`]:
    /// `&OwnedIdentityDid` proves ownership, the token cannot be minted
    /// outside `supervisor/`, and the method shares the type's
    /// `pub(in crate::context)` visibility — so no `private_interfaces`
    /// asymmetry exists to allow.
    #[must_use]
    #[allow(dead_code)]
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
    // Lifecycle bootstrap surface (Phase 2A.9 / ADR-049 finalization).
    //
    // These methods wrap the supervisor's registry operations through a
    // capability-reduced interface so the actor-shape bootstrap entry
    // points in [`crate::context::lifecycle_helpers`] can register fresh
    // `PerContextState` without holding `&Supervisor` directly. All three
    // bootstrap paths (`create` / `restore` / `import`) register through
    // [`Self::spawn_actor_with_state`] (owned-state spawn). Import's
    // replaceability gate runs inside the existing actor via
    // [`Self::dispatch_prepare_for_replace`].
    // -----------------------------------------------------------------

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
    ///
    /// Async because the gauge sweep mailboxes each per-context actor for
    /// its receive-buffer length (ADR-049 Phase 2A finalization — DashMap
    /// removal).
    pub(crate) async fn update_context_gauges(&self) {
        crate::context::manager_methods::update_context_gauges(&self.supervisor).await;
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
    /// `Supervisor::actors`, the sole context registry; there is no
    /// legacy contexts-map.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — only lifecycle bootstrap callers
    /// (`crate::context::lifecycle_helpers`) reach this. The
    /// `private_interfaces` allow mirrors the discipline used by the other
    /// owned-state `pub(in crate::context)` registry methods on this handle:
    /// `PerContextState` and `ActorDeps` are `pub(crate)` while the
    /// method itself is reachable from inside the `context` module
    /// tree.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError::CreationFailed`] when an actor is
    /// already registered for this context id (first-writer-wins).
    #[allow(private_interfaces)]
    pub(in crate::context) async fn spawn_actor_with_state(
        &self,
        state: crate::context::actor::state::PerContextState,
        deps: crate::context::actor::deps::ActorDeps,
        mailbox_capacity: Option<usize>,
    ) -> Result<crate::context::actor::handle::ContextActorHandle, ContextError> {
        self.supervisor
            .spawn_actor_with_state(state, deps, mailbox_capacity)
            .await
    }

    // NOTE (ADR-049 Phase 2J): the spawn-from-Welcome joiner seam is NOT a
    // `SupervisorHandle` method. `Supervisor::reserve_key_package` and
    // `Supervisor::spawn_actor_from_welcome` are bridge-initiated node-level
    // bootstraps (the app receives a Welcome, or pre-publishes KeyPackages), so
    // they live as genuinely-`pub` `Supervisor` entrypoints taking a bare `DID`
    // — the same shape as `Supervisor::create_context`, with local-identity
    // custody enforced at the FFI bridge layer. They are deliberately NOT gated
    // on `&OwnedIdentityDid`: that token is the actor-internal per-identity-
    // secret axis (ADR-049 Decision 5), and neither op returns identity-private
    // crypto — `reserve_key_package` yields only a `ReservationId` + PUBLIC
    // KeyPackage bytes, and `spawn_actor_from_welcome` yields a `ContextHandle`
    // (context state), so §5's "no `&DID` method returning identity state" rule
    // is not triggered.

    /// Dispatch [`LifecycleControlCommand::PrepareForReplace`](crate::context::actor::commands::LifecycleControlCommand::PrepareForReplace) to the
    /// actor currently registered for `context_id`, awaiting its verdict.
    ///
    /// This is the actor-native replacement gate for
    /// [`crate::context::lifecycle_helpers::import_context`]: the existing
    /// actor, running on its own owned state, checks replaceability and
    /// performs the crypto teardown + epoch-floor validate/merge, then
    /// claims itself terminal and exits. Capability-reduced wrapper —
    /// import never holds the raw `ContextActorHandle`.
    ///
    /// # Errors
    ///
    /// - `Err(MembershipFailed)` if the context is live (not replaceable)
    ///   or already claimed by a concurrent replace.
    /// - `Err(PersistenceFailed)` / crypto error from the floor merge.
    /// - `Err(ContextNotRegistered)` if no actor is registered, or the
    ///   mailbox send / reply failed (a stale handle whose actor already
    ///   exited) — the caller re-checks `lookup` and falls back to the
    ///   fresh-import path.
    pub(in crate::context) async fn dispatch_prepare_for_replace(
        &self,
        context_id: &str,
        mls_state: Vec<u8>,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::{ContextCommand, LifecycleControlCommand};

        let Some(actor) = self.supervisor.lookup(context_id) else {
            return Err(ContextError::ContextNotRegistered(context_id.to_owned()));
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
            mls_state,
            reply: reply_tx,
        });
        if actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
            .is_err()
        {
            // Stale handle: the actor exited (e.g. a prior replace) before
            // we could send. Signal the caller to re-`lookup`.
            return Err(ContextError::ContextNotRegistered(context_id.to_owned()));
        }
        // The actor dropped the reply sender mid-flight (it exited
        // without answering) → treat as a stale handle; otherwise return
        // the handler's verdict.
        reply_rx
            .await
            .unwrap_or_else(|_| Err(ContextError::ContextNotRegistered(context_id.to_owned())))
    }

    /// Despawn the actor registered for `context_id`, removing the
    /// entry from `Supervisor::actors` under the supervisor's
    /// `write_lock` so concurrent registrations cannot race.
    ///
    /// Two callers:
    /// - `import_context` — import overwrites an existing context, so the
    ///   prior actor's mailbox is shut down before the fresh actor is
    ///   spawned.
    /// - `ContextActor::run()` on a terminal TTL self-expiry — the actor
    ///   despawns its OWN registry handle (`&self.context_id`) before
    ///   breaking the run loop, so the dead-but-registered handle does not
    ///   linger (the watchdog deliberately leaves clean `Ok(())` exits
    ///   registered to avoid racing PrepareForReplace; ADR-049 finding A3).
    ///
    /// Removing the entry drops the registered
    /// [`ContextActorHandle`](crate::context::actor::handle::ContextActorHandle),
    /// whose `Drop` closes the `mpsc::Sender`, so the actor task's `run()`
    /// loop exits on the next inbox-empty poll (a no-op when the caller is
    /// the exiting actor itself).
    ///
    /// Returns `true` if a handle was registered and removed,
    /// `false` if no entry existed for `context_id`.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — reachable by lifecycle bootstrap and by
    /// the actor's own run loop, not by handler bodies under
    /// `actor/handlers/`.
    pub(in crate::context) async fn despawn_actor(&self, context_id: &str) -> bool {
        self.supervisor.despawn_actor(context_id).await
    }

    /// Whether the context is poisoned (ADR-049 §10) — its actor exceeded
    /// the respawn budget and is no longer being respawned. Lock-free read.
    #[must_use]
    pub fn is_context_poisoned(&self, context_id: &str) -> bool {
        self.supervisor.is_context_poisoned(context_id)
    }

    /// Operator recovery action (ADR-049 §10): clear a poisoned context's
    /// crash window and attempt ONE respawn from the persisted snapshot.
    ///
    /// This is the explicit, operator-driven recovery path for a poisoned
    /// context. It is deliberately surfaced on the `SupervisorHandle` (the
    /// operator-facing capability) rather than on any per-context dispatch
    /// path, so ordinary context callers cannot un-poison a context — only
    /// an operator action (or a process restart that re-runs
    /// [`crate::context::lifecycle_helpers::restore_all_contexts`]) can.
    ///
    /// `owning_did` scopes the rebuilt [`ActorDeps`](crate::context::actor::deps::ActorDeps);
    /// callers pass the local DID performing the recovery.
    ///
    /// # Errors
    ///
    /// Surfaces any error from the respawn (e.g.
    /// [`ContextError::ActorCrashed`](scp_protocol::context::ContextError::ActorCrashed)
    /// when no snapshot exists to rehydrate).
    pub async fn clear_poison(
        &self,
        context_id: &str,
        owning_did: &DID,
    ) -> Result<(), ContextError> {
        self.supervisor.clear_poison(context_id, owning_did).await
    }

    /// Operator recovery action (ADR-049 §10) for a poisoned per-identity
    /// `KeyPackageStoreActor`: clear its `kp::{did}` crash window and
    /// re-resolve the actor, which reconciles its pool from the durable
    /// `mls_storage` journal on spawn.
    ///
    /// This is the KeyPackage-actor twin of [`Self::clear_poison`]. It is a
    /// SEPARATE surface because a KP actor has no context-snapshot to
    /// rehydrate — routing it through the per-context snapshot respawn would
    /// fail and re-dirty the crash window. Surfaced on the operator-facing
    /// `SupervisorHandle` so ordinary callers cannot un-poison a KP actor.
    ///
    /// # Errors
    ///
    /// Surfaces any error from the re-resolve (e.g.
    /// [`ContextError::NotInitialized`](scp_protocol::context::ContextError::NotInitialized)
    /// when providers are absent).
    pub async fn clear_kp_poison(&self, identity: &DID) -> Result<(), ContextError> {
        self.supervisor.clear_kp_poison(identity).await
    }

    // -----------------------------------------------------------------
    // Actor-resolution surface.
    //
    // `lookup` resolves a `context_id` to the owning `ContextActorHandle`
    // through the lock-free `actors` registry. It is used by the
    // supervisor-side dispatch routing (`dispatch_*_command`) and the
    // bootstrap TTL-arm dispatch (`dispatch_start_ttl_timer`). It is NOT a
    // timer surface: TTL + governance timers are ACTOR-OWNED arms
    // reconciled inside `ContextActor::run()` (ADR-049 Decision-1 /
    // finding A3), so no detached timer task resolves actors this way.
    //
    // `lookup` is the ONE place a `SupervisorHandle` yields a
    // `ContextActorHandle`. It does NOT breach the "actors cannot reach
    // sibling actors" contract: the callers are supervisor-side dispatch
    // and bootstrap helpers, not a handler running inside another actor's
    // dispatch turn. Visibility is `pub(in crate::context)` so only
    // `crate::context` infra can reach it — handler bodies under
    // `actor/handlers/` are `pub`-only consumers of the handle and cannot
    // name this method.
    // -----------------------------------------------------------------

    /// Resolve the actor handle for `context_id` through the lock-free
    /// `Supervisor::actors` registry. Returns `None` if no actor is
    /// registered (context gone / not yet spawned).
    ///
    /// See the actor-resolution surface comment above for why this is the
    /// single sanctioned `ContextActorHandle` yield.
    #[must_use]
    pub(in crate::context) fn lookup(
        &self,
        context_id: &str,
    ) -> Option<crate::context::actor::handle::ContextActorHandle> {
        self.supervisor.lookup(context_id)
    }

    /// Install the per-context TTL timer for `context_id` by mailboxing
    /// [`TtlCloseCommand::StartTtlTimer`](crate::context::actor::commands::TtlCloseCommand::StartTtlTimer)
    /// to the owning actor. The actor handler runs the actor-shape
    /// `start_ttl_timer` on its owned `&mut state`, so the timer task and
    /// its `state.ttl.timer` bookkeeping are installed by the actor that
    /// owns the state — no `&Supervisor` / DashMap reach.
    ///
    /// Used by the lifecycle bootstrap paths (`finalize_create`,
    /// `restore_context`, `import_context`) which run AFTER actor spawn
    /// and hold only `&ActorDeps` (no `&mut state`). They delegate timer
    /// installation to the actor through this mailbox dispatch.
    ///
    /// Best-effort: a `lookup → None` (actor not yet registered) or a
    /// mailbox-send failure is logged and skipped — arming the TTL deadline
    /// is a background facility, not part of the create/restore success
    /// contract. (The actor's own `reconcile_timers` arms the one-shot TTL
    /// sleep from the recorded `deadline_unix_secs`; ADR-049 finding A3.)
    pub(in crate::context) async fn dispatch_start_ttl_timer(
        &self,
        context_id: &str,
        params: scp_protocol::context::params::ContextParams,
        // The ABSOLUTE convergent expiry deadline to record, as a
        // [`ConvergentDeadline`](crate::context::ttl_close_helpers::ConvergentDeadline)
        // — the arming-seam newtype that can only be minted from the single
        // authoritative source (B1). `None` (initial-create / spawn-from-Welcome)
        // lets the actor handler derive the convergent create base
        // `creation_timestamp_secs + params.ttl`. The restore/import paths pass
        // `Some` — the deadline `convergent_ttl_deadline` derived from the event
        // log — so a prior extension survives and a `None`-remaining Active
        // snapshot still re-arms (D1/D2). See `TtlTimerPayload::deadline_override`.
        deadline_override: Option<crate::context::ttl_close_helpers::ConvergentDeadline>,
    ) {
        use crate::context::actor::commands::{ContextCommand, TtlCloseCommand, TtlTimerPayload};

        let Some(actor) = self.supervisor.lookup(context_id) else {
            tracing::warn!(
                context_id,
                "dispatch_start_ttl_timer: no actor registered — TTL timer not installed"
            );
            return;
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::TtlClose(TtlCloseCommand::StartTtlTimer {
            payload: Box::new(TtlTimerPayload {
                context_id: context_id.to_owned(),
                params,
                // Vestigial for `StartTtlTimer` — only `ResetTtlTimer` reads
                // `duration` (as the extension amount). The absolute deadline is
                // carried by `deadline_override`.
                duration: std::time::Duration::ZERO,
                deadline_override,
            }),
            reply: reply_tx,
        });
        if actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
            .is_err()
        {
            tracing::warn!(
                context_id,
                "dispatch_start_ttl_timer: mailbox send failed — TTL timer not installed"
            );
            return;
        }
        // Await the install reply so the timer is registered before the
        // bootstrap path returns control to the caller.
        if let Ok(Err(e)) = reply_rx.await {
            tracing::warn!(
                context_id,
                error = %e,
                "dispatch_start_ttl_timer: actor reported TTL timer install failure"
            );
        }
    }

    /// Fix-D — dispatch the restore-time streaming crash-recovery sweep to a
    /// freshly-respawned actor, delegating to
    /// [`Supervisor::reconcile_stream_reservations_via_actor`](crate::context::supervisor::Supervisor::reconcile_stream_reservations_via_actor).
    ///
    /// # Errors
    ///
    /// Propagates the dispatch / reply-channel [`ContextError`] from the inner
    /// supervisor (callers on the restore path treat it best-effort).
    pub(in crate::context) async fn reconcile_stream_reservations_via_actor(
        &self,
        context_id: &str,
    ) -> Result<usize, scp_protocol::context::ContextError> {
        self.supervisor
            .reconcile_stream_reservations_via_actor(context_id)
            .await
    }
}

// Explicit non-exposure check: ensure no public method returns
// `ContextActorHandle` or `Arc<Supervisor>`. This is enforced by the
// methods above (none do), but the file-level contract is documented
// here so future edits see the rule.
//
// Any method added to this impl that returns `ContextActorHandle`,
// `Arc<Supervisor>`, `&Supervisor`, or `&mut Supervisor` breaks the
// capability-reduction contract. The contract is maintained by this
// documented rule plus review — there is no CI grep-ban for it.

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
// "forbid impl of trait X" attribute. The rule is upheld by review,
// not a CI grep-ban.

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
    use scp_platform::in_memory::InMemoryStorage;
    use zeroize::Zeroizing;

    struct TestPersistence;
    #[async_trait::async_trait]
    impl crate::context::persistence::ContextPersistence for TestPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
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
        use crate::context::supervisor::key_package_actor::KeyPackageStoreDeps;
        use crate::crypto::mls::provider::MlsCryptoProvider;
        use crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter;

        let (sup, handle) = test_handle();
        let did = DID("did:dht:z6MkAliceKpStore".to_owned());
        let crypto = Arc::new(MlsCryptoProvider::new(
            did.0.clone(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
                InMemoryStorage::new(),
            )));
        let transport: Arc<dyn crate::context::builder::ContextTransportProvider> =
            Arc::new(crate::context::builder::NotConfiguredTransportProvider);
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::SystemClock);
        let deps = KeyPackageStoreDeps {
            mls: Arc::clone(crypto.mls_backend()),
            mls_storage,
            transport,
            clock,
            wrapping_pubkey: None,
        };
        let (kp_handle, _join) = KeyPackageStoreActor::spawn(did.clone(), deps);
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
