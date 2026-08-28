//! The node's self-DID republish cycle (SCP-RELAYRES-004,
//! §3.10.2/§3.10.5/§3.10.6 of the identity spec).
//!
//! # Why this lives on the node rather than on one caller
//!
//! ADR-003 §2 of `.docs/adrs/phase-1.md` states that republishing "starts when
//! an identity is loaded". A node loads an identity in
//! [`Node::start`](crate::Node::start), so the cycle starts there — in
//! [`build_domain_inner`](crate::build_domain_inner) and
//! [`build_no_domain_inner`](crate::build_no_domain_inner), the two builders
//! every `Node::start` path funnels through. It used to start in
//! `self_host::serve_hosted_site` instead, so a node that the self-hosting
//! serve loop did not wrap published its DID document once and never refreshed
//! it. The shipped surface that reached: `start_node_in_memory` and
//! `start_node_local` in `scp-ffi-common`, the FFI bridges' two node front
//! doors, both of which call `Node::start`. Mainline DHT nodes expire a BEP44
//! record that nobody re-puts, so every identity that document names stops
//! resolving.
//!
//! # Exactly one cycle per node
//!
//! [`ApplicationNode`](crate::ApplicationNode) holds the cycle in a
//! non-optional field that only a builder fills, so a node carries one by
//! construction rather than by a caller remembering to start one. A second
//! cycle would re-put under the sequence ITS entry carries, which gives one
//! BEP44 record two independent writers of one monotonic counter: the lower-seq
//! put loses, so whichever cycle is behind stops keeping the record alive while
//! still reporting success.
//!
//! # Where the DHT client comes from
//!
//! [`DidMethod::dht_client`](scp_identity::DidMethod::dht_client). The client
//! that keeps a record alive is the client that signed the publish, so a node
//! that holds only a `DidMethod` still cannot pair a record with a client that
//! puts it somewhere else.
//!
//! (The items below are `pub` *within* this private module, which is what
//! confines them to the crate — `pub(crate)` here would be the redundant
//! spelling of the same thing.)

#[cfg(test)]
use std::future::Future;
#[cfg(test)]
use std::pin::Pin;
use std::sync::Arc;

use scp_dht::DhtClient;
use scp_identity::republish::{RepublishConfig, RepublishEntry, RepublishManager};
use scp_transport::native::TransportRelayPublisher;
use tokio::sync::watch;

// ---------------------------------------------------------------------------
// Self-DID republishing (SCP-RELAYRES-004, §3.10.2/§3.10.5/§3.10.6)
// ---------------------------------------------------------------------------

/// Constructs the production [`RepublishManager`] (the real `scp-transport`
/// [`TransportRelayPublisher`] is the `R` type parameter, paired with the node's
/// DHT client) and drives the self-host node's own DID-document republishing from
/// a **live view** of the node's published state — or leaves it **fully dormant**
/// (manager present, zero arms) while the node has published nothing.
/// Returns the running cycle for teardown.
///
/// # Both layers, always enabled (§3.10.6 anti-segmentation)
///
/// Neither arm is gated on infrastructure readiness:
///
/// - **DHT (2-hour keep-alive).** Mainline DHT records expire and pkarr performs
///   no internal republish, so this arm is the *only* thing keeping the node's
///   DID record resolvable on the DHT.
/// - **Relay (6-day cycle).** Always enabled, including when no relay is bound
///   yet. `TransportRelayPublisher`'s `RelayPublisher::publish` fails closed
///   with a typed
///   `IdentityError::NoRelayBound` while unbound (NOT the generic
///   `RelayPublishFailed`, which means bound relays actively rejected — the
///   distinction is the whole reason the variant exists: it selects the
///   rate-limited reporting channel, since no retry heals an unconfigured node),
///   and the relay republish loop backs off 30s → 30min — and the arm
///   **self-heals** the instant a relay is bound, with no manager reconstruction
///   and no re-drive.
///
/// Sampling relay readiness once, at construction, to decide whether to enable
/// the arm is what this function used to do, and it was unfixable by
/// construction: the sample necessarily ran before any relay-client connection
/// could exist, so the arm could never be true and — being latched — could never
/// be woken. Turning a layer OFF in [`RepublishConfig`] is reserved for a
/// DELIBERATE user opt-out (§3.10.6, which mandates a warning); an unbound layer
/// is not one, so no production path here ever asks for it.
///
/// **Nothing binds a relay yet.** A shipped self-host node therefore keeps the
/// relay arm failing closed for its whole life; wiring the relay-client bind is
/// SCP-RELAYRES-006. The arm reports that state honestly rather than pretending
/// success — the republish loop distinguishes "no relay configured" from "a
/// configured relay is failing" and rate-limits the former (§3.10.8).
///
/// # Full dormancy — honest disclosure (do not read as active resilience)
///
/// While the node has published **no signed record** (the slot's `record` is
/// `None`) there is nothing to keep alive on either layer, so no arm is scheduled
/// and the manager sits at zero tasks. `DhtMode::Disabled` — the fail-closed
/// default — publishes nothing, so that is its permanent state. The `None` is
/// produced by the publish seam itself, so the log below is literally true: it
/// fires when, and only when, nothing has been published.
///
/// # Re-seeding: a live view, not a snapshot
///
/// The cycle takes a [`watch::Receiver`] over the
/// node's published-state slot, never a `RepublishEntry` by value; see
/// `NodePublishedState`. A NAT tier change re-publishes the document with a NEW
/// `(value, signature, seq)`; against a held snapshot the DHT arm would keep
/// re-putting a superseded `seq` (which BEP44 nodes reject, so the *current*
/// record stops being kept alive and expires) and the relay arm would keep
/// pushing a superseded frame (which a validating relay rejects, miscounted as a
/// publish failure and eventually reported as `RelayPublishDegraded` while the
/// relay is in fact correct).
pub async fn start_self_did_republishing<D: DhtClient + 'static>(
    dht_client: Arc<D>,
    relay_publisher: Arc<TransportRelayPublisher>,
    mut live_state: watch::Receiver<crate::NodePublishedState>,
) -> SelfDidRepublishing<D> {
    let config = RepublishConfig::default();

    // Both degraded callbacks are wired: the DHT keep-alive is this node's only
    // resolvability guarantee, so a keep-alive that has been failing for six
    // consecutive cycles MUST NOT be silent. The relay callback additionally
    // fires on a PARTIAL publish (§3.10.8 suppression), not only total failure.
    let manager = Arc::new(
        RepublishManager::with_relay_publisher_and_warning(
            dht_client,
            relay_publisher,
            config,
            Arc::new(|degraded: scp_identity::republish::DhtPublishDegraded| {
                tracing::warn!(
                    did = %degraded.did,
                    consecutive_failures = degraded.consecutive_failures,
                    "self-DID DHT keep-alive is DEGRADED — this node's DID record \
                     will expire from the Mainline DHT and become unresolvable \
                     (§3.10.2)"
                );
            }),
        )
        .with_relay_warning_callback(Arc::new(
            |degraded: scp_identity::republish::RelayPublishDegraded| {
                tracing::warn!(
                    did = %degraded.did,
                    consecutive_failures = degraded.consecutive_failures,
                    accepted = degraded.last_outcome.map(|o| o.accepted),
                    attempted = degraded.last_outcome.map(|o| o.attempted),
                    "self-DID relay republishing is DEGRADED — some or all relays \
                     are not serving this node's DID record (§3.10.6/§3.10.8)"
                );
            },
        )),
    );

    // Construct the guard BEFORE spawning any arm (LOW-1). `seed_republish_arms`
    // below spawns the republish loops, whose `AbortHandle`s do NOT abort on
    // drop; if the serve future were cancelled DURING that seed `.await` before
    // the guard existed, those arms would detach and keep re-putting this node's
    // DID record past shutdown — the §10.12.1 disclosure the `Drop` backstop
    // exists to prevent. With the guard already in place, such a cancel drops it
    // and its `Drop` stops the arms. `reseed_task` is filled in once seeding
    // completes; the `Drop` backstop stops the manager whether or not it is set.
    let cycle = SelfDidRepublishing {
        manager,
        runtime: tokio::runtime::Handle::current(),
        reseed_task: std::sync::Mutex::new(None),
        stopped: std::sync::atomic::AtomicBool::new(false),
    };

    // Seed synchronously from the CURRENT slot value before returning, so a
    // caller that inspects the manager right after this call (and the teardown
    // path) sees the arms that the node's startup publish already justified —
    // rather than racing the observer task's first poll.
    //
    // `borrow_and_update` (not `borrow`) marks EXACTLY the version just read as
    // seen, so a publish racing this line is either included in `current` or
    // still pending for the observer's first `changed()`. Reading and marking as
    // two steps would drop a publish that landed between them.
    let current = live_state.borrow_and_update().record.clone();
    seed_republish_arms(&cycle.manager, current.clone()).await;

    let reseed_task = tokio::spawn(reseed_republish_arms(
        Arc::clone(&cycle.manager),
        live_state,
        current,
    ));
    cycle.set_reseed_task(reseed_task);

    cycle
}

/// The running self-DID republish cycle: the [`RepublishManager`] plus the
/// observer that keeps it pointed at the node's CURRENT signed record.
///
/// [`ApplicationNode`](crate::ApplicationNode) holds one for its whole life and
/// tears it down in
/// [`shutdown`](crate::ApplicationNode::shutdown), which calls
/// [`stop_and_wait`](RepublishCycle::stop_and_wait). A node dropped without a
/// `shutdown` reaches the [`Drop`] backstop instead.
pub struct SelfDidRepublishing<D: DhtClient + 'static> {
    manager: Arc<RepublishManager<D, TransportRelayPublisher>>,
    /// The runtime every arm was spawned onto, captured at construction.
    ///
    /// Teardown cannot ask [`Handle::try_current`](tokio::runtime::Handle::try_current)
    /// instead, because that answers a question about the CALLER's thread rather
    /// than about this cycle. `ApplicationNode::shutdown` is synchronous, and the
    /// three FFI bridges call it — and drop the node — from the Python
    /// interpreter thread, the Node.js main thread, and the Swift/Kotlin caller
    /// thread, none of which ever entered the runtime the node was built on
    /// (`RunningNode::shutdown` in `scp-ffi-common`, and the `Drop` impls on each
    /// bridge's node handle). A teardown that trusted `try_current` there found
    /// `Err`, aborted nothing, and left both arms re-putting this node's address
    /// for the life of the process — the §10.12.1 disclosure past shutdown.
    runtime: tokio::runtime::Handle,
    /// The re-seed observer. Aborted AND JOINED before the manager is stopped —
    /// see [`stop`](Self::stop).
    ///
    /// `Option` so every teardown path can take the handle by value: [`Drop`]
    /// must move it into the task it spawns, because the join is the barrier and
    /// a synchronous `drop` cannot perform it inline. Behind a
    /// [`std::sync::Mutex`] because the node owns the cycle behind an
    /// [`Arc`] and stops it through a shared `&self`, exactly as
    /// `TierReEvalHandle` holds its completion receiver.
    reseed_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Set by [`stop`](Self::stop) so the [`Drop`] backstop stays out of the way
    /// on the deterministic teardown path.
    stopped: std::sync::atomic::AtomicBool,
}

/// Waits for an already-aborted observer to finish unwinding, then drains both
/// arms.
///
/// The order is load-bearing, and so is the `await`. `abort` only *requests*
/// cancellation: a task already mid-poll runs to its next `Poll::Pending`, and
/// the observer's critical section (`seed_republish_arms` -> `stop_all` ->
/// `start_republishing`) has no guaranteed yield — an uncontended
/// `Mutex::lock().await` resolves on the first poll, and `tokio::spawn` plus the
/// map insert are synchronous. On a multi-thread runtime the whole re-seed could
/// therefore complete on another worker AFTER `stop_all` drained the maps,
/// detaching two arms that keep republishing this node's DID document (a
/// §10.12.1 address disclosure) past shutdown. Joining the aborted handle is the
/// only barrier that rules that out.
///
/// `reseed` is `None` when a teardown path found the handle already taken, or
/// when the observer had not been spawned yet — the guard is constructed BEFORE
/// `seed_republish_arms`. Arms may exist in either case, so `stop_all` runs
/// regardless.
async fn join_then_stop_all<D: DhtClient + 'static>(
    reseed: Option<tokio::task::JoinHandle<()>>,
    manager: Arc<RepublishManager<D, TransportRelayPublisher>>,
) {
    if let Some(reseed) = reseed {
        // `Err(cancelled)` is the expected outcome; `Ok` means it finished
        // first. Both mean the observer can no longer start an arm.
        let _ = reseed.await;
    }
    manager.stop_all().await;
}

impl<D: DhtClient + 'static> SelfDidRepublishing<D> {
    /// Stops the cycle: no arm survives, and none can be started afterwards.
    ///
    /// The awaitable teardown, compiled for the test build alone. Production
    /// stops the cycle through
    /// [`stop_and_wait`](RepublishCycle::stop_and_wait), which
    /// `ApplicationNode::shutdown` can call from a synchronous `&self`; a test on
    /// a `current_thread` runtime needs the `await` instead, because there the
    /// synchronous path spawns the stop rather than blocking on it and an
    /// assertion placed after it would race.
    ///
    /// Ordering is load-bearing, and so is the `await`. `abort` only *requests*
    /// cancellation: a task already mid-poll runs to its next `Poll::Pending`,
    /// and the observer's critical section (`seed_republish_arms` → `stop_all` →
    /// `start_republishing`) has no guaranteed yield — an uncontended
    /// `Mutex::lock().await` resolves on the first poll, and `tokio::spawn` plus
    /// the map insert are synchronous. On a multi-thread runtime the whole
    /// re-seed could therefore complete on another worker AFTER `stop_all`
    /// drained the maps, detaching two arms that keep republishing this node's
    /// DID document (a §10.12.1 address disclosure) past shutdown. Joining the
    /// aborted handle is the only barrier that rules that out.
    ///
    #[cfg(test)]
    async fn stop(&self) {
        let reseed = self.take_reseed_task();
        if let Some(ref reseed) = reseed {
            reseed.abort();
        }
        join_then_stop_all(reseed, Arc::clone(&self.manager)).await;
        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Records the observer handle once `start_self_did_republishing` has
    /// spawned it. Separate from construction because the guard is built BEFORE
    /// the observer exists (see the comment at the construction site).
    fn set_reseed_task(&self, task: tokio::task::JoinHandle<()>) {
        *self
            .reseed_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }

    /// Takes the observer handle, leaving `None`. Whichever teardown path runs
    /// first gets the handle, so the abort-and-join happens exactly once.
    fn take_reseed_task(&self) -> Option<tokio::task::JoinHandle<()>> {
        self.reseed_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl<D: DhtClient + 'static> Drop for SelfDidRepublishing<D> {
    /// Backstop for every path that never reaches [`stop`](Self::stop).
    ///
    /// [`stop_and_wait`](RepublishCycle::stop_and_wait) runs from exactly one
    /// line, `ApplicationNode::shutdown`. A node that is DROPPED without one —
    /// an early `return Err` in `self_host::serve_hosted_site`, a builder future
    /// cancelled mid-construction, a bridge handle released without an explicit
    /// stop — never reaches that line, and nothing else cleans up:
    /// `JoinHandle::drop` detaches rather than aborts, `AbortHandle::drop` does
    /// not abort, and `RepublishManager` has no `Drop` of its own. Both arms
    /// would then keep re-putting this node's DID record for the life of the
    /// process — the §10.12.1 address disclosure past shutdown.
    ///
    /// `Drop` is synchronous, so it cannot perform the join inline — but it MUST
    /// still perform it, and hand-waving that away would reintroduce the exact
    /// race `stop` documents. Aborting the observer and spawning a bare
    /// `stop_all` would let the observer finish `start_republishing` on another
    /// worker AFTER the spawned `stop_all` had drained the maps, leaving two
    /// detached arms republishing this node's address forever — the very outcome
    /// the backstop exists to prevent. So the handle is MOVED into the spawned
    /// task and joined there, before `stop_all`, preserving `stop`'s ordering
    /// asynchronously.
    ///
    /// The spawn goes onto the STORED [`runtime`](Self::runtime) rather than onto
    /// whatever runtime the dropping thread happens to be in, for the reason that
    /// field documents. Should that runtime already be shut down, its tasks —
    /// both arms among them — are gone with it, so a spawn that never runs costs
    /// nothing.
    ///
    /// `stop_and_wait` remains the deterministic path; the flag keeps the two
    /// from doing the work twice. Mirrors the `Drop` backstop on
    /// `TierReEvalHandle`.
    fn drop(&mut self) {
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        // Aborting needs no runtime, so it happens here rather than inside the
        // spawned task: after this line no re-seed can start a further arm, even
        // if the spawn below never runs. `reseed_task` may be `None` — the
        // observer was not spawned yet because the guard is constructed BEFORE
        // `seed_republish_arms` (LOW-1). Arms may still have been seeded, so
        // `stop_all` must run regardless.
        let reseed = self.take_reseed_task();
        if let Some(ref reseed) = reseed {
            reseed.abort();
        }
        let manager = Arc::clone(&self.manager);
        self.runtime.spawn(join_then_stop_all(reseed, manager));
    }
}

/// The number of running republish arms, per layer.
///
/// A node's own answer to "is my DID record being kept alive, and on which
/// layers". Both counts are `1` while the node stands behind a published record,
/// and both are `0` while it has published nothing — the honest dormant state a
/// [`DhtMode::Disabled`](crate::DhtMode) node sits in permanently.
///
/// Compiled for the test build alone: the counts exist so this crate can assert
/// that a node built through the plain path runs exactly one cycle over both
/// layers. Shipped code has no reader for them, and an unread accessor is dead
/// weight on the node's surface.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveArms {
    /// Running DHT keep-alive tasks (the 2-hour cycle, §3.10.2).
    pub dht: usize,
    /// Running relay republish tasks (the 6-day cycle, §3.10.2).
    pub relay: usize,
}

/// A running republish cycle, with its DHT client type erased.
///
/// [`ApplicationNode`](crate::ApplicationNode) is generic over its storage
/// backend alone, while a cycle is generic over the DHT client its
/// [`DidMethod`](scp_identity::DidMethod) publishes through. The node holds the
/// cycle behind this trait so the builder's DID-method type parameter does not
/// have to appear in the node's own type — the same reason the publish seam's
/// `DidPublisher` trait exists in `published_state`.
///
/// Object safety is why neither method returns `impl Future`: `stop_and_wait` is
/// synchronous (it bridges to the async stop the way `TierReEvalHandle` does),
/// and `active_arms` returns a boxed future. `active_arms` carries
/// `#[cfg(test)]`, so a doc build compiles no link target for it.
pub trait RepublishCycle: Send + Sync {
    /// Aborts the re-seed observer, then stops both arms.
    ///
    /// The observer abort is synchronous and unconditional, so no further arm can
    /// be started once this returns. Whether the ARMS are gone by then depends on
    /// where the caller is standing: from a worker of the cycle's own
    /// multi-thread runtime this blocks until both are aborted, and from anywhere
    /// else — a `current_thread` runtime, or a thread that never entered one —
    /// the stop is spawned onto the cycle's runtime and completes on its next
    /// turn.
    ///
    /// Called by [`ApplicationNode::shutdown`](crate::ApplicationNode::shutdown),
    /// which is synchronous and holds the node by shared reference. Idempotent:
    /// a second call finds the observer handle already taken and re-runs only
    /// the (by then empty) `stop_all`.
    fn stop_and_wait(&self);

    /// How many arms are running right now. See `ActiveArms`.
    #[cfg(test)]
    fn active_arms(&self) -> Pin<Box<dyn Future<Output = ActiveArms> + Send + '_>>;
}

impl<D: DhtClient + 'static> RepublishCycle for SelfDidRepublishing<D> {
    /// Bridges the synchronous `shutdown(&self)` surface to [`stop`](Self::stop),
    /// which must `await` the observer join that is the barrier against a
    /// re-seed outrunning `stop_all`.
    ///
    /// The observer abort needs no runtime, so it runs first and on every path:
    /// once it has happened, nothing can start a further arm, whatever the
    /// caller's thread. Only the join-and-`stop_all` needs a runtime, and it gets
    /// the STORED one — see [`runtime`](Self::runtime) for why asking
    /// `Handle::try_current` here answered the wrong question and left the FFI
    /// bridges' nodes republishing past shutdown.
    ///
    /// `block_in_place` PANICS on a `current_thread` runtime and is unavailable
    /// off-runtime, so it is used only when the caller is already on a worker of
    /// this cycle's own multi-thread runtime — the case where blocking makes
    /// teardown deterministic. Every other caller gets a spawn onto the same
    /// runtime. Mirrors `TierReEvalHandle::stop_and_wait`, including its
    /// runtime-flavor check, and its fallback that still aborts.
    fn stop_and_wait(&self) {
        // Synchronous and unconditional: after this line no re-seed can start an
        // arm, whether or not the stop below gets to run promptly.
        let reseed = self.take_reseed_task();
        if let Some(ref reseed) = reseed {
            reseed.abort();
        }
        let manager = Arc::clone(&self.manager);

        let on_own_worker = tokio::runtime::Handle::try_current().is_ok_and(|current| {
            current.id() == self.runtime.id()
                && current.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        });

        if on_own_worker {
            tokio::task::block_in_place(|| {
                self.runtime.block_on(join_then_stop_all(reseed, manager)); // ci-allow: block-on: joins the re-seed observer so no arm outlives shutdown()
            }); // ci-allow: block-on: deterministic node teardown — multi-thread-checked sync-to-async join stopping both republish arms
        } else {
            self.runtime.spawn(join_then_stop_all(reseed, manager));
        }

        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    fn active_arms(&self) -> Pin<Box<dyn Future<Output = ActiveArms> + Send + '_>> {
        Box::pin(async move {
            ActiveArms {
                dht: self.manager.active_count().await,
                relay: self.manager.active_relay_count().await,
            }
        })
    }
}

/// Points both republish arms at `entry`, replacing whatever they were asserting.
///
/// # Why a full stop-then-start rather than a bespoke `reseed` method
///
/// "Make these arms publish this entry" is exactly what
/// [`RepublishManager::start_republishing`] already means — it aborts and
/// replaces the tasks under the entry's derived DID. A separate `reseed` method
/// would be a second spelling of one operation, and the two would have to be kept
/// in agreement forever. Replacing the tasks is also the only *possible*
/// semantics: each arm captured its `RepublishEntry` by value when it was
/// spawned, so nothing short of a new task can make it publish new bytes.
///
/// The preceding [`stop_all`](RepublishManager::stop_all) closes the one gap in
/// `start_republishing`'s replace: it replaces only the arms keyed under THIS
/// entry's DID. This manager hosts exactly one identity — the node's own — so any
/// arm under a different key is by definition asserting a record this node no
/// longer stands behind, and would keep doing so forever. Stopping everything
/// first makes "one entry, one pair of arms" unconditional rather than an
/// invariant argued from the node's identity never changing. The two calls are
/// serial on a single observer task, and `start_republishing` publishes
/// immediately, so the replacement window carries no tick.
async fn seed_republish_arms<D: DhtClient + 'static>(
    manager: &RepublishManager<D, TransportRelayPublisher>,
    entry: Option<RepublishEntry>,
) {
    // Unconditional, and AHEAD of the dormancy branch: "point the arms at
    // `entry`" has to include "point them at nothing". This used to sit after
    // the early return, so `seed_republish_arms(manager, None)` left every
    // running arm intact and asserting the record the node had just retracted —
    // the function silently doing the opposite of what its own contract says.
    // Reaching it requires the published record to go `Some -> None`, which no
    // writer does today (`apply_tier_change` only ever assigns `Some`); that is
    // a fact about the current single writer, not about this function, and it is
    // exactly the kind of fact this module exists to stop relying on. On the
    // startup seed the manager is empty, so this is a no-op.
    manager.stop_all().await;

    let Some(entry) = entry else {
        // Nothing published (yet): no DHT record to keep alive and nothing to
        // publish to relays. Not an error — the `DhtMode::Disabled` default.
        tracing::info!(
            "self-DID republishing dormant: this node has published no signed \
             record, so there is no DID record to keep alive on either layer \
             (DhtMode::Disabled no-publish default)"
        );
        return;
    };

    tracing::info!(
        did = %entry.did(),
        sequence = entry.sequence,
        "self-DID republishing active on BOTH layers: DHT (2h keep-alive) + \
         relay (6d) (§3.10.6 anti-segmentation). The relay arm publishes on \
         every cycle and fails closed until a relay is bound."
    );
    manager.start_republishing(entry).await;
}

/// Re-seeds the republish arms from the node's published-record slot for as long
/// as the node lives.
///
/// This is what makes re-seeding structural: the observer watches the slot that
/// the publish seam writes, so ANY re-publish — the NAT tier change today, and
/// any publish path added later — re-points the arms at the record it produced.
/// No call site re-seeds, because no call site is involved.
///
/// # Racing an in-flight tick
///
/// A re-seed can land while an arm is mid-publish. Each arm is aborted and its
/// replacement inserted under the manager's task-map lock, so the two can neither
/// interleave nor both survive. Aborting mid-publish drops that request; the
/// replacement task publishes immediately with a HIGHER sequence, which
/// supersedes the dropped one on both layers. Losing the stale in-flight put is
/// the desired outcome — it was asserting a record the node has already replaced.
async fn reseed_republish_arms<D: DhtClient + 'static>(
    manager: Arc<RepublishManager<D, TransportRelayPublisher>>,
    mut live_state: watch::Receiver<crate::NodePublishedState>,
    mut current: Option<RepublishEntry>,
) {
    // The version present at construction was read with `borrow_and_update` by
    // `start_self_did_republishing` and is therefore already marked seen, so the
    // first `changed()` waits for the next *publish* rather than replaying it.
    loop {
        if live_state.changed().await.is_err() {
            // Every sender is gone: the node has been dropped, so nothing more
            // will ever be published. The arms keep asserting the last record
            // until teardown aborts them.
            tracing::debug!(
                "self-DID re-seed observer stopping: the node's published-record \
                 slot was dropped"
            );
            return;
        }
        let entry = live_state.borrow_and_update().record.clone();
        // The slot also advances when only the node's advertised address moved
        // (a tier change whose re-publish failed, or a `DhtMode::Disabled`
        // node's, which publishes nothing). Neither produced a new record, and
        // tearing both arms down to re-assert the same bytes would be pure
        // churn — re-seed only on a record that actually changed.
        if entry.as_ref().map(|e| (e.sequence, e.signature))
            == current.as_ref().map(|e| (e.sequence, e.signature))
        {
            continue;
        }
        current = entry.clone();
        seed_republish_arms(manager.as_ref(), entry).await;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use crate::DhtMode;

    use std::pin::Pin;
    use std::time::Duration;

    use scp_clock::SystemClock;
    use scp_dht::InMemoryDhtClient;
    use scp_identity::{DidCache, DidDht};

    /// The signed BEP44 record a node's own publish produces — the SHAPE the
    /// publish seam files into the node's published-record slot, which
    /// `start_self_did_republishing` observes. Built directly from the signing
    /// inputs (no DHT involved), because that is the point: sourcing the
    /// republish entry no longer requires any storage or network read.
    fn self_host_signed_record() -> RepublishEntry {
        use ed25519_dalek::{Signer, SigningKey};

        let identity_signing = SigningKey::from_bytes(&[11u8; 32]);
        let active_signing = SigningKey::from_bytes(&[22u8; 32]);
        let identity_public = identity_signing.verifying_key();

        let did = scp_identity::did_from_ed25519_public_key(identity_public.as_bytes());
        let pre_rotation_commitment: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(
                SigningKey::from_bytes(&[33u8; 32])
                    .verifying_key()
                    .as_bytes(),
            )
            .into()
        };
        let doc = scp_did::DidDocument::new(
            &did,
            identity_public.as_bytes(),
            active_signing.verifying_key().as_bytes(),
            &pre_rotation_commitment,
        );
        let document_bytes = doc.to_json().expect("doc serializes").into_bytes();
        let signature: [u8; 64] = identity_signing
            .sign(&scp_dht::bep44_signable(&document_bytes, 1))
            .to_bytes();

        RepublishEntry {
            public_key: *identity_public.as_bytes(),
            document_bytes,
            signature,
            sequence: 1,
        }
    }

    // -----------------------------------------------------------------------
    // Self-DID republishing (SCP-RELAYRES-004) — §3.10.2/§3.10.5/§3.10.6
    //
    // The production wiring constructs a RepublishManager over the REAL
    // `TransportRelayPublisher` and, when the node has a published signed record
    // to source, drives BOTH the DHT (2h) and relay (6d) cycles. These tests
    // exercise that wiring end-to-end with a testing-gated identity (a genuinely
    // BEP44-signed record seeded into the in-memory DHT) — proving the wiring
    // activates, publishes the full DID-record frame to relays, and covers both
    // layers.
    // -----------------------------------------------------------------------

    use scp_identity::extract_public_key;

    type AdapterFut<'a, T> = Pin<
        Box<
            dyn std::future::Future<Output = Result<T, scp_transport::error::TransportError>>
                + Send
                + 'a,
        >,
    >;

    /// Minimal recording relay adapter: captures every `publish_raw` blob so a
    /// test can decode the DID-record frame the relay layer received. Every other
    /// method is an honest "not connected" (never a fabricated success).
    #[derive(Default)]
    struct RecordingRelayAdapter {
        published: std::sync::Mutex<Vec<(scp_transport::traits::RoutingId, u64, Vec<u8>)>>,
    }

    impl RecordingRelayAdapter {
        fn recorded(&self) -> Vec<(scp_transport::traits::RoutingId, u64, Vec<u8>)> {
            self.published.lock().expect("published lock").clone()
        }
    }

    impl scp_transport::traits::TransportAdapter for RecordingRelayAdapter {
        fn send(
            &self,
            _envelope: &scp_core::envelope::OuterEnvelope,
        ) -> AdapterFut<'_, scp_transport::traits::BlobId> {
            Box::pin(async { Err(scp_transport::error::TransportError::NotConnected) })
        }

        fn subscribe(
            &self,
            _routing_id: &scp_transport::traits::RoutingId,
            _since: Option<u64>,
        ) -> AdapterFut<'_, scp_transport::traits::SubscriptionStream> {
            Box::pin(async { Err(scp_transport::error::TransportError::NotConnected) })
        }

        fn unsubscribe(
            &self,
            _routing_id: &scp_transport::traits::RoutingId,
        ) -> AdapterFut<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn query(
            &self,
            _routing_id: &scp_transport::traits::RoutingId,
            _since: Option<u64>,
        ) -> AdapterFut<'_, Vec<scp_core::envelope::OuterEnvelope>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete(&self, _blob_id: &scp_transport::traits::BlobId) -> AdapterFut<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn publish_raw(
            &self,
            routing_id: &scp_transport::traits::RoutingId,
            blob_ttl: u64,
            blob: Vec<u8>,
        ) -> AdapterFut<'_, ()> {
            self.published
                .lock()
                .expect("published lock")
                .push((*routing_id, blob_ttl, blob));
            Box::pin(async { Ok(()) })
        }
    }

    /// A node published-state slot pre-seeded with `entry`.
    ///
    /// A bare `watch` channel rather than the node's `LiveSlot`: these tests
    /// drive the OBSERVER, and the slot's writer is private to the module that
    /// owns `apply_tier_change` (which is exactly the point — see
    /// `NodePublishedState`). The tests that need the real writer use it.
    ///
    /// Returns the sender alongside the receiver: the sender must outlive the
    /// cycle under test, because dropping every sender is the signal that the
    /// node is gone and stops the re-seed observer.
    fn record_slot(
        entry: Option<RepublishEntry>,
    ) -> (
        watch::Sender<crate::NodePublishedState>,
        watch::Receiver<crate::NodePublishedState>,
    ) {
        let tx = watch::Sender::new(crate::NodePublishedState {
            document: scp_did::DidDocument::new(
                "did:dht:reseedtest",
                &[1u8; 32],
                &[2u8; 32],
                &[3u8; 32],
            ),
            relay_url: "ws://198.51.100.7:32891/scp/v1".to_owned(),
            record: entry,
        });
        let rx = tx.subscribe();
        (tx, rx)
    }

    /// Binds a recording relay adapter onto `publisher` and returns the adapter
    /// so the test can inspect what the relay layer received.
    fn bind_recording_relay(publisher: &TransportRelayPublisher) -> Arc<RecordingRelayAdapter> {
        let adapter = Arc::new(RecordingRelayAdapter::default());
        publisher.bind(
            "wss://relay.example/scp/v1",
            Arc::clone(&adapter) as Arc<dyn scp_transport::traits::TransportAdapter>,
        );
        adapter
    }

    /// AC 3 / AC 5: the production entry point schedules BOTH layers — the DHT
    /// (2h) keep-alive AND the relay (6d) cycle — from the node's own signed
    /// record, with neither arm disabled.
    #[tokio::test]
    async fn self_did_republishing_schedules_both_dht_and_relay_layers() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();

        let publisher = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(publisher.as_ref());
        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_count().await,
            1,
            "the DHT (2h) republish cycle is scheduled"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            1,
            "the relay (6d) republish cycle is scheduled ALONGSIDE the DHT cycle (§3.10.6)"
        );

        republish.stop().await;
    }

    /// AC 5: the production `RepublishManager` publishes to BOTH layers — the DHT
    /// record is present and the relay layer independently receives the frame.
    #[tokio::test]
    async fn production_republish_manager_publishes_both_layers() {
        use scp_dht::DhtClient as _;

        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let public_key = entry.public_key;

        let publisher = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(publisher.as_ref());

        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        republish.stop().await;

        // DHT layer: the record is present (the DHT arm publishes it too).
        assert!(
            dht.resolve(&public_key)
                .await
                .expect("resolve ok")
                .is_some(),
            "the DHT layer holds the DID record (2h cycle)"
        );
        // Relay layer: the frame reached the bound relay (6d cycle) — additive.
        assert!(
            !adapter.recorded().is_empty(),
            "the relay layer received the DID record (additive to the DHT layer, §3.10.6)"
        );
    }

    /// AC 4: a node's DID record reaches the relay as a valid DID-record FRAME
    /// whose `(value, signature, seq)` verifies against the node's DID-derived
    /// key, stored at `did_routing_id` (§9.10.12 publish contract) — never bare
    /// bytes, never an `OuterEnvelope`.
    #[tokio::test]
    async fn node_did_record_reaches_relay_as_verifiable_frame() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let did = entry.did();

        let publisher = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(publisher.as_ref());

        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        republish.stop().await;

        let recorded = adapter.recorded();
        assert!(!recorded.is_empty(), "relay received the node's DID record");
        assert_relay_blob_is_node_frame(&recorded[0], &did);
    }

    /// Shared frame oracle for the relay-blob assertions.
    ///
    /// Recomposes the expected `routing_id` from the DID STRING
    /// (`did_routing_id`), independently of the key-derived path
    /// (`did_key_routing_id`) the publisher takes — so a bug in the shared
    /// derivation cannot make both sides of the assertion vacuously agree.
    fn assert_relay_blob_is_node_frame(
        recorded: &(scp_transport::traits::RoutingId, u64, Vec<u8>),
        did: &str,
    ) {
        let (rid, ttl, blob) = recorded;

        assert_eq!(
            rid.as_bytes(),
            &scp_identity::did_routing_id(did),
            "published at SHA-256('scp:did:' || did)"
        );
        assert_eq!(
            *ttl,
            scp_identity::republish::RELAY_BLOB_TTL_SECS,
            "blob_ttl is the 7-day DID-record TTL (§3.10.2)"
        );

        // The blob is a valid DID-record frame (not bare bytes, not an envelope).
        let frame = scp_core::envelope::did_record::DidRecordV1::decode(blob)
            .expect("relay blob decodes as a DID-record frame (§9.10.12)");

        // Its (value, signature, seq) verify against the node's DID-derived key.
        let pk = extract_public_key(did).expect("DID yields a public key");
        scp_dht::verify_bep44_signature(&pk, frame.signature(), frame.value(), frame.seq())
            .expect("the framed record verifies against the node's DID-derived key");
    }

    /// B1 (the one-shot latch is GONE — self-heal on a LATE bind).
    ///
    /// Constructed through the production entry point with ZERO relays bound —
    /// exactly the state the deleted latch sampled and then disabled the relay
    /// arm on, permanently. A relay is bound only AFTER the manager is running,
    /// and the NEXT tick must publish a real frame with no manager
    /// reconstruction and no re-drive.
    ///
    /// Against the pre-fix code this test fails at the first assertion: the
    /// relay arm was never scheduled at all.
    #[tokio::test(start_paused = true)]
    async fn relay_arm_self_heals_when_a_relay_is_bound_after_start() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let did = entry.did();

        // ZERO relays bound at construction.
        let publisher = Arc::new(TransportRelayPublisher::new());
        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_relay_count().await,
            1,
            "the relay arm is scheduled even with no relay bound — it fails closed \
             per tick rather than being latched off at construction"
        );

        // Let the first tick run: it fails closed (nothing bound) and backs off.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // NOW bind a relay, on the SAME shared publisher instance, after the
        // manager was constructed AND started.
        let adapter = bind_recording_relay(publisher.as_ref());
        assert!(
            adapter.recorded().is_empty(),
            "nothing can have been published before the bind"
        );

        // Advance past the first backoff (30s). The next tick must publish.
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let recorded = adapter.recorded();
        assert!(
            !recorded.is_empty(),
            "binding a relay AFTER start must wake the relay arm on its next tick \
             (no reconstruction, no re-drive)"
        );
        assert_relay_blob_is_node_frame(&recorded[0], &did);

        republish.stop().await;
    }

    /// B2 (CRITICAL): republishing no longer depends on reading the node's own
    /// record back off the DHT.
    ///
    /// The DHT here is EMPTY, so a read-back would return `Ok(None)` — the exact
    /// shape a `DhtMode::Production` resolve timeout takes with no gateways
    /// configured. The pre-fix code turned that single miss into a permanently
    /// dormant manager (no retry, DID unresolvable ~2h later). Sourcing the
    /// entry from the publish that created it removes the dependency entirely.
    #[tokio::test]
    async fn republishing_survives_a_dht_read_back_miss_at_startup() {
        use scp_dht::DhtClient as _;

        let dht = Arc::new(InMemoryDhtClient::new());
        let entry = self_host_signed_record();
        let public_key = entry.public_key;

        // Precondition: a read-back WOULD have found nothing.
        assert!(
            dht.resolve(&public_key)
                .await
                .expect("resolve ok")
                .is_none(),
            "the DHT holds no record — a read-back source would yield None"
        );

        let publisher = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(publisher.as_ref());
        let (_slot, records) = record_slot(Some(entry));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_count().await,
            1,
            "DHT keep-alive scheduled"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            1,
            "relay arm scheduled"
        );

        republish.stop().await;
    }

    /// No signed record → FULLY dormant: zero DHT tasks, zero relay tasks.
    /// The honest absent state, never a fabricated entry. `None` means "this node
    /// published nothing" (the `DhtMode::Disabled` default), which is what the
    /// dormancy log claims — before, it also covered "the network read failed",
    /// making that log a lie.
    #[tokio::test]
    async fn self_did_republishing_fully_dormant_without_published_record() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let publisher = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(publisher.as_ref());

        let (_slot, records) = record_slot(None);
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_count().await,
            0,
            "nothing published → no DHT keep-alive arm (no entry fabricated)"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            0,
            "nothing published → no relay arm"
        );

        // Dormancy is real, not just an empty task map: nothing reaches a relay.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            adapter.recorded().is_empty(),
            "a dormant cycle publishes nothing to any layer"
        );

        republish.stop().await;
    }

    /// Retracting the published record STOPS the arms.
    ///
    /// `seed_republish_arms` is documented as "points both arms at `entry`,
    /// replacing whatever they were asserting", but its dormancy branch used to
    /// `return` ahead of `stop_all()`, so seeding with `None` left every running
    /// arm alive and re-asserting a record the node no longer stands behind — the
    /// function doing the exact opposite of its contract. The observer routes a
    /// `Some -> None` slot transition straight into that branch.
    ///
    /// Driven through the real observer (`reseed_republish_arms`) rather than by
    /// calling the helper directly, so the test pins the reachable behaviour.
    #[tokio::test]
    async fn retracting_the_published_record_stops_both_arms() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let publisher = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(publisher.as_ref());

        let (slot, records) = record_slot(Some(self_host_signed_record()));
        let republish =
            start_self_did_republishing(Arc::clone(&dht), Arc::clone(&publisher), records).await;

        assert_eq!(
            republish.manager.active_count().await,
            1,
            "precondition: the DHT keep-alive arm is running"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            1,
            "precondition: the relay arm is running"
        );

        // The node retracts its published record. The observer runs on its own
        // task, so poll rather than assume it has been scheduled.
        slot.send_modify(|state| state.record = None);
        settle_until("the retracted record to stop both arms", async || {
            republish.manager.active_count().await == 0
                && republish.manager.active_relay_count().await == 0
        })
        .await;

        assert_eq!(
            republish.manager.active_count().await,
            0,
            "a retracted record must stop the DHT keep-alive arm, not leave it \
             asserting bytes the node has withdrawn"
        );
        assert_eq!(
            republish.manager.active_relay_count().await,
            0,
            "a retracted record must stop the relay arm too"
        );

        republish.stop().await;
    }

    // -----------------------------------------------------------------------
    // Re-seeding the running republish arms on a re-publish
    // (SCP-RELAYRES-004 — the tier-change seam; see `NodePublishedState`)
    //
    // `apply_tier_change` re-publishes the node's DID document on a NAT tier
    // change, producing a NEW (value, signature, seq). These tests drive the REAL
    // seam — a signing `DidDht`, the real `NodeDidPublisher`, the real
    // `apply_tier_change` — and assert the RUNNING arms follow it.
    // -----------------------------------------------------------------------

    use crate::{
        LiveSlot, NodePublishedState, NodePublisher, apply_tier_change, seed_from_startup_publish,
    };
    use scp_did::DidDocument;
    use scp_identity::{DidMethod as _, ScpIdentity};
    use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

    /// The concrete signing `DidDht` used by the re-seed tests: a real BEP44
    /// signer over an in-memory DHT, with the real monotonic sequence counter.
    type SigningDidDht = DidDht<InMemoryDhtClient, SystemClock>;

    /// A real identity + relay-carrying DID document + the signing method that
    /// created them.
    ///
    /// Nothing here is synthesized: the records these tests compare are produced
    /// by the same `DidDht::publish_document` signing pass production uses, so a
    /// re-seed that carried the wrong bytes could not pass.
    async fn signing_identity() -> (Arc<SigningDidDht>, ScpIdentity, DidDocument, String) {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let sign_fn = SigningDidDht::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(DidDht::with_client_and_signer(
            Arc::new(InMemoryDhtClient::new()),
            Arc::new(DidCache::new()),
            sign_fn,
        ));
        let (identity, mut document, _pre_rotation) = did_method
            .create(custody.as_ref(), &InMemoryPreRotationCustody::new())
            .await
            .expect("test identity is created");
        let relay_url = "ws://198.51.100.7:32891/scp/v1".to_owned();
        crate::push_relay_service(&mut document, &relay_url);
        (did_method, identity, document, relay_url)
    }

    /// The node's publish seam over `did_method`, in a publishing `DhtMode`.
    fn publish_seam(did_method: &Arc<SigningDidDht>) -> NodePublisher {
        NodePublisher::new(Arc::clone(did_method), DhtMode::Memory)
    }

    /// The node's live slot as the builders construct it: the startup publish's
    /// document, address and signed record, together — produced by the SAME
    /// `seed_from_startup_publish` seam the production builders use, so the publish
    /// and the slot seed are one indivisible step here too.
    async fn published_slot(
        publisher: &NodePublisher,
        identity: &ScpIdentity,
        document: DidDocument,
        relay_url: String,
    ) -> LiveSlot<NodePublishedState> {
        seed_from_startup_publish(publisher, identity, document, &relay_url)
            .await
            .expect("startup publish succeeds")
    }

    /// Drives ONE real tier change through the real writer, alternating the
    /// relay endpoint so every call genuinely re-publishes at a new sequence.
    async fn republish_via_tier_change(
        live_state: &LiveSlot<NodePublishedState>,
        publisher: &NodePublisher,
        identity: &ScpIdentity,
        nth: u32,
    ) {
        let next_url = format!("ws://203.0.113.42:{}/scp/v1", 9000 + nth);
        apply_tier_change(
            live_state,
            &next_url,
            "test tier change",
            publisher,
            identity,
            None,
        )
        .await;
    }

    /// Polls `cond` across task hops until it holds, or panics with `label`.
    ///
    /// The re-seed path crosses several tasks (publish → slot → observer →
    /// manager → arm), so a fixed number of yields would be a guess. Bounded, so
    /// a genuine failure to re-seed fails the test rather than hanging.
    ///
    /// # Why the budget is wall-clock and not an iteration count
    ///
    /// A plain `for _ in 0..N { yield_now().await }` is only a valid wait on a
    /// CURRENT-THREAD runtime, where yielding necessarily hands the one worker to
    /// the task being waited on. `stop_is_a_barrier_even_against_an_in_flight_reseed`
    /// runs on `worker_threads = 2` deliberately, and there the awaited task may
    /// be on the OTHER worker: the yield loop then spins through its whole budget
    /// in microseconds without that worker having been scheduled at all. Under a
    /// full-workspace test run (every core saturated) that is exactly what
    /// happened, and the test failed with "timed out waiting for the initial DHT
    /// arm to publish" while passing in isolation — a flake, not a regression.
    ///
    /// [`std::time::Instant`] is the REAL clock and is unaffected by
    /// `#[tokio::test(start_paused = true)]`, so one deadline is correct for both
    /// the paused current-thread tests and the multi-thread one. The generous
    /// budget costs nothing on the happy path (the condition holds after a few
    /// hops); it is only spent when the test is going to fail anyway.
    async fn settle_until<F>(label: &str, mut cond: F)
    where
        F: AsyncFnMut() -> bool,
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if cond().await {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {label}"
            );
            tokio::task::yield_now().await;
        }
    }

    /// THE regression: a NAT tier change re-publishes the DID document with a NEW
    /// `(value, signature, seq)`, and the ALREADY-RUNNING republish arms must
    /// re-assert THAT record — on both layers.
    ///
    /// Against the pre-fix code this fails: `start_self_did_republishing` took the
    /// startup `RepublishEntry` BY VALUE, so nothing re-seeded the manager. The
    /// DHT arm kept re-putting the superseded `seq` (rejected by BEP44 nodes, so
    /// the *current* record stops being kept alive and expires) and the relay arm
    /// kept pushing the superseded frame (rejected by a validating relay, then
    /// miscounted as a publish failure).
    #[tokio::test(start_paused = true)]
    async fn tier_change_reseeds_the_running_republish_arms() {
        let (did_method, identity, document, relay_url) = signing_identity().await;
        let publisher = publish_seam(&did_method);
        let live_state = published_slot(&publisher, &identity, document, relay_url).await;
        let first = live_state
            .get()
            .record
            .expect("the startup publish records its entry");

        // The keep-alive layers. These are used ONLY by the republish arms (the
        // DID method has its own DHT client), so whatever lands here is exactly
        // what the arms asserted — never leakage from the publish itself.
        let keep_alive_dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(TransportRelayPublisher::new());
        let adapter = bind_recording_relay(relay.as_ref());

        let republish = start_self_did_republishing(
            Arc::clone(&keep_alive_dht),
            Arc::clone(&relay),
            live_state.subscribe(),
        )
        .await;

        assert_arms_assert_record(
            &keep_alive_dht,
            &adapter,
            &first,
            "the record the startup publish signed",
        )
        .await;

        // -- A NAT tier change: the node re-publishes with a new relay endpoint,
        //    producing a NEW (value, signature, seq). --
        let new_relay_url = "ws://203.0.113.42:8443/scp/v1";
        apply_tier_change(
            &live_state,
            new_relay_url,
            "test tier change",
            &publisher,
            &identity,
            None,
        )
        .await;
        // `apply_tier_change` returns nothing: success is observable only where
        // the node actually keeps its state. The DOCUMENT advancing is the signal
        // the re-publish succeeded (it is written on the success arm only), which
        // the record assertions below then corroborate.
        let state = live_state.get();
        assert_eq!(state.relay_url, new_relay_url);
        assert_eq!(
            state.document.relay_service_urls(),
            vec![new_relay_url.to_owned()],
            "a successful tier change advances the node's published document"
        );

        let second = state
            .record
            .expect("the tier-change publish records its entry");
        assert!(
            second.sequence > first.sequence,
            "the re-publish assigns a HIGHER BEP44 sequence ({} -> {})",
            first.sequence,
            second.sequence
        );
        assert_ne!(
            second.signature, first.signature,
            "the re-publish signs different bytes, so the signature differs"
        );
        assert!(
            String::from_utf8_lossy(&second.document_bytes).contains(new_relay_url),
            "the re-published document carries the NEW relay endpoint"
        );

        // -- The running arms must now assert the NEW record, unprompted. --
        assert_arms_assert_record(
            &keep_alive_dht,
            &adapter,
            &second,
            "the record the TIER-CHANGE re-publish signed",
        )
        .await;

        republish.stop().await;
    }

    /// Asserts BOTH republish arms are asserting exactly `entry`: the DHT
    /// keep-alive holds its `(value, signature, seq)` and the relay has received a
    /// frame carrying them.
    ///
    /// Waits for each arm rather than assuming a fixed number of task hops, and
    /// compares full bytes rather than only the sequence — a stale arm republishing
    /// the previous document would otherwise pass on a coincidental sequence match.
    async fn assert_arms_assert_record(
        keep_alive_dht: &InMemoryDhtClient,
        adapter: &RecordingRelayAdapter,
        entry: &RepublishEntry,
        label: &str,
    ) {
        use scp_dht::DhtClient as _;

        settle_until(&format!("the DHT arm to assert {label}"), async || {
            keep_alive_dht
                .resolve(&entry.public_key)
                .await
                .expect("resolve ok")
                .is_some_and(|record| record.seq == entry.sequence)
        })
        .await;
        let kept_alive = keep_alive_dht
            .resolve(&entry.public_key)
            .await
            .expect("resolve ok")
            .expect("record present");
        assert_eq!(
            kept_alive.value, entry.document_bytes,
            "the DHT keep-alive puts the document bytes of {label}"
        );
        assert_eq!(
            kept_alive.signature, entry.signature,
            "the DHT keep-alive puts the signature of {label}"
        );

        settle_until(&format!("the relay arm to assert {label}"), async || {
            adapter.recorded().iter().any(|recorded| {
                scp_core::envelope::did_record::DidRecordV1::decode(&recorded.2)
                    .is_ok_and(|frame| frame.seq() == entry.sequence)
            })
        })
        .await;
        let frame = adapter
            .recorded()
            .into_iter()
            .filter_map(|recorded| {
                scp_core::envelope::did_record::DidRecordV1::decode(&recorded.2).ok()
            })
            .find(|frame| frame.seq() == entry.sequence)
            .expect("the relay arm published a frame at this sequence");
        assert_eq!(
            frame.value(),
            entry.document_bytes.as_slice(),
            "the relay frame carries the document bytes of {label} — a SUPERSEDED \
             frame is what a validating relay rejects as DID_RECORD_REJECTED, which \
             the loop then miscounts as a publish failure"
        );
        assert_eq!(
            frame.signature(),
            &entry.signature,
            "the relay frame carries the signature of {label}"
        );
    }

    /// Re-seeding replaces the arms 1:1: N re-seeds leave exactly one DHT arm and
    /// one relay arm, no leaked tokio tasks, and exactly ONE publish per interval
    /// (N leaked arms would produce N).
    #[tokio::test(start_paused = true)]
    async fn reseeding_neither_leaks_nor_double_spawns_tasks() {
        const RESEEDS: u32 = 5;

        let (did_method, identity, document, relay_url) = signing_identity().await;
        let publisher = publish_seam(&did_method);
        let live_state = published_slot(&publisher, &identity, document, relay_url).await;

        let counting_dht = Arc::new(CountingDhtClient::default());
        let relay = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(relay.as_ref());
        let republish = start_self_did_republishing(
            Arc::clone(&counting_dht),
            Arc::clone(&relay),
            live_state.subscribe(),
        )
        .await;
        settle_until("the initial DHT arm to publish", async || {
            counting_dht.count() >= 1
        })
        .await;

        let alive_before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();

        for n in 0..RESEEDS {
            let expected = counting_dht.count() + 1;
            republish_via_tier_change(&live_state, &publisher, &identity, n).await;
            // Each re-seed publishes immediately on the replacement arm.
            settle_until("the re-seeded DHT arm to publish", async || {
                counting_dht.count() >= expected
            })
            .await;

            assert_eq!(
                republish.manager.active_count().await,
                1,
                "re-seed {n} must REPLACE the DHT arm, never add a second one"
            );
            assert_eq!(
                republish.manager.active_relay_count().await,
                1,
                "re-seed {n} must REPLACE the relay arm, never add a second one"
            );
        }

        // Aborted arms are reaped as the runtime drops them; settle before
        // comparing so a lagging reap is not read as a leak.
        settle_until("aborted arms to be reaped", async || {
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
                <= alive_before
        })
        .await;
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            alive_before,
            "{RESEEDS} re-seeds must leave the live task count unchanged"
        );

        // Behavioural proof, independent of the task map: advance one full DHT
        // republish interval. One arm → exactly one publish. N leaked arms would
        // each fire in the same window.
        let before_window = counting_dht.count();
        tokio::time::advance(Duration::from_secs(
            scp_identity::republish::REPUBLISH_INTERVAL_SECS + 1,
        ))
        .await;
        settle_until("the surviving arm's next tick", async || {
            counting_dht.count() > before_window
        })
        .await;
        assert_eq!(
            counting_dht.count() - before_window,
            1,
            "exactly ONE arm survives {RESEEDS} re-seeds, so exactly one publish \
             lands per republish interval"
        );

        republish.stop().await;
    }

    /// `stop()` is a real barrier on a MULTI-THREAD runtime, even when a re-seed
    /// is in flight on another worker.
    ///
    /// `JoinHandle::abort` only *requests* cancellation. The observer's critical
    /// section (`seed_republish_arms` → `stop_all` → `start_republishing`) has no
    /// guaranteed yield point, so before `stop` joined the aborted handle the
    /// whole re-seed could complete on W2 *after* `stop_all` had drained the maps
    /// on W1 — detaching two arms that keep republishing this node's DID document
    /// (a §10.12.1 address disclosure) for the life of the process. The other
    /// re-seed tests are current-thread and cannot observe this.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_is_a_barrier_even_against_an_in_flight_reseed() {
        let (did_method, identity, document, relay_url) = signing_identity().await;
        let publisher = publish_seam(&did_method);
        let live_state = published_slot(&publisher, &identity, document, relay_url).await;

        let counting_dht = Arc::new(CountingDhtClient::default());
        let relay = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(relay.as_ref());
        let republish = start_self_did_republishing(
            Arc::clone(&counting_dht),
            Arc::clone(&relay),
            live_state.subscribe(),
        )
        .await;
        settle_until("the initial DHT arm to publish", async || {
            counting_dht.count() >= 1
        })
        .await;

        // Wake the observer and tear down immediately: `stop` races the re-seed.
        republish_via_tier_change(&live_state, &publisher, &identity, 1).await;
        republish.stop().await;

        // Nothing may publish after `stop` returned. A detached arm publishes
        // immediately when it is spawned, so a surviving one shows up here.
        let after_stop = counting_dht.count();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            counting_dht.count(),
            after_stop,
            "an arm survived shutdown and kept republishing this node's DID \
             document — `abort` alone is not a barrier"
        );
    }

    /// A re-seed that lands while an arm is MID-PUBLISH is safe: the in-flight
    /// tick is replaced, not duplicated, and the stale record it was asserting
    /// never completes.
    #[tokio::test(start_paused = true)]
    async fn reseed_racing_an_in_flight_tick_replaces_it_safely() {
        let (did_method, identity, document, relay_url) = signing_identity().await;
        let publisher = publish_seam(&did_method);
        let live_state = published_slot(&publisher, &identity, document, relay_url).await;
        let first = live_state.get().record.expect("startup record");

        // A DHT client whose publish PARKS until the test releases it — the arm
        // is genuinely mid-tick when the re-seed arrives.
        let gated = Arc::new(GatedDhtClient::default());
        let relay = Arc::new(TransportRelayPublisher::new());
        let _adapter = bind_recording_relay(relay.as_ref());
        let republish = start_self_did_republishing(
            Arc::clone(&gated),
            Arc::clone(&relay),
            live_state.subscribe(),
        )
        .await;

        settle_until("the first tick to enter publish", async || {
            gated.started() == vec![first.sequence]
        })
        .await;
        assert!(
            gated.completed().is_empty(),
            "the first tick is parked INSIDE publish — that is the race window"
        );

        // Re-seed while the tick is parked.
        republish_via_tier_change(&live_state, &publisher, &identity, 1).await;
        let second = live_state.get().record.expect("re-published record");
        settle_until("the replacement tick to enter publish", async || {
            gated.started() == vec![first.sequence, second.sequence]
        })
        .await;

        // Release both parked publishes. Only the replacement can complete: the
        // superseded one was dropped mid-await by the replace, which is the
        // desired outcome — it was asserting a record the node has replaced.
        gated.release();
        settle_until("the replacement tick to complete", async || {
            !gated.completed().is_empty()
        })
        .await;
        assert_eq!(
            gated.completed(),
            vec![second.sequence],
            "only the re-seeded tick completes; the superseded in-flight put is \
             dropped, never resurrected"
        );
        assert_eq!(
            republish.manager.active_count().await,
            1,
            "the race leaves exactly one DHT arm"
        );

        republish.stop().await;
    }

    /// Records every `publish` as `(public_key, seq)` so a test can count arm
    /// ticks and check which record each tick asserted.
    #[derive(Default)]
    struct CountingDhtClient {
        publishes: std::sync::Mutex<Vec<([u8; 32], u64)>>,
    }

    impl CountingDhtClient {
        fn count(&self) -> usize {
            self.publishes.lock().expect("publishes lock").len()
        }

        fn puts(&self) -> Vec<([u8; 32], u64)> {
            self.publishes.lock().expect("publishes lock").clone()
        }
    }

    impl scp_dht::DhtClient for CountingDhtClient {
        fn publish(
            &self,
            public_key: &[u8; 32],
            _signature: &[u8; 64],
            _value: &[u8],
            seq: u64,
        ) -> impl std::future::Future<Output = Result<(), scp_dht::DhtError>> + Send {
            self.publishes
                .lock()
                .expect("publishes lock")
                .push((*public_key, seq));
            async { Ok(()) }
        }

        /// Never used: these doubles exist to observe what the arms PUBLISH.
        /// An honest `Ok(None)` (nothing stored), never a fabricated record.
        async fn resolve(
            &self,
            _public_key: &[u8; 32],
        ) -> Result<Option<scp_dht::DhtRecord>, scp_dht::DhtError> {
            Ok(None)
        }
    }

    /// A DHT client whose `publish` parks until [`release`](Self::release), so a
    /// test can hold an arm mid-tick and re-seed underneath it.
    #[derive(Default)]
    struct GatedDhtClient {
        started: std::sync::Mutex<Vec<u64>>,
        completed: std::sync::Mutex<Vec<u64>>,
        gate: tokio::sync::Notify,
        open: std::sync::atomic::AtomicBool,
    }

    impl GatedDhtClient {
        fn started(&self) -> Vec<u64> {
            self.started.lock().expect("started lock").clone()
        }

        fn completed(&self) -> Vec<u64> {
            self.completed.lock().expect("completed lock").clone()
        }

        fn release(&self) {
            self.open.store(true, std::sync::atomic::Ordering::SeqCst);
            self.gate.notify_waiters();
        }
    }

    impl scp_dht::DhtClient for GatedDhtClient {
        fn publish(
            &self,
            _public_key: &[u8; 32],
            _signature: &[u8; 64],
            _value: &[u8],
            seq: u64,
        ) -> impl std::future::Future<Output = Result<(), scp_dht::DhtError>> + Send {
            self.started.lock().expect("started lock").push(seq);
            async move {
                while !self.open.load(std::sync::atomic::Ordering::SeqCst) {
                    self.gate.notified().await;
                }
                self.completed.lock().expect("completed lock").push(seq);
                Ok(())
            }
        }

        /// Never used: these doubles exist to observe what the arms PUBLISH.
        /// An honest `Ok(None)` (nothing stored), never a fabricated record.
        async fn resolve(
            &self,
            _public_key: &[u8; 32],
        ) -> Result<Option<scp_dht::DhtRecord>, scp_dht::DhtError> {
            Ok(None)
        }
    }

    /// B3 / §3.10.6: the production self-host `RepublishConfig` enables BOTH
    /// layers. (The mandated layer-disabled warning is emitted unconditionally by
    /// `RepublishConfig::disable_*` itself — see `scp-identity`'s
    /// `disabling_either_layer_always_logs_the_mandated_warning` — so it is not
    /// wired here at all.)
    #[test]
    fn self_host_republish_config_enables_both_layers() {
        let config = RepublishConfig::default();

        assert!(
            config.is_dht_enabled() && config.is_relay_enabled(),
            "the production path enables BOTH layers (§3.10.6 anti-segmentation); \
             an unbound relay is not a user opt-out"
        );
    }

    // -----------------------------------------------------------------------
    // The cycle belongs to the node, not to one caller
    //
    // ADR-003 §2 of `.docs/adrs/phase-1.md`: republishing "starts when an
    // identity is loaded". These two tests drive `Node::start_for_testing` —
    // the plain node front door, with no self-hosting serve loop anywhere in
    // the call chain — and assert that the node it returns is already keeping
    // its own DID record alive. Against the pre-fix code both fail: the cycle
    // was constructed in `self_host::serve_hosted_site`, so a node built
    // through the builder alone had no arms and re-put nothing, ever.
    // -----------------------------------------------------------------------

    /// A node whose DID method signs onto `dht`, started through the plain
    /// `Node::start_for_testing` path.
    ///
    /// `Reach::Local` skips the NAT probe (no network), and `DhtMode::Memory`
    /// is a publishing mode, so the builder performs the real startup publish
    /// and seeds the live slot from it.
    async fn start_plain_node(
        dht: &Arc<CountingDhtClient>,
    ) -> crate::ApplicationNode<scp_platform::in_memory::InMemoryStorage> {
        use crate::config::{IdentitySource, Node, NodeConfig, Reach};
        use scp_transport::native::storage::BlobStorageBackend;

        let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());
        let sign_fn = DidDht::<CountingDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(DidDht::with_client_and_signer(
            Arc::clone(dht),
            Arc::new(DidCache::new()),
            sign_fn,
        ));

        Node::start_for_testing(NodeConfig {
            bind_addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            dht: DhtMode::Memory,
            ..NodeConfig::defaults(
                Reach::Local,
                IdentitySource::Generate {
                    custody,
                    did_method,
                },
                scp_platform::in_memory::InMemoryStorage::new(),
                BlobStorageBackend::in_memory(),
            )
        })
        .await
        .expect("the plain node path starts")
    }

    /// A node built through `Node::start` alone keeps its own DID record alive:
    /// both arms are running, and the DHT arm has already re-put the exact
    /// record the startup publish signed.
    ///
    /// Re-putting is the whole point. Mainline DHT records expire, and pkarr
    /// performs no republish of its own, so a document that only the startup
    /// publish ever wrote stops resolving once its record lapses — and every
    /// identity behind that document stops resolving with it.
    #[tokio::test]
    async fn a_node_started_through_the_plain_path_keeps_its_did_record_alive() {
        let dht = Arc::new(CountingDhtClient::default());
        let node = start_plain_node(&dht).await;

        let record = node
            .published_did_record()
            .expect("DhtMode::Memory publishes, so the node stands behind a record");

        // The arm publishes immediately on seeding; yield until it lands.
        for _ in 0..50 {
            if dht.count() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let arms = node.active_republish_arms().await;
        assert_eq!(
            arms,
            ActiveArms { dht: 1, relay: 1 },
            "the plain node path must run BOTH layers (§3.10.6 anti-segmentation), \
             not only the self-hosting path"
        );

        let puts = dht.puts();
        assert!(
            puts.len() >= 2,
            "the startup publish is one put; the keep-alive arm owes at least one \
             more, and this node made {} in total",
            puts.len()
        );
        assert!(
            puts.iter()
                .skip(1)
                .all(|&(key, seq)| key == record.public_key && seq == record.sequence),
            "every keep-alive put must re-assert the node's OWN record under the \
             sequence the startup publish signed, and these did not: {puts:?}"
        );

        node.shutdown();
    }

    /// One node runs one cycle. Two cycles over one BEP44 record would each
    /// re-put under the sequence their own entry carries, so the record's
    /// monotonic counter would have two independent writers.
    ///
    /// Counted rather than asserted structurally: a paused clock advanced by one
    /// full DHT keep-alive interval must produce exactly ONE further put. Two
    /// cycles would produce two, and the assertion names that number.
    #[tokio::test(start_paused = true)]
    async fn a_node_runs_exactly_one_republish_cycle() {
        use scp_identity::republish::REPUBLISH_INTERVAL_SECS;

        let dht = Arc::new(CountingDhtClient::default());
        let node = start_plain_node(&dht).await;

        // Let the startup publish and the arm's immediate publish both land.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before = dht.count();
        assert_eq!(
            before, 2,
            "one startup publish plus one immediate keep-alive put; a second \
             cycle would have made this 3"
        );

        tokio::time::advance(Duration::from_secs(REPUBLISH_INTERVAL_SECS)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            dht.count(),
            before + 1,
            "one keep-alive interval must produce exactly one put — two would \
             mean two managers writing one BEP44 sequence"
        );

        node.shutdown();
    }

    /// `shutdown()` called from a thread that never entered the node's runtime
    /// still stops both arms.
    ///
    /// This is the shape the three FFI bridges use, and it is the shape a
    /// teardown built on `Handle::try_current()` got wrong.
    /// `RunningNode::shutdown` in `scp-ffi-common` is a plain synchronous method,
    /// and each bridge's node handle calls it from `Drop` as well — from the
    /// Python interpreter thread, the Node.js main thread, and the Swift/Kotlin
    /// caller thread. None of those ever entered the runtime the node was built
    /// on, so `try_current()` returns `Err` there; a teardown that trusted it
    /// aborted nothing and left both arms re-putting this node's address for the
    /// life of the process (§10.12.1).
    ///
    /// The node is built inside a multi-thread runtime and `shutdown()` is then
    /// called from a `std::thread` that is not one of its workers.
    #[test]
    fn shutdown_from_a_thread_outside_the_runtime_stops_both_arms() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime builds");

        let dht = Arc::new(CountingDhtClient::default());
        let node = Arc::new(runtime.block_on(start_plain_node(&dht)));

        assert_eq!(
            runtime.block_on(node.active_republish_arms()),
            ActiveArms { dht: 1, relay: 1 },
            "both arms run before shutdown"
        );

        let off_runtime = Arc::clone(&node);
        std::thread::spawn(move || {
            assert!(
                tokio::runtime::Handle::try_current().is_err(),
                "this thread must be outside every runtime — that is the FFI shape \
                 under test"
            );
            off_runtime.shutdown();
        })
        .join()
        .expect("shutdown thread panicked");

        // The stop is spawned onto the cycle's own runtime, so give that runtime
        // turns until it lands.
        let arms = runtime.block_on(async {
            for _ in 0..200 {
                let arms = node.active_republish_arms().await;
                if arms == (ActiveArms { dht: 0, relay: 0 }) {
                    return arms;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            node.active_republish_arms().await
        });

        assert_eq!(
            arms,
            ActiveArms { dht: 0, relay: 0 },
            "a shutdown from outside the runtime must leave no arm asserting this \
             node's DID record"
        );
    }

    /// `shutdown()` stops the arms. An arm that outlived shutdown would keep
    /// asserting this node's address on the DHT for the life of the process
    /// (§10.12.1).
    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_stops_both_republish_arms() {
        let dht = Arc::new(CountingDhtClient::default());
        let node = start_plain_node(&dht).await;

        assert_eq!(
            node.active_republish_arms().await,
            ActiveArms { dht: 1, relay: 1 },
            "both arms run before shutdown"
        );

        node.shutdown();

        assert_eq!(
            node.active_republish_arms().await,
            ActiveArms { dht: 0, relay: 0 },
            "shutdown() must leave no arm asserting this node's DID record"
        );
    }
}
