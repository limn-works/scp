//! The node's single live published-state slot, its single writer, and the DID
//! publish seam that feeds it (§10.12.1, §3.10.5 — SCP-243 / SCP-RELAYRES-004).
//!
//! A private module on purpose. Two things are confined to it, and both matter:
//!
//! - `LiveSlot::modify` is visible only inside it, and the node's one
//!   post-construction writer, [`apply_tier_change`], lives here beside it. An
//!   out-of-band write from anywhere else in `scp-node` is a compile error rather
//!   than a convention a reviewer has to enforce.
//! - The DID publish seam — the [`DidPublisher`] trait, its production impl
//!   `NodeDidPublisher`, the opaque [`NodePublisher`] handle, and
//!   [`seed_from_startup_publish`] — lives here too. `DidPublisher::publish` takes
//!   a [`PublishAuthorization`] whose only constructor is private to this module,
//!   so the publish operation is uncallable from anywhere else. Publishing this
//!   node's DID document is therefore reachable ONLY through
//!   [`seed_from_startup_publish`] (startup) or [`apply_tier_change`] (tier
//!   change), each of which seeds or advances the slot in the same step — so a
//!   publish that does not (re-)seed the slot cannot be written (AC-6).
//!
//! (The items below are `pub` *within* this private module, which is what
//! confines them to the crate — `pub(crate)` here would be the redundant spelling
//! of the same thing.)

use std::sync::Arc;

use scp_did::DidDocument;
use scp_identity::DidMethod;
use scp_identity::ScpIdentity;
use scp_identity::republish::RepublishEntry;
use scp_transport::nat::NatTierChange;

use crate::DhtMode;
use crate::NodeError;

/// Everything a running node stands behind, advanced as ONE value.
///
/// **This is the authoritative statement of the live-slot invariant; other sites
/// point here rather than restate it.**
///
/// # Why one shared value and not three fields captured at build time
///
/// None of these is fixed for the node's lifetime: a NAT tier change re-points
/// the relay endpoint, rewrites the `SCPRelay` entry in the document, and
/// re-publishes it ([`apply_tier_change`]). Anything that captured one of them
/// **by value** at build time froze it there — the dev-API identity endpoint
/// served a document naming a dead relay, the **public, unauthenticated**
/// `.well-known/scp` discovery document (§18.3) handed every peer an address the
/// node had moved off, and the republish keep-alive re-asserted a superseded
/// `seq` that BEP44 nodes and validating relays alike reject.
///
/// Holding all three in one value behind one [`LiveSlot`] closes the whole class:
/// a running node has exactly one of each, every reader holds a clone of the
/// *slot* rather than of its contents, and a change lands as a single write.
///
/// A **half-applied** change is genuinely unrepresentable: the three fields move
/// under one `send_modify`, so no reader can observe a mixed pair. A **stale
/// read** is not, and this module does not claim otherwise —
/// [`get`](LiveSlot::get) clones the value out, so a caller that stores the
/// clone in a field of its own has re-created the frozen snapshot by hand. What
/// is enforced is narrower and is the part that rotted: the node holds exactly
/// one of each value, and this module is its only writer.
///
/// # The address and the document are gated differently, on purpose
///
/// [`relay_url`](Self::relay_url) is the node's own live answer to "where am I",
/// not published state: a detected tier change means the external address has
/// ALREADY moved, so it advances whether or not the re-publish lands — otherwise
/// `.well-known/scp` keeps handing peers a dead endpoint for as long as
/// publishing fails. [`document`](Self::document) and [`record`](Self::record)
/// ARE the published state and advance only on a successful publish, so what the
/// node serves is what it actually asserted. They still move under one write.
#[derive(Clone, Debug)]
pub struct NodePublishedState {
    /// The DID document the node currently stands behind.
    ///
    /// This is the document of the last SUCCESSFUL publish *call* — which for a
    /// [`DhtMode::Disabled`](crate::DhtMode) node published nothing at all
    /// (`Ok(None)`, the honest non-disclosing success). So "the node serves this
    /// document" must not be read as "this document is retrievable from the
    /// network": only [`record`](Self::record) being `Some` says that.
    pub document: DidDocument,
    /// The relay URL the node is currently reachable at.
    pub relay_url: String,
    /// The signed BEP44 record the node most recently published, or `None` when
    /// it has published nothing: the honest absent state of a
    /// [`DhtMode::Disabled`](crate::DhtMode) node, never a synthesized record.
    pub record: Option<RepublishEntry>,
}

/// A value a running node holds exactly ONE of, handed to readers as a shared
/// slot rather than as a copy. See [`NodePublishedState`] for the invariant.
#[derive(Clone, Debug)]
pub struct LiveSlot<T: Clone>(Arc<tokio::sync::watch::Sender<T>>);

impl<T: Clone> LiveSlot<T> {
    /// A slot seeded with the value the node was built with.
    pub fn new(value: T) -> Self {
        Self(Arc::new(tokio::sync::watch::Sender::new(value)))
    }

    /// The current value.
    ///
    /// Cloned out rather than borrowed: a `watch` borrow guard held across an
    /// `.await` would block every writer, and the readers are async handlers.
    pub fn get(&self) -> T {
        self.0.borrow().clone()
    }

    /// A live view of the slot that yields every subsequent write.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<T> {
        self.0.subscribe()
    }

    /// Applies `update` under the slot's write lock and notifies readers.
    ///
    /// `send_modify` rather than a fallible `send`: this slot has readers rather
    /// than subscribers, so a write must not fail merely because none is parked.
    fn modify(&self, update: impl FnOnce(&mut T)) {
        self.0.send_modify(update);
    }
}

/// Points the document's preferred `SCPRelay` endpoint at `new_url`, appending
/// an entry when the document carries none.
///
/// The **first** `SCPRelay` entry is the subject's preferred relay (§18.2.3) and
/// the only one this node's own reachability owns; any further entries are
/// additional relays a tier change does not move.
///
/// [`push_relay_service`](crate::push_relay_service) is what ESTABLISHES that
/// position — it inserts the node's entry ahead of any the incoming document
/// already carried. `scp_did::DidDocument::add_relay_service` APPENDS and is
/// therefore not an establisher; it is used only by the domain builder, which
/// spawns no tier re-evaluation, so no document built that way ever reaches this
/// function. Do not wire a tier loop to that path without giving it the
/// positional installer too. Keying on position rather than on the address the
/// node currently advertises is what makes this idempotent and retry-stable: the
/// two are allowed to differ while a publish is failing, so an
/// address-keyed rewrite would match nothing on the retry and append a duplicate.
/// The predecessor was address-keyed and simply left the document untouched when
/// nothing matched, while the advertised address advanced regardless — so the
/// two could diverge permanently.
fn repoint_relay_service(document: &mut DidDocument, new_url: &str) {
    match document
        .service
        .iter_mut()
        .find(|svc| svc.service_type == "SCPRelay")
    {
        Some(svc) => new_url.clone_into(&mut svc.service_endpoint),
        None => crate::push_relay_service(document, new_url),
    }
}

/// The endpoint `document` advertises for the node, or `None` if it carries no
/// `SCPRelay` entry. The counterpart of [`repoint_relay_service`]'s key.
pub fn document_relay_url(document: &DidDocument) -> Option<String> {
    document.relay_service_urls().into_iter().next()
}

// ---------------------------------------------------------------------------
// The node's single DID-document publish seam (§3.10.5, SCP-RELAYRES-004 AC-6)
// ---------------------------------------------------------------------------

/// Proof that a [`DidPublisher::publish`] call is being made from INSIDE this
/// module — the module that also owns the live slot and writes it in the same
/// step as the publish.
///
/// Its single field is private to `published_state`, so a value can be minted
/// ONLY here. `DidPublisher::publish` takes one by value, which makes the publish
/// operation **uncallable anywhere else in the crate** — not by convention, but
/// by construction, and even for a hypothetical future `DidPublisher` impl. The
/// only two ways to publish this node's DID document are therefore
/// [`seed_from_startup_publish`] (startup) and [`apply_tier_change`] (NAT tier
/// change), each of which seeds or advances the live slot in the very same call.
/// AC-6 — "the DID publish and the published-state write are one indivisible
/// step" — is thus enforced by the type system, restoring and strengthening the
/// guarantee the live-slot collapse had reduced to a call-site convention.
pub struct PublishAuthorization(());

/// The node's **single** DID-document publish operation.
///
/// Object-safe where the full [`DidMethod`] trait is not (it returns
/// `impl Future`), so the tier re-evaluation background task (SCP-243) can hold
/// it without a generic parameter. Every path that publishes this node's DID
/// document — startup ([`seed_from_startup_publish`]) and tier change
/// ([`apply_tier_change`]) alike — goes through this one method, so the configured
/// [`DhtMode`] gate is honored by construction: a `DhtMode::Disabled` node
/// discloses nothing on *any* publish.
///
/// The [`PublishAuthorization`] parameter is what confines the CALL to this
/// module. The trait itself stays crate-visible so test doubles can implement it,
/// but no caller outside `published_state` can mint the authorization to invoke
/// it — so no site can publish without going through a seam that also (re-)seeds
/// the slot.
pub trait DidPublisher: Send + Sync {
    /// Publishes a DID document per the node's configured `DhtMode`, returning the
    /// signed record, or `Ok(None)` when the mode publishes nothing
    /// (`DhtMode::Disabled`) — the honest absent state, never a synthesized
    /// record.
    fn publish<'a>(
        &'a self,
        _auth: PublishAuthorization,
        identity: &'a ScpIdentity,
        document: &'a DidDocument,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<RepublishEntry>, NodeError>> + Send + 'a,
        >,
    >;
}

/// The production [`DidPublisher`]: a [`DidMethod`] and the node's `DhtMode`
/// bound together, so a publisher that publishes without honoring the mode is not
/// constructible. Private to this module — the only way to obtain one is
/// [`NodePublisher::new`].
struct NodeDidPublisher<D: DidMethod> {
    inner: Arc<D>,
    dht_mode: DhtMode,
}

impl<D: DidMethod + 'static> DidPublisher for NodeDidPublisher<D> {
    fn publish<'a>(
        &'a self,
        _auth: PublishAuthorization,
        identity: &'a ScpIdentity,
        document: &'a DidDocument,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<RepublishEntry>, NodeError>> + Send + 'a,
        >,
    > {
        Box::pin(crate::publish_did_document_for_mode(
            self.dht_mode,
            self.inner.as_ref(),
            identity,
            document,
        ))
    }
}

/// The opaque handle to the node's publish seam.
///
/// Clone-able so the builder and the tier task can each hold one, but it exposes
/// NO way to publish: its inner [`DidPublisher`] is private and that trait's
/// `publish` needs a [`PublishAuthorization`] only this module can mint.
/// Publishing is reachable solely through [`seed_from_startup_publish`] and
/// [`apply_tier_change`], which is what keeps the publish and the slot write one
/// indivisible step (AC-6).
#[derive(Clone)]
pub struct NodePublisher(Arc<dyn DidPublisher>);

impl NodePublisher {
    /// The production seam over a [`DidMethod`] in the configured [`DhtMode`].
    pub fn new<D: DidMethod + 'static>(did_method: Arc<D>, dht_mode: DhtMode) -> Self {
        Self(Arc::new(NodeDidPublisher {
            inner: did_method,
            dht_mode,
        }))
    }

    /// Test-only: wrap an arbitrary [`DidPublisher`] double so unit tests can
    /// drive the seam without a full signing `DidMethod`. Never compiled into a
    /// production build.
    #[cfg(test)]
    pub(crate) fn from_dyn(publisher: Arc<dyn DidPublisher>) -> Self {
        Self(publisher)
    }
}

/// Publishes the node's DID document through the seam AND constructs the seeded
/// live slot as ONE operation.
///
/// This is the ONLY way to perform the node's startup publish (`publish` is
/// uncallable outside this module), and it always returns a slot already carrying
/// the document and the record that publish produced. A caller therefore cannot
/// obtain a startup-seeded [`LiveSlot`] whose contents disagree with what was
/// actually published — the indivisibility AC-6 requires, enforced by the type
/// rather than by each builder remembering to re-seed. `relay_url` is taken by
/// reference because the caller still needs it (e.g. to log "node started")
/// after the slot has taken its own owned copy.
pub async fn seed_from_startup_publish(
    publisher: &NodePublisher,
    identity: &ScpIdentity,
    document: DidDocument,
    relay_url: &str,
) -> Result<LiveSlot<NodePublishedState>, NodeError> {
    let record = publisher
        .0
        .publish(PublishAuthorization(()), identity, &document)
        .await?;
    Ok(LiveSlot::new(NodePublishedState {
        document,
        relay_url: relay_url.to_owned(),
        record,
    }))
}

/// Handles a detected tier change: re-points the node's relay endpoint,
/// re-publishes the document through the node's publish seam, and advances the
/// node's state in ONE write.
///
/// The node's only post-construction writer. Nothing is returned and nothing is
/// handed back for a caller to store. Which fields move is gated per
/// [`NodePublishedState`]: the advertised address always, the document and the
/// signed record only on a successful publish — so a failed re-publish leaves
/// the node serving the document it actually published while still reporting the
/// address it actually moved to, and the next re-evaluation retries the publish.
/// A [`DhtMode::Disabled`](crate::DhtMode) node publishes nothing (`Ok(None)`)
/// and is still a success, so its document advances with `record` left at the
/// honest `None`.
pub async fn apply_tier_change(
    live_state: &LiveSlot<NodePublishedState>,
    new_relay_url: &str,
    trigger_reason: &str,
    publisher: &NodePublisher,
    identity: &ScpIdentity,
    event_tx: Option<&tokio::sync::mpsc::Sender<NatTierChange>>,
) {
    let current = live_state.get();
    let previous_relay_url = current.relay_url;
    let mut next_document = current.document;
    repoint_relay_service(&mut next_document, new_relay_url);

    match publisher
        .0
        .publish(PublishAuthorization(()), identity, &next_document)
        .await
    {
        Ok(signed) => {
            let sequence = signed.as_ref().map(|entry| entry.sequence);
            live_state.modify(|state| {
                new_relay_url.clone_into(&mut state.relay_url);
                state.document = next_document;
                if let Some(entry) = signed {
                    state.record = Some(entry);
                }
            });
            if let Some(sequence) = sequence {
                tracing::info!(
                    new_url = %new_relay_url, did = %identity.did, sequence,
                    "DID document republished with new relay URL"
                );
            } else {
                tracing::info!(
                    new_url = %new_relay_url, did = %identity.did,
                    "reachability tier changed; DID document NOT published \
                     (DhtMode::Disabled — not discoverable by design)"
                );
            }
        }
        Err(e) => {
            live_state.modify(|state| new_relay_url.clone_into(&mut state.relay_url));
            tracing::warn!(
                error = %e, new_url = %new_relay_url,
                "DID document republish failed after tier change; the node reports \
                 the address it has actually moved to, but its DID document still \
                 carries the published one — the next re-evaluation retries"
            );
        }
    }

    // Reports this node's reachability, so it fires exactly when the address
    // moved — including on a failed re-publish, whose retry tick finds the
    // address already advanced and must not re-announce it.
    //
    // `try_send`, never `send().await`. The receiver is a BOUNDED channel
    // (`mpsc::channel(16)`) held on `ApplicationNode`, reachable only through
    // `&mut` — which the serve path, holding the node as an `Arc`, structurally
    // cannot obtain. A consumer is therefore optional in practice, and because
    // the receiver stays alive the channel never closes, so `send().await` does
    // not fail on a full queue: it PARKS. The 17th address change would then
    // block this task forever inside `apply_tier_change`, which (a) stops tier
    // re-evaluation entirely — freezing the advertised address and leaving
    // `.well-known/scp` handing every peer a dead endpoint, the exact defect
    // this module exists to close — and (b) hangs `shutdown()`, whose
    // `stop_and_wait` joins on the task future being dropped. This stream is
    // OBSERVABILITY; reachability must never be a hostage to whether anyone is
    // draining it.
    if previous_relay_url != new_relay_url
        && let Some(tx) = event_tx
    {
        let event = NatTierChange::TierChanged {
            previous_relay_url,
            new_relay_url: new_relay_url.to_owned(),
            reason: trigger_reason.to_owned(),
        };
        match tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // A consumer exists but has stopped draining. The newest event is
                // the one that matters for a "where am I now" stream, so dropping
                // it is the wrong end of the queue — but an `mpsc::Sender` cannot
                // evict the oldest (`try_recv` is on the receiver), and the
                // latest-value type that models this correctly,
                // `tokio::sync::watch`, would change the public
                // `ApplicationNode::tier_change_rx` signature. The gap is at least
                // DETECTABLE rather than silent: every event carries
                // `previous_relay_url`, so a consumer that resumes sees it not
                // match the last `new_relay_url` it observed, and the
                // authoritative surfaces (`.well-known/scp`, the DID document,
                // `relay_url()`) never depended on this stream in the first place.
                tracing::warn!(
                    new_url = %new_relay_url,
                    "tier-change queue full: a consumer has stopped draining, so \
                     this event is dropped. The node's address still advanced — \
                     only the notification was lost."
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // The consumer is gone for good. Not a fault: the receiver is
                // optional and the authoritative surfaces already advanced.
                tracing::debug!(
                    new_url = %new_relay_url,
                    "tier-change event dropped: the TierChanged receiver is closed"
                );
            }
        }
    }
}
