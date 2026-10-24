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
//!   a [`PublishAuthorization`], and the only way to get one is
//!   [`ReservedDocument::authorize`], so the publish operation is uncallable
//!   from anywhere else. Publishing this node's DID document is therefore
//!   reachable ONLY through [`seed_from_startup_publish`] (startup, both
//!   modes) or [`apply_tier_change`] (tier change), each of which seeds or
//!   advances the slot in the same step — so a publish that does not
//!   (re-)seed the slot cannot be written (AC-6).
//! - Both publish the document as a [`ReservedDocument`], which only
//!   [`NodePublisher::reserve_push_routing_id`] builds, after it has moved the
//!   publisher's own relay handle, the relay's live URL handle the builder
//!   bound the publisher to, to the node's own entry and every tier 3 entry of
//!   that same document with the node's `bridgeTarget`. Neither takes a
//!   reservation or a handle from its caller, so a publish of a document whose
//!   tier 3 entries the node's own relay does not reserve cannot be written
//!   either (§10.7.1 "Tier 3 relays").
//!
//! (The items below are `pub` *within* this private module, which is what
//! confines them to the crate — `pub(crate)` here would be the redundant spelling
//! of the same thing.)

use std::sync::Arc;

use scp_did::{BridgeTarget, DidDocument, RelayService};
use scp_identity::DidMethod;
use scp_identity::ScpIdentity;
use scp_identity::republish::RepublishEntry;
use scp_transport::nat::NatTierChange;
use scp_transport::relay::push_gate::LiveRelayUrl;

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
/// [`relay`](Self::relay) is the node's own live answer to "where am I",
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
    /// The `SCPRelay` entry the node currently advertises: the relay URL it is
    /// reachable at and, on tier 3, the `bridgeTarget` the bridge relay forwards
    /// to (§18.2.1).
    pub relay: RelayService,
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

/// The entry `document` advertises for the node, or `None` if it carries no
/// `SCPRelay` entry a reader accepts. The counterpart of
/// [`DidDocument::set_preferred_relay`]'s key: the node's own entry is always
/// first ([`DidDocument::insert_preferred_relay`] puts it there at startup)
/// and always valid (it is written from a [`RelayService`]), so the first
/// accepted entry is the first entry.
///
/// A tier change rewrites that first entry in place rather than an entry
/// matching the address the node advertises: the two differ while a publish
/// is failing, so an address-keyed rewrite would match nothing on the retry
/// and append a duplicate. The domain builder appends through
/// [`DidDocument::add_relay_service`], which does not establish the position,
/// and spawns no tier task, so no document built that way reaches a tier
/// change.
pub fn document_relay_service(document: &DidDocument) -> Option<RelayService> {
    document.relay_services().into_iter().next()
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
///
/// Its only constructor is [`ReservedDocument::authorize`], inside the
/// private `reservation` module, so a publish also carries proof that the
/// relay reserves the document's entries.
pub use reservation::PublishAuthorization;

/// The node's **single** DID-document publish operation.
///
/// Object-safe where the full [`DidMethod`] trait is not (it returns
/// `impl Future`), so the tier re-evaluation background task (SCP-243) can hold
/// it without a generic parameter. Every path that SIGNS a new DID document for
/// this node — startup ([`seed_from_startup_publish`]) and tier change
/// ([`apply_tier_change`]) alike — goes through this one method, so the configured
/// [`DhtMode`] gate is honored by construction: a `DhtMode::Disabled` node
/// signs and discloses nothing on *any* publish.
///
/// # The keep-alive re-put reaches the DHT without this seam
///
/// The node's republish cycle (see the crate-private `republish` module) re-puts
/// an already-signed record through the DHT client directly, holding no
/// [`PublishAuthorization`] and reading no [`DhtMode`]. The mode gate still
/// covers it, but transitively rather than by construction: the cycle publishes
/// only what the live slot's `record` field holds, that field is written only by
/// the two paths above, and a `DhtMode::Disabled` node leaves it `None`, which
/// keeps the cycle dormant at zero arms. A future writer that seeds `record`
/// without going through this seam would break that chain, which is why
/// `LiveSlot::modify` is visible only inside this module.
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
        auth: PublishAuthorization,
        identity: &'a ScpIdentity,
        document: &'a DidDocument,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<RepublishEntry>, NodeError>> + Send + 'a,
        >,
    > {
        // Forward the authorization: `publish_did_document_for_mode` (the real
        // DHT/relay publish) also takes a `PublishAuthorization`, so it too is
        // uncallable outside this seam module (AC-6).
        Box::pin(crate::publish_did_document_for_mode(
            auth,
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
///
/// It also holds a clone of the live URL handle of the relay the node runs
/// (`LiveRelayUrl` is a shared `Arc`, so the clone is that relay's handle), and
/// [`reserve_push_routing_id`](Self::reserve_push_routing_id) moves only that
/// handle. Every reservation the node makes before a publish is therefore made
/// on the relay its publisher is bound to, never on a handle a caller minted
/// with the public `LiveRelayUrl::new` (§10.7.1 "Tier 3 relays": "its relay
/// reserves every one of those IDs before the node publishes the entries").
#[derive(Clone)]
pub struct NodePublisher {
    inner: Arc<dyn DidPublisher>,
    relay: LiveRelayUrl,
}

impl NodePublisher {
    /// The production seam over a [`DidMethod`] in the configured [`DhtMode`],
    /// bound to `relay`, the live URL handle of the relay the node runs
    /// (`RelayConfig::relay_url`).
    pub fn new<D: DidMethod + 'static>(
        did_method: Arc<D>,
        dht_mode: DhtMode,
        relay: LiveRelayUrl,
    ) -> Self {
        Self {
            inner: Arc::new(NodeDidPublisher {
                inner: did_method,
                dht_mode,
            }),
            relay,
        }
    }

    /// Test-only: wrap an arbitrary [`DidPublisher`] double, bound to `relay`,
    /// so unit tests can drive the seam without a full signing `DidMethod`.
    /// Never compiled into a production build.
    #[cfg(test)]
    pub(crate) fn from_dyn(publisher: Arc<dyn DidPublisher>, relay: LiveRelayUrl) -> Self {
        Self {
            inner: publisher,
            relay,
        }
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
/// rather than by each builder remembering to re-seed.
///
/// `entries` carries the document and the node's own entry. The function
/// first has `publisher` reserve every entry of that document the node
/// publishes on the publisher's own relay handle
/// ([`NodePublisher::reserve_push_routing_id`]), and publishes only the
/// [`ReservedDocument`] that reservation returns, through that same publisher.
/// The startup publish of either builder therefore cannot skip the
/// reservation, reserve on another relay's handle, or publish a document
/// another publisher reserved (§10.7.1 "Tier 3 relays").
pub async fn seed_from_startup_publish(
    publisher: &NodePublisher,
    identity: &ScpIdentity,
    entries: &PublishedEntries,
) -> Result<LiveSlot<NodePublishedState>, NodeError> {
    let reserved: ReservedDocument = publisher.reserve_push_routing_id(entries);
    let (auth, document) = reserved.authorize();
    let record = publisher.inner.publish(auth, identity, document).await?;
    let (relay, document) = reserved.into_parts();
    Ok(LiveSlot::new(NodePublishedState {
        document,
        relay,
        record,
    }))
}

pub use reservation::PublishedEntries;
use reservation::ReservedDocument;

/// The reservation that every publish of this node's DID document carries.
///
/// Private, so its fields and the [`PublishAuthorization`] constructor are
/// out of reach even for the rest of `published_state`: the only way to mint
/// an authorization is [`ReservedDocument::authorize`], and the only way to
/// build a [`ReservedDocument`] is
/// [`NodePublisher::reserve_push_routing_id`], which moves the publisher's
/// own relay handle first.
mod reservation {
    use scp_did::{BridgeTarget, DidDocument, RelayService};
    use scp_transport::relay::push_gate::{RelayUrl, ReservedRelayUrls};

    use super::NodePublisher;

    /// Proof that a [`DidPublisher::publish`](super::DidPublisher::publish)
    /// call publishes a document whose entries the relay reserves. See the
    /// re-export in the parent module.
    pub struct PublishAuthorization(());

    /// The `SCPRelay` entries a node is about to publish whose push routing
    /// IDs its relay reserves (§10.7.1 step 2, "Tier 3 relays"), together
    /// with the document they came from.
    ///
    /// It holds the node's own entry, the one its NAT tier or its domain
    /// yields, and every `SCPRelay` entry of the document the node is about
    /// to publish whose `bridgeTarget` is the node's own. An
    /// `IdentitySource::Explicit` document can carry further tier 3 entries
    /// with the node's target, one per bridge relay (§10.12.4 "Multiple
    /// bridges"). The own entry is a separate field, so the set is never
    /// empty and the reservation cannot fail.
    #[derive(Debug, Clone)]
    pub struct PublishedEntries {
        own: RelayService,
        bridged: Vec<RelayService>,
        document: DidDocument,
    }

    impl PublishedEntries {
        /// The node's own entry `own` and every `SCPRelay` entry of
        /// `document` whose `bridgeTarget` is `target`. `document` is the
        /// document the node is about to publish, and the value keeps a copy
        /// of it, which is the copy the node publishes; an entry it holds
        /// twice is reserved once.
        #[must_use]
        pub fn new(own: &RelayService, document: &DidDocument, target: BridgeTarget) -> Self {
            let bridged = document
                .relay_services()
                .into_iter()
                .filter(|entry| entry.bridge_target() == Some(target))
                .collect();
            Self {
                own: own.clone(),
                bridged,
                document: document.clone(),
            }
        }

        /// The reserved relay URL of every entry, the node's own first, each
        /// with its entry's `bridgeTarget`.
        fn relay_urls(&self) -> ReservedRelayUrls {
            ReservedRelayUrls::new(
                RelayUrl::from(&self.own),
                self.bridged.iter().map(RelayUrl::from),
            )
        }
    }

    /// A DID document whose entries the relay reserves, and the node's own
    /// entry, as [`NodePublisher::reserve_push_routing_id`] left them. The
    /// publish seam takes only this, so the document a node publishes is the
    /// document the reserved set was computed from. It is never named outside
    /// `published_state`.
    #[derive(Debug)]
    pub struct ReservedDocument {
        own: RelayService,
        document: DidDocument,
    }

    impl ReservedDocument {
        /// The authorization to publish this document, and the document.
        pub(in crate::published_state) const fn authorize(
            &self,
        ) -> (PublishAuthorization, &DidDocument) {
            (PublishAuthorization(()), &self.document)
        }

        /// The node's own entry and the document, for the live slot.
        pub(in crate::published_state) fn into_parts(self) -> (RelayService, DidDocument) {
            (self.own, self.document)
        }
    }

    impl NodePublisher {
        /// Moves the publisher's own relay handle, the live URL handle of the
        /// relay the node runs, to the entries in `published`, the entries
        /// the node is about to publish, so every listener of that relay
        /// reserves each entry's push routing ID before any client reads the
        /// entry (§10.7.1 step 2, "Tier 3 relays"), and returns the document
        /// those entries came from, ready to publish. It takes no handle: the
        /// only one it can move is the one [`NodePublisher::new`] bound the
        /// publisher to.
        ///
        /// Each entry maps to its own relay URL, keeping the entry's
        /// `bridgeTarget`: a direct entry reserves the
        /// `"scp-push-registration"` ID of its URL, and a tier 3 entry
        /// reserves its tier 3 push routing ID,
        /// `SHA-256("scp-push-bridge:" || bridge_url || bridge_target)`
        /// (`09-security-model.md` §9.18.2). The node never reserves the
        /// `"scp-push-registration"` ID of a bridge relay's URL, which belongs
        /// to the bridge relay. Every ID of the previous set that the new set
        /// lacks joins the handle's retired list, so the relay keeps refusing
        /// it without storing.
        #[must_use]
        pub(in crate::published_state) fn reserve_push_routing_id(
            &self,
            published: &PublishedEntries,
        ) -> ReservedDocument {
            let url = published.relay_urls();
            self.relay.set(url);
            ReservedDocument {
                own: published.own.clone(),
                document: published.document.clone(),
            }
        }
    }

    /// Compile-time pin of the reservation's signature: the method takes the
    /// publisher and the entries and nothing else, so a handle parameter added
    /// back to it stops the crate compiling.
    const _: fn(&NodePublisher, &PublishedEntries) -> ReservedDocument =
        NodePublisher::reserve_push_routing_id;
}

/// Where [`apply_tier_change`] reports a moved address: the reason the
/// re-evaluation ran, and the channel the [`NatTierChange`] event goes to, if
/// any. The reason is read only for that event.
#[derive(Debug, Clone, Copy)]
pub struct TierChangeReport<'a> {
    /// Why the re-evaluation ran, copied into the event.
    pub reason: &'a str,
    /// The node's tier-change channel, or `None` when no event is sent.
    pub events: Option<&'a tokio::sync::mpsc::Sender<NatTierChange>>,
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
    new_relay_url: &RelayService,
    bridge_target: BridgeTarget,
    publisher: &NodePublisher,
    identity: &ScpIdentity,
    report: TierChangeReport<'_>,
) {
    let new_url = new_relay_url.url();
    let current = live_state.get();
    let previous_relay_url = current.relay.url().to_owned();
    let mut next_document = current.document;
    next_document.set_preferred_relay(new_relay_url);
    // The relay moves before the publish: every listener of the relay the
    // publisher is bound to reserves the push routing ID of each entry
    // `next_document` will advertise for this node, the new entry's tier 3 ID
    // for a bridge entry and every other tier 3 entry with `bridge_target`,
    // before any client can read them, so a registration signed for one is
    // intercepted, never stored as a blob (§10.7.1 step 2, "Tier 3 relays").
    let entries = PublishedEntries::new(new_relay_url, &next_document, bridge_target);
    let reserved = publisher.reserve_push_routing_id(&entries);

    let (auth, document) = reserved.authorize();
    match publisher.inner.publish(auth, identity, document).await {
        Ok(signed) => {
            let sequence = signed.as_ref().map(|entry| entry.sequence);
            let (_, document) = reserved.into_parts();
            live_state.modify(|state| {
                state.relay = new_relay_url.clone();
                state.document = document;
                if let Some(entry) = signed {
                    state.record = Some(entry);
                }
            });
            if let Some(sequence) = sequence {
                tracing::info!(
                    new_url = %new_url, did = %identity.did, sequence,
                    "DID document republished with new relay URL"
                );
            } else {
                tracing::info!(
                    new_url = %new_url, did = %identity.did,
                    "reachability tier changed; DID document NOT published \
                     (DhtMode::Disabled — not discoverable by design)"
                );
            }
        }
        Err(e) => {
            live_state.modify(|state| state.relay = new_relay_url.clone());
            tracing::warn!(
                error = %e, new_url = %new_url,
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
    // block this task forever inside `apply_tier_change`, which stops tier
    // re-evaluation entirely — freezing the advertised address and leaving
    // `.well-known/scp` handing every peer a dead endpoint, the exact defect
    // this module exists to close. This stream is
    // OBSERVABILITY; reachability must never be a hostage to whether anyone is
    // draining it.
    if previous_relay_url != new_url
        && let Some(tx) = report.events
    {
        let event = NatTierChange::TierChanged {
            previous_relay_url,
            new_relay_url: new_url.to_owned(),
            reason: report.reason.to_owned(),
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
                    new_url = %new_url,
                    "tier-change queue full: a consumer has stopped draining, so \
                     this event is dropped. The node's address still advanced — \
                     only the notification was lost."
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // The consumer is gone for good. Not a fault: the receiver is
                // optional and the authoritative surfaces already advanced.
                tracing::debug!(
                    new_url = %new_url,
                    "tier-change event dropped: the TierChanged receiver is closed"
                );
            }
        }
    }
}

/// Test-only: the plain (no `bridgeTarget`) relay entry for `url`, which every
/// test fixture names by a canonical relay URL.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub fn test_relay(url: &str) -> RelayService {
    RelayService::direct(
        scp_did::RelayEndpoint::new(url).expect("every test fixture names a canonical relay URL"),
    )
}
