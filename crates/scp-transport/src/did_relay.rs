//! Relay public-record DID path (Model A, §9.10.12) — the concrete READ and
//! WRITE halves of the dual-layer relay resolution layer.
//!
//! `scp-identity` defines the relay abstractions
//! ([`RelayQuerier`](scp_identity::resolution::RelayQuerier) for the READ side,
//! [`RelayPublisher`](scp_identity::republish::RelayPublisher) for the WRITE
//! side) but cannot implement them against a relay: `scp-transport` depends on
//! `scp-identity`, so a relay-talking impl there would form a dependency cycle
//! (§3.10.12). This module supplies the concrete implementations here, where the
//! [`TransportManager`] and its raw public-record path (`publish_raw` /
//! `query_raw`, §9.10.12) live.
//!
//! Both impls read the live [`TransportManager`] through a [`LiveTransport`]
//! handle — a late-binding slot the FFI bridges populate at
//! `transport_connect` time. Before connect (or after disconnect) the handle is
//! empty and both operations **fail closed**: the querier returns `Ok(None)`
//! (an honest not-found, never a fabricated document) and the publisher returns
//! a typed [`IdentityError::RelayPublishFailed`].

use std::sync::Arc;
use std::sync::RwLock;

use tracing::{debug, warn};

use scp_core::envelope::scpr;
use scp_identity::IdentityError;
use scp_identity::republish::RelayPublisher;
use scp_identity::resolution::{RelayQuerier, RelayQueryRecord};

use crate::manager::TransportManager;
use crate::traits::RoutingId;

/// A cheaply-cloneable, late-binding handle to the live [`TransportManager`].
///
/// The transport manager is created only when a relay connection is
/// established (`transport_connect`), which happens *after* the DID resolver and
/// republisher are constructed. `LiveTransport` bridges that ordering: the
/// resolver/publisher are handed a clone of this handle at construction, and it
/// resolves to a live manager once one is set — or stays empty (fail closed) if
/// no relay is connected.
///
/// Cloning shares the same underlying slot (`Arc<RwLock<..>>`), so a manager set
/// through one clone is visible through all of them. This is the mechanism that
/// lets `scp-transport`'s relay impls read a manager owned by the FFI bridge
/// instance without a dependency cycle or a global.
#[derive(Clone, Default)]
pub struct LiveTransport {
    inner: Arc<RwLock<Option<Arc<TransportManager>>>>,
}

impl LiveTransport {
    /// Creates an empty handle (no transport manager set yet).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current transport manager, if one is set.
    ///
    /// Takes a SHORT read-lock, clones the inner `Arc` out, and releases the
    /// lock before returning — so the returned `Arc` is safe to hold across an
    /// `.await` (the lock guard is never held across a suspension point). A
    /// poisoned lock is treated as "unset" (fail closed).
    #[must_use]
    pub fn current(&self) -> Option<Arc<TransportManager>> {
        self.inner.read().ok().and_then(|guard| guard.clone())
    }

    /// Returns the shared inner slot so an owner (the FFI bridge instance) can
    /// apply its own locking policy — poison handling, `Arc::get_mut` for
    /// exclusive access, etc. — while still sharing the same underlying state
    /// with every clone of this handle.
    #[must_use]
    pub fn slot(&self) -> &RwLock<Option<Arc<TransportManager>>> {
        &self.inner
    }
}

/// Upper bound on the number of decodable DID-record candidates the querier
/// collects per routing ID.
///
/// DID resolution needs only enough candidates to find the one valid record;
/// capping bounds the work an adversary (or a misbehaving/greedy relay) can
/// impose by planting many well-framed blobs at a DID-derivable routing ID
/// (defense-in-depth alongside the `query_raw` wire `limit`).
pub const MAX_RELAY_CANDIDATES: usize = 16;

// ---------------------------------------------------------------------------
// READ half — TransportRelayQuerier
// ---------------------------------------------------------------------------

/// Concrete single-relay [`RelayQuerier`] over the live transport (§3.10.4,
/// §9.10.12).
///
/// Performs the relay QUERY via the public-record `query_raw` path.
///
/// SCPR-decodes
/// each returned raw blob as a kind-1 DID-record frame (§9.10.12), and returns
/// **all** decodable candidates' `(value, signature, seq)` triples (up to
/// [`MAX_RELAY_CANDIDATES`]). Malformed (non-decodable) blobs are skipped exactly
/// as an invalid DHT record is (§3.10.4) — never trusted, never partially
/// parsed. **No BEP44 verification** happens here: framing grants no authority;
/// the composer ([`RealMultiRelayQuerier`](scp_identity::RealMultiRelayQuerier))
/// verifies each candidate and picks the first valid one.
///
/// Returning ALL candidates (not just the first decodable one) is what defeats
/// the intra-relay shadow attack: a decodable-but-bad-signature frame planted
/// before the genuine record cannot suppress it (§3.10.8). When no transport is
/// connected the querier fails closed with an empty `Vec`.
pub struct TransportRelayQuerier {
    live: LiveTransport,
}

impl TransportRelayQuerier {
    /// Creates a querier over the given live-transport handle.
    #[must_use]
    pub const fn new(live: LiveTransport) -> Self {
        Self { live }
    }
}

// Trait uses RPITIT with an explicit `+ Send` bound; a manual `impl Future` is
// required to guarantee the future is `Send`.
#[allow(clippy::manual_async_fn)]
impl RelayQuerier for TransportRelayQuerier {
    fn query(
        &self,
        relay_url: &str,
        routing_id: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<RelayQueryRecord>, IdentityError>> + Send {
        let live = self.live.clone();
        let relay_url = relay_url.to_owned();
        let routing_id = RoutingId::new(*routing_id);

        async move {
            // Fail closed: no relay connected => honest empty (no candidates).
            let Some(manager) = live.current() else {
                debug!(
                    relay_url,
                    "no transport connected — relay query fails closed (empty)"
                );
                return Ok(Vec::new());
            };

            let blobs = manager.query_raw(&routing_id).await.map_err(|e| {
                IdentityError::RelayQueryFailed(format!("relay query_raw failed: {e}"))
            })?;

            // SCPR-decode each raw blob into a candidate. Return EVERY decodable
            // candidate (up to MAX_RELAY_CANDIDATES) so the composer can skip a
            // bad-signature frame co-located before the valid one (§3.10.8). Skip
            // non-decodable blobs (§3.10.4 — malformed framing is discarded).
            let mut candidates = Vec::new();
            for blob in blobs {
                match scpr::decode_did_record(&blob) {
                    Ok(record) => {
                        candidates.push(RelayQueryRecord {
                            value: record.value,
                            signature: record.signature,
                            seq: record.seq,
                        });
                        if candidates.len() >= MAX_RELAY_CANDIDATES {
                            debug!(
                                relay_url,
                                cap = MAX_RELAY_CANDIDATES,
                                "reached relay candidate cap — stopping collection"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(relay_url, error = %e, "relay blob failed SCPR decoding — skipping");
                    }
                }
            }

            Ok(candidates)
        }
    }
}

// ---------------------------------------------------------------------------
// WRITE half — TransportRelayPublisher
// ---------------------------------------------------------------------------

/// Concrete [`RelayPublisher`] over the live transport (§3.10.5, §9.10.12).
///
/// Publishes the (already SCPR-framed) blob as a RAW relay blob via the
/// public-record `publish_raw` path — never wrapped in an `OuterEnvelope`. The
/// caller (the republish loop / healing publisher) is responsible for wrapping
/// the `(value, signature, seq)` triple in an SCPR kind-1 frame before calling
/// `publish`. When no transport is connected the publisher fails closed with a
/// typed [`IdentityError::RelayNotConnected`] (distinct from
/// [`IdentityError::RelayPublishFailed`], which signals an actual failure of a
/// connected relay — so callers can log the expected no-transport interim
/// quietly and alarm only on real rejections).
pub struct TransportRelayPublisher {
    live: LiveTransport,
}

impl TransportRelayPublisher {
    /// Creates a publisher over the given live-transport handle.
    #[must_use]
    pub const fn new(live: LiveTransport) -> Self {
        Self { live }
    }
}

// Trait uses RPITIT with an explicit `+ Send` bound; a manual `impl Future` is
// required to guarantee the future is `Send`.
#[allow(clippy::manual_async_fn)]
impl RelayPublisher for TransportRelayPublisher {
    fn publish(
        &self,
        routing_id: &[u8; 32],
        blob_ttl: u64,
        blob: &[u8],
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        let live = self.live.clone();
        let routing_id = RoutingId::new(*routing_id);
        let blob = blob.to_vec();

        async move {
            // Fail closed: no relay connected => typed `RelayNotConnected`, never
            // a silent success against a nonexistent backend. Distinct from
            // `RelayPublishFailed` so best-effort callers can log the expected
            // no-transport interim quietly (the DHT layer stays authoritative).
            let Some(manager) = live.current() else {
                return Err(IdentityError::RelayNotConnected(
                    "no transport connected — cannot publish DID record to relay".to_owned(),
                ));
            };

            manager
                .publish_raw(&routing_id, blob_ttl, blob)
                .await
                .map(|_blob_id| ())
                .map_err(|e| {
                    IdentityError::RelayPublishFailed(format!("relay publish_raw failed: {e}"))
                })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn querier_fails_closed_when_transport_unset() {
        let live = LiveTransport::new();
        let querier = TransportRelayQuerier::new(live);
        let result = querier
            .query("wss://relay.example.com/scp/v1", &[7u8; 32])
            .await
            .expect("fail-closed query returns Ok, not Err");
        assert!(result.is_empty(), "no transport => no candidates");
    }

    #[tokio::test]
    async fn publisher_fails_closed_when_transport_unset() {
        let live = LiveTransport::new();
        let publisher = TransportRelayPublisher::new(live);
        let result = publisher.publish(&[7u8; 32], 604_800, b"blob").await;
        assert!(
            matches!(result, Err(IdentityError::RelayNotConnected(_))),
            "no transport => typed RelayNotConnected, never silent success or a generic failure"
        );
    }

    #[test]
    fn live_transport_clone_shares_slot() {
        let a = LiveTransport::new();
        let b = a.clone();
        // Both clones observe the same empty slot.
        assert!(a.current().is_none());
        assert!(b.current().is_none());
        // Slots are the same allocation.
        assert!(std::ptr::eq(a.slot(), b.slot()));
    }
}
