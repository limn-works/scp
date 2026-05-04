//! Transport abstraction trait and supporting types.
//!
//! The [`TransportAdapter`] trait defines the contract that all SCP transport
//! adapters must implement. It is deliberately thin: five async methods covering
//! send, subscribe, unsubscribe, query, and delete. SCP is transport-independent
//! -- no single transport is "primary."
//!
//! Supporting types:
//! - [`BlobId`] -- opaque blob identifier (SHA-256 hash of the blob).
//! - [`RoutingId`] -- per-context pseudonym used for routing.
//! - [`TransportEvent`] -- events yielded by a transport subscription stream.
//!
//! See ADR-005 in `.docs/adrs/phase-1.md` for the full transport abstraction design.

use std::pin::Pin;

use futures::Stream;
use scp_core::envelope::OuterEnvelope;

use crate::error::TransportError;
use crate::scoring::SuppressionWarning;

/// Opaque blob identifier -- the SHA-256 hash of the blob's wire bytes.
///
/// Returned by [`TransportAdapter::send`] to identify the stored envelope.
/// Used by [`TransportAdapter::delete`] to request deletion and by
/// [`TransportManager`](crate::TransportManager) for deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobId(pub [u8; 32]);

impl BlobId {
    /// Creates a new `BlobId` from a 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 32-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes a `BlobId` by SHA-256 hashing the given data.
    ///
    /// This is the canonical way to derive a `BlobId` from an envelope's
    /// wire bytes.
    #[must_use]
    pub fn from_sha256(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self(bytes)
    }
}

/// Per-context pseudonym used for routing.
///
/// Derived via `HMAC-SHA256` from the participant's identity key and the
/// context ID. Relays route envelopes by matching the outer envelope's
/// `routing_id` field against subscriptions keyed by `RoutingId`.
///
/// See ADR-002 for pseudonym derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingId(pub [u8; 32]);

impl RoutingId {
    /// Creates a new `RoutingId` from a 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 32-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Events yielded by a transport subscription stream.
///
/// A subscription stream (returned by [`TransportAdapter::subscribe`]) emits
/// these events. Callers should handle all variants:
///
/// - [`Envelope`](TransportEvent::Envelope) -- a received envelope.
/// - [`Error`](TransportEvent::Error) -- a transient transport error; the
///   stream may continue (the adapter handles reconnection).
/// - [`BackfillComplete`](TransportEvent::BackfillComplete) -- all stored
///   envelopes newer than the `since` timestamp have been delivered.
/// - [`Reconnected`](TransportEvent::Reconnected) -- the transport
///   reconnected; expect possible duplicate envelopes (deduplicate via
///   `blob_id`).
/// - [`Terminated`](TransportEvent::Terminated) -- the subscription was
///   terminated by the transport (e.g., relay shutdown).
#[derive(Debug)]
pub enum TransportEvent {
    /// A valid envelope received from the transport.
    Envelope(OuterEnvelope),

    /// Transport-level error on this subscription.
    ///
    /// The stream may continue after transient errors -- the adapter handles
    /// reconnection internally.
    Error(TransportError),

    /// Backfill of stored envelopes is complete.
    ///
    /// Only emitted if `since` was provided to
    /// [`TransportAdapter::subscribe`].
    BackfillComplete,

    /// The transport reconnected after a disconnection.
    ///
    /// Callers should expect possible duplicate envelopes and deduplicate
    /// via [`BlobId`].
    Reconnected,

    /// The subscription was terminated by the transport (e.g., relay shutdown).
    Terminated {
        /// Human-readable reason for the termination.
        reason: String,
    },

    /// A suppression was detected: a blob was delivered by fewer than half
    /// the context's relays within the cross-check window.
    ///
    /// The consuming layer should downgrade the reliability scores of relays
    /// that failed to deliver the blob.
    SuppressionDetected(SuppressionWarning),
}

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// A boxed, pinned, `Send`-safe stream of [`TransportEvent`]s.
///
/// Extracted as a type alias to keep the [`TransportAdapter::subscribe`]
/// signature readable.
pub type SubscriptionStream = Pin<Box<dyn Stream<Item = TransportEvent> + Send>>;

/// The transport abstraction trait that all SCP transport adapters implement.
///
/// This trait is deliberately thin: five async methods covering the full
/// lifecycle of envelope transport. Adapters map their transport-specific
/// semantics (WebSocket, Nostr relay, libp2p, etc.) onto this uniform
/// interface.
///
/// All methods return boxed futures so that the trait is dyn-compatible --
/// this allows [`TransportManager`](crate::TransportManager) to hold
/// `Box<dyn TransportAdapter>` instances. The trait requires `Send + Sync`
/// so that adapters can be shared across tokio tasks.
///
/// See ADR-005 in `.docs/adrs/phase-1.md` for design rationale.
///
/// # Implementors
///
/// Phase 1 provides a single adapter: the SCP native relay adapter (ADR-004).
/// Future phases add Nostr, Matrix, Hyperswarm, libp2p, and others.
pub trait TransportAdapter: Send + Sync {
    /// Send an outer envelope to the network.
    ///
    /// The adapter routes based on the envelope's `routing_id`. Returns the
    /// [`BlobId`] (SHA-256 hash) that identifies the stored envelope.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the adapter has no active
    /// connection, [`TransportError::SendFailed`] if the send operation fails,
    /// or [`TransportError::Timeout`] if the operation times out.
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>>;

    /// Subscribe to envelopes for a given routing ID.
    ///
    /// Returns a stream that yields [`TransportEvent`]s as they arrive.
    /// If `since` is provided, the adapter backfills with stored envelopes
    /// newer than that timestamp (epoch seconds) before switching to live
    /// delivery. A [`TransportEvent::BackfillComplete`] event marks the end
    /// of the backfill phase.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SubscriptionFailed`] if the subscription
    /// cannot be established, or [`TransportError::NotConnected`] if the
    /// adapter has no active connection.
    ///
    /// # Behavior on duplicate `routing_id`
    ///
    /// `subscribe` semantics on duplicate routing-id are not uniform across
    /// adapters; callers must not depend on either rejection or replacement.
    /// Track local subscription state and avoid issuing duplicate subscribes.
    /// See the follow-up tracking issue for the planned uniform contract.
    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>>;

    /// Unsubscribe from a routing ID.
    ///
    /// Stops delivery of events for the given routing ID. Any in-flight
    /// events may still be delivered before the stream terminates.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the adapter has no active
    /// connection.
    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>>;

    /// One-shot query for stored envelopes matching a routing ID.
    ///
    /// Returns all stored envelopes with the given routing ID, optionally
    /// filtered to those newer than `since` (epoch seconds). Unlike
    /// [`subscribe`](TransportAdapter::subscribe), this does not establish
    /// a live stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the adapter has no active
    /// connection, or [`TransportError::Timeout`] if the query times out.
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>>;

    /// Request deletion of a blob by its ID.
    ///
    /// Best-effort: untrusted transports may ignore this request. The caller
    /// should not assume the blob is actually deleted after this returns
    /// successfully.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if the adapter has no active
    /// connection, or [`TransportError::SendFailed`] if the delete request
    /// fails.
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn blob_id_from_sha256_is_deterministic() {
        let data = b"hello world";
        let id1 = BlobId::from_sha256(data);
        let id2 = BlobId::from_sha256(data);
        assert_eq!(id1, id2);
    }

    #[test]
    fn blob_id_from_sha256_differs_for_different_data() {
        let id1 = BlobId::from_sha256(b"hello");
        let id2 = BlobId::from_sha256(b"world");
        assert_ne!(id1, id2);
    }

    #[test]
    fn blob_id_new_roundtrip() {
        let bytes = [0xAA; 32];
        let id = BlobId::new(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn routing_id_new_roundtrip() {
        let bytes = [0xBB; 32];
        let id = RoutingId::new(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn routing_id_equality() {
        let a = RoutingId::new([0x01; 32]);
        let b = RoutingId::new([0x01; 32]);
        let c = RoutingId::new([0x02; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn blob_id_hash_is_consistent() {
        use std::collections::HashSet;
        let id1 = BlobId::new([0xCC; 32]);
        let id2 = BlobId::new([0xCC; 32]);
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }
}
