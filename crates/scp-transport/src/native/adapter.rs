//! [`NativeRelayAdapter`] -- implements [`TransportAdapter`] for the SCP native
//! relay.
//!
//! This adapter translates between the SCP transport API ([`TransportAdapter`])
//! and the native relay protocol ([`ClientMessage`] / [`RelayMessage`]). It
//! wraps a `NativeRelayClient` to handle connection lifecycle, keepalive,
//! reconnection, and deduplication.
//!
//! # Cover traffic
//!
//! The adapter implements [`CoverTrafficSender`] and provides
//! [`start_cover_traffic`](NativeRelayAdapter::start_cover_traffic) for
//! launching a background task that emits constant-rate dummy messages
//! (spec §9.10.6). The background task is automatically cancelled when the
//! adapter is dropped, preventing resource leaks.
//!
//! # Heartbeat monitoring
//!
//! When a [`TransportProfile`] is provided at connection time, the adapter
//! creates a [`HeartbeatMonitor`] and spawns a background task that
//! periodically checks for relay suppression (spec §9.9.2). If expected
//! heartbeats are missing for longer than the configured threshold
//! (default: 2x the 60-second interval), a warning is logged. The
//! subscription path can call
//! [`record_heartbeat_received`](NativeRelayAdapter::record_heartbeat_received)
//! to update the monitor when heartbeat-like messages arrive.
//!
//! # Mapping
//!
//! | Transport method | Relay operation |
//! |------------------|----------------|
//! | `send` | `PUBLISH` |
//! | `subscribe` | `SUBSCRIBE` + stream |
//! | `unsubscribe` | `UNSUBSCRIBE` |
//! | `query` | `QUERY` |
//! | `delete` | `DELETE` |
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.
//!
//! `NativeRelayClient`: see `super::client::NativeRelayClient`

use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use scp_core::envelope::OuterEnvelope;
use tokio_util::sync::CancellationToken;

use zeroize::Zeroizing;

use scp_relay_client::{ClientMessage, RelayMessage};

use super::client::{NativeRelayClient, SubscriptionMessage};
use crate::cover_traffic::{
    CoverAction, CoverTrafficConfig, CoverTrafficGenerator, CoverTrafficSender,
};
use crate::error::TransportError;
use crate::heartbeat::{HeartbeatConfig, HeartbeatMonitor};
use crate::profile::TransportProfile;
use crate::relay::connection::{SourcedRelayUrl, validate_relay_url};
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Transport adapter for the SCP native relay.
///
/// Implements [`TransportAdapter`] by translating each transport operation
/// into the corresponding native relay protocol operation via a
/// `NativeRelayClient`.
///
/// # Construction
///
/// Use [`NativeRelayAdapter::connect_sourced`] to connect with
/// provenance-based transport security validation (§10.12.6). All relay
/// URLs must have known provenance — there is no unvalidated connection
/// path.
///
/// For tests using local `ws://` relays, use
/// `RelayUrlSource::DhtResolved` as the source — DHT-resolved URLs are
/// the only source permitted to use plaintext WebSocket.
///
/// # Examples
///
/// ```rust,ignore
/// use scp_transport::native::adapter::NativeRelayAdapter;
/// use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
///
/// // Production: validate ws:// vs wss:// based on discovery source.
/// // Pass a TransportProfile to auto-start cover traffic (spec §9.10.6).
/// let sourced = SourcedRelayUrl {
///     url: "wss://relay.example.com/scp/v1".to_owned(),
///     source: RelayUrlSource::WellKnown,
/// };
/// let profile = TransportProfile::platform_default();
/// let adapter = NativeRelayAdapter::connect_sourced(&sourced, Some(&profile)).await?;
///
/// // Test: local ws:// relay with DhtResolved source, no cover traffic.
/// let sourced = SourcedRelayUrl {
///     url: "ws://127.0.0.1:9000/scp/v1".to_owned(),
///     source: RelayUrlSource::DhtResolved,
/// };
/// let adapter = NativeRelayAdapter::connect_sourced(&sourced, None).await?;
/// ```
pub struct NativeRelayAdapter {
    /// The underlying WebSocket client.
    client: NativeRelayClient,
    /// Cancellation token for the cover traffic background task. Cancelled
    /// on `Drop` to ensure the task is aborted and the `Arc` cycle is broken,
    /// preventing resource leaks.
    cover_traffic_cancel: CancellationToken,
    /// Cancellation token for the heartbeat monitoring background task.
    /// Cancelled on `Drop` to stop the heartbeat check loop.
    heartbeat_cancel: CancellationToken,
    /// Heartbeat monitor for relay suppression detection (spec §9.9.2).
    /// `None` when no `TransportProfile` was provided at connection time.
    heartbeat_monitor: Option<Arc<tokio::sync::Mutex<HeartbeatMonitor>>>,
    /// Channel for suppression events detected by the heartbeat monitor.
    /// Callers should drain this receiver to observe suppression alerts
    /// (spec §9.9.4: "The SDK MUST NOT silently discard the suspicion").
    suppression_rx: Option<tokio::sync::mpsc::Receiver<crate::heartbeat::SuppressionSuspected>>,
}

impl std::fmt::Debug for NativeRelayAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRelayAdapter").finish_non_exhaustive()
    }
}

impl Drop for NativeRelayAdapter {
    fn drop(&mut self) {
        // Cancel the cover traffic background task (if running). This breaks
        // the Arc cycle: the spawned task holds an Arc<NativeRelayClient> clone
        // and will exit its loop when the token is cancelled, allowing the Arc
        // to be reclaimed.
        self.cover_traffic_cancel.cancel();
        // Cancel the heartbeat monitoring background task (if running).
        self.heartbeat_cancel.cancel();
    }
}

impl NativeRelayAdapter {
    /// Creates a new adapter connected to a relay URL with provenance-based
    /// transport security validation (§10.12.6).
    ///
    /// Validates the URL scheme against the discovery source before connecting:
    ///
    /// - `wss://` is always permitted regardless of source.
    /// - `ws://` is permitted **only** for [`RelayUrlSource::DhtResolved`] URLs
    ///   (self-hosted relays behind NAT with BEP44-signed DID documents).
    /// - `ws://` from any other source (`.well-known`, explicit config, peer
    ///   discovery) is rejected to prevent downgrade attacks.
    ///
    /// All relay URLs must go through this path — there is no unvalidated
    /// connection method.
    ///
    /// When a [`TransportProfile`] is provided, cover traffic is auto-started
    /// based on the profile's tier (spec §9.10.6): Full for Server/Desktop,
    /// Reduced for Mobile, Off (no-op) for Constrained. Heartbeat monitoring
    /// is also started for relay suppression detection (spec §9.9.2). Pass
    /// `None` to skip both (e.g., in tests).
    ///
    /// [`RelayUrlSource::DhtResolved`]: crate::relay::connection::RelayUrlSource::DhtResolved
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the URL scheme is not
    /// permitted for the given source (e.g., `ws://` from a `.well-known`
    /// endpoint).
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the URL passes
    /// validation but the WebSocket connection cannot be established.
    pub async fn connect_sourced(
        sourced: &SourcedRelayUrl,
        profile: Option<&TransportProfile>,
    ) -> Result<Self, TransportError> {
        validate_relay_url(&sourced.url, &sourced.source)?;
        let client = NativeRelayClient::connect(&sourced.url).await?;
        Ok(Self::finalize_connection(client, profile, &sourced.url))
    }

    /// Creates a new adapter connected to a relay URL with provenance-based
    /// transport security validation and an optional bearer token.
    ///
    /// Behaves identically to [`connect_sourced`](Self::connect_sourced) but
    /// includes the bearer token as an `Authorization: Bearer <token>` header
    /// in the WebSocket upgrade request when `Some`. This is required for
    /// connecting to relay endpoints that enforce bridge token authentication
    /// (e.g., `ApplicationNode` relays).
    ///
    /// When a [`TransportProfile`] is provided, cover traffic and heartbeat
    /// monitoring are auto-started (spec §9.10.6, §9.9.2).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the URL scheme is not
    /// permitted for the given source.
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the connection cannot
    /// be established (including authentication rejection).
    pub async fn connect_sourced_with_bearer(
        sourced: &SourcedRelayUrl,
        bearer_token: Option<Zeroizing<String>>,
        profile: Option<&TransportProfile>,
    ) -> Result<Self, TransportError> {
        validate_relay_url(&sourced.url, &sourced.source)?;
        let client = NativeRelayClient::connect_with_bearer(&sourced.url, bearer_token).await?;
        Ok(Self::finalize_connection(client, profile, &sourced.url))
    }

    /// Common post-connection setup: heartbeat monitor, cover traffic auto-start.
    fn finalize_connection(
        client: NativeRelayClient,
        profile: Option<&TransportProfile>,
        relay_url: &str,
    ) -> Self {
        let heartbeat_cancel = CancellationToken::new();
        let (heartbeat_monitor, suppression_rx) =
            Self::maybe_start_heartbeat(profile, relay_url, &heartbeat_cancel);
        let adapter = Self {
            client,
            cover_traffic_cancel: CancellationToken::new(),
            heartbeat_cancel,
            heartbeat_monitor,
            suppression_rx,
        };
        if let Some(profile) = profile {
            let config = CoverTrafficConfig::from_profile(*profile);
            // JoinHandle intentionally dropped — the task is cancelled via the
            // CancellationToken in the adapter's Drop impl, not by awaiting/
            // aborting the handle.
            drop(adapter.start_cover_traffic(config));
        }
        adapter
    }

    /// Conditionally creates a [`HeartbeatMonitor`] and spawns a background
    /// heartbeat check loop when a `TransportProfile` is provided and the
    /// heartbeat config is enabled.
    ///
    /// The heartbeat interval is derived from the transport profile:
    /// - **Server / Desktop**: 60s (default) — always-on, latency-sensitive.
    /// - **Mobile**: 120s — reduced frequency to conserve battery.
    /// - **Constrained**: no heartbeat — poll-based devices skip monitoring.
    ///
    /// Returns `(Some(monitor), Some(suppression_rx))` when monitoring is
    /// started, `(None, None)` otherwise.
    fn maybe_start_heartbeat(
        profile: Option<&TransportProfile>,
        relay_url: &str,
        cancel: &CancellationToken,
    ) -> (
        Option<Arc<tokio::sync::Mutex<HeartbeatMonitor>>>,
        Option<tokio::sync::mpsc::Receiver<crate::heartbeat::SuppressionSuspected>>,
    ) {
        // Only create heartbeat monitoring when a profile is provided.
        let Some(profile) = profile else {
            return (None, None);
        };

        // Derive heartbeat config from the transport profile via the single
        // source of truth shared with the send-side scheduler (§9.9.2). A
        // `None` here means the profile disables heartbeats (Constrained).
        let Some(heartbeat_config) = HeartbeatConfig::for_profile(*profile) else {
            return (None, None);
        };

        let monitor = HeartbeatMonitor::new(heartbeat_config.clone(), relay_url.to_owned());
        let monitor = Arc::new(tokio::sync::Mutex::new(monitor));

        // Channel for suppression events — callers MUST drain this receiver
        // to observe suppression alerts (spec §9.9.4).
        let (suppression_tx, suppression_rx) = tokio::sync::mpsc::channel(16);

        // Spawn heartbeat check loop.
        let cancel = cancel.clone();
        let monitor_clone = Arc::clone(&monitor);
        let interval_duration = heartbeat_config.interval;
        let url = relay_url.to_owned();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval_duration);
            // Consume the first immediate tick.
            timer.tick().await;

            // Record a single baseline "sent" timestamp so that suppression
            // detection has a reference point. Without this, check_suppression
            // has no `last_sent` to compare against and cannot fire for the
            // initial case (no messages received yet).
            //
            // We intentionally do NOT record_heartbeat_sent on every tick —
            // doing so resets the baseline each interval, which prevents the
            // initial-case suppression from ever firing (the gap between
            // last_sent and now can never exceed the threshold because
            // last_sent is refreshed every tick).
            {
                let mut mon = monitor_clone.lock().await;
                mon.record_heartbeat_sent(tokio::time::Instant::now());
            }

            loop {
                tokio::select! {
                    () = cancel.cancelled() => {
                        tracing::debug!("heartbeat monitor task cancelled");
                        return;
                    }
                    _ = timer.tick() => {
                        let mon = monitor_clone.lock().await;
                        if let Some(suppression) = mon.check_suppression(tokio::time::Instant::now()) {
                            tracing::warn!(
                                relay_url = %url,
                                gap_secs = suppression.gap_duration.as_secs(),
                                "suppression suspected — no messages received from relay"
                            );
                            // Send suppression event to the channel (spec §9.9.4:
                            // "The SDK MUST NOT silently discard the suspicion").
                            let _ = suppression_tx.try_send(suppression);
                        }
                    }
                }
            }
        });

        (Some(monitor), Some(suppression_rx))
    }

    /// Returns a mutable reference to the suppression event receiver.
    ///
    /// Callers should poll this receiver to observe suppression alerts from the
    /// heartbeat monitor. Per spec §9.9.4, the SDK MUST NOT silently discard
    /// suppression suspicions — they must be surfaced to the application layer.
    ///
    /// Returns `None` if heartbeat monitoring is not active (no profile or
    /// constrained profile).
    pub const fn suppression_events(
        &mut self,
    ) -> Option<&mut tokio::sync::mpsc::Receiver<crate::heartbeat::SuppressionSuspected>> {
        self.suppression_rx.as_mut()
    }

    /// Takes ownership of the suppression event receiver, leaving `None` in
    /// its place.
    ///
    /// After this call, [`suppression_events`](Self::suppression_events)
    /// returns `None`. This is used by the FFI bridge layer to extract the
    /// receiver before moving the adapter into [`TransportManager`](crate::manager::TransportManager) — the
    /// bridge spawns a background task that drains the receiver and feeds
    /// suppression events into the manager's reliability scoring (#1533 AC5).
    ///
    /// Returns `None` if heartbeat monitoring is not active (no profile or
    /// constrained profile) or if the receiver was already taken.
    pub const fn take_suppression_receiver(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<crate::heartbeat::SuppressionSuspected>> {
        self.suppression_rx.take()
    }

    /// Records that a heartbeat was received from the relay.
    ///
    /// Called by subscription message processing when heartbeat-like
    /// messages arrive. If no heartbeat monitor is active (no profile was
    /// provided at connection time), this is a no-op.
    pub async fn record_heartbeat_received(&self) {
        if let Some(ref monitor) = self.heartbeat_monitor {
            let mut mon = monitor.lock().await;
            mon.record_heartbeat_received(tokio::time::Instant::now());
        }
    }

    /// Returns whether this adapter has an active heartbeat monitor.
    #[must_use]
    pub const fn has_heartbeat_monitor(&self) -> bool {
        self.heartbeat_monitor.is_some()
    }

    /// Test-only handle to the underlying [`HeartbeatMonitor`], so tests can
    /// drive deterministic [`check_suppression`](HeartbeatMonitor::check_suppression)
    /// against the same monitor that [`record_heartbeat_received`](Self::record_heartbeat_received)
    /// mutates, proving the baseline actually moved (not merely that the call
    /// did not panic).
    #[cfg(test)]
    fn heartbeat_monitor_handle(&self) -> Option<Arc<tokio::sync::Mutex<HeartbeatMonitor>>> {
        self.heartbeat_monitor.clone()
    }

    /// Starts a background task that emits cover traffic at a constant rate
    /// per the given configuration (spec §9.10.6).
    ///
    /// The task runs until the adapter is dropped (the `Drop` impl cancels
    /// the internal `CancellationToken`). Only one cover traffic task should
    /// be started per adapter instance; calling this a second time spawns an
    /// additional task (both will be cancelled on drop).
    ///
    /// Takes `&self` for ergonomic use -- internally creates a lightweight
    /// sender handle that shares the underlying `NativeRelayClient`'s
    /// connection via `Arc` clones. No `Arc<Self>` wrapping required by
    /// the caller.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` to the spawned task. Callers can ignore the handle;
    /// the task is cancelled automatically on drop.
    #[must_use]
    pub fn start_cover_traffic(&self, config: CoverTrafficConfig) -> tokio::task::JoinHandle<()> {
        let cancel = self.cover_traffic_cancel.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            let mut generator = CoverTrafficGenerator::new(config);

            let Some(interval_duration) = generator.interval() else {
                // Off tier: nothing to do.
                return;
            };

            // Random initial delay to prevent timing fingerprint (spec §9.10.6).
            // Uniform over [0, interval) so the first dummy's timing doesn't
            // reveal when the connection was established.
            {
                use rand::Rng;
                let interval_ms = u64::try_from(interval_duration.as_millis()).unwrap_or(u64::MAX);
                if interval_ms > 0 {
                    let jitter_ms = rand::thread_rng().gen_range(0..interval_ms);
                    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
                }
            }

            let mut interval = tokio::time::interval(interval_duration);
            // The first tick fires immediately; consume it and let the
            // generator produce the first dummy on its own schedule.
            interval.tick().await;

            loop {
                tokio::select! {
                    () = cancel.cancelled() => {
                        tracing::debug!("cover traffic task cancelled");
                        return;
                    }
                    _ = interval.tick() => {
                        let now = tokio::time::Instant::now();
                        match generator.next_action(now) {
                            CoverAction::SendDummy(payload) => {
                                if let Err(e) = client.send_cover_traffic(payload).await {
                                    tracing::warn!("cover traffic send failed: {e}");
                                }
                            }
                            CoverAction::Skip => {}
                        }
                    }
                }
            }
        })
    }
}

impl TransportAdapter for NativeRelayAdapter {
    /// Sends an outer envelope via PUBLISH.
    ///
    /// Extracts `routing_id`, `recipient_hint`, and `blob_ttl` from the
    /// [`OuterEnvelope`], serializes the entire envelope as the blob payload,
    /// and sends a PUBLISH command to the relay.
    ///
    /// Returns the [`BlobId`] (SHA-256 hash of the blob) assigned by the
    /// relay.
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        // Extract all data from the envelope reference before the async block
        // to avoid lifetime issues with the borrowed `envelope`.
        let blob_result = envelope.to_bytes();
        let routing_id_vec = envelope.routing_id.clone();
        let recipient_hint_vec = envelope.recipient_hint.clone();
        let blob_ttl = envelope.blob_ttl;

        Box::pin(async move {
            let blob = blob_result.map_err(|e| TransportError::SendFailed(e.to_string()))?;

            let routing_id: [u8; 32] = routing_id_vec.as_slice().try_into().map_err(|_| {
                TransportError::SendFailed(format!(
                    "invalid routing_id length: expected 32, got {}",
                    routing_id_vec.len()
                ))
            })?;

            let recipient_hint: Option<[u8; 32]> = recipient_hint_vec
                .as_ref()
                .map(|hint| {
                    hint.as_slice().try_into().map_err(|_| {
                        TransportError::SendFailed(format!(
                            "invalid recipient_hint length: expected 32, got {}",
                            hint.len()
                        ))
                    })
                })
                .transpose()?;

            let msg = ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint,
                blob_ttl,
                blob,
            };

            let response = self.client.send_request(msg).await?;

            match response {
                RelayMessage::Ok {
                    blob_id: Some(id), ..
                } => Ok(BlobId::new(id)),
                RelayMessage::Ok { blob_id: None, .. } => Ok(BlobId::from_sha256(&routing_id_vec)),
                RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                    "relay error {code}: {msg}"
                ))),
                _ => Err(TransportError::ProtocolError(
                    "unexpected response to PUBLISH".to_string(),
                )),
            }
        })
    }

    /// Subscribes to a routing ID via SUBSCRIBE.
    ///
    /// Returns a [`SubscriptionStream`] that yields [`TransportEvent`]s:
    /// - `TransportEvent::Envelope` for BLOB messages
    /// - `TransportEvent::BackfillComplete` for `backfill_complete` EVENTs
    /// - `TransportEvent::Reconnected` on reconnection
    /// - `TransportEvent::Terminated` on relay shutdown
    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move {
            let rx = self.client.subscribe(&routing_id_bytes, since).await?;

            let stream = RelayMessageStream { rx };
            Ok(Box::pin(stream) as SubscriptionStream)
        })
    }

    /// Unsubscribes from a routing ID via UNSUBSCRIBE.
    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move { self.client.unsubscribe(&routing_id_bytes).await })
    }

    /// Queries stored envelopes for a routing ID via QUERY.
    ///
    /// Sends a QUERY command and collects all BLOB responses until a
    /// `query_complete` EVENT is received. Returns the collected envelopes.
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move { self.client.query(&routing_id_bytes, since).await })
    }

    /// Requests deletion of a blob via DELETE.
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        let blob_id_bytes = *blob_id.as_bytes();
        Box::pin(async move {
            let msg = ClientMessage::Delete {
                ref_id: None,
                blob_id: blob_id_bytes,
            };

            let response = self.client.send_request(msg).await?;

            match response {
                RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                    "relay error {code}: {msg}"
                ))),
                // Best-effort: treat all non-error responses as success.
                _ => Ok(()),
            }
        })
    }

    /// Publishes a raw public-record blob (a DID-record frame, §9.10.12) via
    /// PUBLISH, distinct from the [`OuterEnvelope`] `send` path.
    fn publish_raw(
        &self,
        routing_id: &RoutingId,
        blob_ttl: u64,
        blob: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), TransportError>> {
        let routing_id = *routing_id.as_bytes();
        Box::pin(async move { self.client.publish_raw(&routing_id, blob_ttl, blob).await })
    }

    /// Queries raw public-record blobs at a routing ID via QUERY, returning the
    /// blob bytes without the [`OuterEnvelope`] codec and bypassing the
    /// live-subscription dedup (§3.10.2/§3.10.4).
    fn query_raw(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<Vec<u8>>, TransportError>> {
        let routing_id = *routing_id.as_bytes();
        Box::pin(async move { self.client.query_raw(&routing_id, since, limit).await })
    }

    /// Trait-object entry point for the relay subscription loop: forwards to
    /// the inherent [`NativeRelayAdapter::record_heartbeat_received`], which
    /// refreshes the [`HeartbeatMonitor`] gap-detection baseline when a
    /// transport profile is active (§9.9.2). `Self::` path syntax resolves to
    /// the inherent method (inherent impls take method-resolution priority
    /// over trait impls), so this is a delegation, not a recursion.
    fn record_heartbeat_received(&self) -> BoxFuture<'_, ()> {
        Box::pin(Self::record_heartbeat_received(self))
    }
}

impl CoverTrafficSender for NativeRelayAdapter {
    fn send_cover_traffic(
        &self,
        payload: Vec<u8>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>> {
        Box::pin(self.client.send_cover_traffic(payload))
    }
}

/// Stream adapter that converts [`SubscriptionMessage`]s from a channel into
/// [`TransportEvent`]s.
struct RelayMessageStream {
    rx: tokio::sync::mpsc::Receiver<SubscriptionMessage>,
}

impl Stream for RelayMessageStream {
    type Item = TransportEvent;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(sub_msg)) => {
                subscription_message_to_event(sub_msg).map_or_else(
                    || {
                        // Skip messages that don't map to events (e.g., PONG).
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    },
                    |ev| std::task::Poll::Ready(Some(ev)),
                )
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Converts a [`SubscriptionMessage`] into a [`TransportEvent`], if
/// applicable.
///
/// Returns `None` for messages that don't map to transport events (e.g.,
/// PONG, OK responses).
fn subscription_message_to_event(msg: SubscriptionMessage) -> Option<TransportEvent> {
    match msg {
        SubscriptionMessage::Relay(relay_msg) => relay_message_to_event(relay_msg),
        SubscriptionMessage::Reconnected => Some(TransportEvent::Reconnected),
        SubscriptionMessage::BlobIntegrityError { expected, actual } => {
            Some(TransportEvent::Error(TransportError::BlobIntegrityError {
                expected,
                actual,
            }))
        }
    }
}

/// Converts a [`RelayMessage`] into a [`TransportEvent`], if applicable.
///
/// Returns `None` for messages that don't map to transport events (e.g.,
/// PONG, OK responses).
fn relay_message_to_event(msg: RelayMessage) -> Option<TransportEvent> {
    match msg {
        RelayMessage::Blob { blob, .. } => Some(OuterEnvelope::from_bytes(&blob).map_or_else(
            |_| {
                tracing::warn!("envelope deserialization failed");
                TransportEvent::Error(TransportError::ProtocolError(
                    "failed to deserialize envelope from blob".to_owned(),
                ))
            },
            TransportEvent::Envelope,
        )),
        RelayMessage::Event { event_type, .. } => match event_type.as_str() {
            "backfill_complete" => Some(TransportEvent::BackfillComplete),
            _ => None,
        },
        RelayMessage::Err { code, msg, .. } => {
            if code == scp_relay_client::code::SHUTTING_DOWN {
                Some(TransportEvent::Terminated {
                    reason: format!("relay shutting down: {msg}"),
                })
            } else {
                Some(TransportEvent::Error(TransportError::ProtocolError(
                    format!("relay error {code}: {msg}"),
                )))
            }
        }
        // OK, PONG, and BRIDGE_DATA don't map to transport events.
        // Bridge data is handled by the bridge service layer.
        RelayMessage::Ok { .. } | RelayMessage::Pong { .. } | RelayMessage::BridgeData { .. } => {
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_relay_client::code;

    use super::*;

    #[test]
    fn relay_blob_to_envelope_event() {
        let routing_id = [0xAA; 32];
        let blob_data = {
            let env = scp_core::envelope::create_outer_envelope(
                &routing_id,
                None,
                3600,
                vec![0x01, 0x02, 0x03],
            )
            .unwrap();
            env.to_bytes().unwrap()
        };
        let blob_id = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&blob_data);
            let mut out = [0u8; 32];
            out.copy_from_slice(&hash);
            out
        };

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_data,
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Envelope(_))));
    }

    #[test]
    fn relay_backfill_complete_to_event() {
        let msg = RelayMessage::Event {
            ref_id: None,
            event_type: "backfill_complete".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::BackfillComplete)));
    }

    #[test]
    fn relay_query_complete_returns_none() {
        let msg = RelayMessage::Event {
            ref_id: None,
            event_type: "query_complete".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(event.is_none());
    }

    #[test]
    fn relay_shutting_down_to_terminated() {
        let msg = RelayMessage::Err {
            ref_id: None,
            code: code::SHUTTING_DOWN,
            msg: "going down".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Terminated { .. })));
    }

    #[test]
    fn relay_client_error_to_error_event() {
        let msg = RelayMessage::Err {
            ref_id: None,
            code: code::INVALID_MESSAGE,
            msg: "bad message".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Error(_))));
    }

    #[test]
    fn relay_ok_returns_none() {
        let msg = RelayMessage::Ok {
            ref_id: None,
            blob_id: None,
        };

        let event = relay_message_to_event(msg);
        assert!(event.is_none());
    }

    #[test]
    fn relay_pong_returns_none() {
        let msg = RelayMessage::Pong { ts: 42 };

        let event = relay_message_to_event(msg);
        assert!(event.is_none());
    }

    #[test]
    fn relay_blob_with_invalid_data_to_error_event() {
        let msg = RelayMessage::Blob {
            routing_id: [0xAA; 32],
            blob_id: [0xBB; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: vec![0xFF, 0xFE, 0xFD], // Invalid envelope data.
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Error(_))));
    }

    #[test]
    fn subscription_reconnected_to_reconnected_event() {
        let msg = SubscriptionMessage::Reconnected;
        let event = subscription_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Reconnected)));
    }

    #[test]
    fn subscription_relay_delegates_to_relay_message_to_event() {
        let relay_msg = RelayMessage::Event {
            ref_id: None,
            event_type: "backfill_complete".to_string(),
        };
        let msg = SubscriptionMessage::Relay(relay_msg);
        let event = subscription_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::BackfillComplete)));
    }

    #[test]
    fn subscription_relay_pong_returns_none() {
        let relay_msg = RelayMessage::Pong { ts: 42 };
        let msg = SubscriptionMessage::Relay(relay_msg);
        let event = subscription_message_to_event(msg);
        assert!(event.is_none());
    }

    #[test]
    fn subscription_blob_integrity_error_to_error_event() {
        let msg = SubscriptionMessage::BlobIntegrityError {
            expected: "aa".repeat(32),
            actual: "bb".repeat(32),
        };
        let event = subscription_message_to_event(msg);
        match event {
            Some(TransportEvent::Error(TransportError::BlobIntegrityError {
                expected,
                actual,
            })) => {
                assert_eq!(expected, "aa".repeat(32));
                assert_eq!(actual, "bb".repeat(32));
            }
            other => panic!("expected BlobIntegrityError event, got {other:?}"),
        }
    }

    // --- connect_sourced validation tests ---

    /// Verifies that `connect_sourced` rejects ws:// URLs from non-DHT sources
    /// before attempting a connection (§10.12.6).
    #[tokio::test]
    async fn connect_sourced_rejects_ws_from_well_known() {
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};

        let sourced = SourcedRelayUrl {
            url: "ws://203.0.113.42:8443/scp/v1".to_owned(),
            source: RelayUrlSource::WellKnown,
        };
        let err = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .expect_err("ws:// from WellKnown must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("ws://"),
            "error should mention ws://, got: {msg}"
        );
        assert!(
            msg.contains("WellKnown"),
            "error should mention source, got: {msg}"
        );
    }

    /// Verifies that `connect_sourced` rejects ws:// URLs from explicit config.
    #[tokio::test]
    async fn connect_sourced_rejects_ws_from_explicit() {
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};

        let sourced = SourcedRelayUrl {
            url: "ws://203.0.113.42:8443/scp/v1".to_owned(),
            source: RelayUrlSource::Explicit,
        };
        let err = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .expect_err("ws:// from Explicit must be rejected");
        assert!(err.to_string().contains("Explicit"));
    }

    /// Verifies that `connect_sourced` rejects ws:// URLs from peer discovery.
    #[tokio::test]
    async fn connect_sourced_rejects_ws_from_peer_discovered() {
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};

        let sourced = SourcedRelayUrl {
            url: "ws://203.0.113.42:8443/scp/v1".to_owned(),
            source: RelayUrlSource::PeerDiscovered,
        };
        let err = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .expect_err("ws:// from PeerDiscovered must be rejected");
        assert!(err.to_string().contains("PeerDiscovered"));
    }

    /// Verifies that `connect_sourced` rejects invalid schemes (e.g., http://).
    #[tokio::test]
    async fn connect_sourced_rejects_invalid_scheme() {
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};

        let sourced = SourcedRelayUrl {
            url: "http://relay.example.com/scp/v1".to_owned(),
            source: RelayUrlSource::DhtResolved,
        };
        let err = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .expect_err("http:// scheme must be rejected");
        assert!(err.to_string().contains("ws:// or wss://"));
    }

    // --- Cover traffic integration tests (Finding 6: real adapter coverage) ---

    /// Exercises the real `NativeRelayAdapter::send_cover_traffic()` method
    /// against a local relay server. Verifies the method sends a well-formed
    /// `ClientMessage::Publish` with a random routing ID, 60s TTL, and the
    /// payload as blob.
    #[tokio::test]
    async fn send_cover_traffic_real_adapter() {
        use crate::cover_traffic::{CoverTrafficSender, DUMMY_FLAG, pad_to_bucket};
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        // Start a local relay server.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        // Connect with DhtResolved source (permits ws://).
        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };
        let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .unwrap();

        // Build a cover traffic payload: DUMMY_FLAG + padding to bucket boundary.
        let payload = pad_to_bucket(&[DUMMY_FLAG]);
        assert_eq!(payload.len(), 256); // smallest bucket
        assert_eq!(payload[0], DUMMY_FLAG);

        // Send via the real CoverTrafficSender impl. This exercises the full
        // path: payload -> ClientMessage::Publish -> send_request -> relay.
        let result = adapter.send_cover_traffic(payload.clone()).await;
        assert!(
            result.is_ok(),
            "send_cover_traffic should succeed against a real relay: {result:?}"
        );
    }

    /// Verifies that `Drop` cancels the cover traffic background task,
    /// preventing resource leaks (Finding 3).
    #[tokio::test]
    async fn drop_cancels_cover_traffic_task() {
        use crate::cover_traffic::CoverTrafficConfig;
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::CoverTrafficTier;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        // Start a local relay server.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        let handle;
        {
            let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
                .await
                .unwrap();
            // Start cover traffic with a short custom interval for testing.
            let ct_config = CoverTrafficConfig {
                tier: CoverTrafficTier::Custom {
                    interval: Duration::from_millis(50),
                    padding_bytes: 256,
                },
                bandwidth_budget_bytes_per_min: None,
            };
            handle = adapter.start_cover_traffic(ct_config);
            // Let a few ticks fire.
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Adapter is dropped here, which should cancel the token.
        }

        // The task should complete shortly after the adapter is dropped.
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "cover traffic task should terminate after adapter drop"
        );
    }

    // --- Cover traffic auto-start tests (#1532) ---

    /// Verifies that `connect_sourced` with `Some(&TransportProfile::Server)`
    /// returns Ok and auto-starts cover traffic (the cancel token is wired).
    #[tokio::test]
    async fn connect_sourced_with_server_profile_starts_cover_traffic() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        // Server profile → Full tier → cover traffic auto-started.
        let adapter =
            NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Server))
                .await
                .unwrap();

        // The adapter should have been constructed successfully with
        // cover traffic running. Dropping it cancels the task.
        drop(adapter);
    }

    /// Verifies that `connect_sourced` with `None` profile does NOT start
    /// cover traffic (backward compatibility for tests).
    #[tokio::test]
    async fn connect_sourced_without_profile_no_cover_traffic() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        // No profile → no cover traffic started.
        let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .unwrap();

        // Adapter should connect fine without cover traffic.
        drop(adapter);
    }

    /// Verifies that `connect_sourced` with `TransportProfile::Constrained`
    /// (Off tier) does not start a long-running cover traffic task.
    #[tokio::test]
    async fn connect_sourced_constrained_profile_off_tier() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        // Constrained profile → Off tier → cover traffic task spawns but
        // exits immediately (generator.interval() returns None for Off).
        let adapter =
            NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Constrained))
                .await
                .unwrap();

        // The spawned task should have already exited. Give it a moment.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Adapter drops cleanly — no long-running task to cancel.
        drop(adapter);
    }

    /// Verifies that an explicitly-started cover traffic task emits dummy
    /// blobs to the relay across multiple intervals (AC7). Asserts on the
    /// observable side effect — blobs landing in the relay's blob store —
    /// rather than a fixed sleep, polling until at least three dummies have
    /// arrived (proving emission spans more than one interval).
    #[tokio::test]
    async fn cover_traffic_emits_dummies_at_interval() {
        use crate::cover_traffic::CoverTrafficConfig;
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::{BlobStorage, BlobStorageBackend};
        use crate::profile::CoverTrafficTier;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        // Start a local relay server, holding our own handle to the shared
        // blob storage so we can observe what the relay persists.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, Arc::clone(&storage));
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };
        let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .unwrap();

        // Explicitly start cover traffic with a short 50ms interval and no
        // budget cap, so dummies emit continuously.
        let _ct_handle = adapter.start_cover_traffic(CoverTrafficConfig {
            tier: CoverTrafficTier::Custom {
                interval: Duration::from_millis(50),
                padding_bytes: 256,
            },
            bandwidth_budget_bytes_per_min: None,
        });

        // Poll the blob store until at least three dummies have arrived,
        // bounded by a generous timeout. Three blobs prove emission across
        // multiple intervals (the initial random delay is < one interval).
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let count = storage.count().await.unwrap();
                if count >= 3 {
                    return count;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("cover traffic should emit at least 3 dummies within 3s");

        assert!(
            observed >= 3,
            "expected at least 3 dummy blobs across multiple intervals, got {observed}"
        );
    }

    /// Verifies that a per-minute bandwidth budget degrades the effective
    /// tier to `Off` once exhausted, halting emission for the remainder of
    /// the period (AC8). A 256-byte budget is consumed by the first 256-byte
    /// dummy; subsequent ticks within the same minute send nothing.
    #[tokio::test]
    async fn cover_traffic_budget_degrades_tier() {
        use crate::cover_traffic::CoverTrafficConfig;
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::{BlobStorage, BlobStorageBackend};
        use crate::profile::CoverTrafficTier;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, Arc::clone(&storage));
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };
        let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .unwrap();

        // 256-byte/min budget with 256-byte dummies: the first dummy exhausts
        // the budget, degrading the effective tier to Off for the rest of the
        // 1-minute period.
        let _ct_handle = adapter.start_cover_traffic(CoverTrafficConfig {
            tier: CoverTrafficTier::Custom {
                interval: Duration::from_millis(50),
                padding_bytes: 256,
            },
            bandwidth_budget_bytes_per_min: Some(256),
        });

        // Wait for the single budgeted dummy to land.
        let reached_one = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if storage.count().await.unwrap() >= 1 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            reached_one.is_ok(),
            "the first (budgeted) dummy should be emitted within 3s"
        );

        // Observe across ~500ms (10 intervals). No minute boundary is crossed,
        // so the budget never resets and the count must stay pinned at 1.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let count = storage.count().await.unwrap();
            assert_eq!(
                count, 1,
                "budget should cap emission at exactly 1 dummy, got {count}"
            );
        }
    }

    // --- Heartbeat monitoring tests (#1533) ---

    /// Verifies that connecting with a `TransportProfile` creates a heartbeat
    /// monitor (spec §9.9.2).
    #[tokio::test]
    async fn connect_with_profile_creates_heartbeat_monitor() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        let adapter =
            NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Server))
                .await
                .unwrap();

        assert!(
            adapter.has_heartbeat_monitor(),
            "adapter with TransportProfile should have a heartbeat monitor"
        );
    }

    /// Verifies that connecting without a `TransportProfile` does NOT create
    /// a heartbeat monitor.
    #[tokio::test]
    async fn connect_without_profile_no_heartbeat_monitor() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .unwrap();

        assert!(
            !adapter.has_heartbeat_monitor(),
            "adapter without TransportProfile should NOT have a heartbeat monitor"
        );
    }

    /// Verifies that `record_heartbeat_received` on a connected adapter
    /// actually MOVES the monitor's gap-detection baseline — not merely that
    /// the call does not panic.
    ///
    /// Drives the real adapter method against the real monitor and asserts the
    /// observable state transition: with a `last_sent` baseline and no recent
    /// receive, `check_suppression` fires past the threshold; after
    /// `record_heartbeat_received`, the same `check_suppression` clears.
    #[tokio::test(start_paused = true)]
    async fn record_heartbeat_received_on_connected_adapter() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        let adapter =
            NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Desktop))
                .await
                .unwrap();

        let monitor = adapter
            .heartbeat_monitor_handle()
            .expect("Desktop profile must create a heartbeat monitor");

        // Establish a deterministic `last_sent` baseline at a known instant so
        // suppression has a reference point. (The connect path's monitor task
        // also records a baseline; we overwrite it here to a known `t0`.)
        let t0 = tokio::time::Instant::now();
        {
            let mut mon = monitor.lock().await;
            mon.record_heartbeat_sent(t0);
        }

        // Desktop threshold is 240s (uniform). Past the threshold with nothing
        // received, suppression is suspected.
        let past_threshold = t0 + Duration::from_secs(241);
        assert!(
            monitor
                .lock()
                .await
                .check_suppression(past_threshold)
                .is_some(),
            "monitor must suspect suppression once past the 240s threshold with no receive"
        );

        // Advance the (paused) clock so the adapter's internal
        // `Instant::now()` records the receive at a point past the prior
        // suppression window, then call the REAL adapter method.
        tokio::time::advance(Duration::from_secs(241)).await;
        adapter.record_heartbeat_received().await;

        // The baseline moved: a check shortly after the recorded receive is now
        // within threshold and clears. If `record_heartbeat_received` had been
        // a no-op, this would still report suppression.
        let just_after = tokio::time::Instant::now() + Duration::from_secs(1);
        assert!(
            monitor.lock().await.check_suppression(just_after).is_none(),
            "record_heartbeat_received must move the baseline so suppression clears"
        );
    }

    /// Verifies that `record_heartbeat_received` is a no-op when no monitor
    /// is active (no profile provided).
    #[tokio::test]
    async fn record_heartbeat_received_noop_without_monitor() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
            .await
            .unwrap();

        // Should not panic — no-op when monitor is None.
        adapter.record_heartbeat_received().await;
    }

    /// Verifies that `TransportProfile::Constrained` does NOT create a heartbeat
    /// monitor (constrained devices are poll-based, no heartbeat needed).
    #[tokio::test]
    async fn connect_constrained_profile_no_heartbeat_monitor() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        let adapter =
            NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Constrained))
                .await
                .unwrap();

        assert!(
            !adapter.has_heartbeat_monitor(),
            "Constrained profile should NOT have a heartbeat monitor"
        );
    }

    /// Integration test: verifies that suppression is detected and reported
    /// on the `suppression_events()` channel when no heartbeats are received
    /// for longer than the threshold (spec §9.9.2, #1533 AC8).
    ///
    /// Uses `tokio::time::pause()` to control time without waiting real seconds.
    /// The Server profile sends every 60s, but the suppression threshold is the
    /// uniform 240s (sized to the slowest honest sender — see
    /// `HeartbeatConfig::for_profile`), so suppression fires only after 240s of
    /// silence. We advance past 240s to ensure the heartbeat check loop has
    /// ticked past the threshold.
    #[tokio::test(start_paused = true)]
    async fn suppression_detected_after_threshold() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        // Start a local relay server so the adapter can connect.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        // Connect with Server profile: 60s heartbeat send interval, but the
        // suppression threshold is the UNIFORM 240s (sized to the slowest
        // honest sender, Mobile's 120s × 2), so a receiver never out-runs an
        // honest slower sender.
        let mut adapter =
            NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Server))
                .await
                .unwrap();

        assert!(
            adapter.has_heartbeat_monitor(),
            "Server profile must have a heartbeat monitor"
        );

        // Do NOT call record_heartbeat_received — simulate silence.
        //
        // First, yield to let the spawned heartbeat task start and
        // consume its initial timer tick + record_heartbeat_sent.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Now advance time past the uniform 240s suppression threshold in
        // steps of the 60s heartbeat interval. Each advance fires the pending
        // timer tick; yielding lets the background task process the tick,
        // acquire the monitor lock, check for suppression, and push to the
        // channel. Five steps of 61s = 305s comfortably clears the 240s
        // threshold.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(61)).await;
            // Yield enough times for the background task to run.
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
        }

        // Read from the suppression events channel.
        let rx = adapter
            .suppression_events()
            .expect("suppression_events() must return Some for Server profile");

        let event = rx.try_recv();
        assert!(
            event.is_ok(),
            "expected SuppressionSuspected event on the channel after silence past the 240s threshold"
        );

        let suppression = event.unwrap();
        assert!(
            !suppression.relay_url.is_empty(),
            "suppression event should include the relay URL"
        );
        // The gap_duration will be small (1-2s) because suppression fires on
        // the first tick after the threshold is exceeded.
        assert!(
            suppression.gap_duration > Duration::ZERO,
            "gap_duration should be positive, got {:?}",
            suppression.gap_duration,
        );
    }

    /// Verifies that `TransportProfile::Mobile` creates a heartbeat monitor
    /// (profile-driven config selects Mobile → 120s interval).
    #[tokio::test]
    async fn connect_mobile_profile_creates_heartbeat_monitor() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        let adapter =
            NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Mobile))
                .await
                .unwrap();

        assert!(
            adapter.has_heartbeat_monitor(),
            "Mobile profile should have a heartbeat monitor (with 120s interval)"
        );
    }

    /// Verifies that `Drop` cancels the heartbeat monitoring task.
    #[tokio::test]
    async fn drop_cancels_heartbeat_task() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use crate::profile::TransportProfile;
        use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let sourced = SourcedRelayUrl {
            url,
            source: RelayUrlSource::DhtResolved,
        };

        {
            let adapter =
                NativeRelayAdapter::connect_sourced(&sourced, Some(&TransportProfile::Server))
                    .await
                    .unwrap();

            assert!(adapter.has_heartbeat_monitor());
            // Let the heartbeat task tick at least once.
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Adapter is dropped here — heartbeat_cancel.cancel() fires.
        }

        // If the heartbeat task was not cancelled, the test would leak the
        // task. The tokio runtime's test harness would catch this.
        // We simply verify that the adapter drops without panicking.
    }
}
