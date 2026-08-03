//! WebTransport session handler.
//!
//! Manages an individual WebTransport session established over HTTP/3 at
//! `/scp/v1`. Each session follows the same per-operation bidirectional stream
//! model as QUIC (spec section 10.14.1): each SCP operation opens an
//! independent bidirectional stream carrying MessagePack-encoded messages.
//!
//! The session handler shares the relay's subscription registry and blob
//! storage with WebSocket and QUIC handlers (spec section 10.15.2, ADR-037).
//!
//! # Session lifecycle
//!
//! 1. Session is accepted by [`WebTransportListener`](super::server::WebTransportListener).
//! 2. The handler spawns a loop accepting bidirectional streams from the client.
//! 3. Each stream is dispatched based on the first `MessagePack` message's `op` field.
//! 4. When the session closes (client disconnect, error, or server shutdown),
//!    all active subscriptions for that session are cleaned up.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::native::did_slot::DidSlotRegistry;
use crate::native::server::DidRecordValidation;
use crate::native::storage::BlobStorage;
use crate::relay::did_record_validation::{
    DidRecordClass, DidRecordRejection, classify_did_record_frame, slot_publish_error_response,
};
use crate::relay::rate_limit::{PublishRateLimiter, SubscribeRateLimiter};
use crate::relay::subscription::{self, SubscriptionRegistry};
use scp_relay_client::code;
use scp_relay_client::{
    ClientMessage, DEFAULT_QUERY_LIMIT, MAX_BLOB_SIZE, MAX_BLOB_TTL, MAX_QUERY_LIMIT, MIN_BLOB_TTL,
    RelayMessage,
};

// ---------------------------------------------------------------------------
// Session-scoped types
// ---------------------------------------------------------------------------

/// Unique identifier for a WebTransport session within this relay instance.
///
/// Assigned monotonically by [`WebTransportListener`](super::server::WebTransportListener).
/// Used to key entries in the shared subscription registry so that session
/// teardown can remove exactly its own subscriptions without affecting other
/// transports (WebSocket, QUIC, other WebTransport sessions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub(crate) u64);

/// State of a WebTransport session.
///
/// Tracks the session's identity, active subscriptions, and cancellation
/// token. The session state is owned by the session handler task and
/// referenced by stream handler tasks via `Arc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being established (HTTP/3 + WebTransport handshake).
    Connecting,
    /// Session is active and accepting streams.
    Active,
    /// Session is draining: no new streams accepted, existing streams
    /// complete their current operation.
    Draining,
    /// Session has been closed.
    Closed,
}

/// Per-stream subscription entry, tracking the routing ID and the sender
/// channel used to push relay messages to the subscription stream.
///
/// Mirrors the `SubscriberEntry` pattern from the WebSocket server
/// (`native/server.rs`) but is keyed by [`SessionId`] + stream ID rather
/// than connection ID.
#[allow(dead_code)] // tx kept alive to hold the subscription channel open
pub(crate) struct StreamSubscription {
    /// The routing ID this subscription is for.
    pub(crate) routing_id: [u8; 32],
    /// Sender channel for pushing relay messages to the subscription stream.
    pub(crate) tx: mpsc::Sender<RelayMessage>,
}

/// Configuration for WebTransport session handling.
///
/// Shares the relay-level configuration (max blob size, TTL, rate limits)
/// plus WebTransport-specific settings.
#[derive(Debug, Clone)]
pub struct WebTransportSessionConfig {
    /// Maximum concurrent bidirectional streams per session (default: 100).
    ///
    /// Limits the number of simultaneous SCP operations a single
    /// WebTransport session can perform. This is enforced at the QUIC
    /// transport level via `max_concurrent_bidi_streams`.
    pub max_concurrent_streams: u64,

    /// Maximum blob size in bytes (inherited from relay config).
    pub max_blob_size: usize,

    /// Maximum blob TTL in seconds (inherited from relay config).
    pub max_blob_ttl: u32,

    /// Maximum subscriptions per session (default: 100).
    ///
    /// Same limit as WebSocket connections (spec ADR-004).
    pub max_subscriptions_per_session: usize,

    /// Maximum QUERY result limit (inherited from relay config).
    pub max_query_limit: u32,

    /// Maximum random delivery jitter in milliseconds (inherited from relay config).
    pub delivery_jitter_ms: u64,

    /// Subscribe rate limit: maximum subscribes per minute per session (default: 20).
    pub subscribe_rate_limit: u32,

    /// Whether this session validates public DID-record frames and enforces the
    /// single slot-exclusive slot per DID-domain `routing_id` (§3.10.2, ADR-004),
    /// exactly like the WebSocket/QUIC/UDP transports. When a WebTransport
    /// listener shares a validating relay's blob store and slot registry, this
    /// MUST match the relay's
    /// [`RelayConfig::did_record_validation`](crate::native::server::RelayConfig::did_record_validation)
    /// so co-deployed transports enforce one consistent set of claimed slots.
    /// Defaults to
    /// [`DidRecordValidation::Enabled`](crate::native::server::DidRecordValidation::Enabled),
    /// the canonical SCP-native behavior. Never a trust dependency (RELAYRES-002).
    pub did_record_validation: DidRecordValidation,
}

impl Default for WebTransportSessionConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            max_blob_size: MAX_BLOB_SIZE,
            max_blob_ttl: MAX_BLOB_TTL,
            max_subscriptions_per_session: 100,
            max_query_limit: MAX_QUERY_LIMIT,
            delivery_jitter_ms: 50,
            subscribe_rate_limit: 20,
            did_record_validation: DidRecordValidation::Enabled,
        }
    }
}

/// Manages a single WebTransport session.
///
/// Created by [`WebTransportListener`](super::server::WebTransportListener)
/// for each accepted session. The handler:
///
/// 1. Accepts bidirectional streams from the client.
/// 2. Reads the first `MessagePack` message to determine the operation (`op`).
/// 3. Dispatches to the appropriate handler (publish, subscribe, query, delete).
/// 4. On session close, removes all subscriptions for this session from the
///    shared registry.
///
/// # Cancellation
///
/// The `shutdown_token` is shared with the listener. When cancelled, the
/// session stops accepting new streams and drains existing ones.
pub struct WebTransportSessionHandler<S: BlobStorage> {
    /// Unique session identifier.
    session_id: SessionId,
    /// Current session state.
    state: SessionState,
    /// Session-level configuration.
    config: WebTransportSessionConfig,
    /// Shared blob storage (same instance as WebSocket/QUIC handlers).
    storage: Arc<S>,
    /// Shared subscription registry.
    subscriptions: SubscriptionRegistry,
    /// Active subscriptions for this session, keyed by routing ID.
    /// Used for cleanup on session close.
    active_subscriptions: Vec<StreamSubscription>,
    /// Cancellation token for graceful shutdown.
    shutdown_token: CancellationToken,
    /// Counter for stream operations processed by this session (metrics).
    streams_processed: u64,
    /// Shared publish rate limiter (per-IP, shared across transports).
    publish_rate_limiter: PublishRateLimiter,
    /// Per-session subscribe rate limiter.
    subscribe_rate_limiter: SubscribeRateLimiter,
    /// Remote IP address for rate limiting.
    remote_ip: IpAddr,
    /// Routing IDs subscribed by this session (for cleanup).
    my_subscriptions: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Shared DID-record slot index (same instance as WebSocket/QUIC/UDP). When
    /// `config.did_record_validation` is `Enabled` and the session shares a
    /// validating relay's blob store, PUBLISH/QUERY/DELETE honor slot-exclusivity
    /// over this registry — so WebTransport cannot be used to bypass a claimed DID
    /// slot in the shared store (§3.10.2, SCP-RELAYRES-003).
    did_slots: DidSlotRegistry,
}

impl<S: BlobStorage + 'static> WebTransportSessionHandler<S> {
    /// Creates a new session handler.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier assigned by the listener.
    /// * `config` - Session-level configuration.
    /// * `storage` - Shared blob storage backend.
    /// * `subscriptions` - Shared subscription registry.
    /// * `shutdown_token` - Cancellation token for coordinated shutdown.
    /// * `publish_rate_limiter` - Shared per-IP publish rate limiter.
    /// * `remote_ip` - Client's remote IP address for rate limiting.
    /// * `did_slots` - Shared DID-record slot index (obtain via
    ///   [`RelayServer::did_slot_registry`](crate::native::server::RelayServer::did_slot_registry));
    ///   pass `config.did_record_validation` equal to the relay's mode.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        config: WebTransportSessionConfig,
        storage: Arc<S>,
        subscriptions: SubscriptionRegistry,
        shutdown_token: CancellationToken,
        publish_rate_limiter: PublishRateLimiter,
        remote_ip: IpAddr,
        did_slots: DidSlotRegistry,
    ) -> Self {
        let subscribe_rate_limit = config.subscribe_rate_limit;
        Self {
            session_id,
            state: SessionState::Connecting,
            config,
            storage,
            subscriptions,
            active_subscriptions: Vec::new(),
            shutdown_token,
            streams_processed: 0,
            subscribe_rate_limiter: SubscribeRateLimiter::new(subscribe_rate_limit),
            publish_rate_limiter,
            remote_ip,
            my_subscriptions: Arc::new(RwLock::new(HashSet::new())),
            did_slots,
        }
    }

    /// Returns the session's unique identifier.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the current session state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the number of streams processed by this session.
    #[must_use]
    pub const fn streams_processed(&self) -> u64 {
        self.streams_processed
    }

    /// Returns the number of active subscriptions for this session.
    #[must_use]
    pub const fn active_subscription_count(&self) -> usize {
        self.active_subscriptions.len()
    }

    /// Transitions the session to the [`Active`](SessionState::Active) state.
    ///
    /// Called by the listener after the HTTP/3 + WebTransport handshake
    /// completes successfully.
    pub const fn mark_active(&mut self) {
        self.state = SessionState::Active;
    }

    /// Runs the session's main loop: accepts bidirectional streams from the
    /// WebTransport session and dispatches each to the appropriate SCP
    /// operation handler.
    ///
    /// This method blocks until the session is closed (client disconnect,
    /// error, or server shutdown). On exit, it calls [`cleanup`](Self::cleanup)
    /// to remove all subscriptions for this session.
    ///
    /// # Errors
    ///
    /// Returns [`WebTransportSessionError`] if the session encounters a
    /// fatal protocol or stream error during operation dispatch.
    pub async fn run(&mut self) -> Result<(), WebTransportSessionError> {
        self.state = SessionState::Active;
        tracing::info!(
            session_id = self.session_id.0,
            "WebTransport session active, accepting streams"
        );

        // Wait for shutdown signal. In a full h3-webtransport integration,
        // this loop would accept bidirectional streams via
        // `session.accept_bi()`. With raw h3, the listener drives stream
        // dispatch externally and calls `dispatch_message()` directly.
        // The session handler runs as a cooperative state machine.
        self.shutdown_token.cancelled().await;

        self.state = SessionState::Draining;
        tracing::info!(
            session_id = self.session_id.0,
            streams_processed = self.streams_processed,
            "WebTransport session draining"
        );

        self.cleanup().await;
        self.state = SessionState::Closed;

        Ok(())
    }

    /// Dispatches a client message and returns all relay messages to send back.
    ///
    /// For most operations this returns a single message. SUBSCRIBE returns an
    /// OK followed by optional backfill blobs and a `backfill_complete` event,
    /// plus a long-lived receiver for live delivery. QUERY returns multiple
    /// BLOB messages followed by a `query_complete` event.
    ///
    /// # Errors
    ///
    /// Returns [`WebTransportSessionError::ProtocolError`] if the message
    /// type is unsupported over WebTransport (ACK, `BRIDGE_REGISTER`, `BRIDGE_DATA`).
    pub async fn dispatch_message_multi(
        &mut self,
        msg: &ClientMessage,
    ) -> Result<DispatchResult, WebTransportSessionError> {
        self.streams_processed += 1;
        match msg {
            ClientMessage::Publish {
                ref_id,
                routing_id,
                recipient_hint,
                blob_ttl,
                blob,
            } => {
                let response = self
                    .handle_publish_inner(
                        ref_id.clone(),
                        *routing_id,
                        *recipient_hint,
                        *blob_ttl,
                        blob,
                    )
                    .await?;
                Ok(DispatchResult::Single(response))
            }
            ClientMessage::Subscribe {
                ref_id,
                routing_id,
                since,
            } => {
                self.handle_subscribe_inner(ref_id.clone(), *routing_id, *since)
                    .await
            }
            ClientMessage::Unsubscribe { ref_id, routing_id } => {
                let response = self
                    .handle_unsubscribe_inner(ref_id.clone(), *routing_id)
                    .await?;
                Ok(DispatchResult::Single(response))
            }
            ClientMessage::Query {
                ref_id,
                routing_id,
                since,
                limit,
            } => {
                let messages = self
                    .handle_query_inner(ref_id.clone(), *routing_id, *since, *limit)
                    .await?;
                Ok(DispatchResult::Multi(messages))
            }
            ClientMessage::Delete { ref_id, blob_id } => {
                let response = self.handle_delete_inner(ref_id.clone(), *blob_id).await?;
                Ok(DispatchResult::Single(response))
            }
            ClientMessage::Ping { ts } => {
                let response = self.handle_ping(*ts)?;
                Ok(DispatchResult::Single(response))
            }
            ClientMessage::Ack { .. }
            | ClientMessage::BridgeRegister { .. }
            | ClientMessage::BridgeData { .. } => Err(WebTransportSessionError::ProtocolError(
                "ACK, BRIDGE_REGISTER, and BRIDGE_DATA not supported over WebTransport".to_owned(),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // PUBLISH handler (spec §10.14.1, same logic as QUIC listener)
    // -----------------------------------------------------------------------

    /// Handles a PUBLISH operation on a bidirectional stream.
    ///
    /// Validates blob size and TTL, computes `blob_id = SHA-256(blob)`, stores
    /// the blob, fans out to active subscribers, and returns an OK with the
    /// `blob_id`.
    #[allow(clippy::too_many_lines)]
    async fn handle_publish_inner(
        &self,
        ref_id: Option<String>,
        routing_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: &[u8],
    ) -> Result<RelayMessage, WebTransportSessionError> {
        // Check publish rate limit (shared per-IP across transports).
        if !self.publish_rate_limiter.check(self.remote_ip).await {
            tracing::warn!(
                session_id = self.session_id.0,
                ip = %self.remote_ip,
                "WebTransport: publish rate limit exceeded"
            );
            return Ok(RelayMessage::Err {
                ref_id,
                code: code::RATE_LIMITED,
                msg: "publish rate limit exceeded".to_string(),
            });
        }

        // Validate blob size.
        if blob.is_empty() || blob.len() > self.config.max_blob_size {
            return Ok(RelayMessage::Err {
                ref_id,
                code: code::BLOB_TOO_LARGE,
                msg: format!(
                    "blob must be 1-{} bytes, got {}",
                    self.config.max_blob_size,
                    blob.len()
                ),
            });
        }

        // Validate TTL.
        if blob_ttl < MIN_BLOB_TTL || blob_ttl > self.config.max_blob_ttl {
            return Ok(RelayMessage::Err {
                ref_id,
                code: code::TTL_TOO_LONG,
                msg: format!(
                    "blob_ttl must be {}-{}, got {}",
                    MIN_BLOB_TTL, self.config.max_blob_ttl, blob_ttl
                ),
            });
        }

        // Compute blob_id = SHA-256(blob) using the canonical BlobId helper.
        let blob_id = *crate::traits::BlobId::from_sha256(blob).as_bytes();

        // OPTIONAL validating-relay DID-record path — mirrors the WebSocket/QUIC/
        // UDP handlers EXACTLY over the shared slot registry (§3.10.2). Only
        // engages for a blob that decodes as a `DidRecordV1` frame.
        if self.config.did_record_validation == DidRecordValidation::Enabled {
            match classify_did_record_frame(&routing_id, blob) {
                DidRecordClass::Valid { seq } => {
                    return match self
                        .did_slots
                        .publish_frame(
                            self.storage.as_ref(),
                            routing_id,
                            blob_id,
                            recipient_hint,
                            blob_ttl,
                            blob.to_vec(),
                            seq,
                        )
                        .await
                    {
                        Ok((stored, _outcome)) => {
                            let _failed_deliveries = subscription::deliver_to_subscribers(
                                &stored,
                                &self.subscriptions,
                                self.config.delivery_jitter_ms,
                            )
                            .await;
                            Ok(RelayMessage::Ok {
                                ref_id,
                                blob_id: Some(blob_id),
                            })
                        }
                        Err(e) => {
                            let (code, msg) = slot_publish_error_response(&e);
                            Ok(RelayMessage::Err { ref_id, code, msg })
                        }
                    };
                }
                DidRecordClass::Invalid(reason) => {
                    let detail = match reason {
                        DidRecordRejection::BindingMismatch => {
                            "DID→routing_id binding mismatch (frame published at the wrong routing_id)"
                        }
                        DidRecordRejection::SignatureInvalid => {
                            "BEP44 signature verification failed"
                        }
                    };
                    return Ok(RelayMessage::Err {
                        ref_id,
                        code: code::DID_RECORD_REJECTED,
                        msg: format!("DID-record frame rejected: {detail}"),
                    });
                }
                DidRecordClass::NotAFrame => {
                    // Slot-exclusivity rule (a): a non-frame blob at a claimed DID
                    // slot is rejected — no co-locating junk with the genuine
                    // record, even over WebTransport.
                    if self
                        .did_slots
                        .is_claimed(self.storage.as_ref(), &routing_id)
                        .await
                    {
                        return Ok(RelayMessage::Err {
                            ref_id,
                            code: code::DID_RECORD_REJECTED,
                            msg: "routing_id has a claimed DID-record slot; \
                                  non-superseding blobs are rejected (slot-exclusive)"
                                .to_string(),
                        });
                    }
                    // Not a claimed DID slot — fall through to opaque storage.
                }
            }
        }

        // Store the blob (opaque path — non-DID blobs, or every blob when
        // did_record_validation is Disabled).
        let stored = match self
            .storage
            .store(routing_id, blob_id, recipient_hint, blob_ttl, blob.to_vec())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(
                    session_id = self.session_id.0,
                    error = %e,
                    "WebTransport: blob store failed"
                );
                return Ok(RelayMessage::Err {
                    ref_id,
                    code: code::STORAGE_FULL,
                    msg: "internal error".to_owned(),
                });
            }
        };

        // Deliver to active subscribers with optional jitter (BLACK-001).
        let _failed_deliveries = subscription::deliver_to_subscribers(
            &stored,
            &self.subscriptions,
            self.config.delivery_jitter_ms,
        )
        .await;

        // Respond with OK + blob_id.
        Ok(RelayMessage::Ok {
            ref_id,
            blob_id: Some(blob_id),
        })
    }

    // -----------------------------------------------------------------------
    // SUBSCRIBE handler (spec §10.14.1, same logic as QUIC listener)
    // -----------------------------------------------------------------------

    /// Handles a SUBSCRIBE operation: registers in the shared subscription
    /// registry, backfills, and returns a receiver for live blob delivery.
    async fn handle_subscribe_inner(
        &mut self,
        ref_id: Option<String>,
        routing_id: [u8; 32],
        since: Option<u64>,
    ) -> Result<DispatchResult, WebTransportSessionError> {
        // Check subscribe rate limit.
        if !self.subscribe_rate_limiter.check() {
            tracing::warn!(
                session_id = self.session_id.0,
                "WebTransport: subscribe rate limit exceeded"
            );
            return Ok(DispatchResult::Single(RelayMessage::Err {
                ref_id,
                code: code::RATE_LIMITED,
                msg: "subscribe rate limit exceeded".to_string(),
            }));
        }

        // Check subscription limit and insert atomically under a single
        // write lock to prevent TOCTOU races.
        let mut my_subs = self.my_subscriptions.write().await;
        if my_subs.len() >= self.config.max_subscriptions_per_session {
            return Ok(DispatchResult::Single(RelayMessage::Err {
                ref_id,
                code: code::TOO_MANY_SUBSCRIPTIONS,
                msg: format!(
                    "maximum {} subscriptions per session",
                    self.config.max_subscriptions_per_session
                ),
            }));
        }
        my_subs.insert(routing_id);
        drop(my_subs);

        // Create a channel for receiving blobs destined for this subscriber.
        let (tx, rx) = mpsc::channel::<RelayMessage>(256);

        // Register the subscription in the shared registry (SEC-006: enforces
        // global + per-routing-ID limits).
        if let Err(reason) = subscription::register_subscriber(
            &self.subscriptions,
            routing_id,
            self.session_id.0,
            tx.clone(),
        )
        .await
        {
            // Undo the my_subscriptions insertion.
            let mut my_subs = self.my_subscriptions.write().await;
            my_subs.remove(&routing_id);
            drop(my_subs);

            tracing::warn!(
                session_id = self.session_id.0,
                routing_id = ?routing_id,
                reason = %reason,
                "subscription registry capacity exceeded"
            );
            return Ok(DispatchResult::Single(RelayMessage::Err {
                ref_id,
                code: code::TOO_MANY_SUBSCRIPTIONS,
                msg: reason,
            }));
        }

        // Track subscription for cleanup.
        self.active_subscriptions
            .push(StreamSubscription { routing_id, tx });

        // Build initial messages: OK + optional backfill.
        let mut messages = vec![RelayMessage::Ok {
            ref_id: ref_id.clone(),
            blob_id: None,
        }];

        // Backfill if `since` is provided. Slot-exclusivity rule (c) applies to
        // backfill too: a claimed DID `routing_id` backfills ONLY the single slot
        // record over the shared registry, never co-located junk.
        if let Some(since_ts) = since {
            let claimed_slot = if self.config.did_record_validation == DidRecordValidation::Enabled
            {
                self.did_slots
                    .slot_blob(self.storage.as_ref(), &routing_id)
                    .await
            } else {
                None
            };

            if let Some(slot) = claimed_slot {
                messages.push(RelayMessage::Blob {
                    routing_id: slot.routing_id,
                    blob_id: slot.blob_id,
                    recipient_hint: slot.recipient_hint,
                    blob_ttl: slot.blob_ttl,
                    stored_at: slot.stored_at,
                    blob: slot.blob,
                });
            } else if let Ok(blobs) = self
                .storage
                .query(&routing_id, Some(since_ts), MAX_QUERY_LIMIT)
                .await
            {
                for stored in blobs {
                    messages.push(RelayMessage::Blob {
                        routing_id: stored.routing_id,
                        blob_id: stored.blob_id,
                        recipient_hint: stored.recipient_hint,
                        blob_ttl: stored.blob_ttl,
                        stored_at: stored.stored_at,
                        blob: stored.blob,
                    });
                }
            }

            messages.push(RelayMessage::Event {
                ref_id,
                event_type: "backfill_complete".to_string(),
            });
        }

        Ok(DispatchResult::Subscription { messages, rx })
    }

    // -----------------------------------------------------------------------
    // UNSUBSCRIBE handler
    // -----------------------------------------------------------------------

    /// Handles an UNSUBSCRIBE operation: removes the subscription from the
    /// shared registry and the local `active_subscriptions` list.
    async fn handle_unsubscribe_inner(
        &mut self,
        ref_id: Option<String>,
        routing_id: [u8; 32],
    ) -> Result<RelayMessage, WebTransportSessionError> {
        // Remove from the shared registry.
        let mut registry = self.subscriptions.write().await;
        if let Some(entries) = registry.get_mut(&routing_id) {
            entries.retain(|e| e.owner_id != self.session_id.0);
            if entries.is_empty() {
                registry.remove(&routing_id);
            }
        }
        drop(registry);

        let mut my_subs = self.my_subscriptions.write().await;
        my_subs.remove(&routing_id);
        drop(my_subs);

        // Also prune from the local active_subscriptions Vec so cleanup
        // doesn't try to remove an already-removed entry.
        self.active_subscriptions
            .retain(|s| s.routing_id != routing_id);

        Ok(RelayMessage::Ok {
            ref_id,
            blob_id: None,
        })
    }

    // -----------------------------------------------------------------------
    // QUERY handler (spec §10.14.1, same logic as QUIC listener)
    // -----------------------------------------------------------------------

    /// Handles a QUERY operation: reads matching blobs from storage,
    /// returns each as a BLOB message, then a `query_complete` event.
    async fn handle_query_inner(
        &self,
        ref_id: Option<String>,
        routing_id: [u8; 32],
        since: Option<u64>,
        limit: Option<u32>,
    ) -> Result<Vec<RelayMessage>, WebTransportSessionError> {
        let effective_limit = limit.unwrap_or(DEFAULT_QUERY_LIMIT);

        // Validate limit.
        if effective_limit == 0 || effective_limit > self.config.max_query_limit {
            return Ok(vec![RelayMessage::Err {
                ref_id,
                code: code::LIMIT_EXCEEDED,
                msg: format!(
                    "limit must be 1-{}, got {}",
                    self.config.max_query_limit, effective_limit
                ),
            }]);
        }

        // Slot-exclusivity rule (c): a claimed DID `routing_id` returns ONLY the
        // single slot record over the shared registry, the same gate the other
        // transports apply.
        let claimed_slot = if self.config.did_record_validation == DidRecordValidation::Enabled {
            self.did_slots
                .slot_blob(self.storage.as_ref(), &routing_id)
                .await
        } else {
            None
        };

        let blobs = if let Some(slot) = claimed_slot {
            vec![slot]
        } else {
            match self
                .storage
                .query(&routing_id, since, effective_limit)
                .await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        session_id = self.session_id.0,
                        error = %e,
                        "WebTransport: blob query failed"
                    );
                    return Ok(vec![RelayMessage::Err {
                        ref_id,
                        code: code::INTERNAL_ERROR,
                        msg: "internal error".to_owned(),
                    }]);
                }
            }
        };

        let mut messages = Vec::with_capacity(blobs.len() + 1);
        for stored in &blobs {
            messages.push(RelayMessage::Blob {
                routing_id: stored.routing_id,
                blob_id: stored.blob_id,
                recipient_hint: stored.recipient_hint,
                blob_ttl: stored.blob_ttl,
                stored_at: stored.stored_at,
                blob: stored.blob.clone(),
            });
        }

        // Emit query_complete event.
        messages.push(RelayMessage::Event {
            ref_id,
            event_type: "query_complete".to_string(),
        });

        Ok(messages)
    }

    // -----------------------------------------------------------------------
    // DELETE handler
    // -----------------------------------------------------------------------

    /// Handles a DELETE operation: best-effort deletion from storage, EXCEPT a
    /// protected DID slot's blob, which is rejected (§3.10.2 rule (d), Fix B).
    async fn handle_delete_inner(
        &self,
        ref_id: Option<String>,
        blob_id: [u8; 32],
    ) -> Result<RelayMessage, WebTransportSessionError> {
        // Slot-exclusivity (§3.10.2 rule (d)): reject a DELETE of a protected DID
        // slot blob over WebTransport, identically to WebSocket/QUIC/UDP. The gate
        // is STORAGE-BACKED (index is a fast-path cache, not the authority) — it
        // decodes+verifies the immutable, content-addressed blob, so it is immune
        // to a cold/empty index. The check-then-delete race is benign (immutable
        // bytes); residual is the availability-only "published just after check"
        // window. Non-slot blobs proceed.
        if self
            .did_slots
            .delete_would_revert_slot(self.storage.as_ref(), &blob_id)
            .await
        {
            return Ok(RelayMessage::Err {
                ref_id,
                code: code::DID_RECORD_REJECTED,
                msg: "blob_id is a claimed DID-record slot; only a superseding \
                      PUBLISH may replace it (slot-exclusive)"
                    .to_string(),
            });
        }

        // Best-effort deletion.
        let _ = self.storage.delete(&blob_id).await;

        Ok(RelayMessage::Ok {
            ref_id,
            blob_id: None,
        })
    }

    // -----------------------------------------------------------------------
    // PING handler
    // -----------------------------------------------------------------------

    /// Handles a PING operation. WebTransport sessions over QUIC have native
    /// keepalive (QUIC PING frames), so application-level PING is less
    /// critical than for WebSocket. We still respond with PONG for
    /// compatibility with clients that send it.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn
    )]
    fn handle_ping(&self, ts: u64) -> Result<RelayMessage, WebTransportSessionError> {
        Ok(RelayMessage::Pong { ts })
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------

    /// Removes all subscriptions for this session from the shared registry.
    ///
    /// Called on session close to ensure no stale entries remain in the
    /// registry after the session's streams are gone.
    async fn cleanup(&mut self) {
        let session_id = self.session_id;
        let mut registry = self.subscriptions.write().await;

        for sub in &self.active_subscriptions {
            if let Some(entries) = registry.get_mut(&sub.routing_id) {
                entries.retain(|entry| entry.owner_id != session_id.0);
                if entries.is_empty() {
                    registry.remove(&sub.routing_id);
                }
            }
        }
        drop(registry);

        let sub_count = self.active_subscriptions.len();
        self.active_subscriptions.clear();

        tracing::info!(
            session_id = session_id.0,
            subscriptions_removed = sub_count,
            "WebTransport session cleanup complete"
        );
    }
}

// ---------------------------------------------------------------------------
// Dispatch result
// ---------------------------------------------------------------------------

/// Result of dispatching a client message, supporting multi-message responses.
///
/// QUERY and SUBSCRIBE produce multiple relay messages (blobs + completion
/// event), while other operations produce a single response.
#[must_use]
#[derive(Debug)]
pub enum DispatchResult {
    /// A single relay message response (PUBLISH OK, DELETE OK, PING PONG, etc.).
    Single(RelayMessage),
    /// Multiple relay messages (QUERY results + `query_complete` event).
    Multi(Vec<RelayMessage>),
    /// A SUBSCRIBE response: initial messages (OK + optional backfill) plus
    /// a receiver for live blob delivery.
    Subscription {
        /// Initial messages to send (OK, optional backfill blobs,
        /// optional `backfill_complete` event).
        messages: Vec<RelayMessage>,
        /// Receiver for live blob delivery. The caller should forward
        /// messages from this receiver to the client stream.
        rx: mpsc::Receiver<RelayMessage>,
    },
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors specific to WebTransport session handling.
#[derive(Debug, Clone, thiserror::Error)]
pub enum WebTransportSessionError {
    /// The session could not be established (HTTP/3 or WebTransport
    /// handshake failure).
    #[error("session establishment failed: {0}")]
    SessionEstablishmentFailed(String),

    /// A stream-level I/O error occurred.
    #[error("stream error: {0}")]
    StreamError(String),

    /// The client sent an invalid or malformed `MessagePack` message.
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// The client exceeded the maximum number of concurrent streams.
    #[error("too many concurrent streams (limit: {limit})")]
    TooManyConcurrentStreams {
        /// The configured limit.
        limit: u64,
    },

    /// The client exceeded the maximum number of subscriptions per session.
    #[error("too many subscriptions (limit: {limit})")]
    TooManySubscriptions {
        /// The configured limit.
        limit: usize,
    },

    /// The session was closed by the server (shutdown).
    #[error("session closed by server")]
    ServerShutdown,

    /// The session was closed by the client.
    #[error("session closed by client")]
    ClientDisconnected,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use crate::native::storage::InMemoryBlobStorage;
    use crate::relay::rate_limit::PublishRateLimiter;
    use crate::relay::subscription::SubscriberEntry;
    use sha2::{Digest, Sha256};
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper: extract the single `RelayMessage` from a `DispatchResult::Single`.
    fn unwrap_single(result: DispatchResult) -> RelayMessage {
        match result {
            DispatchResult::Single(msg) => msg,
            DispatchResult::Multi(_) => panic!("expected Single, got Multi"),
            DispatchResult::Subscription { .. } => panic!("expected Single, got Subscription"),
        }
    }

    /// Helper: creates a session handler with default config and in-memory storage.
    fn make_handler() -> WebTransportSessionHandler<InMemoryBlobStorage> {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = crate::relay::subscription::new_registry();
        let token = CancellationToken::new();
        let rate_limiter = PublishRateLimiter::new(100);
        WebTransportSessionHandler::new(
            SessionId(1),
            WebTransportSessionConfig::default(),
            storage,
            subscriptions,
            token,
            rate_limiter,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DidSlotRegistry::new(),
        )
    }

    #[test]
    fn session_initial_state_is_connecting() {
        let handler = make_handler();
        assert_eq!(handler.state(), SessionState::Connecting);
    }

    #[test]
    fn session_mark_active() {
        let mut handler = make_handler();
        handler.mark_active();
        assert_eq!(handler.state(), SessionState::Active);
    }

    #[test]
    fn session_id_roundtrip() {
        let handler = make_handler();
        assert_eq!(handler.session_id(), SessionId(1));
    }

    #[test]
    fn session_initial_streams_processed_is_zero() {
        let handler = make_handler();
        assert_eq!(handler.streams_processed(), 0);
    }

    #[test]
    fn session_initial_subscription_count_is_zero() {
        let handler = make_handler();
        assert_eq!(handler.active_subscription_count(), 0);
    }

    #[test]
    fn default_config_values() {
        let config = WebTransportSessionConfig::default();
        assert_eq!(config.max_concurrent_streams, 100);
        assert_eq!(config.max_blob_size, MAX_BLOB_SIZE);
        assert_eq!(config.max_blob_ttl, MAX_BLOB_TTL);
        assert_eq!(config.max_subscriptions_per_session, 100);
        assert_eq!(config.max_query_limit, MAX_QUERY_LIMIT);
        assert_eq!(config.delivery_jitter_ms, 50);
        assert_eq!(
            config.did_record_validation,
            DidRecordValidation::Enabled,
            "WebTransport validates DID records by default, like the other transports",
        );
    }

    /// Builds a genuine, self-consistent DID-record frame at the signing key's
    /// own DID-domain `routing_id`, returning `(routing_id, blob_id, bytes)`.
    fn genuine_frame(seed: u8, seq: u64, value: &[u8]) -> ([u8; 32], [u8; 32], Vec<u8>) {
        use ed25519_dalek::{Signer, SigningKey};
        use scp_dht::bep44_signable;
        use scp_identity::{did_from_ed25519_public_key, did_routing_id};
        use scp_protocol::envelope::did_record::DidRecordV1;
        use sha2::{Digest, Sha256};

        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        let did = did_from_ed25519_public_key(&vk.to_bytes());
        let rid = did_routing_id(&did);
        let signature: ed25519_dalek::Signature = sk.sign(&bep44_signable(value, seq));
        let bytes = DidRecordV1::try_new(vk.to_bytes(), seq, signature.to_bytes(), value.to_vec())
            .unwrap()
            .encode();
        let mut bid = [0u8; 32];
        bid.copy_from_slice(&Sha256::digest(&bytes));
        (rid, bid, bytes)
    }

    fn slot_blob_ids(result: &DispatchResult) -> Vec<[u8; 32]> {
        let DispatchResult::Multi(msgs) = result else {
            panic!("expected Multi (QUERY), got a different DispatchResult");
        };
        msgs.iter()
            .filter_map(|m| match m {
                RelayMessage::Blob { blob_id, .. } => Some(*blob_id),
                _ => None,
            })
            .collect()
    }

    /// Fix C: a validating WebTransport session enforces DID-record
    /// slot-exclusivity over the shared registry — a genuine frame claims the
    /// slot, later junk is rejected, QUERY returns only the slot, and an
    /// unauthenticated DELETE of the slot blob is rejected while the slot
    /// survives. Mirrors the QUIC/UDP handler behavior exactly.
    #[tokio::test]
    async fn webtransport_did_record_slot_exclusivity_and_delete_gate() {
        let mut h = make_handler();
        let (rid, bid, frame) = genuine_frame(61, 5, b"did-doc");

        // PUBLISH genuine frame → claims the slot.
        let ok = h
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: None,
                routing_id: rid,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: frame,
            })
            .await
            .unwrap();
        assert!(
            matches!(ok, DispatchResult::Single(RelayMessage::Ok { .. })),
            "genuine frame should be accepted, got {ok:?}",
        );

        // Opaque junk at the claimed routing_id → rejected (rule a).
        let rejected = h
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: None,
                routing_id: rid,
                recipient_hint: None,
                blob_ttl: 3600,
                blob: vec![0x80u8; 64],
            })
            .await
            .unwrap();
        match rejected {
            DispatchResult::Single(RelayMessage::Err { code: c, .. }) => {
                assert_eq!(c, code::DID_RECORD_REJECTED);
            }
            other => panic!("expected DID_RECORD_REJECTED, got {other:?}"),
        }

        // QUERY returns ONLY the slot (rule c).
        let query = ClientMessage::Query {
            ref_id: None,
            routing_id: rid,
            since: None,
            limit: Some(100),
        };
        let q = h.dispatch_message_multi(&query).await.unwrap();
        assert_eq!(slot_blob_ids(&q), vec![bid]);

        // DELETE of the slot blob → rejected (Fix B).
        let deleted = h
            .dispatch_message_multi(&ClientMessage::Delete {
                ref_id: None,
                blob_id: bid,
            })
            .await
            .unwrap();
        match deleted {
            DispatchResult::Single(RelayMessage::Err { code: c, .. }) => {
                assert_eq!(c, code::DID_RECORD_REJECTED);
            }
            other => panic!("expected DID_RECORD_REJECTED, got {other:?}"),
        }

        // Slot survives: QUERY still returns it.
        let q = h.dispatch_message_multi(&query).await.unwrap();
        assert_eq!(slot_blob_ids(&q), vec![bid]);

        // DELETE of a non-slot blob still succeeds.
        let ok = h
            .dispatch_message_multi(&ClientMessage::Delete {
                ref_id: None,
                blob_id: [0xEE; 32],
            })
            .await
            .unwrap();
        assert!(matches!(
            ok,
            DispatchResult::Single(RelayMessage::Ok { .. })
        ));
    }

    #[tokio::test]
    async fn session_run_responds_to_cancellation() {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = crate::relay::subscription::new_registry();
        let token = CancellationToken::new();
        let rate_limiter = PublishRateLimiter::new(100);

        let mut handler = WebTransportSessionHandler::new(
            SessionId(42),
            WebTransportSessionConfig::default(),
            storage,
            subscriptions,
            token.clone(),
            rate_limiter,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DidSlotRegistry::new(),
        );

        // Cancel immediately so the run loop exits.
        token.cancel();

        let result = handler.run().await;
        assert!(result.is_ok());
        assert_eq!(handler.state(), SessionState::Closed);
    }

    #[tokio::test]
    async fn session_cleanup_removes_subscriptions() {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = crate::relay::subscription::new_registry();
        let token = CancellationToken::new();
        let rate_limiter = PublishRateLimiter::new(100);

        let routing_id = [0xAA; 32];
        let (tx, _rx) = mpsc::channel(16);

        // Pre-populate the shared registry with an entry for this session.
        {
            let mut reg = subscriptions.write().await;
            reg.entry(routing_id).or_default().push(SubscriberEntry {
                owner_id: 99,
                tx: tx.clone(),
            });
        }

        let mut handler = WebTransportSessionHandler::new(
            SessionId(99),
            WebTransportSessionConfig::default(),
            storage,
            subscriptions.clone(),
            token,
            rate_limiter,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DidSlotRegistry::new(),
        );

        // Track the subscription in the handler's local list.
        handler
            .active_subscriptions
            .push(StreamSubscription { routing_id, tx });

        assert_eq!(handler.active_subscription_count(), 1);

        // Cleanup should remove the entry from the shared registry.
        handler.cleanup().await;

        assert_eq!(handler.active_subscription_count(), 0);
        let reg = subscriptions.read().await;
        assert!(reg.get(&routing_id).is_none());
    }

    #[tokio::test]
    async fn cleanup_preserves_other_sessions_subscriptions() {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = crate::relay::subscription::new_registry();
        let token = CancellationToken::new();
        let rate_limiter = PublishRateLimiter::new(100);

        let routing_id = [0xBB; 32];
        let (tx_this, _rx_this) = mpsc::channel(16);
        let (tx_other, _rx_other) = mpsc::channel(16);

        // Pre-populate with entries from two sessions.
        {
            let mut reg = subscriptions.write().await;
            let entries = reg.entry(routing_id).or_default();
            entries.push(SubscriberEntry {
                owner_id: 10,
                tx: tx_this.clone(),
            });
            entries.push(SubscriberEntry {
                owner_id: 20,
                tx: tx_other,
            });
        }

        let mut handler = WebTransportSessionHandler::new(
            SessionId(10),
            WebTransportSessionConfig::default(),
            storage,
            subscriptions.clone(),
            token,
            rate_limiter,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DidSlotRegistry::new(),
        );

        handler.active_subscriptions.push(StreamSubscription {
            routing_id,
            tx: tx_this,
        });

        handler.cleanup().await;

        // Session 20's entry should still be there.
        let reg = subscriptions.read().await;
        let entries = reg.get(&routing_id).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].owner_id, 20);
    }

    #[tokio::test]
    async fn handle_ping_returns_pong() {
        let handler = make_handler();
        let result = handler.handle_ping(42);
        assert!(result.is_ok());
        match result.unwrap() {
            RelayMessage::Pong { ts } => assert_eq!(ts, 42),
            other => panic!("expected Pong, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn dispatch_increments_streams_processed() {
        let mut handler = make_handler();
        handler.mark_active();

        let result = handler
            .dispatch_message_multi(&ClientMessage::Ping { ts: 1 })
            .await;
        assert!(result.is_ok());
        assert_eq!(handler.streams_processed(), 1);
    }

    #[tokio::test]
    async fn publish_validates_blob_size() {
        let mut handler = make_handler();
        handler.mark_active();

        // Empty blob should fail.
        let result = handler
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: None,
                routing_id: [0x11; 32],
                recipient_hint: None,
                blob_ttl: 60,
                blob: vec![],
            })
            .await;
        assert!(result.is_ok());
        match unwrap_single(result.unwrap()) {
            RelayMessage::Err { code, .. } => assert_eq!(code, code::BLOB_TOO_LARGE),
            other => panic!("expected Err(BLOB_TOO_LARGE), got {:?}", other),
        }

        // Oversized blob should fail.
        let result = handler
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: None,
                routing_id: [0x11; 32],
                recipient_hint: None,
                blob_ttl: 60,
                blob: vec![0u8; MAX_BLOB_SIZE + 1],
            })
            .await;
        assert!(result.is_ok());
        match unwrap_single(result.unwrap()) {
            RelayMessage::Err { code, .. } => assert_eq!(code, code::BLOB_TOO_LARGE),
            other => panic!("expected Err(BLOB_TOO_LARGE), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn publish_validates_ttl() {
        let mut handler = make_handler();
        handler.mark_active();

        // TTL = 0 should fail.
        let result = handler
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: None,
                routing_id: [0x11; 32],
                recipient_hint: None,
                blob_ttl: 0,
                blob: vec![1, 2, 3],
            })
            .await;
        assert!(result.is_ok());
        match unwrap_single(result.unwrap()) {
            RelayMessage::Err { code, .. } => assert_eq!(code, code::TTL_TOO_LONG),
            other => panic!("expected Err(TTL_TOO_LONG), got {:?}", other),
        }

        // TTL > max should fail.
        let result = handler
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: None,
                routing_id: [0x11; 32],
                recipient_hint: None,
                blob_ttl: MAX_BLOB_TTL + 1,
                blob: vec![1, 2, 3],
            })
            .await;
        assert!(result.is_ok());
        match unwrap_single(result.unwrap()) {
            RelayMessage::Err { code, .. } => assert_eq!(code, code::TTL_TOO_LONG),
            other => panic!("expected Err(TTL_TOO_LONG), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn publish_stores_and_returns_blob_id() {
        let mut handler = make_handler();
        handler.mark_active();

        let blob_data = b"hello world".to_vec();
        let expected_id = {
            let mut hasher = Sha256::new();
            hasher.update(&blob_data);
            let hash = hasher.finalize();
            let mut id = [0u8; 32];
            id.copy_from_slice(&hash);
            id
        };

        let result = handler
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: Some("test-ref".to_owned()),
                routing_id: [0x11; 32],
                recipient_hint: None,
                blob_ttl: 60,
                blob: blob_data,
            })
            .await;

        assert!(result.is_ok());
        match unwrap_single(result.unwrap()) {
            RelayMessage::Ok { ref_id, blob_id } => {
                assert_eq!(ref_id, Some("test-ref".to_owned()));
                assert_eq!(blob_id, Some(expected_id));
            }
            other => panic!("expected Ok with blob_id, got {:?}", other),
        }

        // Verify the blob was stored.
        let stored = handler.storage.get(&expected_id).await;
        assert!(stored.is_ok());
        let stored = stored.unwrap();
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().blob, b"hello world");
    }

    #[tokio::test]
    async fn subscribe_registers_and_returns_ok() {
        let mut handler = make_handler();
        handler.mark_active();

        let routing_id = [0x22; 32];
        let result = handler
            .dispatch_message_multi(&ClientMessage::Subscribe {
                ref_id: Some("sub-1".to_owned()),
                routing_id,
                since: None,
            })
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            DispatchResult::Subscription { messages, rx: _ } => {
                // First message should be OK.
                assert!(!messages.is_empty());
                match &messages[0] {
                    RelayMessage::Ok { ref_id, blob_id } => {
                        assert_eq!(*ref_id, Some("sub-1".to_owned()));
                        assert_eq!(*blob_id, None);
                    }
                    other => panic!("expected Ok, got {:?}", other),
                }
            }
            _ => panic!("expected Subscription dispatch result"),
        }

        // Verify subscription was registered.
        assert_eq!(handler.active_subscription_count(), 1);
        let reg = handler.subscriptions.read().await;
        assert!(reg.contains_key(&routing_id));
    }

    #[tokio::test]
    async fn unsubscribe_removes_from_registry() {
        let mut handler = make_handler();
        handler.mark_active();

        let routing_id = [0x33; 32];

        // Subscribe first.
        let _ = handler
            .dispatch_message_multi(&ClientMessage::Subscribe {
                ref_id: None,
                routing_id,
                since: None,
            })
            .await;

        // Then unsubscribe.
        let result = handler
            .dispatch_message_multi(&ClientMessage::Unsubscribe {
                ref_id: Some("unsub-1".to_owned()),
                routing_id,
            })
            .await;

        assert!(result.is_ok());
        match unwrap_single(result.unwrap()) {
            RelayMessage::Ok { ref_id, blob_id } => {
                assert_eq!(ref_id, Some("unsub-1".to_owned()));
                assert_eq!(blob_id, None);
            }
            other => panic!("expected Ok, got {:?}", other),
        }

        // Verify subscription was removed from shared registry.
        let reg = handler.subscriptions.read().await;
        assert!(reg.get(&routing_id).is_none());
    }

    #[tokio::test]
    async fn query_validates_limit() {
        let mut handler = make_handler();
        handler.mark_active();

        // limit = 0 should fail.
        let result = handler
            .dispatch_message_multi(&ClientMessage::Query {
                ref_id: None,
                routing_id: [0x44; 32],
                since: None,
                limit: Some(0),
            })
            .await;
        assert!(result.is_ok());
        match result.unwrap() {
            DispatchResult::Multi(msgs) => {
                assert_eq!(msgs.len(), 1);
                match &msgs[0] {
                    RelayMessage::Err { code, .. } => assert_eq!(*code, code::LIMIT_EXCEEDED),
                    other => panic!("expected Err(LIMIT_EXCEEDED), got {:?}", other),
                }
            }
            _ => panic!("expected Multi dispatch result"),
        }

        // limit > max should fail.
        let result = handler
            .dispatch_message_multi(&ClientMessage::Query {
                ref_id: None,
                routing_id: [0x44; 32],
                since: None,
                limit: Some(MAX_QUERY_LIMIT + 1),
            })
            .await;
        assert!(result.is_ok());
        match result.unwrap() {
            DispatchResult::Multi(msgs) => {
                assert_eq!(msgs.len(), 1);
                match &msgs[0] {
                    RelayMessage::Err { code, .. } => assert_eq!(*code, code::LIMIT_EXCEEDED),
                    other => panic!("expected Err(LIMIT_EXCEEDED), got {:?}", other),
                }
            }
            _ => panic!("expected Multi dispatch result"),
        }
    }

    #[tokio::test]
    async fn query_multi_returns_blobs_and_complete() {
        let mut handler = make_handler();
        handler.mark_active();

        let routing_id = [0x55; 32];

        // Store a blob first.
        let _ = handler
            .storage
            .store(routing_id, [0xAA; 32], None, 60, b"blob-data".to_vec())
            .await;

        let result = handler
            .handle_query_inner(Some("q-1".to_owned()), routing_id, None, None)
            .await;
        assert!(result.is_ok());
        let messages = result.unwrap();
        // Should have at least 1 blob + 1 query_complete event.
        assert!(messages.len() >= 2);
        // Last message is query_complete.
        match messages.last().unwrap() {
            RelayMessage::Event {
                ref_id, event_type, ..
            } => {
                assert_eq!(*ref_id, Some("q-1".to_owned()));
                assert_eq!(event_type, "query_complete");
            }
            other => panic!("expected Event(query_complete), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn delete_returns_ok() {
        let mut handler = make_handler();
        handler.mark_active();

        let result = handler
            .dispatch_message_multi(&ClientMessage::Delete {
                ref_id: Some("del-1".to_owned()),
                blob_id: [0x66; 32],
            })
            .await;

        assert!(result.is_ok());
        match unwrap_single(result.unwrap()) {
            RelayMessage::Ok { ref_id, blob_id } => {
                assert_eq!(ref_id, Some("del-1".to_owned()));
                assert_eq!(blob_id, None);
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn publish_delivers_to_subscribers() {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = crate::relay::subscription::new_registry();
        let token = CancellationToken::new();
        let rate_limiter = PublishRateLimiter::new(100);

        let routing_id = [0x77; 32];
        let (tx, mut rx) = mpsc::channel::<RelayMessage>(16);

        // Register a subscriber for the routing ID.
        {
            let mut reg = subscriptions.write().await;
            reg.entry(routing_id)
                .or_default()
                .push(SubscriberEntry { owner_id: 999, tx });
        }

        let mut handler = WebTransportSessionHandler::new(
            SessionId(1),
            WebTransportSessionConfig {
                delivery_jitter_ms: 0, // No jitter for test determinism.
                ..WebTransportSessionConfig::default()
            },
            storage,
            subscriptions,
            token,
            rate_limiter,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DidSlotRegistry::new(),
        );
        handler.mark_active();

        let result = handler
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint: None,
                blob_ttl: 60,
                blob: b"published-blob".to_vec(),
            })
            .await;

        assert!(result.is_ok());

        // The subscriber should receive the blob.
        let msg = rx.try_recv();
        assert!(msg.is_ok());
        match msg.unwrap() {
            RelayMessage::Blob { blob, .. } => {
                assert_eq!(blob, b"published-blob");
            }
            other => panic!("expected Blob, got {:?}", other),
        }
    }

    #[test]
    fn session_error_display() {
        let err = WebTransportSessionError::TooManyConcurrentStreams { limit: 100 };
        assert_eq!(err.to_string(), "too many concurrent streams (limit: 100)");

        let err = WebTransportSessionError::TooManySubscriptions { limit: 50 };
        assert_eq!(err.to_string(), "too many subscriptions (limit: 50)");

        let err = WebTransportSessionError::ProtocolError("bad frame".to_string());
        assert_eq!(err.to_string(), "protocol error: bad frame");
    }

    #[test]
    fn session_state_transitions() {
        let mut handler = make_handler();
        assert_eq!(handler.state(), SessionState::Connecting);

        handler.mark_active();
        assert_eq!(handler.state(), SessionState::Active);

        // Draining and Closed are set by run() internally.
        handler.state = SessionState::Draining;
        assert_eq!(handler.state(), SessionState::Draining);

        handler.state = SessionState::Closed;
        assert_eq!(handler.state(), SessionState::Closed);
    }
}
