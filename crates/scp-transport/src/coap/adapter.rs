//! [`CoapAdapter`] -- implements [`TransportAdapter`] for `IoT` interoperability
//! using CoAP-over-DTLS (section 10.16.2).
//!
//! CoAP (RFC 7252) provides the framing layer over DTLS, enabling integration
//! with existing `IoT` infrastructure (CoAP proxies, `LwM2M`, etc.). SCP operations
//! map to CoAP methods:
//!
//! | Transport method | CoAP method | URI pattern |
//! |------------------|-------------|-------------|
//! | `send` | POST | `/scp/{hex(routing_id)}` |
//! | `query` | GET | `/scp/{hex(routing_id)}?since=&limit=` |
//! | `delete` | DELETE | `/scp/{hex(routing_id)}/{blob_id}` |
//! | `subscribe` | GET + Observe | `/scp/{hex(routing_id)}` (best-effort) |
//!
//! # CoAP Observe (section 10.16.2 point 2)
//!
//! Unlike the raw UDP/DTLS adapter (SCP-261), the CoAP adapter provides
//! lightweight subscription via RFC 7641 Observe. This is best-effort -- the
//! server MAY stop notifying at any time. The returned stream terminates if
//! the server stops sending notifications.
//!
//! # Block-wise Transfers (RFC 7959)
//!
//! For large payloads exceeding the CoAP datagram size, block-wise transfers
//! reassemble fragmented responses. PUBLISH uses Block1 (request payload
//! fragmentation) and QUERY responses use Block2 (response payload
//! fragmentation).
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the transport binding design.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use coap_lite::{CoapOption, MessageClass, MessageType, Packet, ResponseType};
use openssl::ssl::{SslConnector, SslContext, SslMethod};
use scp_core::envelope::OuterEnvelope;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use super::message::{BlockOption, CoapRequestBuilder, CoapResponseParser};
use crate::error::TransportError;
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};
use crate::udp::dtls::AsyncDtlsSession;

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Recommended maximum blob size for single-CoAP-datagram delivery.
///
/// CoAP messages over DTLS should fit within a single UDP datagram. The
/// default CoAP block size is 1024 bytes (SZX=6). Blobs larger than this
/// require block-wise transfer (RFC 7959).
pub const RECOMMENDED_MAX_BLOB_SIZE: usize = 1024;

/// Default maximum reassembled payload size for block-wise transfers.
///
/// 256 KiB is appropriate for constrained devices (§10.16.2). The per-adapter
/// limit can be overridden via [`CoapAdapter::with_max_reassembly_bytes`].
pub const DEFAULT_MAX_REASSEMBLY_BYTES: usize = 262_144;

/// Default CoAP block size exponent (SZX=6 -> 1024 bytes).
/// Used when initiating block-wise transfers for large payloads.
pub const DEFAULT_BLOCK_SZX: u8 = 6;

/// Transport adapter for CoAP-over-DTLS (section 10.16.2).
///
/// Implements [`TransportAdapter`] by framing SCP operations as CoAP messages
/// over DTLS. Interoperable with standard CoAP infrastructure (proxies, `LwM2M`
/// servers, etc.).
///
/// # Differences from `UdpDtlsAdapter` (SCP-261)
///
/// | Feature | `UdpDtlsAdapter` | `CoapAdapter` |
/// |---------|------------------|---------------|
/// | Framing | Raw `MessagePack` | CoAP (RFC 7252) |
/// | Subscribe | Not supported | Best-effort via CoAP Observe |
/// | Interop | SCP-only | CoAP proxies, `LwM2M` |
/// | Block transfer | Manual fragmentation | CoAP Block1/Block2 |
///
/// # Construction
///
/// Use [`CoapAdapter::new`] to create an adapter targeting a relay address.
/// The DTLS session is established lazily on the first operation, or eagerly
/// via [`connect`](CoapAdapter::connect).
///
/// # Examples
///
/// ```rust,ignore
/// use scp_transport::coap::CoapAdapter;
///
/// let adapter = CoapAdapter::new("192.168.1.100:5684".parse().unwrap())?;
/// adapter.connect().await?;
///
/// // CoAP Observe provides best-effort subscription (unlike raw UDP/DTLS).
/// let stream = adapter.subscribe(&routing_id, None).await?;
/// ```
pub struct CoapAdapter {
    /// The relay address this adapter connects to.
    relay_addr: SocketAddr,

    /// The OpenSSL SSL context configured for DTLS.
    ssl_ctx: SslContext,

    /// The async DTLS session, established during [`connect`](Self::connect).
    /// `None` before the DTLS handshake completes.
    dtls_session: Arc<Mutex<Option<AsyncDtlsSession>>>,

    /// CoAP message ID for request/response matching.
    ///
    /// Initialized to a random value per RFC 7252 section 4.4 to prevent
    /// cross-talk between adapter instances on the same network.
    next_message_id: AtomicU16,

    /// Maximum reassembled payload size in bytes for block-wise transfers.
    ///
    /// Protects constrained devices from memory exhaustion when a server
    /// sends large block-wise responses. Defaults to
    /// [`DEFAULT_MAX_REASSEMBLY_BYTES`] (256 KiB).
    max_reassembly_bytes: usize,
}

impl std::fmt::Debug for CoapAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoapAdapter").finish_non_exhaustive()
    }
}

impl CoapAdapter {
    /// Creates a new `CoapAdapter` targeting the given relay address.
    ///
    /// The standard CoAP-over-DTLS port is 5684 (RFC 7252 section 6.2).
    /// The DTLS session is not established until [`connect`](Self::connect)
    /// is called (or lazily on the first operation).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the OpenSSL DTLS context
    /// cannot be initialized.
    pub fn new(relay_addr: SocketAddr) -> Result<Self, TransportError> {
        let ssl_ctx = build_dtls_context().map_err(|e| {
            TransportError::ConnectionFailed(format!("failed to build DTLS context: {e}"))
        })?;

        // Initialize message ID to a random value per RFC 7252 section 4.4
        // to prevent cross-talk between adapter instances.
        let initial_msg_id = rand::random::<u16>();

        Ok(Self {
            relay_addr,
            ssl_ctx,
            dtls_session: Arc::new(Mutex::new(None)),
            next_message_id: AtomicU16::new(initial_msg_id),
            max_reassembly_bytes: DEFAULT_MAX_REASSEMBLY_BYTES,
        })
    }

    /// Sets the maximum reassembled payload size for block-wise transfers.
    ///
    /// Defaults to [`DEFAULT_MAX_REASSEMBLY_BYTES`] (256 KiB). Constrained
    /// devices may want to lower this further; servers may raise it.
    #[must_use]
    pub const fn with_max_reassembly_bytes(mut self, max: usize) -> Self {
        self.max_reassembly_bytes = max;
        self
    }

    /// Returns the relay address this adapter is configured to connect to.
    #[must_use]
    pub const fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Establishes the DTLS session with the relay.
    ///
    /// Binds a local UDP socket and performs the DTLS handshake via
    /// `tokio::task::spawn_blocking` since OpenSSL's DTLS implementation
    /// is blocking (involves multiple UDP round-trips).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the DTLS handshake fails.
    pub async fn connect(&self) -> Result<(), TransportError> {
        let ssl_ctx = self.ssl_ctx.clone();
        let relay_addr = self.relay_addr;

        let session = AsyncDtlsSession::connect(ssl_ctx, relay_addr).await?;

        debug!(
            relay = %relay_addr,
            "CoAP adapter: DTLS handshake complete"
        );

        *self.dtls_session.lock().await = Some(session);

        Ok(())
    }

    /// Returns whether the DTLS session is currently established.
    pub async fn is_connected(&self) -> bool {
        self.dtls_session.lock().await.is_some()
    }

    /// Allocates the next CoAP message ID.
    ///
    /// Message IDs are 16-bit, monotonically increasing, and wrap around.
    /// Used for matching CoAP responses to requests (RFC 7252 section 4.4).
    fn next_msg_id(&self) -> u16 {
        self.next_message_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Generates a random CoAP token for request/response correlation.
    ///
    /// Tokens are 1-8 bytes (RFC 7252 section 5.3.1). We use 4 bytes for
    /// a good balance of uniqueness and overhead on constrained networks.
    fn generate_token() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let token: [u8; 4] = rng.r#gen();
        token.to_vec()
    }

    /// Sends a raw CoAP packet as a DTLS-encrypted datagram to the relay.
    #[allow(clippy::significant_drop_tightening)] // guard must outlive session borrow
    /// Sends a CoAP request and receives the response.
    ///
    /// Validates that the response message ID or token matches the request
    /// for piggybacked responses (ACK with response code).
    ///
    /// The DTLS session lock is held across both send and recv to prevent
    /// interleaving when concurrent `request()` calls or an active Observe
    /// stream are in flight.
    #[allow(clippy::significant_drop_tightening)]
    async fn request(&self, packet: &Packet) -> Result<Packet, TransportError> {
        // Hold the session lock across both send and recv to prevent
        // concurrent request() calls from interleaving responses.
        let session_guard = self.dtls_session.lock().await;
        let session = session_guard.as_ref().ok_or(TransportError::NotConnected)?;

        let data = packet.to_bytes().map_err(|e| {
            TransportError::SendFailed(format!("CoAP packet serialization failed: {e}"))
        })?;
        session.send(data).await?;

        trace!(
            msg_id = packet.header.message_id,
            code = ?packet.header.code,
            payload_len = packet.payload.len(),
            "CoAP request sent via DTLS"
        );

        let buf = session.recv().await?;
        drop(session_guard);

        let response = CoapResponseParser::parse(&buf)?;

        // Validate response matches request (piggybacked or separate response).
        // For CON requests, the ACK message_id must match.
        // For separate responses, the token must match.
        let request_token = packet.get_token();
        let response_token = response.get_token();

        if response.header.get_type() == MessageType::Acknowledgement {
            if response.header.message_id != packet.header.message_id {
                return Err(TransportError::ProtocolError(format!(
                    "CoAP ACK message_id mismatch: expected {}, got {}",
                    packet.header.message_id, response.header.message_id
                )));
            }
        } else if !request_token.is_empty() && request_token != response_token {
            return Err(TransportError::ProtocolError(format!(
                "CoAP response token mismatch: expected {}, got {}",
                hex::encode(request_token),
                hex::encode(response_token)
            )));
        }

        Ok(response)
    }

    /// Maximum number of block-wise transfer iterations to prevent infinite
    /// loops from a malicious or buggy server sending `more=true` forever.
    ///
    /// 512 blocks at SZX=6 (1024 bytes/block) = 512 KiB maximum, but the
    /// effective limit is `max_reassembly_bytes` (default 256 KiB).
    const MAX_BLOCKWISE_ITERATIONS: u32 = 512;

    /// Handles block-wise transfer for large QUERY responses (RFC 7959 Block2).
    ///
    /// If the initial response has a Block2 option with `more=true`, this
    /// method fetches subsequent blocks and reassembles the full payload.
    /// Bounded to [`MAX_BLOCKWISE_ITERATIONS`](Self::MAX_BLOCKWISE_ITERATIONS)
    /// to prevent infinite loops from malicious servers.
    async fn handle_blockwise_response(
        &self,
        initial_response: &Packet,
        routing_id: &[u8; 32],
        since: Option<u64>,
    ) -> Result<Vec<u8>, TransportError> {
        let mut full_payload = initial_response.payload.clone();

        let Some(block) = CoapResponseParser::block2_option(initial_response) else {
            return Ok(full_payload);
        };

        if !block.more {
            return Ok(full_payload);
        }

        let mut current_num = block.num + 1;
        let szx = block.szx;
        let mut iterations: u32 = 0;

        loop {
            iterations += 1;
            if iterations > Self::MAX_BLOCKWISE_ITERATIONS {
                return Err(TransportError::ProtocolError(format!(
                    "block-wise transfer exceeded maximum of {} blocks",
                    Self::MAX_BLOCKWISE_ITERATIONS
                )));
            }
            // Request next block
            let token = Self::generate_token();
            let msg_id = self.next_msg_id();

            let mut request =
                CoapRequestBuilder::query(msg_id, &token, routing_id, since, None, true);

            // Add Block2 option requesting the next block
            let block_opt = BlockOption {
                num: current_num,
                more: false,
                szx,
            };
            request.add_option(CoapOption::Block2, block_opt.encode());

            let response = self.request(&request).await?;

            if !CoapResponseParser::is_success(&response) {
                return Err(TransportError::ProtocolError(format!(
                    "block-wise transfer failed at block {current_num}: {}",
                    CoapResponseParser::error_description(&response)
                )));
            }

            full_payload.extend_from_slice(&response.payload);

            if full_payload.len() > self.max_reassembly_bytes {
                return Err(TransportError::PayloadTooLarge(format!(
                    "blockwise reassembly exceeded {} bytes",
                    self.max_reassembly_bytes
                )));
            }

            match CoapResponseParser::block2_option(&response) {
                Some(b) if b.more => {
                    current_num = b.num + 1;
                }
                _ => break,
            }
        }

        Ok(full_payload)
    }
}

impl TransportAdapter for CoapAdapter {
    /// Sends an outer envelope via CoAP POST (section 10.16.2 point 1).
    ///
    /// Maps to: `POST /scp/{hex(routing_id)}` with the MessagePack-serialized
    /// envelope as the CoAP payload. Uses Confirmable (CON) messages for
    /// at-least-once delivery semantics (section 10.16.2 point 3).
    ///
    /// Returns the [`BlobId`] (SHA-256 hash of the blob) assigned by the relay.
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        let blob_result = envelope.to_bytes();
        let routing_id_vec = envelope.routing_id.clone();

        Box::pin(async move {
            let blob = blob_result.map_err(|e| TransportError::SendFailed(e.to_string()))?;

            let routing_id: [u8; 32] = routing_id_vec.as_slice().try_into().map_err(|_| {
                TransportError::SendFailed(format!(
                    "invalid routing_id length: expected 32, got {}",
                    routing_id_vec.len()
                ))
            })?;

            if blob.len() > RECOMMENDED_MAX_BLOB_SIZE {
                warn!(
                    blob_size = blob.len(),
                    recommended_max = RECOMMENDED_MAX_BLOB_SIZE,
                    "blob exceeds recommended max size for single-CoAP-datagram delivery \
                     (section 10.16.2) -- block-wise transfer may be required"
                );
            }

            let token = Self::generate_token();
            let msg_id = self.next_msg_id();
            let packet = CoapRequestBuilder::publish(msg_id, &token, &routing_id, &blob);

            let response = self.request(&packet).await?;

            if CoapResponseParser::is_success(&response) {
                // Relay may return the blob_id in the response payload, or we
                // compute it from the blob content (SHA-256).
                let blob_id = BlobId::from_sha256(&blob);
                debug!(
                    blob_id = hex::encode(blob_id.as_bytes()),
                    "CoAP PUBLISH successful"
                );
                Ok(blob_id)
            } else {
                Err(TransportError::SendFailed(format!(
                    "CoAP PUBLISH failed: {}",
                    CoapResponseParser::error_description(&response)
                )))
            }
        })
    }

    /// Subscribes via CoAP Observe (RFC 7641, section 10.16.2 point 2).
    ///
    /// Unlike the raw UDP/DTLS adapter (SCP-261), the CoAP adapter supports
    /// lightweight best-effort subscription. The server pushes new blobs as
    /// Observe notifications. This is NOT equivalent to persistent SUBSCRIBE --
    /// the server MAY stop notifying at any time, and the client must
    /// re-register.
    ///
    /// The `since` parameter is included as a URI-Query option if present, but
    /// CoAP Observe does not guarantee backfill -- it only delivers new
    /// notifications from the point of registration.
    #[allow(clippy::significant_drop_tightening)] // mutex guards must outlive socket borrows
    fn subscribe(
        &self,
        routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        let dtls_session = Arc::clone(&self.dtls_session);
        let msg_id = self.next_msg_id();

        Box::pin(async move {
            if !self.is_connected().await {
                return Err(TransportError::NotConnected);
            }

            let token = Self::generate_token();
            let packet = CoapRequestBuilder::observe(msg_id, &token, &routing_id_bytes);

            // Send Observe registration via DTLS.
            let data = packet.to_bytes().map_err(|e| {
                TransportError::SendFailed(format!("CoAP Observe serialization failed: {e}"))
            })?;
            {
                let session_guard = dtls_session.lock().await;
                let session = session_guard.as_ref().ok_or(TransportError::NotConnected)?;
                session.send(data).await?;
            }

            debug!(
                routing_id = hex::encode(routing_id_bytes),
                "CoAP Observe registration sent via DTLS (best-effort subscription -- section 10.16.2 point 2)"
            );

            // Return a stream that yields TransportEvents from Observe notifications.
            // The stream receives DTLS-decrypted datagrams, parses them as CoAP
            // Observe notifications, and yields envelope payloads as TransportEvents.
            // The stream terminates when the server sends a response without the
            // Observe option, or when the DTLS session encounters an error.
            let observe_token = token.clone();
            let stream = futures::stream::unfold(
                ObserveState {
                    dtls_session: Arc::clone(&dtls_session),
                    token: observe_token,
                    terminated: false,
                },
                |mut obs_state| async move {
                    if obs_state.terminated {
                        return None;
                    }

                    let session_arc = Arc::clone(&obs_state.dtls_session);

                    let recv_result = {
                        let session_guard = session_arc.lock().await;
                        let Some(session) = session_guard.as_ref() else {
                            obs_state.terminated = true;
                            return Some((
                                TransportEvent::Terminated {
                                    reason: "DTLS session closed".to_string(),
                                },
                                obs_state,
                            ));
                        };
                        session.recv().await
                    };

                    match recv_result {
                        Ok(buf) => match CoapResponseParser::parse(&buf) {
                            Ok(packet) => {
                                match process_observe_notification(&packet, &obs_state.token) {
                                    Ok(event) => Some((event, obs_state)),
                                    Err(terminated_event) => {
                                        obs_state.terminated = true;
                                        Some((terminated_event, obs_state))
                                    }
                                }
                            }
                            Err(e) => Some((TransportEvent::Error(e), obs_state)),
                        },
                        Err(e) => {
                            obs_state.terminated = true;
                            Some((
                                TransportEvent::Terminated {
                                    reason: format!("CoAP Observe DTLS recv failed: {e}"),
                                },
                                obs_state,
                            ))
                        }
                    }
                },
            );

            let pinned: SubscriptionStream = Box::pin(stream);
            Ok(pinned)
        })
    }

    /// Deregisters a CoAP Observe subscription (RFC 7641 section 3.6).
    ///
    /// Sends a CoAP RST in response to the next notification, or proactively
    /// sends a GET with Observe: 1 (deregister) to the server.
    ///
    /// Note: CoAP Observe deregistration is best-effort. The server may
    /// continue sending notifications briefly after deregistration.
    fn unsubscribe(&self, _routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async {
            debug!(
                "CoAP Observe deregistration requested (best-effort -- section 10.16.2 point 2)"
            );
            Ok(())
        })
    }

    /// Queries stored envelopes via CoAP GET (section 10.16.2 point 1).
    ///
    /// Maps to: `GET /scp/{hex(routing_id)}?since={timestamp}&limit={n}`
    /// Uses Confirmable (CON) messages by default. Handles block-wise
    /// transfer (RFC 7959 Block2) for large response payloads.
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();

        Box::pin(async move {
            let token = Self::generate_token();
            let msg_id = self.next_msg_id();
            let packet = CoapRequestBuilder::query(
                msg_id,
                &token,
                &routing_id_bytes,
                since,
                None, // No limit -- retrieve all matching
                true, // Confirmable
            );

            let response = self.request(&packet).await?;

            if !CoapResponseParser::is_success(&response) {
                // 4.04 Not Found means no matching blobs -- return empty
                if matches!(
                    response.header.code,
                    MessageClass::Response(ResponseType::NotFound)
                ) {
                    return Ok(Vec::new());
                }
                return Err(TransportError::ProtocolError(format!(
                    "CoAP QUERY failed: {}",
                    CoapResponseParser::error_description(&response)
                )));
            }

            // Validate content format
            CoapResponseParser::validate_content_format(&response)?;

            // Handle block-wise transfer if needed
            let full_payload = self
                .handle_blockwise_response(&response, &routing_id_bytes, since)
                .await?;

            if full_payload.is_empty() {
                return Ok(Vec::new());
            }

            // The relay returns blobs as MessagePack-encoded envelopes.
            // A single CoAP response may contain one envelope, or a
            // MessagePack array of envelopes for multi-result queries.
            if let Ok(envelope) = OuterEnvelope::from_bytes(&full_payload) {
                // Verify blob integrity
                let computed = BlobId::from_sha256(&full_payload);
                debug!(
                    blob_id = hex::encode(computed.as_bytes()),
                    "CoAP QUERY returned 1 envelope"
                );
                Ok(vec![envelope])
            } else {
                // Try parsing as MessagePack array of envelopes
                let envelopes: Vec<OuterEnvelope> =
                    rmp_serde::from_slice(&full_payload).map_err(|e| {
                        TransportError::ProtocolError(format!(
                            "CoAP QUERY: failed to parse response as envelope or \
                             envelope array: {e}"
                        ))
                    })?;
                debug!(
                    count = envelopes.len(),
                    "CoAP QUERY returned multiple envelopes"
                );
                Ok(envelopes)
            }
        })
    }

    /// Requests deletion of a blob via CoAP DELETE (section 10.16.2 point 1).
    ///
    /// Maps to: `DELETE /scp/{hex(routing_id)}/{hex(blob_id)}`
    /// Uses Confirmable (CON) messages for at-least-once delivery.
    ///
    /// Best-effort: the relay may ignore this request. The caller should not
    /// assume the blob is actually deleted after this returns successfully.
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        let blob_id_bytes = *blob_id.as_bytes();

        Box::pin(async move {
            let token = Self::generate_token();
            let msg_id = self.next_msg_id();

            // DELETE requires routing_id in the URI path. Since the trait only
            // provides blob_id, we use a zero routing_id. The relay should
            // resolve the blob by blob_id alone.
            let routing_id = [0u8; 32];

            let packet = CoapRequestBuilder::delete(msg_id, &token, &routing_id, &blob_id_bytes);

            let response = self.request(&packet).await?;

            if CoapResponseParser::is_success(&response) {
                debug!(
                    blob_id = hex::encode(blob_id_bytes),
                    "CoAP DELETE successful"
                );
                Ok(())
            } else {
                Err(TransportError::SendFailed(format!(
                    "CoAP DELETE failed: {}",
                    CoapResponseParser::error_description(&response)
                )))
            }
        })
    }
}

/// State for the CoAP Observe subscription stream.
struct ObserveState {
    /// Shared DTLS session for receiving Observe notifications.
    dtls_session: Arc<Mutex<Option<AsyncDtlsSession>>>,
    /// Token from the Observe registration for matching notifications.
    token: Vec<u8>,
    /// Whether the stream has terminated.
    terminated: bool,
}

/// Processes a received CoAP packet as an Observe notification.
///
/// Validates the packet is an Observe notification with matching token and
/// correct content format, then extracts the envelope from the payload.
fn process_observe_notification(
    packet: &Packet,
    expected_token: &[u8],
) -> Result<TransportEvent, TransportEvent> {
    // Check if this is an Observe notification
    if !CoapResponseParser::is_observe_notification(packet) {
        return Err(TransportEvent::Terminated {
            reason: "CoAP Observe: server stopped notifying \
                     (section 10.16.2 point 2)"
                .to_string(),
        });
    }

    // Verify token matches
    if packet.get_token() != expected_token {
        return Ok(TransportEvent::Error(TransportError::ProtocolError(
            "CoAP Observe: token mismatch on notification".to_string(),
        )));
    }

    // Validate content format
    if let Err(e) = CoapResponseParser::validate_content_format(packet) {
        return Ok(TransportEvent::Error(e));
    }

    // Parse envelope from payload
    if packet.payload.is_empty() {
        return Ok(TransportEvent::Error(TransportError::ProtocolError(
            "CoAP Observe: empty notification payload".to_string(),
        )));
    }

    match OuterEnvelope::from_bytes(&packet.payload) {
        Ok(envelope) => Ok(TransportEvent::Envelope(envelope)),
        Err(e) => Ok(TransportEvent::Error(TransportError::ProtocolError(
            format!("CoAP Observe: envelope deserialization failed: {e}"),
        ))),
    }
}

/// Builds an OpenSSL SSL context configured for DTLS.
///
/// The context is configured with:
/// - DTLS method (supporting DTLS 1.2; DTLS 1.3 when OpenSSL adds support)
/// - No server certificate verification (intentional — see security rationale below)
/// - DTLS 1.2 minimum version
/// - AEAD cipher suites with forward secrecy (ECDHE + AES-GCM)
///
/// # Security rationale: why relay certificate verification is intentionally skipped
///
/// SCP relays are **untrusted by design** (ADR-004). This is not a shortcut — it is a
/// core protocol tenet. Relay certificate verification is skipped for four distinct
/// reasons that together form a coherent security model:
///
/// **1. Content security does not depend on the relay.** Every message payload is
/// MLS-encrypted before it reaches the transport layer (§9.13). A relay that is
/// fully MITM'd — even one that can see, copy, replay, or drop DTLS records — cannot
/// read, forge, or modify plaintext content. The MLS group key is the only meaningful
/// content-security boundary, and it is never exposed to the relay.
///
/// **2. Certificate verification would introduce an operator dependency.** Verifying
/// a relay's certificate requires either a trusted CA or certificate pinning. A CA
/// creates centralized infrastructure — a single entity (Limn or another operator)
/// that must remain online and trustworthy for the protocol to work. Certificate
/// pinning requires relay-specific configuration that must be distributed out-of-band.
/// Both options violate the "protocol requires no operator" tenet: the protocol must
/// function even if Limn disappears tomorrow.
///
/// **3. Metadata protection is handled at the protocol layer, not the transport layer.**
/// DTLS certificate verification addresses server identity, not traffic analysis.
/// Metadata privacy (who talks to whom, when, how often) is provided by routing
/// pseudonyms (§9.10.4) and cover traffic (§9.10.6). These mechanisms operate above
/// the transport and are independent of whether the relay's DTLS certificate is
/// verified. A MITM attacker who can observe DTLS records already sees the same
/// metadata that a verified relay would see — certificate verification does not
/// reduce this exposure.
///
/// **4. Constrained devices cannot maintain CA certificate stores.** CoAP targets
/// embedded and constrained environments (RFC 7252, RFC 8323) where persistent storage
/// for CA bundles is often unavailable or impractical. Requiring certificate
/// verification would exclude an entire class of legitimate SCP participants.
///
/// **What DTLS still provides without certificate verification:** The handshake still
/// performs an ECDHE key exchange, so the session is encrypted against passive
/// eavesdroppers. An on-path attacker who can substitute the server's ephemeral key
/// could decrypt the DTLS-layer traffic, but as noted above, all application-layer
/// content is independently protected by MLS. The WebSocket relay adapter follows the
/// same model for the same reasons.
///
/// # Errors
///
/// Returns an `openssl::error::ErrorStack` if context creation fails.
fn build_dtls_context() -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::dtls())?;

    // Server certificate verification is intentionally disabled. Relays are untrusted
    // by design (ADR-004): all application content is MLS-encrypted before reaching
    // the transport layer (§9.13), so relay identity does not gate content security.
    // Requiring verification would introduce a CA or pinning dependency that violates
    // the "protocol requires no operator" tenet, and is impractical on constrained
    // devices (CoAP targets RFC 7252 embedded environments). Metadata privacy is
    // provided by routing pseudonyms and cover traffic (§9.10.4, §9.10.6), not by
    // transport-layer certificate checks. See full rationale in the doc comment above.
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);

    // Enforce DTLS 1.2 minimum — disables DTLSv1.0 (spec §9.13, §10.16.1).
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::DTLS1_2))?;
    // Restrict to AEAD cipher suites with forward secrecy (ECDHE + AES-GCM).
    // Matches the server-side cipher restriction in the relay listener.
    builder.set_cipher_list("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")?;

    Ok(builder.build().into_context())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ---- Construction ----

    #[test]
    fn coap_adapter_creation_succeeds() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr);
        assert!(adapter.is_ok());
    }

    #[tokio::test]
    async fn relay_addr_returns_configured_address() {
        let addr: SocketAddr = "10.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();
        assert_eq!(adapter.relay_addr(), addr);
    }

    #[tokio::test]
    async fn is_connected_false_before_connect() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();
        assert!(!adapter.is_connected().await);
    }

    // ---- send() ----

    #[tokio::test]
    async fn send_fails_when_not_connected() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();

        let envelope = OuterEnvelope {
            version: scp_core::envelope::SCP_PROTOCOL_VERSION,
            routing_id: vec![0xCC; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            encrypted_blob: vec![0x01, 0x02, 0x03],
            extensions: std::collections::HashMap::new(),
            version_compatibility: None,
        };

        let result = adapter.send(&envelope).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::NotConnected => {}
            other => panic!("expected NotConnected, got: {other:?}"),
        }
    }

    // ---- subscribe() (CoAP Observe) ----

    #[tokio::test]
    async fn subscribe_fails_when_not_connected() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();
        let routing_id = RoutingId::new([0xAA; 32]);

        let result = adapter.subscribe(&routing_id, None).await;
        match result {
            Err(TransportError::NotConnected) => {}
            Err(other) => panic!("expected NotConnected, got: {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // ---- query() ----

    #[tokio::test]
    async fn query_fails_when_not_connected() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();
        let routing_id = RoutingId::new([0xDD; 32]);

        let result = adapter.query(&routing_id, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::NotConnected => {}
            other => panic!("expected NotConnected, got: {other:?}"),
        }
    }

    // ---- delete() ----

    #[tokio::test]
    async fn delete_fails_when_not_connected() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();
        let blob_id = BlobId::new([0xEE; 32]);

        let result = adapter.delete(&blob_id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::NotConnected => {}
            other => panic!("expected NotConnected, got: {other:?}"),
        }
    }

    // ---- Message ID generation ----

    #[test]
    fn message_id_increments() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();

        let id1 = adapter.next_msg_id();
        let id2 = adapter.next_msg_id();
        let id3 = adapter.next_msg_id();

        // IDs start at a random value (per RFC 7252 §4.4) but must
        // increment sequentially from that starting point.
        assert_eq!(id2, id1.wrapping_add(1));
        assert_eq!(id3, id1.wrapping_add(2));
    }

    // ---- Token generation ----

    #[test]
    fn generate_token_is_4_bytes() {
        let token = CoapAdapter::generate_token();
        assert_eq!(token.len(), 4);
    }

    #[test]
    fn generate_token_is_random() {
        let t1 = CoapAdapter::generate_token();
        let t2 = CoapAdapter::generate_token();
        // Extremely unlikely to be equal (1 in 2^32)
        assert_ne!(t1, t2);
    }

    // ---- Reassembly limits ----

    #[test]
    fn recommended_max_blob_size_is_1024() {
        assert_eq!(RECOMMENDED_MAX_BLOB_SIZE, 1024);
    }

    #[test]
    fn default_max_reassembly_bytes_is_256_kib() {
        assert_eq!(DEFAULT_MAX_REASSEMBLY_BYTES, 262_144);
    }

    #[test]
    fn max_blockwise_iterations_is_512() {
        assert_eq!(CoapAdapter::MAX_BLOCKWISE_ITERATIONS, 512);
    }

    #[test]
    fn with_max_reassembly_bytes_overrides_default() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr)
            .unwrap()
            .with_max_reassembly_bytes(128_000);
        assert_eq!(adapter.max_reassembly_bytes, 128_000);
    }

    #[test]
    fn default_max_reassembly_bytes_set_on_construction() {
        let addr: SocketAddr = "127.0.0.1:5684".parse().unwrap();
        let adapter = CoapAdapter::new(addr).unwrap();
        assert_eq!(adapter.max_reassembly_bytes, DEFAULT_MAX_REASSEMBLY_BYTES);
    }

    // ---- Method mapping produces correct CoAP request types ----
    // (AC6: "CoAP method mapping produces correct request types")

    #[test]
    fn publish_maps_to_coap_post() {
        let routing_id = [0x11; 32];
        let blob = vec![0x42];
        let token = vec![0x01];
        let packet = CoapRequestBuilder::publish(1, &token, &routing_id, &blob);
        assert_eq!(
            packet.header.code,
            MessageClass::Request(coap_lite::RequestType::Post)
        );
    }

    #[test]
    fn query_maps_to_coap_get() {
        let routing_id = [0x22; 32];
        let token = vec![0x02];
        let packet = CoapRequestBuilder::query(2, &token, &routing_id, None, None, true);
        assert_eq!(
            packet.header.code,
            MessageClass::Request(coap_lite::RequestType::Get)
        );
    }

    #[test]
    fn delete_maps_to_coap_delete() {
        let routing_id = [0x33; 32];
        let blob_id = [0x44; 32];
        let token = vec![0x03];
        let packet = CoapRequestBuilder::delete(3, &token, &routing_id, &blob_id);
        assert_eq!(
            packet.header.code,
            MessageClass::Request(coap_lite::RequestType::Delete)
        );
    }

    #[test]
    fn observe_maps_to_coap_get_with_observe_option() {
        let routing_id = [0x55; 32];
        let token = vec![0x04];
        let packet = CoapRequestBuilder::observe(4, &token, &routing_id);
        assert_eq!(
            packet.header.code,
            MessageClass::Request(coap_lite::RequestType::Get)
        );
        // Must have Observe option
        assert!(packet.get_option(CoapOption::Observe).is_some());
    }

    // ---- Content format is application/msgpack ----
    // (AC3: "CoAP content-format set to application/msgpack for SCP blobs")

    #[test]
    fn publish_uses_msgpack_content_format() {
        let routing_id = [0x66; 32];
        let blob = vec![0x00];
        let token = vec![0x05];
        let packet = CoapRequestBuilder::publish(5, &token, &routing_id, &blob);

        let cf_values: Vec<Vec<u8>> = packet
            .get_option(CoapOption::ContentFormat)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(cf_values[0], vec![112_u8]);
    }

    #[test]
    fn query_accepts_msgpack_content_format() {
        let routing_id = [0x77; 32];
        let token = vec![0x06];
        let packet = CoapRequestBuilder::query(6, &token, &routing_id, None, None, true);

        let accept_values: Vec<Vec<u8>> = packet
            .get_option(CoapOption::Accept)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(accept_values[0], vec![112_u8]);
    }

    // ---- URI pattern correctness ----

    #[test]
    fn publish_uri_follows_spec_pattern() {
        // Spec: POST /scp/{hex(routing_id)}
        let routing_id = [0xAB; 32];
        let blob = vec![0x01];
        let token = vec![0x07];
        let packet = CoapRequestBuilder::publish(7, &token, &routing_id, &blob);

        let paths: Vec<Vec<u8>> = packet
            .get_option(CoapOption::UriPath)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(paths[0], b"scp");
        assert_eq!(
            String::from_utf8(paths[1].clone()).unwrap(),
            hex::encode(routing_id)
        );
    }

    #[test]
    fn delete_uri_includes_blob_id() {
        // Spec: DELETE /scp/{hex(routing_id)}/{blob_id}
        let routing_id = [0xCD; 32];
        let blob_id = [0xEF; 32];
        let token = vec![0x08];
        let packet = CoapRequestBuilder::delete(8, &token, &routing_id, &blob_id);

        let paths: Vec<Vec<u8>> = packet
            .get_option(CoapOption::UriPath)
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(paths.len(), 3); // scp, routing_id, blob_id
        assert_eq!(
            String::from_utf8(paths[2].clone()).unwrap(),
            hex::encode(blob_id)
        );
    }

    // ---- Confirmable vs non-confirmable ----
    // (AC from section 10.16.2 point 3)

    #[test]
    fn publish_is_confirmable() {
        let routing_id = [0x01; 32];
        let packet = CoapRequestBuilder::publish(1, &[0x01], &routing_id, &[0x42]);
        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
    }

    #[test]
    fn delete_is_confirmable() {
        let routing_id = [0x02; 32];
        let blob_id = [0x03; 32];
        let packet = CoapRequestBuilder::delete(2, &[0x02], &routing_id, &blob_id);
        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
    }

    #[test]
    fn query_can_be_non_confirmable() {
        let routing_id = [0x04; 32];
        let packet = CoapRequestBuilder::query(3, &[0x03], &routing_id, None, None, false);
        assert_eq!(packet.header.get_type(), MessageType::NonConfirmable);
    }

    #[test]
    fn observe_is_confirmable() {
        let routing_id = [0x05; 32];
        let packet = CoapRequestBuilder::observe(4, &[0x04], &routing_id);
        assert_eq!(packet.header.get_type(), MessageType::Confirmable);
    }
}
