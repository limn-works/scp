//! [`UdpDtlsAdapter`] -- implements [`TransportAdapter`] for constrained devices
//! using MessagePack-over-DTLS (§10.16.1).
//!
//! Each SCP operation (PUBLISH, QUERY, DELETE) is sent as an independent DTLS
//! datagram using the same `MessagePack` wire format as ADR-004. `subscribe()` is
//! not supported -- constrained devices poll via `query()` instead.
//!
//! # DTLS Session Management
//!
//! The adapter manages a DTLS session with the relay. The DTLS handshake is
//! performed via `tokio::task::spawn_blocking` since OpenSSL's DTLS
//! implementation is blocking. All send/recv operations go through the
//! encrypted [`AsyncDtlsSession`](super::dtls::AsyncDtlsSession).
//!
//! # Datagram Size Constraints
//!
//! Common networks allow ~1200 byte UDP payloads. Envelopes exceeding the path
//! MTU require fragmentation at the DTLS layer. Recommended max blob size:
//! 1024 bytes for single-datagram delivery (§10.16.1).
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the transport binding design.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use openssl::ssl::{SslConnector, SslContext, SslMethod};
use scp_core::envelope::OuterEnvelope;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::dtls::AsyncDtlsSession;
use crate::error::TransportError;
use crate::native::protocol::{ClientMessage, RelayMessage};
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter};

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Recommended maximum blob size for single-datagram delivery (§10.16.1).
///
/// Common networks allow ~1200 byte UDP payloads. This is a conservative
/// limit that accounts for DTLS overhead and typical path MTU constraints.
pub const RECOMMENDED_MAX_BLOB_SIZE: usize = 1024;

/// Transport adapter for constrained devices using MessagePack-over-DTLS.
///
/// Implements [`TransportAdapter`] by sending SCP operations as DTLS
/// datagrams. Each operation (PUBLISH, QUERY, DELETE) is an independent
/// datagram (or datagram sequence for payloads exceeding path MTU).
///
/// `subscribe()` is not supported -- constrained devices poll via `query()`
/// at configurable intervals. Calling `subscribe()` returns
/// [`TransportError::NotSupported`].
///
/// # Construction
///
/// Use [`UdpDtlsAdapter::new`] to create an adapter targeting a relay address.
/// The DTLS session is established lazily on the first operation, or eagerly
/// via [`connect`](UdpDtlsAdapter::connect).
///
/// # Examples
///
/// ```rust,ignore
/// use scp_transport::udp::UdpDtlsAdapter;
///
/// let adapter = UdpDtlsAdapter::new("192.168.1.100:9443".parse().unwrap());
/// adapter.connect().await?;
///
/// // Poll for messages (no subscribe -- constrained devices poll).
/// let envelopes = adapter.query(&routing_id, Some(last_seen_ts)).await?;
/// ```
pub struct UdpDtlsAdapter {
    /// The relay address this adapter connects to.
    relay_addr: SocketAddr,

    /// The OpenSSL SSL context configured for DTLS.
    ssl_ctx: SslContext,

    /// The async DTLS session, established during [`connect`](Self::connect).
    /// `None` before the DTLS handshake completes.
    dtls_session: Arc<Mutex<Option<AsyncDtlsSession>>>,
}

impl std::fmt::Debug for UdpDtlsAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpDtlsAdapter").finish_non_exhaustive()
    }
}

impl UdpDtlsAdapter {
    /// Creates a new `UdpDtlsAdapter` targeting the given relay address.
    ///
    /// The DTLS session is not established until [`connect`](Self::connect) is
    /// called (or lazily on the first operation).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the OpenSSL DTLS context
    /// cannot be initialized.
    pub fn new(relay_addr: SocketAddr) -> Result<Self, TransportError> {
        let ssl_ctx = build_dtls_context().map_err(|e| {
            TransportError::ConnectionFailed(format!("failed to build DTLS context: {e}"))
        })?;

        Ok(Self {
            relay_addr,
            ssl_ctx,
            dtls_session: Arc::new(Mutex::new(None)),
        })
    }

    /// Returns the relay address this adapter is configured to connect to.
    #[must_use]
    pub const fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Establishes the DTLS session with the relay.
    ///
    /// Performs the DTLS handshake via `tokio::task::spawn_blocking` since
    /// OpenSSL's DTLS implementation is blocking (involves multiple UDP
    /// round-trips).
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
            "UDP/DTLS adapter: DTLS handshake complete"
        );

        *self.dtls_session.lock().await = Some(session);

        Ok(())
    }

    /// Returns whether the DTLS session is currently established.
    pub async fn is_connected(&self) -> bool {
        self.dtls_session.lock().await.is_some()
    }

    /// Sends a raw `MessagePack`-encoded datagram to the relay via DTLS.
    ///
    /// The datagram is the serialized `ClientMessage` in ADR-004 `MessagePack`
    /// format, encrypted and sent as a DTLS record.
    #[allow(clippy::significant_drop_tightening)] // guard must outlive session borrow
    async fn send_datagram(&self, data: &[u8]) -> Result<(), TransportError> {
        let session_guard = self.dtls_session.lock().await;
        let session = session_guard.as_ref().ok_or(TransportError::NotConnected)?;

        session.send(data.to_vec()).await
    }

    /// Receives and decrypts a datagram from the relay via DTLS.
    ///
    /// Returns the decrypted `MessagePack` payload from a DTLS record.
    #[allow(clippy::significant_drop_tightening)] // guard must outlive session borrow
    async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let session_guard = self.dtls_session.lock().await;
        let session = session_guard.as_ref().ok_or(TransportError::NotConnected)?;

        session.recv().await
    }

    /// Sends a `ClientMessage` and receives the relay's response.
    ///
    /// Serializes the message as `MessagePack` (ADR-004 wire format), sends it
    /// as a DTLS datagram, and deserializes the response.
    async fn send_request(&self, msg: &ClientMessage) -> Result<RelayMessage, TransportError> {
        if !self.is_connected().await {
            return Err(TransportError::NotConnected);
        }

        let data = rmp_serde::to_vec_named(msg).map_err(|e| {
            TransportError::SendFailed(format!("MessagePack serialization failed: {e}"))
        })?;

        self.send_datagram(&data).await?;

        let response_data = self.recv_datagram().await?;

        // `RelayMessage::from_bytes` rejects payloads exceeding `MAX_MESSAGE_SIZE`
        // before invoking the MessagePack deserializer, preventing allocation bombs.
        // The byte payload is relay-supplied and some serde codecs include byte
        // excerpts in `Display`; do not propagate the serde error into the
        // surfaced `TransportError`.
        let response: RelayMessage = RelayMessage::from_bytes(&response_data).map_err(|_| {
            tracing::warn!("relay message deserialization failed");
            TransportError::ProtocolError("invalid relay message".to_owned())
        })?;

        Ok(response)
    }
}

impl TransportAdapter for UdpDtlsAdapter {
    /// Sends an outer envelope via PUBLISH as a DTLS datagram.
    ///
    /// Extracts `routing_id`, `recipient_hint`, and `blob_ttl` from the
    /// [`OuterEnvelope`], serializes the entire envelope as the blob payload,
    /// and sends a PUBLISH datagram to the relay using the ADR-004 `MessagePack`
    /// wire format.
    ///
    /// Returns the [`BlobId`] (SHA-256 hash of the blob) assigned by the relay.
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
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

            if blob.len() > RECOMMENDED_MAX_BLOB_SIZE {
                warn!(
                    blob_size = blob.len(),
                    recommended_max = RECOMMENDED_MAX_BLOB_SIZE,
                    "blob exceeds recommended max size for single-datagram delivery (section 10.16.1)"
                );
            }

            let msg = ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint,
                blob_ttl,
                blob,
            };

            let response = self.send_request(&msg).await?;

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

    /// Returns [`TransportError::NotSupported`] -- constrained devices cannot
    /// maintain persistent subscriptions over connectionless UDP datagrams.
    ///
    /// Constrained devices should poll via [`query()`](Self::query) at
    /// configurable intervals instead. See §10.16.1 point 6 and §10.16.3.
    fn subscribe(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        Box::pin(async {
            Err(TransportError::NotSupported(
                "subscribe() is not supported over UDP/DTLS -- constrained devices \
                 should poll via query() at configurable intervals instead \
                 (see spec section 10.16.1 point 6 and section 10.16.3)"
                    .to_string(),
            ))
        })
    }

    /// Returns [`TransportError::NotSupported`] -- there are no subscriptions
    /// to unsubscribe from over UDP/DTLS.
    fn unsubscribe(&self, _routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async {
            Err(TransportError::NotSupported(
                "unsubscribe() is not supported over UDP/DTLS -- no subscriptions exist \
                 to unsubscribe from (see spec section 10.16.1 point 6)"
                    .to_string(),
            ))
        })
    }

    /// Queries stored envelopes for a routing ID via QUERY datagram.
    ///
    /// Sends a QUERY datagram and collects all BLOB responses until a
    /// `query_complete` EVENT is received. This is the primary data retrieval
    /// mechanism for constrained devices (polling replaces subscription).
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();

        Box::pin(async move {
            let msg = ClientMessage::Query {
                ref_id: None,
                routing_id: routing_id_bytes,
                since,
                limit: None,
            };

            let response = self.send_request(&msg).await?;

            match response {
                RelayMessage::Blob {
                    blob_id,
                    routing_id: _,
                    blob,
                    ..
                } => {
                    // Verify blob integrity (SHA-256 match).
                    let computed = BlobId::from_sha256(&blob);
                    let declared = BlobId::new(blob_id);
                    if computed != declared {
                        return Err(TransportError::BlobIntegrityError {
                            expected: hex::encode(blob_id),
                            actual: hex::encode(computed.as_bytes()),
                        });
                    }

                    let envelope = OuterEnvelope::from_bytes(&blob).map_err(|_| {
                        // The blob is relay-supplied; do not propagate the
                        // serde error into the TransportError -- some codecs
                        // include byte excerpts in `Display`.
                        tracing::warn!("envelope deserialization failed");
                        TransportError::ProtocolError(
                            "failed to deserialize envelope from blob".to_owned(),
                        )
                    })?;

                    Ok(vec![envelope])
                }
                RelayMessage::Event { event_type, .. } if event_type == "query_complete" => {
                    // No results.
                    Ok(Vec::new())
                }
                RelayMessage::Err { code, msg, .. } => Err(TransportError::ProtocolError(format!(
                    "relay error {code}: {msg}"
                ))),
                _ => Err(TransportError::ProtocolError(
                    "unexpected response to QUERY".to_string(),
                )),
            }
        })
    }

    /// Requests deletion of a blob via DELETE datagram.
    ///
    /// Best-effort: the relay may ignore this request. The caller should not
    /// assume the blob is actually deleted after this returns successfully.
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        let blob_id_bytes = *blob_id.as_bytes();

        Box::pin(async move {
            let msg = ClientMessage::Delete {
                ref_id: None,
                blob_id: blob_id_bytes,
            };

            let response = self.send_request(&msg).await?;

            match response {
                RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                    "relay error {code}: {msg}"
                ))),
                // Best-effort: treat all non-error responses as success.
                _ => Ok(()),
            }
        })
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
/// **4. Constrained devices cannot maintain CA certificate stores.** UDP/DTLS targets
/// environments — `IoT`, embedded, constrained-node networks — where persistent storage
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
    // devices. Metadata privacy is provided by routing pseudonyms and cover traffic
    // (§9.10.4, §9.10.6), not by transport-layer certificate checks. See full
    // rationale in the doc comment above.
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

    #[test]
    fn udp_dtls_adapter_creation_succeeds() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let adapter = UdpDtlsAdapter::new(addr);
        assert!(adapter.is_ok());
    }

    #[tokio::test]
    async fn subscribe_returns_not_supported() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let adapter = UdpDtlsAdapter::new(addr).unwrap();
        let routing_id = RoutingId::new([0xAA; 32]);

        let result = adapter.subscribe(&routing_id, None).await;

        match result {
            Err(TransportError::NotSupported(msg)) => {
                assert!(
                    msg.contains("subscribe()"),
                    "error message should mention subscribe()"
                );
                assert!(
                    msg.contains("query()"),
                    "error message should guide users to use query()"
                );
            }
            Err(other) => panic!("expected NotSupported, got: {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn unsubscribe_returns_not_supported() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let adapter = UdpDtlsAdapter::new(addr).unwrap();
        let routing_id = RoutingId::new([0xBB; 32]);

        let result = adapter.unsubscribe(&routing_id).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::NotSupported(msg) => {
                assert!(msg.contains("unsubscribe()"));
            }
            other => panic!("expected NotSupported, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_fails_when_not_connected() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let adapter = UdpDtlsAdapter::new(addr).unwrap();

        // Build a minimal outer envelope for testing.
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

    #[tokio::test]
    async fn query_fails_when_not_connected() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let adapter = UdpDtlsAdapter::new(addr).unwrap();
        let routing_id = RoutingId::new([0xDD; 32]);

        let result = adapter.query(&routing_id, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::NotConnected => {}
            other => panic!("expected NotConnected, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_fails_when_not_connected() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let adapter = UdpDtlsAdapter::new(addr).unwrap();
        let blob_id = BlobId::new([0xEE; 32]);

        let result = adapter.delete(&blob_id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::NotConnected => {}
            other => panic!("expected NotConnected, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn is_connected_false_before_connect() {
        let addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let adapter = UdpDtlsAdapter::new(addr).unwrap();
        assert!(!adapter.is_connected().await);
    }

    #[test]
    fn recommended_max_blob_size_is_1024() {
        assert_eq!(RECOMMENDED_MAX_BLOB_SIZE, 1024);
    }
}
