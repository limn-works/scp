//! Production DHT client using the `mainline` crate for BEP44 operations.
//!
//! [`PkarrDhtClient`] wraps the `mainline::Dht` client to perform BEP44
//! signed mutable item publish and resolve operations on the `BitTorrent`
//! Mainline DHT network.
//!
//! An optional list of HTTP gateway URLs provides fallback resolution when
//! direct DHT access is unavailable (e.g., behind restrictive firewalls).
//! Gateways are queried in order; the first successful response is returned.
//! Gateway format follows the pkarr relay convention: `GET /{z-base-32-key}`
//! returns a binary payload of `signature (64 bytes) || seq (8 bytes BE) || value`.
//!
//! See §3.10 (DID Resolution Layers) and ADR-003 in `.docs/adrs/phase-1.md`.

use std::time::Duration;

use mainline::async_dht::AsyncDht;
use mainline::{Dht, MutableItem};
use tracing::{debug, info, warn};

use super::{DhtClient, DhtRecord};
use crate::IdentityError;

/// Default timeout for DHT operations.
const DHT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for HTTP gateway requests.
const GATEWAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Size of BEP44 gateway response header: 64-byte signature + 8-byte sequence.
const GATEWAY_HEADER_SIZE: usize = 72;

/// Production DHT client using the `mainline` crate for BEP44 operations.
///
/// Connects to the `BitTorrent` Mainline DHT network (millions of nodes) for
/// publishing and resolving BEP44 signed mutable items. This is the production
/// replacement for [`InMemoryDhtClient`](super::InMemoryDhtClient).
///
/// # Construction
///
/// Use [`PkarrDhtClient::new()`] for default configuration or
/// [`PkarrDhtClient::builder()`] for custom settings.
///
/// # HTTP Gateway Fallback
///
/// When configured with gateway URLs, resolution first attempts direct DHT
/// lookup. If the DHT returns no result, each gateway is tried in order.
/// Gateways are NOT used for publishing — BEP44 publish always goes to the
/// DHT directly to ensure the record propagates across the network.
///
/// # Thread Safety
///
/// `PkarrDhtClient` is `Send + Sync` and can be shared across tasks via `Arc`.
///
/// See §3.10.3 (Layer 2: Mainline DHT) and ADR-003.
pub struct PkarrDhtClient {
    /// The async Mainline DHT client.
    dht: AsyncDht,
    /// Optional HTTP gateway URLs for fallback resolution.
    /// Format: `https://relay.example.com` (key appended as `/{z-base-32-key}`).
    gateway_urls: Vec<String>,
    /// HTTP client for gateway requests (created lazily only when gateways
    /// are configured).
    http_client: Option<reqwest::Client>,
    /// Timeout for DHT operations.
    dht_timeout: Duration,
    /// Timeout for individual gateway HTTP requests.
    gateway_timeout: Duration,
}

// mainline::Dht is Send + Sync; reqwest::Client is Send + Sync.
// Manual impl not needed but the doc comment above promises it.

impl std::fmt::Debug for PkarrDhtClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkarrDhtClient")
            .field("gateway_urls", &self.gateway_urls)
            .field("dht_timeout", &self.dht_timeout)
            .field("gateway_timeout", &self.gateway_timeout)
            .finish_non_exhaustive()
    }
}

impl PkarrDhtClient {
    /// Creates a new `PkarrDhtClient` with default settings and no HTTP
    /// gateway fallback.
    ///
    /// Connects to the Mainline DHT using default bootstrap nodes.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::DhtPublishFailed`] if the DHT client cannot
    /// be created (e.g., socket binding failure).
    pub fn new() -> Result<Self, IdentityError> {
        Self::builder().build()
    }

    /// Returns a builder for customizing the `PkarrDhtClient`.
    #[must_use]
    pub fn builder() -> PkarrDhtClientBuilder {
        PkarrDhtClientBuilder::default()
    }

    /// Attempts to resolve a BEP44 record via HTTP gateway fallback.
    ///
    /// Queries each configured gateway in order. The first successful
    /// response is returned. Gateway URL format:
    /// `GET {base_url}/{z-base-32-encoded-public-key}`
    ///
    /// Response format (binary):
    /// - Bytes 0..64: Ed25519 signature
    /// - Bytes 64..72: sequence number (big-endian i64, cast to u64)
    /// - Bytes 72..: value (DID document bytes)
    async fn resolve_via_gateway(
        &self,
        public_key: &[u8; 32],
    ) -> Result<Option<DhtRecord>, IdentityError> {
        let Some(http_client) = &self.http_client else {
            return Ok(None);
        };

        if self.gateway_urls.is_empty() {
            return Ok(None);
        }

        // Encode the public key as z-base-32 for the URL path.
        let key_encoded = zbase32::encode(public_key);

        for gateway_url in &self.gateway_urls {
            let url = format!("{gateway_url}/{key_encoded}");
            debug!(url = %url, "querying HTTP gateway for BEP44 record");

            match http_client.get(&url).send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        if response.status().as_u16() == 404 {
                            debug!(
                                gateway = %gateway_url,
                                "gateway returned 404 — record not found"
                            );
                            continue;
                        }
                        warn!(
                            gateway = %gateway_url,
                            status = %response.status(),
                            "gateway returned error status"
                        );
                        continue;
                    }

                    match response.bytes().await {
                        Ok(body) => {
                            if body.len() < GATEWAY_HEADER_SIZE {
                                warn!(
                                    gateway = %gateway_url,
                                    body_len = body.len(),
                                    "gateway response too short (need >= {GATEWAY_HEADER_SIZE} bytes)"
                                );
                                continue;
                            }

                            let mut signature = [0u8; 64];
                            signature.copy_from_slice(&body[..64]);

                            let seq_bytes: [u8; 8] = body[64..72].try_into().map_err(|_| {
                                IdentityError::DhtResolveFailed(
                                    "invalid sequence bytes in gateway response".to_owned(),
                                )
                            })?;
                            let seq_i64 = i64::from_be_bytes(seq_bytes);
                            // BEP44 uses i64 but our trait uses u64. Negative
                            // sequence numbers are invalid; treat as 0.
                            let seq = u64::try_from(seq_i64).unwrap_or(0);

                            let value = body[GATEWAY_HEADER_SIZE..].to_vec();

                            info!(
                                gateway = %gateway_url,
                                seq = seq,
                                value_len = value.len(),
                                "resolved BEP44 record via HTTP gateway"
                            );

                            return Ok(Some(DhtRecord {
                                value,
                                signature,
                                seq,
                            }));
                        }
                        Err(e) => {
                            warn!(
                                gateway = %gateway_url,
                                error = %e,
                                "failed to read gateway response body"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        gateway = %gateway_url,
                        error = %e,
                        "HTTP gateway request failed"
                    );
                }
            }
        }

        // All gateways failed or returned 404.
        Ok(None)
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl DhtClient for PkarrDhtClient {
    fn publish(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        async move {
            // BEP44 uses i64 for sequence numbers. Saturate at i64::MAX
            // (which is ~9.2e18 — far beyond any realistic sequence).
            let seq_i64 = i64::try_from(seq).unwrap_or(i64::MAX);

            // Construct the MutableItem from pre-signed components.
            // The `new_signed_unchecked` constructor accepts already-signed
            // data — we sign via KeyCustody, not mainline's signing.
            let item = MutableItem::new_signed_unchecked(
                *public_key,
                *signature,
                value,
                seq_i64,
                None, // No salt — BEP44 mutable items for DID are unsalted.
            );

            // Use compare-and-swap with the previous sequence number to
            // prevent overwriting a newer record on the DHT. If seq > 1,
            // CAS expects the prior sequence; if seq == 0 or 1, no CAS.
            let cas = if seq_i64 > 0 { Some(seq_i64 - 1) } else { None };

            debug!(
                seq = seq,
                value_len = value.len(),
                "publishing BEP44 mutable item to Mainline DHT"
            );

            // Apply timeout to the DHT put operation.
            let result =
                tokio::time::timeout(self.dht_timeout, self.dht.put_mutable(item, cas)).await;

            match result {
                Ok(Ok(id)) => {
                    info!(
                        target_id = %id,
                        seq = seq,
                        "BEP44 mutable item published to Mainline DHT"
                    );
                    Ok(())
                }
                Ok(Err(e)) => Err(IdentityError::DhtPublishFailed(format!(
                    "Mainline DHT put_mutable failed: {e}"
                ))),
                Err(_elapsed) => Err(IdentityError::DhtPublishFailed(format!(
                    "Mainline DHT put_mutable timed out after {}s",
                    self.dht_timeout.as_secs()
                ))),
            }
        }
    }

    fn resolve(
        &self,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<Option<DhtRecord>, IdentityError>> + Send {
        async move {
            debug!("resolving BEP44 mutable item from Mainline DHT");

            // Try direct DHT resolution first.
            let dht_result = tokio::time::timeout(
                self.dht_timeout,
                self.dht.get_mutable_most_recent(public_key, None),
            )
            .await;

            match dht_result {
                Ok(Some(item)) => {
                    let seq_i64 = item.seq();
                    let seq = u64::try_from(seq_i64).unwrap_or(0);

                    info!(
                        seq = seq,
                        value_len = item.value().len(),
                        "resolved BEP44 record from Mainline DHT"
                    );

                    return Ok(Some(DhtRecord {
                        value: item.value().to_vec(),
                        signature: *item.signature(),
                        seq,
                    }));
                }
                Ok(None) => {
                    debug!("no BEP44 record found on Mainline DHT, trying gateways");
                }
                Err(_elapsed) => {
                    warn!(
                        timeout_secs = self.dht_timeout.as_secs(),
                        "Mainline DHT resolve timed out, trying gateways"
                    );
                }
            }

            // Fallback to HTTP gateways if configured.
            self.resolve_via_gateway(public_key).await
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for configuring a [`PkarrDhtClient`].
///
/// # Example
///
/// ```ignore
/// let client = PkarrDhtClient::builder()
///     .gateway_url("https://relay.pkarr.org")
///     .gateway_url("https://dns.dht.org")
///     .dht_timeout(Duration::from_secs(15))
///     .build()?;
/// ```
pub struct PkarrDhtClientBuilder {
    gateway_urls: Vec<String>,
    dht_timeout: Duration,
    gateway_timeout: Duration,
}

impl Default for PkarrDhtClientBuilder {
    fn default() -> Self {
        Self {
            gateway_urls: Vec::new(),
            dht_timeout: DHT_OPERATION_TIMEOUT,
            gateway_timeout: GATEWAY_REQUEST_TIMEOUT,
        }
    }
}

impl PkarrDhtClientBuilder {
    /// Adds an HTTP gateway URL for fallback resolution.
    ///
    /// URLs should NOT include a trailing slash. The z-base-32 encoded
    /// public key will be appended as a path segment.
    ///
    /// Multiple gateways can be added; they are tried in order.
    #[must_use]
    pub fn gateway_url(mut self, url: impl Into<String>) -> Self {
        let mut url = url.into();
        // Strip trailing slash for consistent URL construction.
        if url.ends_with('/') {
            url.pop();
        }
        self.gateway_urls.push(url);
        self
    }

    /// Sets the timeout for DHT operations (default: 30s).
    #[must_use]
    pub const fn dht_timeout(mut self, timeout: Duration) -> Self {
        self.dht_timeout = timeout;
        self
    }

    /// Sets the timeout for individual HTTP gateway requests (default: 10s).
    #[must_use]
    pub const fn gateway_timeout(mut self, timeout: Duration) -> Self {
        self.gateway_timeout = timeout;
        self
    }

    /// Builds the [`PkarrDhtClient`].
    ///
    /// Creates a Mainline DHT client that connects to the network using
    /// default bootstrap nodes. If HTTP gateway URLs were configured, an
    /// HTTP client is also created for fallback resolution.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::DhtPublishFailed`] if the Mainline DHT
    /// client cannot be created (e.g., socket binding failure).
    pub fn build(self) -> Result<PkarrDhtClient, IdentityError> {
        // Create the Mainline DHT client in client mode (not server).
        // Client mode participates in the DHT for lookups and stores
        // without serving as a long-running DHT node.
        let dht = Dht::client().map_err(|e| {
            IdentityError::DhtPublishFailed(format!("failed to create Mainline DHT client: {e}"))
        })?;

        let async_dht = dht.as_async();

        // Create HTTP client only if gateways are configured.
        let http_client = if self.gateway_urls.is_empty() {
            None
        } else {
            let client = reqwest::Client::builder()
                .timeout(self.gateway_timeout)
                .user_agent("scp-identity/0.1.0")
                .build()
                .map_err(|e| {
                    IdentityError::DhtPublishFailed(format!(
                        "failed to create HTTP client for gateway fallback: {e}"
                    ))
                })?;
            Some(client)
        };

        info!(
            gateway_count = self.gateway_urls.len(),
            dht_timeout_secs = self.dht_timeout.as_secs(),
            "PkarrDhtClient initialized with Mainline DHT"
        );

        Ok(PkarrDhtClient {
            dht: async_dht,
            gateway_urls: self.gateway_urls,
            http_client,
            dht_timeout: self.dht_timeout,
            gateway_timeout: self.gateway_timeout,
        })
    }
}
