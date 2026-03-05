//! Broadcast projection registry and key management.
//!
//! A [`ProjectedContext`] tracks the per-epoch broadcast keys needed to
//! decrypt messages from a broadcast context that this node projects over
//! HTTP. The projection endpoints serve decrypted content at:
//!
//! - `GET /scp/broadcast/<routing_id_hex>/feed`
//! - `GET /scp/broadcast/<routing_id_hex>/messages/<blob_id_hex>`
//!
//! Where `routing_id = SHA-256(context_id)` per spec section 5.14.6.
//!
//! # Activation
//!
//! Projection is opt-in per context via
//! [`ApplicationNode::enable_broadcast_projection`](crate::ApplicationNode::enable_broadcast_projection)
//! and deactivated via
//! [`ApplicationNode::disable_broadcast_projection`](crate::ApplicationNode::disable_broadcast_projection).
//!
//! See spec sections 18.11.2 and 18.11.5.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_core::crypto::sender_keys::{BroadcastEnvelope, BroadcastKey, open_broadcast};
use scp_transport::native::storage::BlobStorage;

use crate::error::ApiError;
use crate::http::NodeState;

// ---------------------------------------------------------------------------
// Routing ID derivation
// ---------------------------------------------------------------------------

/// Computes the 32-byte routing ID for a broadcast context.
///
/// `routing_id = SHA-256(context_id)` where `context_id` is the raw bytes
/// of the **lowercase** hex-encoded context ID string, per spec section 5.14.6.
/// Normalizes to lowercase before hashing so that mixed-case IDs produce
/// the same routing ID.
#[must_use]
pub fn compute_routing_id(context_id: &str) -> [u8; 32] {
    let normalized = context_id.to_ascii_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// ProjectedContext
// ---------------------------------------------------------------------------

/// A broadcast context whose messages are projected (decrypted and served)
/// by this node's HTTP endpoints.
///
/// Maps epoch numbers to their corresponding [`BroadcastKey`]s so the
/// projection handlers can decrypt messages from any epoch the node has
/// observed. Multiple epochs are retained for the blob TTL window so
/// messages encrypted under previous keys can still be decrypted.
///
/// See spec section 18.11.5.
#[derive(Debug)]
pub struct ProjectedContext {
    /// The 32-byte routing ID derived as `SHA-256(context_id)`.
    ///
    /// Used to subscribe to this context on the relay and to form the
    /// HTTP endpoint paths.
    pub(crate) routing_id: [u8; 32],
    /// The context ID (hex-encoded) for display and API responses.
    pub(crate) context_id: String,
    /// Broadcast keys indexed by epoch number. Multiple epochs are retained
    /// so messages encrypted under previous keys can still be decrypted
    /// within the blob TTL window.
    pub(crate) keys: HashMap<u64, BroadcastKey>,
}

impl ProjectedContext {
    /// Creates a new [`ProjectedContext`] from a context ID and initial broadcast key.
    ///
    /// The routing ID is computed as `SHA-256(context_id)` per spec section 5.14.6.
    /// The key is inserted at its own epoch number.
    #[must_use]
    pub fn new(context_id: &str, broadcast_key: BroadcastKey) -> Self {
        let routing_id = compute_routing_id(context_id);
        let epoch = broadcast_key.epoch();
        let mut keys = HashMap::new();
        keys.insert(epoch, broadcast_key);
        Self {
            routing_id,
            context_id: context_id.to_owned(),
            keys,
        }
    }

    /// Returns the routing ID for this projected context.
    #[must_use]
    pub const fn routing_id(&self) -> &[u8; 32] {
        &self.routing_id
    }

    /// Returns the context ID (hex-encoded string).
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns a reference to the keys map (epoch -> broadcast key).
    #[must_use]
    pub const fn keys(&self) -> &HashMap<u64, BroadcastKey> {
        &self.keys
    }

    /// Inserts a broadcast key for the given epoch.
    ///
    /// Keys are retained indefinitely rather than pruned after the blob TTL
    /// window (spec §18.11.5). This is acceptable because:
    /// - Key rotations only occur on subscriber blocks (uncommon)
    /// - Each key is ~40 bytes (32-byte secret + epoch + author DID ref)
    /// - Even hundreds of epochs per context is negligible memory
    ///
    /// If pruning becomes necessary, add a `prune_before(epoch)` method
    /// keyed to the relay's `max_blob_ttl`.
    pub fn insert_key(&mut self, broadcast_key: BroadcastKey) {
        let epoch = broadcast_key.epoch();
        self.keys.insert(epoch, broadcast_key);
    }

    /// Returns the broadcast key for the given epoch, if present.
    #[must_use]
    pub fn key_for_epoch(&self, epoch: u64) -> Option<&BroadcastKey> {
        self.keys.get(&epoch)
    }
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Encodes a 32-byte array as a lowercase hex string (64 characters).
///
/// Used for formatting routing IDs and blob IDs in API responses.
#[must_use]
pub fn hex_encode(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Decodes a hex string into a 32-byte array.
///
/// Returns `None` if the input is not exactly 64 hex characters or contains
/// invalid hex digits.
#[must_use]
pub fn hex_decode(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

// ---------------------------------------------------------------------------
// Timestamp formatting
// ---------------------------------------------------------------------------

/// Formats a Unix timestamp (seconds since epoch) as an ISO 8601 UTC string.
///
/// Produces the `YYYY-MM-DDThh:mm:ssZ` format used by the feed endpoint's
/// `published_at` field. Returns `"1970-01-01T00:00:00Z"` for timestamp 0.
#[must_use]
pub fn unix_to_iso8601(ts: u64) -> String {
    // Days in each month for non-leap and leap years.
    const DAYS_IN_MONTH: [[u64; 12]; 2] = [
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
    ];

    const fn is_leap(y: u64) -> bool {
        (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
    }

    const fn days_in_year(y: u64) -> u64 {
        if is_leap(y) { 366 } else { 365 }
    }

    let mut remaining = ts;
    let seconds = remaining % 60;
    remaining /= 60;
    let minutes = remaining % 60;
    remaining /= 60;
    let hours = remaining % 24;
    let mut days = remaining / 24;

    let mut year = 1970u64;
    loop {
        let dy = days_in_year(year);
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }

    let leap = usize::from(is_leap(year));
    let mut month = 0usize;
    while month < 11 && days >= DAYS_IN_MONTH[leap][month] {
        days -= DAYS_IN_MONTH[leap][month];
        month += 1;
    }

    format!(
        "{year:04}-{:02}-{:02}T{hours:02}:{minutes:02}:{seconds:02}Z",
        month + 1,
        days + 1
    )
}

// ---------------------------------------------------------------------------
// Feed response types
// ---------------------------------------------------------------------------

/// JSON response body for `GET /scp/broadcast/<routing_id>/feed`.
///
/// Contains the context ID, the primary author DID (from the first message
/// in the response, or the projected context's author), and an array of
/// decrypted broadcast messages.
///
/// See spec section 18.11.3.
#[derive(Debug, Clone, Serialize)]
pub struct FeedResponse {
    /// The hex-encoded context ID that this feed belongs to.
    pub context_id: String,
    /// The DID of the broadcast context's primary author.
    ///
    /// Derived from the first message in the response. If no messages are
    /// present, this is an empty string.
    pub author_did: String,
    /// Array of decrypted broadcast messages, ordered oldest-first.
    pub messages: Vec<FeedMessage>,
}

/// A single decrypted broadcast message in a [`FeedResponse`].
///
/// Each message has been deserialized from `MessagePack` ([`BroadcastEnvelope`])
/// and decrypted with the epoch-matched broadcast key. The content is
/// base64-encoded for JSON transport.
///
/// See spec section 18.11.3.
#[derive(Debug, Clone, Serialize)]
pub struct FeedMessage {
    /// The hex-encoded blob ID (SHA-256 hash) identifying this message.
    pub id: String,
    /// The DID of the author who sealed this broadcast envelope.
    pub author_did: String,
    /// The broadcast key epoch used to encrypt this message.
    pub key_epoch: u64,
    /// ISO 8601 UTC timestamp when the relay stored this blob.
    pub published_at: String,
    /// Base64-encoded decrypted content.
    pub content: String,
}

/// Query parameters for `GET /scp/broadcast/<routing_id>/feed`.
///
/// - `since` — Optional hex-encoded blob ID. When present, only messages
///   stored after that blob are returned (exclusive).
/// - `limit` — Maximum number of messages to return (default 20, max 100).
///
/// See spec section 18.11.3.
#[derive(Debug, Clone, Deserialize)]
pub struct FeedQuery {
    /// Hex-encoded blob ID. Only messages stored after this blob are returned.
    pub since: Option<String>,
    /// Maximum number of messages (default 20, max 100).
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Feed handler
// ---------------------------------------------------------------------------

/// Default number of messages returned when `limit` is not specified.
const DEFAULT_FEED_LIMIT: u32 = 20;

/// Maximum allowed value for the `limit` query parameter.
const MAX_FEED_LIMIT: u32 = 100;

/// Decrypts stored blobs into [`FeedMessage`] values.
///
/// For each blob, deserializes the `MessagePack`-encoded [`BroadcastEnvelope`],
/// looks up the epoch-matched broadcast key, and decrypts the content.
/// Blobs that fail deserialization or decryption are logged at `warn` level
/// and skipped. Returns the messages and the blob ID of the last successfully
/// decrypted message (for the `ETag` header).
fn decrypt_blobs(
    blobs: &[scp_transport::native::storage::StoredBlob],
    keys: &HashMap<u64, BroadcastKey>,
) -> (Vec<FeedMessage>, Option<[u8; 32]>) {
    let mut messages = Vec::with_capacity(blobs.len());
    let mut latest_blob_id: Option<[u8; 32]> = None;

    for stored in blobs {
        // Deserialize BroadcastEnvelope from MessagePack.
        let envelope: BroadcastEnvelope = match rmp_serde::from_slice(&stored.blob) {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(
                    blob_id = hex_encode(&stored.blob_id),
                    error = %e,
                    "failed to deserialize BroadcastEnvelope, skipping"
                );
                continue;
            }
        };

        // Find the matching broadcast key for this epoch.
        let Some(key) = keys.get(&envelope.key_epoch) else {
            tracing::warn!(
                blob_id = hex_encode(&stored.blob_id),
                epoch = envelope.key_epoch,
                "no broadcast key for epoch, skipping"
            );
            continue;
        };

        // Decrypt.
        let plaintext = match open_broadcast(key, &envelope) {
            Ok(pt) => pt,
            Err(e) => {
                tracing::warn!(
                    blob_id = hex_encode(&stored.blob_id),
                    epoch = envelope.key_epoch,
                    error = %e,
                    "decryption failed, skipping"
                );
                continue;
            }
        };

        latest_blob_id = Some(stored.blob_id);

        messages.push(FeedMessage {
            id: hex_encode(&stored.blob_id),
            author_did: envelope.author_did,
            key_epoch: envelope.key_epoch,
            published_at: unix_to_iso8601(stored.stored_at),
            content: BASE64.encode(&plaintext),
        });
    }

    (messages, latest_blob_id)
}

/// Axum handler for `GET /scp/broadcast/<routing_id>/feed`.
///
/// Looks up the projected context by routing ID, queries stored blobs,
/// deserializes each blob as a [`BroadcastEnvelope`], decrypts it with the
/// epoch-matched broadcast key, and returns the result as a JSON
/// [`FeedResponse`]. Blobs that fail deserialization or decryption are
/// logged and skipped (not a 500).
///
/// # Headers
///
/// - `Cache-Control: public, max-age=30, stale-while-revalidate=300`
/// - `ETag: "<latest_blob_id_hex>"` (the blob ID of the last message)
///
/// # Cursor expiry
///
/// When a `since` blob ID refers to a blob that has expired or been purged,
/// the feed returns **empty** (no messages) rather than the full feed. Clients
/// should treat an empty response to a previously-valid cursor as a signal to
/// reset their cursor (omit `since`) and re-fetch from the beginning.
///
/// A `since` blob ID that belongs to a different context returns **400**.
///
/// # Errors
///
/// - **404** — Unknown routing ID (no projected context registered).
/// - **400** — Invalid routing ID hex, invalid `since` blob ID hex, or
///   `since` blob belongs to a different context.
///
/// See spec section 18.11.3.
#[allow(clippy::too_many_lines)]
pub async fn feed_handler(
    State(state): State<Arc<NodeState>>,
    Path(routing_id_hex): Path<String>,
    Query(params): Query<FeedQuery>,
) -> impl IntoResponse {
    // Parse routing_id from hex.
    let Some(routing_id) = hex_decode(&routing_id_hex) else {
        return ApiError::bad_request("invalid routing_id hex").into_response();
    };

    // Look up projected context.
    let projected_contexts = state.projected_contexts.read().await;
    let Some(projected) = projected_contexts.get(&routing_id) else {
        return ApiError::not_found("unknown routing_id").into_response();
    };

    // Extract context_id and keys before dropping the read lock.
    let context_id = projected.context_id.clone();
    // We need a snapshot of the keys to avoid holding the lock during async I/O.
    let keys: HashMap<u64, BroadcastKey> = projected.keys.clone();
    drop(projected_contexts);

    // Resolve `since` parameter: if a blob_id hex is provided, look it up
    // to get its stored_at timestamp for the query filter.
    let since_ts: Option<u64> = if let Some(ref since_hex) = params.since {
        let Some(since_blob_id) = hex_decode(since_hex) else {
            return ApiError::bad_request("invalid since blob_id hex").into_response();
        };
        // Look up the blob to get its stored_at timestamp.
        match state.blob_storage.get(&since_blob_id).await {
            Ok(Some(blob)) => {
                // Verify the blob belongs to this routing_id to prevent
                // cross-context timestamp oracle (BLACK-HTTP-005).
                if blob.routing_id != routing_id {
                    return ApiError::bad_request("since blob_id does not belong to this context")
                        .into_response();
                }
                Some(blob.stored_at)
            }
            Ok(None) => {
                // Blob expired or purged — return empty feed rather than all
                // messages. Returning all would be a surprising behavior change
                // when a previously-valid cursor expires.
                Some(u64::MAX)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    since_blob_id = since_hex,
                    "failed to look up since blob"
                );
                // Storage error — conservative: return empty feed.
                Some(u64::MAX)
            }
        }
    } else {
        None
    };

    // Clamp limit.
    let limit = params
        .limit
        .unwrap_or(DEFAULT_FEED_LIMIT)
        .min(MAX_FEED_LIMIT);

    // Query blobs.
    let blobs = match state.blob_storage.query(&routing_id, since_ts, limit).await {
        Ok(blobs) => blobs,
        Err(e) => {
            tracing::error!(
                error = %e,
                routing_id = routing_id_hex,
                "blob storage query failed"
            );
            return ApiError::internal_error("storage error").into_response();
        }
    };

    // Decrypt each blob into a FeedMessage.
    let (messages, latest_blob_id) = decrypt_blobs(&blobs, &keys);

    // Determine author_did for the top-level response.
    let author_did = messages
        .first()
        .map(|m| m.author_did.clone())
        .unwrap_or_default();

    let response = FeedResponse {
        context_id,
        author_did,
        messages,
    };

    // Build response with caching headers.
    let etag = latest_blob_id
        .map(|id| format!("\"{}\"", hex_encode(&id)))
        .unwrap_or_default();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=30, stale-while-revalidate=300"),
    );
    if let (false, Ok(val)) = (etag.is_empty(), axum::http::HeaderValue::from_str(&etag)) {
        headers.insert(header::ETAG, val);
    }

    (StatusCode::OK, headers, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Per-message handler
// ---------------------------------------------------------------------------

/// Axum handler for `GET /scp/broadcast/<routing_id>/messages/<blob_id>`.
///
/// Retrieves a single stored blob, deserializes it as a [`BroadcastEnvelope`],
/// decrypts it with the epoch-matched broadcast key, and returns the result
/// as a JSON [`FeedMessage`].
///
/// # Headers
///
/// - `Cache-Control: public, immutable, max-age=31536000` — broadcast
///   messages are content-addressed and never change.
/// - `ETag: "<blob_id_hex>"` — enables conditional GET.
///
/// # Conditional GET
///
/// If the client sends `If-None-Match: "<blob_id_hex>"`, the server returns
/// **304 Not Modified** with no body, saving bandwidth for repeated fetches
/// of the same message.
///
/// # Errors
///
/// - **400** — Invalid hex in `routing_id` or `blob_id` path segment.
/// - **404** — Unknown routing ID (no projected context registered) or
///   unknown blob ID (not in storage or routing ID mismatch).
/// - **500** — Decryption failure (missing epoch key, corrupt envelope, or
///   AEAD open failure).
///
/// See spec section 18.11.4.
#[allow(clippy::too_many_lines)]
pub async fn message_handler(
    State(state): State<Arc<NodeState>>,
    Path((routing_id_hex, blob_id_hex_raw)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Normalize blob_id_hex to lowercase for consistent ETag generation.
    let blob_id_hex = blob_id_hex_raw.to_ascii_lowercase();

    // Parse routing_id from hex.
    let Some(routing_id) = hex_decode(&routing_id_hex) else {
        return ApiError::bad_request("invalid routing_id hex").into_response();
    };

    // Parse blob_id from hex.
    let Some(blob_id) = hex_decode(&blob_id_hex) else {
        return ApiError::bad_request("invalid blob_id hex").into_response();
    };

    // Look up projected context (before conditional GET to avoid
    // cross-context blob existence oracle — BLACK-HTTP-005).
    let projected_contexts = state.projected_contexts.read().await;
    let Some(projected) = projected_contexts.get(&routing_id) else {
        return ApiError::not_found("unknown routing_id").into_response();
    };

    // Snapshot keys before dropping the read lock.
    let keys: HashMap<u64, BroadcastKey> = projected.keys.clone();
    drop(projected_contexts);

    // Fetch the blob from storage.
    let stored = match state.blob_storage.get(&blob_id).await {
        Ok(Some(blob)) => blob,
        Ok(None) => {
            return ApiError::not_found("unknown blob_id").into_response();
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                blob_id = blob_id_hex,
                "blob storage get failed"
            );
            return ApiError::internal_error("storage error").into_response();
        }
    };

    // Verify the blob belongs to this routing_id. This MUST happen before
    // the conditional GET check to prevent a cross-context blob existence
    // oracle (BLACK-HTTP-005): without this ordering, an attacker could
    // send If-None-Match with a blob_id from routing_A to routing_B and
    // receive 304 (confirming blob existence) instead of 404.
    if stored.routing_id != routing_id {
        return ApiError::not_found("unknown blob_id").into_response();
    }

    // Conditional GET: check If-None-Match header. Placed after both
    // routing_id validation and blob ownership verification so that
    // unknown routing IDs and cross-context probes always get 404.
    if let Some(inm) = headers.get(header::IF_NONE_MATCH)
        && let Ok(inm_str) = inm.to_str()
    {
        let expected_etag = format!("\"{blob_id_hex}\"");
        if inm_str == expected_etag {
            return StatusCode::NOT_MODIFIED.into_response();
        }
    }

    // Deserialize BroadcastEnvelope from MessagePack.
    let envelope: BroadcastEnvelope = match rmp_serde::from_slice(&stored.blob) {
        Ok(env) => env,
        Err(e) => {
            tracing::error!(
                error = %e,
                blob_id = blob_id_hex,
                "failed to deserialize BroadcastEnvelope"
            );
            return ApiError::internal_error("decryption failure").into_response();
        }
    };

    // Find the matching broadcast key for this epoch.
    let Some(key) = keys.get(&envelope.key_epoch) else {
        tracing::error!(
            blob_id = blob_id_hex,
            epoch = envelope.key_epoch,
            "no broadcast key for epoch"
        );
        return ApiError::internal_error("decryption failure").into_response();
    };

    // Decrypt.
    let plaintext = match open_broadcast(key, &envelope) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::error!(
                error = %e,
                blob_id = blob_id_hex,
                epoch = envelope.key_epoch,
                "decryption failed"
            );
            return ApiError::internal_error("decryption failure").into_response();
        }
    };

    let message = FeedMessage {
        id: hex_encode(&stored.blob_id),
        author_did: envelope.author_did,
        key_epoch: envelope.key_epoch,
        published_at: unix_to_iso8601(stored.stored_at),
        content: BASE64.encode(&plaintext),
    };

    // Build response with immutable caching headers.
    let mut resp_headers = axum::http::HeaderMap::new();
    resp_headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, immutable, max-age=31536000"),
    );
    let etag = format!("\"{blob_id_hex}\"");
    if let Ok(val) = axum::http::HeaderValue::from_str(&etag) {
        resp_headers.insert(header::ETAG, val);
    }

    (StatusCode::OK, resp_headers, Json(message)).into_response()
}

// ---------------------------------------------------------------------------
// Router constructors
// ---------------------------------------------------------------------------

/// Returns an axum [`Router`] serving both broadcast projection endpoints.
///
/// Mounts:
/// - `GET /scp/broadcast/{routing_id}/feed` — paginated feed of decrypted
///   messages ([`feed_handler`], spec section 18.11.3).
/// - `GET /scp/broadcast/{routing_id}/messages/{blob_id}` — single decrypted
///   message with conditional GET ([`message_handler`], spec section 18.11.4).
///
/// The router shares the node's [`NodeState`] for access to projected
/// contexts and blob storage.
///
/// See spec sections 18.11.3 and 18.11.4.
pub fn broadcast_projection_router(state: Arc<NodeState>) -> Router {
    let limiter = state.projection_rate_limiter.clone();
    Router::new()
        .route("/scp/broadcast/{routing_id}/feed", get(feed_handler))
        .route(
            "/scp/broadcast/{routing_id}/messages/{blob_id}",
            get(message_handler),
        )
        .layer(axum::middleware::from_fn(move |req, next| {
            projection_rate_limit_middleware(req, next, limiter.clone())
        }))
        .with_state(state)
}

/// Middleware that enforces per-IP rate limiting on projection endpoints.
///
/// Extracts the client IP from [`axum::extract::ConnectInfo<SocketAddr>`]
/// (injected by `axum::serve` for plain HTTP, or manually for TLS connections
/// in [`crate::tls::serve_tls`]). Falls back to `0.0.0.0` if unavailable.
///
/// Returns HTTP 429 Too Many Requests when the per-IP token bucket is exhausted.
/// See spec section 18.11.6.
async fn projection_rate_limit_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
    limiter: scp_transport::relay::rate_limit::PublishRateLimiter,
) -> axum::response::Response {
    let ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map_or_else(
            || {
                tracing::warn!(
                    "ConnectInfo missing from request extensions; \
                     projection rate limiting falls back to shared 0.0.0.0 bucket \
                     (per-IP isolation lost)"
                );
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            },
            |ci| ci.0.ip(),
        );
    if !limiter.check(ip).await {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )
            .into_response();
    }
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_core::crypto::sender_keys::{
        generate_broadcast_key, rotate_broadcast_key, seal_broadcast,
    };

    // -----------------------------------------------------------------------
    // Hex helpers
    // -----------------------------------------------------------------------

    #[test]
    fn hex_encode_produces_64_char_lowercase() {
        let bytes = [0xab; 32];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded, "ab".repeat(32));
    }

    #[test]
    fn hex_encode_all_zeros() {
        let bytes = [0u8; 32];
        assert_eq!(hex_encode(&bytes), "00".repeat(32));
    }

    #[test]
    fn hex_decode_roundtrip() {
        let bytes = [0xde; 32];
        let encoded = hex_encode(&bytes);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode("abcd").is_none());
        assert!(hex_decode("").is_none());
        assert!(hex_decode(&"a".repeat(63)).is_none());
        assert!(hex_decode(&"a".repeat(65)).is_none());
    }

    #[test]
    fn hex_decode_rejects_invalid_chars() {
        let mut s = "0".repeat(64);
        s.replace_range(0..1, "g"); // invalid hex char
        assert!(hex_decode(&s).is_none());
    }

    #[test]
    fn hex_decode_accepts_uppercase() {
        let lower = hex_encode(&[0xAB; 32]);
        let upper = lower.to_uppercase();
        let decoded = hex_decode(&upper).unwrap();
        assert_eq!(decoded, [0xAB; 32]);
    }

    // -----------------------------------------------------------------------
    // Timestamp formatting
    // -----------------------------------------------------------------------

    #[test]
    fn unix_to_iso8601_epoch_zero() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn unix_to_iso8601_known_timestamp() {
        // 2025-01-15T10:30:00Z = 1736937000
        assert_eq!(unix_to_iso8601(1_736_937_000), "2025-01-15T10:30:00Z");
    }

    #[test]
    fn unix_to_iso8601_y2k() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(unix_to_iso8601(946_684_800), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn unix_to_iso8601_leap_year_feb_29() {
        // 2024-02-29T12:00:00Z = 1709208000
        assert_eq!(unix_to_iso8601(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    // -----------------------------------------------------------------------
    // decrypt_blobs
    // -----------------------------------------------------------------------

    #[test]
    fn decrypt_blobs_with_valid_envelope() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = seal_broadcast(&key, b"hello world").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();

        let blob_id = {
            let mut hasher = Sha256::new();
            hasher.update(&blob_bytes);
            let h: [u8; 32] = hasher.finalize().into();
            h
        };

        let stored = scp_transport::native::storage::StoredBlob {
            routing_id: [0xAA; 32],
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_736_937_000,
            blob: blob_bytes,
        };

        let mut keys = HashMap::new();
        keys.insert(0, key);

        let (messages, latest_id) = decrypt_blobs(&[stored], &keys);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].author_did, "did:dht:alice");
        assert_eq!(messages[0].key_epoch, 0);
        assert_eq!(messages[0].published_at, "2025-01-15T10:30:00Z");
        // Verify content is valid base64 that decodes to "hello world".
        let decoded = BASE64.decode(&messages[0].content).unwrap();
        assert_eq!(decoded, b"hello world");
        assert_eq!(latest_id, Some(blob_id));
    }

    #[test]
    fn decrypt_blobs_skips_invalid_msgpack() {
        let stored = scp_transport::native::storage::StoredBlob {
            routing_id: [0xAA; 32],
            blob_id: [0xBB; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 100,
            blob: vec![0xFF, 0xFE], // invalid MessagePack
        };

        let keys = HashMap::new();
        let (messages, latest_id) = decrypt_blobs(&[stored], &keys);
        assert!(messages.is_empty());
        assert!(latest_id.is_none());
    }

    #[test]
    fn decrypt_blobs_skips_missing_epoch_key() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = seal_broadcast(&key, b"secret").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();

        let stored = scp_transport::native::storage::StoredBlob {
            routing_id: [0xAA; 32],
            blob_id: [0xCC; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 100,
            blob: blob_bytes,
        };

        // Provide keys for epoch 1 only, envelope is epoch 0.
        let (rotated_key, _) = rotate_broadcast_key(&key, 1000).unwrap();
        let mut keys = HashMap::new();
        keys.insert(1, rotated_key);

        let (messages, latest_id) = decrypt_blobs(&[stored], &keys);
        assert!(messages.is_empty());
        assert!(latest_id.is_none());
    }

    // -----------------------------------------------------------------------
    // Feed handler integration tests (via axum test harness)
    // -----------------------------------------------------------------------

    use std::net::SocketAddr;
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::{Request, StatusCode as HttpStatus};
    use http_body_util::BodyExt;
    use scp_transport::native::storage::{BlobStorageBackend, InMemoryBlobStorage};
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use crate::http::NodeState;

    /// Creates a test `NodeState` with the given projected contexts and
    /// blob storage.
    fn test_state_with(
        projected: HashMap<[u8; 32], ProjectedContext>,
        storage: InMemoryBlobStorage,
    ) -> Arc<NodeState> {
        test_state_with_rate(projected, storage, 1000)
    }

    /// Creates a test `NodeState` with the given projected contexts,
    /// blob storage, and projection rate limit.
    fn test_state_with_rate(
        projected: HashMap<[u8; 32], ProjectedContext>,
        storage: InMemoryBlobStorage,
        rate_limit: u32,
    ) -> Arc<NodeState> {
        Arc::new(NodeState {
            did: "did:dht:test".to_owned(),
            relay_url: "wss://localhost/scp/v1".to_owned(),
            broadcast_contexts: RwLock::new(HashMap::new()),
            relay_addr: "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            bridge_secret: zeroize::Zeroizing::new([0u8; 32]),
            dev_token: None,
            dev_bind_addr: None,
            projected_contexts: RwLock::new(projected),
            blob_storage: Arc::new(BlobStorageBackend::from(storage)),
            relay_config: scp_transport::native::server::RelayConfig::default(),
            start_time: Instant::now(),
            http_bind_addr: SocketAddr::from(([0, 0, 0, 0], 8443)),
            shutdown_token: tokio_util::sync::CancellationToken::new(),
            cors_origins: None,
            projection_rate_limiter: scp_transport::relay::rate_limit::PublishRateLimiter::new(
                rate_limit,
            ),
            tls_config: None,
            cert_resolver: None,
        })
    }

    #[tokio::test]
    async fn feed_unknown_routing_id_returns_404() {
        let state = test_state_with(HashMap::new(), InMemoryBlobStorage::new());
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&[0xAA; 32]);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::NOT_FOUND);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn feed_invalid_hex_returns_400() {
        let state = test_state_with(HashMap::new(), InMemoryBlobStorage::new());
        let router = broadcast_projection_router(state);

        let req = Request::builder()
            .uri("/scp/broadcast/not_hex/feed")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::BAD_REQUEST);
    }

    #[tokio::test]
    async fn feed_returns_decrypted_messages_with_cache_headers() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "test_ctx_001";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal and store a broadcast message.
        let envelope = seal_broadcast(&key, b"hello feed").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let blob_id = {
            let mut h = Sha256::new();
            h.update(&blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };

        storage
            .store(routing_id, blob_id, None, 3600, blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        // Check Cache-Control header.
        let cache_control = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            cache_control,
            "public, max-age=30, stale-while-revalidate=300"
        );

        // Check ETag header is present and contains the blob_id.
        let etag = resp.headers().get(header::ETAG).unwrap().to_str().unwrap();
        assert!(etag.contains(&hex_encode(&blob_id)));

        // Parse response body.
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["context_id"], "test_ctx_001");
        assert_eq!(json["author_did"], "did:dht:alice");

        let messages = json["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["author_did"], "did:dht:alice");
        assert_eq!(messages[0]["key_epoch"], 0);

        // Verify decrypted content.
        let content_b64 = messages[0]["content"].as_str().unwrap();
        let decoded = BASE64.decode(content_b64).unwrap();
        assert_eq!(decoded, b"hello feed");
    }

    #[tokio::test]
    async fn feed_respects_limit_parameter() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "limit_ctx";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store 5 messages.
        for i in 0u8..5 {
            let envelope = seal_broadcast(&key, &[i; 10]).unwrap();
            let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
            let blob_id = {
                let mut h = Sha256::new();
                h.update(&blob_bytes);
                let r: [u8; 32] = h.finalize().into();
                r
            };
            storage
                .store(routing_id, blob_id, None, 3600, blob_bytes)
                .await
                .unwrap();
        }

        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed?limit=2"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
    }

    #[tokio::test]
    async fn feed_limit_clamped_to_100() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "clamp_ctx";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();
        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        // Request limit=999 — should not crash, just clamp to 100.
        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed?limit=999"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Empty messages is fine; the point is it didn't error.
        assert!(json["messages"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn feed_empty_context_returns_empty_messages() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "empty_ctx";
        let projected = ProjectedContext::new(context_id, key);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let state = test_state_with(projected_map, InMemoryBlobStorage::new());
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["context_id"], "empty_ctx");
        assert_eq!(json["author_did"], "");
        assert!(json["messages"].as_array().unwrap().is_empty());

        // No ETag when there are no messages.
        // (The resp was consumed, but we checked status above.)
    }

    // -----------------------------------------------------------------------
    // Per-message handler integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn message_unknown_routing_id_returns_404() {
        let state = test_state_with(HashMap::new(), InMemoryBlobStorage::new());
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&[0xAA; 32]);
        let blob_hex = hex_encode(&[0xBB; 32]);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{blob_hex}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::NOT_FOUND);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn message_unknown_blob_id_returns_404() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "msg_ctx_404";
        let projected = ProjectedContext::new(context_id, key);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();
        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let blob_hex = hex_encode(&[0xCC; 32]); // not in storage
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{blob_hex}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::NOT_FOUND);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn message_returns_decrypted_single_message() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "msg_ctx_ok";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal and store a broadcast message.
        let envelope = seal_broadcast(&key, b"single message").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let blob_id = {
            let mut h = Sha256::new();
            h.update(&blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };

        storage
            .store(routing_id, blob_id, None, 3600, blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let blob_hex = hex_encode(&blob_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{blob_hex}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        // Check Cache-Control header (immutable for per-message).
        let cache_control = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "public, immutable, max-age=31536000");

        // Check ETag header contains the blob_id.
        let etag = resp.headers().get(header::ETAG).unwrap().to_str().unwrap();
        assert_eq!(etag, format!("\"{blob_hex}\""));

        // Parse response body.
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["id"], blob_hex);
        assert_eq!(json["author_did"], "did:dht:alice");
        assert_eq!(json["key_epoch"], 0);

        // Verify decrypted content.
        let content_b64 = json["content"].as_str().unwrap();
        let decoded = BASE64.decode(content_b64).unwrap();
        assert_eq!(decoded, b"single message");
    }

    #[tokio::test]
    async fn message_conditional_get_returns_304() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "msg_ctx_304";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        let envelope = seal_broadcast(&key, b"cached msg").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let blob_id = {
            let mut h = Sha256::new();
            h.update(&blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };

        storage
            .store(routing_id, blob_id, None, 3600, blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let blob_hex = hex_encode(&blob_id);
        let etag_value = format!("\"{blob_hex}\"");
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{blob_hex}"))
            .header("If-None-Match", &etag_value)
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::NOT_MODIFIED);

        // Body should be empty.
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn message_conditional_get_non_matching_returns_200() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "msg_ctx_200";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        let envelope = seal_broadcast(&key, b"fresh msg").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let blob_id = {
            let mut h = Sha256::new();
            h.update(&blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };

        storage
            .store(routing_id, blob_id, None, 3600, blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let blob_hex = hex_encode(&blob_id);
        // Send a non-matching ETag.
        let wrong_etag = format!("\"{}\"", hex_encode(&[0xFF; 32]));
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{blob_hex}"))
            .header("If-None-Match", &wrong_etag)
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], blob_hex);
    }

    #[tokio::test]
    async fn message_invalid_hex_returns_400() {
        let state = test_state_with(HashMap::new(), InMemoryBlobStorage::new());
        let router = broadcast_projection_router(state);

        // Invalid routing_id hex.
        let req = Request::builder()
            .uri("/scp/broadcast/not_valid_hex/messages/also_not_hex")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // Original tests
    // -----------------------------------------------------------------------

    #[test]
    fn compute_routing_id_is_sha256_of_context_id_bytes() {
        let context_id = "abc123deadbeef";
        let routing_id = compute_routing_id(context_id);

        // Manually compute expected SHA-256.
        let mut hasher = Sha256::new();
        hasher.update(context_id.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(routing_id, expected);
    }

    #[test]
    fn compute_routing_id_deterministic() {
        let id = "deadbeefcafe0123456789abcdef";
        assert_eq!(compute_routing_id(id), compute_routing_id(id));
    }

    #[test]
    fn compute_routing_id_distinct_for_different_inputs() {
        let a = compute_routing_id("context_a");
        let b = compute_routing_id("context_b");
        assert_ne!(a, b);
    }

    #[test]
    fn projected_context_new_sets_routing_id() {
        let key = generate_broadcast_key("did:dht:alice");
        let ctx = ProjectedContext::new("abc123", key);

        let expected_routing_id = compute_routing_id("abc123");
        assert_eq!(ctx.routing_id, expected_routing_id);
        assert_eq!(ctx.context_id(), "abc123");
    }

    #[test]
    fn projected_context_new_inserts_key_at_epoch() {
        let key = generate_broadcast_key("did:dht:alice");
        let ctx = ProjectedContext::new("abc123", key);

        assert!(ctx.key_for_epoch(0).is_some());
        assert_eq!(ctx.keys().len(), 1);
    }

    #[test]
    fn enable_then_disable_roundtrip() {
        // Simulate the registry lifecycle: insert then remove.
        let mut registry: HashMap<[u8; 32], ProjectedContext> = HashMap::new();

        let context_id = "test_context_001";
        let key = generate_broadcast_key("did:dht:alice");
        let routing_id = compute_routing_id(context_id);

        let projected = ProjectedContext::new(context_id, key);
        registry.insert(routing_id, projected);
        assert!(registry.contains_key(&routing_id));

        // Disable: remove from registry.
        registry.remove(&routing_id);
        assert!(!registry.contains_key(&routing_id));
    }

    #[test]
    fn multiple_epochs_stored_and_retrievable() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let mut ctx = ProjectedContext::new("multi_epoch_ctx", key0);

        // Rotate to epoch 1.
        let key0_ref = ctx.key_for_epoch(0).expect("epoch 0 should exist");
        let (key1, _advance) = rotate_broadcast_key(key0_ref, 1000).expect("rotate should succeed");
        assert_eq!(key1.epoch(), 1);
        ctx.insert_key(key1);

        // Rotate to epoch 2 from epoch 1.
        let key1_ref = ctx.key_for_epoch(1).expect("epoch 1 should exist");
        let (key2, _advance) = rotate_broadcast_key(key1_ref, 2000).expect("rotate should succeed");
        assert_eq!(key2.epoch(), 2);
        ctx.insert_key(key2);

        // All three epochs are retained (no pruning on advance).
        assert!(ctx.key_for_epoch(0).is_some(), "epoch 0 retained");
        assert!(ctx.key_for_epoch(1).is_some(), "epoch 1 retained");
        assert!(ctx.key_for_epoch(2).is_some(), "epoch 2 retained");
        assert_eq!(ctx.keys().len(), 3);

        // Non-existent epoch returns None.
        assert!(ctx.key_for_epoch(99).is_none());
    }

    #[test]
    fn insert_key_replaces_existing_epoch() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let mut ctx = ProjectedContext::new("replace_test", key0);

        // Insert a different key at epoch 0 (replacement).
        let replacement = generate_broadcast_key("did:dht:alice");
        ctx.insert_key(replacement);

        assert_eq!(ctx.keys().len(), 1);
        assert!(ctx.key_for_epoch(0).is_some());
    }

    // -------------------------------------------------------------------
    // Test A: Cross-context routing_id mismatch (BLACK-HTTP-005 defense)
    // -------------------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::similar_names)]
    async fn message_cross_context_routing_id_mismatch_returns_404() {
        // Create two projected contexts with different routing IDs.
        let key_a = generate_broadcast_key("did:dht:alice");
        let key_b = generate_broadcast_key("did:dht:bob");
        let ctx_a = ProjectedContext::new("context_a", key_a.clone());
        let ctx_b = ProjectedContext::new("context_b", key_b);
        let routing_id_a = ctx_a.routing_id;
        let routing_id_b = ctx_b.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id_a, ctx_a);
        projected_map.insert(routing_id_b, ctx_b);

        let storage = InMemoryBlobStorage::new();

        // Seal and store a blob under routing_A.
        let envelope = seal_broadcast(&key_a, b"belongs to context_a").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let blob_id = {
            let mut h = Sha256::new();
            h.update(&blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id_a, blob_id, None, 3600, blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);

        // Request the blob via routing_B (wrong context) → must be 404.
        let router_b = broadcast_projection_router(Arc::clone(&state));
        let routing_b_hex = hex_encode(&routing_id_b);
        let blob_hex = hex_encode(&blob_id);
        let req = Request::builder()
            .uri(format!(
                "/scp/broadcast/{routing_b_hex}/messages/{blob_hex}"
            ))
            .body(Body::empty())
            .unwrap();

        let resp = router_b.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            HttpStatus::NOT_FOUND,
            "cross-context request must return 404, not leak blob existence"
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"], "unknown blob_id",
            "error message must be indistinguishable from genuinely missing blob"
        );

        // Verify the same blob is accessible via routing_A (correct context) → 200.
        let router_a = broadcast_projection_router(state);
        let routing_a_hex = hex_encode(&routing_id_a);
        let req = Request::builder()
            .uri(format!(
                "/scp/broadcast/{routing_a_hex}/messages/{blob_hex}"
            ))
            .body(Body::empty())
            .unwrap();

        let resp = router_a.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            HttpStatus::OK,
            "correct context should return 200"
        );
    }

    // -------------------------------------------------------------------
    // Test B: Feed with `since` parameter
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn feed_since_parameter_filters_messages() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "since_ctx";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store 3 blobs. Because InMemoryBlobStorage uses real timestamps,
        // all blobs may get the same stored_at. We rely on the since
        // parameter resolving via blob lookup → stored_at filtering.
        let mut blob_ids = Vec::new();
        for i in 0u8..3 {
            let envelope = seal_broadcast(&key, &[i; 16]).unwrap();
            let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
            let blob_id = {
                let mut h = Sha256::new();
                h.update(&blob_bytes);
                let r: [u8; 32] = h.finalize().into();
                r
            };
            storage
                .store(routing_id, blob_id, None, 3600, blob_bytes)
                .await
                .unwrap();
            blob_ids.push(blob_id);
        }

        let state = test_state_with(projected_map, storage);
        let routing_hex = hex_encode(&routing_id);

        // Test 1: since=blob_1 — all blobs have the same stored_at (within
        // the same second), so since filtering returns blobs with
        // stored_at > since_blob.stored_at. Since they're all equal, this
        // returns 0. This validates the since lookup path works without error.
        let router = broadcast_projection_router(Arc::clone(&state));
        let since_hex = hex_encode(&blob_ids[0]);
        let req = Request::builder()
            .uri(format!(
                "/scp/broadcast/{routing_hex}/feed?since={since_hex}"
            ))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        // Test 2: since=nonexistent_id — returns empty feed (not all blobs).
        // A nonexistent blob_id could be a cross-context oracle probe, so we
        // treat it as "nothing new" rather than returning the full feed.
        let router = broadcast_projection_router(Arc::clone(&state));
        let nonexistent = hex_encode(&[0xFF; 32]);
        let req = Request::builder()
            .uri(format!(
                "/scp/broadcast/{routing_hex}/feed?since={nonexistent}"
            ))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert_eq!(
            messages.len(),
            0,
            "nonexistent since blob_id should return empty feed (cross-context oracle prevention)"
        );

        // Test 3: since=invalid_hex — should return 400.
        let router = broadcast_projection_router(state);
        let req = Request::builder()
            .uri(format!(
                "/scp/broadcast/{routing_hex}/feed?since=not_valid_hex"
            ))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::BAD_REQUEST);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "BAD_REQUEST");
    }

    // -------------------------------------------------------------------
    // Test C: Multi-epoch feed decryption
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn feed_multi_epoch_decryption() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let (key1, _advance) = rotate_broadcast_key(&key0, 1000).unwrap();

        let context_id = "multi_epoch_feed_ctx";
        let mut projected = ProjectedContext::new(context_id, key0.clone());
        projected.insert_key(key1.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal message_1 with epoch 0 key.
        let envelope_0 = seal_broadcast(&key0, b"epoch zero message").unwrap();
        let blob_bytes_0 = rmp_serde::to_vec(&envelope_0).unwrap();
        let blob_id_0 = {
            let mut h = Sha256::new();
            h.update(&blob_bytes_0);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, blob_id_0, None, 3600, blob_bytes_0)
            .await
            .unwrap();

        // Seal message_2 with epoch 1 key.
        let envelope_1 = seal_broadcast(&key1, b"epoch one message").unwrap();
        let blob_bytes_1 = rmp_serde::to_vec(&envelope_1).unwrap();
        let blob_id_1 = {
            let mut h = Sha256::new();
            h.update(&blob_bytes_1);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, blob_id_1, None, 3600, blob_bytes_1)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert_eq!(
            messages.len(),
            2,
            "both epoch-0 and epoch-1 messages returned"
        );

        // Verify both messages decrypted correctly by checking their content.
        let contents: Vec<String> = messages
            .iter()
            .map(|m| {
                let b64 = m["content"].as_str().unwrap();
                String::from_utf8(BASE64.decode(b64).unwrap()).unwrap()
            })
            .collect();
        assert!(contents.contains(&"epoch zero message".to_owned()));
        assert!(contents.contains(&"epoch one message".to_owned()));

        // Verify epoch values are correct.
        let epochs: Vec<u64> = messages
            .iter()
            .map(|m| m["key_epoch"].as_u64().unwrap())
            .collect();
        assert!(epochs.contains(&0));
        assert!(epochs.contains(&1));
    }

    // -------------------------------------------------------------------
    // Test D: Tampered ciphertext (AEAD authentication failure)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn message_tampered_ciphertext_returns_500() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "tamper_ctx";
        let projected = ProjectedContext::new(context_id, key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal a message, then tamper with the ciphertext.
        let mut envelope = seal_broadcast(&key, b"tamper target").unwrap();
        // Flip a byte in the ciphertext (after the 12-byte nonce).
        if envelope.encrypted_content.len() > 13 {
            envelope.encrypted_content[13] ^= 0xFF;
        }
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let blob_id = {
            let mut h = Sha256::new();
            h.update(&blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, blob_id, None, 3600, blob_bytes)
            .await
            .unwrap();

        // Also store a valid message.
        let valid_envelope = seal_broadcast(&key, b"valid message").unwrap();
        let valid_blob_bytes = rmp_serde::to_vec(&valid_envelope).unwrap();
        let valid_blob_id = {
            let mut h = Sha256::new();
            h.update(&valid_blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, valid_blob_id, None, 3600, valid_blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);

        // Per-message endpoint for tampered blob → 500 "decryption failure".
        let router = broadcast_projection_router(Arc::clone(&state));
        let routing_hex = hex_encode(&routing_id);
        let blob_hex = hex_encode(&blob_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{blob_hex}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::INTERNAL_SERVER_ERROR);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "decryption failure");

        // Feed endpoint → tampered message should be silently skipped,
        // valid message still returned.
        let router = broadcast_projection_router(state);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();
        assert_eq!(
            messages.len(),
            1,
            "tampered message should be skipped, valid message returned"
        );

        let content_b64 = messages[0]["content"].as_str().unwrap();
        let decoded = BASE64.decode(content_b64).unwrap();
        assert_eq!(decoded, b"valid message");
    }

    // -------------------------------------------------------------------
    // Test E: Conditional GET after routing_id fix (BLACK-HTTP-005)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn message_conditional_get_cross_context_returns_404_not_304() {
        // This test verifies that the conditional GET (If-None-Match) does
        // NOT short-circuit before the routing_id ownership check. An
        // attacker sending If-None-Match for a blob from routing_A to
        // routing_B must get 404, not 304.
        let key_a = generate_broadcast_key("did:dht:alice");
        let key_b = generate_broadcast_key("did:dht:bob");
        let ctx_a = ProjectedContext::new("ctx_a_304", key_a.clone());
        let ctx_b = ProjectedContext::new("ctx_b_304", key_b);
        let routing_id_a = ctx_a.routing_id;
        let routing_id_b = ctx_b.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id_a, ctx_a);
        projected_map.insert(routing_id_b, ctx_b);

        let storage = InMemoryBlobStorage::new();

        // Store blob under routing_A.
        let envelope = seal_broadcast(&key_a, b"secret of A").unwrap();
        let blob_bytes = rmp_serde::to_vec(&envelope).unwrap();
        let blob_id = {
            let mut h = Sha256::new();
            h.update(&blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id_a, blob_id, None, 3600, blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let router = broadcast_projection_router(state);

        // Request via routing_B with If-None-Match matching the blob_id.
        let routing_b_hex = hex_encode(&routing_id_b);
        let blob_hex = hex_encode(&blob_id);
        let etag_value = format!("\"{blob_hex}\"");
        let req = Request::builder()
            .uri(format!(
                "/scp/broadcast/{routing_b_hex}/messages/{blob_hex}"
            ))
            .header("If-None-Match", &etag_value)
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            HttpStatus::NOT_FOUND,
            "cross-context conditional GET must return 404, not 304"
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unknown blob_id");
    }

    // -----------------------------------------------------------------------
    // Rate limiting tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rate_limit_returns_429_when_exceeded() {
        // Set rate to 2 req/s so the third request is rate-limited.
        let state = test_state_with_rate(HashMap::new(), InMemoryBlobStorage::new(), 2);
        let routing_hex = hex_encode(&[0xAA; 32]);
        let uri = format!("/scp/broadcast/{routing_hex}/feed");

        // First two requests should succeed (404 for unknown routing, but not 429).
        for i in 0..2 {
            let router = broadcast_projection_router(Arc::clone(&state));
            let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
            let resp = router.oneshot(req).await.unwrap();
            assert_ne!(
                resp.status(),
                HttpStatus::TOO_MANY_REQUESTS,
                "request {i} should not be rate-limited"
            );
        }

        // Third request should be rate-limited (429).
        let router = broadcast_projection_router(Arc::clone(&state));
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            HttpStatus::TOO_MANY_REQUESTS,
            "third request should be rate-limited"
        );
    }

    #[tokio::test]
    async fn rate_limit_allows_different_ips() {
        // Verify the limiter uses per-IP buckets via the PublishRateLimiter API directly.
        let limiter = scp_transport::relay::rate_limit::PublishRateLimiter::new(1);
        let ip_a: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: std::net::IpAddr = "10.0.0.2".parse().unwrap();

        // First request from each IP should be allowed.
        assert!(limiter.check(ip_a).await, "ip_a first request should pass");
        assert!(limiter.check(ip_b).await, "ip_b first request should pass");

        // Second request from ip_a should be rate-limited.
        assert!(
            !limiter.check(ip_a).await,
            "ip_a second request should be rate-limited"
        );

        // Second request from ip_b should also be rate-limited (separate bucket, same rate).
        assert!(
            !limiter.check(ip_b).await,
            "ip_b second request should be rate-limited"
        );
    }
}
