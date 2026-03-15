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

use scp_core::context::broadcast::BroadcastAdmission;
use scp_core::context::params::{ProjectionPolicy, ProjectionRule};
use scp_core::crypto::sender_keys::{BroadcastEnvelope, BroadcastKey, open_broadcast_trusted};
use scp_core::crypto::ucan::CapabilityUri;
use scp_core::crypto::ucan::validate::parse_ucan;
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
/// Stores the context's [`BroadcastAdmission`] mode and optional
/// [`ProjectionPolicy`] so projection handlers can enforce authentication
/// requirements (SCP-GG-007, SCP-GG-008).
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
    /// Admission mode for the broadcast context (open or gated).
    ///
    /// Determines the floor for projection access control: gated contexts
    /// cannot have public projection (spec section 18.11.2.1).
    pub(crate) admission: BroadcastAdmission,
    /// Optional per-author projection access policy.
    ///
    /// When `Some`, the default rule and per-author overrides control whether
    /// projected content requires authentication. When `None`, the admission
    /// mode alone determines the behavior (open = public, gated = gated).
    pub(crate) projection_policy: Option<ProjectionPolicy>,
}

impl ProjectedContext {
    /// Creates a new [`ProjectedContext`] from a context ID, initial broadcast key,
    /// admission mode, and optional projection policy.
    ///
    /// The routing ID is computed as `SHA-256(context_id)` per spec section 5.14.6.
    /// The key is inserted at its own epoch number. The admission mode and
    /// projection policy are stored for use by projection handlers when deciding
    /// whether to require authentication (spec section 18.11.2.1).
    #[must_use]
    pub fn new(
        context_id: &str,
        broadcast_key: BroadcastKey,
        admission: BroadcastAdmission,
        projection_policy: Option<ProjectionPolicy>,
    ) -> Self {
        let routing_id = compute_routing_id(context_id);
        let epoch = broadcast_key.epoch();
        let mut keys = HashMap::new();
        keys.insert(epoch, broadcast_key);
        Self {
            routing_id,
            context_id: context_id.to_owned(),
            keys,
            admission,
            projection_policy,
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

    /// Returns the admission mode for this broadcast context.
    #[must_use]
    pub const fn admission(&self) -> BroadcastAdmission {
        self.admission
    }

    /// Returns the projection policy, if any.
    #[must_use]
    pub const fn projection_policy(&self) -> Option<&ProjectionPolicy> {
        self.projection_policy.as_ref()
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
    ///
    /// **Important:** After a governance ban (`RevokeReadAccess` /
    /// `governance_ban_subscriber`), all author keys are rotated in the
    /// `ContextManager`. The caller MUST propagate the new-epoch keys to
    /// the projection registry via this method; otherwise the projection
    /// endpoint cannot decrypt content encrypted under the new keys.
    pub fn insert_key(&mut self, broadcast_key: BroadcastKey) {
        let epoch = broadcast_key.epoch();
        self.keys.insert(epoch, broadcast_key);
    }

    /// Removes all keys whose epoch is NOT in the given set.
    ///
    /// Used after a `Full`-scope governance ban to ensure historical content
    /// encrypted under pre-ban keys is no longer decryptable by the
    /// projection endpoint. Messages referencing purged epochs will return
    /// 410 Gone rather than serving content that a banned subscriber may
    /// have previously accessed.
    ///
    /// Takes a set of epochs to retain (typically the new post-rotation
    /// epochs). This correctly handles epoch-divergent multi-author contexts
    /// where authors may be at different epochs.
    pub fn retain_only_epochs(&mut self, epochs: &std::collections::HashSet<u64>) {
        self.keys.retain(|e, _| epochs.contains(e));
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
// Projection policy validation
// ---------------------------------------------------------------------------

/// Validates that a projection policy is consistent with the context's
/// admission mode.
///
/// Gated contexts cannot have `ProjectionRule::Public` as the default rule
/// or in any per-author override, because that would allow unauthenticated
/// access to content that the context's admission mode requires
/// authentication for (spec section 18.11.2.1).
///
/// # Errors
///
/// Returns an error message if a gated context has a `Public` default
/// projection rule or a `Public` per-author override.
pub fn validate_projection_policy(
    admission: BroadcastAdmission,
    policy: Option<&ProjectionPolicy>,
) -> Result<(), String> {
    if let (BroadcastAdmission::Gated, Some(p)) = (admission, policy) {
        if p.default_rule == ProjectionRule::Public {
            return Err("gated context cannot have public projection rule".into());
        }
        for override_entry in &p.overrides {
            if override_entry.rule == ProjectionRule::Public {
                return Err(
                    "gated context cannot have public per-author projection override".into(),
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bearer token extraction and UCAN validation
// ---------------------------------------------------------------------------

/// Extracts a bearer token from the `Authorization` header.
///
/// Expects the format `Bearer <token>` (case-insensitive scheme per RFC 7235
/// section 2.1). Returns the raw token string if present and correctly
/// formatted, or `None` if the header is missing or malformed.
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") {
        Some(&value[7..])
    } else {
        None
    }
}

/// Validates a bearer token as a UCAN with `messages:read` capability for the
/// given context.
///
/// Performs structural validation plus temporal checks: parses the JWT,
/// verifies the UCAN header fields (algorithm, version), checks token
/// expiry (`exp`) and not-before (`nbf`), and confirms that at least one
/// attenuation grants `messages:read` for the specified context (or a
/// wildcard context).
///
/// **Note:** This is a simplified validation suitable for projection
/// endpoints. It does NOT perform the full 11-step UCAN validation pipeline
/// (DID resolution, Ed25519 signature verification, delegation chain
/// traversal, revocation check) from
/// [`scp_core::context::broadcast::validate_messages_read_ucan`], because
/// the projection layer does not hold DID documents or the full
/// `BroadcastContext` state. The primary access-control boundary is key
/// distribution (subscribers must obtain broadcast keys via the gated key
/// request flow); this check is a secondary defense-in-depth gate.
///
/// Returns `Ok(())` on success, or an error response on failure.
fn validate_projection_ucan(
    token: &str,
    context_id: &str,
) -> Result<(), Box<axum::response::Response>> {
    let ucan = parse_ucan(token).map_err(|e| {
        tracing::debug!(error = %e, "UCAN parse failed for projection auth");
        Box::new(ApiError::unauthorized_with("invalid UCAN token").into_response())
    })?;

    // Temporal checks: reject expired or not-yet-valid tokens.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if ucan.payload.exp <= now {
        tracing::debug!(
            exp = ucan.payload.exp,
            now = now,
            "UCAN expired for projection auth"
        );
        return Err(Box::new(
            ApiError::unauthorized_with("UCAN token expired").into_response(),
        ));
    }

    if let Some(nbf) = ucan.payload.nbf
        && nbf > now
    {
        tracing::debug!(
            nbf = nbf,
            now = now,
            "UCAN not yet valid for projection auth"
        );
        return Err(Box::new(
            ApiError::unauthorized_with("UCAN token not yet valid").into_response(),
        ));
    }

    // Build the required capability URI for this context.
    let required = CapabilityUri::new(context_id, "messages", "read");

    // Check that at least one attenuation grants the required capability.
    let has_capability = ucan.payload.att.iter().any(|att| {
        att.with
            .parse::<CapabilityUri>()
            .is_ok_and(|cap| cap.matches(&required))
    });

    if !has_capability {
        tracing::debug!(
            context_id = context_id,
            "UCAN missing messages:read capability for context"
        );
        return Err(Box::new(
            ApiError::unauthorized_with("UCAN missing messages:read capability").into_response(),
        ));
    }

    Ok(())
}

/// Determines the effective projection rule for a request, considering the
/// context's admission mode, default projection policy, and optional
/// per-author overrides.
///
/// For gated contexts without an explicit projection policy, returns
/// `ProjectionRule::Gated`. For open contexts without a policy, returns
/// `ProjectionRule::Public`.
///
/// When `author_did` is `Some`, checks for a per-author override before
/// falling back to the default rule.
fn effective_projection_rule(
    admission: BroadcastAdmission,
    policy: Option<&ProjectionPolicy>,
    author_did: Option<&str>,
) -> ProjectionRule {
    match policy {
        Some(p) => {
            // Check per-author override first, if an author DID is available.
            if let Some(author) = author_did
                && let Some(ov) = p.overrides.iter().find(|o| o.did.as_ref() == author)
            {
                return ov.rule;
            }
            p.default_rule
        }
        None => match admission {
            BroadcastAdmission::Gated => ProjectionRule::Gated,
            BroadcastAdmission::Open => ProjectionRule::Public,
        },
    }
}

/// Checks authorization for a projection endpoint request.
///
/// Returns `Ok(())` if the request is authorized, or an error response if not.
/// For `ProjectionRule::Public`, no authorization is required. For
/// `ProjectionRule::Gated`, a valid UCAN with `messages:read` capability must
/// be present in the `Authorization: Bearer <token>` header.
///
/// `ProjectionRule::AuthorChoice` is treated as `Gated` at the projection
/// layer — the author's own choice is enforced at the context level, not
/// at HTTP projection.
fn check_projection_auth(
    headers: &axum::http::HeaderMap,
    context_id: &str,
    rule: ProjectionRule,
) -> Result<(), Box<axum::response::Response>> {
    match rule {
        ProjectionRule::Public => Ok(()),
        ProjectionRule::Gated | ProjectionRule::AuthorChoice => {
            let token = extract_bearer_token(headers).ok_or_else(|| {
                Box::new(
                    ApiError::unauthorized_with("Authorization required for gated broadcast")
                        .into_response(),
                )
            })?;
            validate_projection_ucan(token, context_id)
        }
    }
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
/// Includes all envelope metadata fields per §5.14.5 (issue #352).
///
/// See spec section 18.11.3.
#[derive(Debug, Clone, Serialize)]
pub struct FeedMessage {
    /// The hex-encoded blob ID (SHA-256 hash) identifying this message.
    pub id: String,
    /// The context ID this message belongs to.
    pub context_id: String,
    /// The DID of the author who sealed this broadcast envelope.
    pub author_did: String,
    /// The per-author monotonic sequence number (§5.14.5).
    pub sequence: u64,
    /// Unix timestamp in milliseconds when the message was sealed.
    pub timestamp: u64,
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
        let plaintext = match open_broadcast_trusted(key, &envelope) {
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
            context_id: envelope.context_id,
            author_did: envelope.author_did,
            sequence: envelope.sequence,
            timestamp: envelope.timestamp,
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
    headers: axum::http::HeaderMap,
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

    // Extract context_id, keys, and auth-related fields before dropping the read lock.
    let context_id = projected.context_id.clone();
    let admission = projected.admission;
    let projection_policy = projected.projection_policy.clone();
    // We need a snapshot of the keys to avoid holding the lock during async I/O.
    let keys: HashMap<u64, BroadcastKey> = projected.keys.clone();
    drop(projected_contexts);

    // Enforce projection auth. Feed endpoint uses the default rule (no
    // per-author override) since the feed may contain messages from
    // multiple authors.
    let rule = effective_projection_rule(admission, projection_policy.as_ref(), None);
    if let Err(resp) = check_projection_auth(&headers, &context_id, rule) {
        return *resp;
    }

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
    let (mut messages, latest_blob_id) = decrypt_blobs(&blobs, &keys);

    // Per-author override filtering: if any per-author override makes an
    // author's content Gated (or stricter than the default rule), filter
    // out their messages when the request lacks valid auth. This prevents
    // the feed from leaking per-author-gated content to unauthenticated
    // clients (RED-302).
    //
    // Optimization (#355): pre-compute auth decisions for each distinct
    // ProjectionRule found in the overrides. This parses the UCAN at most
    // once per distinct rule instead of re-parsing per message in the
    // retain loop. ProjectionRule has only 3 variants, so we check each
    // at most once.
    if let Some(ref policy) = projection_policy
        && !policy.overrides.is_empty()
    {
        // Pre-compute auth result for each ProjectionRule variant that
        // appears in the overrides. The default rule already passed auth
        // above, so we mark it as authorized. For other rules, we call
        // check_projection_auth once per distinct variant.
        let auth_public = true; // Public never requires auth
        let mut auth_gated: Option<bool> = None;
        let mut auth_author_choice: Option<bool> = None;

        // Mark the default rule as already authorized.
        match rule {
            ProjectionRule::Public => {} // auth_public is already true
            ProjectionRule::Gated => {
                auth_gated = Some(true);
            }
            ProjectionRule::AuthorChoice => {
                auth_author_choice = Some(true);
            }
        }

        // Pre-compute only the rules that actually appear in overrides
        // and haven't been computed yet.
        for ov in &policy.overrides {
            if ov.rule == ProjectionRule::Gated && auth_gated.is_none() {
                auth_gated = Some(
                    check_projection_auth(&headers, &context_id, ProjectionRule::Gated).is_ok(),
                );
            } else if ov.rule == ProjectionRule::AuthorChoice && auth_author_choice.is_none() {
                auth_author_choice = Some(
                    check_projection_auth(&headers, &context_id, ProjectionRule::AuthorChoice)
                        .is_ok(),
                );
            }
            // ProjectionRule::Public is always authorized; already-computed
            // rules are skipped by the is_none() guards above.
        }

        messages.retain(|msg| {
            let author_rule =
                effective_projection_rule(admission, Some(policy), Some(&msg.author_did));
            match author_rule {
                ProjectionRule::Public => auth_public,
                ProjectionRule::Gated => auth_gated.unwrap_or(true),
                ProjectionRule::AuthorChoice => auth_author_choice.unwrap_or(true),
            }
        });
    }

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

    // Build response with caching headers. Gated contexts use `private`
    // to prevent shared caches from serving authenticated content to
    // unauthorized clients.
    let etag = latest_blob_id
        .map(|id| format!("\"{}\"", hex_encode(&id)))
        .unwrap_or_default();

    // If any per-author override exists, the response content varies based on
    // auth state — use `private` even if the default rule is Public.
    let has_per_author_overrides = projection_policy
        .as_ref()
        .is_some_and(|p| !p.overrides.is_empty());

    let cache_control = match rule {
        ProjectionRule::Public if !has_per_author_overrides => {
            "public, max-age=30, stale-while-revalidate=300"
        }
        _ => "private, max-age=30",
    };

    let mut resp_headers = axum::http::HeaderMap::new();
    resp_headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(cache_control),
    );
    if let (false, Ok(val)) = (etag.is_empty(), axum::http::HeaderValue::from_str(&etag)) {
        resp_headers.insert(header::ETAG, val);
    }

    (StatusCode::OK, resp_headers, Json(response)).into_response()
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
/// - **410** — Content revoked (epoch key purged after a `Full`-scope
///   governance ban).
/// - **500** — Decryption failure (corrupt envelope or AEAD open failure).
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

    // Snapshot keys and auth-related fields before dropping the read lock.
    let context_id = projected.context_id.clone();
    let admission = projected.admission;
    let projection_policy = projected.projection_policy.clone();
    let keys: HashMap<u64, BroadcastKey> = projected.keys.clone();
    drop(projected_contexts);

    // Pre-auth check with default rule (before we know the author). For
    // gated contexts this rejects unauthenticated requests early. The
    // per-author override is checked after decryption reveals the author DID.
    let default_rule = effective_projection_rule(admission, projection_policy.as_ref(), None);
    if matches!(
        default_rule,
        ProjectionRule::Gated | ProjectionRule::AuthorChoice
    ) && let Err(resp) = check_projection_auth(&headers, &context_id, default_rule)
    {
        return *resp;
    }

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

    // Per-author override: the envelope exposes `author_did` without
    // requiring decryption (it's in the MessagePack header, not the
    // ciphertext). Check per-author auth BEFORE decrypting — authenticate
    // before processing is a fundamental security principle.
    let effective_rule = effective_projection_rule(
        admission,
        projection_policy.as_ref(),
        Some(&envelope.author_did),
    );
    if effective_rule != default_rule
        && let Err(resp) = check_projection_auth(&headers, &context_id, effective_rule)
    {
        return *resp;
    }

    // Find the matching broadcast key for this epoch. A missing key
    // indicates the epoch was purged after a Full-scope governance ban
    // (intentional revocation) — return 410 Gone rather than 500.
    let Some(key) = keys.get(&envelope.key_epoch) else {
        tracing::warn!(
            blob_id = blob_id_hex,
            epoch = envelope.key_epoch,
            "no broadcast key for epoch (likely purged after governance ban)"
        );
        return ApiError::gone("content revoked").into_response();
    };

    // Decrypt.
    let plaintext = match open_broadcast_trusted(key, &envelope) {
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
        context_id: envelope.context_id,
        author_did: envelope.author_did,
        sequence: envelope.sequence,
        timestamp: envelope.timestamp,
        key_epoch: envelope.key_epoch,
        published_at: unix_to_iso8601(stored.stored_at),
        content: BASE64.encode(&plaintext),
    };

    // Build response with immutable caching headers. Gated contexts use
    // `private` to prevent shared caches from serving authenticated
    // content to unauthorized clients.
    let cache_control = match effective_rule {
        ProjectionRule::Public => "public, immutable, max-age=31536000",
        ProjectionRule::Gated | ProjectionRule::AuthorChoice => {
            "private, immutable, max-age=31536000"
        }
    };

    let mut resp_headers = axum::http::HeaderMap::new();
    resp_headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(cache_control),
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
    use ed25519_dalek::Signer;
    use scp_core::crypto::sender_keys::{
        SealBroadcastParams, SigningPayloadFields, build_broadcast_signing_payload,
        compute_provenance_hash, generate_broadcast_key, generate_broadcast_nonce,
        rotate_broadcast_key, seal_broadcast,
    };

    /// Seals a broadcast envelope with test defaults for projection tests.
    fn test_seal(key: &BroadcastKey, payload: &[u8]) -> BroadcastEnvelope {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]);
        let nonce = generate_broadcast_nonce();
        let provenance_hash = compute_provenance_hash(None).unwrap();
        let signature = sk.sign(&build_broadcast_signing_payload(&SigningPayloadFields {
            version: scp_core::envelope::SCP_PROTOCOL_VERSION,
            context_id: "test-ctx",
            author_did: key.author_did(),
            sequence: 1,
            key_epoch: key.epoch(),
            timestamp: 1_700_000_000_000,
            nonce: &nonce,
            provenance_hash: &provenance_hash,
        }));
        let params = SealBroadcastParams {
            context_id: "test-ctx",
            sequence: 1,
            timestamp: 1_700_000_000_000,
            provenance: None,
            signature,
        };
        seal_broadcast(key, payload, &nonce, &params).unwrap()
    }

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
        let envelope = test_seal(&key, b"hello world");
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
        let envelope = test_seal(&key, b"secret");
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
            did_document: scp_identity::document::DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:dht:test".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                also_known_as: vec![],
                service: vec![],
            },
            connection_tracker: scp_transport::relay::rate_limit::new_connection_tracker(),
            subscription_registry: scp_transport::relay::subscription::new_registry(),
            acme_challenges: None,
            bridge_state: Arc::new(crate::bridge_handlers::BridgeState::new()),
            bridge_lookup: None,
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal and store a broadcast message.
        let envelope = test_seal(&key, b"hello feed");
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store 5 messages.
        for i in 0u8..5 {
            let envelope = test_seal(&key, &[i; 10]);
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
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
        let projected = ProjectedContext::new(context_id, key, BroadcastAdmission::Open, None);
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
        let projected = ProjectedContext::new(context_id, key, BroadcastAdmission::Open, None);
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal and store a broadcast message.
        let envelope = test_seal(&key, b"single message");
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        let envelope = test_seal(&key, b"cached msg");
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        let envelope = test_seal(&key, b"fresh msg");
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
        let ctx = ProjectedContext::new("abc123", key, BroadcastAdmission::Open, None);

        let expected_routing_id = compute_routing_id("abc123");
        assert_eq!(ctx.routing_id, expected_routing_id);
        assert_eq!(ctx.context_id(), "abc123");
    }

    #[test]
    fn projected_context_new_inserts_key_at_epoch() {
        let key = generate_broadcast_key("did:dht:alice");
        let ctx = ProjectedContext::new("abc123", key, BroadcastAdmission::Open, None);

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

        let projected = ProjectedContext::new(context_id, key, BroadcastAdmission::Open, None);
        registry.insert(routing_id, projected);
        assert!(registry.contains_key(&routing_id));

        // Disable: remove from registry.
        registry.remove(&routing_id);
        assert!(!registry.contains_key(&routing_id));
    }

    #[test]
    fn multiple_epochs_stored_and_retrievable() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let mut ctx =
            ProjectedContext::new("multi_epoch_ctx", key0, BroadcastAdmission::Open, None);

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
        let mut ctx = ProjectedContext::new("replace_test", key0, BroadcastAdmission::Open, None);

        // Insert a different key at epoch 0 (replacement).
        let replacement = generate_broadcast_key("did:dht:alice");
        ctx.insert_key(replacement);

        assert_eq!(ctx.keys().len(), 1);
        assert!(ctx.key_for_epoch(0).is_some());
    }

    #[test]
    fn retain_only_epochs_keeps_specified_purges_rest() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let mut ctx = ProjectedContext::new("purge_test", key0, BroadcastAdmission::Open, None);

        // Build up epochs 0, 1, 2.
        let k0 = ctx.key_for_epoch(0).unwrap().clone();
        let (k1, _) = rotate_broadcast_key(&k0, 1000).unwrap();
        ctx.insert_key(k1.clone());
        let (k2, _) = rotate_broadcast_key(&k1, 2000).unwrap();
        ctx.insert_key(k2);
        assert_eq!(ctx.keys().len(), 3);

        // Retain only epoch 2 (simulates Full-scope ban where author
        // rotated to epoch 2).
        let retain = std::collections::HashSet::from([2]);
        ctx.retain_only_epochs(&retain);

        assert!(ctx.key_for_epoch(0).is_none(), "epoch 0 purged");
        assert!(ctx.key_for_epoch(1).is_none(), "epoch 1 purged");
        assert!(ctx.key_for_epoch(2).is_some(), "epoch 2 retained");
        assert_eq!(ctx.keys().len(), 1);
    }

    #[test]
    fn retain_only_epochs_handles_divergent_authors() {
        // Simulate two authors at different epochs: alice at epoch 3,
        // bob at epoch 1. Full-scope ban should retain only {3, 1}.
        let alice_key = generate_broadcast_key("did:dht:alice");
        let mut ctx = ProjectedContext::new(
            "divergent_test",
            alice_key.clone(),
            BroadcastAdmission::Open,
            None,
        );

        // Alice: epochs 0, 1, 2, 3.
        let (a1, _) = rotate_broadcast_key(&alice_key, 1000).unwrap();
        ctx.insert_key(a1.clone());
        let (a2, _) = rotate_broadcast_key(&a1, 2000).unwrap();
        ctx.insert_key(a2.clone());
        let (a3, _) = rotate_broadcast_key(&a2, 3000).unwrap();
        ctx.insert_key(a3);

        // Bob: epochs 4, 5 (start at epoch 4 to avoid collision with
        // alice's epochs in the HashMap).
        let bob_key = generate_broadcast_key("did:dht:bob");
        let (b1, _) = rotate_broadcast_key(&bob_key, 1000).unwrap();
        let (b2, _) = rotate_broadcast_key(&b1, 2000).unwrap();
        let (b3, _) = rotate_broadcast_key(&b2, 3000).unwrap();
        let (b4, _) = rotate_broadcast_key(&b3, 4000).unwrap();
        ctx.insert_key(b4.clone());
        let (b5, _) = rotate_broadcast_key(&b4, 5000).unwrap();
        ctx.insert_key(b5);

        assert_eq!(ctx.keys().len(), 6); // epochs 0,1,2,3 (alice) + 4,5 (bob)

        // Full-scope ban: alice rotated to 3, bob rotated to 5.
        let retain = std::collections::HashSet::from([3, 5]);
        ctx.retain_only_epochs(&retain);

        assert_eq!(ctx.keys().len(), 2);
        assert!(ctx.key_for_epoch(3).is_some(), "alice new epoch retained");
        assert!(ctx.key_for_epoch(5).is_some(), "bob new epoch retained");
        assert!(ctx.key_for_epoch(0).is_none(), "old alice epoch purged");
        assert!(ctx.key_for_epoch(1).is_none(), "old alice epoch purged");
        assert!(ctx.key_for_epoch(2).is_none(), "old alice epoch purged");
        assert!(ctx.key_for_epoch(4).is_none(), "old bob epoch purged");
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
        let ctx_a =
            ProjectedContext::new("context_a", key_a.clone(), BroadcastAdmission::Open, None);
        let ctx_b = ProjectedContext::new("context_b", key_b, BroadcastAdmission::Open, None);
        let routing_id_a = ctx_a.routing_id;
        let routing_id_b = ctx_b.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id_a, ctx_a);
        projected_map.insert(routing_id_b, ctx_b);

        let storage = InMemoryBlobStorage::new();

        // Seal and store a blob under routing_A.
        let envelope = test_seal(&key_a, b"belongs to context_a");
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store 3 blobs. Because InMemoryBlobStorage uses real timestamps,
        // all blobs may get the same stored_at. We rely on the since
        // parameter resolving via blob lookup → stored_at filtering.
        let mut blob_ids = Vec::new();
        for i in 0u8..3 {
            let envelope = test_seal(&key, &[i; 16]);
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
        let mut projected =
            ProjectedContext::new(context_id, key0.clone(), BroadcastAdmission::Open, None);
        projected.insert_key(key1.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal message_1 with epoch 0 key.
        let envelope_0 = test_seal(&key0, b"epoch zero message");
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
        let envelope_1 = test_seal(&key1, b"epoch one message");
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
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Seal a message, then tamper with the ciphertext.
        let mut envelope = test_seal(&key, b"tamper target");
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
        let valid_envelope = test_seal(&key, b"valid message");
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
    // Test D2: Purged epoch key returns 410 Gone (not 500)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn message_purged_epoch_returns_410_gone() {
        // Seal a message at epoch 0, then purge epoch 0 from the
        // projected context (simulating a Full-scope governance ban).
        // The message_handler should return 410 Gone.
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "purge_410_ctx";
        let mut projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);

        // Rotate to epoch 1 and retain only epoch 1 (purge epoch 0).
        let (key1, _) = rotate_broadcast_key(&key, 1000).unwrap();
        projected.insert_key(key1);
        let retain = std::collections::HashSet::from([1]);
        projected.retain_only_epochs(&retain);
        assert!(projected.key_for_epoch(0).is_none());
        assert!(projected.key_for_epoch(1).is_some());

        let routing_id = projected.routing_id;
        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store a blob encrypted at epoch 0 (the purged epoch).
        let envelope = test_seal(&key, b"old content");
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
        assert_eq!(resp.status(), HttpStatus::GONE);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "content revoked");
        assert_eq!(json["code"], "GONE");
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
        let ctx_a =
            ProjectedContext::new("ctx_a_304", key_a.clone(), BroadcastAdmission::Open, None);
        let ctx_b = ProjectedContext::new("ctx_b_304", key_b, BroadcastAdmission::Open, None);
        let routing_id_a = ctx_a.routing_id;
        let routing_id_b = ctx_b.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id_a, ctx_a);
        projected_map.insert(routing_id_b, ctx_b);

        let storage = InMemoryBlobStorage::new();

        // Store blob under routing_A.
        let envelope = test_seal(&key_a, b"secret of A");
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

    // -----------------------------------------------------------------------
    // SCP-GG-008: UCAN validation for gated projection endpoints
    // -----------------------------------------------------------------------

    use scp_core::context::params::{ProjectionOverride, ProjectionPolicy, ProjectionRule};
    use scp_identity::DID;

    #[tokio::test]
    async fn feed_open_context_serves_without_auth() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "open_no_auth_ctx";
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Open, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store a message.
        let envelope = test_seal(&key, b"public content");
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

        // Request without any Authorization header — should succeed.
        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        // Verify public cache-control header.
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
    }

    #[tokio::test]
    async fn feed_gated_context_rejects_without_auth() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "gated_no_auth_ctx";
        let projected = ProjectedContext::new(context_id, key, BroadcastAdmission::Gated, None);
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
        assert_eq!(resp.status(), HttpStatus::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Authorization required for gated broadcast");
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn feed_gated_context_rejects_malformed_auth() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "gated_bad_auth_ctx";
        let projected = ProjectedContext::new(context_id, key, BroadcastAdmission::Gated, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let state = test_state_with(projected_map, InMemoryBlobStorage::new());
        let router = broadcast_projection_router(state);

        let routing_hex = hex_encode(&routing_id);

        // Test 1: "Basic" scheme (not Bearer).
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::UNAUTHORIZED);

        // Test 2: "Bearer" with invalid JWT (not 3 segments).
        let router = broadcast_projection_router(test_state_with(
            {
                let mut m = HashMap::new();
                let key2 = generate_broadcast_key("did:dht:alice");
                let p2 = ProjectedContext::new(context_id, key2, BroadcastAdmission::Gated, None);
                m.insert(p2.routing_id, p2);
                m
            },
            InMemoryBlobStorage::new(),
        ));

        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .header("Authorization", "Bearer not-a-valid-jwt")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn message_gated_context_rejects_without_auth() {
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "gated_msg_no_auth";
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Gated, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        let envelope = test_seal(&key, b"secret content");
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
        assert_eq!(resp.status(), HttpStatus::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Authorization required for gated broadcast");
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn gated_context_returns_private_cache_headers() {
        // Create a gated context with a synthetic but structurally valid UCAN.
        let key = generate_broadcast_key("did:dht:alice");
        let context_id = "gated_cache_ctx";
        let projected =
            ProjectedContext::new(context_id, key.clone(), BroadcastAdmission::Gated, None);
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        let envelope = test_seal(&key, b"gated content");
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

        // Build a structurally valid UCAN JWT with messages:read capability.
        let ucan_token = build_test_ucan(context_id);

        // Test feed endpoint.
        let router = broadcast_projection_router(Arc::clone(&state));
        let routing_hex = hex_encode(&routing_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .header("Authorization", format!("Bearer {ucan_token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let cache_control = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "private, max-age=30");

        // Test per-message endpoint.
        let router = broadcast_projection_router(state);
        let blob_hex = hex_encode(&blob_id);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{blob_hex}"))
            .header("Authorization", format!("Bearer {ucan_token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        let cache_control = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "private, immutable, max-age=31536000");
    }

    // -----------------------------------------------------------------------
    // SCP-GG-008: effective_projection_rule unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn effective_rule_open_no_policy() {
        let rule = effective_projection_rule(BroadcastAdmission::Open, None, None);
        assert_eq!(rule, ProjectionRule::Public);
    }

    #[test]
    fn effective_rule_gated_no_policy() {
        let rule = effective_projection_rule(BroadcastAdmission::Gated, None, None);
        assert_eq!(rule, ProjectionRule::Gated);
    }

    #[test]
    fn effective_rule_with_policy_default() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![],
        };
        let rule = effective_projection_rule(BroadcastAdmission::Open, Some(&policy), None);
        assert_eq!(rule, ProjectionRule::Gated);
    }

    #[test]
    fn effective_rule_per_author_override() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![ProjectionOverride {
                did: DID::from("did:dht:special_author"),
                rule: ProjectionRule::Public,
            }],
        };
        // Non-matching author falls back to default.
        let rule = effective_projection_rule(
            BroadcastAdmission::Open,
            Some(&policy),
            Some("did:dht:other"),
        );
        assert_eq!(rule, ProjectionRule::Gated);

        // Matching author gets override.
        let rule = effective_projection_rule(
            BroadcastAdmission::Open,
            Some(&policy),
            Some("did:dht:special_author"),
        );
        assert_eq!(rule, ProjectionRule::Public);
    }

    #[test]
    fn effective_rule_no_author_uses_default() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![ProjectionOverride {
                did: DID::from("did:dht:someone"),
                rule: ProjectionRule::Public,
            }],
        };
        // No author DID → default rule.
        let rule = effective_projection_rule(BroadcastAdmission::Open, Some(&policy), None);
        assert_eq!(rule, ProjectionRule::Gated);
    }

    // -----------------------------------------------------------------------
    // SCP-GG-008: validate_projection_policy tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_policy_rejects_public_default_on_gated() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Public,
            overrides: vec![],
        };
        let result = validate_projection_policy(BroadcastAdmission::Gated, Some(&policy));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "gated context cannot have public projection rule"
        );
    }

    #[test]
    fn validate_policy_rejects_public_override_on_gated() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![ProjectionOverride {
                did: DID::from("did:dht:some_author"),
                rule: ProjectionRule::Public,
            }],
        };
        let result = validate_projection_policy(BroadcastAdmission::Gated, Some(&policy));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "gated context cannot have public per-author projection override"
        );
    }

    #[test]
    fn validate_policy_accepts_gated_default_on_gated() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Gated,
            overrides: vec![],
        };
        assert!(validate_projection_policy(BroadcastAdmission::Gated, Some(&policy),).is_ok());
    }

    #[test]
    fn validate_policy_accepts_public_on_open() {
        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Public,
            overrides: vec![],
        };
        assert!(validate_projection_policy(BroadcastAdmission::Open, Some(&policy),).is_ok());
    }

    #[test]
    fn validate_policy_accepts_none_on_gated() {
        assert!(validate_projection_policy(BroadcastAdmission::Gated, None).is_ok());
    }

    // -----------------------------------------------------------------------
    // SCP-GG-008: feed per-author override filtering (RED-302)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn feed_filters_per_author_gated_messages_without_auth() {
        use scp_core::crypto::sender_keys::broadcast::rotate_broadcast_key;

        // Open context with per-author Gated override for alice.
        // Bob's messages should be visible without auth; alice's should not.
        let alice_key = generate_broadcast_key("did:dht:alice");
        let bob_key_epoch0 = generate_broadcast_key("did:dht:bob");
        let (bob_key, _) = rotate_broadcast_key(&bob_key_epoch0, 1_000).unwrap();
        let context_id = "feed_per_author_filter_ctx";

        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Public,
            overrides: vec![ProjectionOverride {
                did: DID::from("did:dht:alice"),
                rule: ProjectionRule::Gated,
            }],
        };

        let mut projected = ProjectedContext::new(
            context_id,
            alice_key.clone(),
            BroadcastAdmission::Open,
            Some(policy),
        );
        projected.keys.insert(bob_key.epoch(), bob_key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store alice's message (should be filtered from unauthenticated feed).
        let alice_env = test_seal(&alice_key, b"alice secret");
        let alice_bytes = rmp_serde::to_vec(&alice_env).unwrap();
        let alice_blob_id = {
            let mut h = Sha256::new();
            h.update(&alice_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, alice_blob_id, None, 3600, alice_bytes)
            .await
            .unwrap();

        // Store bob's message (should be visible without auth).
        let bob_env = test_seal(&bob_key, b"bob public");
        let bob_bytes = rmp_serde::to_vec(&bob_env).unwrap();
        let bob_blob_id = {
            let mut h = Sha256::new();
            h.update(&bob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, bob_blob_id, None, 3600, bob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let routing_hex = hex_encode(&routing_id);

        // Request feed WITHOUT auth — should only include bob's message.
        let router = broadcast_projection_router(Arc::clone(&state));
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);

        // Verify private cache-control (response varies by auth).
        let cache_control = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "private, max-age=30");

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let messages = json["messages"].as_array().unwrap();

        // Only bob's message should be in the feed.
        assert_eq!(
            messages.len(),
            1,
            "feed should filter alice's gated message"
        );
        assert_eq!(messages[0]["author_did"], "did:dht:bob");

        // Request feed WITH valid UCAN — should include both messages.
        let ucan_token = build_test_ucan(context_id);
        let router = broadcast_projection_router(state);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/feed"))
            .header("Authorization", format!("Bearer {ucan_token}"))
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
            "authenticated feed should include both messages"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-GG-008: UCAN temporal validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_ucan_rejects_expired_token() {
        // Build a UCAN with exp in the past.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use scp_core::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};

        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: None,
        };
        let payload = UcanPayload {
            iss: "did:dht:test".to_owned(),
            aud: "did:dht:test".to_owned(),
            exp: 1, // expired (1970-01-01T00:00:01)
            nbf: None,
            nnc: "nonce".to_owned(),
            att: vec![Attenuation {
                with: "scp:ctx:test_ctx/messages:read".to_owned(),
                can: "read".to_owned(),
            }],
            prf: vec![],
            fct: None,
        };

        let h = serde_json::to_vec(&header).unwrap();
        let p = serde_json::to_vec(&payload).unwrap();
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(&h),
            URL_SAFE_NO_PAD.encode(&p),
            URL_SAFE_NO_PAD.encode(vec![0u8; 64]),
        );

        let result = validate_projection_ucan(&token, "test_ctx");
        assert!(result.is_err(), "expired UCAN should be rejected");
    }

    #[test]
    fn validate_ucan_rejects_not_yet_valid_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use scp_core::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};

        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: None,
        };
        let payload = UcanPayload {
            iss: "did:dht:test".to_owned(),
            aud: "did:dht:test".to_owned(),
            exp: u64::MAX,
            nbf: Some(u64::MAX - 1), // not valid until far future
            nnc: "nonce".to_owned(),
            att: vec![Attenuation {
                with: "scp:ctx:test_ctx/messages:read".to_owned(),
                can: "read".to_owned(),
            }],
            prf: vec![],
            fct: None,
        };

        let h = serde_json::to_vec(&header).unwrap();
        let p = serde_json::to_vec(&payload).unwrap();
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(&h),
            URL_SAFE_NO_PAD.encode(&p),
            URL_SAFE_NO_PAD.encode(vec![0u8; 64]),
        );

        let result = validate_projection_ucan(&token, "test_ctx");
        assert!(result.is_err(), "not-yet-valid UCAN should be rejected");
    }

    // -----------------------------------------------------------------------
    // SCP-GG-008: per-author override handler integration test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn message_handler_enforces_per_author_gated_override_on_open_context() {
        use scp_core::crypto::sender_keys::broadcast::rotate_broadcast_key;

        // Open context with a per-author Gated override for "did:dht:alice".
        // Default is Public (because Open admission + no default_rule override),
        // but alice's content requires auth due to the per-author override.
        let alice_key = generate_broadcast_key("did:dht:alice");
        let bob_key_epoch0 = generate_broadcast_key("did:dht:bob");
        // Rotate bob's key to epoch 1 so it doesn't collide with alice's epoch 0.
        let (bob_key, _) = rotate_broadcast_key(&bob_key_epoch0, 1_000).unwrap();
        let context_id = "open_per_author_override_ctx";

        let policy = ProjectionPolicy {
            default_rule: ProjectionRule::Public,
            overrides: vec![ProjectionOverride {
                did: DID::from("did:dht:alice"),
                rule: ProjectionRule::Gated,
            }],
        };

        let mut projected = ProjectedContext::new(
            context_id,
            alice_key.clone(),
            BroadcastAdmission::Open,
            Some(policy),
        );
        // Insert bob's key (epoch 1) so messages from both authors can be decrypted.
        projected.keys.insert(bob_key.epoch(), bob_key.clone());
        let routing_id = projected.routing_id;

        let mut projected_map = HashMap::new();
        projected_map.insert(routing_id, projected);

        let storage = InMemoryBlobStorage::new();

        // Store a message from alice (who has a Gated override).
        let alice_envelope = test_seal(&alice_key, b"alice private content");
        let alice_blob_bytes = rmp_serde::to_vec(&alice_envelope).unwrap();
        let alice_blob_id = {
            let mut h = Sha256::new();
            h.update(&alice_blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, alice_blob_id, None, 3600, alice_blob_bytes)
            .await
            .unwrap();

        // Store a message from bob (no override — default Public applies).
        let bob_envelope = test_seal(&bob_key, b"bob public content");
        let bob_blob_bytes = rmp_serde::to_vec(&bob_envelope).unwrap();
        let bob_blob_id = {
            let mut h = Sha256::new();
            h.update(&bob_blob_bytes);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        storage
            .store(routing_id, bob_blob_id, None, 3600, bob_blob_bytes)
            .await
            .unwrap();

        let state = test_state_with(projected_map, storage);
        let routing_hex = hex_encode(&routing_id);

        // Request alice's message without auth → should be rejected (401)
        // because the per-author override makes alice's content Gated.
        let alice_hex = hex_encode(&alice_blob_id);
        let router = broadcast_projection_router(Arc::clone(&state));
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{alice_hex}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            HttpStatus::UNAUTHORIZED,
            "alice's content should require auth due to per-author Gated override"
        );

        // Request bob's message without auth → should succeed (200)
        // because bob has no override and the default is Public.
        let bob_hex = hex_encode(&bob_blob_id);
        let router = broadcast_projection_router(Arc::clone(&state));
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{bob_hex}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            HttpStatus::OK,
            "bob's content should be public (no per-author override)"
        );

        // Request alice's message with a valid UCAN → should succeed (200).
        let ucan_token = build_test_ucan(context_id);
        let router = broadcast_projection_router(state);
        let req = Request::builder()
            .uri(format!("/scp/broadcast/{routing_hex}/messages/{alice_hex}"))
            .header("Authorization", format!("Bearer {ucan_token}"))
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            HttpStatus::OK,
            "alice's content should be accessible with valid UCAN"
        );

        // Verify private cache-control on alice's gated content.
        let cache_control = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "private, immutable, max-age=31536000");
    }

    // -----------------------------------------------------------------------
    // Helper: build a structurally valid test UCAN JWT
    // -----------------------------------------------------------------------

    /// Builds a structurally valid (but not cryptographically verified) UCAN JWT
    /// with a `messages:read` capability for the given context. The signature is
    /// a dummy — suitable for testing the structural validation path in
    /// `validate_projection_ucan`, not the full 11-step pipeline.
    fn build_test_ucan(context_id: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use scp_core::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};

        let header = UcanHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            ucv: "0.10.0".to_owned(),
            kid: None,
        };
        let payload = UcanPayload {
            iss: "did:dht:test_issuer".to_owned(),
            aud: "did:dht:test_audience".to_owned(),
            exp: u64::MAX,
            nbf: None,
            nnc: "test-nonce-001".to_owned(),
            att: vec![Attenuation {
                with: format!("scp:ctx:{context_id}/messages:read"),
                can: "read".to_owned(),
            }],
            prf: vec![],
            fct: None,
        };

        let header_json = serde_json::to_vec(&header).unwrap();
        let payload_json = serde_json::to_vec(&payload).unwrap();
        // Dummy signature (32 bytes of zeros). Not cryptographically valid,
        // but parse_ucan only checks structural format.
        let signature = vec![0u8; 64];

        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(&header_json),
            URL_SAFE_NO_PAD.encode(&payload_json),
            URL_SAFE_NO_PAD.encode(&signature),
        )
    }
}
