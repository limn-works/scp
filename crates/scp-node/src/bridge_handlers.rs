//! HTTP handlers for bridge endpoints.
//!
//! Implements the REST API surface for bridge operations such as shadow
//! identity creation. All endpoints require bridge authentication via
//! DID-signed JWT (see [`bridge_auth`](crate::bridge_auth)).
//!
//! See spec section 12.10 and ADR-023 in `.docs/adrs/phase-5.md`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    Extension, Json, Router,
    routing::{delete, get, post},
};
use scp_core::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow};
use scp_core::bridge::{BridgeMode, ShadowProvenanceStatus};
use scp_core::crypto::sender_keys::SenderKeyStore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::ApiError;

// ---------------------------------------------------------------------------
// Shared state for bridge operations
// ---------------------------------------------------------------------------

/// A stored platform identity attestation.
#[derive(Debug, Clone, Serialize)]
pub struct StoredAttestation {
    /// Unique attestation identifier.
    pub attestation_id: String,
    /// Current attestation status (e.g., `"active"`, `"revoked"`).
    pub status: String,
    /// The bridge that produced this attestation.
    pub bridge_id: String,
    /// The user's handle on the bridged platform.
    pub platform_handle: String,
    /// The user's unique identifier on the bridged platform.
    pub platform_user_id: String,
    /// Cryptographic evidence supporting the attestation.
    pub evidence: AttestationEvidence,
    /// Unix timestamp (seconds) when the attestation was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the attestation expires.
    pub expires_at: u64,
}

/// Shared state for bridge shadow operations.
///
/// Holds per-context shadow registries, the sender key store,
/// platform identity attestations, webhook event deduplication,
/// emitted messages, and the outbound webhook dispatcher, protected
/// by async `RwLock`s for concurrent handler access.
#[derive(Debug)]
pub struct BridgeState {
    /// Per-context shadow registries, keyed by context ID.
    pub registries: RwLock<HashMap<String, ShadowRegistry>>,

    /// Sender key store for shadow identity encryption keys.
    pub sender_key_store: RwLock<SenderKeyStore>,

    /// Platform identity attestations, keyed by attestation ID.
    pub attestations: RwLock<HashMap<String, StoredAttestation>>,

    /// Deleted shadows, keyed by `(context_id, bridge_id, shadow_id)`
    /// (historical actions remain in event log).
    ///
    /// Context ID and bridge ID are both part of the key so no caller learns,
    /// through the idempotent 204 that a delete returns for an already-deleted
    /// shadow, that a second bridge retired a shadow — whether that bridge sits
    /// in another context or shares this one.
    pub deleted_shadows: RwLock<HashSet<(String, String, String)>>,

    /// Webhook event IDs already processed, keyed by `(bridge_id, event_id)`
    /// (deduplication).
    ///
    /// The bridge ID is part of the key because `event_id` is platform-assigned
    /// (§12.10.4) and two platforms pick their event IDs independently. Keying
    /// on `event_id` alone would let one platform suppress another platform's
    /// event by claiming that ID first.
    pub processed_event_ids: RwLock<HashSet<(String, String)>>,

    /// Emitted messages, keyed by message ID.
    pub messages: RwLock<Vec<EmittedMessage>>,

    /// Monotonically increasing per-context sequence counters for emitted
    /// messages, keyed by context ID.
    ///
    /// Each context counts its own messages, so a bridge operator reading its
    /// own sequence numbers learns nothing about how many messages other
    /// contexts carried.
    pub message_sequence: RwLock<HashMap<String, u64>>,

    /// Outbound webhook dispatcher for delivering context events
    /// to registered bridge webhook endpoints (spec §12.2.1).
    ///
    /// Wrapped in `Arc` so the same dispatcher instance can be shared with
    /// the local-event consumer task spawned via
    /// [`spawn_event_consumer`](crate::webhook::spawn_event_consumer). Both
    /// the inbound HTTP relay path (`process_webhook_event`) and the local
    /// `Supervisor` event channel feed this single dispatcher (§12.10.5).
    pub webhook_dispatcher: Arc<crate::webhook::WebhookDispatcher>,
}

/// A stored emitted message for tracking purposes.
#[derive(Debug, Clone, Serialize)]
pub struct EmittedMessage {
    /// Unique message ID.
    pub message_id: String,
    /// Shadow ID that emitted the message.
    pub shadow_id: String,
    /// Message content.
    pub content: String,
    /// Content type.
    pub content_type: String,
    /// Sequence number.
    pub sequence: u64,
    /// Bridge provenance metadata.
    pub bridge_provenance: BridgeProvenanceResponse,
}

impl BridgeState {
    /// Creates a new empty bridge state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registries: RwLock::new(HashMap::new()),
            sender_key_store: RwLock::new(SenderKeyStore::new()),
            attestations: RwLock::new(HashMap::new()),
            deleted_shadows: RwLock::new(HashSet::new()),
            processed_event_ids: RwLock::new(HashSet::new()),
            messages: RwLock::new(Vec::new()),
            message_sequence: RwLock::new(HashMap::new()),
            webhook_dispatcher: Arc::new(crate::webhook::WebhookDispatcher::new()),
        }
    }

    /// Returns a clonable handle to the outbound webhook dispatcher.
    ///
    /// Used by the node-level event wiring to share the dispatcher with the
    /// local-event consumer task ([`spawn_event_consumer`](crate::webhook::spawn_event_consumer)),
    /// so `Supervisor`-originated events reach the same dispatcher as the
    /// inbound HTTP relay path (§12.10.5).
    #[must_use]
    pub fn webhook_dispatcher(&self) -> Arc<crate::webhook::WebhookDispatcher> {
        Arc::clone(&self.webhook_dispatcher)
    }
}

impl Default for BridgeState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/scp/bridge/shadow`.
#[derive(Debug, Deserialize)]
pub struct CreateShadowRequest {
    /// The external platform handle (e.g., `"@alice#1234"`).
    pub platform_handle: String,

    /// The platform-specific user identifier, used for idempotency.
    /// If a shadow already exists for this ID on the authenticated bridge,
    /// the existing shadow is returned with HTTP 200.
    pub platform_user_id: String,

    /// Optional metadata associated with the shadow identity.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Response body for `POST /v1/scp/bridge/shadow`.
#[derive(Debug, Serialize)]
pub struct CreateShadowResponse {
    /// The unique shadow identity ID.
    pub shadow_id: String,

    /// The external platform handle.
    pub platform_handle: String,

    /// The platform-specific user identifier.
    pub platform_user_id: String,

    /// The role attributed to this shadow (defaults to `"observer"`).
    pub attributed_role: String,

    /// Unix timestamp (seconds) when the shadow was created.
    pub created_at: u64,
}

/// Request body for `POST /v1/scp/bridge/attest`.
#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    /// The user's handle on the external platform.
    pub platform_handle: String,

    /// The platform's internal user identifier.
    pub platform_user_id: String,

    /// Evidence supporting the identity assertion.
    pub attestation_evidence: AttestationEvidence,
}

/// Evidence supporting a platform identity attestation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestationEvidence {
    /// Type of evidence (`platform-verified`, `oauth2`, `signed-challenge`).
    pub evidence_type: String,

    /// How the platform verified the user.
    pub verification_method: String,

    /// Unix timestamp (seconds) of verification.
    pub verified_at: u64,

    /// Confidence level: `"high"`, `"medium"`, or `"low"`.
    pub platform_confidence: String,

    /// Platform-specific trust signals.
    #[serde(default)]
    pub additional_signals: Option<serde_json::Value>,
}

/// Response body for `POST /v1/scp/bridge/attest`.
#[derive(Debug, Serialize)]
pub struct AttestResponse {
    /// The unique attestation ID.
    pub attestation_id: String,

    /// Attestation status (always `"active"` on creation).
    pub status: String,

    /// The user's handle on the external platform.
    pub platform_handle: String,

    /// Unix timestamp (seconds) when the attestation was issued.
    pub issued_at: u64,

    /// Unix timestamp (seconds) when the attestation expires.
    pub expires_at: u64,
}

/// Default attestation TTL: 24 hours in seconds.
const ATTESTATION_TTL_SECS: u64 = 86_400;

/// Returns a 400 response carrying spec §12.10.3's `INVALID_REQUEST` code.
///
/// Every bridge endpoint reports a malformed request body under that code,
/// which §12.10.3's error table pairs with HTTP 400. `ApiError::bad_request`
/// answers `BAD_REQUEST` instead, which no §12.10.3 row defines, so bridge
/// handlers use this helper.
fn invalid_request(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            error: msg.into(),
            code: "INVALID_REQUEST".to_owned(),
        }),
    )
}

/// Maximum request body any bridge route buffers, in bytes.
///
/// Spec §12.10.4 caps `content` at [`MAX_MESSAGE_CONTENT_BYTES`] and requires a
/// larger request to answer `INVALID_REQUEST` (400). Axum's own 2 MiB default
/// answers 413 instead for a body above it, so this limit sits just above that
/// content cap: a body carrying content one byte over the cap still reaches
/// [`emit_message_handler`], which answers the 400 §12.10.4 specifies, while a
/// body far above it is refused before a node buffers it. The 8 KiB of headroom
/// covers a request's JSON envelope — its field names, its `shadow_id`, its
/// `content_type`, and JSON string escaping of the content itself.
pub(crate) const MAX_BRIDGE_BODY_BYTES: usize = MAX_MESSAGE_CONTENT_BYTES + 8 * 1024;

/// Maximum `content` size `POST /v1/scp/bridge/message` accepts, in bytes.
///
/// Spec §12.10.4 caps it at 262,144 bytes (256 KiB), matching a relay's default
/// `max_blob_size` (§10), and requires a bridge node to reject a larger request
/// before it attempts MLS envelope construction.
const MAX_MESSAGE_CONTENT_BYTES: usize = 262_144;

/// Maximum size of the processed webhook event ID dedup set (BLACK-302).
const MAX_PROCESSED_EVENT_IDS: usize = 10_000;

// ---------------------------------------------------------------------------
// Message endpoint types (SCP-BCH-003)
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/scp/bridge/message`.
#[derive(Debug, Deserialize)]
pub struct EmitMessageRequest {
    /// The shadow identity emitting the message.
    pub shadow_id: String,

    /// Message content.
    pub content: String,

    /// MIME content type (e.g., `"text/plain"`).
    pub content_type: String,

    /// Optional platform-specific message ID for correlation.
    #[serde(default)]
    pub platform_message_id: Option<String>,

    /// Optional platform-reported timestamp.
    #[serde(default)]
    pub platform_timestamp: Option<u64>,
}

/// Serializable bridge provenance in API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeProvenanceResponse {
    /// Originating platform name.
    pub originating_platform: String,
    /// Bridge operating mode.
    pub bridge_mode: String,
    /// Shadow provenance status.
    pub shadow_status: String,
    /// Operator DID string.
    pub operator_did: String,
}

/// Response body for `POST /v1/scp/bridge/message`.
#[derive(Debug, Serialize)]
pub struct EmitMessageResponse {
    /// The unique message ID.
    pub message_id: String,
    /// Sequence number of the message.
    pub sequence: u64,
    /// Bridge provenance metadata.
    pub bridge_provenance: BridgeProvenanceResponse,
}

// ---------------------------------------------------------------------------
// Status endpoint types (SCP-BCH-005)
// ---------------------------------------------------------------------------

/// Response body for `GET /v1/scp/bridge/status`.
#[derive(Debug, Serialize)]
pub struct BridgeStatusResponse {
    /// Bridge instance ID.
    pub bridge_id: String,
    /// Current status (Active, Suspended, Revoked).
    pub status: String,
    /// External platform name.
    pub platform: String,
    /// Operating mode.
    pub mode: String,
    /// Operator DID.
    pub operator_did: String,
    /// Registration timestamp.
    pub registered_at: u64,
    /// Number of active shadows.
    pub shadow_count: usize,
    /// Shadows list.
    pub shadows: Vec<ShadowSummary>,
}

/// Summary of a shadow identity in the status response.
#[derive(Debug, Serialize)]
pub struct ShadowSummary {
    /// Shadow identity ID.
    pub shadow_id: String,
    /// Platform handle.
    pub platform_handle: String,
    /// Attributed role.
    pub attributed_role: String,
    /// Provenance status.
    pub provenance_status: String,
    /// Creation timestamp.
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Webhook endpoint types (SCP-BCH-006)
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/scp/bridge/webhook`.
#[derive(Debug, Deserialize)]
pub struct WebhookRequest {
    /// Event type.
    pub event_type: String,
    /// Unique event ID for deduplication.
    pub event_id: String,
    /// Event timestamp.
    pub timestamp: u64,
    /// Event-specific payload.
    pub payload: serde_json::Value,
}

/// Response body for `POST /v1/scp/bridge/webhook`.
#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    /// Whether the event was accepted.
    pub accepted: bool,
    /// Event ID echo.
    pub event_id: String,
    /// Optional rejection reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Supported webhook event types.
const VALID_EVENT_TYPES: &[&str] = &[
    "message",
    "presence",
    "identity_update",
    "user_departed",
    "message_edit",
    "message_delete",
];

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Escapes a segment so a colon-joined composite ID maps one identifier pair to
/// one string.
///
/// A bare `format!("{a}:{b}")` is not injective: bridge `acme:pro` with platform
/// user `u1` and bridge `acme` with platform user `pro:u1` both produce
/// `acme:pro:u1`. Escaping `%` first and then `:` removes every colon from each
/// segment, so a colon in the joined string only ever separates segments and no
/// two distinct pairs collide. A bridge operator picks its own
/// `platform_user_id` values, and a registrant picks its own bridge ID, so both
/// segments carry attacker-chosen text and both need escaping.
fn escape_id_segment(segment: &str) -> String {
    segment.replace('%', "%25").replace(':', "%3A")
}

/// Derives a deterministic shadow ID from bridge and platform user IDs.
///
/// The shadow ID is scoped to the bridge to prevent cross-bridge collisions,
/// and [`escape_id_segment`] keeps that scoping injective.
fn derive_shadow_id(bridge_id: &str, platform_user_id: &str) -> String {
    format!(
        "shadow:{}:{}",
        escape_id_segment(bridge_id),
        escape_id_segment(platform_user_id)
    )
}

/// Derives a deterministic attestation ID from bridge and platform user IDs.
///
/// Uses the same injective join as [`derive_shadow_id`], so one bridge cannot
/// overwrite a second bridge's attestation by choosing a `platform_user_id`
/// that reproduces that bridge's composite key.
fn derive_attestation_id(bridge_id: &str, platform_user_id: &str) -> String {
    format!(
        "attest:{}:{}",
        escape_id_segment(bridge_id),
        escape_id_segment(platform_user_id)
    )
}

/// Handler for `POST /v1/scp/bridge/shadow`.
///
/// Creates a shadow identity for an external platform participant. The
/// handler is idempotent: if a shadow already exists for the given
/// `platform_user_id` on the authenticated bridge, the existing shadow
/// is returned with HTTP 200.
///
/// Requires bridge authentication via the `bridge_auth_middleware`.
/// The authenticated bridge context is extracted from request extensions.
///
/// See SCP-BCH-002 and spec section 12.10.
#[allow(clippy::significant_drop_tightening)] // false positive on async RwLock guard scope
async fn create_shadow_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Json(body): Json<CreateShadowRequest>,
) -> impl IntoResponse {
    // Validate required fields (serde handles presence, but check emptiness).
    if body.platform_handle.is_empty() {
        return invalid_request("platform_handle must not be empty").into_response();
    }
    if body.platform_user_id.is_empty() {
        return invalid_request("platform_user_id must not be empty").into_response();
    }

    let bridge_id = auth_ctx.bridge_id();
    let context_id = auth_ctx.context_id();
    let shadow_id = derive_shadow_id(bridge_id, &body.platform_user_id);

    let mut registries = bridge_state.registries.write().await;
    // `delete_shadow_handler` retires a shadow by adding its identifier here
    // and leaves the registry record in place, so every read below filters
    // this set out. `status_handler` takes these two locks in this order.
    let mut deleted = bridge_state.deleted_shadows.write().await;

    // Ensure a registry exists for this context.
    let registry = registries
        .entry(context_id.to_owned())
        .or_insert_with(|| ShadowRegistry::new(context_id.to_owned()));

    let retirement_key = (
        context_id.to_owned(),
        bridge_id.to_owned(),
        shadow_id.clone(),
    );

    // Idempotency: if a shadow this bridge owns already carries this ID,
    // return 200.
    //
    // A shadow this bridge retired returns here too, and this call un-retires
    // it, because a platform user who departs and returns derives the same
    // identifier from the same `platform_user_id`. Answering 200 while leaving
    // the retirement in place would hand a caller a record that
    // `status_handler` omits and `emit_message_handler` answers 404 for.
    if let Some(existing) = registry
        .shadows()
        .iter()
        .find(|s| s.shadow_id == shadow_id && s.bridge_id == bridge_id)
    {
        deleted.remove(&retirement_key);
        return (
            StatusCode::OK,
            Json(CreateShadowResponse {
                shadow_id: existing.shadow_id.clone(),
                platform_handle: existing.platform_handle.clone(),
                platform_user_id: body.platform_user_id,
                attributed_role: existing.attributed_role.clone(),
                created_at: existing.created_at,
            }),
        )
            .into_response();
    }

    // Spec §12.2.1 makes `max_shadows` a governance-configured limit for this
    // bridge, and `ShadowRegistry` holds one per-bridge limit for a whole
    // context, so it cannot express two bridges with different limits. This
    // check reads the limit governance approved for the calling bridge and
    // counts that bridge's own shadows against it; the registry's own limit
    // stays as a second, context-wide bound.
    //
    // A retired shadow is not one this bridge manages — `status_handler`
    // leaves it out of the roster it reports — so counting it would spend a
    // governance-granted slot on a shadow no endpoint acts on, and a bridge
    // that creates and retires would exhaust its limit permanently.
    let owned_shadows = registry
        .shadows()
        .iter()
        .filter(|shadow| {
            shadow.bridge_id == bridge_id
                && !deleted.contains(&(
                    context_id.to_owned(),
                    bridge_id.to_owned(),
                    shadow.shadow_id.clone(),
                ))
        })
        .count();
    if owned_shadows >= auth_ctx.bridge.max_shadows as usize {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: format!(
                    "bridge has reached its governance-configured shadow limit of {}",
                    auth_ctx.bridge.max_shadows
                ),
                code: "BRIDGE_FORBIDDEN".to_owned(),
            }),
        )
            .into_response();
    }
    drop(deleted);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let bridge_mode = auth_ctx.bridge.mode.clone();

    let params = CreateShadowParams {
        shadow_id: &shadow_id,
        bridge_id,
        bridge_mode,
        platform_handle: &body.platform_handle,
        context_member_dids: &[],
        timestamp: now,
    };

    let mut sender_key_store = bridge_state.sender_key_store.write().await;

    match create_shadow(registry, &mut sender_key_store, &params) {
        Ok((shadow, _event)) => (
            StatusCode::CREATED,
            Json(CreateShadowResponse {
                shadow_id: shadow.shadow_id,
                platform_handle: shadow.platform_handle,
                platform_user_id: body.platform_user_id,
                attributed_role: shadow.attributed_role,
                created_at: shadow.created_at,
            }),
        )
            .into_response(),
        Err(e) => ApiError::internal_error(e.to_string()).into_response(),
    }
}

/// Validates the `platform_confidence` field value.
fn is_valid_confidence(value: &str) -> bool {
    matches!(value, "high" | "medium" | "low")
}

/// Handler for `POST /v1/scp/bridge/attest`.
///
/// Creates a platform identity attestation signed by the bridge operator.
/// The attestation asserts the platform's confidence in the mapping between
/// the platform handle and the user.
///
/// Requires bridge authentication via the `bridge_auth_middleware`.
///
/// See SCP-BCH-004 and spec section 12.10.
#[allow(clippy::significant_drop_tightening)] // false positive on async RwLock guard scope
async fn attest_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Json(body): Json<AttestRequest>,
) -> impl IntoResponse {
    if body.platform_handle.is_empty() {
        return invalid_request("platform_handle must not be empty").into_response();
    }
    if body.platform_user_id.is_empty() {
        return invalid_request("platform_user_id must not be empty").into_response();
    }
    if body.attestation_evidence.evidence_type.is_empty() {
        return invalid_request("attestation_evidence.evidence_type must not be empty")
            .into_response();
    }
    if body.attestation_evidence.verification_method.is_empty() {
        return invalid_request("attestation_evidence.verification_method must not be empty")
            .into_response();
    }
    if !is_valid_confidence(&body.attestation_evidence.platform_confidence) {
        return invalid_request(
            "attestation_evidence.platform_confidence must be \"high\", \"medium\", or \"low\"",
        )
        .into_response();
    }

    let bridge_id = auth_ctx.bridge_id();
    let attestation_id = derive_attestation_id(bridge_id, &body.platform_user_id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let stored = StoredAttestation {
        attestation_id: attestation_id.clone(),
        status: "active".to_owned(),
        bridge_id: bridge_id.to_owned(),
        platform_handle: body.platform_handle.clone(),
        platform_user_id: body.platform_user_id,
        evidence: body.attestation_evidence,
        issued_at: now,
        expires_at: now + ATTESTATION_TTL_SECS,
    };

    let response = AttestResponse {
        attestation_id: stored.attestation_id.clone(),
        status: stored.status.clone(),
        platform_handle: stored.platform_handle.clone(),
        issued_at: stored.issued_at,
        expires_at: stored.expires_at,
    };

    let mut attestations = bridge_state.attestations.write().await;
    attestations.insert(attestation_id, stored);

    (StatusCode::CREATED, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Message handler (SCP-BCH-003)
// ---------------------------------------------------------------------------

/// Finds a shadow identity inside the caller's authorized scope.
///
/// Reads only the registry for `context_id` and returns a shadow only when
/// `bridge_id` created it, so a caller authenticated for one bridge in one
/// context never observes a shadow belonging to another bridge or another
/// context. Spec §12.10.4 scopes the status roster the same way: "The
/// `shadows` array includes all shadow identities managed by this bridge in
/// this context."
///
/// Returning `None` for an out-of-scope shadow, rather than a distinct
/// rejection, keeps the endpoint from telling one bridge operator whether a
/// shadow ID exists somewhere else on the node.
fn find_scoped_shadow(
    registries: &HashMap<String, ShadowRegistry>,
    context_id: &str,
    bridge_id: &str,
    shadow_id: &str,
) -> Option<scp_core::bridge::ShadowIdentity> {
    registries
        .get(context_id)?
        .shadows()
        .iter()
        .find(|s| s.shadow_id == shadow_id && s.bridge_id == bridge_id)
        .cloned()
}

/// Handler for `POST /v1/scp/bridge/message`.
///
/// Emits a message on behalf of a shadow identity with full bridge
/// provenance. Returns 202 Accepted with message ID, sequence, and
/// provenance metadata.
///
/// The handler resolves `shadow_id` only inside the authenticated bridge's
/// context, so a bridge operator cannot emit a message as a shadow that belongs
/// to another bridge or another context. A request naming such a shadow gets
/// 404 `SHADOW_NOT_FOUND`.
///
/// See SCP-BCH-003 and spec section 12.10.4.
async fn emit_message_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Json(body): Json<EmitMessageRequest>,
) -> impl IntoResponse {
    if body.shadow_id.is_empty() {
        return invalid_request("shadow_id must not be empty").into_response();
    }
    if body.content.is_empty() {
        return invalid_request("content must not be empty").into_response();
    }
    if body.content_type.is_empty() {
        return invalid_request("content_type must not be empty").into_response();
    }
    // Spec §12.10.4 states this rejection message verbatim, and requires it
    // before envelope construction.
    if body.content.len() > MAX_MESSAGE_CONTENT_BYTES {
        return invalid_request(format!(
            "Content exceeds maximum size of {MAX_MESSAGE_CONTENT_BYTES} bytes"
        ))
        .into_response();
    }

    let context_id = auth_ctx.context_id().to_owned();
    let bridge_id = auth_ctx.bridge_id();

    let registries = bridge_state.registries.read().await;
    let deleted = bridge_state.deleted_shadows.read().await;

    // A shadow this bridge retired and a shadow this bridge never owned both
    // resolve to `None`, and both answer with one identical body, so a response
    // never tells a caller which of those two situations it hit.
    let retired = deleted.contains(&(
        context_id.clone(),
        bridge_id.to_owned(),
        body.shadow_id.clone(),
    ));
    let shadow_info = if retired {
        None
    } else {
        find_scoped_shadow(&registries, &context_id, bridge_id, &body.shadow_id)
    };
    drop(registries);
    drop(deleted);

    let Some(shadow) = shadow_info else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "shadow not found".to_owned(),
                code: "SHADOW_NOT_FOUND".to_owned(),
            }),
        )
            .into_response();
    };

    let shadow_status = match shadow.provenance_status {
        ShadowProvenanceStatus::Shadow => "Shadow",
        ShadowProvenanceStatus::Claimed => "Claimed",
    };

    let bridge_mode_str = match auth_ctx.bridge.mode {
        BridgeMode::Relay => "Relay",
        BridgeMode::Puppet => "Puppet",
        BridgeMode::Api => "Api",
        BridgeMode::Cooperative => "Cooperative",
    };

    let provenance_resp = BridgeProvenanceResponse {
        originating_platform: auth_ctx.bridge.platform.clone(),
        bridge_mode: bridge_mode_str.to_owned(),
        shadow_status: shadow_status.to_owned(),
        operator_did: auth_ctx.bridge.operator_did.0.clone(),
    };

    let mut sequences = bridge_state.message_sequence.write().await;
    let counter = sequences.entry(context_id).or_insert(0);
    *counter += 1;
    let sequence = *counter;
    drop(sequences);

    let message_id = format!("msg:{}:{sequence}", auth_ctx.bridge_id());

    let emitted = EmittedMessage {
        message_id: message_id.clone(),
        shadow_id: body.shadow_id,
        content: body.content,
        content_type: body.content_type,
        sequence,
        bridge_provenance: provenance_resp.clone(),
    };

    bridge_state.messages.write().await.push(emitted);

    (
        StatusCode::ACCEPTED,
        Json(EmitMessageResponse {
            message_id,
            sequence,
            bridge_provenance: provenance_resp,
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Status handler (SCP-BCH-005)
// ---------------------------------------------------------------------------

/// Handler for `GET /v1/scp/bridge/status`.
///
/// Returns bridge status and the shadow roster this bridge manages in its own
/// context. Spec §12.10.4 defines that roster as "all shadow identities managed
/// by this bridge in this context", so the handler reads the registry for the
/// authenticated context and keeps only shadows the authenticated bridge
/// created.
///
/// See SCP-BCH-005 and spec section 12.10.4.
#[allow(clippy::significant_drop_tightening)] // false positive on async RwLock guard scope
async fn status_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
) -> impl IntoResponse {
    let context_id = auth_ctx.context_id();
    let bridge_id = auth_ctx.bridge_id();

    let registries = bridge_state.registries.read().await;
    let deleted = bridge_state.deleted_shadows.read().await;

    let mut shadows = Vec::new();
    if let Some(registry) = registries.get(context_id) {
        for shadow in registry.shadows() {
            let out_of_scope = shadow.bridge_id != bridge_id;
            let removed = deleted.contains(&(
                context_id.to_owned(),
                bridge_id.to_owned(),
                shadow.shadow_id.clone(),
            ));
            if out_of_scope || removed {
                continue;
            }
            let status_str = match shadow.provenance_status {
                ShadowProvenanceStatus::Shadow => "Shadow",
                ShadowProvenanceStatus::Claimed => "Claimed",
            };
            shadows.push(ShadowSummary {
                shadow_id: shadow.shadow_id.clone(),
                platform_handle: shadow.platform_handle.clone(),
                attributed_role: shadow.attributed_role.clone(),
                provenance_status: status_str.to_owned(),
                created_at: shadow.created_at,
            });
        }
    }

    let bridge_mode_str = match auth_ctx.bridge.mode {
        BridgeMode::Relay => "Relay",
        BridgeMode::Puppet => "Puppet",
        BridgeMode::Api => "Api",
        BridgeMode::Cooperative => "Cooperative",
    };

    let status_str = match auth_ctx.bridge.status {
        scp_core::bridge::BridgeStatus::Active => "Active",
        scp_core::bridge::BridgeStatus::Suspended => "Suspended",
        scp_core::bridge::BridgeStatus::Revoked => "Revoked",
    };

    let shadow_count = shadows.len();

    let resp = BridgeStatusResponse {
        bridge_id: auth_ctx.bridge.bridge_id.clone(),
        status: status_str.to_owned(),
        platform: auth_ctx.bridge.platform.clone(),
        mode: bridge_mode_str.to_owned(),
        operator_did: auth_ctx.bridge.operator_did.0.clone(),
        registered_at: auth_ctx.bridge.registered_at,
        shadow_count,
        shadows,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

// ---------------------------------------------------------------------------
// Delete shadow handler (SCP-BCH-005)
// ---------------------------------------------------------------------------

/// Handler for `DELETE /v1/scp/bridge/shadow/{shadow_id}`.
///
/// Deletes a shadow identity the authenticated bridge created in its own
/// context. Historical actions remain in the event log. Returns 204 on success,
/// 404 if the authenticated bridge has no such shadow in its context, 409 if
/// the shadow is claimed. Deletion is idempotent (re-deleting returns 204).
///
/// A shadow belonging to another bridge or another context is out of the
/// caller's scope, so this handler answers 404 `SHADOW_NOT_FOUND` for it and
/// deletes nothing.
///
/// See SCP-BCH-005 and spec section 12.10.4.
async fn delete_shadow_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Path(shadow_id): Path<String>,
) -> impl IntoResponse {
    let context_id = auth_ctx.context_id().to_owned();
    let bridge_id = auth_ctx.bridge_id();

    let deleted = bridge_state.deleted_shadows.read().await;

    // Idempotent: a shadow this bridge already deleted in this context
    // returns 204. Matching on this bridge's own ID keeps a second bridge from
    // reading that 204 as proof that this bridge retired that shadow.
    if deleted.contains(&(context_id.clone(), bridge_id.to_owned(), shadow_id.clone())) {
        return StatusCode::NO_CONTENT.into_response();
    }
    drop(deleted);

    let registries = bridge_state.registries.read().await;
    let shadow_info = find_scoped_shadow(&registries, &context_id, bridge_id, &shadow_id);
    drop(registries);

    match shadow_info {
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "shadow not found".to_owned(),
                code: "SHADOW_NOT_FOUND".to_owned(),
            }),
        )
            .into_response(),
        Some(shadow) => {
            // Claimed shadows cannot be deleted.
            if shadow.provenance_status == ShadowProvenanceStatus::Claimed {
                return (
                    StatusCode::CONFLICT,
                    Json(ApiError {
                        error: "shadow has been claimed and cannot be deleted".to_owned(),
                        code: "SHADOW_ALREADY_CLAIMED".to_owned(),
                    }),
                )
                    .into_response();
            }

            bridge_state.deleted_shadows.write().await.insert((
                context_id,
                bridge_id.to_owned(),
                shadow_id,
            ));

            StatusCode::NO_CONTENT.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook handler (SCP-BCH-006)
// ---------------------------------------------------------------------------

/// Extracts the `shadow_id` field from a webhook event payload.
fn extract_shadow_id(payload: &serde_json::Value) -> &str {
    payload
        .get("shadow_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// Constructs a webhook rejection response (accepted: false).
fn webhook_reject(event_id: String, reason: &str) -> axum::response::Response {
    (
        StatusCode::OK,
        Json(WebhookResponse {
            accepted: false,
            event_id,
            reason: Some(reason.to_owned()),
        }),
    )
        .into_response()
}

/// Processes a single webhook event inside the signing platform's scope,
/// returning `Some(reason)` if the event should be rejected, or `None` if
/// processing succeeded.
///
/// `context_id` and `bridge_id` come from the verified
/// [`WebhookAuthContext`](crate::bridge_auth::WebhookAuthContext), never from
/// the request payload. Every shadow this function reads or deletes must belong
/// to that bridge in that context, and every outbound dispatch targets that
/// context, so a platform holding one registered webhook key cannot reach a
/// second platform's shadows.
///
/// On success, dispatches the event to any registered outbound webhook
/// targets via [`WebhookDispatcher`](crate::webhook::WebhookDispatcher).
async fn process_webhook_event(
    bridge_state: &BridgeState,
    context_id: &str,
    bridge_id: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> Option<String> {
    // `dispatch` records whether this event reached a shadow the signing
    // platform owns, which decides whether the node notifies outbound webhook
    // targets for the authenticated context.
    let mut dispatch = false;

    match event_type {
        "message" => {
            let shadow_id = extract_shadow_id(payload);
            if shadow_id.is_empty() {
                return Some("payload.shadow_id is required for message events".to_owned());
            }
            let registries = bridge_state.registries.read().await;
            let shadow_info = find_scoped_shadow(&registries, context_id, bridge_id, shadow_id);
            drop(registries);
            if shadow_info.is_none() {
                return Some("shadow not found".to_owned());
            }
            dispatch = true;
        }
        "identity_update" => {
            let shadow_id = extract_shadow_id(payload);
            if !shadow_id.is_empty() {
                let registries = bridge_state.registries.read().await;
                let shadow_info = find_scoped_shadow(&registries, context_id, bridge_id, shadow_id);
                drop(registries);
                if shadow_info.is_none() {
                    return Some("shadow not found for identity_update".to_owned());
                }
                dispatch = true;
            }
        }
        "user_departed" => {
            let shadow_id = extract_shadow_id(payload);
            if !shadow_id.is_empty() {
                // Confirm the shadow belongs to this bridge in this context
                // before deleting it.
                let registries = bridge_state.registries.read().await;
                let shadow_info = find_scoped_shadow(&registries, context_id, bridge_id, shadow_id);
                drop(registries);
                if shadow_info.is_none() {
                    return Some("shadow not found for user_departed".to_owned());
                }

                bridge_state.deleted_shadows.write().await.insert((
                    context_id.to_owned(),
                    bridge_id.to_owned(),
                    shadow_id.to_owned(),
                ));
                dispatch = true;
            }
        }
        // presence, message_edit, message_delete are accepted but
        // don't require specific state changes in the current impl.
        _ => {
            dispatch = true;
        }
    }

    // Dispatch outbound webhook for processed events, always to the
    // authenticated context.
    if dispatch {
        bridge_state
            .webhook_dispatcher
            .dispatch_event(context_id, event_type, payload.clone())
            .await;
    }

    None
}

/// Handler for `POST /v1/scp/bridge/webhook`.
///
/// Accepts platform-initiated events with deduplication by `event_id` within
/// the signing bridge. Supports event types: message, presence,
/// `identity_update`, `user_departed`, `message_edit`, `message_delete`.
///
/// The `WebhookAuthContext` extension names the bridge whose registered
/// platform key signed this request (spec §12.10.2), and the handler restricts
/// every lookup, deletion, and dispatch to that bridge's context.
///
/// See SCP-BCH-006 and spec section 12.10.4.
async fn webhook_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(webhook_ctx): Extension<crate::bridge_auth::WebhookAuthContext>,
    Json(body): Json<WebhookRequest>,
) -> impl IntoResponse {
    if !VALID_EVENT_TYPES.contains(&body.event_type.as_str()) {
        return webhook_reject(
            body.event_id,
            &format!("unknown event_type: {}", body.event_type),
        );
    }
    if body.event_id.is_empty() {
        return invalid_request("event_id must not be empty").into_response();
    }

    let context_id = webhook_ctx.context_id();
    let bridge_id = webhook_ctx.bridge_id();
    let dedup_key = (bridge_id.to_owned(), body.event_id.clone());

    // Deduplication: if this bridge already sent event_id, return accepted.
    {
        let processed = bridge_state.processed_event_ids.read().await;
        if processed.contains(&dedup_key) {
            return (
                StatusCode::OK,
                Json(WebhookResponse {
                    accepted: true,
                    event_id: body.event_id,
                    reason: None,
                }),
            )
                .into_response();
        }
    }

    if let Some(reason) = process_webhook_event(
        &bridge_state,
        context_id,
        bridge_id,
        &body.event_type,
        &body.payload,
    )
    .await
    {
        return webhook_reject(body.event_id, &reason);
    }

    {
        let mut processed = bridge_state.processed_event_ids.write().await;
        processed.insert(dedup_key);
        // Cap dedup set to prevent unbounded memory growth (BLACK-302).
        if processed.len() > MAX_PROCESSED_EVENT_IDS {
            // Evict approximately half the set. HashSet has no LRU, so
            // we drain arbitrarily — dedup is best-effort anyway.
            let to_remove: Vec<(String, String)> = processed
                .iter()
                .take(processed.len() / 2)
                .cloned()
                .collect();
            for id in to_remove {
                processed.remove(&id);
            }
        }
    }

    (
        StatusCode::OK,
        Json(WebhookResponse {
            accepted: true,
            event_id: body.event_id,
            reason: None,
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Returns an axum [`Router`] serving bridge endpoints.
///
/// The router expects [`BridgeState`] as shared state and
/// `BridgeAuthContext` as a request extension (injected by the bridge
/// auth middleware layer applied by the caller).
pub fn bridge_router(state: Arc<BridgeState>) -> Router {
    // `Router::layer` wraps whichever routes a router already holds and adds
    // nothing to a route registered after it, so this call follows all five
    // `route` calls. Applying it to `Router::new()` leaves axum's own 2 MiB
    // default governing every bridge route, and the doc comment on
    // `MAX_BRIDGE_BODY_BYTES` then describes a bound no request ever meets.
    Router::new()
        .route("/v1/scp/bridge/shadow", post(create_shadow_handler))
        .route(
            "/v1/scp/bridge/shadow/{shadow_id}",
            delete(delete_shadow_handler),
        )
        .route("/v1/scp/bridge/attest", post(attest_handler))
        .route("/v1/scp/bridge/message", post(emit_message_handler))
        .route("/v1/scp/bridge/status", get(status_handler))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BRIDGE_BODY_BYTES))
        .with_state(state)
}

/// Creates an axum [`Router`] for webhook-only bridge endpoints.
///
/// Separated from [`bridge_router`] because webhook callbacks from external
/// platforms authenticate via `X-SCP-Signature` headers (spec §12.10.2),
/// NOT the JWT Bearer auth used by other bridge endpoints. Applying
/// `bridge_auth_middleware_dyn` to the webhook route would reject all
/// legitimate platform webhook callbacks with 401.
pub fn bridge_webhook_router(state: Arc<BridgeState>) -> Router {
    // The layer follows the route for the reason `bridge_router` states.
    Router::new()
        .route("/v1/scp/bridge/webhook", post(webhook_handler))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BRIDGE_BODY_BYTES))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use scp_core::bridge::{BridgeConnector, BridgeMode, BridgeStatus};
    use tower::ServiceExt;

    use crate::bridge_auth::{BridgeAuthContext, BridgeJwtClaims};

    fn test_claims() -> BridgeJwtClaims {
        BridgeJwtClaims {
            iss: "did:dht:z6MkTestOperator".to_owned(),
            aud: "https://node.example.com".to_owned(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            scp_bridge_id: "bridge-test-001".to_owned(),
            scp_context_id: "ctx-test-001".to_owned(),
        }
    }

    fn test_auth_ctx() -> BridgeAuthContext {
        BridgeAuthContext {
            claims: test_claims(),
            bridge: BridgeConnector {
                bridge_id: "bridge-test-001".to_owned(),
                operator_did: scp_did::DID("did:dht:z6MkTestOperator".to_owned()),
                platform: "discord".to_owned(),
                mode: BridgeMode::Relay,
                status: BridgeStatus::Active,
                registration_context: "ctx-test-001".to_owned(),
                registered_at: 1_700_000_000,
                max_shadows: 10_000,
            },
        }
    }

    /// Builds a bridge auth context for an arbitrary bridge and context, so a
    /// test can drive two bridges against one `BridgeState` and check that
    /// neither reaches the other's shadows.
    fn auth_ctx_for(bridge_id: &str, context_id: &str) -> BridgeAuthContext {
        let mut ctx = test_auth_ctx();
        ctx.claims.scp_bridge_id = bridge_id.to_owned();
        ctx.claims.scp_context_id = context_id.to_owned();
        ctx.bridge.bridge_id = bridge_id.to_owned();
        ctx.bridge.registration_context = context_id.to_owned();
        ctx
    }

    /// Builds the router mirroring production routing topology for the given
    /// bridge and context.
    ///
    /// JWT-authenticated routes carry `BridgeAuthContext` via an extension
    /// layer, and the webhook route carries `WebhookAuthContext` via its own
    /// extension layer, bypassing the real auth middlewares for unit tests.
    /// Production installs the same two extensions from
    /// `bridge_auth_middleware_dyn` and `webhook_auth_middleware_dyn`.
    fn test_app_for(state: Arc<BridgeState>, bridge_id: &str, context_id: &str) -> Router {
        let auth_ctx = auth_ctx_for(bridge_id, context_id);
        let webhook_ctx = crate::bridge_auth::WebhookAuthContext {
            bridge: auth_ctx.bridge.clone(),
        };

        // JWT-authenticated bridge routes (mirrors `bridge_router`).
        let authed = Router::new()
            .route("/v1/scp/bridge/shadow", post(create_shadow_handler))
            .route(
                "/v1/scp/bridge/shadow/{shadow_id}",
                delete(delete_shadow_handler),
            )
            .route("/v1/scp/bridge/attest", post(attest_handler))
            .route("/v1/scp/bridge/message", post(emit_message_handler))
            .route("/v1/scp/bridge/status", get(status_handler))
            .layer(axum::Extension(auth_ctx))
            .with_state(Arc::clone(&state));

        // Webhook route — signature-authenticated in production, so it carries
        // `WebhookAuthContext` rather than `BridgeAuthContext`.
        let webhook = Router::new()
            .route("/v1/scp/bridge/webhook", post(webhook_handler))
            .layer(axum::Extension(webhook_ctx))
            .with_state(state);

        authed.merge(webhook)
    }

    /// Builds the router for the default test bridge in the default test
    /// context.
    fn test_app(state: Arc<BridgeState>) -> Router {
        test_app_for(state, "bridge-test-001", "ctx-test-001")
    }

    /// Builds the production [`bridge_router`] with the auth extension the
    /// middleware installs, so a test drives the routes an operator reaches
    /// rather than a hand-assembled copy of them.
    fn production_bridge_app(state: Arc<BridgeState>) -> Router {
        bridge_router(state).layer(axum::Extension(test_auth_ctx()))
    }

    /// Builds the production [`bridge_webhook_router`] with the webhook auth
    /// extension, for the reason [`production_bridge_app`] exists.
    fn production_webhook_app(state: Arc<BridgeState>) -> Router {
        let webhook_ctx = crate::bridge_auth::WebhookAuthContext {
            bridge: test_auth_ctx().bridge,
        };
        bridge_webhook_router(state).layer(axum::Extension(webhook_ctx))
    }

    /// Builds a request carrying `len` bytes of JSON string content.
    fn request_of_body_len(uri: &str, len: usize) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(vec![b'x'; len]))
            .expect("test")
    }

    // -----------------------------------------------------------------------
    // Request body limit (spec §12.10.4)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_body_over_the_bridge_limit_is_refused_before_a_handler_runs() {
        let state = Arc::new(BridgeState::new());
        let app = production_bridge_app(state);

        let req = request_of_body_len("/v1/scp/bridge/shadow", MAX_BRIDGE_BODY_BYTES + 1);

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "a body one byte over MAX_BRIDGE_BODY_BYTES must not reach a handler"
        );
    }

    #[tokio::test]
    async fn a_body_over_the_bridge_limit_is_refused_on_the_message_route() {
        let state = Arc::new(BridgeState::new());
        let app = production_bridge_app(state);

        let req = request_of_body_len("/v1/scp/bridge/message", MAX_BRIDGE_BODY_BYTES + 1);

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_body_over_the_bridge_limit_is_refused_on_the_webhook_route() {
        let state = Arc::new(BridgeState::new());
        let app = production_webhook_app(state);

        let req = request_of_body_len("/v1/scp/bridge/webhook", MAX_BRIDGE_BODY_BYTES + 1);

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_body_at_the_bridge_limit_reaches_the_handler() {
        let state = Arc::new(BridgeState::new());
        let app = production_bridge_app(state);

        let req = request_of_body_len("/v1/scp/bridge/shadow", MAX_BRIDGE_BODY_BYTES);

        let resp = app.oneshot(req).await.expect("test");
        // The body is not valid JSON, so axum's own `Json` extractor rejects
        // it. The assertion here is that the limit did not reject it first,
        // which is what distinguishes a correctly-placed layer from one that
        // rejects everything.
        assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // -----------------------------------------------------------------------
    // Governance-configured shadow limit (spec §12.2.1)
    // -----------------------------------------------------------------------

    /// Builds the default test router with `max_shadows` set to `limit`.
    fn test_app_with_shadow_limit(state: Arc<BridgeState>, limit: u32) -> Router {
        let mut auth_ctx = test_auth_ctx();
        auth_ctx.bridge.max_shadows = limit;
        let webhook_ctx = crate::bridge_auth::WebhookAuthContext {
            bridge: auth_ctx.bridge.clone(),
        };
        let authed = Router::new()
            .route("/v1/scp/bridge/shadow", post(create_shadow_handler))
            .route(
                "/v1/scp/bridge/shadow/{shadow_id}",
                delete(delete_shadow_handler),
            )
            .route("/v1/scp/bridge/message", post(emit_message_handler))
            .route("/v1/scp/bridge/status", get(status_handler))
            .layer(axum::Extension(auth_ctx))
            .with_state(Arc::clone(&state));
        let webhook = Router::new()
            .route("/v1/scp/bridge/webhook", post(webhook_handler))
            .layer(axum::Extension(webhook_ctx))
            .with_state(state);
        authed.merge(webhook)
    }

    fn create_shadow_request_for(platform_user_id: &str) -> Request<Body> {
        create_request(serde_json::json!({
            "platform_handle": format!("@{platform_user_id}"),
            "platform_user_id": platform_user_id,
        }))
    }

    #[tokio::test]
    async fn a_retired_shadow_stops_counting_against_the_governance_limit() {
        let state = Arc::new(BridgeState::new());

        let resp = test_app_with_shadow_limit(Arc::clone(&state), 1)
            .oneshot(create_shadow_request_for("user-one"))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = test_app_with_shadow_limit(Arc::clone(&state), 1)
            .oneshot(delete_shadow_request("shadow:bridge-test-001:user-one"))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // The bridge manages zero shadows now, so its one governance-granted
        // slot is free.
        let resp = test_app_with_shadow_limit(Arc::clone(&state), 1)
            .oneshot(create_shadow_request_for("user-two"))
            .await
            .expect("test");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a retired shadow must not hold a governance-granted slot"
        );
    }

    #[tokio::test]
    async fn a_live_shadow_still_exhausts_the_governance_limit() {
        let state = Arc::new(BridgeState::new());

        let resp = test_app_with_shadow_limit(Arc::clone(&state), 1)
            .oneshot(create_shadow_request_for("user-one"))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = test_app_with_shadow_limit(Arc::clone(&state), 1)
            .oneshot(create_shadow_request_for("user-two"))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(response_json(resp).await["code"], "BRIDGE_FORBIDDEN");
    }

    #[tokio::test]
    async fn re_creating_a_retired_shadow_returns_it_to_the_roster() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = "shadow:bridge-test-001:user-one";

        let resp = test_app(Arc::clone(&state))
            .oneshot(create_shadow_request_for("user-one"))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = test_app(Arc::clone(&state))
            .oneshot(delete_shadow_request(shadow_id))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let resp = test_app(Arc::clone(&state))
            .oneshot(status_request())
            .await
            .expect("test");
        assert_eq!(response_json(resp).await["shadow_count"], 0);

        // Re-creating the same platform user derives the same identifier, and
        // the 200 this returns must name a shadow the other endpoints see.
        let resp = test_app(Arc::clone(&state))
            .oneshot(create_shadow_request_for("user-one"))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_json(resp).await["shadow_id"], shadow_id);

        let resp = test_app(Arc::clone(&state))
            .oneshot(status_request())
            .await
            .expect("test");
        let json = response_json(resp).await;
        assert_eq!(
            json["shadow_count"], 1,
            "a re-created shadow must appear in the roster the status endpoint reports"
        );
        assert_eq!(json["shadows"][0]["shadow_id"], shadow_id);
    }

    fn create_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/scp/bridge/shadow")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("test")))
            .expect("test")
    }

    fn attest_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/scp/bridge/attest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("test")))
            .expect("test")
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.expect("test").to_bytes();
        serde_json::from_slice(&bytes).expect("test")
    }

    #[tokio::test]
    async fn successful_creation_returns_201() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = create_request(serde_json::json!({
            "platform_handle": "@alice#1234",
            "platform_user_id": "user-alice-001"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = response_json(resp).await;
        assert_eq!(json["platform_handle"], "@alice#1234");
        assert_eq!(json["platform_user_id"], "user-alice-001");
        assert_eq!(json["attributed_role"], "observer");
        assert_eq!(json["shadow_id"], "shadow:bridge-test-001:user-alice-001");
        assert!(json["created_at"].as_u64().is_some());
    }

    #[tokio::test]
    async fn idempotent_creation_returns_200() {
        let state = Arc::new(BridgeState::new());

        // First creation.
        let app = test_app(Arc::clone(&state));
        let req = create_request(serde_json::json!({
            "platform_handle": "@alice#1234",
            "platform_user_id": "user-alice-001"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Second creation with same platform_user_id — should return 200.
        let app = test_app(state);
        let req = create_request(serde_json::json!({
            "platform_handle": "@alice#1234",
            "platform_user_id": "user-alice-001"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["shadow_id"], "shadow:bridge-test-001:user-alice-001");
        assert_eq!(json["attributed_role"], "observer");
    }

    #[tokio::test]
    async fn missing_platform_handle_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = create_request(serde_json::json!({
            "platform_handle": "",
            "platform_user_id": "user-001"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_platform_user_id_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = create_request(serde_json::json!({
            "platform_handle": "@alice",
            "platform_user_id": ""
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_required_fields_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        // Body with no required fields at all.
        let req = create_request(serde_json::json!({}));

        let resp = app.oneshot(req).await.expect("test");
        // serde deserialization failure → 422 (axum default) or 400.
        // axum returns 422 for JSON deserialization errors by default.
        assert!(
            resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    // -----------------------------------------------------------------------
    // Attest endpoint tests
    // -----------------------------------------------------------------------

    fn valid_attest_body() -> serde_json::Value {
        serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "high",
                "additional_signals": {
                    "account_age_days": 730,
                    "email_verified": true
                }
            }
        })
    }

    #[tokio::test]
    async fn attest_successful_returns_201() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(valid_attest_body());
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = response_json(resp).await;
        assert_eq!(json["status"], "active");
        assert_eq!(json["platform_handle"], "@dave#1234");
        assert_eq!(json["attestation_id"], "attest:bridge-test-001:usr_abc123");
        assert!(json["issued_at"].as_u64().is_some());
        assert!(json["expires_at"].as_u64().is_some());

        let issued = json["issued_at"].as_u64().unwrap();
        let expires = json["expires_at"].as_u64().unwrap();
        assert_eq!(expires - issued, 86_400);
    }

    #[tokio::test]
    async fn attest_stores_attestation() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(Arc::clone(&state));

        let req = attest_request(valid_attest_body());
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let attestations = state.attestations.read().await;
        let stored = attestations
            .get("attest:bridge-test-001:usr_abc123")
            .expect("attestation should be stored");
        assert_eq!(stored.platform_handle, "@dave#1234");
        assert_eq!(stored.evidence.evidence_type, "platform-verified");
        assert_eq!(stored.evidence.platform_confidence, "high");
    }

    #[tokio::test]
    async fn attest_empty_handle_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "high"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_empty_user_id_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "high"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_invalid_confidence_returns_400() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_000_300,
                "platform_confidence": "very-high"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_missing_evidence_returns_422() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert!(
            resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn attest_without_additional_signals() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = attest_request(serde_json::json!({
            "platform_handle": "@dave#1234",
            "platform_user_id": "usr_abc123",
            "attestation_evidence": {
                "evidence_type": "oauth2",
                "verification_method": "oauth2-flow",
                "verified_at": 1_700_000_300,
                "platform_confidence": "medium"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let json = response_json(resp).await;
        assert_eq!(json["status"], "active");
    }

    // -----------------------------------------------------------------------
    // Message endpoint tests (SCP-BCH-003)
    // -----------------------------------------------------------------------

    fn message_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/scp/bridge/message")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("test")))
            .expect("test")
    }

    /// Creates a shadow in the state and returns its `shadow_id`.
    async fn create_test_shadow(state: &Arc<BridgeState>) -> String {
        let app = test_app(Arc::clone(state));
        let req = create_request(serde_json::json!({
            "platform_handle": "@emitter#1234",
            "platform_user_id": "user-emitter-001"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = response_json(resp).await;
        json["shadow_id"].as_str().expect("shadow_id").to_owned()
    }

    #[tokio::test]
    async fn emit_message_returns_202() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(Arc::clone(&state));
        let req = message_request(serde_json::json!({
            "shadow_id": shadow_id,
            "content": "Hello from bridge!",
            "content_type": "text/plain"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let json = response_json(resp).await;
        assert!(json["message_id"].as_str().is_some());
        assert_eq!(json["sequence"], 1);
        assert_eq!(json["bridge_provenance"]["originating_platform"], "discord");
        assert_eq!(json["bridge_provenance"]["bridge_mode"], "Relay");
        assert_eq!(json["bridge_provenance"]["shadow_status"], "Shadow");
        assert_eq!(
            json["bridge_provenance"]["operator_did"],
            "did:dht:z6MkTestOperator"
        );
    }

    #[tokio::test]
    async fn emit_message_shadow_not_found_returns_404() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = message_request(serde_json::json!({
            "shadow_id": "shadow:nonexistent",
            "content": "Hello",
            "content_type": "text/plain"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn emit_message_empty_content_returns_400() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(state);
        let req = message_request(serde_json::json!({
            "shadow_id": shadow_id,
            "content": "",
            "content_type": "text/plain"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Spec §12.10.4 caps `content` at 262,144 bytes and states a verbatim
    /// rejection message, and §12.10.3 pairs HTTP 400 with `INVALID_REQUEST`.
    #[tokio::test]
    async fn emit_message_over_the_content_limit_returns_invalid_request() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(state);
        let req = message_request(serde_json::json!({
            "shadow_id": shadow_id,
            "content": "x".repeat(MAX_MESSAGE_CONTENT_BYTES + 1),
            "content_type": "text/plain"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = response_json(resp).await;
        assert_eq!(body["code"], "INVALID_REQUEST");
        assert_eq!(
            body["error"],
            "Content exceeds maximum size of 262144 bytes"
        );
    }

    /// Content at exactly the §12.10.4 limit is accepted.
    #[tokio::test]
    async fn emit_message_at_the_content_limit_is_accepted() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(state);
        let req = message_request(serde_json::json!({
            "shadow_id": shadow_id,
            "content": "x".repeat(MAX_MESSAGE_CONTENT_BYTES),
            "content_type": "text/plain"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    /// Every bridge 400 carries §12.10.3's `INVALID_REQUEST` code, not the
    /// `BAD_REQUEST` code `ApiError::bad_request` produces.
    #[tokio::test]
    async fn a_malformed_bridge_request_carries_the_spec_error_code() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(state);
        let req = message_request(serde_json::json!({
            "shadow_id": shadow_id,
            "content": "",
            "content_type": "text/plain"
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(resp).await["code"], "INVALID_REQUEST");
    }

    // -----------------------------------------------------------------------
    // Status endpoint tests (SCP-BCH-005)
    // -----------------------------------------------------------------------

    fn status_request() -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/v1/scp/bridge/status")
            .body(Body::empty())
            .expect("test")
    }

    #[tokio::test]
    async fn status_returns_bridge_info() {
        let state = Arc::new(BridgeState::new());
        let _shadow_id = create_test_shadow(&state).await;

        let app = test_app(state);
        let req = status_request();

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["bridge_id"], "bridge-test-001");
        assert_eq!(json["status"], "Active");
        assert_eq!(json["platform"], "discord");
        assert_eq!(json["mode"], "Relay");
        assert_eq!(json["operator_did"], "did:dht:z6MkTestOperator");
        assert_eq!(json["shadow_count"], 1);
        assert_eq!(json["shadows"].as_array().map(std::vec::Vec::len), Some(1));
    }

    #[tokio::test]
    async fn status_empty_returns_zero_shadows() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = status_request();
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["shadow_count"], 0);
    }

    // -----------------------------------------------------------------------
    // Delete shadow endpoint tests (SCP-BCH-005)
    // -----------------------------------------------------------------------

    fn delete_shadow_request(shadow_id: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/scp/bridge/shadow/{shadow_id}"))
            .body(Body::empty())
            .expect("test")
    }

    #[tokio::test]
    async fn delete_shadow_returns_204() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(state);
        let req = delete_shadow_request(&shadow_id);

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_shadow_not_found_returns_404() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = delete_shadow_request("shadow:nonexistent");
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_shadow_idempotent_returns_204() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        // First delete.
        let app = test_app(Arc::clone(&state));
        let req = delete_shadow_request(&shadow_id);
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Second delete — idempotent.
        let app = test_app(state);
        let req = delete_shadow_request(&shadow_id);
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    // -----------------------------------------------------------------------
    // Webhook endpoint tests (SCP-BCH-006)
    // -----------------------------------------------------------------------

    fn webhook_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/scp/bridge/webhook")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("test")))
            .expect("test")
    }

    #[tokio::test]
    async fn webhook_message_event_accepted() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(state);
        let req = webhook_request(serde_json::json!({
            "event_type": "message",
            "event_id": "evt-001",
            "timestamp": 1_700_000_500,
            "payload": {
                "shadow_id": shadow_id,
                "content": "Hello from webhook"
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["accepted"], true);
        assert_eq!(json["event_id"], "evt-001");
    }

    #[tokio::test]
    async fn webhook_deduplication() {
        let state = Arc::new(BridgeState::new());

        let app = test_app(Arc::clone(&state));
        let req = webhook_request(serde_json::json!({
            "event_type": "presence",
            "event_id": "evt-dedup-001",
            "timestamp": 1_700_000_500,
            "payload": {}
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["accepted"], true);

        // Re-send same event_id — should be accepted without reprocessing.
        let app = test_app(state);
        let req = webhook_request(serde_json::json!({
            "event_type": "presence",
            "event_id": "evt-dedup-001",
            "timestamp": 1_700_000_600,
            "payload": {}
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["accepted"], true);
    }

    #[tokio::test]
    async fn webhook_unknown_event_type_rejected() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        let req = webhook_request(serde_json::json!({
            "event_type": "unknown_type",
            "event_id": "evt-002",
            "timestamp": 1_700_000_500,
            "payload": {}
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["accepted"], false);
        assert!(json["reason"].as_str().is_some());
    }

    #[tokio::test]
    async fn webhook_user_departed_triggers_shadow_deletion() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        let app = test_app(Arc::clone(&state));
        let req = webhook_request(serde_json::json!({
            "event_type": "user_departed",
            "event_id": "evt-depart-001",
            "timestamp": 1_700_000_500,
            "payload": {
                "shadow_id": shadow_id
            }
        }));

        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["accepted"], true);

        // Verify shadow was deleted in the authenticated context.
        let deleted = state.deleted_shadows.read().await;
        assert!(deleted.contains(&(
            "ctx-test-001".to_owned(),
            "bridge-test-001".to_owned(),
            shadow_id
        )));
    }

    #[tokio::test]
    async fn webhook_all_event_types_accepted() {
        let state = Arc::new(BridgeState::new());

        for (i, event_type) in [
            "message",
            "presence",
            "identity_update",
            "user_departed",
            "message_edit",
            "message_delete",
        ]
        .iter()
        .enumerate()
        {
            // For message event, we need a shadow; for others, just empty payload.
            let shadow_id = if *event_type == "message" {
                create_test_shadow(&state).await
            } else {
                String::new()
            };

            let payload = if *event_type == "message" {
                serde_json::json!({ "shadow_id": shadow_id, "content": "test" })
            } else {
                serde_json::json!({})
            };

            let app = test_app(Arc::clone(&state));
            let req = webhook_request(serde_json::json!({
                "event_type": event_type,
                "event_id": format!("evt-type-{i}"),
                "timestamp": 1_700_000_500,
                "payload": payload
            }));

            let resp = app.oneshot(req).await.expect("test");
            assert_eq!(resp.status(), StatusCode::OK);
            let json = response_json(resp).await;
            assert_eq!(
                json["accepted"], true,
                "event type '{event_type}' should be accepted"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Integration tests — full lifecycle (SCP-BCH-007)
    // -----------------------------------------------------------------------

    /// Full lifecycle integration test exercising:
    /// create shadow -> emit message -> attest identity -> check status
    /// -> webhook event -> delete shadow.
    #[tokio::test]
    async fn integration_full_lifecycle() {
        let state = Arc::new(BridgeState::new());

        // 1. Create shadow.
        let app = test_app(Arc::clone(&state));
        let req = create_request(serde_json::json!({
            "platform_handle": "@lifecycle-user#1234",
            "platform_user_id": "lifecycle-user-001"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let create_json = response_json(resp).await;
        let shadow_id = create_json["shadow_id"]
            .as_str()
            .expect("shadow_id")
            .to_owned();
        assert_eq!(create_json["attributed_role"], "observer");

        // 2. Emit message.
        let app = test_app(Arc::clone(&state));
        let req = message_request(serde_json::json!({
            "shadow_id": &shadow_id,
            "content": "Hello from lifecycle test!",
            "content_type": "text/plain",
            "platform_message_id": "ext-msg-001",
            "platform_timestamp": 1_700_001_000
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let msg_json = response_json(resp).await;
        assert!(msg_json["message_id"].as_str().is_some());
        assert_eq!(msg_json["sequence"], 1);
        // Verify provenance fields.
        assert_eq!(
            msg_json["bridge_provenance"]["originating_platform"],
            "discord"
        );
        assert_eq!(msg_json["bridge_provenance"]["bridge_mode"], "Relay");
        assert_eq!(
            msg_json["bridge_provenance"]["operator_did"],
            "did:dht:z6MkTestOperator"
        );
        assert_eq!(msg_json["bridge_provenance"]["shadow_status"], "Shadow");

        // 3. Attest identity.
        let app = test_app(Arc::clone(&state));
        let req = attest_request(serde_json::json!({
            "platform_handle": "@lifecycle-user#1234",
            "platform_user_id": "lifecycle-user-001",
            "attestation_evidence": {
                "evidence_type": "platform-verified",
                "verification_method": "oauth2",
                "verified_at": 1_700_001_200,
                "platform_confidence": "high"
            }
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // 4. Check status.
        let app = test_app(Arc::clone(&state));
        let req = status_request();
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        let status_json = response_json(resp).await;
        assert_eq!(status_json["bridge_id"], "bridge-test-001");
        assert_eq!(status_json["status"], "Active");
        assert_eq!(status_json["shadow_count"], 1);
        let shadows = status_json["shadows"].as_array().expect("shadows array");
        assert_eq!(shadows.len(), 1);
        assert_eq!(shadows[0]["shadow_id"], shadow_id);

        // 5. Webhook event (presence).
        let app = test_app(Arc::clone(&state));
        let req = webhook_request(serde_json::json!({
            "event_type": "presence",
            "event_id": "evt-lifecycle-001",
            "timestamp": 1_700_001_500,
            "payload": {}
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        let wh_json = response_json(resp).await;
        assert_eq!(wh_json["accepted"], true);

        // 6. Delete shadow.
        let app = test_app(Arc::clone(&state));
        let req = delete_shadow_request(&shadow_id);
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // 7. Verify shadow is deleted — status should show 0 shadows.
        let app = test_app(state);
        let req = status_request();
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        let status_after = response_json(resp).await;
        assert_eq!(status_after["shadow_count"], 0);
    }

    /// Verifies all endpoints return Content-Type: application/json.
    #[tokio::test]
    async fn all_endpoints_return_json_content_type() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        // POST /shadow
        let app = test_app(Arc::clone(&state));
        let req = create_request(serde_json::json!({
            "platform_handle": "@ct-user",
            "platform_user_id": "ct-user-001"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "POST /shadow must return application/json"
        );

        // POST /message
        let app = test_app(Arc::clone(&state));
        let req = message_request(serde_json::json!({
            "shadow_id": &shadow_id,
            "content": "content-type test",
            "content_type": "text/plain"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "POST /message must return application/json"
        );

        // GET /status
        let app = test_app(Arc::clone(&state));
        let req = status_request();
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "GET /status must return application/json"
        );

        // POST /attest
        let app = test_app(Arc::clone(&state));
        let req = attest_request(valid_attest_body());
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "POST /attest must return application/json"
        );

        // POST /webhook
        let app = test_app(Arc::clone(&state));
        let req = webhook_request(serde_json::json!({
            "event_type": "presence",
            "event_id": "ct-evt-001",
            "timestamp": 1_700_000_500,
            "payload": {}
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "POST /webhook must return application/json"
        );
    }

    /// Verifies error responses use the SCP error format (code + error fields).
    #[tokio::test]
    async fn error_responses_use_scp_format() {
        let state = Arc::new(BridgeState::new());
        let app = test_app(state);

        // 404 for nonexistent shadow on message endpoint.
        let req = message_request(serde_json::json!({
            "shadow_id": "shadow:nonexistent",
            "content": "test",
            "content_type": "text/plain"
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = response_json(resp).await;
        assert!(
            json["code"].as_str().is_some(),
            "error response must have code field"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error response must have error field"
        );
    }

    /// Verifies that deleting an unclaimed shadow succeeds and the
    /// delete handler correctly checks provenance status. The 409
    /// (`SHADOW_ALREADY_CLAIMED`) path is verified structurally: the
    /// handler checks `provenance_status == Claimed` and the claiming
    /// module has its own test coverage for status transitions.
    /// Here we verify the 204 (success) and 404 (not found) paths
    /// through the router.
    #[tokio::test]
    async fn delete_shadow_through_router() {
        let state = Arc::new(BridgeState::new());
        let shadow_id = create_test_shadow(&state).await;

        // Delete succeeds for unclaimed shadow.
        let app = test_app(Arc::clone(&state));
        let req = delete_shadow_request(&shadow_id);
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Nonexistent shadow returns 404 with SCP error format.
        let app = test_app(state);
        let req = delete_shadow_request("shadow:nonexistent:claimed");
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = response_json(resp).await;
        assert_eq!(json["code"], "SHADOW_NOT_FOUND");
    }

    /// Verifies the `bridge_router` function mounts all endpoints.
    #[tokio::test]
    async fn bridge_router_mounts_all_endpoints() {
        let state = Arc::new(BridgeState::new());
        let auth_ctx = test_auth_ctx();
        let router = bridge_router(state).layer(axum::Extension(auth_ctx));

        // POST /shadow
        let req = create_request(serde_json::json!({
            "platform_handle": "@router-test",
            "platform_user_id": "router-user-001"
        }));
        let resp = router.clone().oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // -----------------------------------------------------------------------
    // Authorized-scope tests
    //
    // A `BridgeAuthContext` authorizes one bridge instance inside one context
    // (spec §12.10.2), and §12.10.4 scopes the status roster to "all shadow
    // identities managed by this bridge in this context". Each test below
    // drives two bridges against one `BridgeState` and requires that neither
    // enumerates, deletes, or emits as the other's shadow. Reverting any
    // handler to an unscoped registry sweep fails the matching test.
    // -----------------------------------------------------------------------

    /// Creates a shadow as `bridge_id` in `context_id` and returns its
    /// `shadow_id`.
    async fn create_shadow_as(
        state: &Arc<BridgeState>,
        bridge_id: &str,
        context_id: &str,
        platform_user_id: &str,
    ) -> String {
        let app = test_app_for(Arc::clone(state), bridge_id, context_id);
        let req = create_request(serde_json::json!({
            "platform_handle": format!("@{platform_user_id}"),
            "platform_user_id": platform_user_id,
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = response_json(resp).await;
        json["shadow_id"].as_str().expect("shadow_id").to_owned()
    }

    /// Builds a state holding one shadow for bridge A in context A and one for
    /// bridge B in context B, returning both shadow IDs.
    async fn two_context_state() -> (Arc<BridgeState>, String, String) {
        let state = Arc::new(BridgeState::new());
        let shadow_a = create_shadow_as(&state, "bridge-a", "ctx-a", "user-a").await;
        let shadow_b = create_shadow_as(&state, "bridge-b", "ctx-b", "user-b").await;
        (state, shadow_a, shadow_b)
    }

    /// Builds a state holding one shadow for bridge A and one for bridge B,
    /// both inside the same context, returning both shadow IDs.
    async fn shared_context_state() -> (Arc<BridgeState>, String, String) {
        let state = Arc::new(BridgeState::new());
        let shadow_a = create_shadow_as(&state, "bridge-a", "ctx-shared", "user-a").await;
        let shadow_b = create_shadow_as(&state, "bridge-b", "ctx-shared", "user-b").await;
        (state, shadow_a, shadow_b)
    }

    /// Returns the `shadow_id` values a status response lists.
    fn roster_ids(json: &serde_json::Value) -> Vec<String> {
        json["shadows"]
            .as_array()
            .expect("shadows array")
            .iter()
            .map(|s| s["shadow_id"].as_str().expect("shadow_id").to_owned())
            .collect()
    }

    #[tokio::test]
    async fn status_roster_omits_shadows_in_another_context() {
        let (state, shadow_a, shadow_b) = two_context_state().await;

        let app = test_app_for(state, "bridge-a", "ctx-a");
        let resp = app.oneshot(status_request()).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["shadow_count"], 1);
        assert_eq!(roster_ids(&json), vec![shadow_a]);
        assert!(
            !roster_ids(&json).contains(&shadow_b),
            "bridge A must not enumerate a shadow living in context B"
        );
    }

    #[tokio::test]
    async fn status_roster_omits_another_bridge_in_the_same_context() {
        let (state, shadow_a, shadow_b) = shared_context_state().await;

        let app = test_app_for(state, "bridge-a", "ctx-shared");
        let resp = app.oneshot(status_request()).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["shadow_count"], 1);
        assert_eq!(roster_ids(&json), vec![shadow_a]);
        assert!(
            !roster_ids(&json).contains(&shadow_b),
            "spec section 12.10.4 scopes the roster to shadows this bridge manages"
        );
    }

    #[tokio::test]
    async fn emit_message_rejects_a_shadow_in_another_context() {
        let (state, _shadow_a, shadow_b) = two_context_state().await;

        let app = test_app_for(Arc::clone(&state), "bridge-a", "ctx-a");
        let req = message_request(serde_json::json!({
            "shadow_id": shadow_b,
            "content": "impersonation attempt",
            "content_type": "text/plain",
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let json = response_json(resp).await;
        assert_eq!(json["code"], "SHADOW_NOT_FOUND");
        assert!(
            state.messages.read().await.is_empty(),
            "a rejected emit must record no message"
        );
    }

    #[tokio::test]
    async fn emit_message_rejects_another_bridges_shadow_in_the_same_context() {
        let (state, _shadow_a, shadow_b) = shared_context_state().await;

        let app = test_app_for(Arc::clone(&state), "bridge-a", "ctx-shared");
        let req = message_request(serde_json::json!({
            "shadow_id": shadow_b,
            "content": "impersonation attempt",
            "content_type": "text/plain",
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(state.messages.read().await.is_empty());
    }

    #[tokio::test]
    async fn message_sequence_counts_each_context_separately() {
        let (state, shadow_a, shadow_b) = two_context_state().await;

        let app_a = test_app_for(Arc::clone(&state), "bridge-a", "ctx-a");
        let resp_a = app_a
            .oneshot(message_request(serde_json::json!({
                "shadow_id": shadow_a,
                "content": "first in context A",
                "content_type": "text/plain",
            })))
            .await
            .expect("test");
        assert_eq!(resp_a.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(resp_a).await["sequence"], 1);

        let app_b = test_app_for(Arc::clone(&state), "bridge-b", "ctx-b");
        let resp_b = app_b
            .oneshot(message_request(serde_json::json!({
                "shadow_id": shadow_b,
                "content": "first in context B",
                "content_type": "text/plain",
            })))
            .await
            .expect("test");
        assert_eq!(resp_b.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response_json(resp_b).await["sequence"],
            1,
            "context B counts its own messages, so its first message is sequence 1"
        );
    }

    #[tokio::test]
    async fn delete_shadow_rejects_a_shadow_in_another_context() {
        let (state, _shadow_a, shadow_b) = two_context_state().await;

        let app = test_app_for(Arc::clone(&state), "bridge-a", "ctx-a");
        let resp = app
            .oneshot(delete_shadow_request(&shadow_b))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        assert!(
            state.deleted_shadows.read().await.is_empty(),
            "a rejected delete must retire no shadow"
        );

        // Bridge B still sees its own shadow.
        let app_b = test_app_for(state, "bridge-b", "ctx-b");
        let status = app_b.oneshot(status_request()).await.expect("test");
        let json = response_json(status).await;
        assert_eq!(roster_ids(&json), vec![shadow_b]);
    }

    #[tokio::test]
    async fn delete_shadow_rejects_another_bridges_shadow_in_the_same_context() {
        let (state, _shadow_a, shadow_b) = shared_context_state().await;

        let app = test_app_for(Arc::clone(&state), "bridge-a", "ctx-shared");
        let resp = app
            .oneshot(delete_shadow_request(&shadow_b))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(state.deleted_shadows.read().await.is_empty());
    }

    #[tokio::test]
    async fn delete_idempotency_does_not_reveal_another_contexts_deletion() {
        let (state, shadow_a, _shadow_b) = two_context_state().await;

        // Bridge A retires its own shadow.
        let app_a = test_app_for(Arc::clone(&state), "bridge-a", "ctx-a");
        let resp = app_a
            .oneshot(delete_shadow_request(&shadow_a))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Bridge B naming that same shadow ID gets 404, not the 204 that would
        // tell it the ID was retired somewhere else on this node.
        let app_b = test_app_for(state, "bridge-b", "ctx-b");
        let resp = app_b
            .oneshot(delete_shadow_request(&shadow_a))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn webhook_user_departed_rejects_a_shadow_in_another_context() {
        let (state, _shadow_a, shadow_b) = two_context_state().await;

        let app = test_app_for(Arc::clone(&state), "bridge-a", "ctx-a");
        let req = webhook_request(serde_json::json!({
            "event_type": "user_departed",
            "event_id": "evt-cross-depart",
            "timestamp": 1_700_000_500,
            "payload": { "shadow_id": shadow_b },
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;
        assert_eq!(json["accepted"], false);
        assert!(
            state.deleted_shadows.read().await.is_empty(),
            "a webhook signed for bridge A must not retire a shadow in context B"
        );
    }

    #[tokio::test]
    async fn webhook_message_rejects_a_shadow_in_another_context() {
        let (state, _shadow_a, shadow_b) = two_context_state().await;

        let app = test_app_for(state, "bridge-a", "ctx-a");
        let req = webhook_request(serde_json::json!({
            "event_type": "message",
            "event_id": "evt-cross-message",
            "timestamp": 1_700_000_500,
            "payload": { "shadow_id": shadow_b },
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_json(resp).await["accepted"], false);
    }

    #[tokio::test]
    async fn webhook_ignores_a_context_id_supplied_in_the_payload() {
        let (state, shadow_a, _shadow_b) = two_context_state().await;

        // A `presence` event carries no shadow, and the payload names context B.
        // Dispatch must still target the authenticated context A.
        let app = test_app_for(Arc::clone(&state), "bridge-a", "ctx-a");
        let req = webhook_request(serde_json::json!({
            "event_type": "presence",
            "event_id": "evt-payload-context",
            "timestamp": 1_700_000_500,
            "payload": { "context_id": "ctx-b", "status": "online" },
        }));
        let resp = app.oneshot(req).await.expect("test");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_json(resp).await["accepted"], true);

        // Context A's own shadow is untouched, and nothing was retired.
        assert!(state.deleted_shadows.read().await.is_empty());
        let app_a = test_app_for(state, "bridge-a", "ctx-a");
        let status = app_a.oneshot(status_request()).await.expect("test");
        assert_eq!(roster_ids(&response_json(status).await), vec![shadow_a]);
    }

    #[tokio::test]
    async fn webhook_dedup_is_scoped_to_the_signing_bridge() {
        let (state, shadow_a, shadow_b) = two_context_state().await;

        // Bridge A sends event ID "evt-shared".
        let app_a = test_app_for(Arc::clone(&state), "bridge-a", "ctx-a");
        let resp = app_a
            .oneshot(webhook_request(serde_json::json!({
                "event_type": "message",
                "event_id": "evt-shared",
                "timestamp": 1_700_000_500,
                "payload": { "shadow_id": shadow_a },
            })))
            .await
            .expect("test");
        assert_eq!(response_json(resp).await["accepted"], true);

        // Bridge B reusing that event ID for its own shadow is processed, not
        // suppressed as a duplicate of bridge A's event.
        let app_b = test_app_for(Arc::clone(&state), "bridge-b", "ctx-b");
        let resp = app_b
            .oneshot(webhook_request(serde_json::json!({
                "event_type": "message",
                "event_id": "evt-shared",
                "timestamp": 1_700_000_500,
                "payload": { "shadow_id": shadow_b },
            })))
            .await
            .expect("test");
        assert_eq!(response_json(resp).await["accepted"], true);

        let processed = state.processed_event_ids.read().await;
        assert!(processed.contains(&("bridge-a".to_owned(), "evt-shared".to_owned())));
        assert!(processed.contains(&("bridge-b".to_owned(), "evt-shared".to_owned())));
    }

    #[tokio::test]
    async fn create_shadow_writes_into_the_authenticated_context_registry() {
        let state = Arc::new(BridgeState::new());
        let shadow_a = create_shadow_as(&state, "bridge-a", "ctx-a", "user-a").await;

        let registries = state.registries.read().await;
        assert_eq!(
            registries.keys().collect::<Vec<_>>(),
            vec!["ctx-a"],
            "creation writes only into the authenticated context's registry"
        );
        let shadows = registries.get("ctx-a").expect("registry").shadows();
        assert_eq!(shadows.len(), 1);
        assert_eq!(shadows[0].shadow_id, shadow_a);
        assert_eq!(shadows[0].bridge_id, "bridge-a");
    }

    #[tokio::test]
    async fn attest_keys_each_bridges_attestation_separately() {
        let state = Arc::new(BridgeState::new());

        for bridge_id in ["bridge-a", "bridge-b"] {
            let app = test_app_for(Arc::clone(&state), bridge_id, "ctx-shared");
            let resp = app
                .oneshot(attest_request(valid_attest_body()))
                .await
                .expect("test");
            assert_eq!(resp.status(), StatusCode::CREATED);
            let json = response_json(resp).await;
            assert_eq!(
                json["attestation_id"],
                format!("attest:{bridge_id}:usr_abc123")
            );
        }

        let attestations = state.attestations.read().await;
        assert_eq!(
            attestations.len(),
            2,
            "one bridge's attestation must not overwrite another's"
        );
    }

    // -----------------------------------------------------------------------
    // Composite-identifier injectivity and oracle tests
    //
    // A colon-joined composite ID built from two attacker-chosen segments is
    // not injective: bridge `acme:pro` with platform user `u1` and bridge
    // `acme` with platform user `pro:u1` both flatten to `acme:pro:u1`.
    // `escape_id_segment` removes every colon from each segment, so a colon in
    // a composite ID only ever separates segments.
    // -----------------------------------------------------------------------

    #[test]
    fn escaping_makes_a_composite_shadow_id_injective() {
        // A bridge ID carrying a colon and a platform user ID carrying that
        // same colon on its other side must not flatten to one string.
        assert_ne!(
            derive_shadow_id("acme:pro", "u1"),
            derive_shadow_id("acme", "pro:u1")
        );
        // A percent sign is escaped first, so a segment cannot spell an escape
        // sequence that reintroduces a colon.
        assert_ne!(
            derive_shadow_id("acme%3Apro", "u1"),
            derive_shadow_id("acme:pro", "u1")
        );
    }

    #[test]
    fn escaping_makes_a_composite_attestation_id_injective() {
        assert_ne!(
            derive_attestation_id("acme:pro", "u1"),
            derive_attestation_id("acme", "pro:u1")
        );
        assert_ne!(
            derive_attestation_id("acme%3Apro", "u1"),
            derive_attestation_id("acme:pro", "u1")
        );
    }

    #[tokio::test]
    async fn attest_cannot_overwrite_another_bridges_record_by_id_collision() {
        let state = Arc::new(BridgeState::new());

        // Bridge `acme` attests platform user `pro:u1` in its own context.
        let victim = test_app_for(Arc::clone(&state), "acme", "ctx-1");
        let mut body = valid_attest_body();
        body["platform_user_id"] = serde_json::json!("pro:u1");
        body["platform_handle"] = serde_json::json!("@honest");
        let resp = victim.oneshot(attest_request(body)).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let victim_id = response_json(resp).await["attestation_id"]
            .as_str()
            .expect("attestation_id")
            .to_owned();

        // Bridge `acme:pro` attests platform user `u1` in a second context.
        // Before escaping, both records keyed to `attest:acme:pro:u1`.
        let attacker = test_app_for(Arc::clone(&state), "acme:pro", "ctx-2");
        let mut body = valid_attest_body();
        body["platform_user_id"] = serde_json::json!("u1");
        body["platform_handle"] = serde_json::json!("@attacker");
        let resp = attacker.oneshot(attest_request(body)).await.expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let attacker_id = response_json(resp).await["attestation_id"]
            .as_str()
            .expect("attestation_id")
            .to_owned();

        assert_ne!(
            victim_id, attacker_id,
            "two bridges must not derive one attestation ID"
        );

        let attestations = state.attestations.read().await;
        assert_eq!(attestations.len(), 2);
        let victim_record = attestations.get(&victim_id).expect("victim record");
        assert_eq!(
            victim_record.platform_handle, "@honest",
            "a second bridge must not overwrite this record"
        );
        assert_eq!(victim_record.bridge_id, "acme");
    }

    #[tokio::test]
    async fn shadow_creation_cannot_squat_another_bridges_derived_id() {
        let state = Arc::new(BridgeState::new());

        // Bridge `acme:pro` creates platform user `u1` in a shared context.
        let first_bridge = test_app_for(Arc::clone(&state), "acme:pro", "ctx-1");
        let resp = first_bridge
            .oneshot(create_request(serde_json::json!({
                "platform_handle": "@squat",
                "platform_user_id": "u1",
            })))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let squatted = response_json(resp).await["shadow_id"]
            .as_str()
            .expect("shadow_id")
            .to_owned();

        // Bridge `acme` creating platform user `pro:u1` in that same context
        // derives a different ID, so it succeeds.
        let victim = test_app_for(Arc::clone(&state), "acme", "ctx-1");
        let resp = victim
            .oneshot(create_request(serde_json::json!({
                "platform_handle": "@honest",
                "platform_user_id": "pro:u1",
            })))
            .await
            .expect("test");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a second bridge must not be able to deny this bridge its own shadow ID"
        );
        let honest = response_json(resp).await["shadow_id"]
            .as_str()
            .expect("shadow_id")
            .to_owned();
        assert_ne!(squatted, honest);
    }

    #[tokio::test]
    async fn delete_idempotency_does_not_reveal_another_bridges_deletion() {
        let (state, shadow_a, _shadow_b) = shared_context_state().await;

        // Bridge A retires its own shadow inside a context bridge B shares.
        let app_a = test_app_for(Arc::clone(&state), "bridge-a", "ctx-shared");
        let resp = app_a
            .oneshot(delete_shadow_request(&shadow_a))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Bridge B probing that shadow ID gets 404, not the 204 that would
        // tell it bridge A retired that shadow.
        let app_b = test_app_for(Arc::clone(&state), "bridge-b", "ctx-shared");
        let resp = app_b
            .oneshot(delete_shadow_request(&shadow_a))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // A shadow ID nobody ever created answers identically.
        let app_b = test_app_for(state, "bridge-b", "ctx-shared");
        let resp = app_b
            .oneshot(delete_shadow_request("shadow:bridge-a:never"))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn emit_message_answers_identically_for_a_retired_and_an_unknown_shadow() {
        let (state, shadow_a, _shadow_b) = shared_context_state().await;

        let app_a = test_app_for(Arc::clone(&state), "bridge-a", "ctx-shared");
        let resp = app_a
            .oneshot(delete_shadow_request(&shadow_a))
            .await
            .expect("test");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Bridge A naming its own retired shadow.
        let app_a = test_app_for(Arc::clone(&state), "bridge-a", "ctx-shared");
        let retired = app_a
            .oneshot(message_request(serde_json::json!({
                "shadow_id": shadow_a,
                "content": "probe",
                "content_type": "text/plain",
            })))
            .await
            .expect("test");
        assert_eq!(retired.status(), StatusCode::NOT_FOUND);
        let retired_body = response_json(retired).await;

        // Bridge A naming a shadow that never existed.
        let app_a = test_app_for(state, "bridge-a", "ctx-shared");
        let unknown = app_a
            .oneshot(message_request(serde_json::json!({
                "shadow_id": "shadow:bridge-a:never",
                "content": "probe",
                "content_type": "text/plain",
            })))
            .await
            .expect("test");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        let unknown_body = response_json(unknown).await;

        assert_eq!(
            retired_body, unknown_body,
            "a retired shadow and an unknown shadow must answer identically, \
             so a response never confirms that a shadow once existed"
        );
    }
}
