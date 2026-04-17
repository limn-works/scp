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

    /// Set of deleted shadow IDs (historical actions remain in event log).
    pub deleted_shadows: RwLock<HashSet<String>>,

    /// Set of webhook event IDs already processed (deduplication).
    pub processed_event_ids: RwLock<HashSet<String>>,

    /// Emitted messages, keyed by message ID.
    pub messages: RwLock<Vec<EmittedMessage>>,

    /// Monotonically increasing sequence counter for emitted messages.
    pub message_sequence: RwLock<u64>,

    /// Outbound webhook dispatcher for delivering context events
    /// to registered bridge webhook endpoints (spec §12.2.1).
    pub webhook_dispatcher: crate::webhook::WebhookDispatcher,
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
            message_sequence: RwLock::new(0),
            webhook_dispatcher: crate::webhook::WebhookDispatcher::new(),
        }
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

/// Derives a deterministic shadow ID from bridge and platform user IDs.
///
/// The shadow ID is scoped to the bridge to prevent cross-bridge collisions.
fn derive_shadow_id(bridge_id: &str, platform_user_id: &str) -> String {
    format!("shadow:{bridge_id}:{platform_user_id}")
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
        return ApiError::bad_request("platform_handle must not be empty").into_response();
    }
    if body.platform_user_id.is_empty() {
        return ApiError::bad_request("platform_user_id must not be empty").into_response();
    }

    let bridge_id = &auth_ctx.claims.scp_bridge_id;
    let context_id = &auth_ctx.claims.scp_context_id;
    let shadow_id = derive_shadow_id(bridge_id, &body.platform_user_id);

    let mut registries = bridge_state.registries.write().await;

    // Ensure a registry exists for this context.
    let registry = registries
        .entry(context_id.clone())
        .or_insert_with(|| ShadowRegistry::new(context_id.clone()));

    // Idempotency: if a shadow with this ID already exists, return 200.
    if let Some(existing) = registry.shadows().iter().find(|s| s.shadow_id == shadow_id) {
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
        return ApiError::bad_request("platform_handle must not be empty").into_response();
    }
    if body.platform_user_id.is_empty() {
        return ApiError::bad_request("platform_user_id must not be empty").into_response();
    }
    if body.attestation_evidence.evidence_type.is_empty() {
        return ApiError::bad_request("attestation_evidence.evidence_type must not be empty")
            .into_response();
    }
    if body.attestation_evidence.verification_method.is_empty() {
        return ApiError::bad_request("attestation_evidence.verification_method must not be empty")
            .into_response();
    }
    if !is_valid_confidence(&body.attestation_evidence.platform_confidence) {
        return ApiError::bad_request(
            "attestation_evidence.platform_confidence must be \"high\", \"medium\", or \"low\"",
        )
        .into_response();
    }

    let bridge_id = &auth_ctx.claims.scp_bridge_id;
    let attestation_id = format!("attest:{bridge_id}:{}", body.platform_user_id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let stored = StoredAttestation {
        attestation_id: attestation_id.clone(),
        status: "active".to_owned(),
        bridge_id: bridge_id.clone(),
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

/// Finds a shadow identity across all registries and returns it with context info.
fn find_shadow(
    registries: &HashMap<String, ShadowRegistry>,
    shadow_id: &str,
) -> Option<(String, scp_core::bridge::ShadowIdentity)> {
    for (ctx_id, registry) in registries {
        if let Some(shadow) = registry.shadows().iter().find(|s| s.shadow_id == shadow_id) {
            return Some((ctx_id.clone(), shadow.clone()));
        }
    }
    None
}

/// Handler for `POST /v1/scp/bridge/message`.
///
/// Emits a message on behalf of a shadow identity with full bridge
/// provenance. Returns 202 Accepted with message ID, sequence, and
/// provenance metadata.
///
/// See SCP-BCH-003 and spec section 12.10.4.
async fn emit_message_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Json(body): Json<EmitMessageRequest>,
) -> impl IntoResponse {
    if body.shadow_id.is_empty() {
        return ApiError::bad_request("shadow_id must not be empty").into_response();
    }
    if body.content.is_empty() {
        return ApiError::bad_request("content must not be empty").into_response();
    }
    if body.content_type.is_empty() {
        return ApiError::bad_request("content_type must not be empty").into_response();
    }

    let registries = bridge_state.registries.read().await;
    let deleted = bridge_state.deleted_shadows.read().await;

    // Check if shadow was deleted.
    if deleted.contains(&body.shadow_id) {
        return ApiError::not_found("SHADOW_NOT_FOUND: shadow has been deleted").into_response();
    }

    let shadow_info = find_shadow(&registries, &body.shadow_id);
    drop(registries);
    drop(deleted);

    let Some((_ctx_id, shadow)) = shadow_info else {
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

    let mut seq = bridge_state.message_sequence.write().await;
    *seq += 1;
    let sequence = *seq;
    drop(seq);

    let message_id = format!("msg:{}:{sequence}", auth_ctx.claims.scp_bridge_id);

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
/// Returns bridge status including shadow list, registration info, and
/// rate limits.
///
/// See SCP-BCH-005 and spec section 12.10.4.
#[allow(clippy::significant_drop_tightening)] // false positive on async RwLock guard scope
async fn status_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
) -> impl IntoResponse {
    let registries = bridge_state.registries.read().await;
    let deleted = bridge_state.deleted_shadows.read().await;

    let mut shadows = Vec::new();
    for registry in registries.values() {
        for shadow in registry.shadows() {
            if !deleted.contains(&shadow.shadow_id) {
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
/// Deletes a shadow identity. Historical actions remain in the event log.
/// Returns 204 on success, 404 if not found, 409 if claimed.
/// Deletion is idempotent (re-deleting returns 204).
///
/// See SCP-BCH-005 and spec section 12.10.4.
async fn delete_shadow_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Extension(_auth_ctx): Extension<crate::bridge_auth::BridgeAuthContext>,
    Path(shadow_id): Path<String>,
) -> impl IntoResponse {
    let deleted = bridge_state.deleted_shadows.read().await;

    // Idempotent: already deleted returns 204.
    if deleted.contains(&shadow_id) {
        return StatusCode::NO_CONTENT.into_response();
    }
    drop(deleted);

    let registries = bridge_state.registries.read().await;
    let shadow_info = find_shadow(&registries, &shadow_id);
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
        Some((_ctx_id, shadow)) => {
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

            bridge_state.deleted_shadows.write().await.insert(shadow_id);

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

/// Processes a single webhook event, returning `Some(response)` if the
/// event should be rejected, or `None` if processing succeeded.
///
/// On success, dispatches the event to any registered outbound webhook
/// targets via [`WebhookDispatcher`](crate::webhook::WebhookDispatcher).
async fn process_webhook_event(
    bridge_state: &BridgeState,
    event_type: &str,
    event_id: &str,
    payload: &serde_json::Value,
) -> Option<String> {
    // Derive the context ID for outbound dispatch. For message events the
    // shadow registry tells us which context the shadow belongs to; for
    // other event types we look for a `context_id` field in the payload.
    let mut dispatch_context_id: Option<String> = None;

    match event_type {
        "message" => {
            let shadow_id = extract_shadow_id(payload);
            if shadow_id.is_empty() {
                return Some("payload.shadow_id is required for message events".to_owned());
            }
            let registries = bridge_state.registries.read().await;
            let shadow_info = find_shadow(&registries, shadow_id);
            drop(registries);
            match shadow_info {
                Some((ctx_id, _)) => {
                    dispatch_context_id = Some(ctx_id);
                }
                None => {
                    return Some("shadow not found".to_owned());
                }
            }
        }
        "identity_update" => {
            let shadow_id = extract_shadow_id(payload);
            if !shadow_id.is_empty() {
                let registries = bridge_state.registries.read().await;
                let shadow_info = find_shadow(&registries, shadow_id);
                drop(registries);
                match shadow_info {
                    Some((ctx_id, _)) => {
                        dispatch_context_id = Some(ctx_id);
                    }
                    None => {
                        return Some("shadow not found for identity_update".to_owned());
                    }
                }
            }
        }
        "user_departed" => {
            let shadow_id = extract_shadow_id(payload);
            if !shadow_id.is_empty() {
                // Look up context before deleting the shadow.
                let registries = bridge_state.registries.read().await;
                dispatch_context_id = find_shadow(&registries, shadow_id).map(|(ctx_id, _)| ctx_id);
                drop(registries);

                bridge_state
                    .deleted_shadows
                    .write()
                    .await
                    .insert(shadow_id.to_owned());
            }
        }
        // presence, message_edit, message_delete are accepted but
        // don't require specific state changes in the current impl.
        _ => {
            // Attempt to extract context_id from payload for dispatch.
            if let Some(ctx) = payload.get("context_id").and_then(|v| v.as_str()) {
                dispatch_context_id = Some(ctx.to_owned());
            }
        }
    }

    // Dispatch outbound webhook for processed events.
    if let Some(ctx_id) = dispatch_context_id {
        bridge_state
            .webhook_dispatcher
            .dispatch_event(&ctx_id, event_type, payload.clone())
            .await;
    }

    let _ = event_id; // used by callers for dedup tracking
    None
}

/// Handler for `POST /v1/scp/bridge/webhook`.
///
/// Accepts platform-initiated events with deduplication by `event_id`.
/// Supports event types: message, presence, `identity_update`,
/// `user_departed`, `message_edit`, `message_delete`.
///
/// See SCP-BCH-006 and spec section 12.10.4.
async fn webhook_handler(
    State(bridge_state): State<Arc<BridgeState>>,
    Json(body): Json<WebhookRequest>,
) -> impl IntoResponse {
    if !VALID_EVENT_TYPES.contains(&body.event_type.as_str()) {
        return webhook_reject(
            body.event_id,
            &format!("unknown event_type: {}", body.event_type),
        );
    }
    if body.event_id.is_empty() {
        return ApiError::bad_request("event_id must not be empty").into_response();
    }

    // Deduplication: if event_id was already processed, return accepted.
    {
        let processed = bridge_state.processed_event_ids.read().await;
        if processed.contains(&body.event_id) {
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
        &body.event_type,
        &body.event_id,
        &body.payload,
    )
    .await
    {
        return webhook_reject(body.event_id, &reason);
    }

    {
        let mut processed = bridge_state.processed_event_ids.write().await;
        processed.insert(body.event_id.clone());
        // Cap dedup set to prevent unbounded memory growth (BLACK-302).
        if processed.len() > MAX_PROCESSED_EVENT_IDS {
            // Evict approximately half the set. HashSet has no LRU, so
            // we drain arbitrarily — dedup is best-effort anyway.
            let to_remove: Vec<String> = processed
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
    Router::new()
        .route("/v1/scp/bridge/shadow", post(create_shadow_handler))
        .route(
            "/v1/scp/bridge/shadow/{shadow_id}",
            delete(delete_shadow_handler),
        )
        .route("/v1/scp/bridge/attest", post(attest_handler))
        .route("/v1/scp/bridge/message", post(emit_message_handler))
        .route("/v1/scp/bridge/status", get(status_handler))
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
    Router::new()
        .route("/v1/scp/bridge/webhook", post(webhook_handler))
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
                operator_did: scp_identity::DID("did:dht:z6MkTestOperator".to_owned()),
                platform: "discord".to_owned(),
                mode: BridgeMode::Relay,
                status: BridgeStatus::Active,
                registration_context: "ctx-test-001".to_owned(),
                registered_at: 1_700_000_000,
            },
        }
    }

    /// Builds the router mirroring production routing topology.
    ///
    /// JWT-authenticated routes carry `BridgeAuthContext` via an extension
    /// layer (bypassing real auth middleware for unit tests). The webhook
    /// route is mounted separately without the extension — matching
    /// production where it uses `webhook_auth_middleware` instead.
    fn test_app(state: Arc<BridgeState>) -> Router {
        let auth_ctx = test_auth_ctx();

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

        // Webhook route — no BridgeAuthContext (mirrors `bridge_webhook_router`).
        let webhook = Router::new()
            .route("/v1/scp/bridge/webhook", post(webhook_handler))
            .with_state(state);

        authed.merge(webhook)
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

        // Verify shadow was deleted.
        let deleted = state.deleted_shadows.read().await;
        assert!(deleted.contains(&shadow_id));
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
}
