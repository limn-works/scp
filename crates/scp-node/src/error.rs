//! Unified JSON error type for all scp-node HTTP endpoints.
//!
//! Both the dev API (section 18.10.4) and broadcast projection endpoints
//! return errors in the same `{ "error": "…", "code": "…" }` shape. This
//! module provides the single [`ApiError`] struct used by both.

use axum::Json;
use axum::http::StatusCode;
use serde::Serialize;

/// JSON error body returned by all scp-node HTTP endpoints.
///
/// The wire shape is specified in section 18.10.4 and reused by the
/// broadcast projection endpoints for consistency.
///
/// # Example
///
/// ```json
/// { "error": "unauthorized", "code": "UNAUTHORIZED" }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    /// Human-readable error description.
    pub error: String,
    /// Machine-readable error code.
    pub code: String,
}

impl ApiError {
    /// Returns the standard unauthorized error response (HTTP 401).
    pub(crate) fn unauthorized() -> (StatusCode, Json<Self>) {
        (
            StatusCode::UNAUTHORIZED,
            Json(Self {
                error: "unauthorized".to_owned(),
                code: "UNAUTHORIZED".to_owned(),
            }),
        )
    }

    /// Returns an unauthorized error response (HTTP 401) with a custom message.
    pub(crate) fn unauthorized_with(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::UNAUTHORIZED,
            Json(Self {
                error: msg.into(),
                code: "UNAUTHORIZED".to_owned(),
            }),
        )
    }

    /// Returns a not-found error response (HTTP 404) with the given message.
    pub(crate) fn not_found(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::NOT_FOUND,
            Json(Self {
                error: msg.into(),
                code: "NOT_FOUND".to_owned(),
            }),
        )
    }

    /// Returns a conflict error response (HTTP 409) with the given message.
    pub(crate) fn conflict(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::CONFLICT,
            Json(Self {
                error: msg.into(),
                code: "CONFLICT".to_owned(),
            }),
        )
    }

    /// Returns a bad-request error response (HTTP 400) with the given message.
    pub(crate) fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::BAD_REQUEST,
            Json(Self {
                error: msg.into(),
                code: "BAD_REQUEST".to_owned(),
            }),
        )
    }

    /// Returns a forbidden error response (HTTP 403) with the given message.
    pub(crate) fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::FORBIDDEN,
            Json(Self {
                error: msg.into(),
                code: "FORBIDDEN".to_owned(),
            }),
        )
    }

    /// Returns a gone error response (HTTP 410) with the given message.
    ///
    /// Used when content has been intentionally revoked (e.g., after a
    /// `Full`-scope governance ban purges old-epoch broadcast keys).
    pub(crate) fn gone(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::GONE,
            Json(Self {
                error: msg.into(),
                code: "GONE".to_owned(),
            }),
        )
    }

    /// Returns an internal server error response (HTTP 500) with the given message.
    pub(crate) fn internal_error(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Self {
                error: msg.into(),
                code: "INTERNAL_ERROR".to_owned(),
            }),
        )
    }
}
