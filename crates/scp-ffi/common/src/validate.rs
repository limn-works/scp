//! Shared input validation for FFI bridge boundaries.
//!
//! All FFI bridges (`PyO3`, napi-rs, `UniFFI`, WASM) validate string inputs before
//! passing them to scp-core. This module provides the shared validation
//! functions used across all bridge layers.
//!
//! # Design rationale
//!
//! Defense-in-depth: these validators catch malformed input at the FFI
//! boundary with clear, actionable error messages rather than allowing
//! invalid data to propagate into Rust internals where failures are harder
//! to diagnose.
//!
//! All validators are O(n) string scans with no allocations on the happy
//! path. They return `Result<(), ValidationError>` so callers can convert
//! to their bridge-specific error type via `From`/`Into`.
//!
//! See GitHub issue #104, #446, and ADR-013 sections 3-7 (bridge function
//! signatures).

use std::fmt;

// ---------------------------------------------------------------------------
// ValidationError — bridge-agnostic validation error
// ---------------------------------------------------------------------------

/// A validation error from the shared FFI input validation layer.
///
/// Each bridge converts this to its own error type:
/// - `PyO3`: `ScpPyError::ValidationError`
/// - NAPI: `ScpNapiError::Validation`
/// - `UniFFI`: `ScpError::Validation`
/// - WASM: `ScpWasmError::Validation`
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Human-readable error message describing what failed and why.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ValidationError {}

impl ValidationError {
    /// Creates a new validation error with the given message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length for a context ID (64 hex chars = 32 bytes).
pub const MAX_CONTEXT_ID_LEN: usize = 256;

/// Maximum length for a DID string. did:dht DIDs are typically ~60 chars;
/// allow generous headroom for other methods.
pub const MAX_DID_LEN: usize = 512;

/// Maximum length for a tool name.
pub const MAX_TOOL_NAME_LEN: usize = 256;

/// Maximum length for a tool ID (spec §5.4.1).
pub const MAX_TOOL_ID_LEN: usize = 128;

/// Maximum length for a capability URI string.
pub const MAX_CAPABILITY_URI_LEN: usize = 1024;

/// Maximum length for a UCAN token string (JWT format). UCAN tokens with
/// deep delegation chains can be large; 64 KiB is a generous upper bound.
pub const MAX_UCAN_TOKEN_LEN: usize = 65_536;

/// Maximum length for an MCP handle ID.
pub const MAX_MCP_HANDLE_LEN: usize = 256;

/// Maximum length for a relay URL.
pub const MAX_RELAY_URL_LEN: usize = 2048;

/// Maximum length for a transport mode string.
pub const MAX_TRANSPORT_MODE_LEN: usize = 64;

/// Maximum length for a deploy ID (matches `scp-core::context::broadcast_content::MAX_DEPLOY_ID_BYTES`).
pub const MAX_DEPLOY_ID_LEN: usize = 128;

/// Maximum length for an attestation platform string (e.g., "github.com").
pub const MAX_ATTESTATION_PLATFORM_LEN: usize = 256;

/// Maximum length for an attestation platform handle (e.g., "@alice").
pub const MAX_ATTESTATION_HANDLE_LEN: usize = 256;

/// Maximum length for an attestation proof JSON string.
pub const MAX_ATTESTATION_PROOF_LEN: usize = 65_536;

// ---------------------------------------------------------------------------
// String emptiness and length
// ---------------------------------------------------------------------------

/// Validates that a string is non-empty and within the given length limit.
fn validate_non_empty(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new(format!(
            "{field_name} must not be empty"
        )));
    }
    if value.len() > max_len {
        return Err(ValidationError::new(format!(
            "{field_name} exceeds maximum length ({} > {max_len} bytes)",
            value.len()
        )));
    }
    Ok(())
}

/// Validates that a string contains no control characters (U+0000..U+001F,
/// U+007F..U+009F). Control characters in identifiers can cause log injection,
/// display confusion, and format string issues.
fn reject_control_chars(value: &str, field_name: &str) -> Result<(), ValidationError> {
    if let Some(pos) = value.chars().position(char::is_control) {
        return Err(ValidationError::new(format!(
            "{field_name} contains control character at position {pos}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Context ID validation
// ---------------------------------------------------------------------------

/// Validates a context ID string.
///
/// Context IDs are 64-character hex strings (32 bytes, per section 18.4.1) when
/// generated by scp-core, but the bridge also accepts shorter IDs for
/// testing. Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_CONTEXT_ID_LEN`]
/// - Alphanumeric + hyphens + underscores only (hex chars plus test IDs)
/// - No control characters
///
/// # Errors
///
/// Returns [`ValidationError`] if the context ID is empty,
/// too long, contains control characters, or contains invalid characters.
pub fn validate_context_id(context_id: &str) -> Result<(), ValidationError> {
    validate_non_empty(context_id, "context_id", MAX_CONTEXT_ID_LEN)?;
    reject_control_chars(context_id, "context_id")?;

    if !context_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ValidationError::new(format!(
            "context_id contains invalid characters: expected alphanumeric, \
             hyphens, or underscores, got {context_id:?}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Deploy ID validation
// ---------------------------------------------------------------------------

/// Validates a deploy ID string.
///
/// Deploy IDs are 1-128 byte ASCII identifiers used by broadcast content
/// delivery (spec section 18.11.9). Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_DEPLOY_ID_LEN`] (128 bytes)
/// - ASCII alphanumeric + hyphens + underscores only
/// - No control characters
///
/// # Errors
///
/// Returns [`ValidationError`] if the deploy ID is empty, too long,
/// contains control characters, or contains invalid characters.
pub fn validate_deploy_id(deploy_id: &str) -> Result<(), ValidationError> {
    validate_non_empty(deploy_id, "deploy_id", MAX_DEPLOY_ID_LEN)?;
    reject_control_chars(deploy_id, "deploy_id")?;

    if !deploy_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ValidationError::new(format!(
            "deploy_id contains invalid characters: expected alphanumeric, \
             hyphens, or underscores, got {deploy_id:?}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DID string validation
// ---------------------------------------------------------------------------

/// Validates a DID string.
///
/// DIDs must match the `did:{method}:{id}` format per the W3C DID Core
/// specification. Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_DID_LEN`] (512 bytes)
/// - Starts with `did:`
/// - Contains at least two `:` separators (method + id)
/// - Method is non-empty lowercase alphanumeric
/// - No control characters
///
/// # Errors
///
/// Returns [`ValidationError`] if the DID is empty, exceeds 512 bytes,
/// missing the `did:` prefix, missing the method or ID, method is not
/// lowercase alphanumeric, or contains control characters.
pub fn validate_did(did: &str) -> Result<(), ValidationError> {
    validate_non_empty(did, "DID", MAX_DID_LEN)?;
    reject_control_chars(did, "DID")?;

    if !did.starts_with("did:") {
        return Err(ValidationError::new(format!(
            "DID must start with 'did:', got {did:?}"
        )));
    }

    // Must have at least `did:method:id` (two colons).
    let rest = &did[4..];
    if !rest.contains(':') {
        return Err(ValidationError::new(format!(
            "DID must match 'did:{{method}}:{{id}}' format, got {did:?}"
        )));
    }

    // Method must be non-empty and lowercase alphanumeric.
    let method = rest.split(':').next().unwrap_or("");
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(ValidationError::new(format!(
            "DID method must be non-empty lowercase alphanumeric, got {method:?} in {did:?}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tool name / ID validation
// ---------------------------------------------------------------------------

/// Validates a tool name string.
///
/// Tool names are human-readable identifiers used in tool registration.
/// Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_TOOL_NAME_LEN`]
/// - No control characters
/// - No characters that could cause issues in format strings (`{`, `}`)
///
/// # Errors
///
/// Returns [`ValidationError`] if the tool name is empty,
/// too long, contains control characters, or contains format string
/// characters.
pub fn validate_tool_name(name: &str) -> Result<(), ValidationError> {
    validate_non_empty(name, "tool name", MAX_TOOL_NAME_LEN)?;
    reject_control_chars(name, "tool name")?;

    if name.contains('{') || name.contains('}') {
        return Err(ValidationError::new(format!(
            "tool name must not contain '{{' or '}}' (format string risk), got {name:?}"
        )));
    }

    Ok(())
}

/// Validates a tool ID string.
///
/// Tool IDs are derived from tool names (e.g., `tool-my-tool`). Per spec
/// §5.4.1, tool IDs must contain only lowercase alphanumeric characters,
/// hyphens, and underscores (`[a-z0-9_-]`). Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_TOOL_ID_LEN`] (128 chars per §5.4.1)
/// - Characters restricted to `[a-z0-9_-]`
/// - No control characters
///
/// # Errors
///
/// Returns [`ValidationError`] if the tool ID is empty,
/// too long, contains control characters, or contains characters outside
/// the `[a-z0-9_-]` class.
pub fn validate_tool_id(tool_id: &str) -> Result<(), ValidationError> {
    validate_non_empty(tool_id, "tool_id", MAX_TOOL_ID_LEN)?;
    reject_control_chars(tool_id, "tool_id")?;

    if !tool_id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ValidationError::new(format!(
            "tool_id contains invalid characters: expected [a-z0-9_-], got {tool_id:?}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Capability URI validation
// ---------------------------------------------------------------------------

/// Validates a capability URI string.
///
/// Capability URIs follow one of these patterns:
/// - `scp:ctx:{context_id}/{action}` -- context-scoped capability
/// - Bare capability (e.g., `messages:write`) -- resolved against context
///
/// Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_CAPABILITY_URI_LEN`]
/// - No control characters
///
/// # Errors
///
/// Returns [`ValidationError`] if the capability URI is empty,
/// too long, or contains control characters.
pub fn validate_capability_uri(uri: &str) -> Result<(), ValidationError> {
    validate_non_empty(uri, "capability URI", MAX_CAPABILITY_URI_LEN)?;
    reject_control_chars(uri, "capability URI")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// UCAN token validation
// ---------------------------------------------------------------------------

/// Validates a UCAN token string (JWT format) at the boundary.
///
/// This is a lightweight structural check -- full JWT validation is handled
/// by scp-core's `parse_ucan`. The boundary check enforces:
/// - Non-empty
/// - Length <= [`MAX_UCAN_TOKEN_LEN`]
/// - No control characters other than those in the base64url alphabet
///
/// # Errors
///
/// Returns [`ValidationError`] if the token is empty, too long,
/// or contains control characters.
pub fn validate_ucan_token(token: &str) -> Result<(), ValidationError> {
    validate_non_empty(token, "UCAN token", MAX_UCAN_TOKEN_LEN)?;

    // JWT tokens should not contain newlines or other control chars
    // (base64url alphabet is [A-Za-z0-9_.-]).
    if token.chars().any(char::is_control) {
        return Err(ValidationError::new(
            "UCAN token contains control characters",
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// MCP handle validation
// ---------------------------------------------------------------------------

/// Validates an MCP server or client handle string.
///
/// Handles are opaque hex IDs generated by the bridge (e.g.,
/// `mcp-server-{hex}`). Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_MCP_HANDLE_LEN`]
/// - No control characters
///
/// # Errors
///
/// Returns [`ValidationError`] if the handle is empty, too
/// long, or contains control characters.
pub fn validate_mcp_handle(handle: &str) -> Result<(), ValidationError> {
    validate_non_empty(handle, "MCP handle", MAX_MCP_HANDLE_LEN)?;
    reject_control_chars(handle, "MCP handle")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Relay URL validation
// ---------------------------------------------------------------------------

/// Validates a relay URL string.
///
/// Relay URLs must be valid WebSocket or HTTP URLs. Validation enforces:
/// - Non-empty
/// - Length <= [`MAX_RELAY_URL_LEN`]
/// - No control characters (CRLF injection defense)
/// - Starts with a recognized scheme (`ws://`, `wss://`, `http://`, `https://`)
///
/// # Errors
///
/// Returns [`ValidationError`] if the URL is empty, too long,
/// contains control characters, or does not start with a valid scheme.
pub fn validate_relay_url(url: &str) -> Result<(), ValidationError> {
    validate_non_empty(url, "relay URL", MAX_RELAY_URL_LEN)?;
    reject_control_chars(url, "relay URL")?;

    let valid_scheme = url.starts_with("ws://")
        || url.starts_with("wss://")
        || url.starts_with("http://")
        || url.starts_with("https://");

    if !valid_scheme {
        return Err(ValidationError::new(format!(
            "relay URL must start with ws://, wss://, http://, or https://, got {url:?}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Transport mode validation
// ---------------------------------------------------------------------------

/// Validates a transport mode string.
///
/// Accepted values: `"stdio"`, `"sse"`.
///
/// # Errors
///
/// Returns [`ValidationError`] if the mode is empty or not one
/// of the accepted values.
pub fn validate_transport_mode(mode: &str) -> Result<(), ValidationError> {
    validate_non_empty(mode, "transport mode", MAX_TRANSPORT_MODE_LEN)?;

    match mode {
        "stdio" | "sse" => Ok(()),
        _ => Err(ValidationError::new(format!(
            "transport must be 'stdio' or 'sse', got {mode:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// JSON value type name
// ---------------------------------------------------------------------------

/// Returns a human-readable type name for a [`serde_json::Value`] variant.
///
/// Used in error messages when schema or test-vector validation encounters an
/// unexpected JSON type (e.g. "expected a JSON object, got array").
#[must_use]
pub const fn json_value_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// Attestation field validation
// ---------------------------------------------------------------------------

/// Validates the input fields for an identity link attestation creation.
///
/// Enforces size limits on `platform`, `handle`, and `proof` to prevent
/// unbounded input sizes in all FFI bridges. Limits are defined by
/// [`MAX_ATTESTATION_PLATFORM_LEN`], [`MAX_ATTESTATION_HANDLE_LEN`], and
/// [`MAX_ATTESTATION_PROOF_LEN`].
///
/// # Errors
///
/// Returns [`ValidationError`] if any field is empty or exceeds its limit.
pub fn validate_attestation_fields(
    platform: &str,
    handle: &str,
    proof: &str,
) -> Result<(), ValidationError> {
    validate_non_empty(platform, "platform", MAX_ATTESTATION_PLATFORM_LEN)?;
    reject_control_chars(platform, "platform")?;
    validate_non_empty(handle, "handle", MAX_ATTESTATION_HANDLE_LEN)?;
    reject_control_chars(handle, "handle")?;
    validate_non_empty(proof, "proof", MAX_ATTESTATION_PROOF_LEN)?;
    reject_control_chars(proof, "proof")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- Context ID --

    #[test]
    fn valid_hex_context_id() {
        let hex_id = "a".repeat(64);
        assert!(validate_context_id(&hex_id).is_ok());
    }

    #[test]
    fn valid_test_context_id_with_hyphens() {
        assert!(validate_context_id("ctx-test-123").is_ok());
    }

    #[test]
    fn empty_context_id_rejected() {
        let err = validate_context_id("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn context_id_with_control_chars_rejected() {
        let err = validate_context_id("abc\0def").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn context_id_with_special_chars_rejected() {
        let err = validate_context_id("abc/def").unwrap_err();
        assert!(err.message.contains("invalid characters"));
    }

    #[test]
    fn context_id_too_long_rejected() {
        let long_id = "a".repeat(MAX_CONTEXT_ID_LEN + 1);
        let err = validate_context_id(&long_id).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- Deploy ID --

    #[test]
    fn valid_deploy_id() {
        assert!(validate_deploy_id("deploy-abc-123").is_ok());
    }

    #[test]
    fn valid_deploy_id_with_underscores() {
        assert!(validate_deploy_id("deploy_v2_final").is_ok());
    }

    #[test]
    fn empty_deploy_id_rejected() {
        let err = validate_deploy_id("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn deploy_id_with_special_chars_rejected() {
        let err = validate_deploy_id("deploy/abc").unwrap_err();
        assert!(err.message.contains("invalid characters"));
    }

    #[test]
    fn deploy_id_with_control_chars_rejected() {
        let err = validate_deploy_id("deploy\0id").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn deploy_id_too_long_rejected() {
        let long_id = "a".repeat(MAX_DEPLOY_ID_LEN + 1);
        let err = validate_deploy_id(&long_id).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    #[test]
    fn deploy_id_at_max_length_accepted() {
        let id = "a".repeat(MAX_DEPLOY_ID_LEN);
        assert!(validate_deploy_id(&id).is_ok());
    }

    // -- DID --

    #[test]
    fn valid_did_dht() {
        assert!(validate_did("did:dht:z6Mkabcdef").is_ok());
    }

    #[test]
    fn valid_did_key() {
        assert!(validate_did("did:key:z6Mkabcdef").is_ok());
    }

    #[test]
    fn empty_did_rejected() {
        let err = validate_did("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn did_without_prefix_rejected() {
        let err = validate_did("not-a-did").unwrap_err();
        assert!(err.message.contains("must start with 'did:'"));
    }

    #[test]
    fn did_without_id_rejected() {
        let err = validate_did("did:dht").unwrap_err();
        assert!(err.message.contains("did:{method}:{id}"));
    }

    #[test]
    fn did_with_empty_method_rejected() {
        let err = validate_did("did::something").unwrap_err();
        assert!(err.message.contains("method must be non-empty"));
    }

    #[test]
    fn did_with_uppercase_method_rejected() {
        let err = validate_did("did:DHT:z6Mk").unwrap_err();
        assert!(err.message.contains("lowercase alphanumeric"));
    }

    #[test]
    fn did_too_long_rejected() {
        let long_did = format!("did:dht:{}", "a".repeat(MAX_DID_LEN));
        let err = validate_did(&long_did).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    #[test]
    fn did_with_control_chars_rejected() {
        let err = validate_did("did:dht:\nz6Mk").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    // -- Tool name --

    #[test]
    fn valid_tool_name() {
        assert!(validate_tool_name("my-tool").is_ok());
    }

    #[test]
    fn empty_tool_name_rejected() {
        let err = validate_tool_name("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn tool_name_with_braces_rejected() {
        let err = validate_tool_name("tool-{name}").unwrap_err();
        assert!(err.message.contains("format string risk"));
    }

    #[test]
    fn tool_name_too_long_rejected() {
        let long_name = "a".repeat(MAX_TOOL_NAME_LEN + 1);
        let err = validate_tool_name(&long_name).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- Tool ID --

    #[test]
    fn valid_tool_id() {
        assert!(validate_tool_id("tool-my-tool").is_ok());
    }

    #[test]
    fn valid_tool_id_with_underscores_and_digits() {
        assert!(validate_tool_id("my_tool_42").is_ok());
    }

    #[test]
    fn empty_tool_id_rejected() {
        let err = validate_tool_id("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn tool_id_with_uppercase_rejected() {
        let err = validate_tool_id("Tool-My-Tool").unwrap_err();
        assert!(err.message.contains("invalid characters"));
        assert!(err.message.contains("[a-z0-9_-]"));
    }

    #[test]
    fn tool_id_with_spaces_rejected() {
        let err = validate_tool_id("tool my tool").unwrap_err();
        assert!(err.message.contains("invalid characters"));
    }

    #[test]
    fn tool_id_with_special_chars_rejected() {
        let err = validate_tool_id("tool/my.tool").unwrap_err();
        assert!(err.message.contains("invalid characters"));
    }

    #[test]
    fn tool_id_too_long_rejected() {
        let long_id = "a".repeat(MAX_TOOL_ID_LEN + 1);
        let err = validate_tool_id(&long_id).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    #[test]
    fn tool_id_at_max_length_accepted() {
        let id = "a".repeat(MAX_TOOL_ID_LEN);
        assert!(validate_tool_id(&id).is_ok());
    }

    // -- Capability URI --

    #[test]
    fn valid_scoped_capability_uri() {
        assert!(validate_capability_uri("scp:ctx:abc123/messages:write").is_ok());
    }

    #[test]
    fn valid_bare_capability() {
        assert!(validate_capability_uri("messages:write").is_ok());
    }

    #[test]
    fn empty_capability_uri_rejected() {
        let err = validate_capability_uri("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    // -- UCAN token --

    #[test]
    fn valid_ucan_token() {
        assert!(
            validate_ucan_token("eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6ZGh0Ono2TWsifQ.sig").is_ok()
        );
    }

    #[test]
    fn empty_ucan_token_rejected() {
        let err = validate_ucan_token("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn ucan_token_with_newlines_rejected() {
        let err = validate_ucan_token("token\ninjection").unwrap_err();
        assert!(err.message.contains("control characters"));
    }

    #[test]
    fn ucan_token_too_long_rejected() {
        let long_token = "a".repeat(MAX_UCAN_TOKEN_LEN + 1);
        let err = validate_ucan_token(&long_token).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- MCP handle --

    #[test]
    fn valid_mcp_handle() {
        assert!(validate_mcp_handle("mcp-server-a1b2c3d4").is_ok());
    }

    #[test]
    fn empty_mcp_handle_rejected() {
        let err = validate_mcp_handle("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    // -- Relay URL --

    #[test]
    fn valid_ws_relay_url() {
        assert!(validate_relay_url("ws://127.0.0.1:9000/scp/v1").is_ok());
    }

    #[test]
    fn valid_wss_relay_url() {
        assert!(validate_relay_url("wss://relay.example.com/scp/v1").is_ok());
    }

    #[test]
    fn valid_http_relay_url() {
        assert!(validate_relay_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn empty_relay_url_rejected() {
        let err = validate_relay_url("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn relay_url_with_invalid_scheme_rejected() {
        let err = validate_relay_url("ftp://relay.example.com").unwrap_err();
        assert!(err.message.contains("must start with"));
    }

    #[test]
    fn relay_url_with_crlf_rejected() {
        let err = validate_relay_url("ws://relay.example.com\r\nHost: evil.com").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn relay_url_too_long_rejected() {
        let long_url = format!("ws://{}", "a".repeat(MAX_RELAY_URL_LEN));
        let err = validate_relay_url(&long_url).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- Transport mode --

    #[test]
    fn valid_transport_modes() {
        assert!(validate_transport_mode("stdio").is_ok());
        assert!(validate_transport_mode("sse").is_ok());
    }

    #[test]
    fn invalid_transport_mode_rejected() {
        let err = validate_transport_mode("grpc").unwrap_err();
        assert!(err.message.contains("'stdio' or 'sse'"));
    }

    #[test]
    fn empty_transport_mode_rejected() {
        let err = validate_transport_mode("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    // -- Attestation fields --

    #[test]
    fn valid_attestation_fields() {
        assert!(validate_attestation_fields("github.com", "@alice", r#"{"sig":"abc"}"#).is_ok());
    }

    #[test]
    fn attestation_empty_platform_rejected() {
        let err = validate_attestation_fields("", "@alice", "proof").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn attestation_empty_handle_rejected() {
        let err = validate_attestation_fields("github.com", "", "proof").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn attestation_empty_proof_rejected() {
        let err = validate_attestation_fields("github.com", "@alice", "").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn attestation_platform_control_chars_rejected() {
        let err = validate_attestation_fields("git\nhub.com", "@alice", "proof").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn attestation_handle_control_chars_rejected() {
        let err = validate_attestation_fields("github.com", "@al\0ice", "proof").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn attestation_proof_control_chars_rejected() {
        let err =
            validate_attestation_fields("github.com", "@alice", "proof\x1binject").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn attestation_platform_too_long_rejected() {
        let long = "a".repeat(MAX_ATTESTATION_PLATFORM_LEN + 1);
        let err = validate_attestation_fields(&long, "@alice", "proof").unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    #[test]
    fn attestation_handle_too_long_rejected() {
        let long = "a".repeat(MAX_ATTESTATION_HANDLE_LEN + 1);
        let err = validate_attestation_fields("github.com", &long, "proof").unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    #[test]
    fn attestation_proof_too_long_rejected() {
        let long = "a".repeat(MAX_ATTESTATION_PROOF_LEN + 1);
        let err = validate_attestation_fields("github.com", "@alice", &long).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- json_value_type_name --

    #[test]
    fn json_value_type_name_covers_all_variants() {
        assert_eq!(json_value_type_name(&serde_json::Value::Null), "null");
        assert_eq!(
            json_value_type_name(&serde_json::Value::Bool(true)),
            "boolean"
        );
        assert_eq!(json_value_type_name(&serde_json::json!(42)), "number");
        assert_eq!(json_value_type_name(&serde_json::json!("hello")), "string");
        assert_eq!(json_value_type_name(&serde_json::json!([1, 2])), "array");
        assert_eq!(json_value_type_name(&serde_json::json!({"a": 1})), "object");
    }
}
