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

/// Maximum number of identity link attestations per DID (spec §3.5.3).
///
/// Unified across the DID document layer (`scp-identity`) and all FFI bridge
/// attestation stores. A single constant ensures consistent enforcement
/// everywhere — no divergent limits.
pub const MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID: usize = 64;

/// Maximum length for a role name (spec §5.9).
pub const MAX_ROLE_NAME_LEN: usize = 256;

/// Maximum length for a context name (spec §5.9).
pub const MAX_CONTEXT_NAME_LEN: usize = 256;

/// Maximum length for a context description (spec §5.9).
pub const MAX_CONTEXT_DESCRIPTION_LEN: usize = 4096;

/// Maximum length for a governance action reason/purpose field.
pub const MAX_GOVERNANCE_REASON_LEN: usize = 4096;

/// Maximum length for a payment adapter reference (spec §19.1).
pub const MAX_PAYMENT_ADAPTER_REF_LEN: usize = 256;

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

/// HTML-special characters that could enable injection when string fields
/// are serialized for SDK consumers or rendered in UIs.
const HTML_SPECIAL_CHARS: [char; 5] = ['<', '>', '&', '"', '\''];

/// Rejects strings containing HTML-special characters (`<`, `>`, `&`, `"`, `'`).
/// These characters create injection vectors when user-controlled fields are
/// serialized into JSON for SDK consumers or rendered in downstream UIs.
fn reject_html_special_chars(value: &str, field_name: &str) -> Result<(), ValidationError> {
    if let Some((pos, ch)) = value
        .chars()
        .enumerate()
        .find(|(_, c)| HTML_SPECIAL_CHARS.contains(c))
    {
        return Err(ValidationError::new(format!(
            "{field_name} contains HTML-special character U+{:04X} at position {pos}",
            ch as u32
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
    reject_html_special_chars(name, "tool name")?;

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
    reject_html_special_chars(uri, "capability URI")?;
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
    // (base64url alphabet is [A-Za-z0-9_.-]).  Use the shared helper for
    // consistent error message format (includes position info).
    reject_control_chars(token, "UCAN token")?;
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
// User-controlled string validation (§9.1A, #1601)
// ---------------------------------------------------------------------------

/// Validates a user-controlled string field: non-empty, within length limit,
/// no control characters (U+0000–U+001F, U+007F–U+009F), no HTML-special
/// characters (`<`, `>`, `&`, `"`, `'`).
fn validate_user_string(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), ValidationError> {
    validate_non_empty(value, field_name, max_len)?;
    reject_control_chars(value, field_name)?;
    reject_html_special_chars(value, field_name)?;
    Ok(())
}

/// Validates a role name (governance actions, role definitions). Max 256 bytes.
///
/// # Errors
///
/// Returns [`ValidationError`] per [`validate_user_string`] rules.
pub fn validate_role_name(role: &str) -> Result<(), ValidationError> {
    validate_user_string(role, "role name", MAX_ROLE_NAME_LEN)
}

/// Validates a context name (context metadata). Max 256 bytes.
///
/// # Errors
///
/// Returns [`ValidationError`] per [`validate_user_string`] rules.
pub fn validate_context_name(name: &str) -> Result<(), ValidationError> {
    validate_user_string(name, "context name", MAX_CONTEXT_NAME_LEN)
}

/// Validates a context description (context metadata). Max 4096 bytes.
///
/// # Errors
///
/// Returns [`ValidationError`] per [`validate_user_string`] rules.
pub fn validate_context_description(description: &str) -> Result<(), ValidationError> {
    validate_user_string(
        description,
        "context description",
        MAX_CONTEXT_DESCRIPTION_LEN,
    )
}

/// Validates a governance action reason or purpose string. Max 4096 bytes.
///
/// Rejects empty strings, whitespace-only strings (audit-evasion defense),
/// control characters, HTML-special characters, and strings exceeding the
/// length limit.
///
/// # Errors
///
/// Returns [`ValidationError`] per [`validate_user_string`] rules, plus
/// an additional check that the string is not whitespace-only.
pub fn validate_governance_reason(reason: &str) -> Result<(), ValidationError> {
    validate_user_string(reason, "governance reason", MAX_GOVERNANCE_REASON_LEN)?;
    if !has_visible_content(reason) {
        return Err(ValidationError::new(
            "governance reason must contain visible content".to_string(),
        ));
    }
    Ok(())
}

/// Returns `true` if `s` contains at least one character that is neither
/// whitespace nor a zero-width / invisible format character.
fn has_visible_content(s: &str) -> bool {
    s.chars().any(|c| {
        !c.is_whitespace()
            && !matches!(
                c,
                '\u{00AD}'
                    | '\u{034F}'
                    | '\u{061C}'
                    | '\u{180E}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{2028}'..='\u{2029}'
                    | '\u{2060}'..='\u{2064}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{FEFF}'
            )
    })
}

/// Validates a payment adapter reference (§19.1). Max 256 bytes.
///
/// # Errors
///
/// Returns [`ValidationError`] per [`validate_user_string`] rules.
pub fn validate_payment_adapter_ref(adapter_ref: &str) -> Result<(), ValidationError> {
    validate_user_string(
        adapter_ref,
        "payment adapter ref",
        MAX_PAYMENT_ADAPTER_REF_LEN,
    )
}

// ---------------------------------------------------------------------------
// Governance action string validation (#1601)
// ---------------------------------------------------------------------------

/// Validates all user-controlled string fields on a [`GovernanceAction`].
///
/// Called from all FFI bridge `governance_propose` functions after JSON
/// deserialization and before passing the action to the `ContextManager`.
///
/// Covers role names, reason/purpose text, payment adapter refs, and
/// nested string fields inside `ContextParams` and `ToolRegistration`.
///
/// # Errors
///
/// Returns [`ValidationError`] if any string field contains control
/// characters, HTML-special characters, or exceeds its maximum length.
pub fn validate_governance_action_strings(
    action: &scp_protocol::context::governance::GovernanceAction,
) -> Result<(), ValidationError> {
    use scp_protocol::context::governance::GovernanceAction;

    match action {
        GovernanceAction::AddMember { role, .. } => {
            validate_role_name(role)?;
        }
        GovernanceAction::ChangeRole { new_role, .. } => {
            validate_role_name(new_role)?;
        }
        GovernanceAction::RemoveMember {
            reason: Some(r), ..
        }
        | GovernanceAction::CloseContext {
            reason: Some(r), ..
        }
        | GovernanceAction::RotateContentKeys {
            reason: Some(r), ..
        } => {
            if !r.is_empty() {
                validate_governance_reason(r)?;
            }
        }
        GovernanceAction::ResetMember { reason, .. } => {
            validate_governance_reason(reason)?;
        }
        GovernanceAction::ProposeContextMigration {
            reason,
            new_context_params,
            ..
        } => {
            validate_governance_reason(reason)?;
            validate_context_params_strings(new_context_params)?;
        }
        GovernanceAction::ApproveSpend { purpose, .. } => {
            validate_governance_reason(purpose)?;
        }
        GovernanceAction::SetEconomicPolicy { policy } => {
            validate_economic_policy_strings(policy)?;
        }
        GovernanceAction::RegisterTool { registration } => {
            validate_tool_name(&registration.name)?;
            validate_governance_reason(&registration.description)?;
        }
        GovernanceAction::CreateChildContext { params } => {
            validate_context_params_strings(params)?;
        }
        // Variants without user-controlled string fields.
        GovernanceAction::RemoveMember { reason: None, .. }
        | GovernanceAction::CloseContext { reason: None, .. }
        | GovernanceAction::RotateContentKeys { reason: None, .. }
        | GovernanceAction::RemoveTool { .. }
        | GovernanceAction::ModifyCeiling { .. }
        | GovernanceAction::ExtendTtl { .. }
        | GovernanceAction::TransferAdmin { .. }
        | GovernanceAction::RevokeAccess { .. }
        | GovernanceAction::RestoreAccess { .. }
        | GovernanceAction::ModifyPruningPolicy { .. }
        | GovernanceAction::AddSigner { .. }
        | GovernanceAction::RemoveSigner { .. }
        | GovernanceAction::ModifyThreshold { .. }
        | GovernanceAction::EstablishToolInterface { .. }
        | GovernanceAction::ResolveConflict { .. }
        | GovernanceAction::PromoteContext
        | GovernanceAction::SuspendCapability { .. }
        | GovernanceAction::SuspendAccess { .. }
        | GovernanceAction::ReconfigureGovernance { .. }
        | GovernanceAction::LockEconomicPolicy
        | GovernanceAction::ModifyHardRateLimit { .. }
        | GovernanceAction::CancelContextMigration => {}
    }
    Ok(())
}

/// Validates string fields inside an [`EconomicPolicy`].
fn validate_economic_policy_strings(
    policy: &scp_protocol::economy::types::EconomicPolicy,
) -> Result<(), ValidationError> {
    for adapter in &policy.payment_adapters {
        validate_payment_adapter_ref(adapter)?;
    }
    Ok(())
}

/// Validates user-controlled string fields inside a [`ContextParams`].
///
/// Checks role names in role definitions and payment adapter refs in
/// economic policy. Tool registration names/descriptions are also validated.
fn validate_context_params_strings(
    params: &scp_protocol::context::params::ContextParams,
) -> Result<(), ValidationError> {
    for role_def in &params.roles {
        validate_role_name(&role_def.name)?;
    }
    for tool_reg in &params.tools {
        validate_tool_name(&tool_reg.name)?;
        validate_governance_reason(&tool_reg.description)?;
    }
    if let Some(policy) = &params.economic_policy {
        validate_economic_policy_strings(policy)?;
    }
    Ok(())
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
    reject_html_special_chars(platform, "platform")?;
    validate_non_empty(handle, "handle", MAX_ATTESTATION_HANDLE_LEN)?;
    reject_control_chars(handle, "handle")?;
    reject_html_special_chars(handle, "handle")?;
    validate_non_empty(proof, "proof", MAX_ATTESTATION_PROOF_LEN)?;
    reject_control_chars(proof, "proof")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixed-length byte narrowing
// ---------------------------------------------------------------------------

/// Narrows a byte slice to a fixed-length `[u8; N]` array, returning a
/// human-readable message on length mismatch.
///
/// All four FFI bridges narrow caller-supplied `Vec<u8>` / `Buffer` /
/// `Uint8Array` parameters to fixed-length arrays (most commonly the
/// 32-byte `testing_seed`). This helper centralizes the `TryFrom` +
/// length-mismatch-message pattern so bridges agree on wording — each
/// bridge wraps the returned `String` in its own error type with the
/// appropriate `SCP-VALID-XXXX` code.
///
/// # Errors
///
/// Returns `Err` with a message of the form `"{field} must be exactly
/// {N} bytes, got {actual}"` when `bytes.len() != N`.
pub fn expect_fixed_bytes<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], String> {
    <[u8; N]>::try_from(bytes)
        .map_err(|_| format!("{field} must be exactly {N} bytes, got {}", bytes.len()))
}

/// Narrows a byte slice to a zeroize-wrapped `Zeroizing<[u8; N]>`.
///
/// Same contract as [`expect_fixed_bytes`], but the returned array is
/// wrapped in `zeroize::Zeroizing` so it is overwritten when dropped.
/// Use for private-key material (sender keys, bridge credential keys,
/// any 32-byte Ed25519/X25519 seed): the common shape is `raw Vec<u8>
/// → narrow → Zeroizing<[u8; 32]>` and this helper eliminates the
/// repeated `Zeroizing::new(expect_fixed_bytes::<32>(...))` dance.
///
/// # Errors
///
/// Same as [`expect_fixed_bytes`] — length-mismatch string.
pub fn expect_fixed_bytes_zeroized<const N: usize>(
    bytes: &[u8],
    field: &str,
) -> Result<zeroize::Zeroizing<[u8; N]>, String> {
    expect_fixed_bytes::<N>(bytes, field).map(zeroize::Zeroizing::new)
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
        assert!(err.message.contains("control character"));
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

    // -- Role name --

    #[test]
    fn valid_role_name() {
        assert!(validate_role_name("admin").is_ok());
    }

    #[test]
    fn role_name_with_html_rejected() {
        let err = validate_role_name("<script>admin").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    #[test]
    fn role_name_with_control_chars_rejected() {
        let err = validate_role_name("admin\0").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn role_name_too_long_rejected() {
        let long = "a".repeat(MAX_ROLE_NAME_LEN + 1);
        let err = validate_role_name(&long).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    #[test]
    fn empty_role_name_rejected() {
        let err = validate_role_name("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    // -- Context name --

    #[test]
    fn valid_context_name() {
        assert!(validate_context_name("My Context").is_ok());
    }

    #[test]
    fn context_name_with_html_rejected() {
        let err = validate_context_name("<b>My Context</b>").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    #[test]
    fn context_name_with_control_chars_rejected() {
        let err = validate_context_name("My\nContext").unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn context_name_too_long_rejected() {
        let long = "a".repeat(MAX_CONTEXT_NAME_LEN + 1);
        let err = validate_context_name(&long).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- Context description --

    #[test]
    fn valid_context_description() {
        assert!(validate_context_description("A context for collaboration").is_ok());
    }

    #[test]
    fn context_description_with_html_rejected() {
        let err = validate_context_description("test &amp; things").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    #[test]
    fn context_description_too_long_rejected() {
        let long = "a".repeat(MAX_CONTEXT_DESCRIPTION_LEN + 1);
        let err = validate_context_description(&long).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- Governance reason --

    #[test]
    fn valid_governance_reason() {
        assert!(validate_governance_reason("Member violated community guidelines").is_ok());
    }

    #[test]
    fn governance_reason_with_html_rejected() {
        let err = validate_governance_reason("reason <script>alert(1)</script>").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    #[test]
    fn governance_reason_too_long_rejected() {
        let long = "a".repeat(MAX_GOVERNANCE_REASON_LEN + 1);
        let err = validate_governance_reason(&long).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    #[test]
    fn governance_reason_empty_string_rejected() {
        let err = validate_governance_reason("").unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn governance_reason_whitespace_only_rejected() {
        let err = validate_governance_reason("   ").unwrap_err();
        assert!(err.message.contains("visible content"));
    }

    #[test]
    fn governance_reason_zero_width_chars_rejected() {
        let err = validate_governance_reason("\u{200B}").unwrap_err();
        assert!(err.message.contains("visible content"));
        let err2 = validate_governance_reason("\u{200B}\u{200C}\u{FEFF}").unwrap_err();
        assert!(err2.message.contains("visible content"));
    }

    // -- Payment adapter ref --

    #[test]
    fn valid_payment_adapter_ref() {
        assert!(validate_payment_adapter_ref("lightning").is_ok());
    }

    #[test]
    fn payment_adapter_ref_with_html_rejected() {
        let err = validate_payment_adapter_ref("stripe<script>").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    #[test]
    fn payment_adapter_ref_too_long_rejected() {
        let long = "a".repeat(MAX_PAYMENT_ADAPTER_REF_LEN + 1);
        let err = validate_payment_adapter_ref(&long).unwrap_err();
        assert!(err.message.contains("exceeds maximum length"));
    }

    // -- HTML special char helper --

    #[test]
    fn html_chars_angle_bracket_rejected() {
        let err = reject_html_special_chars("test<value", "field").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
        assert!(err.message.contains("U+003C"));
    }

    #[test]
    fn html_chars_ampersand_rejected() {
        let err = reject_html_special_chars("test&value", "field").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
        assert!(err.message.contains("U+0026"));
    }

    #[test]
    fn html_chars_quote_rejected() {
        let err = reject_html_special_chars("test\"value", "field").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
        assert!(err.message.contains("U+0022"));
    }

    #[test]
    fn html_chars_apostrophe_rejected() {
        let err = reject_html_special_chars("test'value", "field").unwrap_err();
        assert!(err.message.contains("HTML-special character"));
        assert!(err.message.contains("U+0027"));
    }

    #[test]
    fn clean_string_passes_html_check() {
        assert!(reject_html_special_chars("hello world 123-_.", "field").is_ok());
    }

    // -- Governance action string validation --

    #[test]
    fn governance_action_register_tool_braces_in_name_rejected() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::context::tools::registry::{ToolRegistration, ToolSchema};

        let action = GovernanceAction::RegisterTool {
            registration: Box::new(ToolRegistration {
                tool_id: "test-tool".to_owned(),
                name: "tool-{inject}".to_owned(),
                description: "a tool".to_owned(),
                schema: ToolSchema {
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: serde_json::json!({"type": "object"}),
                },
                implementation_hash: [0u8; 32],
                test_vectors: vec![],
                operator_did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
                cost: None,
                registered_at: 0,
                signature: vec![],
            }),
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(err.message.contains("format string risk"));
    }

    #[test]
    fn governance_action_register_tool_html_in_description_rejected() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::context::tools::registry::{ToolRegistration, ToolSchema};

        let action = GovernanceAction::RegisterTool {
            registration: Box::new(ToolRegistration {
                tool_id: "test-tool".to_owned(),
                name: "my-tool".to_owned(),
                description: "a <script>alert(1)</script> tool".to_owned(),
                schema: ToolSchema {
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: serde_json::json!({"type": "object"}),
                },
                implementation_hash: [0u8; 32],
                test_vectors: vec![],
                operator_did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
                cost: None,
                registered_at: 0,
                signature: vec![],
            }),
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    #[test]
    fn governance_action_add_member_valid_role_accepted() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::AddMember {
            did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
            role: "moderator".to_owned(),
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn governance_action_add_member_html_role_rejected() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::AddMember {
            did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
            role: "<admin>".to_owned(),
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    #[test]
    fn governance_action_none_reason_accepted() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::RemoveMember {
            did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
            reason: None,
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn remove_member_empty_string_reason_accepted() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::RemoveMember {
            did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
            reason: Some(String::new()),
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn remove_member_whitespace_only_reason_rejected() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::RemoveMember {
            did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
            reason: Some("   ".to_owned()),
        };
        assert!(validate_governance_action_strings(&action).is_err());
    }

    #[test]
    fn remove_member_tab_only_reason_rejected() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::RemoveMember {
            did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
            reason: Some("\t".to_owned()),
        };
        assert!(validate_governance_action_strings(&action).is_err());
    }

    #[test]
    fn close_context_empty_string_reason_accepted() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::CloseContext {
            reason: Some(String::new()),
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn rotate_content_keys_empty_string_reason_accepted() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::RotateContentKeys {
            reason: Some(String::new()),
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn governance_action_control_chars_in_reason_rejected() {
        use scp_protocol::context::governance::GovernanceAction;

        let action = GovernanceAction::RemoveMember {
            did: scp_primitives::DID("did:dht:z6MkTest".to_owned()),
            reason: Some("bad\0actor".to_owned()),
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(err.message.contains("control character"));
    }

    #[test]
    fn governance_action_propose_migration_validates_nested_params() {
        use scp_protocol::context::governance::GovernanceAction;
        use scp_protocol::context::params::ContextParams;
        use scp_protocol::context::roles::RoleDefinition;
        use std::collections::HashSet;

        let mut params = ContextParams::default();
        params.roles.push(RoleDefinition {
            name: "role<xss>".to_owned(),
            capabilities: HashSet::new(),
        });

        let action = GovernanceAction::ProposeContextMigration {
            new_context_params: Box::new(params),
            reason: "migration reason".to_owned(),
            grace_period_secs: 604_800,
            auto_invite: false,
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(err.message.contains("HTML-special character"));
    }

    // -- Fixed-length byte narrowing --

    #[test]
    fn expect_fixed_bytes_accepts_exact_length() {
        let bytes = [0_u8; 32];
        let arr: [u8; 32] = expect_fixed_bytes(&bytes, "testing_seed").unwrap();
        assert_eq!(arr, [0_u8; 32]);
    }

    #[test]
    fn expect_fixed_bytes_rejects_short_slice() {
        let bytes = [0_u8; 31];
        let err = expect_fixed_bytes::<32>(&bytes, "testing_seed").unwrap_err();
        assert_eq!(err, "testing_seed must be exactly 32 bytes, got 31");
    }

    #[test]
    fn expect_fixed_bytes_rejects_long_slice() {
        let bytes = [0_u8; 33];
        let err = expect_fixed_bytes::<32>(&bytes, "testing_seed").unwrap_err();
        assert_eq!(err, "testing_seed must be exactly 32 bytes, got 33");
    }

    #[test]
    fn expect_fixed_bytes_rejects_empty_slice() {
        let bytes: [u8; 0] = [];
        let err = expect_fixed_bytes::<32>(&bytes, "testing_seed").unwrap_err();
        assert_eq!(err, "testing_seed must be exactly 32 bytes, got 0");
    }

    #[test]
    fn expect_fixed_bytes_uses_provided_field_name() {
        let bytes = [0_u8; 10];
        let err = expect_fixed_bytes::<32>(&bytes, "session_key").unwrap_err();
        assert!(err.starts_with("session_key must be exactly 32 bytes"));
    }

    // -- Zeroize-wrapped narrowing --

    #[test]
    fn expect_fixed_bytes_zeroized_accepts_exact_length() {
        let bytes = [7_u8; 32];
        let wrapped: zeroize::Zeroizing<[u8; 32]> =
            expect_fixed_bytes_zeroized(&bytes, "sender_key").unwrap();
        // Deref through Zeroizing to compare array contents.
        assert_eq!(*wrapped, [7_u8; 32]);
    }

    #[test]
    fn expect_fixed_bytes_zeroized_rejects_wrong_length() {
        let bytes = [0_u8; 31];
        let err = expect_fixed_bytes_zeroized::<32>(&bytes, "sender_key").unwrap_err();
        assert_eq!(err, "sender_key must be exactly 32 bytes, got 31");
    }

    /// Confirms that `Zeroizing<[u8; N]>` carries the `ZeroizeOnDrop`
    /// marker trait — this is the whole point of the helper. If the
    /// zeroize crate ever drops this impl, the helper loses its
    /// security guarantee and the migration sites should be revisited.
    #[test]
    fn zeroizing_fixed_array_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<zeroize::Zeroizing<[u8; 32]>>();
        assert_zeroize_on_drop::<zeroize::Zeroizing<[u8; 64]>>();
    }
}
