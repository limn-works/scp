//! `wasm-bindgen` bridge for discovery address operations.
//!
//! Exposes address parsing and normalization to JavaScript (browser target):
//!
//! - [`discovery_parse_address`] — Parse a `local@scope` address into components.
//! - [`discovery_normalize_address`] — Normalize an address to canonical form.
//! - [`discovery_create_query`] — Create a discovery query descriptor.
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Address parsing and normalization are pure
//! string operations re-implemented locally with algorithm-identical validation.
//!
//! DHT-based context discovery (`context_discover`) is NOT included — it
//! requires network I/O and must be handled by the TypeScript wrapper layer.
//!
//! See spec section 22 and ADR-022.

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Constants (mirror scp-core::discovery::addressing)
// ---------------------------------------------------------------------------

/// Maximum length of the local-part of an address.
const MAX_LOCAL_PART_LENGTH: usize = 64;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates the local-part of an address.
///
/// Rules (mirror scp-core):
/// - Max 64 characters.
/// - ASCII lowercase, digits, `.`, `-`, `_` only.
/// - No leading/trailing `-` or `.`.
/// - No consecutive dots.
fn validate_local_part(local: &str) -> Result<(), String> {
    if local.is_empty() {
        return Err("local-part must not be empty".to_owned());
    }
    if local.len() > MAX_LOCAL_PART_LENGTH {
        return Err(format!(
            "local-part exceeds maximum length of {MAX_LOCAL_PART_LENGTH} characters"
        ));
    }
    for (i, ch) in local.chars().enumerate() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '.' && ch != '-' && ch != '_' {
            return Err(format!(
                "invalid character '{ch}' at position {i} in local-part"
            ));
        }
    }
    if local.starts_with('-')
        || local.ends_with('-')
        || local.starts_with('.')
        || local.ends_with('.')
    {
        return Err("local-part must not start or end with '-' or '.'".to_owned());
    }
    if local.contains("..") {
        return Err("local-part must not contain consecutive dots".to_owned());
    }
    Ok(())
}

/// Validates the scope part of an address.
///
/// Rules (mirror local-part validation pattern):
/// - No control characters (< 0x20 or 0x7F).
/// - No zero-width spaces (U+200B), zero-width joiners (U+200C/U+200D),
///   or other invisible formatting characters (U+FEFF BOM, U+2060 word joiner).
fn validate_scope(scope: &str) -> Result<(), String> {
    for (i, ch) in scope.chars().enumerate() {
        if ch < '\u{0020}' || ch == '\u{007F}' {
            return Err(format!(
                "invalid control character at position {i} in scope"
            ));
        }
        if matches!(
            ch,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}'
        ) {
            return Err(format!(
                "invalid zero-width/invisible character U+{:04X} at position {i} in scope",
                ch as u32
            ));
        }
    }
    Ok(())
}

/// Determines the address type from the scope part.
///
/// - Scope contains `.` => `"DomainHandle"` (e.g., `alice@example.com`)
/// - Scope starts with `did:` => `"AttestationHandle"` (e.g., `alice@did:key:z6Mk...`)
/// - Scope is `_` => `"Unscoped"` (e.g., `alice@_`)
/// - Otherwise => `"DiscoveryHandle"` (e.g., `alice@photography`)
fn classify_scope(scope: &str) -> &'static str {
    if scope == "_" {
        "Unscoped"
    } else if scope.contains('.') {
        "DomainHandle"
    } else if scope.starts_with("did:") {
        "AttestationHandle"
    } else {
        "DiscoveryHandle"
    }
}

// ---------------------------------------------------------------------------
// discovery_parse_address
// ---------------------------------------------------------------------------

/// Parses a `local@scope` address into its components.
///
/// Returns a JSON string with `local`, `scope`, `address_type`, and `raw` fields.
///
/// # Errors
///
/// Returns `JsError` if the address is empty, missing `@`, or the local-part is invalid.
///
/// # JS usage
///
/// ```js
/// const parsed = discovery_parse_address("alice@photography");
/// const obj = JSON.parse(parsed);
/// console.log(obj.address_type); // "DiscoveryHandle"
/// console.log(obj.local);        // "alice"
/// console.log(obj.scope);        // "photography"
/// ```
#[wasm_bindgen]
pub fn discovery_parse_address(address: String) -> Result<String, JsError> {
    if address.is_empty() {
        return Err(JsError::new("[SCP-VALID-7100] address must not be empty"));
    }

    let Some(at_pos) = address.find('@') else {
        return Err(JsError::new(
            "[SCP-VALID-7101] address must contain '@' separator",
        ));
    };

    let local = &address[..at_pos];
    let scope = &address[at_pos + 1..];

    if scope.is_empty() {
        return Err(JsError::new(
            "[SCP-VALID-7102] scope part must not be empty",
        ));
    }

    validate_local_part(local).map_err(|e| JsError::new(&format!("[SCP-VALID-7103] {e}")))?;
    validate_scope(scope).map_err(|e| JsError::new(&format!("[SCP-VALID-7104] {e}")))?;

    let address_type = classify_scope(scope);

    let result = serde_json::json!({
        "local": local,
        "scope": scope,
        "address_type": address_type,
        "raw": address,
    });

    Ok(result.to_string())
}

// ---------------------------------------------------------------------------
// discovery_normalize_address
// ---------------------------------------------------------------------------

/// Normalizes an address to canonical form.
///
/// Canonical form: lowercase local-part, lowercase scope, trimmed whitespace.
/// If the address does not contain `@`, it is returned as-is (lowercased).
///
/// # JS usage
///
/// ```js
/// const normalized = discovery_normalize_address("Alice@Photography");
/// console.log(normalized); // "alice@photography"
/// ```
#[must_use]
#[wasm_bindgen]
pub fn discovery_normalize_address(address: String) -> String {
    address.trim().to_lowercase()
}

// ---------------------------------------------------------------------------
// discovery_create_query
// ---------------------------------------------------------------------------

/// Creates a discovery query descriptor as JSON.
///
/// Used to build structured discovery queries for the TypeScript wrapper to
/// execute against the DHT or other discovery backends.
///
/// # Arguments
///
/// - `handle` — Optional address handle to search for.
/// - `context_type` — Optional context type filter.
/// - `max_results` — Optional maximum number of results (f64 for JS compatibility).
///
/// # Errors
///
/// Returns `JsError` if both `handle` and `context_type` are `None` (empty query).
///
/// # JS usage
///
/// ```js
/// const query = discovery_create_query("alice@photography", null, 10);
/// const obj = JSON.parse(query);
/// ```
#[wasm_bindgen]
pub fn discovery_create_query(
    handle: Option<String>,
    context_type: Option<String>,
    max_results: Option<f64>,
) -> Result<String, JsError> {
    if handle.is_none() && context_type.is_none() {
        return Err(JsError::new(
            "[SCP-VALID-7110] at least one of handle or context_type must be provided",
        ));
    }

    let max = match max_results {
        Some(v) if v < 0.0 => {
            return Err(JsError::new(
                "[SCP-VALID-7040] max_results must be non-negative",
            ));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(v) => v as u64,
        None => 20,
    };

    let result = serde_json::json!({
        "handle": handle,
        "context_type": context_type,
        "max_results": max,
    });

    Ok(result.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_arch = "wasm32"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_discovery_handle() {
        let result = discovery_parse_address("alice@photography".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["address_type"], "DiscoveryHandle");
        assert_eq!(json["local"], "alice");
        assert_eq!(json["scope"], "photography");
    }

    #[test]
    fn parse_domain_handle() {
        let result = discovery_parse_address("alice@example.com".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["address_type"], "DomainHandle");
    }

    #[test]
    fn parse_attestation_handle() {
        let result = discovery_parse_address("alice@did:key:z6MkTest".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["address_type"], "AttestationHandle");
    }

    #[test]
    fn parse_unscoped() {
        let result = discovery_parse_address("alice@_".to_owned()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["address_type"], "Unscoped");
    }

    #[test]
    fn parse_empty_address_fails() {
        assert!(discovery_parse_address(String::new()).is_err());
    }

    #[test]
    fn parse_no_at_sign_fails() {
        assert!(discovery_parse_address("alice".to_owned()).is_err());
    }

    #[test]
    fn parse_empty_scope_fails() {
        assert!(discovery_parse_address("alice@".to_owned()).is_err());
    }

    #[test]
    fn parse_invalid_local_part_fails() {
        assert!(discovery_parse_address("ALICE@scope".to_owned()).is_err());
    }

    #[test]
    fn parse_leading_dash_fails() {
        assert!(discovery_parse_address("-alice@scope".to_owned()).is_err());
    }

    #[test]
    fn parse_consecutive_dots_fails() {
        assert!(discovery_parse_address("al..ice@scope".to_owned()).is_err());
    }

    #[test]
    fn normalize_lowercases() {
        assert_eq!(
            discovery_normalize_address("Alice@Photography".to_owned()),
            "alice@photography"
        );
    }

    #[test]
    fn normalize_trims_whitespace() {
        assert_eq!(
            discovery_normalize_address("  alice@scope  ".to_owned()),
            "alice@scope"
        );
    }

    #[test]
    fn create_query_with_handle() {
        let result =
            discovery_create_query(Some("alice@photo".to_owned()), None, Some(5.0)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["handle"], "alice@photo");
        assert_eq!(json["max_results"], 5);
    }

    #[test]
    fn create_query_empty_fails() {
        assert!(discovery_create_query(None, None, None).is_err());
    }

    #[test]
    fn create_query_default_max_results() {
        let result = discovery_create_query(Some("alice@photo".to_owned()), None, None).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["max_results"], 20);
    }

    #[test]
    fn validate_local_part_valid() {
        assert!(validate_local_part("alice").is_ok());
        assert!(validate_local_part("alice.bob").is_ok());
        assert!(validate_local_part("alice_bob").is_ok());
        assert!(validate_local_part("alice-bob").is_ok());
        assert!(validate_local_part("a123").is_ok());
    }

    #[test]
    fn validate_local_part_too_long() {
        let long = "a".repeat(65);
        assert!(validate_local_part(&long).is_err());
    }

    #[test]
    fn validate_scope_rejects_control_chars() {
        // Null byte
        assert!(validate_scope("scope\x00bad").is_err());
        // Tab
        assert!(validate_scope("scope\ttab").is_err());
        // Newline
        assert!(validate_scope("scope\nnewline").is_err());
        // Carriage return
        assert!(validate_scope("scope\rreturn").is_err());
        // DEL (0x7F)
        assert!(validate_scope("scope\x7Fdel").is_err());
    }

    #[test]
    fn validate_scope_rejects_zero_width_chars() {
        // Zero-width space (U+200B)
        assert!(validate_scope("scope\u{200B}zwsp").is_err());
        // Zero-width non-joiner (U+200C)
        assert!(validate_scope("scope\u{200C}zwnj").is_err());
        // Zero-width joiner (U+200D)
        assert!(validate_scope("scope\u{200D}zwj").is_err());
        // BOM (U+FEFF)
        assert!(validate_scope("\u{FEFF}scope").is_err());
        // Word joiner (U+2060)
        assert!(validate_scope("scope\u{2060}wj").is_err());
    }

    #[test]
    fn validate_scope_accepts_valid() {
        assert!(validate_scope("photography").is_ok());
        assert!(validate_scope("example.com").is_ok());
        assert!(validate_scope("did:key:z6MkTest").is_ok());
        assert!(validate_scope("_").is_ok());
    }

    #[test]
    fn parse_scope_control_char_fails() {
        assert!(discovery_parse_address("alice@scope\x00bad".to_owned()).is_err());
    }

    #[test]
    fn parse_scope_zero_width_space_fails() {
        assert!(discovery_parse_address("alice@scope\u{200B}zwsp".to_owned()).is_err());
    }

    #[test]
    fn create_query_negative_max_results_errors() {
        let result = discovery_create_query(Some("alice@photo".to_owned()), None, Some(-1.0));
        assert!(result.is_err(), "negative max_results should error");
    }

    #[test]
    fn create_query_neg_infinity_max_results_errors() {
        let result = discovery_create_query(
            Some("alice@photo".to_owned()),
            None,
            Some(f64::NEG_INFINITY),
        );
        assert!(result.is_err(), "NEG_INFINITY max_results should error");
    }

    #[test]
    fn create_query_f64_min_max_results_errors() {
        let result = discovery_create_query(Some("alice@photo".to_owned()), None, Some(f64::MIN));
        assert!(result.is_err(), "f64::MIN max_results should error");
    }
}
