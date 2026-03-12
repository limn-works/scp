//! SCP context URI type, parsing, and serialization.
//!
//! Implements the `scp://` URI scheme as specified in section 18.4 of the SCP
//! specification. Context URIs are discovery-only references that can be shared
//! out-of-band (chat, email, QR codes) to point to a context's metadata.
//!
//! # URI Format
//!
//! Universal format:
//! ```text
//! scp://context/<context_id_hex>?relay=<url>[&relay=<url2>][&mode=<mode>][&name=<name>]
//! ```
//!
//! Legacy broadcast alias (accepted on parse, normalized to universal format):
//! ```text
//! scp://broadcast/<context_id_hex>?relay=<url>
//! ```
//!
//! # Examples
//!
//! ```
//! use scp_core::uri::ScpUri;
//!
//! let uri: ScpUri = "scp://context/a1b2c3d4?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1"
//!     .parse()
//!     .unwrap();
//! assert_eq!(uri.to_string(),
//!     "scp://context/a1b2c3d4?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1");
//! ```

use std::fmt;
use std::str::FromStr;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::context::ContextMode;

/// Characters that must be percent-encoded in query parameter values per
/// RFC 3986. We encode everything except unreserved characters
/// (ALPHA / DIGIT / "-" / "." / "_" / "~").
const QUERY_VALUE_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

// ---------------------------------------------------------------------------
// ScpUriError
// ---------------------------------------------------------------------------

/// Errors produced when parsing an `scp://` URI.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScpUriError {
    /// The URI scheme is not `scp`.
    #[error("invalid URI scheme: expected 'scp', got '{scheme}'")]
    InvalidScheme {
        /// The scheme that was found.
        scheme: String,
    },

    /// The URI path does not start with `context/` (or the legacy
    /// `broadcast/`).
    #[error("missing or invalid context path — expected 'context/<hex>' or 'broadcast/<hex>'")]
    MissingContextPath,

    /// The context ID is not valid hexadecimal.
    #[error("invalid context ID hex: '{id}'")]
    InvalidHex {
        /// The invalid hex string that was found.
        id: String,
    },

    /// No `relay` query parameter was provided (at least one is required).
    #[error("missing required 'relay' query parameter")]
    MissingRelay,

    /// A relay URL does not use the required `wss://` scheme.
    #[error("relay URL must use wss:// scheme: '{url}'")]
    InvalidRelayScheme {
        /// The relay URL with an invalid scheme.
        url: String,
    },

    /// The URI string is malformed and cannot be parsed at all.
    #[error("malformed URI: {reason}")]
    Malformed {
        /// A description of why the URI is malformed.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// ScpUri
// ---------------------------------------------------------------------------

/// A parsed `scp://` context URI.
///
/// Represents a shareable reference to an SCP context. The URI contains a
/// context ID, one or more relay URLs, and optional advisory metadata (mode
/// and human-readable name).
///
/// # Parsing
///
/// Accepts both the universal format (`scp://context/...`) and the legacy
/// broadcast alias (`scp://broadcast/...`). The legacy form is normalized to
/// the universal format with `mode` set to [`ContextMode::Broadcast`].
///
/// # Serialization
///
/// `Display` always emits the canonical universal format
/// (`scp://context/...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpUri {
    /// A context reference.
    Context {
        /// Hex-encoded context identifier.
        context_id: String,
        /// Relay URLs where the context is reachable. Must use `wss://` scheme.
        relays: Vec<String>,
        /// Advisory context mode (`encrypted` or `broadcast`). Not verified
        /// against actual context metadata.
        mode: Option<ContextMode>,
        /// Advisory human-readable context name. Not verified against actual
        /// context metadata.
        name: Option<String>,
        /// Advisory human-readable handle (e.g.,
        /// `recipes@cooking-community`). Provides a resolution starting
        /// point for clients but the canonical reference remains the
        /// `context_id`. See spec section 22.9.1.
        handle: Option<String>,
    },
}

impl ScpUri {
    /// Returns the context ID for this URI.
    #[must_use]
    pub fn context_id(&self) -> &str {
        let Self::Context { context_id, .. } = self;
        context_id
    }

    /// Returns the relay URLs for this URI.
    #[must_use]
    pub fn relays(&self) -> &[String] {
        let Self::Context { relays, .. } = self;
        relays
    }

    /// Returns the advisory mode, if present.
    #[must_use]
    pub const fn mode(&self) -> Option<ContextMode> {
        let Self::Context { mode, .. } = self;
        *mode
    }

    /// Returns the advisory name, if present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        let Self::Context { name, .. } = self;
        name.as_deref()
    }

    /// Returns the advisory handle, if present (e.g.,
    /// `recipes@cooking-community`). See spec section 22.9.1.
    #[must_use]
    pub fn handle(&self) -> Option<&str> {
        let Self::Context { handle, .. } = self;
        handle.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Validates that a string contains only hexadecimal characters and is
/// non-empty.
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validates that a relay URL uses the `wss://` scheme.
fn validate_relay_scheme(url: &str) -> Result<(), ScpUriError> {
    // Check for wss:// prefix (case-insensitive per URL spec convention,
    // but SCP relays canonically use lowercase).
    if url.starts_with("wss://") || url.starts_with("WSS://") {
        Ok(())
    } else {
        Err(ScpUriError::InvalidRelayScheme {
            url: url.to_owned(),
        })
    }
}

/// Parses query parameters from a query string. Returns key-value pairs in
/// order. Values are percent-decoded.
fn parse_query_params(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (key, value) = if let Some(eq_pos) = pair.find('=') {
                (&pair[..eq_pos], &pair[eq_pos + 1..])
            } else {
                // Parameters without values are ignored.
                return None;
            };
            let decoded_key = percent_decode_str(key).decode_utf8_lossy().into_owned();
            let decoded_value = percent_decode_str(value).decode_utf8_lossy().into_owned();
            Some((decoded_key, decoded_value))
        })
        .collect()
}

/// Parses the mode string into a `ContextMode`.
fn parse_mode(s: &str) -> Option<ContextMode> {
    match s {
        "encrypted" => Some(ContextMode::Encrypted),
        "broadcast" => Some(ContextMode::Broadcast),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// FromStr
// ---------------------------------------------------------------------------

impl FromStr for ScpUri {
    type Err = ScpUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split scheme from the rest.
        let (scheme, after_scheme) = s.split_once("://").ok_or_else(|| ScpUriError::Malformed {
            reason: "missing '://' separator".to_owned(),
        })?;

        if scheme != "scp" {
            return Err(ScpUriError::InvalidScheme {
                scheme: scheme.to_owned(),
            });
        }

        // Split path from query string.
        let (path, query_str) = match after_scheme.split_once('?') {
            Some((p, q)) => (p, q),
            None => (after_scheme, ""),
        };

        // Determine path type and extract context ID.
        let (context_id_raw, is_legacy_broadcast) = if let Some(hex) = path.strip_prefix("context/")
        {
            (hex, false)
        } else if let Some(hex) = path.strip_prefix("broadcast/") {
            (hex, true)
        } else {
            return Err(ScpUriError::MissingContextPath);
        };

        // Percent-decode the context ID (though hex chars don't need encoding,
        // be defensive).
        let context_id = percent_decode_str(context_id_raw)
            .decode_utf8_lossy()
            .into_owned();

        if !is_valid_hex(&context_id) {
            return Err(ScpUriError::InvalidHex { id: context_id });
        }

        // Parse query parameters.
        let params = parse_query_params(query_str);

        let mut relays = Vec::new();
        let mut mode: Option<ContextMode> = if is_legacy_broadcast {
            Some(ContextMode::Broadcast)
        } else {
            None
        };
        let mut name: Option<String> = None;
        let mut handle: Option<String> = None;

        for (key, value) in &params {
            match key.as_str() {
                "relay" => {
                    validate_relay_scheme(value)?;
                    relays.push(value.clone());
                }
                "mode" => {
                    if let Some(parsed) = parse_mode(value) {
                        mode = Some(parsed);
                    }
                    // Unknown mode values are ignored (advisory field).
                }
                "name" => {
                    name = Some(value.clone());
                }
                "handle" => {
                    handle = Some(value.clone());
                }
                _ => {
                    // Unknown query parameters are ignored (forward
                    // compatibility per spec).
                }
            }
        }

        if relays.is_empty() {
            return Err(ScpUriError::MissingRelay);
        }

        Ok(Self::Context {
            context_id,
            relays,
            mode,
            name,
            handle,
        })
    }
}

// ---------------------------------------------------------------------------
// Display (canonical serialization)
// ---------------------------------------------------------------------------

impl fmt::Display for ScpUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::Context {
            context_id,
            relays,
            mode,
            name,
            handle,
        } = self;

        // Always emit universal format.
        write!(f, "scp://context/{context_id}")?;

        // Build query string. Relay params come first.
        let mut first = true;
        for relay in relays {
            if first {
                write!(f, "?")?;
                first = false;
            } else {
                write!(f, "&")?;
            }
            write!(
                f,
                "relay={}",
                utf8_percent_encode(relay, QUERY_VALUE_ENCODE_SET)
            )?;
        }

        if let Some(m) = mode {
            let mode_str = match m {
                ContextMode::Encrypted => "encrypted",
                ContextMode::Broadcast => "broadcast",
            };
            if first {
                write!(f, "?")?;
                first = false;
            } else {
                write!(f, "&")?;
            }
            write!(f, "mode={mode_str}")?;
        }

        if let Some(n) = name {
            if first {
                write!(f, "?")?;
                first = false;
            } else {
                write!(f, "&")?;
            }
            write!(f, "name={}", utf8_percent_encode(n, QUERY_VALUE_ENCODE_SET))?;
        }

        if let Some(h) = handle {
            if first {
                write!(f, "?")?;
            } else {
                write!(f, "&")?;
            }
            write!(
                f,
                "handle={}",
                utf8_percent_encode(h, QUERY_VALUE_ENCODE_SET)
            )?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- Basic parsing tests --------------------------------------------------

    #[test]
    fn parse_context_uri_with_single_relay() {
        let input = "scp://context/a1b2c3d4e5f6?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.context_id(), "a1b2c3d4e5f6");
        assert_eq!(uri.relays(), &["wss://relay.example.com/scp/v1"]);
        assert_eq!(uri.mode(), None);
        assert_eq!(uri.name(), None);
    }

    #[test]
    fn parse_context_uri_with_multiple_relays() {
        let input = "scp://context/a1b2c3d4e5f6\
            ?relay=wss%3A%2F%2Frelay1.example.com%2Fscp%2Fv1\
            &relay=wss%3A%2F%2Frelay2.example.com%2Fscp%2Fv1";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.context_id(), "a1b2c3d4e5f6");
        assert_eq!(
            uri.relays(),
            &[
                "wss://relay1.example.com/scp/v1",
                "wss://relay2.example.com/scp/v1",
            ]
        );
    }

    #[test]
    fn parse_context_uri_with_all_optional_params() {
        let input = "scp://context/a1b2c3d4e5f6\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
            &mode=broadcast\
            &name=Test%20Name";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.context_id(), "a1b2c3d4e5f6");
        assert_eq!(uri.relays(), &["wss://relay.example.com/scp/v1"]);
        assert_eq!(uri.mode(), Some(ContextMode::Broadcast));
        assert_eq!(uri.name(), Some("Test Name"));
    }

    #[test]
    fn parse_context_uri_with_plus_encoded_name() {
        // '+' in query strings is sometimes used for spaces (HTML form
        // encoding). Per RFC 3986, '+' is a literal character. We test that
        // percent-encoding (%20) is decoded but '+' is preserved literally.
        let input = "scp://context/abcdef\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
            &mode=broadcast\
            &name=Test+Name";
        let uri: ScpUri = input.parse().unwrap();
        // '+' is preserved literally per RFC 3986.
        assert_eq!(uri.name(), Some("Test+Name"));
    }

    // -- Legacy broadcast alias -----------------------------------------------

    #[test]
    fn parse_legacy_broadcast_alias_normalized_to_context() {
        let input = "scp://broadcast/a1b2c3d4e5f6?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.context_id(), "a1b2c3d4e5f6");
        assert_eq!(uri.mode(), Some(ContextMode::Broadcast));
        // Serialization uses universal format.
        let serialized = uri.to_string();
        assert!(serialized.starts_with("scp://context/"));
        assert!(serialized.contains("mode=broadcast"));
    }

    // -- Relay scheme validation ----------------------------------------------

    #[test]
    fn parse_rejects_non_wss_relay() {
        let input = "scp://context/abcdef?relay=https%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert!(matches!(err, ScpUriError::InvalidRelayScheme { .. }));
    }

    #[test]
    fn parse_rejects_ws_relay() {
        let input = "scp://context/abcdef?relay=ws%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert!(matches!(err, ScpUriError::InvalidRelayScheme { .. }));
    }

    // -- Error variant tests --------------------------------------------------

    #[test]
    fn parse_rejects_wrong_scheme() {
        let input = "https://context/abcdef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert_eq!(
            err,
            ScpUriError::InvalidScheme {
                scheme: "https".to_owned()
            }
        );
    }

    #[test]
    fn parse_rejects_missing_context_path() {
        let input = "scp://other/abcdef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert_eq!(err, ScpUriError::MissingContextPath);
    }

    #[test]
    fn parse_rejects_invalid_hex() {
        let input = "scp://context/zzzz?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert!(matches!(err, ScpUriError::InvalidHex { .. }));
    }

    #[test]
    fn parse_rejects_empty_context_id() {
        let input = "scp://context/?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert!(matches!(err, ScpUriError::InvalidHex { .. }));
    }

    #[test]
    fn parse_rejects_missing_relay() {
        let input = "scp://context/abcdef";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert_eq!(err, ScpUriError::MissingRelay);
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let input = "scp:context/abcdef";
        let err = input.parse::<ScpUri>().unwrap_err();
        assert!(matches!(err, ScpUriError::Malformed { .. }));
    }

    // -- Unknown query parameters ignored (forward compatibility) -------------

    #[test]
    fn parse_ignores_unknown_query_params() {
        let input = "scp://context/abcdef\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
            &future_param=hello\
            &version=2";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.context_id(), "abcdef");
        assert_eq!(uri.relays(), &["wss://relay.example.com/scp/v1"]);
    }

    // -- Roundtrip tests ------------------------------------------------------

    #[test]
    fn roundtrip_encrypted_context_uri() {
        let original = ScpUri::Context {
            context_id: "a1b2c3d4e5f6".to_owned(),
            relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
            mode: Some(ContextMode::Encrypted),
            name: None,
            handle: None,
        };
        let serialized = original.to_string();
        let parsed: ScpUri = serialized.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_broadcast_context_uri() {
        let original = ScpUri::Context {
            context_id: "deadbeef0123".to_owned(),
            relays: vec![
                "wss://relay1.example.com/scp/v1".to_owned(),
                "wss://relay2.example.com/scp/v1".to_owned(),
            ],
            mode: Some(ContextMode::Broadcast),
            name: Some("Tech News".to_owned()),
            handle: None,
        };
        let serialized = original.to_string();
        let parsed: ScpUri = serialized.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_context_uri_no_optional_params() {
        let original = ScpUri::Context {
            context_id: "abcdef012345".to_owned(),
            relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
            mode: None,
            name: None,
            handle: None,
        };
        let serialized = original.to_string();
        let parsed: ScpUri = serialized.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_preserves_name_with_special_chars() {
        let original = ScpUri::Context {
            context_id: "aabbccdd".to_owned(),
            relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
            mode: None,
            name: Some("Hello World & Friends!".to_owned()),
            handle: None,
        };
        let serialized = original.to_string();
        let parsed: ScpUri = serialized.parse().unwrap();
        assert_eq!(original, parsed);
    }

    // -- Serialization format tests -------------------------------------------

    #[test]
    fn display_uses_canonical_context_format() {
        let uri = ScpUri::Context {
            context_id: "abcdef".to_owned(),
            relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
            mode: Some(ContextMode::Broadcast),
            name: None,
            handle: None,
        };
        let s = uri.to_string();
        assert!(s.starts_with("scp://context/"));
        assert!(!s.contains("broadcast/"));
    }

    #[test]
    fn display_percent_encodes_relay_urls() {
        let uri = ScpUri::Context {
            context_id: "abcdef".to_owned(),
            relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
            mode: None,
            name: None,
            handle: None,
        };
        let s = uri.to_string();
        // The relay URL should be percent-encoded (colons, slashes).
        assert!(s.contains("relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1"));
    }

    #[test]
    fn display_percent_encodes_name() {
        let uri = ScpUri::Context {
            context_id: "abcdef".to_owned(),
            relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
            mode: None,
            name: Some("Hello World".to_owned()),
            handle: None,
        };
        let s = uri.to_string();
        assert!(s.contains("name=Hello%20World"));
    }

    // -- Error display tests --------------------------------------------------

    #[test]
    fn error_display_messages_are_descriptive() {
        let err = ScpUriError::InvalidScheme {
            scheme: "http".to_owned(),
        };
        assert_eq!(
            format!("{err}"),
            "invalid URI scheme: expected 'scp', got 'http'"
        );

        let err = ScpUriError::MissingContextPath;
        assert_eq!(
            format!("{err}"),
            "missing or invalid context path \
             — expected 'context/<hex>' or 'broadcast/<hex>'"
        );

        let err = ScpUriError::InvalidHex {
            id: "zzzz".to_owned(),
        };
        assert_eq!(format!("{err}"), "invalid context ID hex: 'zzzz'");

        let err = ScpUriError::MissingRelay;
        assert_eq!(format!("{err}"), "missing required 'relay' query parameter");

        let err = ScpUriError::InvalidRelayScheme {
            url: "https://example.com".to_owned(),
        };
        assert_eq!(
            format!("{err}"),
            "relay URL must use wss:// scheme: 'https://example.com'"
        );

        let err = ScpUriError::Malformed {
            reason: "test".to_owned(),
        };
        assert_eq!(format!("{err}"), "malformed URI: test");
    }

    // -- Mode parsing ---------------------------------------------------------

    #[test]
    fn parse_encrypted_mode() {
        let input = "scp://context/abcdef\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
            &mode=encrypted";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.mode(), Some(ContextMode::Encrypted));
    }

    #[test]
    fn parse_unknown_mode_ignored() {
        let input = "scp://context/abcdef\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
            &mode=unknown_future_mode";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.mode(), None);
    }

    #[test]
    fn legacy_broadcast_with_explicit_mode_uses_broadcast() {
        // Legacy broadcast path + explicit mode param. The path sets broadcast,
        // and the mode param should also be broadcast. Since the legacy path
        // pre-sets it, the explicit mode=broadcast is redundant but consistent.
        let input = "scp://broadcast/abcdef\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
            &mode=broadcast";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.mode(), Some(ContextMode::Broadcast));
    }

    // -- Handle query parameter (§22.9.1) ------------------------------------

    #[test]
    fn parse_handle_query_parameter() {
        let input = "scp://context/a1b2c3d4e5f6\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1\
            &handle=recipes%40cooking-community";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.context_id(), "a1b2c3d4e5f6");
        assert_eq!(uri.handle(), Some("recipes@cooking-community"));
        assert_eq!(uri.name(), None);
    }

    #[test]
    fn roundtrip_uri_with_handle() {
        let original = ScpUri::Context {
            context_id: "a1b2c3d4e5f6".to_owned(),
            relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
            mode: Some(ContextMode::Broadcast),
            name: Some("Recipes".to_owned()),
            handle: Some("recipes@cooking-community".to_owned()),
        };
        let serialized = original.to_string();
        let parsed: ScpUri = serialized.parse().unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.handle(), Some("recipes@cooking-community"));
    }

    #[test]
    fn uri_without_handle_has_none() {
        let input = "scp://context/abcdef\
            ?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
        let uri: ScpUri = input.parse().unwrap();
        assert_eq!(uri.handle(), None);
    }
}
