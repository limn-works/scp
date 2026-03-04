//! WebSocket fallback logic for the WebTransport adapter.
//!
//! Implements the fallback chain defined in spec section 10.15.3:
//!
//! 1. **WebTransport** -- attempt first. If the `WebTransport` API is
//!    unavailable or the connection fails, fall through.
//! 2. **WebSocket** -- mandatory baseline. All relays support WebSocket.
//! 3. **Error** -- if WebSocket also fails, report connection failure.
//!
//! The fallback is transparent to [`TransportAdapter`] callers. The
//! [`FallbackState`] tracks which transport is active and handles switching.
//!
//! # Mid-session upgrade (spec section 10.15.3)
//!
//! The adapter MAY switch from WebSocket to WebTransport mid-session if the
//! relay advertises WebTransport support via `Alt-Svc`. This involves
//! establishing a new WebTransport session and re-opening subscription streams
//! (same gap-fill strategy as reconnection), not an in-place protocol upgrade.
//!
//! See ADR-037 for the full specification.
//!
//! [`TransportAdapter`]: crate::TransportAdapter

use crate::error::TransportError;

// ---------------------------------------------------------------------------
// TransportKind -- which transport is currently active
// ---------------------------------------------------------------------------

/// Identifies which underlying transport is currently active.
///
/// Used by [`FallbackState`] to track the current transport and by callers
/// to inspect which transport was selected after connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// The browser's `WebTransport` API (HTTP/3 + QUIC).
    WebTransport,

    /// The browser's `WebSocket` API (mandatory baseline per spec section 10.15.3).
    WebSocket,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebTransport => write!(f, "WebTransport"),
            Self::WebSocket => write!(f, "WebSocket"),
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackState -- tracks fallback progression
// ---------------------------------------------------------------------------

/// Tracks the fallback state for the WebTransport adapter.
///
/// The state machine progresses through:
///
/// ```text
/// Disconnected -> AttemptingWebTransport -> Connected(WebTransport)
///                                        \-> AttemptingWebSocket -> Connected(WebSocket)
///                                                                \-> Failed
/// ```
///
/// Once connected, the state records which transport is active. The adapter
/// uses this to dispatch operations to the correct underlying transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackState {
    /// No connection attempt has been made.
    Disconnected,

    /// Currently attempting a WebTransport connection.
    AttemptingWebTransport,

    /// WebTransport failed; currently attempting WebSocket fallback.
    AttemptingWebSocket,

    /// Successfully connected via the specified transport.
    Connected(TransportKind),

    /// Both WebTransport and WebSocket failed. The error message describes
    /// the failure chain.
    Failed(String),
}

impl FallbackState {
    /// Returns `true` if the state represents an active connection.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(self, Self::Connected(_))
    }

    /// Returns the active transport kind, or `None` if not connected.
    #[must_use]
    pub const fn transport_kind(&self) -> Option<TransportKind> {
        match self {
            Self::Connected(kind) => Some(*kind),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Feature detection
// ---------------------------------------------------------------------------

/// Checks whether the browser's `WebTransport` API is available.
///
/// Returns `true` if `globalThis.WebTransport` is defined and is a
/// constructor. This detects both API absence (Safari, older browsers)
/// and environments where the API exists but is disabled.
///
/// # Platform
///
/// This function is only meaningful on `wasm32` targets. On non-WASM
/// targets it always returns `false`.
// Not const: the wasm32 branch calls runtime JS functions via js_sys.
// Clippy only sees the non-WASM branch (which is trivially const) but
// the function must be non-const for wasm32 correctness.
#[must_use]
#[allow(clippy::missing_const_for_fn)]
pub fn is_webtransport_available() -> bool {
    // In WASM, check the global scope for the WebTransport constructor.
    // We use js_sys to probe `globalThis.WebTransport`.
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::prelude::*;

        let global = js_sys::global();
        let wt = js_sys::Reflect::get(&global, &JsValue::from_str("WebTransport"));
        match wt {
            Ok(val) => !val.is_undefined() && !val.is_null() && val.is_function(),
            Err(_) => false,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

/// Converts a relay URL to the appropriate WebTransport URL.
///
/// WebTransport connections use `https://` scheme (HTTP/3 over QUIC) and
/// connect to the `/scp/v1` endpoint per spec section 10.15.2.
///
/// URL scheme matching is case-insensitive per RFC 3986 section 3.1.
///
/// # Errors
///
/// Returns [`TransportError::ConnectionFailed`] if the URL cannot be
/// converted (e.g., missing host, unsupported scheme).
pub fn relay_url_to_webtransport(relay_url: &str) -> Result<String, TransportError> {
    // Normalize scheme to lowercase per RFC 3986 section 3.1:
    // "the scheme is case-insensitive"
    let lower = relay_url.to_ascii_lowercase();
    let host_and_path = if let Some(stripped) = lower.strip_prefix("wss://") {
        stripped
    } else if let Some(stripped) = lower.strip_prefix("https://") {
        stripped
    } else {
        return Err(TransportError::ConnectionFailed(format!(
            "WebTransport requires wss:// or https:// URL, got: {relay_url}"
        )));
    };

    // Extract just the host (possibly with port), discarding any existing path
    let host = host_and_path
        .split('/')
        .next()
        .ok_or_else(|| TransportError::ConnectionFailed("empty host in URL".to_owned()))?;

    if host.is_empty() {
        return Err(TransportError::ConnectionFailed(
            "empty host in relay URL".to_owned(),
        ));
    }

    // WebTransport connects to /scp/v1 per spec section 10.15.2
    Ok(format!("https://{host}/scp/v1"))
}

/// Converts a relay URL to the appropriate WebSocket URL.
///
/// WebSocket connections use `wss://` scheme and connect to the `/scp/v1`
/// endpoint per ADR-004.
///
/// URL scheme matching is case-insensitive per RFC 3986 section 3.1.
///
/// # Errors
///
/// Returns [`TransportError::ConnectionFailed`] if the URL cannot be
/// converted.
pub fn relay_url_to_websocket(relay_url: &str) -> Result<String, TransportError> {
    // Normalize scheme to lowercase per RFC 3986 section 3.1
    let lower = relay_url.to_ascii_lowercase();
    let host_and_path = if let Some(stripped) = lower.strip_prefix("wss://") {
        stripped
    } else if let Some(stripped) = lower.strip_prefix("https://") {
        stripped
    } else {
        return Err(TransportError::ConnectionFailed(format!(
            "WebSocket requires wss:// or https:// URL, got: {relay_url}"
        )));
    };

    let host = host_and_path
        .split('/')
        .next()
        .ok_or_else(|| TransportError::ConnectionFailed("empty host in URL".to_owned()))?;

    if host.is_empty() {
        return Err(TransportError::ConnectionFailed(
            "empty host in relay URL".to_owned(),
        ));
    }

    Ok(format!("wss://{host}/scp/v1"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- TransportKind -------------------------------------------------

    #[test]
    fn transport_kind_display() {
        assert_eq!(TransportKind::WebTransport.to_string(), "WebTransport");
        assert_eq!(TransportKind::WebSocket.to_string(), "WebSocket");
    }

    #[test]
    fn transport_kind_equality() {
        assert_eq!(TransportKind::WebTransport, TransportKind::WebTransport);
        assert_eq!(TransportKind::WebSocket, TransportKind::WebSocket);
        assert_ne!(TransportKind::WebTransport, TransportKind::WebSocket);
    }

    // -- FallbackState -------------------------------------------------

    #[test]
    fn fallback_state_disconnected_is_not_connected() {
        let state = FallbackState::Disconnected;
        assert!(!state.is_connected());
        assert_eq!(state.transport_kind(), None);
    }

    #[test]
    fn fallback_state_attempting_webtransport_is_not_connected() {
        let state = FallbackState::AttemptingWebTransport;
        assert!(!state.is_connected());
        assert_eq!(state.transport_kind(), None);
    }

    #[test]
    fn fallback_state_attempting_websocket_is_not_connected() {
        let state = FallbackState::AttemptingWebSocket;
        assert!(!state.is_connected());
        assert_eq!(state.transport_kind(), None);
    }

    #[test]
    fn fallback_state_connected_webtransport() {
        let state = FallbackState::Connected(TransportKind::WebTransport);
        assert!(state.is_connected());
        assert_eq!(state.transport_kind(), Some(TransportKind::WebTransport));
    }

    #[test]
    fn fallback_state_connected_websocket() {
        let state = FallbackState::Connected(TransportKind::WebSocket);
        assert!(state.is_connected());
        assert_eq!(state.transport_kind(), Some(TransportKind::WebSocket));
    }

    #[test]
    fn fallback_state_failed_is_not_connected() {
        let state = FallbackState::Failed("both transports failed".to_owned());
        assert!(!state.is_connected());
        assert_eq!(state.transport_kind(), None);
    }

    // -- is_webtransport_available (non-WASM) --------------------------

    #[test]
    fn webtransport_not_available_on_non_wasm() {
        // On non-WASM targets, this always returns false.
        assert!(!is_webtransport_available());
    }

    // -- relay_url_to_webtransport -------------------------------------

    #[test]
    fn webtransport_url_from_wss() {
        let url = relay_url_to_webtransport("wss://relay.example.com/scp/v1").unwrap();
        assert_eq!(url, "https://relay.example.com/scp/v1");
    }

    #[test]
    fn webtransport_url_from_wss_with_port() {
        let url = relay_url_to_webtransport("wss://relay.example.com:8443/scp/v1").unwrap();
        assert_eq!(url, "https://relay.example.com:8443/scp/v1");
    }

    #[test]
    fn webtransport_url_from_https() {
        let url = relay_url_to_webtransport("https://relay.example.com/scp/v1").unwrap();
        assert_eq!(url, "https://relay.example.com/scp/v1");
    }

    #[test]
    fn webtransport_url_rejects_ws() {
        let err = relay_url_to_webtransport("ws://relay.example.com/scp/v1");
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            TransportError::ConnectionFailed(_)
        ));
    }

    #[test]
    fn webtransport_url_rejects_http() {
        let err = relay_url_to_webtransport("http://relay.example.com/scp/v1");
        assert!(err.is_err());
    }

    #[test]
    fn webtransport_url_strips_existing_path() {
        let url = relay_url_to_webtransport("wss://relay.example.com/old/path").unwrap();
        assert_eq!(url, "https://relay.example.com/scp/v1");
    }

    // -- relay_url_to_websocket ----------------------------------------

    #[test]
    fn websocket_url_from_wss() {
        let url = relay_url_to_websocket("wss://relay.example.com/scp/v1").unwrap();
        assert_eq!(url, "wss://relay.example.com/scp/v1");
    }

    #[test]
    fn websocket_url_from_https() {
        let url = relay_url_to_websocket("https://relay.example.com/scp/v1").unwrap();
        assert_eq!(url, "wss://relay.example.com/scp/v1");
    }

    #[test]
    fn websocket_url_with_port() {
        let url = relay_url_to_websocket("wss://relay.example.com:8443/scp/v1").unwrap();
        assert_eq!(url, "wss://relay.example.com:8443/scp/v1");
    }

    #[test]
    fn websocket_url_rejects_ws() {
        let err = relay_url_to_websocket("ws://relay.example.com/scp/v1");
        assert!(err.is_err());
    }

    #[test]
    fn websocket_url_rejects_http() {
        let err = relay_url_to_websocket("http://relay.example.com/scp/v1");
        assert!(err.is_err());
    }

    // -- Case-insensitive URL scheme (RFC 3986 §3.1) ----------------------

    #[test]
    fn webtransport_url_case_insensitive_scheme() {
        let url = relay_url_to_webtransport("WSS://relay.example.com/scp/v1").unwrap();
        assert_eq!(url, "https://relay.example.com/scp/v1");

        let url = relay_url_to_webtransport("Https://relay.example.com/scp/v1").unwrap();
        assert_eq!(url, "https://relay.example.com/scp/v1");
    }

    #[test]
    fn websocket_url_case_insensitive_scheme() {
        let url = relay_url_to_websocket("WSS://relay.example.com/scp/v1").unwrap();
        assert_eq!(url, "wss://relay.example.com/scp/v1");

        let url = relay_url_to_websocket("HTTPS://relay.example.com/path").unwrap();
        assert_eq!(url, "wss://relay.example.com/scp/v1");
    }
}
