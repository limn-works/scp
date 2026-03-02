//! Relay URL validation with provenance-based transport security (§10.12.6).
//!
//! Self-hosted relays behind NAT without a domain cannot obtain TLS
//! certificates. This module enforces that `ws://` (plaintext WebSocket)
//! is permitted **only** for relay URLs resolved from BEP44-signed DID
//! documents — the self-certifying path where TLS adds no authentication
//! benefit. MLS provides the confidentiality boundary (§10.5); TLS on the
//! relay connection is defense-in-depth, not the security layer.
//!
//! # Enforcement Rules (§10.12.6)
//!
//! | Relay type             | Discovery path              | Transport | TLS required |
//! |------------------------|-----------------------------|-----------|-------------|
//! | Domain-based           | `.well-known/scp` or config | `wss://`  | Yes (§9.13) |
//! | Self-hosted, no domain | DHT-resolved DID document   | `ws://`   | No          |
//! | Self-hosted, w/ domain | Either                      | `wss://`  | Yes         |
//!
//! `wss://` is always permitted regardless of source. `ws://` is rejected
//! for any source other than [`RelayUrlSource::DhtResolved`].

use crate::error::TransportError;

// ---------------------------------------------------------------------------
// RelayUrlSource
// ---------------------------------------------------------------------------

/// Provenance of a relay URL — tracks how the URL was discovered.
///
/// Determines whether `ws://` (plaintext WebSocket) is permitted per the
/// transport security rules in spec section 10.12.6. Only DHT-resolved
/// URLs may use `ws://`; all other sources require `wss://`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RelayUrlSource {
    /// Resolved from a BEP44-signed DID document via DHT or SCP relay QUERY.
    /// `ws://` is permitted — the DID document signature is the trust anchor,
    /// not a TLS certificate.
    DhtResolved,

    /// Discovered from `.well-known/scp` HTTP endpoint.
    /// `ws://` is NOT permitted — HTTP discovery lacks the self-certifying
    /// property of BEP44, enabling downgrade attacks.
    WellKnown,

    /// Explicitly configured by the user or operator.
    /// `ws://` is NOT permitted without DHT verification — only `wss://`.
    Explicit,

    /// Discovered from a peer within a context (e.g., relay recommendation).
    /// `ws://` is NOT permitted — peer-provided URLs are not self-certifying.
    PeerDiscovered,
}

impl std::fmt::Display for RelayUrlSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DhtResolved => write!(f, "DhtResolved"),
            Self::WellKnown => write!(f, "WellKnown"),
            Self::Explicit => write!(f, "Explicit"),
            Self::PeerDiscovered => write!(f, "PeerDiscovered"),
        }
    }
}

// ---------------------------------------------------------------------------
// SourcedRelayUrl
// ---------------------------------------------------------------------------

/// A relay URL paired with its discovery provenance.
///
/// The `source` field determines which transport security rules apply
/// when connecting to this URL (§10.12.6).
#[derive(Debug, Clone)]
pub struct SourcedRelayUrl {
    /// The relay WebSocket URL (e.g., `wss://relay.example.com/scp/v1`
    /// or `ws://203.0.113.42:8443/scp/v1`).
    pub url: String,

    /// How this URL was discovered — governs `ws://` vs `wss://` enforcement.
    pub source: RelayUrlSource,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates whether a relay URL is permitted given its discovery source.
///
/// Enforces the transport security rules from spec section 10.12.6:
///
/// - `wss://` is always permitted regardless of source.
/// - `ws://` is permitted only when `source` is [`RelayUrlSource::DhtResolved`].
/// - `ws://` from any other source is rejected to prevent downgrade attacks
///   where an attacker substitutes `ws://` URLs in HTTP-based discovery.
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if the URL scheme is not
/// permitted for the given source, with a descriptive error message.
pub fn validate_relay_url(url: &str, source: &RelayUrlSource) -> Result<(), TransportError> {
    let is_plaintext = url.starts_with("ws://");
    let is_secure = url.starts_with("wss://");

    if !is_plaintext && !is_secure {
        return Err(TransportError::ProtocolError(format!(
            "relay URL must use ws:// or wss:// scheme, got: {url}"
        )));
    }

    // wss:// is always permitted.
    if is_secure {
        return Ok(());
    }

    // ws:// is only permitted from DHT-resolved DID documents.
    match source {
        RelayUrlSource::DhtResolved => Ok(()),
        other => Err(TransportError::ProtocolError(format!(
            "ws:// relay URL rejected: plaintext WebSocket is only permitted for \
             DHT-resolved DID documents (§10.12.6), but source is {other}. \
             Use wss:// or verify via DHT."
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // --- ws:// validation ---

    #[test]
    fn ws_dht_resolved_is_permitted() {
        let result = validate_relay_url(
            "ws://203.0.113.42:8443/scp/v1",
            &RelayUrlSource::DhtResolved,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn ws_well_known_is_rejected() {
        let result =
            validate_relay_url("ws://203.0.113.42:8443/scp/v1", &RelayUrlSource::WellKnown);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ws://"), "error should mention ws://");
        assert!(err.contains("WellKnown"), "error should mention source");
    }

    #[test]
    fn ws_explicit_is_rejected() {
        let result = validate_relay_url("ws://203.0.113.42:8443/scp/v1", &RelayUrlSource::Explicit);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Explicit"));
    }

    #[test]
    fn ws_peer_discovered_is_rejected() {
        let result = validate_relay_url(
            "ws://203.0.113.42:8443/scp/v1",
            &RelayUrlSource::PeerDiscovered,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("PeerDiscovered"));
    }

    // --- wss:// validation (always permitted) ---

    #[test]
    fn wss_dht_resolved_is_permitted() {
        let result = validate_relay_url(
            "wss://relay.example.com/scp/v1",
            &RelayUrlSource::DhtResolved,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn wss_well_known_is_permitted() {
        let result =
            validate_relay_url("wss://relay.example.com/scp/v1", &RelayUrlSource::WellKnown);
        assert!(result.is_ok());
    }

    #[test]
    fn wss_explicit_is_permitted() {
        let result =
            validate_relay_url("wss://relay.example.com/scp/v1", &RelayUrlSource::Explicit);
        assert!(result.is_ok());
    }

    #[test]
    fn wss_peer_discovered_is_permitted() {
        let result = validate_relay_url(
            "wss://relay.example.com/scp/v1",
            &RelayUrlSource::PeerDiscovered,
        );
        assert!(result.is_ok());
    }

    // --- Invalid schemes ---

    #[test]
    fn http_scheme_is_rejected() {
        let result = validate_relay_url(
            "http://relay.example.com/scp/v1",
            &RelayUrlSource::DhtResolved,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ws:// or wss://"));
    }

    #[test]
    fn https_scheme_is_rejected() {
        let result = validate_relay_url(
            "https://relay.example.com/scp/v1",
            &RelayUrlSource::DhtResolved,
        );
        assert!(result.is_err());
    }

    // --- SourcedRelayUrl ---

    #[test]
    fn sourced_relay_url_construction() {
        let sourced = SourcedRelayUrl {
            url: "wss://relay.example.com/scp/v1".to_owned(),
            source: RelayUrlSource::WellKnown,
        };
        assert_eq!(sourced.source, RelayUrlSource::WellKnown);
        assert!(sourced.url.starts_with("wss://"));
    }

    // --- Display ---

    #[test]
    fn relay_url_source_display() {
        assert_eq!(RelayUrlSource::DhtResolved.to_string(), "DhtResolved");
        assert_eq!(RelayUrlSource::WellKnown.to_string(), "WellKnown");
        assert_eq!(RelayUrlSource::Explicit.to_string(), "Explicit");
        assert_eq!(RelayUrlSource::PeerDiscovered.to_string(), "PeerDiscovered");
    }

    // --- Edge cases ---

    #[test]
    fn ws_with_ip_literal_and_port() {
        let result = validate_relay_url(
            "ws://198.51.100.7:32891/scp/v1",
            &RelayUrlSource::DhtResolved,
        );
        assert!(
            result.is_ok(),
            "ws:// with IP literal should work for DhtResolved"
        );
    }

    #[test]
    fn wss_with_bridge_query_param() {
        // Tier 3 bridge URLs use wss:// with query params (§10.12.7).
        let result = validate_relay_url(
            "wss://bridge.example.com/scp/v1?bridge_target=deadbeef",
            &RelayUrlSource::DhtResolved,
        );
        assert!(result.is_ok());
    }
}
