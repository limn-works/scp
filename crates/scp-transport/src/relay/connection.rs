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

/// Returns `true` if the given URL targets a loopback address.
///
/// Recognizes `127.0.0.1`, `[::1]`, and `localhost` as loopback hosts.
/// Plaintext `ws://` is safe for these addresses because loopback traffic
/// cannot be intercepted by network attackers.
fn is_loopback_url(url: &str) -> bool {
    // Strip scheme prefix to get the authority portion.
    let after_scheme = if let Some(rest) = url.strip_prefix("ws://") {
        rest
    } else if let Some(rest) = url.strip_prefix("wss://") {
        rest
    } else {
        return false;
    };

    // The authority extends to the first `/` or the end of the string.
    let authority = after_scheme.split('/').next().unwrap_or("");

    // Strip userinfo (RFC 3986 §3.2.1) to prevent bypass via
    // `ws://127.0.0.1:password@evil.com` — the `@` is a userinfo
    // separator, so the actual connection target is `evil.com`.
    let authority = authority
        .rfind('@')
        .map_or(authority, |at_pos| &authority[at_pos + 1..]);

    // Strip port suffix (if present) to isolate the host.
    // Handle IPv6 bracket notation: `[::1]:8080` → host is `[::1]`.
    let host = if authority.starts_with('[') {
        // IPv6 literal: everything up to and including `]`.
        authority
            .split(']')
            .next()
            .map_or(authority, |h| h.strip_prefix('[').unwrap_or(h))
    } else {
        // IPv4 or hostname: strip `:port` suffix.
        authority.split(':').next().unwrap_or(authority)
    };

    host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost")
}

/// Validates whether a relay URL is permitted given its discovery source.
///
/// Enforces the transport security rules from spec section 10.12.6:
///
/// - `wss://` is always permitted regardless of source.
/// - `ws://` is permitted for loopback addresses (`127.0.0.1`, `[::1]`,
///   `localhost`) regardless of source — loopback traffic cannot be
///   intercepted by network attackers.
/// - `ws://` is permitted for [`RelayUrlSource::DhtResolved`] URLs
///   (self-hosted relays with BEP44-signed DID documents).
/// - `ws://` from any other source to a non-loopback host is rejected to
///   prevent downgrade attacks.
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

    // ws:// to loopback addresses is always safe — traffic stays on-host.
    if is_loopback_url(url) {
        return Ok(());
    }

    // ws:// to non-loopback hosts is only permitted from DHT-resolved DID
    // documents.
    match source {
        RelayUrlSource::DhtResolved => Ok(()),
        other => Err(TransportError::ProtocolError(format!(
            "ws:// relay URL rejected: plaintext WebSocket is only permitted for \
             loopback addresses or DHT-resolved DID documents (§10.12.6), but \
             source is {other} and host is not loopback. \
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

    // --- Loopback ws:// exemption ---

    #[test]
    fn ws_localhost_explicit_is_permitted() {
        // ws:// to 127.0.0.1 is safe regardless of source — loopback
        // traffic cannot be intercepted.
        let result = validate_relay_url("ws://127.0.0.1:9000/scp/v1", &RelayUrlSource::Explicit);
        assert!(
            result.is_ok(),
            "ws://127.0.0.1 should be permitted for any source"
        );
    }

    #[test]
    fn ws_localhost_hostname_explicit_is_permitted() {
        let result = validate_relay_url("ws://localhost:9000/scp/v1", &RelayUrlSource::Explicit);
        assert!(
            result.is_ok(),
            "ws://localhost should be permitted for any source"
        );
    }

    #[test]
    fn ws_ipv6_loopback_explicit_is_permitted() {
        let result = validate_relay_url("ws://[::1]:9000/scp/v1", &RelayUrlSource::Explicit);
        assert!(
            result.is_ok(),
            "ws://[::1] should be permitted for any source"
        );
    }

    #[test]
    fn ws_localhost_well_known_is_permitted() {
        let result = validate_relay_url("ws://127.0.0.1:8080/scp/v1", &RelayUrlSource::WellKnown);
        assert!(
            result.is_ok(),
            "ws://127.0.0.1 should be permitted even for WellKnown"
        );
    }

    #[test]
    fn ws_localhost_peer_discovered_is_permitted() {
        let result = validate_relay_url(
            "ws://localhost:8080/scp/v1",
            &RelayUrlSource::PeerDiscovered,
        );
        assert!(
            result.is_ok(),
            "ws://localhost should be permitted even for PeerDiscovered"
        );
    }

    #[test]
    fn ws_non_loopback_explicit_is_still_rejected() {
        // Non-loopback ws:// from Explicit must still be rejected.
        let result =
            validate_relay_url("ws://192.168.1.100:9000/scp/v1", &RelayUrlSource::Explicit);
        assert!(
            result.is_err(),
            "ws:// to non-loopback from Explicit must be rejected"
        );
    }

    // --- is_loopback_url unit tests ---

    #[test]
    fn is_loopback_ipv4() {
        assert!(is_loopback_url("ws://127.0.0.1:9000/scp/v1"));
        assert!(is_loopback_url("ws://127.0.0.1/scp/v1"));
        assert!(is_loopback_url("wss://127.0.0.1:443/scp/v1"));
    }

    #[test]
    fn is_loopback_localhost() {
        assert!(is_loopback_url("ws://localhost:9000/scp/v1"));
        assert!(is_loopback_url("ws://localhost/scp/v1"));
        assert!(is_loopback_url("ws://LOCALHOST:9000/scp/v1")); // case insensitive
    }

    #[test]
    fn is_loopback_ipv6() {
        assert!(is_loopback_url("ws://[::1]:9000/scp/v1"));
        assert!(is_loopback_url("ws://[::1]/scp/v1"));
    }

    #[test]
    fn is_not_loopback() {
        assert!(!is_loopback_url("ws://192.168.1.1:9000/scp/v1"));
        assert!(!is_loopback_url("ws://relay.example.com/scp/v1"));
        assert!(!is_loopback_url("ws://10.0.0.1:9000/scp/v1"));
        assert!(!is_loopback_url("ftp://127.0.0.1/file")); // wrong scheme
    }

    // --- Userinfo bypass (CVE-style) ---

    #[test]
    fn is_loopback_rejects_userinfo_bypass() {
        // The `@` is a userinfo separator per RFC 3986 §3.2.1.
        // `ws://127.0.0.1:password@evil.com` connects to evil.com, not 127.0.0.1.
        assert!(!is_loopback_url("ws://127.0.0.1:password@evil.com/scp/v1"));
        assert!(!is_loopback_url("ws://127.0.0.1@evil.com:9000/scp/v1"));
    }

    #[test]
    fn is_loopback_allows_userinfo_to_loopback() {
        // After stripping userinfo, the host is still 127.0.0.1 — safe.
        // The userinfo would be sent as HTTP Basic Auth in the upgrade request.
        assert!(is_loopback_url("ws://user:pass@127.0.0.1:9000/scp/v1"));
    }

    // --- Non-primary loopback and wildcard addresses ---

    #[test]
    fn is_not_loopback_secondary_and_wildcard() {
        // 127.0.0.2 is technically loopback on Linux, but we only allow
        // 127.0.0.1 — matching the canonical loopback address.
        assert!(!is_loopback_url("ws://127.0.0.2:9000/scp/v1"));
        // 0.0.0.0 binds all interfaces — not a safe loopback target.
        assert!(!is_loopback_url("ws://0.0.0.0:9000/scp/v1"));
    }
}
