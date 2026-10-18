//! The canonical relay URL of `09-security-model.md` §9.18.2, and the relay
//! URLs an `SCPRelay` entry may carry.
//!
//! [`canonical_relay_url`] computes the eight steps of the **Canonical relay
//! URL** paragraph. Push preimages (§9.5.2) and the reserved push routing ID
//! (§10.7.1) end in this form, and `18-addressability-and-deployment.md`
//! §18.2.1 requires every `SCPRelay` entry's `serviceEndpoint` to have it, so
//! the function lives beside the DID document that carries those entries.
//! [`RelayEndpoint`] and [`BridgeEndpoint`] hold a URL that passed §18.2.1's
//! URL rules, so a relay entry built from one cannot fail them.

use crate::document::DidError;

/// Why a relay URL has no §9.18.2 canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayUrlError {
    /// The scheme is missing or is neither `ws` nor `wss`.
    #[error("relay URL scheme must be ws or wss")]
    UnsupportedScheme,
    /// The URL holds a byte outside printable ASCII (`0x21..=0x7E`).
    #[error("relay URL holds a byte outside printable ASCII")]
    InvalidCharacter,
    /// The URL carries a query or a fragment, which a canonical URL never holds.
    #[error("relay URL carries a query or fragment")]
    QueryOrFragment,
    /// The authority carries user information (`user@host`).
    #[error("relay URL carries user information")]
    UserInfo,
    /// The authority has no host.
    #[error("relay URL has no host")]
    MissingHost,
    /// The host holds a character no DNS name or bracketed IPv6 literal holds.
    #[error("relay URL host is malformed")]
    InvalidHost,
    /// The port is empty, non-numeric, zero, or above 65535.
    #[error("relay URL port is malformed")]
    InvalidPort,
    /// The path still ends with `/` after §9.18.2 removes one trailing `/`,
    /// so canonicalizing the result again would change it.
    #[error("relay URL path ends with an empty segment")]
    TrailingEmptySegment,
}

/// Why `18-addressability-and-deployment.md` §18.2.1 rejects a relay entry's
/// URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayEntryUrlError {
    /// The URL has no §9.18.2 canonical form.
    #[error(transparent)]
    Canonical(#[from] RelayUrlError),
    /// The canonical path does not end in `/scp/v1` (§18.2.1, ADR-004).
    #[error("relay URL canonical path does not end in {SCP_RELAY_PATH}")]
    PathNotScpV1,
    /// A tier 3 bridge relay URL uses `ws`, but a bridge relay is reached
    /// over TLS (`10-infrastructure-and-self-hosting.md` §10.12.7).
    #[error("bridge relay URL scheme must be wss")]
    PlaintextBridge,
}

/// The path every `SCPRelay` URL's canonical form ends in (§18.2.1, ADR-004).
pub const SCP_RELAY_PATH: &str = "/scp/v1";

/// A relay URL an `SCPRelay` entry may carry: it has a §9.18.2 canonical form,
/// and that form's path ends in `/scp/v1` (§18.2.1).
///
/// [`RelayEndpoint::new`] is the only constructor, and the value holds the
/// canonical form, so every spelling of one relay yields one endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayEndpoint {
    canonical: String,
}

impl RelayEndpoint {
    /// Canonicalizes `url` and checks its path.
    ///
    /// # Errors
    ///
    /// [`DidError::InvalidRelayUrl`] with reason
    /// [`RelayEntryUrlError::Canonical`] when `url` has no §9.18.2 canonical
    /// form (a scheme other than `ws` or `wss`, a query, a fragment, or user
    /// information among the causes), or [`RelayEntryUrlError::PathNotScpV1`]
    /// when the canonical path does not end in `/scp/v1`.
    pub fn new(url: &str) -> Result<Self, DidError> {
        let canonical = canonical_relay_url(url).map_err(|e| invalid_relay_url(url, e.into()))?;
        // The canonical form is `scheme://authority[path]`; the path starts at
        // the first `/` after the authority, so a host spelled `scp` never
        // passes as the path.
        let after_scheme = canonical.split_once("://").map_or("", |(_, rest)| rest);
        let path = after_scheme.find('/').map_or("", |i| &after_scheme[i..]);
        if !path.ends_with(SCP_RELAY_PATH) {
            return Err(invalid_relay_url(url, RelayEntryUrlError::PathNotScpV1));
        }
        Ok(Self { canonical })
    }

    /// The §9.18.2 canonical URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Whether the scheme is `wss`. The canonical form lowercases the scheme.
    fn is_tls(&self) -> bool {
        self.canonical.starts_with("wss://")
    }
}

/// A tier 3 bridge relay's URL: a [`RelayEndpoint`] whose scheme is `wss`
/// (`10-infrastructure-and-self-hosting.md` §10.12.7).
///
/// [`BridgeEndpoint::new`] is the only public constructor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeEndpoint(RelayEndpoint);

impl BridgeEndpoint {
    /// Validates `url` as a [`RelayEndpoint`] and requires `wss`.
    ///
    /// # Errors
    ///
    /// Every error of [`RelayEndpoint::new`], and
    /// [`DidError::InvalidRelayUrl`] with reason
    /// [`RelayEntryUrlError::PlaintextBridge`] when the scheme is `ws`.
    pub fn new(url: &str) -> Result<Self, DidError> {
        Self::from_endpoint(RelayEndpoint::new(url)?)
    }

    /// Requires `endpoint`'s scheme to be `wss`.
    pub(crate) fn from_endpoint(endpoint: RelayEndpoint) -> Result<Self, DidError> {
        if endpoint.is_tls() {
            Ok(Self(endpoint))
        } else {
            Err(invalid_relay_url(
                endpoint.as_str(),
                RelayEntryUrlError::PlaintextBridge,
            ))
        }
    }

    /// The bridge relay's endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &RelayEndpoint {
        &self.0
    }

    /// Consumes the value and returns the bridge relay's endpoint.
    #[must_use]
    pub fn into_endpoint(self) -> RelayEndpoint {
        self.0
    }

    /// The §9.18.2 canonical URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// [`DidError::InvalidRelayUrl`] for `url`, with any user information removed
/// so the error never repeats a credential.
fn invalid_relay_url(url: &str, reason: RelayEntryUrlError) -> DidError {
    DidError::InvalidRelayUrl {
        url: without_userinfo(url),
        reason,
    }
}

/// `url` with any `user@` part of its authority removed.
fn without_userinfo(url: &str) -> String {
    let (scheme, rest) = url
        .split_once("://")
        .map_or((None, url), |(scheme, rest)| (Some(scheme), rest));
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    scheme.map_or_else(
        || format!("{host}{tail}"),
        |scheme| format!("{scheme}://{host}{tail}"),
    )
}

/// Returns the canonical form of a relay's WebSocket URL, computed by the
/// eight steps of the **Canonical relay URL** paragraph of §9.18.2.
///
/// # Errors
///
/// Returns the [`RelayUrlError`] that names the defect.
pub fn canonical_relay_url(relay_url: &str) -> Result<String, RelayUrlError> {
    let (scheme, rest) = relay_url
        .split_once("://")
        .ok_or(RelayUrlError::UnsupportedScheme)?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "wss" => 443,
        "ws" => 80,
        _ => return Err(RelayUrlError::UnsupportedScheme),
    };
    if !rest.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(RelayUrlError::InvalidCharacter);
    }
    if rest.contains(['?', '#']) {
        return Err(RelayUrlError::QueryOrFragment);
    }
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if authority.contains('@') {
        return Err(RelayUrlError::UserInfo);
    }

    let (host, port) = split_host_port(authority)?;
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RelayUrlError::InvalidPort);
            }
            let n: u16 = p.parse().map_err(|_| RelayUrlError::InvalidPort)?;
            if n == 0 {
                return Err(RelayUrlError::InvalidPort);
            }
            (n != default_port).then_some(n)
        }
    };

    let path = path.strip_suffix('/').unwrap_or(path);
    if path.ends_with('/') {
        return Err(RelayUrlError::TrailingEmptySegment);
    }

    let mut out = String::with_capacity(relay_url.len());
    out.push_str(&scheme);
    out.push_str("://");
    out.push_str(&host.to_ascii_lowercase());
    if let Some(n) = port {
        out.push(':');
        out.push_str(&n.to_string());
    }
    out.push_str(path);
    Ok(out)
}

/// Splits an authority into its host and its optional port text, and checks
/// the host's characters.
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), RelayUrlError> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(RelayUrlError::InvalidHost)?;
        let (host, after) = authority.split_at(end + 1);
        let inner = &host[1..host.len() - 1];
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(RelayUrlError::InvalidHost);
        }
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(RelayUrlError::InvalidHost)?),
        };
        (host, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        {
            return Err(RelayUrlError::InvalidHost);
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(RelayUrlError::MissingHost);
    }
    Ok((host, port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn canonical_relay_url_applies_section_9_18_2() {
        let cases = [
            ("WSS://Relay.Example:443/", "wss://relay.example"),
            ("wss://relay.example", "wss://relay.example"),
            ("ws://Relay.Example:80", "ws://relay.example"),
            ("ws://relay.example:443", "ws://relay.example:443"),
            ("wss://relay.example:80/", "wss://relay.example:80"),
            ("wss://relay.example:00443", "wss://relay.example"),
            ("wss://relay.example/scp/v1", "wss://relay.example/scp/v1"),
            ("wss://relay.example/Scp/V1/", "wss://relay.example/Scp/V1"),
            ("wss://[2001:DB8::1]:8443/", "wss://[2001:db8::1]:8443"),
            ("wss://[::1]", "wss://[::1]"),
        ];
        for (input, want) in cases {
            let got = canonical_relay_url(input).unwrap();
            assert_eq!(got, want, "{input}");
            assert_eq!(canonical_relay_url(&got).unwrap(), got, "fixed point");
        }
    }

    /// The rows of the §9.18.2 **Canonical relay URL** vector table, in order;
    /// each rejected row maps to the error of the step that rejects it.
    #[test]
    fn canonical_relay_url_reproduces_section_9_18_2_vectors() {
        let cases: [(&str, Result<&str, RelayUrlError>); 14] = [
            ("WSS://Relay.Example:443/", Ok("wss://relay.example")),
            ("ws://Relay.Example:80", Ok("ws://relay.example")),
            ("ws://relay.example:443", Ok("ws://relay.example:443")),
            ("wss://relay.example:00443", Ok("wss://relay.example")),
            ("wss://relay.example:08443", Ok("wss://relay.example:8443")),
            (
                "wss://relay.example/Scp/V1/",
                Ok("wss://relay.example/Scp/V1"),
            ),
            ("wss://[2001:DB8::1]:8443/", Ok("wss://[2001:db8::1]:8443")),
            (
                "https://relay.example",
                Err(RelayUrlError::UnsupportedScheme),
            ),
            ("wss://relay.exämple", Err(RelayUrlError::InvalidCharacter)),
            (
                "wss://relay.example/?k=v",
                Err(RelayUrlError::QueryOrFragment),
            ),
            ("wss://u@relay.example", Err(RelayUrlError::UserInfo)),
            ("wss://re*lay", Err(RelayUrlError::InvalidHost)),
            ("wss://relay.example:0", Err(RelayUrlError::InvalidPort)),
            (
                "wss://relay.example//",
                Err(RelayUrlError::TrailingEmptySegment),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(
                canonical_relay_url(input).as_deref(),
                want.map(str::to_owned).as_deref(),
                "{input}"
            );
        }
    }

    #[test]
    fn canonical_relay_url_rejects_malformed_input() {
        let cases = [
            ("relay.example", RelayUrlError::UnsupportedScheme),
            ("https://relay.example", RelayUrlError::UnsupportedScheme),
            ("://relay.example", RelayUrlError::UnsupportedScheme),
            ("wss://", RelayUrlError::MissingHost),
            ("wss:///path", RelayUrlError::MissingHost),
            ("wss://:443", RelayUrlError::MissingHost),
            ("wss://relay.example?x=1", RelayUrlError::QueryOrFragment),
            ("wss://relay.example/#f", RelayUrlError::QueryOrFragment),
            ("wss://u@relay.example", RelayUrlError::UserInfo),
            ("wss://relay example", RelayUrlError::InvalidCharacter),
            ("wss://relay.exämple", RelayUrlError::InvalidCharacter),
            ("wss://relay.example:", RelayUrlError::InvalidPort),
            ("wss://relay.example:0", RelayUrlError::InvalidPort),
            ("wss://relay.example:65536", RelayUrlError::InvalidPort),
            ("wss://relay.example:44a", RelayUrlError::InvalidPort),
            ("wss://relay.example:1:2", RelayUrlError::InvalidPort),
            ("wss://[::1", RelayUrlError::InvalidHost),
            ("wss://[]", RelayUrlError::InvalidHost),
            ("wss://[::1]x", RelayUrlError::InvalidHost),
            ("wss://re*lay", RelayUrlError::InvalidHost),
            ("wss://relay.example//", RelayUrlError::TrailingEmptySegment),
        ];
        for (input, want) in cases {
            assert_eq!(canonical_relay_url(input), Err(want), "{input}");
        }
    }
}
