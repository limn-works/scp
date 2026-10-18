//! The canonical relay URL of `09-security-model.md` §9.18.2.
//!
//! [`canonical_relay_url`] computes the eight steps of the **Canonical relay
//! URL** paragraph. Push preimages (§9.5.2) and the reserved push routing ID
//! (§10.7.1) end in this form, and `18-addressability-and-deployment.md`
//! §18.2.1 requires every `SCPRelay` entry's `serviceEndpoint` to have it, so
//! the function lives beside the DID document that carries those entries.

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
