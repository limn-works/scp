//! The canonical node URL of `09-security-model.md` §9.18.2, and the node
//! URLs a service entry may carry.
//!
//! [`canonical_node_url`] computes the steps of the **Canonical node URL**
//! paragraph of §9.18.2. Push preimages (§9.5.2) and the reserved push routing
//! ID (§10.7.1) end in this form, and `18-addressability-and-deployment.md`
//! §18.2.1 requires every node entry's `serviceEndpoint` to have it, so the
//! function lives beside the DID document that carries those entries.
//! [`NodeUrl`], the node URL of `03-identity.md` §3.10.10, and
//! [`BridgeEndpoint`] hold a URL that passed §18.2.1's URL rules, so an entry
//! built from one cannot fail them.

use crate::document::DidError;

/// Why a node URL has no §9.18.2 canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NodeUrlError {
    /// The scheme is missing or is neither `ws` nor `wss`.
    #[error("node URL scheme must be ws or wss")]
    UnsupportedScheme,
    /// The URL holds a byte outside printable ASCII (`0x21..=0x7E`).
    #[error("node URL holds a byte outside printable ASCII")]
    InvalidCharacter,
    /// The URL carries a query or a fragment, which a canonical URL never holds.
    #[error("node URL carries a query or fragment")]
    QueryOrFragment,
    /// The authority carries user information (`user@host`).
    #[error("node URL carries user information")]
    UserInfo,
    /// The authority has no host.
    #[error("node URL has no host")]
    MissingHost,
    /// The host holds a character no DNS name or bracketed IPv6 literal holds.
    #[error("node URL host is malformed")]
    InvalidHost,
    /// The port is empty, non-numeric, zero, or above 65535.
    #[error("node URL port is malformed")]
    InvalidPort,
    /// The path still ends with `/` after §9.18.2 removes one trailing `/`,
    /// so canonicalizing the result again would change it.
    #[error("node URL path ends with an empty segment")]
    TrailingEmptySegment,
}

/// Why `18-addressability-and-deployment.md` §18.2.1 rejects a node entry's
/// URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NodeEntryUrlError {
    /// The URL has no §9.18.2 canonical form.
    #[error(transparent)]
    Canonical(#[from] NodeUrlError),
    /// The canonical path does not end in `/scp/v1` (§18.2.1, ADR-004).
    #[error("node URL canonical path does not end in {SCP_NODE_PATH}")]
    PathNotScpV1,
    /// A tier 3 bridge node URL uses `ws`, but a bridge node is reached
    /// over TLS (`10-infrastructure-and-self-hosting.md` §10.12.7).
    #[error("bridge node URL scheme must be wss")]
    PlaintextBridge,
}

/// The path every node URL's canonical form ends in (§18.2.1, ADR-004).
pub const SCP_NODE_PATH: &str = "/scp/v1";

/// A node's canonical URL (`03-identity.md` §3.10.10 `NodeUrl`): it has a
/// §9.18.2 canonical form, and that form's path ends in `/scp/v1` (§18.2.1).
///
/// [`NodeUrl::new`] is the only constructor, and the value holds the
/// canonical form, so every spelling of one node's URL yields one value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeUrl {
    canonical: String,
}

impl NodeUrl {
    /// Canonicalizes `url` and checks its path.
    ///
    /// # Errors
    ///
    /// [`DidError::InvalidNodeUrl`] with reason
    /// [`NodeEntryUrlError::Canonical`] when `url` has no §9.18.2 canonical
    /// form (a scheme other than `ws` or `wss`, a query, a fragment, or user
    /// information among the causes), or [`NodeEntryUrlError::PathNotScpV1`]
    /// when the canonical path does not end in `/scp/v1`.
    pub fn new(url: &str) -> Result<Self, DidError> {
        let canonical = canonical_node_url(url).map_err(|e| invalid_node_url(url, e.into()))?;
        // The canonical form is `scheme://authority[path]`; the path starts at
        // the first `/` after the authority, so a host spelled `scp` never
        // passes as the path.
        let after_scheme = canonical.split_once("://").map_or("", |(_, rest)| rest);
        let path = after_scheme.find('/').map_or("", |i| &after_scheme[i..]);
        if !path.ends_with(SCP_NODE_PATH) {
            return Err(invalid_node_url(url, NodeEntryUrlError::PathNotScpV1));
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

/// A tier 3 bridge node's URL: a [`NodeUrl`] whose scheme is `wss`
/// (`10-infrastructure-and-self-hosting.md` §10.12.7).
///
/// [`BridgeEndpoint::new`] is the only public constructor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeEndpoint(NodeUrl);

impl BridgeEndpoint {
    /// Validates `url` as a [`NodeUrl`] and requires `wss`.
    ///
    /// # Errors
    ///
    /// Every error of [`NodeUrl::new`], and
    /// [`DidError::InvalidNodeUrl`] with reason
    /// [`NodeEntryUrlError::PlaintextBridge`] when the scheme is `ws`.
    pub fn new(url: &str) -> Result<Self, DidError> {
        Self::from_endpoint(NodeUrl::new(url)?)
    }

    /// Requires `endpoint`'s scheme to be `wss`.
    pub(crate) fn from_endpoint(endpoint: NodeUrl) -> Result<Self, DidError> {
        if endpoint.is_tls() {
            Ok(Self(endpoint))
        } else {
            Err(invalid_node_url(
                endpoint.as_str(),
                NodeEntryUrlError::PlaintextBridge,
            ))
        }
    }

    /// The bridge node's endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &NodeUrl {
        &self.0
    }

    /// Consumes the value and returns the bridge node's endpoint.
    #[must_use]
    pub fn into_endpoint(self) -> NodeUrl {
        self.0
    }

    /// The §9.18.2 canonical URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// [`DidError::InvalidNodeUrl`] for `url`, with any user information removed
/// so the error never repeats a credential.
fn invalid_node_url(url: &str, reason: NodeEntryUrlError) -> DidError {
    DidError::InvalidNodeUrl {
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

/// Returns the canonical form of a node's WebSocket URL, computed by the
/// steps of the **Canonical node URL** paragraph of §9.18.2.
///
/// # Errors
///
/// Returns the [`NodeUrlError`] that names the defect.
pub fn canonical_node_url(url: &str) -> Result<String, NodeUrlError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or(NodeUrlError::UnsupportedScheme)?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "wss" => 443,
        "ws" => 80,
        _ => return Err(NodeUrlError::UnsupportedScheme),
    };
    if !rest.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(NodeUrlError::InvalidCharacter);
    }
    if rest.contains(['?', '#']) {
        return Err(NodeUrlError::QueryOrFragment);
    }
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if authority.contains('@') {
        return Err(NodeUrlError::UserInfo);
    }

    let (host, port) = split_host_port(authority)?;
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(NodeUrlError::InvalidPort);
            }
            let n: u16 = p.parse().map_err(|_| NodeUrlError::InvalidPort)?;
            if n == 0 {
                return Err(NodeUrlError::InvalidPort);
            }
            (n != default_port).then_some(n)
        }
    };

    let path = path.strip_suffix('/').unwrap_or(path);
    if path.ends_with('/') {
        return Err(NodeUrlError::TrailingEmptySegment);
    }

    let mut out = String::with_capacity(url.len());
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
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), NodeUrlError> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(NodeUrlError::InvalidHost)?;
        let (host, after) = authority.split_at(end + 1);
        let inner = &host[1..host.len() - 1];
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(NodeUrlError::InvalidHost);
        }
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(NodeUrlError::InvalidHost)?),
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
            return Err(NodeUrlError::InvalidHost);
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(NodeUrlError::MissingHost);
    }
    Ok((host, port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `18-addressability-and-deployment.md` §18.2.1: a node URL's canonical
    /// path ends in `/scp/v1`, and construction refuses any other path.
    #[test]
    fn node_url_new_accepts_scp_v1_and_refuses_another_path() {
        let url = NodeUrl::new("WSS://Node.Example:443/scp/v1/").unwrap();
        assert_eq!(url.as_str(), "wss://node.example/scp/v1");
        assert_eq!(
            NodeUrl::new("wss://node.example/scp/v2"),
            Err(DidError::InvalidNodeUrl {
                url: "wss://node.example/scp/v2".to_owned(),
                reason: NodeEntryUrlError::PathNotScpV1,
            })
        );
    }

    #[test]
    fn canonical_node_url_applies_section_9_18_2() {
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
            let got = canonical_node_url(input).unwrap();
            assert_eq!(got, want, "{input}");
            assert_eq!(canonical_node_url(&got).unwrap(), got, "fixed point");
        }
    }

    /// The rows of the §9.18.2 **Canonical node URL** vector table, in order;
    /// each rejected row maps to the error of the step that rejects it.
    #[test]
    fn canonical_node_url_reproduces_section_9_18_2_vectors() {
        let cases: [(&str, Result<&str, NodeUrlError>); 14] = [
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
                Err(NodeUrlError::UnsupportedScheme),
            ),
            ("wss://relay.exämple", Err(NodeUrlError::InvalidCharacter)),
            (
                "wss://relay.example/?k=v",
                Err(NodeUrlError::QueryOrFragment),
            ),
            ("wss://u@relay.example", Err(NodeUrlError::UserInfo)),
            ("wss://re*lay", Err(NodeUrlError::InvalidHost)),
            ("wss://relay.example:0", Err(NodeUrlError::InvalidPort)),
            (
                "wss://relay.example//",
                Err(NodeUrlError::TrailingEmptySegment),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(
                canonical_node_url(input).as_deref(),
                want.map(str::to_owned).as_deref(),
                "{input}"
            );
        }
    }

    #[test]
    fn canonical_node_url_rejects_malformed_input() {
        let cases = [
            ("relay.example", NodeUrlError::UnsupportedScheme),
            ("https://relay.example", NodeUrlError::UnsupportedScheme),
            ("://relay.example", NodeUrlError::UnsupportedScheme),
            ("wss://", NodeUrlError::MissingHost),
            ("wss:///path", NodeUrlError::MissingHost),
            ("wss://:443", NodeUrlError::MissingHost),
            ("wss://relay.example?x=1", NodeUrlError::QueryOrFragment),
            ("wss://relay.example/#f", NodeUrlError::QueryOrFragment),
            ("wss://u@relay.example", NodeUrlError::UserInfo),
            ("wss://relay example", NodeUrlError::InvalidCharacter),
            ("wss://relay.exämple", NodeUrlError::InvalidCharacter),
            ("wss://relay.example:", NodeUrlError::InvalidPort),
            ("wss://relay.example:0", NodeUrlError::InvalidPort),
            ("wss://relay.example:65536", NodeUrlError::InvalidPort),
            ("wss://relay.example:44a", NodeUrlError::InvalidPort),
            ("wss://relay.example:1:2", NodeUrlError::InvalidPort),
            ("wss://[::1", NodeUrlError::InvalidHost),
            ("wss://[]", NodeUrlError::InvalidHost),
            ("wss://[::1]x", NodeUrlError::InvalidHost),
            ("wss://re*lay", NodeUrlError::InvalidHost),
            ("wss://relay.example//", NodeUrlError::TrailingEmptySegment),
        ];
        for (input, want) in cases {
            assert_eq!(canonical_node_url(input), Err(want), "{input}");
        }
    }
}
