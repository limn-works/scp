//! Transport configuration and relay bootstrap resolution.
//!
//! [`TransportConfig`] is the configuration struct passed to
//! [`TransportManager`](crate::TransportManager) at initialization. It carries
//! explicit relay URLs, an optional bootstrap domain for `.well-known/scp`
//! discovery, and deduplication cache parameters.
//!
//! [`ResolveRelays`] defines the async relay resolution contract.
//! [`DefaultRelayResolver`] implements the 5-level bootstrap priority chain
//! specified in spec section 18.5.1:
//!
//! 1. Explicit `relay_urls` from [`TransportConfig`]
//! 2. DID document `SCPRelay` service entries
//! 3. `.well-known/scp` resolution from `bootstrap_domain`
//! 4. Peer relay discovery from shared contexts
//! 5. Hardcoded fallback relay list
//!
//! Each level is tried in order. The first level yielding at least one relay
//! URL is used.
//!
//! See ADR-032 in `.docs/adrs/phase-2.md` and spec section 18.5 for the full
//! relay bootstrap design.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::error::TransportError;

// ---------------------------------------------------------------------------
// TransportConfig
// ---------------------------------------------------------------------------

/// Default deduplication cache capacity (number of entries).
///
/// See ADR-012 acceptance criterion 3 for the rationale behind 10,000 entries.
const DEFAULT_DEDUP_CACHE_SIZE: usize = 10_000;

/// Default deduplication cache entry TTL.
///
/// Entries older than this duration are evicted even if the capacity has not
/// been reached. This prevents stale entries from consuming memory in
/// low-throughput scenarios.
const DEFAULT_DEDUP_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Transport layer configuration.
///
/// Passed to [`TransportManager::with_config`](crate::TransportManager::with_config)
/// at initialization. Carries explicit relay URLs, an optional bootstrap
/// domain for `.well-known/scp` discovery, and deduplication cache parameters.
///
/// # Defaults
///
/// ```rust
/// use scp_transport::config::TransportConfig;
/// use std::time::Duration;
///
/// let config = TransportConfig::default();
/// assert!(config.relay_urls.is_empty());
/// assert!(config.bootstrap_domain.is_none());
/// assert_eq!(config.dedup_cache_size, 10_000);
/// assert_eq!(config.dedup_cache_ttl, Duration::from_secs(3600));
/// ```
///
/// See ADR-032 in `.docs/adrs/phase-2.md` for the full design.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Explicit relay URLs provided at SDK initialization.
    ///
    /// Highest trust level in the bootstrap priority chain (section 18.5.1
    /// level 1). When non-empty, the resolver returns these URLs without
    /// trying lower priority levels.
    pub relay_urls: Vec<String>,

    /// Optional domain for `.well-known/scp` relay discovery.
    ///
    /// When set, the resolver fetches `https://<domain>/.well-known/scp` and
    /// extracts the `relay` field (section 18.3). This is priority level 3
    /// in the bootstrap chain.
    pub bootstrap_domain: Option<String>,

    /// Maximum number of entries in the deduplication cache.
    ///
    /// The dedup cache tracks recently seen [`BlobId`](crate::BlobId) values
    /// to prevent duplicate envelope delivery in merged subscription streams.
    /// Defaults to 10,000 entries (ADR-012 acceptance criterion 3).
    pub dedup_cache_size: usize,

    /// Time-to-live for deduplication cache entries.
    ///
    /// Entries older than this duration are evicted even if the cache has not
    /// reached capacity. Defaults to 1 hour. This prevents stale entries from
    /// consuming memory in low-throughput scenarios and ensures that a slow
    /// relay delivering a blob after the LRU entry was evicted does not bypass
    /// deduplication.
    pub dedup_cache_ttl: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            relay_urls: Vec::new(),
            bootstrap_domain: None,
            dedup_cache_size: DEFAULT_DEDUP_CACHE_SIZE,
            dedup_cache_ttl: DEFAULT_DEDUP_CACHE_TTL,
        }
    }
}

impl TransportConfig {
    /// Creates a new `TransportConfig` with explicit relay URLs.
    ///
    /// All other fields use their defaults.
    #[must_use]
    pub fn with_relay_urls(relay_urls: Vec<String>) -> Self {
        Self {
            relay_urls,
            ..Self::default()
        }
    }

    /// Creates a new `TransportConfig` with a bootstrap domain.
    ///
    /// All other fields use their defaults.
    #[must_use]
    pub fn with_bootstrap_domain(domain: String) -> Self {
        Self {
            bootstrap_domain: Some(domain),
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// ResolveRelays trait
// ---------------------------------------------------------------------------

/// A boxed, pinned, `Send`-safe future -- the return type for
/// [`ResolveRelays::resolve`] to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for resolving relay URLs at transport initialization.
///
/// Implementations follow the bootstrap priority chain in spec section 18.5.1.
/// The trait is dyn-compatible (`BoxFuture` return) so callers can inject mock
/// resolvers for testing.
///
/// See ADR-032 in `.docs/adrs/phase-2.md` for the full design.
pub trait ResolveRelays: Send + Sync {
    /// Resolves relay URLs according to the implementation's priority chain.
    ///
    /// Returns at least one relay URL on success. Returns
    /// [`TransportError::ConnectionFailed`] if no relays can be discovered
    /// at any priority level.
    fn resolve(&self) -> BoxFuture<'_, Result<Vec<String>, TransportError>>;
}

// ---------------------------------------------------------------------------
// DefaultRelayResolver
// ---------------------------------------------------------------------------

/// Hardcoded fallback relay list (section 18.5.1 level 5).
///
/// Last resort. These relays are not privileged -- they are default
/// suggestions that can be overridden. The list includes at least one free
/// relay per the protocol invariant that prevents economic gatekeeping of
/// basic protocol operation (section 19.8, section 19.14).
const FALLBACK_RELAYS: &[&str] = &["wss://relay.scp.community/scp/v1"];

/// Default relay resolver implementing the 5-level bootstrap priority chain.
///
/// Priority order (spec section 18.5.1):
///
/// 1. **Explicit configuration** -- `relay_urls` from [`TransportConfig`].
/// 2. **DID document resolution** -- `SCPRelay` service entries from the
///    identity's DID document resolved via Mainline DHT.
/// 3. **`.well-known/scp` resolution** -- fetch the relay URL from the
///    configured `bootstrap_domain`.
/// 4. **Peer relay discovery** -- relay URLs from peers in shared contexts.
/// 5. **Fallback relay list** -- hardcoded community relays.
///
/// Each level is tried in order. The first level that yields at least one
/// relay URL is used. The SDK logs a warning when falling through to the
/// hardcoded fallback (acceptance criterion).
///
/// # Extensibility
///
/// Levels 2 and 4 depend on DID resolution and context state that are not
/// available inside the transport crate. The resolver accepts optional
/// provider callbacks via [`DefaultRelayResolver::with_did_resolver`] and
/// [`DefaultRelayResolver::with_peer_provider`]. When these callbacks are not
/// set, the corresponding levels are skipped.
///
/// Level 3 (`.well-known/scp`) requires an HTTP fetch. The resolver accepts
/// an optional callback via
/// [`DefaultRelayResolver::with_well_known_fetcher`]. When not set, level 3
/// is skipped.
pub struct DefaultRelayResolver {
    /// The transport configuration providing explicit relay URLs and
    /// bootstrap domain.
    config: TransportConfig,

    /// Optional callback to resolve DID document relay URLs (level 2).
    did_resolver: Option<Box<dyn Fn() -> BoxFuture<'static, Vec<String>> + Send + Sync>>,

    /// Optional callback to fetch `.well-known/scp` relay URL (level 3).
    ///
    /// Receives the bootstrap domain and returns the relay URL extracted
    /// from the `.well-known/scp` JSON document.
    well_known_fetcher:
        Option<Box<dyn Fn(&str) -> BoxFuture<'static, Option<String>> + Send + Sync>>,

    /// Optional callback to discover relays from peers in shared contexts
    /// (level 4).
    peer_provider: Option<Box<dyn Fn() -> BoxFuture<'static, Vec<String>> + Send + Sync>>,
}

impl DefaultRelayResolver {
    /// Creates a new `DefaultRelayResolver` with the given configuration.
    ///
    /// Without provider callbacks, only levels 1 (explicit) and 5 (fallback)
    /// are available. Use the `with_*` methods to enable additional levels.
    #[must_use]
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            did_resolver: None,
            well_known_fetcher: None,
            peer_provider: None,
        }
    }

    /// Sets the DID document resolver callback (level 2).
    ///
    /// The callback should resolve the identity's own DID document via
    /// Mainline DHT and return `SCPRelay` service endpoint URLs.
    #[must_use]
    pub fn with_did_resolver(
        mut self,
        resolver: Box<dyn Fn() -> BoxFuture<'static, Vec<String>> + Send + Sync>,
    ) -> Self {
        self.did_resolver = Some(resolver);
        self
    }

    /// Sets the `.well-known/scp` fetcher callback (level 3).
    ///
    /// The callback receives a bootstrap domain and should fetch
    /// `https://<domain>/.well-known/scp`, extract the `relay` field, and
    /// return it. Returns `None` if the fetch fails or the document is
    /// invalid.
    #[must_use]
    pub fn with_well_known_fetcher(
        mut self,
        fetcher: Box<dyn Fn(&str) -> BoxFuture<'static, Option<String>> + Send + Sync>,
    ) -> Self {
        self.well_known_fetcher = Some(fetcher);
        self
    }

    /// Sets the peer relay discovery callback (level 4).
    ///
    /// The callback should resolve relay URLs from peers in shared contexts
    /// by inspecting their DID documents for overlapping relay sets.
    #[must_use]
    pub fn with_peer_provider(
        mut self,
        provider: Box<dyn Fn() -> BoxFuture<'static, Vec<String>> + Send + Sync>,
    ) -> Self {
        self.peer_provider = Some(provider);
        self
    }
}

impl ResolveRelays for DefaultRelayResolver {
    fn resolve(&self) -> BoxFuture<'_, Result<Vec<String>, TransportError>> {
        Box::pin(async move {
            // Level 1: Explicit relay URLs from TransportConfig.
            if !self.config.relay_urls.is_empty() {
                return Ok(self.config.relay_urls.clone());
            }

            // Level 2: DID document SCPRelay entries.
            if let Some(resolver) = &self.did_resolver {
                let urls = resolver().await;
                if !urls.is_empty() {
                    return Ok(urls);
                }
            }

            // Level 3: .well-known/scp from bootstrap_domain.
            if let Some(domain) = &self.config.bootstrap_domain
                && let Some(fetcher) = &self.well_known_fetcher
                    && let Some(url) = fetcher(domain).await {
                        return Ok(vec![url]);
                    }

            // Level 4: Peer relay discovery from shared contexts.
            if let Some(provider) = &self.peer_provider {
                let urls = provider().await;
                if !urls.is_empty() {
                    return Ok(urls);
                }
            }

            // Level 5: Hardcoded fallback relay list.
            tracing::warn!(
                "relay resolution fell through to hardcoded fallback relay list; \
                 configure explicit relay_urls or bootstrap_domain for production use"
            );
            Ok(FALLBACK_RELAYS.iter().map(|&s| s.to_owned()).collect())
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn transport_config_default_values() {
        let config = TransportConfig::default();
        assert!(config.relay_urls.is_empty());
        assert!(config.bootstrap_domain.is_none());
        assert_eq!(config.dedup_cache_size, 10_000);
        assert_eq!(config.dedup_cache_ttl, Duration::from_secs(3600));
    }

    #[test]
    fn transport_config_with_relay_urls_sets_urls() {
        let urls = vec![
            "wss://relay1.example.com/scp/v1".to_owned(),
            "wss://relay2.example.com/scp/v1".to_owned(),
        ];
        let config = TransportConfig::with_relay_urls(urls.clone());
        assert_eq!(config.relay_urls, urls);
        assert!(config.bootstrap_domain.is_none());
    }

    #[test]
    fn transport_config_with_bootstrap_domain_sets_domain() {
        let config = TransportConfig::with_bootstrap_domain("example.com".to_owned());
        assert!(config.relay_urls.is_empty());
        assert_eq!(config.bootstrap_domain.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn resolve_with_explicit_relay_urls_returns_those_urls() {
        let config = TransportConfig::with_relay_urls(vec![
            "wss://relay1.example.com/scp/v1".to_owned(),
            "wss://relay2.example.com/scp/v1".to_owned(),
        ]);

        // Even with all providers set, explicit URLs should be returned
        // without trying other levels.
        let resolver = DefaultRelayResolver::new(config.clone())
            .with_did_resolver(Box::new(|| {
                Box::pin(async { vec!["wss://did-relay.example.com/scp/v1".to_owned()] })
            }))
            .with_well_known_fetcher(Box::new(|_| {
                Box::pin(async { Some("wss://well-known-relay.example.com/scp/v1".to_owned()) })
            }))
            .with_peer_provider(Box::new(|| {
                Box::pin(async { vec!["wss://peer-relay.example.com/scp/v1".to_owned()] })
            }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, config.relay_urls);
    }

    #[tokio::test]
    async fn resolve_with_empty_relay_urls_falls_through_to_did_resolution() {
        let config = TransportConfig::default();

        let expected_url = "wss://did-relay.example.com/scp/v1".to_owned();
        let expected_clone = expected_url.clone();

        let resolver = DefaultRelayResolver::new(config).with_did_resolver(Box::new(move || {
            let url = expected_clone.clone();
            Box::pin(async move { vec![url] })
        }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, vec![expected_url]);
    }

    #[tokio::test]
    async fn resolve_skips_empty_did_and_falls_to_well_known() {
        let config = TransportConfig {
            bootstrap_domain: Some("example.com".to_owned()),
            ..TransportConfig::default()
        };

        let expected_url = "wss://well-known-relay.example.com/scp/v1".to_owned();
        let expected_clone = expected_url.clone();

        let resolver = DefaultRelayResolver::new(config)
            .with_did_resolver(Box::new(|| {
                Box::pin(async { vec![] }) // Empty DID result
            }))
            .with_well_known_fetcher(Box::new(move |domain| {
                assert_eq!(domain, "example.com");
                let url = expected_clone.clone();
                Box::pin(async move { Some(url) })
            }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, vec![expected_url]);
    }

    #[tokio::test]
    async fn resolve_with_bootstrap_domain_fetches_well_known() {
        let config = TransportConfig::with_bootstrap_domain("example.com".to_owned());

        let expected_url = "wss://relay.example.com/scp/v1".to_owned();
        let expected_clone = expected_url.clone();

        let resolver =
            DefaultRelayResolver::new(config).with_well_known_fetcher(Box::new(move |domain| {
                assert_eq!(domain, "example.com");
                let url = expected_clone.clone();
                Box::pin(async move { Some(url) })
            }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, vec![expected_url]);
    }

    #[tokio::test]
    async fn resolve_falls_through_to_peer_discovery() {
        let config = TransportConfig::default();

        let expected_url = "wss://peer-relay.example.com/scp/v1".to_owned();
        let expected_clone = expected_url.clone();

        let resolver = DefaultRelayResolver::new(config)
            .with_did_resolver(Box::new(|| {
                Box::pin(async { vec![] }) // Empty DID result
            }))
            .with_peer_provider(Box::new(move || {
                let url = expected_clone.clone();
                Box::pin(async move { vec![url] })
            }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, vec![expected_url]);
    }

    #[tokio::test]
    async fn resolve_falls_through_to_fallback_relays() {
        let config = TransportConfig::default();

        // No providers set -- should fall through all levels to the fallback.
        let resolver = DefaultRelayResolver::new(config);
        let urls = resolver.resolve().await.unwrap();

        assert!(!urls.is_empty());
        assert_eq!(urls, vec!["wss://relay.scp.community/scp/v1"]);
    }

    #[tokio::test]
    async fn resolve_with_all_empty_providers_falls_to_fallback() {
        let config = TransportConfig {
            bootstrap_domain: Some("example.com".to_owned()),
            ..TransportConfig::default()
        };

        let resolver = DefaultRelayResolver::new(config)
            .with_did_resolver(Box::new(|| {
                Box::pin(async { vec![] }) // Empty
            }))
            .with_well_known_fetcher(Box::new(|_| {
                Box::pin(async { None }) // Failed fetch
            }))
            .with_peer_provider(Box::new(|| {
                Box::pin(async { vec![] }) // Empty
            }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, vec!["wss://relay.scp.community/scp/v1"]);
    }

    #[tokio::test]
    async fn resolve_level_2_stops_at_did_when_urls_found() {
        let config = TransportConfig::default();

        let did_url = "wss://did-relay.example.com/scp/v1".to_owned();
        let did_clone = did_url.clone();

        // Peer provider should NOT be called if DID provides relays.
        let resolver = DefaultRelayResolver::new(config)
            .with_did_resolver(Box::new(move || {
                let url = did_clone.clone();
                Box::pin(async move { vec![url] })
            }))
            .with_peer_provider(Box::new(|| {
                Box::pin(async {
                    // If this is called, the test would still pass, but the
                    // assertion below verifies we got DID URLs, not peer URLs.
                    vec!["wss://peer-relay.example.com/scp/v1".to_owned()]
                })
            }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, vec![did_url]);
    }

    #[tokio::test]
    async fn resolve_without_well_known_fetcher_skips_level_3() {
        let config = TransportConfig {
            bootstrap_domain: Some("example.com".to_owned()),
            ..TransportConfig::default()
        };

        let peer_url = "wss://peer-relay.example.com/scp/v1".to_owned();
        let peer_clone = peer_url.clone();

        // No well_known_fetcher set, but bootstrap_domain is configured.
        // Should skip level 3 and proceed to level 4 (peer discovery).
        let resolver = DefaultRelayResolver::new(config).with_peer_provider(Box::new(move || {
            let url = peer_clone.clone();
            Box::pin(async move { vec![url] })
        }));

        let urls = resolver.resolve().await.unwrap();
        assert_eq!(urls, vec![peer_url]);
    }
}
