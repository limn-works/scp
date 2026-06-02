//! Connect-time relay transport discovery (spec §10.5.1, §10.14.3 item 4).
//!
//! A relay advertises the transports it supports in its `.well-known/scp`
//! document under `relay_config.transports` (spec §10.5.1). A native client
//! that wants to prefer QUIC over WebSocket (spec §10.14.3 item 4) must read
//! that list *before* it connects — otherwise it can never know QUIC is on
//! offer and always falls back to the WebSocket baseline.
//!
//! This module fetches and parses that list at connect time and caches it per
//! relay so repeated connects to the same relay do not re-fetch on every dial.
//! It is consumed by [`TransportSelector`](crate::selection::TransportSelector),
//! which feeds the discovered list into its transparent QUIC↔WebSocket
//! selection.
//!
//! # Fail-open
//!
//! Discovery is a pure optimization layered on top of the mandatory WebSocket
//! baseline (spec §10.5.1: *"`websocket` is always present"*). Any failure —
//! the relay serves no `.well-known/scp`, a timeout, a 404, a parse error —
//! resolves to *"transports unknown"* (`None`), which the selector treats as
//! the WebSocket baseline. A discovery failure NEVER fails a connect.
//!
//! # No globals
//!
//! [`RelayTransportDiscovery`] holds its own per-relay cache; there are no
//! singletons or mutable module globals. One instance is owned per
//! [`TransportSelector`](crate::selection::TransportSelector), i.e. per logical
//! relay-connection context (e.g. per bridge instance).
//!
//! # TLS
//!
//! The well-known fetch is `https://` and uses the crate's ring-backed rustls
//! provider via `reqwest`'s `rustls-tls` feature (non-permissive, `WebPKI`
//! roots). It never falls back to a permissive HTTPS client. See spec §10.5.1
//! (`.well-known/scp` is HTTP discovery) and ADR-037.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Bounded timeout for the `.well-known/scp` discovery fetch.
///
/// Discovery is an optimization (it only decides QUIC-vs-WebSocket), so the
/// fetch is kept short: a slow or unreachable well-known endpoint must not
/// stall the connect. On timeout the selector falls open to the WebSocket
/// baseline (spec §10.5.1).
#[cfg(feature = "quic")]
const DISCOVERY_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Default time-to-live for a cached transports list.
///
/// A relay's advertised transports change rarely (operator reconfiguration),
/// so a 5-minute TTL avoids re-fetching `.well-known/scp` on every reconnect
/// while still picking up changes within a bounded window. Expiry of a cache
/// entry is the natural `.well-known/scp` *refresh* point referenced by spec
/// §10.14.3 item 4 ("until the next `.well-known/scp` refresh"): a refresh is
/// where the selector clears QUIC suppression for the relay.
pub const DEFAULT_DISCOVERY_TTL: Duration = Duration::from_mins(5);

/// Outcome of a transports lookup for a relay.
///
/// Distinguishes a *fresh* fetch (a new `.well-known/scp` read just happened)
/// from a *cached* hit, so the caller can clear QUIC suppression only on a
/// genuine refresh (spec §10.14.3 item 4) rather than on every connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredTransports {
    /// The advertised transports list (`relay_config.transports`), or `None`
    /// when discovery failed or the relay advertised no list — both resolve to
    /// the WebSocket baseline at the selector.
    pub transports: Option<Vec<String>>,
    /// `true` when this result came from a fresh network fetch (a refresh),
    /// `false` when served from cache. A fresh result is the refresh point at
    /// which QUIC suppression for the relay should be cleared.
    pub refreshed: bool,
}

/// A cache entry: the resolved transports and when it was stored.
#[derive(Debug, Clone)]
struct CacheEntry {
    transports: Option<Vec<String>>,
    stored_at: Instant,
}

/// Result of consulting the per-relay cache.
///
/// Distinguishes "no usable entry, must fetch" from "cached, transports
/// unknown" — a relay that previously served no well-known is cached as
/// [`Fresh(None)`](CacheLookup::Fresh) so it is not re-fetched on every connect
/// within the TTL window. Avoids the `Option<Option<_>>` the two states would
/// otherwise require.
enum CacheLookup {
    /// A non-expired entry: serve its transports (possibly `None`) from cache.
    Fresh(Option<Vec<String>>),
    /// No entry, or the entry has expired: a fresh fetch is required.
    Miss,
}

/// Per-relay cache of advertised transports discovered from `.well-known/scp`.
///
/// Instance-scoped (no globals): one per
/// [`TransportSelector`](crate::selection::TransportSelector). Lookups fetch on
/// a cache miss/expiry and serve from cache otherwise. Every failure mode
/// resolves to `None` (WebSocket baseline) — discovery never errors out to the
/// caller.
#[derive(Debug)]
pub struct RelayTransportDiscovery {
    /// relay URL → cached transports + timestamp.
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// How long a cached entry is served before a re-fetch.
    ttl: Duration,
    /// HTTPS client used for the `.well-known/scp` fetch.
    ///
    /// Built lazily on first use from the crate's non-permissive ring-backed
    /// rustls provider (`reqwest`'s `rustls-tls`), then reused. Lazily because
    /// most `RelayTransportDiscovery` instances may never fetch (e.g. only ever
    /// see plaintext relays, or the `quic` feature is off), so the client is
    /// not constructed until the first real fetch is needed.
    ///
    /// Tests inject a client that trusts a local self-signed cert via
    /// [`with_client_for_test`](Self::with_client_for_test); production never
    /// uses a permissive client.
    #[cfg(feature = "quic")]
    client: std::sync::OnceLock<Option<reqwest::Client>>,
}

impl Default for RelayTransportDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayTransportDiscovery {
    /// Creates a discovery cache with the [`DEFAULT_DISCOVERY_TTL`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_DISCOVERY_TTL)
    }

    /// Creates a discovery cache with an explicit TTL (used by tests).
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl,
            #[cfg(feature = "quic")]
            client: std::sync::OnceLock::new(),
        }
    }

    /// Test-only constructor that injects a preconfigured HTTPS client.
    ///
    /// Lets tests point discovery at a local self-signed HTTPS endpoint by
    /// supplying a client that trusts the test cert. Production always builds
    /// its own non-permissive client (see [`client`](Self::client)); this seam
    /// never weakens production TLS.
    #[cfg(all(test, feature = "quic"))]
    #[must_use]
    pub(crate) fn with_client_for_test(client: reqwest::Client, ttl: Duration) -> Self {
        let cell = std::sync::OnceLock::new();
        let _ = cell.set(Some(client));
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl,
            client: cell,
        }
    }

    /// Returns the advertised transports for `relay_url`, fetching
    /// `.well-known/scp` on a cache miss/expiry and serving from cache
    /// otherwise.
    ///
    /// The result is fail-open: any fetch/parse failure (or a relay that
    /// serves no well-known) resolves to `transports: None`, which the selector
    /// treats as the WebSocket baseline (spec §10.5.1). A network fetch is
    /// reported with `refreshed: true` so the caller can clear QUIC suppression
    /// for the relay only on a genuine refresh (spec §10.14.3 item 4).
    pub async fn advertised_transports(&self, relay_url: &str) -> DiscoveredTransports {
        if let CacheLookup::Fresh(transports) = self.cached(relay_url) {
            return DiscoveredTransports {
                transports,
                refreshed: false,
            };
        }

        // Cache miss or expiry: fetch fresh. `fetch_transports` is fail-open
        // (returns None on any error) so this never propagates a failure.
        let transports = self.fetch_transports(relay_url).await;
        self.store(relay_url, transports.clone());
        DiscoveredTransports {
            transports,
            refreshed: true,
        }
    }

    /// Consults the per-relay cache for a non-expired entry.
    ///
    /// Returns [`CacheLookup::Fresh`] (serve from cache, possibly with `None`
    /// transports for a relay that advertised nothing) or [`CacheLookup::Miss`]
    /// (no entry or expired — fetch).
    fn cached(&self, relay_url: &str) -> CacheLookup {
        let Ok(cache) = self.cache.lock() else {
            return CacheLookup::Miss;
        };
        let lookup = match cache.get(relay_url) {
            Some(entry) if entry.stored_at.elapsed() < self.ttl => {
                CacheLookup::Fresh(entry.transports.clone())
            }
            _ => CacheLookup::Miss,
        };
        drop(cache);
        lookup
    }

    /// Stores a transports result for `relay_url`, stamped with the current
    /// time for TTL accounting.
    fn store(&self, relay_url: &str, transports: Option<Vec<String>>) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                relay_url.to_owned(),
                CacheEntry {
                    transports,
                    stored_at: Instant::now(),
                },
            );
        }
    }

    /// Fetches and parses `.well-known/scp` for `relay_url`, returning its
    /// `relay_config.transports` list.
    ///
    /// Fail-open: returns `None` on any failure (no well-known URL derivable, a
    /// non-TLS relay, a network/timeout/HTTP error, a parse error, or an absent
    /// `transports` field).
    ///
    /// When the `quic` feature is disabled there is no HTTP client and no QUIC
    /// to select, so this always returns `None` (WebSocket baseline) without a
    /// fetch.
    #[cfg_attr(not(feature = "quic"), allow(clippy::unused_async))]
    async fn fetch_transports(&self, relay_url: &str) -> Option<Vec<String>> {
        #[cfg(feature = "quic")]
        {
            let well_known_url = well_known_url(relay_url)?;
            self.http_fetch_transports(&well_known_url).await
        }
        #[cfg(not(feature = "quic"))]
        {
            let _ = relay_url;
            None
        }
    }

    /// Returns the HTTPS client for the discovery fetch, building it on first
    /// use.
    ///
    /// The client uses `reqwest`'s `rustls-tls` (the crate's ring-backed rustls
    /// provider): a non-permissive, WebPKI-roots TLS client. It is NEVER
    /// permissive. Returns `None` if the client cannot be built (treated as a
    /// fail-open discovery failure → WebSocket baseline).
    #[cfg(feature = "quic")]
    fn http_client(&self) -> Option<&reqwest::Client> {
        self.client
            .get_or_init(|| {
                reqwest::Client::builder()
                    .timeout(DISCOVERY_FETCH_TIMEOUT)
                    .build()
                    .ok()
            })
            .as_ref()
    }

    /// Performs the actual HTTPS GET of the well-known document and extracts
    /// the transports list. Fail-open (`None` on any error).
    #[cfg(feature = "quic")]
    async fn http_fetch_transports(&self, well_known_url: &str) -> Option<Vec<String>> {
        use crate::relay::wellknown::parse_well_known;

        let client = self.http_client()?;

        let response = match client.get(well_known_url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(
                    well_known_url = %well_known_url,
                    error = %e,
                    "relay transport discovery: .well-known/scp fetch failed; \
                     falling open to WebSocket baseline"
                );
                return None;
            }
        };

        if !response.status().is_success() {
            tracing::debug!(
                well_known_url = %well_known_url,
                status = %response.status(),
                "relay transport discovery: .well-known/scp returned non-success; \
                 falling open to WebSocket baseline"
            );
            return None;
        }

        let body = match response.text().await {
            Ok(body) => body,
            Err(e) => {
                tracing::debug!(
                    well_known_url = %well_known_url,
                    error = %e,
                    "relay transport discovery: reading .well-known/scp body failed; \
                     falling open to WebSocket baseline"
                );
                return None;
            }
        };

        match parse_well_known(&body) {
            Ok(doc) => doc.relay_config.and_then(|rc| rc.transports),
            Err(e) => {
                tracing::debug!(
                    well_known_url = %well_known_url,
                    error = %e,
                    "relay transport discovery: parsing .well-known/scp failed; \
                     falling open to WebSocket baseline"
                );
                None
            }
        }
    }
}

/// Maps a relay URL to its `.well-known/scp` discovery URL.
///
/// `wss://host:port/scp/v1` → `https://host:port/.well-known/scp`. The
/// well-known document lives at the authority root (spec §18.3, RFC 8615), not
/// under the relay's `/scp/v1` path. Only TLS relay schemes map to a discovery
/// URL: `wss://`/`https://` → `https://...`. Plaintext schemes (`ws://`,
/// `http://`) return `None` — they cannot offer QUIC (which mandates TLS 1.3),
/// so there is nothing to discover and no `https://` authority to fetch from.
///
/// Userinfo is stripped from the authority (RFC 3986 §3.2.1) to prevent a
/// `wss://host:pw@evil.com/...` form from redirecting the fetch to `evil.com`.
///
/// Returns `None` for any URL without a recognized TLS scheme or with an empty
/// authority.
#[must_use]
pub fn well_known_url(relay_url: &str) -> Option<String> {
    let lower = relay_url.to_ascii_lowercase();
    // Only TLS schemes have an https authority to fetch the well-known from.
    let after_scheme = if lower.starts_with("wss://") {
        &relay_url["wss://".len()..]
    } else if lower.starts_with("https://") {
        &relay_url["https://".len()..]
    } else {
        return None;
    };

    // Authority is everything up to the first '/' (or the whole remainder).
    let authority = after_scheme.split('/').next().unwrap_or("");

    // Strip userinfo (everything up to and including the last '@') so a
    // `host:pw@evil.com` form cannot redirect the discovery fetch.
    let authority = authority
        .rfind('@')
        .map_or(authority, |at| &authority[at + 1..]);

    if authority.is_empty() {
        return None;
    }

    Some(format!("https://{authority}/.well-known/scp"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- well_known_url ----------------------------------------------------

    #[test]
    fn wss_relay_maps_to_https_well_known() {
        assert_eq!(
            well_known_url("wss://relay.example.com/scp/v1").as_deref(),
            Some("https://relay.example.com/.well-known/scp")
        );
    }

    #[test]
    fn wss_relay_with_port_preserves_port() {
        assert_eq!(
            well_known_url("wss://relay.example.com:8443/scp/v1").as_deref(),
            Some("https://relay.example.com:8443/.well-known/scp")
        );
    }

    #[test]
    fn https_relay_maps_to_https_well_known() {
        assert_eq!(
            well_known_url("https://relay.example.com:443/scp/v1").as_deref(),
            Some("https://relay.example.com:443/.well-known/scp")
        );
    }

    #[test]
    fn scheme_match_is_case_insensitive() {
        assert_eq!(
            well_known_url("WSS://Relay.Example.com/scp/v1").as_deref(),
            // Host casing is preserved; only the scheme match is case-insensitive.
            Some("https://Relay.Example.com/.well-known/scp")
        );
    }

    #[test]
    fn plaintext_ws_has_no_well_known_url() {
        assert!(well_known_url("ws://127.0.0.1:9000/scp/v1").is_none());
        assert!(well_known_url("http://127.0.0.1:9000/scp/v1").is_none());
    }

    #[test]
    fn userinfo_is_stripped_to_real_authority() {
        // The connection target is the host after '@', not the userinfo.
        assert_eq!(
            well_known_url("wss://user:pw@relay.example.com:8443/scp/v1").as_deref(),
            Some("https://relay.example.com:8443/.well-known/scp")
        );
    }

    #[test]
    fn empty_authority_returns_none() {
        assert!(well_known_url("wss:///scp/v1").is_none());
    }

    #[test]
    fn well_known_url_at_authority_root_not_relay_path() {
        // Even when the relay path is deep, the well-known is at the root.
        assert_eq!(
            well_known_url("wss://relay.example.com/scp/v1/deep/path").as_deref(),
            Some("https://relay.example.com/.well-known/scp")
        );
    }

    // -- cache behavior (no network) ---------------------------------------

    #[tokio::test]
    async fn plaintext_relay_resolves_to_none_without_fetch() {
        // A ws:// relay has no discoverable transports → None, baseline.
        let discovery = RelayTransportDiscovery::new();
        let result = discovery
            .advertised_transports("ws://127.0.0.1:9000/scp/v1")
            .await;
        assert_eq!(result.transports, None);
        // First lookup is always a (fail-open) refresh.
        assert!(result.refreshed);

        // Second lookup is served from cache (no refresh) — the negative
        // result is cached so we don't repeatedly try a relay with no
        // discoverable transports.
        let cached = discovery
            .advertised_transports("ws://127.0.0.1:9000/scp/v1")
            .await;
        assert_eq!(cached.transports, None);
        assert!(!cached.refreshed);
    }

    #[tokio::test]
    async fn expired_entry_refreshes() {
        // A zero TTL forces every lookup to be a fresh fetch.
        let discovery = RelayTransportDiscovery::with_ttl(Duration::from_millis(0));
        let first = discovery
            .advertised_transports("ws://127.0.0.1:9000/scp/v1")
            .await;
        assert!(first.refreshed);
        let second = discovery
            .advertised_transports("ws://127.0.0.1:9000/scp/v1")
            .await;
        // With an expired entry, the second lookup re-fetches (refreshes).
        assert!(second.refreshed);
    }

    // -- real HTTPS fetch against a local well-known server ------------------

    /// A relay whose `.well-known/scp` advertises `["quic", "websocket"]` is
    /// fetched over real HTTPS and the transports list is parsed and returned.
    /// This exercises the full production fetch + parse path (only the trusted
    /// root differs from production).
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn fetches_and_parses_advertised_transports_over_https() {
        use crate::discovery_test_support::{start_well_known_server, trusting_client};

        let body = r#"{
            "version": 1,
            "did": "did:dht:z6MkRelay",
            "relay": "wss://127.0.0.1/scp/v1",
            "relay_config": { "transports": ["websocket", "quic"] }
        }"#
        .to_owned();
        let server = start_well_known_server(body).await;
        let client = trusting_client(&server.cert_pem, Duration::from_secs(2));
        let discovery =
            RelayTransportDiscovery::with_client_for_test(client, DEFAULT_DISCOVERY_TTL);

        let result = discovery.advertised_transports(&server.relay_url()).await;
        assert!(result.refreshed, "first lookup is a fresh fetch");
        assert_eq!(
            result.transports,
            Some(vec!["websocket".to_owned(), "quic".to_owned()]),
            "the advertised transports must be parsed from the fetched document"
        );
    }

    /// Two connects to the same relay fetch `.well-known/scp` exactly once: the
    /// second lookup is served from the per-relay cache.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn caches_per_relay_fetches_once() {
        use crate::discovery_test_support::{start_well_known_server, trusting_client};

        let body = r#"{
            "version": 1,
            "did": "did:dht:z6MkRelay",
            "relay": "wss://127.0.0.1/scp/v1",
            "relay_config": { "transports": ["websocket", "quic"] }
        }"#
        .to_owned();
        let server = start_well_known_server(body).await;
        let client = trusting_client(&server.cert_pem, Duration::from_secs(2));
        let discovery =
            RelayTransportDiscovery::with_client_for_test(client, DEFAULT_DISCOVERY_TTL);

        let first = discovery.advertised_transports(&server.relay_url()).await;
        assert!(first.refreshed);
        let second = discovery.advertised_transports(&server.relay_url()).await;
        assert!(!second.refreshed, "second lookup must be served from cache");
        assert_eq!(first.transports, second.transports);

        assert_eq!(
            server.request_count(),
            1,
            ".well-known/scp must be fetched exactly once for two connects"
        );
    }

    /// A relay that serves no `.well-known/scp` (connection refused) resolves
    /// to `None` (WebSocket baseline) without erroring — fail-open.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn fetch_failure_resolves_to_none_fail_open() {
        use crate::discovery_test_support::trusting_client;

        // A self-signed cert PEM that no server is listening behind: the fetch
        // to this dead port fails, and discovery must fall open to None.
        let dummy_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .cert
            .pem();
        let client = trusting_client(&dummy_cert, Duration::from_millis(500));
        let discovery =
            RelayTransportDiscovery::with_client_for_test(client, DEFAULT_DISCOVERY_TTL);

        // Port 1 on loopback has nothing listening → connection refused.
        let result = discovery
            .advertised_transports("wss://127.0.0.1:1/scp/v1")
            .await;
        assert_eq!(
            result.transports, None,
            "a failed discovery fetch must fail open to the WebSocket baseline"
        );
        assert!(
            result.refreshed,
            "a failed fetch is still a refresh attempt"
        );
    }
}
