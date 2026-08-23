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

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

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

/// Short time-to-live applied to a *transient fetch failure*.
///
/// A failed fetch (timeout, connection refused, redirect-induced non-success,
/// oversized/garbled body) is cached only briefly so one network blip does not
/// suppress QUIC for the full [`DEFAULT_DISCOVERY_TTL`]. A *resolved* result —
/// the relay genuinely advertised a list, or genuinely advertised nothing — is
/// cached for the full TTL because it reflects relay configuration, not a
/// transient condition. The short window still avoids hammering a flapping
/// relay on every reconnect.
const DISCOVERY_FAILURE_TTL: Duration = Duration::from_secs(10);

/// Maximum number of distinct relays whose discovery results are cached.
///
/// The cache is keyed by relay URL; without a bound it would grow one entry per
/// distinct relay URL seen for the lifetime of the
/// [`TransportSelector`](crate::selection::TransportSelector). An LRU bound caps
/// memory while keeping the hot set of recently-dialed relays resident. 256 is
/// the same bound scp-node's webhook dispatcher uses for an analogous per-URL
/// registry.
const MAX_CACHED_RELAYS: usize = 256;

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

/// A cache entry: the transports result, when it was stored, and whether it
/// came from a transient fetch failure (so a short TTL applies to it).
#[derive(Debug, Clone)]
struct CacheEntry {
    transports: Option<Vec<String>>,
    stored_at: Instant,
    /// `true` when this entry records a transient fetch failure (timeout,
    /// connection refused, non-success status, oversized/garbled body) rather
    /// than a resolved answer. Failures expire after [`DISCOVERY_FAILURE_TTL`];
    /// resolved entries live for the full [`RelayTransportDiscovery::ttl`].
    transient_failure: bool,
}

impl CacheEntry {
    /// Whether this entry is still fresh given the resolved/failure TTLs.
    ///
    /// Transient failures use the short `failure_ttl` so a single network blip
    /// does not suppress QUIC for the full resolved TTL; resolved answers use
    /// `resolved_ttl`.
    fn is_fresh(&self, resolved_ttl: Duration, failure_ttl: Duration) -> bool {
        let ttl = if self.transient_failure {
            failure_ttl
        } else {
            resolved_ttl
        };
        self.stored_at.elapsed() < ttl
    }
}

/// Outcome of a `.well-known/scp` fetch, distinguishing a *resolved* answer
/// (the relay genuinely advertised a list, or genuinely advertised nothing)
/// from a *transient failure* (timeout, connection refused, non-success,
/// oversized/garbled body).
///
/// Both resolve to the same WebSocket baseline at the selector, but they cache
/// for different durations: a resolved answer reflects relay configuration and
/// is cached for the full TTL, whereas a transient failure is cached only
/// briefly (see [`DISCOVERY_FAILURE_TTL`]) so one blip does not suppress QUIC
/// for minutes.
#[derive(Debug)]
enum FetchOutcome {
    /// The fetch completed and produced an answer: `Some(list)` when the relay
    /// advertised transports, `None` when it advertised none.
    Resolved(Option<Vec<String>>),
    /// The fetch failed transiently; the relay's transports remain unknown.
    ///
    /// Only the `quic` build path can produce a real fetch (and therefore a real
    /// failure); without `quic` there is no HTTP client, so this variant is
    /// never constructed in that configuration.
    #[cfg_attr(not(feature = "quic"), allow(dead_code))]
    Failed,
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
    /// relay URL → cached transports + timestamp, bounded LRU
    /// ([`MAX_CACHED_RELAYS`]) so the cache cannot grow without bound across
    /// distinct relay URLs. `LruCache::get` requires `&mut`, which the `Mutex`
    /// already provides; the guard is always dropped before any `.await`.
    cache: Mutex<LruCache<String, CacheEntry>>,
    /// How long a *resolved* cached entry is served before a re-fetch.
    ttl: Duration,
    /// How long a *transient failure* entry is served before a re-fetch. Always
    /// the short [`DISCOVERY_FAILURE_TTL`] in production; a test constructor may
    /// shrink it for deterministic expiry assertions.
    failure_ttl: Duration,
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
            cache: Mutex::new(Self::new_cache()),
            ttl,
            failure_ttl: DISCOVERY_FAILURE_TTL,
            #[cfg(feature = "quic")]
            client: std::sync::OnceLock::new(),
        }
    }

    /// Test-only constructor that sets both the resolved and failure TTLs, so a
    /// test can drive failure-entry expiry deterministically without sleeping
    /// the full production [`DISCOVERY_FAILURE_TTL`].
    #[cfg(test)]
    #[must_use]
    fn with_ttls_for_test(ttl: Duration, failure_ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(Self::new_cache()),
            ttl,
            failure_ttl,
            #[cfg(feature = "quic")]
            client: std::sync::OnceLock::new(),
        }
    }

    /// Builds the bounded LRU backing store for the per-relay cache.
    ///
    /// [`MAX_CACHED_RELAYS`] is a non-zero compile-time constant, so the
    /// `NonZeroUsize` conversion cannot fail; a `const` assertion keeps that
    /// guarantee from silently regressing if the bound is ever changed to `0`.
    fn new_cache() -> LruCache<String, CacheEntry> {
        const {
            assert!(MAX_CACHED_RELAYS > 0, "MAX_CACHED_RELAYS must be non-zero");
        }
        let capacity = NonZeroUsize::new(MAX_CACHED_RELAYS).unwrap_or(NonZeroUsize::MIN);
        LruCache::new(capacity)
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
            cache: Mutex::new(Self::new_cache()),
            ttl,
            failure_ttl: DISCOVERY_FAILURE_TTL,
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
        // (never errors out) but reports whether the answer was *resolved* or a
        // *transient failure* so the two can be cached for different durations.
        let (transports, transient_failure) = match self.fetch_transports(relay_url).await {
            FetchOutcome::Resolved(transports) => (transports, false),
            FetchOutcome::Failed => (None, true),
        };
        self.store(relay_url, transports.clone(), transient_failure);
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
        // `LruCache::get` takes `&mut self` (it updates recency), so the guard
        // must be mutable. It is dropped at the end of this sync scope, before
        // `advertised_transports` performs any `.await`.
        let Ok(mut cache) = self.cache.lock() else {
            return CacheLookup::Miss;
        };
        let lookup = match cache.get(relay_url) {
            // A transient failure expires after the short DISCOVERY_FAILURE_TTL;
            // a resolved answer lives for the full configured TTL.
            Some(entry) if entry.is_fresh(self.ttl, self.failure_ttl) => {
                CacheLookup::Fresh(entry.transports.clone())
            }
            _ => CacheLookup::Miss,
        };
        drop(cache);
        lookup
    }

    /// Stores a transports result for `relay_url`, stamped with the current
    /// time for TTL accounting.
    ///
    /// `transient_failure` records whether the result came from a failed fetch
    /// (short TTL) or a resolved answer (full TTL). Insertion may evict the
    /// least-recently-used entry once [`MAX_CACHED_RELAYS`] is reached.
    fn store(&self, relay_url: &str, transports: Option<Vec<String>>, transient_failure: bool) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.put(
                relay_url.to_owned(),
                CacheEntry {
                    transports,
                    stored_at: Instant::now(),
                    transient_failure,
                },
            );
        }
    }

    /// Fetches and parses `.well-known/scp` for `relay_url`, returning its
    /// `relay_config.transports` list as a [`FetchOutcome`].
    ///
    /// Fail-open: never errors out. A [`FetchOutcome::Resolved`] means the relay
    /// answered (with a list or with nothing); a [`FetchOutcome::Failed`] means
    /// the fetch failed transiently (network/timeout/HTTP error, oversized or
    /// garbled body). A parse error or an absent `transports` field on an
    /// otherwise-successful response is a *resolved* `None`, not a failure — the
    /// relay simply advertises no usable list.
    ///
    /// A non-TLS relay (no `https://` authority to fetch from) is also
    /// `Resolved(None)`: there is genuinely nothing to discover, not a transient
    /// failure, so it is cached for the full TTL.
    ///
    /// When the `quic` feature is disabled there is no HTTP client and no QUIC
    /// to select, so this always returns `Resolved(None)` (WebSocket baseline)
    /// without a fetch.
    #[cfg_attr(
        not(feature = "quic"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn fetch_transports(&self, relay_url: &str) -> FetchOutcome {
        #[cfg(feature = "quic")]
        {
            // No https authority to fetch from (plaintext relay / empty
            // authority): nothing to discover. This is a settled answer, not a
            // transient failure, so cache it for the full TTL.
            let Some(well_known_url) = well_known_url(relay_url) else {
                return FetchOutcome::Resolved(None);
            };
            self.http_fetch_transports(&well_known_url).await
        }
        #[cfg(not(feature = "quic"))]
        {
            let _ = relay_url;
            FetchOutcome::Resolved(None)
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
                    // SSRF: the `.well-known/scp` document is served directly at
                    // the authority root (RFC 8615), so a redirect is never a
                    // legitimate part of discovery. Following one would let a
                    // hostile relay 30x-bounce the fetch to an internal service
                    // (SSRF) or to a cleartext `http://` target. Refuse all
                    // redirects; a 3xx then hits the `!is_success()` branch and
                    // falls open to the WebSocket baseline. Matches the hardened
                    // precedent in scp-node's webhook dispatcher.
                    .redirect(reqwest::redirect::Policy::none())
                    // Never downgrade the discovery fetch to `http://`: QUIC
                    // mandates TLS 1.3, and a cleartext fetch is exactly the
                    // downgrade a hostile relay would force. `well_known_url`
                    // only ever yields an `https://` URL, so this is also a
                    // defense-in-depth guard against any future caller.
                    .https_only(true)
                    .build()
                    .ok()
            })
            .as_ref()
    }

    /// Performs the actual HTTPS GET of the well-known document and extracts
    /// the transports list.
    ///
    /// Fail-open: returns [`FetchOutcome::Failed`] on any transport-level error
    /// (no client, network/timeout error, non-success status, or an oversized
    /// or unreadable body), and [`FetchOutcome::Resolved`] once the body is read
    /// — including `Resolved(None)` when the body fails to parse or carries no
    /// `transports` field (the relay simply advertises nothing usable).
    #[cfg(feature = "quic")]
    async fn http_fetch_transports(&self, well_known_url: &str) -> FetchOutcome {
        use crate::relay::wellknown::parse_well_known;

        let Some(client) = self.http_client() else {
            return FetchOutcome::Failed;
        };

        let response = match client.get(well_known_url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(
                    well_known_url = %well_known_url,
                    error = %e,
                    "relay transport discovery: .well-known/scp fetch failed; \
                     falling open to WebSocket baseline"
                );
                return FetchOutcome::Failed;
            }
        };

        if !response.status().is_success() {
            tracing::debug!(
                well_known_url = %well_known_url,
                status = %response.status(),
                "relay transport discovery: .well-known/scp returned non-success; \
                 falling open to WebSocket baseline"
            );
            return FetchOutcome::Failed;
        }

        let Some(body) = read_capped_body(response, well_known_url).await else {
            return FetchOutcome::Failed;
        };

        match parse_well_known(&body) {
            // A successful read that parses: the relay's settled answer, whether
            // it lists transports or not.
            Ok(doc) => FetchOutcome::Resolved(doc.relay_config.and_then(|rc| rc.transports)),
            Err(e) => {
                tracing::debug!(
                    well_known_url = %well_known_url,
                    error = %e,
                    "relay transport discovery: parsing .well-known/scp failed; \
                     falling open to WebSocket baseline"
                );
                // A response that parses to nothing is a resolved "no usable
                // list", not a transient failure: re-fetching won't help, so
                // cache it for the full TTL rather than retrying every 10s.
                FetchOutcome::Resolved(None)
            }
        }
    }
}

/// Maximum number of bytes read from a `.well-known/scp` response body.
///
/// The document is a small JSON object (a DID, a relay URL, a short transports
/// list); 64 KiB is generous. reqwest imposes no default body-size limit, so an
/// uncapped `text()`/`bytes()` would let a hostile relay stream an unbounded
/// body into memory. The cap bounds memory both via the advertised
/// `Content-Length` (cheap reject) and via a running byte count while streaming
/// (defends against a chunked response that omits `Content-Length`).
#[cfg(feature = "quic")]
const MAX_WELL_KNOWN_BODY: u64 = 64 * 1024;

/// Reads a response body into a `String`, capping it at [`MAX_WELL_KNOWN_BODY`].
///
/// Returns `None` (a transient failure) when the body is too large or cannot be
/// read/decoded:
/// - an advertised `Content-Length` over the cap is rejected before any body is
///   buffered;
/// - the body is then streamed chunk-by-chunk with a running total, so a
///   chunked response that omits `Content-Length` is still bounded;
/// - a chunk read error or non-UTF-8 body yields `None`.
#[cfg(feature = "quic")]
async fn read_capped_body(response: reqwest::Response, well_known_url: &str) -> Option<String> {
    use futures::StreamExt;

    // Cheap reject: an advertised length over the cap never gets buffered.
    if response
        .content_length()
        .is_some_and(|n| n > MAX_WELL_KNOWN_BODY)
    {
        tracing::debug!(
            well_known_url = %well_known_url,
            "relay transport discovery: .well-known/scp Content-Length exceeds cap; \
             falling open to WebSocket baseline"
        );
        return None;
    }

    // Chunked responses omit Content-Length, so also stream with a running cap.
    let mut stream = response.bytes_stream();
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
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
        if body.len() as u64 + chunk.len() as u64 > MAX_WELL_KNOWN_BODY {
            tracing::debug!(
                well_known_url = %well_known_url,
                "relay transport discovery: .well-known/scp body exceeds cap; \
                 falling open to WebSocket baseline"
            );
            return None;
        }
        body.extend_from_slice(&chunk);
    }

    match String::from_utf8(body) {
        Ok(body) => Some(body),
        Err(e) => {
            tracing::debug!(
                well_known_url = %well_known_url,
                error = %e,
                "relay transport discovery: .well-known/scp body is not valid UTF-8; \
                 falling open to WebSocket baseline"
            );
            None
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

    // -- SSRF / cleartext downgrade hardening (fix 1) -----------------------

    /// A relay that 30x-redirects the well-known fetch to an `http://` target
    /// (SSRF + cleartext downgrade) must NOT be followed: the discovery client
    /// refuses all redirects, surfaces the 302 as a non-success status, falls
    /// open to `None`, and issues exactly one request (no second fetch).
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn redirect_is_refused_and_issues_no_second_request() {
        use crate::discovery_test_support::{hardened_trusting_client, start_redirect_server};

        // A hostile relay tries to bounce the fetch to an internal cleartext
        // service. With redirects refused this is never followed.
        let server = start_redirect_server("http://169.254.169.254/latest/meta-data").await;
        let client = hardened_trusting_client(&server.cert_pem, Duration::from_secs(2));
        let discovery =
            RelayTransportDiscovery::with_client_for_test(client, DEFAULT_DISCOVERY_TTL);

        let result = discovery.advertised_transports(&server.relay_url()).await;
        assert_eq!(
            result.transports, None,
            "a 30x redirect must fall open to the WebSocket baseline, not be followed"
        );
        assert_eq!(
            server.request_count(),
            1,
            "the redirect must not trigger a second request (no SSRF follow)"
        );
    }

    /// The hardened discovery client refuses to fetch an `http://` URL outright
    /// (`https_only`), so even a caller that somehow produced a cleartext target
    /// can never downgrade the discovery fetch.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn https_only_rejects_cleartext_target() {
        use crate::discovery_test_support::hardened_trusting_client;

        let dummy_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .cert
            .pem();
        let client = hardened_trusting_client(&dummy_cert, Duration::from_millis(500));

        // A direct GET of an http:// URL must error before any connection: the
        // client is https_only. This asserts the flag the production builder
        // sets, independent of whether anything is listening.
        let err = client
            .get("http://127.0.0.1:1/.well-known/scp")
            .send()
            .await;
        assert!(
            err.is_err(),
            "an https_only client must reject an http:// target outright"
        );
    }

    // -- response body cap (fix 2) -----------------------------------------

    /// A relay that serves an oversized `.well-known/scp` body (here via a
    /// truthful Content-Length over the 64 KiB cap) is rejected before parse and
    /// falls open to `None`, bounding memory.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn oversized_body_is_rejected_fail_open() {
        use crate::discovery_test_support::{start_oversized_body_server, trusting_client};

        let oversized = usize::try_from(MAX_WELL_KNOWN_BODY).expect("64 KiB fits in usize") + 1;
        let server = start_oversized_body_server(oversized).await;
        let client = trusting_client(&server.cert_pem, Duration::from_secs(2));
        let discovery =
            RelayTransportDiscovery::with_client_for_test(client, DEFAULT_DISCOVERY_TTL);

        let result = discovery.advertised_transports(&server.relay_url()).await;
        assert_eq!(
            result.transports, None,
            "an oversized well-known body must fail open to the WebSocket baseline"
        );
    }

    // -- transient-vs-resolved TTL (fix 3) ---------------------------------

    /// A transient fetch failure is cached only for the short failure TTL, so a
    /// network blip does not suppress QUIC for the full resolved TTL: a second
    /// lookup after the short window re-fetches (refreshes).
    ///
    /// Uses a tiny real failure TTL and a real sleep: the cache stamps entries
    /// with `std::time::Instant`, which is unaffected by tokio's virtual clock,
    /// so `tokio::time::advance` cannot drive its expiry.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn transient_failure_caches_briefly() {
        // Long resolved TTL, tiny failure TTL: if the failure were cached as a
        // resolved entry it would NOT re-fetch for 5 minutes. The short failure
        // TTL must win. The production client is built lazily on first fetch;
        // the dead-port connect is refused before any TLS, so no trusted root is
        // needed for this failure path.
        let failure_ttl = Duration::from_millis(100);
        let discovery =
            RelayTransportDiscovery::with_ttls_for_test(DEFAULT_DISCOVERY_TTL, failure_ttl);

        // Nothing listening on port 1 → transient failure.
        let first = discovery
            .advertised_transports("wss://127.0.0.1:1/scp/v1")
            .await;
        assert!(first.refreshed, "first lookup fetches");
        assert_eq!(first.transports, None);

        // Within the short failure window: served from cache, not re-fetched.
        let within = discovery
            .advertised_transports("wss://127.0.0.1:1/scp/v1")
            .await;
        assert!(
            !within.refreshed,
            "a transient failure is cached for the short failure TTL"
        );

        // Past the failure TTL (but far within the resolved TTL): must re-fetch.
        tokio::time::sleep(failure_ttl + Duration::from_millis(50)).await;
        let after = discovery
            .advertised_transports("wss://127.0.0.1:1/scp/v1")
            .await;
        assert!(
            after.refreshed,
            "past the short failure TTL the failure entry expires and re-fetches"
        );
    }

    /// A *resolved* negative (a relay that genuinely advertises no transports —
    /// here a plaintext relay with nothing to discover) is cached for the full
    /// resolved TTL, NOT the short failure TTL: it is not re-fetched after the
    /// short window.
    ///
    /// Uses a tiny real failure TTL and a real sleep that exceeds it while
    /// staying far inside the long resolved TTL, so the assertion proves the
    /// resolved path ignores the failure TTL (cache uses `std::time::Instant`,
    /// which tokio's virtual clock cannot drive).
    #[tokio::test]
    async fn resolved_none_caches_for_full_ttl() {
        let failure_ttl = Duration::from_millis(50);
        let discovery =
            RelayTransportDiscovery::with_ttls_for_test(DEFAULT_DISCOVERY_TTL, failure_ttl);

        // A ws:// relay resolves to None (nothing to discover) — a settled
        // answer, not a transient failure.
        let first = discovery
            .advertised_transports("ws://127.0.0.1:9000/scp/v1")
            .await;
        assert!(first.refreshed);
        assert_eq!(first.transports, None);

        // Sleep past the SHORT failure TTL but far within the resolved TTL: a
        // resolved-none must still be served from cache (no re-fetch). If the
        // resolved entry were (wrongly) subject to the failure TTL it would have
        // expired here and re-fetched.
        tokio::time::sleep(failure_ttl + Duration::from_millis(50)).await;
        let after = discovery
            .advertised_transports("ws://127.0.0.1:9000/scp/v1")
            .await;
        assert!(
            !after.refreshed,
            "a resolved-none is cached for the full TTL, not the short failure TTL"
        );
    }

    // -- bounded LRU cache (fix 4) -----------------------------------------

    /// Inserting more than `MAX_CACHED_RELAYS` distinct relays evicts the
    /// least-recently-used entry: the oldest relay is no longer served from
    /// cache (its next lookup is a refresh), while a recent relay still is.
    #[tokio::test]
    async fn cache_evicts_oldest_beyond_capacity() {
        let discovery = RelayTransportDiscovery::with_ttl(DEFAULT_DISCOVERY_TTL);

        // Fill the cache to capacity with distinct plaintext relays (each
        // resolves to None without a network fetch and is cached).
        for i in 0..MAX_CACHED_RELAYS {
            let url = format!("ws://127.0.0.1:{}/scp/v1", 10_000 + i);
            let r = discovery.advertised_transports(&url).await;
            assert!(r.refreshed, "first insert of relay {i} fetches");
        }

        // The first relay is currently the least-recently-used. Insert one more
        // distinct relay to push the cache over capacity and evict it.
        let overflow = format!("ws://127.0.0.1:{}/scp/v1", 10_000 + MAX_CACHED_RELAYS);
        let r = discovery.advertised_transports(&overflow).await;
        assert!(r.refreshed);

        // The evicted (oldest) relay is no longer cached → its next lookup is a
        // fresh fetch (refresh), proving the cache is bounded, not unbounded.
        let evicted = discovery
            .advertised_transports("ws://127.0.0.1:10000/scp/v1")
            .await;
        assert!(
            evicted.refreshed,
            "the least-recently-used relay must have been evicted past capacity"
        );

        // A recently-inserted relay is still resident (served from cache).
        let recent = discovery.advertised_transports(&overflow).await;
        assert!(
            !recent.refreshed,
            "a recently-used relay must remain cached"
        );
    }
}
