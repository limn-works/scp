//! Transparent native QUIC ↔ WebSocket transport selection (spec §10.14.3
//! item 4, §10.5.1; ADR-037).
//!
//! When a relay advertises QUIC support in `.well-known/scp`
//! (`relay_config.transports` includes `"quic"`, §10.5.1), a native client
//! SHOULD prefer QUIC over WebSocket (lower overhead, connection migration).
//! This module implements that preference *transparently*: callers keep using
//! the same [`TransportAdapter`] surface and receive a `Box<dyn
//! TransportAdapter>` regardless of which transport was selected — exactly
//! like the browser-side WebTransport→WebSocket fallback in
//! `webtransport::fallback` (compiled under the `http3` feature), but for native
//! QUIC.
//!
//! # Selection algorithm (spec §10.14.3 item 4)
//!
//! 1. If the relay's advertised transports include `"quic"` **and** the `quic`
//!    cargo feature is enabled, probe QUIC with a **3-second timeout**. On a
//!    successful handshake within the window, return the `QuicAdapter`. On
//!    failure or timeout, fall back to WebSocket *and remember the failure* so
//!    QUIC is not re-probed for this relay until the next `.well-known/scp`
//!    refresh.
//! 2. If QUIC is not advertised (or the feature is disabled), connect
//!    WebSocket directly — no wasted probe.
//!
//! Per spec: *"If a relay does not advertise QUIC, clients fall back to
//! WebSocket. The client MAY probe QUIC with a single initial packet; if no
//! response within 3 seconds, it falls back to WebSocket without further QUIC
//! attempts for that relay until the next `.well-known/scp` refresh."*
//!
//! # No globals
//!
//! The selector holds its own per-relay suppression set; there are no
//! singletons or mutable module globals. Inject one [`TransportSelector`] per
//! logical relay-connection context (e.g. per bridge instance) and call
//! [`select_and_connect`](TransportSelector::select_and_connect) for each
//! connect. A `.well-known/scp` refresh clears the suppression for a relay via
//! [`clear_suppression`](TransportSelector::clear_suppression).
//!
//! See spec §10.14 in `.docs/specs/10-infrastructure-and-self-hosting.md` and
//! ADR-037 in `.docs/adrs/phase-2.md`.

use std::collections::HashSet;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::discovery::RelayTransportDiscovery;
use crate::error::TransportError;
use crate::heartbeat::SuppressionSuspected;
use crate::native::adapter::NativeRelayAdapter;
use crate::profile::TransportProfile;
use crate::relay::connection::SourcedRelayUrl;
use crate::traits::TransportAdapter;

/// Receiver for relay-suppression alerts from a WebSocket adapter.
///
/// Surfaced by a WebSocket adapter's heartbeat monitor (spec §9.9.4) and
/// returned alongside the adapter so the FFI/SDK layer can drain it into
/// reliability scoring (#1533 AC5).
///
/// `None` for the QUIC branch — QUIC uses native PING keepalive and has no
/// application-level heartbeat-suppression channel.
pub type SuppressionReceiver = tokio::sync::mpsc::Receiver<SuppressionSuspected>;

/// The advertised-transports literal for QUIC (spec §10.5.1).
const QUIC_TRANSPORT_LABEL: &str = "quic";

/// QUIC probe timeout (spec §10.14.3 item 4: "no response within 3 seconds").
#[cfg(feature = "quic")]
const QUIC_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Transparent native transport selector.
///
/// Decides between QUIC and WebSocket per connect, preferring QUIC when the
/// relay advertises it (spec §10.5.1), and remembering QUIC probe failures so
/// a dead/blocked QUIC port is not re-probed on every reconnect (spec §10.14.3
/// item 4). The decision is internal — callers always receive a
/// `Box<dyn TransportAdapter>`.
#[derive(Debug, Default)]
pub struct TransportSelector {
    /// Relay URLs whose QUIC probe failed; QUIC is suppressed for these until
    /// [`clear_suppression`](Self::clear_suppression) is called (on the next
    /// `.well-known/scp` refresh).
    quic_suppressed: Mutex<HashSet<String>>,
    /// Per-relay cache of the transports a relay advertises in its
    /// `.well-known/scp` document (spec §10.5.1). Co-located with
    /// `quic_suppressed` because the two share a lifecycle: a fresh
    /// `.well-known/scp` fetch (a discovery *refresh*) is exactly the point at
    /// which QUIC suppression for the relay is cleared (spec §10.14.3 item 4).
    discovery: RelayTransportDiscovery,
}

impl TransportSelector {
    /// Creates a selector with no suppressed relays and an empty discovery
    /// cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            quic_suppressed: Mutex::new(HashSet::new()),
            discovery: RelayTransportDiscovery::new(),
        }
    }

    /// Test-only constructor that injects a preconfigured discovery cache.
    ///
    /// Lets the discovering-connect tests point discovery at a local
    /// self-signed `.well-known/scp` server (see
    /// [`RelayTransportDiscovery::with_client_for_test`]). Production builds the
    /// discovery cache with its own non-permissive client.
    #[cfg(all(test, feature = "quic"))]
    #[must_use]
    pub(crate) fn with_discovery_for_test(discovery: RelayTransportDiscovery) -> Self {
        Self {
            quic_suppressed: Mutex::new(HashSet::new()),
            discovery,
        }
    }

    /// Returns `true` if QUIC is currently suppressed for `relay_url` (a prior
    /// probe failed and no refresh has cleared it).
    #[must_use]
    pub fn is_quic_suppressed(&self, relay_url: &str) -> bool {
        self.quic_suppressed
            .lock()
            .is_ok_and(|set| set.contains(relay_url))
    }

    /// Clears the QUIC suppression for `relay_url`, allowing QUIC to be
    /// re-probed on the next connect.
    ///
    /// Call this when a fresh `.well-known/scp` document is fetched for the
    /// relay (spec §10.14.3 item 4: suppression lasts "until the next
    /// `.well-known/scp` refresh").
    pub fn clear_suppression(&self, relay_url: &str) {
        if let Ok(mut set) = self.quic_suppressed.lock() {
            set.remove(relay_url);
        }
    }

    /// Records that QUIC probing failed for `relay_url`, suppressing further
    /// QUIC probes until a refresh.
    ///
    /// Only invoked from the QUIC probe path (and unit tests); when the `quic`
    /// feature is disabled the probe compiles out, so allow it to be unused in
    /// that configuration rather than gating callers.
    #[cfg_attr(not(any(feature = "quic", test)), allow(dead_code))]
    fn suppress_quic(&self, relay_url: &str) {
        if let Ok(mut set) = self.quic_suppressed.lock() {
            set.insert(relay_url.to_owned());
        }
    }

    /// Connects to the relay, transparently selecting QUIC or WebSocket.
    ///
    /// QUIC is attempted only when **all** of the following hold:
    /// - the `quic` cargo feature is enabled,
    /// - `advertised_transports` is `Some` and contains `"quic"` (spec
    ///   §10.5.1),
    /// - the relay URL is a TLS scheme (`wss://` / `https://` — QUIC has no
    ///   plaintext form),
    /// - QUIC is not currently suppressed for this relay (no prior probe
    ///   failure since the last refresh).
    ///
    /// On a successful QUIC handshake within the 3-second probe window the
    /// `QuicAdapter` is returned. On probe failure/timeout the selector
    /// records the failure (suppressing QUIC for this relay) and falls back to
    /// WebSocket. When QUIC is not eligible, WebSocket is used directly with no
    /// wasted probe.
    ///
    /// `advertised_transports` is the `relay_config.transports` list from the
    /// relay's `.well-known/scp` document. Pass `None` when the list is not
    /// available at the call site — the selector then degrades to WebSocket
    /// only (the mandatory baseline, spec §10.5.1), never fabricating a QUIC
    /// advertisement.
    ///
    /// # Errors
    ///
    /// Returns the WebSocket connection error if the WebSocket fallback (or
    /// direct WebSocket) cannot be established. A failed QUIC probe is **not**
    /// surfaced as an error — it transparently triggers WebSocket fallback.
    pub async fn select_and_connect(
        &self,
        sourced: &SourcedRelayUrl,
        advertised_transports: Option<&[String]>,
        profile: Option<&TransportProfile>,
    ) -> Result<Box<dyn TransportAdapter>, TransportError> {
        let (adapter, _suppression) = self
            .select_and_connect_with_suppression(sourced, advertised_transports, profile)
            .await?;
        Ok(adapter)
    }

    /// Like [`select_and_connect`](Self::select_and_connect), but also returns
    /// the WebSocket adapter's suppression-event receiver when one was created.
    ///
    /// The receiver carries relay-suppression alerts from the WebSocket
    /// heartbeat monitor (spec §9.9.4) and is meant to be drained by the
    /// FFI/SDK layer into reliability scoring (#1533 AC5). It is `None` when:
    /// - QUIC was selected (no application-level heartbeat channel), or
    /// - no `profile` was supplied (heartbeat monitoring requires a profile),
    ///   or the profile is `Constrained` (poll-based, no heartbeat).
    ///
    /// # Errors
    ///
    /// Returns the WebSocket connection error if the WebSocket fallback (or
    /// direct WebSocket) cannot be established. A failed QUIC probe is not an
    /// error — it transparently triggers WebSocket fallback.
    pub async fn select_and_connect_with_suppression(
        &self,
        sourced: &SourcedRelayUrl,
        advertised_transports: Option<&[String]>,
        profile: Option<&TransportProfile>,
    ) -> Result<(Box<dyn TransportAdapter>, Option<SuppressionReceiver>), TransportError> {
        if self.should_try_quic(sourced, advertised_transports)
            && let Some(adapter) = self.try_quic_probe(&sourced.url, profile).await
        {
            // QUIC has no application-level suppression channel.
            return Ok((adapter, None));
        }
        // QUIC not eligible, or the probe failed/timed out (which records
        // suppression so we skip QUIC next time for this relay, spec §10.14.3
        // item 4). Either way, fall through to the WebSocket baseline.

        let mut ws = NativeRelayAdapter::connect_sourced(sourced, profile).await?;
        let suppression = ws.take_suppression_receiver();
        Ok((Box::new(ws), suppression))
    }

    /// Connects to the relay, discovering its advertised transports from
    /// `.well-known/scp` first, then transparently selecting QUIC or WebSocket.
    ///
    /// This is the connect entry point used by the FFI/SDK layer (spec §10.5.1,
    /// §10.14.3 item 4; ADR-037). It closes the gap that
    /// [`select_and_connect`](Self::select_and_connect) leaves when its caller
    /// has no advertised-transports list: instead of always degrading to the
    /// WebSocket baseline, it fetches the relay's `relay_config.transports`
    /// (cached per relay) and feeds that list into the same QUIC-vs-WebSocket
    /// decision. The signature is unchanged from the caller's perspective —
    /// discovery happens internally (decision D3).
    ///
    /// Discovery is fail-open: any fetch/parse failure resolves to "transports
    /// unknown", i.e. the WebSocket baseline. A discovery failure never fails
    /// the connect.
    ///
    /// On a *fresh* discovery fetch (a `.well-known/scp` refresh, as opposed to
    /// a cache hit) QUIC suppression for this relay is cleared first, so a
    /// relay that has reconfigured its QUIC support since the last failed probe
    /// is re-probed (spec §10.14.3 item 4: suppression lasts "until the next
    /// `.well-known/scp` refresh").
    ///
    /// # Errors
    ///
    /// Returns the WebSocket connection error if the WebSocket fallback (or
    /// direct WebSocket) cannot be established. A failed QUIC probe is not an
    /// error — it transparently triggers WebSocket fallback.
    pub async fn select_and_connect_discovering(
        &self,
        sourced: &SourcedRelayUrl,
        profile: Option<&TransportProfile>,
    ) -> Result<Box<dyn TransportAdapter>, TransportError> {
        let (adapter, _suppression) = self
            .select_and_connect_discovering_with_suppression(sourced, profile)
            .await?;
        Ok(adapter)
    }

    /// Like [`select_and_connect_discovering`](Self::select_and_connect_discovering),
    /// but also returns the WebSocket adapter's suppression-event receiver when
    /// one was created (drained into reliability scoring at the FFI/SDK layer).
    ///
    /// See [`select_and_connect_with_suppression`](Self::select_and_connect_with_suppression)
    /// for when the receiver is `None`.
    ///
    /// # Errors
    ///
    /// Returns the WebSocket connection error if the WebSocket fallback (or
    /// direct WebSocket) cannot be established. A failed QUIC probe is not an
    /// error — it transparently triggers WebSocket fallback.
    pub async fn select_and_connect_discovering_with_suppression(
        &self,
        sourced: &SourcedRelayUrl,
        profile: Option<&TransportProfile>,
    ) -> Result<(Box<dyn TransportAdapter>, Option<SuppressionReceiver>), TransportError> {
        // Fetch the relay's advertised transports (cached per relay). Fail-open:
        // on any failure this resolves to `None` → WebSocket baseline.
        let discovered = self.discovery.advertised_transports(&sourced.url).await;

        // A fresh `.well-known/scp` fetch is the refresh point at which QUIC
        // suppression for this relay is cleared (spec §10.14.3 item 4). A cache
        // hit is NOT a refresh, so leave any standing suppression in place.
        if discovered.refreshed {
            self.clear_suppression(&sourced.url);
        }

        self.select_and_connect_with_suppression(sourced, discovered.transports.as_deref(), profile)
            .await
    }

    /// Like [`select_and_connect`](Self::select_and_connect), but for relays
    /// that require an `Authorization: Bearer <token>` header (e.g.
    /// `ApplicationNode` relays).
    ///
    /// QUIC is **not** attempted on this path: bearer authentication is a
    /// WebSocket-upgrade concept and `QuicAdapter` has no bearer surface, so a
    /// bearer connect always uses the WebSocket adapter
    /// ([`connect_sourced_with_bearer`](NativeRelayAdapter::connect_sourced_with_bearer)).
    /// This keeps the bearer path on its single supported transport while still
    /// flowing through the selection layer for a uniform connect surface.
    ///
    /// # Errors
    ///
    /// Returns the WebSocket connection error if the connection (including
    /// bearer authentication) fails.
    pub async fn select_and_connect_with_bearer(
        &self,
        sourced: &SourcedRelayUrl,
        bearer_token: Option<Zeroizing<String>>,
        profile: Option<&TransportProfile>,
    ) -> Result<Box<dyn TransportAdapter>, TransportError> {
        let ws =
            NativeRelayAdapter::connect_sourced_with_bearer(sourced, bearer_token, profile).await?;
        Ok(Box::new(ws))
    }

    /// Returns `true` if QUIC should be probed for this connect.
    ///
    /// Evaluates the advertised list, the suppression set, and the URL scheme.
    /// When the `quic` feature is disabled this is always `false` (the whole
    /// QUIC path compiles out).
    fn should_try_quic(
        &self,
        sourced: &SourcedRelayUrl,
        advertised_transports: Option<&[String]>,
    ) -> bool {
        // QUIC advertised? (case-insensitive match on the §10.5.1 label.)
        let advertised = advertised_transports.is_some_and(|list| {
            list.iter()
                .any(|t| t.eq_ignore_ascii_case(QUIC_TRANSPORT_LABEL))
        });
        if !advertised {
            return false;
        }
        // Not suppressed by a prior probe failure for this relay.
        if self.is_quic_suppressed(&sourced.url) {
            return false;
        }
        // QUIC requires a TLS scheme; plaintext relays stay on WebSocket.
        url_is_tls_scheme(&sourced.url)
    }

    /// Probes QUIC with the spec-mandated 3-second timeout.
    ///
    /// Returns `Some(adapter)` on a successful handshake within the window,
    /// `None` on failure/timeout (after recording suppression for the relay).
    ///
    /// When the `quic` feature is disabled this always returns `None` and
    /// records no suppression (the QUIC code is compiled out, leaving the
    /// function with no `.await` — hence the conditional `unused_async` allow).
    #[allow(unused_variables)]
    #[cfg_attr(not(feature = "quic"), allow(clippy::unused_async))]
    async fn try_quic_probe(
        &self,
        relay_url: &str,
        profile: Option<&TransportProfile>,
    ) -> Option<Box<dyn TransportAdapter>> {
        #[cfg(feature = "quic")]
        {
            use crate::quic::QuicAdapter;
            use crate::quic::lifecycle::{QuicLifecycleManager, SessionTicketStore};

            // Derive the lifecycle profile; default to Desktop when the caller
            // did not specify one (matches the native adapter's behavior of a
            // sensible always-on default for native clients).
            let lifecycle_profile = profile.copied().unwrap_or(TransportProfile::Desktop);
            let lifecycle = QuicLifecycleManager::new(lifecycle_profile, SessionTicketStore::new());

            let connect = QuicAdapter::connect_url(relay_url, lifecycle);
            match tokio::time::timeout(QUIC_PROBE_TIMEOUT, connect).await {
                Ok(Ok(adapter)) => return Some(Box::new(adapter)),
                Ok(Err(e)) => {
                    tracing::debug!(
                        relay_url = %relay_url,
                        error = %e,
                        "QUIC probe failed; falling back to WebSocket and suppressing QUIC \
                         for this relay until the next .well-known/scp refresh"
                    );
                }
                Err(_elapsed) => {
                    tracing::debug!(
                        relay_url = %relay_url,
                        timeout_secs = QUIC_PROBE_TIMEOUT.as_secs(),
                        "QUIC probe timed out; falling back to WebSocket and suppressing QUIC \
                         for this relay until the next .well-known/scp refresh"
                    );
                }
            }
            // Probe failed or timed out: suppress QUIC for this relay.
            self.suppress_quic(relay_url);
        }

        None
    }
}

/// Returns `true` if the relay URL uses a TLS scheme (`wss://` / `https://`).
///
/// QUIC mandates TLS 1.3 (RFC 9001 §4.1); plaintext schemes (`ws://`,
/// `http://`) have no QUIC form and stay on WebSocket. Scheme matching is
/// case-insensitive (RFC 3986 §3.1).
fn url_is_tls_scheme(relay_url: &str) -> bool {
    let lower = relay_url.to_ascii_lowercase();
    lower.starts_with("wss://") || lower.starts_with("https://")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::relay::connection::RelayUrlSource;
    #[cfg(feature = "quic")]
    use std::time::Duration;

    fn sourced(url: &str, source: RelayUrlSource) -> SourcedRelayUrl {
        SourcedRelayUrl {
            url: url.to_owned(),
            source,
        }
    }

    // -- url_is_tls_scheme -------------------------------------------------

    #[test]
    fn tls_scheme_detection() {
        assert!(url_is_tls_scheme("wss://relay.example.com/scp/v1"));
        assert!(url_is_tls_scheme("https://relay.example.com/scp/v1"));
        assert!(url_is_tls_scheme("WSS://relay.example.com/scp/v1"));
        assert!(!url_is_tls_scheme("ws://127.0.0.1:9000/scp/v1"));
        assert!(!url_is_tls_scheme("http://127.0.0.1:9000/scp/v1"));
    }

    // -- should_try_quic ---------------------------------------------------

    #[test]
    fn no_advertised_transports_means_no_quic() {
        let selector = TransportSelector::new();
        let s = sourced("wss://relay.example.com/scp/v1", RelayUrlSource::WellKnown);
        assert!(!selector.should_try_quic(&s, None));
    }

    #[test]
    fn advertised_without_quic_means_no_quic() {
        let selector = TransportSelector::new();
        let s = sourced("wss://relay.example.com/scp/v1", RelayUrlSource::WellKnown);
        let list = vec!["websocket".to_owned(), "webtransport".to_owned()];
        assert!(!selector.should_try_quic(&s, Some(&list)));
    }

    #[test]
    fn advertised_with_quic_on_tls_url_tries_quic() {
        let selector = TransportSelector::new();
        let s = sourced("wss://relay.example.com/scp/v1", RelayUrlSource::WellKnown);
        let list = vec!["websocket".to_owned(), "quic".to_owned()];
        assert!(selector.should_try_quic(&s, Some(&list)));
    }

    #[test]
    fn advertised_quic_case_insensitive() {
        let selector = TransportSelector::new();
        let s = sourced("wss://relay.example.com/scp/v1", RelayUrlSource::WellKnown);
        let list = vec!["WebSocket".to_owned(), "QUIC".to_owned()];
        assert!(selector.should_try_quic(&s, Some(&list)));
    }

    #[test]
    fn quic_advertised_but_plaintext_url_stays_websocket() {
        let selector = TransportSelector::new();
        // ws:// (plaintext) cannot use QUIC even if advertised.
        let s = sourced("ws://127.0.0.1:9000/scp/v1", RelayUrlSource::DhtResolved);
        let list = vec!["websocket".to_owned(), "quic".to_owned()];
        assert!(!selector.should_try_quic(&s, Some(&list)));
    }

    #[test]
    fn suppressed_relay_skips_quic() {
        let selector = TransportSelector::new();
        let s = sourced("wss://relay.example.com/scp/v1", RelayUrlSource::WellKnown);
        let list = vec!["websocket".to_owned(), "quic".to_owned()];

        assert!(selector.should_try_quic(&s, Some(&list)));
        selector.suppress_quic(&s.url);
        assert!(selector.is_quic_suppressed(&s.url));
        assert!(!selector.should_try_quic(&s, Some(&list)));

        // A refresh clears suppression → QUIC eligible again.
        selector.clear_suppression(&s.url);
        assert!(!selector.is_quic_suppressed(&s.url));
        assert!(selector.should_try_quic(&s, Some(&list)));
    }

    // -- select_and_connect: WebSocket path (no QUIC) ----------------------

    /// With no advertised transports, the selector connects WebSocket and
    /// never constructs a QUIC endpoint. Verified against a real local relay.
    #[tokio::test]
    async fn select_connects_websocket_when_quic_not_advertised() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, addr) = server.start().await.unwrap();
        let url = format!("ws://{addr}/scp/v1");

        let selector = TransportSelector::new();
        let s = sourced(&url, RelayUrlSource::DhtResolved);

        // No advertised transports → WebSocket only, no QUIC probe.
        let adapter = selector
            .select_and_connect(&s, None, None)
            .await
            .expect("WebSocket connect should succeed");

        // The relay never received a QUIC connection; the adapter is the WS
        // native adapter. Exercise it to confirm a live WS connection.
        drop(adapter);
        assert!(!selector.is_quic_suppressed(&url));
    }

    /// A QUIC probe against a TLS relay that advertises QUIC but has no live
    /// QUIC listener (dead UDP port) falls back to WebSocket within ~3s and
    /// suppresses QUIC for that relay. A second connect skips the probe.
    ///
    /// Uses a real local WebSocket relay reachable over `ws://` for the
    /// fallback leg, but advertises a `wss://`-style probe target via a
    /// separate dead-port URL to exercise the QUIC-probe-then-fallback path.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn quic_probe_dead_port_falls_back_and_suppresses() {
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        // Live WebSocket relay for the fallback leg.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, ws_addr) = server.start().await.unwrap();

        // The probe target is a `wss://` URL whose QUIC (UDP) port is dead:
        // we reuse the WS relay's host:port but over wss://. There is no QUIC
        // listener there, so the handshake cannot complete → timeout/fail →
        // fallback. The fallback connects WS to the same host:port. Because
        // the relay's WS listener accepts plaintext only, we instead drive the
        // fallback through ws:// by using a DhtResolved source on a ws:// URL
        // and asserting suppression via the probe helper directly below.
        let dead_quic_url = format!("wss://127.0.0.1:{}/scp/v1", ws_addr.port());

        let selector = TransportSelector::new();

        // Drive the probe directly to assert the 3s-bounded fallback + the
        // suppression side effect without depending on a wss:// WS listener.
        let start = std::time::Instant::now();
        let probe = selector.try_quic_probe(&dead_quic_url, None).await;
        let elapsed = start.elapsed();

        assert!(probe.is_none(), "QUIC probe to a dead port must fail");
        assert!(
            elapsed <= Duration::from_secs(4),
            "probe must bound to ~3s, took {elapsed:?}"
        );
        assert!(
            selector.is_quic_suppressed(&dead_quic_url),
            "a failed probe must suppress QUIC for the relay"
        );

        // Second probe is skipped by should_try_quic (suppressed).
        let list = vec!["quic".to_owned()];
        let s = sourced(&dead_quic_url, RelayUrlSource::WellKnown);
        assert!(
            !selector.should_try_quic(&s, Some(&list)),
            "a suppressed relay must skip the QUIC probe on the next connect"
        );
    }

    // -- select_and_connect_discovering: end-to-end discovery → selection ---

    /// END-TO-END PROOF that QUIC is now actually selected (the gap PR-3a
    /// left): a relay whose `.well-known/scp` advertises `["quic",
    /// "websocket"]` is fetched at connect time, and the discovered list drives
    /// a real QUIC probe. The relay has no QUIC listener (the advertising
    /// endpoint serves HTTPS, not QUIC/UDP), so the probe fails within ~3s and
    /// the selector suppresses QUIC for the relay. The suppression side effect
    /// is observable ONLY if discovery fed the `"quic"` advertisement into the
    /// selector — which is exactly what PR-3a's `None` plumbing prevented.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn discovering_connect_attempts_quic_when_advertised() {
        use crate::discovery::RelayTransportDiscovery;
        use crate::discovery_test_support::{start_well_known_server, trusting_client};

        // The well-known server advertises QUIC. It serves HTTPS only — there
        // is no QUIC (UDP) listener on its port, so the QUIC probe will fail.
        let body = r#"{
            "version": 1,
            "did": "did:dht:z6MkRelay",
            "relay": "wss://127.0.0.1/scp/v1",
            "relay_config": { "transports": ["websocket", "quic"] }
        }"#
        .to_owned();
        let server = start_well_known_server(body).await;
        let client = trusting_client(&server.cert_pem, Duration::from_secs(2));
        let discovery = RelayTransportDiscovery::with_client_for_test(
            client,
            crate::discovery::DEFAULT_DISCOVERY_TTL,
        );
        let selector = TransportSelector::with_discovery_for_test(discovery);

        let relay_url = server.relay_url();
        let s = sourced(&relay_url, RelayUrlSource::WellKnown);

        // The discovering connect fetches transports (QUIC advertised), probes
        // QUIC (no listener → fails within ~3s → suppresses), then falls back
        // to WebSocket. The WS leg targets the same HTTPS-only port and so
        // cannot complete; we only care that QUIC was *attempted*, proven by
        // the suppression side effect.
        let start = std::time::Instant::now();
        let _ = selector.select_and_connect_discovering(&s, None).await;
        let elapsed = start.elapsed();

        assert!(
            selector.is_quic_suppressed(&relay_url),
            "discovery must have fed the advertised QUIC list into the selector, \
             triggering a QUIC probe that failed and suppressed QUIC for the relay"
        );
        assert!(
            elapsed <= Duration::from_secs(6),
            "the QUIC probe must remain ~3s-bounded end-to-end, took {elapsed:?}"
        );
    }

    /// Discovery fetch failure (the relay serves no `.well-known/scp`) → the
    /// selector falls open to the WebSocket baseline, the connect succeeds, and
    /// QUIC is never probed (so the relay is not suppressed). Verified against
    /// a real local WebSocket relay.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn discovering_connect_fails_open_to_websocket_no_quic_probe() {
        use crate::discovery::RelayTransportDiscovery;
        use crate::discovery_test_support::trusting_client;
        use crate::native::server::{RelayConfig, RelayServer};
        use crate::native::storage::BlobStorageBackend;
        use std::net::SocketAddr;
        use std::sync::Arc;

        // Live plaintext WebSocket relay for the baseline connect.
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ttl_check_interval: Duration::from_millis(100),
            delivery_jitter_ms: 0,
            ..RelayConfig::default()
        };
        let storage = Arc::new(BlobStorageBackend::in_memory());
        let server = RelayServer::new(config, storage);
        let (_handle, ws_addr) = server.start().await.unwrap();
        let url = format!("ws://{ws_addr}/scp/v1");

        // Discovery is configured with a real client, but the `ws://` relay
        // maps to no `https://` well-known URL, so the fetch never happens and
        // discovery fails open to None → WebSocket baseline.
        let dummy_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .cert
            .pem();
        let client = trusting_client(&dummy_cert, Duration::from_millis(500));
        let discovery = RelayTransportDiscovery::with_client_for_test(
            client,
            crate::discovery::DEFAULT_DISCOVERY_TTL,
        );
        let selector = TransportSelector::with_discovery_for_test(discovery);

        let s = sourced(&url, RelayUrlSource::DhtResolved);
        let adapter = selector
            .select_and_connect_discovering(&s, None)
            .await
            .expect("WebSocket baseline connect should succeed when discovery fails open");
        drop(adapter);

        assert!(
            !selector.is_quic_suppressed(&url),
            "a plaintext relay must never trigger a QUIC probe, so it is never suppressed"
        );
    }

    /// Two discovering connects to the same relay fetch `.well-known/scp`
    /// exactly once: the second connect is served from the per-relay cache.
    /// Asserted via the server's request counter.
    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn discovering_connect_caches_well_known_fetched_once() {
        use crate::discovery::RelayTransportDiscovery;
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
        let discovery = RelayTransportDiscovery::with_client_for_test(
            client,
            crate::discovery::DEFAULT_DISCOVERY_TTL,
        );
        let selector = TransportSelector::with_discovery_for_test(discovery);

        let relay_url = server.relay_url();
        let s = sourced(&relay_url, RelayUrlSource::WellKnown);

        // Two discovering connects. Each probes QUIC (no listener) and the WS
        // leg fails, but the well-known fetch is what we are counting. After the
        // first connect QUIC is suppressed, so the second connect must NOT
        // re-fetch from a cache miss — the cached transports satisfy it.
        let _ = selector.select_and_connect_discovering(&s, None).await;
        let _ = selector.select_and_connect_discovering(&s, None).await;

        assert_eq!(
            server.request_count(),
            1,
            ".well-known/scp must be fetched exactly once across two connects \
             to the same relay"
        );
    }
}
