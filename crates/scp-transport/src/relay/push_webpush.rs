//! The `WebPush` push sender (PUSH-022, spec 10 §10.7.1 step 5, RFC 8030,
//! RFC 8291, RFC 8292, ADR-004).
//!
//! Sends the `WebPush` row of the §10.7.1 step 5 wake-signal table: `POST
//! <endpoint>` over HTTPS, the endpoint used byte for byte, with the headers
//! `Content-Encoding: aes128gcm`, `Urgency: high`, `TTL: 3600` and
//! `Authorization: vapid t=<VAPID JWT>, k=<VAPID public key>`, and the body
//! the RFC 8291 encryption of `{"scp":"1"}`, one 114-byte aes128gcm record
//! sealed under a fresh ephemeral key and salt (`scp_crypto::webpush::seal`).
//!
//! The VAPID JWT has the constant JOSE header `{"typ":"JWT","alg":"ES256"}`
//! and the claims `aud` (the endpoint's RFC 6454 origin), `exp` (12 hours
//! after minting) and `sub` (the operator's contact), in that order. The
//! sender keeps one JWT per origin in a bounded LRU cache and mints a new one
//! when the cached one is within 5 minutes of `exp`. The cache holds JWTs
//! only; back-off state lives apart (**Back-off** below).
//!
//! Every connection goes through the ADR-004 endpoint refusal rule
//! ([`super::push_endpoint`]): the HTTP client resolves each host through a
//! [`CheckedResolver`], an IP-literal host is judged before the request, no
//! proxy is used, and no redirect is followed.
//!
//! Response mapping (spec 10 §10.7.1, the `WebPush` responses, and PUSH-022):
//!
//! | Response | Outcome |
//! |---|---|
//! | 201 | `Delivered` |
//! | 404, 410, 403 | `InvalidToken` |
//! | 3xx, or a refused address | `InvalidToken` |
//! | 400, 401, 413 | `ConfigError` |
//! | no answer before [`WEBPUSH_CLIENT_LIMITS`]' request deadline, or a connection refused or reset | `Unreachable`, and that origin backs off |
//! | 429, 5xx | `Transient`, and that origin backs off |
//! | a name that does not resolve, or another transport failure | `Transient`, and that origin backs off |
//! | any other 2xx | `Delivered` |
//! | any other status | `Transient`, and that origin backs off |
//!
//! A hostile endpoint chooses its own status, so a status the table does not
//! name is `Transient`, never `ConfigError`. The dispatcher counts
//! `Unreachable` toward removal as it counts `InvalidToken` (spec 10 §10.7.1
//! **Unreachable `WebPush` push service**).
//!
//! **Back-off.** One registrant chooses each endpoint, so the back-off after
//! a `Transient` or `Unreachable` outcome is per endpoint origin, not per
//! platform. The dispatcher (`push_dispatch`) holds a wake for an origin in
//! back-off until the back-off ends, and [`WebPushSender::send`] itself waits
//! out a back-off that started after the dispatcher looked, so no wake is
//! consumed by a back-off. Each send carries its origin's back-off epoch, and
//! only an outcome from the current epoch moves the back-off: sends already
//! in flight when a back-off starts cannot double it or clear it. The
//! back-off map is bounded and never forgets an origin whose back-off has not
//! ended.
//!
//! No log line or `Debug` output carries the endpoint, its host or origin,
//! `p256dh`, `auth`, the VAPID key or a JWT.

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lru::LruCache;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use scp_clock::{Clock, SystemClock};
use scp_crypto::p256::jose::es256_sign;
use scp_crypto::p256::{P256PublicKey, P256SecretKey};
use scp_protocol::discovery::push::WebPushSubscription;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::push::{
    CONNECT_TIMEOUT, PRODUCTION_KEEP_ALIVE, PushSendOutcome, PushSenderError, compact_jws_bytes,
    read_bounded, transport_error_kind,
};
use super::push_endpoint::{
    CheckedResolver, EndpointError, Nat64Prefixes, OwnAddresses, parse_endpoint,
};
use crate::backoff::ReconnectBackoff;

/// The plaintext of every `WebPush` wake (§10.7.1 step 5).
pub(super) const WEBPUSH_WAKE_PLAINTEXT: &[u8] = br#"{"scp":"1"}"#;

/// The `TTL` header of every `WebPush` wake: the `WebPush` wake TTL,
/// 3,600 seconds (`09-security-model.md` §9.18.13).
pub const WEBPUSH_WAKE_TTL_SECS: u32 = 3600;

/// The constant JOSE header of every VAPID JWT (§10.7.1 **VAPID JWT**), as
/// bytes, so its member order is the spec's.
const VAPID_JWT_HEADER: &[u8] = br#"{"typ":"JWT","alg":"ES256"}"#;

/// How long after minting a VAPID JWT expires (indicator: 12 hours; RFC 8292
/// §2 allows at most 24).
const VAPID_JWT_LIFETIME_SECS: u64 = 12 * 60 * 60;

/// A cached VAPID JWT closer than this to its `exp` is replaced (indicator:
/// 5 minutes).
const VAPID_JWT_REMINT_BEFORE_SECS: u64 = 5 * 60;

/// The most endpoint origins whose JWT the sender keeps (indicator: 1,024).
/// The least recently used origin is forgotten first.
const ORIGIN_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(1023);

/// The most endpoint origins the sender keeps back-off state for (indicator:
/// 1,024). An origin whose back-off has not ended is never forgotten; when
/// every entry is still backing off, a newly failing origin gets no back-off
/// (the dispatcher's per-origin cap still bounds its sends).
const ORIGIN_BACKOFF_CAPACITY: usize = 1024;

/// The first back-off of an origin after a `Transient` or `Unreachable`
/// outcome (indicator: 1 s), doubling on each further one with up to 25%
/// jitter.
pub(super) const ORIGIN_BACKOFF_MIN: Duration = Duration::from_secs(1);

/// The longest back-off of an origin (indicator: 60 s).
const ORIGIN_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// The deadlines and idle-pool bounds of the sender's HTTP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientLimits {
    /// The whole request's deadline; a send that gets no answer by then is
    /// `Unreachable`.
    pub(crate) request_timeout: Duration,
    /// How long an idle connection stays in the pool.
    pub(crate) pool_idle_timeout: Duration,
    /// The most idle connections the pool keeps per host.
    pub(crate) pool_max_idle_per_host: usize,
}

/// The production limits. A push service answers a wake in milliseconds, so
/// a 5-second deadline (indicator) loses no live service and frees a hung
/// send's slot quickly. Registrants choose the hosts, so idle connections
/// stay 5 seconds (indicator) and at most 2 per host (indicator), and a
/// registrant cannot fill the relay with idle sockets.
pub(crate) const WEBPUSH_CLIENT_LIMITS: ClientLimits = ClientLimits {
    request_timeout: Duration::from_secs(5),
    pool_idle_timeout: Duration::from_secs(5),
    pool_max_idle_per_host: 2,
};

/// The operator's VAPID contact, the JWT `sub` claim: a `mailto:` or `https:`
/// URI (RFC 8292 §2.1).
#[derive(Clone, PartialEq, Eq)]
pub struct VapidSubject(String);

impl VapidSubject {
    /// Parses a VAPID contact.
    ///
    /// # Errors
    ///
    /// [`PushSenderError::InvalidConfig`] for field `subject` when `value` is
    /// not a URL, its scheme is neither `mailto` nor `https`, a `mailto:`
    /// URI names no address, an `https:` URI has no host, or `value` holds
    /// whitespace or a control character.
    pub fn parse(value: &str) -> Result<Self, PushSenderError> {
        let invalid = |reason| PushSenderError::InvalidConfig {
            field: "subject",
            reason,
        };
        if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(invalid("contains whitespace or a control character"));
        }
        let url = url::Url::parse(value).map_err(|_| invalid("not a URI"))?;
        match url.scheme() {
            "mailto" if !url.path().is_empty() => Ok(Self(value.to_owned())),
            "mailto" => Err(invalid("mailto: names no address")),
            "https" if url.host().is_some() => Ok(Self(value.to_owned())),
            "https" => Err(invalid("https: URI has no host")),
            _ => Err(invalid("scheme is neither mailto nor https")),
        }
    }

    /// The contact as configured.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VapidSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VapidSubject").field(&self.0).finish()
    }
}

/// Everything the `WebPush` sender needs. Relay startup (PUSH-023) loads the
/// key, parses the subject, gathers the relay's own addresses and reads the
/// operator's NAT64 prefixes.
pub struct WebPushConfig {
    /// The relay's VAPID signing key. Zeroized on drop by `scp-crypto`.
    pub vapid_key: P256SecretKey,
    /// The operator contact, the JWT `sub`.
    pub subject: VapidSubject,
    /// The relay's own addresses, refused as endpoint addresses (ADR-004).
    pub own_addresses: OwnAddresses,
    /// The NAT64 network-specific prefixes of the relay's network, whose
    /// addresses ADR-004 judges by their embedded IPv4 address; empty when
    /// the network has no NAT64 translator.
    pub nat64_prefixes: Nat64Prefixes,
}

impl fmt::Debug for WebPushConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPushConfig")
            .field("vapid_key", &"<redacted>")
            .field("subject", &self.subject)
            .field("own_addresses", &self.own_addresses)
            .field("nat64_prefixes", &self.nat64_prefixes)
            .finish()
    }
}

/// How the sender's HTTP client reaches push services.
pub(crate) enum Transport {
    /// The operating system's resolver behind the ADR-004 rule, and the
    /// `WebPKI` roots.
    Production,
    /// A test resolver, one extra trusted root and a test request deadline,
    /// so a test reaches a local TLS server and sees a hung one time out
    /// quickly. Absent from every non-test build.
    #[cfg(test)]
    Test {
        resolver: CheckedResolver,
        root: reqwest::Certificate,
        request_timeout: Duration,
    },
}

/// The VAPID claims, in the member order of §10.7.1 **VAPID JWT**.
#[derive(serde::Serialize)]
struct VapidClaims<'a> {
    aud: &'a str,
    exp: u64,
    sub: &'a str,
}

/// A VAPID JWT and its `exp`.
struct CachedJwt {
    jwt: Zeroizing<String>,
    exp: u64,
}

/// One origin's back-off.
struct OriginBackoff {
    backoff: ReconnectBackoff,
    /// No send to the origin starts before this.
    retry_at: Instant,
    /// The epoch this back-off step started; never 0.
    epoch: u64,
}

/// The back-off of every origin that failed and has not answered since.
///
/// An origin with no entry is in epoch 0. Each step of a back-off takes a
/// fresh epoch from `next_epoch`, so a send stamped before the step cannot
/// match it.
struct Backoffs {
    origins: HashMap<String, OriginBackoff>,
    next_epoch: u64,
}

impl Backoffs {
    fn new() -> Self {
        Self {
            origins: HashMap::new(),
            next_epoch: 1,
        }
    }

    /// `origin`'s current epoch and, while it is backing off at `now`, when
    /// the back-off ends.
    fn stamp(&self, origin: &str, now: Instant) -> (u64, Option<Instant>) {
        self.origins.get(origin).map_or((0, None), |state| {
            (
                state.epoch,
                (now < state.retry_at).then_some(state.retry_at),
            )
        })
    }

    /// Applies a send's `outcome` to `origin`'s back-off when the send was
    /// stamped with the current `epoch`, and ignores it otherwise. A
    /// `Transient` or `Unreachable` outcome takes the next back-off step under
    /// a new epoch; any other outcome ends the back-off.
    fn record(&mut self, origin: &str, epoch: u64, outcome: PushSendOutcome, now: Instant) {
        let current = self.origins.get(origin).map_or(0, |state| state.epoch);
        if epoch != current {
            return;
        }
        let failed = matches!(
            outcome,
            PushSendOutcome::Transient | PushSendOutcome::Unreachable
        );
        if !failed {
            self.origins.remove(origin);
            return;
        }
        let epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.saturating_add(1);
        if let Some(state) = self.origins.get_mut(origin) {
            state.retry_at = now + state.backoff.next_delay();
            state.epoch = epoch;
            return;
        }
        if self.origins.len() >= ORIGIN_BACKOFF_CAPACITY {
            // Forget only back-offs that have ended.
            self.origins.retain(|_, state| now < state.retry_at);
        }
        if self.origins.len() >= ORIGIN_BACKOFF_CAPACITY {
            tracing::debug!(
                platform = "webpush",
                "back-off map full of active back-offs; origin not backed off"
            );
            return;
        }
        let mut backoff = ReconnectBackoff::new(ORIGIN_BACKOFF_MIN, ORIGIN_BACKOFF_MAX);
        let retry_at = now + backoff.next_delay();
        self.origins.insert(
            origin.to_owned(),
            OriginBackoff {
                backoff,
                retry_at,
                epoch,
            },
        );
    }
}

/// The most verbose level the relay logs from hyper-util.
#[cfg(any(test, feature = "startup"))]
const HYPER_UTIL_LOG_CAP: tracing::Level = tracing::Level::INFO;

/// Whether the relay's log keeps an event with `metadata`. hyper-util's
/// DEBUG and TRACE lines name the host and port each connection goes to, and
/// a `WebPush` endpoint's host is a registrant's choice that PUSH-022 keeps
/// out of the log, so hyper-util is held at [`HYPER_UTIL_LOG_CAP`] whatever
/// `RUST_LOG` asks for. The relay's tracing subscriber (`startup`) and the
/// push sender tests' log capture apply this one predicate.
#[cfg(any(test, feature = "startup"))]
pub(crate) fn admits_log_event(metadata: &tracing::Metadata<'_>) -> bool {
    let target = metadata.target();
    let hyper_util = target == "hyper_util" || target.starts_with("hyper_util::");
    !hyper_util || *metadata.level() <= HYPER_UTIL_LOG_CAP
}

/// The endpoint origin of a registered `WebPush` token, the key of the
/// per-origin back-off and in-flight cap. `None` when the token or its
/// endpoint does not decode; the send of such a token sends nothing.
#[cfg(feature = "push-store")]
pub(crate) fn token_origin(token: &[u8]) -> Option<String> {
    let subscription = WebPushSubscription::decode(token).ok()?;
    parse_endpoint(subscription.endpoint())
        .ok()
        .map(|parsed| parsed.aud().to_owned())
}

/// Whether a request error is one spec 10 §10.7.1 **Unreachable `WebPush`
/// push service** counts: the request deadline passed, or the connection was
/// refused, reset or aborted before an answer arrived.
fn is_unreachable(error: &reqwest::Error) -> bool {
    if error.is_timeout() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::TimedOut
            );
        }
        source = current.source();
    }
    false
}

/// Sends `WebPush` wake signals. Built once per relay from a
/// [`WebPushConfig`].
pub struct WebPushSender {
    client: reqwest::Client,
    resolver: CheckedResolver,
    vapid_key: P256SecretKey,
    /// `k`: the base64url uncompressed VAPID public key.
    vapid_k: String,
    subject: VapidSubject,
    clock: Arc<dyn Clock>,
    jwts: Mutex<LruCache<String, CachedJwt>>,
    backoffs: Mutex<Backoffs>,
}

impl fmt::Debug for WebPushSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPushSender")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// Whether a request's error chain holds the ADR-004 refusal that the
/// [`CheckedResolver`] returned, and which.
fn endpoint_error_in(error: &reqwest::Error) -> Option<EndpointError> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(found) = current.downcast_ref::<EndpointError>() {
            return Some(*found);
        }
        source = current.source();
    }
    None
}

/// The sender's HTTP client builder under `limits`: no proxy, HTTPS only, no
/// redirect, and the production keep-alive.
fn client_builder(limits: ClientLimits) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(limits.request_timeout)
        .connect_timeout(CONNECT_TIMEOUT.min(limits.request_timeout))
        .pool_idle_timeout(limits.pool_idle_timeout)
        .pool_max_idle_per_host(limits.pool_max_idle_per_host)
        .http2_keep_alive_interval(PRODUCTION_KEEP_ALIVE.interval)
        .http2_keep_alive_timeout(PRODUCTION_KEEP_ALIVE.timeout)
        .http2_keep_alive_while_idle(true)
}

/// Maps a push service's status to the PUSH-022 outcome table.
const fn map_status(status: u16) -> PushSendOutcome {
    use PushSendOutcome::{ConfigError, Delivered, InvalidToken, Transient};
    match status {
        200..=299 => Delivered,
        300..=399 | 403 | 404 | 410 => InvalidToken,
        400 | 401 | 413 => ConfigError,
        _ => Transient,
    }
}

impl WebPushSender {
    /// Builds the production sender.
    ///
    /// # Errors
    ///
    /// [`PushSenderError::HttpClient`] when TLS cannot be initialized.
    pub fn new(config: WebPushConfig) -> Result<Self, PushSenderError> {
        Self::build(config, &Transport::Production, Arc::new(SystemClock))
    }

    /// Builds the sender with `transport` and `clock`. [`Self::new`] passes
    /// the production transport and the system clock.
    pub(crate) fn build(
        config: WebPushConfig,
        transport: &Transport,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PushSenderError> {
        let WebPushConfig {
            vapid_key,
            subject,
            own_addresses,
            nat64_prefixes,
        } = config;
        let (builder, resolver) = match transport {
            Transport::Production => (
                client_builder(WEBPUSH_CLIENT_LIMITS),
                CheckedResolver::new(own_addresses, nat64_prefixes),
            ),
            #[cfg(test)]
            Transport::Test {
                resolver,
                root,
                request_timeout,
            } => (
                client_builder(ClientLimits {
                    request_timeout: *request_timeout,
                    ..WEBPUSH_CLIENT_LIMITS
                })
                .add_root_certificate(root.clone()),
                resolver.clone(),
            ),
        };
        let client = builder
            .dns_resolver(Arc::new(resolver.clone()))
            .build()
            .map_err(|e| PushSenderError::HttpClient(e.without_url().to_string()))?;
        let vapid_k = URL_SAFE_NO_PAD.encode(vapid_key.public_key().to_uncompressed());
        Ok(Self {
            client,
            resolver,
            vapid_key,
            vapid_k,
            subject,
            clock,
            jwts: Mutex::new(LruCache::new(ORIGIN_CACHE_CAPACITY)),
            backoffs: Mutex::new(Backoffs::new()),
        })
    }

    /// The VAPID public key the relay publishes under ADR-004 (PUSH-023), so
    /// a browser can create a subscription this sender can authenticate to.
    #[must_use]
    pub fn vapid_public_key(&self) -> P256PublicKey {
        self.vapid_key.public_key()
    }

    /// The registration-time ADR-004 check of `endpoint` (PUSH-022): its URL
    /// rules, then its IP literal or every address its host resolves to.
    ///
    /// # Errors
    ///
    /// The [`EndpointError`] that refuses the endpoint or reports the failed
    /// lookup.
    pub async fn check_registration_endpoint(&self, endpoint: &str) -> Result<(), EndpointError> {
        self.resolver.check_registration_endpoint(endpoint).await
    }

    fn jwts(&self) -> MutexGuard<'_, LruCache<String, CachedJwt>> {
        // Each critical section leaves the cache consistent at every step.
        self.jwts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn backoffs(&self) -> MutexGuard<'_, Backoffs> {
        // Each critical section leaves the map consistent at every step.
        self.backoffs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// When `origin`'s back-off ends, while it is backing off.
    #[cfg(any(test, feature = "push-store"))]
    pub(crate) fn retry_at(&self, origin: &str) -> Option<Instant> {
        self.backoffs().stamp(origin, Instant::now()).1
    }

    /// Waits until `origin` is not backing off and returns the epoch the
    /// send carries.
    async fn wait_out_backoff(&self, origin: &str) -> u64 {
        loop {
            let (epoch, retry_at) = self.backoffs().stamp(origin, Instant::now());
            match retry_at {
                None => return epoch,
                Some(retry_at) => {
                    tracing::debug!(
                        platform = "webpush",
                        "endpoint origin backing off; wake waits"
                    );
                    tokio::time::sleep_until(retry_at).await;
                }
            }
        }
    }

    /// Sends one wake signal to `subscription`.
    pub async fn send(&self, subscription: &WebPushSubscription) -> PushSendOutcome {
        let parsed = match parse_endpoint(subscription.endpoint()) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::debug!(platform = "webpush", %error, "endpoint refused before sending");
                return PushSendOutcome::InvalidToken;
            }
        };
        if let Err(error) = self.resolver.check_literal(&parsed) {
            tracing::debug!(platform = "webpush", %error, "endpoint refused before sending");
            return PushSendOutcome::InvalidToken;
        }
        let aud = parsed.aud();
        // The dispatcher holds a wake for an origin in back-off; this wait
        // covers a back-off that began after it looked.
        let epoch = self.wait_out_backoff(aud).await;
        let Some(authorization) = self.authorization(aud) else {
            return PushSendOutcome::ConfigError;
        };
        let body = match scp_crypto::webpush::seal(
            subscription.p256dh(),
            subscription.auth(),
            WEBPUSH_WAKE_PLAINTEXT,
        ) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(platform = "webpush", %error, "wake encryption failed");
                return PushSendOutcome::ConfigError;
            }
        };
        let mut headers = HeaderMap::with_capacity(4);
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("aes128gcm"),
        );
        headers.insert(
            HeaderName::from_static("urgency"),
            HeaderValue::from_static("high"),
        );
        headers.insert(
            HeaderName::from_static("ttl"),
            HeaderValue::from(WEBPUSH_WAKE_TTL_SECS),
        );
        headers.insert(reqwest::header::AUTHORIZATION, authorization);

        let outcome = match self
            .client
            .post(parsed.url().clone())
            .headers(headers)
            .body(body)
            .send()
            .await
        {
            Ok(response) => {
                let status = read_bounded(response).await.status;
                let outcome = map_status(status);
                // The registrant chooses the endpoint, so a 400, 401 or 413
                // is no evidence about the relay's credentials; it stays at
                // `debug`, as every other answer does.
                tracing::debug!(platform = "webpush", status, ?outcome, "push send answered");
                outcome
            }
            Err(error) => match endpoint_error_in(&error) {
                Some(refusal) if refusal.is_refusal() => {
                    tracing::debug!(platform = "webpush", error = %refusal, "endpoint refused at connect");
                    PushSendOutcome::InvalidToken
                }
                Some(lookup) => {
                    tracing::debug!(platform = "webpush", error = %lookup, "endpoint lookup failed");
                    PushSendOutcome::Transient
                }
                None if is_unreachable(&error) => {
                    tracing::debug!(
                        platform = "webpush",
                        error_kind = transport_error_kind(&error),
                        "push service unreachable"
                    );
                    PushSendOutcome::Unreachable
                }
                None => {
                    tracing::debug!(
                        platform = "webpush",
                        error_kind = transport_error_kind(&error),
                        "push send failed in transport"
                    );
                    PushSendOutcome::Transient
                }
            },
        };
        self.backoffs().record(aud, epoch, outcome, Instant::now());
        outcome
    }

    /// The `Authorization` header for `aud`, reusing the origin's cached JWT
    /// unless it is within [`VAPID_JWT_REMINT_BEFORE_SECS`] of `exp`. `None`
    /// when signing failed.
    fn authorization(&self, aud: &str) -> Option<HeaderValue> {
        let now = self.clock.now_secs();
        let mut jwts = self.jwts();
        let fresh = jwts
            .get(aud)
            .filter(|cached| cached.exp > now.saturating_add(VAPID_JWT_REMINT_BEFORE_SECS))
            .map(|cached| cached.jwt.clone());
        let jwt = if let Some(jwt) = fresh {
            jwt
        } else {
            let exp = now.saturating_add(VAPID_JWT_LIFETIME_SECS);
            let jwt = self.mint_jwt(aud, exp)?;
            jwts.put(
                aud.to_owned(),
                CachedJwt {
                    jwt: jwt.clone(),
                    exp,
                },
            );
            jwt
        };
        drop(jwts);
        let value = Zeroizing::new(format!("vapid t={}, k={}", jwt.as_str(), self.vapid_k));
        let Ok(mut header) = HeaderValue::from_str(&value) else {
            tracing::warn!(
                platform = "webpush",
                "VAPID authorization is not a header value"
            );
            return None;
        };
        header.set_sensitive(true);
        Some(header)
    }

    /// Mints a VAPID JWT for `aud` expiring at `exp`.
    fn mint_jwt(&self, aud: &str, exp: u64) -> Option<Zeroizing<String>> {
        let claims = VapidClaims {
            aud,
            exp,
            sub: self.subject.as_str(),
        };
        let claims = match serde_json::to_vec(&claims) {
            Ok(claims) => claims,
            Err(error) => {
                tracing::warn!(platform = "webpush", %error, "VAPID claims did not serialize");
                return None;
            }
        };
        match compact_jws_bytes(VAPID_JWT_HEADER, &claims, |input| {
            es256_sign(&self.vapid_key, input).map(|signature| signature.to_vec())
        }) {
            Ok(jwt) => Some(jwt),
            Err(error) => {
                tracing::warn!(platform = "webpush", %error, "VAPID JWT signing failed");
                None
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use scp_clock::TestClock;
    use scp_crypto::p256::jose::es256_verify_lenient;

    use super::super::log_capture::LogCapture;
    use super::super::push::PushSender;
    use super::super::push_test_server::{
        CapturedRequest, HUNG_HOSTS, Reply, TLS_TEST_HOSTS, TestServer, TlsTestServer, hung_host,
    };
    use super::*;

    pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// §25.2's reference key, the VAPID key of Vector 60.
    const VAPID_SCALAR: &str = "6f0712104c3f61ba04526a822836d3f4a13be12e09a8c3c7586b2da0c795998b";
    /// Vector 60's `exp` less the sender's 12-hour lifetime.
    const VECTOR_60_NOW: u64 = 1_700_043_200 - VAPID_JWT_LIFETIME_SECS;
    const SUBJECT: &str = "mailto:operator@relay.example";
    pub const AUTH: [u8; 16] = *b"wake-auth-secret";
    /// A path no log line may carry.
    pub const PATH: &str = "/wpush/v2/subscription-secret-7b3e";

    pub fn vapid_key() -> TestResult<P256SecretKey> {
        let scalar: [u8; 32] = hex::decode(VAPID_SCALAR)?
            .try_into()
            .map_err(|_| "the scalar is 32 bytes")?;
        Ok(P256SecretKey::from_scalar_bytes(&scalar)?)
    }

    pub fn config() -> TestResult<WebPushConfig> {
        Ok(WebPushConfig {
            vapid_key: vapid_key()?,
            subject: VapidSubject::parse(SUBJECT)?,
            own_addresses: OwnAddresses::new([]),
            nat64_prefixes: Nat64Prefixes::new([]),
        })
    }

    /// A resolver that maps every [`TLS_TEST_HOSTS`] name and every
    /// [`hung_host`] to `127.0.0.1`, and `empty.example.net` to no address,
    /// letting loopback through only when `allow_loopback`.
    pub fn resolver(allow_loopback: bool) -> CheckedResolver {
        let mut table: HashMap<String, Vec<IpAddr>> = TLS_TEST_HOSTS
            .iter()
            .map(|host| (*host).to_owned())
            .chain((0..HUNG_HOSTS).map(hung_host))
            .map(|host| (host, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]))
            .collect();
        table.insert("empty.example.net".to_owned(), Vec::new());
        CheckedResolver::for_tests(OwnAddresses::new([]), table, allow_loopback)
    }

    /// A sender that reaches `server`; `allow_loopback` false applies the
    /// production ADR-004 rule, which refuses `server`'s address.
    pub fn sender_for(
        server: &TlsTestServer,
        allow_loopback: bool,
        clock: Arc<dyn Clock>,
    ) -> TestResult<WebPushSender> {
        sender_with_deadline(
            server,
            allow_loopback,
            clock,
            WEBPUSH_CLIENT_LIMITS.request_timeout,
        )
    }

    /// [`sender_for`] with `request_timeout` as the request deadline, so a
    /// test sees a hung endpoint time out quickly.
    pub fn sender_with_deadline(
        server: &TlsTestServer,
        allow_loopback: bool,
        clock: Arc<dyn Clock>,
        request_timeout: Duration,
    ) -> TestResult<WebPushSender> {
        Ok(WebPushSender::build(
            config()?,
            &Transport::Test {
                resolver: resolver(allow_loopback),
                root: server.root(),
                request_timeout,
            },
            clock,
        )?)
    }

    /// A user agent's subscription key pair and a subscription to `endpoint`.
    pub fn subscribe(endpoint: String) -> TestResult<(P256SecretKey, WebPushSubscription)> {
        let ua = P256SecretKey::random(&mut rand::rngs::OsRng);
        let subscription = WebPushSubscription::new(endpoint, ua.public_key(), AUTH)?;
        Ok((ua, subscription))
    }

    fn clock() -> Arc<TestClock> {
        Arc::new(TestClock::new(VECTOR_60_NOW))
    }

    fn production_sender(clock: Arc<TestClock>) -> TestResult<WebPushSender> {
        Ok(WebPushSender::build(
            config()?,
            &Transport::Production,
            clock,
        )?)
    }

    /// The `t` and `k` of a captured `Authorization: vapid` header.
    fn vapid_parts(request: &CapturedRequest) -> TestResult<(String, String)> {
        let value = request.header("authorization").ok_or("no Authorization")?;
        let rest = value.strip_prefix("vapid t=").ok_or("not vapid")?;
        let (t, k) = rest.split_once(", k=").ok_or("no k")?;
        Ok((t.to_owned(), k.to_owned()))
    }

    /// The JWT of an `Authorization` header value.
    fn jwt_of(header: &HeaderValue) -> TestResult<String> {
        let value = header.to_str()?;
        let rest = value.strip_prefix("vapid t=").ok_or("not vapid")?;
        let (t, _) = rest.split_once(", k=").ok_or("no k")?;
        Ok(t.to_owned())
    }

    /// Verifies `jwt` under the VAPID key and returns its claims.
    fn verified_claims(jwt: &str) -> TestResult<serde_json::Value> {
        let (input, signature) = jwt.rsplit_once('.').ok_or("no signature")?;
        let signature = URL_SAFE_NO_PAD.decode(signature)?;
        es256_verify_lenient(&vapid_key()?.public_key(), input.as_bytes(), &signature)?;
        let (header, claims) = input.split_once('.').ok_or("no claims")?;
        assert_eq!(URL_SAFE_NO_PAD.decode(header)?, VAPID_JWT_HEADER);
        Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims)?)?)
    }

    /// The port of a URL that names one.
    fn port_of(url: &str) -> TestResult<u16> {
        Ok(url::Url::parse(url)?.port().ok_or("no port")?)
    }

    #[test]
    fn vapid_subject_accepts_mailto_and_https_only() -> TestResult {
        for good in [SUBJECT, "https://relay.example/contact"] {
            assert_eq!(VapidSubject::parse(good)?.as_str(), good);
        }
        for bad in [
            "",
            "operator@relay.example",
            "mailto:",
            "http://relay.example",
            "https://",
            "mailto:operator@relay.example\n",
            "mailto:operator @relay.example",
            "mailto:op\u{7f}@relay.example",
            "ftp://relay.example",
        ] {
            assert!(
                matches!(
                    VapidSubject::parse(bad),
                    Err(PushSenderError::InvalidConfig {
                        field: "subject",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        Ok(())
    }

    /// Vector 60 (`25-test-vectors.md` §25.30): the exact JWT and
    /// `Authorization` value for its claims.
    #[tokio::test]
    async fn vector_60_authorization_header() -> TestResult {
        let sender = production_sender(clock())?;
        let header = sender
            .authorization("https://push.example.net")
            .ok_or("signing failed")?;
        assert!(header.is_sensitive());
        let expected = concat!(
            "vapid t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczo",
            "vL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE3MDAwNDMyMDAsInN1YiI6Im1haWx",
            "0bzpvcGVyYXRvckByZWxheS5leGFtcGxlIn0.Vxa-kpDihzYNFcdHNgEVnGRpO2y",
            "szVs4D7BZPJoValdiiKgi0AWtI-wBA17yN8nI4Aiww9cX5HpHZqcOHY72IQ, k=B",
            "DscrCP0XPHN_fCzL493e5kWbBtpZJwilbFReIPUfzAnRxaVV054co31A6DCHdHan",
            "3t3JS2DmFJ6GyF3x4Ik8FE",
        );
        assert_eq!(header.to_str()?, expected);
        assert_eq!(
            sender.vapid_public_key().to_uncompressed(),
            vapid_key()?.public_key().to_uncompressed()
        );
        Ok(())
    }

    #[tokio::test]
    async fn jwt_audience_keeps_a_non_default_port() -> TestResult {
        let sender = production_sender(clock())?;
        for (endpoint, aud) in [
            (
                "https://push.example.net:8443/s/1",
                "https://push.example.net:8443",
            ),
            ("https://push.example.net/s/1", "https://push.example.net"),
        ] {
            let parsed = parse_endpoint(endpoint)?;
            assert_eq!(parsed.aud(), aud);
            let header = sender.authorization(parsed.aud()).ok_or("signing failed")?;
            let claims = verified_claims(&jwt_of(&header)?)?;
            assert_eq!(claims["aud"], aud);
            assert_eq!(claims["sub"], SUBJECT);
            assert_eq!(claims["exp"], VECTOR_60_NOW + VAPID_JWT_LIFETIME_SECS);
        }
        Ok(())
    }

    #[tokio::test]
    async fn jwt_is_cached_per_origin_and_reminted_near_exp() -> TestResult {
        let clock = clock();
        let sender = production_sender(clock.clone())?;
        let aud = "https://push.example.net";
        let first = sender.authorization(aud).ok_or("signing failed")?;
        // Reused until 5 minutes before `exp`.
        clock.advance(VAPID_JWT_LIFETIME_SECS - VAPID_JWT_REMINT_BEFORE_SECS - 1);
        assert_eq!(sender.authorization(aud), Some(first.clone()));
        // Another origin gets its own JWT.
        let other = sender
            .authorization("https://other.example.net")
            .ok_or("signing failed")?;
        assert_ne!(other, first);
        // Within 5 minutes of `exp`: a new JWT with a later `exp`.
        clock.advance(1);
        let second = sender.authorization(aud).ok_or("signing failed")?;
        assert_ne!(second, first);
        let claims = verified_claims(&jwt_of(&second)?)?;
        assert_eq!(claims["exp"], clock.now_secs() + VAPID_JWT_LIFETIME_SECS);
        Ok(())
    }

    #[tokio::test]
    async fn origin_cache_is_bounded() -> TestResult {
        let sender = production_sender(clock())?;
        for n in 0..ORIGIN_CACHE_CAPACITY.get() + 50 {
            sender
                .authorization(&format!("https://h{n}.example.net"))
                .ok_or("signing failed")?;
        }
        assert_eq!(sender.jwts().len(), ORIGIN_CACHE_CAPACITY.get());
        Ok(())
    }

    /// D2 and L2: the production client's deadline and idle-pool bounds.
    #[test]
    fn production_client_limits_are_bounded() {
        assert_eq!(
            WEBPUSH_CLIENT_LIMITS,
            ClientLimits {
                request_timeout: Duration::from_secs(5),
                pool_idle_timeout: Duration::from_secs(5),
                pool_max_idle_per_host: 2,
            }
        );
    }

    /// B1: a send stamped before a back-off step cannot move it. A 201 that
    /// started before a 429 does not clear the 429's back-off, and a second
    /// failure from the same epoch does not double it.
    #[test]
    fn a_stale_outcome_does_not_move_the_backoff() -> TestResult {
        let origin = "https://push.example.net";
        let now = Instant::now();
        let mut backoffs = Backoffs::new();
        let (slow_201, _) = backoffs.stamp(origin, now);
        let (fast_429, _) = backoffs.stamp(origin, now);
        let (other_failure, _) = backoffs.stamp(origin, now);
        backoffs.record(origin, fast_429, PushSendOutcome::Transient, now);
        let first = backoffs.stamp(origin, now).1;
        let retry_at = first.ok_or("a 429 starts a back-off")?;
        assert!(retry_at - now <= ORIGIN_BACKOFF_MIN.mul_f64(1.25));
        backoffs.record(origin, slow_201, PushSendOutcome::Delivered, now);
        assert_eq!(
            backoffs.stamp(origin, now).1,
            first,
            "a stale 201 cleared it"
        );
        backoffs.record(origin, other_failure, PushSendOutcome::Unreachable, now);
        assert_eq!(
            backoffs.stamp(origin, now).1,
            first,
            "a stale failure moved it"
        );
        // A send stamped in the current epoch moves it.
        let (current, _) = backoffs.stamp(origin, now);
        backoffs.record(origin, current, PushSendOutcome::Delivered, now);
        assert_eq!(backoffs.stamp(origin, now), (0, None));
        Ok(())
    }

    /// B3: the back-off map is bounded and never forgets a back-off that has
    /// not ended; once full of active back-offs a new origin gets none, and
    /// an ended back-off makes room.
    #[test]
    fn backoff_map_is_bounded_and_keeps_active_backoffs() {
        let now = Instant::now();
        let mut backoffs = Backoffs::new();
        for n in 0..ORIGIN_BACKOFF_CAPACITY {
            let origin = format!("https://h{n}.example.net");
            let (epoch, _) = backoffs.stamp(&origin, now);
            backoffs.record(&origin, epoch, PushSendOutcome::Transient, now);
        }
        let late = "https://late.example.net";
        backoffs.record(late, 0, PushSendOutcome::Transient, now);
        assert_eq!(backoffs.origins.len(), ORIGIN_BACKOFF_CAPACITY);
        assert_eq!(backoffs.stamp(late, now).1, None);
        assert!(
            (0..ORIGIN_BACKOFF_CAPACITY).all(|n| backoffs
                .stamp(&format!("https://h{n}.example.net"), now)
                .1
                .is_some()),
            "an active back-off was forgotten"
        );
        // Every back-off has ended: the new origin's failure makes room.
        let later = now + ORIGIN_BACKOFF_MIN * 2;
        backoffs.record(late, 0, PushSendOutcome::Transient, later);
        assert!(backoffs.stamp(late, later).1.is_some());
        assert_eq!(backoffs.origins.len(), 1);
    }

    /// B3: JWT cache churn never forgets an origin's back-off.
    #[tokio::test]
    async fn jwt_cache_churn_keeps_a_backoff() -> TestResult {
        let sender = production_sender(clock())?;
        let origin = "https://push.example.net";
        sender
            .backoffs()
            .record(origin, 0, PushSendOutcome::Transient, Instant::now());
        for n in 0..ORIGIN_CACHE_CAPACITY.get() + 50 {
            sender
                .authorization(&format!("https://h{n}.example.net"))
                .ok_or("signing failed")?;
        }
        assert!(sender.retry_at(origin).is_some());
        Ok(())
    }

    /// AC2: the request's headers, and a body that opens to `{"scp":"1"}`
    /// under the subscription's key and `auth`.
    #[tokio::test]
    async fn wake_request_has_the_section_10_7_1_shape() -> TestResult {
        let server = TlsTestServer::start_routed(vec![("/", vec![Reply::empty(201)])]).await;
        let sender = sender_for(&server, true, clock())?;
        let endpoint = server.endpoint("push.example.net", PATH);
        let (ua, subscription) = subscribe(endpoint.clone())?;
        assert_eq!(sender.send(&subscription).await, PushSendOutcome::Delivered);

        let requests = server.requests().await;
        let [request] = requests.as_slice() else {
            return Err(format!("{} requests", requests.len()).into());
        };
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, PATH);
        assert_eq!(request.header("content-encoding"), Some("aes128gcm"));
        assert_eq!(request.header("urgency"), Some("high"));
        assert_eq!(request.header("ttl"), Some("3600"));
        let (t, k) = vapid_parts(request)?;
        assert_eq!(
            k,
            URL_SAFE_NO_PAD.encode(vapid_key()?.public_key().to_uncompressed())
        );
        let claims = verified_claims(&t)?;
        assert_eq!(claims["aud"], parse_endpoint(&endpoint)?.aud());
        assert_eq!(request.body.len(), 114);
        assert_eq!(
            scp_crypto::webpush::open(&ua, &AUTH, &request.body)?,
            WEBPUSH_WAKE_PLAINTEXT
        );
        Ok(())
    }

    /// AC3: every wake draws a fresh salt and ephemeral key, and the key id is
    /// never the VAPID key.
    #[tokio::test]
    async fn every_wake_has_a_fresh_salt_and_ephemeral_key() -> TestResult {
        let server = TlsTestServer::start_routed(vec![("/", vec![Reply::empty(201); 3])]).await;
        let sender = sender_for(&server, true, clock())?;
        let (ua, subscription) = subscribe(server.endpoint("push.example.net", PATH))?;
        for _ in 0..3 {
            assert_eq!(sender.send(&subscription).await, PushSendOutcome::Delivered);
        }
        let bodies: Vec<Vec<u8>> = server
            .requests()
            .await
            .into_iter()
            .map(|r| r.body)
            .collect();
        assert_eq!(bodies.len(), 3);
        let vapid_public = vapid_key()?.public_key().to_uncompressed();
        for (i, a) in bodies.iter().enumerate() {
            assert_eq!(
                scp_crypto::webpush::open(&ua, &AUTH, a)?,
                WEBPUSH_WAKE_PLAINTEXT
            );
            let (salt, keyid) = (&a[..16], &a[21..86]);
            assert_ne!(keyid, vapid_public.as_slice());
            for b in &bodies[i + 1..] {
                assert_ne!(salt, &b[..16]);
                assert_ne!(keyid, &b[21..86]);
            }
        }
        Ok(())
    }

    /// AC5: an endpoint whose literal or resolved address the ADR-004 rule
    /// refuses is `InvalidToken`, and nothing reaches it.
    #[tokio::test]
    async fn refused_addresses_send_nothing() -> TestResult {
        let server = TlsTestServer::start_routed(vec![("/", vec![Reply::empty(201); 8])]).await;
        // The production rule: loopback is refused.
        let sender = sender_for(&server, false, clock())?;
        let port = port_of(&server.endpoint("push.example.net", "/"))?;
        for endpoint in [
            format!("https://127.0.0.1:{port}{PATH}"),
            format!("https://[::1]:{port}{PATH}"),
            format!("https://[::ffff:7f00:1]:{port}{PATH}"),
            "https://10.0.0.1/x".to_owned(),
            "https://169.254.169.254/latest".to_owned(),
            // Unique-local.
            "https://[fd12:3456::1]/x".to_owned(),
            // A name that resolves to loopback.
            server.endpoint("push.example.net", PATH),
        ] {
            let (_, subscription) = subscribe(endpoint.clone())?;
            assert_eq!(
                sender.send(&subscription).await,
                PushSendOutcome::InvalidToken,
                "{endpoint}"
            );
        }
        assert!(server.requests().await.is_empty());

        // The connect-time refusal is the resolver's typed error, found in the
        // client's error chain.
        let Err(error) = sender
            .client
            .post(server.endpoint("push.example.net", PATH))
            .send()
            .await
        else {
            return Err("a refused address was reached".into());
        };
        assert!(matches!(
            endpoint_error_in(&error),
            Some(EndpointError::Refused(_))
        ));
        assert!(server.requests().await.is_empty());
        Ok(())
    }

    /// AC6: the PUSH-022 response table. A fresh sender per row, so no row
    /// sees another's back-off.
    #[tokio::test]
    async fn responses_map_to_the_push_022_outcomes() -> TestResult {
        use PushSendOutcome::{ConfigError, Delivered, InvalidToken, Transient, Unreachable};
        let rows: [(u16, PushSendOutcome); 16] = [
            (201, Delivered),
            (200, Delivered),
            (202, Delivered),
            (404, InvalidToken),
            (410, InvalidToken),
            (403, InvalidToken),
            (301, InvalidToken),
            (307, InvalidToken),
            (400, ConfigError),
            (401, ConfigError),
            (413, ConfigError),
            (429, Transient),
            (500, Transient),
            (503, Transient),
            (418, Transient),
            (409, Transient),
        ];
        for (status, expected) in rows {
            let server = TlsTestServer::start_routed(vec![("/", vec![Reply::empty(status)])]).await;
            let sender = sender_for(&server, true, clock())?;
            let (_, subscription) = subscribe(server.endpoint("push.example.net", PATH))?;
            assert_eq!(sender.send(&subscription).await, expected, "{status}");
            assert_eq!(server.requests().await.len(), 1, "{status}");
        }

        // A refused connection is Unreachable (spec 10 §10.7.1).
        let closed = TestServer::closed_origin();
        let port = port_of(closed.origin())?;
        let server = TlsTestServer::start_routed(vec![]).await;
        let sender = sender_for(&server, true, clock())?;
        let (_, subscription) = subscribe(format!("https://push.example.net:{port}{PATH}"))?;
        assert_eq!(sender.send(&subscription).await, Unreachable);

        // No answer before the deadline is Unreachable.
        let server = TlsTestServer::start_routed(vec![("/", vec![Reply::hang()])]).await;
        let sender = sender_with_deadline(&server, true, clock(), Duration::from_millis(300))?;
        let (_, subscription) = subscribe(server.endpoint("push.example.net", PATH))?;
        assert_eq!(sender.send(&subscription).await, Unreachable);
        assert_eq!(server.requests().await.len(), 1);
        Ok(())
    }

    /// T1: a name that does not resolve at send, or resolves to no address,
    /// is `Transient` (spec 10 §10.7.1 counts neither), and nothing is sent.
    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_transient() -> TestResult {
        let server = TlsTestServer::start_routed(vec![("/", vec![Reply::empty(201); 2])]).await;
        let sender = sender_for(&server, false, clock())?;
        for host in ["absent.example.net", "empty.example.net"] {
            let (_, subscription) = subscribe(format!("https://{host}{PATH}"))?;
            assert_eq!(
                sender.send(&subscription).await,
                PushSendOutcome::Transient,
                "{host}"
            );
        }
        assert!(server.requests().await.is_empty());
        Ok(())
    }

    /// Q6 and B2: a failure backs off its own origin only. A wake to that
    /// origin during the back-off waits it out and is delivered, and another
    /// origin is unaffected.
    #[tokio::test]
    async fn transient_backs_off_only_its_own_origin() -> TestResult {
        let server = TlsTestServer::start_routed(vec![
            ("/busy", vec![Reply::empty(503)]),
            ("/ok", vec![Reply::empty(201); 2]),
        ])
        .await;
        let sender = sender_for(&server, true, clock())?;
        let (_, busy) = subscribe(server.endpoint("push.example.net", "/busy"))?;
        let (_, same_origin) = subscribe(server.endpoint("push.example.net", "/ok"))?;
        let (_, other_origin) = subscribe(server.endpoint("hung.example.net", "/ok"))?;

        assert_eq!(sender.send(&busy).await, PushSendOutcome::Transient);
        let aud = parse_endpoint(&server.endpoint("push.example.net", "/"))?
            .aud()
            .to_owned();
        let retry_at = sender.retry_at(&aud).ok_or("no back-off")?;
        assert!(retry_at - Instant::now() <= ORIGIN_BACKOFF_MIN.mul_f64(1.25));
        // Another origin is unaffected.
        let started = Instant::now();
        assert_eq!(sender.send(&other_origin).await, PushSendOutcome::Delivered);
        assert!(started.elapsed() < ORIGIN_BACKOFF_MIN / 2);
        // A wake to the backing-off origin is held, not consumed, and
        // delivered once the back-off ends.
        assert_eq!(sender.send(&same_origin).await, PushSendOutcome::Delivered);
        assert!(Instant::now() >= retry_at);
        let paths: Vec<String> = server
            .requests()
            .await
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(paths, ["/busy", "/ok", "/ok"]);
        Ok(())
    }

    /// B1: sends already in flight when their origin starts backing off,
    /// all failing, leave one first back-off step, not one per failure.
    #[tokio::test]
    async fn concurrent_failures_take_one_backoff_step() -> TestResult {
        const IN_FLIGHT: usize = 8;
        let server = TlsTestServer::start_routed(vec![("/", vec![Reply::hang(); IN_FLIGHT])]).await;
        let sender = sender_with_deadline(&server, true, clock(), Duration::from_millis(300))?;
        let (_, subscription) = subscribe(server.endpoint("push.example.net", PATH))?;
        let outcomes =
            futures::future::join_all((0..IN_FLIGHT).map(|_| sender.send(&subscription))).await;
        assert_eq!(outcomes, [PushSendOutcome::Unreachable; IN_FLIGHT]);
        assert_eq!(server.requests().await.len(), IN_FLIGHT);
        let aud = parse_endpoint(&server.endpoint("push.example.net", "/"))?
            .aud()
            .to_owned();
        let retry_at = sender.retry_at(&aud).ok_or("no back-off")?;
        let left = retry_at - Instant::now();
        assert!(left <= ORIGIN_BACKOFF_MIN.mul_f64(1.25), "{left:?}");
        Ok(())
    }

    /// `PushSender::WebPush` decodes the registered §22.11.4 token: a token
    /// that does not decode is `InvalidToken` with no request.
    #[tokio::test]
    async fn registered_token_is_decoded_before_sending() -> TestResult {
        let server = TlsTestServer::start_routed(vec![("/", vec![Reply::empty(201)])]).await;
        let sender = PushSender::WebPush(sender_for(&server, true, clock())?);
        let (ua, subscription) = subscribe(server.endpoint("push.example.net", PATH))?;
        let token = subscription.encode();
        for malformed in [
            Vec::new(),
            token[..token.len() - 1].to_vec(),
            [token.as_slice(), &[0]].concat(),
            b"not a webpush token".to_vec(),
        ] {
            assert_eq!(
                sender.send_registered(&malformed).await,
                PushSendOutcome::InvalidToken
            );
        }
        assert!(server.requests().await.is_empty());
        assert_eq!(
            sender.send_registered(&token).await,
            PushSendOutcome::Delivered
        );
        let requests = server.requests().await;
        let [request] = requests.as_slice() else {
            return Err(format!("{} requests", requests.len()).into());
        };
        assert_eq!(
            scp_crypto::webpush::open(&ua, &AUTH, &request.body)?,
            WEBPUSH_WAKE_PLAINTEXT
        );
        Ok(())
    }

    /// A 3xx is never followed.
    #[tokio::test]
    async fn redirects_are_not_followed() -> TestResult {
        let server = TlsTestServer::start_routed(vec![
            ("/moved", vec![Reply::empty(308)]),
            ("/", vec![Reply::empty(201)]),
        ])
        .await;
        let sender = sender_for(&server, true, clock())?;
        let (_, subscription) = subscribe(server.endpoint("push.example.net", "/moved"))?;
        assert_eq!(
            sender.send(&subscription).await,
            PushSendOutcome::InvalidToken
        );
        assert_eq!(server.requests().await.len(), 1);
        Ok(())
    }

    /// AC7: no log line or `Debug` output carries the endpoint, the
    /// subscription keys, the VAPID key or a JWT, and no line of this
    /// sender's names the endpoint's host or address.
    #[tokio::test]
    async fn no_log_line_carries_a_secret() -> TestResult {
        let capture = LogCapture::install(admits_log_event);
        let server = TlsTestServer::start_routed(vec![(
            "/",
            vec![Reply::empty(201), Reply::empty(400), Reply::empty(503)],
        )])
        .await;
        let sender = sender_for(&server, true, clock())?;
        let endpoint = server.endpoint("push.example.net", PATH);
        let (_, subscription) = subscribe(endpoint.clone())?;
        for _ in 0..3 {
            sender.send(&subscription).await;
        }
        let refusing = sender_for(&server, false, clock())?;
        refusing.send(&subscription).await;
        let (_, literal) = subscribe(format!("https://10.9.8.7{PATH}"))?;
        refusing.send(&literal).await;

        let mut jwts = Vec::new();
        for request in server.requests().await {
            jwts.push(vapid_parts(&request)?.0);
        }
        assert_eq!(jwts.len(), 3);
        let logs = capture.contents();
        // The capture applies the relay's own log cap, which holds
        // hyper-util, whose DEBUG and TRACE lines name the host and port it
        // connects to, at INFO. No captured line, from any target, names the
        // endpoint's host or address.
        let own = logs
            .lines()
            .filter(|line| line.contains("scp_transport::relay::push_webpush"))
            .count();
        assert!(own >= 5, "log capture saw too little: {logs}");
        assert!(logs.lines().any(|line| line.contains("400")), "{logs}");
        for line in logs.lines() {
            for host in ["push.example.net", "10.9.8.7", "127.0.0.1"] {
                assert!(!line.contains(host), "{line}");
            }
        }
        let p256dh = subscription.p256dh().to_uncompressed();
        let mut secrets = vec![
            endpoint,
            PATH.to_owned(),
            VAPID_SCALAR.to_owned(),
            hex::encode(AUTH),
            URL_SAFE_NO_PAD.encode(AUTH),
            String::from_utf8_lossy(&AUTH).into_owned(),
            URL_SAFE_NO_PAD.encode(p256dh),
            hex::encode(p256dh),
        ];
        for jwt in &jwts {
            secrets.push(jwt.clone());
            // The claims and signature segments on their own; the header
            // segment is a constant.
            secrets.extend(jwt.split('.').skip(1).map(str::to_owned));
        }
        for printed in [
            format!("{:?}", config()?),
            format!("{sender:?}"),
            format!("{subscription:?}"),
            logs,
        ] {
            for secret in &secrets {
                assert!(!printed.contains(secret.as_str()), "{secret} in {printed}");
            }
        }
        Ok(())
    }
}
