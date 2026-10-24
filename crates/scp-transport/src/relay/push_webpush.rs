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
//! when the cached one is within 5 minutes of `exp`.
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
//! | 429, 5xx | `Transient`, and that origin backs off |
//! | transport failure | `Transient`, and that origin backs off |
//! | any other 2xx | `Delivered` |
//! | any other status | `Transient`, and that origin backs off |
//!
//! A hostile endpoint chooses its own status, so a status the table does not
//! name is `Transient`, never `ConfigError`, which would read as a fault in
//! the relay's credentials.
//!
//! **Lane rule.** One registrant chooses each endpoint, so the back-off after
//! a `Transient` outcome is per endpoint origin, not per platform: while an
//! origin backs off, a send to it sends nothing and answers `Transient`, and
//! every other origin is unaffected. The dispatcher runs `WebPush` sends
//! concurrently up to a bound (`push_dispatch`), so one origin that stops
//! answering holds one send slot per wake in flight to it, not the platform.
//!
//! No log line or `Debug` output carries the endpoint, its host or origin,
//! `p256dh`, `auth`, the VAPID key or a JWT.

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
    CONNECT_TIMEOUT, PRODUCTION_KEEP_ALIVE, PushSendOutcome, PushSenderError, REQUEST_TIMEOUT,
    compact_jws_bytes, read_bounded, transport_error_kind,
};
use super::push_endpoint::{CheckedResolver, EndpointError, OwnAddresses, parse_endpoint};
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

/// The most endpoint origins whose JWT and back-off the sender keeps
/// (indicator: 1,024). The least recently used origin is forgotten first.
const ORIGIN_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(1023);

/// The first back-off of an origin after a `Transient` outcome (indicator:
/// 1 s), doubling on each further `Transient` with up to 25% jitter.
const ORIGIN_BACKOFF_MIN: Duration = Duration::from_secs(1);

/// The longest back-off of an origin (indicator: 60 s).
const ORIGIN_BACKOFF_MAX: Duration = Duration::from_secs(60);

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
/// key, parses the subject and gathers the relay's own addresses.
pub struct WebPushConfig {
    /// The relay's VAPID signing key. Zeroized on drop by `scp-crypto`.
    pub vapid_key: P256SecretKey,
    /// The operator contact, the JWT `sub`.
    pub subject: VapidSubject,
    /// The relay's own addresses, refused as endpoint addresses (ADR-004).
    pub own_addresses: OwnAddresses,
}

impl fmt::Debug for WebPushConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPushConfig")
            .field("vapid_key", &"<redacted>")
            .field("subject", &self.subject)
            .field("own_addresses", &self.own_addresses)
            .finish()
    }
}

/// How the sender's HTTP client reaches push services.
pub(crate) enum Transport {
    /// The operating system's resolver behind the ADR-004 rule, and the
    /// `WebPKI` roots.
    Production,
    /// A test resolver and one extra trusted root, so a test reaches a local
    /// TLS server. Absent from every non-test build.
    #[cfg(test)]
    Test {
        resolver: CheckedResolver,
        root: reqwest::Certificate,
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

/// What the sender remembers about one endpoint origin.
struct OriginState {
    jwt: Option<CachedJwt>,
    backoff: ReconnectBackoff,
    /// While set and in the future, a send to this origin sends nothing.
    retry_at: Option<Instant>,
}

impl OriginState {
    const fn new() -> Self {
        Self {
            jwt: None,
            backoff: ReconnectBackoff::new(ORIGIN_BACKOFF_MIN, ORIGIN_BACKOFF_MAX),
            retry_at: None,
        }
    }
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
    origins: Mutex<LruCache<String, OriginState>>,
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
        } = config;
        let builder = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .http2_keep_alive_interval(PRODUCTION_KEEP_ALIVE.interval)
            .http2_keep_alive_timeout(PRODUCTION_KEEP_ALIVE.timeout)
            .http2_keep_alive_while_idle(true);
        let (builder, resolver) = match transport {
            Transport::Production => (builder, CheckedResolver::new(own_addresses)),
            #[cfg(test)]
            Transport::Test { resolver, root } => {
                (builder.add_root_certificate(root.clone()), resolver.clone())
            }
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
            origins: Mutex::new(LruCache::new(ORIGIN_CACHE_CAPACITY)),
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

    fn origins(&self) -> MutexGuard<'_, LruCache<String, OriginState>> {
        // Each critical section leaves the cache consistent at every step.
        self.origins.lock().unwrap_or_else(PoisonError::into_inner)
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
        if self.backing_off(aud) {
            tracing::debug!(
                platform = "webpush",
                "endpoint origin backing off; wake not sent"
            );
            return PushSendOutcome::Transient;
        }
        let Some(authorization) = self.authorization(aud) else {
            return PushSendOutcome::ConfigError;
        };
        let body = match scp_crypto::webpush::seal(
            subscription.p256dh(),
            subscription.auth(),
            WEBPUSH_WAKE_PLAINTEXT,
            &mut rand::rngs::OsRng,
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
                if outcome == PushSendOutcome::ConfigError {
                    tracing::warn!(
                        platform = "webpush",
                        status,
                        "push service rejected the relay's VAPID authentication or request"
                    );
                } else {
                    tracing::debug!(platform = "webpush", status, ?outcome, "push send answered");
                }
                outcome
            }
            Err(error) => match endpoint_error_in(&error) {
                Some(refusal) if refusal.is_refusal() => {
                    tracing::debug!(platform = "webpush", error = %refusal, "endpoint refused at connect");
                    PushSendOutcome::InvalidToken
                }
                _ => {
                    tracing::debug!(
                        platform = "webpush",
                        error_kind = transport_error_kind(&error),
                        "push send failed in transport"
                    );
                    PushSendOutcome::Transient
                }
            },
        };
        self.record(aud, outcome);
        outcome
    }

    /// Whether `aud` is inside a back-off a `Transient` outcome started.
    fn backing_off(&self, aud: &str) -> bool {
        self.origins()
            .get(aud)
            .and_then(|state| state.retry_at)
            .is_some_and(|retry_at| Instant::now() < retry_at)
    }

    /// Starts or extends `aud`'s back-off after a `Transient` outcome, and
    /// resets it after any other.
    #[allow(clippy::significant_drop_tightening)]
    fn record(&self, aud: &str, outcome: PushSendOutcome) {
        let mut origins = self.origins();
        let state = origins.get_or_insert_mut(aud.to_owned(), OriginState::new);
        if outcome == PushSendOutcome::Transient {
            state.retry_at = Some(Instant::now() + state.backoff.next_delay());
        } else {
            state.backoff.reset();
            state.retry_at = None;
        }
    }

    /// The `Authorization` header for `aud`, reusing the origin's cached JWT
    /// unless it is within [`VAPID_JWT_REMINT_BEFORE_SECS`] of `exp`. `None`
    /// when signing failed.
    #[allow(clippy::significant_drop_tightening)]
    fn authorization(&self, aud: &str) -> Option<HeaderValue> {
        let now = self.clock.now_secs();
        let mut origins = self.origins();
        let state = origins.get_or_insert_mut(aud.to_owned(), OriginState::new);
        let fresh = state
            .jwt
            .as_ref()
            .filter(|cached| cached.exp > now.saturating_add(VAPID_JWT_REMINT_BEFORE_SECS));
        let jwt = if let Some(cached) = fresh {
            cached.jwt.clone()
        } else {
            let exp = now.saturating_add(VAPID_JWT_LIFETIME_SECS);
            let jwt = self.mint_jwt(aud, exp)?;
            state.jwt = Some(CachedJwt {
                jwt: jwt.clone(),
                exp,
            });
            jwt
        };
        drop(origins);
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
        CapturedRequest, Reply, TLS_TEST_HOSTS, TestServer, TlsTestServer,
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
            own_addresses: OwnAddresses::default(),
        })
    }

    /// A resolver that maps every [`TLS_TEST_HOSTS`] name to `127.0.0.1`,
    /// letting loopback through only when `allow_loopback`.
    pub fn resolver(allow_loopback: bool) -> CheckedResolver {
        let table: HashMap<String, Vec<IpAddr>> = TLS_TEST_HOSTS
            .iter()
            .map(|host| ((*host).to_owned(), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]))
            .collect();
        CheckedResolver::for_tests(OwnAddresses::default(), table, allow_loopback)
    }

    /// A sender that reaches `server`; `allow_loopback` false applies the
    /// production ADR-004 rule, which refuses `server`'s address.
    pub fn sender_for(
        server: &TlsTestServer,
        allow_loopback: bool,
        clock: Arc<dyn Clock>,
    ) -> TestResult<WebPushSender> {
        Ok(WebPushSender::build(
            config()?,
            &Transport::Test {
                resolver: resolver(allow_loopback),
                root: server.root(),
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
        assert_eq!(sender.origins().len(), ORIGIN_CACHE_CAPACITY.get());
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
        use PushSendOutcome::{ConfigError, Delivered, InvalidToken, Transient};
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

        // A transport failure is Transient.
        let closed = TestServer::closed_origin();
        let port = port_of(closed.origin())?;
        let server = TlsTestServer::start_routed(vec![]).await;
        let sender = sender_for(&server, true, clock())?;
        let (_, subscription) = subscribe(format!("https://push.example.net:{port}{PATH}"))?;
        assert_eq!(sender.send(&subscription).await, Transient);
        Ok(())
    }

    /// Q6: a `Transient` outcome backs off its own origin only, and the
    /// back-off ends.
    #[tokio::test]
    async fn transient_backs_off_only_its_own_origin() -> TestResult {
        let server = TlsTestServer::start_routed(vec![
            ("/busy", vec![Reply::empty(503), Reply::empty(201)]),
            ("/ok", vec![Reply::empty(201); 2]),
        ])
        .await;
        let sender = sender_for(&server, true, clock())?;
        let (_, busy) = subscribe(server.endpoint("push.example.net", "/busy"))?;
        let (_, same_origin) = subscribe(server.endpoint("push.example.net", "/ok"))?;
        let (_, other_origin) = subscribe(server.endpoint("hung.example.net", "/ok"))?;

        assert_eq!(sender.send(&busy).await, PushSendOutcome::Transient);
        assert_eq!(server.requests().await.len(), 1);
        // The busy origin sends nothing while it backs off, whatever the path.
        assert_eq!(sender.send(&busy).await, PushSendOutcome::Transient);
        assert_eq!(sender.send(&same_origin).await, PushSendOutcome::Transient);
        assert_eq!(server.requests().await.len(), 1);
        // Another origin is unaffected.
        assert_eq!(sender.send(&other_origin).await, PushSendOutcome::Delivered);
        assert_eq!(server.requests().await.len(), 2);
        // The first back-off is at most 1.25 s.
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert_eq!(sender.send(&busy).await, PushSendOutcome::Delivered);
        assert_eq!(server.requests().await.len(), 3);
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
        let capture = LogCapture::install();
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
        // hyper-util's own TRACE and DEBUG lines name the host and port it
        // connects to (PUSH-022 AC7 names the endpoint, not its host); this
        // sender's lines name neither the host nor an address.
        let own: Vec<&str> = logs
            .lines()
            .filter(|line| line.contains("scp_transport::relay::push_webpush"))
            .collect();
        assert!(own.len() >= 5, "log capture saw too little: {logs}");
        assert!(own.iter().any(|line| line.contains("400")), "{logs}");
        for line in own {
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
