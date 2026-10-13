//! The APNs push sender (PUSH-010, spec §10.7.1 step 5, ADR-025).
//!
//! Sends the APNs row of the §10.7.1 step 5 wake-signal table:
//! `POST /3/device/<device token>` over HTTP/2 to `api.push.apple.com`, or to
//! `api.sandbox.push.apple.com` when the configured environment is
//! [`ApnsEnvironment::Sandbox`], with the headers `authorization: bearer
//! <provider JWT>`, `apns-push-type: background`, `apns-priority: 5` and
//! `apns-topic: <bundle ID>`, and the body `{"aps":{"content-available":1}}`.
//!
//! The provider JWT is ES256, signed by the team's .p8 key through
//! `scp_crypto::p256::jose`, with header `{"alg":"ES256","kid":<key ID>}` and
//! claims `{"iss":<team ID>,"iat":<seconds>}`. The sender reuses one JWT and
//! mints a new one once it is 50 minutes old (indicator; Apple rejects a
//! token older than an hour and throttles refreshes more often than every 20
//! minutes).
//!
//! Response mapping (PUSH-010):
//!
//! | Response | Outcome |
//! |---|---|
//! | 200 | `Delivered` |
//! | 410, or 400 `BadDeviceToken` | `InvalidToken` |
//! | `DeviceTokenNotForTopic` | `InvalidToken` |
//! | 403 `InvalidProviderToken` or `ExpiredProviderToken` | mint a new JWT and resend once; the same answer again is `ConfigError` |
//! | `TopicDisallowed` | `ConfigError` |
//! | 429 or 5xx | `Transient` |
//!
//! A response the table does not name maps to `ConfigError` when it is any
//! other 4xx, since the relay's request or credentials are what the service
//! refused, and to `Transient` for any other status. A transport failure
//! (connect, TLS, timeout) is `Transient`. A device token that is not
//! hexadecimal is `InvalidToken` without a request, because APNs issues only
//! hexadecimal tokens and the token is a path segment.

use std::fmt;
use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use scp_clock::{Clock, SystemClock};
use scp_crypto::p256::P256SecretKey;
use scp_crypto::p256::jose::{ES256_ALG, es256_sign};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::push::{
    PushDeviceToken, PushSendOutcome, PushSenderError, compact_jws, http2_client, loggable_reason,
    read_bounded, transport_error_kind,
};

/// The exact §10.7.1 step 5 APNs body.
pub(super) const APNS_WAKE_BODY: &[u8] = br#"{"aps":{"content-available":1}}"#;

/// The age at which the sender replaces its provider JWT (indicator: 50 min).
const JWT_REFRESH_AFTER_SECS: u64 = 50 * 60;

/// Which APNs gateway the relay sends to.
///
/// A token a development build of the app registered is valid only on the
/// sandbox gateway, and a production token only on the production gateway;
/// the wrong one answers `BadDeviceToken`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsEnvironment {
    /// `https://api.push.apple.com`.
    Production,
    /// `https://api.sandbox.push.apple.com`.
    Sandbox,
}

impl ApnsEnvironment {
    /// The gateway origin for this environment.
    #[must_use]
    pub const fn origin(self) -> &'static str {
        match self {
            Self::Production => "https://api.push.apple.com",
            Self::Sandbox => "https://api.sandbox.push.apple.com",
        }
    }
}

/// Everything the APNs sender needs. PUSH-012 loads it from the operator's
/// files and environment.
pub struct ApnsConfig {
    /// The team's APNs authentication key (the .p8 file's P-256 key). Zeroized
    /// on drop by `scp-crypto`.
    pub signing_key: P256SecretKey,
    /// The 10-character key ID Apple assigned to `signing_key`; the JWT `kid`.
    pub key_id: String,
    /// The Apple developer team ID; the JWT `iss`.
    pub team_id: String,
    /// The app's bundle ID; the `apns-topic` header.
    pub topic: String,
    /// The gateway to send to.
    pub environment: ApnsEnvironment,
}

impl fmt::Debug for ApnsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApnsConfig")
            .field("signing_key", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("team_id", &self.team_id)
            .field("topic", &self.topic)
            .field("environment", &self.environment)
            .finish()
    }
}

/// A provider JWT and the clock second it was minted at.
struct ProviderToken {
    jwt: Zeroizing<String>,
    minted_at: u64,
}

/// Sends APNs wake signals. Built once per relay from an [`ApnsConfig`].
pub struct ApnsSender {
    client: reqwest::Client,
    origin: String,
    signing_key: P256SecretKey,
    key_id: String,
    team_id: String,
    topic: HeaderValue,
    environment: ApnsEnvironment,
    clock: Arc<dyn Clock>,
    token: Mutex<Option<ProviderToken>>,
}

impl fmt::Debug for ApnsSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApnsSender")
            .field("origin", &self.origin)
            .field("key_id", &self.key_id)
            .field("team_id", &self.team_id)
            .field("topic", &self.topic)
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

/// What one request attempt produced.
enum Attempt {
    Done(PushSendOutcome),
    /// 403 with a provider-token reason: the JWT that was sent is rejected.
    ProviderTokenRejected,
}

impl ApnsSender {
    /// Builds the sender for `config.environment`'s gateway.
    ///
    /// # Errors
    ///
    /// [`PushSenderError::InvalidConfig`] when the key ID, team ID or topic is
    /// empty or not a valid header or JSON string value, and
    /// [`PushSenderError::HttpClient`] when TLS cannot be initialized.
    pub fn new(config: ApnsConfig) -> Result<Self, PushSenderError> {
        let origin = config.environment.origin().to_owned();
        Self::build(config, origin, Arc::new(SystemClock))
    }

    /// Builds the sender against `origin` with `clock`. [`Self::new`] passes
    /// the environment's gateway and the system clock; the tests pass a local
    /// server and a test clock.
    pub(super) fn build(
        config: ApnsConfig,
        origin: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PushSenderError> {
        let ApnsConfig {
            signing_key,
            key_id,
            team_id,
            topic,
            environment,
        } = config;
        require_printable("key_id", &key_id)?;
        require_printable("team_id", &team_id)?;
        require_printable("topic", &topic)?;
        let topic = HeaderValue::from_str(&topic).map_err(|_| PushSenderError::InvalidConfig {
            field: "topic",
            reason: "not a valid header value",
        })?;
        Ok(Self {
            client: http2_client()?,
            origin,
            signing_key,
            key_id,
            team_id,
            topic,
            environment,
            clock,
            token: Mutex::new(None),
        })
    }

    /// Sends one wake signal to `token`.
    pub async fn send(&self, token: &PushDeviceToken) -> PushSendOutcome {
        let device = token.expose();
        if device.is_empty() || !device.bytes().all(|b| b.is_ascii_hexdigit()) {
            tracing::debug!(platform = "apns", "device token is not hexadecimal");
            return PushSendOutcome::InvalidToken;
        }
        let url = format!("{}/3/device/{device}", self.origin);

        let Some(jwt) = self.provider_jwt(None).await else {
            return PushSendOutcome::ConfigError;
        };
        match self.attempt(&url, &jwt).await {
            Attempt::Done(outcome) => outcome,
            Attempt::ProviderTokenRejected => {
                let Some(fresh) = self.provider_jwt(Some(&jwt)).await else {
                    return PushSendOutcome::ConfigError;
                };
                match self.attempt(&url, &fresh).await {
                    Attempt::Done(outcome) => outcome,
                    Attempt::ProviderTokenRejected => {
                        tracing::warn!(
                            platform = "apns",
                            "provider token rejected after a refresh; check the key ID, team ID and key"
                        );
                        PushSendOutcome::ConfigError
                    }
                }
            }
        }
    }

    /// Sends one request carrying `jwt` and maps the response.
    async fn attempt(&self, url: &str, jwt: &Zeroizing<String>) -> Attempt {
        let mut headers = HeaderMap::with_capacity(4);
        let Ok(mut authorization) = HeaderValue::from_str(&format!("bearer {}", jwt.as_str()))
        else {
            return Attempt::Done(PushSendOutcome::ConfigError);
        };
        authorization.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        headers.insert(
            HeaderName::from_static("apns-push-type"),
            HeaderValue::from_static("background"),
        );
        headers.insert(
            HeaderName::from_static("apns-priority"),
            HeaderValue::from_static("5"),
        );
        headers.insert(HeaderName::from_static("apns-topic"), self.topic.clone());

        let response = match self
            .client
            .post(url)
            .headers(headers)
            .body(APNS_WAKE_BODY)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(
                    platform = "apns",
                    error_kind = transport_error_kind(&error),
                    "push send failed in transport"
                );
                return Attempt::Done(PushSendOutcome::Transient);
            }
        };
        let response = read_bounded(response).await;
        let reason = apns_reason(&response.body);
        let outcome = map_response(response.status, reason.as_deref());
        match outcome {
            Mapped::Outcome(PushSendOutcome::ConfigError) => {
                tracing::warn!(
                    platform = "apns",
                    status = response.status,
                    reason = loggable_reason(reason.as_deref()),
                    "push service rejected the relay's configuration"
                );
            }
            Mapped::Outcome(outcome) => {
                tracing::debug!(
                    platform = "apns",
                    status = response.status,
                    reason = loggable_reason(reason.as_deref()),
                    ?outcome,
                    "push send answered"
                );
            }
            Mapped::ProviderTokenRejected => {
                tracing::debug!(
                    platform = "apns",
                    status = response.status,
                    reason = loggable_reason(reason.as_deref()),
                    "provider token rejected"
                );
            }
        }
        match outcome {
            Mapped::Outcome(outcome) => Attempt::Done(outcome),
            Mapped::ProviderTokenRejected => Attempt::ProviderTokenRejected,
        }
    }

    /// Returns the current provider JWT, minting one when none is cached, the
    /// cached one is [`JWT_REFRESH_AFTER_SECS`] old, or the cached one is
    /// `rejected`. When another send already replaced a rejected JWT, the
    /// replacement is returned rather than minting again, so a burst of 403s
    /// refreshes once. `None` means signing failed.
    async fn provider_jwt(
        &self,
        rejected: Option<&Zeroizing<String>>,
    ) -> Option<Zeroizing<String>> {
        let mut cached = self.token.lock().await;
        let now = self.clock.now_secs();
        if let Some(token) = cached.as_ref() {
            let fresh = now >= token.minted_at && now - token.minted_at < JWT_REFRESH_AFTER_SECS;
            let is_rejected = rejected.is_some_and(|r| r.as_str() == token.jwt.as_str());
            if fresh && !is_rejected {
                return Some(token.jwt.clone());
            }
        }
        let jwt = self.mint_jwt(now)?;
        *cached = Some(ProviderToken {
            jwt: jwt.clone(),
            minted_at: now,
        });
        drop(cached);
        Some(jwt)
    }

    /// Mints a provider JWT with `iat = now`.
    fn mint_jwt(&self, now: u64) -> Option<Zeroizing<String>> {
        let header = serde_json::json!({ "alg": ES256_ALG, "kid": self.key_id });
        let claims = serde_json::json!({ "iss": self.team_id, "iat": now });
        match compact_jws(&header, &claims, |input| {
            es256_sign(&self.signing_key, input).map(|signature| signature.to_vec())
        }) {
            Ok(jwt) => Some(jwt),
            Err(error) => {
                tracing::warn!(platform = "apns", %error, "provider JWT signing failed");
                None
            }
        }
    }
}

/// The result of mapping one response.
#[derive(Debug, PartialEq, Eq)]
enum Mapped {
    Outcome(PushSendOutcome),
    ProviderTokenRejected,
}

/// Maps an APNs status and reason to the PUSH-010 outcome table.
fn map_response(status: u16, reason: Option<&str>) -> Mapped {
    use PushSendOutcome::{ConfigError, Delivered, InvalidToken, Transient};
    let outcome = match (status, reason) {
        (200, _) => Delivered,
        (403, Some("InvalidProviderToken" | "ExpiredProviderToken")) => {
            return Mapped::ProviderTokenRejected;
        }
        (410, _) | (_, Some("BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered")) => {
            InvalidToken
        }
        (_, Some("TopicDisallowed")) => ConfigError,
        (429 | 500..=599, _) => Transient,
        (400..=499, _) => ConfigError,
        _ => Transient,
    };
    Mapped::Outcome(outcome)
}

/// The `reason` field of an APNs error body, when the body is JSON with one.
fn apns_reason(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("reason")?.as_str().map(str::to_owned)
}

/// Rejects an empty value or one with a control character.
fn require_printable(field: &'static str, value: &str) -> Result<(), PushSenderError> {
    if value.is_empty() {
        return Err(PushSenderError::InvalidConfig {
            field,
            reason: "empty",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(PushSenderError::InvalidConfig {
            field,
            reason: "contains a control character",
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use scp_clock::TestClock;
    use scp_crypto::p256::jose::es256_verify_strict;

    use super::super::log_capture::LogCapture;
    use super::super::push::PushSender;
    use super::super::push_test_server::{CapturedRequest, Reply, TestServer, json_reply};
    use super::*;

    const DEVICE_TOKEN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const START: u64 = 1_800_000_000;
    /// When a mapping row is sent, inside the cached JWT's window. A refresh at
    /// this time mints a JWT whose `iat` differs from the cached one; ES256 is
    /// RFC 6979 deterministic here, so a JWT minted for the same key, claims
    /// and second would be byte-identical.
    const ROW_AT: u64 = 600;

    fn test_key() -> P256SecretKey {
        P256SecretKey::from_scalar_bytes(&[7u8; 32]).expect("7 repeated is a valid P-256 scalar")
    }

    fn config() -> ApnsConfig {
        ApnsConfig {
            signing_key: test_key(),
            key_id: "ABC123DEFG".to_owned(),
            team_id: "TEAM456XYZ".to_owned(),
            topic: "works.limn.app".to_owned(),
            environment: ApnsEnvironment::Production,
        }
    }

    async fn sender_with(replies: Vec<Reply>) -> (ApnsSender, TestServer, Arc<TestClock>) {
        let server = TestServer::start(replies).await;
        let clock = Arc::new(TestClock::new(START));
        let sender = ApnsSender::build(config(), server.origin(), clock.clone())
            .unwrap_or_else(|e| panic!("build: {e}"));
        (sender, server, clock)
    }

    fn reason(status: u16, reason: &str) -> Reply {
        json_reply(status, &serde_json::json!({ "reason": reason }))
    }

    fn token() -> PushDeviceToken {
        PushDeviceToken::new(DEVICE_TOKEN)
    }

    fn bearer(request: &CapturedRequest) -> String {
        let value = request
            .header("authorization")
            .unwrap_or_else(|| panic!("no authorization header"));
        value
            .strip_prefix("bearer ")
            .unwrap_or_else(|| panic!("authorization is not `bearer <jwt>`: {value}"))
            .to_owned()
    }

    fn decode_segment(segment: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD
            .decode(segment)
            .unwrap_or_else(|e| panic!("base64url: {e}"));
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("json: {e}"))
    }

    #[test]
    fn environment_selects_the_table_gateway() {
        assert_eq!(
            ApnsEnvironment::Production.origin(),
            "https://api.push.apple.com"
        );
        assert_eq!(
            ApnsEnvironment::Sandbox.origin(),
            "https://api.sandbox.push.apple.com"
        );
    }

    #[test]
    fn new_targets_the_configured_environment() {
        let production = ApnsSender::new(config()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(production.origin, "https://api.push.apple.com");
        let sandbox = ApnsSender::new(ApnsConfig {
            environment: ApnsEnvironment::Sandbox,
            ..config()
        })
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sandbox.origin, "https://api.sandbox.push.apple.com");
    }

    #[test]
    fn new_rejects_empty_and_control_character_fields() {
        for (field, cfg) in [
            (
                "key_id",
                ApnsConfig {
                    key_id: String::new(),
                    ..config()
                },
            ),
            (
                "team_id",
                ApnsConfig {
                    team_id: String::new(),
                    ..config()
                },
            ),
            (
                "topic",
                ApnsConfig {
                    topic: "works.limn\napp".to_owned(),
                    ..config()
                },
            ),
        ] {
            match ApnsSender::new(cfg) {
                Err(PushSenderError::InvalidConfig { field: got, .. }) => assert_eq!(got, field),
                other => panic!("{field}: expected InvalidConfig, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn request_carries_exactly_the_table_row() {
        let (sender, server, _) = sender_with(vec![Reply::empty(200)]).await;
        let outcome = PushSender::Apns(sender).send(&token()).await;
        assert_eq!(outcome, PushSendOutcome::Delivered);

        let requests = server.requests().await;
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, format!("/3/device/{DEVICE_TOKEN}"));
        assert_eq!(request.body, br#"{"aps":{"content-available":1}}"#);

        assert_eq!(bearer(request).split('.').count(), 3);
        assert_eq!(request.header("apns-push-type"), Some("background"));
        assert_eq!(request.header("apns-priority"), Some("5"));
        assert_eq!(request.header("apns-topic"), Some("works.limn.app"));
        // Beyond the four table headers the request carries only HTTP framing:
        // the body length, and reqwest's `accept: */*` default. No content
        // type, no `apns-expiration`, no `apns-collapse-id`.
        let mut names: Vec<&str> = request.headers.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "accept",
                "apns-priority",
                "apns-push-type",
                "apns-topic",
                "authorization",
                "content-length"
            ]
        );
        assert_eq!(request.header("accept"), Some("*/*"));
    }

    #[tokio::test]
    async fn provider_jwt_has_es256_kid_iss_iat_and_verifies() {
        let (sender, server, _) = sender_with(vec![Reply::empty(200)]).await;
        assert_eq!(sender.send(&token()).await, PushSendOutcome::Delivered);
        let jwt = bearer(&server.requests().await[0]);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            decode_segment(parts[0]),
            serde_json::json!({ "alg": "ES256", "kid": "ABC123DEFG" })
        );
        assert_eq!(
            decode_segment(parts[1]),
            serde_json::json!({ "iss": "TEAM456XYZ", "iat": START })
        );
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap_or_else(|e| panic!("{e}"));
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        es256_verify_strict(
            &test_key().public_key(),
            signing_input.as_bytes(),
            &signature,
        )
        .unwrap_or_else(|e| panic!("ES256 signature does not verify: {e}"));
    }

    #[tokio::test]
    async fn provider_jwt_is_reused_for_fifty_minutes_then_refreshed() {
        let (sender, server, clock) = sender_with(vec![
            Reply::empty(200),
            Reply::empty(200),
            Reply::empty(200),
        ])
        .await;
        sender.send(&token()).await;
        clock.advance(JWT_REFRESH_AFTER_SECS - 1);
        sender.send(&token()).await;
        clock.advance(1);
        sender.send(&token()).await;

        let requests = server.requests().await;
        let jwts: Vec<String> = requests.iter().map(bearer).collect();
        assert_eq!(jwts[0], jwts[1], "a JWT under 50 minutes old is reused");
        assert_ne!(jwts[1], jwts[2], "a 50-minute-old JWT is replaced");
        let claims = decode_segment(jwts[2].split('.').nth(1).unwrap_or_default());
        assert_eq!(claims["iat"], START + JWT_REFRESH_AFTER_SECS);
    }

    #[tokio::test]
    async fn each_response_row_maps_to_its_outcome() {
        use PushSendOutcome::{ConfigError, Delivered, InvalidToken, Transient};
        let rows: Vec<(&str, Vec<Reply>, PushSendOutcome, usize)> = vec![
            ("200", vec![Reply::empty(200)], Delivered, 1),
            ("410", vec![reason(410, "Unregistered")], InvalidToken, 1),
            ("410 no body", vec![Reply::empty(410)], InvalidToken, 1),
            (
                "400 BadDeviceToken",
                vec![reason(400, "BadDeviceToken")],
                InvalidToken,
                1,
            ),
            (
                "400 DeviceTokenNotForTopic",
                vec![reason(400, "DeviceTokenNotForTopic")],
                InvalidToken,
                1,
            ),
            (
                "400 TopicDisallowed",
                vec![reason(400, "TopicDisallowed")],
                ConfigError,
                1,
            ),
            (
                "403 InvalidProviderToken twice",
                vec![
                    reason(403, "InvalidProviderToken"),
                    reason(403, "InvalidProviderToken"),
                ],
                ConfigError,
                2,
            ),
            (
                "403 ExpiredProviderToken twice",
                vec![
                    reason(403, "ExpiredProviderToken"),
                    reason(403, "ExpiredProviderToken"),
                ],
                ConfigError,
                2,
            ),
            (
                "403 ExpiredProviderToken then 200",
                vec![reason(403, "ExpiredProviderToken"), Reply::empty(200)],
                Delivered,
                2,
            ),
            ("429", vec![reason(429, "TooManyRequests")], Transient, 1),
            (
                "500",
                vec![reason(500, "InternalServerError")],
                Transient,
                1,
            ),
            ("503", vec![reason(503, "ServiceUnavailable")], Transient, 1),
            (
                "400 BadTopic",
                vec![reason(400, "BadTopic")],
                ConfigError,
                1,
            ),
        ];
        // Each row first primes the sender with a delivered send at START, then
        // sends the row ROW_AT seconds later, while the cached JWT is still in
        // its 50-minute window.
        for (name, replies, expected, request_count) in rows {
            let mut scripted = vec![Reply::empty(200)];
            scripted.extend(replies);
            let (sender, server, clock) = sender_with(scripted).await;
            assert_eq!(sender.send(&token()).await, Delivered, "{name}: priming");
            clock.advance(ROW_AT);
            assert_eq!(sender.send(&token()).await, expected, "{name}");
            let requests = server.requests().await;
            assert_eq!(requests.len(), 1 + request_count, "{name}");
            let cached = bearer(&requests[0]);
            assert_eq!(
                bearer(&requests[1]),
                cached,
                "{name}: the cached JWT is reused"
            );
            if request_count == 2 {
                let resent = bearer(&requests[2]);
                assert_ne!(
                    resent, cached,
                    "{name}: the resend carries a newly minted JWT"
                );
                let claims = decode_segment(resent.split('.').nth(1).unwrap_or_default());
                assert_eq!(claims["iat"], START + ROW_AT, "{name}");
            }
        }
    }

    #[tokio::test]
    async fn unreachable_gateway_is_transient() {
        let clock = Arc::new(TestClock::new(START));
        let sender = ApnsSender::build(config(), TestServer::closed_origin().await, clock)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sender.send(&token()).await, PushSendOutcome::Transient);
    }

    #[tokio::test]
    async fn non_hex_token_is_invalid_without_a_request() {
        let (sender, server, _) = sender_with(vec![Reply::empty(200)]).await;
        for bad in ["", "zz11", "a1b2/../c3", "a1b2?x=1"] {
            assert_eq!(
                sender.send(&PushDeviceToken::new(bad)).await,
                PushSendOutcome::InvalidToken,
                "{bad:?}"
            );
        }
        assert!(server.requests().await.is_empty());
    }

    #[tokio::test]
    async fn no_log_line_carries_the_key_jwt_or_device_token() {
        let capture = LogCapture::install();
        let (sender, server, _) = sender_with(vec![
            Reply::empty(200),
            reason(400, "TopicDisallowed"),
            reason(403, "InvalidProviderToken"),
            reason(403, "InvalidProviderToken"),
            reason(503, "ServiceUnavailable"),
            reason(400, "BadDeviceToken"),
        ])
        .await;
        for _ in 0..5 {
            sender.send(&token()).await;
        }
        let unreachable = ApnsSender::build(
            config(),
            TestServer::closed_origin().await,
            Arc::new(TestClock::new(START)),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        unreachable.send(&token()).await;

        let jwts: Vec<String> = server.requests().await.iter().map(bearer).collect();
        assert!(jwts.len() >= 2);
        let logs = capture.contents();
        // The capture is live: the ConfigError warning reached it.
        assert!(
            logs.contains("TopicDisallowed") && logs.contains("apns"),
            "log capture saw nothing: {logs}"
        );
        let scalar_hex = hex::encode(test_key().to_scalar_bytes().as_ref());
        let mut secrets = vec![DEVICE_TOKEN.to_owned(), scalar_hex];
        for jwt in &jwts {
            secrets.push(jwt.clone());
            // Each JWT segment on its own, so a partial print is caught too.
            secrets.extend(jwt.split('.').map(str::to_owned));
        }
        for secret in secrets {
            assert!(!logs.contains(&secret), "a log line carries a secret");
        }
    }

    #[tokio::test]
    async fn debug_output_carries_no_key_or_jwt() {
        let printed_config = format!("{:?}", config());
        let (sender, server, _) = sender_with(vec![Reply::empty(200)]).await;
        sender.send(&token()).await;
        let jwt = bearer(&server.requests().await[0]);
        let printed_sender = format!("{sender:?}");
        let scalar_hex = hex::encode(test_key().to_scalar_bytes().as_ref());
        for printed in [&printed_config, &printed_sender] {
            assert!(!printed.contains(&scalar_hex), "{printed}");
            assert!(!printed.contains(&jwt), "{printed}");
            assert!(printed.contains("TEAM456XYZ"), "{printed}");
        }
    }
}
