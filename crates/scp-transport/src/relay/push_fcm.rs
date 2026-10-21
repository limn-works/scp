//! The FCM push sender over the HTTP v1 API (PUSH-011, spec §10.7.1 step 5,
//! ADR-027).
//!
//! Sends the FCM row of the §10.7.1 step 5 wake-signal table:
//! `POST https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`
//! with `Authorization: Bearer <OAuth 2.0 access token>` and
//! `Content-Type: application/json`, and the body
//! `{"message":{"token":"<FCM registration token>","data":{"scp":"1"},"android":{"priority":"HIGH"}}}`.
//! The body has no `notification` key, and the token appears only in
//! `message.token`.
//!
//! The access token comes from Google's OAuth 2.0 token endpoint
//! (`https://oauth2.googleapis.com/token`) through the JWT-bearer grant: the
//! sender mints an RS256 JWT signed by the service account's private key, with
//! claims `iss` (the service-account email), `scope`
//! (`https://www.googleapis.com/auth/firebase.messaging`), `aud` (the token
//! endpoint), `iat` and `exp` (`iat` + 3600). It reuses the access token until
//! 60 seconds before it expires (indicator), then fetches a new one.
//!
//! Response mapping (PUSH-011):
//!
//! | Response | Outcome |
//! |---|---|
//! | 200 | `Delivered` |
//! | 404 `UNREGISTERED`, or 400 `INVALID_ARGUMENT` naming the token | `InvalidToken` |
//! | 401 | fetch a new access token and resend once; 401 again is `ConfigError` |
//! | 403 `SENDER_ID_MISMATCH` | `InvalidToken` |
//! | 429 `QUOTA_EXCEEDED`, 503 or 500 | `Transient` |
//!
//! A response the table does not name maps to `ConfigError` when it is any
//! other 4xx and to `Transient` for any other status. A transport failure is
//! `Transient`. The token endpoint maps the same way: a 4xx answer (a revoked
//! or wrong key) is `ConfigError`, and a 429, a 5xx or a transport failure is
//! `Transient`.
//!
//! The RSA signer is `ring`'s, which is constant-time and is this crate's
//! existing rustls provider.

use std::fmt;
use std::sync::Arc;

use reqwest::header::{CONTENT_TYPE, HeaderValue};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use scp_clock::{Clock, SystemClock};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::push::{
    PushDeviceToken, PushSendOutcome, PushSenderError, compact_jws, http2_client, loggable_reason,
    pem_pkcs8_der, read_bounded, transport_error_kind,
};

/// The FCM HTTP v1 origin.
const FCM_ORIGIN: &str = "https://fcm.googleapis.com";

/// Google's OAuth 2.0 token endpoint, which is also the assertion's `aud`.
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// The OAuth scope that authorizes FCM sends.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// The lifetime the assertion JWT requests; Google's maximum.
const ASSERTION_LIFETIME_SECS: u64 = 3600;

/// How long before its expiry the sender stops reusing an access token
/// (indicator: 60 s).
const ACCESS_TOKEN_MARGIN_SECS: u64 = 60;

/// The form-encoded JWT-bearer grant type (RFC 7523 §2.1).
const JWT_BEARER_GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";

/// A service-account JSON that could not be read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FcmCredentialError {
    /// The bytes are not a JSON object.
    #[error("service-account file is not a JSON object")]
    NotJson,
    /// The `type` field is not `service_account`.
    #[error("service-account file `type` is not `service_account`")]
    NotServiceAccount,
    /// A required string field is missing or empty.
    #[error("service-account file has no `{0}`")]
    MissingField(&'static str),
    /// `private_key` is not a PEM `PRIVATE KEY` block.
    #[error("service-account `private_key` is not a PEM PKCS#8 private key")]
    PrivateKeyNotPem,
    /// `private_key` is PEM but not an RSA key `ring` accepts for RS256
    /// (2048 to 8192 bits).
    #[error("service-account `private_key` is not an RSA key usable for RS256")]
    PrivateKeyRejected,
}

/// A Google service account read from its JSON key file.
///
/// The private key is held as PKCS#8 DER in a zeroizing buffer and parsed
/// only for the moment it signs an assertion. `Debug` prints the email and
/// project ID, never the key.
pub struct FcmServiceAccount {
    client_email: String,
    project_id: Option<String>,
    private_key_pkcs8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for FcmServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FcmServiceAccount")
            .field("client_email", &self.client_email)
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

/// The service-account fields the sender reads. The key is moved into a
/// zeroizing buffer as soon as it is parsed.
#[derive(serde::Deserialize)]
struct RawServiceAccount {
    #[serde(rename = "type")]
    kind: Option<String>,
    project_id: Option<String>,
    client_email: Option<String>,
    private_key: Option<String>,
}

impl FcmServiceAccount {
    /// Reads a service-account JSON key file's bytes.
    ///
    /// # Errors
    ///
    /// An [`FcmCredentialError`] naming the first field that is missing or
    /// unusable. The private key is checked by parsing it, so a key that
    /// cannot sign fails here rather than at the first send.
    pub fn from_json(json: &[u8]) -> Result<Self, FcmCredentialError> {
        let raw: RawServiceAccount =
            serde_json::from_slice(json).map_err(|_| FcmCredentialError::NotJson)?;
        let private_key = Zeroizing::new(raw.private_key.unwrap_or_default());
        if raw.kind.as_deref() != Some("service_account") {
            return Err(FcmCredentialError::NotServiceAccount);
        }
        let client_email = raw
            .client_email
            .filter(|e| !e.is_empty())
            .ok_or(FcmCredentialError::MissingField("client_email"))?;
        if private_key.is_empty() {
            return Err(FcmCredentialError::MissingField("private_key"));
        }
        let private_key_pkcs8 = pem_private_key_der(&private_key)?;
        RsaKeyPair::from_pkcs8(&private_key_pkcs8)
            .map_err(|_| FcmCredentialError::PrivateKeyRejected)?;
        Ok(Self {
            client_email,
            project_id: raw.project_id.filter(|p| !p.is_empty()),
            private_key_pkcs8,
        })
    }

    /// The service-account email; the assertion's `iss`.
    #[must_use]
    pub fn client_email(&self) -> &str {
        &self.client_email
    }

    /// The `project_id` the JSON names, if any. PUSH-012 uses it when the
    /// operator names no project ID.
    #[must_use]
    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
    }

    /// Signs `input` with RS256.
    fn sign_rs256(&self, input: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
        let key = RsaKeyPair::from_pkcs8(&self.private_key_pkcs8)
            .map_err(|_| ring::error::Unspecified)?;
        let mut signature = vec![0u8; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input,
            &mut signature,
        )?;
        Ok(signature)
    }
}

/// Decodes the one `-----BEGIN PRIVATE KEY-----` block of `pem` to DER.
fn pem_private_key_der(pem: &str) -> Result<Zeroizing<Vec<u8>>, FcmCredentialError> {
    pem_pkcs8_der(pem).ok_or(FcmCredentialError::PrivateKeyNotPem)
}

/// Everything the FCM sender needs. PUSH-012 loads it from the operator's
/// files and environment.
#[derive(Debug)]
pub struct FcmConfig {
    /// The service account whose key authorizes sends.
    pub service_account: FcmServiceAccount,
    /// The Firebase project ID in the send URL.
    pub project_id: String,
}

/// An OAuth access token and the clock second it expires at.
struct AccessToken {
    value: Zeroizing<String>,
    expires_at: u64,
}

/// The token endpoint's success body.
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Sends FCM wake signals. Built once per relay from an [`FcmConfig`].
pub struct FcmSender {
    client: reqwest::Client,
    send_url: String,
    token_url: String,
    service_account: FcmServiceAccount,
    clock: Arc<dyn Clock>,
    access: Mutex<Option<AccessToken>>,
}

impl fmt::Debug for FcmSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FcmSender")
            .field("send_url", &self.send_url)
            .field("token_url", &self.token_url)
            .field("service_account", &self.service_account)
            .finish_non_exhaustive()
    }
}

/// What one send attempt produced.
enum Attempt {
    Done(PushSendOutcome),
    /// 401: the access token that was sent is rejected.
    Unauthorized,
}

impl FcmSender {
    /// Builds the sender for `config.project_id` against Google's endpoints.
    ///
    /// # Errors
    ///
    /// [`PushSenderError::InvalidConfig`] when the project ID is empty or holds
    /// a character outside `a-z`, `0-9` and `-` (the characters a Firebase
    /// project ID may hold), and [`PushSenderError::HttpClient`] when TLS
    /// cannot be initialized.
    pub fn new(config: FcmConfig) -> Result<Self, PushSenderError> {
        Self::build(
            config,
            FCM_ORIGIN,
            TOKEN_ENDPOINT.to_owned(),
            Arc::new(SystemClock),
        )
    }

    /// Builds the sender against `fcm_origin` and `token_url` with `clock`.
    /// [`Self::new`] passes Google's endpoints and the system clock; the tests
    /// pass a local server and a test clock.
    pub(crate) fn build(
        config: FcmConfig,
        fcm_origin: &str,
        token_url: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PushSenderError> {
        let FcmConfig {
            service_account,
            project_id,
        } = config;
        if project_id.is_empty() {
            return Err(PushSenderError::InvalidConfig {
                field: "project_id",
                reason: "empty",
            });
        }
        if !project_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PushSenderError::InvalidConfig {
                field: "project_id",
                reason: "holds a character outside a-z, 0-9 and -",
            });
        }
        Ok(Self {
            client: http2_client()?,
            send_url: format!("{fcm_origin}/v1/projects/{project_id}/messages:send"),
            token_url,
            service_account,
            clock,
            access: Mutex::new(None),
        })
    }

    /// Sends one wake signal to `token`.
    pub async fn send(&self, token: &PushDeviceToken) -> PushSendOutcome {
        if token.expose().is_empty() {
            tracing::debug!(platform = "fcm", "registration token is empty");
            return PushSendOutcome::InvalidToken;
        }
        let body = wake_body(token);

        let access = match self.access_token(None).await {
            Ok(access) => access,
            Err(outcome) => return outcome,
        };
        match self.attempt(&body, &access).await {
            Attempt::Done(outcome) => outcome,
            Attempt::Unauthorized => {
                let fresh = match self.access_token(Some(&access)).await {
                    Ok(fresh) => fresh,
                    Err(outcome) => return outcome,
                };
                match self.attempt(&body, &fresh).await {
                    Attempt::Done(outcome) => outcome,
                    Attempt::Unauthorized => {
                        tracing::warn!(
                            platform = "fcm",
                            status = 401,
                            "access token rejected after a refresh; check the service account's FCM permission"
                        );
                        PushSendOutcome::ConfigError
                    }
                }
            }
        }
    }

    /// Sends one request carrying `access` and maps the response.
    async fn attempt(&self, body: &[u8], access: &Zeroizing<String>) -> Attempt {
        let Ok(mut authorization) = HeaderValue::from_str(&format!("Bearer {}", access.as_str()))
        else {
            return Attempt::Done(PushSendOutcome::ConfigError);
        };
        authorization.set_sensitive(true);
        let response = match self
            .client
            .post(&self.send_url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(body.to_vec())
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(
                    platform = "fcm",
                    error_kind = transport_error_kind(&error),
                    "push send failed in transport"
                );
                return Attempt::Done(PushSendOutcome::Transient);
            }
        };
        let response = read_bounded(response).await;
        let error = FcmError::parse(&response.body);
        let mapped = map_response(response.status, &error);
        let code = loggable_reason(error.code());
        match mapped {
            Mapped::Outcome(PushSendOutcome::ConfigError) => tracing::warn!(
                platform = "fcm",
                status = response.status,
                reason = code,
                "push service rejected the relay's configuration"
            ),
            Mapped::Outcome(outcome) => tracing::debug!(
                platform = "fcm",
                status = response.status,
                reason = code,
                ?outcome,
                "push send answered"
            ),
            Mapped::Unauthorized => tracing::debug!(
                platform = "fcm",
                status = response.status,
                reason = code,
                "access token rejected"
            ),
        }
        match mapped {
            Mapped::Outcome(outcome) => Attempt::Done(outcome),
            Mapped::Unauthorized => Attempt::Unauthorized,
        }
    }

    /// Returns the cached access token while it has more than
    /// [`ACCESS_TOKEN_MARGIN_SECS`] left and is not `rejected`; otherwise
    /// fetches a new one. When another send already replaced a rejected token,
    /// the replacement is returned, so a burst of 401s fetches once. The lock
    /// is held across the fetch, so concurrent sends share one fetch.
    async fn access_token(
        &self,
        rejected: Option<&Zeroizing<String>>,
    ) -> Result<Zeroizing<String>, PushSendOutcome> {
        let mut cached = self.access.lock().await;
        let now = self.clock.now_secs();
        if let Some(token) = cached.as_ref() {
            let fresh = now.saturating_add(ACCESS_TOKEN_MARGIN_SECS) < token.expires_at;
            let is_rejected = rejected.is_some_and(|r| r.as_str() == token.value.as_str());
            if fresh && !is_rejected {
                return Ok(token.value.clone());
            }
        }
        let token = self.fetch_access_token(now).await?;
        let value = token.value.clone();
        *cached = Some(token);
        drop(cached);
        Ok(value)
    }

    /// Exchanges a freshly minted assertion for an access token.
    async fn fetch_access_token(&self, now: u64) -> Result<AccessToken, PushSendOutcome> {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iss": self.service_account.client_email,
            "scope": FCM_SCOPE,
            "aud": TOKEN_ENDPOINT,
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECS,
        });
        let assertion = compact_jws(&header, &claims, |input| {
            self.service_account.sign_rs256(input)
        })
        .map_err(|_| {
            tracing::warn!(platform = "fcm", "service-account assertion signing failed");
            PushSendOutcome::ConfigError
        })?;
        let mut form = Zeroizing::new(format!("grant_type={JWT_BEARER_GRANT}&assertion="));
        form.push_str(&assertion);

        let response = self
            .client
            .post(&self.token_url)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(form.as_bytes().to_vec())
            .send()
            .await
            .map_err(|error| {
                tracing::debug!(
                    platform = "fcm",
                    error_kind = transport_error_kind(&error),
                    "token request failed in transport"
                );
                PushSendOutcome::Transient
            })?;
        let response = read_bounded(response).await;
        let status = response.status;
        let body = Zeroizing::new(response.body);
        if status == 200 {
            if let Ok(parsed) = serde_json::from_slice::<TokenResponse>(&body) {
                let value = Zeroizing::new(parsed.access_token);
                if !value.is_empty() {
                    return Ok(AccessToken {
                        value,
                        expires_at: now.saturating_add(parsed.expires_in),
                    });
                }
            }
            tracing::warn!(
                platform = "fcm",
                status,
                "token endpoint answered without an access token"
            );
            return Err(PushSendOutcome::ConfigError);
        }
        let error = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(str::to_owned));
        let outcome = if status == 429 || (500..=599).contains(&status) {
            PushSendOutcome::Transient
        } else {
            PushSendOutcome::ConfigError
        };
        tracing::warn!(
            platform = "fcm",
            status,
            reason = loggable_reason(error.as_deref()),
            ?outcome,
            "token endpoint refused the service-account assertion"
        );
        Err(outcome)
    }
}

/// The §10.7.1 step 5 FCM body for `token`, in the table's key order. The
/// token is JSON-escaped by `serde_json`.
fn wake_body(token: &PushDeviceToken) -> Vec<u8> {
    let escaped = serde_json::Value::String(token.expose().to_owned()).to_string();
    format!(
        r#"{{"message":{{"token":{escaped},"data":{{"scp":"1"}},"android":{{"priority":"HIGH"}}}}}}"#
    )
    .into_bytes()
}

/// The fields of an FCM v1 error body the mapping reads.
#[derive(Debug, Default)]
struct FcmError {
    /// `error.status`, the google.rpc code name.
    status: Option<String>,
    /// `errorCode` of the `google.firebase.fcm.v1.FcmError` detail.
    error_code: Option<String>,
    /// Whether the error names the registration token: a
    /// `google.rpc.BadRequest` field violation on `message.token`, or a
    /// message that mentions the registration token.
    names_token: bool,
}

impl FcmError {
    fn parse(body: &[u8]) -> Self {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Self::default();
        };
        let Some(error) = value.get("error") else {
            return Self::default();
        };
        let mut parsed = Self {
            status: error
                .get("status")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            ..Self::default()
        };
        parsed.names_token = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|m| m.to_ascii_lowercase().contains("registration token"));
        for detail in error
            .get("details")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(code) = detail.get("errorCode").and_then(serde_json::Value::as_str) {
                parsed.error_code = Some(code.to_owned());
            }
            let names_token = detail
                .get("fieldViolations")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|v| {
                    v.get("field").and_then(serde_json::Value::as_str) == Some("message.token")
                });
            parsed.names_token |= names_token;
        }
        parsed
    }

    /// The FCM error code, else the google.rpc status, for matching and logs.
    fn code(&self) -> Option<&str> {
        self.error_code.as_deref().or(self.status.as_deref())
    }

    fn is(&self, code: &str) -> bool {
        self.error_code.as_deref() == Some(code) || self.status.as_deref() == Some(code)
    }
}

/// The result of mapping one response.
#[derive(Debug, PartialEq, Eq)]
enum Mapped {
    Outcome(PushSendOutcome),
    Unauthorized,
}

/// Maps an FCM status and error body to the PUSH-011 outcome table.
fn map_response(status: u16, error: &FcmError) -> Mapped {
    use PushSendOutcome::{ConfigError, Delivered, InvalidToken, Transient};
    let outcome = match status {
        200 => Delivered,
        401 => return Mapped::Unauthorized,
        404 if error.is("UNREGISTERED") => InvalidToken,
        400 if error.is("INVALID_ARGUMENT") && error.names_token => InvalidToken,
        403 if error.is("SENDER_ID_MISMATCH") => InvalidToken,
        429 | 500..=599 => Transient,
        400..=499 => ConfigError,
        _ => Transient,
    };
    Mapped::Outcome(outcome)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use scp_clock::TestClock;

    use super::super::log_capture::LogCapture;
    use super::super::push::PushSender;
    use super::super::push_test_server::{CapturedRequest, Reply, TestServer, json_reply};
    use super::*;

    /// A fresh RSA-2048 service-account key as PKCS#8 PEM, generated once per
    /// test process with the `rsa` crate (dev-only), so no private key is
    /// committed. It signs nothing outside these tests.
    fn test_rsa_key_pem() -> &'static str {
        use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};
        static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PEM.get_or_init(|| {
            let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
                .expect("RSA-2048 key generation");
            key.to_pkcs8_pem(LineEnding::LF)
                .expect("PKCS#8 PEM encoding")
                .to_string()
        })
    }
    const REG_TOKEN: &str = "fcm-reg-token:APA91bTestTokenValue_0123456789";
    const ACCESS_TOKEN_1: &str = "ya29.test-access-token-one";
    const ACCESS_TOKEN_2: &str = "ya29.test-access-token-two";
    const START: u64 = 1_800_000_000;
    pub const SEND_PATH: &str = "/v1/projects/scp-test-project/messages:send";

    fn service_account_json() -> Vec<u8> {
        serde_json::json!({
            "type": "service_account",
            "project_id": "scp-test-project",
            "private_key_id": "0123456789abcdef",
            "private_key": test_rsa_key_pem(),
            "client_email": "relay@scp-test-project.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string()
        .into_bytes()
    }

    pub fn config() -> FcmConfig {
        FcmConfig {
            service_account: FcmServiceAccount::from_json(&service_account_json()).unwrap(),
            project_id: "scp-test-project".to_owned(),
        }
    }

    pub fn token_reply(access_token: &str, expires_in: u64) -> Reply {
        json_reply(
            200,
            &serde_json::json!({
                "access_token": access_token,
                "expires_in": expires_in,
                "token_type": "Bearer",
            }),
        )
    }

    fn fcm_error(status: u16, rpc_status: &str, error_code: Option<&str>) -> Reply {
        let mut details = Vec::new();
        if let Some(code) = error_code {
            details.push(serde_json::json!({
                "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                "errorCode": code,
            }));
        }
        json_reply(
            status,
            &serde_json::json!({
                "error": {
                    "code": status,
                    "message": "test error",
                    "status": rpc_status,
                    "details": details,
                }
            }),
        )
    }

    async fn sender_with(
        token_replies: Vec<Reply>,
        send_replies: Vec<Reply>,
    ) -> (FcmSender, TestServer, Arc<TestClock>) {
        let server =
            TestServer::start_routed(vec![("/token", token_replies), ("/v1/", send_replies)]).await;
        let clock = Arc::new(TestClock::new(START));
        let sender = FcmSender::build(
            config(),
            &server.origin(),
            format!("{}/token", server.origin()),
            clock.clone(),
        )
        .unwrap();
        (sender, server, clock)
    }

    fn sends(requests: &[CapturedRequest]) -> Vec<&CapturedRequest> {
        requests.iter().filter(|r| r.path == SEND_PATH).collect()
    }

    fn token_requests(requests: &[CapturedRequest]) -> Vec<&CapturedRequest> {
        requests.iter().filter(|r| r.path == "/token").collect()
    }

    fn assertion_of(request: &CapturedRequest) -> String {
        let body = std::str::from_utf8(&request.body).unwrap();
        let rest = body
            .strip_prefix(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
            )
            .unwrap_or_else(|| panic!("unexpected token request body: {body}"));
        rest.to_owned()
    }

    fn decode_segment(segment: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    fn reg_token() -> PushDeviceToken {
        PushDeviceToken::new(REG_TOKEN)
    }

    #[tokio::test]
    async fn body_and_headers_are_the_table_row() {
        let (sender, server, _) = sender_with(
            vec![token_reply(ACCESS_TOKEN_1, 3599)],
            vec![Reply::empty(200)],
        )
        .await;
        let outcome = PushSender::Fcm(sender).send(&reg_token()).await;
        assert_eq!(outcome, PushSendOutcome::Delivered);

        let requests = server.requests().await;
        let sends = sends(&requests);
        assert_eq!(sends.len(), 1);
        let send = sends[0];
        assert_eq!(send.method, "POST");
        assert_eq!(send.path, SEND_PATH);
        assert_eq!(
            send.header("authorization"),
            Some(format!("Bearer {ACCESS_TOKEN_1}").as_str())
        );
        assert_eq!(send.header("content-type"), Some("application/json"));

        let body: serde_json::Value = serde_json::from_slice(&send.body).unwrap();
        let table: serde_json::Value = serde_json::from_str(&format!(
            r#"{{"message":{{"token":"{REG_TOKEN}","data":{{"scp":"1"}},"android":{{"priority":"HIGH"}}}}}}"#
        ))
        .unwrap();
        assert_eq!(
            body, table,
            "body equals the §10.7.1 FCM row after normalization"
        );
        assert!(!String::from_utf8_lossy(&send.body).contains("notification"));
        assert!(body["message"].get("notification").is_none());
        assert_eq!(body["message"]["android"]["priority"], "HIGH");
        assert_eq!(
            body["message"]["data"]["scp"], "1",
            "the wake value is the string \"1\""
        );
    }

    #[tokio::test]
    async fn token_request_carries_an_rs256_assertion_that_verifies() {
        let (sender, server, _) = sender_with(
            vec![token_reply(ACCESS_TOKEN_1, 3599)],
            vec![Reply::empty(200)],
        )
        .await;
        sender.send(&reg_token()).await;
        let requests = server.requests().await;
        let token_requests = token_requests(&requests);
        assert_eq!(token_requests.len(), 1);
        let request = token_requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        let assertion = assertion_of(request);
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            decode_segment(parts[0]),
            serde_json::json!({ "alg": "RS256", "typ": "JWT" })
        );
        assert_eq!(
            decode_segment(parts[1]),
            serde_json::json!({
                "iss": "relay@scp-test-project.iam.gserviceaccount.com",
                "scope": "https://www.googleapis.com/auth/firebase.messaging",
                "aud": "https://oauth2.googleapis.com/token",
                "iat": START,
                "exp": START + 3600,
            })
        );
        let der = pem_private_key_der(test_rsa_key_pem()).unwrap();
        let key = RsaKeyPair::from_pkcs8(&der).unwrap();
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref());
        public
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
            )
            .expect("RS256 signature verifies against the service-account key");
    }

    #[tokio::test]
    async fn access_token_is_reused_within_its_lifetime_and_refreshed_after() {
        let (sender, server, clock) = sender_with(
            vec![
                token_reply(ACCESS_TOKEN_1, 3600),
                token_reply(ACCESS_TOKEN_2, 3600),
            ],
            vec![Reply::empty(200), Reply::empty(200), Reply::empty(200)],
        )
        .await;
        sender.send(&reg_token()).await;
        // 61 s before expiry: still reused.
        clock.advance(3600 - ACCESS_TOKEN_MARGIN_SECS - 1);
        sender.send(&reg_token()).await;
        // 60 s before expiry: replaced.
        clock.advance(1);
        sender.send(&reg_token()).await;

        let requests = server.requests().await;
        assert_eq!(token_requests(&requests).len(), 2);
        let auth: Vec<&str> = sends(&requests)
            .iter()
            .map(|r| r.header("authorization").unwrap())
            .collect();
        let first = format!("Bearer {ACCESS_TOKEN_1}");
        let second = format!("Bearer {ACCESS_TOKEN_2}");
        assert_eq!(auth, [first.as_str(), first.as_str(), second.as_str()]);
        // The second assertion was minted at the refresh time.
        let claims = decode_segment(
            assertion_of(token_requests(&requests)[1])
                .split('.')
                .nth(1)
                .unwrap(),
        );
        assert_eq!(claims["iat"], START + 3600 - ACCESS_TOKEN_MARGIN_SECS);
    }

    /// One mapping row: what the token endpoint and FCM answer, the outcome,
    /// and how many token and send requests the sender makes.
    struct Row {
        name: &'static str,
        token: Vec<Reply>,
        send: Vec<Reply>,
        expected: PushSendOutcome,
        token_requests: usize,
        sends: usize,
    }

    /// A row whose token request succeeds and whose single send gets `reply`.
    fn one_send(name: &'static str, reply: Reply, expected: PushSendOutcome) -> Row {
        Row {
            name,
            token: vec![token_reply(ACCESS_TOKEN_1, 3599)],
            send: vec![reply],
            expected,
            token_requests: 1,
            sends: 1,
        }
    }

    /// A row whose first send gets 401 and whose resend gets `second`.
    fn after_401(name: &'static str, second: Reply, expected: PushSendOutcome) -> Row {
        Row {
            name,
            token: vec![
                token_reply(ACCESS_TOKEN_1, 3599),
                token_reply(ACCESS_TOKEN_2, 3599),
            ],
            send: vec![fcm_error(401, "UNAUTHENTICATED", None), second],
            expected,
            token_requests: 2,
            sends: 2,
        }
    }

    /// A row whose token request gets `reply`, so no send is made.
    fn token_refused(name: &'static str, reply: Reply, expected: PushSendOutcome) -> Row {
        Row {
            name,
            token: vec![reply],
            send: vec![],
            expected,
            token_requests: 1,
            sends: 0,
        }
    }

    /// A 400 `INVALID_ARGUMENT` with `message` whose `BadRequest` detail names
    /// `field`.
    fn invalid_argument(field: &str, message: &str) -> Reply {
        json_reply(
            400,
            &serde_json::json!({
                "error": {
                    "code": 400,
                    "message": message,
                    "status": "INVALID_ARGUMENT",
                    "details": [
                        {
                            "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                            "errorCode": "INVALID_ARGUMENT"
                        },
                        {
                            "@type": "type.googleapis.com/google.rpc.BadRequest",
                            "fieldViolations": [{ "field": field, "description": "invalid" }]
                        }
                    ]
                }
            }),
        )
    }

    fn mapping_rows() -> Vec<Row> {
        use PushSendOutcome::{ConfigError, Delivered, InvalidToken, Transient};
        vec![
            one_send("200", Reply::empty(200), Delivered),
            one_send(
                "404 UNREGISTERED",
                fcm_error(404, "NOT_FOUND", Some("UNREGISTERED")),
                InvalidToken,
            ),
            one_send(
                "400 INVALID_ARGUMENT naming the token",
                invalid_argument(
                    "message.token",
                    "The registration token is not a valid FCM registration token",
                ),
                InvalidToken,
            ),
            one_send(
                "400 INVALID_ARGUMENT naming another field",
                invalid_argument("message.data", "Invalid JSON payload received."),
                ConfigError,
            ),
            after_401(
                "401 twice",
                fcm_error(401, "UNAUTHENTICATED", None),
                ConfigError,
            ),
            after_401("401 then 200", Reply::empty(200), Delivered),
            one_send(
                "403 SENDER_ID_MISMATCH",
                fcm_error(403, "PERMISSION_DENIED", Some("SENDER_ID_MISMATCH")),
                InvalidToken,
            ),
            one_send(
                "403 PERMISSION_DENIED",
                fcm_error(403, "PERMISSION_DENIED", None),
                ConfigError,
            ),
            one_send(
                "429 QUOTA_EXCEEDED",
                fcm_error(429, "RESOURCE_EXHAUSTED", Some("QUOTA_EXCEEDED")),
                Transient,
            ),
            one_send(
                "503",
                fcm_error(503, "UNAVAILABLE", Some("UNAVAILABLE")),
                Transient,
            ),
            one_send(
                "500",
                fcm_error(500, "INTERNAL", Some("INTERNAL")),
                Transient,
            ),
            token_refused(
                "token endpoint 400 invalid_grant",
                json_reply(400, &serde_json::json!({ "error": "invalid_grant" })),
                ConfigError,
            ),
            token_refused("token endpoint 503", Reply::empty(503), Transient),
        ]
    }

    #[tokio::test]
    async fn each_response_row_maps_to_its_outcome() {
        for row in mapping_rows() {
            let name = row.name;
            let (sender, server, _) = sender_with(row.token, row.send).await;
            assert_eq!(sender.send(&reg_token()).await, row.expected, "{name}");
            let requests = server.requests().await;
            assert_eq!(
                token_requests(&requests).len(),
                row.token_requests,
                "{name}"
            );
            let sends = sends(&requests);
            assert_eq!(sends.len(), row.sends, "{name}");
            if row.sends == 2 {
                assert_eq!(
                    sends[1].header("authorization"),
                    Some(format!("Bearer {ACCESS_TOKEN_2}").as_str()),
                    "{name}: the resend carries the refreshed access token"
                );
            }
        }
    }

    #[tokio::test]
    async fn unreachable_endpoints_are_transient() {
        let closed = TestServer::closed_origin();
        let origin = closed.origin();
        let sender = FcmSender::build(
            config(),
            origin,
            format!("{origin}/token"),
            Arc::new(TestClock::new(START)),
        )
        .unwrap();
        assert_eq!(sender.send(&reg_token()).await, PushSendOutcome::Transient);
    }

    #[tokio::test]
    async fn token_with_json_metacharacters_stays_inside_message_token() {
        let tricky = r#"abc","notification":{"title":"x"},"z":""#;
        let (sender, server, _) = sender_with(
            vec![token_reply(ACCESS_TOKEN_1, 3599)],
            vec![Reply::empty(200)],
        )
        .await;
        sender.send(&PushDeviceToken::new(tricky)).await;
        let requests = server.requests().await;
        let body: serde_json::Value = serde_json::from_slice(&sends(&requests)[0].body).unwrap();
        assert_eq!(body["message"]["token"], tricky);
        assert!(body["message"].get("notification").is_none());
    }

    #[tokio::test]
    async fn no_log_line_carries_the_key_assertion_access_token_or_registration_token() {
        let capture = LogCapture::install();
        let (sender, server, _) = sender_with(
            vec![
                token_reply(ACCESS_TOKEN_1, 3599),
                token_reply(ACCESS_TOKEN_2, 3599),
            ],
            vec![
                Reply::empty(200),
                fcm_error(403, "PERMISSION_DENIED", None),
                fcm_error(401, "UNAUTHENTICATED", None),
                fcm_error(401, "UNAUTHENTICATED", None),
                fcm_error(503, "UNAVAILABLE", Some("UNAVAILABLE")),
            ],
        )
        .await;
        for _ in 0..4 {
            sender.send(&reg_token()).await;
        }
        let closed = TestServer::closed_origin();
        let origin = closed.origin();
        FcmSender::build(
            config(),
            origin,
            format!("{origin}/token"),
            Arc::new(TestClock::new(START)),
        )
        .unwrap()
        .send(&reg_token())
        .await;

        let logs = capture.contents();
        assert!(
            logs.contains("PERMISSION_DENIED") && logs.contains("fcm"),
            "log capture saw nothing: {logs}"
        );
        let requests = server.requests().await;
        let mut secrets = vec![
            REG_TOKEN.to_owned(),
            ACCESS_TOKEN_1.to_owned(),
            ACCESS_TOKEN_2.to_owned(),
        ];
        for request in token_requests(&requests) {
            let assertion = assertion_of(request);
            secrets.extend(assertion.split('.').map(str::to_owned));
            secrets.push(assertion);
        }
        // Every line of the PEM body, so a partial key print is caught.
        secrets.extend(
            test_rsa_key_pem()
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .map(str::to_owned),
        );
        for secret in secrets {
            assert!(!logs.contains(&secret), "a log line carries a secret");
        }
    }

    #[test]
    fn debug_output_carries_no_key_or_token() {
        let printed = format!("{:?}", config());
        for line in test_rsa_key_pem()
            .lines()
            .filter(|l| !l.starts_with("-----"))
        {
            assert!(!printed.contains(line), "{printed}");
        }
        assert!(printed.contains("relay@scp-test-project.iam.gserviceaccount.com"));
    }

    #[tokio::test]
    async fn sender_debug_carries_no_access_token() {
        let (sender, _server, _) = sender_with(
            vec![token_reply(ACCESS_TOKEN_1, 3599)],
            vec![Reply::empty(200)],
        )
        .await;
        sender.send(&reg_token()).await;
        let printed = format!("{sender:?}");
        assert!(!printed.contains(ACCESS_TOKEN_1), "{printed}");
        assert!(!printed.contains("PRIVATE KEY"), "{printed}");
    }

    #[test]
    fn service_account_json_errors_are_typed() {
        let with = |patch: serde_json::Value| {
            let mut value: serde_json::Value =
                serde_json::from_slice(&service_account_json()).unwrap();
            for (k, v) in patch.as_object().unwrap() {
                value[k] = v.clone();
            }
            FcmServiceAccount::from_json(value.to_string().as_bytes())
        };
        assert_eq!(
            FcmServiceAccount::from_json(b"not json").unwrap_err(),
            FcmCredentialError::NotJson
        );
        assert_eq!(
            with(serde_json::json!({ "type": "authorized_user" })).unwrap_err(),
            FcmCredentialError::NotServiceAccount
        );
        assert_eq!(
            with(serde_json::json!({ "client_email": "" })).unwrap_err(),
            FcmCredentialError::MissingField("client_email")
        );
        assert_eq!(
            with(serde_json::json!({ "private_key": "" })).unwrap_err(),
            FcmCredentialError::MissingField("private_key")
        );
        assert_eq!(
            with(serde_json::json!({ "private_key": "MIIB" })).unwrap_err(),
            FcmCredentialError::PrivateKeyNotPem
        );
        assert_eq!(
            with(serde_json::json!({
                "private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
            }))
            .unwrap_err(),
            FcmCredentialError::PrivateKeyRejected
        );
        let account = FcmServiceAccount::from_json(&service_account_json()).unwrap();
        assert_eq!(account.project_id(), Some("scp-test-project"));
        assert_eq!(
            account.client_email(),
            "relay@scp-test-project.iam.gserviceaccount.com"
        );
    }

    #[test]
    fn project_id_outside_the_firebase_alphabet_is_rejected() {
        for bad in ["", "Bad", "a/b", "a?b"] {
            let result = FcmSender::new(FcmConfig {
                project_id: bad.to_owned(),
                ..config()
            });
            assert!(
                matches!(
                    result,
                    Err(PushSenderError::InvalidConfig {
                        field: "project_id",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        let sender = FcmSender::new(config()).unwrap();
        assert_eq!(
            sender.send_url,
            "https://fcm.googleapis.com/v1/projects/scp-test-project/messages:send"
        );
        assert_eq!(sender.token_url, "https://oauth2.googleapis.com/token");
    }
}
