//! The relay push sender seam (spec §10.7.1 step 5).
//!
//! A relay wakes a registered device by sending the §10.7.1 step 5 wake-signal
//! request for the registration's platform. [`PushSender`] is the one type the
//! relay holds per configured platform; its arms are the production senders
//! [`ApnsSender`] (PUSH-010), [`FcmSender`] (PUSH-011) and [`WebPushSender`]
//! (PUSH-022). Every send returns a
//! [`PushSendOutcome`], which the dispatcher of PUSH-008
//! ([`push_dispatch`](super::push_dispatch)) reads to keep or remove a
//! registration.
//!
//! No shipped arm of [`PushSender`] accepts a send without performing it. The
//! `Recording` arm reports scripted outcomes for sends that never happened, so
//! it is a nullifier (§17.17.2 of the persistence spec) and compiles only under
//! `testing`; `scripts/check-shipped-feature-graph.sh` keeps `testing` out of
//! every shipped build.
//!
//! Secrets: the APNs signing key, the FCM service-account key, the VAPID key,
//! the provider and VAPID JWTs and the OAuth access token live in zeroizing
//! buffers, and no `Debug` implementation in this module or its senders prints
//! them, a device token, or a `WebPush` endpoint, `p256dh` or `auth`. No log
//! line carries any of them: a send logs only the platform, the HTTP status,
//! the platform's reason code, and a typed error that carries none of them.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use scp_protocol::discovery::push::{PushPlatform, WebPushSubscription};
use zeroize::Zeroizing;

pub use super::push_apns::{
    ApnsConfig, ApnsEnvironment, ApnsKeyError, ApnsSender, apns_key_from_p8,
};
pub use super::push_fcm::{FcmConfig, FcmCredentialError, FcmSender, FcmServiceAccount};
pub use super::push_webpush::{VapidSubject, WebPushConfig, WebPushSender};

/// The result of one wake-signal send.
///
/// The PUSH-008 dispatcher counts only [`InvalidToken`](Self::InvalidToken)
/// toward the §10.7.1 three-failure removal rule, resets the count on
/// [`Delivered`](Self::Delivered), and leaves it unchanged on the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushSendOutcome {
    /// The push service accepted the wake signal for delivery.
    Delivered,
    /// The push service reports that the device token is not valid for this
    /// sender: unregistered, malformed, or issued for another app or project.
    InvalidToken,
    /// The push service is unavailable, throttling, or unreachable; a later
    /// send may succeed.
    Transient,
    /// The relay's own push credentials or configuration are rejected; no send
    /// succeeds until the operator fixes them. The registration is kept.
    ConfigError,
}

/// A platform push token as the registration carried it: an APNs device token
/// or an FCM registration token.
///
/// The token is held in a zeroizing buffer, and `Debug` prints only its length,
/// so a token never reaches a log through formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct PushDeviceToken(Zeroizing<String>);

impl PushDeviceToken {
    /// Wraps a token string.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self(Zeroizing::new(token.into()))
    }

    /// The token text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PushDeviceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushDeviceToken")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A push sender for one platform.
///
/// The relay builds one per platform its operator configured (PUSH-012) and
/// routes each registration's wake to the sender whose
/// [`platform`](Self::platform) matches the registration.
#[derive(Debug)]
pub enum PushSender {
    /// Sends the APNs row of the §10.7.1 step 5 table.
    Apns(ApnsSender),
    /// Sends the FCM row of the §10.7.1 step 5 table.
    Fcm(FcmSender),
    /// Sends the `WebPush` row of the §10.7.1 step 5 table.
    WebPush(WebPushSender),
    /// Records each token and returns scripted outcomes without sending
    /// anything. A nullifier, so it compiles only under `testing`.
    #[cfg(feature = "testing")]
    Recording(RecordingSender),
}

impl PushSender {
    /// The platform this sender wakes.
    #[must_use]
    pub const fn platform(&self) -> PushPlatform {
        match self {
            Self::Apns(_) => PushPlatform::Apns,
            Self::Fcm(_) => PushPlatform::Fcm,
            Self::WebPush(_) => PushPlatform::WebPush,
            #[cfg(feature = "testing")]
            Self::Recording(sender) => sender.platform,
        }
    }

    /// Sends one wake signal to a token as a registration carries it, the
    /// raw `token` bytes of `PushRegistration` (§22.11.4), and reports the
    /// outcome. Never fails: every network, credential, and response
    /// condition maps to a [`PushSendOutcome`].
    ///
    /// - APNs: the bytes are the device token, which iOS hands the app as
    ///   raw bytes; the request path carries their lowercase hex (§10.7.1
    ///   step 5 `POST /3/device/<APNs device token>`). Empty bytes are
    ///   `InvalidToken`.
    /// - FCM: the bytes are the UTF-8 registration token; bytes that are not
    ///   UTF-8 are `InvalidToken`, because no FCM token can match them.
    /// - `WebPush`: the bytes are the §22.11.4 `WebPush` token; bytes that
    ///   [`WebPushSubscription::decode`] rejects are `InvalidToken`, and no
    ///   request is sent for them.
    pub async fn send_registered(&self, token: &[u8]) -> PushSendOutcome {
        match self {
            Self::Apns(sender) => {
                if token.is_empty() {
                    tracing::debug!(platform = "apns", "device token is empty");
                    return PushSendOutcome::InvalidToken;
                }
                sender.send(&PushDeviceToken::new(hex::encode(token))).await
            }
            Self::Fcm(sender) => {
                let Ok(text) = std::str::from_utf8(token) else {
                    tracing::debug!(platform = "fcm", "registration token is not UTF-8");
                    return PushSendOutcome::InvalidToken;
                };
                sender.send(&PushDeviceToken::new(text)).await
            }
            Self::WebPush(sender) => match WebPushSubscription::decode(token) {
                Ok(subscription) => sender.send(&subscription).await,
                Err(error) => {
                    tracing::debug!(platform = "webpush", %error, "WebPush token is malformed");
                    PushSendOutcome::InvalidToken
                }
            },
            #[cfg(feature = "testing")]
            Self::Recording(sender) => sender.record(token).await,
        }
    }
}

/// A sender that sends nothing: it records each token it is handed and
/// returns the next scripted outcome, or `ConfigError` once the script runs
/// out, so an unscripted send never passes for a delivery.
///
/// A gated sender (see [`Self::gated`]) records the token and then holds the
/// send until its [`RecordingGate`] admits it, so a test can keep a send in
/// flight for as long as it needs, as a push service that stops answering
/// does.
///
/// It reports deliveries that never happened, so it is a nullifier (§17.17.2)
/// and compiles only under `testing`. Clones share the script, the record and
/// the gate.
#[cfg(feature = "testing")]
#[derive(Clone)]
pub struct RecordingSender {
    platform: PushPlatform,
    state: std::sync::Arc<tokio::sync::Mutex<RecordingState>>,
    gate: Option<std::sync::Arc<tokio::sync::Semaphore>>,
}

/// Admits the sends of a gated [`RecordingSender`], one permit per send.
#[cfg(feature = "testing")]
#[derive(Clone, Debug)]
pub struct RecordingGate(std::sync::Arc<tokio::sync::Semaphore>);

#[cfg(feature = "testing")]
impl RecordingGate {
    /// Admits `sends` more sends.
    pub fn admit(&self, sends: usize) {
        self.0.add_permits(sends);
    }
}

/// The script still to play and the tokens handed over so far.
#[cfg(feature = "testing")]
struct RecordingState {
    script: std::collections::VecDeque<PushSendOutcome>,
    sent: Vec<Zeroizing<Vec<u8>>>,
}

#[cfg(feature = "testing")]
impl RecordingSender {
    /// A recording sender for `platform` that returns `outcomes` in order.
    pub fn new(
        platform: PushPlatform,
        outcomes: impl IntoIterator<Item = PushSendOutcome>,
    ) -> Self {
        Self {
            platform,
            state: std::sync::Arc::new(tokio::sync::Mutex::new(RecordingState {
                script: outcomes.into_iter().collect(),
                sent: Vec::new(),
            })),
            gate: None,
        }
    }

    /// As [`Self::new`], with every send held until the returned gate admits
    /// it. The gate starts closed.
    pub fn gated(
        platform: PushPlatform,
        outcomes: impl IntoIterator<Item = PushSendOutcome>,
    ) -> (Self, RecordingGate) {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let sender = Self {
            gate: Some(gate.clone()),
            ..Self::new(platform, outcomes)
        };
        (sender, RecordingGate(gate))
    }

    /// Every token handed to this sender so far, in order.
    pub async fn sent(&self) -> Vec<Vec<u8>> {
        self.state
            .lock()
            .await
            .sent
            .iter()
            .map(|t| t.to_vec())
            .collect()
    }

    async fn record(&self, token: &[u8]) -> PushSendOutcome {
        let outcome = {
            let mut state = self.state.lock().await;
            state.sent.push(Zeroizing::new(token.to_vec()));
            state
                .script
                .pop_front()
                .unwrap_or(PushSendOutcome::ConfigError)
        };
        if let Some(gate) = &self.gate {
            match gate.acquire().await {
                Ok(permit) => permit.forget(),
                // No code closes the semaphore; a closed gate answers
                // `ConfigError` so it never passes for a delivery.
                Err(_) => return PushSendOutcome::ConfigError,
            }
        }
        outcome
    }
}

#[cfg(feature = "testing")]
impl fmt::Debug for RecordingSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingSender")
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

/// A sender that could not be built from its configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PushSenderError {
    /// A configured value is empty or contains characters its platform does
    /// not allow. `field` names the configuration field.
    #[error("push sender configuration field `{field}` is invalid: {reason}")]
    InvalidConfig {
        /// The configuration field.
        field: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The HTTP client could not be built (TLS initialization failed).
    #[error("push sender HTTP client could not be built: {0}")]
    HttpClient(String),
}

/// The per-request deadline of a push send or token request (indicator: 10 s).
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The TCP and TLS connect deadline (indicator: 5 s).
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The most response-body bytes a sender reads; push-service error bodies are
/// a few hundred bytes, and a longer body is truncated, never buffered whole.
const MAX_RESPONSE_BODY: usize = 16 * 1024;

/// The HTTP/2 keep-alive a sender's client runs.
#[derive(Debug, Clone, Copy)]
pub(super) struct KeepAlive {
    /// Time from the last frame read to the next PING.
    pub(super) interval: Duration,
    /// Time a PING may go unacknowledged before the connection is closed.
    pub(super) timeout: Duration,
}

/// The keep-alive every production sender runs (indicators: a PING 5 s after
/// the last frame read, 3 s to acknowledge it). The two sum to less than
/// [`REQUEST_TIMEOUT`], so a send on a connection whose path died fails on
/// the keep-alive before the request deadline, and the next send opens a new
/// connection.
pub(super) const PRODUCTION_KEEP_ALIVE: KeepAlive = KeepAlive {
    interval: Duration::from_secs(5),
    timeout: Duration::from_secs(3),
};

/// Builds the HTTP/2 client a sender uses.
///
/// Both senders speak HTTP/2 only: APNs requires it, and the Google endpoints
/// FCM uses serve it. Over TLS the client offers only `h2` in ALPN. The
/// client runs [`PRODUCTION_KEEP_ALIVE`] on every connection, idle or not.
pub(super) fn http2_client() -> Result<reqwest::Client, PushSenderError> {
    http2_client_with(PRODUCTION_KEEP_ALIVE)
}

/// [`http2_client`] with `keep_alive` in place of the production values, so
/// a test can watch a dead connection close without waiting seconds.
pub(super) fn http2_client_with(keep_alive: KeepAlive) -> Result<reqwest::Client, PushSenderError> {
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .http2_keep_alive_interval(keep_alive.interval)
        .http2_keep_alive_timeout(keep_alive.timeout)
        .http2_keep_alive_while_idle(true)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| PushSenderError::HttpClient(e.without_url().to_string()))
}

/// A response's status and at most [`MAX_RESPONSE_BODY`] bytes of its body.
pub(super) struct BoundedResponse {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

/// Reads a response's status and a bounded prefix of its body. A body that
/// fails mid-read keeps the bytes read so far.
pub(super) async fn read_bounded(mut response: reqwest::Response) -> BoundedResponse {
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        let room = MAX_RESPONSE_BODY.saturating_sub(body.len());
        if room == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }
    BoundedResponse { status, body }
}

/// The kind of a transport failure, for logging. A `reqwest::Error`'s text
/// carries the request URL, and an APNs URL carries the device token, so a
/// sender logs only this kind, never the error itself.
pub(super) fn transport_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_request() {
        "request"
    } else if error.is_body() || error.is_decode() {
        "body"
    } else {
        "other"
    }
}

/// Returns `reason` when it has the shape of a platform reason code (ASCII
/// letters, digits and `_`, at most 64 bytes), and `"unrecognized"` otherwise,
/// so a log line never carries free text a push service echoed back.
pub(super) fn loggable_reason(reason: Option<&str>) -> &str {
    match reason {
        Some(r)
            if !r.is_empty()
                && r.len() <= 64
                && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') =>
        {
            r
        }
        Some(_) => "unrecognized",
        None => "none",
    }
}

/// Builds a compact JWS: `BASE64URL(header) '.' BASE64URL(claims)`, signed by
/// `sign`, with the signature appended. The result is zeroizing.
pub(super) fn compact_jws<E>(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Zeroizing<String>, E> {
    compact_jws_bytes(
        header.to_string().as_bytes(),
        claims.to_string().as_bytes(),
        sign,
    )
}

/// [`compact_jws`] over the exact header and claims bytes, so a caller whose
/// spec fixes the member order (the VAPID JWT of §10.7.1) keeps it;
/// `serde_json::Value` sorts object members.
pub(super) fn compact_jws_bytes<E>(
    header: &[u8],
    claims: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<Zeroizing<String>, E> {
    let mut jws = Zeroizing::new(String::new());
    jws.push_str(&URL_SAFE_NO_PAD.encode(header));
    jws.push('.');
    jws.push_str(&URL_SAFE_NO_PAD.encode(claims));
    let signature = sign(jws.as_bytes())?;
    jws.push('.');
    jws.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(jws)
}

/// Decodes the one `-----BEGIN PRIVATE KEY-----` (PKCS#8) block of `pem` to
/// DER, or `None` when `pem` holds no such block or its body is not base64.
/// The body copy and the DER are zeroizing.
pub(super) fn pem_pkcs8_der(pem: &str) -> Option<Zeroizing<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let end = pem.get(start..)?.find(END)? + start;
    let body: Zeroizing<String> = Zeroizing::new(
        pem.get(start..end)?
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect(),
    );
    STANDARD.decode(body.as_bytes()).ok().map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build without `testing` holds only the production senders: this
    /// match names `Apns`, `Fcm` and `WebPush` with no wildcard, so it stops
    /// compiling if any other arm, such as `Recording`, is present.
    #[cfg(not(feature = "testing"))]
    #[test]
    fn sender_without_testing_has_only_production_arms() -> Result<(), Box<dyn std::error::Error>> {
        fn arm_name(sender: &PushSender) -> &'static str {
            match sender {
                PushSender::Apns(_) => "apns",
                PushSender::Fcm(_) => "fcm",
                PushSender::WebPush(_) => "webpush",
            }
        }
        let key = scp_crypto::p256::P256SecretKey::from_scalar_bytes(&[7u8; 32])?;
        let sender = PushSender::Apns(ApnsSender::new(ApnsConfig {
            signing_key: key,
            key_id: "ABC123DEFG".to_owned(),
            team_id: "TEAM456XYZ".to_owned(),
            topic: "works.limn.app".to_owned(),
            environment: ApnsEnvironment::Sandbox,
        })?);
        assert_eq!(arm_name(&sender), "apns");
        Ok(())
    }

    /// The recording sender keeps every token, answers in script order, and
    /// answers `ConfigError` once the script runs out; its `Debug` prints no
    /// token.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn recording_sender_follows_its_script() {
        let recorder = RecordingSender::new(PushPlatform::Fcm, [PushSendOutcome::Delivered]);
        let sender = PushSender::Recording(recorder.clone());
        assert_eq!(sender.platform(), PushPlatform::Fcm);
        assert_eq!(
            sender.send_registered(b"tok-a").await,
            PushSendOutcome::Delivered
        );
        assert_eq!(
            sender.send_registered(b"tok-b").await,
            PushSendOutcome::ConfigError
        );
        assert_eq!(
            recorder.sent().await,
            vec![b"tok-a".to_vec(), b"tok-b".to_vec()]
        );
        let shown = format!("{sender:?}");
        assert!(!shown.contains("tok-a"), "{shown}");
        assert!(shown.contains("Fcm"), "{shown}");
    }

    /// A gated recording sender records the token at once and answers only
    /// after its gate admits the send.
    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn gated_recording_sender_waits_for_its_gate() -> Result<(), Box<dyn std::error::Error>> {
        let (recorder, gate) =
            RecordingSender::gated(PushPlatform::Apns, [PushSendOutcome::Delivered]);
        let sender = PushSender::Recording(recorder.clone());
        let mut send = tokio::spawn(async move { sender.send_registered(b"tok").await });
        for _ in 0..500 {
            if !recorder.sent().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(recorder.sent().await, vec![b"tok".to_vec()]);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut send)
                .await
                .is_err(),
            "the send answered before its gate opened"
        );
        gate.admit(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), send).await??,
            PushSendOutcome::Delivered
        );
        Ok(())
    }

    /// An empty APNs device token is `InvalidToken`, and the sender makes no
    /// request for it.
    #[tokio::test]
    async fn empty_apns_token_is_invalid_and_sends_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::super::push_test_server::TestServer;
        let server = TestServer::start(Vec::new()).await;
        let sender = PushSender::Apns(ApnsSender::build(
            super::super::push_apns::tests::config(),
            server.origin(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )?);
        assert_eq!(
            sender.send_registered(b"").await,
            PushSendOutcome::InvalidToken
        );
        assert!(server.requests().await.is_empty(), "a request was made");
        Ok(())
    }

    /// FCM token bytes that are not UTF-8 are `InvalidToken`, and the sender
    /// makes no request for them, not even for an access token.
    #[tokio::test]
    async fn non_utf8_fcm_token_is_invalid_and_sends_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::super::push_test_server::TestServer;
        let server = TestServer::start(Vec::new()).await;
        let origin = server.origin();
        let sender = PushSender::Fcm(FcmSender::build(
            super::super::push_fcm::tests::config(),
            &origin,
            format!("{origin}/token"),
            std::sync::Arc::new(scp_clock::SystemClock),
        )?);
        assert_eq!(
            sender.send_registered(&[0xff, 0xfe, 0x41]).await,
            PushSendOutcome::InvalidToken
        );
        assert!(server.requests().await.is_empty(), "a request was made");
        Ok(())
    }

    /// The production keep-alive detects a dead connection before the
    /// request deadline runs out.
    #[test]
    fn production_keep_alive_fits_inside_the_request_deadline() {
        let KeepAlive { interval, timeout } = PRODUCTION_KEEP_ALIVE;
        assert!(
            interval + timeout < REQUEST_TIMEOUT,
            "{interval:?} + {timeout:?} >= {REQUEST_TIMEOUT:?}"
        );
    }

    /// A push service that stops reading its connection (it answers nothing
    /// and acknowledges no PING) costs a send one keep-alive interval plus
    /// one timeout, not the request deadline: the client closes the dead
    /// connection and the send fails.
    #[tokio::test]
    async fn keep_alive_closes_a_connection_whose_peer_stopped_reading()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::super::push_test_server::FrozenServer;
        let server = FrozenServer::start().await?;
        let client = http2_client_with(KeepAlive {
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(200),
        })?;
        let started = std::time::Instant::now();
        let result = client
            .post(format!("{}/3/device/ab", server.origin()))
            .body("{}")
            .send()
            .await;
        let elapsed = started.elapsed();
        assert!(result.is_err(), "a frozen peer answered: {result:?}");
        assert!(
            elapsed < Duration::from_secs(3),
            "the send waited {elapsed:?}, close to the request deadline"
        );
        assert!(
            server.took_a_request(),
            "the request never reached the peer"
        );
        Ok(())
    }

    #[test]
    fn device_token_debug_prints_no_token_text() {
        let token = PushDeviceToken::new("a1b2c3d4e5f60718");
        let printed = format!("{token:?}");
        assert!(!printed.contains("a1b2c3d4e5f60718"), "{printed}");
        assert!(printed.contains("len: 16"), "{printed}");
    }

    #[test]
    fn loggable_reason_keeps_codes_and_drops_free_text() {
        assert_eq!(loggable_reason(Some("BadDeviceToken")), "BadDeviceToken");
        assert_eq!(loggable_reason(Some("QUOTA_EXCEEDED")), "QUOTA_EXCEEDED");
        assert_eq!(
            loggable_reason(Some("token abc/def is bad")),
            "unrecognized"
        );
        assert_eq!(loggable_reason(Some("")), "unrecognized");
        assert_eq!(loggable_reason(None), "none");
    }
}
