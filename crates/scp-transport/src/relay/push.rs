//! The relay push sender seam (spec §10.7.1 step 5).
//!
//! A relay wakes a registered device by sending the §10.7.1 step 5 wake-signal
//! request for the registration's platform. [`PushSender`] is the one type the
//! relay holds per configured platform; its arms are the production senders
//! [`ApnsSender`] (PUSH-010) and [`FcmSender`] (PUSH-011). Every send returns a
//! [`PushSendOutcome`], which the dispatcher of PUSH-008 reads to keep or remove
//! a registration.
//!
//! No arm of [`PushSender`] accepts a send without performing it: a sender that
//! reports deliveries that never happened is a nullifier (§17.17.2 of the
//! persistence spec), so any recording arm PUSH-008 adds compiles only under
//! `testing`.
//!
//! Secrets: the APNs signing key, the FCM service-account key, the provider JWT
//! and the OAuth access token live in zeroizing buffers, and no `Debug`
//! implementation in this module or its senders prints them or a device token.
//! No log line carries any of them: a send logs only the platform, the HTTP
//! status and the platform's reason code.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use scp_protocol::discovery::push::PushPlatform;
use zeroize::Zeroizing;

pub use super::push_apns::{
    ApnsConfig, ApnsEnvironment, ApnsKeyError, ApnsSender, apns_key_from_p8,
};
pub use super::push_fcm::{FcmConfig, FcmCredentialError, FcmSender, FcmServiceAccount};

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
}

impl PushSender {
    /// The platform this sender wakes.
    #[must_use]
    pub const fn platform(&self) -> PushPlatform {
        match self {
            Self::Apns(_) => PushPlatform::Apns,
            Self::Fcm(_) => PushPlatform::Fcm,
        }
    }

    /// Sends one wake signal to `token` and reports the outcome.
    ///
    /// Never fails: every network, credential, and response condition maps to
    /// a [`PushSendOutcome`].
    pub async fn send(&self, token: &PushDeviceToken) -> PushSendOutcome {
        match self {
            Self::Apns(sender) => sender.send(token).await,
            Self::Fcm(sender) => sender.send(token).await,
        }
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
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The TCP and TLS connect deadline (indicator: 5 s).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The most response-body bytes a sender reads; push-service error bodies are
/// a few hundred bytes, and a longer body is truncated, never buffered whole.
const MAX_RESPONSE_BODY: usize = 16 * 1024;

/// Builds the HTTP/2 client a sender uses.
///
/// Both senders speak HTTP/2 only: APNs requires it, and the Google endpoints
/// FCM uses serve it. Over TLS the client offers only `h2` in ALPN.
pub(super) fn http2_client() -> Result<reqwest::Client, PushSenderError> {
    reqwest::Client::builder()
        .http2_prior_knowledge()
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
    let mut jws = Zeroizing::new(String::new());
    jws.push_str(&URL_SAFE_NO_PAD.encode(header.to_string()));
    jws.push('.');
    jws.push_str(&URL_SAFE_NO_PAD.encode(claims.to_string()));
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
