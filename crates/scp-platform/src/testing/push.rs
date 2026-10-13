//! Test-double in-memory [`Push`] implementation, behind the `testing` feature.
//!
//! Returns synthetic push tokens (UUIDs) and a fixed wake signal for each wake
//! body of the §10.7.1 step 5 table, and rejects every other notification
//! payload. No push service issued the token, so no wake reaches a device that
//! registers with it. See ADR-006 in `.docs/adrs/phase-1.md` and
//! ADR-062 §0 (amended 2026-10-12).

// `lib.rs` already gates `testing` behind this feature. The file repeats the
// gate because scp-testing's `test_double_gating` test parses each file alone
// and fails on a declaration of `InMemoryPush` that carries no gate of its own.
#![cfg(feature = "testing")]

use uuid::Uuid;

use crate::error::{PlatformError, PushFailureKind};
use crate::traits::{Push, PushToken, WakeSignal};

/// Test-double in-memory implementation of [`Push`].
///
/// Produces synthetic push tokens using UUID v4. `handle_notification`
/// accepts only [`APNS_WAKE_BODY`] and [`FCM_WAKE_DATA`], returns
/// `WAKE_SIGNAL` for each and never the received bytes, and rejects every
/// other payload with [`PushFailureKind::WakePayloadInvalid`].
/// §10.7 of the infrastructure spec states: "Push payloads MUST contain a wake
/// signal and nothing else. No context ID, no sender identifier, no message
/// preview, no metadata of any kind." A wake signal built from the received
/// bytes would hand the caller whatever a relay put there.
///
/// See ADR-006 in `.docs/adrs/phase-1.md`.
pub struct InMemoryPush;

/// The APNs wake payload: the APNs row's body in the wake-signal table of
/// §10.7.1 step 5 (`.docs/specs/10-infrastructure-and-self-hosting.md`).
pub const APNS_WAKE_BODY: &[u8] = br#"{"aps":{"content-available":1}}"#;

/// The FCM wake payload, the FCM row's `data` map as a JSON object.
///
/// The map is the one in the FCM row's body of the wake-signal table of
/// §10.7.1 step 5. The FCM receipt rule
/// of that step reads this map, the one Android hands the app, and not the
/// HTTP v1 envelope around it.
pub const FCM_WAKE_DATA: &[u8] = br#"{"scp":"1"}"#;

/// The wake signal [`InMemoryPush`] returns for every payload it accepts: the
/// bytes of [`APNS_WAKE_BODY`]. The signal is fixed so that no byte of the
/// received payload reaches the caller; the [`InMemoryPush`] doc quotes the
/// §10.7 rule this follows.
const WAKE_SIGNAL: &[u8] = APNS_WAKE_BODY;

impl InMemoryPush {
    /// Creates a new in-memory push adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for InMemoryPush {
    fn default() -> Self {
        Self::new()
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl Push for InMemoryPush {
    fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send {
        async move {
            let token = Uuid::new_v4().to_string();
            Ok(PushToken::new(token.into_bytes()))
        }
    }

    fn handle_notification(
        &self,
        payload: &[u8],
    ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send {
        let accepted = payload == APNS_WAKE_BODY || payload == FCM_WAKE_DATA;
        async move {
            if accepted {
                Ok(WakeSignal::new(WAKE_SIGNAL))
            } else {
                Err(PlatformError::PushError {
                    kind: PushFailureKind::WakePayloadInvalid,
                    detail: "payload is not a wake body of spec §10.7.1 step 5".into(),
                })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_returns_uuid_token() {
        let push = InMemoryPush::new();
        let token = push.register().await.unwrap();
        let token_str = String::from_utf8(token.as_bytes().to_vec()).unwrap();
        // UUID v4 format: 8-4-4-4-12 hex digits
        assert_eq!(token_str.len(), 36);
        assert_eq!(token_str.chars().filter(|c| *c == '-').count(), 4);
    }

    #[tokio::test]
    async fn sequential_registrations_produce_unique_tokens() {
        let push = InMemoryPush::new();
        let token_a = push.register().await.unwrap();
        let token_b = push.register().await.unwrap();
        assert_ne!(token_a.as_bytes(), token_b.as_bytes());
    }

    #[tokio::test]
    async fn handle_notification_returns_fixed_wake_signal() {
        // FCM_WAKE_DATA differs from WAKE_SIGNAL, so an adapter that returned
        // the received bytes would fail the FCM case.
        let push = InMemoryPush::new();
        assert_ne!(FCM_WAKE_DATA, WAKE_SIGNAL);
        for payload in [APNS_WAKE_BODY, FCM_WAKE_DATA] {
            let signal = push.handle_notification(payload).await.unwrap();
            assert_eq!(signal.payload(), WAKE_SIGNAL);
        }
    }

    /// Asserts that `push` rejects `payload` as an invalid wake payload.
    async fn assert_rejected(push: &InMemoryPush, payload: &[u8]) {
        let err = push.handle_notification(payload).await.unwrap_err();
        assert!(
            matches!(
                err,
                PlatformError::PushError {
                    kind: PushFailureKind::WakePayloadInvalid,
                    ..
                }
            ),
            "unexpected error {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_notification_rejects_payload_metadata() {
        // A payload carrying a context ID breaks §10.7's opacity rule, and the
        // APNs receipt rule of §10.7.1 step 5 rejects its extra key.
        let push = InMemoryPush::new();
        assert_rejected(
            &push,
            br#"{"aps":{"content-available":1},"contextId":"ctx-42"}"#,
        )
        .await;
    }

    #[tokio::test]
    async fn handle_notification_rejects_alert_key() {
        let push = InMemoryPush::new();
        assert_rejected(&push, br#"{"aps":{"alert":"hi","content-available":1}}"#).await;
    }

    #[tokio::test]
    async fn handle_notification_rejects_empty_payload() {
        assert_rejected(&InMemoryPush::new(), b"").await;
    }

    #[tokio::test]
    async fn handle_notification_rejects_large_payload() {
        assert_rejected(&InMemoryPush::new(), &[0xAB; 4096]).await;
    }
}
