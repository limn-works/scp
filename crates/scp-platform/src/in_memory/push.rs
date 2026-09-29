//! Durability-only in-memory [`Push`] implementation (ADR-062 §0).
//!
//! Returns synthetic push tokens (UUIDs) and a fixed wake signal for every
//! notification payload. See ADR-006 in `.docs/adrs/phase-1.md`.

use uuid::Uuid;

use crate::error::PlatformError;
use crate::traits::{Push, PushToken, WakeSignal};

/// Durability-only in-memory implementation of [`Push`].
///
/// Produces synthetic push tokens using UUID v4. `handle_notification`
/// returns `WAKE_SIGNAL` for every payload and never the received bytes.
/// §10.7 of the infrastructure spec forbids a context ID, a sender identifier,
/// and any other metadata in a push payload, and a wake signal built from the
/// received bytes would hand whatever metadata a relay put there to the
/// caller.
///
/// See ADR-006 in `.docs/adrs/phase-1.md`.
pub struct InMemoryPush;

/// The wake signal [`InMemoryPush`] returns for every notification: the UTF-8
/// bytes of `{"aps":{"content-available":1}}`, the APNs payload ADR-025
/// criterion 4 names. The signal is fixed because §10.7's opacity rule allows
/// a push payload no content, context, sender, or metadata, so no byte of the
/// received payload may reach the caller.
const WAKE_SIGNAL: &[u8] = br#"{"aps":{"content-available":1}}"#;

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
        _payload: &[u8],
    ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send {
        async move { Ok(WakeSignal::new(WAKE_SIGNAL.to_vec())) }
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
        let push = InMemoryPush::new();
        let payload = br#"{"aps":{"content-available":1}}"#;
        let signal = push.handle_notification(payload).await.unwrap();
        assert_eq!(signal.payload, br#"{"aps":{"content-available":1}}"#);
    }

    #[tokio::test]
    async fn handle_notification_drops_payload_metadata() {
        // A payload carrying a context ID breaks §10.7's opacity rule; the
        // wake signal must not carry any of it to the caller.
        let push = InMemoryPush::new();
        let payload = br#"{"aps":{"content-available":1},"contextId":"ctx-42"}"#;
        let signal = push.handle_notification(payload).await.unwrap();
        assert_eq!(signal.payload, WAKE_SIGNAL);
        assert!(
            !signal.payload.windows(6).any(|w| w == b"ctx-42"),
            "wake signal carries the payload's context ID"
        );
    }

    #[tokio::test]
    async fn handle_notification_empty_payload() {
        let push = InMemoryPush::new();
        let signal = push.handle_notification(b"").await.unwrap();
        assert_eq!(signal.payload, WAKE_SIGNAL);
    }

    #[tokio::test]
    async fn handle_notification_large_payload() {
        let push = InMemoryPush::new();
        let payload = vec![0xAB; 4096];
        let signal = push.handle_notification(&payload).await.unwrap();
        assert_eq!(signal.payload, WAKE_SIGNAL);
    }
}
