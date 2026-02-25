//! In-memory [`Push`] implementation for testing.
//!
//! Returns synthetic push tokens (UUIDs) and passes notification payloads
//! through as wake signals. See ADR-006 in `.docs/adrs/phase-1.md`.

use uuid::Uuid;

use crate::error::PlatformError;
use crate::traits::{Push, PushToken, WakeSignal};

/// In-memory implementation of [`Push`] for testing and development.
///
/// Produces synthetic push tokens using UUID v4 and passes notification
/// payloads through directly as wake signals. For Phase 1 testing, push is
/// not actively exercised (processes use direct relay subscriptions), but
/// this adapter satisfies the trait requirements.
///
/// See ADR-006 in `.docs/adrs/phase-1.md`.
pub struct InMemoryPush;

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

// The trait uses RPITIT (`-> impl Future<...> + Send`), so each impl method
// must return a future rather than use `async fn` directly.
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
        let payload = payload.to_vec();
        async move { Ok(WakeSignal::new(payload)) }
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
    async fn handle_notification_passes_through_payload() {
        let push = InMemoryPush::new();
        let payload = b"wake up, new messages";
        let signal = push.handle_notification(payload).await.unwrap();
        assert_eq!(signal.payload, payload);
    }

    #[tokio::test]
    async fn handle_notification_empty_payload() {
        let push = InMemoryPush::new();
        let signal = push.handle_notification(b"").await.unwrap();
        assert!(signal.payload.is_empty());
    }

    #[tokio::test]
    async fn handle_notification_large_payload() {
        let push = InMemoryPush::new();
        let payload = vec![0xAB; 4096];
        let signal = push.handle_notification(&payload).await.unwrap();
        assert_eq!(signal.payload, payload);
    }
}
