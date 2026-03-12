//! Push notification conformance test macro.
//!
//! The `push_conformance` macro generates 2 test cases that validate
//! any `Push` implementation against the protocol
//! specification (ADR-006):
//!
//! 1. `register_returns_token` — `register()` returns a non-empty push token
//! 2. `handle_notification_produces_event` — `handle_notification(payload)` returns a wake signal
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the platform adapter design.

/// Generates 2 conformance tests for a `Push` implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance of a type
/// implementing `Push`. This expression is called once per test to create a
/// fresh push notification provider.
///
/// # Example
///
/// ```ignore
/// use scp_testing::push_conformance;
///
/// push_conformance!(InMemoryPush::new());
/// ```
///
/// See ADR-006 and spec section 17.11.
#[macro_export]
macro_rules! push_conformance {
    ($factory:expr) => {
        #[allow(
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            unused_imports
        )]
        mod push_conformance {
            use super::*;

            use scp_platform::Push;

            #[tokio::test]
            async fn register_returns_token() {
                let push = $factory;

                let token = push.register().await.expect("register should succeed");

                assert!(
                    !token.as_bytes().is_empty(),
                    "push token should not be empty"
                );
            }

            #[tokio::test]
            async fn handle_notification_produces_event() {
                let push = $factory;

                let payload = b"test-notification-payload";
                let wake_signal = push
                    .handle_notification(payload)
                    .await
                    .expect("handle_notification should succeed");

                // The wake signal should contain the original payload (or a
                // processed version of it). At minimum it should be non-empty.
                assert!(
                    !wake_signal.payload.is_empty(),
                    "wake signal payload should not be empty"
                );
            }
        }
    };
}
