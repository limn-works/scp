//! Push notification conformance test macro.
//!
//! The `push_conformance` macro generates 2 test cases that validate
//! any `Push` implementation against the protocol
//! specification (ADR-006):
//!
//! 1. `register_returns_token` — `register()` returns a non-empty push token
//! 2. `handle_notification_produces_event` — [`check_fixed_wake_signal`]:
//!    `handle_notification` accepts the APNs payload ADR-025 criterion 4 names
//!    and returns a non-empty wake signal, and for three other payloads (a JSON
//!    context ID and sender, a context ID in plain bytes, and the permitted
//!    payload with trailing whitespace a relay chose) it either returns an
//!    error or returns a signal byte-identical to the first. The fixed signal is this suite's reading of §10.7's opacity rule
//!    (`.docs/specs/10-infrastructure-and-self-hosting.md`: a push payload
//!    carries "no context ID, no sender identifier, no message preview, no
//!    metadata of any kind"): a signal that varied with the payload would hand
//!    the caller whatever a relay put in it. ADR-006, as amended 2026-09-29,
//!    states the same rule for `InMemoryPush`.
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the platform adapter design.

use scp_platform::Push;

/// The APNs push payload ADR-025 criterion 4 names; every adapter accepts it.
pub const PERMITTED_PAYLOAD: &[u8] = br#"{"aps":{"content-available":1}}"#;

/// Payloads other than [`PERMITTED_PAYLOAD`].
///
/// Two carry metadata §10.7 forbids, and the third is the permitted payload
/// with trailing whitespace a relay chose. An adapter rejects each one or returns the signal it returns for
/// [`PERMITTED_PAYLOAD`].
pub const OTHER_PAYLOADS: [&[u8]; 3] = [
    br#"{"aps":{"content-available":1},"contextId":"ctx-42","sender":"relay-7"}"#,
    b"new-message-ctx-123",
    b"{\"aps\":{\"content-available\":1}}   ",
];

/// Asserts that `push` returns one fixed, non-empty wake signal: the signal for
/// [`PERMITTED_PAYLOAD`], and for each of [`OTHER_PAYLOADS`] either an error
/// or a byte-identical signal.
///
/// # Panics
///
/// Panics when `push` rejects [`PERMITTED_PAYLOAD`], returns an empty signal,
/// or returns a signal for another payload that differs from the signal for
/// [`PERMITTED_PAYLOAD`].
pub async fn check_fixed_wake_signal<P: Push>(push: &P) {
    let result = push.handle_notification(PERMITTED_PAYLOAD).await;
    assert!(
        result.is_ok(),
        "handle_notification rejected the permitted payload: {:?}",
        result.as_ref().err()
    );
    let Ok(fixed) = result else { return };
    assert!(
        !fixed.payload.is_empty(),
        "wake signal payload should not be empty"
    );
    for payload in OTHER_PAYLOADS {
        if let Ok(signal) = push.handle_notification(payload).await {
            assert_eq!(
                signal, fixed,
                "wake signal varies with the notification payload"
            );
        }
    }
}

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
                $crate::conformance::push::check_fixed_wake_signal(&push).await;
            }
        }
    };
}

#[cfg(test)]
#[allow(clippy::manual_async_fn)]
mod tests {
    use std::future::Future;

    use scp_platform::error::PlatformError;
    use scp_platform::in_memory::InMemoryPush;
    use scp_platform::{PushToken, WakeSignal};

    use super::*;

    /// A strict adapter: rejects every payload but the permitted one.
    struct RejectingPush;

    impl Push for RejectingPush {
        fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send {
            async { Ok(PushToken::new(b"token".to_vec())) }
        }

        fn handle_notification(
            &self,
            payload: &[u8],
        ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send {
            let accepted = payload == PERMITTED_PAYLOAD;
            async move {
                if accepted {
                    Ok(WakeSignal::new(b"wake".to_vec()))
                } else {
                    Err(PlatformError::PushError("opaque payload violation".into()))
                }
            }
        }
    }

    /// An adapter that derives its signal from the payload with `transform`.
    struct DerivingPush(fn(&[u8]) -> Vec<u8>);

    impl Push for DerivingPush {
        fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send {
            async { Ok(PushToken::new(b"token".to_vec())) }
        }

        fn handle_notification(
            &self,
            payload: &[u8],
        ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send {
            let signal = WakeSignal::new((self.0)(payload));
            async move { Ok(signal) }
        }
    }

    /// A strict adapter that echoes an accepted payload: it rejects every
    /// payload but the permitted one with trailing whitespace allowed, and
    /// returns the received bytes.
    struct EchoingStrictPush;

    impl Push for EchoingStrictPush {
        fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send {
            async { Ok(PushToken::new(b"token".to_vec())) }
        }

        fn handle_notification(
            &self,
            payload: &[u8],
        ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send {
            let result = if payload.trim_ascii_end() == PERMITTED_PAYLOAD {
                Ok(WakeSignal::new(payload.to_vec()))
            } else {
                Err(PlatformError::PushError("opaque payload violation".into()))
            };
            async move { result }
        }
    }

    #[tokio::test]
    #[should_panic(expected = "wake signal varies with the notification payload")]
    async fn rejects_echo_of_accepted_payload() {
        // Only the whitespace-padded payload reaches the comparison, so this
        // case fails on the relay's trailing whitespace alone.
        check_fixed_wake_signal(&EchoingStrictPush).await;
    }

    #[tokio::test]
    async fn accepts_in_memory_push() {
        check_fixed_wake_signal(&InMemoryPush::new()).await;
    }

    #[tokio::test]
    async fn accepts_adapter_rejecting_metadata_payloads() {
        check_fixed_wake_signal(&RejectingPush).await;
    }

    #[tokio::test]
    #[should_panic(expected = "wake signal varies with the notification payload")]
    async fn rejects_pass_through() {
        check_fixed_wake_signal(&DerivingPush(<[u8]>::to_vec)).await;
    }

    #[tokio::test]
    #[should_panic(expected = "wake signal varies with the notification payload")]
    async fn rejects_truncated_payload() {
        check_fixed_wake_signal(&DerivingPush(|p| p[1..].to_vec())).await;
    }

    #[tokio::test]
    #[should_panic(expected = "wake signal varies with the notification payload")]
    async fn rejects_extracted_context_id() {
        // Returns the bytes after the last `ctx-`, or a constant when the
        // payload names no context.
        check_fixed_wake_signal(&DerivingPush(|p| {
            p.windows(4)
                .rposition(|w| w == b"ctx-")
                .map_or_else(|| b"wake".to_vec(), |i| p[i..].to_vec())
        }))
        .await;
    }

    #[tokio::test]
    #[should_panic(expected = "wake signal payload should not be empty")]
    async fn rejects_empty_signal() {
        check_fixed_wake_signal(&DerivingPush(|_| Vec::new())).await;
    }

    #[tokio::test]
    #[should_panic(expected = "rejected the permitted payload")]
    async fn rejects_adapter_refusing_permitted_payload() {
        struct RefusingPush;
        impl Push for RefusingPush {
            fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send {
                async { Ok(PushToken::new(b"token".to_vec())) }
            }
            fn handle_notification(
                &self,
                _payload: &[u8],
            ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send {
                async { Err(PlatformError::PushError("refused".into())) }
            }
        }
        check_fixed_wake_signal(&RefusingPush).await;
    }
}
