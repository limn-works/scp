//! Push notification conformance test macro.
//!
//! The `push_conformance` macro generates 2 test cases that validate
//! any `Push` implementation against the protocol
//! specification (ADR-006):
//!
//! 1. `register_returns_token` — `register()` returns a non-empty push token
//! 2. `handle_notification_produces_event` — [`check_fixed_wake_signal`]:
//!    `handle_notification` accepts at least one of [`PERMITTED_PAYLOADS`], the
//!    wake payloads the platform artifacts name, and returns a non-empty wake
//!    signal for it. Every other payload the adapter accepts, whether another
//!    permitted payload, a permitted payload with trailing whitespace a relay
//!    chose, or one of [`METADATA_PAYLOADS`], yields a signal byte-identical
//!    to that first one; the adapter may reject any of them instead. The fixed
//!    signal is this suite's reading of §10.7's opacity rule
//!    (`.docs/specs/10-infrastructure-and-self-hosting.md`: a push payload
//!    carries "no context ID, no sender identifier, no message preview, no
//!    metadata of any kind"): a signal that varied with the payload would hand
//!    the caller whatever a relay put in it. ADR-006, as amended 2026-09-29,
//!    states the same rule for `InMemoryPush`.
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the platform adapter design.

use scp_platform::{Push, WakeSignal};

/// The wake payloads the platform artifacts name. Each adapter accepts the one
/// its platform uses and may reject the others:
///
/// - `{"aps":{"content-available":1}}`: the APNs payload of ADR-025 criterion
///   4 (`.docs/adrs/phase-5.md`).
/// - `{"data": {"scp": "1"}}`: the FCM payload of ADR-027
///   (`.docs/adrs/phase-6.md`).
/// - `{ "scp": 1 }`: the relay push payload of spec §10.7.1 step 5.
pub const PERMITTED_PAYLOADS: [&[u8]; 3] = [
    br#"{"aps":{"content-available":1}}"#,
    br#"{"data": {"scp": "1"}}"#,
    br#"{ "scp": 1 }"#,
];

/// Payloads carrying metadata §10.7 forbids: a JSON context ID and sender next
/// to the APNs wake field, and a context ID in plain bytes. An adapter rejects
/// each one or returns its fixed signal.
pub const METADATA_PAYLOADS: [&[u8]; 2] = [
    br#"{"aps":{"content-available":1},"contextId":"ctx-42","sender":"relay-7"}"#,
    b"new-message-ctx-123",
];

/// Asserts that `push` returns one fixed, non-empty wake signal.
///
/// `push` must accept at least one of [`PERMITTED_PAYLOADS`]. The signal for
/// the first permitted payload it accepts is the fixed signal, and every
/// payload it accepts among [`PERMITTED_PAYLOADS`], each of them with three
/// trailing spaces, and [`METADATA_PAYLOADS`] must yield a signal
/// byte-identical to it.
///
/// # Panics
///
/// Panics when `push` rejects every one of [`PERMITTED_PAYLOADS`], returns an
/// empty signal, or returns two different signals.
pub async fn check_fixed_wake_signal<P: Push>(push: &P) {
    let mut fixed = None;
    for payload in PERMITTED_PAYLOADS {
        if let Ok(signal) = push.handle_notification(payload).await {
            record_signal(&mut fixed, signal);
        }
    }
    assert!(
        fixed.is_some(),
        "handle_notification rejected every permitted payload"
    );
    let padded = PERMITTED_PAYLOADS.map(|p| [p, b"   ".as_slice()].concat());
    let others = padded.iter().map(Vec::as_slice).chain(METADATA_PAYLOADS);
    for payload in others {
        if let Ok(signal) = push.handle_notification(payload).await {
            record_signal(&mut fixed, signal);
        }
    }
}

/// Stores `signal` as the fixed signal when none is held yet, asserting that
/// it is non-empty; otherwise asserts that `signal` equals the held one.
fn record_signal(fixed: &mut Option<WakeSignal>, signal: WakeSignal) {
    if let Some(held) = fixed {
        assert_eq!(
            signal, *held,
            "wake signal varies with the notification payload"
        );
    } else {
        assert!(
            !signal.payload.is_empty(),
            "wake signal payload should not be empty"
        );
        *fixed = Some(signal);
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

    use scp_platform::PushToken;
    use scp_platform::error::PlatformError;
    use scp_platform::in_memory::InMemoryPush;

    use super::*;

    /// A strict adapter: rejects every payload but the one it holds.
    struct StrictPush(&'static [u8]);

    impl Push for StrictPush {
        fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send {
            async { Ok(PushToken::new(b"token".to_vec())) }
        }

        fn handle_notification(
            &self,
            payload: &[u8],
        ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send {
            let accepted = payload == self.0;
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
            let result = if payload.trim_ascii_end() == PERMITTED_PAYLOADS[0] {
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
    async fn accepts_strict_adapter_for_each_platform_payload() {
        // An APNs, an FCM, and a §10.7.1 adapter each reject every payload
        // but their own, and each passes.
        for payload in PERMITTED_PAYLOADS {
            check_fixed_wake_signal(&StrictPush(payload)).await;
        }
    }

    #[tokio::test]
    #[should_panic(expected = "rejected every permitted payload")]
    async fn rejects_adapter_accepting_only_metadata_payload() {
        check_fixed_wake_signal(&StrictPush(METADATA_PAYLOADS[1])).await;
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
    #[should_panic(expected = "rejected every permitted payload")]
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
