//! Push notification conformance test macro.
//!
//! The `push_conformance` macro generates 2 test cases that validate
//! any `Push` implementation against the protocol
//! specification (ADR-006):
//!
//! 1. `register_returns_token` — `register()` returns a non-empty push token
//! 2. `handle_notification_returns_fixed_wake` — [`check_fixed_wake_signal`]:
//!    `handle_notification` accepts at least one of [`PERMITTED_PAYLOADS`], the
//!    wake payloads of the wake-signal table in §10.7.1 step 5
//!    (`.docs/specs/10-infrastructure-and-self-hosting.md`), and returns a
//!    non-empty wake signal for it. Every payload the adapter accepts, among
//!    the permitted payloads, those payloads with trailing whitespace a relay
//!    chose, and [`PROBE_PAYLOADS`], passes the APNs or the FCM device receipt
//!    rule of that step ([`apns_receipt_accepts`], [`fcm_receipt_accepts`])
//!    and yields a signal byte-identical to the first one; the adapter may
//!    reject any payload but its own permitted one. Spec §16.12.5
//!    (`.docs/specs/16-test-infrastructure.md`) and ADR-006's testing harness
//!    paragraph state this contract for every adapter. It follows §10.7:
//!    "Push payloads MUST contain a wake signal and nothing else. No context
//!    ID, no sender identifier, no message preview, no metadata of any kind."
//!    A signal that varied with the payload would hand the caller whatever a
//!    relay put in it.
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the platform adapter design.

use scp_platform::testing::{APNS_WAKE_BODY, FCM_WAKE_DATA};
use scp_platform::{Push, WakeSignal};
use serde_json::Value;

/// The wake payloads of the §10.7.1 step 5 wake-signal table.
///
/// They are the payloads a device receives from that table's bodies:
/// [`APNS_WAKE_BODY`], and [`FCM_WAKE_DATA`], the FCM row's `data` map as a
/// JSON object. Each adapter accepts the one its
/// platform uses and may reject the other.
pub const PERMITTED_PAYLOADS: [&[u8]; 2] = [APNS_WAKE_BODY, FCM_WAKE_DATA];

/// Payloads the check sends besides the permitted ones.
///
/// The FCM receipt rule
/// accepts the first, a data map with a context ID and sender beside `scp`,
/// because it reads no key but `scp`; an adapter rejects it or returns its
/// fixed signal. Both receipt rules reject the rest, so an adapter rejects
/// each of them: an APNs dictionary with a context ID and sender beside `aps`,
/// an APNs dictionary whose `aps` holds an `alert`, the dictionary of the
/// relay payload §10.7.1 step 5 named before the wake-signal table replaced
/// it, whose integer `scp` the FCM rule rejects, and a context ID in plain
/// bytes.
pub const PROBE_PAYLOADS: [&[u8]; 5] = [
    br#"{"scp":"1","contextId":"ctx-42","sender":"relay-7"}"#,
    br#"{"aps":{"content-available":1},"contextId":"ctx-42","sender":"relay-7"}"#,
    br#"{"aps":{"alert":"ctx-42","content-available":1}}"#,
    br#"{"scp":1}"#,
    b"new-message-ctx-123",
];

/// The APNs device receipt rule of §10.7.1 step 5, applied to `payload` parsed
/// as the JSON dictionary iOS hands the app.
#[must_use]
pub fn apns_receipt_accepts(payload: &[u8]) -> bool {
    let Ok(Value::Object(top)) = serde_json::from_slice::<Value>(payload) else {
        return false;
    };
    top.len() == 1
        && top
            .get("aps")
            .and_then(Value::as_object)
            .is_some_and(|aps| {
                aps.len() == 1 && aps.get("content-available").and_then(Value::as_i64) == Some(1)
            })
}

/// The FCM device receipt rule of §10.7.1 step 5, applied to `payload` parsed
/// as a JSON object holding the message's data map.
#[must_use]
pub fn fcm_receipt_accepts(payload: &[u8]) -> bool {
    serde_json::from_slice::<Value>(payload)
        .is_ok_and(|map| map.get("scp").and_then(Value::as_str) == Some("1"))
}

/// Asserts that `push` returns one fixed, non-empty wake signal and accepts
/// only payloads that a §10.7.1 step 5 receipt rule accepts.
///
/// `push` must accept at least one of [`PERMITTED_PAYLOADS`]. The signal for
/// the first permitted payload it accepts is the fixed signal. Every payload it
/// accepts among [`PERMITTED_PAYLOADS`], each of them with three trailing
/// spaces, and [`PROBE_PAYLOADS`] must pass [`apns_receipt_accepts`] or
/// [`fcm_receipt_accepts`] and yield a signal byte-identical to the fixed one.
///
/// # Panics
///
/// Panics when `push` rejects every one of [`PERMITTED_PAYLOADS`], accepts a
/// payload that both receipt rules reject, returns an empty signal, or returns
/// two different signals.
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
    let others = padded.iter().map(Vec::as_slice).chain(PROBE_PAYLOADS);
    for payload in others {
        if let Ok(signal) = push.handle_notification(payload).await {
            assert!(
                apns_receipt_accepts(payload) || fcm_receipt_accepts(payload),
                "handle_notification accepted a payload no §10.7.1 receipt rule accepts: {}",
                String::from_utf8_lossy(payload)
            );
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
            !signal.payload().is_empty(),
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
/// See ADR-006 and spec §16.12.5 (`.docs/specs/16-test-infrastructure.md`).
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
            async fn handle_notification_returns_fixed_wake() {
                let push = $factory;
                $crate::conformance::push::check_fixed_wake_signal(&push).await;
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use scp_platform::PushToken;
    use scp_platform::error::{PlatformError, PushFailureKind};
    use scp_platform::testing::InMemoryPush;

    use super::*;

    /// The bytes of the relay payload §10.7.1 step 5 named before the
    /// wake-signal table replaced it. Only the tests that prove its rejection
    /// hold it.
    const RETIRED_PAYLOAD: &[u8] = b"{ \"scp\": 1 }";

    /// An APNs dictionary whose `aps` carries an `alert` beside the wake key.
    const ALERT_PAYLOAD: &[u8] = br#"{"aps":{"alert":"hi","content-available":1}}"#;

    fn invalid() -> PlatformError {
        PlatformError::PushError {
            kind: PushFailureKind::WakePayloadInvalid,
            detail: "opaque payload violation".into(),
        }
    }

    /// A strict adapter: rejects every payload but the one it holds.
    struct StrictPush(&'static [u8]);

    impl Push for StrictPush {
        async fn register(&self) -> Result<PushToken, PlatformError> {
            Ok(PushToken::new(b"token".to_vec()))
        }

        async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal, PlatformError> {
            if payload == self.0 {
                Ok(WakeSignal::new(b"wake"))
            } else {
                Err(invalid())
            }
        }
    }

    /// An adapter that accepts every payload whose parsed JSON equals one of
    /// the parsed payloads it holds, and returns one constant signal.
    struct ParsedPush(&'static [&'static [u8]]);

    impl Push for ParsedPush {
        async fn register(&self) -> Result<PushToken, PlatformError> {
            Ok(PushToken::new(b"token".to_vec()))
        }

        async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal, PlatformError> {
            let parsed = serde_json::from_slice::<Value>(payload).map_err(|_| invalid())?;
            let held = self
                .0
                .iter()
                .any(|p| serde_json::from_slice::<Value>(p).is_ok_and(|v| v == parsed));
            if held {
                Ok(WakeSignal::new(b"wake"))
            } else {
                Err(invalid())
            }
        }
    }

    /// An adapter that derives its signal from the payload with its function.
    /// It leaks the derived bytes to get the `&'static` slice `WakeSignal`
    /// holds, one of the ways an adapter can make its signal vary with the
    /// payload.
    struct DerivingPush(fn(&[u8]) -> Vec<u8>);

    impl Push for DerivingPush {
        async fn register(&self) -> Result<PushToken, PlatformError> {
            Ok(PushToken::new(b"token".to_vec()))
        }

        async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal, PlatformError> {
            Ok(WakeSignal::new((self.0)(payload).leak()))
        }
    }

    /// A strict adapter that echoes an accepted payload: it rejects every
    /// payload but the permitted one with trailing whitespace allowed, and
    /// returns a leaked copy of the received bytes.
    struct EchoingStrictPush;

    impl Push for EchoingStrictPush {
        async fn register(&self) -> Result<PushToken, PlatformError> {
            Ok(PushToken::new(b"token".to_vec()))
        }

        async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal, PlatformError> {
            if payload.trim_ascii_end() == PERMITTED_PAYLOADS[0] {
                Ok(WakeSignal::new(payload.to_vec().leak()))
            } else {
                Err(invalid())
            }
        }
    }

    #[test]
    fn each_permitted_payload_passes_only_its_platform_rule() {
        assert!(apns_receipt_accepts(APNS_WAKE_BODY));
        assert!(!fcm_receipt_accepts(APNS_WAKE_BODY));
        assert!(fcm_receipt_accepts(FCM_WAKE_DATA));
        assert!(!apns_receipt_accepts(FCM_WAKE_DATA));
    }

    #[test]
    fn apns_rule_rejects_retired_payload() {
        assert!(!apns_receipt_accepts(RETIRED_PAYLOAD));
        assert!(!fcm_receipt_accepts(RETIRED_PAYLOAD));
    }

    #[test]
    fn apns_rule_rejects_extra_alert_key() {
        assert!(!apns_receipt_accepts(ALERT_PAYLOAD));
        assert!(!apns_receipt_accepts(
            br#"{"aps":{"content-available":1},"alert":"hi"}"#
        ));
    }

    #[test]
    fn apns_rule_rejects_non_integer_wake_value() {
        for payload in [
            br#"{"aps":{"content-available":"1"}}"#.as_slice(),
            br#"{"aps":{"content-available":1.0}}"#,
            br#"{"aps":{"content-available":2}}"#,
            br#"{"aps":1}"#,
        ] {
            assert!(!apns_receipt_accepts(payload));
        }
    }

    #[test]
    fn apns_rule_reads_the_parsed_dictionary() {
        assert!(apns_receipt_accepts(
            br#" { "aps" : { "content-available" : 1 } } "#
        ));
    }

    #[test]
    fn fcm_rule_requires_the_string_one() {
        assert!(fcm_receipt_accepts(PROBE_PAYLOADS[0]));
        for payload in [
            br#"{"scp":"2"}"#.as_slice(),
            br#"{"data":{"scp":"1"}}"#,
            b"{}",
            b"scp=1",
        ] {
            assert!(!fcm_receipt_accepts(payload));
        }
    }

    #[tokio::test]
    #[should_panic(expected = "no §10.7.1 receipt rule accepts")]
    async fn rejects_adapter_accepting_retired_payload() {
        check_fixed_wake_signal(&ParsedPush(&[APNS_WAKE_BODY, RETIRED_PAYLOAD])).await;
    }

    #[tokio::test]
    #[should_panic(expected = "no §10.7.1 receipt rule accepts")]
    async fn rejects_adapter_accepting_alert_key() {
        check_fixed_wake_signal(&ParsedPush(&[
            APNS_WAKE_BODY,
            br#"{"aps":{"alert":"ctx-42","content-available":1}}"#,
        ]))
        .await;
    }

    #[tokio::test]
    #[should_panic(expected = "no §10.7.1 receipt rule accepts")]
    async fn rejects_adapter_accepting_every_payload() {
        check_fixed_wake_signal(&DerivingPush(|_| b"wake".to_vec())).await;
    }

    #[tokio::test]
    async fn accepts_fcm_adapter_reading_only_scp() {
        // The FCM receipt rule reads no key but `scp`, so an adapter applying
        // it accepts the probe that carries a context ID beside `scp`.
        struct FcmRulePush;
        impl Push for FcmRulePush {
            async fn register(&self) -> Result<PushToken, PlatformError> {
                Ok(PushToken::new(b"token".to_vec()))
            }
            async fn handle_notification(
                &self,
                payload: &[u8],
            ) -> Result<WakeSignal, PlatformError> {
                if fcm_receipt_accepts(payload) {
                    Ok(WakeSignal::new(b"wake"))
                } else {
                    Err(invalid())
                }
            }
        }
        check_fixed_wake_signal(&FcmRulePush).await;
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
        // An APNs and an FCM adapter each reject every payload but their own,
        // and each passes.
        for payload in PERMITTED_PAYLOADS {
            check_fixed_wake_signal(&StrictPush(payload)).await;
        }
    }

    #[tokio::test]
    #[should_panic(expected = "rejected every permitted payload")]
    async fn rejects_adapter_accepting_only_metadata_payload() {
        check_fixed_wake_signal(&StrictPush(PROBE_PAYLOADS[4])).await;
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
        // payload names no context. The first probe passes the FCM rule and
        // names a context, so the signal varies before any rejected probe.
        check_fixed_wake_signal(&DerivingPush(|p| {
            p.windows(4)
                .rposition(|w| w == b"ctx-")
                .map_or_else(|| b"wake".to_vec(), |i| p[i..].to_vec())
        }))
        .await;
    }

    #[tokio::test]
    #[should_panic(expected = "wake signal varies with the notification payload")]
    async fn rejects_constant_chosen_by_payload_content() {
        // Two `'static` constants and no leak: the type accepts this adapter,
        // and only the conformance check rejects it.
        struct SelectingPush;
        impl Push for SelectingPush {
            async fn register(&self) -> Result<PushToken, PlatformError> {
                Ok(PushToken::new(b"token".to_vec()))
            }
            async fn handle_notification(
                &self,
                payload: &[u8],
            ) -> Result<WakeSignal, PlatformError> {
                if payload.windows(4).any(|w| w == b"ctx-") {
                    Ok(WakeSignal::new(b"wake-ctx"))
                } else {
                    Ok(WakeSignal::new(b"wake"))
                }
            }
        }
        check_fixed_wake_signal(&SelectingPush).await;
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
            async fn register(&self) -> Result<PushToken, PlatformError> {
                Ok(PushToken::new(b"token".to_vec()))
            }
            async fn handle_notification(
                &self,
                _payload: &[u8],
            ) -> Result<WakeSignal, PlatformError> {
                Err(invalid())
            }
        }
        check_fixed_wake_signal(&RefusingPush).await;
    }
}
