//! Device wake handling: the push-wake pull mode of ADR-029 §2
//! (`.docs/adrs/phase-6.md`), which ADR-025 criterion 4 and ADR-027 criterion
//! 10 call on a silent push.
//!
//! [`handle_wake`] applies the device receipt rule of
//! `10-infrastructure-and-self-hosting.md` §10.7.1 for the push platform and
//! rejects a payload that fails it with [`WakeError::WakePayloadInvalid`]
//! (`SCP-TRANS-5080`) before any I/O. It then runs, under one
//! [`WAKE_DEADLINE`]:
//!
//! 1. a restore of every persisted context when none is resident;
//! 2. a dial of the union of the Active contexts' persisted relay URLs on a
//!    transient transport with no cover traffic (`09-security-model.md`
//!    §9.10.6), never installed on the instance and dropped on return;
//! 3. [`wake_pull_contexts`], which runs Phases 1, 2 and 4 with no
//!    [`CommandSigner`](scp_core::context::actor::CommandSigner), so the
//!    device signs and publishes nothing and `needs_reconnect` stays set.
//!
//! The FFI exports that call [`handle_wake`] belong to story PUSH-015.

use std::collections::BTreeSet;
use std::time::Duration;

use scp_core::context::ContextError;
use scp_protocol::discovery::push::PushPlatform;
use scp_protocol::sync::SyncPolicy;
use scp_transport::native::adapter::CoverTraffic;
use serde_json::Value;

use crate::bridge_instance::{CoreFields, LifecycleError};
use crate::error_codes;
use crate::reconnect::{WakePullError, wake_pull_contexts};

/// The one deadline over a wake's restore, dial, queries and deliveries
/// (ADR-029 §2 push-wake pull mode step 7). iOS gives a woken app about 30
/// seconds; 25 leaves the host time to report the outcome.
pub const WAKE_DEADLINE: Duration = Duration::from_secs(25);

/// What a wake reports to the platform (ADR-029 §2 push-wake pull mode step
/// 7). iOS maps the three values to `UIBackgroundFetchResult`.
#[derive(Debug)]
pub enum WakeOutcome {
    /// The actor accepted at least one application envelope.
    NewData,
    /// Every relay answered and the actor accepted no application envelope.
    NoData,
    /// The pull did not complete; the reason says which step failed.
    Failed(WakeFailure),
}

/// Why a wake returned [`WakeOutcome::Failed`].
#[derive(Debug, thiserror::Error)]
pub enum WakeFailure {
    /// The instance was shut down.
    #[error("the instance is shut down")]
    ShutDown,
    /// The instance holds no supervisor.
    #[error("the instance holds no supervisor")]
    NoSupervisor,
    /// The instance's crypto provider holds no local member DID.
    #[error("the instance holds no local member DID")]
    NoLocalIdentity,
    /// The instance holds no `last_relay_contact` store.
    #[error("the instance holds no relay contact store")]
    NoContactStore,
    /// Restoring or reading the persisted contexts failed.
    #[error("restoring persisted contexts failed: {0}")]
    Restore(#[source] ContextError),
    /// Persisted Active contexts are neither resident nor down with a crash
    /// record, because their restore failed; the pull cannot reach them.
    #[error("persisted Active contexts are not resident: {context_ids:?}")]
    Unrestored {
        /// The contexts whose restore failed.
        context_ids: Vec<String>,
    },
    /// Listing the Active contexts' relay URLs and routing IDs failed.
    #[error("listing the wake targets failed: {0}")]
    Targets(#[source] ContextError),
    /// Active contexts exist but none persists a relay URL.
    #[error("no Active context persists a relay URL")]
    NoRelays,
    /// A relay dial failed or was cancelled.
    #[error("relay dial failed: {0}")]
    Dial(#[source] LifecycleError),
    /// A Phase 1 query or a contact-store access failed.
    #[error(transparent)]
    Pull(WakePullError),
    /// [`WAKE_DEADLINE`] expired before the pull completed.
    #[error("the wake deadline of {} seconds expired", WAKE_DEADLINE.as_secs())]
    DeadlineExpired,
}

/// A wake the device must not act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WakeError {
    /// The payload fails the §10.7.1 device receipt rule of `platform`.
    #[error("{platform:?} payload is not the platform's wake signal")]
    WakePayloadInvalid {
        /// The platform whose rule rejected the payload.
        platform: PushPlatform,
    },
}

impl WakeError {
    /// The bridge error code: `SCP-TRANS-5080` (ADR-006 2026-10-12
    /// amendment).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::WakePayloadInvalid { .. } => error_codes::TRANS_5080,
        }
    }
}

/// Applies the §10.7.1 device receipt rule of `platform` to `payload`, the
/// JSON the host hands over:
/// - APNs: the payload dictionary, which must be exactly
///   `{"aps":{"content-available":1}}` with the integer 1;
/// - FCM: the message's data map, which must hold `scp` with the string value
///   `"1"`; no other key is read;
/// - `WebPush`: the push event's data, which must be exactly `{"scp":"1"}`.
///
/// # Errors
///
/// [`WakeError::WakePayloadInvalid`] for a payload that is not JSON or fails
/// the rule.
pub fn check_wake_payload(platform: PushPlatform, payload: &[u8]) -> Result<(), WakeError> {
    let accepted = serde_json::from_slice::<Value>(payload).is_ok_and(|value| match platform {
        PushPlatform::Apns => is_apns_wake(&value),
        PushPlatform::Fcm => is_fcm_wake(&value),
        PushPlatform::WebPush => is_webpush_wake(&value),
    });
    if accepted {
        Ok(())
    } else {
        Err(WakeError::WakePayloadInvalid { platform })
    }
}

/// Exactly one top-level key `aps`, whose object has exactly one key
/// `content-available` holding the integer 1 (not `true`, not `1.0`).
fn is_apns_wake(value: &Value) -> bool {
    let Some(top) = value.as_object() else {
        return false;
    };
    top.len() == 1
        && top
            .get("aps")
            .and_then(Value::as_object)
            .is_some_and(|aps| {
                aps.len() == 1
                    && aps
                        .get("content-available")
                        .is_some_and(|flag| flag.is_u64() && flag.as_u64() == Some(1))
            })
}

/// A data map holding `scp` = `"1"`; no other key is read.
fn is_fcm_wake(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|map| map.get("scp"))
        .and_then(Value::as_str)
        == Some("1")
}

/// Exactly one key `scp` holding the string `"1"`.
fn is_webpush_wake(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.len() == 1 && map.get("scp").and_then(Value::as_str) == Some("1"))
}

/// Handles a silent push (module doc).
///
/// # Errors
///
/// [`WakeError::WakePayloadInvalid`] when `payload` fails the receipt rule of
/// `platform`; no connection is opened. Every failure after the payload check
/// is [`WakeOutcome::Failed`].
pub async fn handle_wake(
    core: &CoreFields,
    platform: PushPlatform,
    payload: &[u8],
) -> Result<WakeOutcome, WakeError> {
    check_wake_payload(platform, payload)?;
    Ok(
        match tokio::time::timeout(WAKE_DEADLINE, pull_on_wake(core)).await {
            Ok(Ok(0)) => WakeOutcome::NoData,
            Ok(Ok(_)) => WakeOutcome::NewData,
            Ok(Err(failure)) => WakeOutcome::Failed(failure),
            Err(_elapsed) => WakeOutcome::Failed(WakeFailure::DeadlineExpired),
        },
    )
}

/// The steps after the payload check; returns the count of application
/// envelopes the actor accepted.
async fn pull_on_wake(core: &CoreFields) -> Result<u64, WakeFailure> {
    // A suspended instance still pulls: the wake arrives while the app is
    // backgrounded, and the transient transport leaves the instance's own
    // transport untouched.
    if core.is_shutdown() {
        return Err(WakeFailure::ShutDown);
    }
    let supervisor = core.supervisor().ok_or(WakeFailure::NoSupervisor)?;
    if supervisor.local_member_did().is_none() {
        return Err(WakeFailure::NoLocalIdentity);
    }
    let relay_contacts = core
        .relay_contact_store()
        .ok_or(WakeFailure::NoContactStore)?;

    if !supervisor.has_known_contexts() {
        supervisor
            .restore_on_startup()
            .await
            .map_err(WakeFailure::Restore)?;
    }
    // A context whose restore failed (here or at resume) has no actor, so
    // `wake_targets` cannot name it; `NoData` would then report traffic the
    // wake never pulled.
    let context_ids = supervisor
        .unrestored_active_contexts()
        .await
        .map_err(WakeFailure::Restore)?;
    if !context_ids.is_empty() {
        return Err(WakeFailure::Unrestored { context_ids });
    }
    let targets = supervisor
        .wake_targets()
        .await
        .map_err(WakeFailure::Targets)?;
    if targets.is_empty() {
        return Ok(0);
    }
    let urls: BTreeSet<String> = targets
        .iter()
        .flat_map(|t| t.relay_urls.iter().cloned())
        .collect();
    if urls.is_empty() {
        return Err(WakeFailure::NoRelays);
    }

    let dialed = core
        .dial_relays(urls.into_iter().collect(), CoverTraffic::Off)
        .await
        .map_err(WakeFailure::Dial)?;
    if let Some(failure) = dialed.first_failure {
        return Err(WakeFailure::Dial(failure));
    }
    let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
    wake_pull_contexts(
        &dialed.manager,
        supervisor,
        &targets,
        relay_contacts.as_ref(),
        &SyncPolicy::default(),
        now,
    )
    .await
    .map_err(WakeFailure::Pull)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn invalid(platform: PushPlatform, payload: &[u8]) {
        assert_eq!(
            check_wake_payload(platform, payload),
            Err(WakeError::WakePayloadInvalid { platform }),
            "{platform:?} must reject {}",
            String::from_utf8_lossy(payload)
        );
    }

    #[test]
    fn apns_accepts_only_the_integer_one_under_aps() {
        assert_eq!(
            check_wake_payload(PushPlatform::Apns, br#"{"aps":{"content-available":1}}"#),
            Ok(())
        );
        for payload in [
            br#"{"aps":{"content-available":true}}"#.as_slice(),
            br#"{"aps":{"content-available":1.0}}"#,
            br#"{"aps":{"content-available":"1"}}"#,
            br#"{"aps":{"content-available":2}}"#,
            br#"{"aps":{"content-available":1,"alert":"x"}}"#,
            br#"{"aps":{"content-available":1},"scp":"1"}"#,
            br#"{"aps":{}}"#,
            br#"{"scp":"1"}"#,
            b"",
            b"not json",
        ] {
            invalid(PushPlatform::Apns, payload);
        }
    }

    #[test]
    fn fcm_reads_only_the_scp_key() {
        assert_eq!(
            check_wake_payload(PushPlatform::Fcm, br#"{"scp":"1"}"#),
            Ok(())
        );
        assert_eq!(
            check_wake_payload(PushPlatform::Fcm, br#"{"scp":"1","other":"x"}"#),
            Ok(()),
            "FCM reads no key but scp"
        );
        for payload in [
            br#"{"scp":1}"#.as_slice(),
            br#"{"scp":"2"}"#,
            br#"{"other":"1"}"#,
            b"{}",
            br#"["scp","1"]"#,
            b"",
        ] {
            invalid(PushPlatform::Fcm, payload);
        }
    }

    #[test]
    fn webpush_accepts_exactly_scp_one() {
        assert_eq!(
            check_wake_payload(PushPlatform::WebPush, br#"{"scp":"1"}"#),
            Ok(())
        );
        for payload in [
            br#"{"scp":"1","other":"x"}"#.as_slice(),
            br#"{"scp":1}"#,
            br#"{"scp":true}"#,
            b"{}",
            b"",
        ] {
            invalid(PushPlatform::WebPush, payload);
        }
    }

    #[test]
    fn an_invalid_payload_carries_trans_5080() {
        let err = check_wake_payload(PushPlatform::Apns, b"{}").unwrap_err();
        assert_eq!(err.code(), "SCP-TRANS-5080");
    }

    /// The payload check runs before the lifecycle checks: a shut-down
    /// instance still answers an invalid payload with 5080.
    #[tokio::test]
    async fn the_payload_check_precedes_every_other_step() {
        let core = CoreFields::new();
        core.shutdown();
        let err = handle_wake(&core, PushPlatform::WebPush, b"{}")
            .await
            .unwrap_err();
        assert_eq!(err.code(), error_codes::TRANS_5080);
        let outcome = handle_wake(&core, PushPlatform::WebPush, br#"{"scp":"1"}"#)
            .await
            .unwrap();
        assert!(
            matches!(outcome, WakeOutcome::Failed(WakeFailure::ShutDown)),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn an_instance_without_a_supervisor_fails_the_wake() {
        let core = CoreFields::new();
        let outcome = handle_wake(&core, PushPlatform::Fcm, br#"{"scp":"1"}"#)
            .await
            .unwrap();
        assert!(
            matches!(outcome, WakeOutcome::Failed(WakeFailure::NoSupervisor)),
            "{outcome:?}"
        );
    }
}
