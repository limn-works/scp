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
//! 1. the startup restore when no context is resident, and then a restore of
//!    each persisted Active context that is still not resident, with no saga
//!    replay ([`Supervisor::restore_unrestored_contexts`](scp_core::context::supervisor::Supervisor::restore_unrestored_contexts));
//! 2. one dial of the union of the Active contexts' persisted relay URLs on a
//!    transient transport with no cover traffic (`09-security-model.md`
//!    §9.10.6) and one connection per relay ([`DialBudget::DialSet`]), never
//!    installed on the instance and dropped on return;
//! 3. [`wake_pull_contexts`], which runs Phases 1, 2 and 4 for each context
//!    at that context's own relays, delivers in pull-only mode, and takes no
//!    [`CommandSigner`](scp_core::context::actor::CommandSigner), so the
//!    device signs, ratchets and publishes nothing and `needs_reconnect`
//!    stays set. A relay that failed to dial fails only the contexts that
//!    name it.
//!
//! The outcome is [`WakeOutcome::NewData`] when the actor accepted an
//! application envelope in any context, even one the deadline stopped;
//! otherwise [`WakeOutcome::Failed`] when any step or context failed;
//! otherwise [`WakeOutcome::NoData`]. Each [`WakeFailure`] has a stable code
//! ([`WakeFailure::code`]) and a flat view for the FFI ([`WakeFailureView`]).
//!
//! The FFI exports that call [`handle_wake`] are each bridge's
//! `push_handle_wake` (story PUSH-015). Each bridge's push register and
//! deregister exports return [`push_registration_unavailable`]
//! (`SCP-TRANS-5104`) until story PUSH-037 gives them the device's P-256
//! `#active` signing key. napi and Python name the platform with
//! [`parse_push_platform`].

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use scp_core::context::ContextError;
use scp_protocol::discovery::push::PushPlatform;
use scp_protocol::sync::SyncPolicy;
use scp_transport::native::adapter::CoverTraffic;
use serde_json::Value;

use crate::bridge_instance::{CoreFields, DialBudget, LifecycleError};
use crate::error_codes;
use crate::reconnect::{DeliveryTally, WakePull, WakePullError, wake_pull_contexts};

/// The one deadline over a wake's restore, dial, queries and deliveries
/// (ADR-029 §2 push-wake pull mode step 7). iOS gives a woken app about 30
/// seconds; 25 leaves the host time to report the outcome.
pub const WAKE_DEADLINE: Duration = Duration::from_secs(25);

/// What a wake reports to the platform (ADR-029 §2 push-wake pull mode step
/// 7). iOS maps the three values to `UIBackgroundFetchResult`.
#[derive(Debug)]
pub enum WakeOutcome {
    /// The actor accepted at least one application envelope in some context.
    NewData,
    /// Every step and every context's pull succeeded, and the actor accepted
    /// no application envelope.
    NoData,
    /// The actor accepted no application envelope, and a step or a context's
    /// pull failed; the reason says which.
    Failed(WakeFailure),
}

impl WakeOutcome {
    /// The flat view an FFI bridge returns for this outcome.
    #[must_use]
    pub fn view(&self) -> WakeOutcomeView {
        match self {
            Self::NewData => WakeOutcomeView {
                outcome: WAKE_OUTCOME_NEW_DATA,
                failure: None,
            },
            Self::NoData => WakeOutcomeView {
                outcome: WAKE_OUTCOME_NO_DATA,
                failure: None,
            },
            Self::Failed(failure) => WakeOutcomeView {
                outcome: WAKE_OUTCOME_FAILED,
                failure: Some(failure.view()),
            },
        }
    }
}

/// [`WakeOutcomeView::outcome`] of [`WakeOutcome::NewData`].
pub const WAKE_OUTCOME_NEW_DATA: &str = "new_data";
/// [`WakeOutcomeView::outcome`] of [`WakeOutcome::NoData`].
pub const WAKE_OUTCOME_NO_DATA: &str = "no_data";
/// [`WakeOutcomeView::outcome`] of [`WakeOutcome::Failed`].
pub const WAKE_OUTCOME_FAILED: &str = "failed";

/// A [`WakeOutcome`] flattened for the napi and Python bridges, which carry
/// no Rust enum with payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeOutcomeView {
    /// `new_data`, `no_data` or `failed`.
    pub outcome: &'static str,
    /// The failure for `failed`; `None` for the other two outcomes.
    pub failure: Option<WakeFailureView>,
}

/// Why a wake returned [`WakeOutcome::Failed`]. Each variant is one cause
/// ADR-029 §2 push-wake pull mode step 7 lists.
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
    /// A suspend or shutdown cancelled the relay dial.
    #[error("relay dial cancelled: {0}")]
    DialCancelled(#[source] LifecycleError),
    /// One or more contexts' pulls failed; each entry names its context.
    #[error("{} context pull(s) failed: {}", .0.len(), join_failures(.0))]
    Pull(Vec<WakePullError>),
    /// [`WAKE_DEADLINE`] expired before the pull completed.
    #[error("the wake deadline of {} seconds expired", WAKE_DEADLINE.as_secs())]
    DeadlineExpired,
}

/// The `Display` of each failure, joined by `"; "`.
fn join_failures(failures: &[WakePullError]) -> String {
    failures
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

impl WakeFailure {
    /// The bridge error code of this failure: one `SCP-TRANS` code per
    /// variant, `SCP-TRANS-5085` to `SCP-TRANS-5094` (`sdk-common.md`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ShutDown => error_codes::TRANS_5085,
            Self::NoSupervisor => error_codes::TRANS_5086,
            Self::NoLocalIdentity => error_codes::TRANS_5087,
            Self::Restore(_) => error_codes::TRANS_5089,
            Self::Unrestored { .. } => error_codes::TRANS_5090,
            Self::Targets(_) => error_codes::TRANS_5091,
            Self::DialCancelled(_) => error_codes::TRANS_5092,
            Self::Pull(_) => error_codes::TRANS_5093,
            Self::DeadlineExpired => error_codes::TRANS_5094,
        }
    }

    /// The flat view an FFI bridge returns for this failure.
    #[must_use]
    pub fn view(&self) -> WakeFailureView {
        let (named, mut context_failures): (Vec<&str>, Vec<WakeContextFailureView>) = match self {
            Self::Unrestored { context_ids } => {
                (context_ids.iter().map(String::as_str).collect(), Vec::new())
            }
            Self::Pull(failures) => (
                failures.iter().map(WakePullError::context_id).collect(),
                failures
                    .iter()
                    .map(|f| WakeContextFailureView {
                        context_id: f.context_id().to_owned(),
                        code: f.code(),
                        message: f.to_string(),
                    })
                    .collect(),
            ),
            Self::ShutDown
            | Self::NoSupervisor
            | Self::NoLocalIdentity
            | Self::Restore(_)
            | Self::Targets(_)
            | Self::DialCancelled(_)
            | Self::DeadlineExpired => (Vec::new(), Vec::new()),
        };
        // Every arm goes through one sort and deduplication, so no arm can
        // hand a bridge its IDs in arrival order.
        let context_ids = named
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        context_failures
            .sort_by(|a, b| (a.context_id.as_str(), a.code).cmp(&(b.context_id.as_str(), b.code)));
        WakeFailureView {
            code: self.code(),
            message: self.to_string(),
            context_ids,
            context_failures,
        }
    }
}

/// A [`WakeFailure`] flattened for the FFI bridges, which carry no Rust enum
/// with payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeFailureView {
    /// The variant's stable code ([`WakeFailure::code`]).
    pub code: &'static str,
    /// The failure's `Display` text.
    pub message: String,
    /// The contexts the failure names, sorted and deduplicated; empty for a
    /// failure of the whole wake.
    pub context_ids: Vec<String>,
    /// For [`WakeFailure::Pull`], each failed context with its own code,
    /// sorted by context ID and then code; empty for every other variant.
    pub context_failures: Vec<WakeContextFailureView>,
}

/// One context's failure in a [`WakeFailureView`] (ADR-029 §2 push-wake pull
/// mode step 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeContextFailureView {
    /// The context that failed.
    pub context_id: String,
    /// The failure's stable code ([`WakePullError::code`]).
    pub code: &'static str,
    /// The failure's `Display` text.
    pub message: String,
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

/// Why a push register, deregister or provider-backed wake export refused
/// to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PushRegistrationError {
    /// The device has no P-256 `#active` signing key to sign a
    /// `PushRegistration` or `PushDeregistration` with (§10.7.1 step 3).
    #[error("push registration is unavailable: the device has no P-256 #active signing key")]
    SigningKeyUnavailable,
    /// The instance holds no enabled `PushProvider`, so a `UniFFI` wake has
    /// no provider to hand the payload to.
    #[error("push is not enabled on this instance")]
    NotEnabled,
}

impl PushRegistrationError {
    /// The bridge error code: `SCP-TRANS-5104` or `SCP-TRANS-5105`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SigningKeyUnavailable => error_codes::TRANS_5104,
            Self::NotEnabled => error_codes::TRANS_5105,
        }
    }
}

/// The error every push register and deregister export returns until the
/// device has a P-256 `#active` signing key to sign with.
#[must_use]
pub const fn push_registration_unavailable() -> PushRegistrationError {
    // Stub — see PUSH-037
    PushRegistrationError::SigningKeyUnavailable
}

/// A push argument a napi or Python caller passed that the export refuses
/// before any other step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PushInputError {
    /// The platform name is not `apns`, `fcm` or `web_push`. The message
    /// does not echo the caller's string.
    #[error("unknown push platform: expected `apns`, `fcm` or `web_push`")]
    UnknownPlatform,
    /// The push token is empty.
    #[error("the push token is empty")]
    EmptyToken,
}

impl PushInputError {
    /// The bridge error code: `SCP-VALID-7005` for an unknown platform name,
    /// `SCP-VALID-7004` for an empty token.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownPlatform => error_codes::VALID_7005,
            Self::EmptyToken => error_codes::VALID_7004,
        }
    }
}

/// The platform a napi or Python caller names: `apns`, `fcm` or `web_push`,
/// matched exactly.
///
/// # Errors
///
/// [`PushInputError::UnknownPlatform`] for any other string.
pub fn parse_push_platform(name: &str) -> Result<PushPlatform, PushInputError> {
    match name {
        "apns" => Ok(PushPlatform::Apns),
        "fcm" => Ok(PushPlatform::Fcm),
        "web_push" => Ok(PushPlatform::WebPush),
        _ => Err(PushInputError::UnknownPlatform),
    }
}

/// Refuses an empty push token.
///
/// # Errors
///
/// [`PushInputError::EmptyToken`] when `token` is empty.
pub const fn check_push_token(token: &[u8]) -> Result<(), PushInputError> {
    if token.is_empty() {
        Err(PushInputError::EmptyToken)
    } else {
        Ok(())
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
    // The tally lives outside the deadline, so the envelopes a context
    // delivered before the deadline dropped the pull still count.
    let tally = DeliveryTally::default();
    let result = tokio::time::timeout(WAKE_DEADLINE, pull_on_wake(core, &tally)).await;
    Ok(wake_outcome(tally.total(), result))
}

/// The ADR-029 §2 push-wake pull mode step 7 outcome rule over the count of
/// accepted application envelopes and the pull's result.
fn wake_outcome(
    delivered: u64,
    result: Result<Result<Vec<WakePullError>, WakeFailure>, tokio::time::error::Elapsed>,
) -> WakeOutcome {
    let failure = match result {
        Ok(Ok(failures)) if failures.is_empty() => None,
        Ok(Ok(failures)) => Some(WakeFailure::Pull(failures)),
        Ok(Err(failure)) => Some(failure),
        Err(_elapsed) => Some(WakeFailure::DeadlineExpired),
    };
    match (delivered, failure) {
        (0, None) => WakeOutcome::NoData,
        (0, Some(failure)) => WakeOutcome::Failed(failure),
        (_, failure) => {
            if let Some(failure) = failure {
                tracing::warn!(
                    code = failure.code(),
                    error = %failure,
                    delivered,
                    "push wake delivered data and a step failed"
                );
            }
            WakeOutcome::NewData
        }
    }
}

/// The steps after the payload check. Returns the failure of each context
/// whose pull failed; every accepted application envelope is added to
/// `tally`.
async fn pull_on_wake(
    core: &CoreFields,
    tally: &DeliveryTally,
) -> Result<Vec<WakePullError>, WakeFailure> {
    // A suspended instance still pulls: the wake arrives while the app is
    // backgrounded, and the transient transport leaves the instance's own
    // transport untouched.
    if core.is_shutdown() {
        return Err(WakeFailure::ShutDown);
    }
    let supervisor = core.supervisor().ok_or(WakeFailure::NoSupervisor)?;
    if supervisor.node_identity().is_err() {
        return Err(WakeFailure::NoLocalIdentity);
    }
    let relay_contacts = supervisor.relay_contact_store();

    // A cold process runs the startup restore, context restore then saga
    // replay. A context still missing after it, or one whose restore failed in
    // an earlier pass of this process, is restored alone: a saga replay in a
    // live process would reconcile in-flight sagas as crashed.
    if !supervisor.has_known_contexts() {
        supervisor
            .restore_on_startup()
            .await
            .map_err(WakeFailure::Restore)?;
    }
    let context_ids = supervisor
        .restore_unrestored_contexts()
        .await
        .map_err(WakeFailure::Restore)?;
    // A context whose restore failed has no actor, so `wake_targets` cannot
    // name it; `NoData` would then report traffic the wake never pulled.
    if !context_ids.is_empty() {
        return Err(WakeFailure::Unrestored { context_ids });
    }
    let targets = supervisor
        .wake_targets()
        .await
        .map_err(WakeFailure::Targets)?;
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let urls: BTreeSet<String> = targets
        .iter()
        .flat_map(|t| t.relay_urls.iter().cloned())
        .collect();

    // Every failed URL fails only the contexts that name it, inside
    // `wake_pull_contexts`.
    let (manager, unreachable) = if urls.is_empty() {
        (
            scp_transport::TransportManager::with_connection_budget(1),
            BTreeMap::new(),
        )
    } else {
        let dialed = core
            .dial_relays(
                urls.into_iter().collect(),
                CoverTraffic::Off,
                DialBudget::DialSet,
            )
            .await
            .map_err(WakeFailure::DialCancelled)?;
        (dialed.manager, dialed.failed)
    };
    let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
    Ok(wake_pull_contexts(
        &WakePull {
            transport: &manager,
            supervisor,
            unreachable: &unreachable,
            relay_contacts: relay_contacts.as_ref(),
            policy: &SyncPolicy::default(),
            now,
            tally,
        },
        &targets,
    )
    .await)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_core::store::sync::RelayContactStore;

    fn invalid(platform: PushPlatform, payload: &[u8]) {
        assert_eq!(
            check_wake_payload(platform, payload),
            Err(WakeError::WakePayloadInvalid { platform }),
            "{platform:?} must reject {}",
            String::from_utf8_lossy(payload)
        );
    }

    #[test]
    fn parse_push_platform_accepts_exactly_the_three_names() {
        assert_eq!(parse_push_platform("apns"), Ok(PushPlatform::Apns));
        assert_eq!(parse_push_platform("fcm"), Ok(PushPlatform::Fcm));
        assert_eq!(parse_push_platform("web_push"), Ok(PushPlatform::WebPush));
        for name in [
            "", "APNS", "Apns", "webpush", "web-push", "WebPush", " fcm", "gcm",
        ] {
            let err = parse_push_platform(name).unwrap_err();
            assert_eq!(err, PushInputError::UnknownPlatform, "{name:?}");
            assert_eq!(err.code(), error_codes::VALID_7005);
        }
    }

    #[test]
    fn check_push_token_refuses_only_an_empty_token() {
        assert_eq!(check_push_token(b"t"), Ok(()));
        let err = check_push_token(b"").unwrap_err();
        assert_eq!(err, PushInputError::EmptyToken);
        assert_eq!(err.code(), error_codes::VALID_7004);
    }

    #[test]
    fn push_registration_errors_carry_their_own_codes() {
        assert_eq!(
            push_registration_unavailable(),
            PushRegistrationError::SigningKeyUnavailable
        );
        assert_eq!(
            PushRegistrationError::SigningKeyUnavailable.code(),
            error_codes::TRANS_5104
        );
        assert_eq!(
            PushRegistrationError::NotEnabled.code(),
            error_codes::TRANS_5105
        );
    }

    #[test]
    fn wake_outcome_view_names_each_outcome() {
        assert_eq!(
            WakeOutcome::NewData.view(),
            WakeOutcomeView {
                outcome: "new_data",
                failure: None
            }
        );
        assert_eq!(
            WakeOutcome::NoData.view(),
            WakeOutcomeView {
                outcome: "no_data",
                failure: None
            }
        );
        let failed = WakeOutcome::Failed(WakeFailure::NoSupervisor).view();
        assert_eq!(failed.outcome, "failed");
        let failure = failed.failure.unwrap();
        assert_eq!(failure.code, error_codes::TRANS_5086);
        assert_eq!(failure, WakeFailure::NoSupervisor.view());
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
        crate::bridge_instance::tests::shut_down(&core).await;
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

    /// Every `WakeFailure` variant has its own code, and each code is one the
    /// error-code registry defines.
    #[test]
    fn every_wake_failure_has_a_distinct_code_and_a_flat_view() {
        let failures = [
            WakeFailure::ShutDown,
            WakeFailure::NoSupervisor,
            WakeFailure::NoLocalIdentity,
            WakeFailure::Restore(ContextError::PersistenceFailed("x".to_owned())),
            WakeFailure::Unrestored {
                context_ids: vec!["b".to_owned(), "a".to_owned()],
            },
            WakeFailure::Targets(ContextError::PersistenceFailed("x".to_owned())),
            WakeFailure::DialCancelled(LifecycleError::AlreadyShutDown),
            WakeFailure::Pull(vec![
                WakePullError::NoRelays {
                    context_id: "c2".to_owned(),
                },
                WakePullError::RelayUnavailable {
                    context_id: "c1".to_owned(),
                    relay_url: "wss://r".to_owned(),
                    reason: "refused".to_owned(),
                },
                WakePullError::NoRelays {
                    context_id: "c2".to_owned(),
                },
            ]),
            WakeFailure::DeadlineExpired,
        ];
        let codes: BTreeSet<String> = failures.iter().map(|f| f.code().to_owned()).collect();
        assert_eq!(codes.len(), failures.len(), "each variant has its own code");
        let expected: BTreeSet<String> = (5085..=5094)
            .filter(|n| *n != 5088)
            .map(|n| format!("SCP-TRANS-{n}"))
            .collect();
        assert_eq!(codes, expected);
        let unrestored = failures[4].view();
        assert_eq!(unrestored.context_ids, vec!["a".to_owned(), "b".to_owned()]);
        assert!(unrestored.context_failures.is_empty());
        let pull = failures[7].view();
        assert_eq!(pull.code, error_codes::TRANS_5093);
        assert_eq!(pull.context_ids, vec!["c1".to_owned(), "c2".to_owned()]);
        assert!(pull.message.contains("wss://r"), "{}", pull.message);
        let per_context: Vec<(&str, &str)> = pull
            .context_failures
            .iter()
            .map(|f| (f.context_id.as_str(), f.code))
            .collect();
        assert_eq!(
            per_context,
            vec![
                ("c1", error_codes::TRANS_5097),
                ("c2", error_codes::TRANS_5096),
                ("c2", error_codes::TRANS_5096),
            ],
            "one entry per failure, sorted by context"
        );
        assert!(pull.context_failures[0].message.contains("wss://r"));
        assert!(failures[0].view().context_ids.is_empty());
    }

    /// Each per-context failure carries its own registered code.
    #[test]
    fn every_wake_pull_error_has_its_own_code() {
        let err = || ContextError::ActorCrashed("x".to_owned());
        let errors = [
            WakePullError::NoRelays {
                context_id: "a".to_owned(),
            },
            WakePullError::RelayUnavailable {
                context_id: "a".to_owned(),
                relay_url: "wss://r".to_owned(),
                reason: "x".to_owned(),
            },
            WakePullError::ContactRead {
                context_id: "a".to_owned(),
                source: scp_core::store::StoreError::SerializationFailed("x".to_owned()),
            },
            WakePullError::Query {
                context_id: "a".to_owned(),
                source: scp_protocol::sync::SyncError::RelayCatchUpFailed {
                    context_id: "a".to_owned(),
                    reason: "x".to_owned(),
                },
            },
            WakePullError::ContactWrite {
                context_id: "a".to_owned(),
                source: scp_core::store::StoreError::SerializationFailed("x".to_owned()),
            },
            WakePullError::Undelivered {
                context_id: "a".to_owned(),
                count: 1,
                source: err(),
            },
        ];
        let codes: BTreeSet<&str> = errors.iter().map(WakePullError::code).collect();
        let expected: BTreeSet<&str> = [
            error_codes::TRANS_5096,
            error_codes::TRANS_5097,
            error_codes::TRANS_5098,
            error_codes::TRANS_5099,
            error_codes::TRANS_5100,
            error_codes::TRANS_5101,
        ]
        .into_iter()
        .collect();
        assert_eq!(codes, expected);
    }

    /// The step 7 outcome rule: a delivery in any context gives `NewData`
    /// whatever failed; otherwise any failure gives `Failed`; otherwise
    /// `NoData`.
    #[tokio::test]
    async fn the_outcome_rule_puts_a_delivery_before_a_failure() {
        async fn elapsed() -> tokio::time::error::Elapsed {
            tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
                .await
                .unwrap_err()
        }
        let failed = || {
            vec![WakePullError::NoRelays {
                context_id: "b".to_owned(),
            }]
        };
        assert!(matches!(
            wake_outcome(0, Ok(Ok(Vec::new()))),
            WakeOutcome::NoData
        ));
        assert!(matches!(
            wake_outcome(2, Ok(Ok(Vec::new()))),
            WakeOutcome::NewData
        ));
        assert!(matches!(
            wake_outcome(1, Ok(Ok(failed()))),
            WakeOutcome::NewData
        ));
        assert!(matches!(
            wake_outcome(1, Err(elapsed().await)),
            WakeOutcome::NewData
        ));
        assert!(matches!(
            wake_outcome(0, Ok(Ok(failed()))),
            WakeOutcome::Failed(WakeFailure::Pull(ref f)) if f.len() == 1
        ));
        assert!(matches!(
            wake_outcome(0, Err(elapsed().await)),
            WakeOutcome::Failed(WakeFailure::DeadlineExpired)
        ));
        assert!(matches!(
            wake_outcome(0, Ok(Err(WakeFailure::NoSupervisor))),
            WakeOutcome::Failed(WakeFailure::NoSupervisor)
        ));
    }

    /// A supervisor with no crypto provider holds no local member DID, so the
    /// wake fails before it opens anything.
    #[tokio::test]
    async fn an_instance_without_a_local_identity_fails_the_wake() {
        let core = CoreFields::with_supervisor(std::sync::Arc::new(
            scp_core::context::supervisor::Supervisor::for_query_shim(),
        ));
        let outcome = handle_wake(&core, PushPlatform::Fcm, br#"{"scp":"1"}"#)
            .await
            .unwrap();
        assert!(
            matches!(outcome, WakeOutcome::Failed(WakeFailure::NoLocalIdentity)),
            "{outcome:?}"
        );
    }

    type Contacts = std::sync::Arc<
        scp_core::store::sync::StorageRelayContactStore<scp_platform::in_memory::InMemoryStorage>,
    >;

    fn contacts() -> Contacts {
        std::sync::Arc::new(scp_core::store::sync::StorageRelayContactStore::new(
            std::sync::Arc::new(scp_platform::in_memory::InMemoryStorage::new()),
        ))
    }

    /// A context with an empty relay set fails with `NoRelays`, a context
    /// naming an undialed relay fails with `RelayUnavailable`, neither is
    /// queried, and neither gets a contact.
    #[tokio::test]
    async fn a_context_with_no_relay_or_an_undialed_relay_fails_alone() {
        let supervisor = crate::bridge_instance::tests::test_supervisor();
        let manager = scp_transport::TransportManager::with_connection_budget(1);
        let store = contacts();
        let targets = vec![
            scp_core::context::ContextWakeTarget {
                context_id: "no-relay".to_owned(),
                relay_urls: Vec::new(),
                routing_ids: vec![[1; 32]],
            },
            scp_core::context::ContextWakeTarget {
                context_id: "dead-relay".to_owned(),
                relay_urls: vec!["wss://dead.example".to_owned()],
                routing_ids: vec![[2; 32]],
            },
        ];
        let unreachable = BTreeMap::from([(
            "wss://dead.example".to_owned(),
            "connection refused".to_owned(),
        )]);
        let tally = DeliveryTally::default();
        let failures = wake_pull_contexts(
            &WakePull {
                transport: &manager,
                supervisor: &supervisor,
                unreachable: &unreachable,
                relay_contacts: store.as_ref(),
                policy: &SyncPolicy::default(),
                now: 1_700_000_000,
                tally: &tally,
            },
            &targets,
        )
        .await;
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(
            matches!(&failures[0], WakePullError::NoRelays { context_id } if context_id == "no-relay"),
            "{failures:?}"
        );
        assert!(
            matches!(&failures[1], WakePullError::RelayUnavailable { context_id, relay_url, reason }
                if context_id == "dead-relay" && relay_url == "wss://dead.example" && reason == "connection refused"),
            "{failures:?}"
        );
        assert_eq!(tally.total(), 0);
        for id in ["no-relay", "dead-relay"] {
            assert_eq!(
                store.load_last_relay_contact(id).await.unwrap(),
                None,
                "{id}"
            );
        }
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
