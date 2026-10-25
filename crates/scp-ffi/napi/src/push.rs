//! Push exports for TypeScript: `pushEnable`, `pushDisable` and
//! `pushHandleWake` (story PUSH-015).
//!
//! A TypeScript host has no `PushProvider` callback, so it passes the
//! platform and the token to `pushEnable` and hands each delivered payload to
//! `pushHandleWake`. The platform is the [`NapiPushPlatform`] string enum.
//!
//! `pushHandleWake(payload)` starts with
//! [`scp_ffi_common::push::begin_wake`]: a shut-down instance returns the
//! `failed` outcome `SCP-TRANS-5085`, and an instance with no enabled
//! platform returns `SCP-TRANS-5105`. It then runs
//! [`scp_ffi_common::push::handle_wake`] for the enabled platform, which
//! checks `payload` against that platform's wake signal (`SCP-TRANS-5080`
//! before any connection) and runs the ADR-029 §2 push-wake pull.
//!
//! `pushEnable` and `pushDisable` check their arguments, then the instance
//! (`SCP-CTX-2138` when it is shut down, `SCP-IDENT-1002` when it holds no
//! local member DID), then return `SCP-TRANS-5104`: the registrar signs with
//! the device's P-256 `#active` key, and no production constructor builds it
//! until story PUSH-036. Story PUSH-037 makes them register and deregister,
//! resolve to each relay's result as [`NapiPushRelayOutcomes`], and record
//! the platform in the instance's slot. Until then the slot stays empty in a
//! shipped build, so `pushHandleWake` returns `SCP-TRANS-5105`.

use napi_derive::napi;
use scp_core::discovery::PushPlatform;
use scp_ffi_common::push::{
    self as shared, PushInputError, PushRegistrationError, WakeContextFailureView, WakeEntry,
    WakeError, WakeFailureView, WakeOutcomeKind, WakeOutcomeView,
};

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

/// The push service a device registers with, and whose wake signal
/// `pushHandleWake` checks.
#[napi(string_enum = "snake_case", js_name = "PushPlatform")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiPushPlatform {
    /// Apple Push Notification service: `apns`.
    Apns,
    /// Firebase Cloud Messaging: `fcm`.
    Fcm,
    /// Web Push (RFC 8030): `web_push`.
    WebPush,
}

impl From<NapiPushPlatform> for PushPlatform {
    fn from(platform: NapiPushPlatform) -> Self {
        match platform {
            NapiPushPlatform::Apns => Self::Apns,
            NapiPushPlatform::Fcm => Self::Fcm,
            NapiPushPlatform::WebPush => Self::WebPush,
        }
    }
}

/// Which outcome a wake reported (ADR-029 §2 push-wake pull mode step 7).
#[napi(string_enum = "snake_case", js_name = "WakeOutcomeKind")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiWakeOutcomeKind {
    /// The pull stored new events: `new_data`.
    NewData,
    /// The pull completed and stored nothing: `no_data`.
    NoData,
    /// The wake failed: `failed`; `failure` says why.
    Failed,
}

impl From<WakeOutcomeKind> for NapiWakeOutcomeKind {
    fn from(kind: WakeOutcomeKind) -> Self {
        match kind {
            WakeOutcomeKind::NewData => Self::NewData,
            WakeOutcomeKind::NoData => Self::NoData,
            WakeOutcomeKind::Failed => Self::Failed,
        }
    }
}

/// One context's failed pull in a [`NapiWakeFailure`].
#[napi(object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapiWakeContextFailure {
    /// The context that failed.
    pub context_id: String,
    /// The failure's stable code.
    pub code: String,
    /// The failure's description.
    pub message: String,
}

/// Why a wake returned `failed`.
#[napi(object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapiWakeFailure {
    /// The failure's stable code, `SCP-TRANS-5085` to `SCP-TRANS-5094`.
    pub code: String,
    /// The failure's description.
    pub message: String,
    /// The contexts the failure names, sorted; empty for a failure of the
    /// whole wake.
    pub context_ids: Vec<String>,
    /// Each failed context's pull with its own code; empty unless the
    /// failure is a context pull failure.
    pub context_failures: Vec<NapiWakeContextFailure>,
}

/// What a wake reports (ADR-029 §2 push-wake pull mode step 7).
#[napi(object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapiWakeOutcome {
    /// Which outcome the wake reported.
    pub outcome: NapiWakeOutcomeKind,
    /// The failure when `outcome` is `failed`; absent otherwise.
    pub failure: Option<NapiWakeFailure>,
}

/// Each relay's result of a `pushEnable` or `pushDisable`, mirroring the
/// registrar's `RelayOutcomes`: deregistrations first, then registrations
/// (`10-infrastructure-and-self-hosting.md` §10.7.1).
#[napi(object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapiPushRelayOutcomes {
    /// Each `PushDeregistration`, one entry per relay.
    pub deregistered: Vec<NapiPushRelayResult>,
    /// Each `PushRegistration`, one entry per relay.
    pub registered: Vec<NapiPushRelayResult>,
}

/// One relay's result in a [`NapiPushRelayOutcomes`].
#[napi(object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapiPushRelayResult {
    /// The relay's canonical URL (`09-security-model.md` §9.5.2).
    pub relay_url: String,
    /// Why the relay refused; absent when it accepted.
    pub failure: Option<NapiPushRelayFailure>,
}

/// Why one relay refused a push registration or deregistration.
#[napi(object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapiPushRelayFailure {
    /// The failure's stable code.
    pub code: String,
    /// The failure's description.
    pub message: String,
}

impl From<WakeContextFailureView> for NapiWakeContextFailure {
    fn from(view: WakeContextFailureView) -> Self {
        Self {
            context_id: view.context_id,
            code: view.code.to_owned(),
            message: view.message,
        }
    }
}

impl From<WakeFailureView> for NapiWakeFailure {
    fn from(view: WakeFailureView) -> Self {
        Self {
            code: view.code.to_owned(),
            message: view.message,
            context_ids: view.context_ids,
            context_failures: view.context_failures.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<WakeOutcomeView> for NapiWakeOutcome {
    fn from(view: WakeOutcomeView) -> Self {
        Self {
            outcome: view.kind.into(),
            failure: view.failure.map(Into::into),
        }
    }
}

fn input_error(e: PushInputError) -> napi::Error {
    napi::Error::from(ScpNapiError::Validation {
        message: e.to_string(),
        code: e.code().to_owned(),
    })
}

fn registration_error(e: PushRegistrationError) -> napi::Error {
    let (message, code) = (e.to_string(), e.code().to_owned());
    napi::Error::from(match e {
        PushRegistrationError::ShutDown => ScpNapiError::Context { message, code },
        PushRegistrationError::NoLocalIdentity => ScpNapiError::Identity { message, code },
        PushRegistrationError::SigningKeyUnavailable => ScpNapiError::Transport { message, code },
    })
}

fn wake_error(e: WakeError) -> napi::Error {
    napi::Error::from(ScpNapiError::Transport {
        message: e.to_string(),
        code: e.code().to_owned(),
    })
}

/// `pushEnable` on `bi`: checks `token` and the instance, then refuses. Story
/// PUSH-037 registers `token` for `platform` and records `platform` in the
/// instance's slot.
///
/// # Errors
///
/// `SCP-VALID-7004` for an empty token, `SCP-CTX-2138` for a shut-down
/// instance, `SCP-IDENT-1002` for one with no local member DID, and
/// otherwise `SCP-TRANS-5104`.
pub async fn push_enable_on(
    bi: &NapiBridgeInstance,
    _platform: NapiPushPlatform,
    token: &[u8],
) -> napi::Result<NapiPushRelayOutcomes> {
    shared::check_push_token(token).map_err(input_error)?;
    match shared::push_registration(&bi.core)
        .await
        .map_err(registration_error)? {}
}

/// `pushDisable` on `bi`: checks the instance, then refuses.
///
/// # Errors
///
/// `SCP-CTX-2138` for a shut-down instance, `SCP-IDENT-1002` for one with no
/// local member DID, and otherwise `SCP-TRANS-5104`.
pub async fn push_disable_on(bi: &NapiBridgeInstance) -> napi::Result<NapiPushRelayOutcomes> {
    match shared::push_registration(&bi.core)
        .await
        .map_err(registration_error)? {}
}

/// `pushHandleWake` on `bi`: runs the shared wake for the enabled platform.
///
/// A shut-down instance returns the `failed` outcome `SCP-TRANS-5085`.
///
/// # Errors
///
/// `SCP-TRANS-5105` when no platform is enabled, `SCP-TRANS-5080` for a
/// payload that is not the enabled platform's wake signal. Every later
/// failure is a `failed` outcome.
pub async fn push_handle_wake_on(
    bi: &NapiBridgeInstance,
    payload: &[u8],
) -> napi::Result<NapiWakeOutcome> {
    let platform = match shared::begin_wake(&bi.core, &bi.push).map_err(wake_error)? {
        WakeEntry::Enabled(platform) => platform,
        WakeEntry::Finished(outcome) => return Ok(outcome.view().into()),
    };
    let outcome = scp_ffi_common::push::handle_wake(&bi.core, platform, payload)
        .await
        .map_err(wake_error)?;
    Ok(outcome.view().into())
}

/// Records `platform` as enabled on `bi`, the slot story PUSH-037's
/// `pushEnable` fills, so tests reach the wake path.
#[cfg(any(test, feature = "testing"))]
pub fn install_push_platform_for_testing(bi: &NapiBridgeInstance, platform: NapiPushPlatform) {
    bi.push.set(platform.into());
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
    use scp_ffi_common::error_codes as codes;
    use std::sync::Arc;
    use std::time::Duration;

    fn has_code(e: &napi::Error, code: &str) {
        let text = e.to_string();
        assert!(text.contains(code), "expected {code}, got {text}");
    }

    /// An instance whose supervisor holds a local member DID.
    fn ready_bi() -> NapiBridgeInstance {
        let bi = NapiBridgeInstance::new_napi();
        crate::runtime::init_supervisor(&bi, "did:test:push-napi");
        assert!(bi.core.has_supervisor(), "the test supervisor attaches");
        bi
    }

    #[tokio::test]
    async fn enable_and_disable_return_5104_and_record_nothing() {
        let bi = ready_bi();
        has_code(
            &push_enable_on(&bi, NapiPushPlatform::Apns, b"token")
                .await
                .unwrap_err(),
            codes::TRANS_5104,
        );
        has_code(&push_disable_on(&bi).await.unwrap_err(), codes::TRANS_5104);
        assert!(
            bi.push.get().is_none(),
            "a refused enable records no platform"
        );
    }

    #[tokio::test]
    async fn enable_and_disable_without_a_local_identity_return_1002() {
        let bi = NapiBridgeInstance::new_napi();
        has_code(
            &push_enable_on(&bi, NapiPushPlatform::Apns, b"token")
                .await
                .unwrap_err(),
            codes::IDENT_1002,
        );
        has_code(&push_disable_on(&bi).await.unwrap_err(), codes::IDENT_1002);
    }

    /// The token is checked before the instance, so an empty token answers
    /// `SCP-VALID-7004` even on an instance with no local identity.
    #[tokio::test]
    async fn an_empty_token_returns_7004() {
        for bi in [ready_bi(), NapiBridgeInstance::new_napi()] {
            has_code(
                &push_enable_on(&bi, NapiPushPlatform::Fcm, b"")
                    .await
                    .unwrap_err(),
                codes::VALID_7004,
            );
        }
    }

    #[tokio::test]
    async fn a_wake_with_no_enabled_platform_returns_5105() {
        has_code(
            &push_handle_wake_on(&ready_bi(), br#"{"scp":"1"}"#)
                .await
                .unwrap_err(),
            codes::TRANS_5105,
        );
    }

    /// The enabled platform decides which wake signal passes: an instance
    /// enabled for `fcm` refuses the APNs wake signal.
    #[tokio::test]
    async fn the_enabled_platform_decides_which_wake_signal_passes() {
        let bi = NapiBridgeInstance::new_napi();
        install_push_platform_for_testing(&bi, NapiPushPlatform::Fcm);
        has_code(
            &push_handle_wake_on(&bi, br#"{"aps":{"content-available":1}}"#)
                .await
                .unwrap_err(),
            codes::TRANS_5080,
        );
    }

    #[tokio::test]
    async fn a_valid_payload_reaches_handle_wake() {
        // No supervisor on this instance, so `handle_wake` itself answers
        // `failed` with `SCP-TRANS-5086`: the payload passed the check.
        let bi = NapiBridgeInstance::new_napi();
        install_push_platform_for_testing(&bi, NapiPushPlatform::Fcm);
        let outcome = push_handle_wake_on(&bi, br#"{"scp":"1"}"#).await.unwrap();
        assert_eq!(outcome.outcome, NapiWakeOutcomeKind::Failed);
        assert_eq!(outcome.failure.unwrap().code, codes::TRANS_5086);
    }

    /// Shutdown is read before the slot, so a shut-down instance answers the
    /// shutdown outcome, not `SCP-TRANS-5105`, though shutdown emptied the
    /// slot.
    #[tokio::test]
    async fn a_wake_after_shutdown_returns_the_shutdown_outcome() {
        let bi = Arc::new(NapiBridgeInstance::new_napi());
        install_push_platform_for_testing(&bi, NapiPushPlatform::Fcm);
        Arc::clone(&bi)
            .shutdown(Duration::from_secs(10))
            .await
            .unwrap();
        assert!(bi.push.get().is_none(), "shutdown empties the slot");
        let outcome = push_handle_wake_on(&bi, br#"{"scp":"1"}"#).await.unwrap();
        assert_eq!(outcome.outcome, NapiWakeOutcomeKind::Failed);
        assert_eq!(outcome.failure.unwrap().code, codes::TRANS_5085);
    }
}
