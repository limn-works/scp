//! Push exports for Swift and Kotlin: `push_enable`, `push_disable` and
//! `push_handle_wake` (story PUSH-015; ADR-025 criterion 4, ADR-027
//! criterion 10).
//!
//! `push_handle_wake(payload)` starts with
//! [`scp_ffi_common::push::begin_wake`]: a shut-down instance returns the
//! `Failed` outcome `SCP-TRANS-5085`, and an instance with no enabled
//! provider returns `SCP-TRANS-5105`. It then hands the payload to the
//! enabled provider's `handle_notification`, which applies the platform's
//! receipt rule and returns the wake signal bytes or throws. A thrown
//! [`ScpError`] returns to the caller unchanged and no relay connection
//! opens. The returned bytes go to [`scp_ffi_common::push::handle_wake`],
//! which checks them against the enabled platform's wake signal and runs the
//! ADR-029 §2 push-wake pull.
//!
//! `push_enable` and `push_disable` check the instance first
//! (`SCP-CTX-2138` when it is shut down, `SCP-IDENT-1002` when it holds no
//! local member DID), then return `SCP-TRANS-5104` before they touch the
//! provider: the registrar signs with the device's P-256 `#active` key,
//! and no production constructor builds it until story PUSH-036. Story
//! PUSH-037 makes them register and deregister, return each relay's result
//! as [`PushRelayOutcomes`], and fill the instance's provider slot. Until
//! then the slot stays empty in a shipped build, so `push_handle_wake`
//! returns `SCP-TRANS-5105`.

use std::sync::Arc;

use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::push::{
    PushRegistrationError, WakeContextFailureView, WakeEntry, WakeError, WakeFailureView,
    begin_wake, push_registration,
};

use crate::PushProvider;
use crate::bridge::ScpError;
use crate::scp::Scp;

/// The push service whose wake signal `push_handle_wake` checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PushPlatform {
    /// Apple Push Notification service.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
    /// The Web Push protocol (RFC 8030).
    WebPush,
}

impl From<PushPlatform> for scp_core::discovery::PushPlatform {
    fn from(platform: PushPlatform) -> Self {
        match platform {
            PushPlatform::Apns => Self::Apns,
            PushPlatform::Fcm => Self::Fcm,
            PushPlatform::WebPush => Self::WebPush,
        }
    }
}

/// What a wake reports to the platform (ADR-029 §2 push-wake pull mode step
/// 7). iOS maps the three values to `UIBackgroundFetchResult`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum WakeOutcome {
    /// The actor accepted at least one application envelope in some context.
    NewData,
    /// Every step and every context's pull succeeded, and the actor accepted
    /// no application envelope.
    NoData,
    /// The actor accepted no application envelope, and a step or a context's
    /// pull failed.
    Failed {
        /// Which step or contexts failed.
        failure: WakeFailureInfo,
    },
}

/// Why a wake returned [`WakeOutcome::Failed`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WakeFailureInfo {
    /// The failure's stable code, `SCP-TRANS-5085` to `SCP-TRANS-5094`.
    pub code: String,
    /// The failure's description.
    pub message: String,
    /// The contexts the failure names, sorted; empty for a failure of the
    /// whole wake.
    pub context_ids: Vec<String>,
    /// Each failed context's pull with its own code; empty unless the
    /// failure is a context pull failure.
    pub context_failures: Vec<WakeContextFailure>,
}

/// One context's failed pull in a [`WakeFailureInfo`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WakeContextFailure {
    /// The context that failed.
    pub context_id: String,
    /// The failure's stable code.
    pub code: String,
    /// The failure's description.
    pub message: String,
}

impl From<WakeContextFailureView> for WakeContextFailure {
    fn from(view: WakeContextFailureView) -> Self {
        Self {
            context_id: view.context_id,
            code: view.code.to_owned(),
            message: view.message,
        }
    }
}

impl From<WakeFailureView> for WakeFailureInfo {
    fn from(view: WakeFailureView) -> Self {
        Self {
            code: view.code.to_owned(),
            message: view.message,
            context_ids: view.context_ids,
            context_failures: view.context_failures.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<&scp_ffi_common::push::WakeOutcome> for WakeOutcome {
    fn from(outcome: &scp_ffi_common::push::WakeOutcome) -> Self {
        match outcome {
            scp_ffi_common::push::WakeOutcome::NewData => Self::NewData,
            scp_ffi_common::push::WakeOutcome::NoData => Self::NoData,
            scp_ffi_common::push::WakeOutcome::Failed(failure) => Self::Failed {
                failure: failure.view().into(),
            },
        }
    }
}

/// Each relay's result of a `push_enable` or `push_disable`, mirroring the
/// registrar's `RelayOutcomes`: deregistrations first, then registrations
/// (`10-infrastructure-and-self-hosting.md` §10.7.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushRelayOutcomes {
    /// Each `PushDeregistration`, one entry per relay.
    pub deregistered: Vec<PushRelayResult>,
    /// Each `PushRegistration`, one entry per relay.
    pub registered: Vec<PushRelayResult>,
}

/// One relay's result in a [`PushRelayOutcomes`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushRelayResult {
    /// The relay's canonical URL (`09-security-model.md` §9.5.2).
    pub relay_url: String,
    /// Why the relay refused; `None` when it accepted.
    pub failure: Option<PushRelayFailure>,
}

/// Why one relay refused a push registration or deregistration.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushRelayFailure {
    /// The failure's stable code.
    pub code: String,
    /// The failure's description.
    pub message: String,
}

/// The provider and platform `push_enable` enabled on one instance.
#[derive(Clone)]
pub(crate) struct EnabledPush {
    /// The host's push provider.
    pub(crate) provider: Arc<dyn PushProvider>,
    /// The platform whose wake signal the wake checks.
    pub(crate) platform: PushPlatform,
}

fn registration_error(e: PushRegistrationError) -> ScpError {
    let (msg, code) = (e.to_string(), e.code().to_owned());
    match e {
        PushRegistrationError::ShutDown => ScpError::Context { msg, code },
        PushRegistrationError::NoLocalIdentity => ScpError::Identity { msg, code },
        PushRegistrationError::SigningKeyUnavailable => ScpError::Transport { msg, code },
    }
}

fn wake_error(e: WakeError) -> ScpError {
    ScpError::Transport {
        msg: e.to_string(),
        code: e.code().to_owned(),
    }
}

/// The enable path: story PUSH-037 calls `provider.register_push()`, runs the
/// registrar for `platform` and fills the instance's slot. Until then the
/// registrar refuses before either argument is read.
async fn enable_push(
    core: &CoreFields,
    _provider: &dyn PushProvider,
    _platform: PushPlatform,
) -> Result<PushRelayOutcomes, ScpError> {
    match push_registration(core).await.map_err(registration_error)? {}
}

#[uniffi::export(async_runtime = "tokio")]
impl Scp {
    /// Enables push: registers the device's push token with every relay in
    /// the relay set and returns each relay's result (ADR-025 criterion 4,
    /// ADR-027 criterion 10).
    ///
    /// # Errors
    ///
    /// `SCP-CTX-2138` for a shut-down instance, `SCP-IDENT-1002` for one with
    /// no local member DID, and otherwise `SCP-TRANS-5104`: the device has no
    /// P-256 `#active` signing key to sign a `PushRegistration` with. Each is
    /// returned before `provider` is called or any relay is addressed.
    pub async fn push_enable(
        &self,
        provider: Box<dyn PushProvider>,
        platform: PushPlatform,
    ) -> Result<PushRelayOutcomes, ScpError> {
        enable_push(&self.inner.core, provider.as_ref(), platform).await
    }

    /// Disables push: deregisters the device's push token from every relay
    /// it registered with and returns each relay's result.
    ///
    /// # Errors
    ///
    /// `SCP-CTX-2138` for a shut-down instance, `SCP-IDENT-1002` for one with
    /// no local member DID, and otherwise `SCP-TRANS-5104`: the device has no
    /// P-256 `#active` signing key to sign a `PushDeregistration` with.
    pub async fn push_disable(&self) -> Result<PushRelayOutcomes, ScpError> {
        match push_registration(&self.inner.core)
            .await
            .map_err(registration_error)? {}
    }

    /// Handles a silent push. `payload` is what the platform delivered:
    /// the JSON serialization of the APNs `userInfo` dictionary or of the
    /// FCM data map.
    ///
    /// A shut-down instance returns [`WakeOutcome::Failed`] with
    /// `SCP-TRANS-5085` and calls no `handle_notification`.
    ///
    /// # Errors
    ///
    /// - `SCP-TRANS-5105` when push is not enabled on this instance;
    ///   `handle_notification` is not called.
    /// - The [`ScpError`] the provider's `handle_notification` throws,
    ///   unchanged; no relay connection opens.
    /// - `SCP-TRANS-5080` when the provider's bytes are not the enabled
    ///   platform's wake signal; no relay connection opens.
    ///
    /// Every failure after those checks is [`WakeOutcome::Failed`].
    pub async fn push_handle_wake(&self, payload: Vec<u8>) -> Result<WakeOutcome, ScpError> {
        let EnabledPush { provider, platform } =
            match begin_wake(&self.inner.core, &self.inner.push).map_err(wake_error)? {
                WakeEntry::Enabled(enabled) => enabled,
                WakeEntry::Finished(outcome) => return Ok((&outcome).into()),
            };
        let wake_bytes = provider.handle_notification(payload).await?;
        let outcome =
            scp_ffi_common::push::handle_wake(&self.inner.core, platform.into(), &wake_bytes)
                .await
                .map_err(wake_error)?;
        Ok(outcome.as_ref().into())
    }
}

/// Rust-only test affordance, not a `#[uniffi::export]` block, so Swift and
/// Kotlin never see it.
#[cfg(any(test, feature = "testing"))]
impl Scp {
    /// Enables `provider` for `platform` on this instance without
    /// registering, so a test can drive `push_handle_wake` before story
    /// PUSH-037 lets `push_enable` fill the slot.
    pub fn install_push_provider_for_testing(
        &self,
        provider: Arc<dyn PushProvider>,
        platform: PushPlatform,
    ) {
        self.inner.push.set(EnabledPush { provider, platform });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use scp_ffi_common::error_codes as codes;

    /// A host provider that counts its calls and answers `handle_notification`
    /// with fixed bytes or a fixed error.
    struct FakePushProvider {
        register_calls: AtomicUsize,
        notification_calls: AtomicUsize,
        answer: Result<Vec<u8>, ScpError>,
    }

    impl FakePushProvider {
        fn new(answer: Result<Vec<u8>, ScpError>) -> Arc<Self> {
            Arc::new(Self {
                register_calls: AtomicUsize::new(0),
                notification_calls: AtomicUsize::new(0),
                answer,
            })
        }
    }

    #[async_trait::async_trait]
    impl PushProvider for FakePushProvider {
        async fn register_push(&self) -> Result<Vec<u8>, ScpError> {
            self.register_calls.fetch_add(1, Ordering::SeqCst);
            Ok(b"token".to_vec())
        }

        async fn handle_notification(&self, _payload: Vec<u8>) -> Result<Vec<u8>, ScpError> {
            self.notification_calls.fetch_add(1, Ordering::SeqCst);
            self.answer.clone()
        }
    }

    /// Forwards to a shared fake, so a test keeps its counters after
    /// `push_enable` takes the box.
    struct Forward(Arc<FakePushProvider>);

    #[async_trait::async_trait]
    impl PushProvider for Forward {
        async fn register_push(&self) -> Result<Vec<u8>, ScpError> {
            self.0.register_push().await
        }

        async fn handle_notification(&self, payload: Vec<u8>) -> Result<Vec<u8>, ScpError> {
            self.0.handle_notification(payload).await
        }
    }

    /// The code of a register, deregister or wake refusal, each in the
    /// variant its code family names.
    fn code(e: &ScpError) -> String {
        match e {
            ScpError::Transport { code, .. } if code.starts_with("SCP-TRANS-") => code.clone(),
            ScpError::Context { code, .. } if code.starts_with("SCP-CTX-") => code.clone(),
            ScpError::Identity { code, .. } if code.starts_with("SCP-IDENT-") => code.clone(),
            other => panic!("expected a refusal in its own variant, got {other:?}"),
        }
    }

    /// An instance whose supervisor holds a local member DID.
    fn ready_scp() -> Arc<Scp> {
        let scp = Scp::new_in_memory_for_test();
        scp.inner
            .init_context_manager_with_local_transport("did:test:push-uniffi");
        scp
    }

    #[tokio::test]
    async fn push_enable_fails_closed_without_calling_register_push() {
        for (scp, expected) in [
            (Scp::new_in_memory_for_test(), codes::IDENT_1002),
            (ready_scp(), codes::TRANS_5104),
        ] {
            let fake = FakePushProvider::new(Ok(Vec::new()));
            let err = scp
                .push_enable(Box::new(Forward(Arc::clone(&fake))), PushPlatform::Apns)
                .await
                .unwrap_err();
            assert_eq!(code(&err), expected);
            assert_eq!(fake.register_calls.load(Ordering::SeqCst), 0);
            assert!(
                scp.inner.push.get().is_none(),
                "a failed enable leaves no provider"
            );
        }
    }

    #[tokio::test]
    async fn push_disable_fails_closed() {
        assert_eq!(
            code(
                &Scp::new_in_memory_for_test()
                    .push_disable()
                    .await
                    .unwrap_err()
            ),
            codes::IDENT_1002
        );
        assert_eq!(
            code(&ready_scp().push_disable().await.unwrap_err()),
            codes::TRANS_5104
        );
    }

    /// Shutdown is read before the provider slot, so a shut-down instance
    /// answers the shutdown outcome, not `SCP-TRANS-5105`, even though
    /// shutdown emptied the slot, and calls no `handle_notification`.
    #[tokio::test]
    async fn a_wake_after_shutdown_returns_the_shutdown_outcome() {
        let scp = Scp::new_in_memory_for_test();
        let fake = FakePushProvider::new(Ok(br#"{"aps":{"content-available":1}}"#.to_vec()));
        scp.install_push_provider_for_testing(Arc::clone(&fake) as _, PushPlatform::Apns);
        scp.shutdown(1_000).await.unwrap();
        assert!(
            scp.inner.push.get().is_none(),
            "shutdown drops the provider"
        );
        let outcome = scp.push_handle_wake(b"payload".to_vec()).await.unwrap();
        let WakeOutcome::Failed { failure } = outcome else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert_eq!(failure.code, codes::TRANS_5085);
        assert_eq!(fake.notification_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wake_without_an_enabled_provider_returns_5105() {
        let scp = Scp::new_in_memory_for_test();
        let err = scp
            .push_handle_wake(br#"{"aps":{"content-available":1}}"#.to_vec())
            .await
            .unwrap_err();
        assert_eq!(code(&err), codes::TRANS_5105);
    }

    #[tokio::test]
    async fn invalid_wake_bytes_return_5080_after_one_handle_notification() {
        let scp = Scp::new_in_memory_for_test();
        let fake = FakePushProvider::new(Ok(b"{}".to_vec()));
        scp.install_push_provider_for_testing(Arc::clone(&fake) as _, PushPlatform::Fcm);
        let err = scp.push_handle_wake(b"payload".to_vec()).await.unwrap_err();
        assert_eq!(code(&err), codes::TRANS_5080);
        assert_eq!(fake.notification_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake.register_calls.load(Ordering::SeqCst), 0);
    }

    /// The platform `push_enable` recorded is the one whose wake signal the
    /// provider's bytes are checked against: an instance enabled for `Fcm`
    /// refuses the APNs wake signal.
    #[tokio::test]
    async fn the_enabled_platform_decides_which_wake_signal_passes() {
        let scp = Scp::new_in_memory_for_test();
        let fake = FakePushProvider::new(Ok(br#"{"aps":{"content-available":1}}"#.to_vec()));
        scp.install_push_provider_for_testing(Arc::clone(&fake) as _, PushPlatform::Fcm);
        let err = scp.push_handle_wake(b"payload".to_vec()).await.unwrap_err();
        assert_eq!(code(&err), codes::TRANS_5080);
        assert_eq!(fake.notification_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_provider_error_returns_unchanged() {
        let scp = Scp::new_in_memory_for_test();
        let thrown = ScpError::Validation {
            msg: "not a wake".to_owned(),
            code: codes::VALID_7005.to_owned(),
        };
        let fake = FakePushProvider::new(Err(thrown.clone()));
        scp.install_push_provider_for_testing(Arc::clone(&fake) as _, PushPlatform::Apns);
        let err = scp.push_handle_wake(b"payload".to_vec()).await.unwrap_err();
        assert!(
            matches!(&err, ScpError::Validation { code, .. } if code == codes::VALID_7005),
            "the provider's error returns unchanged, got {err:?}"
        );
        assert_eq!(err.to_string(), thrown.to_string());
        assert_eq!(fake.notification_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn valid_wake_bytes_reach_handle_wake() {
        // No supervisor on this instance, so `handle_wake` itself answers
        // `Failed(NoSupervisor)`: the bytes passed the receipt check.
        let scp = Scp::new_in_memory_for_test();
        let fake = FakePushProvider::new(Ok(br#"{"aps":{"content-available":1}}"#.to_vec()));
        scp.install_push_provider_for_testing(Arc::clone(&fake) as _, PushPlatform::Apns);
        let outcome = scp.push_handle_wake(b"payload".to_vec()).await.unwrap();
        let WakeOutcome::Failed { failure } = outcome else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert_eq!(failure.code, codes::TRANS_5086);
        assert_eq!(fake.notification_calls.load(Ordering::SeqCst), 1);
    }
}
