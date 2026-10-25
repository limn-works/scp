//! Push exports for Python: `push_enable`, `push_disable` and
//! `push_handle_wake` on `SCP` (story PUSH-015).
//!
//! A Python host has no `PushProvider` callback, so it passes the platform
//! and the token to `push_enable` and hands each delivered payload to
//! `push_handle_wake`. The platform is the [`PyPushPlatform`] enum.
//!
//! `push_handle_wake(payload)` starts with
//! [`scp_ffi_common::push::begin_wake`]: a shut-down instance returns the
//! `FAILED` outcome `SCP-TRANS-5085`, and an instance with no enabled
//! platform raises `SCP-TRANS-5105`. It then runs
//! [`scp_ffi_common::push::handle_wake`] for the enabled platform with the
//! GIL released, which checks `payload` against that platform's wake signal
//! (`SCP-TRANS-5080` before any connection) and runs the ADR-029 §2
//! push-wake pull.
//!
//! `push_enable` and `push_disable` check their arguments, then the
//! instance (`SCP-CTX-2138` when it is shut down, `SCP-IDENT-1002` when it
//! holds no local member DID), then raise `SCP-TRANS-5104`: the registrar
//! signs with the device's P-256 `#active` key, and no production
//! constructor builds it until story PUSH-036. Story PUSH-037 makes them
//! register and deregister with the GIL released, return each relay's result
//! as [`PyPushRelayOutcomes`], and record the platform in the instance's
//! slot. Until then the slot stays empty in a shipped build, so
//! `push_handle_wake` raises `SCP-TRANS-5105`.

use pyo3::prelude::*;
use scp_core::discovery::PushPlatform;
use scp_ffi_common::push::{
    self as shared, PushInputError, PushRegistrationError, WakeContextFailureView, WakeEntry,
    WakeError, WakeFailureView, WakeOutcomeKind, WakeOutcomeView,
};

use crate::error::ScpPyError;
use crate::runtime::PyBridgeInstance;
use crate::scp::PyScp;

/// The push service a device registers with, and whose wake signal
/// `push_handle_wake` checks.
#[pyclass(name = "PushPlatform", eq, eq_int, frozen)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyPushPlatform {
    /// Apple Push Notification service.
    #[pyo3(name = "APNS")]
    Apns,
    /// Firebase Cloud Messaging.
    #[pyo3(name = "FCM")]
    Fcm,
    /// Web Push (RFC 8030).
    #[pyo3(name = "WEB_PUSH")]
    WebPush,
}

impl From<PyPushPlatform> for PushPlatform {
    fn from(platform: PyPushPlatform) -> Self {
        match platform {
            PyPushPlatform::Apns => Self::Apns,
            PyPushPlatform::Fcm => Self::Fcm,
            PyPushPlatform::WebPush => Self::WebPush,
        }
    }
}

/// Which outcome a wake reported (ADR-029 §2 push-wake pull mode step 7).
#[pyclass(name = "WakeOutcomeKind", eq, eq_int, frozen)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyWakeOutcomeKind {
    /// The pull stored new events.
    #[pyo3(name = "NEW_DATA")]
    NewData,
    /// The pull completed and stored nothing.
    #[pyo3(name = "NO_DATA")]
    NoData,
    /// The wake failed; `failure` says why.
    #[pyo3(name = "FAILED")]
    Failed,
}

impl From<WakeOutcomeKind> for PyWakeOutcomeKind {
    fn from(kind: WakeOutcomeKind) -> Self {
        match kind {
            WakeOutcomeKind::NewData => Self::NewData,
            WakeOutcomeKind::NoData => Self::NoData,
            WakeOutcomeKind::Failed => Self::Failed,
        }
    }
}

/// One context's failed pull in a [`PyWakeFailure`].
#[pyclass(name = "WakeContextFailure", frozen)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyWakeContextFailure {
    /// The context that failed.
    #[pyo3(get)]
    pub context_id: String,
    /// The failure's stable code.
    #[pyo3(get)]
    pub code: String,
    /// The failure's description.
    #[pyo3(get)]
    pub message: String,
}

/// Why a wake returned `FAILED`.
#[pyclass(name = "WakeFailure", frozen)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyWakeFailure {
    /// The failure's stable code, `SCP-TRANS-5085` to `SCP-TRANS-5094`.
    #[pyo3(get)]
    pub code: String,
    /// The failure's description.
    #[pyo3(get)]
    pub message: String,
    /// The contexts the failure names, sorted; empty for a failure of the
    /// whole wake.
    #[pyo3(get)]
    pub context_ids: Vec<String>,
    /// Each failed context's pull with its own code; empty unless the
    /// failure is a context pull failure.
    #[pyo3(get)]
    pub context_failures: Vec<PyWakeContextFailure>,
}

/// What a wake reports (ADR-029 §2 push-wake pull mode step 7).
#[pyclass(name = "WakeOutcome", frozen)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyWakeOutcome {
    /// Which outcome the wake reported.
    #[pyo3(get)]
    pub outcome: PyWakeOutcomeKind,
    /// The failure when `outcome` is `FAILED`; `None` otherwise.
    #[pyo3(get)]
    pub failure: Option<PyWakeFailure>,
}

/// Each relay's result of a `push_enable` or `push_disable`, mirroring the
/// registrar's `RelayOutcomes`: deregistrations first, then registrations
/// (`10-infrastructure-and-self-hosting.md` §10.7.1).
#[pyclass(name = "PushRelayOutcomes", frozen)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyPushRelayOutcomes {
    /// Each `PushDeregistration`, one entry per relay.
    #[pyo3(get)]
    pub deregistered: Vec<PyPushRelayResult>,
    /// Each `PushRegistration`, one entry per relay.
    #[pyo3(get)]
    pub registered: Vec<PyPushRelayResult>,
}

/// One relay's result in a [`PyPushRelayOutcomes`].
#[pyclass(name = "PushRelayResult", frozen)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyPushRelayResult {
    /// The relay's canonical URL (`09-security-model.md` §9.5.2).
    #[pyo3(get)]
    pub relay_url: String,
    /// Why the relay refused; `None` when it accepted.
    #[pyo3(get)]
    pub failure: Option<PyPushRelayFailure>,
}

/// Why one relay refused a push registration or deregistration.
#[pyclass(name = "PushRelayFailure", frozen)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyPushRelayFailure {
    /// The failure's stable code.
    #[pyo3(get)]
    pub code: String,
    /// The failure's description.
    #[pyo3(get)]
    pub message: String,
}

impl From<WakeContextFailureView> for PyWakeContextFailure {
    fn from(view: WakeContextFailureView) -> Self {
        Self {
            context_id: view.context_id,
            code: view.code.to_owned(),
            message: view.message,
        }
    }
}

impl From<WakeFailureView> for PyWakeFailure {
    fn from(view: WakeFailureView) -> Self {
        Self {
            code: view.code.to_owned(),
            message: view.message,
            context_ids: view.context_ids,
            context_failures: view.context_failures.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<WakeOutcomeView> for PyWakeOutcome {
    fn from(view: WakeOutcomeView) -> Self {
        Self {
            outcome: view.kind.into(),
            failure: view.failure.map(Into::into),
        }
    }
}

fn input_error(e: PushInputError) -> PyErr {
    PyErr::from(ScpPyError::ValidationError {
        message: e.to_string(),
        code: e.code().to_owned(),
    })
}

fn registration_error(e: PushRegistrationError) -> PyErr {
    let (message, code) = (e.to_string(), e.code().to_owned());
    PyErr::from(match e {
        PushRegistrationError::ShutDown => ScpPyError::ContextError { message, code },
        PushRegistrationError::NoLocalIdentity => ScpPyError::IdentityError { message, code },
        PushRegistrationError::SigningKeyUnavailable => {
            ScpPyError::TransportError { message, code }
        }
    })
}

fn wake_error(e: WakeError) -> PyErr {
    PyErr::from(ScpPyError::TransportError {
        message: e.to_string(),
        code: e.code().to_owned(),
    })
}

/// `push_enable` on `bi` with the GIL released: checks `token` and the
/// instance, then refuses. Story PUSH-037 registers `token` for `platform`
/// and records `platform` in the instance's slot.
fn push_enable_on(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    _platform: PyPushPlatform,
    token: &[u8],
) -> PyResult<PyPushRelayOutcomes> {
    shared::check_push_token(token).map_err(input_error)?;
    match crate::actor_wait::block_on_released(py, shared::push_registration(&bi.core))?
        .map_err(registration_error)? {}
}

/// `push_disable` on `bi` with the GIL released: checks the instance, then
/// refuses.
fn push_disable_on(py: Python<'_>, bi: &PyBridgeInstance) -> PyResult<PyPushRelayOutcomes> {
    match crate::actor_wait::block_on_released(py, shared::push_registration(&bi.core))?
        .map_err(registration_error)? {}
}

/// `push_handle_wake` on `bi`: runs the shared wake for the enabled platform
/// with the GIL released.
fn push_handle_wake_on(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    payload: &[u8],
) -> PyResult<PyWakeOutcome> {
    let platform = match shared::begin_wake(&bi.core, &bi.push).map_err(wake_error)? {
        WakeEntry::Enabled(platform) => platform,
        WakeEntry::Finished(outcome) => return Ok(outcome.view().into()),
    };
    let outcome = crate::actor_wait::block_on_released(
        py,
        scp_ffi_common::push::handle_wake(&bi.core, platform, payload),
    )?
    .map_err(wake_error)?;
    Ok(outcome.view().into())
}

/// Records `platform` as enabled on `bi`, the slot story PUSH-037's
/// `push_enable` fills, so tests reach the wake path.
#[cfg(any(test, feature = "testing"))]
pub fn install_push_platform_for_testing(bi: &PyBridgeInstance, platform: PyPushPlatform) {
    bi.push.set(platform.into());
}

#[pymethods]
impl PyScp {
    /// Enables push: registers the device's push `token` for `platform` with
    /// every relay in the relay set and returns each relay's result.
    ///
    /// # Errors
    ///
    /// `ValidationError` `SCP-VALID-7004` for an empty token, `ContextError`
    /// `SCP-CTX-2138` for a shut-down instance, `IdentityError`
    /// `SCP-IDENT-1002` for one with no local member DID, and otherwise
    /// `TransportError` `SCP-TRANS-5104`: the device has no P-256 `#active`
    /// signing key to sign a `PushRegistration` with.
    #[pyo3(signature = (platform, token))]
    pub fn push_enable(
        &self,
        py: Python<'_>,
        platform: PyPushPlatform,
        token: Vec<u8>,
    ) -> PyResult<PyPushRelayOutcomes> {
        push_enable_on(py, &self.inner, platform, &token)
    }

    /// Disables push: deregisters the device's push token from every relay
    /// it registered with and returns each relay's result.
    ///
    /// # Errors
    ///
    /// `ContextError` `SCP-CTX-2138` for a shut-down instance, `IdentityError`
    /// `SCP-IDENT-1002` for one with no local member DID, and otherwise
    /// `TransportError` `SCP-TRANS-5104`: the device has no P-256 `#active`
    /// signing key to sign a `PushDeregistration` with.
    pub fn push_disable(&self, py: Python<'_>) -> PyResult<PyPushRelayOutcomes> {
        push_disable_on(py, &self.inner)
    }

    /// Handles a silent push: `payload` is what the enabled platform
    /// delivered. A shut-down instance returns the `FAILED` outcome
    /// `SCP-TRANS-5085`.
    ///
    /// # Errors
    ///
    /// `TransportError` `SCP-TRANS-5105` when push is not enabled,
    /// `SCP-TRANS-5080` for a payload that is not the enabled platform's wake
    /// signal (no connection opens). Every later failure is a `FAILED`
    /// outcome.
    #[pyo3(signature = (payload))]
    pub fn push_handle_wake(&self, py: Python<'_>, payload: Vec<u8>) -> PyResult<PyWakeOutcome> {
        push_handle_wake_on(py, &self.inner, &payload)
    }
}

/// Registers the push enums and result classes on the `_scp_core` module.
///
/// # Errors
///
/// Returns a `PyErr` if a class cannot be added to the module.
pub fn register_push(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPushPlatform>()?;
    m.add_class::<PyWakeOutcomeKind>()?;
    m.add_class::<PyWakeOutcome>()?;
    m.add_class::<PyWakeFailure>()?;
    m.add_class::<PyWakeContextFailure>()?;
    m.add_class::<PyPushRelayOutcomes>()?;
    m.add_class::<PyPushRelayResult>()?;
    m.add_class::<PyPushRelayFailure>()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
    use scp_ffi_common::error_codes as codes;

    fn init() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();
    }

    fn has_code(e: &PyErr, code: &str) {
        let text = e.to_string();
        assert!(text.contains(code), "expected {code}, got {text}");
    }

    /// An instance whose supervisor holds a local member DID.
    fn ready_bi() -> PyBridgeInstance {
        let bi = PyBridgeInstance::new_in_memory_for_test();
        crate::runtime::init_context_manager(&bi, "did:test:push-pyo3")
            .expect("the test supervisor attaches");
        bi
    }

    #[test]
    fn enable_and_disable_return_5104_and_record_nothing() {
        init();
        let bi = ready_bi();
        Python::with_gil(|py| {
            has_code(
                &push_enable_on(py, &bi, PyPushPlatform::Apns, b"token").unwrap_err(),
                codes::TRANS_5104,
            );
            has_code(&push_disable_on(py, &bi).unwrap_err(), codes::TRANS_5104);
        });
        assert!(
            bi.push.get().is_none(),
            "a refused enable records no platform"
        );
    }

    #[test]
    fn enable_and_disable_without_a_local_identity_return_1002() {
        init();
        let bi = PyBridgeInstance::new_py();
        Python::with_gil(|py| {
            has_code(
                &push_enable_on(py, &bi, PyPushPlatform::Apns, b"token").unwrap_err(),
                codes::IDENT_1002,
            );
            has_code(&push_disable_on(py, &bi).unwrap_err(), codes::IDENT_1002);
        });
    }

    /// The token is checked before the instance, so an empty token raises
    /// `SCP-VALID-7004` even on an instance with no local identity.
    #[test]
    fn an_empty_token_returns_7004() {
        init();
        for bi in [ready_bi(), PyBridgeInstance::new_py()] {
            Python::with_gil(|py| {
                has_code(
                    &push_enable_on(py, &bi, PyPushPlatform::Fcm, b"").unwrap_err(),
                    codes::VALID_7004,
                );
            });
        }
    }

    #[test]
    fn a_wake_with_no_enabled_platform_returns_5105() {
        init();
        Python::with_gil(|py| {
            has_code(
                &push_handle_wake_on(py, &ready_bi(), br#"{"scp":"1"}"#).unwrap_err(),
                codes::TRANS_5105,
            );
        });
    }

    /// The enabled platform decides which wake signal passes: an instance
    /// enabled for `FCM` refuses the APNs wake signal.
    #[test]
    fn the_enabled_platform_decides_which_wake_signal_passes() {
        init();
        Python::with_gil(|py| {
            let bi = PyBridgeInstance::new_py();
            install_push_platform_for_testing(&bi, PyPushPlatform::Fcm);
            has_code(
                &push_handle_wake_on(py, &bi, br#"{"aps":{"content-available":1}}"#).unwrap_err(),
                codes::TRANS_5080,
            );
        });
    }

    #[test]
    fn a_valid_payload_reaches_handle_wake() {
        // No supervisor on this instance, so `handle_wake` itself answers
        // `FAILED` with `SCP-TRANS-5086`: the payload passed the check.
        init();
        Python::with_gil(|py| {
            let bi = PyBridgeInstance::new_py();
            install_push_platform_for_testing(&bi, PyPushPlatform::Fcm);
            let outcome = push_handle_wake_on(py, &bi, br#"{"scp":"1"}"#).unwrap();
            assert_eq!(outcome.outcome, PyWakeOutcomeKind::Failed);
            assert_eq!(outcome.failure.unwrap().code, codes::TRANS_5086);
        });
    }

    /// Shutdown is read before the slot, so a shut-down instance answers the
    /// shutdown outcome, not `SCP-TRANS-5105`, though shutdown emptied the
    /// slot.
    #[test]
    fn a_wake_after_shutdown_returns_the_shutdown_outcome() {
        init();
        let bi = std::sync::Arc::new(PyBridgeInstance::new_py());
        install_push_platform_for_testing(&bi, PyPushPlatform::Fcm);
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(std::sync::Arc::clone(&bi).shutdown(std::time::Duration::from_secs(10)))
            .unwrap();
        assert!(bi.push.get().is_none(), "shutdown empties the slot");
        Python::with_gil(|py| {
            let outcome = push_handle_wake_on(py, &bi, br#"{"scp":"1"}"#).unwrap();
            assert_eq!(outcome.outcome, PyWakeOutcomeKind::Failed);
            assert_eq!(outcome.failure.unwrap().code, codes::TRANS_5085);
        });
    }
}
