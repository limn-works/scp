//! Push exports for Python: `push_register`, `push_deregister` and
//! `push_handle_wake` on `SCP` (story PUSH-015).
//!
//! A Python host has no `PushProvider` callback, so it passes the token to
//! `push_register` and the platform to each call by name (`apns`, `fcm`,
//! `web_push`; anything else is `SCP-VALID-7005`).
//!
//! `push_handle_wake(platform, payload)` runs
//! [`scp_ffi_common::push::handle_wake`] with the GIL released, which checks
//! `payload` against the platform's wake signal (`SCP-TRANS-5080` before any
//! connection) and runs the ADR-029 §2 push-wake pull.
//!
//! `push_register` and `push_deregister` check their arguments, then the
//! instance (`SCP-CTX-2138` when it is shut down, `SCP-IDENT-1002` when it
//! holds no local member DID), then raise `SCP-TRANS-5104`: the registrar
//! signs with the device's P-256
//! `#active` key, and no production constructor builds it until story
//! PUSH-036. Story PUSH-037 makes them register and deregister.

use pyo3::prelude::*;
use scp_ffi_common::push::{
    self as shared, PushInputError, PushRegistrationError, WakeContextFailureView, WakeError,
    WakeFailureView, WakeOutcomeView,
};

use crate::error::ScpPyError;
use crate::runtime::PyBridgeInstance;
use crate::scp::PyScp;

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

/// Why a wake returned `failed`.
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
    /// `new_data`, `no_data` or `failed`.
    #[pyo3(get)]
    pub outcome: String,
    /// The failure when `outcome` is `failed`; `None` otherwise.
    #[pyo3(get)]
    pub failure: Option<PyWakeFailure>,
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
            outcome: view.outcome.to_owned(),
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
        PushRegistrationError::SigningKeyUnavailable | PushRegistrationError::NotEnabled => {
            ScpPyError::TransportError { message, code }
        }
    })
}

/// Checks that `bi` can register or deregister, then refuses until story
/// PUSH-037.
fn registration_refusal(bi: &PyBridgeInstance) -> PyErr {
    shared::check_push_registration_ready(&bi.core).map_or_else(registration_error, |()| {
        registration_error(shared::push_registration_unavailable())
    })
}

fn wake_error(e: WakeError) -> PyErr {
    PyErr::from(ScpPyError::TransportError {
        message: e.to_string(),
        code: e.code().to_owned(),
    })
}

/// `push_register` on `bi`: checks `platform`, `token` and the instance,
/// then refuses.
fn push_register_on(bi: &PyBridgeInstance, platform: &str, token: &[u8]) -> PyResult<()> {
    shared::parse_push_platform(platform).map_err(input_error)?;
    shared::check_push_token(token).map_err(input_error)?;
    Err(registration_refusal(bi))
}

/// `push_deregister` on `bi`: checks the instance, then refuses.
fn push_deregister_on(bi: &PyBridgeInstance) -> PyResult<()> {
    Err(registration_refusal(bi))
}

/// `push_handle_wake`: names the platform, then runs the shared wake on `bi`
/// with the GIL released.
fn push_handle_wake_on(
    py: Python<'_>,
    bi: &PyBridgeInstance,
    platform: &str,
    payload: &[u8],
) -> PyResult<PyWakeOutcome> {
    let platform = shared::parse_push_platform(platform).map_err(input_error)?;
    let outcome = crate::actor_wait::block_on_released(
        py,
        scp_ffi_common::push::handle_wake(&bi.core, platform, payload),
    )?
    .map_err(wake_error)?;
    Ok(outcome.view().into())
}

#[pymethods]
impl PyScp {
    /// Registers the device's push `token` for `platform` with every relay
    /// in the relay set.
    ///
    /// # Errors
    ///
    /// `ValidationError` `SCP-VALID-7005` for a platform other than `apns`,
    /// `fcm` or `web_push`, `SCP-VALID-7004` for an empty token,
    /// `ContextError` `SCP-CTX-2138` for a shut-down instance, `IdentityError`
    /// `SCP-IDENT-1002` for one with no local member DID, and otherwise
    /// `TransportError` `SCP-TRANS-5104`: the device has no P-256 `#active`
    /// signing key to sign a `PushRegistration` with.
    #[pyo3(signature = (platform, token))]
    pub fn push_register(&self, platform: &str, token: Vec<u8>) -> PyResult<()> {
        push_register_on(&self.inner, platform, &token)
    }

    /// Deregisters the device's push token from every relay it registered
    /// with.
    ///
    /// # Errors
    ///
    /// `ContextError` `SCP-CTX-2138` for a shut-down instance, `IdentityError`
    /// `SCP-IDENT-1002` for one with no local member DID, and otherwise
    /// `TransportError` `SCP-TRANS-5104`: the device has no P-256 `#active`
    /// signing key to sign a `PushDeregistration` with.
    pub fn push_deregister(&self) -> PyResult<()> {
        push_deregister_on(&self.inner)
    }

    /// Handles a silent push: `payload` is what `platform` delivered.
    ///
    /// # Errors
    ///
    /// `ValidationError` `SCP-VALID-7005` for an unknown platform name,
    /// `TransportError` `SCP-TRANS-5080` for a payload that is not the
    /// platform's wake signal (no connection opens). Every later failure is
    /// a `failed` outcome.
    #[pyo3(signature = (platform, payload))]
    pub fn push_handle_wake(
        &self,
        py: Python<'_>,
        platform: &str,
        payload: Vec<u8>,
    ) -> PyResult<PyWakeOutcome> {
        push_handle_wake_on(py, &self.inner, platform, &payload)
    }
}

/// Registers the push result classes on the `_scp_core` module.
///
/// # Errors
///
/// Returns a `PyErr` if a class cannot be added to the module.
pub fn register_push(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyWakeOutcome>()?;
    m.add_class::<PyWakeFailure>()?;
    m.add_class::<PyWakeContextFailure>()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
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
    fn an_unknown_platform_name_returns_7005() {
        init();
        has_code(
            &push_register_on(&ready_bi(), "webpush", b"token").unwrap_err(),
            codes::VALID_7005,
        );
        Python::with_gil(|py| {
            let bi = PyBridgeInstance::new_py();
            has_code(
                &push_handle_wake_on(py, &bi, "APNS", br#"{"aps":{"content-available":1}}"#)
                    .unwrap_err(),
                codes::VALID_7005,
            );
        });
    }

    #[test]
    fn register_and_deregister_return_5104() {
        init();
        let bi = ready_bi();
        has_code(
            &push_register_on(&bi, "apns", b"token").unwrap_err(),
            codes::TRANS_5104,
        );
        has_code(&push_deregister_on(&bi).unwrap_err(), codes::TRANS_5104);
    }

    #[test]
    fn register_and_deregister_without_a_local_identity_return_1002() {
        init();
        let bi = PyBridgeInstance::new_py();
        has_code(
            &push_register_on(&bi, "apns", b"token").unwrap_err(),
            codes::IDENT_1002,
        );
        has_code(&push_deregister_on(&bi).unwrap_err(), codes::IDENT_1002);
    }

    #[test]
    fn an_empty_token_returns_7004() {
        init();
        has_code(
            &push_register_on(&ready_bi(), "fcm", b"").unwrap_err(),
            codes::VALID_7004,
        );
    }

    #[test]
    fn an_invalid_fcm_payload_returns_5080() {
        init();
        Python::with_gil(|py| {
            let bi = PyBridgeInstance::new_py();
            has_code(
                &push_handle_wake_on(py, &bi, "fcm", br#"{"scp":1}"#).unwrap_err(),
                codes::TRANS_5080,
            );
            assert!(
                bi.core.get_transport_arc().ok().flatten().is_none(),
                "a rejected wake dials nothing"
            );
        });
    }

    #[test]
    fn a_valid_payload_reaches_handle_wake() {
        // No supervisor on this instance, so `handle_wake` itself answers
        // `failed` with `SCP-TRANS-5086`: the payload passed the check.
        init();
        Python::with_gil(|py| {
            let bi = PyBridgeInstance::new_py();
            let outcome = push_handle_wake_on(py, &bi, "fcm", br#"{"scp":"1"}"#).unwrap();
            assert_eq!(outcome.outcome, "failed");
            assert_eq!(outcome.failure.unwrap().code, codes::TRANS_5086);
        });
    }
}
