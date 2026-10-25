//! Push exports for TypeScript: `pushRegister`, `pushDeregister` and
//! `pushHandleWake` (story PUSH-015).
//!
//! A TypeScript host has no `PushProvider` callback, so it passes the token
//! to `pushRegister` and the platform to each call by name (`apns`, `fcm`,
//! `web_push`; anything else is `SCP-VALID-7005`).
//!
//! `pushHandleWake(platform, payload)` runs
//! [`scp_ffi_common::push::handle_wake`], which checks `payload` against the
//! platform's wake signal (`SCP-TRANS-5080` before any connection) and runs
//! the ADR-029 §2 push-wake pull.
//!
//! `pushRegister` and `pushDeregister` check their arguments, then the
//! instance (`SCP-CTX-2138` when it is shut down, `SCP-IDENT-1002` when it
//! holds no local member DID), then return `SCP-TRANS-5104`: the registrar
//! signs with the device's P-256
//! `#active` key, and no production constructor builds it until story
//! PUSH-036. Story PUSH-037 makes them register and deregister.

use napi_derive::napi;
use scp_ffi_common::push::{
    self as shared, PushInputError, PushRegistrationError, WakeContextFailureView, WakeError,
    WakeFailureView, WakeOutcomeView,
};

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

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
    /// `new_data`, `no_data` or `failed`.
    pub outcome: String,
    /// The failure when `outcome` is `failed`; absent otherwise.
    pub failure: Option<NapiWakeFailure>,
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
            outcome: view.outcome.to_owned(),
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
        PushRegistrationError::SigningKeyUnavailable | PushRegistrationError::NotEnabled => {
            ScpNapiError::Transport { message, code }
        }
    })
}

/// Checks that `bi` can register or deregister, then refuses until story
/// PUSH-037.
fn registration_refusal(bi: &NapiBridgeInstance) -> napi::Error {
    shared::check_push_registration_ready(&bi.core).map_or_else(registration_error, |()| {
        registration_error(shared::push_registration_unavailable())
    })
}

fn wake_error(e: WakeError) -> napi::Error {
    napi::Error::from(ScpNapiError::Transport {
        message: e.to_string(),
        code: e.code().to_owned(),
    })
}

/// `pushRegister` on `bi`: checks `platform`, `token` and the instance, then
/// refuses.
///
/// # Errors
///
/// `SCP-VALID-7005` for an unknown platform name, `SCP-VALID-7004` for an
/// empty token, `SCP-CTX-2138` for a shut-down instance, `SCP-IDENT-1002`
/// for one with no local member DID, and otherwise `SCP-TRANS-5104`.
pub fn push_register_on(bi: &NapiBridgeInstance, platform: &str, token: &[u8]) -> napi::Result<()> {
    shared::parse_push_platform(platform).map_err(input_error)?;
    shared::check_push_token(token).map_err(input_error)?;
    Err(registration_refusal(bi))
}

/// `pushDeregister` on `bi`: checks the instance, then refuses.
///
/// # Errors
///
/// `SCP-CTX-2138` for a shut-down instance, `SCP-IDENT-1002` for one with no
/// local member DID, and otherwise `SCP-TRANS-5104`.
pub fn push_deregister_on(bi: &NapiBridgeInstance) -> napi::Result<()> {
    Err(registration_refusal(bi))
}

/// `pushHandleWake`: names the platform, then runs the shared wake on `bi`.
///
/// # Errors
///
/// `SCP-VALID-7005` for an unknown platform name, `SCP-TRANS-5080` for a
/// payload that is not the platform's wake signal. Every later failure is a
/// `failed` outcome.
pub async fn push_handle_wake_on(
    bi: &NapiBridgeInstance,
    platform: &str,
    payload: &[u8],
) -> napi::Result<NapiWakeOutcome> {
    let platform = shared::parse_push_platform(platform).map_err(input_error)?;
    let outcome = scp_ffi_common::push::handle_wake(&bi.core, platform, payload)
        .await
        .map_err(wake_error)?;
    Ok(outcome.view().into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

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
    async fn an_unknown_platform_name_returns_7005() {
        let bi = ready_bi();
        has_code(
            &push_register_on(&bi, "webpush", b"token").unwrap_err(),
            codes::VALID_7005,
        );
        has_code(
            &push_handle_wake_on(&bi, "APNS", br#"{"aps":{"content-available":1}}"#)
                .await
                .unwrap_err(),
            codes::VALID_7005,
        );
    }

    #[test]
    fn register_and_deregister_return_5104() {
        let bi = ready_bi();
        has_code(
            &push_register_on(&bi, "apns", b"token").unwrap_err(),
            codes::TRANS_5104,
        );
        has_code(&push_deregister_on(&bi).unwrap_err(), codes::TRANS_5104);
    }

    #[test]
    fn register_and_deregister_without_a_local_identity_return_1002() {
        let bi = NapiBridgeInstance::new_napi();
        has_code(
            &push_register_on(&bi, "apns", b"token").unwrap_err(),
            codes::IDENT_1002,
        );
        has_code(&push_deregister_on(&bi).unwrap_err(), codes::IDENT_1002);
    }

    #[test]
    fn an_empty_token_returns_7004() {
        has_code(
            &push_register_on(&ready_bi(), "fcm", b"").unwrap_err(),
            codes::VALID_7004,
        );
    }

    #[tokio::test]
    async fn an_invalid_fcm_payload_returns_5080() {
        let bi = NapiBridgeInstance::new_napi();
        has_code(
            &push_handle_wake_on(&bi, "fcm", br#"{"scp":1}"#)
                .await
                .unwrap_err(),
            codes::TRANS_5080,
        );
        assert!(
            bi.core.get_transport_arc().ok().flatten().is_none(),
            "a rejected wake dials nothing"
        );
    }

    #[tokio::test]
    async fn a_valid_payload_reaches_handle_wake() {
        // No supervisor on this instance, so `handle_wake` itself answers
        // `failed` with `SCP-TRANS-5086`: the payload passed the check.
        let bi = NapiBridgeInstance::new_napi();
        let outcome = push_handle_wake_on(&bi, "fcm", br#"{"scp":"1"}"#)
            .await
            .unwrap();
        assert_eq!(outcome.outcome, "failed");
        assert_eq!(outcome.failure.unwrap().code, codes::TRANS_5086);
    }
}
