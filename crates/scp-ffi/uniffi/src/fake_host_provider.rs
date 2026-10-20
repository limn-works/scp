//! A `KeyCustodyProvider` over the shared software host, for the unit tests of
//! `bridge` and `testing_custody`. Compiled only under `cfg(test)`.

use std::sync::Arc;

use scp_ffi_common::error_codes as codes;

use crate::ScpError;

/// A `KeyCustodyProvider` over the shared software host.
///
/// A round trip runs through `CallbackKeyCustody` and the shared flows. A
/// host not-found answers with the typed `SCP-CRYPTO-4006`; `sign_error`,
/// when set, replaces every `sign` answer; `custody_type` is the string
/// the provider reports for every key.
pub struct FakeHostProvider {
    pub host: Arc<scp_ffi_common::callback_custody::fake_host::FakeHost>,
    pub sign_error: Option<ScpError>,
    pub custody_type: &'static str,
}

impl FakeHostProvider {
    pub fn over(host: &Arc<scp_ffi_common::callback_custody::fake_host::FakeHost>) -> Self {
        Self {
            host: Arc::clone(host),
            sign_error: None,
            custody_type: "software",
        }
    }
}

fn fake_host_err(e: &scp_platform::error::PlatformError) -> ScpError {
    match e {
        scp_platform::error::PlatformError::KeyNotFound => ScpError::Crypto {
            msg: e.to_string(),
            code: codes::CRYPTO_4006.to_owned(),
        },
        _ => ScpError::Context {
            msg: e.to_string(),
            code: codes::CTX_2050.to_owned(),
        },
    }
}

#[async_trait::async_trait]
impl crate::KeyCustodyProvider for FakeHostProvider {
    async fn sign(&self, key_id: String, message: Vec<u8>) -> Result<Vec<u8>, ScpError> {
        let answer = self
            .host
            .sign(&key_id, &message)
            .map_err(|e| fake_host_err(&e))?;
        self.sign_error
            .as_ref()
            .map_or(Ok(answer), |e| Err(e.clone()))
    }

    async fn get_public_key(&self, key_id: String) -> Result<crate::CustodyPublicKey, ScpError> {
        let answer = self
            .host
            .get_public_key(&key_id)
            .map_err(|e| fake_host_err(&e))?;
        Ok(crate::CustodyPublicKey {
            key_type: answer.key_type.into(),
            public_key: answer.public_key,
            role: answer.role.into(),
        })
    }

    async fn destroy_key(&self, key_id: String) -> Result<(), ScpError> {
        self.host
            .destroy_key(&key_id)
            .map_err(|e| fake_host_err(&e))
    }

    async fn generate_keypair(
        &self,
        key_type: crate::CustodyKeyType,
        role: crate::CustodyKeyRole,
    ) -> Result<String, ScpError> {
        self.host
            .generate_keypair(key_type.into(), role.into())
            .map_err(|e| fake_host_err(&e))
    }

    async fn dh_agree(&self, key_id: String, peer_public: Vec<u8>) -> Result<Vec<u8>, ScpError> {
        self.host
            .dh_agree(&key_id, &peer_public)
            .map_err(|e| fake_host_err(&e))
    }

    async fn derive_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
    ) -> Result<Vec<u8>, ScpError> {
        self.host
            .derive_pseudonym(&key_id, &context_id, None)
            .map_err(|e| fake_host_err(&e))
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
        pseudonym_epoch: u64,
    ) -> Result<Vec<u8>, ScpError> {
        self.host
            .derive_pseudonym(&key_id, &context_id, Some(pseudonym_epoch))
            .map_err(|e| fake_host_err(&e))
    }

    fn custody_type(&self, _key_id: String) -> String {
        self.custody_type.to_owned()
    }
}
