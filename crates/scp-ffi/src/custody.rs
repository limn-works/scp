//! Enum dispatch for [`KeyCustody`] in the `PyO3` FFI bridge.
//!
//! The [`KeyCustody`] trait uses RPITIT (return-position `impl Trait` in trait),
//! which makes it NOT object-safe. This module provides [`FfiKeyCustody`], an
//! enum that wraps the concrete custody implementations used by the FFI bridge
//! and manually delegates each trait method to the active variant.
//!
//! # Variants
//!
//! - `InMemoryKeyCustody` — Test/development only. Keys exist only in memory
//!   and are lost when the process exits. Available because `scp-ffi` enables
//!   `scp-platform/testing`.
//! - [`FileKeyCustody`] — Encrypted-at-rest key storage using Argon2id +
//!   AES-256-GCM. The default production custody for desktop/server platforms.
//!
//! See issue #323 and ADR-006.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use scp_platform::error::PlatformError;
use scp_platform::file::FileKeyCustody;
#[cfg(feature = "testing")]
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

/// Enum dispatch wrapper for [`KeyCustody`] implementations used by the
/// `PyO3` FFI bridge.
///
/// Since [`KeyCustody`] uses RPITIT and is not object-safe, we cannot use
/// `Arc<dyn KeyCustody>`. Instead, this enum wraps the concrete types and
/// delegates each method to the active variant.
pub enum FfiKeyCustody {
    /// Test/development in-memory custody. Keys are lost on process exit.
    /// Available because `scp-ffi` enables `scp-platform/testing`.
    #[cfg(feature = "testing")]
    InMemory(InMemoryKeyCustody),
    /// Encrypted file-backed custody (Argon2id + AES-256-GCM).
    /// Production default for desktop/server platforms.
    File(FileKeyCustody),
    /// Caller-provided custody backed by a Python object implementing the
    /// `KeyCustodyProvider` protocol. Used by `identity_create_with_custody`
    /// to inject platform-specific key management (e.g. an OS keychain, a
    /// hardware token wrapper) without the private key material ever crossing
    /// the FFI boundary into Rust ownership (ADR-006).
    Callback(PyCallbackKeyCustody),
}

impl KeyCustody for FfiKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.generate_keypair(key_type).await,
            Self::File(kc) => kc.generate_keypair(key_type).await,
            Self::Callback(kc) => kc.generate_keypair(key_type).await,
        }
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.sign(key, data).await,
            Self::File(kc) => kc.sign(key, data).await,
            Self::Callback(kc) => kc.sign(key, data).await,
        }
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.public_key(key).await,
            Self::File(kc) => kc.public_key(key).await,
            Self::Callback(kc) => kc.public_key(key).await,
        }
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.destroy_key(key).await,
            Self::File(kc) => kc.destroy_key(key).await,
            Self::Callback(kc) => kc.destroy_key(key).await,
        }
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.dh_agree(key, peer_public).await,
            Self::File(kc) => kc.dh_agree(key, peer_public).await,
            Self::Callback(kc) => kc.dh_agree(key, peer_public).await,
        }
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.derive_pseudonym(key, context_id).await,
            Self::File(kc) => kc.derive_pseudonym(key, context_id).await,
            Self::Callback(kc) => kc.derive_pseudonym(key, context_id).await,
        }
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => {
                kc.derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
                    .await
            }
            Self::File(kc) => {
                kc.derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
                    .await
            }
            Self::Callback(kc) => {
                kc.derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
                    .await
            }
        }
    }

    async fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => {
                kc.ed25519_to_x25519_agree(ed25519_handle, peer_x25519_public)
                    .await
            }
            Self::File(kc) => {
                kc.ed25519_to_x25519_agree(ed25519_handle, peer_x25519_public)
                    .await
            }
            Self::Callback(kc) => {
                kc.ed25519_to_x25519_agree(ed25519_handle, peer_x25519_public)
                    .await
            }
        }
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.custody_type(key),
            Self::File(kc) => kc.custody_type(key),
            Self::Callback(kc) => kc.custody_type(key),
        }
    }

    async fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.generate_ephemeral_ed25519_seed().await,
            Self::File(kc) => kc.generate_ephemeral_ed25519_seed().await,
            Self::Callback(kc) => kc.generate_ephemeral_ed25519_seed().await,
        }
    }

    async fn import_ed25519_signing_key(
        &self,
        seed: &zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<KeyHandle, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.import_ed25519_signing_key(seed).await,
            Self::File(kc) => kc.import_ed25519_signing_key(seed).await,
            Self::Callback(kc) => kc.import_ed25519_signing_key(seed).await,
        }
    }
}

// ---------------------------------------------------------------------------
// PyKeyCustodyProvider — object-safe shim over a Python callback object
//
// `KeyCustody` uses RPITIT and is NOT object-safe, so we cannot store a
// `Box<dyn KeyCustody>`. Instead this shim exposes the small set of raw
// byte/string operations the Python `KeyCustodyProvider` protocol defines,
// and the concrete `PyCallbackKeyCustody` below adapts those into the typed
// `KeyCustody` surface. Mirrors the UniFFI bridge's
// `KeyCustodyProvider` (object-safe, `#[async_trait]`) + `CallbackKeyCustody`
// (concrete `impl KeyCustody`) split. See ADR-006.
//
// Private key material never crosses into Rust ownership: every method
// re-acquires the GIL, calls the Python object, and translates the returned
// public bytes / opaque key-id strings. The Python implementation owns the
// secrets (e.g. an OS keychain handle).
// ---------------------------------------------------------------------------

/// Object-safe wrapper over a Python object implementing the
/// `KeyCustodyProvider` protocol (see `scp_sdk.scp.KeyCustodyProvider`).
///
/// Each method re-acquires the GIL via [`Python::with_gil`] and invokes the
/// correspondingly-named Python method. Returned values are extracted into
/// owned Rust types. Any Python exception is mapped to
/// [`PlatformError::CustodyError`] carrying the exception text.
pub struct PyKeyCustodyProvider {
    /// The Python object exposing the custody methods. Held as a GIL-
    /// independent [`Py<PyAny>`] so it can be moved across the
    /// `py.allow_threads` boundary and re-bound under a fresh GIL per call.
    obj: Py<PyAny>,
}

impl std::fmt::Debug for PyKeyCustodyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PyKeyCustodyProvider([python])")
    }
}

impl PyKeyCustodyProvider {
    /// The Python method names the provider object MUST expose. Validated
    /// up-front by [`Self::validate`] so a malformed provider fails fast at
    /// the FFI boundary with a clear `ValidationError` rather than deep
    /// inside an async DID-creation flow.
    const REQUIRED_METHODS: [&'static str; 9] = [
        "sign",
        "get_public_key",
        "destroy_key",
        "generate_keypair",
        "dh_agree",
        "derive_pseudonym",
        "derive_rotatable_pseudonym",
        "export_signing_key_bytes",
        "custody_type",
    ];

    /// Wraps a Python provider object, validating that it exposes every
    /// required callable method.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if any required method is
    /// missing or not callable.
    pub fn new(py: Python<'_>, obj: Py<PyAny>) -> Result<Self, PlatformError> {
        Self::validate(py, &obj)?;
        Ok(Self { obj })
    }

    /// Validates that `obj` exposes every method in [`Self::REQUIRED_METHODS`]
    /// as a callable attribute.
    fn validate(py: Python<'_>, obj: &Py<PyAny>) -> Result<(), PlatformError> {
        let bound = obj.bind(py);
        for name in Self::REQUIRED_METHODS {
            let attr = bound.getattr(name).map_err(|_| {
                PlatformError::CustodyError(format!(
                    "KeyCustodyProvider is missing the required method '{name}'"
                ))
            })?;
            if !attr.is_callable() {
                return Err(PlatformError::CustodyError(format!(
                    "KeyCustodyProvider attribute '{name}' is not callable"
                )));
            }
        }
        Ok(())
    }

    /// Calls `method_name(key_id)` on the Python object under a fresh GIL and
    /// extracts the result as `T`.
    fn call_str<T>(&self, method_name: &str, key_id: &str) -> Result<T, PlatformError>
    where
        T: for<'py> pyo3::FromPyObject<'py>,
    {
        Python::with_gil(|py| {
            let result = self
                .obj
                .bind(py)
                .call_method1(method_name, (key_id,))
                .map_err(|e| Self::call_err(method_name, &e))?;
            result
                .extract::<T>()
                .map_err(|e| Self::type_err(method_name, &e))
        })
    }

    /// Calls `method_name(key_id, payload)` (payload as Python `bytes`) on the
    /// Python object under a fresh GIL and extracts the result as `T`.
    fn call_str_bytes<T>(
        &self,
        method_name: &str,
        key_id: &str,
        payload: &[u8],
    ) -> Result<T, PlatformError>
    where
        T: for<'py> pyo3::FromPyObject<'py>,
    {
        Python::with_gil(|py| {
            let bytes = PyBytes::new(py, payload);
            let result = self
                .obj
                .bind(py)
                .call_method1(method_name, (key_id, bytes))
                .map_err(|e| Self::call_err(method_name, &e))?;
            result
                .extract::<T>()
                .map_err(|e| Self::type_err(method_name, &e))
        })
    }

    /// Calls `method_name(key_id, payload, epoch)` (payload as Python `bytes`,
    /// epoch as a Python `int`) on the Python object under a fresh GIL and
    /// extracts the result as `T`. Used by the rotatable-pseudonym path, which
    /// must thread the epoch through to the provider so the provider performs
    /// the canonical v2 derivation itself (no bridge-side preimage synthesis).
    fn call_str_bytes_u64<T>(
        &self,
        method_name: &str,
        key_id: &str,
        payload: &[u8],
        epoch: u64,
    ) -> Result<T, PlatformError>
    where
        T: for<'py> pyo3::FromPyObject<'py>,
    {
        Python::with_gil(|py| {
            let bytes = PyBytes::new(py, payload);
            let result = self
                .obj
                .bind(py)
                .call_method1(method_name, (key_id, bytes, epoch))
                .map_err(|e| Self::call_err(method_name, &e))?;
            result
                .extract::<T>()
                .map_err(|e| Self::type_err(method_name, &e))
        })
    }

    /// Calls `method_name(key_id)` for its side effect only, discarding the
    /// Python return value. Used for `destroy_key`, which returns `None`.
    fn call_str_void(&self, method_name: &str, key_id: &str) -> Result<(), PlatformError> {
        Python::with_gil(|py| {
            self.obj
                .bind(py)
                .call_method1(method_name, (key_id,))
                .map_err(|e| Self::call_err(method_name, &e))?;
            Ok(())
        })
    }

    fn call_err(method_name: &str, e: &PyErr) -> PlatformError {
        PlatformError::CustodyError(format!("KeyCustodyProvider.{method_name} raised: {e}"))
    }

    fn type_err(method_name: &str, e: &PyErr) -> PlatformError {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method_name} returned an unexpected type: {e}"
        ))
    }
}

impl FfiKeyCustody {
    /// Exports the raw Ed25519 signing key for the given handle.
    ///
    /// Required by the governance lifecycle bridge functions
    /// (`propose_governance_action`, `approve_governance_proposal`,
    /// `reject_governance_proposal`) which delegate to core functions
    /// that accept `&ed25519_dalek::SigningKey` directly.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an
    /// X25519 key.
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ed25519_dalek::SigningKey, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.export_ed25519_signing_key(handle).await,
            Self::File(kc) => kc.export_ed25519_signing_key(handle).await,
            Self::Callback(kc) => kc.export_ed25519_signing_key(handle).await,
        }
    }
}

// ---------------------------------------------------------------------------
// PyCallbackKeyCustody — concrete `KeyCustody` adapter over a Python provider
//
// Bridges the gap between scp-platform's `KeyCustody` trait (RPITIT, not
// object-safe) and the object-safe `PyKeyCustodyProvider`. Mirrors the UniFFI
// bridge's `CallbackKeyCustody`. Translates the typed scp-platform API
// (KeyHandle / Signature / PublicKey / SharedSecret) to/from the provider's
// raw byte and opaque-string protocol. See ADR-006.
// ---------------------------------------------------------------------------

/// Concrete [`KeyCustody`] adapter delegating to a [`PyKeyCustodyProvider`].
///
/// The provider returns:
/// - `generate_keypair(key_type: str) -> str` — a numeric key-id string.
/// - `sign(key_id: str, message: bytes) -> bytes` — a 64-byte Ed25519 sig.
/// - `get_public_key(key_id: str) -> bytes` — 32 public-key bytes.
/// - `destroy_key(key_id: str) -> None`.
/// - `dh_agree(key_id: str, peer_public: bytes) -> bytes` — 32 shared bytes.
/// - `derive_pseudonym(key_id: str, context_id: bytes) -> bytes` —
///   `[public_key (32) || key_id_utf8]`.
/// - `derive_rotatable_pseudonym(key_id: str, context_id: bytes, pseudonym_epoch: int) -> bytes`
///   — `[public_key (32) || key_id_utf8]`. The provider performs the canonical
///   v2 derivation (HMAC key is the private-derived `pseudonym_secret`, domain
///   `"scp-pseudonym-v2"`); the bridge does NOT synthesize the preimage.
/// - `export_signing_key_bytes(key_id: str) -> bytes` — 32 private seed bytes.
/// - `custody_type(key_id: str) -> str` — `"hardware"` / `"software"` /
///   `"in_memory"`.
pub struct PyCallbackKeyCustody {
    provider: PyKeyCustodyProvider,
}

impl std::fmt::Debug for PyCallbackKeyCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PyCallbackKeyCustody([python])")
    }
}

impl PyCallbackKeyCustody {
    /// Wraps a validated [`PyKeyCustodyProvider`].
    #[must_use]
    pub const fn new(provider: PyKeyCustodyProvider) -> Self {
        Self { provider }
    }

    /// Exports the raw Ed25519 signing key via the provider's
    /// `export_signing_key_bytes`.
    ///
    /// `async` for signature uniformity with the [`FfiKeyCustody`] enum
    /// dispatch (the `InMemory` / `File` arms are genuinely async); the
    /// `PyO3` callback path re-acquires the GIL synchronously under the hood.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if the provider raises or
    /// returns a non-32-byte value.
    #[allow(clippy::unused_async)]
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ed25519_dalek::SigningKey, PlatformError> {
        // Private seed material: wrap in `Zeroizing` the moment it crosses
        // back from Python so the heap buffer is wiped on drop (ADR-006).
        let bytes: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
            self.provider
                .call_str("export_signing_key_bytes", &handle.id().to_string())?,
        );
        let arr = zeroize::Zeroizing::new(scp_ffi_common::custody_parse::expect_32(
            "export_signing_key_bytes",
            &bytes,
        )?);
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }
}

impl KeyCustody for PyCallbackKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        let type_str = match key_type {
            KeyType::Ed25519 => "ed25519".to_owned(),
            KeyType::X25519 => "x25519".to_owned(),
        };
        let key_id: String = self.provider.call_str("generate_keypair", &type_str)?;
        scp_ffi_common::custody_parse::parse_handle("generate_keypair", &key_id)
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        let sig: Vec<u8> = self
            .provider
            .call_str_bytes("sign", &key.id().to_string(), data)?;
        Ok(Signature::new(sig))
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        let pk: Vec<u8> = self
            .provider
            .call_str("get_public_key", &key.id().to_string())?;
        Ok(PublicKey::new(pk))
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.provider
            .call_str_void("destroy_key", &key.id().to_string())
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        // Wrap the raw shared secret in `Zeroizing` so the intermediate heap
        // buffer is wiped on drop once it has been copied into `SharedSecret`
        // (defense-in-depth, matching `export_ed25519_signing_key`; ADR-006).
        let shared: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
            self.provider
                .call_str_bytes("dh_agree", &key.id().to_string(), peer_public)?,
        );
        Ok(SharedSecret::new(scp_ffi_common::custody_parse::expect_32(
            "dh_agree", &shared,
        )?))
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError> {
        let bytes: Vec<u8> =
            self.provider
                .call_str_bytes("derive_pseudonym", &key.id().to_string(), context_id)?;
        scp_ffi_common::custody_parse::unpack_pseudonym("derive_pseudonym", &bytes)
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        // Canonical v2 recipe (spec §9.10.4.A / §9.10.4.1): the HMAC key is the
        // private-derived `pseudonym_secret` (HKDF over the Ed25519 private
        // seed), NEVER the public key. The provider performs the canonical
        // derivation itself — seed = HMAC-SHA256(pseudonym_secret, context_id ||
        // BE64(pseudonym_epoch) || "scp-pseudonym-v2"); keypair =
        // Ed25519_keygen(seed[0..32]). The epoch is passed through directly
        // rather than synthesized into the context_id bridge-side, so the v1
        // platform adapter does not re-append its own "scp-pseudonym" domain
        // separator (which would corrupt the v2 domain). Mirrors the UniFFI /
        // napi CallbackKeyCustody contract.
        let bytes: Vec<u8> = self.provider.call_str_bytes_u64(
            "derive_rotatable_pseudonym",
            &key.id().to_string(),
            context_id,
            pseudonym_epoch,
        )?;
        scp_ffi_common::custody_parse::unpack_pseudonym("derive_rotatable_pseudonym", &bytes)
    }

    async fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        // The Python callback protocol does not expose a distinct birational
        // conversion; the provider manages key types internally, so delegate
        // to dh_agree (mirrors the UniFFI CallbackKeyCustody contract).
        // Wrap the raw shared secret in `Zeroizing` so the intermediate heap
        // buffer is wiped on drop once it has been copied into `SharedSecret`
        // (defense-in-depth, matching `export_ed25519_signing_key`; ADR-006).
        let shared: zeroize::Zeroizing<Vec<u8>> =
            zeroize::Zeroizing::new(self.provider.call_str_bytes(
                "dh_agree",
                &ed25519_handle.id().to_string(),
                peer_x25519_public,
            )?);
        Ok(SharedSecret::new(scp_ffi_common::custody_parse::expect_32(
            "ed25519_to_x25519_agree",
            &shared,
        )?))
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        // Sync query; on any provider error fall back to the most conservative
        // classification (InMemory) rather than panicking across the FFI
        // boundary — matches the UniFFI adapter's lenient mapping.
        let type_str: Result<String, _> = self
            .provider
            .call_str("custody_type", &key.id().to_string());
        match type_str.as_deref() {
            Ok("hardware") => CustodyType::Hardware,
            Ok("software" | "software_biometric") => CustodyType::Software,
            _ => CustodyType::InMemory,
        }
    }

    async fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PlatformError> {
        // Generate the pre-rotation seed LOCALLY via OsRng — the bytes never
        // traverse the consumer's `KeyCustodyProvider` callback. The bridge
        // hands them straight to a `PreRotationCustody` instance (ADR-003
        // §4b). This is what makes identity CREATION work with callback
        // custody (the operational keys live in the provider; only the
        // pre-rotation seed is minted locally). Mirrors the UniFFI
        // `CallbackKeyCustody` contract.
        //
        // Storage-isolation status: type-level isolation holds (the seed
        // never enters the operational provider); substrate isolation
        // depends on the `PreRotationCustody` backend (currently in-memory).
        // HSM-bound platforms should instead route platform-CSPRNG bytes
        // directly into a `PreRotationCustody`, bypassing `KeyCustody`.
        use rand::RngCore;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Ok(seed)
    }

    async fn import_ed25519_signing_key(
        &self,
        seed: &zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<KeyHandle, PlatformError> {
        // Migration installs the revealed pre-rotation private bytes as the
        // NEW operational `#0` key. The `KeyCustodyProvider` callback protocol
        // has no "import a known seed → handle" method (only
        // `generate_keypair`, which mints a fresh random key), so this MUST
        // surface a clear error rather than failing deeper in the migration
        // flow. Identity CREATION via callback custody is unaffected — it
        // routes the pre-rotation seed through `PreRotationCustody`, never
        // touching the consumer callback. Mirrors the UniFFI contract.
        let _ = seed;
        Err(PlatformError::Unsupported(
            "callback KeyCustodyProvider cannot import pre-rotation seed bytes \
             (no import method on the protocol); identity creation is unaffected",
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use pyo3::types::PyModule;

    use super::*;

    /// Python source for a fake `KeyCustodyProvider` that exercises the
    /// `Callback` enum delegation using ONLY the stdlib (`hashlib`/`hmac`) —
    /// no `PyNaCl`/cryptography. The returned bytes are NOT a real Ed25519
    /// keypair (`sign` returns a deterministic 64-byte HMAC, `get_public_key` a
    /// 32-byte SHA-256), so this verifies the bridge WIRING — argument
    /// marshalling, return-shape unpacking, error mapping — independently of
    /// cryptographic validity (which the Python integration test covers
    /// end-to-end against `dht.create`). Mirrors the protocol contract
    /// documented on `PyCallbackKeyCustody`.
    const FAKE_PROVIDER_PY: &std::ffi::CStr = c"
import hashlib, hmac

class FakeCustody:
    def __init__(self):
        self._seeds = {}
        self._next = 1

    def generate_keypair(self, key_type):
        kid = str(self._next)
        self._next += 1
        self._seeds[kid] = hashlib.sha256(kid.encode()).digest()
        return kid

    def sign(self, key_id, message):
        return hmac.new(self._seeds[key_id], bytes(message), hashlib.sha512).digest()

    def get_public_key(self, key_id):
        return hashlib.sha256(self._seeds[key_id]).digest()

    def destroy_key(self, key_id):
        self._seeds.pop(key_id, None)

    def dh_agree(self, key_id, peer_public):
        return hmac.new(self._seeds[key_id], bytes(peer_public), hashlib.sha256).digest()

    def derive_pseudonym(self, key_id, context_id):
        d = hmac.new(self._seeds[key_id], bytes(context_id), hashlib.sha256).digest()
        kid = str(self._next)
        self._next += 1
        self._seeds[kid] = d
        return d + kid.encode('utf-8')

    def derive_rotatable_pseudonym(self, key_id, context_id, pseudonym_epoch):
        # Canonical v2 preimage: context_id || BE64(epoch) || 'scp-pseudonym-v2'.
        # The bridge passes the epoch through unmodified and does NOT append the
        # v1 'scp-pseudonym' separator, so this provider owns the full recipe.
        preimage = bytes(context_id) + pseudonym_epoch.to_bytes(8, 'big') + b'scp-pseudonym-v2'
        d = hmac.new(self._seeds[key_id], preimage, hashlib.sha256).digest()
        kid = str(self._next)
        self._next += 1
        self._seeds[kid] = d
        return d + kid.encode('utf-8')

    def export_signing_key_bytes(self, key_id):
        return self._seeds[key_id]

    def custody_type(self, key_id):
        return 'software'
";

    /// Builds a `FfiKeyCustody::Callback` wrapping a freshly-constructed
    /// stdlib-only `FakeCustody` Python instance.
    fn fake_callback_custody() -> FfiKeyCustody {
        Python::with_gil(|py| {
            let module =
                PyModule::from_code(py, FAKE_PROVIDER_PY, c"fake_custody.py", c"fake_custody")
                    .expect("fake provider module compiles");
            let cls = module.getattr("FakeCustody").expect("FakeCustody class");
            let obj = cls.call0().expect("FakeCustody instance");
            let provider = PyKeyCustodyProvider::new(py, obj.unbind()).expect("valid provider");
            FfiKeyCustody::Callback(PyCallbackKeyCustody::new(provider))
        })
    }

    #[tokio::test]
    async fn ffi_custody_callback_delegates_generate_sign_pubkey_type() {
        let custody = fake_callback_custody();
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("callback generate keypair");
        let pk = custody
            .public_key(&handle)
            .await
            .expect("callback public_key");
        assert_eq!(
            pk.as_bytes().len(),
            32,
            "fake provider returns 32 pubkey bytes"
        );
        let sig = custody
            .sign(&handle, b"test data")
            .await
            .expect("callback sign");
        assert_eq!(
            sig.as_bytes().len(),
            64,
            "fake provider returns 64 sig bytes"
        );
        assert_eq!(
            custody.custody_type(&handle),
            CustodyType::Software,
            "fake provider reports software custody"
        );
    }

    #[tokio::test]
    async fn ffi_custody_callback_derive_pseudonym_unpacks_handle() {
        let custody = fake_callback_custody();
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("callback generate keypair");
        let pseudo = custody
            .derive_pseudonym(&handle, b"context-xyz")
            .await
            .expect("callback derive_pseudonym");
        assert_eq!(
            pseudo.public_key.as_bytes().len(),
            32,
            "pseudonym public key is 32 bytes"
        );
        // The unpacked key handle must be usable for a follow-up sign — proves
        // the `[pubkey(32) || key_id_utf8]` return is unpacked correctly.
        let sig = custody
            .sign(&pseudo.key_handle, b"as pseudonym")
            .await
            .expect("sign with derived pseudonym handle");
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[tokio::test]
    async fn ffi_custody_callback_rotatable_pseudonym_threads_epoch() {
        // The rotatable path must call the provider's
        // `derive_rotatable_pseudonym(key_id, context_id, epoch)` directly,
        // passing the RAW context_id and the epoch as a separate argument — NOT
        // a bridge-synthesized `context_id || BE64(epoch) || "scp-pseudonym-v2"`
        // preimage fed into v1 `derive_pseudonym`. The fake provider computes
        // the canonical v2 preimage itself; this test reproduces that preimage
        // out-of-band and confirms the bridge delivered the exact same inputs.
        let custody = fake_callback_custody();
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("callback generate keypair");

        let context_id = b"context-xyz";
        let epoch: u64 = 7;
        let pseudo = custody
            .derive_rotatable_pseudonym(&handle, context_id, epoch)
            .await
            .expect("callback derive_rotatable_pseudonym");
        assert_eq!(
            pseudo.public_key.as_bytes().len(),
            32,
            "rotatable pseudonym public key is 32 bytes"
        );

        // Reproduce the fake provider's canonical v2 preimage. handle id 1 is the
        // first generate_keypair; its seed is SHA-256("1").
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        let seed = Sha256::digest(handle.id().to_string().as_bytes());
        let mut preimage = context_id.to_vec();
        preimage.extend_from_slice(&epoch.to_be_bytes());
        preimage.extend_from_slice(b"scp-pseudonym-v2");
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&seed).expect("HMAC accepts any key length");
        mac.update(&preimage);
        let expected_pubkey = mac.finalize().into_bytes();
        assert_eq!(
            pseudo.public_key.as_bytes(),
            expected_pubkey.as_slice(),
            "bridge must pass raw context_id + epoch (canonical v2), not a \
             double-domain-appended preimage"
        );

        // The unpacked handle must be usable for a follow-up sign.
        let sig = custody
            .sign(&pseudo.key_handle, b"as rotatable pseudonym")
            .await
            .expect("sign with derived rotatable pseudonym handle");
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[tokio::test]
    async fn ffi_custody_callback_import_is_unsupported() {
        let custody = fake_callback_custody();
        let seed = zeroize::Zeroizing::new([7u8; 32]);
        assert!(
            matches!(
                custody.import_ed25519_signing_key(&seed).await,
                Err(PlatformError::Unsupported(_))
            ),
            "callback custody must reject raw seed import (no protocol method)"
        );
    }

    #[tokio::test]
    async fn ffi_custody_callback_generates_ephemeral_seed_locally() {
        // The pre-rotation seed is minted locally via OsRng — NOT delegated to
        // the Python provider — so it succeeds even though the provider has no
        // ephemeral-seed method. This is what lets `dht.create` complete with
        // callback custody. Two draws must differ (CSPRNG, not constant).
        let custody = fake_callback_custody();
        let a = custody
            .generate_ephemeral_ed25519_seed()
            .await
            .expect("local ephemeral seed");
        let b = custody
            .generate_ephemeral_ed25519_seed()
            .await
            .expect("local ephemeral seed");
        assert_ne!(*a, *b, "OsRng-backed seeds must not repeat");
    }

    #[test]
    fn py_provider_rejects_missing_methods() {
        Python::with_gil(|py| {
            let module = PyModule::from_code(
                py,
                c"class Incomplete:\n    def sign(self, k, m):\n        return b''\n",
                c"incomplete.py",
                c"incomplete",
            )
            .expect("module compiles");
            let obj = module
                .getattr("Incomplete")
                .expect("class")
                .call0()
                .expect("instance")
                .unbind();
            let err = PyKeyCustodyProvider::new(py, obj)
                .expect_err("incomplete provider must be rejected");
            assert!(
                matches!(err, PlatformError::CustodyError(_)),
                "missing-method rejection is a CustodyError"
            );
        });
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn ffi_custody_in_memory_generates_and_signs() {
        let custody = FfiKeyCustody::InMemory(InMemoryKeyCustody::new());
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        let sig = custody.sign(&handle, b"test data").await.expect("sign");
        assert_eq!(sig.as_bytes().len(), 64, "Ed25519 signature is 64 bytes");
    }

    #[tokio::test]
    async fn ffi_custody_file_generates_and_signs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys.bin");
        let file_kc = FileKeyCustody::new(&path, "test-passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        let sig = custody.sign(&handle, b"test data").await.expect("sign");
        assert_eq!(sig.as_bytes().len(), 64, "Ed25519 signature is 64 bytes");
    }

    #[tokio::test]
    async fn ffi_custody_file_custody_type_is_software() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys_type.bin");
        let file_kc = FileKeyCustody::new(&path, "test-passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        assert_eq!(custody.custody_type(&handle), CustodyType::Software);
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn ffi_custody_in_memory_custody_type_is_in_memory() {
        let custody = FfiKeyCustody::InMemory(InMemoryKeyCustody::new());
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        assert_eq!(custody.custody_type(&handle), CustodyType::InMemory);
    }

    #[tokio::test]
    async fn ffi_custody_file_dh_agree_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys_dh.bin");
        let file_kc = FileKeyCustody::new(&path, "passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);

        let handle_a = custody
            .generate_keypair(KeyType::X25519)
            .await
            .expect("generate X25519 keypair A");
        let handle_b = custody
            .generate_keypair(KeyType::X25519)
            .await
            .expect("generate X25519 keypair B");

        let pub_b = custody.public_key(&handle_b).await.expect("public key B");
        let pub_b_bytes: [u8; 32] = pub_b.as_bytes().try_into().expect("32 bytes");

        let shared = custody
            .dh_agree(&handle_a, &pub_b_bytes)
            .await
            .expect("dh_agree");
        assert_eq!(shared.as_bytes().len(), 32, "shared secret is 32 bytes");
    }

    #[tokio::test]
    async fn ffi_custody_file_destroy_key_prevents_sign() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_keys_destroy.bin");
        let file_kc = FileKeyCustody::new(&path, "passphrase").expect("FileKeyCustody::new");
        let custody = FfiKeyCustody::File(file_kc);

        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair");
        custody.destroy_key(&handle).await.expect("destroy key");
        let result = custody.sign(&handle, b"test").await;
        assert!(result.is_err(), "signing with destroyed key should fail");
    }
}
