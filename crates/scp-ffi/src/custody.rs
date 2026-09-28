//! Enum dispatch for [`KeyCustody`] in the `PyO3` FFI bridge.
//!
//! The [`KeyCustody`] trait uses RPITIT (return-position `impl Trait` in trait),
//! which makes it NOT object-safe. This module provides [`FfiKeyCustody`], an
//! enum that wraps the concrete custody implementations used by the FFI bridge
//! and manually delegates each trait method to the active variant.
//!
//! # Variants
//!
//! - `InMemoryKeyCustody` — Test-harness nullifier. Keys exist only in memory
//!   and are lost when the process exits. Compiled ONLY under `scp-ffi`'s own
//!   `testing` feature, which is the sole place that forwards
//!   `scp-platform/testing` (ADR-062 §Decision 6); the variant does not exist
//!   in a shipped build.
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
#[allow(clippy::large_enum_variant)]
pub enum FfiKeyCustody {
    /// Test-harness in-memory custody (nullifier). Keys are lost on process
    /// exit. Compiled only under `scp-ffi`'s `testing` feature, the sole
    /// place forwarding `scp-platform/testing` — absent from a shipped build.
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

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.generate_identity_keypair().await,
            Self::File(kc) => kc.generate_identity_keypair().await,
            Self::Callback(kc) => kc.generate_identity_keypair().await,
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
        peer_public: &[u8],
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
/// owned Rust types. An exception whose `code` is `SCP-CRYPTO-4006` maps to
/// [`PlatformError::KeyNotFound`]; any other exception maps to
/// [`PlatformError::CustodyError`] carrying its code and text.
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
                .map_err(|e| Self::call_err(py, method_name, &e))?;
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
                .map_err(|e| Self::call_err(py, method_name, &e))?;
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
                .map_err(|e| Self::call_err(py, method_name, &e))?;
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
                .map_err(|e| Self::call_err(py, method_name, &e))?;
            Ok(())
        })
    }

    /// Maps a provider exception: the typed host not-found
    /// ([`KeyNotFoundError`](crate::error::KeyNotFoundError), exported as
    /// `scp_sdk.KeyNotFoundError`) is [`PlatformError::KeyNotFound`]; any
    /// other exception goes through the shared host-failure mapping, where a
    /// `code` attribute of `SCP-CRYPTO-4006` is key-not-found and anything
    /// else is a custody error carrying its code and text.
    fn call_err(py: Python<'_>, method_name: &str, e: &PyErr) -> PlatformError {
        if e.is_instance_of::<crate::error::KeyNotFoundError>(py) {
            return PlatformError::KeyNotFound;
        }
        let code = e
            .value(py)
            .getattr("code")
            .ok()
            .and_then(|c| c.extract::<String>().ok());
        scp_ffi_common::custody_parse::host_failure(method_name, code.as_deref(), &e.to_string())
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
/// - `generate_keypair(key_type: str) -> str` — a numeric key-id string;
///   `key_type` is `"ed25519"`, `"x25519"`, `"p256"` or `"hpke-p256"`.
/// - `sign(key_id: str, message: bytes) -> bytes` — a 64-byte Ed25519 sig;
///   for a `"p256"` key or a pseudonym key id, `message` is the 32-byte
///   digest and the result is raw `r ‖ s` or DER, which the bridge normalises
///   to low-`s` and verifies strictly under the key's registered point.
///   A software host MUST derive the ECDSA nonce by RFC 6979 with SHA-256; a
///   hardware host (Secure Enclave, `StrongBox`/TEE) may use a random nonce.
/// - `get_public_key(key_id: str) -> tuple[str, bytes]` — `(key_type,
///   public_key)`: the key's type (`"ed25519"`, `"x25519"`, `"p256"` or
///   `"hpke-p256"`; a pseudonym key is `"p256"`) and its public key, exactly
///   32 bytes (Ed25519 / X25519), 33 (compressed SEC1, `"p256"`) or 65
///   (uncompressed SEC1, `"hpke-p256"`). The bridge types the key from
///   `key_type`, never from the length, and refuses any other length.
/// - Any method raises `scp_sdk.KeyNotFoundError`, or any exception whose
///   `code` is `SCP-CRYPTO-4006`, for a key id the host does not hold; the
///   bridge reports it as `KeyNotFound`. Any other exception is a custody
///   error (`SCP-CRYPTO-4060`) carrying its code and text.
/// - `destroy_key(key_id: str) -> None`.
/// - `dh_agree(key_id: str, peer_public: bytes) -> bytes` — 32 shared bytes;
///   an `"hpke-p256"` key receives the 65-byte uncompressed peer point.
/// - `derive_pseudonym(key_id: str, context_id: bytes) -> tuple[bytes, str]` —
///   `(public_key, key_id)`: the 33-byte compressed P-256 point and the key id
///   of its signing key, whose `get_public_key` must return the same point.
/// - `derive_rotatable_pseudonym(key_id: str, context_id: bytes, pseudonym_epoch: int) -> tuple[bytes, str]`
///   — `(public_key, key_id)`, checked as above. The provider performs the canonical
///   v2 derivation (HMAC key is the private-derived `pseudonym_secret`, domain
///   `"scp-pseudonym-v2"`); the bridge does NOT synthesize the preimage.
/// - `export_signing_key_bytes(key_id: str) -> bytes` — 32 private seed bytes.
/// - `custody_type(key_id: str) -> str` — `"hardware"` / `"software"` /
///   `"in_memory"`.
pub struct PyCallbackKeyCustody {
    provider: PyKeyCustodyProvider,
    /// Every handle's type, role and life-cycle state, resolved through the
    /// host's structured `get_public_key` for handles this adapter did not
    /// mint.
    registry: scp_ffi_common::callback_custody::CallbackKeyRegistry,
}

impl PyKeyCustodyProvider {
    /// `get_public_key(key_id)` as the structured `(key_type, public_key)`
    /// answer the shared flows take.
    fn host_public_key(
        &self,
        key_id: &str,
    ) -> std::future::Ready<Result<scp_ffi_common::callback_custody::HostPublicKey, PlatformError>>
    {
        std::future::ready(
            self.call_str::<(String, Vec<u8>)>("get_public_key", key_id)
                .map(
                    |(key_type, public_key)| scp_ffi_common::callback_custody::HostPublicKey {
                        key_type,
                        public_key,
                    },
                ),
        )
    }
}

impl std::fmt::Debug for PyCallbackKeyCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PyCallbackKeyCustody([python])")
    }
}

impl PyCallbackKeyCustody {
    /// Wraps a validated [`PyKeyCustodyProvider`].
    #[must_use]
    pub fn new(provider: PyKeyCustodyProvider) -> Self {
        Self {
            provider,
            registry: scp_ffi_common::callback_custody::CallbackKeyRegistry::new(),
        }
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
    /// [`PlatformError::WrongKeyType`] for a handle of another type, before
    /// any export call; [`PlatformError::KeyNotFound`] for a handle the host
    /// does not hold; [`PlatformError::CustodyError`] if the provider raises
    /// or returns a non-32-byte value.
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ed25519_dalek::SigningKey, PlatformError> {
        let p = &self.provider;
        scp_ffi_common::callback_custody::require_ed25519(&self.registry, handle, |key_id| {
            p.host_public_key(&key_id)
        })
        .await?;
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

impl PyCallbackKeyCustody {
    /// Mints a key of `key_type` in `role` through the shared flow.
    async fn generate(
        &self,
        key_type: KeyType,
        role: scp_ffi_common::callback_custody::KeyRole,
    ) -> Result<KeyHandle, PlatformError> {
        let p = &self.provider;
        scp_ffi_common::callback_custody::generate_keypair(
            &self.registry,
            key_type,
            role,
            |type_str| std::future::ready(p.call_str("generate_keypair", type_str)),
            |key_id| p.host_public_key(&key_id),
            |key_id| std::future::ready(p.call_str_void("destroy_key", &key_id)),
        )
        .await
    }
}

impl KeyCustody for PyCallbackKeyCustody {
    // The shared flows in `scp_ffi_common::callback_custody` hold every
    // key-type, length, role and signature rule; each closure is one
    // synchronous provider call (the GIL is taken inside `call_*`). Every
    // entry point resolves a handle this adapter has not registered through
    // `get_public_key`.
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        self.generate(
            key_type,
            scp_ffi_common::callback_custody::KeyRole::Operational,
        )
        .await
    }

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        self.generate(
            KeyType::Ed25519,
            scp_ffi_common::callback_custody::KeyRole::Identity,
        )
        .await
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        let p = &self.provider;
        scp_ffi_common::callback_custody::sign(
            &self.registry,
            key,
            data,
            |key_id, data| std::future::ready(p.call_str_bytes("sign", &key_id, &data)),
            |key_id| p.host_public_key(&key_id),
        )
        .await
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        let p = &self.provider;
        scp_ffi_common::callback_custody::public_key(&self.registry, key, |key_id| {
            p.host_public_key(&key_id)
        })
        .await
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        let p = &self.provider;
        scp_ffi_common::callback_custody::destroy_key(&self.registry, key, |key_id| {
            std::future::ready(p.call_str_void("destroy_key", &key_id))
        })
        .await
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> Result<SharedSecret, PlatformError> {
        let p = &self.provider;
        scp_ffi_common::callback_custody::dh_agree(
            &self.registry,
            key,
            peer_public,
            |key_id, peer| std::future::ready(p.call_str_bytes("dh_agree", &key_id, &peer)),
            |key_id| p.host_public_key(&key_id),
        )
        .await
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError> {
        let p = &self.provider;
        scp_ffi_common::callback_custody::derive_pseudonym(
            &self.registry,
            "derive_pseudonym",
            key,
            context_id,
            None,
            |key_id| std::future::ready(p.call_str_bytes("derive_pseudonym", &key_id, context_id)),
            |key_id| p.host_public_key(&key_id),
        )
        .await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        // Canonical v2 recipe (spec §9.10.4.A / §9.10.4.1): the HMAC key is the
        // private-derived `pseudonym_secret` (HKDF over the identity private
        // seed), NEVER the public key. The provider performs the canonical
        // derivation itself — seed = HMAC-SHA256(pseudonym_secret, context_id ||
        // BE64(pseudonym_epoch) || "scp-pseudonym-v2"); d =
        // seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed), returned as the 33-byte
        // compressed P-256 point. The epoch is passed through directly
        // rather than synthesized into the context_id bridge-side, so the v1
        // platform adapter does not re-append its own "scp-pseudonym" domain
        // separator (which would corrupt the v2 domain). Mirrors the UniFFI /
        // napi CallbackKeyCustody contract.
        let p = &self.provider;
        scp_ffi_common::callback_custody::derive_pseudonym(
            &self.registry,
            "derive_rotatable_pseudonym",
            key,
            context_id,
            Some(pseudonym_epoch),
            |key_id| {
                std::future::ready(p.call_str_bytes_u64(
                    "derive_rotatable_pseudonym",
                    &key_id,
                    context_id,
                    pseudonym_epoch,
                ))
            },
            |key_id| p.host_public_key(&key_id),
        )
        .await
    }

    async fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        // The Python callback protocol does not expose a distinct birational
        // conversion; the provider manages key types internally, so delegate
        // to dh_agree (mirrors the UniFFI CallbackKeyCustody contract) once
        // the handle resolves to an Ed25519 key.
        let p = &self.provider;
        scp_ffi_common::callback_custody::require_ed25519(&self.registry, ed25519_handle, |id| {
            p.host_public_key(&id)
        })
        .await?;
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
        // depends on the `PreRotationCustody` backend, and no such backend
        // ships — the only implementation is the `testing`-gated
        // `InMemoryPreRotationCustody` nullifier, so a shipped build fails
        // closed with `SCP-IDENT-1059` instead (#1729 / RFC #2130 track the
        // real backends). HSM-bound platforms should route platform-CSPRNG
        // bytes directly into a `PreRotationCustody`, bypassing `KeyCustody`.
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

/// A stdlib-only fake Python `KeyCustodyProvider`, shared by this module's
/// tests and the `context` bridge tests.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod test_fakes {
    use pyo3::types::PyModule;

    use super::*;

    /// Python source for a fake `KeyCustodyProvider` using ONLY the stdlib
    /// (`hashlib`/`hmac`), no `PyNaCl`/cryptography. Ed25519 keys are real
    /// RFC 8032 keypairs over the seed `SHA-256(key_id)`, because the bridge
    /// verifies every Ed25519 host signature strictly. Pseudonym keys are
    /// real P-256 keys: the bridge validates the point, binds it to
    /// `get_public_key(key_id)`, and verifies every pseudonym signature
    /// strictly, so the fake runs the §9.10.4 seed-to-scalar step over its
    /// context seed and signs digests with a compact affine P-256. An unknown
    /// key id raises `KeyNotFoundError` (injected by [`fake_py_custody_of`]).
    /// `fault` makes one path misbehave in one named way: `legacy32`,
    /// `wrong_public_key`, `high_s` or `junk_sig` (pseudonyms), `ed_junk_sig`
    /// (64 junk bytes from an Ed25519 `sign`), `transport` (`sign` raises
    /// `ConnectionError`), or `fixed_id` (every pseudonym gets id 777).
    /// Pseudonym key ids are deterministic per (identity key id, context,
    /// epoch), as the provider contract requires.
    const FAKE_PROVIDER_PY: &std::ffi::CStr = c"
import hashlib, hmac

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] - 3) * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)

def mul(k, p):
    acc = None
    while k:
        if k & 1:
            acc = add(acc, p)
        p = add(p, p)
        k >>= 1
    return acc

Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, -1, Q) % Q

def ed_add(p, q):
    t = ED_D * p[0] * q[0] * p[1] * q[1] % Q
    return ((p[0] * q[1] + q[0] * p[1]) * pow(1 + t, -1, Q) % Q,
            (p[1] * q[1] + p[0] * q[0]) * pow(1 - t, -1, Q) % Q)

def ed_mul(k, p):
    acc = (0, 1)
    while k:
        if k & 1:
            acc = ed_add(acc, p)
        p = ed_add(p, p)
        k >>= 1
    return acc

def ed_base():
    y = 4 * pow(5, -1, Q) % Q
    xx = (y * y - 1) * pow(ED_D * y * y + 1, -1, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q:
        x = x * pow(2, (Q - 1) // 4, Q) % Q
    if x & 1:
        x = Q - x
    return (x, y)

ED_B = ed_base()

def ed_enc(p):
    return (p[1] | ((p[0] & 1) << 255)).to_bytes(32, 'little')

def ed_expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little') & ((1 << 254) - 8) | (1 << 254)
    return a, h[32:]

def ed_public(seed):
    return ed_enc(ed_mul(ed_expand(seed)[0], ED_B))

def ed_sign(seed, m):
    a, prefix = ed_expand(seed)
    pub = ed_enc(ed_mul(a, ED_B))
    r = int.from_bytes(hashlib.sha512(prefix + m).digest(), 'little') % L
    big_r = ed_enc(ed_mul(r, ED_B))
    k = int.from_bytes(hashlib.sha512(big_r + pub + m).digest(), 'little') % L
    return big_r + ((r + k * a) % L).to_bytes(32, 'little')

def compressed(d):
    x, y = mul(d, G)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')

def seed_to_scalar(seed):
    okm, block, i = b'', b'', 1
    while len(okm) < 48:
        block = hmac.new(seed, block + b'SCP-PSEUDONYM-P256-V1' + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return int.from_bytes(okm[:48], 'big') % (N - 1) + 1

def sign_prehash(d, digest, high_s):
    z = int.from_bytes(digest, 'big')
    k = int.from_bytes(hmac.new(d.to_bytes(32, 'big'), digest, hashlib.sha256).digest(), 'big') % (N - 1) + 1
    r = mul(k, G)[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    if (s > N // 2) != high_s:
        s = N - s
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

class HostError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code

class FakeCustody:
    def __init__(self, fault=None):
        self._seeds = {}
        self._key_types = {}
        self._pseudonyms = {}
        self._next = 1
        self._fault = fault
        self.calls = {}

    def _count(self, method):
        self.calls[method] = self.calls.get(method, 0) + 1

    def _seed(self, key_id):
        if key_id not in self._seeds:
            raise KeyNotFoundError(key_id)
        return self._seeds[key_id]

    def generate_keypair(self, key_type):
        self._count('generate_keypair')
        kid = str(self._next)
        self._next += 1
        self._seeds[kid] = hashlib.sha256(kid.encode()).digest()
        self._key_types[kid] = key_type
        return kid

    def sign(self, key_id, message):
        self._count('sign')
        if self._fault == 'transport':
            raise ConnectionError('custody service unreachable')
        if self._fault == 'sign_4001':
            raise HostError('hsm offline', 'SCP-CRYPTO-4001')
        if key_id not in self._pseudonyms and key_id not in self._seeds:
            raise HostError('key not found: ' + key_id, 'SCP-CRYPTO-4006')
        if key_id in self._pseudonyms:
            if self._fault == 'junk_sig':
                return bytes([0x11]) * 64
            return sign_prehash(self._pseudonyms[key_id], bytes(message), self._fault == 'high_s')
        seed = self._seed(key_id)
        if self._fault == 'ed_junk_sig':
            return bytes([0x22]) * 64
        return ed_sign(seed, bytes(message))

    def get_public_key(self, key_id):
        self._count('get_public_key')
        if key_id in self._pseudonyms:
            point = compressed(self._pseudonyms[key_id])
            if self._fault == 'wrong_public_key':
                point = bytes([point[0] ^ 1]) + point[1:]
            return ('p256', point)
        seed = self._seed(key_id)
        if self._key_types[key_id] == 'x25519':
            return ('x25519', hashlib.sha256(seed).digest())
        return ('ed25519', ed_public(seed))

    def destroy_key(self, key_id):
        self._count('destroy_key')
        probe = getattr(self, 'probe', None)
        if probe is not None:
            probe(key_id)
        self._seeds.pop(key_id, None)
        self._pseudonyms.pop(key_id, None)

    def dh_agree(self, key_id, peer_public):
        self._count('dh_agree')
        return hmac.new(self._seed(key_id), bytes(peer_public), hashlib.sha256).digest()

    def _register(self, key_id, seed, context_id, epoch_tag):
        if self._fault == 'legacy32':
            return (hashlib.sha256(seed).digest(), key_id)
        if self._fault == 'fixed_id':
            kid = '777'
        else:
            tag = hashlib.sha256(b'fake-pseudonym-key-id' + key_id.encode() + b'|'
                                 + bytes(context_id) + epoch_tag).digest()
            kid = str(int.from_bytes(tag[:8], 'big'))
        self._pseudonyms[kid] = seed_to_scalar(seed)
        return (compressed(self._pseudonyms[kid]), kid)

    def derive_pseudonym(self, key_id, context_id):
        self._count('derive_pseudonym')
        seed = hmac.new(self._seed(key_id), bytes(context_id), hashlib.sha256).digest()
        return self._register(key_id, seed, context_id, b'v1')

    def derive_rotatable_pseudonym(self, key_id, context_id, pseudonym_epoch):
        # Canonical v2 preimage: context_id || BE64(epoch) || 'scp-pseudonym-v2'.
        # The bridge passes the epoch through unmodified and does NOT append the
        # v1 'scp-pseudonym' separator, so this provider owns the full recipe.
        self._count('derive_rotatable_pseudonym')
        preimage = bytes(context_id) + pseudonym_epoch.to_bytes(8, 'big') + b'scp-pseudonym-v2'
        seed = hmac.new(self._seed(key_id), preimage, hashlib.sha256).digest()
        return self._register(key_id, seed, context_id, b'v2' + pseudonym_epoch.to_bytes(8, 'big'))

    def export_signing_key_bytes(self, key_id):
        self._count('export_signing_key_bytes')
        return self._seed(key_id)

    def custody_type(self, key_id):
        return 'software'

# P-256 generator coordinates and group order (SEC 2).
G_COMPRESSED = compressed(1)
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def der_int(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, 'big')
    if b[0] & 0x80:
        b = bytes([0]) + b
    return bytes([2, len(b)]) + b

class P256Custody(FakeCustody):
    '''Every P-256 key is d = 1 (public key G) and signs with nonce k = 1, so
    r = Gx and s = z + r mod n. `sign` returns DER with the HIGH s, the form
    a platform keystore may emit; the bridge must return raw low-s.'''

    def __init__(self, fault=None):
        super().__init__(fault)
        self._types = {}
        self.dh_peers = []

    def generate_keypair(self, key_type):
        kid = super().generate_keypair(key_type)
        self._types[kid] = key_type
        return kid

    def get_public_key(self, key_id):
        t = self._types.get(key_id)
        if t == 'p256':
            return ('p256', G_COMPRESSED)
        if t == 'hpke-p256':
            return ('hpke-p256', bytes([4]) + GX.to_bytes(32, 'big') + GY.to_bytes(32, 'big'))
        return super().get_public_key(key_id)

    def sign(self, key_id, message):
        if self._types.get(key_id) != 'p256':
            return super().sign(key_id, message)
        self._count('sign')
        s = (int.from_bytes(bytes(message), 'big') + GX) % N
        high_s = s if s > N // 2 else N - s
        body = der_int(GX) + der_int(high_s)
        return bytes([0x30, len(body)]) + body

    def dh_agree(self, key_id, peer_public):
        if self._types.get(key_id) != 'hpke-p256':
            return super().dh_agree(key_id, peer_public)
        self._count('dh_agree')
        peer = bytes(peer_public)
        self.dh_peers.append(peer)
        # d = 1: the shared secret is the peer's x-coordinate.
        return peer[1:33]

class BadP256Custody(P256Custody):
    '''Returns a 32-byte public key and an unverifiable signature for P-256.'''

    def get_public_key(self, key_id):
        if self._types.get(key_id) == 'hpke-p256':
            return ('hpke-p256', bytes([7]) * 32)
        return super().get_public_key(key_id)

    def sign(self, key_id, message):
        if self._types.get(key_id) == 'p256':
            return bytes([1]) * 64
        return super().sign(key_id, message)

# SEC 2 P-256 point 2G, SEC1-compressed (the Rust test checks this constant).
TWO_G_COMPRESSED = bytes.fromhex('037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978')

class WrongLengthCustody(P256Custody):
    '''Returns a wrong length from every host call the bridge checks: a
    33-byte X25519 shared secret, a 72-byte Ed25519 signature, a 31-byte
    Ed25519 public key, and, after a P-256 key is generated (public key G),
    a different valid point (2G) for it.'''

    def __init__(self):
        super().__init__()
        self._served = set()

    def dh_agree(self, key_id, peer_public):
        return bytes([3]) * 33

    def sign(self, key_id, message):
        if self._types.get(key_id) == 'ed25519':
            return bytes([5]) * 72
        return super().sign(key_id, message)

    def get_public_key(self, key_id):
        t = self._types.get(key_id)
        if t == 'ed25519':
            return ('ed25519', bytes([6]) * 31)
        if t == 'p256':
            if key_id in self._served:
                return ('p256', TWO_G_COMPRESSED)
            self._served.add(key_id)
        return super().get_public_key(key_id)
";

    /// Builds a `PyCallbackKeyCustody` over a fresh `FakeCustody(fault)`.
    pub fn fake_py_custody(fault: Option<&str>) -> PyCallbackKeyCustody {
        fake_py_custody_of(c"FakeCustody", fault)
    }

    /// Builds a `PyCallbackKeyCustody` over a fresh instance of the named
    /// class from [`FAKE_PROVIDER_PY`], passing `fault` when it is set.
    pub fn fake_py_custody_of(class: &std::ffi::CStr, fault: Option<&str>) -> PyCallbackKeyCustody {
        fake_py_host_of(class, fault).0
    }

    /// [`fake_py_custody`], also returning the `FakeCustody` object so a test
    /// can set attributes on it, such as the `probe` its `destroy_key` calls.
    pub fn fake_py_custody_and_host(fault: Option<&str>) -> (PyCallbackKeyCustody, Py<PyAny>) {
        fake_py_host_of(c"FakeCustody", fault)
    }

    /// [`fake_py_custody_of`], also returning the host object.
    fn fake_py_host_of(
        class: &std::ffi::CStr,
        fault: Option<&str>,
    ) -> (PyCallbackKeyCustody, Py<PyAny>) {
        Python::with_gil(|py| {
            let module =
                PyModule::from_code(py, FAKE_PROVIDER_PY, c"fake_custody.py", c"fake_custody")
                    .expect("fake provider module compiles");
            module
                .setattr(
                    "KeyNotFoundError",
                    py.get_type::<crate::error::KeyNotFoundError>(),
                )
                .expect("inject KeyNotFoundError");
            let cls = module
                .getattr(class.to_str().expect("utf-8 class name"))
                .expect("fake provider class");
            let obj = fault
                .map_or_else(|| cls.call0(), |fault| cls.call1((fault,)))
                .expect("fake provider instance")
                .unbind();
            let provider =
                PyKeyCustodyProvider::new(py, obj.clone_ref(py)).expect("valid provider");
            (PyCallbackKeyCustody::new(provider), obj)
        })
    }

    /// The fake's context seed for identity key id `key_id`, v1 or v2.
    pub fn fake_context_seed(key_id: u64, context_id: &[u8], epoch: Option<u64>) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        let identity_seed = Sha256::digest(key_id.to_string().as_bytes());
        let mut preimage = context_id.to_vec();
        if let Some(epoch) = epoch {
            preimage.extend_from_slice(&epoch.to_be_bytes());
            preimage.extend_from_slice(b"scp-pseudonym-v2");
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&identity_seed)
            .expect("HMAC accepts any key length");
        mac.update(&preimage);
        mac.finalize().into_bytes().into()
    }

    /// How many calls to `method` reached the fake behind `custody`.
    pub fn fake_calls(custody: &PyCallbackKeyCustody, method: &str) -> usize {
        Python::with_gil(|py| {
            custody
                .provider
                .obj
                .bind(py)
                .getattr("calls")
                .and_then(|calls| calls.call_method1("get", (method, 0)))
                .and_then(|n| n.extract())
                .expect("fake call count")
        })
    }

    /// Drops `key_id` inside the fake itself, behind the adapter's back.
    pub fn fake_forget(custody: &PyCallbackKeyCustody, key_id: u64) {
        Python::with_gil(|py| {
            custody
                .provider
                .obj
                .bind(py)
                .call_method1("destroy_key", (key_id.to_string(),))
                .expect("fake destroy");
        });
    }

    /// The compressed pseudonym point the fake returns for a context seed.
    pub fn fake_pseudonym_point(context_seed: &[u8; 32]) -> [u8; 33] {
        scp_crypto::p256::P256SigningKey::from_seed(b"SCP-PSEUDONYM-P256-V1", context_seed)
            .expect("seed_to_scalar is total")
            .public_key()
            .to_compressed()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::test_fakes::{
        fake_calls, fake_context_seed, fake_forget, fake_pseudonym_point, fake_py_custody,
        fake_py_custody_of,
    };
    use super::*;

    /// A `FfiKeyCustody::Callback` over a fresh instance of the named fake.
    fn fake_callback_custody_of(class: &std::ffi::CStr) -> FfiKeyCustody {
        FfiKeyCustody::Callback(fake_py_custody_of(class, None))
    }

    /// Builds a `FfiKeyCustody::Callback` wrapping a fresh fault-free fake.
    fn fake_callback_custody() -> FfiKeyCustody {
        FfiKeyCustody::Callback(fake_py_custody(None))
    }

    #[tokio::test]
    async fn ffi_custody_callback_p256_der_high_s_normalises_to_raw_low_s() {
        use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
        let custody = fake_callback_custody_of(c"P256Custody");
        let handle = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .expect("callback generate p256");
        let pk = custody.public_key(&handle).await.expect("public_key");
        assert_eq!(pk.as_bytes().len(), 33);
        let pk = P256PublicKey::from_sec1(pk.as_bytes()).expect("valid point");

        for digest in [[0x5au8; 32], [0xF0u8; 32], [0u8; 32]] {
            let sig = custody.sign(&handle, &digest).await.expect("p256 sign");
            assert_eq!(
                sig.as_bytes().len(),
                64,
                "the host's DER signature must come back as raw r || s"
            );
            verify_prehash_strict(&pk, &digest, sig.as_bytes())
                .expect("the normalised signature verifies strictly (low-s)");
        }
        // Not a 32-byte digest: refused before any host call.
        assert!(matches!(
            custody.sign(&handle, b"not a digest").await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(matches!(
            custody.dh_agree(&handle, &pk.to_uncompressed()).await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::HpkeP256,
                actual: KeyType::P256Signing
            })
        ));
        custody.destroy_key(&handle).await.expect("destroy");
    }

    #[tokio::test]
    async fn ffi_custody_callback_hpke_p256_dh_agree_validates_peer() {
        use scp_crypto::p256::{P256PublicKey, P256SigningKey, ecdh_p256};
        let custody = fake_callback_custody_of(c"P256Custody");
        let handle = custody
            .generate_keypair(KeyType::HpkeP256)
            .await
            .expect("callback generate hpke-p256");
        let own = custody.public_key(&handle).await.expect("public_key");
        assert_eq!(own.as_bytes().len(), 65);
        let own = P256PublicKey::from_sec1(own.as_bytes()).expect("valid point");

        // The fake's key is d = 1, so ecdh_p256(peer, G) is the peer's x.
        let peer = P256SigningKey::from_scalar_bytes(&[9u8; 32]).expect("scalar");
        let shared = custody
            .dh_agree(&handle, &peer.public_key().to_uncompressed())
            .await
            .expect("dh_agree with an uncompressed peer");
        assert_eq!(shared.as_bytes(), &*ecdh_p256(&peer, &own));

        // Only the 65-byte uncompressed point is accepted (RFC 9180 §7.1.1).
        let compressed = peer.public_key().to_compressed();
        let mut off_curve = peer.public_key().to_uncompressed();
        off_curve[64] ^= 1;
        for bad in [&compressed[..], &off_curve[..], &[9u8; 32][..], &[][..]] {
            assert!(matches!(
                custody.dh_agree(&handle, bad).await,
                Err(PlatformError::CustodyError(_))
            ));
        }
        assert!(matches!(
            custody.sign(&handle, &[0u8; 32]).await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::P256Signing,
                actual: KeyType::HpkeP256
            })
        ));
    }

    #[tokio::test]
    async fn ffi_custody_callback_rejects_bad_p256_host_returns() {
        let custody = fake_callback_custody_of(c"BadP256Custody");
        // A 32-byte public key for an hpke-p256 key fails generation.
        assert!(matches!(
            custody.generate_keypair(KeyType::HpkeP256).await,
            Err(PlatformError::CustodyError(_))
        ));
        // A signature that does not verify is an error, never a value.
        let handle = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .expect("p256 key with a valid public key");
        assert!(matches!(
            custody.sign(&handle, &[1u8; 32]).await,
            Err(PlatformError::CustodyError(_))
        ));
    }

    /// A10: every wrong-length or changed host return reaching the shared
    /// flows is a `CustodyError`, never a value.
    #[tokio::test]
    async fn ffi_custody_callback_rejects_wrong_length_host_returns() {
        use scp_crypto::p256::P256SigningKey;
        let mut two = [0u8; 32];
        two[31] = 2;
        let two_g = hex::encode(
            P256SigningKey::from_scalar_bytes(&two)
                .expect("2 is a valid scalar")
                .public_key()
                .to_compressed(),
        );
        assert_eq!(
            two_g, "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            "the fake's changed key must be a valid point, so only the change is rejected"
        );

        let custody = fake_callback_custody_of(c"WrongLengthCustody");
        let x = custody
            .generate_keypair(KeyType::X25519)
            .await
            .expect("x25519 key");
        assert!(matches!(
            custody.dh_agree(&x, &[9u8; 32]).await,
            Err(PlatformError::CustodyError(_))
        ));

        // A 31-byte Ed25519 public key fails generation itself, and the
        // rejected host key is destroyed rather than orphaned.
        let FfiKeyCustody::Callback(inner) = &custody else {
            unreachable!("callback custody")
        };
        let destroys = fake_calls(inner, "destroy_key");
        match custody.generate_keypair(KeyType::Ed25519).await {
            Err(PlatformError::CustodyError(_)) => {}
            other => panic!("expected CustodyError, got {other:?}"),
        }
        assert_eq!(fake_calls(inner, "destroy_key"), destroys + 1);

        // Generation sees G; every later fetch returns 2G.
        let p = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .expect("p256 key validated against G at generation");
        assert!(matches!(
            custody.public_key(&p).await,
            Err(PlatformError::CustodyError(_))
        ));
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

    /// v1: the bridge returns the host's exact point and key id, binds the
    /// handle, and a 32-byte digest signed through it verifies strictly.
    #[tokio::test]
    async fn ffi_custody_callback_derive_pseudonym_returns_host_point() {
        let custody = fake_callback_custody();
        let handle = custody
            .generate_identity_keypair()
            .await
            .expect("callback generate keypair");
        let pseudo = custody
            .derive_pseudonym(&handle, b"context-xyz")
            .await
            .expect("callback derive_pseudonym");
        let expected = fake_pseudonym_point(&fake_context_seed(handle.id(), b"context-xyz", None));
        assert_eq!(pseudo.public_key().as_bytes(), &expected);
        assert_eq!(
            pseudo.routing_id(),
            &scp_crypto::pseudonym::pseudonym_routing_id(&expected)
        );
        assert_ne!(pseudo.key_handle(), &handle, "a fresh pseudonym key id");

        let digest = [0x33u8; 32];
        let sig = custody
            .sign(pseudo.key_handle(), &digest)
            .await
            .expect("sign a digest with the pseudonym handle");
        let point = scp_crypto::p256::P256PublicKey::from_sec1(&expected).expect("point");
        scp_crypto::p256::verify_prehash_strict(&point, &digest, sig.as_bytes())
            .expect("strict signature under the bound point");
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
            .generate_identity_keypair()
            .await
            .expect("callback generate keypair");
        let pseudo = custody
            .derive_rotatable_pseudonym(&handle, b"context-xyz", 7)
            .await
            .expect("callback derive_rotatable_pseudonym");
        let expected =
            fake_pseudonym_point(&fake_context_seed(handle.id(), b"context-xyz", Some(7)));
        assert_eq!(
            pseudo.public_key().as_bytes(),
            &expected,
            "bridge must pass raw context_id + epoch (canonical v2), not a \
             double-domain-appended preimage"
        );
        let sig = custody
            .sign(pseudo.key_handle(), &[0x07u8; 32])
            .await
            .expect("sign with derived rotatable pseudonym handle");
        assert_eq!(sig.as_bytes().len(), 64);
    }

    /// A host exception whose `code` is `SCP-CRYPTO-4006` is key-not-found, and
    /// one whose `code` is the generic `SCP-CRYPTO-4001` is a custody error;
    /// the bridge reports them as `SCP-CRYPTO-4006` and `SCP-CRYPTO-4060`.
    #[tokio::test]
    async fn callback_host_exception_codes_map_to_typed_errors() {
        use scp_ffi_common::error_codes as codes;
        let custody = fake_callback_custody();
        let identity = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("identity key");
        let pseudonym = custody
            .derive_pseudonym(&identity, b"ctx")
            .await
            .expect("derive");
        custody
            .destroy_key(pseudonym.key_handle())
            .await
            .expect("destroy pseudonym");
        let err = custody
            .sign(pseudonym.key_handle(), &[0x42u8; 32])
            .await
            .expect_err("destroyed key");
        assert!(matches!(err, PlatformError::KeyNotFound), "{err:?}");
        match crate::error::ScpPyError::from(err) {
            crate::error::ScpPyError::CryptoError { code, .. } => {
                assert_eq!(code, codes::CRYPTO_4006);
            }
            other => panic!("expected CRYPTO_4006, got {other:?}"),
        }

        let custody = FfiKeyCustody::Callback(fake_py_custody(Some("sign_4001")));
        let identity = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("identity key");
        let err = custody
            .sign(&identity, b"message")
            .await
            .expect_err("host 4001");
        match &err {
            PlatformError::CustodyError(m) => {
                assert!(
                    m.contains(codes::CRYPTO_4001) && m.contains("hsm offline"),
                    "{m}"
                );
            }
            other => panic!("4001 must be a custody error, got {other:?}"),
        }
        match crate::error::ScpPyError::from(err) {
            crate::error::ScpPyError::CryptoError { code, .. } => {
                assert_eq!(code, codes::CRYPTO_4060);
            }
            other => panic!("expected CRYPTO_4060, got {other:?}"),
        }
    }

    /// Asserts that `err` is the `CustodyError` variant; tests assert the
    /// variant, never the message text.
    fn assert_custody_error(err: &PlatformError) {
        assert!(
            matches!(err, PlatformError::CustodyError(_)),
            "expected CustodyError, got {err:?}"
        );
    }

    /// A pseudonym handle signs only a 32-byte digest: 12 bytes is a
    /// `CustodyError` before the host is called, while the same handle signs
    /// a digest through the host.
    #[tokio::test]
    async fn ffi_custody_callback_pseudonym_sign_requires_digest() {
        let custody = fake_py_custody(None);
        let handle = custody.generate_identity_keypair().await.expect("key");
        let pseudo = custody
            .derive_pseudonym(&handle, b"ctx")
            .await
            .expect("derive");
        assert!(matches!(
            custody.sign(pseudo.key_handle(), b"as pseudonym").await,
            Err(PlatformError::CustodyError(_))
        ));
        assert_eq!(fake_calls(&custody, "sign"), 0, "refused before the host");
        custody
            .sign(pseudo.key_handle(), &[0x42u8; 32])
            .await
            .expect("a digest signs");
        assert_eq!(fake_calls(&custody, "sign"), 1);
    }

    /// B1: deriving the same pseudonym twice returns the same key id, which
    /// re-binds cleanly.
    #[tokio::test]
    async fn ffi_custody_callback_rederive_reuses_key_id() {
        let custody = fake_callback_custody();
        let handle = custody.generate_identity_keypair().await.expect("key");
        let first = custody
            .derive_pseudonym(&handle, b"ctx")
            .await
            .expect("first derive");
        let second = custody
            .derive_pseudonym(&handle, b"ctx")
            .await
            .expect("second derive re-binds");
        assert_eq!(first.key_handle(), second.key_handle());
        assert_eq!(first.routing_id(), second.routing_id());
    }

    /// B3: `destroy_key` retires the handle. A host that reuses key id 777
    /// for a second point is refused while the first is live, and accepted
    /// once the first is destroyed.
    #[tokio::test]
    async fn ffi_custody_callback_destroy_unbinds_pseudonym() {
        let custody = FfiKeyCustody::Callback(fake_py_custody(Some("fixed_id")));
        let handle = custody.generate_identity_keypair().await.expect("key");
        let first = custody
            .derive_pseudonym(&handle, b"ctx-a")
            .await
            .expect("first derive");
        assert_eq!(first.key_handle().id(), 777);
        assert_custody_error(
            &custody
                .derive_pseudonym(&handle, b"ctx-b")
                .await
                .expect_err("id 777 is bound to ctx-a's point"),
        );
        custody
            .destroy_key(first.key_handle())
            .await
            .expect("destroy");
        let second = custody
            .derive_pseudonym(&handle, b"ctx-b")
            .await
            .expect("re-derive under the freed id");
        assert_eq!(second.key_handle().id(), 777);
        assert_ne!(second.public_key(), first.public_key());
    }

    /// §9.15: destroying an identity retires every pseudonym derived from it
    /// in the adapter. The fake host's `destroy_key` drops only the identity,
    /// so a pseudonym still reaching the host would sign; the adapter answers
    /// `KeyNotFound` with no host call. A host that then reuses the retired
    /// id 777 for another identity's pseudonym binds it afresh. Removing the
    /// registry's identity sweep fails the first half.
    #[tokio::test]
    async fn ffi_custody_callback_identity_destroy_retires_its_pseudonyms() {
        let adapter = fake_py_custody(Some("fixed_id"));
        let identity = adapter.generate_identity_keypair().await.expect("key");
        let other = adapter.generate_identity_keypair().await.expect("key");
        let first = adapter
            .derive_pseudonym(&identity, b"ctx")
            .await
            .expect("derive");
        assert_eq!(first.key_handle().id(), 777);
        adapter.destroy_key(&identity).await.expect("destroy");
        let signs = fake_calls(&adapter, "sign");
        for result in [
            adapter
                .sign(first.key_handle(), &[0x42u8; 32])
                .await
                .map(drop),
            adapter.public_key(first.key_handle()).await.map(drop),
        ] {
            assert!(matches!(result, Err(PlatformError::KeyNotFound)));
        }
        assert_eq!(fake_calls(&adapter, "sign"), signs, "no host call");
        let second = adapter
            .derive_pseudonym(&other, b"ctx-b")
            .await
            .expect("the host reuses id 777");
        assert_eq!(second.key_handle().id(), 777);
        assert_ne!(second.public_key(), first.public_key());
        adapter
            .sign(second.key_handle(), &[0x42u8; 32])
            .await
            .expect("the new pseudonym signs");
    }

    /// D5: the adapter retires a pseudonym handle (`Destroying`) before it
    /// calls the host's `destroy_key`: a probe the host's `destroy_key` calls
    /// reads the adapter's registry and finds the handle no longer live.
    /// Calling the host first leaves the handle live during that call, and
    /// this fails.
    #[tokio::test]
    async fn ffi_custody_callback_unbinds_before_the_host_destroy() {
        use pyo3::types::{PyCFunction, PyDict, PyTuple};
        let (adapter, host) = super::test_fakes::fake_py_custody_and_host(None);
        let custody = std::sync::Arc::new(adapter);
        let bound_during_host_destroy = std::sync::Arc::new(std::sync::Mutex::new(None::<bool>));
        let (probe_adapter, probe_seen) = (
            std::sync::Arc::downgrade(&custody),
            bound_during_host_destroy.clone(),
        );
        Python::with_gil(|py| {
            let probe = PyCFunction::new_closure(
                py,
                None,
                None,
                move |args: &Bound<'_, PyTuple>, _kwargs: Option<&Bound<'_, PyDict>>| {
                    let (key_id,): (String,) = args.extract()?;
                    let custody = probe_adapter
                        .upgrade()
                        .expect("adapter is alive during destroy");
                    let handle = KeyHandle::new(key_id.parse().expect("numeric key id"));
                    *probe_seen.lock().expect("probe mutex") =
                        Some(custody.registry.is_live(&handle));
                    PyResult::Ok(())
                },
            )
            .expect("probe function");
            host.bind(py).setattr("probe", probe).expect("set probe");
        });

        let identity = custody
            .generate_identity_keypair()
            .await
            .expect("identity key");
        let pseudonym = custody
            .derive_pseudonym(&identity, b"ctx")
            .await
            .expect("derive");
        assert!(custody.registry.is_live(pseudonym.key_handle()));
        custody
            .destroy_key(pseudonym.key_handle())
            .await
            .expect("destroy");
        assert_eq!(
            *bound_during_host_destroy.lock().expect("probe mutex"),
            Some(false),
            "the host's destroy_key ran while the handle was still live"
        );
    }

    /// Each host misbehavior on the pseudonym path fails closed for its own
    /// reason: a 32-byte legacy key, a `get_public_key` that disagrees with the
    /// derived point, and a signature that does not verify. A high-`s`
    /// signature is valid ECDSA and comes out as its low-`s` form.
    #[tokio::test]
    async fn ffi_custody_callback_pseudonym_faults_fail_closed() {
        let custody = FfiKeyCustody::Callback(fake_py_custody(Some("legacy32")));
        let handle = custody.generate_identity_keypair().await.expect("key");
        assert_custody_error(
            &custody
                .derive_pseudonym(&handle, b"ctx")
                .await
                .expect_err("legacy 32-byte key"),
        );

        let custody = FfiKeyCustody::Callback(fake_py_custody(Some("wrong_public_key")));
        let handle = custody.generate_identity_keypair().await.expect("key");
        assert_custody_error(
            &custody
                .derive_pseudonym(&handle, b"ctx")
                .await
                .expect_err("public_key mismatch"),
        );

        let custody = FfiKeyCustody::Callback(fake_py_custody(Some("high_s")));
        let handle = custody.generate_identity_keypair().await.expect("key");
        let pseudo = custody
            .derive_pseudonym(&handle, b"ctx")
            .await
            .expect("derive");
        let digest = [0x11u8; 32];
        let sig: [u8; 64] = custody
            .sign(pseudo.key_handle(), &digest)
            .await
            .expect("a high-s host signature is normalised")
            .as_bytes()
            .try_into()
            .expect("raw r || s");
        let point = scp_crypto::p256::P256PublicKey::from_sec1(pseudo.public_key().as_bytes())
            .expect("point");
        assert_eq!(scp_crypto::p256::normalize_low_s(&sig).expect("valid"), sig);
        scp_crypto::p256::verify_prehash_strict(&point, &digest, &sig).expect("strict");

        let custody = FfiKeyCustody::Callback(fake_py_custody(Some("junk_sig")));
        let handle = custody.generate_identity_keypair().await.expect("key");
        let pseudo = custody
            .derive_pseudonym(&handle, b"ctx")
            .await
            .expect("derive");
        assert_custody_error(
            &custody
                .sign(pseudo.key_handle(), &digest)
                .await
                .expect_err("a junk 64-byte signature"),
        );
    }

    /// A pseudonym handle is a P-256 signing key: `dh_agree` is
    /// `WrongKeyType`, and it cannot derive a further pseudonym. A handle the
    /// adapter never minted is looked up through `get_public_key` by every
    /// entry point, so a host without it (the fake raises `KeyNotFoundError`)
    /// fails each one with `KeyNotFound`.
    #[tokio::test]
    async fn ffi_custody_callback_pseudonym_and_unknown_handles() {
        let custody = fake_callback_custody();
        let handle = custody.generate_identity_keypair().await.expect("key");
        let pseudo = custody
            .derive_pseudonym(&handle, b"ctx")
            .await
            .expect("derive");
        assert!(matches!(
            custody.dh_agree(pseudo.key_handle(), &[9u8; 32]).await,
            Err(PlatformError::WrongKeyType { .. })
        ));
        assert!(matches!(
            custody.derive_pseudonym(pseudo.key_handle(), b"ctx").await,
            Err(PlatformError::WrongKeyType { .. })
        ));

        let unknown = KeyHandle::new(4242);
        assert!(matches!(
            custody.sign(&unknown, &[0u8; 32]).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            custody.public_key(&unknown).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            custody.dh_agree(&unknown, &[9u8; 32]).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            custody.derive_pseudonym(&unknown, b"ctx").await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            custody
                .derive_rotatable_pseudonym(&unknown, b"ctx", 1)
                .await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            custody.export_ed25519_signing_key(&unknown).await,
            Err(PlatformError::KeyNotFound)
        ));
        assert!(matches!(
            custody.ed25519_to_x25519_agree(&unknown, &[9u8; 32]).await,
            Err(PlatformError::KeyNotFound)
        ));
    }

    /// A3: an Ed25519 host signature passes `verify_strict` under the
    /// registered key; 64 junk bytes from the host are a `CustodyError`,
    /// never a signature.
    #[tokio::test]
    async fn ffi_custody_callback_ed25519_signatures_verify() {
        use ed25519_dalek::Verifier;
        let custody = fake_py_custody(None);
        let key = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("key");
        let public: [u8; 32] = custody
            .public_key(&key)
            .await
            .expect("public key")
            .as_bytes()
            .try_into()
            .expect("32 bytes");
        let sig: [u8; 64] = custody
            .sign(&key, b"message")
            .await
            .expect("sign")
            .as_bytes()
            .try_into()
            .expect("64 bytes");
        ed25519_dalek::VerifyingKey::from_bytes(&public)
            .expect("key")
            .verify(b"message", &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("the fake signs real Ed25519");

        let junk = fake_py_custody(Some("ed_junk_sig"));
        let key = junk.generate_keypair(KeyType::Ed25519).await.expect("key");
        assert!(matches!(
            junk.sign(&key, b"message").await,
            Err(PlatformError::CustodyError(_))
        ));
        assert_eq!(fake_calls(&junk, "sign"), 1, "the junk came from the host");
    }

    /// D2: a host `KeyNotFoundError` from `sign` reaches the caller as
    /// `KeyNotFound`; any other exception (here `ConnectionError`) stays a
    /// `CustodyError`. Both come from the host `sign` call.
    #[tokio::test]
    async fn ffi_custody_callback_maps_host_not_found_through_sign() {
        let custody = fake_py_custody(None);
        let key = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("key");
        fake_forget(&custody, key.id());
        assert!(matches!(
            custody.sign(&key, b"m").await,
            Err(PlatformError::KeyNotFound)
        ));
        assert_eq!(fake_calls(&custody, "sign"), 1);

        let transport = fake_py_custody(Some("transport"));
        let key = transport
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("key");
        assert!(matches!(
            transport.sign(&key, b"m").await,
            Err(PlatformError::CustodyError(_))
        ));
        assert_eq!(fake_calls(&transport, "sign"), 1);
    }

    /// F2: `export_ed25519_signing_key` and `ed25519_to_x25519_agree` refuse a
    /// P-256 handle, minted or resolved, with `WrongKeyType` before any host
    /// export or agreement call; an Ed25519 handle reaches the host.
    #[tokio::test]
    async fn ffi_custody_callback_ed25519_only_paths_refuse_p256() {
        let custody = fake_py_custody_of(c"P256Custody", None);
        let minted = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .expect("p256 key");
        // A second adapter resolves a P-256 key its host minted directly.
        let fresh = fake_py_custody_of(c"P256Custody", None);
        let resolved = Python::with_gil(|py| {
            fresh
                .provider
                .obj
                .bind(py)
                .call_method1("generate_keypair", ("p256",))
                .and_then(|id| id.extract::<String>())
                .expect("host-side key")
        });
        let resolved = KeyHandle::new(resolved.parse().expect("numeric id"));
        for (c, handle) in [(&custody, minted), (&fresh, resolved)] {
            assert!(matches!(
                c.export_ed25519_signing_key(&handle).await,
                Err(PlatformError::WrongKeyType { .. })
            ));
            assert!(matches!(
                c.ed25519_to_x25519_agree(&handle, &[9u8; 32]).await,
                Err(PlatformError::WrongKeyType { .. })
            ));
            assert_eq!(fake_calls(c, "export_signing_key_bytes"), 0);
            assert_eq!(fake_calls(c, "dh_agree"), 0);
        }

        let ed = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("ed25519 key");
        custody
            .export_ed25519_signing_key(&ed)
            .await
            .expect("an Ed25519 key exports");
        assert_eq!(fake_calls(&custody, "export_signing_key_bytes"), 1);
    }

    /// C2: an operational Ed25519 key is not a derive source; the host is
    /// never asked to derive from it.
    #[tokio::test]
    async fn ffi_custody_callback_derivation_needs_an_identity_key() {
        let custody = fake_py_custody(None);
        let operational = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("key");
        assert!(matches!(
            custody.derive_pseudonym(&operational, b"ctx").await,
            Err(PlatformError::WrongKeyType { .. })
        ));
        assert!(matches!(
            custody
                .derive_rotatable_pseudonym(&operational, b"ctx", 1)
                .await,
            Err(PlatformError::WrongKeyType { .. })
        ));
        assert_eq!(fake_calls(&custody, "derive_pseudonym"), 0);
        assert_eq!(fake_calls(&custody, "derive_rotatable_pseudonym"), 0);
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
