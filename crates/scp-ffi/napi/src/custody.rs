//! Enum dispatch for [`KeyCustody`] in the napi-rs FFI bridge.
//!
//! The [`KeyCustody`] trait uses RPITIT (return-position `impl Trait` in
//! trait), so it is NOT object-safe — we cannot store `Arc<dyn KeyCustody>`.
//! This module provides [`NapiKeyCustody`], an enum that wraps the concrete
//! custody implementations the bridge uses and manually delegates each trait
//! method to the active variant.
//!
//! Mirrors the `PyO3` bridge's `FfiKeyCustody` and the `UniFFI` bridge's
//! `CallbackKeyCustody` split. See ADR-006.
//!
//! # Variants
//!
//! - `InMemory` — test/dev in-memory custody (feature-gated), wrapped in
//!   [`OpaqueInMemoryKeyCustody`] for redacted `Debug`.
//! - `File` — the encrypted key file §3.2.2 of the identity spec names
//!   `encrypted_file` (Argon2id + AES-256-GCM), which `identityCreate` builds.
//! - `Callback` — caller-provided custody backed by JS callbacks
//!   ([`NapiCallbackKeyCustody`]), which `identityCreateWithCustody` builds for
//!   the value §3.2.2 names `os_keystore`.

use std::fmt;

use napi::bindgen_prelude::Function;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use scp_ffi_common::custody_substrate::ReportedCustodySubstrate;
use scp_ffi_common::error_codes as codes;
use scp_platform::error::PlatformError;
use scp_platform::file::FileKeyCustody;

use crate::error::ScpNapiError;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};

#[cfg(feature = "testing")]
use crate::identity::OpaqueInMemoryKeyCustody;

// ---------------------------------------------------------------------------
// NapiKeyCustodyProvider — JS-supplied callback record (the `#[napi(object)]`
// the SDK passes to identityCreateWithCustody)
// ---------------------------------------------------------------------------

/// JS-supplied custody provider.
///
/// Each field is a JS function; napi-rs converts them into
/// [`ThreadsafeFunction`]s so they can be invoked from the tokio worker
/// threads that drive `DidDht::create`. Mirrors the `UniFFI`
/// `KeyCustodyProvider` callback interface and the Python `KeyCustodyProvider`
/// protocol.
///
/// The JS callbacks are synchronous (they return the value directly, not a
/// `Promise`) — keystore reads are fast and the bridge awaits the dispatch via
/// [`ThreadsafeFunction::call_async`]. Private key material never crosses into
/// Rust ownership (ADR-006): the consumer owns the secrets and returns only
/// public bytes / opaque key-id strings.
#[napi(object, object_to_js = false)]
pub struct NapiKeyCustodyProvider {
    /// `(keyType: string) => string` — generate a keypair, return its id.
    #[napi(ts_type = "(keyType: string) => string")]
    pub generate_keypair: Function<'static, String, String>,
    /// `(keyId: string, message: Uint8Array) => Uint8Array` — 64-byte sig.
    #[napi(ts_type = "(keyId: string, message: Uint8Array) => Uint8Array")]
    pub sign: Function<'static, (String, Vec<u8>), Vec<u8>>,
    /// `(keyId: string) => Uint8Array` — 32 public-key bytes.
    #[napi(ts_type = "(keyId: string) => Uint8Array")]
    pub get_public_key: Function<'static, String, Vec<u8>>,
    /// `(keyId: string) => void` — destroy key material.
    #[napi(ts_type = "(keyId: string) => void")]
    pub destroy_key: Function<'static, String, ()>,
    /// `(keyId: string, peerPublic: Uint8Array) => Uint8Array` — 32 shared bytes.
    #[napi(ts_type = "(keyId: string, peerPublic: Uint8Array) => Uint8Array")]
    pub dh_agree: Function<'static, (String, Vec<u8>), Vec<u8>>,
    /// `(keyId: string, contextId: Uint8Array) => Uint8Array` —
    /// `publicKey(32) || keyIdUtf8`.
    #[napi(ts_type = "(keyId: string, contextId: Uint8Array) => Uint8Array")]
    pub derive_pseudonym: Function<'static, (String, Vec<u8>), Vec<u8>>,
    /// `(keyId: string, contextId: Uint8Array, pseudonymEpoch: bigint) => Uint8Array`
    /// — canonical rotatable v2 pseudonym; returns `publicKey(32) || keyIdUtf8`.
    /// The provider performs the canonical derivation (HMAC key is the
    /// private-derived `pseudonym_secret`, domain `"scp-pseudonym-v2"`); the
    /// bridge does NOT synthesize the preimage.
    #[napi(
        ts_type = "(keyId: string, contextId: Uint8Array, pseudonymEpoch: bigint) => Uint8Array"
    )]
    pub derive_rotatable_pseudonym: Function<'static, (String, Vec<u8>, u64), Vec<u8>>,
    /// `(keyId: string) => Uint8Array` — 32 raw private-seed bytes.
    #[napi(ts_type = "(keyId: string) => Uint8Array")]
    pub export_signing_key_bytes: Function<'static, String, Vec<u8>>,
    /// `(keyId: string) => string` — `"hardware"` / `"software"` / `"in_memory"`.
    /// Names the storage location, which `scp_platform::CustodyType` consumes.
    #[napi(ts_type = "(keyId: string) => string")]
    pub custody_type: Function<'static, String, String>,
    /// `(keyId: string) => boolean` — whether the private key can leave the
    /// store this provider holds it in. One of the two facts a DID document
    /// publishes about custody (§3.2.2 of the identity spec).
    #[napi(ts_type = "(keyId: string) => boolean")]
    pub key_is_extractable: Function<'static, String, bool>,
    /// `(keyId: string) => string` — which factor unlocks the key: one of
    /// `"biometric"`, `"pin"`, `"passphrase"`, `"caller_supplied_key"`, or
    /// `"unprotected"`. The other fact a DID document publishes about custody
    /// (§3.2.2 of the identity spec). A string outside that set publishes no
    /// custody value.
    #[napi(ts_type = "(keyId: string) => string")]
    pub unlock_factor: Function<'static, String, String>,
}

// ---------------------------------------------------------------------------
// NapiCallbackKeyCustody — concrete `KeyCustody` adapter over the JS callbacks
// ---------------------------------------------------------------------------

/// Threadsafe-function handles for each custody operation. Built once from a
/// [`NapiKeyCustodyProvider`] at `identityCreateWithCustody` time; thereafter
/// callable from any tokio worker thread driving the async custody trait.
///
/// The `ThreadsafeFunction` generics are intrinsically verbose (arg type,
/// return type, raw-arg type, error status, callee-handled flag); there is no
/// type alias that meaningfully simplifies them without obscuring the
/// per-field arg/return shapes.
#[allow(clippy::type_complexity)]
struct CallbackTsfns {
    generate_keypair: ThreadsafeFunction<String, String, String, napi::Status, false>,
    sign: ThreadsafeFunction<(String, Vec<u8>), Vec<u8>, (String, Vec<u8>), napi::Status, false>,
    get_public_key: ThreadsafeFunction<String, Vec<u8>, String, napi::Status, false>,
    destroy_key: ThreadsafeFunction<String, (), String, napi::Status, false>,
    dh_agree:
        ThreadsafeFunction<(String, Vec<u8>), Vec<u8>, (String, Vec<u8>), napi::Status, false>,
    derive_pseudonym:
        ThreadsafeFunction<(String, Vec<u8>), Vec<u8>, (String, Vec<u8>), napi::Status, false>,
    derive_rotatable_pseudonym: ThreadsafeFunction<
        (String, Vec<u8>, u64),
        Vec<u8>,
        (String, Vec<u8>, u64),
        napi::Status,
        false,
    >,
    export_signing_key_bytes: ThreadsafeFunction<String, Vec<u8>, String, napi::Status, false>,
    custody_type: ThreadsafeFunction<String, String, String, napi::Status, false>,
    key_is_extractable: ThreadsafeFunction<String, bool, String, napi::Status, false>,
    unlock_factor: ThreadsafeFunction<String, String, String, napi::Status, false>,
}

/// Concrete [`KeyCustody`] adapter delegating to JS callbacks. The
/// callbacks run on the Node.js event loop (marshalled via
/// [`ThreadsafeFunction`]); the bridge awaits each via `call_async`.
pub(crate) struct NapiCallbackKeyCustody {
    tsfns: CallbackTsfns,
}

impl fmt::Debug for NapiCallbackKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NapiCallbackKeyCustody([js])")
    }
}

impl NapiCallbackKeyCustody {
    /// Builds threadsafe-function handles from a JS-supplied provider record.
    ///
    /// Each `Function` is converted into a non-callee-handled
    /// [`ThreadsafeFunction`] (`Weak = false`, `CalleeHandled = false`) whose
    /// return value the bridge awaits. The `MaxQueueSize = 0` default is
    /// unbounded — custody calls are infrequent and short-lived.
    ///
    /// # Errors
    ///
    /// Returns a `napi::Error` if any callback cannot be promoted to a
    /// threadsafe function.
    pub fn from_provider(provider: NapiKeyCustodyProvider) -> napi::Result<Self> {
        Ok(Self {
            tsfns: CallbackTsfns {
                generate_keypair: provider
                    .generate_keypair
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                sign: provider
                    .sign
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                get_public_key: provider
                    .get_public_key
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                destroy_key: provider
                    .destroy_key
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                dh_agree: provider
                    .dh_agree
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                derive_pseudonym: provider
                    .derive_pseudonym
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                derive_rotatable_pseudonym: provider
                    .derive_rotatable_pseudonym
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                export_signing_key_bytes: provider
                    .export_signing_key_bytes
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                custody_type: provider
                    .custody_type
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                key_is_extractable: provider
                    .key_is_extractable
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
                unlock_factor: provider
                    .unlock_factor
                    .build_threadsafe_function()
                    .weak::<false>()
                    .build()?,
            },
        })
    }

    fn map_call_err(method: &str, e: &napi::Error) -> PlatformError {
        PlatformError::CustodyError(format!("KeyCustodyProvider.{method} raised: {e}"))
    }

    /// Exports the raw Ed25519 signing key via the provider's
    /// `export_signing_key_bytes` callback.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if the callback raises or
    /// returns a non-32-byte value.
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ed25519_dalek::SigningKey, PlatformError> {
        let bytes = zeroize::Zeroizing::new(
            self.tsfns
                .export_signing_key_bytes
                .call_async(handle.id().to_string())
                .await
                .map_err(|e| Self::map_call_err("export_signing_key_bytes", &e))?,
        );
        let arr = zeroize::Zeroizing::new(scp_ffi_common::custody_parse::expect_32(
            "export_signing_key_bytes",
            &bytes,
        )?);
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }

    /// Asks the JS provider the two questions a published custody value
    /// answers, and returns the answers as a
    /// [`CustodySubstrate`](scp_did::attestation::CustodySubstrate).
    ///
    /// §3.2.2 of the identity spec states that a DID document publishes
    /// whether the key can leave its store and which factor unlocks it, and
    /// that `ScpKeyCustodyAttestation::derive` reads both off the backend. The
    /// JS provider is the only party that knows either fact about a key it
    /// holds, so this method dispatches both questions to the event loop and
    /// awaits the answers. `KeyCustody::custody_type` cannot do the same,
    /// because that trait method is synchronous and a threadsafe-function
    /// dispatch returns no value to a tokio worker thread synchronously.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] if either callback throws or
    /// returns a value napi-rs cannot read as a `boolean` or a `string`.
    pub async fn custody_substrate(
        &self,
        handle: &KeyHandle,
    ) -> Result<ReportedCustodySubstrate, PlatformError> {
        let key_is_extractable = self
            .tsfns
            .key_is_extractable
            .call_async(handle.id().to_string())
            .await
            .map_err(|e| Self::map_call_err("key_is_extractable", &e))?;
        let unlock_factor = self
            .tsfns
            .unlock_factor
            .call_async(handle.id().to_string())
            .await
            .map_err(|e| Self::map_call_err("unlock_factor", &e))?;
        Ok(ReportedCustodySubstrate::new(
            key_is_extractable,
            &unlock_factor,
        ))
    }
}

impl KeyCustody for NapiCallbackKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        let type_str = match key_type {
            KeyType::Ed25519 => "ed25519".to_owned(),
            KeyType::X25519 => "x25519".to_owned(),
        };
        let key_id = self
            .tsfns
            .generate_keypair
            .call_async(type_str)
            .await
            .map_err(|e| Self::map_call_err("generate_keypair", &e))?;
        scp_ffi_common::custody_parse::parse_handle("generate_keypair", &key_id)
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        let sig = self
            .tsfns
            .sign
            .call_async((key.id().to_string(), data.to_vec()))
            .await
            .map_err(|e| Self::map_call_err("sign", &e))?;
        Ok(Signature::new(sig))
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        let pk = self
            .tsfns
            .get_public_key
            .call_async(key.id().to_string())
            .await
            .map_err(|e| Self::map_call_err("get_public_key", &e))?;
        Ok(PublicKey::new(pk))
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.tsfns
            .destroy_key
            .call_async(key.id().to_string())
            .await
            .map_err(|e| Self::map_call_err("destroy_key", &e))
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        // Wrap the raw shared secret in `Zeroizing` so the intermediate heap
        // buffer is wiped on drop once it has been copied into `SharedSecret`
        // (defense-in-depth, matching `export_ed25519_signing_key`; ADR-006).
        let shared = zeroize::Zeroizing::new(
            self.tsfns
                .dh_agree
                .call_async((key.id().to_string(), peer_public.to_vec()))
                .await
                .map_err(|e| Self::map_call_err("dh_agree", &e))?,
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
        let bytes = self
            .tsfns
            .derive_pseudonym
            .call_async((key.id().to_string(), context_id.to_vec()))
            .await
            .map_err(|e| Self::map_call_err("derive_pseudonym", &e))?;
        scp_ffi_common::custody_parse::unpack_pseudonym("derive_pseudonym", &bytes)
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        // Canonical v2 recipe (spec §9.10.4.A / §9.10.4.1): the provider performs
        // the rotatable derivation itself — seed = HMAC-SHA256(pseudonym_secret,
        // context_id || BE64(pseudonym_epoch) || "scp-pseudonym-v2"); keypair =
        // Ed25519_keygen(seed[0..32]). The epoch is threaded through to the
        // provider rather than synthesized into the context_id bridge-side, so
        // the v1 platform adapter does not re-append its own "scp-pseudonym"
        // domain separator (which would corrupt the v2 domain). Mirrors the
        // UniFFI / PyO3 CallbackKeyCustody contract.
        let bytes = self
            .tsfns
            .derive_rotatable_pseudonym
            .call_async((key.id().to_string(), context_id.to_vec(), pseudonym_epoch))
            .await
            .map_err(|e| Self::map_call_err("derive_rotatable_pseudonym", &e))?;
        scp_ffi_common::custody_parse::unpack_pseudonym("derive_rotatable_pseudonym", &bytes)
    }

    async fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        // The JS callback protocol does not expose a distinct birational
        // conversion; the provider manages key types internally, so delegate
        // to dh_agree (matches the UniFFI/PyO3 contract).
        // Wrap the raw shared secret in `Zeroizing` so the intermediate heap
        // buffer is wiped on drop once it has been copied into `SharedSecret`
        // (defense-in-depth, matching `export_ed25519_signing_key`; ADR-006).
        let shared = zeroize::Zeroizing::new(
            self.tsfns
                .dh_agree
                .call_async((ed25519_handle.id().to_string(), peer_x25519_public.to_vec()))
                .await
                .map_err(|e| Self::map_call_err("dh_agree", &e))?,
        );
        Ok(SharedSecret::new(scp_ffi_common::custody_parse::expect_32(
            "ed25519_to_x25519_agree",
            &shared,
        )?))
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        // Sync query. `custody_type` returns immediately on the JS side; we
        // dispatch NonBlocking and, lacking a synchronous return path from a
        // worker thread, classify conservatively. The custody-type
        // classification is advisory metadata only (it does not gate any
        // security decision — membership is enforced by MLS keys), so a
        // callback-backed key is reported as `Software`, the correct class
        // for any non-HSM software keystore the SDK consumer would wire here.
        let _ = self.tsfns.custody_type.call(
            key.id().to_string(),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
        CustodyType::Software
    }

    async fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PlatformError> {
        // Generate the pre-rotation seed LOCALLY via OsRng — the bytes never
        // traverse the consumer's callbacks. The bridge hands them straight to
        // a `PreRotationCustody` (ADR-003 §4b). This is what makes identity
        // CREATION work with callback custody. Mirrors the UniFFI/PyO3
        // CallbackKeyCustody contract.
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
        // NEW operational `#0` key. The callback protocol has no "import a
        // known seed → handle" method (only `generateKeypair`, which mints a
        // fresh random key), so this surfaces a clear error. Identity CREATION
        // via callback custody is unaffected. Mirrors the UniFFI/PyO3 contract.
        let _ = seed;
        Err(PlatformError::Unsupported(
            "callback KeyCustodyProvider cannot import pre-rotation seed bytes \
             (no import method on the protocol); identity creation is unaffected",
        ))
    }
}

// ---------------------------------------------------------------------------
// NapiKeyCustody — enum dispatch wrapper
// ---------------------------------------------------------------------------

/// Enum dispatch wrapper for the [`KeyCustody`] implementations the napi-rs
/// bridge uses. Since [`KeyCustody`] is not object-safe (RPITIT), this enum
/// wraps the concrete types and delegates each method to the active variant.
#[allow(clippy::large_enum_variant)]
pub(crate) enum NapiKeyCustody {
    /// Test/dev in-memory custody (feature-gated), wrapped for redacted Debug.
    #[cfg(feature = "testing")]
    InMemory(OpaqueInMemoryKeyCustody),
    /// The encrypted key file §3.2.2 of the identity spec names
    /// `encrypted_file`: Argon2id derives an AES-256 key from the caller's
    /// passphrase, and each key entry is encrypted under AES-256-GCM.
    File(FileKeyCustody),
    /// Caller-provided custody backed by JS callbacks. §3.2.2 of the identity
    /// spec names the value that selects it `os_keystore`.
    Callback(NapiCallbackKeyCustody),
}

impl fmt::Debug for NapiKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(_) => f.write_str("NapiKeyCustody::InMemory([redacted])"),
            Self::File(_) => f.write_str("NapiKeyCustody::File([encrypted])"),
            Self::Callback(_) => f.write_str("NapiKeyCustody::Callback([js])"),
        }
    }
}

impl NapiKeyCustody {
    /// Returns the custody value this bridge reports for the active backend:
    /// `"encrypted_file"`, `"os_keystore"`, or the test-harness `"in_memory"`.
    ///
    /// §3.2.2 of the identity spec gives a caller the first two values, and the
    /// `PyO3` and `UniFFI` bridges report the same string for the same backend,
    /// so one name carries one meaning across all three bridges.
    ///
    /// This is a cheap, sync variant discriminator — distinct from the
    /// [`KeyCustody::custody_type`] trait method, which reports the
    /// per-key-handle [`CustodyType`] (hardware/software/in-memory) the
    /// underlying backend declares.
    pub(crate) const fn custody_type_label(&self) -> &'static str {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(_) => "in_memory",
            Self::File(_) => "encrypted_file",
            Self::Callback(_) => "os_keystore",
        }
    }

    /// Exports the raw Ed25519 signing key for the given handle, dispatching
    /// through the active variant. Mirrors the inherent helper on the `PyO3`
    /// `FfiKeyCustody` enum (required by SCPID signing, event-log
    /// checkpointing, and pseudonym announcements).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if the handle is invalid or (for callback
    /// custody) the JS `exportSigningKeyBytes` callback fails.
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ed25519_dalek::SigningKey, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.export_ed25519_signing_key(handle).await,
            Self::File(kc) => kc.export_ed25519_signing_key(handle).await,
            Self::Callback(kc) => kc.export_ed25519_signing_key(handle).await,
        }
    }

    /// Reads the two facts a DID document publishes about the backend holding
    /// `handle`: whether the private key can leave its store, and which factor
    /// unlocks it (§3.2.2 of the identity spec).
    ///
    /// `FileKeyCustody` and `InMemoryKeyCustody` implement
    /// [`CustodySubstrate`](scp_did::attestation::CustodySubstrate) about
    /// themselves, so those two arms copy the answers. The callback arm asks
    /// the injected JS provider, which is the only party that knows what the
    /// operating system's key store does with the key.
    ///
    /// `ScpKeyCustodyAttestation::derive` takes one substrate per key, so this
    /// method takes one handle rather than describing the whole backend.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] when a JS callback throws or
    /// returns a value napi-rs cannot read.
    pub(crate) async fn custody_substrate(
        &self,
        handle: &KeyHandle,
    ) -> Result<ReportedCustodySubstrate, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => Ok(ReportedCustodySubstrate::from_substrate(&kc.0)),
            Self::File(kc) => Ok(ReportedCustodySubstrate::from_substrate(kc)),
            Self::Callback(kc) => kc.custody_substrate(handle).await,
        }
    }
}

impl KeyCustody for NapiKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.generate_keypair(key_type).await,
            Self::File(kc) => kc.generate_keypair(key_type).await,
            Self::Callback(kc) => kc.generate_keypair(key_type).await,
        }
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.sign(key, data).await,
            Self::File(kc) => kc.sign(key, data).await,
            Self::Callback(kc) => kc.sign(key, data).await,
        }
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.public_key(key).await,
            Self::File(kc) => kc.public_key(key).await,
            Self::Callback(kc) => kc.public_key(key).await,
        }
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.destroy_key(key).await,
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
            Self::InMemory(kc) => kc.0.dh_agree(key, peer_public).await,
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
            Self::InMemory(kc) => kc.0.derive_pseudonym(key, context_id).await,
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
                kc.0.derive_rotatable_pseudonym(key, context_id, pseudonym_epoch)
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
                kc.0.ed25519_to_x25519_agree(ed25519_handle, peer_x25519_public)
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
            Self::InMemory(kc) => kc.0.custody_type(key),
            Self::File(kc) => kc.custody_type(key),
            Self::Callback(kc) => kc.custody_type(key),
        }
    }

    async fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.generate_ephemeral_ed25519_seed().await,
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
            Self::InMemory(kc) => kc.0.import_ed25519_signing_key(seed).await,
            Self::File(kc) => kc.import_ed25519_signing_key(seed).await,
            Self::Callback(kc) => kc.import_ed25519_signing_key(seed).await,
        }
    }
}

// ---------------------------------------------------------------------------
// The custody factory
// ---------------------------------------------------------------------------

/// Builds the key custody backend a caller's custody value names.
///
/// §3.2.2 of the identity spec, the custody vocabulary, gives a caller two
/// values: `"encrypted_file"` selects the on-disk key store SCP implements, and
/// `"os_keystore"` selects the operating system's own key store, which this
/// bridge reaches through the `KeyCustodyProvider` a JavaScript caller
/// supplies. This function is the one place on this bridge that maps either
/// value onto a backend, so `identityCreate`, `identityCreateWithAgentKey`, and
/// `identityCreateWithCustody` all reach the same decision.
///
/// A shipped build additionally answers `"in_memory"`, the test-harness string,
/// with `SCP-IDENT-1008`; a build carrying the `testing` cargo feature builds
/// the in-memory backend for it, seeded from `testing_seed` when the caller
/// supplied one (ADR-046 cross-bridge parity). §3.2.2 states that the string is
/// a test affordance and not a value of the vocabulary.
///
/// # Arguments
///
/// * `custody` — the custody value, one of the two §3.2.2 names.
/// * `provider` — the JavaScript `KeyCustodyProvider` record that holds the
///   key, supplied only alongside `"os_keystore"`. The caller MUST promote it
///   on the JavaScript thread, which is where this function runs for that
///   value, because the record's `Function` fields are not `Send`.
/// * `testing_seed` — the 32-byte deterministic RNG seed, valid only alongside
///   `"in_memory"`.
///
/// # Errors
///
/// Returns [`ScpNapiError::Identity`] carrying:
/// - `SCP-IDENT-1003` when a caller names `"os_keystore"` and supplies no
///   provider. §3.2.2 states the rule this applies: the bridge returns a typed
///   error and falls back to neither `encrypted_file` nor an in-memory store.
/// - `SCP-IDENT-1008` when a caller names `"in_memory"` on a build that carries
///   no `testing` feature.
/// - `SCP-IDENT-1005` when a caller supplies a provider alongside a value other
///   than `"os_keystore"`. No public entry point forms that pair, so the error
///   reports a bridge-layer bug.
/// - An opening failure from the encrypted key file.
///
/// Returns [`ScpNapiError::Validation`] carrying:
/// - `SCP-VALID-7005` for every string outside the vocabulary, and for a
///   JavaScript provider napi-rs cannot promote to threadsafe functions.
/// - `SCP-VALID-7008` for a `testing_seed` on a build carrying no `testing`
///   feature, and `SCP-VALID-7009` for a `testing_seed` paired with
///   `"encrypted_file"`.
/// - `SCP-VALID-7005` for an unset or empty `SCP_KEY_PASSPHRASE` under
///   `"encrypted_file"`, and for an unset `HOME` or a `$HOME/.scp` this
///   process cannot create. `KeyFileError::code` states that code once for
///   all three bridges, and it answers a key file that will not open with
///   `SCP-IDENT-1001` on the bridge's identity error instead.
pub(crate) fn build_key_custody(
    custody: &str,
    provider: Option<NapiKeyCustodyProvider>,
    testing_seed: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> Result<(std::sync::Arc<NapiKeyCustody>, String), ScpNapiError> {
    if provider.is_some() && custody != "os_keystore" {
        return Err(ScpNapiError::Identity {
            message: "internal: a KeyCustodyProvider was supplied alongside a custody value \
                      other than \"os_keystore\" — this is a bug in the bridge layer"
                .to_owned(),
            code: codes::IDENT_1005.to_owned(),
        });
    }

    // The custody name is judged before the seed pairing, so a caller who
    // passes an unusable custody name together with a seed reads the custody
    // error rather than the seed error. `"in_memory"` consumes the seed below;
    // `"encrypted_file"` is the one other value this bridge builds a backend
    // for, so this guard is closed against the accepted set rather than
    // open-ended. Mirrors the `PyO3` bridge's `parse_custody_with_seed`.
    if custody == "encrypted_file" && testing_seed.is_some() {
        return Err(ScpNapiError::Validation {
            message: "`testingSeed` parameter is only valid for custody=\"in_memory\"".to_owned(),
            code: codes::VALID_7009.to_owned(),
        });
    }

    match custody {
        // `FileKeyCustody` derives an AES-256 key from a passphrase with
        // Argon2id and encrypts each key entry under AES-256-GCM
        // (`scp-platform/src/file.rs`). All three bridges open the same store
        // at the same path through
        // `scp_ffi_common::key_file::open_default_key_file`, so they cannot
        // drift on the path, the environment variable, or the message text.
        "encrypted_file" => {
            let file_kc = scp_ffi_common::key_file::open_default_key_file().map_err(|e| {
                use scp_ffi_common::key_file::KeyFileErrorCategory;
                // One condition, one code on all three bridges. `KeyFileError`
                // states both the code and the category, so this bridge picks
                // neither and cannot drift from the other two.
                let code = e.code().to_owned();
                let message = e.to_string();
                match e.category() {
                    KeyFileErrorCategory::Validation => ScpNapiError::Validation { message, code },
                    KeyFileErrorCategory::Identity => ScpNapiError::Identity { message, code },
                }
            })?;
            Ok((
                std::sync::Arc::new(NapiKeyCustody::File(file_kc)),
                "encrypted_file".to_owned(),
            ))
        }
        // The operating system's own key store sits on the far side of the JS
        // callbacks, so this arm needs the provider a caller passed to
        // `identityCreateWithCustody`.
        "os_keystore" => match provider {
            Some(record) => {
                let callback = NapiCallbackKeyCustody::from_provider(record).map_err(|e| {
                    ScpNapiError::Validation {
                        message: format!("invalid KeyCustodyProvider: {e}"),
                        code: codes::VALID_7005.to_owned(),
                    }
                })?;
                Ok((
                    std::sync::Arc::new(NapiKeyCustody::Callback(callback)),
                    "os_keystore".to_owned(),
                ))
            }
            // FAIL CLOSED. §3.2.2 of the identity spec states that this bridge
            // returns a typed error here, falls back to neither
            // `encrypted_file` nor an in-memory store, and cites the
            // no-dev-stand-in tenet of `CLAUDE.md` as the rule it applies.
            None => Err(ScpNapiError::Identity {
                message: "custody type \"os_keystore\" reaches the operating system's key \
                          store through a KeyCustodyProvider, and identityCreate supplies \
                          none — call identityCreateWithCustody() and pass a provider backed \
                          by the Apple Keychain or the Android Keystore. For the encrypted \
                          key file SCP implements, pass \"encrypted_file\". Both of those \
                          calls return SCP-IDENT-1059 on a shipped build today, because no \
                          pre-rotation custody backend is wired yet, so no shipped build \
                          creates an identity."
                    .to_owned(),
                code: codes::IDENT_1003.to_owned(),
            }),
        },
        #[cfg(feature = "testing")]
        "in_memory" => {
            use scp_platform::testing::InMemoryKeyCustody;

            // Deref through `Zeroizing<[u8; 32]>` so the wrapper drops (and
            // wipes) at the end of this scope. The inner `[u8; 32]` is consumed
            // by value by `from_seed_bytes` (one unavoidable Copy) and then
            // discarded inside `StdRng::from_seed`.
            let in_memory = testing_seed
                .as_ref()
                .map_or_else(InMemoryKeyCustody::new, |seed| {
                    InMemoryKeyCustody::from_seed_bytes(**seed)
                });
            Ok((
                std::sync::Arc::new(NapiKeyCustody::InMemory(OpaqueInMemoryKeyCustody(
                    in_memory,
                ))),
                "in_memory".to_owned(),
            ))
        }
        #[cfg(not(feature = "testing"))]
        "in_memory" => {
            // A `testingSeed` is a parity-harness affordance gated on the
            // `testing` feature, so surface it as SCP-VALID-7008 ("testing-only
            // feature requires feature flag") ahead of the generic
            // custody-unavailable error. Mirrors the `PyO3` bridge's
            // `#[cfg(not(feature = "testing"))] parse_custody_with_seed`.
            if testing_seed.is_some() {
                return Err(ScpNapiError::Validation {
                    message: "`testingSeed` parameter requires the testing feature".to_owned(),
                    code: codes::VALID_7008.to_owned(),
                });
            }
            Err(ScpNapiError::Identity {
                message: "in_memory custody is not available in this build -- use \
                          \"encrypted_file\" custody for an encrypted key file, or \
                          identityCreateWithCustody() to inject a platform-native \
                          KeyCustodyProvider for \"os_keystore\". Both of those calls return \
                          SCP-IDENT-1059 on a shipped build today, because no pre-rotation \
                          custody backend is wired yet, so no shipped build creates an \
                          identity."
                    .to_owned(),
                code: codes::IDENT_1008.to_owned(),
            })
        }
        // `validate_custody_type` rejects every string outside the vocabulary
        // before any caller reaches this function, so this arm reports a
        // bridge-layer bug rather than a caller's mistake.
        other => Err(ScpNapiError::Identity {
            code: codes::IDENT_1005.to_owned(),
            message: format!(
                "internal: unexpected custody type {other:?} passed validate_custody_type — \
                 this is a bug in the bridge layer"
            ),
        }),
    }
}

#[cfg(test)]
#[cfg(feature = "testing")]
#[allow(clippy::expect_used)]
mod tests {
    use scp_platform::testing::InMemoryKeyCustody;

    use super::*;
    use crate::identity::OpaqueInMemoryKeyCustody;

    /// The enum dispatch routes every trait method to the active variant. The
    /// `Callback` variant requires a Node.js runtime (threadsafe functions) and
    /// is exercised end-to-end by the TypeScript SDK test; here we verify the
    /// `InMemory` arm so the migration's dispatch wiring (`generate_keypair` →
    /// `sign` → `public_key` → `custody_type`, plus the inherent export helper)
    /// is covered in plain `cargo test`.
    #[tokio::test]
    async fn napi_key_custody_in_memory_dispatch() {
        let custody = NapiKeyCustody::InMemory(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let handle = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("generate keypair via enum");
        let pk = custody
            .public_key(&handle)
            .await
            .expect("public_key via enum");
        assert_eq!(pk.as_bytes().len(), 32);
        let sig = custody.sign(&handle, b"data").await.expect("sign via enum");
        assert_eq!(sig.as_bytes().len(), 64);
        assert_eq!(custody.custody_type(&handle), CustodyType::InMemory);
        // Inherent export helper dispatches through the enum.
        let sk = custody
            .export_ed25519_signing_key(&handle)
            .await
            .expect("export via enum");
        assert_eq!(sk.to_bytes().len(), 32);
    }

    /// The locally-minted ephemeral pre-rotation seed path works through the
    /// enum for the in-memory variant (the callback variant mints its own seed
    /// locally too — covered by the inherent test below).
    #[tokio::test]
    async fn napi_key_custody_in_memory_ephemeral_seed() {
        let custody = NapiKeyCustody::InMemory(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let seed = custody
            .generate_ephemeral_ed25519_seed()
            .await
            .expect("ephemeral seed via enum");
        assert_eq!(seed.len(), 32);
    }
}
