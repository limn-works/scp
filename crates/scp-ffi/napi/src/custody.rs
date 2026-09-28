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
//! - `Callback` — caller-provided custody backed by JS callbacks
//!   ([`NapiCallbackKeyCustody`]), used by `identityCreateWithCustody`.

use std::fmt;

use napi::bindgen_prelude::Function;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use scp_platform::error::PlatformError;
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
/// Every callback returns a structured outcome, `{ ok: true, value }` or
/// `{ ok: false, code?, message }`, and never throws: napi-rs turns an
/// exception thrown inside a threadsafe-function callback into a process-level
/// uncaught exception, so `custody-adapter.ts` catches each host throw and
/// returns the failure arm. A failure whose `code` is `SCP-CRYPTO-4001` maps to
/// [`PlatformError::KeyNotFound`]; any other failure maps to
/// [`PlatformError::CustodyError`].
///
/// The JS callbacks are synchronous (they return the outcome directly, not a
/// `Promise`) — keystore reads are fast and the bridge awaits the dispatch via
/// [`ThreadsafeFunction::call_async`]. Private key material never crosses into
/// Rust ownership (ADR-006): the consumer owns the secrets and returns only
/// public bytes / opaque key-id strings.
#[napi(object, object_to_js = false)]
pub struct NapiKeyCustodyProvider {
    /// `(keyType: string) => string` — generate a keypair, return its id.
    #[napi(
        ts_type = "(keyType: string) => { ok: boolean; value?: string; code?: string; message?: string }"
    )]
    pub generate_keypair: Function<'static, String, HostStringResult>,
    /// `(keyId: string, message: Uint8Array) => Uint8Array` — 64-byte sig: an
    /// Ed25519 signature, or for a pseudonym key id a 32-byte digest in and
    /// the low-`s` P-256 `r || s` out (§9.5), which the bridge verifies.
    #[napi(
        ts_type = "(args: [string, number[]]) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub sign: Function<'static, (String, Vec<u8>), HostBytesResult>,
    /// `(keyId: string) => Uint8Array` — 32 public-key bytes, or the 33-byte
    /// compressed P-256 point for a pseudonym key id.
    #[napi(
        ts_type = "(keyId: string) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub get_public_key: Function<'static, String, HostBytesResult>,
    /// `(keyId: string) => void` — destroy key material.
    #[napi(
        ts_type = "(keyId: string) => { ok: boolean; value?: undefined; code?: string; message?: string }"
    )]
    pub destroy_key: Function<'static, String, HostUnitResult>,
    /// `(keyId: string, peerPublic: Uint8Array) => Uint8Array` — 32 shared bytes.
    #[napi(
        ts_type = "(args: [string, number[]]) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub dh_agree: Function<'static, (String, Vec<u8>), HostBytesResult>,
    /// `(keyId: string, contextId: Uint8Array) => { publicKey, keyId }` —
    /// the §9.10.4 v1 pseudonym: `publicKey` is the 33-byte compressed P-256
    /// point and `keyId` the numeric handle of the pseudonym key. The bridge
    /// requires `getPublicKey(keyId)` to return the same 33 bytes. The same
    /// (`keyId`, `contextId`) MUST return the same pseudonym `keyId` on every
    /// call, so re-deriving names one key rather than minting another.
    #[napi(
        ts_type = "(args: [string, number[]]) => { ok: boolean; value?: { publicKey: number[]; keyId: string }; code?: string; message?: string }"
    )]
    pub derive_pseudonym: Function<'static, (String, Vec<u8>), HostPseudonymResult>,
    /// `(keyId: string, contextId: Uint8Array, pseudonymEpoch: bigint) => { publicKey, keyId }`
    /// — the §9.10.4 rotatable v2 pseudonym, same return shape as
    /// `derivePseudonym`; the same (`keyId`, `contextId`, `pseudonymEpoch`)
    /// MUST return the same pseudonym `keyId`. The provider performs the canonical derivation
    /// (HMAC key is the private-derived `pseudonym_secret`, domain
    /// `"scp-pseudonym-v2"`); the bridge does NOT synthesize the preimage.
    #[napi(
        ts_type = "(args: [string, number[], bigint]) => { ok: boolean; value?: { publicKey: number[]; keyId: string }; code?: string; message?: string }"
    )]
    pub derive_rotatable_pseudonym: Function<'static, (String, Vec<u8>, u64), HostPseudonymResult>,
    /// `(keyId: string) => Uint8Array` — 32 raw private-seed bytes.
    #[napi(
        ts_type = "(keyId: string) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub export_signing_key_bytes: Function<'static, String, HostBytesResult>,
    /// `(keyId: string) => string` — `"hardware"` / `"software"` / `"in_memory"`.
    #[napi(
        ts_type = "(keyId: string) => { ok: boolean; value?: string; code?: string; message?: string }"
    )]
    pub custody_type: Function<'static, String, HostStringResult>,
}

/// A host pseudonym derivation result: the 33-byte compressed P-256 point and
/// the key id of the pseudonym key, as separate fields (§9.10.4).
#[napi(object)]
pub struct NapiPseudonymResult {
    /// 33-byte SEC1 compressed P-256 public key.
    pub public_key: Vec<u8>,
    /// Numeric key id of the pseudonym key, as a decimal string.
    pub key_id: String,
}

/// A host callback outcome carrying a string (`generateKeypair`, `custodyType`).
#[napi(object, object_to_js = false)]
pub struct HostStringResult {
    /// `true` when the host call succeeded and `value` holds its result.
    pub ok: bool,
    /// The host's result when `ok`.
    pub value: Option<String>,
    /// The failure's `SCP-` code when the host error carried one.
    pub code: Option<String>,
    /// The host error's message when not `ok`.
    pub message: Option<String>,
}

/// A host callback outcome carrying bytes (`sign`, `getPublicKey`, `dhAgree`,
/// `exportSigningKeyBytes`).
#[napi(object, object_to_js = false)]
pub struct HostBytesResult {
    /// `true` when the host call succeeded and `value` holds its result.
    pub ok: bool,
    /// The host's result when `ok`.
    pub value: Option<Vec<u8>>,
    /// The failure's `SCP-` code when the host error carried one.
    pub code: Option<String>,
    /// The host error's message when not `ok`.
    pub message: Option<String>,
}

/// A host callback outcome with no value (`destroyKey`).
#[napi(object, object_to_js = false)]
pub struct HostUnitResult {
    /// `true` when the host call succeeded.
    pub ok: bool,
    /// The failure's `SCP-` code when the host error carried one.
    pub code: Option<String>,
    /// The host error's message when not `ok`.
    pub message: Option<String>,
}

/// A host callback outcome carrying a pseudonym (`derivePseudonym`,
/// `deriveRotatablePseudonym`).
#[napi(object, object_to_js = false)]
pub struct HostPseudonymResult {
    /// `true` when the host call succeeded and `value` holds its result.
    pub ok: bool,
    /// The host's result when `ok`.
    pub value: Option<NapiPseudonymResult>,
    /// The failure's `SCP-` code when the host error carried one.
    pub code: Option<String>,
    /// The host error's message when not `ok`.
    pub message: Option<String>,
}

/// A host failure's `SCP-` code and message.
type HostFailure = (Option<String>, Option<String>);

/// One accessor over the four host outcome shapes, so every custody method
/// maps a host failure the same way.
trait HostOutcome {
    type Value;
    /// The value on success (`None` when the host sent none), or the failure.
    fn into_outcome(self) -> Result<Option<Self::Value>, HostFailure>;
}

macro_rules! host_outcome_with_value {
    ($ty:ty, $value:ty) => {
        impl HostOutcome for $ty {
            type Value = $value;
            fn into_outcome(self) -> Result<Option<Self::Value>, HostFailure> {
                if self.ok {
                    Ok(self.value)
                } else {
                    Err((self.code, self.message))
                }
            }
        }
    };
}

host_outcome_with_value!(HostStringResult, String);
host_outcome_with_value!(HostBytesResult, Vec<u8>);
host_outcome_with_value!(HostPseudonymResult, NapiPseudonymResult);

impl HostOutcome for HostUnitResult {
    type Value = ();
    fn into_outcome(self) -> Result<Option<()>, HostFailure> {
        if self.ok {
            Ok(Some(()))
        } else {
            Err((self.code, self.message))
        }
    }
}

/// Maps a host callback's outcome to the custody result: the value on
/// success, [`PlatformError::KeyNotFound`] for a `SCP-CRYPTO-4001` failure,
/// and [`PlatformError::CustodyError`] for any other failure, for a success
/// with no value, and for a call the bridge could not complete.
fn host_value<R: HostOutcome>(
    method: &str,
    call: napi::Result<R>,
) -> Result<R::Value, PlatformError> {
    let outcome = call.map_err(|e| {
        PlatformError::CustodyError(format!("KeyCustodyProvider.{method} call failed: {e}"))
    })?;
    match outcome.into_outcome() {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} reported success with no value"
        ))),
        Err((Some(code), _)) if code == scp_ffi_common::error_codes::CRYPTO_4001 => {
            Err(PlatformError::KeyNotFound)
        }
        Err((code, message)) => Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} failed{}: {}",
            code.map(|c| format!(" ({c})")).unwrap_or_default(),
            message.unwrap_or_default()
        ))),
    }
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
    generate_keypair: ThreadsafeFunction<String, HostStringResult, String, napi::Status, false>,
    sign: ThreadsafeFunction<
        (String, Vec<u8>),
        HostBytesResult,
        (String, Vec<u8>),
        napi::Status,
        false,
    >,
    get_public_key: ThreadsafeFunction<String, HostBytesResult, String, napi::Status, false>,
    destroy_key: ThreadsafeFunction<String, HostUnitResult, String, napi::Status, false>,
    dh_agree: ThreadsafeFunction<
        (String, Vec<u8>),
        HostBytesResult,
        (String, Vec<u8>),
        napi::Status,
        false,
    >,
    derive_pseudonym: ThreadsafeFunction<
        (String, Vec<u8>),
        HostPseudonymResult,
        (String, Vec<u8>),
        napi::Status,
        false,
    >,
    derive_rotatable_pseudonym: ThreadsafeFunction<
        (String, Vec<u8>, u64),
        HostPseudonymResult,
        (String, Vec<u8>, u64),
        napi::Status,
        false,
    >,
    export_signing_key_bytes:
        ThreadsafeFunction<String, HostBytesResult, String, napi::Status, false>,
    custody_type: ThreadsafeFunction<String, HostStringResult, String, napi::Status, false>,
}

/// Concrete [`KeyCustody`] adapter delegating to JS callbacks. The
/// callbacks run on the Node.js event loop (marshalled via
/// [`ThreadsafeFunction`]); the bridge awaits each via `call_async`.
pub(crate) struct NapiCallbackKeyCustody {
    tsfns: CallbackTsfns,
    /// Pseudonym key ids bound to the point their derivation returned; a
    /// `sign` on one of them is checked strictly against that point.
    pub(crate) pseudonyms: scp_ffi_common::custody_parse::PseudonymBindings,
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
            },
            pseudonyms: scp_ffi_common::custody_parse::PseudonymBindings::default(),
        })
    }

    /// Validates a host pseudonym result and binds its key id to its point.
    ///
    /// The point must be a valid 33-byte compressed P-256 point, the key id
    /// numeric, and `getPublicKey(keyId)` must return the same 33 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::CustodyError`] on any of those failures.
    async fn bind_pseudonym(
        &self,
        method: &str,
        result: NapiPseudonymResult,
    ) -> Result<PseudonymKeypair, PlatformError> {
        let pseudonym = scp_ffi_common::custody_parse::parse_pseudonym(
            method,
            &result.public_key,
            &result.key_id,
        )?;
        let host_public_key = host_value(
            "get_public_key",
            self.tsfns
                .get_public_key
                .call_async(pseudonym.key_handle().id().to_string())
                .await,
        )?;
        self.pseudonyms.bind(method, &pseudonym, &host_public_key)?;
        Ok(pseudonym)
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
        let bytes = zeroize::Zeroizing::new(host_value(
            "export_signing_key_bytes",
            self.tsfns
                .export_signing_key_bytes
                .call_async(handle.id().to_string())
                .await,
        )?);
        let arr = zeroize::Zeroizing::new(scp_ffi_common::custody_parse::expect_32(
            "export_signing_key_bytes",
            &bytes,
        )?);
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }
}

impl KeyCustody for NapiCallbackKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        let type_str = match key_type {
            KeyType::Ed25519 => "ed25519".to_owned(),
            KeyType::X25519 => "x25519".to_owned(),
        };
        let key_id = host_value(
            "generate_keypair",
            self.tsfns.generate_keypair.call_async(type_str).await,
        )?;
        scp_ffi_common::custody_parse::parse_handle("generate_keypair", &key_id)
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        let pseudonym = self.pseudonyms.check_sign_input(key, data)?;
        let sig = host_value(
            "sign",
            self.tsfns
                .sign
                .call_async((key.id().to_string(), data.to_vec()))
                .await,
        )?;
        if let Some((point, digest)) = pseudonym {
            scp_ffi_common::custody_parse::PseudonymBindings::check_signature(
                &point, &digest, &sig,
            )?;
        }
        Ok(Signature::new(sig))
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        let pk = host_value(
            "get_public_key",
            self.tsfns
                .get_public_key
                .call_async(key.id().to_string())
                .await,
        )?;
        Ok(PublicKey::new(pk))
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.pseudonyms
            .destroy_unbound(key, async {
                host_value(
                    "destroy_key",
                    self.tsfns
                        .destroy_key
                        .call_async(key.id().to_string())
                        .await,
                )
            })
            .await
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        // Wrap the raw shared secret in `Zeroizing` so the intermediate heap
        // buffer is wiped on drop once it has been copied into `SharedSecret`
        // (defense-in-depth, matching `export_ed25519_signing_key`; ADR-006).
        let shared = zeroize::Zeroizing::new(host_value(
            "dh_agree",
            self.tsfns
                .dh_agree
                .call_async((key.id().to_string(), peer_public.to_vec()))
                .await,
        )?);
        Ok(SharedSecret::new(scp_ffi_common::custody_parse::expect_32(
            "dh_agree", &shared,
        )?))
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError> {
        let result = host_value(
            "derive_pseudonym",
            self.tsfns
                .derive_pseudonym
                .call_async((key.id().to_string(), context_id.to_vec()))
                .await,
        )?;
        self.bind_pseudonym("derive_pseudonym", result).await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        // Canonical v2 recipe (spec §9.10.4.A / §9.10.4.1): the provider performs
        // the rotatable derivation itself — seed = HMAC-SHA256(pseudonym_secret,
        // context_id || BE64(pseudonym_epoch) || "scp-pseudonym-v2"); d =
        // seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed), returned as the 33-byte
        // compressed P-256 point. The epoch is threaded through to the
        // provider rather than synthesized into the context_id bridge-side, so
        // the v1 platform adapter does not re-append its own "scp-pseudonym"
        // domain separator (which would corrupt the v2 domain). Mirrors the
        // UniFFI / PyO3 CallbackKeyCustody contract.
        let result = host_value(
            "derive_rotatable_pseudonym",
            self.tsfns
                .derive_rotatable_pseudonym
                .call_async((key.id().to_string(), context_id.to_vec(), pseudonym_epoch))
                .await,
        )?;
        self.bind_pseudonym("derive_rotatable_pseudonym", result)
            .await
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
        let shared = zeroize::Zeroizing::new(host_value(
            "dh_agree",
            self.tsfns
                .dh_agree
                .call_async((ed25519_handle.id().to_string(), peer_x25519_public.to_vec()))
                .await,
        )?);
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
pub(crate) enum NapiKeyCustody {
    /// Test/dev in-memory custody (feature-gated), wrapped for redacted Debug.
    /// Boxed so the enum stays the size of the callback variant.
    #[cfg(feature = "testing")]
    InMemory(Box<OpaqueInMemoryKeyCustody>),
    /// Caller-provided custody backed by JS callbacks.
    Callback(NapiCallbackKeyCustody),
}

impl fmt::Debug for NapiKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(_) => f.write_str("NapiKeyCustody::InMemory([redacted])"),
            Self::Callback(_) => f.write_str("NapiKeyCustody::Callback([js])"),
        }
    }
}

impl NapiKeyCustody {
    /// Returns the custody-type label for handle reporting (`"in_memory"` for
    /// the in-memory test backend, `"callback"` for caller-provided callback
    /// custody).
    ///
    /// This is a cheap, sync variant discriminator — distinct from the async
    /// [`KeyCustody::custody_type`] trait method, which reports the
    /// per-key-handle [`CustodyType`] (hardware/software/in-memory) the
    /// underlying provider declares.
    pub(crate) const fn custody_type_label(&self) -> &'static str {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(_) => "in_memory",
            Self::Callback(_) => "callback",
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
            Self::Callback(kc) => kc.export_ed25519_signing_key(handle).await,
        }
    }
}

impl KeyCustody for NapiKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.generate_keypair(key_type).await,
            Self::Callback(kc) => kc.generate_keypair(key_type).await,
        }
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.sign(key, data).await,
            Self::Callback(kc) => kc.sign(key, data).await,
        }
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.public_key(key).await,
            Self::Callback(kc) => kc.public_key(key).await,
        }
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.destroy_key(key).await,
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
            Self::Callback(kc) => kc.custody_type(key),
        }
    }

    async fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.generate_ephemeral_ed25519_seed().await,
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
            Self::Callback(kc) => kc.import_ed25519_signing_key(seed).await,
        }
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
        let custody = NapiKeyCustody::InMemory(Box::new(OpaqueInMemoryKeyCustody(
            InMemoryKeyCustody::new(),
        )));
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
        let custody = NapiKeyCustody::InMemory(Box::new(OpaqueInMemoryKeyCustody(
            InMemoryKeyCustody::new(),
        )));
        let seed = custody
            .generate_ephemeral_ed25519_seed()
            .await
            .expect("ephemeral seed via enum");
        assert_eq!(seed.len(), 32);
    }
}
