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
use scp_ffi_common::callback_custody::{self as flow, CallbackKeyRegistry, HostPublicKey};
use scp_platform::error::PlatformError;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyRole, KeyType, Pseudonym, PublicKey, SharedSecret,
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
/// returns the failure arm. A failure whose `code` is `SCP-CRYPTO-4006` maps to
/// [`PlatformError::KeyNotFound`]; any other failure maps to
/// [`PlatformError::CustodyError`].
///
/// The JS callbacks are synchronous (they return the outcome directly, not a
/// `Promise`) — keystore reads are fast and the bridge awaits the dispatch via
/// [`call_host`]. Private key material never crosses into
/// Rust ownership (ADR-006): the consumer owns the secrets and returns only
/// public bytes and key-id strings.
///
/// Every key id the host returns is the canonical decimal form of a `u64`, as
/// `String(n)` writes it for a `bigint` `n`: ASCII digits only, with no sign,
/// no leading zero (`"0"` itself is allowed) and no whitespace
/// ([`parse_handle`](scp_ffi_common::custody_parse::parse_handle)). Any other
/// id is rejected with the custody error `SCP-CRYPTO-4060`.
///
/// A pseudonym has no private key (§9.10.4): `derivePseudonym` and
/// `deriveRotatablePseudonym` return only the 33-byte compressed P-256 point,
/// and the bridge fails the derivation with `SCP-IDENT-1055` when the bytes
/// are not a valid point (ADR-021 2026-09-29 amendment). `sign`,
/// `getPublicKey` and `destroyKey` never receive a pseudonym.
#[napi(object, object_to_js = false)]
pub struct NapiKeyCustodyProvider {
    /// `(keyType: CustodyKeyType, role: CustodyKeyRole) => string` —
    /// generate a keypair, return its id, a canonical decimal `u64` string
    /// (`SCP-CRYPTO-4060` otherwise). `role` is `"identity"` (the only
    /// pseudonym-derivation source) or `"operational"`. The host records
    /// `role` and reports it from `getPublicKey` for the key's lifetime; the
    /// bridge refuses and destroys a key whose reported type or role differs.
    /// The host never reuses a key id: an id it returns here names no other
    /// key for the host's lifetime, even after that key is destroyed.
    #[napi(
        ts_type = "(args: [\"ed25519\" | \"x25519\" | \"p256\" | \"hpke-p256\", \"identity\" | \"operational\"]) => { ok: boolean; value?: string; code?: string; message?: string }"
    )]
    pub generate_keypair:
        Function<'static, (NapiCustodyKeyType, NapiCustodyKeyRole), HostStringResult>,
    /// `(keyId: string, message: Uint8Array) => Uint8Array` — 64-byte sig.
    /// For a `"p256"` key `message` is a 32-byte prehash and the result is
    /// raw `r || s` (64 bytes) or DER; Rust normalises to low-s and verifies
    /// it strictly against the key's public key, rejecting any mismatch. A
    /// software host MUST derive the ECDSA nonce by RFC 6979 with SHA-256; a
    /// hardware host may use a random nonce.
    #[napi(
        ts_type = "(args: [string, number[]]) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub sign: Function<'static, (String, Vec<u8>), HostBytesResult>,
    /// `(keyId: string) => { keyType, publicKey, role }` — the key's type
    /// (`"ed25519"`, `"x25519"`, `"p256"` or `"hpke-p256"`) and its public
    /// key: exactly 32 bytes (Ed25519 / X25519), the 33-byte compressed SEC1
    /// point (`"p256"`) or the 65-byte uncompressed SEC1 point
    /// (`"hpke-p256"`). The bridge types the key from `keyType`, never from
    /// the length, and refuses any other length. A key id the host does not
    /// hold is a failure whose `code` is `"SCP-CRYPTO-4006"`. `role` is the
    /// role `generateKeypair` minted the key in, reported across sessions. A
    /// key id the bridge has not seen binds as an identity only when `role`
    /// is `"identity"`. A `keyType` or `role` outside the two enums is a
    /// custody error. The bridge cannot check the host's word: a host that
    /// reports `"identity"` for a key it minted as `"operational"` lets that
    /// key derive pseudonyms, which is outside Rust's control.
    #[napi(
        ts_type = "(keyId: string) => { ok: boolean; value?: { keyType: \"ed25519\" | \"x25519\" | \"p256\" | \"hpke-p256\"; publicKey: number[]; role: \"identity\" | \"operational\" }; code?: string; message?: string }"
    )]
    pub get_public_key: Function<'static, String, HostPublicKeyResult>,
    /// `(keyId: string) => void` — destroy key material.
    #[napi(
        ts_type = "(keyId: string) => { ok: boolean; value?: undefined; code?: string; message?: string }"
    )]
    pub destroy_key: Function<'static, String, HostUnitResult>,
    /// `(keyId: string, peerPublic: Uint8Array) => Uint8Array` — 32 shared
    /// bytes; an `"hpke-p256"` key receives the 65-byte uncompressed peer
    /// point.
    #[napi(
        ts_type = "(args: [string, number[]]) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub dh_agree: Function<'static, (String, Vec<u8>), HostBytesResult>,
    /// `(keyId: string, contextId: Uint8Array) => Uint8Array` — the §9.10.4
    /// v1 pseudonym: the 33-byte compressed P-256 point. The bridge rejects
    /// any other bytes with `SCP-IDENT-1055`; a host `SCP-CRYPTO-4006` means
    /// the identity key is not found.
    ///
    /// Canonical recipe (§9.10.4, §9.10.4.A; `ikm` is the identity private key
    /// material, the 32-byte Ed25519 seed until the identity key
    /// moves to P-256 (SCP-315)):
    ///   1. `pseudonym_secret = HKDF-SHA256(ikm, salt="scp-pseudonym-secret-v1", info="", L=32)`
    ///   2. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
    ///   3. `d = seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed)`; return the
    ///      compressed point `d·G`. `d` is discarded, never stored.
    ///
    /// The HMAC key is the 32-byte `pseudonym_secret`, never the public key:
    /// public key bytes would be a membership-enumeration oracle (§9.10.4.A).
    #[napi(
        ts_type = "(args: [string, number[]]) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub derive_pseudonym: Function<'static, (String, Vec<u8>), HostBytesResult>,
    /// `(keyId: string, contextId: Uint8Array, pseudonymEpoch: bigint) => Uint8Array`
    /// — the §9.10.4.1 rotatable v2 pseudonym, same return shape and checks
    /// as `derivePseudonym`. The provider performs the canonical derivation,
    /// steps 1 and 3 of `derivePseudonym` with step 2 replaced by
    ///   `seed = HMAC-SHA256(pseudonym_secret, context_id || BE64(pseudonymEpoch) || "scp-pseudonym-v2")`
    /// where `BE64` is the 8-byte big-endian epoch; the HMAC key is the
    /// `pseudonym_secret`, never the public key. The bridge does NOT
    /// synthesize the preimage.
    #[napi(
        ts_type = "(args: [string, number[], bigint]) => { ok: boolean; value?: number[]; code?: string; message?: string }"
    )]
    pub derive_rotatable_pseudonym: Function<'static, (String, Vec<u8>, u64), HostBytesResult>,
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

/// The type of a host custody key, as the host contract names it.
#[napi(string_enum, js_name = "CustodyKeyType")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiCustodyKeyType {
    /// An Ed25519 signing key.
    #[napi(value = "ed25519")]
    Ed25519,
    /// An X25519 key-agreement key.
    #[napi(value = "x25519")]
    X25519,
    /// A P-256 signing key.
    #[napi(value = "p256")]
    P256,
    /// A P-256 HPKE key-agreement key.
    #[napi(value = "hpke-p256")]
    HpkeP256,
}

impl From<KeyType> for NapiCustodyKeyType {
    fn from(key_type: KeyType) -> Self {
        match key_type {
            KeyType::Ed25519 => Self::Ed25519,
            KeyType::X25519 => Self::X25519,
            KeyType::P256Signing => Self::P256,
            KeyType::HpkeP256 => Self::HpkeP256,
        }
    }
}

impl From<NapiCustodyKeyType> for KeyType {
    fn from(key_type: NapiCustodyKeyType) -> Self {
        match key_type {
            NapiCustodyKeyType::Ed25519 => Self::Ed25519,
            NapiCustodyKeyType::X25519 => Self::X25519,
            NapiCustodyKeyType::P256 => Self::P256Signing,
            NapiCustodyKeyType::HpkeP256 => Self::HpkeP256,
        }
    }
}

/// The role a host custody key was minted in.
#[napi(string_enum, js_name = "CustodyKeyRole")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiCustodyKeyRole {
    /// The participant's identity key, the only pseudonym-derivation source.
    #[napi(value = "identity")]
    Identity,
    /// Any other key.
    #[napi(value = "operational")]
    Operational,
}

impl From<KeyRole> for NapiCustodyKeyRole {
    fn from(role: KeyRole) -> Self {
        match role {
            KeyRole::Identity => Self::Identity,
            KeyRole::Operational => Self::Operational,
        }
    }
}

impl From<NapiCustodyKeyRole> for KeyRole {
    fn from(role: NapiCustodyKeyRole) -> Self {
        match role {
            NapiCustodyKeyRole::Identity => Self::Identity,
            NapiCustodyKeyRole::Operational => Self::Operational,
        }
    }
}

/// A host key's stated type, public key and role, returned by `getPublicKey`.
#[napi(object)]
pub struct NapiCustodyPublicKey {
    /// The key's type.
    pub key_type: NapiCustodyKeyType,
    /// The public key in the exact encoding its type names.
    pub public_key: Vec<u8>,
    /// The role the key was minted in.
    pub role: NapiCustodyKeyRole,
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
/// `derivePseudonym`, `deriveRotatablePseudonym`, `exportSigningKeyBytes`).
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

/// A host callback outcome carrying a key's type and public key
/// (`getPublicKey`).
#[napi(object, object_to_js = false)]
pub struct HostPublicKeyResult {
    /// `true` when the host call succeeded and `value` holds its result.
    pub ok: bool,
    /// The host's result when `ok`.
    pub value: Option<NapiCustodyPublicKey>,
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

/// A host failure's `SCP-` code and message.
type HostFailure = (Option<String>, Option<String>);

/// One accessor over the three host outcome shapes, so every custody method
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
host_outcome_with_value!(HostPublicKeyResult, NapiCustodyPublicKey);

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
/// success, [`PlatformError::KeyNotFound`] for a `SCP-CRYPTO-4006` failure,
/// and [`PlatformError::CustodyError`] for any other failure and for a
/// success with no value.
fn host_value<R: HostOutcome>(method: &str, outcome: R) -> Result<R::Value, PlatformError> {
    match outcome.into_outcome() {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} reported success with no value"
        ))),
        Err((code, message)) => Err(scp_ffi_common::custody_parse::host_failure(
            method,
            code.as_deref(),
            message.as_deref().unwrap_or_default(),
        )),
    }
}

// ---------------------------------------------------------------------------
// NapiCallbackKeyCustody — concrete `KeyCustody` adapter over the JS callbacks
// ---------------------------------------------------------------------------

/// Calls a JS custody callback and awaits its outcome.
///
/// The SDK's `custody-adapter.ts` returns every host call as a structured
/// outcome, which [`host_value`] maps through the shared code table. The
/// callback runs through `call_with_return_value`, whose completion closure
/// runs on the JS thread, so a callback that throws anyway (a record built
/// without the SDK adapter) reaches this closure as a value (napi's
/// `call_async` instead re-throws it through `napi_fatal_exception`, an
/// uncaught exception in the host) and maps through the same table by its
/// `code`. A return of the wrong JS type, or a call that cannot be queued, is
/// a custody error.
async fn call_host<T, R>(
    method: &'static str,
    tsfn: &ThreadsafeFunction<T, R, T, napi::Status, false>,
    value: T,
) -> Result<R::Value, PlatformError>
where
    T: 'static + napi::bindgen_prelude::JsValuesTupleIntoVec,
    R: 'static + napi::bindgen_prelude::FromNapiValue + HostOutcome + Send,
    R::Value: Send,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let status = tsfn.call_with_return_value(
        value,
        ThreadsafeFunctionCallMode::NonBlocking,
        move |result: napi::Result<R>, env: napi::Env| {
            let result = match result {
                Ok(outcome) => host_value(method, outcome),
                Err(e) => {
                    let reason = e.reason.clone();
                    Err(scp_ffi_common::custody_parse::host_failure(
                        method,
                        js_error_code(&env, e).as_deref(),
                        &reason,
                    ))
                }
            };
            // A send fails only when the awaiting caller was dropped, so
            // there is no one left to report to.
            let _ = tx.send(result);
            Ok(())
        },
    );
    if status != napi::Status::Ok {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method}: the call could not be queued ({status})"
        )));
    }
    rx.await.map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method}: the call ended without a result"
        ))
    })?
}

/// The string `code` property of a thrown JS object, if it has one.
fn js_error_code(env: &napi::Env, e: napi::Error) -> Option<String> {
    use napi::bindgen_prelude::{FromNapiValue, ToNapiValue};
    use napi::sys;
    let raw_env = env.raw();
    // SAFETY: this runs inside a threadsafe-function completion on the JS
    // thread, with the live `env` napi passed to it. `to_napi_value` returns
    // the referenced thrown value (or a fresh error when there is none), and
    // each property read is checked for success and type before use.
    unsafe {
        let thrown = napi::Error::to_napi_value(raw_env, e).ok()?;
        let mut kind = 0;
        if sys::napi_typeof(raw_env, thrown, &raw mut kind) != sys::Status::napi_ok
            || kind != sys::ValueType::napi_object
        {
            return None;
        }
        let mut code = std::ptr::null_mut();
        if sys::napi_get_named_property(raw_env, thrown, c"code".as_ptr(), &raw mut code)
            != sys::Status::napi_ok
            || sys::napi_typeof(raw_env, code, &raw mut kind) != sys::Status::napi_ok
            || kind != sys::ValueType::napi_string
        {
            return None;
        }
        String::from_napi_value(raw_env, code).ok()
    }
}

/// Threadsafe-function handles for each custody operation. Built once from a
/// [`NapiKeyCustodyProvider`] at `identityCreateWithCustody` time; thereafter
/// callable from any tokio worker thread driving the async custody trait.
///
/// The `ThreadsafeFunction` generics are intrinsically verbose (arg type,
/// return type, raw-arg type, error status, callee-handled flag); there is no
/// type alias that meaningfully simplifies them without obscuring the
/// per-field arg/return shapes.
#[allow(clippy::type_complexity)]
pub(crate) struct CallbackTsfns {
    generate_keypair: ThreadsafeFunction<
        (NapiCustodyKeyType, NapiCustodyKeyRole),
        HostStringResult,
        (NapiCustodyKeyType, NapiCustodyKeyRole),
        napi::Status,
        false,
    >,
    sign: ThreadsafeFunction<
        (String, Vec<u8>),
        HostBytesResult,
        (String, Vec<u8>),
        napi::Status,
        false,
    >,
    get_public_key: ThreadsafeFunction<String, HostPublicKeyResult, String, napi::Status, false>,
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
        HostBytesResult,
        (String, Vec<u8>),
        napi::Status,
        false,
    >,
    derive_rotatable_pseudonym: ThreadsafeFunction<
        (String, Vec<u8>, u64),
        HostBytesResult,
        (String, Vec<u8>, u64),
        napi::Status,
        false,
    >,
    export_signing_key_bytes:
        ThreadsafeFunction<String, HostBytesResult, String, napi::Status, false>,
    custody_type: ThreadsafeFunction<String, HostStringResult, String, napi::Status, false>,
}

/// The JS custody callbacks as the adapter calls them: one method per
/// callback, each returning the host's answer or a [`PlatformError`].
/// [`CallbackTsfns`] is the production host; a test host stands in for Node
/// so the adapter's wiring runs under plain `cargo test`.
pub(crate) trait JsCustodyHost: Send + Sync {
    fn generate_keypair(
        &self,
        key_type: KeyType,
        role: KeyRole,
    ) -> impl Future<Output = Result<String, PlatformError>> + Send;
    fn sign(
        &self,
        key_id: String,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, PlatformError>> + Send;
    fn get_public_key(
        &self,
        key_id: String,
    ) -> impl Future<Output = Result<HostPublicKey, PlatformError>> + Send;
    fn destroy_key(&self, key_id: String)
    -> impl Future<Output = Result<(), PlatformError>> + Send;
    fn dh_agree(
        &self,
        key_id: String,
        peer: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, PlatformError>> + Send;
    fn derive_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, PlatformError>> + Send;
    fn derive_rotatable_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
        epoch: u64,
    ) -> impl Future<Output = Result<Vec<u8>, PlatformError>> + Send;
    fn export_signing_key_bytes(
        &self,
        key_id: String,
    ) -> impl Future<Output = Result<Vec<u8>, PlatformError>> + Send;
    /// Fire-and-forget: the answer is advisory and has no synchronous path.
    fn notify_custody_type(&self, key_id: String);
}

impl JsCustodyHost for CallbackTsfns {
    async fn generate_keypair(
        &self,
        key_type: KeyType,
        role: KeyRole,
    ) -> Result<String, PlatformError> {
        call_host(
            "generate_keypair",
            &self.generate_keypair,
            (key_type.into(), role.into()),
        )
        .await
    }

    async fn sign(&self, key_id: String, data: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        call_host("sign", &self.sign, (key_id, data)).await
    }

    async fn get_public_key(&self, key_id: String) -> Result<HostPublicKey, PlatformError> {
        let answer = call_host("get_public_key", &self.get_public_key, key_id).await?;
        Ok(HostPublicKey {
            key_type: answer.key_type.into(),
            public_key: answer.public_key,
            role: answer.role.into(),
        })
    }

    async fn destroy_key(&self, key_id: String) -> Result<(), PlatformError> {
        call_host("destroy_key", &self.destroy_key, key_id).await
    }

    async fn dh_agree(&self, key_id: String, peer: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        call_host("dh_agree", &self.dh_agree, (key_id, peer)).await
    }

    async fn derive_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
    ) -> Result<Vec<u8>, PlatformError> {
        call_host(
            "derive_pseudonym",
            &self.derive_pseudonym,
            (key_id, context_id),
        )
        .await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key_id: String,
        context_id: Vec<u8>,
        epoch: u64,
    ) -> Result<Vec<u8>, PlatformError> {
        call_host(
            "derive_rotatable_pseudonym",
            &self.derive_rotatable_pseudonym,
            (key_id, context_id, epoch),
        )
        .await
    }

    async fn export_signing_key_bytes(&self, key_id: String) -> Result<Vec<u8>, PlatformError> {
        call_host(
            "export_signing_key_bytes",
            &self.export_signing_key_bytes,
            key_id,
        )
        .await
    }

    fn notify_custody_type(&self, key_id: String) {
        // The advisory answer is discarded (see `custody_type`), so a failed
        // enqueue loses nothing.
        let _ = self
            .custody_type
            .call(key_id, ThreadsafeFunctionCallMode::NonBlocking);
    }
}

/// Concrete [`KeyCustody`] adapter delegating to a [`JsCustodyHost`]. In
/// production the host is the JS callbacks ([`NapiCallbackKeyCustody`]),
/// which run on the Node.js event loop and are awaited through
/// [`call_host`].
pub(crate) struct CallbackAdapter<H> {
    host: H,
    /// The type, public key and role of each handle this adapter minted or
    /// resolved through the host's structured `getPublicKey`.
    pub(crate) registry: CallbackKeyRegistry,
}

/// The adapter over the JS callbacks.
pub(crate) type NapiCallbackKeyCustody = CallbackAdapter<CallbackTsfns>;

impl<H> fmt::Debug for CallbackAdapter<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NapiCallbackKeyCustody([js])")
    }
}

impl<H> CallbackAdapter<H> {
    fn over(host: H) -> Self {
        Self {
            host,
            registry: CallbackKeyRegistry::new(),
        }
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
        Ok(Self::over(CallbackTsfns {
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
        }))
    }
}

impl<H: JsCustodyHost> CallbackAdapter<H> {
    /// Exports the raw Ed25519 signing key via the provider's
    /// `exportSigningKeyBytes` callback through
    /// [`flow::export_ed25519_signing_key`], which requires the seed to
    /// produce the handle's verifying key.
    ///
    /// # Errors
    ///
    /// [`PlatformError::WrongKeyType`] for a handle of another type, before
    /// any export call; [`PlatformError::KeyNotFound`] for a handle the host
    /// does not hold; [`PlatformError::CustodyError`] if the callback raises,
    /// returns a non-32-byte value, or returns a seed for another key.
    pub async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ed25519_dalek::SigningKey, PlatformError> {
        let h = &self.host;
        flow::export_ed25519_signing_key(
            &self.registry,
            handle,
            |key_id| h.export_signing_key_bytes(key_id),
            |key_id| h.get_public_key(key_id),
        )
        .await
    }
}

impl<H: JsCustodyHost> KeyCustody for CallbackAdapter<H> {
    // The shared flows in `scp_ffi_common::callback_custody` hold every
    // key-type, length, role and signature rule; each closure is one host
    // callback. Every entry point resolves a handle this adapter has not
    // registered through `getPublicKey`.
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        let h = &self.host;
        flow::generate_operational(
            &self.registry,
            key_type,
            |key_type, role| h.generate_keypair(key_type, role),
            |key_id| h.get_public_key(key_id),
            |key_id| h.destroy_key(key_id),
        )
        .await
    }

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        let h = &self.host;
        flow::generate_identity(
            &self.registry,
            |key_type, role| h.generate_keypair(key_type, role),
            |key_id| h.get_public_key(key_id),
            |key_id| h.destroy_key(key_id),
        )
        .await
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        let h = &self.host;
        flow::sign(
            &self.registry,
            key,
            data,
            |key_id, data| h.sign(key_id, data),
            |key_id| h.get_public_key(key_id),
        )
        .await
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        let h = &self.host;
        flow::public_key(&self.registry, key, |key_id| h.get_public_key(key_id)).await
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        let h = &self.host;
        flow::destroy_key(&self.registry, key, |key_id| h.destroy_key(key_id)).await
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> Result<SharedSecret, PlatformError> {
        let h = &self.host;
        flow::dh_agree(
            &self.registry,
            key,
            peer_public,
            |key_id, peer| h.dh_agree(key_id, peer),
            |key_id| h.get_public_key(key_id),
        )
        .await
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<Pseudonym, PlatformError> {
        let h = &self.host;
        flow::derive_pseudonym(
            &self.registry,
            key,
            None,
            |key_id| h.derive_pseudonym(key_id, context_id.to_vec()),
            |key_id| h.get_public_key(key_id),
        )
        .await
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<Pseudonym, PlatformError> {
        // Canonical v2 recipe (spec §9.10.4.A / §9.10.4.1): the provider performs
        // the rotatable derivation itself — seed = HMAC-SHA256(pseudonym_secret,
        // context_id || BE64(pseudonym_epoch) || "scp-pseudonym-v2"); d =
        // seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed), returned as the 33-byte
        // compressed P-256 point. The epoch is threaded through to the
        // provider rather than synthesized into the context_id bridge-side, so
        // the v1 platform adapter does not re-append its own "scp-pseudonym"
        // domain separator (which would corrupt the v2 domain). Mirrors the
        // UniFFI / PyO3 CallbackKeyCustody contract.
        let h = &self.host;
        flow::derive_pseudonym(
            &self.registry,
            key,
            Some(pseudonym_epoch),
            |key_id| h.derive_rotatable_pseudonym(key_id, context_id.to_vec(), pseudonym_epoch),
            |key_id| h.get_public_key(key_id),
        )
        .await
    }

    async fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        let h = &self.host;
        flow::ed25519_to_x25519_agree(
            &self.registry,
            ed25519_handle,
            peer_x25519_public,
            |key_id, peer| h.dh_agree(key_id, peer),
            |key_id| h.get_public_key(key_id),
        )
        .await
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        // Sync query. `custody_type` returns immediately on the JS side; we
        // dispatch NonBlocking and, lacking a synchronous return path from a
        // worker thread, classify conservatively. The custody-type
        // classification is advisory metadata only (it does not gate any
        // security decision — membership is enforced by MLS keys), so a
        // callback-backed key is reported as `Software`, the correct class
        // for any non-HSM software keystore the SDK consumer would wire here.
        self.host.notify_custody_type(key.id().to_string());
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
        // NEW identity `#0` key, in the identity role. The callback protocol has no "import a
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

    async fn generate_identity_keypair(&self) -> Result<KeyHandle, PlatformError> {
        match self {
            #[cfg(feature = "testing")]
            Self::InMemory(kc) => kc.0.generate_identity_keypair().await,
            Self::Callback(kc) => kc.generate_identity_keypair().await,
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
        peer_public: &[u8],
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
    ) -> Result<Pseudonym, PlatformError> {
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
    ) -> Result<Pseudonym, PlatformError> {
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

/// The adapter itself ([`CallbackAdapter`]) over a software host that stands
/// in for the JS callbacks, one method per callback: a `ThreadsafeFunction`
/// needs a live Node.js runtime. The TypeScript SDK test covers the JS side.
#[cfg(test)]
#[allow(clippy::expect_used)]
mod adapter_tests {
    use std::sync::Arc;

    use scp_crypto::p256::{
        P256PublicKey, P256SecretKey, ecdh_p256, normalize_low_s, verify_prehash_strict,
    };
    use scp_ffi_common::callback_custody::fake_host::FakeHost;

    use super::*;

    /// A [`JsCustodyHost`] over the shared fake host. `sign_error`, when set,
    /// replaces every `sign` answer after the host call.
    struct TestHost {
        host: Arc<FakeHost>,
        sign_error: Option<fn() -> PlatformError>,
    }

    impl JsCustodyHost for TestHost {
        async fn generate_keypair(
            &self,
            key_type: KeyType,
            role: KeyRole,
        ) -> Result<String, PlatformError> {
            self.host.generate_keypair(key_type, role)
        }

        async fn sign(&self, key_id: String, data: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
            let answer = self.host.sign(&key_id, &data)?;
            self.sign_error.map_or(Ok(answer), |e| Err(e()))
        }

        async fn get_public_key(&self, key_id: String) -> Result<HostPublicKey, PlatformError> {
            self.host.get_public_key(&key_id)
        }

        async fn destroy_key(&self, key_id: String) -> Result<(), PlatformError> {
            self.host.destroy_key(&key_id)
        }

        async fn dh_agree(&self, key_id: String, peer: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
            self.host.dh_agree(&key_id, &peer)
        }

        async fn derive_pseudonym(
            &self,
            key_id: String,
            context_id: Vec<u8>,
        ) -> Result<Vec<u8>, PlatformError> {
            self.host.derive_pseudonym(&key_id, &context_id, None)
        }

        async fn derive_rotatable_pseudonym(
            &self,
            key_id: String,
            context_id: Vec<u8>,
            epoch: u64,
        ) -> Result<Vec<u8>, PlatformError> {
            self.host
                .derive_pseudonym(&key_id, &context_id, Some(epoch))
        }

        async fn export_signing_key_bytes(&self, key_id: String) -> Result<Vec<u8>, PlatformError> {
            self.host.export_signing_key_bytes(&key_id)
        }

        fn notify_custody_type(&self, _key_id: String) {}
    }

    fn adapter(host: &Arc<FakeHost>) -> CallbackAdapter<TestHost> {
        CallbackAdapter::over(TestHost {
            host: Arc::clone(host),
            sign_error: None,
        })
    }

    /// P-256 sign and HPKE `dh_agree` through the adapter. The host
    /// signs with a high `s` in DER; the adapter returns the raw low-`s`
    /// signature that strictly verifies. The host receives the peer as the
    /// 65-byte uncompressed point, and a compressed peer never reaches it.
    #[tokio::test]
    async fn napi_adapter_p256_sign_and_dh_agree_round_trip() {
        let host = Arc::new(FakeHost::default());
        let custody = adapter(&host);

        let signer = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .expect("p256 generation");
        let public = P256PublicKey::from_sec1(
            custody
                .public_key(&signer)
                .await
                .expect("public key")
                .as_bytes(),
        )
        .expect("a valid point");
        for i in 0u8..16 {
            let digest = [i; 32];
            let sig: [u8; 64] = custody
                .sign(&signer, &digest)
                .await
                .expect("sign")
                .as_bytes()
                .try_into()
                .expect("raw r || s");
            assert_eq!(normalize_low_s(&sig).expect("valid"), sig, "low s");
            verify_prehash_strict(&public, &digest, &sig).expect("strict verify");
        }

        let hpke = custody
            .generate_keypair(KeyType::HpkeP256)
            .await
            .expect("hpke-p256 generation");
        let hpke_public = P256PublicKey::from_sec1(
            custody
                .public_key(&hpke)
                .await
                .expect("public key")
                .as_bytes(),
        )
        .expect("a valid point");
        let peer = P256SecretKey::from_scalar_bytes(&[0x33; 32]).expect("scalar");
        let peer_point = peer.public_key().to_uncompressed();
        let shared = custody
            .dh_agree(&hpke, &peer_point)
            .await
            .expect("dh_agree");
        assert_eq!(shared.as_bytes(), ecdh_p256(&peer, &hpke_public).as_slice());
        assert_eq!(
            host.last_peer.lock().expect("lock").as_deref(),
            Some(peer_point.as_slice())
        );

        *host.last_peer.lock().expect("lock") = None;
        assert!(matches!(
            custody
                .dh_agree(&hpke, &peer.public_key().to_compressed())
                .await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(host.last_peer.lock().expect("lock").is_none());

        // An uncompressed point whose last coordinate byte is flipped is off
        // the curve, and is rejected before the host call.
        let mut off_curve = peer_point;
        off_curve[64] ^= 1;
        assert!(matches!(
            custody.dh_agree(&hpke, &off_curve).await,
            Err(PlatformError::CustodyError(_))
        ));
        assert!(
            host.last_peer.lock().expect("lock").is_none(),
            "an off-curve peer must be rejected before the host call"
        );
    }

    /// Each derivation reaches its own callback. Wiring
    /// `derive_rotatable_pseudonym` to the plain callback (or the reverse)
    /// changes the call counts and the derived point.
    #[tokio::test]
    async fn napi_adapter_routes_each_derivation_to_its_callback() {
        let host = Arc::new(FakeHost::default());
        let custody = adapter(&host);
        let identity = custody
            .generate_identity_keypair()
            .await
            .expect("identity generation");
        let seed = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(
                host.export_signing_key_bytes(&identity.id().to_string())
                    .expect("seed")
                    .as_slice(),
            )
            .expect("32 bytes"),
        );
        let expected = |version| scp_crypto::pseudonym::derive_pseudonym(&seed, b"ctx", version);

        let rotatable = custody
            .derive_rotatable_pseudonym(&identity, b"ctx", 3)
            .await
            .expect("rotatable derive");
        assert_eq!(host.calls("derive_rotatable_pseudonym"), 1);
        assert_eq!(host.calls("derive_pseudonym"), 0);
        assert_eq!(
            rotatable.public_key(),
            &expected(scp_crypto::pseudonym::PseudonymVersion::Rotatable { epoch: 3 })
        );

        let plain = custody
            .derive_pseudonym(&identity, b"ctx")
            .await
            .expect("plain derive");
        assert_eq!(host.calls("derive_pseudonym"), 1);
        assert_eq!(host.calls("derive_rotatable_pseudonym"), 1);
        assert_eq!(
            plain.public_key(),
            &expected(scp_crypto::pseudonym::PseudonymVersion::Static)
        );

        // An operational key is not a derive source (§9.10.4.A interim).
        let operational = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("ed25519 generation");
        assert!(matches!(
            custody.derive_pseudonym(&operational, b"ctx").await,
            Err(PlatformError::NotIdentityKey)
        ));
        assert_eq!(host.calls("derive_pseudonym"), 1);
    }

    /// A host failure whose `code` is `SCP-CRYPTO-4006` is the typed
    /// not-found, and any other failure, or a success with no value, a
    /// custody error; through `sign`, a host not-found reaches the caller as
    /// `KeyNotFound` and a transport error as `CustodyError`.
    #[tokio::test]
    async fn napi_adapter_maps_host_not_found_through_sign() {
        let failed = |code: Option<&str>| HostBytesResult {
            ok: false,
            value: None,
            code: code.map(str::to_owned),
            message: Some("boom".to_owned()),
        };
        assert!(matches!(
            host_value(
                "sign",
                failed(Some(scp_ffi_common::error_codes::CRYPTO_4006))
            ),
            Err(PlatformError::KeyNotFound)
        ));
        for code in [None, Some("ECONNRESET"), Some("KEY_NOT_FOUND")] {
            assert!(matches!(
                host_value("sign", failed(code)),
                Err(PlatformError::CustodyError(_))
            ));
        }
        assert!(matches!(
            host_value(
                "sign",
                HostBytesResult {
                    ok: true,
                    value: None,
                    code: None,
                    message: None,
                }
            ),
            Err(PlatformError::CustodyError(_))
        ));

        let host = Arc::new(FakeHost::default());
        let custody = adapter(&host);
        let key = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("ed25519 generation");
        // The host drops the key behind the adapter's back, so the not-found
        // comes from the host `sign` call, not from a lookup.
        host.destroy_key(&key.id().to_string())
            .expect("host destroy");
        assert!(matches!(
            custody.sign(&key, b"m").await,
            Err(PlatformError::KeyNotFound)
        ));
        assert_eq!(host.calls("sign"), 1);

        let transport = CallbackAdapter::over(TestHost {
            host: Arc::clone(&host),
            sign_error: Some(|| {
                scp_ffi_common::custody_parse::host_failure(
                    "sign",
                    Some("ECONNRESET"),
                    "socket closed",
                )
            }),
        });
        let key = transport
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("ed25519 generation");
        assert!(matches!(
            transport.sign(&key, b"m").await,
            Err(PlatformError::CustodyError(_))
        ));
        assert_eq!(host.calls("sign"), 2);
    }

    /// `export_ed25519_signing_key` and `ed25519_to_x25519_agree` refuse a
    /// P-256 handle, minted or resolved, with `WrongKeyType` before any host
    /// export or agreement call.
    #[tokio::test]
    async fn napi_adapter_ed25519_only_paths_refuse_p256() {
        let host = Arc::new(FakeHost::default());
        let custody = adapter(&host);
        let minted = custody
            .generate_keypair(KeyType::P256Signing)
            .await
            .expect("p256 generation");
        let resolved = KeyHandle::new(
            host.generate_keypair(KeyType::P256Signing, KeyRole::Operational)
                .expect("host-side key")
                .parse()
                .expect("numeric id"),
        );
        for handle in [minted, resolved] {
            assert!(matches!(
                custody.export_ed25519_signing_key(&handle).await,
                Err(PlatformError::WrongKeyType { .. })
            ));
            assert!(matches!(
                custody.ed25519_to_x25519_agree(&handle, &[9u8; 32]).await,
                Err(PlatformError::WrongKeyType { .. })
            ));
        }
        assert_eq!(host.calls("export_signing_key_bytes"), 0);
        assert_eq!(host.calls("dh_agree"), 0);

        let ed = custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .expect("ed25519 generation");
        custody
            .export_ed25519_signing_key(&ed)
            .await
            .expect("an Ed25519 key exports");
        assert_eq!(host.calls("export_signing_key_bytes"), 1);
    }
}
