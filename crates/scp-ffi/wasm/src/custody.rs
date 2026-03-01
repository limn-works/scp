//! JS-injected key custody callback types.
//!
//! The WASM bridge cannot use platform-native key stores (Secure Enclave,
//! Android Keystore) or a Rust-side key custody implementation that requires
//! native OS APIs. Instead, the TypeScript wrapper injects an object that
//! satisfies the `JsKeyCustody` extern type contract, backed by the browser's
//! `WebCrypto` API (`SubtleCrypto`).
//!
//! The extern "C" block declares the JS interface. The TypeScript SDK is
//! responsible for providing a conforming implementation at the call site.
//!
//! # `WebCrypto` integration pattern
//!
//! ```ts
//! // TypeScript wrapper creates a `WebCrypto`-backed custody object:
//! const custody = {
//!     sign(keyId: string, data: Uint8Array): Uint8Array { ... },
//!     getPublicKey(keyId: string): Uint8Array { ... },
//!     generateKeypair(keyType: string): string { ... },
//!     destroyKey(keyId: string): void { ... },
//! };
//! identity_create(custody);
//! ```
//!
//! # wasm-bindgen `catch` convention
//!
//! Methods annotated with `#[wasm_bindgen(method, catch)]` must return
//! `Result<T, JsValue>`. Thrown JS exceptions are caught by wasm-bindgen
//! and converted to `Err(JsValue)`. The bridge propagates these as
//! [`ScpWasmError::Crypto`](crate::error::ScpWasmError) messages.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` for the full specification.

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// JsKeyCustody — injected `WebCrypto`-backed key custody
// ---------------------------------------------------------------------------

/// Opaque JS object implementing key custody operations.
///
/// Declared as an extern type so that any JS object with the matching
/// method signatures can be passed in. The TypeScript SDK provides a
/// conforming implementation backed by `SubtleCrypto`.
///
/// All methods use `catch` so that thrown JS exceptions are converted to
/// `Err(JsValue)` at the Rust boundary.
#[wasm_bindgen]
extern "C" {
    /// A JS object that implements key custody for the WASM bridge.
    ///
    /// Implemented in TypeScript using the browser's `WebCrypto` API
    /// (`SubtleCrypto`). Injected at identity creation time.
    pub type JsKeyCustody;

    /// Signs `data` with the key identified by `key_id`.
    ///
    /// Returns the signature bytes (`Uint8Array` on the JS side). Throws
    /// on key-not-found or crypto failure.
    ///
    /// `key_id` is an opaque string issued by [`generate_keypair`].
    #[wasm_bindgen(method, catch, js_name = "sign")]
    pub fn sign(this: &JsKeyCustody, key_id: &str, data: &[u8]) -> Result<Vec<u8>, JsValue>;

    /// Returns the raw public key bytes for the key identified by `key_id`.
    ///
    /// Returns a `Uint8Array` on the JS side. Throws if the key is not found.
    #[wasm_bindgen(method, catch, js_name = "getPublicKey")]
    pub fn get_public_key(this: &JsKeyCustody, key_id: &str) -> Result<Vec<u8>, JsValue>;

    /// Generates a new keypair of type `key_type` and returns its `key_id`.
    ///
    /// `key_type` is one of `"ed25519"` or `"x25519"`. Returns a string key
    /// ID that identifies the generated keypair. Throws on key generation
    /// failure.
    #[wasm_bindgen(method, catch, js_name = "generateKeypair")]
    pub fn generate_keypair(this: &JsKeyCustody, key_type: &str) -> Result<String, JsValue>;

    /// Destroys the key identified by `key_id`, zeroing all key material.
    ///
    /// Idempotent — calling on a key that does not exist is a no-op.
    /// Throws on unexpected internal errors.
    #[wasm_bindgen(method, catch, js_name = "destroyKey")]
    pub fn destroy_key(this: &JsKeyCustody, key_id: &str) -> Result<(), JsValue>;

    /// Perform X25519 DH key agreement.
    /// peer_public: 32-byte peer X25519 public key as Uint8Array.
    /// Returns 32-byte shared secret as Uint8Array.
    #[wasm_bindgen(method, catch, js_name = "dhAgree")]
    pub fn dh_agree(
        this: &JsKeyCustody,
        key_id: &str,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, JsValue>;

    /// Derive a context-scoped Ed25519 pseudonym keypair.
    /// Algorithm: seed = HMAC-SHA256(public_key_bytes, context_id || "scp-pseudonym"), Ed25519_keygen(seed[0..32])
    /// Returns a JS object: { publicKeyBytes: Uint8Array, keyId: string }
    #[wasm_bindgen(method, catch, js_name = "derivePseudonym")]
    pub fn derive_pseudonym(
        this: &JsKeyCustody,
        key_id: &str,
        context_id: &[u8],
    ) -> Result<JsValue, JsValue>;
}
