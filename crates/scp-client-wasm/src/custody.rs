//! JS-injected key custody, adapted to the driver's [`scp_client::Signer`].
//!
//! Restores the deleted WASM bridge's `JsKeyCustody` extern shape
//! (`crates/scp-ffi/wasm/`, pinned at `1a3b41a5e^`): a JS object the TypeScript
//! wrapper injects, backed by the browser `WebCrypto` (`SubtleCrypto`) API. The
//! design intent (ADR-022, carried into ADR-057 component 3) is that the
//! private signing key lives in JS/WebCrypto and **never enters wasm linear
//! memory** — the Rust side calls *out* to JS to sign, holding only an opaque
//! `key_id` string.
//!
//! # IMPORTANT — what this slice can and cannot enforce (ADR-057 friction)
//!
//! The driver's identity abstraction is [`scp_client::Signer`], and in Slice 2
//! that trait does **not** sign: it returns only `did()` and
//! `signing_key_id()`. The MLS signing key actually used to sign MLS leaves and
//! commits is an ed25519 `SignatureKeyPair` generated and held **inside
//! `scp-mls`** (`create_group` / `generate_key_package`), in wasm linear
//! memory. So in this slice the "key never enters wasm" property is **not yet
//! achievable through `Signer`** — `scp-mls` holds the MLS key directly. This is
//! acknowledged by `scp_client::signer`'s own docs ("A future custody slice
//! unifies them behind one on-device key boundary").
//!
//! Consequently this module:
//! - restores the full [`JsKeyCustody`] extern surface (sign / getPublicKey /
//!   generateKeypair / destroyKey / dhAgree) so the `WebCrypto` custody seam is
//!   present and a later slice can route the MLS key through it **without a
//!   signature change**; and
//! - wires a [`JsSigner`] that reads the on-device DID identity (DID string +
//!   key id) from the injected custody object to satisfy today's `Signer`
//!   contract.
//!
//! The `sign` / `dhAgree` / key-generation externs are therefore declared (the
//! seam) but have no driver call site in this slice — exactly the honest
//! "extern present, not yet the signing path" state the deleted bridge
//! documented for its own injection-point methods. They are not dead-code
//! gamed: they are the typed contract the custody slice consumes next.

#[cfg(target_arch = "wasm32")]
pub use wasm_impl::{JsKeyCustody, JsSigner};

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use scp_client::Signer;
    use scp_did::SigningKeyId;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        /// Opaque JS object implementing on-device key custody.
        ///
        /// Injected by the TypeScript SDK, backed by `WebCrypto`
        /// (`SubtleCrypto`). The private key stays JS-side; the Rust boundary
        /// holds only the opaque `key_id`. Methods use `catch`, so a thrown JS
        /// exception surfaces as `Err(JsValue)`.
        pub type JsKeyCustody;

        /// The participant's DID string (e.g. `did:dht:z6Mk…`). Throws if the
        /// custody object has no bound identity.
        #[wasm_bindgen(method, catch, js_name = "did")]
        fn did(this: &JsKeyCustody) -> Result<String, JsValue>;

        /// Signs `data` with the key identified by `key_id`, returning the
        /// signature bytes. The private key never leaves JS/WebCrypto.
        ///
        /// `data` is passed **by value** (an owned `Vec<u8>`), so wasm-bindgen
        /// marshals it as a JS-owned `Uint8Array` copy detached from wasm linear
        /// memory — NOT a `subarray` view into it (which `&[u8]` would produce).
        /// This matches [`storage::JsStorage::set`](crate::storage)'s owned-copy
        /// discipline and is load-bearing for the same reason: a synchronous-facade
        /// or async-`WebCrypto` implementation that *retains* the buffer past the
        /// call (queues it, awaits `SubtleCrypto.sign`, or logs it) is sound with an
        /// owned `Vec<u8>`, but with a `&[u8]` view would alias wasm memory that
        /// later allocations reuse — corrupting the bytes it later signs. Handing
        /// over an owned copy makes the contract sound for any embedder, not only
        /// one that copies before returning.
        ///
        /// SEAM: declared for the future custody slice (ADR-057 component 3);
        /// no driver call site in this slice (the MLS key is held in `scp-mls`
        /// — see module docs). Frozen to `Vec<u8>` NOW so that slice wires it
        /// without a signature change and does not inherit the view-aliasing
        /// footgun.
        #[wasm_bindgen(method, catch, js_name = "sign")]
        fn sign(this: &JsKeyCustody, key_id: &str, data: Vec<u8>) -> Result<Vec<u8>, JsValue>;

        /// Returns the raw public key bytes for `key_id`. Throws if absent.
        ///
        /// SEAM: see [`JsKeyCustody::sign`].
        #[wasm_bindgen(method, catch, js_name = "getPublicKey")]
        fn get_public_key(this: &JsKeyCustody, key_id: &str) -> Result<Vec<u8>, JsValue>;

        /// Generates a keypair of type `key_type` (`"ed25519"` / `"x25519"`)
        /// and returns its opaque `key_id`.
        ///
        /// SEAM: see [`JsKeyCustody::sign`].
        #[wasm_bindgen(method, catch, js_name = "generateKeypair")]
        fn generate_keypair(this: &JsKeyCustody, key_type: &str) -> Result<String, JsValue>;

        /// Destroys the key identified by `key_id`, zeroing its material.
        /// Idempotent.
        ///
        /// SEAM: see [`JsKeyCustody::sign`].
        #[wasm_bindgen(method, catch, js_name = "destroyKey")]
        fn destroy_key(this: &JsKeyCustody, key_id: &str) -> Result<(), JsValue>;

        /// Performs X25519 DH agreement against `peer_public`, returning the
        /// 32-byte shared secret.
        ///
        /// `peer_public` is passed **by value** (an owned `Vec<u8>`) for the same
        /// owned-copy-detached-from-wasm-memory reason as [`JsKeyCustody::sign`] —
        /// a retaining async-`WebCrypto` (`SubtleCrypto.deriveBits`) facade is sound
        /// with `Vec<u8>` where a `&[u8]` view would alias reused wasm memory.
        ///
        /// SEAM: see [`JsKeyCustody::sign`].
        #[wasm_bindgen(method, catch, js_name = "dhAgree")]
        fn dh_agree(
            this: &JsKeyCustody,
            key_id: &str,
            peer_public: Vec<u8>,
        ) -> Result<Vec<u8>, JsValue>;
    }

    /// Adapts an injected [`JsKeyCustody`] to the driver's [`Signer`] trait.
    ///
    /// Reads the on-device DID once at construction (so the `Signer` accessors
    /// stay infallible, matching the trait), and acts as the human's active
    /// signing key ([`SigningKeyId::Active`]) — the common participant case.
    pub struct JsSigner {
        did: String,
        signing_key_id: SigningKeyId,
        // The custody handle is retained so the future custody slice can route
        // the MLS signing key through `JsKeyCustody::sign` without re-injecting.
        // It has no call site in this slice (see module docs).
        #[allow(dead_code)]
        custody: JsKeyCustody,
    }

    impl JsSigner {
        /// Builds a signer from an injected custody object, reading its bound
        /// DID. Acts as [`SigningKeyId::Active`].
        ///
        /// # Errors
        ///
        /// Returns the JS exception (as a `JsValue`) if the custody object has
        /// no bound DID identity.
        pub fn from_custody(custody: JsKeyCustody) -> Result<Self, JsValue> {
            let did = custody.did()?;
            Ok(Self {
                did,
                signing_key_id: SigningKeyId::Active,
                custody,
            })
        }
    }

    // SAFETY: identical single-thread justification to `storage::JsStorageAdapter`
    // — see that module's "Single-thread soundness" + "Embedder obligation"
    // notes. The wrapped `JsKeyCustody` handle is a JS-heap index that cannot
    // cross a worker-agent boundary; under the single-tab driver model it is
    // never sent to another agent, so the driver's `Send + Sync` bound on
    // `Signer` is satisfied. Compiled ONLY for wasm32; does not relax the shared
    // `scp_client::Signer` bound. The embedder must keep one client pinned to
    // one agent if it ever wires shared-memory threads.
    unsafe impl Send for JsSigner {}
    // SAFETY: as above (see storage.rs module docs).
    unsafe impl Sync for JsSigner {}

    impl Signer for JsSigner {
        fn did(&self) -> &str {
            &self.did
        }

        fn signing_key_id(&self) -> SigningKeyId {
            self.signing_key_id
        }
    }
}
