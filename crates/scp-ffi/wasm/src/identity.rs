//! `wasm-bindgen` bridge for identity operations.
//!
//! Exposes [`WasmIdentity`] and [`WasmDIDDocument`] as opaque JS objects with
//! getter properties, plus three bridge functions for identity lifecycle:
//!
//! - [`identity_create`] — Creates a new DID identity (returns `Promise<WasmIdentity>`).
//! - [`identity_load`] — Loads an existing identity by DID string.
//! - [`identity_resolve`] — Resolves a DID to its document.
//!
//! All async operations use [`wasm_bindgen_futures::future_to_promise`] to
//! return JS `Promise` objects. No Tokio runtime is used — the browser event
//! loop drives all async execution.
//!
//! # WASM constraints and scp-core dependency
//!
//! `scp-core` depends on `tokio = { features = ["full"] }`, which includes the
//! multi-thread runtime. The `wasm32-unknown-unknown` target cannot compile
//! tokio's multi-thread runtime. Therefore, this bridge does NOT directly call
//! `scp-core` identity functions. Instead, it:
//!
//! 1. Provides the correct opaque types ([`WasmIdentity`], [`WasmDIDDocument`])
//!    that the TypeScript SDK wrapper consumes.
//! 2. Returns typed errors signalling which operations require JS-side
//!    implementation (WebCrypto for key ops, DHT HTTP gateway for resolution).
//! 3. Acts as the stable ABI boundary — the TypeScript wrapper implements the
//!    actual protocol operations and stores results in these opaque handles.
//!
//! When a future story adds WASM-compatible scp-core feature flags (e.g.,
//! `tokio/single-thread`), these stubs will be connected to scp-core directly.
//!
//! # Opaque types
//!
//! [`WasmIdentity`] stores the DID string and custody type — NOT raw key
//! material. Key operations are delegated to the JS-injected [`JsKeyCustody`]
//! (see `custody.rs`), backed by `SubtleCrypto`.
//!
//! [`WasmDIDDocument`] exposes all document fields as JSON strings for
//! ergonomic TypeScript consumption.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` for the full specification.

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// WasmIdentity — opaque JS object for SCP identity
// ---------------------------------------------------------------------------

/// An SCP identity handle exposed to JavaScript.
///
/// Stores the DID string and custody type as safe, cloneable metadata.
/// Internal key material is NOT stored here — it remains within the
/// [`JsKeyCustody`](crate::custody::JsKeyCustody) boundary on the JS side,
/// managed by the browser's `SubtleCrypto` API.
///
/// # JS usage
///
/// ```js
/// const identity = await identity_create("js_custody");
/// console.log(identity.did);          // "did:dht:z..."
/// console.log(identity.custodyType);  // "js_custody"
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmIdentity {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    did: String,
    /// The custody type used at identity creation (`"js_custody"`).
    custody_type: String,
}

#[wasm_bindgen]
impl WasmIdentity {
    /// Returns the DID string for this identity.
    #[wasm_bindgen(getter)]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    /// Returns the custody type string for this identity.
    ///
    /// Always `"js_custody"` for browser targets.
    #[wasm_bindgen(getter, js_name = "custodyType")]
    pub fn custody_type(&self) -> String {
        self.custody_type.clone()
    }

    /// Constructs a `WasmIdentity` from a DID string.
    ///
    /// Called by the TypeScript SDK after performing identity creation
    /// operations via WebCrypto. The SDK is responsible for:
    /// 1. Generating the Ed25519 keypairs via `SubtleCrypto.generateKey`.
    /// 2. Computing the `did:dht` string from the identity key public bytes.
    /// 3. Publishing the DID document to the DHT via HTTP gateway.
    /// 4. Calling `WasmIdentity.fromDid(did)` to obtain this handle.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1000]` if the DID prefix is not `did:dht:`.
    #[wasm_bindgen(js_name = "fromDid")]
    pub fn from_did(did: String) -> Result<WasmIdentity, JsError> {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity(format!(
                "unsupported DID method in {did:?} — only did:dht is supported"
            ))
            .into_js());
        }
        Ok(WasmIdentity {
            did,
            custody_type: "js_custody".to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// WasmDIDDocument — opaque JS object for DID documents
// ---------------------------------------------------------------------------

/// A DID Document exposed to JavaScript.
///
/// Exposes the document's public fields via getter properties. All structured
/// fields (verification methods, services) are returned as JSON strings for
/// ergonomic TypeScript consumption — the TS wrapper parses them with
/// `JSON.parse()`.
///
/// # JS usage
///
/// ```js
/// const doc = await identity_resolve("did:dht:z...");
/// const vms = JSON.parse(doc.verificationMethodsJson);
/// console.log(doc.id); // "did:dht:z..."
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmDIDDocument {
    /// The DID string this document describes.
    id: String,
    /// Verification methods serialized as JSON (array of objects with
    /// `id`, `type`, `controller`, `publicKeyMultibase`).
    verification_methods_json: String,
    /// Service entries serialized as JSON (array of objects with
    /// `id`, `type`, `serviceEndpoint`).
    services_json: String,
    /// `alsoKnownAs` entries serialized as JSON (array of strings).
    also_known_as_json: String,
    /// Authentication method references serialized as JSON (array of strings).
    authentication_json: String,
    /// Assertion method references serialized as JSON (array of strings).
    assertion_methods_json: String,
}

#[wasm_bindgen]
impl WasmDIDDocument {
    /// Returns the DID string this document describes.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Returns the verification methods as a JSON string.
    ///
    /// Each object has `id`, `type`, `controller`, and `publicKeyMultibase`.
    #[wasm_bindgen(getter, js_name = "verificationMethodsJson")]
    pub fn verification_methods_json(&self) -> String {
        self.verification_methods_json.clone()
    }

    /// Returns the service entries as a JSON string.
    ///
    /// Each object has `id`, `type`, and `serviceEndpoint`.
    #[wasm_bindgen(getter, js_name = "servicesJson")]
    pub fn services_json(&self) -> String {
        self.services_json.clone()
    }

    /// Returns the `alsoKnownAs` entries as a JSON string.
    #[wasm_bindgen(getter, js_name = "alsoKnownAsJson")]
    pub fn also_known_as_json(&self) -> String {
        self.also_known_as_json.clone()
    }

    /// Returns the authentication method references as a JSON string.
    #[wasm_bindgen(getter, js_name = "authenticationJson")]
    pub fn authentication_json(&self) -> String {
        self.authentication_json.clone()
    }

    /// Returns the assertion method references as a JSON string.
    #[wasm_bindgen(getter, js_name = "assertionMethodsJson")]
    pub fn assertion_methods_json(&self) -> String {
        self.assertion_methods_json.clone()
    }

    /// Constructs a `WasmDIDDocument` from JSON-encoded fields.
    ///
    /// Called by the TypeScript SDK after resolving a DID via the DHT HTTP
    /// gateway. The TypeScript layer performs the resolution and passes the
    /// parsed document fields back into the WASM boundary as JSON strings.
    ///
    /// All parameters must be valid JSON strings. Validation is performed by
    /// the TypeScript SDK before calling this constructor.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = "fromFields")]
    pub fn from_fields(
        id: String,
        verification_methods_json: String,
        services_json: String,
        also_known_as_json: String,
        authentication_json: String,
        assertion_methods_json: String,
    ) -> WasmDIDDocument {
        WasmDIDDocument {
            id,
            verification_methods_json,
            services_json,
            also_known_as_json,
            authentication_json,
            assertion_methods_json,
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Creates a new DID identity.
///
/// In the browser WASM target, identity creation requires WebCrypto (via the
/// injected [`JsKeyCustody`](crate::custody::JsKeyCustody)) and DHT
/// publication via an HTTP gateway. These operations are implemented in the
/// TypeScript SDK wrapper layer, which then calls
/// [`WasmIdentity::from_did`] to obtain this handle.
///
/// This function signals the correct calling pattern to the TypeScript layer.
/// It validates the custody type and returns a typed error indicating that the
/// TypeScript wrapper must perform the actual key generation and DID creation.
///
/// # Arguments
///
/// * `custody_type` — The custody type string. Pass `"js_custody"` for
///   WebCrypto-backed custody (the only supported type in browser targets).
///
/// # Returns
///
/// `Promise<WasmIdentity>` — resolves to a new identity handle.
///
/// # Errors
///
/// - Rejects with `[SCP-VALID-7000]` if `custody_type` is not `"js_custody"`.
/// - Rejects with `[SCP-IDENT-1000]` indicating that the TypeScript SDK wrapper
///   must perform identity creation via WebCrypto, then call
///   `WasmIdentity.fromDid(did)`.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn identity_create(custody_type: String) -> Promise {
    future_to_promise(async move {
        if custody_type != "js_custody" {
            return Err(ScpWasmError::Validation(format!(
                "unknown custody type: {custody_type:?} — \
                 expected \"js_custody\" for browser targets"
            ))
            .into_js()
            .into());
        }

        // Browser identity creation requires WebCrypto (SubtleCrypto.generateKey)
        // for key generation and an HTTP gateway for DHT publication.
        // These are JS operations that cannot run inside Rust/WASM directly —
        // they require the injected JsKeyCustody and a DHT HTTP client.
        //
        // The TypeScript SDK wrapper handles identity creation as follows:
        // 1. Call custody.generateKeypair("ed25519") × 3 (identity, active, pre-rotation).
        // 2. Compute did:dht:<z-base-32(identity_pub_key)>.
        // 3. Build the DID document JSON.
        // 4. Sign via custody.sign(identityKeyId, bep44_payload).
        // 5. Publish to DHT HTTP gateway (pkarr relay).
        // 6. Call WasmIdentity.fromDid(did) to get the handle.
        //
        // When a future story adds wasm32-compatible scp-core (via
        // tokio/single-thread feature flag), this stub will be replaced with
        // a direct scp-core call.
        Err(ScpWasmError::Identity(
            "identity_create: use the TypeScript SDK wrapper which handles WebCrypto \
             key generation and DHT publication, then call WasmIdentity.fromDid(did) \
             to obtain the identity handle"
                .to_owned(),
        )
        .into_js()
        .into())
    })
}

/// Loads an existing identity from a DID string.
///
/// Validates the DID format and returns an identity handle. Storage loading
/// from wa-sqlite/IndexedDB is performed by the TypeScript SDK wrapper, which
/// then calls [`WasmIdentity::from_did`] to obtain this handle.
///
/// # Arguments
///
/// * `did` — The DID string (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// `Promise<WasmIdentity>` — resolves to the identity handle.
///
/// # Errors
///
/// Rejects with `[SCP-IDENT-1000]` if the DID method is not supported (only
/// `did:dht:` is accepted).
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn identity_load(did: String) -> Promise {
    future_to_promise(async move {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity(format!(
                "unsupported DID method in {did:?} — only did:dht is supported"
            ))
            .into_js()
            .into());
        }

        Ok(JsValue::from(WasmIdentity {
            did,
            custody_type: "js_custody".to_owned(),
        }))
    })
}

/// Resolves a DID to its document.
///
/// DID resolution in browser targets requires querying a DHT HTTP gateway
/// (pkarr relay) — a network operation that must be performed in TypeScript
/// using the Fetch API. The TypeScript SDK wrapper resolves the DID and then
/// calls [`WasmDIDDocument::from_fields`] to create this handle.
///
/// # Arguments
///
/// * `did` — The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// `Promise<WasmDIDDocument>` — resolves to the DID document.
///
/// # Errors
///
/// - Rejects with `[SCP-IDENT-1000]` if the DID format is invalid.
/// - Rejects with `[SCP-IDENT-1000]` indicating that the TypeScript SDK
///   wrapper must resolve via the DHT HTTP gateway and call
///   `WasmDIDDocument.fromFields(...)`.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn identity_resolve(did: String) -> Promise {
    future_to_promise(async move {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity(format!(
                "unsupported DID method in {did:?} — only did:dht is supported"
            ))
            .into_js()
            .into());
        }

        // DID resolution requires an HTTP request to the pkarr DHT gateway.
        // In browser targets this is performed via the Fetch API (a JS
        // operation). The TypeScript SDK wrapper resolves the DID and calls
        // WasmDIDDocument.fromFields(...) to create the document handle.
        //
        // When a future story adds wasm32-compatible scp-core (via
        // tokio/single-thread and a Fetch-based DhtClient), this stub will
        // be replaced with a direct scp-core call.
        Err(ScpWasmError::Identity(
            "identity_resolve: use the TypeScript SDK wrapper which resolves the DID \
             via the DHT HTTP gateway (Fetch API), then call WasmDIDDocument.fromFields() \
             to obtain the document handle"
                .to_owned(),
        )
        .into_js()
        .into())
    })
}
