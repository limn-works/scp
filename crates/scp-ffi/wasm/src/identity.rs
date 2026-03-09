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
//!    implementation (`WebCrypto` for key ops, DHT HTTP gateway for resolution).
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

use std::cell::RefCell;
use std::collections::HashMap;

use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// WASM-local identity registry
// ---------------------------------------------------------------------------

/// Per-identity state stored in the WASM-local registry.
#[derive(Debug, Clone)]
struct IdentityEntry {
    /// Ed25519 public key bytes (32 bytes).
    public_key_bytes: [u8; 32],
    /// Custody type string. Retained for future use when custody operations
    /// are wired (e.g., signing, key rotation).
    #[allow(dead_code)]
    custody_type: String,
}

thread_local! {
    /// Maps DID strings to identity state. WASM is single-threaded, so
    /// `RefCell` is sufficient.
    static IDENTITY_REGISTRY: RefCell<HashMap<String, IdentityEntry>> =
        RefCell::new(HashMap::new());
}

// ---------------------------------------------------------------------------
// z-base-32 encoding (mirrors ucan.rs zbase32_encode)
// ---------------------------------------------------------------------------

/// Minimal z-base-32 encoder for did:dht DID derivation.
///
/// z-base-32 uses the alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`.
fn zbase32_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut output = String::new();

    for &byte in input {
        bits = (bits << 8) | u64::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            #[allow(clippy::cast_possible_truncation)]
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            output.push(ALPHABET[idx] as char);
            bits &= (1u64 << bit_count) - 1;
        }
    }

    // Encode remaining bits (padded to 5 bits).
    if bit_count > 0 {
        #[allow(clippy::cast_possible_truncation)]
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        output.push(ALPHABET[idx] as char);
    }

    output
}

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
    /// Whether this identity has an `#agent` verification method.
    ///
    /// Managed locally (no scp-core dependency, per ADR-034).
    /// Set via `addAgentKey()` / `removeAgentKey()` / `rotateAgentKey()`.
    has_agent_key: bool,
    /// The agent key's public key as a multibase-encoded string, if present.
    ///
    /// Stored as metadata for JS-side consumption. Actual key material is
    /// managed by the JS `SubtleCrypto` API via `JsKeyCustody`.
    agent_public_key_multibase: Option<String>,
}

#[wasm_bindgen]
impl WasmIdentity {
    /// Returns the DID string for this identity.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    /// Returns the custody type string for this identity.
    ///
    /// Always `"js_custody"` for browser targets.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "custodyType")]
    pub fn custody_type(&self) -> String {
        self.custody_type.clone()
    }

    /// Constructs a `WasmIdentity` from a DID string.
    ///
    /// Called by the TypeScript SDK after performing identity creation
    /// operations via `WebCrypto`. The SDK is responsible for:
    /// 1. Generating the Ed25519 keypairs via `SubtleCrypto.generateKey`.
    /// 2. Computing the `did:dht` string from the identity key public bytes.
    /// 3. Publishing the DID document to the DHT via HTTP gateway.
    /// 4. Calling `WasmIdentity.fromDid(did)` to obtain this handle.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1000]` if the DID prefix is not `did:dht:`.
    #[wasm_bindgen(js_name = "fromDid")]
    pub fn from_did(did: String) -> Result<Self, JsError> {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity {
                message: format!("unsupported DID method in {did:?} — only did:dht is supported"),
                code: "SCP-IDENT-1004".to_owned(),
            }
            .into_js());
        }
        Ok(Self {
            did,
            custody_type: "js_custody".to_owned(),
            has_agent_key: false,
            agent_public_key_multibase: None,
        })
    }

    /// Returns whether this identity has an agent signing key (`#agent` VM).
    ///
    /// See ADR-039 acceptance criterion 4.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "hasAgentKey")]
    pub fn has_agent_key(&self) -> bool {
        self.has_agent_key
    }

    /// Returns the agent key's public key as a multibase string, or `null`.
    ///
    /// See ADR-039 acceptance criterion 4.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "agentPublicKey")]
    pub fn agent_public_key(&self) -> Option<String> {
        self.agent_public_key_multibase.clone()
    }

    /// Adds an agent signing key to this identity (ADR-039).
    ///
    /// # Contract
    ///
    /// The caller (TypeScript SDK) **MUST** have already updated the DID
    /// document on the DHT to include the `#agent` verification method
    /// **BEFORE** calling this method. Local state is **NOT** automatically
    /// synced with the DHT — this method only updates the in-memory
    /// `WasmIdentity`. Calling this method without completing the DHT update
    /// first will result in inconsistent state between the local
    /// `WasmIdentity` and the published DID document.
    ///
    /// ## Required steps (in order)
    ///
    /// 1. Generate the Ed25519 agent keypair via `SubtleCrypto.generateKey`.
    /// 2. Encode the public key as multibase.
    /// 3. Update the DID document on the DHT to include the `#agent` VM.
    /// 4. Call this method with the multibase public key to record state.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1009]` if the identity already has an agent key.
    /// Returns `[SCP-IDENT-1010]` if the public key is empty.
    #[wasm_bindgen(js_name = "addAgentKey")]
    pub fn add_agent_key(&mut self, public_key_multibase: String) -> Result<(), JsError> {
        if self.has_agent_key {
            return Err(ScpWasmError::Identity {
                message: "identity already has an agent key — remove it first or use \
                          rotateAgentKey"
                    .to_owned(),
                code: "SCP-IDENT-1009".to_owned(),
            }
            .into_js());
        }
        if public_key_multibase.is_empty() {
            return Err(ScpWasmError::Identity {
                message: "agent public key multibase string must not be empty".to_owned(),
                code: "SCP-IDENT-1010".to_owned(),
            }
            .into_js());
        }
        self.has_agent_key = true;
        self.agent_public_key_multibase = Some(public_key_multibase);
        Ok(())
    }

    /// Removes the agent signing key from this identity (ADR-039).
    ///
    /// # Contract
    ///
    /// The caller (TypeScript SDK) **MUST** have already updated the DID
    /// document on the DHT to remove the `#agent` verification method
    /// **BEFORE** calling this method. Local state is **NOT** automatically
    /// synced with the DHT — this method only updates the in-memory
    /// `WasmIdentity`. Calling this method without completing the DHT update
    /// first will result in inconsistent state between the local
    /// `WasmIdentity` and the published DID document.
    ///
    /// ## Required steps (in order)
    ///
    /// 1. Remove the `#agent` VM from the DID document on the DHT.
    /// 2. Call this method to update local state.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1011]` if the identity has no agent key.
    #[wasm_bindgen(js_name = "removeAgentKey")]
    pub fn remove_agent_key(&mut self) -> Result<(), JsError> {
        if !self.has_agent_key {
            return Err(ScpWasmError::Identity {
                message: "identity has no agent key to remove".to_owned(),
                code: "SCP-IDENT-1011".to_owned(),
            }
            .into_js());
        }
        self.has_agent_key = false;
        self.agent_public_key_multibase = None;
        Ok(())
    }

    /// Rotates the agent signing key for this identity (ADR-039).
    ///
    /// # Contract
    ///
    /// The caller (TypeScript SDK) **MUST** have already updated the DID
    /// document on the DHT to retire the old `#agent` verification method
    /// and install the new one **BEFORE** calling this method. Local state
    /// is **NOT** automatically synced with the DHT — this method only
    /// updates the in-memory `WasmIdentity`. Calling this method without
    /// completing the DHT update first will result in inconsistent state
    /// between the local `WasmIdentity` and the published DID document.
    ///
    /// ## Required steps (in order)
    ///
    /// 1. Generate the new Ed25519 agent keypair via `SubtleCrypto.generateKey`.
    /// 2. Encode the new public key as multibase.
    /// 3. Update the DID document on the DHT (retiring old `#agent`,
    ///    installing new).
    /// 4. Call this method with the new multibase public key to update state.
    ///
    /// # Errors
    ///
    /// Returns `[SCP-IDENT-1011]` if the identity has no agent key to rotate.
    /// Returns `[SCP-IDENT-1010]` if the new public key is empty.
    #[wasm_bindgen(js_name = "rotateAgentKey")]
    pub fn rotate_agent_key(&mut self, new_public_key_multibase: String) -> Result<(), JsError> {
        if !self.has_agent_key {
            return Err(ScpWasmError::Identity {
                message: "identity has no agent key to rotate — use addAgentKey first".to_owned(),
                code: "SCP-IDENT-1011".to_owned(),
            }
            .into_js());
        }
        if new_public_key_multibase.is_empty() {
            return Err(ScpWasmError::Identity {
                message: "new agent public key multibase string must not be empty".to_owned(),
                code: "SCP-IDENT-1010".to_owned(),
            }
            .into_js());
        }
        self.agent_public_key_multibase = Some(new_public_key_multibase);
        Ok(())
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
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Returns the verification methods as a JSON string.
    ///
    /// Each object has `id`, `type`, `controller`, and `publicKeyMultibase`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "verificationMethodsJson")]
    pub fn verification_methods_json(&self) -> String {
        self.verification_methods_json.clone()
    }

    /// Returns the service entries as a JSON string.
    ///
    /// Each object has `id`, `type`, and `serviceEndpoint`.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "servicesJson")]
    pub fn services_json(&self) -> String {
        self.services_json.clone()
    }

    /// Returns the `alsoKnownAs` entries as a JSON string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "alsoKnownAsJson")]
    pub fn also_known_as_json(&self) -> String {
        self.also_known_as_json.clone()
    }

    /// Returns the authentication method references as a JSON string.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "authenticationJson")]
    pub fn authentication_json(&self) -> String {
        self.authentication_json.clone()
    }

    /// Returns the assertion method references as a JSON string.
    #[must_use]
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
    #[must_use]
    // wasm-bindgen JS constructor must accept all fields individually.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = "fromFields")]
    pub fn from_fields(
        id: String,
        verification_methods_json: String,
        services_json: String,
        also_known_as_json: String,
        authentication_json: String,
        assertion_methods_json: String,
    ) -> Self {
        Self {
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

/// Creates a new SCP identity.
///
/// Generates an Ed25519 keypair using the browser's cryptographic random
/// number generator (`crypto.getRandomValues` via `getrandom/js`), derives
/// a `did:dht` DID string from the public key, and returns a
/// [`WasmIdentity`] handle.
///
/// # Arguments
///
/// * `custody` — The custody type string. Must be `"js_custody"` or
///   `"in_memory"` for browser targets.
///
/// # Returns
///
/// `Promise<WasmIdentity>` — resolves to the newly created identity handle.
///
/// # Errors
///
/// - Rejects with `[SCP-IDENT-1000]` if key generation fails.
/// - Rejects with `[SCP-IDENT-1004]` if the custody type is not supported.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn identity_create(custody: String) -> Promise {
    future_to_promise(async move {
        if custody != "js_custody" && custody != "in_memory" {
            return Err(ScpWasmError::Identity {
                message: format!(
                    "unsupported custody type {custody:?} — only \"js_custody\" and \"in_memory\" \
                     are supported in the browser WASM bridge"
                ),
                code: "SCP-IDENT-1004".to_owned(),
            }
            .into_js()
            .into());
        }

        // Generate Ed25519 keypair.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        // Derive did:dht DID from the public key using z-base-32 encoding.
        let did = format!("did:dht:z{}", zbase32_encode(&pub_bytes));

        // Store the signing key in the WASM-local identity registry so that
        // identity_resolve can return the public key from the DID document.
        IDENTITY_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            map.insert(
                did.clone(),
                IdentityEntry {
                    public_key_bytes: pub_bytes,
                    custody_type: custody.clone(),
                },
            );
        });

        Ok(JsValue::from(WasmIdentity {
            did,
            custody_type: custody,
            has_agent_key: false,
            agent_public_key_multibase: None,
        }))
    })
}

/// Resolves a DID to its DID Document.
///
/// For locally-created identities, returns a DID document with the Ed25519
/// public key from the WASM-local identity registry. For unknown DIDs,
/// returns a minimal document with just the DID ID (the TypeScript SDK
/// performs full DHT resolution for remote DIDs).
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
/// Rejects with `[SCP-IDENT-1004]` if the DID method is not supported.
///
/// See ADR-022 acceptance criterion 1.
#[wasm_bindgen]
pub fn identity_resolve(did: String) -> Promise {
    future_to_promise(async move {
        if !did.starts_with("did:dht:") {
            return Err(ScpWasmError::Identity {
                message: format!("unsupported DID method in {did:?} — only did:dht is supported"),
                code: "SCP-IDENT-1004".to_owned(),
            }
            .into_js()
            .into());
        }

        // Look up in the local identity registry.
        let entry = IDENTITY_REGISTRY.with(|reg| {
            let map = reg.borrow();
            map.get(&did).cloned()
        });

        let (verification_methods_json, authentication_json, assertion_methods_json) =
            if let Some(entry) = entry {
                // Build a verification method from the stored public key.
                let multibase_key = format!("z{}", zbase32_encode(&entry.public_key_bytes));
                let vm = serde_json::json!([{
                    "id": format!("{did}#0"),
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": multibase_key,
                }]);
                let auth = serde_json::json!([format!("{did}#0")]);
                let assertion = serde_json::json!([format!("{did}#0")]);
                (
                    serde_json::to_string(&vm).unwrap_or_else(|_| "[]".to_owned()),
                    serde_json::to_string(&auth).unwrap_or_else(|_| "[]".to_owned()),
                    serde_json::to_string(&assertion).unwrap_or_else(|_| "[]".to_owned()),
                )
            } else {
                // Unknown DID — return minimal document.
                ("[]".to_owned(), "[]".to_owned(), "[]".to_owned())
            };

        Ok(JsValue::from(WasmDIDDocument::from_fields(
            did,
            verification_methods_json,
            "[]".to_owned(),
            "[]".to_owned(),
            authentication_json,
            assertion_methods_json,
        )))
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
            return Err(ScpWasmError::Identity {
                message: format!("unsupported DID method in {did:?} — only did:dht is supported"),
                code: "SCP-IDENT-1004".to_owned(),
            }
            .into_js()
            .into());
        }

        Ok(JsValue::from(WasmIdentity {
            did,
            custody_type: "js_custody".to_owned(),
            has_agent_key: false,
            agent_public_key_multibase: None,
        }))
    })
}
