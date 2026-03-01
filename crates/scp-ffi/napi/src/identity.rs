//! napi-rs bridge for identity operations.
//!
//! Exposes [`NapiIdentity`] as an opaque JS class and three bridge functions
//! for the identity lifecycle:
//!
//! - [`identity_create`] — Creates a new DID identity (returns `Promise<NapiIdentity>`).
//! - [`identity_load`] — Loads an existing identity by DID string.
//! - [`identity_resolve`] — Resolves a DID to its document.
//!
//! Unlike the WASM bridge, this bridge calls `scp-core` directly for the
//! `"in_memory"` custody path — the tokio multi-thread runtime is available
//! in the Bun/Node environment.
//!
//! # Key custody
//!
//! `"in_memory"` custody stores key material in heap memory via
//! `InMemoryKeyCustody`. This is suitable for testing and CLI usage but NOT
//! for production on devices with HSM capability. Production callers should
//! use `"platform"` custody, which requires a wired `KeyCustodyProvider`.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

use std::fmt;
use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;
use scp_core::identity::{DidDht, DidMethod, ScpIdentity};
use scp_platform::testing::InMemoryKeyCustody;

use crate::error::{ScpNapiError, validate_custody_type};
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// OpaqueInMemoryKeyCustody — redacted Debug wrapper
// ---------------------------------------------------------------------------

/// Wraps [`InMemoryKeyCustody`] with a redacted `Debug` impl.
///
/// Prevents key material from appearing in log output or panic messages.
struct OpaqueInMemoryKeyCustody(InMemoryKeyCustody);

impl fmt::Debug for OpaqueInMemoryKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryKeyCustody([redacted])")
    }
}

// ---------------------------------------------------------------------------
// NapiIdentityInner — inner state held behind the napi object
// ---------------------------------------------------------------------------

/// Inner state for a [`NapiIdentity`] handle.
#[derive(Debug)]
struct NapiIdentityInner {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    did: String,
    /// The custody type string: `"in_memory"`, `"platform"`, or `"software"`.
    custody_type: String,
    /// Retained `ScpIdentity` for in-memory custody paths.
    ///
    /// Holds the `KeyHandle`s into `in_memory_custody`. Must outlive any
    /// signing or key-rotation operation on this handle.
    #[allow(dead_code)]
    scp_identity: Option<ScpIdentity>,
    /// Retained `InMemoryKeyCustody` for in-memory custody paths.
    ///
    /// Key material lives here. Dropping this destroys all private keys.
    #[allow(dead_code)]
    in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
}

// ---------------------------------------------------------------------------
// NapiIdentity — opaque JS class for SCP identity
// ---------------------------------------------------------------------------

/// An SCP identity handle exposed to JavaScript (Node.js/Bun).
///
/// Wraps the DID string and retains key material for in-memory custody paths.
/// Platform custody paths use an injected `KeyCustodyProvider`.
///
/// # JS usage
///
/// ```js
/// const identity = await identityCreate("in_memory");
/// console.log(identity.did);          // "did:dht:z..."
/// console.log(identity.custodyType);  // "in_memory"
/// ```
#[napi]
pub struct NapiIdentity {
    /// Shared inner state.
    inner: Arc<NapiIdentityInner>,
}

#[napi]
impl NapiIdentity {
    /// Returns the DID string for this identity.
    #[napi(getter)]
    #[must_use]
    pub fn did(&self) -> String {
        self.inner.did.clone()
    }

    /// Returns the custody type string for this identity.
    ///
    /// One of: `"in_memory"`, `"platform"`, `"software"`.
    #[napi(getter, js_name = "custodyType")]
    #[must_use]
    pub fn custody_type(&self) -> String {
        self.inner.custody_type.clone()
    }

    /// Rotates the active signing key for this identity.
    ///
    /// Generates a new Active Signing Key, updates the DID document on the
    /// DHT, and returns an updated identity with the same DID but a new
    /// active signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if key rotation or DID document publish fails.
    /// Platform and software custody paths require a wired
    /// `KeyCustodyProvider` — this will be connected in a future story.
    #[napi]
    #[allow(clippy::unused_async)] // napi-rs requires async for Promise return
    pub async fn rotate_key(&self) -> napi::Result<Self> {
        Err(ScpNapiError::Identity {
            message: "key rotation requires a wired platform KeyCustodyProvider — \
                      use the KeyCustodyProvider callback interface to inject \
                      Secure Enclave (iOS) or Android Keystore (Android) backed custody"
                .to_owned(),
            code: "SCP-IDENT-1002".to_owned(),
        }
        .into())
    }
}

impl NapiIdentity {
    /// Returns the retained `InMemoryKeyCustody` if this identity uses in-memory
    /// custody. Used by context creation for routing ID derivation (SCP-214).
    pub(crate) fn in_memory_custody(&self) -> Option<&InMemoryKeyCustody> {
        self.inner.in_memory_custody.as_ref().map(|c| &c.0)
    }

    /// Returns the retained `ScpIdentity` if available. Used by context creation
    /// for routing ID derivation (SCP-214).
    pub(crate) fn scp_identity(&self) -> Option<&ScpIdentity> {
        self.inner.scp_identity.as_ref()
    }
}

impl Drop for NapiIdentity {
    /// Decrements the global FFI handle count when the JS object is GC'd.
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// NapiDIDDocument — DID document data returned by identity_resolve
// ---------------------------------------------------------------------------

/// A DID Document returned by identity resolution.
///
/// All fields are plain data (no crypto state) and safe to copy across the
/// FFI boundary as a napi-rs object literal.
///
/// # JS usage
///
/// ```js
/// const doc = await identityResolve("did:dht:z...");
/// console.log(doc.id);               // "did:dht:z..."
/// console.log(doc.authentication);   // ["did:dht:z...#key-0"]
/// ```
#[napi(object)]
pub struct NapiDIDDocument {
    /// The DID string this document describes.
    pub id: String,
    /// Verification method IDs listed in the `authentication` relationship.
    pub authentication: Vec<String>,
    /// Verification method IDs listed in the `assertion_method` relationship.
    pub assertion_methods: Vec<String>,
    /// `alsoKnownAs` entries (alternative DID identifiers for this subject).
    pub also_known_as: Vec<String>,
    /// Service endpoint URLs declared in the DID document.
    pub service_endpoints: Vec<String>,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Creates a new DID identity with the specified custody method.
///
/// For `"in_memory"` custody, this function calls `scp-core` directly using
/// [`InMemoryKeyCustody`] to generate a real `did:dht` identity on the tokio
/// runtime. The key material is retained inside the returned [`NapiIdentity`]
/// handle.
///
/// For `"platform"` and `"software"` custody types, this function returns an
/// error until the `KeyCustodyProvider` callback interface is wired to `scp-core`.
///
/// # Arguments
///
/// * `custody` — The custody type string: `"in_memory"`, `"platform"`, or
///   `"software"`.
///
/// # Returns
///
/// A `Promise<NapiIdentity>` resolving to the new identity handle.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7007` if `custody` is not a recognized value.
/// - Rejects with `SCP-IDENT-1003` for `"platform"` or `"software"` custody
///   (not yet wired).
/// - Rejects with `SCP-IDENT-1001` if key generation or DID creation fails.
///
/// # Security
///
/// `"in_memory"` stores key material in unprotected heap memory. Suitable for
/// testing, CLI, and desktop builds. NOT suitable for production mobile use —
/// use `"platform"` custody on iOS/Android.
#[napi]
pub async fn identity_create(custody: String) -> napi::Result<NapiIdentity> {
    validate_custody_type(&custody).map_err(NapiError::from)?;

    match custody.as_str() {
        "in_memory" => {
            // Wire to scp-core using InMemoryKeyCustody.
            //
            // Both `scp_identity` and `key_custody` must be retained in the
            // handle. `ScpIdentity` holds `KeyHandle`s that are indices into
            // `key_custody`'s internal store. Dropping `key_custody` destroys
            // all private key material and renders those handles dangling.
            let key_custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
            let dht = DidDht::new();
            let (scp_identity, _document) = dht
                .create(&key_custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let handle = NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did: scp_identity.did.clone(),
                    custody_type: "in_memory".to_owned(),
                    scp_identity: Some(scp_identity),
                    in_memory_custody: Some(key_custody),
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
        "platform" | "software" => Err(ScpNapiError::Identity {
            message: format!(
                "custody type {custody:?} requires a wired platform \
                 KeyCustodyProvider — use the KeyCustodyProvider callback \
                 interface to inject Secure Enclave (iOS) or Android \
                 Keystore (Android) backed custody"
            ),
            code: "SCP-IDENT-1003".to_owned(),
        }
        .into()),
        _ => Err(ScpNapiError::Identity {
            code: "SCP-IDENT-1005".to_owned(),
            message: format!(
                "internal: unexpected custody type {custody:?} passed validate_custody_type — \
                 this is a bug in the bridge layer"
            ),
        }
        .into()),
    }
}

/// Loads an existing identity from a DID string.
///
/// Validates the DID format and returns an identity handle. Key operations
/// require a wired `KeyCustodyProvider` callback.
///
/// # Arguments
///
/// * `did` — The DID string to load (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// A `Promise<NapiIdentity>` resolving to the identity handle.
///
/// # Errors
///
/// Rejects with `SCP-IDENT-1004` if the DID method is not `"did:dht:"`.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn identity_load(did: String) -> napi::Result<NapiIdentity> {
    if !did.starts_with("did:dht:") {
        return Err(ScpNapiError::Identity {
            message: format!("unsupported DID method: {did} — only did:dht is supported"),
            code: "SCP-IDENT-1004".to_owned(),
        }
        .into());
    }

    let handle = NapiIdentity {
        inner: Arc::new(NapiIdentityInner {
            did,
            custody_type: "external".to_owned(),
            scp_identity: None,
            in_memory_custody: None,
        }),
    };
    increment_handle_count();
    Ok(handle)
}

/// Resolves a DID to its DID Document.
///
/// Queries the DHT for the DID document associated with `did`. This requires
/// network connectivity to the pkarr DHT gateway.
///
/// # Arguments
///
/// * `did` — The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// A `Promise<NapiDIDDocument>` resolving to the DID document fields.
///
/// # Errors
///
/// - Rejects with `SCP-IDENT-1004` if the DID format is invalid.
/// - Rejects with `SCP-IDENT-1001` if the DID cannot be resolved (not found
///   on DHT, verification failure, network error).
#[napi]
pub async fn identity_resolve(did: String) -> napi::Result<NapiDIDDocument> {
    if !did.starts_with("did:dht:") {
        return Err(ScpNapiError::Identity {
            message: format!("unsupported DID method: {did} — only did:dht is supported"),
            code: "SCP-IDENT-1004".to_owned(),
        }
        .into());
    }

    let dht = DidDht::new();
    let document = dht
        .resolve(&did)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    Ok(NapiDIDDocument {
        id: document.id.clone(),
        authentication: document.authentication.clone(),
        assertion_methods: document.assertion_method.clone(),
        also_known_as: document.also_known_as.clone(),
        service_endpoints: document
            .service
            .iter()
            .map(|s| s.service_endpoint.clone())
            .collect(),
    })
}
