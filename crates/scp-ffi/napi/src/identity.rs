//! napi-rs bridge for identity operations.
//!
//! Exposes [`NapiIdentity`] as an opaque JS class and bridge functions for
//! the identity lifecycle:
//!
//! - [`identity_create`] — Creates a new DID identity (returns `Promise<NapiIdentity>`).
//! - [`identity_create_with_agent_key`] — Creates a new DID identity with an
//!   agent signing key.
//! - [`identity_load`] — Loads an existing identity by DID string.
//! - [`identity_resolve`] — Resolves a DID to its document.
//!
//! Agent key management (ADR-039):
//!
//! - [`NapiIdentity::add_agent_key`] — Adds an agent signing key.
//! - [`NapiIdentity::rotate_agent_key`] — Rotates the agent signing key.
//! - [`NapiIdentity::remove_agent_key`] — Removes the agent signing key.
//! - [`NapiIdentity::has_agent_key`] — Checks if an agent key exists.
//! - [`NapiIdentity::agent_public_key`] — Returns the agent key's public key.
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
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-039.

use std::fmt;
use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;
use scp_identity::{
    DidCache, DidDht, DidDocument, DidMethod, IdentityError, InMemoryDhtClient, ScpIdentity,
};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::KeyCustody;

use crate::error::{ScpNapiError, validate_custody_type};
use crate::{decrement_handle_count, increment_handle_count};

// ---------------------------------------------------------------------------
// OpaqueInMemoryKeyCustody — redacted Debug wrapper
// ---------------------------------------------------------------------------

/// Wraps [`InMemoryKeyCustody`] with a redacted `Debug` impl.
///
/// Prevents key material from appearing in log output or panic messages.
pub(crate) struct OpaqueInMemoryKeyCustody(pub(crate) InMemoryKeyCustody);

impl fmt::Debug for OpaqueInMemoryKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryKeyCustody([redacted])")
    }
}

/// Creates a `DidDht` instance with a signing function derived from the
/// custody held inside an [`OpaqueInMemoryKeyCustody`].
///
/// `DidDht::new()` creates an instance with `sign_fn: None`, which causes
/// all DHT publish operations (used by `add_agent_key`, `rotate_agent_key`,
/// `remove_agent_key`, `rotate_active_key`) to fail. This helper constructs
/// a properly configured instance with the signing function wired to the
/// custody's key material.
#[allow(clippy::type_complexity)]
fn make_dht_with_signer(
    custody: &Arc<OpaqueInMemoryKeyCustody>,
) -> DidDht<InMemoryDhtClient, scp_identity::cache::SystemClock> {
    let custody_clone = Arc::clone(custody);
    let sign_fn: Arc<
        dyn Fn(
                u64,
                Vec<u8>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<u8>, IdentityError>> + Send>,
            > + Send
            + Sync,
    > = Arc::new(move |key_id: u64, data: Vec<u8>| {
        let kc = Arc::clone(&custody_clone);
        Box::pin(async move {
            let handle = scp_platform::traits::KeyHandle::new(key_id);
            let sig =
                kc.0.sign(&handle, &data)
                    .await
                    .map_err(IdentityError::Platform)?;
            Ok(sig.into_bytes())
        })
    });
    DidDht::with_client_and_signer(
        Arc::new(InMemoryDhtClient::new()),
        Arc::new(DidCache::new()),
        sign_fn,
    )
}

// ---------------------------------------------------------------------------
// NapiIdentityInner — inner state held behind the napi object
// ---------------------------------------------------------------------------

/// Inner state for a [`NapiIdentity`] handle.
#[derive(Debug)]
pub(crate) struct NapiIdentityInner {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    pub(crate) did: String,
    /// The custody type string: `"in_memory"`, `"platform"`, or `"software"`.
    pub(crate) custody_type: String,
    /// Retained `ScpIdentity` for in-memory custody paths.
    ///
    /// Holds the `KeyHandle`s into `in_memory_custody`. Must outlive any
    /// signing or key-rotation operation on this handle.
    pub(crate) scp_identity: Option<ScpIdentity>,
    /// Retained `InMemoryKeyCustody` for in-memory custody paths.
    ///
    /// Key material lives here. Dropping this destroys all private keys.
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
    /// Retained DID document for this identity.
    ///
    /// Used by agent key operations to read/modify the document. `None` for
    /// externally loaded identities.
    pub(crate) document: Option<DidDocument>,
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
    pub(crate) inner: Arc<NapiIdentityInner>,
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

    /// Returns `true` if this identity has an agent signing key (`#agent`
    /// verification method in the DID document).
    ///
    /// Returns `false` for externally loaded identities (no retained
    /// document state).
    ///
    /// See ADR-039 acceptance criterion 19 and SCP-AB-016.
    #[napi(getter, js_name = "hasAgentKey")]
    #[must_use]
    pub fn has_agent_key(&self) -> bool {
        self.inner
            .document
            .as_ref()
            .is_some_and(DidDocument::has_agent_key)
    }

    /// Returns the agent key's public key as a multibase-encoded string, or
    /// `null` if no agent key exists.
    ///
    /// The returned string is z-base-32 multibase-encoded (prefix `z`),
    /// matching the `publicKeyMultibase` field in the DID document.
    ///
    /// See ADR-039 acceptance criterion 19 and SCP-AB-016.
    #[napi(getter, js_name = "agentPublicKey")]
    #[must_use]
    pub fn agent_public_key(&self) -> Option<String> {
        self.inner
            .document
            .as_ref()
            .and_then(|doc| doc.agent_verification_method())
            .map(|vm| vm.public_key_multibase.clone())
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

    /// Adds an agent signing key to this identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair for the `#agent` verification method,
    /// updates the DID document, and publishes to the DHT.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the agent key added.
    ///
    /// # Errors
    ///
    /// - `SCP-IDENT-1006`: The identity already has an agent key.
    /// - `SCP-IDENT-1007`: The identity was externally loaded (no retained
    ///   crypto state).
    /// - `SCP-IDENT-1001`: Key generation or DHT publishing failed.
    ///
    /// See ADR-039 acceptance criterion 4 and SCP-AB-016.
    #[napi(js_name = "addAgentKey")]
    pub async fn add_agent_key(&self) -> napi::Result<Self> {
        let (scp_identity, custody, document) = self.extract_in_memory_state("addAgentKey")?;

        let dht = make_dht_with_signer(&custody);
        let (new_identity, new_document) = dht
            .add_agent_key(&scp_identity, &document, &custody.0)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let handle = Self {
            inner: Arc::new(NapiIdentityInner {
                did: new_identity.did.clone(),
                custody_type: self.inner.custody_type.clone(),
                scp_identity: Some(new_identity),
                in_memory_custody: self.inner.in_memory_custody.clone(),
                document: Some(new_document),
            }),
        };
        increment_handle_count();
        Ok(handle)
    }

    /// Rotates the agent signing key for this identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair, retires the old `#agent` key as
    /// `#retired-agent-{sequence}`, and installs the new key as `#agent`.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the rotated agent key.
    ///
    /// # Errors
    ///
    /// - `SCP-IDENT-1008`: The identity has no agent key to rotate.
    /// - `SCP-IDENT-1007`: The identity was externally loaded (no retained
    ///   crypto state).
    /// - `SCP-IDENT-1001`: Key generation or DHT publishing failed.
    ///
    /// See ADR-039 acceptance criterion 4 and SCP-AB-016.
    #[napi(js_name = "rotateAgentKey")]
    pub async fn rotate_agent_key(&self) -> napi::Result<Self> {
        let (scp_identity, custody, document) = self.extract_in_memory_state("rotateAgentKey")?;

        let dht = make_dht_with_signer(&custody);
        let (new_identity, new_document) = dht
            .rotate_agent_key(&scp_identity, &document, &custody.0)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let handle = Self {
            inner: Arc::new(NapiIdentityInner {
                did: new_identity.did.clone(),
                custody_type: self.inner.custody_type.clone(),
                scp_identity: Some(new_identity),
                in_memory_custody: self.inner.in_memory_custody.clone(),
                document: Some(new_document),
            }),
        };
        increment_handle_count();
        Ok(handle)
    }

    /// Removes the agent signing key from this identity (ADR-039).
    ///
    /// Removes the `#agent` verification method from the DID document and
    /// publishes the update to the DHT.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the agent key removed.
    ///
    /// # Errors
    ///
    /// - `SCP-IDENT-1009`: The identity has no agent key to remove.
    /// - `SCP-IDENT-1007`: The identity was externally loaded (no retained
    ///   crypto state).
    /// - `SCP-IDENT-1001`: DHT publishing failed.
    ///
    /// See ADR-039 acceptance criterion 4 and SCP-AB-016.
    #[napi(js_name = "removeAgentKey")]
    pub async fn remove_agent_key(&self) -> napi::Result<Self> {
        let (scp_identity, custody, document) = self.extract_in_memory_state("removeAgentKey")?;

        let dht = make_dht_with_signer(&custody);
        let (new_identity, new_document) = dht
            .remove_agent_key(&scp_identity, &document)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

        let handle = Self {
            inner: Arc::new(NapiIdentityInner {
                did: new_identity.did.clone(),
                custody_type: self.inner.custody_type.clone(),
                scp_identity: Some(new_identity),
                in_memory_custody: self.inner.in_memory_custody.clone(),
                document: Some(new_document),
            }),
        };
        increment_handle_count();
        Ok(handle)
    }
}

impl NapiIdentity {
    /// Returns the retained `InMemoryKeyCustody` if this identity uses in-memory
    /// custody. Used by context creation for routing ID derivation (SCP-214).
    #[allow(dead_code)]
    pub(crate) fn in_memory_custody(&self) -> Option<&InMemoryKeyCustody> {
        self.inner.in_memory_custody.as_ref().map(|c| &c.0)
    }

    /// Returns the retained `ScpIdentity` if available. Used by context creation
    /// for routing ID derivation (SCP-214).
    #[allow(dead_code)]
    pub(crate) fn scp_identity(&self) -> Option<&ScpIdentity> {
        self.inner.scp_identity.as_ref()
    }

    /// Extracts the in-memory crypto state required for agent key operations.
    ///
    /// Returns the `ScpIdentity`, `InMemoryKeyCustody` (via `Arc`), and
    /// `DidDocument` if this identity was created with in-memory custody.
    /// Returns an error for externally loaded identities that have no
    /// retained crypto state.
    fn extract_in_memory_state(
        &self,
        operation: &str,
    ) -> napi::Result<(ScpIdentity, Arc<OpaqueInMemoryKeyCustody>, DidDocument)> {
        let scp_identity = self
            .inner
            .scp_identity
            .as_ref()
            .ok_or_else(|| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!(
                        "{operation} requires retained crypto state — this identity was \
                         externally loaded and has no in-memory key material"
                    ),
                    code: "SCP-IDENT-1007".to_owned(),
                })
            })?
            .clone();

        let custody = self
            .inner
            .in_memory_custody
            .as_ref()
            .ok_or_else(|| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!(
                        "{operation} requires in-memory custody — this identity uses \
                         external custody"
                    ),
                    code: "SCP-IDENT-1007".to_owned(),
                })
            })?
            .clone();

        let document = self
            .inner
            .document
            .as_ref()
            .ok_or_else(|| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!(
                        "{operation} requires a retained DID document — this identity \
                         was externally loaded"
                    ),
                    code: "SCP-IDENT-1007".to_owned(),
                })
            })?
            .clone();

        Ok((scp_identity, custody, document))
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
    /// Whether this document contains an `#agent` verification method.
    ///
    /// See ADR-039 acceptance criterion 19 and SCP-AB-016.
    pub has_agent_key: bool,
    /// The agent key's public key as a multibase-encoded string, or `null`
    /// if no agent key exists.
    ///
    /// See ADR-039 acceptance criterion 19 and SCP-AB-016.
    pub agent_public_key: Option<String>,
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
            let (scp_identity, document) = dht
                .create(&key_custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let handle = NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did: scp_identity.did.clone(),
                    custody_type: "in_memory".to_owned(),
                    scp_identity: Some(scp_identity),
                    in_memory_custody: Some(key_custody),
                    document: Some(document),
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

/// Creates a new DID identity with an agent signing key.
///
/// Like [`identity_create`], but the resulting identity also has an `#agent`
/// verification method in its DID document.
///
/// # Arguments
///
/// * `custody` — The custody type string: `"in_memory"`, `"platform"`, or
///   `"software"`.
///
/// # Returns
///
/// A `Promise<NapiIdentity>` resolving to the new identity handle with
/// `hasAgentKey === true`.
///
/// # Errors
///
/// - Rejects with `SCP-VALID-7007` if `custody` is not a recognized value.
/// - Rejects with `SCP-IDENT-1003` for `"platform"` or `"software"` custody.
/// - Rejects with `SCP-IDENT-1001` if key generation or DID creation fails.
///
/// See ADR-039 acceptance criterion 4 and SCP-AB-016.
#[napi(js_name = "identityCreateWithAgentKey")]
pub async fn identity_create_with_agent_key(custody: String) -> napi::Result<NapiIdentity> {
    validate_custody_type(&custody).map_err(NapiError::from)?;

    match custody.as_str() {
        "in_memory" => {
            let key_custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
            let dht = DidDht::new();
            let (scp_identity, document) = dht
                .create_with_agent_key(&key_custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let handle = NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did: scp_identity.did.clone(),
                    custody_type: "in_memory".to_owned(),
                    scp_identity: Some(scp_identity),
                    in_memory_custody: Some(key_custody),
                    document: Some(document),
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
/// Validates the DID format, resolves the DID document from the DHT, and
/// returns an identity handle with the document retained. The retained
/// document is needed for `hasAgentKey` and `agentPublicKey` to return
/// correct values.
///
/// Key operations (signing, key rotation) require a wired
/// `KeyCustodyProvider` callback — loaded identities do not have retained
/// key material.
///
/// # Arguments
///
/// * `did` — The DID string to load (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// A `Promise<NapiIdentity>` resolving to the identity handle with the
/// resolved DID document retained.
///
/// # Errors
///
/// - Rejects with `SCP-IDENT-1004` if the DID method is not `"did:dht:"`.
/// - Rejects with `SCP-IDENT-1001` if the DID cannot be resolved from the
///   DHT (network error, not found, verification failure).
#[napi]
pub async fn identity_load(did: String) -> napi::Result<NapiIdentity> {
    if !did.starts_with("did:dht:") {
        return Err(ScpNapiError::Identity {
            message: format!("unsupported DID method: {did} — only did:dht is supported"),
            code: "SCP-IDENT-1004".to_owned(),
        }
        .into());
    }

    // Resolve the DID document from the DHT so that `hasAgentKey` and
    // `agentPublicKey` return meaningful values for loaded identities.
    let dht = DidDht::new();
    let document = dht
        .resolve(&did)
        .await
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    let handle = NapiIdentity {
        inner: Arc::new(NapiIdentityInner {
            did,
            custody_type: "external".to_owned(),
            scp_identity: None,
            in_memory_custody: None,
            document: Some(document),
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

    let has_agent_key = document.has_agent_key();
    let agent_public_key = document
        .agent_verification_method()
        .map(|vm| vm.public_key_multibase.clone());

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
        has_agent_key,
        agent_public_key,
    })
}
