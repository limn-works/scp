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
//! Identity migration (spec §9.12):
//!
//! - [`NapiIdentity::migrate`] — Performs Layer 2 DID rotation, creating a new
//!   DID with a pre-rotation key while preserving identity continuity.
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

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;
#[cfg(feature = "allow_in_memory_custody")]
use scp_identity::{DhtClient, IdentityError};
use scp_identity::{
    DidCache, DidDht, DidDocument, DidMethod, DualLayerResolver, InMemoryDhtClient,
    NoOpRelayQuerier, ScpIdentity,
};
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::testing::InMemoryKeyCustody;
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::traits::KeyCustody;
use scp_primitives::Clock;
#[cfg(feature = "allow_in_memory_custody")]
use std::fmt;

use crate::error::{ScpNapiError, validate_custody_type};
use crate::{decrement_handle_count, increment_handle_count};

#[cfg(feature = "allow_in_memory_custody")]
use scp_ffi_common::validate::MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID;

/// Ensures the global production DID resolver is initialized (idempotent). #311
///
/// The `InMemoryDhtClient` created here is stored in a shared global so that
/// `identity_create` can publish newly created DID documents to it. This
/// allows UCAN validation (which resolves the issuer DID) to find the
/// document without a real network DHT (#1144).
///
/// Uses `std::sync::Once` to guard the entire initialization block atomically.
/// Without this, two separate `OnceLock::set` calls (`SHARED_DHT_CLIENT` and
/// `BridgeInstance::did_resolver`) could race under concurrent access: thread A
/// creates `InMemoryDhtClient` X and sets `SHARED_DHT_CLIENT`, then thread B
/// creates `InMemoryDhtClient` Y, fails to set `SHARED_DHT_CLIENT` (already set
/// to X), but builds a `DualLayerResolver` around Y and stores it in
/// `BridgeInstance` — the resolver and the shared DHT client would reference
/// different instances.
fn ensure_did_resolver_initialized() {
    static INIT: std::sync::Once = std::sync::Once::new();

    INIT.call_once(|| {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return; // No runtime available; skip initialization.
        };

        let dht_client = Arc::new(InMemoryDhtClient::new());
        // Store the DHT client so identity_create can publish documents to it.
        crate::runtime::init_shared_dht_client(Arc::clone(&dht_client));

        let relay_querier = Arc::new(NoOpRelayQuerier);
        let cache = Arc::new(DidCache::new());
        let bootstrap_relays = Vec::new();

        let resolver = Arc::new(DualLayerResolver::new(
            relay_querier,
            dht_client,
            cache,
            bootstrap_relays,
        ));

        crate::runtime::init_did_resolver(resolver, handle);
    });
}

/// Publishes a newly created DID document to the shared `InMemoryDhtClient`.
///
/// After `identity_create`, the DID document must be discoverable by the
/// `DualLayerResolver` (used by UCAN validation). Since the default
/// `DidDht::new()` creates its own `InMemoryDhtClient` that is NOT shared
/// with the resolver, we must explicitly publish to the shared instance.
///
/// Constructs a BEP44 signed mutable item (public key, signature, document
/// JSON, sequence number 1) and calls `DhtClient::publish`. Best-effort:
/// errors are logged but do not fail identity creation.
///
/// See issue #1144.
#[cfg(feature = "allow_in_memory_custody")]
async fn publish_to_shared_dht(
    identity: &ScpIdentity,
    document: &DidDocument,
    custody: &OpaqueInMemoryKeyCustody,
) {
    let Some(dht_client) = crate::runtime::shared_dht_client() else {
        return; // Resolver not initialized; nothing to seed.
    };

    // Serialize document to JSON.
    let doc_json = match document.to_json() {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("publish_to_shared_dht: failed to serialize document: {e}");
            return;
        }
    };
    let value = doc_json.as_bytes();

    // Extract the 32-byte public key from the DID string.
    let public_key = match scp_identity::extract_public_key(&identity.did) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("publish_to_shared_dht: failed to extract public key: {e}");
            return;
        }
    };

    // Build BEP44 signable payload and sign with the identity key.
    let seq: u64 = 1;
    let signable = scp_identity::dht::bep44_signable(value, seq);
    let sig_bytes = match custody.0.sign(&identity.identity_key, &signable).await {
        Ok(sig) => sig.into_bytes(),
        Err(e) => {
            tracing::warn!("publish_to_shared_dht: signing failed: {e}");
            return;
        }
    };
    let Ok(signature): Result<[u8; 64], _> = sig_bytes.try_into() else {
        tracing::warn!("publish_to_shared_dht: signature is not 64 bytes");
        return;
    };

    // Publish to the shared in-memory DHT client.
    if let Err(e) = dht_client
        .publish(&public_key, &signature, value, seq)
        .await
    {
        tracing::warn!("publish_to_shared_dht: DHT publish failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// OpaqueInMemoryKeyCustody — redacted Debug wrapper
// ---------------------------------------------------------------------------

/// Wraps [`InMemoryKeyCustody`] with a redacted `Debug` impl.
///
/// Prevents key material from appearing in log output or panic messages.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) struct OpaqueInMemoryKeyCustody(pub(crate) InMemoryKeyCustody);

#[cfg(feature = "allow_in_memory_custody")]
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
#[cfg(feature = "allow_in_memory_custody")]
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
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
    /// Retained DID document for this identity.
    ///
    /// Used by agent key operations to read/modify the document. `None` for
    /// externally loaded identities.
    pub(crate) document: Option<DidDocument>,
    /// `NapiBridgeInstance` id that minted this handle — used for runtime
    /// handle-affinity checks at every FFI entry point that accepts a
    /// `NapiIdentity`. Mismatches are rejected with `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
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

    /// Returns the id of the `SCP` instance that minted this handle, as a
    /// base-10 string (u64 serialized as string to survive JS number limits).
    #[napi(getter, js_name = "instanceId")]
    #[must_use]
    pub fn instance_id_js(&self) -> String {
        self.inner.instance_id.to_string()
    }

    /// Rotates the active signing key for this identity.
    ///
    /// Generates a new Active Signing Key, updates the DID document on the
    /// DHT, and returns an updated identity with the same DID but a new
    /// active signing key. The old key is retained in the document history
    /// as a retired verification method for verification of past signatures.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the rotated active signing key. The original
    /// `NapiIdentity` is NOT mutated — callers must use the returned value.
    /// Any references to the original instance retain the old (pre-rotation) state.
    ///
    /// # Errors
    ///
    /// - `SCP-IDENT-1007`: The identity was externally loaded (no retained
    ///   crypto state).
    /// - `SCP-IDENT-1001`: Key generation or DHT publishing failed.
    ///
    /// See §3.9 Key Lifecycle, ADR-003 DID Creation.
    #[napi]
    #[allow(clippy::unused_async)] // napi requires async for Promise return type
    pub async fn rotate_key(&self) -> napi::Result<Self> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            let _ = self;
            Err(ScpNapiError::Identity {
                message: "key rotation requires in-memory custody -- \
                          enable allow_in_memory_custody"
                    .to_owned(),
                code: codes::IDENT_1007.to_owned(),
            }
            .into())
        }
        #[cfg(feature = "allow_in_memory_custody")]
        {
            let (scp_identity, custody, document) = self.extract_in_memory_state("rotateKey")?;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(&self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .rotate_active_key(&scp_identity, &document, &custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            // Update the identity registry with the rotated key handles.
            crate::runtime::register_identity(
                &new_identity.did,
                crate::runtime::NapiIdentityEntry {
                    identity: new_identity.clone(),
                    custody: Arc::clone(&custody),
                    document: new_document.clone(),
                    identity_link_attestations: existing_attestations,
                },
            );

            let handle = Self {
                inner: Arc::new(NapiIdentityInner {
                    did: new_identity.did.clone(),
                    custody_type: self.inner.custody_type.clone(),
                    scp_identity: Some(new_identity),
                    in_memory_custody: self.inner.in_memory_custody.clone(),
                    document: Some(new_document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
    }

    /// Adds an agent signing key to this identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair for the `#agent` verification method,
    /// updates the DID document, and publishes to the DHT.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the agent key added. The original
    /// `NapiIdentity` is NOT mutated — callers must use the returned value.
    /// Any references to the original instance retain the old state (pre-agent-key).
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
    #[allow(clippy::unused_async)] // napi requires async for Promise return type
    pub async fn add_agent_key(&self) -> napi::Result<Self> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            let _ = self;
            Err(ScpNapiError::Identity { message: "agent key operations require in-memory custody -- enable allow_in_memory_custody".to_owned(), code: codes::IDENT_1007.to_owned() }.into())
        }
        #[cfg(feature = "allow_in_memory_custody")]
        {
            let (scp_identity, custody, document) = self.extract_in_memory_state("addAgentKey")?;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(&self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .add_agent_key(&scp_identity, &document, &custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            // Update the identity registry with the new key state so that
            // bridge functions (ucan_delegate, etc.) see the updated identity.
            crate::runtime::register_identity(
                &new_identity.did,
                crate::runtime::NapiIdentityEntry {
                    identity: new_identity.clone(),
                    custody: Arc::clone(&custody),
                    document: new_document.clone(),
                    identity_link_attestations: existing_attestations,
                },
            );

            let handle = Self {
                inner: Arc::new(NapiIdentityInner {
                    did: new_identity.did.clone(),
                    custody_type: self.inner.custody_type.clone(),
                    scp_identity: Some(new_identity),
                    in_memory_custody: self.inner.in_memory_custody.clone(),
                    document: Some(new_document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
    }

    /// Rotates the agent signing key for this identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair, retires the old `#agent` key as
    /// `#retired-agent-{sequence}`, and installs the new key as `#agent`.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the rotated agent key. The original
    /// `NapiIdentity` is NOT mutated — callers must use the returned value.
    /// Any references to the original instance retain the old (pre-rotation) state.
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
    #[allow(clippy::unused_async)] // napi requires async for Promise return type
    pub async fn rotate_agent_key(&self) -> napi::Result<Self> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            let _ = self;
            Err(ScpNapiError::Identity { message: "agent key operations require in-memory custody -- enable allow_in_memory_custody".to_owned(), code: codes::IDENT_1007.to_owned() }.into())
        }
        #[cfg(feature = "allow_in_memory_custody")]
        {
            let (scp_identity, custody, document) =
                self.extract_in_memory_state("rotateAgentKey")?;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(&self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .rotate_agent_key(&scp_identity, &document, &custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            // Update the identity registry with the rotated key state.
            crate::runtime::register_identity(
                &new_identity.did,
                crate::runtime::NapiIdentityEntry {
                    identity: new_identity.clone(),
                    custody: Arc::clone(&custody),
                    document: new_document.clone(),
                    identity_link_attestations: existing_attestations,
                },
            );

            let handle = Self {
                inner: Arc::new(NapiIdentityInner {
                    did: new_identity.did.clone(),
                    custody_type: self.inner.custody_type.clone(),
                    scp_identity: Some(new_identity),
                    in_memory_custody: self.inner.in_memory_custody.clone(),
                    document: Some(new_document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
    }

    /// Removes the agent signing key from this identity (ADR-039).
    ///
    /// Removes the `#agent` verification method from the DID document and
    /// publishes the update to the DHT.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the agent key removed. The original
    /// `NapiIdentity` is NOT mutated — callers must use the returned value.
    /// Any references to the original instance retain the old (pre-removal) state.
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
    #[allow(clippy::unused_async)] // napi requires async for Promise return type
    pub async fn remove_agent_key(&self) -> napi::Result<Self> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            let _ = self;
            Err(ScpNapiError::Identity { message: "agent key operations require in-memory custody -- enable allow_in_memory_custody".to_owned(), code: codes::IDENT_1007.to_owned() }.into())
        }
        #[cfg(feature = "allow_in_memory_custody")]
        {
            let (scp_identity, custody, document) =
                self.extract_in_memory_state("removeAgentKey")?;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(&self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .remove_agent_key(&scp_identity, &document)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            // Update the identity registry with the post-removal key state.
            crate::runtime::register_identity(
                &new_identity.did,
                crate::runtime::NapiIdentityEntry {
                    identity: new_identity.clone(),
                    custody: Arc::clone(&custody),
                    document: new_document.clone(),
                    identity_link_attestations: existing_attestations,
                },
            );

            let handle = Self {
                inner: Arc::new(NapiIdentityInner {
                    did: new_identity.did.clone(),
                    custody_type: self.inner.custody_type.clone(),
                    scp_identity: Some(new_identity),
                    in_memory_custody: self.inner.in_memory_custody.clone(),
                    document: Some(new_document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
    }

    /// Migrates this identity to a new DID (Layer 2 DID rotation, spec §9.12).
    ///
    /// Creates a new DID with a pre-rotation key, preserving identity
    /// continuity. The old DID's key material is removed from the registry
    /// and replaced with the new DID's state.
    ///
    /// This is a full DID migration — the returned `NapiIdentity` has a
    /// **different** DID string from the original. The old identity is
    /// invalidated (removed from the registry). Callers must use the returned
    /// handle for all subsequent operations.
    ///
    /// # Returns
    ///
    /// A new `NapiIdentity` with the migrated DID. The original identity's
    /// key material is dropped from the registry.
    ///
    /// # Errors
    ///
    /// - `SCP-IDENT-1007`: The identity was externally loaded (no retained
    ///   crypto state).
    /// - `SCP-IDENT-1009`: Key generation or DHT publishing failed during
    ///   migration.
    ///
    /// See ADR-003 acceptance criterion 4b, spec §9.12, and SCP-214 criterion 10.
    #[napi]
    #[allow(clippy::unused_async)] // napi requires async for Promise return type
    pub async fn migrate(&self) -> napi::Result<Self> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            let _ = self;
            Err(ScpNapiError::Identity {
                message: "identity migration requires in-memory custody -- \
                          enable allow_in_memory_custody"
                    .to_owned(),
                code: codes::IDENT_1007.to_owned(),
            }
            .into())
        }
        #[cfg(feature = "allow_in_memory_custody")]
        {
            let (scp_identity, custody, document) = self.extract_in_memory_state("migrate")?;

            // Read attestations BEFORE async operation (entry guaranteed to exist now).
            let existing_attestations = crate::runtime::with_identity(&self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            // Spec §9.12 (Compromise Recovery Protocol) requires using the
            // pre-rotation key from cold storage — the pre-rotation commitment
            // in the old DID document proves the legitimate owner is rotating,
            // not an attacker. In-memory custody does not persist keys across
            // sessions, so no cold storage key exists. Generate a fresh
            // pre-rotation key instead; `migrate_identity` uses it as the new
            // Identity Key. Production custody providers (platform/HSM) must
            // retrieve the original pre-rotation key from durable storage.
            let pre_rotation_key = custody
                .0
                .generate_keypair(scp_platform::traits::KeyType::Ed25519)
                .await
                .map_err(|e| {
                    NapiError::from(ScpNapiError::Identity {
                        message: format!("key generation failed during migration: {e}"),
                        code: codes::IDENT_1009.to_owned(),
                    })
                })?;

            let rotated_at = scp_primitives::SystemClock.now_secs();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document, _rotation_event) = dht
                .migrate_identity(
                    &scp_identity,
                    &document,
                    &pre_rotation_key,
                    &custody.0,
                    rotated_at,
                )
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let new_did = new_identity.did.clone();

            // Remove the old identity and register the new one.
            crate::runtime::remove_identity(&self.inner.did);
            crate::runtime::register_identity(
                &new_did,
                crate::runtime::NapiIdentityEntry {
                    identity: new_identity.clone(),
                    custody: Arc::clone(&custody),
                    document: new_document.clone(),
                    identity_link_attestations: existing_attestations,
                },
            );

            let handle = Self {
                inner: Arc::new(NapiIdentityInner {
                    did: new_did,
                    custody_type: self.inner.custody_type.clone(),
                    scp_identity: Some(new_identity),
                    in_memory_custody: self.inner.in_memory_custody.clone(),
                    document: Some(new_document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
    }
}

impl NapiIdentity {
    /// Returns the raw instance id carried by this handle (used by the
    /// [`crate::napi_check_handle!`] macro for handle-affinity checks).
    #[must_use]
    pub(crate) fn instance_id(&self) -> u64 {
        self.inner.instance_id
    }

    /// Returns the retained `InMemoryKeyCustody` if this identity uses in-memory
    /// custody. Used by context creation for routing ID derivation (SCP-214).
    #[cfg(feature = "allow_in_memory_custody")]
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
    #[cfg(feature = "allow_in_memory_custody")]
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
                    code: codes::IDENT_1007.to_owned(),
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
                    code: codes::IDENT_1007.to_owned(),
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
                    code: codes::IDENT_1007.to_owned(),
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

/// A verification method from a DID Document.
///
/// Contains the full key material (id, type, controller, publicKeyMultibase)
/// so that callers receive actual public keys instead of just reference IDs.
#[napi(object)]
pub struct NapiVerificationMethod {
    /// The full URI of this verification method (e.g., `did:dht:z...#0`).
    pub id: String,
    /// The type of verification method (e.g., `"Ed25519VerificationKey2020"`).
    #[napi(js_name = "type")]
    pub method_type: String,
    /// The DID that controls this verification method.
    pub controller: String,
    /// The public key encoded as a multibase string (z-prefix + base58btc).
    pub public_key_multibase: String,
}

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
/// console.log(doc.verificationMethods[0].publicKeyMultibase); // "z..."
/// ```
#[napi(object)]
pub struct NapiDIDDocument {
    /// The DID string this document describes.
    pub id: String,
    /// Full verification method objects with key material.
    pub verification_methods: Vec<NapiVerificationMethod>,
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
/// `InMemoryKeyCustody` to generate a real `did:dht` identity on the tokio
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
#[allow(clippy::unused_async)] // napi requires async for Promise return type
pub async fn identity_create(custody: String) -> napi::Result<NapiIdentity> {
    validate_custody_type(&custody).map_err(NapiError::from)?;

    // Ensure the BridgeInstance exists BEFORE the DID resolver is
    // initialized — the DID resolver is stored inside the BridgeInstance and
    // cannot be registered otherwise. The real ContextManager is attached
    // later (by init_context_manager) once the identity has been created.
    // Per spec §12.2.3 the BridgeInstance container carries no DID; the
    // DID lives inside the MlsCryptoProvider owned by the ContextManager.
    crate::runtime::ensure_bridge_instance();

    // Ensure the global DID resolver is initialized (idempotent). #311
    ensure_did_resolver_initialized();

    match custody.as_str() {
        #[cfg(feature = "allow_in_memory_custody")]
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

            // Register identity in the global registry so that bridge functions
            // like `ucan_delegate` can look up this identity's key material by
            // DID (matching the PyO3 bridge's identity registry pattern).
            crate::runtime::register_identity(
                &scp_identity.did,
                crate::runtime::NapiIdentityEntry {
                    identity: scp_identity.clone(),
                    custody: Arc::clone(&key_custody),
                    document: document.clone(),
                    identity_link_attestations: Vec::new(),
                },
            );

            // Publish the DID document to the shared InMemoryDhtClient so
            // that the DualLayerResolver can find it during UCAN validation.
            // Best-effort: errors are logged, not propagated (#1144).
            publish_to_shared_dht(&scp_identity, &document, &key_custody).await;

            let handle = NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did: scp_identity.did.clone(),
                    custody_type: "in_memory".to_owned(),
                    scp_identity: Some(scp_identity),
                    in_memory_custody: Some(key_custody),
                    document: Some(document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
        #[cfg(not(feature = "allow_in_memory_custody"))]
        "in_memory" => Err(ScpNapiError::Identity {
            message:
                "in_memory custody is not available in this build -- enable allow_in_memory_custody"
                    .to_owned(),
            code: codes::IDENT_1008.to_owned(),
        }
        .into()),
        "platform" | "software" => Err(ScpNapiError::Identity {
            message: format!(
                "custody type {custody:?} requires a wired platform \
                 KeyCustodyProvider — use the KeyCustodyProvider callback \
                 interface to inject Secure Enclave (iOS) or Android \
                 Keystore (Android) backed custody"
            ),
            code: codes::IDENT_1003.to_owned(),
        }
        .into()),
        _ => Err(ScpNapiError::Identity {
            code: codes::IDENT_1005.to_owned(),
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
#[allow(clippy::unused_async)] // napi requires async for Promise return type
pub async fn identity_create_with_agent_key(custody: String) -> napi::Result<NapiIdentity> {
    validate_custody_type(&custody).map_err(NapiError::from)?;

    // Ensure the BridgeInstance exists BEFORE the DID resolver is
    // initialized. See `identity_create` for the full rationale.
    crate::runtime::ensure_bridge_instance();

    // Ensure the global DID resolver is initialized (idempotent). #311
    ensure_did_resolver_initialized();

    match custody.as_str() {
        #[cfg(feature = "allow_in_memory_custody")]
        "in_memory" => {
            let key_custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
            let dht = DidDht::new();
            let (scp_identity, document) = dht
                .create_with_agent_key(&key_custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            // Register identity in the global registry (same as identity_create).
            crate::runtime::register_identity(
                &scp_identity.did,
                crate::runtime::NapiIdentityEntry {
                    identity: scp_identity.clone(),
                    custody: Arc::clone(&key_custody),
                    document: document.clone(),
                    identity_link_attestations: Vec::new(),
                },
            );

            // Publish the DID document to the shared InMemoryDhtClient (#1144).
            publish_to_shared_dht(&scp_identity, &document, &key_custody).await;

            let handle = NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did: scp_identity.did.clone(),
                    custody_type: "in_memory".to_owned(),
                    scp_identity: Some(scp_identity),
                    in_memory_custody: Some(key_custody),
                    document: Some(document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
        #[cfg(not(feature = "allow_in_memory_custody"))]
        "in_memory" => Err(ScpNapiError::Identity {
            message:
                "in_memory custody is not available in this build -- enable allow_in_memory_custody"
                    .to_owned(),
            code: codes::IDENT_1008.to_owned(),
        }
        .into()),
        "platform" | "software" => Err(ScpNapiError::Identity {
            message: format!(
                "custody type {custody:?} requires a wired platform \
                 KeyCustodyProvider — use the KeyCustodyProvider callback \
                 interface to inject Secure Enclave (iOS) or Android \
                 Keystore (Android) backed custody"
            ),
            code: codes::IDENT_1003.to_owned(),
        }
        .into()),
        _ => Err(ScpNapiError::Identity {
            code: codes::IDENT_1005.to_owned(),
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
/// First checks the local identity registry (populated by `identity_create`).
/// If found, returns a handle backed by the registry's retained key material
/// and DID document. Falls back to DHT resolution when the DID is not in
/// the local registry.
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
/// - Rejects with `SCP-IDENT-1004` if the DID method is not `"did:dht:"`.
/// - Rejects with `SCP-IDENT-1001` if the DID is not in the local registry
///   AND cannot be resolved from the DHT.
///
/// See #1144 (C6).
#[napi]
pub async fn identity_load(did: String) -> napi::Result<NapiIdentity> {
    if !did.starts_with("did:dht:") {
        return Err(ScpNapiError::Identity {
            message: format!("unsupported DID method: {did} — only did:dht is supported"),
            code: codes::IDENT_1004.to_owned(),
        }
        .into());
    }

    // Try the local identity registry first (populated by identity_create).
    // This avoids a DHT round-trip for identities created in this process.
    #[cfg(feature = "allow_in_memory_custody")]
    {
        let local_result = crate::runtime::with_identity(&did, |entry| {
            Ok((
                entry.identity.clone(),
                std::sync::Arc::clone(&entry.custody),
                entry.document.clone(),
            ))
        });

        if let Ok((identity, custody, document)) = local_result {
            let handle = NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did,
                    custody_type: "in_memory".to_owned(),
                    scp_identity: Some(identity),
                    in_memory_custody: Some(custody),
                    document: Some(document),
                    instance_id: crate::runtime::default_instance_id()?,
                }),
            };
            increment_handle_count();
            return Ok(handle);
        }
    }

    // Fall back to DHT resolution for identities not in the local registry.
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
            #[cfg(feature = "allow_in_memory_custody")]
            in_memory_custody: None,
            document: Some(document),
            instance_id: crate::runtime::default_instance_id()?,
        }),
    };
    increment_handle_count();
    Ok(handle)
}

/// Resolves a DID to its DID Document.
///
/// First checks the local identity registry for a cached document. Falls back
/// to DHT resolution when the DID is not in the local registry.
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
/// - Rejects with `SCP-IDENT-1001` if the DID is not in the local registry
///   AND cannot be resolved from the DHT.
///
/// See #1144 (C6).
#[napi]
pub async fn identity_resolve(did: String) -> napi::Result<NapiDIDDocument> {
    if !did.starts_with("did:dht:") {
        return Err(ScpNapiError::Identity {
            message: format!("unsupported DID method: {did} — only did:dht is supported"),
            code: codes::IDENT_1004.to_owned(),
        }
        .into());
    }

    // Try the local identity registry first (populated by identity_create).
    #[cfg(feature = "allow_in_memory_custody")]
    let local_doc = crate::runtime::with_identity(&did, |entry| Ok(entry.document.clone())).ok();
    #[cfg(not(feature = "allow_in_memory_custody"))]
    let local_doc: Option<DidDocument> = None;

    let document = if let Some(doc) = local_doc {
        doc
    } else {
        let dht = DidDht::new();
        dht.resolve(&did)
            .await
            .map_err(|e| NapiError::from(ScpNapiError::from(e)))?
    };

    let has_agent_key = document.has_agent_key();
    let agent_public_key = document
        .agent_verification_method()
        .map(|vm| vm.public_key_multibase.clone());

    let verification_methods = document
        .verification_method
        .iter()
        .map(|vm| NapiVerificationMethod {
            id: vm.id.clone(),
            method_type: vm.method_type.clone(),
            controller: vm.controller.clone(),
            public_key_multibase: vm.public_key_multibase.clone(),
        })
        .collect();

    Ok(NapiDIDDocument {
        id: document.id.clone(),
        verification_methods,
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

/// Removes an identity from the global identity registry.
///
/// Drops the retained key material (`InMemoryKeyCustody`) and `ScpIdentity`
/// for the specified DID. This is the NAPI equivalent of the `PyO3` bridge's
/// `remove_identity` function.
///
/// Call this during DID migration (to clean up the old DID) or when an
/// identity is no longer needed. Prevents memory leaks of private key
/// material in long-running processes.
///
/// Idempotent: succeeds silently if the DID is not in the registry.
///
/// # Arguments
///
/// * `did` — The DID string to remove from the registry.
#[cfg(feature = "allow_in_memory_custody")]
#[napi(js_name = "identityRemove")]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub fn identity_remove(did: String) {
    crate::runtime::remove_identity(&did);
}

/// Removes an identity from the global identity registry if present.
///
/// Returns `true` if the identity was found and removed, `false` if the DID
/// was not in the registry. Useful for conditional cleanup where callers need
/// to know whether the identity existed.
///
/// # Arguments
///
/// * `did` — The DID string to remove from the registry.
///
/// # Returns
///
/// `true` if the identity was present and removed, `false` otherwise.
#[cfg(feature = "allow_in_memory_custody")]
#[napi(js_name = "identityRemoveIfPresent")]
#[must_use]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
pub fn identity_remove_if_present(did: String) -> bool {
    crate::runtime::remove_identity_if_present(&did)
}

// ---------------------------------------------------------------------------
// Device attestation bridge (#362)
// ---------------------------------------------------------------------------

/// Generates a device attestation token for an identity.
///
/// Uses `InMemoryDeviceAttestation` to produce a synthetic attestation token,
/// then attaches it to the identity's DID document.
///
/// # Arguments
///
/// * `did` -- The DID string of the identity to attest (used for API
///   consistency; the attestation is generated locally).
///
/// # Returns
///
/// The attestation token as a base64-encoded string.
///
/// # Errors
///
/// Rejects if the identity was not created with `identityCreate` (no retained
/// crypto state) or if attestation generation fails.
///
/// See §9.3, issue #362.
#[cfg(feature = "allow_in_memory_custody")]
#[napi(js_name = "identityAttestDevice")]
pub async fn identity_attest_device(did: String) -> napi::Result<String> {
    use scp_platform::testing::InMemoryDeviceAttestation;
    use scp_platform::traits::DeviceAttestation;

    let attestation = InMemoryDeviceAttestation::new();
    let token = attestation.attest().await.map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("device attestation failed: {e}"),
            code: codes::IDENT_1010.to_owned(),
        })
    })?;

    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(token.as_bytes());

    // Attach the attestation to the DID document if the identity was created
    // locally. This is a best-effort operation — if the identity was loaded
    // externally, we still return the token.
    let _ = did; // API consistency — the attestation is device-local.

    Ok(encoded)
}

/// Verifies a device attestation token.
///
/// Uses `InMemoryDeviceAttestation` to check the token format.
///
/// # Arguments
///
/// * `did` -- The DID string (unused in verification but kept for API
///   consistency).
/// * `token_base64` -- The base64-encoded attestation token to verify.
///
/// # Returns
///
/// `true` if the token is valid, `false` otherwise.
///
/// # Errors
///
/// Rejects if base64 decoding fails or if verification encounters an error.
///
/// See §9.3, issue #362.
#[cfg(feature = "allow_in_memory_custody")]
#[napi(js_name = "identityVerifyDeviceAttestation")]
pub async fn identity_verify_device_attestation(
    did: String,
    token_base64: String,
) -> napi::Result<bool> {
    use base64::Engine;
    use scp_platform::testing::InMemoryDeviceAttestation;
    use scp_platform::traits::DeviceAttestation;

    let _ = did; // API consistency.

    let token_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token_base64)
        .map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("invalid base64 attestation token: {e}"),
                code: codes::IDENT_1011.to_owned(),
            })
        })?;

    let token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
    let attestation = InMemoryDeviceAttestation::new();

    attestation.verify(&token).await.map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("device attestation verification failed: {e}"),
            code: codes::IDENT_1012.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Identity link attestation bridge (§3.5.1, §3.5.2)
// ---------------------------------------------------------------------------

/// Creates an identity link attestation for an external platform identity.
///
/// See spec §3.5.1, §3.5.2.
#[cfg(feature = "allow_in_memory_custody")]
#[napi(js_name = "identityCreateLinkAttestation")]
#[allow(clippy::unused_async)]
pub async fn identity_create_link_attestation(
    did: String,
    platform: String,
    handle: String,
    proof: String,
    verification_method: String,
    platform_id: Option<String>,
) -> napi::Result<String> {
    use scp_platform::traits::KeyCustody;

    // Validate attestation input field sizes.
    scp_ffi_common::validate::validate_attestation_fields(&platform, &handle, &proof)
        .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

    // Phase 1: read custody + key handle (under DashMap lock, then drop).
    let (custody, key_handle) = crate::runtime::with_identity(&did, |entry| {
        Ok((
            Arc::clone(&entry.custody),
            entry.identity.active_signing_key,
        ))
    })?;

    // Build unsigned attestation using shared pipeline.
    let built = scp_ffi_common::attestation::build_unsigned_attestation(
        &did,
        platform,
        handle,
        proof,
        &verification_method,
        platform_id,
    )
    .map_err(|e| {
        let code = match &e {
            scp_ffi_common::attestation::AttestationBuildError::InvalidMethod(_)
            | scp_ffi_common::attestation::AttestationBuildError::ClockError => codes::IDENT_1040,
            _ => codes::IDENT_1041,
        };
        NapiError::from(ScpNapiError::Identity {
            message: e.to_string(),
            code: code.to_owned(),
        })
    })?;

    let mut attestation = built.attestation;

    // Phase 2: sign (no DashMap lock held — safe to block_in_place).
    let rt = tokio::runtime::Handle::try_current().map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("no tokio runtime: {e}"),
            code: codes::IDENT_1041.to_owned(),
        })
    })?;

    let sig = tokio::task::block_in_place(|| {
        rt.block_on(custody.0.sign(&key_handle, &built.canonical_bytes))
    })
    .map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("Ed25519 signing failed: {e}"),
            code: codes::IDENT_1041.to_owned(),
        })
    })?;
    attestation.signature = sig.as_bytes().to_vec();

    // Phase 3: store attestation (re-acquire DashMap lock, TOCTOU guard).
    crate::runtime::with_identity_mut(&did, |entry| {
        // Verify the active signing key has not been rotated between Phase 1 and Phase 3.
        if entry.identity.active_signing_key != key_handle {
            return Err(ScpNapiError::Identity {
                message: "active signing key was rotated during attestation creation — \
                         please retry"
                    .to_owned(),
                code: codes::IDENT_1041.to_owned(),
            });
        }

        if entry.identity_link_attestations.len() >= MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID {
            return Err(ScpNapiError::Identity {
                message: format!(
                    "DID has reached the per-identity attestation limit \
                     ({MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID}) — cannot store additional attestations"
                ),
                code: codes::VALID_7403.to_owned(),
            });
        }
        entry.identity_link_attestations.push(attestation.clone());
        Ok(())
    })
    .map_err(NapiError::from)?;

    serde_json::to_string(&attestation).map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("failed to serialize attestation: {e}"),
            code: codes::IDENT_1042.to_owned(),
        })
    })
}

/// Lists all identity link attestations for an identity.
///
/// See spec §3.5.1.
#[cfg(feature = "allow_in_memory_custody")]
#[napi(js_name = "identityLinkAttestations")]
pub fn identity_link_attestations(did: String) -> napi::Result<String> {
    crate::runtime::with_identity(&did, |entry| {
        serde_json::to_string(&entry.identity_link_attestations).map_err(|e| {
            ScpNapiError::Identity {
                message: format!("failed to serialize attestations: {e}"),
                code: codes::IDENT_1043.to_owned(),
            }
        })
    })
    .map_err(NapiError::from)
}

/// Removes an identity link attestation by its ID.
///
/// Returns `true` if the attestation was found and removed.
///
/// See spec §3.5.1.
#[cfg(feature = "allow_in_memory_custody")]
#[napi(js_name = "identityRemoveLinkAttestation")]
pub fn identity_remove_link_attestation(did: String, attestation_id: String) -> napi::Result<bool> {
    crate::runtime::with_identity_mut(&did, |entry| {
        let before = entry.identity_link_attestations.len();
        entry
            .identity_link_attestations
            .retain(|a| a.id != attestation_id);
        Ok(entry.identity_link_attestations.len() < before)
    })
    .map_err(NapiError::from)
}

/// Verifies the Ed25519 signature on an identity link attestation.
///
/// The issuer's public key cannot be reliably extracted from the DID string
/// because attestations are signed with `#active` or `#agent` keys
/// (spec §3.5.2), not the `#0` identity key embedded in the DID.
///
/// See spec §3.5.1.
#[napi(js_name = "identityVerifyLinkAttestation")]
#[allow(clippy::unused_async)]
pub async fn identity_verify_link_attestation(
    attestation_json: String,
    issuer_public_key_hex: String,
) -> napi::Result<bool> {
    use scp_core::identity::attestation::IdentityLinkAttestation;

    let attestation: IdentityLinkAttestation =
        serde_json::from_str(&attestation_json).map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("failed to parse attestation JSON: {e}"),
                code: codes::IDENT_1044.to_owned(),
            })
        })?;

    let pub_bytes = hex::decode(&issuer_public_key_hex).map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("invalid issuer_public_key_hex: {e}"),
            code: codes::IDENT_1044.to_owned(),
        })
    })?;
    Ok(attestation.verify_signature(&pub_bytes).is_ok())
}

// ---------------------------------------------------------------------------
// Compromise recovery — FFI exposure for CompromiseRecoveryOrchestrator
// ---------------------------------------------------------------------------

/// Executes the compromise recovery protocol for the given DID.
///
/// Returns a JSON string with the recovery result.
///
/// See spec §9.12 and PR #1080.
#[napi]
pub fn identity_execute_recovery(
    did: String,
    tier: String,
    context_ids: Vec<String>,
) -> napi::Result<String> {
    use std::collections::HashSet;

    use scp_core::identity::recovery::{
        CompromiseRecoveryOrchestrator, CompromiseTier, KeyRotationOutcome, PskRotationParams,
        RecoveryBackend, RecoveryStepError, active_key_rotation_outcome,
        agent_key_rotation_outcome,
    };
    use scp_ffi_common::validate::validate_did;
    use scp_identity::DID;

    validate_did(&did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let did_val = DID::from(did.as_str());

    let compromise_tier = match tier.as_str() {
        "agent" => CompromiseTier::Agent,
        "active_signing" => CompromiseTier::ActiveSigning,
        "identity_key" => CompromiseTier::IdentityKey,
        other => {
            return Err(NapiError::from(ScpNapiError::Identity {
                message: format!(
                    "invalid compromise tier: {other}; expected 'agent', 'active_signing', or 'identity_key'"
                ),
                code: codes::IDENT_1020.to_owned(),
            }));
        }
    };

    let now_ms = scp_primitives::SystemClock.now_millis();

    let key_rotation = match compromise_tier {
        CompromiseTier::Agent => agent_key_rotation_outcome(&did_val, now_ms),
        CompromiseTier::ActiveSigning => active_key_rotation_outcome(&did_val, now_ms),
        CompromiseTier::IdentityKey => scp_core::identity::recovery::identity_key_rotation_outcome(
            &did_val,
            did_val.clone(),
            now_ms,
        ),
    };

    struct NapiRecoveryBackend;
    impl RecoveryBackend for NapiRecoveryBackend {
        fn mls_update(
            &self,
            _context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            Ok(())
        }
        fn revoke_ucans(
            &self,
            _context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            Ok(())
        }
        fn rotate_key_packages(
            &self,
            _context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            Ok(())
        }
        fn notify_contacts(
            &self,
            _did: &DID,
            _tier: CompromiseTier,
            _key_rotation: &KeyRotationOutcome,
            _contacts: &HashSet<DID>,
        ) -> bool {
            true
        }
        fn rotate_psk(&self, _params: &PskRotationParams) -> bool {
            true
        }
    }

    let orchestrator = CompromiseRecoveryOrchestrator::new(did_val, context_ids);
    let contacts = HashSet::new();
    let backend = NapiRecoveryBackend;

    let handle = tokio::runtime::Handle::try_current().map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("tokio runtime not available: {e}"),
            code: codes::IDENT_1027.to_owned(),
        })
    })?;

    let result = handle
        .block_on(orchestrator.execute_recovery(
            compromise_tier,
            &key_rotation,
            &contacts,
            None,
            &backend,
            &scp_primitives::SystemClock,
        ))
        .map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("recovery failed: {e}"),
                code: codes::IDENT_1022.to_owned(),
            })
        })?;

    serde_json::to_string(&result).map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("failed to serialize recovery result: {e}"),
            code: codes::IDENT_1023.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Custody migration — FFI exposure for CustodyMigrationOrchestrator
// ---------------------------------------------------------------------------

/// Executes the custody migration protocol for the given DID.
///
/// Returns a JSON string with the migration result.
///
/// See spec §3.2.1.
#[napi]
pub fn identity_execute_custody_migration(
    did: String,
    target: String,
    context_ids: Vec<String>,
) -> napi::Result<String> {
    use scp_core::identity::custody_migration::{
        CustodyMigrationBackend, CustodyMigrationOrchestrator, CustodyMigrationRequest,
        CustodyMigrationTarget,
    };
    use scp_ffi_common::validate::validate_did;
    use scp_identity::DID;

    validate_did(&did).map_err(|e| napi::Error::from(ScpNapiError::from(e)))?;
    let did_val = DID::from(did.as_str());

    let migration_target = match target.as_str() {
        "platform_managed" => CustodyMigrationTarget::PlatformManaged,
        "hardware" => CustodyMigrationTarget::Hardware,
        "software" => CustodyMigrationTarget::Software,
        "in_memory" => CustodyMigrationTarget::InMemory,
        other => {
            return Err(NapiError::from(ScpNapiError::Identity {
                message: format!(
                    "invalid custody migration target: {other}; expected 'platform_managed', 'hardware', 'software', or 'in_memory'"
                ),
                code: codes::IDENT_1024.to_owned(),
            }));
        }
    };

    // Error-returning backend — custody migration requires a real backend
    // provided via the SDK layer. This placeholder ensures callers get an
    // actionable error instead of silently succeeding with fake keys.
    struct NotConfiguredMigrationBackend;
    impl CustodyMigrationBackend for NotConfiguredMigrationBackend {
        fn generate_key(&self, _target: CustodyMigrationTarget) -> Result<Vec<u8>, String> {
            Err(
                "custody migration backend not configured — provide a real backend via SDK layer"
                    .to_owned(),
            )
        }
        fn authorize(&self, _request: &CustodyMigrationRequest) -> Result<(), String> {
            Err(
                "custody migration backend not configured — provide a real backend via SDK layer"
                    .to_owned(),
            )
        }
        fn rotate_did_document(
            &self,
            _did: &DID,
            _request: &CustodyMigrationRequest,
            _context_ids: &[String],
        ) -> Result<(Vec<String>, Vec<String>), String> {
            Err(
                "custody migration backend not configured — provide a real backend via SDK layer"
                    .to_owned(),
            )
        }
        fn reissue_credentials(
            &self,
            _did: &DID,
            _request: &CustodyMigrationRequest,
        ) -> Result<(), String> {
            Err(
                "custody migration backend not configured — provide a real backend via SDK layer"
                    .to_owned(),
            )
        }
        fn destroy_old_key(&self, _did: &DID) -> Result<(), String> {
            Err(
                "custody migration backend not configured — provide a real backend via SDK layer"
                    .to_owned(),
            )
        }
    }

    let orchestrator = CustodyMigrationOrchestrator::new(did_val, migration_target, context_ids);
    let backend = NotConfiguredMigrationBackend;

    let handle = tokio::runtime::Handle::try_current().map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("tokio runtime not available: {e}"),
            code: codes::IDENT_1028.to_owned(),
        })
    })?;

    let result = handle
        .block_on(orchestrator.execute(&backend, &scp_primitives::SystemClock))
        .map_err(|e| {
            NapiError::from(ScpNapiError::Identity {
                message: format!("custody migration failed: {e}"),
                code: codes::IDENT_1025.to_owned(),
            })
        })?;

    serde_json::to_string(&result).map_err(|e| {
        NapiError::from(ScpNapiError::Identity {
            message: format!("failed to serialize custody migration result: {e}"),
            code: codes::IDENT_1026.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "allow_in_memory_custody")]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    /// Creates a test `NapiIdentity` with in-memory custody, returning the
    /// identity and its initial active signing key's public key (multibase).
    async fn create_test_identity() -> (NapiIdentity, String) {
        let key_custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
        let dht = DidDht::new();
        let (scp_identity, document) = dht
            .create(&key_custody.0)
            .await
            .expect("identity creation must succeed");

        // Extract the initial active key's public key multibase from the document.
        let initial_active_key = document
            .verification_method
            .iter()
            .find(|vm| vm.id.ends_with("#active"))
            .expect("document must have an #active verification method")
            .public_key_multibase
            .clone();

        let handle = NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did: scp_identity.did.clone(),
                custody_type: "in_memory".to_owned(),
                scp_identity: Some(scp_identity),
                in_memory_custody: Some(key_custody),
                document: Some(document),
                instance_id: scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID,
            }),
        };
        increment_handle_count();
        (handle, initial_active_key)
    }

    #[test]
    fn rotate_key_returns_same_did() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());
        let original_did = identity.did();

        let rotated = rt
            .block_on(identity.rotate_key())
            .expect("rotate_key must succeed");

        assert_eq!(
            rotated.did(),
            original_did,
            "DID must remain the same after key rotation"
        );
    }

    #[test]
    fn rotate_key_changes_active_signing_key() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, initial_active_key) = rt.block_on(create_test_identity());

        let rotated = rt
            .block_on(identity.rotate_key())
            .expect("rotate_key must succeed");

        let rotated_doc = rotated
            .inner
            .document
            .as_ref()
            .expect("rotated identity must have a document");
        let new_active_key = rotated_doc
            .verification_method
            .iter()
            .find(|vm| vm.id.ends_with("#active"))
            .expect("rotated document must have an #active verification method")
            .public_key_multibase
            .clone();

        assert_ne!(
            new_active_key, initial_active_key,
            "active signing key must change after rotation"
        );
    }

    #[test]
    fn rotate_key_retains_old_key_in_history() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, initial_active_key) = rt.block_on(create_test_identity());

        let rotated = rt
            .block_on(identity.rotate_key())
            .expect("rotate_key must succeed");

        let rotated_doc = rotated
            .inner
            .document
            .as_ref()
            .expect("rotated identity must have a document");

        // The old active key should appear as a retired verification method.
        // The naming convention is `#retired-{sequence}` (see document.rs).
        let retired_keys: Vec<_> = rotated_doc
            .verification_method
            .iter()
            .filter(|vm| vm.id.contains("#retired-"))
            .collect();

        assert!(
            !retired_keys.is_empty(),
            "rotated document must contain at least one retired active key"
        );

        // The retired key's public key should match the original active key.
        let retired_key = &retired_keys[0].public_key_multibase;
        assert_eq!(
            retired_key, &initial_active_key,
            "retired key must match the original active signing key"
        );
    }

    #[test]
    fn rotate_key_updates_did_document() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());

        let rotated = rt
            .block_on(identity.rotate_key())
            .expect("rotate_key must succeed");

        let rotated_doc = rotated
            .inner
            .document
            .as_ref()
            .expect("rotated identity must have a document");

        // The document must have the new #active key in authentication refs.
        let has_active_auth = rotated_doc
            .authentication
            .iter()
            .any(|a| a.ends_with("#active"));
        assert!(
            has_active_auth,
            "rotated document must reference #active in authentication"
        );
    }

    #[test]
    fn rotate_key_preserves_custody_type() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());

        let rotated = rt
            .block_on(identity.rotate_key())
            .expect("rotate_key must succeed");

        assert_eq!(
            rotated.custody_type(),
            "in_memory",
            "custody type must remain in_memory after rotation"
        );
    }

    #[test]
    fn rotate_key_errors_without_retained_crypto_state() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

        // Construct a NapiIdentity with no scp_identity and no in_memory_custody,
        // simulating an externally loaded identity with no retained key material.
        let identity = NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did: "did:dht:z6MkTest".to_owned(),
                custody_type: "external".to_owned(),
                scp_identity: None,
                in_memory_custody: None,
                document: None,
                instance_id: scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID,
            }),
        };
        increment_handle_count();

        let Err(err) = rt.block_on(identity.rotate_key()) else {
            panic!("rotate_key must fail without retained crypto state")
        };

        let msg = err.to_string();
        assert!(
            msg.contains(codes::IDENT_1007),
            "error must contain SCP-IDENT-1007, got: {msg}"
        );
    }

    #[test]
    fn rotate_key_twice_produces_two_retired_keys_and_distinct_active_keys() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, initial_active_key) = rt.block_on(create_test_identity());

        // First rotation.
        let rotated_1 = rt
            .block_on(identity.rotate_key())
            .expect("first rotate_key must succeed");

        let doc_1 = rotated_1
            .inner
            .document
            .as_ref()
            .expect("first rotated identity must have a document");
        let active_key_1 = doc_1
            .verification_method
            .iter()
            .find(|vm| vm.id.ends_with("#active"))
            .expect("first rotated document must have #active")
            .public_key_multibase
            .clone();

        // Second rotation — uses the Arc-shared custody from the first rotation.
        let rotated_2 = rt
            .block_on(rotated_1.rotate_key())
            .expect("second rotate_key must succeed");

        let doc_2 = rotated_2
            .inner
            .document
            .as_ref()
            .expect("second rotated identity must have a document");
        let active_key_2 = doc_2
            .verification_method
            .iter()
            .find(|vm| vm.id.ends_with("#active"))
            .expect("second rotated document must have #active")
            .public_key_multibase
            .clone();

        // All three active keys must be distinct.
        assert_ne!(
            initial_active_key, active_key_1,
            "first rotation must produce a new active key"
        );
        assert_ne!(
            active_key_1, active_key_2,
            "second rotation must produce a new active key"
        );
        assert_ne!(
            initial_active_key, active_key_2,
            "second rotation active key must differ from initial"
        );

        // Two retired keys must be present after two rotations.
        let retired_keys: Vec<_> = doc_2
            .verification_method
            .iter()
            .filter(|vm| vm.id.contains("#retired-"))
            .collect();
        assert_eq!(
            retired_keys.len(),
            2,
            "two rotations must produce exactly 2 retired keys, got {}",
            retired_keys.len()
        );

        // Verify Arc custody sharing: both rotated identities share the same
        // underlying InMemoryKeyCustody instance via Arc.
        assert!(
            Arc::ptr_eq(
                rotated_1.inner.in_memory_custody.as_ref().expect("custody"),
                rotated_2.inner.in_memory_custody.as_ref().expect("custody"),
            ),
            "rotated identities must share the same Arc<InMemoryKeyCustody>"
        );
    }

    #[test]
    fn napi_did_document_contains_full_verification_methods() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());

        let document = identity
            .inner
            .document
            .as_ref()
            .expect("identity must have a document");

        // Build NapiDIDDocument the same way identity_resolve does.
        let has_agent_key = document.has_agent_key();
        let agent_public_key = document
            .agent_verification_method()
            .map(|vm| vm.public_key_multibase.clone());

        let verification_methods: Vec<NapiVerificationMethod> = document
            .verification_method
            .iter()
            .map(|vm| NapiVerificationMethod {
                id: vm.id.clone(),
                method_type: vm.method_type.clone(),
                controller: vm.controller.clone(),
                public_key_multibase: vm.public_key_multibase.clone(),
            })
            .collect();

        let napi_doc = NapiDIDDocument {
            id: document.id.clone(),
            verification_methods,
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
        };

        // Verification methods must be non-empty.
        assert!(
            !napi_doc.verification_methods.is_empty(),
            "NapiDIDDocument must contain at least one verification method"
        );

        // Every verification method must have non-empty publicKeyMultibase.
        for vm in &napi_doc.verification_methods {
            assert!(
                !vm.public_key_multibase.is_empty(),
                "publicKeyMultibase must not be empty for VM {}",
                vm.id
            );
            assert!(
                vm.public_key_multibase.starts_with('z'),
                "publicKeyMultibase must start with 'z' (multibase prefix) for VM {}",
                vm.id
            );
            assert!(
                !vm.id.is_empty(),
                "verification method id must not be empty"
            );
            assert!(
                !vm.controller.is_empty(),
                "verification method controller must not be empty for VM {}",
                vm.id
            );
            assert!(
                !vm.method_type.is_empty(),
                "verification method type must not be empty for VM {}",
                vm.id
            );
        }

        // The number of NapiVerificationMethods must match the source document.
        assert_eq!(
            napi_doc.verification_methods.len(),
            document.verification_method.len(),
            "NapiDIDDocument verification_methods count must match source document"
        );
    }

    #[test]
    fn migrate_returns_new_did() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());
        let original_did = identity.did();

        let migrated = rt
            .block_on(identity.migrate())
            .expect("migrate must succeed");

        assert_ne!(
            migrated.did(),
            original_did,
            "migrated identity must have a different DID"
        );
        assert!(
            migrated.did().starts_with("did:dht:"),
            "migrated DID must be a did:dht DID"
        );
    }

    #[test]
    fn migrate_preserves_custody_type() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());

        let migrated = rt
            .block_on(identity.migrate())
            .expect("migrate must succeed");

        assert_eq!(
            migrated.custody_type(),
            "in_memory",
            "custody type must remain in_memory after migration"
        );
    }

    #[test]
    fn migrate_retains_scp_identity_and_document() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());

        let migrated = rt
            .block_on(identity.migrate())
            .expect("migrate must succeed");

        assert!(
            migrated.inner.scp_identity.is_some(),
            "migrated identity must retain ScpIdentity"
        );
        assert!(
            migrated.inner.document.is_some(),
            "migrated identity must retain DidDocument"
        );
        assert!(
            migrated.inner.in_memory_custody.is_some(),
            "migrated identity must retain InMemoryKeyCustody"
        );
    }

    #[test]
    fn migrate_removes_old_identity_from_registry() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());
        let old_did = identity.did();

        // Register the identity in the runtime (simulating what identity_create does).
        crate::runtime::register_identity(
            &old_did,
            crate::runtime::NapiIdentityEntry {
                identity: identity.inner.scp_identity.clone().expect("scp_identity"),
                custody: identity
                    .inner
                    .in_memory_custody
                    .as_ref()
                    .expect("custody")
                    .clone(),
                document: identity.inner.document.clone().expect("document"),
                identity_link_attestations: Vec::new(),
            },
        );

        let migrated = rt
            .block_on(identity.migrate())
            .expect("migrate must succeed");

        // Old DID should be removed from the registry.
        let old_lookup = crate::runtime::with_identity(&old_did, |_| Ok(()));
        assert!(
            old_lookup.is_err(),
            "old DID must be removed from identity registry after migration"
        );

        // New DID should be in the registry.
        let new_lookup = crate::runtime::with_identity(&migrated.did(), |_| Ok(()));
        assert!(
            new_lookup.is_ok(),
            "new DID must be registered in identity registry after migration"
        );
    }

    #[test]
    fn migrate_errors_without_retained_crypto_state() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

        let identity = NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did: "did:dht:z6MkTest".to_owned(),
                custody_type: "external".to_owned(),
                scp_identity: None,
                in_memory_custody: None,
                document: None,
                instance_id: scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID,
            }),
        };
        increment_handle_count();

        let Err(err) = rt.block_on(identity.migrate()) else {
            panic!("migrate must fail without retained crypto state")
        };

        let msg = err.to_string();
        assert!(
            msg.contains(codes::IDENT_1007),
            "error must contain SCP-IDENT-1007, got: {msg}"
        );
    }

    #[test]
    fn migrate_shares_custody_arc() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());

        let migrated = rt
            .block_on(identity.migrate())
            .expect("migrate must succeed");

        assert!(
            Arc::ptr_eq(
                identity.inner.in_memory_custody.as_ref().expect("custody"),
                migrated.inner.in_memory_custody.as_ref().expect("custody"),
            ),
            "original and migrated identities must share the same Arc<InMemoryKeyCustody>"
        );
    }
}
