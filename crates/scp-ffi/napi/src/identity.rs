//! napi-rs bridge for identity operations.
//!
//! Exposes [`NapiIdentity`] as an opaque JS class and bridge functions for
//! the identity lifecycle:
//!
//! - `identity_create` — Creates a new DID identity (returns `Promise<NapiIdentity>`).
//! - `identity_create_with_agent_key` — Creates a new DID identity with an
//!   agent signing key.
//! - `identity_load` — Loads an existing identity by DID string.
//! - `identity_resolve` — Resolves a DID to its document.
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
#[cfg(all(test, feature = "allow_in_memory_custody"))]
use scp_identity::DidMethod;
#[cfg(feature = "allow_in_memory_custody")]
use scp_identity::{DhtClient, IdentityError};
use scp_identity::{
    DidCache, DidDht, DidDocument, DualLayerResolver, InMemoryDhtClient, NoOpRelayQuerier,
    ScpIdentity,
};
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::testing::InMemoryKeyCustody;
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::traits::KeyCustody;
use scp_primitives::Clock;
#[cfg(feature = "allow_in_memory_custody")]
use std::fmt;

use crate::error::ScpNapiError;
use crate::{decrement_handle_count, increment_handle_count};

/// Ensures the production DID resolver is initialized on the given bridge
/// instance (idempotent). #311
///
/// The `InMemoryDhtClient` created here is stored in a process-wide
/// `SHARED_DHT_CLIENT` (#1144) so every `SCP` instance in the same process
/// reads/writes the same test DHT — cross-identity flows (Alice publishes,
/// Bob resolves in the same process) depend on a single shared DHT. The
/// per-instance part is only the `DualLayerResolver` slot on
/// [`crate::runtime::NapiBridgeInstance::core`].
///
/// Uses `std::sync::Once` to guard the initial `SHARED_DHT_CLIENT` +
/// `DualLayerResolver` construction atomically. Without this, two separate
/// `OnceLock::set` calls (`SHARED_DHT_CLIENT` and
/// `BridgeInstance::did_resolver`) could race under concurrent access: thread A
/// creates `InMemoryDhtClient` X and sets `SHARED_DHT_CLIENT`, then thread B
/// creates `InMemoryDhtClient` Y, fails to set `SHARED_DHT_CLIENT` (already set
/// to X), but builds a `DualLayerResolver` around Y and stores it in
/// `BridgeInstance` — the resolver and the shared DHT client would reference
/// different instances.
///
/// Subsequent calls on the same bridge instance are no-ops: once a resolver is
/// attached (via [`crate::runtime::init_did_resolver`]) the helper short-
/// circuits. For a fresh `SCP` instance that hasn't yet acquired a resolver,
/// this reuses the process-wide `SHARED_DHT_CLIENT` (if already set) to build
/// the instance-local `DualLayerResolver`.
pub(crate) fn ensure_did_resolver_initialized_on(bi: &crate::runtime::NapiBridgeInstance) {
    if crate::runtime::did_resolver(bi).is_some() {
        return;
    }

    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return; // No runtime available; skip initialization.
    };

    // Reuse the process-wide `SHARED_DHT_CLIENT` when already set so Alice
    // (on `SCP` A) publishes to the same DHT Bob (on `SCP` B) reads from.
    // The client is `init`'d at most once per process regardless of how many
    // `SCP` instances exist.
    let dht_client = crate::runtime::shared_dht_client().map_or_else(
        || {
            let client = Arc::new(InMemoryDhtClient::new());
            crate::runtime::init_shared_dht_client(Arc::clone(&client));
            client
        },
        Arc::clone,
    );

    let relay_querier = Arc::new(NoOpRelayQuerier);
    let cache = Arc::new(DidCache::new());
    let bootstrap_relays = Vec::new();

    let resolver = Arc::new(DualLayerResolver::new(
        relay_querier,
        dht_client,
        cache,
        bootstrap_relays,
    ));

    crate::runtime::init_did_resolver(bi, resolver, handle);
}

// Phase D (#1695): `ensure_did_resolver_initialized` default-bridge wrapper
// deleted. All callers pass `&NapiBridgeInstance` and invoke
// `ensure_did_resolver_initialized_on(bi)` directly.

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
pub(crate) async fn publish_to_shared_dht_for(
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
    /// The `NapiBridgeInstance` that minted this identity.
    ///
    /// Retained so mutable identity methods (rotateKey, addAgentKey,
    /// rotateAgentKey, removeAgentKey, migrate) can register the derived
    /// identity state on the correct bridge registry without depending on
    /// the process-global default bridge. Phase D (#1695).
    pub(crate) bi: Arc<crate::runtime::NapiBridgeInstance>,
    /// Hex-encoded Ed25519 verifying-key bytes for the identity key
    /// (VM `#0`, the key that derives the DID). 64 hex chars = 32 raw
    /// bytes. Populated for identities created via `Scp::identity_create`;
    /// `None` for externally loaded identities.
    ///
    /// Uses `identity_key` (not `#active`) because the WASM bridge has a
    /// simplified single-key model; exposing the identity key gives
    /// byte-exact cross-bridge parity under a deterministic `seed`
    /// (ADR-046).
    pub(crate) verifying_key_hex: Option<String>,
    /// `NapiBridgeInstance` id that minted this handle — used for runtime
    /// handle-affinity checks at every FFI entry point that accepts a
    /// `NapiIdentity`. Mismatches are rejected with `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
    /// JSON-serialized `scp_identity::DidRotationEvent` produced when
    /// this handle was minted by [`NapiIdentity::migrate`]. SDK callers
    /// MUST distribute the event to active context members per spec
    /// §3.2.1 step 4b. `None` for handles produced by `identity_create`,
    /// `rotate_key`, agent-key ops, or external load — those operations
    /// do not change the DID, so no `DidRotationEvent` is constructed.
    pub(crate) rotation_event_json: Option<String>,
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

    /// Returns the hex-encoded Ed25519 verifying-key bytes for the
    /// identity key (VM `#0`, the DID-deriving key), or `null` if this
    /// handle was loaded without live key material.
    ///
    /// Under a deterministic `seed`, this value is byte-identical across
    /// every bridge (ADR-046). See the `verifying_key_hex` field docs
    /// for why `#0` rather than `#active`.
    #[napi(getter, js_name = "verifyingKey")]
    #[must_use]
    pub fn verifying_key(&self) -> Option<String> {
        self.inner.verifying_key_hex.clone()
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

            let bi = &self.inner.bi;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(bi, &self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .rotate_active_key(&scp_identity, &document, &custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let verifying_key_hex =
                identity_verifying_key_hex(&custody, &new_identity.identity_key).await;

            // Update the identity registry with the rotated key handles.
            crate::runtime::register_identity(
                bi,
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
                    bi: Arc::clone(&self.inner.bi),
                    verifying_key_hex,
                    instance_id: self.inner.bi.instance_id(),
                    rotation_event_json: None,
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

            let bi = &self.inner.bi;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(bi, &self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .add_agent_key(&scp_identity, &document, &custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let verifying_key_hex =
                identity_verifying_key_hex(&custody, &new_identity.identity_key).await;

            // Update the identity registry with the new key state so that
            // bridge functions (ucan_delegate, etc.) see the updated identity.
            crate::runtime::register_identity(
                bi,
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
                    bi: Arc::clone(&self.inner.bi),
                    verifying_key_hex,
                    instance_id: self.inner.bi.instance_id(),
                    rotation_event_json: None,
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

            let bi = &self.inner.bi;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(bi, &self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .rotate_agent_key(&scp_identity, &document, &custody.0)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let verifying_key_hex =
                identity_verifying_key_hex(&custody, &new_identity.identity_key).await;

            // Update the identity registry with the rotated key state.
            crate::runtime::register_identity(
                bi,
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
                    bi: Arc::clone(&self.inner.bi),
                    verifying_key_hex,
                    instance_id: self.inner.bi.instance_id(),
                    rotation_event_json: None,
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

            let bi = &self.inner.bi;

            // Read attestations BEFORE async operation (entry guaranteed to exist).
            let existing_attestations = crate::runtime::with_identity(bi, &self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document) = dht
                .remove_agent_key(&scp_identity, &document)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let verifying_key_hex =
                identity_verifying_key_hex(&custody, &new_identity.identity_key).await;

            // Update the identity registry with the post-removal key state.
            crate::runtime::register_identity(
                bi,
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
                    bi: Arc::clone(&self.inner.bi),
                    verifying_key_hex,
                    instance_id: self.inner.bi.instance_id(),
                    rotation_event_json: None,
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
    /// Returns the migrated identity. The handle exposes the
    /// `DidRotationEvent` JSON via the `rotationEventJson` getter
    /// (spec §3.7, ADR-003 §4b/4c). The SDK distributes the event to
    /// active context members per spec §3.2.1 step 4b. Wire shape is
    /// `serde_json::to_string(&scp_identity::DidRotationEvent)`.
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

            let bi = &self.inner.bi;

            // Read attestations BEFORE async operation (entry guaranteed to exist now).
            let existing_attestations = crate::runtime::with_identity(bi, &self.inner.did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            // Spec §3.7 / §9.12 (Compromise Recovery Protocol): the
            // pre-rotation key whose hash equals the published
            // `pre_rotation_commitment` is the only key that satisfies the
            // `SHA-256(revealed_key) == commitment` invariant verified by
            // `verify_migration`. It is retained on `ScpIdentity` from
            // `dht.create()` onward.
            let rotated_at = scp_primitives::SystemClock.now_secs();

            let dht = make_dht_with_signer(&custody);
            let (new_identity, new_document, rotation_event) = dht
                .migrate_identity(
                    &scp_identity,
                    &document,
                    &scp_identity.pre_rotation_key,
                    &custody.0,
                    rotated_at,
                )
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;

            let rotation_event_json = serde_json::to_string(&rotation_event).map_err(|e| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!("failed to serialize rotation event: {e}"),
                    code: codes::IDENT_1004.to_owned(),
                })
            })?;

            let new_did = new_identity.did.clone();

            let verifying_key_hex =
                identity_verifying_key_hex(&custody, &new_identity.identity_key).await;

            // Remove the old identity and register the new one.
            crate::runtime::remove_identity(bi, &self.inner.did);
            crate::runtime::register_identity(
                bi,
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
                    bi: Arc::clone(&self.inner.bi),
                    verifying_key_hex,
                    instance_id: self.inner.bi.instance_id(),
                    rotation_event_json: Some(rotation_event_json),
                }),
            };
            increment_handle_count();
            Ok(handle)
        }
    }

    /// Returns the JSON-serialized `DidRotationEvent` if this handle was
    /// produced by [`NapiIdentity::migrate`]; `None` otherwise. The SDK
    /// distributes the event to active context members per spec §3.2.1
    /// step 4b.
    #[napi(getter, js_name = "rotationEventJson")]
    #[must_use]
    pub fn rotation_event_json(&self) -> Option<String> {
        self.inner.rotation_event_json.clone()
    }
}

/// Returns the hex-encoded identity-key (`#0`) verifying-key bytes for the
/// supplied handle+custody pair, or `None` if the custody fails to produce
/// a public key. Best-effort — failures are swallowed because
/// `verifying_key` is a parity-test convenience, not a correctness-
/// critical field.
///
/// Callers pass `identity.identity_key` (not `active_signing_key`): the
/// WASM bridge has only one key per identity, so byte-exact cross-bridge
/// parity requires every bridge to expose the DID-deriving identity key.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) async fn identity_verifying_key_hex(
    custody: &Arc<OpaqueInMemoryKeyCustody>,
    handle: &scp_platform::traits::KeyHandle,
) -> Option<String> {
    custody
        .0
        .public_key(handle)
        .await
        .ok()
        .map(|pk| hex::encode(pk.as_bytes()))
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
//
// Phase D (#1695): the `identity_remove` and `identity_remove_if_present`
// free-function exports moved onto `Scp` (see `scp.rs`). The underlying
// runtime helpers (`remove_identity` / `remove_identity_if_present`) still
// exist in `runtime.rs` but are now called via the `Scp` methods which pass
// `&self.inner` explicitly.

// Phase D (#1695): device attestation, identity link attestation, and
// compromise recovery free-function façade exports were deleted. Their
// `Scp` methods in `scp.rs` are now the only entry points — bridge state
// flows through `&self.inner` rather than the process-global default.

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
    /// identity (stamped with a dedicated `NapiBridgeInstance`) and its
    /// initial active signing key's public key (multibase).
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

        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        // Register the identity on the bridge so rotate_key / agent-key
        // methods can look it up via `with_identity`.
        crate::runtime::register_identity(
            &bi,
            &scp_identity.did,
            crate::runtime::NapiIdentityEntry {
                identity: scp_identity.clone(),
                custody: Arc::clone(&key_custody),
                document: document.clone(),
                identity_link_attestations: Vec::new(),
            },
        );
        let instance_id = bi.instance_id();
        let verifying_key_hex =
            identity_verifying_key_hex(&key_custody, &scp_identity.identity_key).await;

        let handle = NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did: scp_identity.did.clone(),
                custody_type: "in_memory".to_owned(),
                scp_identity: Some(scp_identity),
                in_memory_custody: Some(key_custody),
                document: Some(document),
                bi,
                verifying_key_hex,
                instance_id,
                rotation_event_json: None,
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
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let instance_id = bi.instance_id();
        let identity = NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did: "did:dht:z6MkTest".to_owned(),
                custody_type: "external".to_owned(),
                scp_identity: None,
                in_memory_custody: None,
                document: None,
                bi,
                verifying_key_hex: None,
                instance_id,
                rotation_event_json: None,
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

        // Rotation event JSON deserializes into the canonical
        // DidRotationEvent shape (spec §3.7, ADR-003 §4b/4c).
        let event_json = migrated
            .rotation_event_json()
            .expect("migrated handle must surface rotationEventJson");
        let event: scp_identity::DidRotationEvent = serde_json::from_str(&event_json)
            .expect("rotation_event_json must deserialize as DidRotationEvent");
        assert_eq!(event.old_did, original_did);
        assert_eq!(event.new_did, migrated.did());
        // Pre-rotation proof must satisfy the cryptographic invariant
        // `SHA-256(revealed_key) == commitment` — the same check
        // recipients run via `verify_migration` (spec §3.7).
        let pre_rot = event
            .pre_rotation_proof
            .as_ref()
            .expect("pre-rotation proof MUST be present");
        use sha2::{Digest, Sha256};
        let recomputed: [u8; 32] = Sha256::digest(pre_rot.revealed_key).into();
        assert_eq!(
            recomputed, pre_rot.commitment,
            "PreRotationProof MUST satisfy SHA-256(revealed_key) == commitment"
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
        // `create_test_identity` stamped the handle with its own bridge;
        // reuse that bridge so registry writes land on the same instance
        // the migrate() method will consult via `self.inner.bi`.
        let bi = Arc::clone(&identity.inner.bi);

        // Register the identity in the runtime (simulating what identity_create does).
        crate::runtime::register_identity(
            &bi,
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
        let old_lookup = crate::runtime::with_identity(&bi, &old_did, |_| Ok(()));
        assert!(
            old_lookup.is_err(),
            "old DID must be removed from identity registry after migration"
        );

        // New DID should be in the registry.
        let new_lookup = crate::runtime::with_identity(&bi, &migrated.did(), |_| Ok(()));
        assert!(
            new_lookup.is_ok(),
            "new DID must be registered in identity registry after migration"
        );
    }

    #[test]
    fn migrate_errors_without_retained_crypto_state() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let instance_id = bi.instance_id();
        let identity = NapiIdentity {
            inner: Arc::new(NapiIdentityInner {
                did: "did:dht:z6MkTest".to_owned(),
                custody_type: "external".to_owned(),
                scp_identity: None,
                in_memory_custody: None,
                document: None,
                bi,
                verifying_key_hex: None,
                instance_id,
                rotation_event_json: None,
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
