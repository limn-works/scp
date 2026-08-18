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
//! This bridge calls `scp-core` directly for the
//! `"in_memory"` custody path — the tokio multi-thread runtime is available
//! in the Bun/Node environment.
//!
//! # Key custody
//!
//! The production custody path is `identityCreateWithCustody(provider)`, which
//! wires a caller-supplied `KeyCustodyProvider` (keychain/HSM-backed). Identities
//! created this way report `custodyType == "callback"`, since key material
//! stays behind the provider and never enters this bridge's heap.
//!
//! `"in_memory"` custody stores key material in heap memory via
//! `InMemoryKeyCustody`. It is dev/test-only and gated behind the
//! `testing` feature; identities created this way report
//! `custodyType == "in_memory"`. Externally loaded identities (DID-string only,
//! no retained key material) report `custodyType == "external"`.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and ADR-039.

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use napi::Error as NapiError;
use napi_derive::napi;
// `Clock::now_secs` is only reached from the `testing`-gated migration path
// (`NapiIdentity::migrate`); production migration fails closed before using it
// (ADR-062 §Decision 6).
#[cfg(feature = "testing")]
use scp_clock::Clock;
// The `DhtClient::publish` trait method is only invoked from the
// `testing`-gated `publish_to_shared_dht_for` (production create fails closed
// before publishing — ADR-062 §Decision 6).
#[cfg(feature = "testing")]
use scp_dht::DhtClient;
// `InMemoryDhtClient` is the §17.17.3 DHT nullifier. Since the cfg-gated DHT
// construction is now hoisted into `scp_ffi_common::dht::build_ffi_dht_client`,
// this bridge names the type only in its own `#[cfg(test)]` unit tests — hence
// the bare `test` gate (the `testing`-feature seam lives in scp-ffi-common now).
// Gated on `all(test, feature = "testing")` to match its sole consumer
// (`migrate_fails_closed_when_shared_dht_client_uninitialized`), which mints via
// the `testing`-gated `InMemoryKeyCustody`; a bare `#[cfg(test)]` would leave the
// import unused under the shipped `--features server` test build.
#[cfg(all(test, feature = "testing"))]
use scp_dht::InMemoryDhtClient;
use scp_did::DidDocument;
use scp_ffi_common::dht::FfiDhtClient;
#[cfg(all(test, feature = "testing"))]
use scp_identity::DidMethod;
use scp_identity::IdentityError;
use scp_identity::{DidCache, DidDht, ScpIdentity};
#[cfg(feature = "testing")]
use scp_platform::testing::InMemoryKeyCustody;
#[cfg(feature = "testing")]
use std::fmt;

use crate::decrement_handle_count;
use crate::error::ScpNapiError;
// `increment_handle_count` is only reached from `testing`-gated create /
// rotation / migration paths in this module; production create fails closed
// before minting a handle (ADR-062 §Decision 6).
#[cfg(feature = "testing")]
use crate::increment_handle_count;

/// Builds the shared [`FfiDhtClient`] for this process, **failing closed**.
///
/// Delegates to the single cfg-gated [`scp_ffi_common::dht::build_ffi_dht_client`]
/// (shared by all three bridges) and maps its [`DhtInitError`] to a napi error.
/// A shipped (non-`testing`) build constructs the real Mainline Pkarr client; a
/// malformed gateway or a Mainline build failure surfaces as
/// [`codes::IDENT_1058`] (dedicated DHT-init-failure code), never an in-memory
/// or no-op substitute (ADR-062 §Decision 1 / spec §17.17.3). The in-memory arm
/// is reachable only through the common test seam under `testing`.
pub(crate) fn build_ffi_dht_client() -> Result<FfiDhtClient, ScpNapiError> {
    scp_ffi_common::dht::build_ffi_dht_client().map_err(|e| ScpNapiError::Identity {
        message: format!("failed to initialize production DHT client for DID resolution: {e}"),
        code: codes::IDENT_1058.to_owned(),
    })
}

/// Fail-closed error for a production identity path when no real pre-rotation
/// custody backend is available (ADR-062 §Decision 6).
///
/// Every identity commits a pre-rotation commitment at creation (spec §9.7.4.1
/// §3 — mandatory), which requires a `PreRotationCustody` backend. The only
/// implementation is the test-harness `InMemoryPreRotationCustody` nullifier,
/// severed from every production dependency line, so a shipped (no-`testing`)
/// build returns this typed [`codes::IDENT_1059`] error rather than silently
/// minting the nullifier. Mirrors the `PyO3` reference bridge's
/// `no_pre_rotation_backend`.
#[cfg(not(feature = "testing"))]
pub(crate) fn no_pre_rotation_backend() -> ScpNapiError {
    ScpNapiError::Identity {
        message: IdentityError::NoPreRotationBackend.to_string(),
        code: codes::IDENT_1059.to_owned(),
    }
}

/// Builds a [`DidDht`] over the process-shared DHT client, for **minting**
/// (`create`) and **resolution** alike.
///
/// Both paths use the process-wide [`SHARED_DHT_CLIENT`](crate::runtime) (the
/// one `identity_create` published into) when it is initialized, and otherwise
/// build the production client fail-closed via [`build_ffi_dht_client`]. Never
/// substitutes an in-memory/no-op client on a shipped path. The returned method
/// has no `sign_fn` — that is fine for `create` (which does not publish;
/// publishing is a separate [`publish_to_shared_dht_for`] step) and for
/// `resolve` (which never signs).
pub(crate) fn shared_did_method()
-> Result<DidDht<FfiDhtClient, scp_clock::SystemClock>, ScpNapiError> {
    let client = match crate::runtime::shared_dht_client() {
        Some(client) => Arc::clone(client),
        None => Arc::new(build_ffi_dht_client()?),
    };
    Ok(DidDht::with_client(client))
}

/// Ensures the production DID resolver is initialized on the given bridge
/// instance (idempotent). #311
///
/// The shared [`FfiDhtClient`] built here is stored in a process-wide
/// `SHARED_DHT_CLIENT` (#1144) so every `SCP` instance in the same process
/// reads/writes the same DHT — cross-identity flows (Alice publishes,
/// Bob resolves in the same process) depend on a single shared DHT. The shipped
/// client is the real Mainline Pkarr client (the in-memory arm exists only under
/// `testing`). The per-instance part is only the `DualLayerResolver` slot on
/// [`crate::runtime::NapiBridgeInstance::core`].
///
/// Fails closed: when the production DHT client cannot be built, this returns a
/// typed [`ScpNapiError`] rather than substituting a nullifier (ADR-062
/// §Decision 1 / spec §17.17.3).
///
/// Subsequent calls on the same bridge instance are no-ops: once a resolver is
/// attached (via [`crate::runtime::init_did_resolver`]) the helper short-
/// circuits. For a fresh `SCP` instance that hasn't yet acquired a resolver,
/// this reuses the process-wide `SHARED_DHT_CLIENT` (if already set) to build
/// the instance-local `DualLayerResolver`.
pub(crate) fn ensure_did_resolver_initialized_on(
    bi: &crate::runtime::NapiBridgeInstance,
) -> Result<(), ScpNapiError> {
    if crate::runtime::did_resolver(bi).is_some() {
        return Ok(());
    }

    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return Ok(()); // No runtime available; skip initialization.
    };

    // Reuse the process-wide `SHARED_DHT_CLIENT` when already set so Alice
    // (on `SCP` A) publishes to the same DHT Bob (on `SCP` B) reads from.
    // The client is `init`'d at most once per process regardless of how many
    // `SCP` instances exist.
    //
    // Atomic init (closes the drop-`Once` TOCTOU): build a candidate, publish it
    // into the `OnceLock` if still unset, then RE-READ the canonical winner. Two
    // threads racing here each build a candidate; exactly one wins
    // `init_shared_dht_client` (a set-if-unset `OnceLock::set`), and BOTH then
    // re-read the winner — so every resolver is built over the SAME client the
    // global retains, never an orphaned loser client. (Harmless in a shipped
    // build where Pkarr is stateless, but required for in-memory-seam test
    // determinism where the resolver and publisher MUST share one store.)
    let dht_client = if let Some(client) = crate::runtime::shared_dht_client() {
        Arc::clone(client)
    } else {
        let candidate = Arc::new(build_ffi_dht_client()?);
        crate::runtime::init_shared_dht_client(Arc::clone(&candidate));
        // Re-read: the winner's client is authoritative (may not be `candidate`).
        crate::runtime::shared_dht_client()
            .map(Arc::clone)
            .unwrap_or(candidate)
    };

    // Bind the resolver over the CANONICAL per-instance cache (set-if-unset then
    // re-read). Retaining the SAME cache `Arc` the resolver reads from lets
    // post-rotation re-publishes drop the stale cached document (see
    // `invalidate_resolver_cache`) — without it a rotated identity keeps
    // resolving to its pre-rotation document (and pre-rotation `#active` key) for
    // the multi-day resolver-cache TTL, defeating rotation's revocation purpose.
    // The set-then-re-read closes the same concurrent-first-init race as the
    // client above: a losing thread must not leave the stored resolver wrapping
    // one cache while `resolver_cache()` (what invalidation targets) returns
    // another. Every resolver ends up over the cache the instance retains.
    let candidate_cache = Arc::new(DidCache::new());
    bi.core.set_resolver_cache(Arc::clone(&candidate_cache));
    let cache = bi
        .core
        .resolver_cache()
        .map(Arc::clone)
        .unwrap_or(candidate_cache);

    // The relay layer is this instance's `TransportRelayQuerier` behind the
    // production `RealMultiRelayQuerier` composer, and the same object supplies
    // the bootstrap relay URLs — so the resolver queries exactly the relays
    // `transport_connect` has bound, including relays bound after this call
    // (§3.10.4 step 3a, §18.5.1 priority 1).
    let resolver =
        scp_ffi_common::build_production_did_resolver(bi.core.relay_querier(), dht_client, cache);

    crate::runtime::init_did_resolver(bi, resolver, handle);
    Ok(())
}

/// Drops the resolver's cached document for `did` after a higher-sequence
/// re-publish (key rotation, agent-key add/rotate/remove, migration).
///
/// The per-instance `DualLayerResolver` caches resolved documents with a
/// multi-day TTL and short-circuits on a cached hit without re-querying the
/// DHT. Without this invalidation a freshly rotated identity keeps resolving to
/// its pre-rotation document — and pre-rotation `#active` key — until the TTL
/// expires, defeating rotation's revocation purpose. The rotation re-publish
/// (higher BEP44 `seq`) has already landed in the shared DHT client; this drops
/// the resolver's stale copy so the next resolve reads the fresh document.
/// Best-effort: a no-op when no resolver cache is wired on this instance.
///
/// Delegates to the shared [`BridgeInstanceCore::invalidate_resolver_cache`]
/// (the single implementation of the invalidation body, shared across bridges).
///
/// Only reached from the `testing`-gated rotation / migration methods
/// (production create fails closed, so no identity exists to rotate — ADR-062
/// §Decision 6).
#[cfg(feature = "testing")]
async fn invalidate_resolver_cache(bi: &crate::runtime::NapiBridgeInstance, did: &str) {
    bi.core.invalidate_resolver_cache(did).await;
}

// Phase D (#1695): `ensure_did_resolver_initialized` default-bridge wrapper
// deleted. All callers pass `&NapiBridgeInstance` and invoke
// `ensure_did_resolver_initialized_on(bi)` directly.

/// Publishes a newly created DID document to the shared [`FfiDhtClient`].
///
/// After `identity_create`, the DID document must be discoverable by the
/// `DualLayerResolver` (used by UCAN validation). The minting `DidDht` used by
/// `create` carries no `sign_fn` and does not publish, so we explicitly publish
/// the freshly signed document into the process-shared client the resolver
/// reads from.
///
/// Constructs a BEP44 signed mutable item (public key, signature, document
/// JSON, sequence number 1) and calls `DhtClient::publish`. Best-effort:
/// errors are logged but do not fail identity creation.
///
/// See issue #1144.
///
/// Only reached from the `testing`-gated identity-create paths (production
/// create fails closed before publishing — ADR-062 §Decision 6).
#[cfg(feature = "testing")]
pub(crate) async fn publish_to_shared_dht_for(
    identity: &ScpIdentity,
    document: &DidDocument,
    custody: &crate::custody::NapiKeyCustody,
) {
    use scp_platform::traits::KeyCustody as _;
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
    let signable = scp_dht::bep44_signable(value, seq);
    let sig_bytes = match custody.sign(&identity.identity_key, &signable).await {
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
#[cfg(feature = "testing")]
pub(crate) struct OpaqueInMemoryKeyCustody(pub(crate) InMemoryKeyCustody);

#[cfg(feature = "testing")]
impl fmt::Debug for OpaqueInMemoryKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryKeyCustody([redacted])")
    }
}

/// Creates a `DidDht` instance with a signing function derived from a
/// [`NapiKeyCustody`](crate::custody::NapiKeyCustody), over the **process-shared**
/// DHT client.
///
/// A `DidDht` with `sign_fn: None` cannot publish (used by `add_agent_key`,
/// `rotate_agent_key`, `remove_agent_key`, `rotate_active_key`), so this helper
/// constructs a properly configured instance with the signing function wired to
/// the custody's key material — dispatching through the enum so it works for both
/// in-memory and callback custody.
///
/// The DHT client is the process-wide [`SHARED_DHT_CLIENT`](crate::runtime) the
/// resolver reads from — NOT a fresh per-call client — so the re-published
/// (higher-`seq`) document lands where DID resolution will see it and the retired
/// key is rejected on the next resolve. Fails closed if the shared client is
/// somehow absent (a fresh client would let the re-published document land
/// somewhere the resolver never reads, silently defeating rotation's revocation
/// purpose; and, in a shipped build, the in-memory arm does not even exist).
// Only reached from the `testing`-gated rotation / migration methods
// (production create fails closed, so no identity exists to rotate — ADR-062
// §Decision 6).
#[cfg(feature = "testing")]
#[allow(clippy::type_complexity)]
fn make_dht_with_signer(
    custody: &Arc<crate::custody::NapiKeyCustody>,
) -> Result<DidDht<FfiDhtClient, scp_clock::SystemClock>, ScpNapiError> {
    use scp_platform::traits::KeyCustody as _;
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
            let sig = kc
                .sign(&handle, &data)
                .await
                .map_err(IdentityError::Platform)?;
            Ok(sig.into_bytes())
        })
    });
    let dht_client = crate::runtime::shared_dht_client()
        .map(Arc::clone)
        .ok_or_else(|| ScpNapiError::Identity {
            message: "DID resolver DHT client is not initialized on this process — \
                      create an identity (identityCreate) before publishing document updates"
                .to_owned(),
            code: codes::IDENT_1001.to_owned(),
        })?;
    Ok(DidDht::with_client_and_signer(
        dht_client,
        Arc::new(DidCache::new()),
        sign_fn,
    ))
}

// ---------------------------------------------------------------------------
// NapiIdentityInner — inner state held behind the napi object
// ---------------------------------------------------------------------------

/// Inner state for a [`NapiIdentity`] handle.
pub(crate) struct NapiIdentityInner {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    pub(crate) did: String,
    /// The custody type string: `"in_memory"`, `"callback"`, or `"external"`.
    pub(crate) custody_type: String,
    /// Retained `ScpIdentity` for in-memory custody paths.
    ///
    /// Holds the `KeyHandle`s into `in_memory_custody`. Must outlive any
    /// signing or key-rotation operation on this handle.
    pub(crate) scp_identity: Option<ScpIdentity>,
    /// Retained custody backing this handle's key material.
    ///
    /// Shares the same `Arc<NapiKeyCustody>` as the identity registry entry
    /// so handle-based crypto (event-log checkpoints, SCPID signing) and
    /// registry-based crypto operate on identical key material. Enum-dispatched
    /// so it backs either an in-memory test key or a callback custody. Dropping
    /// the last `Arc` destroys all in-memory private keys. `None` for
    /// externally loaded identities (DID-string-only handles).
    ///
    /// Available in production (not feature-gated): in the production
    /// callback-custody path this holds the `Arc<NapiKeyCustody::Callback>`
    /// so handle-based signing reaches the caller's custody. The field name
    /// is historical — it backs any retained custody, not just in-memory.
    pub(crate) in_memory_custody: Option<Arc<crate::custody::NapiKeyCustody>>,
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
    ///
    /// On a shipped (no-`testing`) build every mutable identity method fails
    /// closed before reading this field (production create can never mint an
    /// identity — ADR-062 §Decision 6), so it is written at construction but
    /// never read; the field stays (`identity_load` still populates it) with a
    /// scoped dead-code allowance.
    #[cfg_attr(not(feature = "testing"), allow(dead_code))]
    pub(crate) bi: Arc<crate::runtime::NapiBridgeInstance>,
    /// Hex-encoded Ed25519 verifying-key bytes for the identity key
    /// (VM `#0`, the key that derives the DID). 64 hex chars = 32 raw
    /// bytes. Populated for identities created via `Scp::identity_create`;
    /// `None` for externally loaded identities.
    ///
    /// Uses `identity_key` (not `#active`): exposing the DID-deriving
    /// identity key gives byte-exact cross-bridge parity under a
    /// deterministic `seed` (ADR-046).
    pub(crate) verifying_key_hex: Option<String>,
    /// `NapiBridgeInstance` id that minted this handle — used for runtime
    /// handle-affinity checks at every FFI entry point that accepts a
    /// `NapiIdentity`. Mismatches are rejected with `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
    /// JSON-serialized `scp_did::DidRotationEvent` produced when
    /// this handle was minted by [`NapiIdentity::migrate`]. SDK callers
    /// MUST distribute the event to active context members per spec
    /// §9.12, ADR-003 §4b. `None` for handles produced by `identity_create`,
    /// `rotate_key`, agent-key ops, or external load — those operations
    /// do not change the DID, so no `DidRotationEvent` is constructed.
    pub(crate) rotation_event_json: Option<String>,
}

// ---------------------------------------------------------------------------
// NapiIdentity — opaque JS class for SCP identity
// ---------------------------------------------------------------------------

/// An SCP identity handle exposed to JavaScript (Node.js/Bun).
///
/// Wraps the DID string and retains key material for the in-memory (dev/test)
/// custody path. The production custody path is `identityCreateWithCustody`,
/// which injects a caller-supplied `KeyCustodyProvider` (keychain/HSM-backed).
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
    /// One of: `"in_memory"`, `"callback"`, `"external"`.
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
        // FAIL CLOSED on a shipped (no-`testing`) build: no identity can exist
        // (every production create path fails closed before building a registry
        // entry — ADR-062 §Decision 6), so key rotation is unreachable. The
        // `NapiIdentityEntry.pre_rotation_custody` field this method reads and
        // rebuilds exists only under `testing`, so the original body must be
        // `testing`-gated to compile. Mirror the create-path fail-closed shape.
        #[cfg(not(feature = "testing"))]
        {
            Err::<Self, NapiError>(NapiError::from(no_pre_rotation_backend()))
        }
        #[cfg(feature = "testing")]
        {
            let (scp_identity, custody, document) = self.extract_in_memory_state("rotateKey")?;

            let bi = &self.inner.bi;

            // Read attestations + pre-rotation state BEFORE async operation
            // (entry guaranteed to exist). `rotate_active_key` does not touch
            // the pre-rotation key, so we reuse the existing handle/custody.
            let (existing_attestations, pre_rotation_handle, pre_rotation_custody) =
                crate::runtime::with_identity(bi, &self.inner.did, |e| {
                    Ok((
                        e.identity_link_attestations.clone(),
                        e.pre_rotation_handle,
                        Arc::clone(&e.pre_rotation_custody),
                    ))
                })
                .map_err(|e| {
                    // Fail-fast rather than fabricate a synthetic
                    // `(handle = 0, fresh empty custody)` pair: a fresh
                    // empty custody would silently overwrite the
                    // registered pre-rotation state, leaving the
                    // identity un-migratable. Surface the real error
                    // so the caller can recover.
                    NapiError::from(e)
                })?;

            let dht = make_dht_with_signer(&custody)?;
            // Bootstrap the BEP44 sequence past the shared DHT's current record so
            // the rotated document strictly overwrites it — a lower-or-equal seq is
            // a silent no-op (BEP44 monotonicity). Mirrors the PyO3 bridge.
            dht.initialize_sequence(&scp_identity.did)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
            let (new_identity, new_document) = dht
                .rotate_active_key(&scp_identity, &document, &*custody)
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
                    pre_rotation_handle,
                    pre_rotation_custody,
                },
            );

            // The rotated document was re-published at a higher BEP44 `seq` into the
            // shared DHT client; drop the resolver's now-stale cached copy so the
            // next resolve serves the rotated `#active` key and rejects the retired
            // one (AC[6]).
            invalidate_resolver_cache(bi, &new_identity.did).await;

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
        // FAIL CLOSED on a shipped build: no identity can exist, so agent-key
        // add is unreachable; the `testing`-gated `pre_rotation_custody` field
        // rebuilt below forces the original body under `testing`
        // (ADR-062 §Decision 6).
        #[cfg(not(feature = "testing"))]
        {
            Err::<Self, NapiError>(NapiError::from(no_pre_rotation_backend()))
        }
        #[cfg(feature = "testing")]
        {
            let (scp_identity, custody, document) = self.extract_in_memory_state("addAgentKey")?;

            let bi = &self.inner.bi;

            // Read attestations + pre-rotation state BEFORE async operation.
            // `add_agent_key` does not touch the pre-rotation key.
            let (existing_attestations, pre_rotation_handle, pre_rotation_custody) =
                crate::runtime::with_identity(bi, &self.inner.did, |e| {
                    Ok((
                        e.identity_link_attestations.clone(),
                        e.pre_rotation_handle,
                        Arc::clone(&e.pre_rotation_custody),
                    ))
                })
                .map_err(|e| {
                    // Fail-fast rather than fabricate a synthetic
                    // `(handle = 0, fresh empty custody)` pair: a fresh
                    // empty custody would silently overwrite the
                    // registered pre-rotation state, leaving the
                    // identity un-migratable. Surface the real error
                    // so the caller can recover.
                    NapiError::from(e)
                })?;

            let dht = make_dht_with_signer(&custody)?;
            // Bootstrap the BEP44 sequence past the shared DHT's current record so
            // the agent-key-bearing document strictly overwrites it (see rotate_key).
            dht.initialize_sequence(&scp_identity.did)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
            let (new_identity, new_document) = dht
                .add_agent_key(&scp_identity, &document, &*custody)
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
                    pre_rotation_handle,
                    pre_rotation_custody,
                },
            );

            // The agent-key-bearing document was re-published at a higher BEP44
            // `seq` into the shared DHT client; drop the resolver's stale cached
            // copy so the next resolve serves the new agent key (AC[6]).
            invalidate_resolver_cache(bi, &new_identity.did).await;

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
        // FAIL CLOSED on a shipped build: no identity can exist, so agent-key
        // rotation is unreachable; the `testing`-gated `pre_rotation_custody`
        // field rebuilt below forces the original body under `testing`
        // (ADR-062 §Decision 6).
        #[cfg(not(feature = "testing"))]
        {
            Err::<Self, NapiError>(NapiError::from(no_pre_rotation_backend()))
        }
        #[cfg(feature = "testing")]
        {
            let (scp_identity, custody, document) =
                self.extract_in_memory_state("rotateAgentKey")?;

            let bi = &self.inner.bi;

            // Read attestations + pre-rotation state BEFORE async operation.
            // `rotate_agent_key` does not touch the pre-rotation key.
            let (existing_attestations, pre_rotation_handle, pre_rotation_custody) =
                crate::runtime::with_identity(bi, &self.inner.did, |e| {
                    Ok((
                        e.identity_link_attestations.clone(),
                        e.pre_rotation_handle,
                        Arc::clone(&e.pre_rotation_custody),
                    ))
                })
                .map_err(|e| {
                    // Fail-fast rather than fabricate a synthetic
                    // `(handle = 0, fresh empty custody)` pair: a fresh
                    // empty custody would silently overwrite the
                    // registered pre-rotation state, leaving the
                    // identity un-migratable. Surface the real error
                    // so the caller can recover.
                    NapiError::from(e)
                })?;

            let dht = make_dht_with_signer(&custody)?;
            // Bootstrap the BEP44 sequence past the shared DHT's current record so
            // the rotated-agent-key document strictly overwrites it (see rotate_key).
            dht.initialize_sequence(&scp_identity.did)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
            let (new_identity, new_document) = dht
                .rotate_agent_key(&scp_identity, &document, &*custody)
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
                    pre_rotation_handle,
                    pre_rotation_custody,
                },
            );

            // The rotated-agent-key document was re-published at a higher BEP44
            // `seq` into the shared DHT client; drop the resolver's stale cached
            // copy so the next resolve rejects the retired agent key (AC[6]).
            invalidate_resolver_cache(bi, &new_identity.did).await;

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
        // FAIL CLOSED on a shipped build: no identity can exist, so agent-key
        // removal is unreachable; the `testing`-gated `pre_rotation_custody`
        // field rebuilt below forces the original body under `testing`
        // (ADR-062 §Decision 6).
        #[cfg(not(feature = "testing"))]
        {
            Err::<Self, NapiError>(NapiError::from(no_pre_rotation_backend()))
        }
        #[cfg(feature = "testing")]
        {
            let (scp_identity, custody, document) =
                self.extract_in_memory_state("removeAgentKey")?;

            let bi = &self.inner.bi;

            // Read attestations + pre-rotation state BEFORE async operation.
            // `remove_agent_key` does not touch the pre-rotation key.
            let (existing_attestations, pre_rotation_handle, pre_rotation_custody) =
                crate::runtime::with_identity(bi, &self.inner.did, |e| {
                    Ok((
                        e.identity_link_attestations.clone(),
                        e.pre_rotation_handle,
                        Arc::clone(&e.pre_rotation_custody),
                    ))
                })
                .map_err(|e| {
                    // Fail-fast rather than fabricate a synthetic
                    // `(handle = 0, fresh empty custody)` pair: a fresh
                    // empty custody would silently overwrite the
                    // registered pre-rotation state, leaving the
                    // identity un-migratable. Surface the real error
                    // so the caller can recover.
                    NapiError::from(e)
                })?;

            let dht = make_dht_with_signer(&custody)?;
            // Bootstrap the BEP44 sequence past the shared DHT's current record so
            // the agent-key-removed document strictly overwrites it (see rotate_key).
            dht.initialize_sequence(&scp_identity.did)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
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
                    pre_rotation_handle,
                    pre_rotation_custody,
                },
            );

            // The agent-key-removed document was re-published at a higher BEP44
            // `seq` into the shared DHT client; drop the resolver's stale cached
            // copy so the next resolve stops serving the removed agent key (AC[6]).
            invalidate_resolver_cache(bi, &new_identity.did).await;

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
    /// (spec §9.12, ADR-003 §4b/4c). The SDK distributes the event to
    /// active context members per spec §9.12, ADR-003 §4b. Wire shape is
    /// `serde_json::to_string(&scp_did::DidRotationEvent)`.
    #[napi]
    #[allow(clippy::unused_async)] // napi requires async for Promise return type
    pub async fn migrate(&self) -> napi::Result<Self> {
        // FAIL CLOSED on a shipped build: no identity can exist, so DID
        // migration is unreachable. Migration reveals the committed pre-rotation
        // key from the `testing`-gated `pre_rotation_custody`, so the original
        // body must be `testing`-gated to compile (ADR-062 §Decision 6). Mirrors
        // the `PyO3` reference bridge's `identity_migrate` fail-closed arm.
        #[cfg(not(feature = "testing"))]
        {
            Err::<Self, NapiError>(NapiError::from(no_pre_rotation_backend()))
        }
        #[cfg(feature = "testing")]
        {
            let (scp_identity, custody, document) = self.extract_in_memory_state("migrate")?;

            let bi = &self.inner.bi;

            // Read attestations + pre-rotation state BEFORE async operation
            // (entry guaranteed to exist now).
            let (existing_attestations, pre_rotation_handle, pre_rotation_custody) =
                crate::runtime::with_identity(bi, &self.inner.did, |e| {
                    Ok((
                        e.identity_link_attestations.clone(),
                        e.pre_rotation_handle,
                        Arc::clone(&e.pre_rotation_custody),
                    ))
                })
                .map_err(NapiError::from)?;

            // Spec §3.7 / §9.12 (Compromise Recovery Protocol): the
            // pre-rotation key whose hash equals the published
            // `pre_rotation_commitment` is the only key that satisfies the
            // `SHA-256(revealed_key) == commitment` invariant verified by
            // `verify_migration`. The committed pre-rotation key is held in
            // cold-storage `pre_rotation_custody`, referenced by
            // `pre_rotation_handle`.
            let rotated_at = scp_clock::SystemClock.now_secs();

            let dht = make_dht_with_signer(&custody)?;
            // Bootstrap the BEP44 sequence from the OLD DID's current record so the
            // migration republish (old-DID `alsoKnownAs` update + new-DID document)
            // strictly overwrites the pre-migration record (see rotate_key).
            dht.initialize_sequence(&scp_identity.did)
                .await
                .map_err(|e| NapiError::from(ScpNapiError::from(e)))?;
            let scp_identity::MigrationOutcome {
                new_identity,
                new_document,
                rotation_event,
                new_pre_rotation_handle,
            } = dht
                .migrate_identity(
                    &scp_identity,
                    &document,
                    &pre_rotation_handle,
                    pre_rotation_custody.as_ref(),
                    &*custody,
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

            // Remove the old identity and register the new one. The same
            // pre-rotation custody Arc is reused (we don't mint a new
            // custody per migration); only the handle changes to point at
            // the freshly committed key.
            crate::runtime::remove_identity(bi, &self.inner.did);
            crate::runtime::register_identity(
                bi,
                &new_did,
                crate::runtime::NapiIdentityEntry {
                    identity: new_identity.clone(),
                    custody: Arc::clone(&custody),
                    document: new_document.clone(),
                    identity_link_attestations: existing_attestations,
                    pre_rotation_handle: new_pre_rotation_handle,
                    pre_rotation_custody,
                },
            );

            // Migration re-published BOTH documents at higher BEP44 sequences into
            // the shared DHT client: the new DID's document and the old DID's
            // `alsoKnownAs` update. Drop both stale cache entries so resolution
            // follows the migration forward instead of serving pre-migration docs
            // (AC[6]).
            invalidate_resolver_cache(bi, &self.inner.did).await;
            invalidate_resolver_cache(bi, &new_did).await;

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
    /// distributes the event to active context members per spec §9.12,
    /// ADR-003 §4b.
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
/// Callers pass `identity.identity_key` (not `active_signing_key`):
/// byte-exact cross-bridge parity requires every bridge to expose the
/// DID-deriving identity key.
pub(crate) async fn identity_verifying_key_hex(
    custody: &Arc<crate::custody::NapiKeyCustody>,
    handle: &scp_platform::traits::KeyHandle,
) -> Option<String> {
    use scp_platform::traits::KeyCustody as _;
    custody
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

    /// Returns the retained custody if this identity has live key material.
    /// Used by context creation for routing ID derivation (SCP-214).
    #[allow(dead_code)]
    pub(crate) fn in_memory_custody(&self) -> Option<&crate::custody::NapiKeyCustody> {
        self.inner.in_memory_custody.as_deref()
    }

    /// Returns the retained `ScpIdentity` if available. Used by context creation
    /// for routing ID derivation (SCP-214).
    #[allow(dead_code)]
    pub(crate) fn scp_identity(&self) -> Option<&ScpIdentity> {
        self.inner.scp_identity.as_ref()
    }

    /// Extracts the retained crypto state required for agent key operations.
    ///
    /// Returns the `ScpIdentity`, custody (via `Arc<NapiKeyCustody>`), and
    /// `DidDocument` if this identity has retained crypto state. Returns an
    /// error for externally loaded identities that have none. The custody is
    /// enum-dispatched so the agent-key paths work for both in-memory and
    /// callback-backed identities.
    ///
    /// Only reached from the `testing`-gated rotation / migration methods
    /// (production create fails closed, so no identity has retained state —
    /// ADR-062 §Decision 6).
    #[cfg(feature = "testing")]
    fn extract_in_memory_state(
        &self,
        operation: &str,
    ) -> napi::Result<(
        ScpIdentity,
        Arc<crate::custody::NapiKeyCustody>,
        DidDocument,
    )> {
        let scp_identity = self
            .inner
            .scp_identity
            .as_ref()
            .ok_or_else(|| {
                NapiError::from(ScpNapiError::Identity {
                    message: format!(
                        "{operation} requires retained crypto state — this identity was \
                         externally loaded and has no retained key material"
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
                        "{operation} requires retained key custody — this identity was \
                         loaded without retained custody"
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
//
// PR-E #28 (ADR-048 §1): `identity_verify_link_attestation` is restored
// as a module-level free fn. The operation is pure Ed25519 signature
// verification — no bridge-instance state is required — so the per-
// instance method on `Scp` was Gaming-the-Gate fraud (`let _ = &self.inner;`
// to satisfy the pure-helpers scanner). The TypeScript SDK's
// `SCP.identityVerifyLinkAttestation` routes through the addon's module-
// level export per ADR-048 §7 (TS keeps the method shape as a TS-local
// ergonomic choice; the body routes via `nativeFreeFn`).

/// Verifies an identity link attestation signature using a provided issuer
/// public key.
///
/// Pure Ed25519 signature verification — touches no bridge-instance state
/// and is exposed at module scope per ADR-048 §1.
///
/// # Errors
///
/// Returns `SCP-IDENT-1044` on JSON parse failure or invalid hex.
#[napi(js_name = "identityVerifyLinkAttestation")]
pub fn identity_verify_link_attestation(
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "testing")]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    /// Creates a test `NapiIdentity` with in-memory custody, returning the
    /// identity (stamped with a dedicated `NapiBridgeInstance`) and its
    /// initial active signing key's public key (multibase).
    async fn create_test_identity() -> (NapiIdentity, String) {
        let key_custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
            OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
        ));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());

        // Mirror the real `Scp::identity_create` flow (scp.rs): initialize the
        // process-shared DHT client on this bridge instance BEFORE minting,
        // through the exact `ensure_did_resolver_initialized_on` testing seam
        // production `identityCreate` uses (which sets `SHARED_DHT_CLIENT` from
        // the `#[cfg(testing)]` in-memory `build_ffi_dht_client`). Without this
        // initialization, `SHARED_DHT_CLIENT` is never set and any later
        // `migrate()` / `rotate_key()` fails closed with `[SCP-IDENT-1001] DID
        // resolver DHT client is not initialized on this process`, because
        // `make_dht_with_signer` reads that global and never substitutes an
        // in-memory fallback (ADR-062 §Decision 1). `create_test_identity`
        // simulates `identityCreate`, so it must reproduce that ordering rather
        // than bypass the fail-closed guard.
        let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        ensure_did_resolver_initialized_on(&bi)
            .expect("shared DHT client init (testing in-memory seam) must succeed");

        // Mint over the process-shared client — exactly as `identity_create`
        // does — rather than a fresh throwaway client, so the created document
        // is published where `migrate()`'s BEP44 sequence bootstrap reads it.
        let dht = shared_did_method().expect("shared DID method must build");
        let (scp_identity, document, pre_rotation_handle) = dht
            .create(&*key_custody, pre_rotation_custody.as_ref())
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
                pre_rotation_handle,
                pre_rotation_custody: Arc::clone(&pre_rotation_custody),
            },
        );

        // Seed the shared DHT with the freshly minted document, mirroring
        // `identity_create`, so `migrate()`'s `initialize_sequence` reads a
        // real pre-migration record for the old DID.
        publish_to_shared_dht_for(&scp_identity, &document, &key_custody).await;
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

    /// AC[6]: `rotate_key` drops the resolver's cached pre-rotation document so
    /// the next resolution serves the rotated `#active` key, not the stale one.
    ///
    /// The `DualLayerResolver` short-circuits on a cached hit within TTL without
    /// re-querying the DHT. `rotate_key` re-publishes the rotated document (a
    /// higher BEP44 `seq`) into the shared DHT client AND calls
    /// `invalidate_resolver_cache` on the SAME cache the resolver reads from
    /// (retained per-instance by `ensure_did_resolver_initialized_on`). This
    /// test seeds that cache with the pre-rotation document (modelling a prior
    /// resolution), runs the real bridge rotation op, and asserts the cached
    /// entry is gone — so a subsequent resolve re-queries the DHT and serves the
    /// new key. Without the invalidation the resolver would keep serving the
    /// pre-rotation document (and its retired `#active` key) for the multi-day
    /// cache TTL, silently defeating rotation's revocation purpose.
    #[test]
    fn rotate_key_invalidates_resolver_cache() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let (identity, _) = rt.block_on(create_test_identity());
        let did = identity.did();
        let bi = Arc::clone(&identity.inner.bi);

        // Model a prior resolution that cached the pre-rotation document in the
        // SAME cache the resolver reads from.
        let cache = bi
            .core
            .resolver_cache()
            .expect("resolver init must retain the resolver cache")
            .clone();
        let pre_doc = identity
            .inner
            .document
            .clone()
            .expect("created identity retains its DID document");
        rt.block_on(cache.insert(&did, pre_doc, 1));
        assert!(
            rt.block_on(cache.get(&did)).is_some(),
            "pre-condition: the pre-rotation document is cached"
        );

        // The real bridge rotation op re-publishes at a higher seq into the
        // shared client and MUST invalidate the resolver's cached copy (AC[6]).
        rt.block_on(identity.rotate_key())
            .expect("rotate_key must succeed");

        assert!(
            rt.block_on(cache.get(&did)).is_none(),
            "rotate_key must drop the stale cached document so the next resolve \
             serves the rotated #active key (AC[6])"
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
        // DidRotationEvent shape (spec §9.12, ADR-003 §4b/4c).
        let event_json = migrated
            .rotation_event_json()
            .expect("migrated handle must surface rotationEventJson");
        let event: scp_did::DidRotationEvent = serde_json::from_str(&event_json)
            .expect("rotation_event_json must deserialize as DidRotationEvent");
        assert_eq!(event.old_did, original_did);
        assert_eq!(event.new_did, migrated.did());
        // Pre-rotation proof must satisfy the cryptographic invariant
        // `SHA-256(revealed_key) == commitment` — the same check
        // recipients run via `verify_migration` (spec §9.12 / ADR-003 §4c).
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
        // `create_test_identity` already registered the entry — read its
        // pre-rotation state so we can re-register without losing the
        // committed handle that `migrate()` will consume.
        let (pre_rotation_handle, pre_rotation_custody) =
            crate::runtime::with_identity(&bi, &old_did, |e| {
                Ok((e.pre_rotation_handle, Arc::clone(&e.pre_rotation_custody)))
            })
            .expect("create_test_identity must have registered the entry");
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
                pre_rotation_handle,
                pre_rotation_custody,
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

    /// Fail-closed guard (ADR-062 §Decision 1 / spec §17.17.3): `migrate()`
    /// must surface the honest `[SCP-IDENT-1001]` error — never silently mint
    /// over an in-memory nullifier — when the process-shared DHT client was
    /// never initialized (i.e. no prior `identityCreate` on this process).
    ///
    /// `SHARED_DHT_CLIENT` is a process-global `OnceLock`; a co-resident test
    /// in this binary may already have set it, in which case the fail-closed
    /// branch is unreachable here and `migrate()` legitimately succeeds. So we
    /// assert the invariant *both ways*: success is permitted only when the
    /// shared client is present, and any error must be exactly the fail-closed
    /// `SCP-IDENT-1001`. Under nextest's process-per-test isolation (CI) the
    /// client is guaranteed absent, so the negative branch is exercised
    /// deterministically. This construction never sets the global, and mints
    /// with an in-memory test double only under `#[cfg(test)]`.
    #[test]
    fn migrate_fails_closed_when_shared_dht_client_uninitialized() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

        // Mint an identity with full retained crypto state but WITHOUT calling
        // `ensure_did_resolver_initialized_on` — deliberately skipping the
        // `SHARED_DHT_CLIENT` initialization that real `identityCreate` does,
        // to simulate a caller that reached `migrate()` before any create.
        let identity = rt.block_on(async {
            let key_custody = Arc::new(crate::custody::NapiKeyCustody::InMemory(
                OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()),
            ));
            let pre_rotation_custody =
                Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
            let dht = DidDht::with_client(Arc::new(InMemoryDhtClient::new()));
            let (scp_identity, document, pre_rotation_handle) = dht
                .create(&*key_custody, pre_rotation_custody.as_ref())
                .await
                .expect("identity creation must succeed");

            let bi = Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
            crate::runtime::register_identity(
                &bi,
                &scp_identity.did,
                crate::runtime::NapiIdentityEntry {
                    identity: scp_identity.clone(),
                    custody: Arc::clone(&key_custody),
                    document: document.clone(),
                    identity_link_attestations: Vec::new(),
                    pre_rotation_handle,
                    pre_rotation_custody,
                },
            );
            let instance_id = bi.instance_id();
            let handle = NapiIdentity {
                inner: Arc::new(NapiIdentityInner {
                    did: scp_identity.did.clone(),
                    custody_type: "in_memory".to_owned(),
                    scp_identity: Some(scp_identity),
                    in_memory_custody: Some(key_custody),
                    document: Some(document),
                    bi,
                    verifying_key_hex: None,
                    instance_id,
                    rotation_event_json: None,
                }),
            };
            increment_handle_count();
            handle
        });

        match rt.block_on(identity.migrate()) {
            Ok(_) => assert!(
                crate::runtime::shared_dht_client().is_some(),
                "migrate() succeeded, so the process-shared DHT client MUST have \
                 been initialized — it must never mint over an absent client"
            ),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains(codes::IDENT_1001),
                    "migrate() with an uninitialized shared DHT client must fail \
                     closed with SCP-IDENT-1001, got: {msg}"
                );
            }
        }
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

// ---------------------------------------------------------------------------
// Shipped-build (no-`testing`) fail-closed proof — ADR-062 §Decision 6 /
// SCP-CAPINJECT-006 (AC5). Runs in the napi PRODUCTION test lane
// (`cargo test -p scp-ffi-napi --features server`, CI's "napi tests in
// production config" step), where this bridge's own `identity_create`
// pre-rotation arm selects the fail-closed path. The whole module above is
// `#[cfg(feature = "testing")]`; this one is `#[cfg(not(feature = "testing"))]`
// so it exists ONLY in the shipped config.
// ---------------------------------------------------------------------------
#[cfg(test)]
#[cfg(not(feature = "testing"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod prod_fail_closed_tests {
    use crate::scp::Scp;

    /// AC5 (napi `identity_create` string-custody surface): on a shipped build the
    /// `identity_create(kind)` string entry point mints no identity — every custody
    /// kind fails closed *before* any DID creation, so the pre-rotation nullifier is
    /// unreachable via this surface. Unlike `PyO3` (which exposes a `"file"` custody
    /// kind that reaches the shared `scp-identity::config::create_inner` lowering and
    /// returns `SCP-IDENT-1059`), napi's real production key custody is the callback
    /// `KeyCustodyProvider` (keychain/HSM) reached only via `identity_create_with_custody`,
    /// not the string API. The string kinds fail closed earlier: `in_memory` is severed
    /// (`SCP-IDENT-1008`) and `software`/`platform` require the callback provider
    /// (`SCP-IDENT-1003`). This test pins that string-surface fail-closed on `"software"`.
    ///
    /// The *callback* path's own pre-rotation fail-closed (`SCP-IDENT-1059`) is NOT
    /// exercised here — it takes a napi `Env` + JS `Function`s that cannot be
    /// constructed in a Rust `#[test]`. That arm is guaranteed by construction, not by
    /// this test: `identity_create_with_custody`'s shipped branch is an unconditional
    /// `#[cfg(not(feature = "testing"))]` early return of `no_pre_rotation_backend()`
    /// (`crate::identity::no_pre_rotation_backend`, `IDENT_1059`) — the mint arm is
    /// `#[cfg(feature = "testing")]`, and the G1 shipped-feature-graph gate
    /// (`check-shipped-feature-graph.sh`) mechanically proves `InMemoryPreRotationCustody`
    /// is absent from the shipped graph. The shared `create_inner` lowering that the
    /// `PyO3` bridge reaches is separately proven fail-closed by scp-identity's
    /// `config::tests::ephemeral_create_fails_closed_without_pre_rotation_backend` and
    /// the `PyO3` `"file"`-custody test.
    ///
    /// `identity_create` is `async`; the crate tokio runtime drives it, mirroring the
    /// napi-rs worker's `block_on`.
    #[test]
    fn identity_create_fails_closed_without_pre_rotation_backend() {
        let scp = Scp::new_in_memory_for_test();
        // `software` is a real production custody kind; on a shipped build it
        // fails closed (it requires the callback `KeyCustodyProvider`) rather than
        // minting an identity — so no nullifier-backed identity is ever produced.
        let result = crate::runtime().block_on(scp.identity_create("software".to_owned(), None));
        let msg = match result {
            Ok(_) => panic!(
                "shipped identity_create must FAIL CLOSED — no identity may be minted \
                 on a production path without a real custody + pre-rotation backend"
            ),
            Err(err) => err.to_string(),
        };
        assert!(
            msg.contains(scp_ffi_common::error_codes::IDENT_1003),
            "shipped `software` identity_create must fail closed (SCP-IDENT-1003, \
             requires callback custody), got: {msg}"
        );
    }
}
