//! `PyO3` bridge for identity operations.
//!
//! Exposes [`PyIdentity`] and [`PyDIDDocument`] as opaque Python objects with
//! attribute access, plus identity lifecycle methods on the `SCP` class:
//!
//! - `PyScp::identity_create` — creates a new DID identity.
//! - `PyScp::identity_create_with_agent_key` — creates a new DID identity
//!   with an agent signing key.
//! - `PyScp::identity_load` — loads an existing identity from storage.
//! - `PyScp::identity_resolve` — resolves a DID to its document.
//! - `PyScp::identity_rotate_key` — rotates the identity's active signing
//!   key.
//! - `PyScp::identity_add_agent_key` — adds an agent signing key to an
//!   identity.
//! - `PyScp::identity_rotate_agent_key` — rotates the agent signing key.
//! - `PyScp::identity_remove_agent_key` — removes the agent signing key.
//! - `PyScp::identity_migrate` — migrates an identity to a new DID.
//!
//! Plus device-attestation and identity-link-attestation methods. All free
//! `#[pyfunction]` exports were migrated to `#[pymethods] impl PyScp` methods
//! in Phase 4 PR 4 sub-slice C (#1549).
//!
//! All async operations run on the shared tokio runtime via
//! `crate::runtime()`. The GIL is released during Rust async execution
//! via `py.allow_threads()` so Python threads are not blocked.
//!
//! # Opaque types
//!
//! [`PyIdentity`] stores the DID string and custody type — NOT the raw
//! [`ScpIdentity`], which contains
//! `KeyHandle`s that are not safe to hold across
//! Python GIL boundaries. Crypto operations reconstruct state from stored
//! metadata when the full runtime is wired.
//!
//! [`PyDIDDocument`] wraps [`DidDocument`]
//! and exposes safe getters for the document's public fields.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` and ADR-039 for the full
//! specification.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// `Clock` brings `SystemClock::now_secs` into scope for one `testing`-gated
// pre-rotation reveal arm of `py_identity_rotate_key`, this crate's only caller.
// A shipped build (no `testing`) compiles no user of that trait, so this import
// carries a matching gate, which keeps such a build warning-free.
#[cfg(feature = "testing")]
use scp_clock::Clock;
use scp_did::DidDocument;
// Production DHT construction (real fail-closed Pkarr) and the `testing`
// in-memory seam are both encapsulated in the single cfg-gated
// `scp_ffi_common::dht::build_ffi_dht_client`; this bridge only maps its error.
use scp_ffi_common::dht::FfiDhtClient;
use scp_identity::{DidCache, DidDht, DidMethod, DualLayerResolver, NoOpRelayQuerier};
// Only the testing-gated `identity_migrate` path constructs a `ScpIdentity`
// value directly (production migration is unreachable — ADR-062 §Decision 6).
#[cfg(feature = "testing")]
use scp_identity::ScpIdentity;
use scp_platform::file::FileKeyCustody;
#[cfg(feature = "testing")]
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, Storage};

use crate::custody::FfiKeyCustody;
use crate::error::ScpPyError;
// `IdentityEntry` is only constructed on the testing-gated create/migrate paths
// (production create fails closed before building an entry — ADR-062 §Decision 6).
#[cfg(feature = "testing")]
use crate::runtime::IdentityEntry;
use crate::runtime::PyBridgeInstance;
use crate::validate;

use scp_ffi_common::validate::MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID;

/// Builds the shared [`FfiDhtClient`] for this bridge instance, **failing
/// closed**.
///
/// Delegates to the single cfg-gated [`scp_ffi_common::dht::build_ffi_dht_client`]
/// (shared by all three bridges) and maps its [`DhtInitError`] to a `ScpPyError`.
/// A shipped (non-`testing`) build constructs the real Mainline Pkarr client; a
/// malformed gateway or a Mainline build failure surfaces as the dedicated
/// `IDENT_1058` DHT-init-failure code (distinct from the generic `IDENT_1001`),
/// never an in-memory or no-op substitute (ADR-062 §Decision 1 / spec §17.17.3).
/// The in-memory arm is reachable only through the common test seam under
/// `testing`.
pub(crate) fn build_ffi_dht_client() -> Result<FfiDhtClient, ScpPyError> {
    scp_ffi_common::dht::build_ffi_dht_client().map_err(|e| {
        ScpPyError::identity_with_code(
            format!("failed to initialize production DHT client for DID resolution: {e}"),
            scp_ffi_common::error_codes::IDENT_1058,
        )
    })
}

/// Fail-closed error for a production identity-creation path when no real
/// pre-rotation custody backend is available (ADR-062 §Decision 6).
///
/// Every identity commits a pre-rotation commitment at creation (spec §9.7.4.1
/// §3 — mandatory), which requires a `PreRotationCustody` backend. The only
/// implementation is the test-harness `InMemoryPreRotationCustody` nullifier, so
/// a shipped (no-`testing`) build returns this typed [`IDENT_1059`] error rather
/// than silently minting the nullifier. See #1729 / RFC #2130 for the real
/// backend; Option A (non-committing create) is #1553, out of scope.
///
/// [`IDENT_1059`]: scp_ffi_common::error_codes::IDENT_1059
#[cfg(not(feature = "testing"))]
pub(crate) fn no_pre_rotation_backend() -> ScpPyError {
    ScpPyError::identity_with_code(
        scp_identity::IdentityError::NoPreRotationBackend.to_string(),
        scp_ffi_common::error_codes::IDENT_1059,
    )
}

/// Ensures the given bridge instance's production DID resolver is initialized.
///
/// Creates a `DualLayerResolver` backed by the shared [`FfiDhtClient`] (the
/// real Mainline Pkarr client in a shipped build, or the in-memory test seam
/// under `testing`) and `NoOpRelayQuerier` (relay resolution will be upgraded
/// when a production relay querier is available). The resolver is shared across
/// all UCAN validation and attestation verification calls on the same bridge.
///
/// This is idempotent: subsequent calls are no-ops.
///
/// Fails closed: when the production DHT client cannot be built, this returns
/// the [`DhtInitError`](scp_ffi_common::dht::DhtInitError)-derived
/// [`ScpPyError`] rather than substituting a nullifier.
///
/// See #311 for the DID resolver unification design and ADR-062 §Decision 1.
fn ensure_did_resolver_initialized_on(
    bi: &PyBridgeInstance,
    handle: tokio::runtime::Handle,
) -> Result<(), ScpPyError> {
    if crate::runtime::did_resolver(bi).is_some() {
        return Ok(());
    }

    // Retain the DHT client on the instance so `identity_create` can publish
    // freshly minted DID documents into the SAME client the resolver reads
    // from. Without a shared client, freshly minted identities are never
    // resolvable and any DID-resolving verification (UCAN validation,
    // governance vote verification) fails with "unknown voter". Scoped
    // per-instance to match where the resolver itself is stored.
    let dht_client = Arc::new(build_ffi_dht_client()?);
    let relay_querier = Arc::new(NoOpRelayQuerier);
    let cache = Arc::new(DidCache::new());
    let bootstrap_relays = Vec::new();

    let resolver = Arc::new(DualLayerResolver::new(
        relay_querier,
        Arc::clone(&dht_client),
        Arc::clone(&cache),
        bootstrap_relays,
    ));

    crate::runtime::init_did_resolver(bi, resolver, handle);
    crate::runtime::set_resolver_dht_client(bi, dht_client);
    // Retain the SAME cache `Arc` the resolver was built over so post-rotation
    // re-publishes can invalidate the stale cached document (see
    // `invalidate_resolver_cache`).
    crate::runtime::set_resolver_cache(bi, cache);
    Ok(())
}

/// Builds a [`DidDht`] over the instance's shared DHT client, for **minting**
/// (`create`) and **resolution** alike.
///
/// Both paths use the shared per-instance client (the one
/// `identity_create`/rotation published into) when the resolver is initialized,
/// and otherwise build the production client fail-closed via
/// [`build_ffi_dht_client`]. Never substitutes an in-memory/no-op client on a
/// shipped path. The returned method has no `sign_fn` — that is fine for
/// `create` (which does not publish; publishing is a separate
/// [`publish_to_resolver_dht_for`] step) and for `resolve` (which never signs).
fn shared_did_method(
    bi: &PyBridgeInstance,
) -> Result<DidDht<FfiDhtClient, scp_clock::SystemClock>, ScpPyError> {
    let client = match crate::runtime::resolver_dht_client(bi) {
        Some(client) => client,
        None => Arc::new(build_ffi_dht_client()?),
    };
    Ok(DidDht::with_client(client))
}

/// Publishes a newly created in-memory DID document into the instance's
/// resolver DHT client.
///
/// After `identity_create`, the DID document must be discoverable by the
/// per-instance `DualLayerResolver` (used by UCAN validation and governance
/// vote-signature verification). The document is otherwise only held in the
/// local identity registry, never in the resolver's DHT — so resolving the DID
/// to fetch its verification key fails.
///
/// Constructs a BEP44 signed mutable item (32-byte public key, 64-byte
/// signature, document JSON, sequence number 1) and calls
/// [`scp_dht::DhtClient::publish`]. Best-effort: errors are
/// logged but never fail identity creation (the document is still registered
/// locally; only resolver discoverability is affected).
///
/// This is the FIRST publish of a freshly minted DID, so `seq = 1` is correct
/// by construction. SUBSEQUENT publishes (key rotation, agent-key add/rotate/
/// remove, migration) do NOT route through here: they go through a `DidDht`
/// built against the same resolver client (see `rotation_publish_client`) whose
/// monotonic BEP44 sequence is bootstrapped via `DidDht::initialize_sequence`,
/// guaranteeing each re-publish carries a strictly higher `seq` that overwrites
/// the prior record and advances the resolver's downgrade tracker.
///
/// Mirrors the NAPI bridge's `publish_to_shared_dht_for`.
///
/// Only reached from the testing-gated identity-create paths (production create
/// fails closed before publishing — ADR-062 §Decision 6).
#[cfg(feature = "testing")]
async fn publish_to_resolver_dht_for(
    bi: &PyBridgeInstance,
    identity: &ScpIdentity,
    document: &DidDocument,
    custody: &FfiKeyCustody,
) {
    use scp_dht::DhtClient as _;

    let Some(dht_client) = crate::runtime::resolver_dht_client(bi) else {
        // Resolver not initialized on this instance; nothing to seed.
        return;
    };

    // Serialize the document to JSON (the BEP44 value).
    let doc_json = match document.to_json() {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("publish_to_resolver_dht: failed to serialize document: {e}");
            return;
        }
    };
    let value = doc_json.as_bytes();

    // Extract the 32-byte public key from the DID string.
    let public_key = match scp_identity::extract_public_key(&identity.did) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("publish_to_resolver_dht: failed to extract public key: {e}");
            return;
        }
    };

    // Build the BEP44 signable payload and sign it with the identity key.
    let seq: u64 = 1;
    let signable = scp_dht::bep44_signable(value, seq);
    let sig_bytes = match custody.sign(&identity.identity_key, &signable).await {
        Ok(sig) => sig.into_bytes(),
        Err(e) => {
            tracing::warn!("publish_to_resolver_dht: signing failed: {e}");
            return;
        }
    };
    let Ok(signature): Result<[u8; 64], _> = sig_bytes.try_into() else {
        tracing::warn!("publish_to_resolver_dht: signature is not 64 bytes");
        return;
    };

    // Publish into the per-instance in-memory DHT the resolver reads from.
    if let Err(e) = dht_client
        .publish(&public_key, &signature, value, seq)
        .await
    {
        tracing::warn!("publish_to_resolver_dht: DHT publish failed: {e}");
    }
}

/// Selects the DHT client that key-rotation / agent-key / migration operations
/// should publish their UPDATED DID document into.
///
/// Rotation, agent-key, and migration operations re-publish a NEW DID document
/// (a higher BEP44 sequence). That document MUST land in the per-instance
/// resolver DHT client — the one [`IdentityBackedDidResolver`] reads from
/// (seeded by [`set_resolver_dht_client`] / read via [`resolver_dht_client`]) —
/// so that subsequent DID resolution (UCAN validation, governance vote-signature
/// verification) sees the rotated `#active` key and rejects signatures from the
/// retired one. Publishing into a throwaway client would leave the resolver
/// permanently serving the stale, pre-rotation document, so the retired key
/// would keep passing every current-key check: a KeyPackage attestation
/// (§9.7.1 check 1 of the security-model spec) and a live DID authentication
/// (§3.11.4 steps 7 and 8 of the identity spec).
///
/// Returns the shared resolver client. Rotation / agent-key / migration
/// operations only run against an identity already in the registry, which is
/// only populated by `identity_create` — and `identity_create` initializes the
/// resolver DHT client first. So by the time any re-publish runs, the shared
/// client is always present.
///
/// Fails closed if the client is somehow absent: fabricating a throwaway
/// in-memory client would let the re-published document land somewhere the
/// resolver never reads, so the retired key would keep passing the two
/// current-key checks named above (and, in a shipped build, the in-memory arm
/// does not even exist). A typed error is strictly better than a lie.
fn rotation_publish_client(bi: &PyBridgeInstance) -> Result<Arc<FfiDhtClient>, ScpPyError> {
    crate::runtime::resolver_dht_client(bi).ok_or_else(|| {
        ScpPyError::identity(
            "DID resolver DHT client is not initialized on this instance — \
             create an identity (identity_create) before publishing document updates",
        )
    })
}

/// Runs the migration publish chain against the SHARED resolver DHT client.
///
/// Migration publishes TWO documents — the new DID's document and the old DID's
/// `alsoKnownAs` update — both of which must land in the resolver client (see
/// [`rotation_publish_client`]) so DID resolution follows the migration forward
/// instead of pinning the pre-migration document. The BEP44 sequence is seeded
/// from the OLD DID's current value via `DidDht::initialize_sequence`, so the
/// old-document republish strictly overwrites the pre-migration record (the new
/// DID is fresh and starts at sequence 1). A failure is logged loudly because
/// it leaves the resolver potentially serving the pre-migration document.
// Only reached from the testing-gated `identity_migrate` path (production
// migration is unreachable — no identity can be created — ADR-062 §Decision 6).
#[cfg(feature = "testing")]
#[allow(clippy::too_many_arguments)] // Mirrors `DidDht::migrate_identity`'s arity (FFI seam).
async fn run_migrate_publish<C>(
    bi: &PyBridgeInstance,
    old_did: &str,
    old_identity: &ScpIdentity,
    old_doc: &DidDocument,
    pre_rotation_handle: &scp_platform::PreRotationKeyHandle,
    pre_rotation_custody: &impl scp_platform::PreRotationCustody,
    key_custody: &Arc<C>,
    rotated_at: u64,
) -> Result<scp_identity::MigrationOutcome, ScpPyError>
where
    C: KeyCustody + Send + Sync + 'static,
{
    let sign_fn =
        DidDht::<FfiDhtClient, scp_clock::SystemClock>::make_sign_fn(Arc::clone(key_custody));
    let publish_client = rotation_publish_client(bi)?;
    let did_method =
        DidDht::with_client_and_signer(publish_client, Arc::new(DidCache::new()), sign_fn);
    did_method
        .initialize_sequence(old_did)
        .await
        .map_err(ScpPyError::from)?;
    did_method
        .migrate_identity(
            old_identity,
            old_doc,
            pre_rotation_handle,
            pre_rotation_custody,
            key_custody.as_ref(),
            rotated_at,
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                old_did = %old_did,
                error = %e,
                "identity_migrate: migration/republish failed — resolver may still serve the pre-migration document"
            );
            ScpPyError::from(e)
        })
}

// ---------------------------------------------------------------------------
// PyIdentity — opaque Python object for SCP identity
// ---------------------------------------------------------------------------

/// An SCP identity handle exposed to Python.
///
/// Stores the DID string and custody type as safe, cloneable metadata.
/// Internal key material is NOT stored here — it remains within the
/// [`KeyCustody`] boundary. Python code accesses
/// identity state through getter methods only.
///
/// # Python usage
///
/// ```python
/// identity = await scp.identity_create("in_memory")
/// print(identity.did)       # "did:dht:z..."
/// print(identity.custody)   # "in_memory"
/// ```
#[pyclass(name = "PyIdentity", frozen)]
#[derive(Debug, Clone)]
pub struct PyIdentity {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    did: String,
    /// The custody type used to create this identity (`"in_memory"` or `"platform"`).
    custody: String,
    /// Whether this identity has an agent signing key (`#agent` VM).
    has_agent_key: bool,
    /// The agent verification method's public key in multibase form (if any).
    ///
    /// Snapshot of `DidDocument::agent_verification_method().public_key_multibase`
    /// at construction time. We store it on the handle (instead of looking it
    /// up through the bridge instance on each call) because `PyIdentity` is
    /// a `frozen` `#[pyclass]` with no access to the owning `PyBridgeInstance`
    /// from its getter methods. Returned by [`PyIdentity::get_agent_public_key`].
    agent_public_key_multibase: Option<String>,
    /// Hex-encoded Ed25519 verifying-key bytes for the identity key
    /// (VM `#0`, the key that derives the DID). 64 hex chars = 32 raw
    /// bytes. Populated for identities created via `PyScp::identity_create`;
    /// `None` for identities loaded from storage without a live custody.
    ///
    /// Why `#0` (`identity_key`), not `#active`: the DID-deriving identity
    /// key is exposed (scp-core uses three distinct keys per
    /// [`ScpIdentity`]) so the value is byte-identical across all bridges
    /// under a deterministic `seed` (ADR-046). SCPID signatures use
    /// `#active`, derived from `seed[32..64]`, so `#active`-signed
    /// signatures are likewise byte-identical across all bridges under the
    /// `signed_at_override` affordance.
    verifying_key_hex: Option<String>,
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549). Consumed by
    /// [`crate::pyscp_check_handle!`] at every entry point that accepts this
    /// handle.
    pub(crate) instance_id: u64,
}

#[pymethods]
impl PyIdentity {
    /// Returns the DID string for this identity.
    #[getter]
    pub(crate) fn did(&self) -> &str {
        &self.did
    }

    /// Returns the custody type string for this identity.
    #[getter]
    fn custody(&self) -> &str {
        &self.custody
    }

    /// Returns `True` if this identity has an agent signing key (`#agent`
    /// verification method in the DID document).
    ///
    /// See ADR-039 acceptance criterion 19.
    #[getter]
    const fn has_agent_key(&self) -> bool {
        self.has_agent_key
    }

    /// Returns the hex-encoded Ed25519 verifying-key bytes for the
    /// identity key (VM `#0`, the key that derives the DID), or `None`
    /// if this handle was loaded without live key material (e.g. via
    /// [`py_identity_load`]).
    ///
    /// Intended for cross-bridge parity assertions: under a deterministic
    /// `seed`, this value is byte-identical across every bridge
    /// (ADR-046). See the `verifying_key_hex` field docs for why `#0`
    /// rather than `#active`.
    #[getter]
    fn verifying_key(&self) -> Option<String> {
        self.verifying_key_hex.clone()
    }

    /// Returns the agent key's public key as a multibase-encoded string, or
    /// `None` if no agent key exists.
    ///
    /// The value is snapshotted from the `DidDocument`'s `#agent`
    /// verification method at the time this [`PyIdentity`] was constructed.
    /// Rotating or removing the agent key returns a new `PyIdentity` with
    /// the updated snapshot; callers must use the returned handle rather
    /// than the stale one.
    ///
    /// Mirrors the `UniFFI` bridge's `Identity::get_agent_public_key`
    /// (see `crates/scp-ffi/uniffi/src/bridge.rs`) and the `NAPI` bridge.
    ///
    /// See ADR-039 acceptance criterion 19 and 4.
    #[must_use]
    fn get_agent_public_key(&self) -> Option<String> {
        self.agent_public_key_multibase.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "PyIdentity(did={:?}, custody={:?}, has_agent_key={})",
            self.did, self.custody, self.has_agent_key
        )
    }

    fn __str__(&self) -> &str {
        &self.did
    }
}

impl PyIdentity {
    /// Creates a new `PyIdentity` tagged with the given bridge instance's
    /// `instance_id`.
    ///
    /// `agent_public_key_multibase` should be the `#agent` verification
    /// method's `publicKeyMultibase` from the identity's DID document, or
    /// `None` if the identity has no agent key. Use
    /// [`PyIdentity::from_document`] when a `DidDocument` is in scope to
    /// avoid computing `has_agent_key` and the agent key multibase twice.
    ///
    /// `verifying_key_hex` is the hex-encoded VM `#0` public key for
    /// deterministic cross-bridge parity assertions (ADR-046). Pass `None`
    /// when the handle is loaded without live key material (e.g. via
    /// `identity_load`).
    #[must_use]
    pub const fn new(
        bi: &crate::runtime::PyBridgeInstance,
        did: String,
        custody: String,
        has_agent_key: bool,
        agent_public_key_multibase: Option<String>,
        verifying_key_hex: Option<String>,
    ) -> Self {
        Self {
            did,
            custody,
            has_agent_key,
            agent_public_key_multibase,
            verifying_key_hex,
            instance_id: bi.core.instance_id(),
        }
    }

    /// Creates a new `PyIdentity` by snapshotting agent key state from the
    /// given [`DidDocument`].
    ///
    /// Prefer this over [`PyIdentity::new`] at callsites that already have a
    /// `DidDocument` in scope — it guarantees `has_agent_key` and
    /// `agent_public_key_multibase` agree (both derived from the same
    /// document).
    #[must_use]
    pub fn from_document(
        bi: &crate::runtime::PyBridgeInstance,
        did: String,
        custody: String,
        document: &DidDocument,
        verifying_key_hex: Option<String>,
    ) -> Self {
        let agent_vm = document.agent_verification_method();
        let has_agent_key = agent_vm.is_some();
        let agent_public_key_multibase = agent_vm.map(|vm| vm.public_key_multibase.clone());
        Self {
            did,
            custody,
            has_agent_key,
            agent_public_key_multibase,
            verifying_key_hex,
            instance_id: bi.core.instance_id(),
        }
    }
}

// ---------------------------------------------------------------------------
// PyDIDDocument — opaque Python object for DID documents
// ---------------------------------------------------------------------------

/// A DID Document exposed to Python.
///
/// Wraps the Rust [`DidDocument`] and provides getter methods for all public
/// fields. Verification methods and services are returned as lists of Python
/// dicts for easy consumption. Internal crypto state is not exposed.
///
/// # Python usage
///
/// ```python
/// doc = await scp.identity_resolve("did:dht:z...")
/// print(doc.id)                       # "did:dht:z..."
/// print(doc.verification_methods)     # [{"id": "...", "type": "...", ...}]
/// print(doc.services)                 # [{"id": "...", "type": "...", ...}]
/// print(doc.also_known_as)            # ["did:dht:z..."]
/// ```
#[pyclass(name = "PyDIDDocument", frozen)]
#[derive(Debug, Clone)]
pub struct PyDIDDocument {
    /// The underlying Rust DID document.
    inner: DidDocument,
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549).
    ///
    /// `dead_code` allowance: future commits of this PR will add
    /// `check_handle` at every entry point that accepts this handle.
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
}

#[pymethods]
impl PyDIDDocument {
    /// Returns the DID string that this document describes.
    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }

    /// Returns the verification methods as a list of Python dicts.
    ///
    /// Each dict contains `id`, `type`, `controller`, and `public_key_multibase`.
    #[getter]
    fn verification_methods<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for vm in &self.inner.verification_method {
            let dict = PyDict::new(py);
            dict.set_item("id", &vm.id)?;
            dict.set_item("type", &vm.method_type)?;
            dict.set_item("controller", &vm.controller)?;
            dict.set_item("public_key_multibase", &vm.public_key_multibase)?;
            list.append(dict)?;
        }
        Ok(list)
    }

    /// Returns the service entries as a list of Python dicts.
    ///
    /// Each dict contains `id`, `type`, and `service_endpoint`.
    #[getter]
    fn services<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for svc in &self.inner.service {
            let dict = PyDict::new(py);
            dict.set_item("id", &svc.id)?;
            dict.set_item("type", &svc.service_type)?;
            dict.set_item("service_endpoint", &svc.service_endpoint)?;
            list.append(dict)?;
        }
        Ok(list)
    }

    /// Returns the `alsoKnownAs` entries as a list of strings.
    #[getter]
    fn also_known_as<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for aka in &self.inner.also_known_as {
            list.append(aka)?;
        }
        Ok(list)
    }

    /// Returns the authentication method references as a list of strings.
    #[getter]
    fn authentication<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for auth in &self.inner.authentication {
            list.append(auth)?;
        }
        Ok(list)
    }

    /// Returns the assertion method references as a list of strings.
    #[getter]
    fn assertion_methods<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for am in &self.inner.assertion_method {
            list.append(am)?;
        }
        Ok(list)
    }

    /// Returns `True` if this document contains an `#agent` verification method.
    ///
    /// See ADR-039 acceptance criterion 19.
    #[getter]
    fn has_agent_key(&self) -> bool {
        self.inner.has_agent_key()
    }

    /// Returns the agent key's public key as a multibase-encoded string, or
    /// `None` if no agent key exists.
    ///
    /// See ADR-039 acceptance criterion 19.
    #[getter]
    fn agent_public_key(&self) -> Option<String> {
        self.inner
            .agent_verification_method()
            .map(|vm| vm.public_key_multibase.clone())
    }

    fn __repr__(&self) -> String {
        format!("PyDIDDocument(id={:?})", self.inner.id)
    }

    fn __str__(&self) -> &str {
        &self.inner.id
    }
}

impl PyDIDDocument {
    /// Creates a new `PyDIDDocument` tagged with the given bridge instance's
    /// `instance_id`.
    #[must_use]
    pub const fn new(bi: &crate::runtime::PyBridgeInstance, document: DidDocument) -> Self {
        Self {
            inner: document,
            instance_id: bi.core.instance_id(),
        }
    }
}

// ---------------------------------------------------------------------------
// Custody parsing helper
// ---------------------------------------------------------------------------

/// Parses a custody type string and returns an [`FfiKeyCustody`] instance.
///
/// Supported custody types:
///
/// - `"in_memory"` — Test-only in-memory custody. Keys are lost on process
///   exit. Only available when compiled with `cfg(feature = "testing")`.
/// - `"file"` — Encrypted file-backed custody ([`FileKeyCustody`]) using
///   Argon2id + AES-256-GCM. This is the production default for desktop/server
///   platforms. Mobile platforms (iOS/Android) should use their native
///   `KeyCustodyProvider` callback interface via `UniFFI` instead.
/// - `"platform"` — Backward-compatible alias for `"file"` (SCP-294a).
///
/// The `"file"` / `"platform"` path creates a [`FileKeyCustody`] at a default
/// location (`$HOME/.scp/keys.bin`) with a passphrase from the
/// `SCP_KEY_PASSPHRASE` environment variable. If the variable is not set, an
/// error is returned.
///
/// # Errors
///
/// Returns [`ScpPyError::ValidationError`] if:
/// - The custody string is not recognized.
/// - `"in_memory"` is requested but the `testing` feature is not enabled.
/// - `"file"` / `"platform"` is requested but `SCP_KEY_PASSPHRASE` is not set.
/// - [`FileKeyCustody`] initialization fails (I/O error, corrupt key file).
///
/// See issue #323, ADR-006, and SCP-294a.
fn parse_custody(custody: &str) -> Result<(Arc<FfiKeyCustody>, String), ScpPyError> {
    parse_custody_with_seed(custody, None)
}

/// Variant of [`parse_custody`] that optionally accepts a 32-byte
/// `testing_seed` for the `"in_memory"` custody path, used by the
/// cross-bridge parity harness (ADR-046). The seed is fed directly into
/// [`InMemoryKeyCustody::from_seed_bytes`], making every subsequent
/// `generate_keypair` call deterministic.
///
/// A non-`None` seed on any custody type other than `"in_memory"` is a
/// validation error (`SCP-VALID-7009`) — seeded determinism is only
/// meaningful for the in-process testing custody.
#[cfg(feature = "testing")]
fn parse_custody_with_seed(
    custody: &str,
    testing_seed: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> Result<(Arc<FfiKeyCustody>, String), ScpPyError> {
    match custody {
        "in_memory" => {
            // Deref through `Zeroizing<[u8; 32]>` so the seed bytes are
            // wiped when `testing_seed` is dropped at the end of this
            // scope. `from_seed_bytes` takes `[u8; 32]` by value (Copy),
            // so one unavoidable stack copy is consumed by the RNG —
            // that copy lives only inside `InMemoryKeyCustody`'s
            // `StdRng::from_seed`, which discards it after seeding.
            let kc = testing_seed
                .as_ref()
                .map_or_else(InMemoryKeyCustody::new, |seed| {
                    InMemoryKeyCustody::from_seed_bytes(**seed)
                });
            Ok((Arc::new(FfiKeyCustody::InMemory(kc)), custody.to_owned()))
        }
        _ if testing_seed.is_some() => Err(ScpPyError::ValidationError {
            message: "`testing_seed` parameter is only valid for custody=\"in_memory\"".to_owned(),
            code: scp_ffi_common::error_codes::VALID_7009.to_owned(),
        }),
        other => parse_custody_inner(other),
    }
}

#[cfg(not(feature = "testing"))]
fn parse_custody_with_seed(
    custody: &str,
    testing_seed: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> Result<(Arc<FfiKeyCustody>, String), ScpPyError> {
    if testing_seed.is_some() {
        return Err(ScpPyError::ValidationError {
            message: "`testing_seed` parameter requires the testing feature".to_owned(),
            code: scp_ffi_common::error_codes::VALID_7008.to_owned(),
        });
    }
    parse_custody_inner(custody)
}

fn parse_custody_inner(custody: &str) -> Result<(Arc<FfiKeyCustody>, String), ScpPyError> {
    match custody {
        #[cfg(feature = "testing")]
        "in_memory" => {
            let kc = Arc::new(FfiKeyCustody::InMemory(InMemoryKeyCustody::new()));
            Ok((kc, custody.to_owned()))
        }
        #[cfg(not(feature = "testing"))]
        "in_memory" => Err(ScpPyError::identity_with_code(
            "in_memory custody is not available in this build -- use \"file\" or \
             \"platform\" custody for production key storage",
            scp_ffi_common::error_codes::IDENT_1008,
        )),
        // "file" is the canonical name; "platform" is a backward-compat alias
        // (SCP-294a). Both resolve to FileKeyCustody.
        "file" | "platform" => {
            let passphrase =
                zeroize::Zeroizing::new(std::env::var("SCP_KEY_PASSPHRASE").map_err(|_| {
                    ScpPyError::validation(
                        "file custody requires the SCP_KEY_PASSPHRASE environment \
                         variable to be set — this passphrase protects the encrypted key file",
                    )
                })?);

            let key_dir = dirs_home().join(".scp");
            std::fs::create_dir_all(&key_dir).map_err(|e| {
                ScpPyError::validation(format!(
                    "failed to create key directory {}: {e}",
                    key_dir.display()
                ))
            })?;

            let key_path = key_dir.join("keys.bin");
            let file_kc = FileKeyCustody::new(&key_path, &passphrase).map_err(|e| {
                ScpPyError::identity(format!(
                    "failed to initialize file-backed key custody at {}: {e}",
                    key_path.display()
                ))
            })?;

            // Normalize: always store "file" as the canonical custody type,
            // even when the caller passed the "platform" backward-compat alias.
            Ok((Arc::new(FfiKeyCustody::File(file_kc)), "file".to_owned()))
        }
        // Align with NAPI + UniFFI: unknown custody strings return the
        // generic "unrecognised value" code `SCP-VALID-7005` rather than
        // `SCP-VALID-7001` (reserved for basic malformed-input failures).
        // See #1549 round-2 api-design review.
        other => Err(ScpPyError::ValidationError {
            message: format!(
                "unknown custody type: {other:?} — expected \"in_memory\", \"file\", or \"platform\""
            ),
            code: scp_ffi_common::error_codes::VALID_7005.to_owned(),
        }),
    }
}

/// Returns the user's home directory.
///
/// Falls back to the current directory if `$HOME` is not set (unlikely on
/// any supported platform).
fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME").map_or_else(|_| std::path::PathBuf::from("."), std::path::PathBuf::from)
}

// ---------------------------------------------------------------------------
// Storage key helpers (spec section 17.3)
// ---------------------------------------------------------------------------

/// Returns the storage key for an identity's persisted state.
///
/// Follows the key convention from spec section 17.3:
/// `identity/{did}/state`.
fn identity_state_key(did: &str) -> String {
    format!("identity/{did}/state")
}

/// Serialized identity state for storage persistence.
///
/// Stores the minimum metadata needed to reconstruct a [`PyIdentity`] from
/// storage: the DID string and custody type. Key material is NOT stored
/// here — it remains within the [`KeyCustody`](scp_platform::KeyCustody)
/// boundary.
///
/// Uses a simple `did\ncustody` text format. When `ProtocolRepository`'s identity
/// module lands (spec 17.4), this will migrate to `StoredValue<T>` with
/// `MessagePack` serialization.
#[cfg(feature = "testing")]
fn serialize_identity_state(did: &str, custody: &str) -> Vec<u8> {
    format!("{did}\n{custody}").into_bytes()
}

/// Deserializes identity state from storage bytes.
///
/// Returns `(did, custody)` on success.
///
/// # Errors
///
/// Returns `ScpPyError::IdentityError` if the stored data is malformed.
fn deserialize_identity_state(data: &[u8]) -> Result<(String, String), ScpPyError> {
    let text = std::str::from_utf8(data).map_err(|e| {
        ScpPyError::identity(format!("stored identity state is not valid UTF-8: {e}"))
    })?;
    let mut lines = text.splitn(2, '\n');
    let did = lines
        .next()
        .ok_or_else(|| ScpPyError::identity("stored identity state is empty".to_owned()))?
        .to_owned();
    let custody = lines
        .next()
        .ok_or_else(|| {
            ScpPyError::identity("stored identity state is missing custody type".to_owned())
        })?
        .to_owned();
    Ok((did, custody))
}

/// Serializes a [`scp_did::DidRotationEvent`] to JSON for return
/// across the `PyO3` boundary, wrapping serialization errors in
/// `ScpPyError::IdentityError` with code `IDENT_1004`.
///
/// Extracted from `identity_migrate` to keep the latter inside the
/// `too_many_lines` clippy threshold after the recovery-handle
/// refactor moved the call to `migrate_identity` to a struct
/// destructure.
#[cfg(feature = "testing")]
fn serialize_rotation_event(event: &scp_did::DidRotationEvent) -> Result<String, ScpPyError> {
    serde_json::to_string(event).map_err(|e| ScpPyError::IdentityError {
        message: format!("failed to serialize rotation event: {e}"),
        code: scp_ffi_common::error_codes::IDENT_1004.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Pure helpers — module-level `#[pyfunction]` exports (ADR-048 §1).
// ---------------------------------------------------------------------------

/// Verifies a device attestation token.
///
/// Uses `InMemoryDeviceAttestation` to check the token format.
///
/// # Arguments
///
/// * `_did` -- The DID string (unused in verification but kept for API
///   consistency with the `UniFFI` bridge).
/// * `token_base64` -- The base64-encoded attestation token to verify.
///
/// # Returns
///
/// `True` if the token is valid, `False` otherwise.
///
/// # Errors
///
/// Raises `IdentityError` if base64 decoding fails.
///
/// See §9.3.
#[cfg(feature = "testing")]
#[pyfunction]
pub fn identity_verify_device_attestation(
    py: Python<'_>,
    _did: &str,
    token_base64: &str,
) -> PyResult<bool> {
    let token_b64_owned = token_base64.to_owned();
    let rt = crate::runtime()?;

    py.allow_threads(|| -> Result<bool, ScpPyError> {
        use base64::Engine;
        let token_bytes = base64::engine::general_purpose::STANDARD
            .decode(&token_b64_owned)
            .map_err(|e| ScpPyError::identity(format!("invalid base64 attestation token: {e}")))?;

        let token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
        let attestation = scp_platform::testing::InMemoryDeviceAttestation::new();

        let result = rt
            .block_on(async {
                scp_platform::traits::DeviceAttestation::verify(&attestation, &token).await
            })
            .map_err(|e| {
                ScpPyError::identity(format!("device attestation verification failed: {e}"))
            })?;

        Ok(result)
    })
    .map_err(PyErr::from)
}

/// Fail-closed device attestation verification on a shipped (no-`testing`)
/// build.
///
/// Spec §9:187 — device attestation (Apple App Attest / Google Play Integrity)
/// is an optional SDK-level trust signal whose absence is expected and
/// non-penalizing. No production device-attestation backend is wired yet: App
/// Attest / Play Integrity are hardware/platform-backed and are intentionally
/// deferred (with hardware keychain custody) until an e2e-driven integration
/// lands (ADR-062 §Decision 3 severs the test-harness
/// `InMemoryDeviceAttestation` nullifier from every production path). So a
/// shipped build returns a typed
/// [`IDENT_1016`](scp_ffi_common::error_codes::IDENT_1016) honest-absent error
/// rather than a silently-valid `true`. This is a module-level `#[pyfunction]`
/// free fn (no receiver), so ADR-048 §1 imposes no self-dereference obligation.
/// See ADR-025 and #2171 for the real backend.
#[cfg(not(feature = "testing"))]
#[pyfunction]
pub fn identity_verify_device_attestation(_did: &str, token_base64: &str) -> PyResult<bool> {
    let _ = token_base64;
    Err(PyErr::from(ScpPyError::identity_with_code(
        "device attestation verification unavailable: no production \
         device-attestation backend is wired yet — Apple App Attest / \
         Google Play Integrity are hardware/platform-backed and are \
         intentionally deferred (with hardware keychain custody) until an \
         e2e-driven integration lands (spec §9:187). See #2171."
            .to_owned(),
        scp_ffi_common::error_codes::IDENT_1016,
    )))
}

/// Verifies the Ed25519 signature on an identity link attestation.
///
/// Parses the attestation JSON string and verifies the signature using the
/// provided issuer public key.
///
/// The issuer's public key cannot be reliably extracted from the DID string
/// because attestations are signed with `#active` or `#agent` keys
/// (spec §3.5.2), not the `#0` identity key embedded in the DID.
///
/// # Arguments
///
/// * `attestation_json` — JSON string of an `IdentityLinkAttestation`.
/// * `issuer_public_key_hex` — Hex-encoded Ed25519 public key of the
///   issuer.
///
/// # Returns
///
/// `True` if the signature is valid, `False` otherwise.
///
/// # Errors
///
/// Raises `IdentityError` if the JSON is malformed or the hex key is
/// invalid.
///
/// See spec §3.5.1.
#[pyfunction]
#[pyo3(name = "py_verify_identity_link_attestation")]
pub fn verify_identity_link_attestation(
    py: Python<'_>,
    attestation_json: &str,
    issuer_public_key_hex: &str,
) -> PyResult<bool> {
    use scp_core::identity::attestation::IdentityLinkAttestation;

    let json_owned = attestation_json.to_owned();
    let hex_key_owned = issuer_public_key_hex.to_owned();

    py.allow_threads(move || -> Result<bool, ScpPyError> {
        let attestation: IdentityLinkAttestation = serde_json::from_str(&json_owned)
            .map_err(|e| ScpPyError::identity(format!("failed to parse attestation JSON: {e}")))?;

        let pub_bytes = hex::decode(&hex_key_owned)
            .map_err(|e| ScpPyError::identity(format!("invalid issuer_public_key_hex: {e}")))?;
        Ok(attestation.verify_signature(&pub_bytes).is_ok())
    })
    .map_err(PyErr::from)
}

// ---------------------------------------------------------------------------
// PyScp methods — stateful identity operations.
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Creates a new DID identity.
    ///
    /// # Arguments
    ///
    /// * `custody` — The custody type: `"in_memory"` or `"platform"`.
    ///
    /// # Returns
    ///
    /// A [`PyIdentity`] containing the new DID string and custody type.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if key generation or DID creation fails.
    /// Raises `ValidationError` if the custody string is invalid.
    ///
    /// # Storage
    ///
    /// If a storage provider was attached at construction via
    /// `PyScp::with_storage`, the identity state (DID, custody type) is
    /// persisted under the key `identity/{did}/state` after successful
    /// creation (SCP-217).
    ///
    /// See ADR-013 acceptance criterion 2.
    #[pyo3(signature = (custody, testing_seed=None))]
    pub fn identity_create(
        &self,
        py: Python<'_>,
        custody: &str,
        testing_seed: Option<&[u8]>,
    ) -> PyResult<PyIdentity> {
        let bi_arc = Arc::clone(&self.inner);
        // Validate that an optional `testing_seed` byte slice is either
        // `None` or exactly 32 bytes long. Keeping seed-length validation
        // on the FFI boundary means the runtime never sees malformed
        // bytes. Mismatched length is `SCP-VALID-7007` (format error);
        // seed-plus-wrong-custody is `SCP-VALID-7009` and is raised by
        // `parse_custody_with_seed` below.
        // Wrap in `Zeroizing` immediately on the FFI boundary so the
        // 32 seed bytes are wiped when dropped, not left on the stack.
        // The seed feeds `Ed25519 SigningKey::from_bytes` inside
        // `InMemoryKeyCustody::from_seed_bytes`, so the same hygiene
        // we apply to other private-key material applies here.
        //
        // Unlike the UniFFI / NAPI bridges, PyO3 hands us a
        // `&[u8]` borrow straight from the caller's `PyBytes` — the
        // narrowing below copies through `expect_fixed_bytes::<32>`
        // with no intermediate `Vec` on the Rust side, so there is no
        // bridge-owned heap buffer to wipe. The caller's `PyBytes` is
        // owned by the Python interpreter and is not ours to mutate:
        // Python callers are responsible for zeroing their own byte
        // string (e.g. by reusing a `bytearray` and clearing it) after
        // this call returns.
        let testing_seed_array: Option<zeroize::Zeroizing<[u8; 32]>> = testing_seed
            .map(|bytes| {
                scp_ffi_common::validate::expect_fixed_bytes::<32>(bytes, "testing_seed").map_err(
                    |message| ScpPyError::ValidationError {
                        message,
                        code: scp_ffi_common::error_codes::VALID_7007.to_owned(),
                    },
                )
            })
            .transpose()?
            .map(zeroize::Zeroizing::new);
        let (key_custody, custody_str) = parse_custody_with_seed(custody, testing_seed_array)?;
        let rt = crate::runtime()?;

        // Ensure the production DID resolver is initialized on this bridge
        // (idempotent). #311.
        ensure_did_resolver_initialized_on(&bi_arc, rt.handle().clone()).map_err(PyErr::from)?;

        py.allow_threads(|| {
            rt.block_on(async {
                let did_method = shared_did_method(&bi_arc)?;

                // Pre-rotation is mandatory at creation (spec §9.7.4.1 §3), which
                // requires a `PreRotationCustody` backend. The only implementation
                // is the test-harness `InMemoryPreRotationCustody` nullifier, so a
                // shipped build FAILS CLOSED (ADR-062 §Decision 6, IDENT_1059)
                // rather than silently minting it.
                #[cfg(not(feature = "testing"))]
                {
                    let _ = (&bi_arc, &key_custody, &custody_str, &did_method);
                    Err::<PyIdentity, pyo3::PyErr>(
                        crate::identity::no_pre_rotation_backend().into(),
                    )
                }
                #[cfg(feature = "testing")]
                {
                    // Mint a fresh per-identity pre-rotation custody. ADR-003
                    // §4b: the pre-rotation key lives in a separate substrate
                    // from operational `key_custody`. The same `Arc` is
                    // preserved across migrations.
                    let pre_rotation_custody =
                        Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                    let (identity, document, pre_rotation_handle) = did_method
                        .create(key_custody.as_ref(), pre_rotation_custody.as_ref())
                        .await
                        .map_err(ScpPyError::from)?;

                    let did = identity.did.clone();
                    let document_for_handle = document.clone();

                    // Extract the verifying-key bytes for the identity (`#0`)
                    // signing key BEFORE moving the custody into the registry.
                    // Under a deterministic `seed`, this value is byte-identical
                    // across every bridge (ADR-046).
                    let pk = key_custody
                        .public_key(&identity.identity_key)
                        .await
                        .map_err(|e| {
                            ScpPyError::identity(format!(
                                "failed to read identity key after identity create: {e}"
                            ))
                        })?;
                    let verifying_key_hex = Some(hex::encode(pk.as_bytes()));

                    // Publish the DID document into this instance's resolver DHT so
                    // the document is resolvable for signature verification (UCAN
                    // validation, governance vote verification). Best-effort; the
                    // document is still registered locally regardless. Done BEFORE
                    // moving `identity`/`key_custody`/`document` into the registry.
                    publish_to_resolver_dht_for(
                        &bi_arc,
                        &identity,
                        &document,
                        key_custody.as_ref(),
                    )
                    .await;

                    // Register the identity in this instance's registry so that
                    // subsequent bridge methods (UCAN minting, pseudonym
                    // derivation, signing, key rotation) can access the retained
                    // KeyCustody and KeyHandle references. See SCP-214 criterion 3.
                    crate::runtime::register_identity(
                        &bi_arc,
                        &did,
                        IdentityEntry {
                            identity,
                            custody: key_custody,
                            document,
                            identity_link_attestations: Vec::new(),
                            pre_rotation_handle,
                            pre_rotation_custody,
                        },
                    );

                    // Persist identity state if storage is initialized (SCP-217).
                    if let Ok(storage) = crate::runtime::get_storage(&bi_arc) {
                        let key = identity_state_key(&did);
                        let data = serialize_identity_state(&did, &custody_str);
                        storage.store(&key, &data).await.map_err(|e| {
                            ScpPyError::identity(format!("failed to persist identity state: {e}"))
                        })?;
                    }

                    Ok(PyIdentity::from_document(
                        &bi_arc,
                        did,
                        custody_str,
                        &document_for_handle,
                        verifying_key_hex,
                    ))
                }
            })
        })
    }

    /// Creates a new DID identity with an agent signing key.
    ///
    /// Like `PyScp::identity_create`, but the resulting identity also has
    /// an `#agent` verification method in its DID document.
    ///
    /// # Arguments
    ///
    /// * `custody` — The custody type: `"in_memory"` or `"platform"`.
    ///
    /// # Returns
    ///
    /// A [`PyIdentity`] with `has_agent_key == True`.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if key generation or DID creation fails.
    /// Raises `ValidationError` if the custody string is invalid.
    ///
    /// See ADR-039 acceptance criterion 4 and SCP-AB-016.
    pub fn identity_create_with_agent_key(
        &self,
        py: Python<'_>,
        custody: &str,
    ) -> PyResult<PyIdentity> {
        let bi_arc = Arc::clone(&self.inner);
        let (key_custody, custody_str) = parse_custody(custody)?;
        let rt = crate::runtime()?;

        // Ensure the production DID resolver is initialized on this bridge
        // (idempotent). #311.
        ensure_did_resolver_initialized_on(&bi_arc, rt.handle().clone()).map_err(PyErr::from)?;

        py.allow_threads(|| {
            rt.block_on(async {
                let did_method = shared_did_method(&bi_arc)?;

                // FAIL CLOSED on a shipped build — no real pre-rotation backend
                // (ADR-062 §Decision 6, IDENT_1059). See `identity_create`.
                #[cfg(not(feature = "testing"))]
                {
                    let _ = (&bi_arc, &key_custody, &custody_str, &did_method);
                    Err::<PyIdentity, pyo3::PyErr>(
                        crate::identity::no_pre_rotation_backend().into(),
                    )
                }
                #[cfg(feature = "testing")]
                {
                    // Fresh per-identity pre-rotation custody (see
                    // `identity_create` for rationale).
                    let pre_rotation_custody =
                        Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                    let (identity, document, pre_rotation_handle) = did_method
                        .create_with_agent_key(key_custody.as_ref(), pre_rotation_custody.as_ref())
                        .await
                        .map_err(ScpPyError::from)?;

                    let did = identity.did.clone();
                    let document_for_handle = document.clone();

                    // Extract the verifying-key bytes for the identity (`#0`)
                    // signing key BEFORE moving the custody into the registry
                    // (ADR-046 parity).
                    let pk = key_custody
                        .public_key(&identity.identity_key)
                        .await
                        .map_err(|e| {
                            ScpPyError::identity(format!(
                                "failed to read identity key after identity create: {e}"
                            ))
                        })?;
                    let verifying_key_hex = Some(hex::encode(pk.as_bytes()));

                    // Publish into the resolver DHT (best-effort) so the DID is
                    // resolvable for signature verification, before moving owned
                    // state into the registry. See `identity_create`.
                    publish_to_resolver_dht_for(
                        &bi_arc,
                        &identity,
                        &document,
                        key_custody.as_ref(),
                    )
                    .await;

                    crate::runtime::register_identity(
                        &bi_arc,
                        &did,
                        IdentityEntry {
                            identity,
                            custody: key_custody,
                            document,
                            identity_link_attestations: Vec::new(),
                            pre_rotation_handle,
                            pre_rotation_custody,
                        },
                    );

                    // Persist identity state if storage is initialized (SCP-217).
                    if let Ok(storage) = crate::runtime::get_storage(&bi_arc) {
                        let key = identity_state_key(&did);
                        let data = serialize_identity_state(&did, &custody_str);
                        storage.store(&key, &data).await.map_err(|e| {
                            ScpPyError::identity(format!("failed to persist identity state: {e}"))
                        })?;
                    }

                    Ok(PyIdentity::from_document(
                        &bi_arc,
                        did,
                        custody_str,
                        &document_for_handle,
                        verifying_key_hex,
                    ))
                }
            })
        })
    }

    /// Creates a new DID identity whose key material lives in a
    /// caller-provided custody backend.
    ///
    /// The `provider` is a Python object implementing the
    /// [`KeyCustodyProvider`](scp_sdk.scp.KeyCustodyProvider) protocol
    /// (`sign`, `get_public_key`, `destroy_key`, `generate_keypair`,
    /// `dh_agree`, `derive_pseudonym`, `export_signing_key_bytes`,
    /// `custody_type`). The private key material never crosses into Rust
    /// ownership — every cryptographic operation re-enters Python under a
    /// fresh GIL (ADR-006). This is the desktop/server equivalent of the
    /// `UniFFI` bridge's `identity_create_with_custody`, used to inject an OS
    /// keychain, hardware-token wrapper, or any platform custody.
    ///
    /// # Arguments
    ///
    /// * `provider` — a Python object exposing the `KeyCustodyProvider`
    ///   protocol methods. Validated up-front; a missing or non-callable
    ///   method raises `ValidationError`.
    ///
    /// # Returns
    ///
    /// A [`PyIdentity`] whose `custody` is reported as `"callback"`. The
    /// `did:dht:` value is derived from the provider-generated identity key
    /// and `verifying_key()` is populated from the provider's public key.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if the provider does not expose the required
    /// custody methods. Raises `IdentityError` if key generation, signing, or
    /// DID creation fails inside the provider.
    ///
    /// See ADR-006 for the private-key-never-crosses-FFI custody contract.
    pub fn identity_create_with_custody(
        &self,
        py: Python<'_>,
        provider: Py<PyAny>,
    ) -> PyResult<PyIdentity> {
        let bi_arc = Arc::clone(&self.inner);

        // Validate the provider exposes the required protocol methods BEFORE
        // releasing the GIL. A malformed provider fails fast here with a
        // typed ValidationError instead of deep inside the async DID-creation
        // flow. Construction binds the (validated) Python object into the
        // GIL-independent shim.
        let provider_shim =
            crate::custody::PyKeyCustodyProvider::new(py, provider).map_err(|e| {
                ScpPyError::ValidationError {
                    message: format!("invalid KeyCustodyProvider: {e}"),
                    code: scp_ffi_common::error_codes::VALID_7005.to_owned(),
                }
            })?;
        let key_custody = Arc::new(FfiKeyCustody::Callback(
            crate::custody::PyCallbackKeyCustody::new(provider_shim),
        ));
        let custody_str = "callback".to_owned();
        let rt = crate::runtime()?;

        // Ensure the production DID resolver is initialized on this bridge
        // (idempotent).
        ensure_did_resolver_initialized_on(&bi_arc, rt.handle().clone()).map_err(PyErr::from)?;

        // CRITICAL: a single top-level `py.allow_threads` releases the GIL for
        // the whole async DID-creation flow. The provider's custody methods
        // re-acquire the GIL via `Python::with_gil` per call — there is NO
        // nested `block_on` and the GIL is NOT held across `block_on`, so
        // tokio cannot deadlock against a Python callback that itself needs
        // the GIL.
        py.allow_threads(|| {
            rt.block_on(async {
                let did_method = shared_did_method(&bi_arc)?;

                // FAIL CLOSED on a shipped build — no real pre-rotation backend
                // (ADR-062 §Decision 6, IDENT_1059). This callback-custody path
                // funnels through the same pre-rotation commitment as every other
                // create path, so it fails closed identically. See `identity_create`.
                #[cfg(not(feature = "testing"))]
                {
                    let _ = (&bi_arc, &key_custody, &custody_str, &did_method);
                    Err::<PyIdentity, pyo3::PyErr>(
                        crate::identity::no_pre_rotation_backend().into(),
                    )
                }
                #[cfg(feature = "testing")]
                {
                    // Fresh per-identity pre-rotation custody (see
                    // `identity_create` for rationale). The pre-rotation key lives
                    // in a separate in-memory substrate from the caller's
                    // operational custody (ADR-003 §4b).
                    let pre_rotation_custody =
                        Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                    let (identity, document, pre_rotation_handle) = did_method
                        .create(key_custody.as_ref(), pre_rotation_custody.as_ref())
                        .await
                        .map_err(ScpPyError::from)?;

                    let did = identity.did.clone();
                    let document_for_handle = document.clone();

                    // Snapshot the #0 (identity) verifying key for ADR-046 parity
                    // BEFORE moving the custody into the registry.
                    let pk = key_custody
                        .public_key(&identity.identity_key)
                        .await
                        .map_err(|e| {
                            ScpPyError::identity(format!(
                                "failed to read identity key after identity create: {e}"
                            ))
                        })?;
                    let verifying_key_hex = Some(hex::encode(pk.as_bytes()));

                    // Publish into the resolver DHT (best-effort) so the DID is
                    // resolvable for signature verification, before moving owned
                    // state into the registry. See `identity_create`.
                    publish_to_resolver_dht_for(
                        &bi_arc,
                        &identity,
                        &document,
                        key_custody.as_ref(),
                    )
                    .await;

                    crate::runtime::register_identity(
                        &bi_arc,
                        &did,
                        IdentityEntry {
                            identity,
                            custody: key_custody,
                            document,
                            identity_link_attestations: Vec::new(),
                            pre_rotation_handle,
                            pre_rotation_custody,
                        },
                    );

                    // Persist identity state if storage is initialized.
                    if let Ok(storage) = crate::runtime::get_storage(&bi_arc) {
                        let key = identity_state_key(&did);
                        let data = serialize_identity_state(&did, &custody_str);
                        storage.store(&key, &data).await.map_err(|e| {
                            ScpPyError::identity(format!("failed to persist identity state: {e}"))
                        })?;
                    }

                    Ok(PyIdentity::from_document(
                        &bi_arc,
                        did,
                        custody_str,
                        &document_for_handle,
                        verifying_key_hex,
                    ))
                }
            })
        })
    }

    /// Loads an existing identity from storage.
    ///
    /// Retrieves persisted identity state (DID, custody type) from the storage
    /// provider and returns a [`PyIdentity`] only if the identity has live
    /// crypto state in the runtime registry.
    ///
    /// If the identity was created in this process (via
    /// `PyScp::identity_create`), it will be in the registry and this method
    /// succeeds. If the identity was created in a different process with
    /// in-memory custody, the key material is lost and this method returns
    /// `SCP-IDENT-1010`. File-backed custody persists across restarts if the
    /// same passphrase is provided.
    ///
    /// # Arguments
    ///
    /// * `did` -- The DID string to load (e.g., `"did:dht:z6Mk..."`).
    ///
    /// # Returns
    ///
    /// A [`PyIdentity`] containing the loaded DID string and custody type,
    /// but only if the identity has live crypto state in the registry.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if:
    /// - The DID format is unsupported (not `did:dht:` prefix).
    /// - Storage has not been initialized (construct via
    ///   `SCP.with_storage({...})` instead of bare `SCP()`).
    /// - The DID is not found in storage.
    /// - The stored state is malformed.
    /// - The identity has no live crypto state in the registry
    ///   (`SCP-IDENT-1010`). This happens when loading an identity created
    ///   in a different process with in-memory custody (which does not
    ///   persist key material). File-backed custody survives restarts.
    ///
    /// Does NOT silently fall back to in-memory -- an explicit error is
    /// raised if the DID is not found.
    ///
    /// See spec section 17.3.
    pub fn identity_load(&self, py: Python<'_>, did: &str) -> PyResult<PyIdentity> {
        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(did)?;
        let did_owned = did.to_owned();
        let rt = crate::runtime()?;

        py.allow_threads(|| {
            if !did_owned.starts_with("did:dht:") {
                return Err(PyErr::from(ScpPyError::identity(format!(
                    "unsupported DID method: {did_owned} -- only did:dht is supported"
                ))));
            }

            let storage = crate::runtime::get_storage(&bi_arc).map_err(PyErr::from)?;

            rt.block_on(async {
                let key = identity_state_key(&did_owned);
                // `storage` is `&StorageProvider` which impls `Storage` directly
                // via enum dispatch — no Arc blanket-impl ambiguity.
                let data = storage
                    .retrieve(&key)
                    .await
                    .map_err(|e| {
                        ScpPyError::identity(format!(
                            "failed to read identity state from storage: {e}"
                        ))
                    })?
                    .ok_or_else(|| {
                        ScpPyError::identity(format!(
                            "identity not found in storage: {did_owned} -- \
                             was it created with identity_create?"
                        ))
                    })?;

                let (stored_did, custody_str) = deserialize_identity_state(&data)?;

                if stored_did != did_owned {
                    return Err(PyErr::from(ScpPyError::identity(format!(
                        "stored DID mismatch: expected {did_owned}, found {stored_did}"
                    ))));
                }

                // Verify the identity has live crypto state in the registry.
                // Without this check, the returned PyIdentity would be a
                // dangling handle — subsequent bridge methods (UCAN
                // minting, signing, pseudonym derivation, key rotation) would
                // fail with "identity not found in registry".
                if crate::runtime::identity_registry_contains(&bi_arc, &did_owned) {
                    let document_snapshot =
                        crate::runtime::with_identity(&bi_arc, &did_owned, |entry| {
                            Ok(entry.document.clone())
                        })
                        .ok();
                    if let Some(document) = document_snapshot {
                        // Recover the identity (#0) verifying key from the
                        // live registry entry so loaded identities also
                        // populate the ADR-046 parity field. Failures are
                        // non-fatal.
                        let verifying_key_hex =
                            crate::runtime::with_identity(&bi_arc, &did_owned, |entry| {
                                Ok((Arc::clone(&entry.custody), entry.identity.identity_key))
                            })
                            .ok()
                            .and_then(|(custody, handle)| {
                                rt.block_on(custody.public_key(&handle))
                                    .ok()
                                    .map(|pk| hex::encode(pk.as_bytes()))
                            });
                        return Ok(PyIdentity::from_document(
                            &bi_arc,
                            stored_did,
                            custody_str,
                            &document,
                            verifying_key_hex,
                        ));
                    }
                }

                Err(PyErr::from(ScpPyError::identity(format!(
                    "SCP-IDENT-1010: identity '{did_owned}' was found in storage \
                     but has no live crypto state in the runtime registry. \
                     If using in-memory custody, key material does not persist \
                     across process boundaries. Use identity_create to create \
                     a new identity, or use platform custody (custody='platform') \
                     for cross-process identity persistence."
                ))))
            })
        })
    }

    /// Resolves a DID to its document.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
    ///
    /// # Returns
    ///
    /// A [`PyDIDDocument`] containing the resolved document.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the DID cannot be resolved (not found on DHT,
    /// invalid format, verification failure).
    ///
    /// See ADR-013 acceptance criterion 2.
    pub fn identity_resolve(&self, py: Python<'_>, did: &str) -> PyResult<PyDIDDocument> {
        validate::validate_did(did)?;
        let did_owned = did.to_owned();
        let rt = crate::runtime()?;
        let bi = Arc::clone(&self.inner);

        py.allow_threads(|| {
            rt.block_on(async {
                let did_method = shared_did_method(&bi)?;
                let document = did_method
                    .resolve(&did_owned)
                    .await
                    .map_err(ScpPyError::from)?;

                Ok(PyDIDDocument::new(&bi, document))
            })
        })
    }

    /// Rotates the active signing key for an identity.
    ///
    /// Generates a new Active Signing Key via the retained [`KeyCustody`]
    /// provider, updates the DID document, and returns the same [`PyIdentity`]
    /// (DID string unchanged — only the active signing key changes per Layer 1
    /// rotation).
    ///
    /// The identity registry entry is updated in-place with the new
    /// [`ScpIdentity`] and [`DidDocument`].
    ///
    /// # Arguments
    ///
    /// * `identity` — The [`PyIdentity`] whose key should be rotated.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the identity is not in the registry or if key
    /// generation or DHT publishing fails.
    ///
    /// See ADR-003 acceptance criterion 4a and SCP-214 criterion 9.
    pub fn identity_rotate_key(
        &self,
        py: Python<'_>,
        identity: &PyIdentity,
    ) -> PyResult<PyIdentity> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, identity);
        let bi_arc = Arc::clone(&self.inner);
        let did = identity.did.clone();
        let custody_str = identity.custody.clone();
        let rt = crate::runtime()?;

        let publish_client = rotation_publish_client(&self.inner).map_err(PyErr::from)?;
        let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
            crate::runtime::with_identity_mut(&bi_arc, &did, |entry| {
                let sign_fn =
                    DidDht::<FfiDhtClient, scp_clock::SystemClock>::make_sign_fn(
                        Arc::clone(&entry.custody),
                    );
                // Publish the rotated document into the SHARED resolver DHT
                // client so DID resolution serves the new `#active` key and
                // rejects the retired one. `initialize_sequence` advances this
                // method's BEP44 sequence past whatever the resolver already
                // holds, so the rotated document strictly overwrites it (a
                // lower-or-equal `seq` would be a silent no-op).
                let did_method = DidDht::with_client_and_signer(
                    Arc::clone(&publish_client),
                    Arc::new(DidCache::new()),
                    sign_fn,
                );

                let rotation_result = rt.block_on(async {
                    did_method.initialize_sequence(&did).await?;
                    did_method
                        .rotate_active_key(&entry.identity, &entry.document, entry.custody.as_ref())
                        .await
                });

                let (new_identity, new_document) = rotation_result.map_err(|e| {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "identity_rotate_key: rotation/republish failed — resolver may still serve the pre-rotation key"
                    );
                    ScpPyError::from(e)
                })?;
                entry.identity = new_identity;
                entry.document = new_document;

                let verifying_key_hex = rt
                    .block_on(entry.custody.public_key(&entry.identity.identity_key))
                    .ok()
                    .map(|pk| hex::encode(pk.as_bytes()));

                Ok(PyIdentity::from_document(
                    &bi_arc,
                    did.clone(),
                    custody_str.clone(),
                    &entry.document,
                    verifying_key_hex,
                ))
            })
        });
        if result.is_ok() {
            // The re-published document carries a higher BEP44 sequence; drop
            // the resolver's now-stale cached copy so the next resolution reads
            // the fresh document (with the rotated/updated keys).
            crate::runtime::invalidate_resolver_cache(&self.inner, &did, rt);
        }
        result.map_err(PyErr::from)
    }

    /// Adds an agent signing key to an identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair for the `#agent` verification method,
    /// updates the DID document, and publishes to the DHT. The identity
    /// registry entry is updated in-place.
    ///
    /// # Arguments
    ///
    /// * `identity` — The [`PyIdentity`] to add an agent key to.
    ///
    /// # Returns
    ///
    /// An updated [`PyIdentity`] with `has_agent_key == True`.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if:
    /// - The identity already has an agent key (`AgentKeyAlreadyExists`).
    /// - Key generation fails.
    /// - DHT publishing fails.
    /// - The identity is not in the runtime registry.
    ///
    /// See ADR-039 acceptance criterion 4 and SCP-AB-016.
    pub fn identity_add_agent_key(
        &self,
        py: Python<'_>,
        identity: &PyIdentity,
    ) -> PyResult<PyIdentity> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, identity);
        let bi_arc = Arc::clone(&self.inner);
        let did = identity.did.clone();
        let custody_str = identity.custody.clone();
        let rt = crate::runtime()?;

        let publish_client = rotation_publish_client(&self.inner).map_err(PyErr::from)?;
        let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
            crate::runtime::with_identity_mut(&bi_arc, &did, |entry| {
                let sign_fn =
                    DidDht::<FfiDhtClient, scp_clock::SystemClock>::make_sign_fn(
                        Arc::clone(&entry.custody),
                    );
                // Publish the agent-key-bearing document into the SHARED
                // resolver DHT client (see `rotation_publish_client`), advancing
                // the BEP44 sequence past the resolver's current value first.
                let did_method = DidDht::with_client_and_signer(
                    Arc::clone(&publish_client),
                    Arc::new(DidCache::new()),
                    sign_fn,
                );

                let add_result = rt.block_on(async {
                    did_method.initialize_sequence(&did).await?;
                    did_method
                        .add_agent_key(&entry.identity, &entry.document, entry.custody.as_ref())
                        .await
                });

                let (new_identity, new_document) = add_result.map_err(|e| {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "identity_add_agent_key: add/republish failed — resolver may not serve the new agent key"
                    );
                    ScpPyError::from(e)
                })?;
                entry.identity = new_identity;
                entry.document = new_document;

                let verifying_key_hex = rt
                    .block_on(entry.custody.public_key(&entry.identity.identity_key))
                    .ok()
                    .map(|pk| hex::encode(pk.as_bytes()));

                Ok(PyIdentity::from_document(
                    &bi_arc,
                    did.clone(),
                    custody_str.clone(),
                    &entry.document,
                    verifying_key_hex,
                ))
            })
        });
        if result.is_ok() {
            // The re-published document carries a higher BEP44 sequence; drop
            // the resolver's now-stale cached copy so the next resolution reads
            // the fresh document (with the rotated/updated keys).
            crate::runtime::invalidate_resolver_cache(&self.inner, &did, rt);
        }
        result.map_err(PyErr::from)
    }

    /// Rotates the agent signing key for an identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair, retires the old `#agent` key as
    /// `#retired-agent-{sequence}`, and installs the new key as `#agent`.
    /// The identity registry entry is updated in-place.
    ///
    /// # Arguments
    ///
    /// * `identity` — The [`PyIdentity`] whose agent key should be rotated.
    ///
    /// # Returns
    ///
    /// An updated [`PyIdentity`] with the same DID but a new agent key.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if:
    /// - The identity has no agent key (`AgentKeyNotFound`).
    /// - Key generation fails.
    /// - DHT publishing fails.
    /// - The identity is not in the runtime registry.
    ///
    /// See ADR-039 acceptance criterion 4 and SCP-AB-016.
    pub fn identity_rotate_agent_key(
        &self,
        py: Python<'_>,
        identity: &PyIdentity,
    ) -> PyResult<PyIdentity> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, identity);
        let bi_arc = Arc::clone(&self.inner);
        let did = identity.did.clone();
        let custody_str = identity.custody.clone();
        let rt = crate::runtime()?;

        let publish_client = rotation_publish_client(&self.inner).map_err(PyErr::from)?;
        let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
            crate::runtime::with_identity_mut(&bi_arc, &did, |entry| {
                let sign_fn =
                    DidDht::<FfiDhtClient, scp_clock::SystemClock>::make_sign_fn(
                        Arc::clone(&entry.custody),
                    );
                // Publish the rotated-agent-key document into the SHARED
                // resolver DHT client (see `rotation_publish_client`), advancing
                // the BEP44 sequence past the resolver's current value first.
                let did_method = DidDht::with_client_and_signer(
                    Arc::clone(&publish_client),
                    Arc::new(DidCache::new()),
                    sign_fn,
                );

                let rotate_result = rt.block_on(async {
                    did_method.initialize_sequence(&did).await?;
                    did_method
                        .rotate_agent_key(&entry.identity, &entry.document, entry.custody.as_ref())
                        .await
                });

                let (new_identity, new_document) = rotate_result.map_err(|e| {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "identity_rotate_agent_key: rotation/republish failed — resolver may still serve the retired agent key"
                    );
                    ScpPyError::from(e)
                })?;
                entry.identity = new_identity;
                entry.document = new_document;

                let verifying_key_hex = rt
                    .block_on(entry.custody.public_key(&entry.identity.identity_key))
                    .ok()
                    .map(|pk| hex::encode(pk.as_bytes()));

                Ok(PyIdentity::from_document(
                    &bi_arc,
                    did.clone(),
                    custody_str.clone(),
                    &entry.document,
                    verifying_key_hex,
                ))
            })
        });
        if result.is_ok() {
            // The re-published document carries a higher BEP44 sequence; drop
            // the resolver's now-stale cached copy so the next resolution reads
            // the fresh document (with the rotated/updated keys).
            crate::runtime::invalidate_resolver_cache(&self.inner, &did, rt);
        }
        result.map_err(PyErr::from)
    }

    /// Removes the agent signing key from an identity (ADR-039).
    ///
    /// Removes the `#agent` verification method from the DID document and
    /// publishes the update to the DHT. The identity registry entry is
    /// updated in-place with `agent_signing_key: None`.
    ///
    /// # Arguments
    ///
    /// * `identity` — The [`PyIdentity`] whose agent key should be removed.
    ///
    /// # Returns
    ///
    /// An updated [`PyIdentity`] with `has_agent_key == False`.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if:
    /// - The identity has no agent key (`AgentKeyNotFound`).
    /// - DHT publishing fails.
    /// - The identity is not in the runtime registry.
    ///
    /// See ADR-039 acceptance criterion 4 and SCP-AB-016.
    pub fn identity_remove_agent_key(
        &self,
        py: Python<'_>,
        identity: &PyIdentity,
    ) -> PyResult<PyIdentity> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, identity);
        let bi_arc = Arc::clone(&self.inner);
        let did = identity.did.clone();
        let custody_str = identity.custody.clone();
        let rt = crate::runtime()?;

        let publish_client = rotation_publish_client(&self.inner).map_err(PyErr::from)?;
        let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
            crate::runtime::with_identity_mut(&bi_arc, &did, |entry| {
                let sign_fn =
                    DidDht::<FfiDhtClient, scp_clock::SystemClock>::make_sign_fn(
                        Arc::clone(&entry.custody),
                    );
                // Publish the agent-key-removed document into the SHARED
                // resolver DHT client (see `rotation_publish_client`) so the
                // resolver stops serving the removed agent key. Advance the
                // BEP44 sequence past the resolver's current value first.
                let did_method = DidDht::with_client_and_signer(
                    Arc::clone(&publish_client),
                    Arc::new(DidCache::new()),
                    sign_fn,
                );

                let remove_result = rt.block_on(async {
                    did_method.initialize_sequence(&did).await?;
                    did_method
                        .remove_agent_key(&entry.identity, &entry.document)
                        .await
                });

                let (new_identity, new_document) = remove_result.map_err(|e| {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "identity_remove_agent_key: removal/republish failed — resolver may still serve the removed agent key"
                    );
                    ScpPyError::from(e)
                })?;
                entry.identity = new_identity;
                entry.document = new_document;

                let verifying_key_hex = rt
                    .block_on(entry.custody.public_key(&entry.identity.identity_key))
                    .ok()
                    .map(|pk| hex::encode(pk.as_bytes()));

                Ok(PyIdentity::from_document(
                    &bi_arc,
                    did.clone(),
                    custody_str.clone(),
                    &entry.document,
                    verifying_key_hex,
                ))
            })
        });
        if result.is_ok() {
            // The re-published document carries a higher BEP44 sequence; drop
            // the resolver's now-stale cached copy so the next resolution reads
            // the fresh document (with the rotated/updated keys).
            crate::runtime::invalidate_resolver_cache(&self.inner, &did, rt);
        }
        result.map_err(PyErr::from)
    }

    /// Removes a DID from this instance's SCP-side identity registry.
    ///
    /// Drops the retained identity state (opaque key handles, custody
    /// provider, DID document) for the given DID. Idempotent — succeeds
    /// silently when the DID is not in the registry, matching the NAPI
    /// bridge's `identity_remove` semantics.
    ///
    /// Use this as a cleanup mechanism for long-running processes that
    /// create many ephemeral identities. The DID document published to the
    /// DHT is unaffected; this only releases the bridge's retained registry
    /// state. Custody-agnostic registry teardown — available in production.
    #[pyo3(name = "identity_remove")]
    pub fn identity_remove(&self, did: &str) -> PyResult<()> {
        validate::validate_did(did)?;
        crate::runtime::remove_identity(&self.inner, did);
        Ok(())
    }

    /// Removes a DID from this instance's SCP-side identity registry if
    /// present, reporting whether anything was removed.
    ///
    /// Returns `true` if the identity was found and removed, `false` if the
    /// DID was not in the registry. Companion to
    /// [`PyScp::identity_remove`] (which is unconditional), matching the
    /// NAPI bridge's `identity_remove_if_present` semantics. Custody-agnostic
    /// registry teardown — available in production.
    #[pyo3(name = "identity_remove_if_present")]
    pub fn identity_remove_if_present(&self, did: &str) -> PyResult<bool> {
        validate::validate_did(did)?;
        Ok(crate::runtime::remove_identity_if_present(&self.inner, did))
    }

    /// Migrates an identity to a new DID (Layer 2 rotation).
    ///
    /// Creates a new DID using the pre-rotation key as the new Identity Key.
    /// The old DID document is updated with an `alsoKnownAs` pointing to the
    /// new DID. Both documents are published. The old identity registry entry
    /// is replaced with the new one.
    ///
    /// # Arguments
    ///
    /// * `identity` — The [`PyIdentity`] to migrate.
    ///
    /// # Returns
    ///
    /// A new [`PyIdentity`] with the new DID string.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the identity is not in the registry, if key
    /// generation fails, or if DHT publishing fails.
    ///
    /// See ADR-003 acceptance criterion 4b and SCP-214 criterion 10.
    /// Returns `(new_identity, rotation_event_json)`. The JSON shape is
    /// `serde_json::to_string(&scp_did::DidRotationEvent)` so JS-,
    /// Python-, Swift-, or Kotlin-side consumers parse it directly. The
    /// SDK distributes the event to context members (spec §9.12,
    /// ADR-003 §4b).
    // The fail-closed/testing cfg split adds a few lines over the 100-line lint
    // budget; the body is otherwise a single linear migration flow.
    #[allow(clippy::too_many_lines)]
    pub fn identity_migrate(
        &self,
        py: Python<'_>,
        identity: &PyIdentity,
    ) -> PyResult<(PyIdentity, String)> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, identity);
        let bi_arc = Arc::clone(&self.inner);
        let old_did = identity.did.clone();
        let custody_str = identity.custody.clone();
        let rt = crate::runtime()?;

        py.allow_threads(|| {
            rt.block_on(async {
                // FAIL CLOSED on a shipped build: DID migration reads the
                // retained pre-rotation custody, which is test-harness-only
                // (ADR-062 §Decision 6). Production create fails closed, so no
                // migratable identity ever exists — this path is unreachable and
                // returns the typed IDENT_1059 error rather than referencing the
                // gated machinery.
                #[cfg(not(feature = "testing"))]
                {
                    let _ = (&bi_arc, &old_did, &custody_str);
                    Err::<(PyIdentity, String), pyo3::PyErr>(
                        crate::identity::no_pre_rotation_backend().into(),
                    )
                }
                #[cfg(feature = "testing")]
                {
                    // Extract what we need from the registry entry. The
                    // pre-rotation handle points into the cold-storage
                    // `pre_rotation_custody`; revealing it must yield a public
                    // key whose SHA-256 matches `pre_rotation_commitment`
                    // (spec §9.7.4.1 §6) — using a fresh handle here would
                    // break that invariant.
                    let (
                        custody,
                        old_identity_key,
                        old_active_key,
                        old_agent_key,
                        pre_rotation_commitment,
                        pre_rotation_handle,
                        pre_rotation_custody,
                        old_doc,
                    ) = crate::runtime::with_identity(&bi_arc, &old_did, |entry| {
                        Ok((
                            Arc::clone(&entry.custody),
                            entry.identity.identity_key,
                            entry.identity.active_signing_key,
                            entry.identity.agent_signing_key,
                            entry.identity.pre_rotation_commitment,
                            entry.pre_rotation_handle,
                            Arc::clone(&entry.pre_rotation_custody),
                            entry.document.clone(),
                        ))
                    })?;

                    let rotated_at = scp_clock::SystemClock.now_secs();

                    let old_identity = ScpIdentity {
                        identity_key: old_identity_key,
                        active_signing_key: old_active_key,
                        agent_signing_key: old_agent_key,
                        pre_rotation_commitment,
                        did: old_did.clone(),
                    };

                    let outcome = run_migrate_publish(
                        &bi_arc,
                        &old_did,
                        &old_identity,
                        &old_doc,
                        &pre_rotation_handle,
                        pre_rotation_custody.as_ref(),
                        &custody,
                        rotated_at,
                    )
                    .await?;
                    let rotation_event_json = serialize_rotation_event(&outcome.rotation_event)?;
                    let scp_identity::MigrationOutcome {
                        new_identity,
                        new_document,
                        new_pre_rotation_handle,
                        ..
                    } = outcome;
                    let new_did = new_identity.did.clone();
                    let document_for_handle = new_document.clone();

                    // Snapshot the migrated identity's verifying-key BEFORE the
                    // identity / custody move into the registry (ADR-046 parity).
                    let verifying_key_hex = custody
                        .public_key(&new_identity.identity_key)
                        .await
                        .ok()
                        .map(|pk| hex::encode(pk.as_bytes()));

                    // Preserve existing attestations from the old DID across migration.
                    let existing_attestations =
                        crate::runtime::with_identity(&bi_arc, &old_did, |e| {
                            Ok(e.identity_link_attestations.clone())
                        })
                        .unwrap_or_default();

                    // Remove old identity and register the new one. We carry
                    // the SAME pre-rotation custody Arc forward — only the
                    // handle changes per migration (ADR-003 §4b: each
                    // migration mints a fresh pre-rotation key).
                    crate::runtime::remove_identity(&bi_arc, &old_did);
                    crate::runtime::register_identity(
                        &bi_arc,
                        &new_did,
                        IdentityEntry {
                            identity: new_identity,
                            custody,
                            document: new_document,
                            identity_link_attestations: existing_attestations,
                            pre_rotation_handle: new_pre_rotation_handle,
                            pre_rotation_custody,
                        },
                    );

                    // Migration re-published BOTH documents at higher sequences:
                    // the new DID's document and the old DID's `alsoKnownAs`
                    // update. Drop both stale cache entries so resolution follows
                    // the migration forward instead of serving pre-migration docs.
                    if let Some(cache) = crate::runtime::resolver_cache(&bi_arc) {
                        cache.remove(&old_did).await;
                        cache.remove(&new_did).await;
                    }

                    Ok((
                        PyIdentity::from_document(
                            &bi_arc,
                            new_did,
                            custody_str,
                            &document_for_handle,
                            verifying_key_hex,
                        ),
                        rotation_event_json,
                    ))
                }
            })
        })
    }

    // -----------------------------------------------------------------------
    // Device attestation bridge (#362)
    // -----------------------------------------------------------------------

    /// Generates a device attestation token for an identity.
    ///
    /// Uses `InMemoryDeviceAttestation` (available only with
    /// `testing` feature) to produce a synthetic attestation
    /// token, then attaches it to the identity's DID document via
    /// [`DidDht::attach_device_attestation`].
    ///
    /// # Arguments
    ///
    /// * `identity_did` -- The DID string of the identity to attest.
    ///
    /// # Returns
    ///
    /// The attestation token as a base64-encoded string.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the identity is not in the registry or
    /// attestation fails.
    ///
    /// See §9.3.
    #[cfg(feature = "testing")]
    pub fn identity_attest_device(&self, py: Python<'_>, identity_did: &str) -> PyResult<String> {
        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(identity_did)?;
        let did_owned = identity_did.to_owned();
        let rt = crate::runtime()?;

        py.allow_threads(|| {
            crate::runtime::with_identity_mut(&bi_arc, &did_owned, |entry| {
                let attestation = scp_platform::testing::InMemoryDeviceAttestation::new();
                let dht = shared_did_method(&bi_arc)?;

                let new_document = rt
                    .block_on(async {
                        dht.attach_device_attestation(&entry.document, &attestation)
                            .await
                    })
                    .map_err(|e| ScpPyError::identity(format!("device attestation failed: {e}")))?;

                // Extract the attestation token from the updated document's
                // service entries. The service_endpoint is already base64-encoded
                // by `set_device_attestation_token`, so return it directly —
                // no double-encoding.
                let token_b64 = new_document
                    .service
                    .iter()
                    .find(|s| s.service_type == "ScpDeviceAttestation")
                    .map(|s| s.service_endpoint.clone())
                    .ok_or_else(|| {
                        ScpPyError::identity(
                            "device attestation succeeded but no ScpDeviceAttestation \
                             service entry found in updated document"
                                .to_owned(),
                        )
                    })?;

                // Update the identity's document with the attestation.
                entry.document = new_document;

                Ok(token_b64)
            })
        })
        .map_err(PyErr::from)
    }

    /// Fail-closed device attestation on a shipped (no-`testing`) build.
    ///
    /// Spec §9:187 — device attestation (Apple App Attest / Google Play
    /// Integrity) is an optional SDK-level trust signal whose absence is
    /// expected and non-penalizing. No production device-attestation backend is
    /// wired yet: App Attest / Play Integrity are hardware/platform-backed and
    /// are intentionally deferred (with hardware keychain custody) until an
    /// e2e-driven integration lands (ADR-062 §Decision 3 severs the test-harness
    /// `InMemoryDeviceAttestation` nullifier from every production path). So a
    /// shipped build returns a typed
    /// [`IDENT_1015`](scp_ffi_common::error_codes::IDENT_1015) honest-absent
    /// error rather than a silently-valid attestation. See ADR-025 and #2171 for
    /// the real backend.
    #[cfg(not(feature = "testing"))]
    pub fn identity_attest_device(&self, py: Python<'_>, identity_did: &str) -> PyResult<String> {
        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(identity_did)?;
        let did_owned = identity_did.to_owned();

        // Resolve the identity against THIS instance's registry first: an
        // unregistered DID surfaces the bridge's standard not-found identity
        // error, so a caller can distinguish "unknown identity" from "backend
        // unavailable". A registered DID then fails closed with the typed
        // honest-absent IDENT_1015 rather than a silently-valid attestation.
        py.allow_threads(move || {
            crate::runtime::with_identity(&bi_arc, &did_owned, |_entry| {
                Err(ScpPyError::identity_with_code(
                    "device attestation unavailable: no production device-attestation \
                     backend is wired yet — Apple App Attest / Google Play Integrity are \
                     hardware/platform-backed and are intentionally deferred (with hardware \
                     keychain custody) until an e2e-driven integration lands (spec §9:187). \
                     See #2171."
                        .to_owned(),
                    scp_ffi_common::error_codes::IDENT_1015,
                ))
            })
        })
        .map_err(PyErr::from)
    }

    // -----------------------------------------------------------------------
    // Identity link attestation bridge (§3.5.1, §3.5.2)
    // -----------------------------------------------------------------------

    /// Creates an identity link attestation for an external platform identity.
    ///
    /// Constructs an `IdentityLinkAttestation` with a real Ed25519 signature
    /// from the identity's active signing key. The attestation is stored in the
    /// identity registry for retrieval via `identity_link_attestations`.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string of the attesting identity.
    /// * `platform` — Platform identifier (e.g., `"github.com"`, `"x.com"`).
    /// * `handle` — Handle on the platform (e.g., `"@alice"`, `"alice123"`).
    /// * `proof` — Method-specific proof data (e.g., OAuth JWT, post URL).
    /// * `verification_method` — One of `"oauth"`, `"signed_post"`,
    ///   `"dns_record"`, `"challenge_response"`.
    /// * `platform_id` — Optional platform-specific immutable user ID.
    ///
    /// # Returns
    ///
    /// JSON string of the created attestation.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the identity is not found, the verification
    /// method is invalid, or signing fails.
    ///
    /// See spec §3.5.1, §3.5.2.
    #[pyo3(signature = (did, platform, handle, proof, verification_method, platform_id=None))]
    #[allow(clippy::too_many_arguments)] // FFI surface: spec-defined signature
    pub fn create_identity_link_attestation(
        &self,
        py: Python<'_>,
        did: &str,
        platform: &str,
        handle: &str,
        proof: &str,
        verification_method: &str,
        platform_id: Option<&str>,
    ) -> PyResult<String> {
        use scp_platform::traits::KeyCustody;

        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(did)?;
        validate::validate_attestation_fields(platform, handle, proof)?;
        let did_owned = did.to_owned();
        let platform_owned = platform.to_owned();
        let handle_owned = handle.to_owned();
        let proof_owned = proof.to_owned();
        let method_owned = verification_method.to_owned();
        let platform_id_owned = platform_id.map(ToOwned::to_owned);
        let rt = crate::runtime()?;

        py.allow_threads(move || {
            // Phase 1: read custody + key handle (under DashMap lock, then drop).
            let (custody, key_handle) =
                crate::runtime::with_identity(&bi_arc, &did_owned, |entry| {
                    Ok((
                        Arc::clone(&entry.custody),
                        entry.identity.active_signing_key,
                    ))
                })?;

            // Build unsigned attestation using shared pipeline.
            let built = scp_ffi_common::attestation::build_unsigned_attestation(
                &did_owned,
                platform_owned,
                handle_owned,
                proof_owned,
                &method_owned,
                platform_id_owned,
            )
            .map_err(|e| ScpPyError::identity(e.to_string()))?;

            let mut attestation = built.attestation;

            // Phase 2: sign (no DashMap lock held — safe to block_on).
            let sig = rt
                .block_on(custody.sign(&key_handle, &built.canonical_bytes))
                .map_err(|e| ScpPyError::identity(format!("Ed25519 signing failed: {e}")))?;
            attestation.signature = sig.as_bytes().to_vec();

            // Phase 3: re-acquire lock, verify key unchanged (TOCTOU guard), store.
            crate::runtime::with_identity_mut(&bi_arc, &did_owned, |entry| {
                if entry.identity.active_signing_key != key_handle {
                    return Err(ScpPyError::identity(
                        "active signing key was rotated during attestation creation — \
                         please retry",
                    ));
                }

                if entry.identity_link_attestations.len() >= MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID
                {
                    return Err(ScpPyError::validation(format!(
                        "DID has reached the per-identity attestation limit \
                         ({MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID}) — cannot store additional attestations"
                    )));
                }
                entry.identity_link_attestations.push(attestation.clone());

                // Return as JSON.
                serde_json::to_string(&attestation).map_err(|e| {
                    ScpPyError::identity(format!("failed to serialize attestation: {e}"))
                })
            })
        })
        .map_err(PyErr::from)
    }

    /// Lists all identity link attestations for an identity.
    ///
    /// Returns a JSON array of all stored attestations for the given DID.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string to list attestations for.
    ///
    /// # Returns
    ///
    /// JSON string containing an array of attestation objects.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the identity is not found.
    ///
    /// See spec §3.5.1.
    pub fn identity_link_attestations(&self, py: Python<'_>, did: &str) -> PyResult<String> {
        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(did)?;
        let did_owned = did.to_owned();

        py.allow_threads(move || {
            crate::runtime::with_identity(&bi_arc, &did_owned, |entry| {
                serde_json::to_string(&entry.identity_link_attestations).map_err(|e| {
                    ScpPyError::identity(format!("failed to serialize attestations: {e}"))
                })
            })
        })
        .map_err(PyErr::from)
    }

    /// Removes an identity link attestation by its ID.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string of the attesting identity.
    /// * `attestation_id` — The deterministic attestation ID to remove.
    ///
    /// # Returns
    ///
    /// `True` if the attestation was found and removed, `False` otherwise.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if the identity is not found.
    ///
    /// See spec §3.5.1.
    pub fn remove_identity_link_attestation(
        &self,
        py: Python<'_>,
        did: &str,
        attestation_id: &str,
    ) -> PyResult<bool> {
        let bi_arc = Arc::clone(&self.inner);
        validate::validate_did(did)?;
        let did_owned = did.to_owned();
        let id_owned = attestation_id.to_owned();

        py.allow_threads(move || {
            crate::runtime::with_identity_mut(&bi_arc, &did_owned, |entry| {
                let before = entry.identity_link_attestations.len();
                entry
                    .identity_link_attestations
                    .retain(|a| a.id != id_owned);
                Ok(entry.identity_link_attestations.len() < before)
            })
        })
        .map_err(PyErr::from)
    }

    // -----------------------------------------------------------------------
    // Compromise recovery (§9.12) — fails closed pending the WIRE (#2240 Part B)
    // -----------------------------------------------------------------------

    /// Executes the compromise recovery protocol for the given DID (§9.12).
    ///
    /// # Fails closed (#2240)
    ///
    /// The §9.12 compromise-recovery WIRE (a real `RecoveryBackend` that rotates
    /// keys, revokes UCANs, rotates `KeyPackages`, notifies contacts, and
    /// rotates the PSK, plus step-1 key rotation) is not yet built — it needs
    /// custody / DID-method operations that are tracked as #2240 Part B and
    /// require human design sign-off. Until that backend is wired via the SDK
    /// layer, this surface **fails closed** with a typed `IdentityError`
    /// ("recovery backend not configured — provide a real backend via SDK
    /// layer"). It NEVER returns a fabricated success. The former inline
    /// always-`Ok` backend returned `key_rotation_completed: true` while
    /// rotating no key and revoking no token — a nullifier shipping a false
    /// guarantee on a security-critical operation, forbidden by the builder
    /// tenets. This mirrors the sibling
    /// [`Self::identity_execute_custody_migration`], which likewise fails closed
    /// via a `NotConfigured*Backend`.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string to recover.
    /// * `tier` — Compromise tier: `"agent"`, `"active_signing"`, or
    ///   `"identity_key"`.
    /// * `context_ids` — List of context IDs where the DID is a member.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` — an invalid `tier`, or (on any valid input) the
    /// fail-closed "recovery backend not configured" error.
    ///
    /// See spec §9.12 and issue #2240.
    #[pyo3(name = "identity_execute_recovery")]
    pub fn identity_execute_recovery(
        &self,
        did: &str,
        tier: &str,
        context_ids: Vec<String>,
    ) -> PyResult<String> {
        validate::validate_did(did)?;

        // Ownership gate (parity with the NAPI bridge's RED-PR5-003 check):
        // recovery is restricted to identities THIS SCP instance hosts in its
        // identity registry (populated by `identity_create*` / migrate, never by
        // `identity_load`, which only reads the registry and fails
        // `SCP-IDENT-1010` if the DID is absent).
        // A DID this instance does not own is rejected here — before any
        // recovery bookkeeping — so a realm-local caller cannot drive recovery
        // against arbitrary DIDs. `SCP-IDENT-1020` matches NAPI/UniFFI.
        if !crate::runtime::identity_registry_contains(&self.inner, did) {
            return Err(PyErr::from(ScpPyError::identity_with_code(
                format!(
                    "identity_execute_recovery: DID '{did}' is not owned by this SCP instance — \
                     recovery is restricted to identities registered on this instance (populated \
                     only by identity_create* / migrate, never by identity_load, on every \
                     binding). The ownership-registry keying mechanism differs across bindings \
                     (UniFFI custody registry vs PyO3/NAPI identity registry) and is unified in \
                     #2240 Part B."
                ),
                scp_ffi_common::error_codes::IDENT_1020,
            )));
        }

        // `context_ids` is accepted for FFI/SDK signature symmetry with the
        // eventual wired backend (#2240 Part B); it is unused on the
        // fail-closed path (cf. `let _ = old_did;` in recovery.rs). NAPI's
        // length-cap + libuv-worker concurrency gates bound the orchestrator
        // work that only runs once that backend lands, so they belong with the
        // Part B WIRE, not this fail-closed path.
        let _ = context_ids;

        // Validate the tier first so callers still get the precise invalid-tier
        // error rather than the generic fail-closed one.
        match tier {
            "agent" | "active_signing" | "identity_key" => {}
            other => {
                return Err(PyErr::from(ScpPyError::identity_with_code(
                    format!(
                        "invalid compromise tier: {other}; expected 'agent', 'active_signing', or 'identity_key'"
                    ),
                    scp_ffi_common::error_codes::IDENT_1021,
                )));
            }
        }

        // FAIL CLOSED (#2240): there is no configured recovery backend at the
        // FFI layer, and step 1 (real key rotation) cannot be performed here.
        // Unlike custody migration — whose orchestrator surfaces its
        // NotConfigured backend's first `Err` as a fatal error —
        // `CompromiseRecoveryOrchestrator::execute_recovery` isolates
        // per-context failures (§9.12) and never returns a fatal "backend
        // absent" error, so recovery must fail closed at the bridge boundary
        // before any `KeyRotationOutcome` / `RecoveryResult` is fabricated.
        Err(PyErr::from(ScpPyError::identity_with_code(
            "recovery backend not configured — provide a real backend via SDK layer",
            scp_ffi_common::error_codes::IDENT_1022,
        )))
    }

    // -----------------------------------------------------------------------
    // Custody migration — FFI exposure for CustodyMigrationOrchestrator
    // -----------------------------------------------------------------------

    /// Executes the custody migration protocol for the given DID.
    ///
    /// This method creates a `CustodyMigrationOrchestrator` and runs the
    /// 5-step migration protocol using an FFI backend that succeeds for all
    /// operations by default.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string to migrate.
    /// * `target` — Target custody type: `"platform_managed"`, `"hardware"`,
    ///   `"software"`, or `"in_memory"`.
    /// * `context_ids` — List of context IDs where the DID is a member.
    ///
    /// # Returns
    ///
    /// A JSON string with migration outcome fields.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if migration fails.
    ///
    /// See spec §3.2.1.
    #[pyo3(name = "identity_execute_custody_migration")]
    pub fn identity_execute_custody_migration(
        &self,
        py: Python<'_>,
        did: &str,
        target: &str,
        context_ids: Vec<String>,
    ) -> PyResult<String> {
        use scp_core::identity::custody_migration::{
            CustodyMigrationBackend, CustodyMigrationOrchestrator, CustodyMigrationRequest,
            CustodyMigrationTarget,
        };
        use scp_did::DID;

        validate::validate_did(did)?;
        let did_owned = did.to_owned();
        let target_owned = target.to_owned();
        let rt = crate::runtime()?;

        py.allow_threads(move || -> Result<String, ScpPyError> {
            let did_val = DID::from(did_owned.as_str());

            let migration_target = match target_owned.as_str() {
                "platform_managed" => CustodyMigrationTarget::PlatformManaged,
                "hardware" => CustodyMigrationTarget::Hardware,
                "software" => CustodyMigrationTarget::Software,
                "in_memory" => CustodyMigrationTarget::InMemory,
                other => {
                    return Err(ScpPyError::identity(format!(
                        "invalid custody migration target: {other}; expected 'platform_managed', 'hardware', 'software', or 'in_memory'"
                    )));
                }
            };

            // Error-returning backend — custody migration requires a real backend
            // provided via the SDK layer. This placeholder ensures callers get an
            // actionable error instead of silently succeeding with fake keys.
            struct NotConfiguredMigrationBackend;
            impl CustodyMigrationBackend for NotConfiguredMigrationBackend {
                fn generate_key(
                    &self,
                    _target: CustodyMigrationTarget,
                ) -> Result<Vec<u8>, String> {
                    Err("custody migration backend not configured — provide a real backend via SDK layer".to_owned())
                }
                fn authorize(&self, _request: &CustodyMigrationRequest) -> Result<(), String> {
                    Err("custody migration backend not configured — provide a real backend via SDK layer".to_owned())
                }
                fn rotate_did_document(
                    &self,
                    _did: &DID,
                    _request: &CustodyMigrationRequest,
                    _context_ids: &[String],
                ) -> Result<(Vec<String>, Vec<String>), String> {
                    Err("custody migration backend not configured — provide a real backend via SDK layer".to_owned())
                }
                fn reissue_credentials(
                    &self,
                    _did: &DID,
                    _request: &CustodyMigrationRequest,
                ) -> Result<(), String> {
                    Err("custody migration backend not configured — provide a real backend via SDK layer".to_owned())
                }
                fn destroy_old_key(&self, _did: &DID) -> Result<(), String> {
                    Err("custody migration backend not configured — provide a real backend via SDK layer".to_owned())
                }
            }

            let orchestrator =
                CustodyMigrationOrchestrator::new(did_val, migration_target, context_ids);
            let backend = NotConfiguredMigrationBackend;

            let result = rt
                .block_on(orchestrator.execute(&backend, &scp_clock::SystemClock))
                .map_err(|e| ScpPyError::identity(format!("custody migration failed: {e}")))?;

            // Serialize to JSON and return — the Python layer converts to dict.
            let json = serde_json::to_string(&result).map_err(|e| {
                ScpPyError::identity(format!(
                    "failed to serialize custody migration result: {e}"
                ))
            })?;
            Ok(json)
        })
        .map_err(PyErr::from)
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers identity bridge classes on the `_scp_core` module.
///
/// Stateful identity operations are methods on the `SCP` class (see the
/// `#[pymethods]` block above) and registered automatically with the
/// class. The opaque [`PyIdentity`] and [`PyDIDDocument`] classes plus the
/// pure verification helpers (`identity_verify_device_attestation`,
/// `verify_identity_link_attestation`) are registered manually here per
/// ADR-048 §1.
///
/// Called from the `_scp_core` module init function in `lib.rs`.
///
/// # Errors
///
/// Returns `PyErr` if adding classes or functions to the module fails.
pub fn register_identity(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyDIDDocument>()?;
    // Registered unconditionally: a `testing` build gets the real verifier, a
    // shipped build gets the fail-closed (IDENT_1016) free fn. Both cfg arms
    // define `identity_verify_device_attestation`, so the name always resolves.
    m.add_function(wrap_pyfunction!(identity_verify_device_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(verify_identity_link_attestation, m)?)?;
    Ok(())
}

#[cfg(all(test, feature = "testing"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Once;

    static TEST_INIT: Once = Once::new();

    fn setup() {
        TEST_INIT.call_once(|| {
            pyo3::prepare_freethreaded_python();
            crate::init_runtime().unwrap();
        });
    }

    fn default_scp() -> crate::scp::PyScp {
        crate::scp::PyScp::new_in_memory_for_test()
    }

    /// Verifies that `PyScp::identity_migrate` succeeds end-to-end.
    ///
    /// Before the fix (#777), identity migration used `DidDht::new()`
    /// which has no signer, causing DHT publish to fail. The fix wires
    /// `DidDht::with_client_and_signer` with `make_sign_fn` from the
    /// retained custody. This test calls the actual bridge method to
    /// confirm the signer is properly wired and migration produces a
    /// valid new identity.
    #[test]
    #[cfg(feature = "testing")]
    fn py_identity_migrate_succeeds_with_signer() {
        setup();

        Python::with_gil(|py| {
            let scp = default_scp();
            let bi = Arc::clone(&scp.inner);
            // Create an identity via the actual bridge method.
            let original = scp.identity_create(py, "in_memory", None).unwrap();
            let old_did = original.did.clone();
            assert!(old_did.starts_with("did:dht:"));
            assert!(crate::runtime::identity_registry_contains(&bi, &old_did));

            // Migrate to a new DID via the actual bridge method.
            let (migrated, rotation_event_json) = scp.identity_migrate(py, &original).unwrap();
            let new_did = migrated.did.clone();

            // New DID is a valid, distinct did:dht.
            assert!(new_did.starts_with("did:dht:"));
            assert_ne!(old_did, new_did);

            // Custody type is preserved.
            assert_eq!(migrated.custody, "in_memory");

            // Old identity removed from registry, new one registered.
            assert!(!crate::runtime::identity_registry_contains(&bi, &old_did));
            assert!(crate::runtime::identity_registry_contains(&bi, &new_did));

            // New identity's registry entry has a valid document.
            let doc_did =
                crate::runtime::with_identity(&bi, &new_did, |entry| Ok(entry.document.id.clone()))
                    .unwrap();
            assert_eq!(doc_did, new_did);

            // Rotation event JSON deserializes into the canonical
            // `DidRotationEvent` shape (spec §9.12, ADR-003 §4b/4c) so the
            // SDK can distribute it to context members per spec §9.12, ADR-003 §4b.
            let event: scp_did::DidRotationEvent =
                serde_json::from_str(&rotation_event_json).unwrap();
            assert_eq!(event.old_did, old_did);
            assert_eq!(event.new_did, new_did);
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
        });
    }
}
