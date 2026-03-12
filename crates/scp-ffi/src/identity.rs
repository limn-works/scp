//! `PyO3` bridge for identity operations.
//!
//! Exposes [`PyIdentity`] and [`PyDIDDocument`] as opaque Python objects with
//! attribute access, plus bridge functions for identity lifecycle:
//!
//! - [`py_identity_create`] — creates a new DID identity.
//! - [`py_identity_create_with_agent_key`] — creates a new DID identity with
//!   an agent signing key.
//! - [`py_identity_load`] — loads an existing identity from storage.
//! - [`py_identity_resolve`] — resolves a DID to its document.
//! - [`py_identity_rotate_key`] — rotates the identity's active signing key.
//! - [`py_identity_add_agent_key`] — adds an agent signing key to an identity.
//! - [`py_identity_rotate_agent_key`] — rotates the agent signing key.
//! - [`py_identity_remove_agent_key`] — removes the agent signing key.
//!
//! All async operations run on the shared tokio runtime via
//! [`crate::runtime()`]. The GIL is released during Rust async execution
//! via `py.allow_threads()` so Python threads are not blocked.
//!
//! # Opaque types
//!
//! [`PyIdentity`] stores the DID string and custody type — NOT the raw
//! [`ScpIdentity`](scp_identity::ScpIdentity), which contains
//! [`KeyHandle`](scp_platform::KeyHandle)s that are not safe to hold across
//! Python GIL boundaries. Crypto operations reconstruct state from stored
//! metadata when the full runtime is wired.
//!
//! [`PyDIDDocument`] wraps [`DidDocument`](scp_identity::DidDocument)
//! and exposes safe getters for the document's public fields.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` and ADR-039 for the full
//! specification.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use scp_identity::{
    DidCache, DidDht, DidDocument, DidMethod, DualLayerResolver, InMemoryDhtClient,
    NoOpRelayQuerier, ScpIdentity,
};
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::file::FileKeyCustody;
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::testing::InMemoryStorage;
use scp_platform::traits::{KeyCustody, Storage};

use crate::custody::FfiKeyCustody;
use crate::error::ScpPyError;
use crate::runtime::IdentityEntry;
use crate::validate;

/// Ensures the global production DID resolver is initialized.
///
/// Creates a `DualLayerResolver` backed by `InMemoryDhtClient` and
/// `NoOpRelayQuerier` (relay resolution will be upgraded when a production
/// relay querier is available). The resolver is shared across all UCAN
/// validation and attestation verification calls.
///
/// This is idempotent: subsequent calls are no-ops.
///
/// See #311 for the DID resolver unification design.
fn ensure_did_resolver_initialized(handle: tokio::runtime::Handle) {
    if crate::runtime::did_resolver().is_some() {
        return;
    }

    let dht_client = Arc::new(InMemoryDhtClient::new());
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
}

// ---------------------------------------------------------------------------
// PyIdentity — opaque Python object for SCP identity
// ---------------------------------------------------------------------------

/// An SCP identity handle exposed to Python.
///
/// Stores the DID string and custody type as safe, cloneable metadata.
/// Internal key material is NOT stored here — it remains within the
/// [`KeyCustody`](scp_platform::KeyCustody) boundary. Python code accesses
/// identity state through getter methods only.
///
/// # Python usage
///
/// ```python
/// identity = await py_identity_create("in_memory")
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
}

#[pymethods]
impl PyIdentity {
    /// Returns the DID string for this identity.
    #[getter]
    fn did(&self) -> &str {
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

    /// Returns the agent key's public key as a multibase-encoded string, or
    /// `None` if no agent key exists.
    ///
    /// The returned string is z-base-32 multibase-encoded (prefix `z`),
    /// matching the `publicKeyMultibase` field in the DID document.
    ///
    /// See ADR-039 acceptance criterion 19.
    fn get_agent_public_key(&self) -> PyResult<Option<String>> {
        crate::runtime::with_identity(&self.did, |entry| {
            Ok(entry
                .document
                .agent_verification_method()
                .map(|vm| vm.public_key_multibase.clone()))
        })
        .map_err(PyErr::from)
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
/// doc = await py_identity_resolve("did:dht:z...")
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

// ---------------------------------------------------------------------------
// Custody parsing helper
// ---------------------------------------------------------------------------

/// Parses a custody type string and returns an [`FfiKeyCustody`] instance.
///
/// Supported custody types:
///
/// - `"in_memory"` — Test-only in-memory custody. Keys are lost on process
///   exit. Only available when compiled with `cfg(feature = "testing")`.
/// - `"platform"` — Encrypted file-backed custody ([`FileKeyCustody`]) using
///   Argon2id + AES-256-GCM. This is the production default for desktop/server
///   platforms. Mobile platforms (iOS/Android) should use their native
///   `KeyCustodyProvider` callback interface via `UniFFI` instead.
///
/// The `"platform"` path creates a [`FileKeyCustody`] at a default location
/// (`$HOME/.scp/keys.bin`) with a passphrase from the `SCP_KEY_PASSPHRASE`
/// environment variable. If the variable is not set, an error is returned.
///
/// # Errors
///
/// Returns [`ScpPyError::ValidationError`] if:
/// - The custody string is not recognized.
/// - `"in_memory"` is requested but the `testing` feature is not enabled.
/// - `"platform"` is requested but `SCP_KEY_PASSPHRASE` is not set.
/// - [`FileKeyCustody`] initialization fails (I/O error, corrupt key file).
///
/// See issue #323 and ADR-006.
fn parse_custody(custody: &str) -> Result<(Arc<FfiKeyCustody>, String), ScpPyError> {
    match custody {
        #[cfg(feature = "allow_in_memory_custody")]
        "in_memory" => {
            let kc = Arc::new(FfiKeyCustody::InMemory(InMemoryKeyCustody::new()));
            Ok((kc, custody.to_owned()))
        }
        #[cfg(not(feature = "allow_in_memory_custody"))]
        "in_memory" => Err(ScpPyError::validation(
            "in_memory custody is not available in this build -- enable the              allow_in_memory_custody feature for dev/desktop use",
        )),
        "platform" => {
            let passphrase = std::env::var("SCP_KEY_PASSPHRASE").map_err(|_| {
                ScpPyError::validation(
                    "platform custody requires the SCP_KEY_PASSPHRASE environment \
                     variable to be set — this passphrase protects the encrypted key file",
                )
            })?;

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

            Ok((Arc::new(FfiKeyCustody::File(file_kc)), custody.to_owned()))
        }
        other => Err(ScpPyError::validation(format!(
            "unknown custody type: {other:?} — expected \"in_memory\" or \"platform\""
        ))),
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
/// Uses a simple `did\ncustody` text format. When `ProtocolStore`'s identity
/// module lands (spec 17.4), this will migrate to `StoredValue<T>` with
/// `MessagePack` serialization.
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

// ---------------------------------------------------------------------------
// Storage initialization bridge function
// ---------------------------------------------------------------------------

/// Initializes the global storage provider for identity persistence.
///
/// Must be called before `py_identity_create` or `py_identity_load` if
/// storage persistence is desired. The storage provider follows the same
/// injection pattern as the runtime registry (global `OnceLock`).
///
/// # Arguments
///
/// * `storage_type` — The storage backend type: `"in_memory"`.
///
/// # Errors
///
/// Raises `ValidationError` if the storage type is not recognized.
///
/// See SCP-217 and spec section 17.4.
#[pyfunction]
fn py_init_storage(storage_type: &str) -> PyResult<()> {
    crate::runtime::init_storage(storage_type).map_err(PyErr::from)
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

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
/// If a storage provider has been initialized via [`py_init_storage`],
/// the identity state (DID, custody type) is persisted under the key
/// `identity/{did}/state` after successful creation (SCP-217).
///
/// See ADR-013 acceptance criterion 2.
#[pyfunction]
fn py_identity_create(py: Python<'_>, custody: &str) -> PyResult<PyIdentity> {
    let (key_custody, custody_str) = parse_custody(custody)?;
    let rt = crate::runtime()?;

    // Ensure the global DID resolver is initialized (idempotent). #311
    ensure_did_resolver_initialized(rt.handle().clone());

    py.allow_threads(|| {
        rt.block_on(async {
            let did_method = DidDht::new();
            let (identity, document) = did_method
                .create(key_custody.as_ref())
                .await
                .map_err(ScpPyError::from)?;

            let did = identity.did.clone();

            // Register the identity in the global registry so that
            // subsequent bridge functions (UCAN minting, pseudonym
            // derivation, signing, key rotation) can access the retained
            // KeyCustody and KeyHandle references. See SCP-214 criterion 3.
            crate::runtime::register_identity(
                &did,
                IdentityEntry {
                    identity,
                    custody: key_custody,
                    document,
                },
            );

            // Persist identity state if storage is initialized (SCP-217).
            // Bind to concrete type to resolve method ambiguity with the
            // Arc<T>: Storage blanket impl (issue #329).
            if let Ok(arc_storage) = crate::runtime::get_storage() {
                let s: &EncryptingAdapter<InMemoryStorage> = arc_storage.as_ref();
                let key = identity_state_key(&did);
                let data = serialize_identity_state(&did, &custody_str);
                s.store(&key, &data).await.map_err(|e| {
                    ScpPyError::identity(format!("failed to persist identity state: {e}"))
                })?;
            }

            Ok(PyIdentity {
                did,
                custody: custody_str,
                has_agent_key: false,
            })
        })
    })
}

/// Creates a new DID identity with an agent signing key.
///
/// Like [`py_identity_create`], but the resulting identity also has an
/// `#agent` verification method in its DID document.
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
#[pyfunction]
fn py_identity_create_with_agent_key(py: Python<'_>, custody: &str) -> PyResult<PyIdentity> {
    let (key_custody, custody_str) = parse_custody(custody)?;
    let rt = crate::runtime()?;

    // Ensure the global DID resolver is initialized (idempotent). #311
    ensure_did_resolver_initialized(rt.handle().clone());

    py.allow_threads(|| {
        rt.block_on(async {
            let did_method = DidDht::new();
            let (identity, document) = did_method
                .create_with_agent_key(key_custody.as_ref())
                .await
                .map_err(ScpPyError::from)?;

            let did = identity.did.clone();

            crate::runtime::register_identity(
                &did,
                IdentityEntry {
                    identity,
                    custody: key_custody,
                    document,
                },
            );

            // Persist identity state if storage is initialized (SCP-217).
            // Bind to concrete type to resolve method ambiguity with the
            // Arc<T>: Storage blanket impl (issue #329).
            if let Ok(arc_storage) = crate::runtime::get_storage() {
                let s: &EncryptingAdapter<InMemoryStorage> = arc_storage.as_ref();
                let key = identity_state_key(&did);
                let data = serialize_identity_state(&did, &custody_str);
                s.store(&key, &data).await.map_err(|e| {
                    ScpPyError::identity(format!("failed to persist identity state: {e}"))
                })?;
            }

            Ok(PyIdentity {
                did,
                custody: custody_str,
                has_agent_key: true,
            })
        })
    })
}

/// Loads an existing identity from storage.
///
/// Retrieves persisted identity state (DID, custody type) from the storage
/// provider and returns a [`PyIdentity`] only if the identity has live
/// crypto state in the runtime registry.
///
/// If the identity was created in this process (via `py_identity_create`),
/// it will be in the registry and this function succeeds. If the identity
/// was created in a different process with in-memory custody, the key
/// material is lost and this function returns `SCP-IDENT-1010`. File-backed
/// custody persists across restarts if the same passphrase is provided.
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
/// - Storage has not been initialized (call `py_init_storage` first).
/// - The DID is not found in storage.
/// - The stored state is malformed.
/// - The identity has no live crypto state in the registry
///   (`SCP-IDENT-1010`). This happens when loading an identity created
///   in a different process with in-memory custody (which does not
///   persist key material). File-backed custody survives restarts.
///
/// Does NOT silently fall back to in-memory -- an explicit error is raised
/// if the DID is not found (SCP-217 acceptance criterion 4).
///
/// See SCP-217, spec section 17.3, and RED-013.
#[pyfunction]
fn py_identity_load(py: Python<'_>, did: &str) -> PyResult<PyIdentity> {
    validate::validate_did(did)?;
    let did_owned = did.to_owned();
    let rt = crate::runtime()?;

    py.allow_threads(|| {
        if !did_owned.starts_with("did:dht:") {
            return Err(PyErr::from(ScpPyError::identity(format!(
                "unsupported DID method: {did_owned} -- only did:dht is supported"
            ))));
        }

        let arc_storage = crate::runtime::get_storage().map_err(PyErr::from)?;

        rt.block_on(async {
            let key = identity_state_key(&did_owned);
            // Bind to concrete type to resolve method ambiguity with the
            // Arc<T>: Storage blanket impl (issue #329).
            let s: &EncryptingAdapter<InMemoryStorage> = arc_storage.as_ref();
            let data = s
                .retrieve(&key)
                .await
                .map_err(|e| {
                    ScpPyError::identity(format!("failed to read identity state from storage: {e}"))
                })?
                .ok_or_else(|| {
                    ScpPyError::identity(format!(
                        "identity not found in storage: {did_owned} -- \
                     was it created with py_identity_create?"
                    ))
                })?;

            let (stored_did, custody_str) = deserialize_identity_state(&data)?;

            if stored_did != did_owned {
                return Err(PyErr::from(ScpPyError::identity(format!(
                    "stored DID mismatch: expected {did_owned}, found {stored_did}"
                ))));
            }

            // SCP-IDENT-1010: Verify the identity has live crypto state
            // in the registry. Without this check, the returned PyIdentity
            // would be a dangling handle -- subsequent bridge functions
            // (UCAN minting, signing, pseudonym derivation, key rotation)
            // would fail with "identity not found in registry" (RED-013).
            if crate::runtime::identity_registry_contains(&did_owned) {
                let has_agent = crate::runtime::with_identity(&did_owned, |entry| {
                    Ok(entry.document.has_agent_key())
                })
                .unwrap_or(false);
                return Ok(PyIdentity {
                    did: stored_did,
                    custody: custody_str,
                    has_agent_key: has_agent,
                });
            }

            Err(PyErr::from(ScpPyError::identity(format!(
                "SCP-IDENT-1010: identity '{did_owned}' was found in storage \
                 but has no live crypto state in the runtime registry. \
                 If using in-memory custody, key material does not persist \
                 across process boundaries. Use py_identity_create to create \
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
#[pyfunction]
fn py_identity_resolve(py: Python<'_>, did: &str) -> PyResult<PyDIDDocument> {
    validate::validate_did(did)?;
    let did_owned = did.to_owned();
    let rt = crate::runtime()?;

    py.allow_threads(|| {
        rt.block_on(async {
            let did_method = DidDht::new();
            let document = did_method
                .resolve(&did_owned)
                .await
                .map_err(ScpPyError::from)?;

            Ok(PyDIDDocument { inner: document })
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
#[pyfunction]
fn py_identity_rotate_key(py: Python<'_>, identity: &PyIdentity) -> PyResult<PyIdentity> {
    let did = identity.did.clone();
    let custody_str = identity.custody.clone();
    let rt = crate::runtime()?;

    let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
        crate::runtime::with_identity_mut(&did, |entry| {
            let sign_fn =
                DidDht::<InMemoryDhtClient, scp_identity::cache::SystemClock>::make_sign_fn(
                    Arc::clone(&entry.custody),
                );
            let did_method = DidDht::with_client_and_signer(
                Arc::new(InMemoryDhtClient::new()),
                Arc::new(DidCache::new()),
                sign_fn,
            );

            let rotation_result = rt.block_on(async {
                did_method
                    .rotate_active_key(&entry.identity, &entry.document, entry.custody.as_ref())
                    .await
            });

            let (new_identity, new_document) = rotation_result.map_err(ScpPyError::from)?;
            let has_agent = new_document.has_agent_key();
            entry.identity = new_identity;
            entry.document = new_document;

            Ok(PyIdentity {
                did: did.clone(),
                custody: custody_str.clone(),
                has_agent_key: has_agent,
            })
        })
    });
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
#[pyfunction]
fn py_identity_add_agent_key(py: Python<'_>, identity: &PyIdentity) -> PyResult<PyIdentity> {
    let did = identity.did.clone();
    let custody_str = identity.custody.clone();
    let rt = crate::runtime()?;

    let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
        crate::runtime::with_identity_mut(&did, |entry| {
            let sign_fn =
                DidDht::<InMemoryDhtClient, scp_identity::cache::SystemClock>::make_sign_fn(
                    Arc::clone(&entry.custody),
                );
            let did_method = DidDht::with_client_and_signer(
                Arc::new(InMemoryDhtClient::new()),
                Arc::new(DidCache::new()),
                sign_fn,
            );

            let add_result = rt.block_on(async {
                did_method
                    .add_agent_key(&entry.identity, &entry.document, entry.custody.as_ref())
                    .await
            });

            let (new_identity, new_document) = add_result.map_err(ScpPyError::from)?;
            entry.identity = new_identity;
            entry.document = new_document;

            Ok(PyIdentity {
                did: did.clone(),
                custody: custody_str.clone(),
                has_agent_key: true,
            })
        })
    });
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
#[pyfunction]
fn py_identity_rotate_agent_key(py: Python<'_>, identity: &PyIdentity) -> PyResult<PyIdentity> {
    let did = identity.did.clone();
    let custody_str = identity.custody.clone();
    let rt = crate::runtime()?;

    let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
        crate::runtime::with_identity_mut(&did, |entry| {
            let sign_fn =
                DidDht::<InMemoryDhtClient, scp_identity::cache::SystemClock>::make_sign_fn(
                    Arc::clone(&entry.custody),
                );
            let did_method = DidDht::with_client_and_signer(
                Arc::new(InMemoryDhtClient::new()),
                Arc::new(DidCache::new()),
                sign_fn,
            );

            let rotate_result = rt.block_on(async {
                did_method
                    .rotate_agent_key(&entry.identity, &entry.document, entry.custody.as_ref())
                    .await
            });

            let (new_identity, new_document) = rotate_result.map_err(ScpPyError::from)?;
            entry.identity = new_identity;
            entry.document = new_document;

            Ok(PyIdentity {
                did: did.clone(),
                custody: custody_str.clone(),
                has_agent_key: true,
            })
        })
    });
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
#[pyfunction]
fn py_identity_remove_agent_key(py: Python<'_>, identity: &PyIdentity) -> PyResult<PyIdentity> {
    let did = identity.did.clone();
    let custody_str = identity.custody.clone();
    let rt = crate::runtime()?;

    let result: Result<PyIdentity, ScpPyError> = py.allow_threads(|| {
        crate::runtime::with_identity_mut(&did, |entry| {
            let sign_fn =
                DidDht::<InMemoryDhtClient, scp_identity::cache::SystemClock>::make_sign_fn(
                    Arc::clone(&entry.custody),
                );
            let did_method = DidDht::with_client_and_signer(
                Arc::new(InMemoryDhtClient::new()),
                Arc::new(DidCache::new()),
                sign_fn,
            );

            let remove_result = rt.block_on(async {
                did_method
                    .remove_agent_key(&entry.identity, &entry.document)
                    .await
            });

            let (new_identity, new_document) = remove_result.map_err(ScpPyError::from)?;
            entry.identity = new_identity;
            entry.document = new_document;

            Ok(PyIdentity {
                did: did.clone(),
                custody: custody_str.clone(),
                has_agent_key: false,
            })
        })
    });
    result.map_err(PyErr::from)
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
#[pyfunction]
fn py_identity_migrate(py: Python<'_>, identity: &PyIdentity) -> PyResult<PyIdentity> {
    let old_did = identity.did.clone();
    let custody_str = identity.custody.clone();
    let rt = crate::runtime()?;

    py.allow_threads(|| {
        rt.block_on(async {
            // Extract what we need from the registry entry.
            let (
                custody,
                old_identity_key,
                old_active_key,
                old_agent_key,
                pre_rotation_commitment,
                old_doc,
            ) = crate::runtime::with_identity(&old_did, |entry| {
                Ok((
                    Arc::clone(&entry.custody),
                    entry.identity.identity_key,
                    entry.identity.active_signing_key,
                    entry.identity.agent_signing_key,
                    entry.identity.pre_rotation_commitment,
                    entry.document.clone(),
                ))
            })?;

            // We need a pre-rotation key handle. Generate one for the
            // migration — in a full implementation, the pre-rotation key
            // would have been generated and stored during identity creation.
            // The custody provider already holds the pre-rotation key from
            // the original create call (handle = identity_key + 2, following
            // the sequential handle allocation in DidDht::create).
            //
            // For now, generate a fresh pre-rotation key. The migrate_identity
            // method uses it as the new Identity Key.
            let pre_rotation_key = custody
                .generate_keypair(scp_platform::traits::KeyType::Ed25519)
                .await
                .map_err(|e| ScpPyError::identity(format!("key generation failed: {e}")))?;

            let rotated_at =
                scp_core::time::now_secs().map_err(|e| ScpPyError::identity(format!("{e}")))?;

            let old_identity = ScpIdentity {
                identity_key: old_identity_key,
                active_signing_key: old_active_key,
                agent_signing_key: old_agent_key,
                pre_rotation_commitment,
                did: old_did.clone(),
            };

            let sign_fn =
                DidDht::<InMemoryDhtClient, scp_identity::cache::SystemClock>::make_sign_fn(
                    Arc::clone(&custody),
                );
            let did_method = DidDht::with_client_and_signer(
                Arc::new(InMemoryDhtClient::new()),
                Arc::new(DidCache::new()),
                sign_fn,
            );
            let (new_identity, new_document, _rotation_event) = did_method
                .migrate_identity(
                    &old_identity,
                    &old_doc,
                    &pre_rotation_key,
                    custody.as_ref(),
                    rotated_at,
                )
                .await
                .map_err(ScpPyError::from)?;

            let new_did = new_identity.did.clone();
            let has_agent = new_document.has_agent_key();

            // Remove old identity and register the new one.
            crate::runtime::remove_identity(&old_did);
            crate::runtime::register_identity(
                &new_did,
                IdentityEntry {
                    identity: new_identity,
                    custody,
                    document: new_document,
                },
            );
            Ok(PyIdentity {
                did: new_did,
                custody: custody_str,
                has_agent_key: has_agent,
            })
        })
    })
}

// ---------------------------------------------------------------------------
// Device attestation bridge (#362)
// ---------------------------------------------------------------------------

/// Generates a device attestation token for an identity.
///
/// Uses [`InMemoryDeviceAttestation`] (available only with
/// `allow_in_memory_custody` feature) to produce a synthetic attestation
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
/// See §9.3, issue #362.
#[pyfunction]
#[cfg(feature = "allow_in_memory_custody")]
fn py_identity_attest_device(py: Python<'_>, identity_did: &str) -> PyResult<String> {
    validate::validate_did(identity_did)?;
    let did_owned = identity_did.to_owned();
    let rt = crate::runtime()?;

    py.allow_threads(|| {
        crate::runtime::with_identity_mut(&did_owned, |entry| {
            let attestation = scp_platform::testing::InMemoryDeviceAttestation::new();
            let dht = DidDht::new();

            let new_document = rt
                .block_on(async {
                    dht.attach_device_attestation(&entry.document, &attestation)
                        .await
                })
                .map_err(|e| ScpPyError::identity(format!("device attestation failed: {e}")))?;

            // Extract the attestation token from the updated document's
            // service entries.
            let token_bytes = new_document
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

            use base64::Engine;
            Ok(base64::engine::general_purpose::STANDARD.encode(token_bytes.as_bytes()))
        })
    })
    .map_err(PyErr::from)
}

/// Verifies a device attestation token.
///
/// Uses [`InMemoryDeviceAttestation`] to check the token format.
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
/// See §9.3, issue #362.
#[pyfunction]
#[cfg(feature = "allow_in_memory_custody")]
fn py_identity_verify_device_attestation(
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

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers identity bridge classes and functions on the `_scp_core` module.
///
/// Called from the `_scp_core` module init function in `lib.rs`.
///
/// # Errors
///
/// Returns `PyErr` if adding classes or functions to the module fails.
pub fn register_identity(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyDIDDocument>()?;
    m.add_function(wrap_pyfunction!(py_init_storage, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_create, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_create_with_agent_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_load, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_resolve, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_rotate_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_add_agent_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_rotate_agent_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_remove_agent_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_migrate, m)?)?;
    // Device attestation (#362)
    #[cfg(feature = "allow_in_memory_custody")]
    {
        m.add_function(wrap_pyfunction!(py_identity_attest_device, m)?)?;
        m.add_function(wrap_pyfunction!(py_identity_verify_device_attestation, m)?)?;
    }
    Ok(())
}
