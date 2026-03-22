//! `PyO3` bridge for identity operations.
//!
//! Exposes [`PyIdentity`] and [`PyDIDDocument`] as opaque Python objects with
//! attribute access, plus bridge functions for identity lifecycle:
//!
//! - `py_identity_create` — creates a new DID identity.
//! - `py_identity_create_with_agent_key` — creates a new DID identity with
//!   an agent signing key.
//! - `py_identity_load` — loads an existing identity from storage.
//! - `py_identity_resolve` — resolves a DID to its document.
//! - `py_identity_rotate_key` — rotates the identity's active signing key.
//! - `py_identity_add_agent_key` — adds an agent signing key to an identity.
//! - `py_identity_rotate_agent_key` — rotates the agent signing key.
//! - `py_identity_remove_agent_key` — removes the agent signing key.
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
use scp_primitives::Clock;

use crate::custody::FfiKeyCustody;
use crate::error::ScpPyError;
use crate::runtime::IdentityEntry;
use crate::validate;

use scp_ffi_common::validate::MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID;

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
/// [`KeyCustody`] boundary. Python code accesses
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
        other => Err(ScpPyError::validation(format!(
            "unknown custody type: {other:?} — expected \"in_memory\", \"file\", or \"platform\""
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
/// Uses a simple `did\ncustody` text format. When `ProtocolRepository`'s identity
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
                    identity_link_attestations: Vec::new(),
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
                    identity_link_attestations: Vec::new(),
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

            let rotated_at = scp_primitives::SystemClock.now_secs();

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

            // Preserve existing attestations from the old DID across migration.
            let existing_attestations = crate::runtime::with_identity(&old_did, |e| {
                Ok(e.identity_link_attestations.clone())
            })
            .unwrap_or_default();

            // Remove old identity and register the new one.
            crate::runtime::remove_identity(&old_did);
            crate::runtime::register_identity(
                &new_did,
                IdentityEntry {
                    identity: new_identity,
                    custody,
                    document: new_document,
                    identity_link_attestations: existing_attestations,
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
// Identity link attestation bridge (§3.5.1, §3.5.2)
// ---------------------------------------------------------------------------

/// Creates an identity link attestation for an external platform identity.
///
/// Constructs an [`IdentityLinkAttestation`] with a real Ed25519 signature
/// from the identity's active signing key. The attestation is stored in the
/// identity registry for retrieval via `py_identity_link_attestations`.
///
/// # Arguments
///
/// * `did` — The DID string of the attesting identity.
/// * `platform` — Platform identifier (e.g., `"github.com"`, `"x.com"`).
/// * `handle` — Handle on the platform (e.g., `"@alice"`, `"alice123"`).
/// * `proof` — Method-specific proof data (e.g., OAuth JWT, post URL).
/// * `verification_method` — One of `"oauth"`, `"signed_post"`, `"dns_record"`,
///   `"challenge_response"`.
/// * `platform_id` — Optional platform-specific immutable user ID.
///
/// # Returns
///
/// JSON string of the created attestation.
///
/// # Errors
///
/// Raises `IdentityError` if the identity is not found, the verification method
/// is invalid, or signing fails.
///
/// See spec §3.5.1, §3.5.2.
#[pyfunction]
#[pyo3(signature = (did, platform, handle, proof, verification_method, platform_id=None))]
fn py_create_identity_link_attestation(
    py: Python<'_>,
    did: &str,
    platform: &str,
    handle: &str,
    proof: &str,
    verification_method: &str,
    platform_id: Option<&str>,
) -> PyResult<String> {
    use std::borrow::Cow;

    use scp_core::identity::attestation::{
        ATTESTATION_TYPE_IDENTITY_LINK, AttestationClaim, AttestationEvidence,
        IdentityLinkAttestation, VerificationMethod,
    };
    use scp_core::trust::attestation::RevocationStatus;
    use scp_identity::DID;
    use scp_platform::traits::KeyCustody;

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
        let method: VerificationMethod = method_owned.parse().map_err(ScpPyError::identity)?;

        // Proof is an opaque string per §3.5.2 — pass through as-is.
        // Do not parse and re-serialize.

        // Phase 1: read custody + key handle (under DashMap lock, then drop).
        let (custody, key_handle) = crate::runtime::with_identity(&did_owned, |entry| {
            Ok((
                Arc::clone(&entry.custody),
                entry.identity.active_signing_key,
            ))
        })?;

        let issuer = DID::from(did_owned.as_str());
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ScpPyError::identity("system clock is before UNIX epoch"))?
            .as_secs();

        let id =
            IdentityLinkAttestation::compute_id(&issuer, &platform_owned, &handle_owned, now_secs);

        // Build the attestation with a placeholder signature.
        let mut attestation = IdentityLinkAttestation {
            id,
            attestation_type: Cow::Borrowed(ATTESTATION_TYPE_IDENTITY_LINK),
            issuer: issuer.clone(),
            subject: issuer,
            issued_at: now_secs,
            expires_at: None,
            claim: AttestationClaim::new(platform_owned, handle_owned, platform_id_owned),
            evidence: AttestationEvidence {
                method,
                proof: proof_owned,
                verified_at: now_secs,
                verifier_did: None,
            },
            revocation_status: RevocationStatus::Active,
            signature: Vec::new(),
        };

        // Structural validation before signing.
        let structure_errors = attestation.validate_structure();
        if !structure_errors.is_empty() {
            return Err(ScpPyError::identity(format!(
                "attestation structure validation failed: {}",
                structure_errors
                    .iter()
                    .map(AsRef::as_ref)
                    .collect::<Vec<_>>()
                    .join("; "),
            )));
        }

        // Compute canonical bytes and sign with active signing key.
        let canonical = attestation
            .canonical_signing_bytes()
            .map_err(|e| ScpPyError::identity(format!("attestation signing failed: {e}")))?;

        // Phase 2: sign (no DashMap lock held — safe to block_on).
        let sig = rt
            .block_on(custody.sign(&key_handle, &canonical))
            .map_err(|e| ScpPyError::identity(format!("Ed25519 signing failed: {e}")))?;
        attestation.signature = sig.as_bytes().to_vec();

        // Phase 3: re-acquire lock, verify key unchanged (TOCTOU guard), store.
        crate::runtime::with_identity_mut(&did_owned, |entry| {
            if entry.identity.active_signing_key != key_handle {
                return Err(ScpPyError::identity(
                    "active signing key was rotated during attestation creation — \
                     please retry",
                ));
            }

            if entry.identity_link_attestations.len() >= MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID {
                return Err(ScpPyError::validation(format!(
                    "DID has reached the per-identity attestation limit \
                     ({MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID}) — cannot store additional attestations"
                )));
            }
            entry.identity_link_attestations.push(attestation.clone());

            // Return as JSON.
            serde_json::to_string(&attestation)
                .map_err(|e| ScpPyError::identity(format!("failed to serialize attestation: {e}")))
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
/// See spec §3.5.1.
#[pyfunction]
fn py_identity_link_attestations(py: Python<'_>, did: &str) -> PyResult<String> {
    validate::validate_did(did)?;
    let did_owned = did.to_owned();

    py.allow_threads(move || {
        crate::runtime::with_identity(&did_owned, |entry| {
            serde_json::to_string(&entry.identity_link_attestations)
                .map_err(|e| ScpPyError::identity(format!("failed to serialize attestations: {e}")))
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
/// See spec §3.5.1.
#[pyfunction]
fn py_remove_identity_link_attestation(
    py: Python<'_>,
    did: &str,
    attestation_id: &str,
) -> PyResult<bool> {
    validate::validate_did(did)?;
    let did_owned = did.to_owned();
    let id_owned = attestation_id.to_owned();

    py.allow_threads(move || {
        crate::runtime::with_identity_mut(&did_owned, |entry| {
            let before = entry.identity_link_attestations.len();
            entry
                .identity_link_attestations
                .retain(|a| a.id != id_owned);
            Ok(entry.identity_link_attestations.len() < before)
        })
    })
    .map_err(PyErr::from)
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
/// * `issuer_public_key_hex` — Hex-encoded Ed25519 public key of the issuer.
///
/// # Returns
///
/// `True` if the signature is valid, `False` otherwise.
///
/// # Errors
///
/// Raises `IdentityError` if the JSON is malformed or the hex key is invalid.
///
/// See spec §3.5.1.
#[pyfunction]
#[pyo3(name = "py_verify_identity_link_attestation")]
fn py_verify_identity_link_attestation(
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
// Compromise recovery — FFI exposure for CompromiseRecoveryOrchestrator
// ---------------------------------------------------------------------------

/// Executes the compromise recovery protocol for the given DID.
///
/// This function creates a [`CompromiseRecoveryOrchestrator`] and a mock
/// [`RecoveryBackend`] and runs the 6-step recovery protocol. Step 1 (key
/// rotation) is represented by the caller-provided `tier` and
/// `rotated_key_scopes`.
///
/// # Arguments
///
/// * `did` — The DID string to recover.
/// * `tier` — Compromise tier: `"agent"`, `"active_signing"`, or
///   `"identity_key"`.
/// * `context_ids` — List of context IDs where the DID is a member.
///
/// # Returns
///
/// A dict with recovery outcome fields.
///
/// See spec §9.12 and PR #1080.
#[pyfunction]
#[pyo3(name = "identity_execute_recovery")]
fn py_identity_execute_recovery(
    py: Python<'_>,
    did: &str,
    tier: &str,
    context_ids: Vec<String>,
) -> PyResult<String> {
    use std::collections::HashSet;

    use scp_core::identity::recovery::{
        CompromiseRecoveryOrchestrator, CompromiseTier, KeyRotationOutcome, PskRotationParams,
        RecoveryBackend, RecoveryStepError, active_key_rotation_outcome,
        agent_key_rotation_outcome,
    };
    use scp_identity::DID;

    validate::validate_did(did)?;
    let did_owned = did.to_owned();
    let tier_owned = tier.to_owned();
    let rt = crate::runtime()?;

    py.allow_threads(move || -> Result<String, ScpPyError> {
        let did_val = DID::from(did_owned.as_str());

        let compromise_tier = match tier_owned.as_str() {
            "agent" => CompromiseTier::Agent,
            "active_signing" => CompromiseTier::ActiveSigning,
            "identity_key" => CompromiseTier::IdentityKey,
            other => {
                return Err(ScpPyError::identity(format!(
                    "invalid compromise tier: {other}; expected 'agent', 'active_signing', or 'identity_key'"
                )));
            }
        };

        // Build key rotation outcome (step 1 is pre-completed by caller).
        let now_ms = scp_primitives::SystemClock.now_millis();
        let key_rotation = match compromise_tier {
            CompromiseTier::Agent => agent_key_rotation_outcome(&did_val, now_ms),
            CompromiseTier::ActiveSigning => active_key_rotation_outcome(&did_val, now_ms),
            CompromiseTier::IdentityKey => {
                // Identity key migration creates a new DID; for FFI exposure
                // we use the same DID as a placeholder since the caller
                // manages the actual DID migration externally.
                scp_core::identity::recovery::identity_key_rotation_outcome(
                    &did_val,
                    did_val.clone(),
                    now_ms,
                )
            }
        };

        // Use a simple backend that succeeds for all operations.
        struct FfiRecoveryBackend;
        impl RecoveryBackend for FfiRecoveryBackend {
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
        let backend = FfiRecoveryBackend;

        let result = rt.block_on(orchestrator.execute_recovery(
            compromise_tier,
            &key_rotation,
            &contacts,
            None,
            &backend,
            &scp_primitives::SystemClock,
        )).map_err(|e| ScpPyError::identity(format!("recovery failed: {e}")))?;

        // Serialize to JSON and return — the Python layer converts to dict.
        let json = serde_json::to_string(&result)
            .map_err(|e| ScpPyError::identity(format!("failed to serialize recovery result: {e}")))?;
        Ok(json)
    })
    .map_err(PyErr::from)
}

// ---------------------------------------------------------------------------
// Custody migration — FFI exposure for CustodyMigrationOrchestrator
// ---------------------------------------------------------------------------

/// Executes the custody migration protocol for the given DID.
///
/// This function creates a [`CustodyMigrationOrchestrator`] and runs the
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
/// A dict with migration outcome fields.
///
/// See spec §3.2.1.
#[pyfunction]
#[pyo3(name = "identity_execute_custody_migration")]
fn py_identity_execute_custody_migration(
    py: Python<'_>,
    did: &str,
    target: &str,
    context_ids: Vec<String>,
) -> PyResult<String> {
    use scp_core::identity::custody_migration::{
        CustodyMigrationBackend, CustodyMigrationOrchestrator, CustodyMigrationRequest,
        CustodyMigrationTarget,
    };
    use scp_identity::DID;

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
            fn generate_key(&self, _target: CustodyMigrationTarget) -> Result<Vec<u8>, String> {
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

        let result = rt.block_on(orchestrator.execute(&backend, &scp_primitives::SystemClock)).map_err(|e| {
            ScpPyError::identity(format!("custody migration failed: {e}"))
        })?;

        // Serialize to JSON and return — the Python layer converts to dict.
        let json = serde_json::to_string(&result)
            .map_err(|e| ScpPyError::identity(format!(
                "failed to serialize custody migration result: {e}"
            )))?;
        Ok(json)
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
    // Recovery and custody migration (#632)
    m.add_function(wrap_pyfunction!(py_identity_execute_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_execute_custody_migration, m)?)?;
    // Device attestation (#362)
    #[cfg(feature = "allow_in_memory_custody")]
    {
        m.add_function(wrap_pyfunction!(py_identity_attest_device, m)?)?;
        m.add_function(wrap_pyfunction!(py_identity_verify_device_attestation, m)?)?;
    }
    // Identity link attestation (§3.5.1)
    m.add_function(wrap_pyfunction!(py_create_identity_link_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_link_attestations, m)?)?;
    m.add_function(wrap_pyfunction!(py_remove_identity_link_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_identity_link_attestation, m)?)?;
    Ok(())
}

#[cfg(test)]
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

    /// Verifies that `py_identity_migrate` succeeds end-to-end.
    ///
    /// Before the fix (#777), `py_identity_migrate` used `DidDht::new()`
    /// which has no signer, causing DHT publish to fail. The fix wires
    /// `DidDht::with_client_and_signer` with `make_sign_fn` from the
    /// retained custody. This test calls the actual bridge function to
    /// confirm the signer is properly wired and migration produces a
    /// valid new identity.
    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn py_identity_migrate_succeeds_with_signer() {
        setup();

        Python::with_gil(|py| {
            // Create an identity via the actual bridge function.
            let original = py_identity_create(py, "in_memory").unwrap();
            let old_did = original.did.clone();
            assert!(old_did.starts_with("did:dht:"));
            assert!(crate::runtime::identity_registry_contains(&old_did));

            // Migrate to a new DID via the actual bridge function.
            let migrated = py_identity_migrate(py, &original).unwrap();
            let new_did = migrated.did.clone();

            // New DID is a valid, distinct did:dht.
            assert!(new_did.starts_with("did:dht:"));
            assert_ne!(old_did, new_did);

            // Custody type is preserved.
            assert_eq!(migrated.custody, "in_memory");

            // Old identity removed from registry, new one registered.
            assert!(!crate::runtime::identity_registry_contains(&old_did));
            assert!(crate::runtime::identity_registry_contains(&new_did));

            // New identity's registry entry has a valid document.
            let doc_did =
                crate::runtime::with_identity(&new_did, |entry| Ok(entry.document.id.clone()))
                    .unwrap();
            assert_eq!(doc_did, new_did);
        });
    }
}
