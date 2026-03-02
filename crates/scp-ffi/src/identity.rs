//! `PyO3` bridge for identity operations.
//!
//! Exposes [`PyIdentity`] and [`PyDIDDocument`] as opaque Python objects with
//! attribute access, plus four bridge functions for identity lifecycle:
//!
//! - [`py_identity_create`] — creates a new DID identity.
//! - [`py_identity_load`] — loads an existing identity from storage.
//! - [`py_identity_resolve`] — resolves a DID to its document.
//! - [`py_identity_rotate_key`] — rotates the identity's active signing key.
//!
//! All async operations run on the shared tokio runtime via
//! [`crate::runtime()`]. The GIL is released during Rust async execution
//! via `py.allow_threads()` so Python threads are not blocked.
//!
//! # Opaque types
//!
//! [`PyIdentity`] stores the DID string and custody type — NOT the raw
//! [`ScpIdentity`](scp_core::identity::ScpIdentity), which contains
//! [`KeyHandle`](scp_platform::KeyHandle)s that are not safe to hold across
//! Python GIL boundaries. Crypto operations reconstruct state from stored
//! metadata when the full runtime is wired.
//!
//! [`PyDIDDocument`] wraps [`DidDocument`](scp_core::identity::DidDocument)
//! and exposes safe getters for the document's public fields.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` for the full specification.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use scp_core::identity::{DidDht, DidDocument, DidMethod, ScpIdentity};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, Storage};

use crate::error::ScpPyError;
use crate::runtime::IdentityEntry;
use crate::validate;

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

    fn __repr__(&self) -> String {
        format!("PyIdentity(did={:?}, custody={:?})", self.did, self.custody)
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

/// Parses a custody type string and returns an [`InMemoryKeyCustody`] instance.
///
/// Only `"in_memory"` creates an [`InMemoryKeyCustody`]. The `"platform"`
/// custody type is reserved for hardware-backed custody (Secure Enclave,
/// Android Keystore) which is not yet implemented. Using `"platform"` returns
/// an error to prevent silent fallback to in-memory custody (SCP-214
/// criterion 11).
///
/// # Errors
///
/// Returns [`ScpPyError::ValidationError`] if the custody string is not
/// recognized or if platform custody is requested but not available.
fn parse_custody(custody: &str) -> Result<(Arc<InMemoryKeyCustody>, String), ScpPyError> {
    match custody {
        "in_memory" => {
            let kc = Arc::new(InMemoryKeyCustody::new());
            Ok((kc, custody.to_owned()))
        }
        "platform" => Err(ScpPyError::ValidationError(
            "platform custody (Secure Enclave, Android Keystore) is not yet \
             implemented — use \"in_memory\" for testing"
                .to_owned(),
        )),
        other => Err(ScpPyError::ValidationError(format!(
            "unknown custody type: {other:?} — expected \"in_memory\" or \"platform\""
        ))),
    }
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
        ScpPyError::IdentityError(format!("stored identity state is not valid UTF-8: {e}"))
    })?;
    let mut lines = text.splitn(2, '\n');
    let did = lines
        .next()
        .ok_or_else(|| ScpPyError::IdentityError("stored identity state is empty".to_owned()))?
        .to_owned();
    let custody = lines
        .next()
        .ok_or_else(|| {
            ScpPyError::IdentityError("stored identity state is missing custody type".to_owned())
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
            if let Ok(storage) = crate::runtime::get_storage() {
                let key = identity_state_key(&did);
                let data = serialize_identity_state(&did, &custody_str);
                storage.store(&key, &data).await.map_err(|e| {
                    ScpPyError::IdentityError(format!("failed to persist identity state: {e}"))
                })?;
            }

            Ok(PyIdentity {
                did,
                custody: custody_str,
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
/// was created in a different process, the [`InMemoryKeyCustody`] key
/// material is lost and this function returns `SCP-IDENT-1010`.
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
///   in a different process, since [`InMemoryKeyCustody`] does not
///   persist key material.
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
            return Err(PyErr::from(ScpPyError::IdentityError(format!(
                "unsupported DID method: {did_owned} -- only did:dht is supported"
            ))));
        }

        let storage = crate::runtime::get_storage().map_err(PyErr::from)?;

        rt.block_on(async {
            let key = identity_state_key(&did_owned);
            let data = storage
                .retrieve(&key)
                .await
                .map_err(|e| {
                    ScpPyError::IdentityError(format!(
                        "failed to read identity state from storage: {e}"
                    ))
                })?
                .ok_or_else(|| {
                    ScpPyError::IdentityError(format!(
                        "identity not found in storage: {did_owned} -- \
                     was it created with py_identity_create?"
                    ))
                })?;

            let (stored_did, custody_str) = deserialize_identity_state(&data)?;

            if stored_did != did_owned {
                return Err(PyErr::from(ScpPyError::IdentityError(format!(
                    "stored DID mismatch: expected {did_owned}, found {stored_did}"
                ))));
            }

            // SCP-IDENT-1010: Verify the identity has live crypto state
            // in the registry. Without this check, the returned PyIdentity
            // would be a dangling handle -- subsequent bridge functions
            // (UCAN minting, signing, pseudonym derivation, key rotation)
            // would fail with "identity not found in registry" (RED-013).
            if crate::runtime::identity_registry_contains(&did_owned) {
                return Ok(PyIdentity {
                    did: stored_did,
                    custody: custody_str,
                });
            }

            Err(PyErr::from(ScpPyError::IdentityError(format!(
                "SCP-IDENT-1010: identity '{did_owned}' was found in storage \
                 but has no live crypto state in the runtime registry. \
                 InMemoryKeyCustody does not persist key material across \
                 process boundaries. Use py_identity_create to create a \
                 new identity, or use platform custody (when available) \
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
            let did_method = DidDht::new();

            let rotation_result = rt.block_on(async {
                did_method
                    .rotate_active_key(&entry.identity, &entry.document, entry.custody.as_ref())
                    .await
            });

            let (new_identity, new_document) = rotation_result.map_err(ScpPyError::from)?;
            entry.identity = new_identity;
            entry.document = new_document;

            Ok(PyIdentity {
                did: did.clone(),
                custody: custody_str.clone(),
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
            let (custody, old_identity_key, old_active_key, pre_rotation_commitment, old_doc) =
                crate::runtime::with_identity(&old_did, |entry| {
                    Ok((
                        Arc::clone(&entry.custody),
                        entry.identity.identity_key,
                        entry.identity.active_signing_key,
                        entry.identity.pre_rotation_commitment,
                        entry.document.clone(),
                    ))
                })?;

            // We need a pre-rotation key handle. Generate one for the
            // migration — in a full implementation, the pre-rotation key
            // would have been generated and stored during identity creation.
            // The InMemoryKeyCustody already holds the pre-rotation key from
            // the original create call (handle = identity_key + 2, following
            // the sequential handle allocation in DidDht::create).
            //
            // For now, generate a fresh pre-rotation key. The migrate_identity
            // method uses it as the new Identity Key.
            let pre_rotation_key = custody
                .generate_keypair(scp_platform::traits::KeyType::Ed25519)
                .await
                .map_err(|e| ScpPyError::IdentityError(format!("key generation failed: {e}")))?;

            let rotated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| ScpPyError::IdentityError(format!("system clock error: {e}")))?
                .as_secs();

            let old_identity = ScpIdentity {
                identity_key: old_identity_key,
                active_signing_key: old_active_key,
                pre_rotation_commitment,
                did: old_did.clone(),
            };

            let did_method = DidDht::new();
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
            })
        })
    })
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
    m.add_function(wrap_pyfunction!(py_identity_load, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_resolve, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_rotate_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_migrate, m)?)?;
    Ok(())
}
