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

use scp_core::identity::{DidDht, DidDocument, DidMethod};
use scp_platform::testing::InMemoryKeyCustody;

use crate::error::ScpPyError;

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
/// Currently both `"in_memory"` and `"platform"` resolve to
/// [`InMemoryKeyCustody`] because platform-native custody (Secure Enclave,
/// Android Keystore) is a future story. When platform custody is implemented,
/// this function will return a trait object or enum dispatch.
///
/// # Errors
///
/// Returns [`ScpPyError::ValidationError`] if the custody string is not
/// recognized.
fn parse_custody(custody: &str) -> Result<(Arc<InMemoryKeyCustody>, String), ScpPyError> {
    match custody {
        "in_memory" | "platform" => {
            let kc = Arc::new(InMemoryKeyCustody::new());
            Ok((kc, custody.to_owned()))
        }
        other => Err(ScpPyError::ValidationError(format!(
            "unknown custody type: {other:?} — expected \"in_memory\" or \"platform\""
        ))),
    }
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
/// See ADR-013 acceptance criterion 2.
#[pyfunction]
fn py_identity_create(py: Python<'_>, custody: &str) -> PyResult<PyIdentity> {
    let (key_custody, custody_str) = parse_custody(custody)?;
    let rt = crate::runtime()?;

    py.allow_threads(|| {
        rt.block_on(async {
            let did_method = DidDht::new();
            let (identity, _document) = did_method
                .create(key_custody.as_ref())
                .await
                .map_err(ScpPyError::from)?;

            Ok(PyIdentity {
                did: identity.did,
                custody: custody_str,
            })
        })
    })
}

/// Loads an existing identity from storage.
///
/// # Arguments
///
/// * `did` — The DID string to load (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// A [`PyIdentity`] containing the loaded DID string.
///
/// # Errors
///
/// Raises `IdentityError` if the DID format is unsupported.
///
/// # Note
///
/// Stub — see SCP-217 for `StorageProvider` wiring. Currently reconstructs a
/// `PyIdentity` from the DID string with `"in_memory"` custody instead of
/// loading from persistent storage (ADR-013 acceptance criterion 2).
#[pyfunction]
fn py_identity_load(py: Python<'_>, did: &str) -> PyResult<PyIdentity> {
    let did_owned = did.to_owned();

    py.allow_threads(|| {
        // Validate the DID format.
        if !did_owned.starts_with("did:dht:") {
            return Err(PyErr::from(ScpPyError::IdentityError(format!(
                "unsupported DID method: {did_owned} — only did:dht is supported"
            ))));
        }

        Ok(PyIdentity {
            did: did_owned,
            custody: "in_memory".to_owned(),
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
/// Generates a new Active Signing Key, updates the DID document, and returns
/// an updated [`PyIdentity`]. The DID string remains the same — only the
/// active signing key changes (Layer 1 rotation).
///
/// # Arguments
///
/// * `identity` — The [`PyIdentity`] whose key should be rotated.
///
/// # Errors
///
/// Always raises `IdentityError`. Key rotation requires a wired platform
/// `KeyCustodyProvider` that retains key handles across the FFI boundary.
/// `PyIdentity` currently stores only the DID string and custody label,
/// which is insufficient for cryptographic key rotation. The previous
/// implementation silently created a *new* identity with a different DID,
/// which is incorrect.
///
/// NAPI and `UniFFI` bindings also return explicit errors for this operation.
///
/// Tracked: full key rotation will be wired when persistent key storage
/// lands (see SCP-164 and ADR-013 acceptance criterion 2).
#[pyfunction]
fn py_identity_rotate_key(_identity: &PyIdentity) -> PyResult<PyIdentity> {
    Err(ScpPyError::IdentityError(
        "key rotation requires a wired platform KeyCustodyProvider — \
         PyIdentity does not retain key handles across the FFI boundary"
            .to_owned(),
    )
    .into())
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
    m.add_function(wrap_pyfunction!(py_identity_create, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_load, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_resolve, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_rotate_key, m)?)?;
    Ok(())
}
