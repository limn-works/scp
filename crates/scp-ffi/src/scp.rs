//! `#[pyclass]` wrapper exposing [`PyBridgeInstance`] to Python as `SCP`.
//!
//! The `SCP` class is the Python SDK's sole user-facing entry point.
//! Each `SCP` instance owns its own [`PyBridgeInstance`] with a unique
//! monotonic `instance_id`, so handles issued by one instance are
//! rejected by others via
//! [`scp_ffi_common::bridge_instance::HandleAffinityError`].
//!
//! ```python
//! from scp_sdk import SCP
//!
//! # Storage selection is required — there is no default (spec §17.6).
//! scp = SCP({"type": "in_memory"})   # explicit dev/test in-memory storage
//! scp.shutdown(1000)                 # graceful shutdown (milliseconds)
//! ```
//!
//! Phase D (#1695) deleted the default-instance infrastructure: there is
//! no longer a `DEFAULT_BRIDGE_INSTANCE` static or `default_instance()`
//! factory. Every operation routes through an explicit `SCP` instance.

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_ffi_common::bridge_instance::BridgeInstanceCore;

use crate::error::ScpPyError;
use crate::runtime::{PyBridgeInstance, SqliteKeyMaterial, StorageConfig};

/// Python-facing `SCP` instance.
///
/// A thin wrapper around `Arc<PyBridgeInstance>`. `frozen` because the
/// wrapper itself is immutable — all mutation happens through the interior
/// atomics/mutexes of `CoreFields` and the typed fields on
/// `PyBridgeInstance`, which is safe under concurrent Python calls.
#[pyclass(name = "SCP", frozen)]
pub struct PyScp {
    pub(crate) inner: Arc<PyBridgeInstance>,
}

#[pymethods]
impl PyScp {
    /// Constructs a new `SCP` instance configured by a storage-config dict.
    ///
    /// Storage selection is MANDATORY and fail-closed (spec §17.6): there
    /// is no zero-argument constructor and no default backend. Bare
    /// `SCP()` raises `TypeError` (the `config` argument is required);
    /// passing a dict whose `type` is missing or unrecognised raises
    /// `ValidationError`.
    ///
    /// Accepted shapes:
    /// - `{"type": "in_memory"}` — encrypted in-memory storage (ephemeral,
    ///   development/test only).
    /// - `{"type": "sqlite", "path": "/path/to/dir", "key": b"\x00..."}`
    ///   — SQLCipher-encrypted storage at `{path}/scp.db`. `key` must be a
    ///   `bytes` object holding raw encryption key material (32 bytes
    ///   recommended).
    /// - `{"type": "sqlite", "path": "/path/to/dir", "passphrase": "..."}`
    ///   — SQLCipher-encrypted storage whose key is derived from a passphrase
    ///   via Argon2id (with a persisted per-database salt sidecar). `passphrase`
    ///   must be a `str`.
    ///
    /// For the `sqlite` type, exactly ONE of `key` or `passphrase` must be
    /// supplied — both-present or neither raises `ValidationError`.
    ///
    /// Each call produces a brand-new instance with a fresh monotonic
    /// `instance_id`, a fresh `CancellationToken`, and an empty
    /// `JoinSet`. Handles issued against this instance are incompatible
    /// with any other instance — the affinity check at every FFI entry
    /// point surfaces a mismatch as `PermissionError` (`SCP-PERM-3030`).
    /// Phase D (#1695, ADR-048) deleted the prior `default_instance()`
    /// factory and `DEFAULT_BRIDGE_INSTANCE` static; there is no
    /// process-global bridge anymore.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `config["type"]` is missing or not a
    /// recognised storage variant, or if required fields for the selected
    /// variant are missing or wrongly typed (including supplying both or
    /// neither of `key`/`passphrase` for `sqlite`).
    #[new]
    pub fn new(py: Python<'_>, config: &Bound<'_, PyDict>) -> PyResult<Self> {
        Self::build_from_config(py, config)
    }

    /// Constructs a new `SCP` instance configured by a storage-config dict.
    ///
    /// Alias for the constructor (`SCP(config)`) — retained so the SDK
    /// wrapper and existing callers can spell the storage selection as
    /// `SCP.with_storage({...})`. Both surfaces fold into the same
    /// fail-closed dict parser; there is no behavioural difference.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` under the same conditions as the
    /// constructor.
    #[staticmethod]
    pub fn with_storage(py: Python<'_>, config: &Bound<'_, PyDict>) -> PyResult<Self> {
        Self::build_from_config(py, config)
    }

    /// Constructs a new `SCP` instance with an explicit persistence provider.
    ///
    /// PR 1 does not expose a Python-side constructor for
    /// `Box<dyn ContextPersistence>` (this requires wiring a Rust trait
    /// across the FFI boundary, which lands in PR 3). This therefore
    /// builds an explicit in-memory instance; callers who need real
    /// persistence must use `SCP.with_storage({...})` (or `SCP({...})`)
    /// with the `sqlite` variant.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if the in-memory backend cannot be
    /// constructed. Returns `PyResult` for API forward-compat.
    #[staticmethod]
    pub fn with_persistence(_py: Python<'_>) -> PyResult<Self> {
        // No Python-accessible ContextPersistence impl yet — build an
        // explicit in-memory instance (NOT a silent no-storage one;
        // spec §17.6).
        let bi = PyBridgeInstance::with_storage_py(StorageConfig::InMemory)
            .map_err(|e| ScpPyError::validation(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(bi),
        })
    }
}

// Non-pyo3 impl block for the storage-config parser. Not annotated with
// `#[pymethods]`, so it does not become a Python attribute — it is the
// shared fail-closed dict parser that both the `#[new]` constructor and
// the `with_storage` staticmethod delegate to (spec §17.6 — storage
// selection is mandatory; bare `SCP()` is a `TypeError` because `config`
// is a required positional argument).
impl PyScp {
    /// Parses a storage-config dict into a [`StorageConfig`] and builds the
    /// bridge instance. Fail-closed: a missing or unknown `type`, or
    /// malformed `sqlite` key material, is a `ValidationError`.
    fn build_from_config(_py: Python<'_>, config: &Bound<'_, PyDict>) -> PyResult<Self> {
        let storage_type: String = match config.get_item("type")? {
            Some(v) => v.extract()?,
            None => {
                // Storage selection is mandatory (spec §17.6): a missing
                // `type` is the selection-required case, carried by
                // SCP-STORAGE-8000 rather than the generic validation code.
                return Err(ScpPyError::ValidationError {
                    message: "SCP storage selection is required: missing key 'type' — expected \
                     {\"type\": \"in_memory\"} (development) or \
                     {\"type\": \"sqlite\", \"path\": ..., \"key\"|\"passphrase\": ...} \
                     (production). There is no default storage."
                        .to_owned(),
                    code: scp_ffi_common::error_codes::STORAGE_8000.to_owned(),
                }
                .into());
            }
        };
        let cfg = match storage_type.as_str() {
            "in_memory" => StorageConfig::InMemory,
            "sqlite" => {
                let path_str: String = match config.get_item("path")? {
                    Some(v) => v.extract()?,
                    None => {
                        return Err(ScpPyError::validation(
                            "SCP.with_storage(sqlite): missing required key 'path' (directory for scp.db)"
                                .to_owned(),
                        )
                        .into());
                    }
                };
                // Defense-in-depth: validate path string at FFI boundary
                // (matches the project pattern for every other caller-supplied
                // string — DID, relay URL, tool name, etc.). #1543 PR-C
                // security review found this was the lone unvalidated string
                // input. See crates/scp-ffi/common/src/validate.rs.
                scp_ffi_common::validate::validate_storage_path(&path_str).map_err(|e| {
                    ScpPyError::validation(format!(
                        "SCP.with_storage(sqlite): invalid 'path' — {}",
                        e.message
                    ))
                })?;
                // Exactly ONE of `key` (raw bytes) or `passphrase` (str) must
                // be supplied — the `SqliteKeyMaterial` sum type enforces mutual
                // exclusion at the type level; here we enforce it at the dict
                // boundary (spec §17.6). The passphrase is moved into
                // `Zeroizing` immediately so it never lingers in an un-wiped
                // `String`.
                let key_item = config.get_item("key")?;
                let passphrase_item = config.get_item("passphrase")?;
                let key_material = match (key_item, passphrase_item) {
                    (Some(_), Some(_)) => {
                        return Err(ScpPyError::validation(
                            "SCP.with_storage(sqlite): supply exactly one of 'key' or 'passphrase', not both"
                                .to_owned(),
                        )
                        .into());
                    }
                    (None, None) => {
                        return Err(ScpPyError::validation(
                            "SCP.with_storage(sqlite): missing key material — supply either 'key' (raw encryption key bytes) or 'passphrase' (str)"
                                .to_owned(),
                        )
                        .into());
                    }
                    (Some(key_val), None) => {
                        let key_bytes: Vec<u8> = key_val.extract().map_err(|e| {
                            ScpPyError::validation(format!(
                                "SCP.with_storage(sqlite): 'key' must be bytes — {e}"
                            ))
                        })?;
                        SqliteKeyMaterial::Raw(zeroize::Zeroizing::new(key_bytes))
                    }
                    (None, Some(pass_val)) => {
                        let passphrase: String = pass_val.extract().map_err(|e| {
                            ScpPyError::validation(format!(
                                "SCP.with_storage(sqlite): 'passphrase' must be a str — {e}"
                            ))
                        })?;
                        SqliteKeyMaterial::Passphrase(zeroize::Zeroizing::new(passphrase))
                    }
                };
                StorageConfig::Sqlite {
                    path: std::path::PathBuf::from(path_str),
                    key: key_material,
                }
            }
            other => {
                return Err(ScpPyError::validation(format!(
                    "SCP.with_storage: unknown storage type {other:?} — expected \"in_memory\" or \"sqlite\""
                ))
                .into());
            }
        };
        let bi = PyBridgeInstance::with_storage_py(cfg)
            .map_err(|e| ScpPyError::validation(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(bi),
        })
    }
}

#[pymethods]
impl PyScp {
    /// Returns the monotonic identifier for this instance.
    #[getter]
    #[must_use]
    pub fn instance_id(&self) -> u64 {
        self.inner.core.instance_id()
    }

    /// Suspends the instance for mobile backgrounding.
    ///
    /// Disconnects transport (clears relay connection) and marks the
    /// instance as suspended. Context state is preserved. Transport-
    /// dependent operations will fail until [`PyScp::resume`] is called.
    ///
    /// # Errors
    ///
    /// Raises `TransportError` if the transport lock is poisoned.
    pub fn suspend(&self) -> PyResult<()> {
        self.inner
            .core
            .suspend()
            .map_err(|e| ScpPyError::transport(format!("suspend failed: {e}")))?;
        Ok(())
    }

    /// Resumes a suspended instance.
    ///
    /// Clears the suspended flag so bridge operations can proceed. The
    /// caller must re-establish the relay connection explicitly — resume
    /// does not reconnect automatically.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` (code `SCP-CTX-2000`) if the instance has
    /// been permanently shut down.
    pub fn resume(&self, py: Python<'_>) -> PyResult<()> {
        let rt = crate::runtime()?;
        let inner = Arc::clone(&self.inner);
        // Release the GIL while we drive the tokio runtime. The
        // `BridgeInstanceCore::resume` override performs async work
        // (transport reconnect, context restore) that must not block the
        // Python interpreter.
        py.allow_threads(|| {
            rt.block_on(async move {
                scp_ffi_common::bridge_instance::BridgeInstanceCore::resume(&*inner).await
            })
        })
        .map_err(|e| ScpPyError::ContextError {
            message: format!("resume failed: {e}"),
            code: scp_ffi_common::error_codes::CTX_2000.to_owned(),
        })?;
        Ok(())
    }

    /// Shuts the instance down with a graceful deadline for in-flight tasks.
    ///
    /// Delegates to [`PyBridgeInstance::shutdown`] via the
    /// [`BridgeInstanceCore`] trait: fires the cancellation token, drains
    /// the `JoinSet` inside the `timeout_millis` budget, then runs
    /// typed-field cleanup. A second call is a no-op from the Python
    /// caller's perspective (the underlying `ShutdownError::AlreadyShutDown`
    /// is swallowed — idempotency is expected).
    ///
    /// The timeout unit is **milliseconds** — unified across all Rust
    /// bridges so the Python, TypeScript, Swift, and Kotlin SDKs can
    /// share a single conversion surface. Pass 0 for a best-effort
    /// immediate shutdown (tasks not yet cancelled are aborted without
    /// waiting).
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the tokio runtime is unavailable.
    pub fn shutdown(&self, py: Python<'_>, timeout_millis: u64) -> PyResult<()> {
        let timeout = Duration::from_millis(timeout_millis);
        let rt = crate::runtime()?;
        let inner = Arc::clone(&self.inner);
        // Release the GIL while we drive the tokio runtime — shutdown may
        // drain tasks for up to `timeout_millis`, and we must not block the
        // Python interpreter meanwhile.
        py.allow_threads(|| {
            rt.block_on(async move {
                match inner.shutdown(timeout).await {
                    Ok(_) => Ok::<(), ScpPyError>(()),
                    Err(e) => {
                        // AlreadyShutDown is swallowed: Python callers
                        // expect `.shutdown()` to be idempotent.
                        tracing::debug!("SCP.shutdown: {e} — treating as no-op");
                        Ok(())
                    }
                }
            })
        })?;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!("SCP(instance_id={})", self.inner.core.instance_id())
    }
}

// Non-pyo3 impl block — exposes internals for Rust consumers (integration
// tests and downstream bridge glue). Items here do NOT become Python
// attributes because they're not annotated with `#[pymethods]`.
impl PyScp {
    /// Returns a shared reference to this instance's `PyBridgeInstance`.
    ///
    /// Useful for Rust-side code (integration tests, crate-internal glue)
    /// that needs to pass the same `PyBridgeInstance` to `runtime::*`
    /// helpers that this `PyScp` services. Python code should never see
    /// this — it is not `#[pymethods]`.
    #[must_use]
    pub const fn bridge_instance(&self) -> &Arc<PyBridgeInstance> {
        &self.inner
    }

    /// Constructs a `PyScp` that wraps an existing `PyBridgeInstance`.
    ///
    /// Used by integration tests that need the same `PyBridgeInstance`
    /// for both `runtime::*` helpers (which take `&PyBridgeInstance`) and
    /// `PyScp::*` methods (which route through `self.inner`). Production
    /// code should use [`PyScp::new`] or [`PyScp::with_storage`] instead.
    #[must_use]
    pub const fn from_bridge_instance(inner: Arc<PyBridgeInstance>) -> Self {
        Self { inner }
    }

    /// Constructs a `PyScp` with explicit in-memory storage, for Rust-side
    /// tests only.
    ///
    /// The public constructor (`SCP(config)`) requires a storage-config
    /// dict and a GIL; Rust integration/unit tests want a one-liner that
    /// selects in-memory storage without building a `PyDict`. This wraps
    /// the equivalent of `SCP({"type": "in_memory"})` — an explicit
    /// dev/test selection, NOT a silent default (spec §17.6).
    ///
    /// In-memory construction is infallible (it cannot perform any I/O), so
    /// this never returns an error and never panics.
    #[cfg(any(test, feature = "testing", feature = "allow_in_memory_custody"))]
    #[must_use]
    pub fn new_in_memory_for_test() -> Self {
        Self {
            inner: Arc::new(PyBridgeInstance::new_in_memory_for_test()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    use crate::scp::PyScp;

    /// Build the `{"type": "sqlite", "path": dir}` dict shared by the parse
    /// tests; the caller adds `key`/`passphrase` as needed.
    fn sqlite_dict<'py>(py: Python<'py>, dir: &str) -> Bound<'py, PyDict> {
        let dict = PyDict::new(py);
        dict.set_item("type", "sqlite").expect("set type");
        dict.set_item("path", dir).expect("set path");
        dict
    }

    /// Parity with the NAPI passphrase parse: a `sqlite` config carrying a
    /// `passphrase` (and no `key`) constructs successfully — the dict path
    /// wires the passphrase through to `SqliteStorage::with_passphrase`.
    #[test]
    fn with_storage_sqlite_passphrase_constructs() {
        pyo3::prepare_freethreaded_python();
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_str().expect("utf8 path").to_owned();
        Python::with_gil(|py| {
            let dict = sqlite_dict(py, &dir);
            dict.set_item("passphrase", "correct horse battery staple")
                .expect("set passphrase");
            let result = PyScp::with_storage(py, &dict);
            assert!(
                result.is_ok(),
                "sqlite + passphrase must construct: {:?}",
                result.err()
            );
        });
    }

    /// Parity with the NAPI raw-key parse: a `sqlite` config carrying `key`
    /// bytes (and no `passphrase`) constructs successfully.
    #[test]
    fn with_storage_sqlite_raw_key_constructs() {
        pyo3::prepare_freethreaded_python();
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_str().expect("utf8 path").to_owned();
        Python::with_gil(|py| {
            let dict = sqlite_dict(py, &dir);
            dict.set_item("key", vec![0x11_u8; 32]).expect("set key");
            let result = PyScp::with_storage(py, &dict);
            assert!(
                result.is_ok(),
                "sqlite + raw key must construct: {:?}",
                result.err()
            );
        });
    }

    /// Supplying BOTH `key` and `passphrase` for `sqlite` is a `ValidationError`
    /// (exactly-one-of enforcement at the dict boundary, spec §17.6).
    #[test]
    fn with_storage_sqlite_both_key_and_passphrase_rejected() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = sqlite_dict(py, "/tmp/scp-test-both");
            dict.set_item("key", vec![0x22_u8; 32]).expect("set key");
            dict.set_item("passphrase", "also-a-passphrase")
                .expect("set passphrase");
            // `PyScp` does not implement `Debug`, so match on the `Result`
            // rather than using `expect_err`.
            let msg = match PyScp::with_storage(py, &dict) {
                Ok(_) => panic!("both key and passphrase must be rejected"),
                Err(err) => err.to_string(),
            };
            assert!(
                msg.contains("exactly one of 'key' or 'passphrase'"),
                "error must explain the exactly-one constraint: {msg}"
            );
        });
    }

    /// Supplying NEITHER `key` nor `passphrase` for `sqlite` is a
    /// `ValidationError`.
    #[test]
    fn with_storage_sqlite_neither_key_nor_passphrase_rejected() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = sqlite_dict(py, "/tmp/scp-test-neither");
            // `PyScp` does not implement `Debug`, so match on the `Result`
            // rather than using `expect_err`.
            let msg = match PyScp::with_storage(py, &dict) {
                Ok(_) => panic!("missing key material must be rejected"),
                Err(err) => err.to_string(),
            };
            assert!(
                msg.contains("missing key material"),
                "error must explain the missing key material: {msg}"
            );
        });
    }

    /// Storage selection is mandatory (spec §17.6): a config dict missing
    /// the `type` key is rejected, and the error carries the storage
    /// selection-required code `SCP-STORAGE-8000`.
    #[test]
    fn missing_type_is_rejected_with_storage_8000() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            // No "type" key at all — the mandatory selection is absent.
            let msg = match PyScp::with_storage(py, &dict) {
                Ok(_) => panic!("missing storage 'type' must be rejected — no default"),
                Err(err) => err.to_string(),
            };
            assert!(
                msg.contains(scp_ffi_common::error_codes::STORAGE_8000),
                "missing-selection error must carry SCP-STORAGE-8000: {msg}"
            );
        });
    }

    /// The explicit `{"type": "in_memory"}` dev path constructs successfully
    /// and yields a live instance with a non-zero monotonic id (it can run a
    /// real operation — reading `instance_id`).
    #[test]
    fn in_memory_dict_constructs_and_is_live() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "in_memory").expect("set type");
            let scp = match PyScp::with_storage(py, &dict) {
                Ok(scp) => scp,
                Err(err) => panic!("in_memory selection must construct: {err}"),
            };
            assert!(
                scp.instance_id() > 0,
                "constructed instance must expose a live, non-zero instance_id"
            );
        });
    }

    /// An unknown storage `type` is rejected (fail-closed; spec §17.6).
    #[test]
    fn unknown_type_is_rejected() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "redis").expect("set type");
            let msg = match PyScp::with_storage(py, &dict) {
                Ok(_) => panic!("unknown storage type must be rejected"),
                Err(err) => err.to_string(),
            };
            assert!(
                msg.contains("unknown storage type"),
                "error must name the unknown type: {msg}"
            );
        });
    }
}
