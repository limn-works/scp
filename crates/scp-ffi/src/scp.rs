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
//! scp = SCP()          # fresh instance — no shared process-global state
//! scp.shutdown(1000)   # graceful shutdown (milliseconds)
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
use crate::runtime::{PyBridgeInstance, StorageConfig};

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
    /// Constructs a new `SCP` instance with its own `PyBridgeInstance`.
    ///
    /// Unlike [`PyScp::default_instance`], this bypasses the process-global
    /// `DEFAULT_BRIDGE_INSTANCE` entirely — each call produces a brand-new
    /// instance with a fresh monotonic `instance_id`, a fresh
    /// `CancellationToken`, and an empty `JoinSet`. Handles issued against
    /// this instance are incompatible with any other instance.
    #[new]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(PyBridgeInstance::new_py()),
        }
    }

    /// Constructs a new `SCP` instance configured by a storage-config dict.
    ///
    /// Accepted shapes:
    /// - `{"type": "in_memory"}` — encrypted in-memory storage (ephemeral).
    /// - `{"type": "sqlite", "path": "/path/to/dir", "key": b"\x00..."}`
    ///   — SQLCipher-encrypted storage at `{path}/scp.db`. `key` must be a
    ///   `bytes` object holding raw encryption key material (32 bytes
    ///   recommended).
    ///
    /// Unknown types or malformed shapes raise `ValidationError`.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if `config["type"]` is missing or not a
    /// recognised storage variant, or if required fields for the selected
    /// variant are missing or wrongly typed.
    #[staticmethod]
    pub fn with_storage(_py: Python<'_>, config: &Bound<'_, PyDict>) -> PyResult<Self> {
        let storage_type: String = match config.get_item("type")? {
            Some(v) => v.extract()?,
            None => {
                return Err(ScpPyError::validation(
                    "SCP.with_storage: missing required key 'type' — expected \"in_memory\" or \"sqlite\""
                        .to_owned(),
                )
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
                let key_bytes: Vec<u8> = match config.get_item("key")? {
                    Some(v) => v.extract().map_err(|e| {
                        ScpPyError::validation(format!(
                            "SCP.with_storage(sqlite): 'key' must be bytes — {e}"
                        ))
                    })?,
                    None => {
                        return Err(ScpPyError::validation(
                            "SCP.with_storage(sqlite): missing required key 'key' (raw encryption key bytes)"
                                .to_owned(),
                        )
                        .into());
                    }
                };
                StorageConfig::Sqlite {
                    path: std::path::PathBuf::from(path_str),
                    key: zeroize::Zeroizing::new(key_bytes),
                }
            }
            other => {
                return Err(ScpPyError::validation(format!(
                    "SCP.with_storage: unknown storage type {other:?} — expected \"in_memory\" or \"sqlite\""
                ))
                .into());
            }
        };
        Ok(Self {
            inner: Arc::new(PyBridgeInstance::with_storage_py(cfg)),
        })
    }

    /// Constructs a new `SCP` instance with an explicit persistence provider.
    ///
    /// PR 1 does not expose a Python-side constructor for
    /// `Box<dyn ContextPersistence>` (this requires wiring a Rust trait
    /// across the FFI boundary, which lands in PR 3). Passing `None`
    /// therefore produces a plain `new()` instance; callers who need
    /// real persistence must use `SCP.with_storage(...)` until PR 3
    /// lands.
    ///
    /// # Errors
    ///
    /// Currently cannot fail. Returns `PyResult` for API forward-compat.
    #[staticmethod]
    pub fn with_persistence(_py: Python<'_>) -> PyResult<Self> {
        // PR 1 minimal: no Python-accessible ContextPersistence impl yet.
        // This matches the PyO3 signature pattern documented in the plan.
        Ok(Self {
            inner: Arc::new(PyBridgeInstance::new_py()),
        })
    }

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

impl Default for PyScp {
    fn default() -> Self {
        Self::new()
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
}
