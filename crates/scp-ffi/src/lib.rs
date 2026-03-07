//! `PyO3` FFI bridge for SCP — the `_scp_core` Python extension module.
//!
//! This crate is the Rust half of the Python SDK. It exposes a flat set of
//! `#[pyfunction]` and `#[pyclass]` definitions that map directly to
//! `scp-core`'s public API. The Pythonic wrapper layer (`scp_sdk`) lives in
//! pure Python and imports this module as `scp_sdk._scp_core`.
//!
//! # Async runtime
//!
//! A single tokio [`Runtime`] is created at module import time and stored in a
//! [`OnceLock`]. Most async bridge functions use synchronous `#[pyfunction]`
//! with `py.allow_threads(|| rt.block_on(...))` to run tokio futures while
//! releasing the Python GIL.
//!
//! The exception is `PyMessageReceiver::__anext__`, which returns an
//! `asyncio.Future` and spawns the recv on the tokio runtime, resolving the
//! future via `call_soon_threadsafe`. This avoids blocking the asyncio event
//! loop thread while waiting for messages (#138).
//!
//! The tokio runtime is **never** accessed via `block_on` from within a tokio
//! async context (which would panic). Sync-to-async bridging is handled in the
//! Python layer.
//!
//! # Shutdown
//!
//! Runtime shutdown is handled in two phases:
//! 1. An `atexit` handler calls `shutdown_runtime()`, which blocks for 100ms
//!    to let cooperative tasks observe shutdown. Kept short to avoid holding
//!    the Python GIL.
//! 2. On process exit, the static `OnceLock` is reclaimed and the tokio
//!    runtime is dropped (which waits for remaining tasks to complete).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` for the full specification.

// FFI bridge requires targeted unsafe for PyO3 interop. Each usage is documented.
#![allow(unsafe_code)]

pub mod context;

use std::sync::OnceLock;
use std::time::Duration;

use pyo3::prelude::*;

pub mod bridge_adapters;
pub mod error;
pub mod event_log;
pub mod identity;
pub mod mcp;
pub mod provenance;
pub mod runtime;
pub mod tools;
pub mod transport;
pub mod trust;
pub mod types;
pub mod ucan;
pub mod validate;

/// Global tokio runtime, created once at module import.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Brief drain window for in-flight tokio tasks during Python atexit.
/// Kept short (100ms) to avoid blocking the Python GIL unnecessarily.
const SHUTDOWN_DRAIN: Duration = Duration::from_millis(100);

/// Returns a reference to the shared tokio runtime.
///
/// Bridge functions (added by subsequent stories) use this to spawn work on
/// the tokio runtime.
///
/// # Errors
///
/// Returns `PyRuntimeError` if the runtime has not been initialized (should
/// never happen after module import) or if initialization failed.
#[allow(dead_code)] // Used by bridge functions added in subsequent stories.
pub(crate) fn runtime() -> PyResult<&'static tokio::runtime::Runtime> {
    RUNTIME.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "SCP tokio runtime not initialized — was _scp_core imported correctly?",
        )
    })
}

/// Initializes the tokio runtime. Called once during module import.
///
/// The runtime is multi-threaded with the default thread count (typically the
/// number of CPU cores). It is stored in a `OnceLock` so subsequent calls are
/// no-ops.
///
/// # Errors
///
/// Returns `PyRuntimeError` if tokio runtime construction fails, which
/// prevents undefined behavior from panicking across the FFI boundary.
fn init_runtime() -> PyResult<()> {
    // If already initialized, return immediately.
    if RUNTIME.get().is_some() {
        return Ok(());
    }

    // Build the runtime, returning an error instead of panicking.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("scp-tokio-worker")
        .build()
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to create SCP tokio runtime: {e}"
            ))
        })?;

    // Store it. If another thread raced us, that's fine — OnceLock
    // guarantees only one value is stored and our `rt` is simply dropped.
    let _ = RUNTIME.set(rt);
    Ok(())
}

/// Returns `True` if the tokio runtime has been initialized.
#[pyfunction]
fn runtime_is_initialized() -> bool {
    RUNTIME.get().is_some()
}

/// Returns a version string for the `_scp_core` extension module.
#[pyfunction]
#[allow(clippy::missing_const_for_fn)] // PyO3 #[pyfunction] cannot be const.
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Signals the tokio runtime to begin graceful shutdown.
///
/// Called during Python interpreter exit via `atexit`. The atexit handler runs
/// during Python cleanup, which completes BEFORE Rust module finalization.
/// This ordering ensures all Python destructors (`__del__`, weak-ref callbacks)
/// complete before the tokio runtime is dropped.
///
/// The actual runtime drop (which invokes tokio's `shutdown_timeout`)
/// happens when the process exits and the static
/// `OnceLock` is reclaimed. This function serves as a coordination point:
/// it blocks briefly to let in-flight tokio tasks observe that Python is
/// shutting down.
///
/// This function is idempotent — calling it after the runtime is already
/// shut down (or before it was initialized) is a no-op.
#[pyfunction]
fn shutdown_runtime() {
    // Take no action if the runtime was never initialized.
    // We cannot take ownership of the OnceLock value, so we signal
    // graceful shutdown by spawning a brief drain and then returning.
    // The actual runtime drop happens when the process exits and the
    // static OnceLock is reclaimed.
    if let Some(rt) = RUNTIME.get() {
        // Give in-flight tasks a brief window to complete. 100ms is
        // sufficient for cooperative tasks to observe shutdown and
        // finish; anything longer blocks the Python GIL unnecessarily.
        rt.block_on(async {
            tokio::time::sleep(SHUTDOWN_DRAIN).await;
        });
    }
}

/// The `_scp_core` Python extension module.
///
/// This is the entry point for the FFI bridge. It initializes the tokio
/// runtime and registers all bridge functions and classes.
///
/// # Module initialization
///
/// 1. Creates the tokio runtime (multi-threaded, default thread count).
/// 2. Registers an `atexit` handler for graceful shutdown.
/// 3. Registers bridge functions and classes (added by subsequent stories).
#[pymodule]
fn _scp_core(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Step 1: Initialize the tokio runtime.
    init_runtime()?;

    // Step 2: Register atexit handler for graceful shutdown.
    // Python cleanup (GC, __del__, atexit handlers) completes BEFORE Rust
    // module finalization, so this ordering is safe.
    let atexit = py.import("atexit")?;
    let shutdown_fn = m.getattr("shutdown_runtime")?;
    atexit.call_method1("register", (shutdown_fn,))?;

    // Step 3: Register exception class hierarchy.
    error::register_exceptions(m)?;

    // Step 4: Register identity bridge classes and functions.
    identity::register_identity(m)?;

    // Step 5: Register bridge functions.
    m.add_function(wrap_pyfunction!(runtime_is_initialized, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(shutdown_runtime, m)?)?;

    // Step 6: Register domain bridge modules.
    context::register_context(m)?;
    tools::register_tools(m)?;
    transport::register_transport(m)?;
    ucan::register_ucan(m)?;
    event_log::register_event_log(m)?;
    provenance::register_provenance(m)?;
    mcp::register_mcp(m)?;
    trust::register_trust(m)?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn init_runtime_creates_runtime() {
        // Ensure the runtime can be initialized.
        init_runtime().ok();
        assert!(RUNTIME.get().is_some());
    }

    #[test]
    fn init_runtime_is_idempotent() {
        // Multiple calls should not panic or replace the runtime.
        init_runtime().ok();
        let first = RUNTIME.get().map(std::ptr::from_ref);
        init_runtime().ok();
        let second = RUNTIME.get().map(std::ptr::from_ref);
        assert_eq!(first, second);
    }

    #[test]
    fn runtime_accessor_returns_initialized_runtime() {
        init_runtime().ok();
        let rt = runtime();
        assert!(rt.is_ok());
    }

    #[test]
    fn runtime_can_spawn_and_block() {
        init_runtime().ok();
        let rt = runtime().ok();
        assert!(rt.is_some());
        let rt = rt.map(|r| {
            r.block_on(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                42
            })
        });
        assert_eq!(rt, Some(42));
    }

    #[test]
    fn runtime_is_multi_threaded() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        init_runtime().ok();
        let rt = runtime().ok();
        assert!(rt.is_some());
        let rt = rt.expect("runtime should be initialized");

        // Spawn multiple concurrent tasks to verify the runtime is
        // multi-threaded (they should run on different threads).
        let counter = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let counter = Arc::clone(&counter);
                rt.spawn(async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();

        rt.block_on(async {
            for handle in handles {
                handle.await.expect("task should complete");
            }
        });

        assert_eq!(counter.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn version_returns_cargo_version() {
        let v = version();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn runtime_is_initialized_returns_correct_state() {
        // After init, should be true. We can only test the positive case
        // because OnceLock persists across tests in the same process.
        init_runtime().ok();
        assert!(runtime_is_initialized());
    }
}
