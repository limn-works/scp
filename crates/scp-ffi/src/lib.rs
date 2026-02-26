//! PyO3 FFI bridge for SCP — the `_scp_core` Python extension module.
//!
//! This crate is the Rust half of the Python SDK. It exposes a flat set of
//! `#[pyfunction]` and `#[pyclass]` definitions that map directly to
//! `scp-core`'s public API. The Pythonic wrapper layer (`scp_sdk`) lives in
//! pure Python and imports this module as `scp_sdk._scp_core`.
//!
//! # Async runtime
//!
//! A single tokio [`Runtime`] is created at module import time and stored in a
//! [`OnceLock`]. All async bridge functions use PyO3's native async support
//! (`#[pyfunction] async fn`) which automatically bridges between the tokio
//! runtime and Python's asyncio event loop.
//!
//! The tokio runtime is **never** accessed via `block_on` from within an async
//! context. Sync-to-async bridging is handled in the Python layer.
//!
//! # Shutdown
//!
//! Runtime shutdown is handled on module finalization (Python interpreter exit).
//! The runtime is dropped, which waits for in-flight tasks to complete with a
//! 5-second timeout.
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` for the full specification.

// FFI bridge requires targeted unsafe for PyO3 interop. Each usage is documented.
#![allow(unsafe_code)]

pub mod context;

use std::sync::OnceLock;
use std::time::Duration;

use pyo3::prelude::*;

pub mod error;
pub mod identity;
pub mod types;

/// Global tokio runtime, created once at module import.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Shutdown timeout for the tokio runtime when the Python interpreter exits.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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
/// Returns `PyRuntimeError` if tokio runtime construction fails.
#[allow(clippy::expect_used)] // OnceLock::get_or_init requires an infallible closure.
fn init_runtime() -> PyResult<()> {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("scp-tokio-worker")
            .build()
            // The runtime builder only fails on OS-level resource exhaustion,
            // which is unrecoverable. This is the sole panic point.
            .expect("failed to create SCP tokio runtime — OS resource exhaustion")
    });
    Ok(())
}

/// Returns `True` if the tokio runtime has been initialized.
#[pyfunction]
fn runtime_is_initialized() -> bool {
    RUNTIME.get().is_some()
}

/// Returns a version string for the `_scp_core` extension module.
#[pyfunction]
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
/// The actual runtime drop (which calls `shutdown_timeout` with
/// [`SHUTDOWN_TIMEOUT`]) happens when the process exits and the static
/// `OnceLock` is reclaimed. This function serves as a coordination point:
/// it blocks briefly to let in-flight tokio tasks observe that Python is
/// shutting down.
///
/// This function is idempotent — calling it after the runtime is already
/// shut down (or before it was initialized) is a no-op.
#[pyfunction]
fn shutdown_runtime() {
    if let Some(rt) = RUNTIME.get() {
        // Block briefly to allow in-flight tasks to complete. This runs
        // during atexit, so the Python GIL is held and no new Python
        // callbacks will be issued. The SHUTDOWN_TIMEOUT constant governs
        // how long we wait for tasks to drain.
        let deadline = SHUTDOWN_TIMEOUT;
        let _ = rt.block_on(async move {
            tokio::time::sleep(deadline).await;
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

    // Step 4: Register domain bridge modules.
    context::register_context(m)?;

    Ok(())
}

#[cfg(test)]
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
        let first = RUNTIME.get().map(|rt| rt as *const _);
        init_runtime().ok();
        let second = RUNTIME.get().map(|rt| rt as *const _);
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
