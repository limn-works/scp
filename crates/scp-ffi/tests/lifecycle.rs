//! Integration tests for the bridge lifecycle methods
//! (`PyScp::suspend` / `PyScp::resume`).
//!
//! These tests live in a separate integration test binary (i.e. outside the
//! lib-test binary) so that flipping the process-wide `BridgeInstance`
//! `suspended` flag does not race with other tests in `src/lib.rs` that
//! assume a non-suspended bridge (e.g. `transport_disconnect_is_idempotent`,
//! which reads `bridge_instance()` and errors on suspended state).
//!
//! Run with:
//! ```sh
//! DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
//!   cargo test -p scp-ffi --test lifecycle --features allow_in_memory_custody
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use _scp_core::init_runtime;
use _scp_core::scp::PyScp;
use pyo3::Python;

/// Consolidated lifecycle roundtrip — suspend/resume roundtrips on the
/// process-wide default `SCP` instance, exercising the idempotent paths.
///
/// Consolidated into a single `#[test]` so that cargo's test runner does not
/// interleave these assertions on parallel threads. Because the suspended
/// flag is global and observable from any thread, splitting this into
/// multiple tests can produce races.
///
/// Phase 4 PR 4 demolition (#1549): the free-function `scp_suspend` /
/// `scp_resume` exports were deleted — tests now drive the default `SCP`
/// instance through `PyScp::default_instance().suspend()` / `.resume()`.
#[test]
fn scp_suspend_resume_roundtrip() {
    // `PyScp::resume` releases the GIL while driving the async
    // `BridgeInstanceCore::resume` override on the tokio runtime. The test
    // therefore acquires the GIL once and drives every call through
    // `Python::with_gil`.
    Python::with_gil(|py| {
        // `PyScp::resume` uses `py.allow_threads(|| rt.block_on(...))` so the
        // shared tokio runtime must be initialized before the first call. In
        // the normal Python entry point, `_scp_core(m)` calls `init_runtime()`
        // during module init — integration tests bypass that, so we
        // initialize it explicitly here.
        init_runtime().expect("init_runtime must succeed");

        // `default_instance` also materialises the process-wide
        // `DEFAULT_BRIDGE_INSTANCE` if it hasn't been initialised yet. Every
        // subsequent call returns the same underlying `Arc<PyBridgeInstance>`.
        let scp = PyScp::default_instance().expect("default SCP instance");

        // Case 1: suspend/resume on a freshly-initialised instance must
        // succeed.
        scp.suspend().expect("scp.suspend must succeed");
        scp.resume(py).expect("scp.resume must succeed");

        // Case 2: a second suspend/resume cycle still succeeds — the
        // operations are idempotent by design.
        scp.suspend()
            .expect("scp.suspend after prior resume must succeed");
        scp.resume(py)
            .expect("scp.resume after second suspend must succeed");

        // Case 3: double-suspend / double-resume are idempotent (no error on
        // repeated calls — matches the semantics documented on the `SCP`
        // methods).
        scp.suspend().expect("double suspend must succeed");
        scp.suspend().expect("double suspend must succeed");
        scp.resume(py).expect("double resume must succeed");
        scp.resume(py).expect("double resume must succeed");
    });
}
