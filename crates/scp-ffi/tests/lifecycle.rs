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
//!   cargo test -p scp-ffi --test lifecycle --features testing
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "allow_in_memory_custody")]
use _scp_core::init_runtime;
#[cfg(feature = "allow_in_memory_custody")]
use _scp_core::scp::PyScp;
#[cfg(feature = "allow_in_memory_custody")]
use pyo3::Python;

/// Consolidated lifecycle roundtrip — suspend/resume roundtrips on a
/// caller-owned `PyScp` instance, exercising the idempotent paths.
///
/// Consolidated into a single `#[test]` so that cargo's test runner does not
/// interleave these assertions on parallel threads. Although Phase 4 PR 4
/// (#1549) deleted the process-wide default bridge, the tokio runtime
/// and some shutdown bookkeeping remain process-global, so parallel
/// execution of lifecycle tests can still race.
///
/// Phase 4 PR 4 demolition (#1549): the free-function `scp_suspend` /
/// `scp_resume` exports were deleted along with the process-wide default
/// bridge — tests now drive a freshly constructed `PyScp::new_in_memory_for_test()`
/// instance through `.suspend()` / `.resume()`.
#[test]
#[cfg(feature = "allow_in_memory_custody")]
fn scp_suspend_resume_roundtrip() {
    // `PyScp::resume` releases the GIL while driving the async
    // `BridgeInstanceCore::resume` default body on the tokio runtime. The test
    // therefore acquires the GIL once and drives every call through
    // `Python::with_gil`.
    Python::with_gil(|py| {
        // `PyScp::resume` uses `py.allow_threads(|| rt.block_on(...))` so the
        // shared tokio runtime must be initialized before the first call. In
        // the normal Python entry point, `_scp_core(m)` calls `init_runtime()`
        // during module init — integration tests bypass that, so we
        // initialize it explicitly here.
        init_runtime().expect("init_runtime must succeed");

        // Construct a fresh `PyScp` instance — each call produces a
        // brand-new `PyBridgeInstance` with its own monotonic
        // `instance_id`. Phase D (#1695) deleted the prior
        // `DEFAULT_BRIDGE_INSTANCE`, so there is no shared bridge for
        // this test to accidentally mutate.
        let scp = PyScp::new_in_memory_for_test();

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
