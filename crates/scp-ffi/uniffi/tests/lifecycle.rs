//! Integration tests for the `UniFFI` bridge lifecycle methods
//! (`Scp::suspend` / `Scp::resume`).
//!
//! These tests live in a separate integration test binary so that flipping
//! the process-wide `BridgeInstance::suspended` flag does not race with
//! other tests in `src/lib.rs` that assume a non-suspended bridge.
//!
//! Run with:
//! ```sh
//! cargo test -p scp-ffi-uniffi --test lifecycle --features allow_in_memory_custody
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_ffi_uniffi::Scp;

/// Consolidated lifecycle roundtrip — suspend/resume roundtrips on the
/// process-wide default `Scp` instance, exercising the idempotent paths.
///
/// Consolidated into a single test to avoid cargo's parallel test runner
/// interleaving concurrent invocations on the same global flag.
///
/// Multi-threaded flavor because `resume()` now reaches into async
/// persistence paths (`ProtocolRepositoryEventLogBridge::store_entries`
/// uses `block_in_place`), which panic on the default current-thread
/// runtime.
///
/// Phase 4 PR 4 demolition (#1549): the free-function `scp_suspend` /
/// `scp_resume` façade exports were deleted — tests now drive the default
/// `Scp` instance through `Scp::default_instance().suspend()` / `.resume()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scp_suspend_resume_roundtrip() {
    // `default_instance` materialises the process-wide
    // `DEFAULT_BRIDGE_INSTANCE` on first call. Every subsequent call
    // returns the same underlying `Arc<UniffiBridgeInstance>`.
    let scp = Scp::default_instance().expect("default Scp instance");

    // Case 1: suspend/resume on a freshly-initialised instance.
    scp.suspend().expect("scp.suspend must succeed");
    scp.resume()
        .await
        .expect("scp.resume after suspend must succeed");

    // Case 2: a second suspend/resume cycle still succeeds — idempotent
    // by design.
    scp.suspend()
        .expect("scp.suspend after prior resume must succeed");
    scp.resume()
        .await
        .expect("scp.resume after second suspend must succeed");

    // Case 3: double-suspend / double-resume are idempotent.
    scp.suspend().expect("double suspend must succeed");
    scp.suspend().expect("double suspend must succeed");
    scp.resume().await.expect("double resume must succeed");
    scp.resume().await.expect("double resume must succeed");
}
