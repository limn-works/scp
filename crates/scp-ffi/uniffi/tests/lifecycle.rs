//! Integration tests for the `UniFFI` bridge lifecycle functions
//! (`scp_suspend`, `scp_resume`).
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

use scp_ffi_uniffi::{runtime, scp_resume, scp_suspend};

/// Consolidated lifecycle roundtrip — suspend/resume before and after
/// `ensure_bridge_instance`.
///
/// Consolidated into a single test to avoid cargo's parallel test runner
/// interleaving concurrent invocations on the same global flag.
#[tokio::test]
async fn scp_suspend_resume_roundtrip() {
    // Case 1: suspend / resume before any bridge init must succeed.
    //
    // Note: "before init" is not strictly guaranteed — a prior test in the
    // same binary may have initialized the bridge. The guarantee we assert
    // is that both functions succeed regardless of init state.
    scp_suspend().expect("scp_suspend must succeed");
    scp_resume().await.expect("scp_resume must succeed");

    // Case 2: after ensure_bridge_instance(), suspend then resume round-trip.
    runtime::ensure_bridge_instance();
    scp_suspend().expect("scp_suspend after init must succeed");
    scp_resume()
        .await
        .expect("scp_resume after suspend must succeed");

    // Case 3: double-suspend / double-resume are idempotent.
    scp_suspend().expect("double suspend must succeed");
    scp_suspend().expect("double suspend must succeed");
    scp_resume().await.expect("double resume must succeed");
    scp_resume().await.expect("double resume must succeed");
}
