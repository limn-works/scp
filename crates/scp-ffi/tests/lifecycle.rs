//! Integration tests for the bridge lifecycle functions (`scp_suspend`,
//! `scp_resume`).
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

use _scp_core::{runtime, scp_resume, scp_suspend};

/// Consolidated lifecycle roundtrip — suspend/resume before init (no-op
/// branch), then suspend/resume after init (happy-path branch).
///
/// Consolidated into a single `#[test]` so that cargo's test runner does not
/// interleave these assertions on parallel threads. Because the suspended
/// flag is global and observable from any thread, splitting this into
/// multiple tests can produce races.
#[test]
fn scp_suspend_resume_roundtrip() {
    // Case 1: suspend / resume before any bridge init must succeed (no-op
    // branch — `bridge_instance_raw()` returns `None`).
    //
    // Note: even "before init" isn't strictly guaranteed here because an
    // earlier integration test in the same binary may have initialized the
    // bridge. The guarantee we are asserting is the functions succeed
    // regardless of init state.
    scp_suspend().expect("scp_suspend must succeed");
    scp_resume().expect("scp_resume must succeed");

    // Case 2: after ensure_bridge_instance(), suspend then resume round-trip.
    runtime::ensure_bridge_instance();
    scp_suspend().expect("scp_suspend after init must succeed");
    scp_resume().expect("scp_resume after suspend must succeed");

    // Case 3: double-suspend / double-resume are idempotent (no error on
    // repeated calls — matches the semantics documented on the PyO3
    // bindings).
    scp_suspend().expect("double suspend must succeed");
    scp_suspend().expect("double suspend must succeed");
    scp_resume().expect("double resume must succeed");
    scp_resume().expect("double resume must succeed");
}
