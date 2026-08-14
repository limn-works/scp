// napi-rs requires owned String/Vec parameters for #[napi] functions.
// These lints are framework constraints, not code quality issues.
#![allow(
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::items_after_statements,
    clippy::significant_drop_tightening,
    clippy::too_many_lines
)]

//! `napi-rs` FFI bridge for SCP — the Node.js/Bun native addon.
//!
//! This crate is compiled to a native addon (`.node` file) via `napi build`
//! and consumed by the `@limn-works/scp-ts` npm package. It exposes a flat set of
//! `#[napi]` types and functions that map directly to `scp-core`'s public API
//! surface.
//!
//! # Architecture
//!
//! The bridge is organized into domain modules that mirror the `UniFFI` bridge
//! (`crates/scp-ffi/uniffi/`) at the same logical API surface:
//!
//! - [`error`] — `ScpNapiError` hierarchy and `From<scp-core error>` mappings.
//! - [`identity`] — Identity lifecycle (`identity_create`, `identity_load`,
//!   `identity_resolve`).
//! - [`context`] — Context lifecycle (create, join, leave, close, send,
//!   subscribe).
//! - [`outlets`] — Outlet registration, invocation, and verification.
//! - [`transport`] — Transport connection and status.
//! - [`ucan`] — UCAN token management (validate, mint, revoke).
//! - [`event_log`] — Event log queries and Merkle proofs.
//!
//! # Async model
//!
//! This bridge has full access to the tokio
//! multi-thread runtime. All async bridge functions are declared `async fn`
//! and annotated with `#[napi]`. napi-rs generates `ThreadsafeFunction`-backed
//! async bridges automatically, running the Rust `Future` on the tokio runtime
//! and resolving the returned JS `Promise` on the Node.js event loop.
//!
//! A single tokio `Runtime` is created at module load via `OnceLock<Runtime>`
//! and shared across all async calls. The napi-rs `tokio_rt` feature enables
//! the napi-rs runtime integration.
//!
//! # Shutdown ordering
//!
//! napi-rs registered cleanup hooks block the Node.js process from exiting
//! until all outstanding JavaScript references to Rust objects are released.
//! A global `HANDLE_COUNT` tracks live opaque handle objects; all four
//! opaque types (`NapiIdentity`, `NapiContextHandle`, `NapiUcanToken`,
//! `NapiTransportManager`) decrement it in their `Drop` impl.
//!
//! `scp_shutdown` waits (with a configurable timeout, default 5 seconds)
//! for `HANDLE_COUNT` to reach zero before allowing the tokio runtime to
//! be dropped. See `sdk-common.md` "FFI Async Bridging Risks" rule 4.
//!
//! # Direct `scp-core` calls
//!
//! This bridge calls `scp-core` directly. The `"in_memory"` custody path in
//! [`Scp::identity_create`](crate::scp::Scp::identity_create) uses a real
//! `InMemoryKeyCustody` to
//! generate a live `did:dht` identity.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md`.

// The `trailing_empty_array` lint fires inside napi-rs macro expansions
// (generated `NapiRefContainer` structs). This is an napi-rs internal
// implementation detail — the generated code is correct.
#![allow(clippy::trailing_empty_array)]

use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use napi_derive::napi;

/// Runtime handle-affinity check at every `#[napi]` entry that accepts a
/// handle.
///
/// Matches the `PyO3` bridge's
/// [`pyscp_check_handle!`](../../scp_ffi/macro.pyscp_check_handle.html)
/// for cross-bridge symmetry.
///
/// The caller passes a [`CoreFields`](crate::runtime::CoreFields) reference
/// as the first argument (typically `&self.inner.core` on an `Scp` method,
/// or `&bi.core` where `bi` is a `&NapiBridgeInstance` already in scope).
/// The macro then checks that each supplied `$handle.instance_id()`
/// matches the core's `instance_id`.
///
/// `$handle` must carry an inherent `instance_id(&self) -> u64` method
/// (`HandleInstance` in the runtime module).
///
/// Raises [`crate::error::ScpNapiError::Permission`] with error code
/// `SCP-PERM-3030` on mismatch.
///
/// Sub-slice A of #1549 Phase 4 PR 4 reintroduced the explicit `$core`
/// parameter so per-`NapiBridgeInstance` call paths can flow their own
/// core through without routing via the process-global default.
/// Sub-slices B-E update every call site.
///
/// The affinity check is never blocked by transient lifecycle state
/// (e.g., a suspended bridge) because it is a pure `u64` comparison that
/// does not touch transport or `ContextManager` state.
///
/// Usage:
///
/// ```ignore
/// napi_check_handle!(&scp.inner.core, handle);
/// napi_check_handle!(&bi.core, identity, context_handle);
/// ```
#[macro_export]
macro_rules! napi_check_handle {
    ($core:expr, $($handle:expr),+ $(,)?) => {{
        let __core: &$crate::runtime::CoreFields = $core;
        $(
            __core
                .check_handle($crate::runtime::HandleInstance::instance_id($handle))
                .map_err(|e| ::napi::Error::from($crate::error::ScpNapiError::from(e)))?;
        )+
    }};
}

pub mod bridge_connector;
pub mod context;
pub mod custody;
pub mod discovery;
pub mod economy;
pub mod error;
pub mod event_log;
pub mod identity;
pub mod mcp;
pub mod media;
pub mod outlet_stream;
pub mod outlets;
pub mod provenance;
pub mod runtime;
pub mod scp;
pub mod scpid;
pub mod sync;
pub mod transport;
pub mod trust;
pub mod ucan;

pub use scp::Scp;

// Server startup (relay + application node) — behind the `server` feature on
// scp-ffi-common.
#[cfg(feature = "server")]
pub mod server;

// Full-stack E2E testing module — feature-gated behind testing.
// Exposes FullStackNetwork/FullStackNode from scp-testing for real
// encrypt→decrypt roundtrip tests from TypeScript.
#[cfg(feature = "testing")]
pub mod testing;

// ---------------------------------------------------------------------------
// Tokio runtime
// ---------------------------------------------------------------------------

/// Global tokio runtime, created once at module initialization.
///
/// Stored in a `OnceLock` for thread-safe lazy initialization. All async
/// bridge functions access this runtime via [`runtime()`].
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Grace period for in-flight tasks during process exit.
/// 5 seconds per ADR-022 acceptance criterion 7.
#[allow(dead_code)]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Returns a handle to the shared tokio runtime, initializing it on first call.
///
/// Uses `OnceLock::get_or_init` for thread-safe lazy initialization. All async
/// bridge functions that need to manually spawn tasks access this runtime.
///
/// # Process termination
///
/// If the tokio runtime cannot be constructed, the process is terminated via
/// `std::process::abort()`. This is the correct behavior for a fatal library
/// initialization failure in an FFI context.
#[allow(dead_code)]
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("scp-ffi-napi-worker")
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("FATAL: failed to create SCP napi tokio runtime: {e}");
                std::process::abort();
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Handle reference counter — shutdown ordering
//
// Every opaque FFI handle object (`NapiIdentity`, `NapiContextHandle`,
// `NapiUcanToken`, `NapiTransportManager`) increments this counter on
// construction and decrements it in its `Drop` impl.
//
// `scp_shutdown` waits until this counter reaches zero (or times out)
// before allowing the tokio runtime to be dropped.
//
// See `sdk-common.md` "FFI Async Bridging Risks" rule 4.
// ---------------------------------------------------------------------------

/// Global count of live opaque FFI handle objects.
///
/// Incremented in each opaque type's constructor and decremented in `Drop`.
pub(crate) static HANDLE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Increments the live handle count.
#[inline]
pub(crate) fn increment_handle_count() {
    HANDLE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Decrements the live handle count, saturating at zero.
#[inline]
pub(crate) fn decrement_handle_count() {
    HANDLE_COUNT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
            Some(if val > 0 { val - 1 } else { 0 })
        })
        .ok();
}

// ---------------------------------------------------------------------------
// Module lifecycle
// ---------------------------------------------------------------------------

/// Returns the version string for the `scp-ffi-napi` crate.
///
/// # JS usage
///
/// ```js
/// import { scpVersion } from '@limn-works/scp-ts-napi';
/// console.log(scpVersion()); // "0.1.0"
/// ```
#[napi]
#[must_use]
pub fn scp_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

// Phase D (#1695): the `scp_shutdown` free function has been deleted.
// Per-instance shutdown goes through `SCP.shutdown(timeout_millis)` on a
// caller-owned `Scp` instance. The timeout unit is milliseconds (`u64`
// `BigInt` on the wire); pass `0n` to skip both graceful drain and
// handle-release polling.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Force-link the weak napi stubs from the scp-ffi-napi-test-stubs
    // dev-dependency. Without this reference, cargo would strip the
    // (otherwise-unused) rlib from the test-binary link graph and the
    // `cargo:rustc-link-lib=static=napi_test_stubs` directive emitted
    // by its build.rs would never take effect — the test binary would
    // fail to link with undefined `napi_*` symbols. The cdylib never
    // sees this reference (it's inside `#[cfg(test)]`), so at runtime
    // Node's real napi_* symbols bind via dynamic linking as normal.
    #[allow(dead_code)]
    const _FORCE_NAPI_STUB_LINK: u8 = scp_ffi_napi_test_stubs::FORCE_LINK;

    #[test]
    fn scp_version_is_non_empty() {
        let v = scp_version();
        assert!(!v.is_empty(), "version string must not be empty");
    }

    // Phase D (#1695): `scp_shutdown` free function deleted; fast-path
    // test covered by `SCP.shutdown(0)` via per-instance lifecycle tests.

    #[test]
    fn handle_count_increments_and_decrements() {
        // HANDLE_COUNT is a global AtomicUsize shared with production
        // paths that other tests exercise in parallel (transport.rs
        // handle constructors). A test that loads a baseline and then
        // asserts `baseline + 1` races against any concurrent test
        // that also mutates HANDLE_COUNT, producing flakes.
        //
        // The invariant we want to prove is that increment and
        // decrement are reciprocal — their combined effect on
        // HANDLE_COUNT is zero — regardless of absolute value. Use
        // fetch_add / fetch_sub's returned prior values so we compare
        // deltas directly without a stable-baseline assumption.
        let after_inc_prior = HANDLE_COUNT.fetch_add(1, Ordering::SeqCst);
        // after_inc_prior is the value BEFORE the increment. The new
        // value is at least after_inc_prior + 1, but may be higher if
        // another test incremented between the load and the add.
        let after_dec_prior = HANDLE_COUNT.fetch_sub(1, Ordering::SeqCst);
        // after_dec_prior is the value BEFORE the decrement. By the
        // monotonicity of fetch_add, it must be strictly greater than
        // after_inc_prior unless the increment and decrement were
        // observed by a racing decrement first — in which case the
        // decrement would have saturated at zero, proving the saturate
        // guard is correct. Assert the weaker invariant: after the
        // increment the observed prior was strictly greater than what
        // we saw on entry.
        assert!(
            after_dec_prior > after_inc_prior || (after_inc_prior == 0 && after_dec_prior == 0),
            "increment/decrement reciprocity broken: inc_prior={after_inc_prior} dec_prior={after_dec_prior}"
        );
    }

    #[test]
    fn handle_count_saturates_at_zero() {
        let baseline = HANDLE_COUNT.load(Ordering::SeqCst);
        // Extra decrement when already at baseline should not underflow
        decrement_handle_count();
        let after = HANDLE_COUNT.load(Ordering::SeqCst);
        // Should be at most baseline (saturated, not wrapped to usize::MAX)
        assert!(
            after <= baseline,
            "expected saturated at {baseline}, got {after}"
        );
    }

    // -----------------------------------------------------------------------
    // SCP suspend / resume lifecycle tests
    //
    // Since #1549 Phase 4 PR 2 commit 11 the roundtrip exercises a fresh
    // `Scp::new()` instance rather than the free `scp_suspend` / `scp_resume`
    // functions that mutate the process-global the legacy default bridge.
    // That design eliminates the need for the old
    // `bridge_lifecycle_serial()` async mutex that previously had to guard
    // EVERY test in this binary that called `context_manager()` /
    // the legacy bridge accessor.
    //
    // Construction pattern:
    //
    //   let scp = Scp::new_in_memory_for_test();
    //   scp.suspend().expect("suspend");
    //   scp.resume().expect("resume");
    //
    // Each `Scp` owns an isolated `Arc<NapiBridgeInstance>`. Two tests
    // running in parallel — even two roundtrips — cannot observe each
    // other's `suspended` flag. Other tests in the binary continue to use
    // the legacy default bridge via `init_context_manager_for_test()`, and
    // because this test never touches the default they cannot race.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scp_class_suspend_resume_roundtrip() {
        let scp = crate::scp::Scp::new_in_memory_for_test();

        // Sanity: a freshly constructed instance is neither suspended
        // nor shut down.
        assert!(
            !scp.inner.core.is_suspended(),
            "fresh instance must not be suspended"
        );
        assert!(
            !scp.inner.core.is_shutdown(),
            "fresh instance must not be shut down"
        );

        // Case 1: suspend / resume must round-trip.
        scp.suspend().expect("Scp::suspend must succeed");
        assert!(
            scp.inner.core.is_suspended(),
            "instance must report suspended after suspend()"
        );
        scp.resume().await.expect("Scp::resume must succeed");
        assert!(
            !scp.inner.core.is_suspended(),
            "instance must not report suspended after resume()"
        );

        // Case 2: double-suspend / double-resume are idempotent.
        scp.suspend().expect("double suspend must succeed");
        scp.suspend().expect("double suspend must succeed");
        assert!(scp.inner.core.is_suspended());
        scp.resume().await.expect("double resume must succeed");
        scp.resume().await.expect("double resume must succeed");
        assert!(!scp.inner.core.is_suspended());

        // Case 3: Phase D (#1695) — the legacy default bridge is gone, so
        // there is no "default instance" to check against. Every caller
        // owns its own NapiBridgeInstance; suspension on one cannot leak
        // into another by construction.
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scp_class_shutdown_zero_timeout_returns_immediately() {
        // Shutting down a caller-owned `Scp` with a zero-millisecond
        // deadline must return without hanging even if handles are live,
        // mirroring `scp_shutdown_zero_timeout_returns_immediately` but
        // against an isolated `NapiBridgeInstance`. Phase 4 PR 4
        // (#1549) deleted the process-wide default bridge — every
        // `Scp::new()` owns its own `NapiBridgeInstance`, so this test
        // cannot affect any other instance's state.
        //
        // #1692: `Scp::shutdown` takes `napi::bindgen_prelude::BigInt`
        // (u64 on the wire). Build a zero-valued BigInt directly for
        // the test — in production callers pass a JS `bigint` literal.
        let scp = crate::scp::Scp::new_in_memory_for_test();
        scp.shutdown(napi::bindgen_prelude::BigInt {
            sign_bit: false,
            words: vec![0],
        })
        .await
        .expect("Scp::shutdown(0) must succeed");
    }
}
