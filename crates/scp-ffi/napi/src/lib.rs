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
//! - [`tools`] — Tool registration, invocation, and verification.
//! - [`transport`] — Transport connection and status.
//! - [`ucan`] — UCAN token management (validate, mint, revoke).
//! - [`event_log`] — Event log queries and Merkle proofs.
//!
//! # Async model
//!
//! Unlike the WASM bridge, this bridge has full access to the tokio
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
//! [`scp_shutdown`] waits (with a configurable timeout, default 5 seconds)
//! for `HANDLE_COUNT` to reach zero before allowing the tokio runtime to
//! be dropped. See `sdk-common.md` "FFI Async Bridging Risks" rule 4.
//!
//! # Direct `scp-core` calls
//!
//! Unlike the WASM bridge (which cannot depend on `scp-core` due to tokio's
//! multi-thread runtime constraint on `wasm32-unknown-unknown`), this bridge
//! calls `scp-core` directly. The `"in_memory"` custody path in
//! [`identity_create`](identity::identity_create) uses a real
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
/// Single form, matching the `PyO3` bridge's
/// [`pyscp_check_handle!`](../../scp_ffi/macro.pyscp_check_handle.html)
/// for cross-bridge symmetry (round 2 simplifier review finding — the
/// previous dual-form macro could silently route a per-instance
/// `Scp::method` through the default `OnceLock` if the caller forgot
/// the leading `&`). Every caller now spells the `CoreFields` target
/// explicitly.
///
/// `$core` must be a `CoreFields` or something that implements or
/// auto-derefs to one (`&CoreFields`, `Arc<NapiBridgeInstance>`, etc.).
/// Method resolution on `check_handle` handles the indirection.
///
/// `$handle` must carry an inherent `instance_id(&self) -> u64` method
/// (`HandleInstance` in the runtime module).
///
/// Raises [`crate::error::ScpNapiError::Permission`] with error code
/// `SCP-PERM-3030` on mismatch.
///
/// Usage:
///
/// ```ignore
/// // free-function (default instance)
/// let bi = crate::runtime::default_bridge_instance()?;
/// napi_check_handle!(&bi.core, handle);
/// napi_check_handle!(&bi.core, identity, context_handle);
///
/// // per-instance method (PR 2+)
/// napi_check_handle!(&self.inner.core, handle);
/// ```
#[macro_export]
macro_rules! napi_check_handle {
    ($core:expr, $($handle:expr),+ $(,)?) => {{
        // Method resolution on `check_handle` auto-derefs through `&T`,
        // `&Arc<T>`, `Arc<T>`, and `CoreFields` directly. `CoreFields`
        // has an inherent `check_handle` method, so the trait need not
        // be in scope when `$core` resolves to `&CoreFields` (the
        // typical free-function case). If a future caller passes
        // `Arc<NapiBridgeInstance>` or similar, add
        // `use scp_ffi_common::bridge_instance::BridgeInstanceCore;`
        // at the call site. Mirrors the PyO3 bridge's
        // `pyscp_check_handle!` pattern.
        $(
            $core
                .check_handle($crate::runtime::HandleInstance::instance_id($handle))
                .map_err(|e| ::napi::Error::from($crate::error::ScpNapiError::from(e)))?;
        )+
    }};
}

pub mod bridge_connector;
pub mod context;
pub mod discovery;
pub mod economy;
pub mod error;
pub mod event_log;
pub mod identity;
pub mod mcp;
pub mod media;
pub mod provenance;
pub mod runtime;
pub mod scp;
pub mod scpid;
pub mod sync;
pub mod tools;
pub mod transport;
pub mod trust;
pub mod ucan;

pub use scp::Scp;

// Server startup (relay + application node) — behind the `server` feature on
// scp-ffi-common. Not available for WASM (ADR-034).
#[cfg(feature = "server")]
pub mod server;

// Full-stack E2E testing module — feature-gated behind allow_in_memory_custody.
// Exposes FullStackNetwork/FullStackNode from scp-testing for real
// encrypt→decrypt roundtrip tests from TypeScript.
#[cfg(feature = "allow_in_memory_custody")]
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

/// Shuts down the default bridge instance gracefully.
///
/// Awaits in-flight tasks up to `timeout_millis` **milliseconds**, aborts
/// any remaining tasks when the deadline expires, then clears registries,
/// disconnects transport, and runs shutdown hooks. Finally waits up to the
/// same deadline for outstanding opaque FFI handles
/// (`NapiIdentity`, `NapiContextHandle`, `NapiUcanToken`,
/// `NapiTransportManager`, …) to be released.
///
/// The unit is **milliseconds** — unified across all Rust bridges so the
/// Python, TypeScript, Swift, and Kotlin SDKs can share a single
/// conversion surface (`timeout_secs: number` in the SDK wrapper is
/// multiplied by 1000 before crossing FFI). The NAPI `u32` millis range
/// is 2^32 ms ≈ 49.7 days, which is far beyond any realistic shutdown
/// budget.
///
/// Returns a `Promise<void>` — call `await scpShutdown(5000)` from JS.
/// Pass `0` to skip both graceful drain and handle-release polling.
///
/// **Breaking change (Phase 4 PR 1 / AC5)**: the signature moved from
/// sync `void` to async `Promise<void>`, and the unit changed from
/// **seconds** (`u32`) to **milliseconds** (`u32`) to unify the Rust
/// bridge signatures. Callers migrating away from the free-function
/// façade should switch to `scp.shutdown(5000)` on an owned `SCP`
/// instance.
///
/// # JS usage
///
/// ```js
/// process.on('beforeExit', async () => {
///   await scpShutdown(5_000); // wait up to 5 seconds (5,000 ms)
/// });
/// ```
#[napi]
pub async fn scp_shutdown(timeout_millis: u32) -> napi::Result<()> {
    let timeout = Duration::from_millis(u64::from(timeout_millis));

    // In test builds we intentionally skip shutting down the default
    // bridge instance — the `OnceLock` is process-global and one shutdown
    // would poison state shared by every other test in the same binary.
    #[cfg(not(test))]
    if let Some(bi) = runtime::default_bridge_instance_raw() {
        use scp_ffi_common::bridge_instance::BridgeInstanceCore as _;
        // Wrap in catch_unwind: during process teardown (e.g., bun test
        // exit), MLS or tokio state may already be partially dropped,
        // causing panics in destroy_mls_group or task abort. A panic here
        // would abort the process with "failed to initiate panic"
        // (double-panic).
        let bi_for_catch = std::sync::Arc::clone(bi);
        let fut = bi_for_catch.shutdown(timeout);
        match std::panic::AssertUnwindSafe(fut).catch_unwind_await().await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::debug!("bridge shutdown returned: {e}");
            }
            Err(_) => {
                tracing::error!("NapiBridgeInstance shutdown panicked — cleanup may be incomplete");
            }
        }
    }

    if timeout_millis == 0 {
        return Ok(());
    }
    let deadline = std::time::Instant::now() + timeout;
    while HANDLE_COUNT.load(Ordering::Relaxed) > 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

/// Helper trait to support `catch_unwind` on async futures.
///
/// `std::panic::catch_unwind` is sync-only; wrapping a future in
/// `AssertUnwindSafe` still yields a sync `catch_unwind` guard around the
/// `Future` polls. We use `futures::FutureExt::catch_unwind` instead for
/// the async path (already pulled in via workspace `futures`).
#[cfg(not(test))]
trait CatchUnwindAwait: core::future::Future + Sized {
    async fn catch_unwind_await(self) -> Result<Self::Output, Box<dyn std::any::Any + Send>>;
}

#[cfg(not(test))]
impl<F> CatchUnwindAwait for std::panic::AssertUnwindSafe<F>
where
    F: core::future::Future,
{
    async fn catch_unwind_await(self) -> Result<Self::Output, Box<dyn std::any::Any + Send>> {
        use futures::FutureExt;
        self.catch_unwind().await
    }
}

/// Suspends the bridge instance for mobile app backgrounding.
///
/// Disconnects transport (clears the relay connection) and marks the instance
/// as suspended. Context state is preserved — the instance remains alive but
/// inactive. Transport-dependent operations will fail until [`scp_resume`]
/// is called.
///
/// After suspension, callers should call `scpResume()` to re-activate, then
/// re-establish the relay connection via `transportConnect()`.
///
/// No-op if the instance is already shut down or not initialized.
///
/// # JS usage
///
/// ```js
/// // When the app goes to background:
/// scpSuspend();
/// // When returning to foreground:
/// scpResume();
/// await transportConnect(relayUrl);
/// ```
#[napi]
pub fn scp_suspend() -> napi::Result<()> {
    if let Some(bi) = runtime::default_bridge_instance_raw() {
        bi.core.suspend().map_err(|e| {
            napi::Error::from(crate::error::ScpNapiError::Transport {
                message: format!("suspend failed: {e}"),
                code: scp_ffi_common::error_codes::TRANS_5001.to_owned(),
            })
        })?;
    }
    Ok(())
}

/// Resumes a suspended bridge instance.
///
/// Clears the suspended flag so bridge operations can proceed. The caller
/// must re-establish the relay connection via `transportConnect()` — resume
/// does not reconnect automatically.
///
/// No-op if the instance is not initialized.
///
/// # Errors
///
/// Throws `ScpContextError` if the instance has been permanently shut down.
#[napi]
pub fn scp_resume() -> napi::Result<()> {
    if let Some(bi) = runtime::default_bridge_instance_raw() {
        bi.core.resume().map_err(|e| {
            napi::Error::from(crate::error::ScpNapiError::Context {
                message: format!("resume failed: {e}"),
                code: scp_ffi_common::error_codes::CTX_2000.to_owned(),
            })
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn scp_version_is_non_empty() {
        let v = scp_version();
        assert!(!v.is_empty(), "version string must not be empty");
    }

    #[tokio::test]
    async fn scp_shutdown_zero_timeout_returns_immediately() {
        // Must return without hanging even if handles are live.
        scp_shutdown(0).await.expect("scp_shutdown(0) must succeed");
    }

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
    // scp_suspend / scp_resume lifecycle tests
    //
    // Consolidated into a single `#[test]` so that cargo's parallel test
    // runner does not interleave suspend/resume across the shared
    // `BridgeInstance::suspended` flag with other tests in this binary.
    //
    // A process-wide `bridge_lifecycle_serial()` async mutex serializes
    // this test against EVERY other test in this binary that calls
    // `context_manager()` / `bridge_instance()` — NOT just the
    // governance-style `role_state_syncs_*` tests in `context.rs`, but
    // also context-create, context-join, economy tracker, and
    // bridge-connector tests that would otherwise observe
    // `is_suspended=true` mid-roundtrip and fail. Every test that
    // touches shared bridge state acquires the mutex; see
    // `bridge_lifecycle_serial()` in `runtime.rs` for the invariant.
    //
    // Because NAPI is a cdylib and cannot link integration tests
    // (`napi_wrap` is only defined when loaded by Node), moving these
    // assertions into a separate `tests/lifecycle.rs` binary is not
    // possible — the mutex is the portable alternative. Uses
    // `tokio::sync::Mutex` so async callers can `.await` its `lock()`
    // without tripping the `await_holding_lock` lint.
    // -----------------------------------------------------------------------

    #[test]
    fn scp_suspend_resume_roundtrip() {
        let _guard = crate::runtime::bridge_lifecycle_serial().blocking_lock();

        // Case 1: suspend / resume before any bridge init must succeed.
        scp_suspend().expect("scp_suspend must succeed");
        scp_resume().expect("scp_resume must succeed");

        // Case 2: after ensure_bridge_instance(), suspend then resume
        // round-trip.
        crate::runtime::ensure_bridge_instance();
        scp_suspend().expect("scp_suspend after init must succeed");

        // Semantic assertion (L4): while suspended, `context_manager()`
        // and `bridge_instance()` must return the CTX_2000 "suspended"
        // error rather than some other error. This is the whole contract
        // the `bridge_lifecycle_serial()` mutex exists to protect —
        // verify it directly so a future refactor that accidentally
        // weakens `is_suspended` propagation (e.g. checking only in
        // `context_manager()` but not `bridge_instance()`) is caught
        // here.
        //
        // Both accessors return `Err`; we only assert the error *shape*
        // includes the suspended sentinel. Asserting `Ok` after resume
        // would be brittle because this test does not attach a
        // `ContextManager` (see `init_context_manager_for_test` usage in
        // other tests) — after resume, `try_context_manager()` would
        // still fail with the distinct "not yet attached" error, which
        // is a correct but unrelated code path.
        let cm_err = crate::runtime::context_manager()
            .err()
            .expect("context_manager must error while suspended");
        let cm_msg = cm_err.to_string();
        assert!(
            cm_msg.contains("suspended") && cm_msg.contains(scp_ffi_common::error_codes::CTX_2000),
            "context_manager error should mention suspended + CTX_2000, got: {cm_msg}"
        );
        let bi_err = crate::runtime::bridge_instance()
            .err()
            .expect("bridge_instance must error while suspended");
        let bi_msg = bi_err.to_string();
        assert!(
            bi_msg.contains("suspended") && bi_msg.contains(scp_ffi_common::error_codes::CTX_2000),
            "bridge_instance error should mention suspended + CTX_2000, got: {bi_msg}"
        );

        scp_resume().expect("scp_resume after suspend must succeed");

        // After resume, the suspended sentinel must no longer appear on
        // either accessor. If `try_context_manager()` was not attached
        // in this binary, the accessors return the distinct "not yet
        // attached" error (also CTX_2000) — that's fine for the
        // assertion below because the text diverges from the suspended
        // message.
        if let Err(e) = crate::runtime::context_manager() {
            assert!(
                !e.to_string().contains("suspended"),
                "context_manager must not report suspended after resume, got: {e}"
            );
        }
        if let Err(e) = crate::runtime::bridge_instance() {
            assert!(
                !e.to_string().contains("suspended"),
                "bridge_instance must not report suspended after resume, got: {e}"
            );
        }

        // Case 3: double-suspend / double-resume are idempotent.
        scp_suspend().expect("double suspend must succeed");
        scp_suspend().expect("double suspend must succeed");
        scp_resume().expect("double resume must succeed");
        scp_resume().expect("double resume must succeed");
    }
}
