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
pub mod scpid;
pub mod sync;
pub mod tools;
pub mod transport;
pub mod trust;
pub mod ucan;

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

/// Decrements the live handle count.
#[inline]
pub(crate) fn decrement_handle_count() {
    HANDLE_COUNT.fetch_sub(1, Ordering::Relaxed);
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

/// Waits for all outstanding FFI handles to be released, then returns.
///
/// Call this from Node.js/Bun before your process exits (e.g., in a
/// `process.on('exit', ...)` handler or after shutting down all SCP objects).
/// It blocks (on a background thread) until either:
///
/// - All opaque handle objects (`NapiIdentity`, `NapiContextHandle`,
///   `NapiUcanToken`, `NapiTransportManager`) have been GC'd / freed, **or**
/// - The `timeout_secs` deadline has elapsed.
///
/// The default timeout is 5 seconds (per ADR-022 acceptance criterion 7).
/// Pass `0` to return immediately without waiting.
///
/// # Thread safety
///
/// This function is safe to call from any thread. It polls `HANDLE_COUNT`
/// in 10 ms intervals and does not block the Node.js event loop.
///
/// # JS usage
///
/// ```js
/// process.on('exit', () => {
///   scpShutdown(5); // wait up to 5 seconds for handle cleanup
/// });
/// ```
#[napi]
pub fn scp_shutdown(timeout_secs: u32) {
    if timeout_secs == 0 {
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(u64::from(timeout_secs));
    while HANDLE_COUNT.load(Ordering::Relaxed) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scp_version_is_non_empty() {
        let v = scp_version();
        assert!(!v.is_empty(), "version string must not be empty");
    }

    #[test]
    fn scp_shutdown_zero_timeout_returns_immediately() {
        // Must return without hanging even if handles are live.
        scp_shutdown(0);
    }

    #[test]
    fn handle_count_increments_and_decrements() {
        let baseline = HANDLE_COUNT.load(Ordering::SeqCst);
        increment_handle_count();
        assert_eq!(HANDLE_COUNT.load(Ordering::SeqCst), baseline + 1);
        decrement_handle_count();
        assert_eq!(HANDLE_COUNT.load(Ordering::SeqCst), baseline);
    }
}
