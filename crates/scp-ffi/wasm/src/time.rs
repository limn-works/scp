//! Hardened time source for the WASM bridge.
//!
//! `js_sys::Date::now()` delegates to JavaScript's `Date.now()`, which is
//! overridable by any same-origin script (`Date.now = () => 0`). An attacker
//! who replaces `Date.now` can bypass UCAN expiry/nbf validation, device
//! attestation freshness checks, and nonce replay windows.
//!
//! This module captures the original `Date.now` function reference at module
//! load time via `#[wasm_bindgen(inline_js)]`. The captured binding survives
//! later `Date.now` overrides, significantly narrowing the attack window to
//! code that executes *before* the WASM module is instantiated.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = "
const _dateNow = Date.now.bind(Date);
export function captured_date_now() { return _dateNow(); }
")]
extern "C" {
    /// Returns milliseconds since Unix epoch using a captured `Date.now`
    /// reference that was bound at module initialization time.
    #[wasm_bindgen(js_name = "captured_date_now")]
    fn captured_date_now() -> f64;
}

/// Returns the current time in milliseconds since Unix epoch.
///
/// Uses the captured `Date.now` reference (see module docs). All WASM bridge
/// code should use this instead of `js_sys::Date::now()`.
///
/// On non-`wasm32` targets (native host test builds) the `inline_js` extern
/// does not exist — calling it panics with "cannot call wasm-bindgen imported
/// functions on non-wasm targets". So native builds fall back to `SystemTime`,
/// letting tests drive real WASM-bridge code paths (e.g. governance
/// proposal/vote handlers) that need a clock without a JS runtime. This branch
/// is compiled out of the real `wasm32-unknown-unknown` browser build and
/// therefore cannot weaken the hardened-clock security property in production.
#[must_use]
#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> f64 {
    captured_date_now()
}

/// Native-host fallback for [`now_ms`] (see the `wasm32` variant's docs).
#[must_use]
#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // `as_secs_f64() * 1000.0` mirrors JS `Date.now()`'s millisecond `f64`
    // without an int→float cast (so no `cast_precision_loss`).
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
}

/// Returns the current time in milliseconds since Unix epoch as `u64`.
///
/// Converts the `f64` value from `Date.now()` to `u64`. Negative values
/// (clock misconfiguration) are clamped to `0`. The `f64` representation
/// is exact for integers up to 2^53, and Unix millis in 2026 (~1.8e12) is
/// well within that range.
///
/// Used by nonce freshness validation, which needs millisecond precision
/// with integer arithmetic to match scp-core's `NonceTracker`.
///
/// **ADR-034 behavior difference from NAPI:** The NAPI bridge (via
/// `scp_primitives::time::now_secs()`) propagates errors on negative timestamps.
/// The WASM bridge silently clamps negative `Date.now()` to 0. This is
/// intentional per ADR-034 constraints — WASM cannot depend on scp-core,
/// and `Date.now()` returning a negative value in a browser indicates clock
/// misconfiguration rather than an actionable error. Clamping to 0 ensures
/// time-dependent operations (UCAN expiry, nonce freshness) fail closed
/// rather than panicking.
#[must_use]
pub fn now_ms_u64() -> u64 {
    let ms = now_ms();
    if ms < 0.0 {
        return 0;
    }
    // f64 -> u64: sign loss is guarded above; truncation is safe because
    // Unix millis (~1.8e12) is far below u64::MAX (~1.8e19).
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    {
        ms as u64
    }
}

/// Returns the current time in seconds since Unix epoch (truncated).
///
/// Convenience wrapper for UCAN time validation and other second-precision
/// checks.
#[must_use]
pub fn now_secs() -> u64 {
    now_ms_u64() / 1000
}

// ---------------------------------------------------------------------------
// WasmClock — Clock trait adapter for WASM
// ---------------------------------------------------------------------------

/// WASM clock implementation that uses the captured `Date.now()` reference.
///
/// Implements `scp_protocol::time::Clock` so that protocol functions requiring
/// a clock (UCAN validation, handle registration, rate limiting) can use the
/// hardened WASM time source.
///
/// For native test targets, the underlying `now_secs()` / `now_ms_u64()`
/// functions fall back to `SystemTime` to avoid requiring the WASM JS runtime.
pub(crate) struct WasmClock;

impl scp_protocol::time::Clock for WasmClock {
    fn now_secs(&self) -> u64 {
        super::time::now_secs()
    }

    fn now_millis(&self) -> u64 {
        super::time::now_ms_u64()
    }
}
