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

use wasm_bindgen::prelude::*;

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
#[must_use]
pub fn now_ms() -> f64 {
    captured_date_now()
}

/// Returns the current time in seconds since Unix epoch (truncated).
///
/// Convenience wrapper for UCAN time validation and other second-precision
/// checks.
#[must_use]
pub fn now_secs() -> u64 {
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    {
        (now_ms() / 1000.0) as u64
    }
}
