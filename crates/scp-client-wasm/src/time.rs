//! Hardened time source for the browser participant surface.
//!
//! Restored faithfully from the deleted WASM bridge's `time.rs`
//! (`crates/scp-ffi/wasm/`, pinned at `1a3b41a5e^`) — this module is
//! **security-load-bearing**, so its hardening is preserved rather than
//! simplified.
//!
//! `js_sys::Date::now()` delegates to JavaScript's `Date.now()`, which any
//! same-origin script can override (`Date.now = () => 0`). An attacker who
//! replaces `Date.now` after the page loads can push the wall clock to forge
//! the time the protocol reads — driving committer-assigned event-log leaf
//! timestamps, and (via the same wall clock the rest of the client uses) any
//! local-time-dependent check such as a `KeyPackage` `Lifetime` or UCAN
//! expiry/nbf (ADR-057 Consequences: "local wall-clock is attacker-controllable
//! in-tab").
//!
//! Mitigation: capture the *original* `Date.now` function reference at WASM
//! module instantiation time via `#[wasm_bindgen(inline_js)]`. The captured
//! binding survives later `Date.now` overrides, narrowing the attack window to
//! script that runs *before* the WASM module is initialized. This does not
//! *close* the window — page same-origin integrity (CSP/SRI/COOP/COEP) remains
//! load-bearing per ADR-057 — but it removes the trivial post-init override.
//!
//! # Relationship to the openmls `Lifetime` clock (ADR-057 Prerequisite 1)
//!
//! openmls's `js` feature wires `web_time::SystemTime` (openmls 0.9.0), which
//! reads a *live, un-captured* `Date.now()` — a second, unhardened clock openmls
//! uses internally to stamp (`Lifetime::default`/`new`) and validate
//! (`Lifetime::validate`) `KeyPackage` / `LeafNode` lifetimes. Prerequisite 1
//! routes SCP's use of that clock through the captured/hardened
//! [`Clock`](scp_clock::Clock) this module provides. As of the Prereq-1 landing:
//!
//! - **Generation is fully routed.** Every `KeyPackage` and group-leaf
//!   `Lifetime` SCP *mints* is built via `scp_mls::lifetime::key_package_lifetime`
//!   from the injected hardened clock (`Lifetime::init` with explicit bounds),
//!   never openmls's `Lifetime::default()`. See `scp-mls/src/group.rs`.
//! - **The add side is bracketed, with a minimum.** Every `KeyPackage` SCP
//!   *adds* is re-validated after `KeyPackageIn::validate` against the injected
//!   hardened clock (`scp_mls::lifetime::validate_key_package_lifetime_for_add`):
//!   the current time lies within its `Lifetime`, its range is within the RFC
//!   9420 maximum openmls never enforces, and at least
//!   `KEY_PACKAGE_MIN_REMAINING_LIFETIME_SECS` (7 days + 1 hour) remains
//!   (security-model spec §9.7.1, the adder).
//! - **The receive side reads no clock.** An Add received in a Commit or a
//!   Proposal is checked for range only
//!   (`MlsError::ReceivedKeyPackageLifetimeRangeInvalid`), so neither this
//!   module's clock nor `Date.now()` takes part in SCP's own verdict on it
//!   (security-model spec §9.7.1, the receiver).
//! - **Welcome tree leaves: no clock (V3).**
//!   `scp_mls::group::join_group_from_bytes` switches openmls's tree-leaf
//!   `Lifetime` check off (`skip_lifetime_validation`) and checks only each
//!   KeyPackage-sourced leaf's range: it rejects a leaf whose `not_after` is
//!   not later than its `not_before` or whose range exceeds the maximum. No
//!   clock, neither this module's nor `Date.now()`, takes part in the decision
//!   on another member's tree leaf. The joiner's own `KeyPackage` must still be
//!   current: `scp_client::ScpClient::join_context_encrypted` passes this
//!   module's clock to `join_group_from_bytes`, which checks the joiner's own
//!   leaf's `Lifetime` against it before it returns a group.
//! - **Residual: openmls's internal check still runs on two paths.** openmls
//!   0.9.0's internal checks call `Lifetime::validate`, never
//!   `validate_with_time` with a caller's time, so its own check inside
//!   `KeyPackageIn::validate` and `process_message` still reads `web_time`'s
//!   `Date.now()`. On the add path SCP's check against this module's clock
//!   also runs, so there openmls's clock can only add rejections, and a page
//!   script that overrides `Date.now()` cannot get a forged `Lifetime`
//!   accepted on an add. On the receive path SCP's verdict is the range
//!   check, which reads no clock; openmls's own check is the only clock check
//!   there, so a `Date.now()` override can only add rejections and can make an
//!   honest add-Commit fail. The adder's minimum remaining lifetime bounds
//!   openmls's check, and the residual-case list of security-model spec
//!   §9.7.1 names every case in which it still refuses an add-Commit.
//!   Page same-origin integrity (CSP/SRI/COOP/COEP) stays load-bearing for
//!   every add-side `Lifetime` decision, because a script that runs before this module
//!   initializes shifts the captured clock too. The residual closes when
//!   openmls exposes a receive-side lifetime policy SCP can set to skip the
//!   current-time check, and lets the caller supply the clock
//!   `KeyPackageIn::validate` reads.

use scp_clock::Clock;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = "
const _dateNow = Date.now.bind(Date);
export function captured_date_now() { return _dateNow(); }
")]
extern "C" {
    /// Returns milliseconds since the Unix epoch using a `Date.now` reference
    /// bound at module-initialization time (before any later override).
    #[wasm_bindgen(js_name = "captured_date_now")]
    fn captured_date_now() -> f64;
}

/// Returns the current time in milliseconds since the Unix epoch.
///
/// On `wasm32` this reads the captured `Date.now` reference (see module docs).
/// On native host builds (where the `inline_js` extern does not exist) it falls
/// back to `SystemTime`, so host tests can drive the surface without a JS
/// runtime. The native branch is compiled out of the real
/// `wasm32-unknown-unknown` browser build and therefore cannot weaken the
/// hardened-clock property in production.
#[must_use]
#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    captured_date_now()
}

/// Native-host fallback for [`now_ms`] (see the `wasm32` variant's docs).
#[must_use]
#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // `as_secs_f64() * 1000.0` mirrors JS `Date.now()`'s millisecond `f64`
    // without an int->float cast (so no `cast_precision_loss`).
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
}

/// Returns the current time in milliseconds since the Unix epoch as `u64`.
///
/// Negative values (clock misconfiguration) clamp to `0`. The `f64`
/// representation is exact for integers up to 2^53, and Unix millis in 2026
/// (~1.8e12) is well within that range.
///
/// Clamping (rather than erroring) makes time-dependent operations fail closed:
/// a `Date.now()` of `0` yields the *oldest* possible timestamp, which expires
/// rather than extends any window. This mirrors the deleted bridge's documented
/// ADR-034 behavior.
#[must_use]
fn now_ms_u64() -> u64 {
    let ms = now_ms();
    if ms < 0.0 {
        return 0;
    }
    // f64 -> u64: sign loss is guarded above; truncation is safe because Unix
    // millis (~1.8e12) is far below u64::MAX (~1.8e19).
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    {
        ms as u64
    }
}

/// The hardened [`Clock`] the participant driver reads for committer-assigned
/// event-log leaf timestamps.
///
/// Implements [`scp_clock::Clock`], so it drops straight into
/// [`scp_client::ScpClient::new`]'s clock slot. In a browser this is the *only*
/// SCP-layer clock; the driver must never read `js_sys::Date::now()` directly
/// (which would reintroduce the post-init override the capture defends against).
#[derive(Debug, Default, Clone, Copy)]
pub struct WasmClock;

impl WasmClock {
    /// Creates a hardened wasm clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for WasmClock {
    fn now_secs(&self) -> u64 {
        now_ms_u64() / 1000
    }

    fn now_millis(&self) -> u64 {
        now_ms_u64()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn wasm_clock_reads_a_plausible_native_time() {
        // On the host the clock falls back to SystemTime; assert it is a sane,
        // post-2020 value (the wasm path is exercised by the wasm-target tests).
        let clock = WasmClock::new();
        assert!(
            clock.now_secs() > 1_577_836_800,
            "native fallback clock returns a post-2020 timestamp"
        );
        assert!(
            clock.now_millis() >= clock.now_secs().saturating_mul(1000),
            "millis is consistent with seconds"
        );
    }
}
