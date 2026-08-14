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
//! openmls's `js` feature wires `fluvio_wasm_timer::SystemTime`, which reads a
//! *live, un-captured* `Date.now()` — a second, unhardened clock openmls uses
//! internally to stamp (`Lifetime::default`/`new`) and validate
//! (`Lifetime::is_valid`) `KeyPackage` / `LeafNode` lifetimes. Prerequisite 1
//! routes SCP's use of that clock through the captured/hardened
//! [`Clock`](scp_clock::Clock) this module provides. As of the Prereq-1 landing:
//!
//! - **Generation is fully routed.** Every `KeyPackage` and group-leaf
//!   `Lifetime` SCP *mints* is built via `scp_mls::lifetime::key_package_lifetime`
//!   from the injected hardened clock (`Lifetime::init` with explicit bounds),
//!   never openmls's `Lifetime::default()`. See `scp-mls/src/group.rs`.
//! - **The receive/accept side is bracketed.** Every `Lifetime` SCP *accepts*
//!   is additionally re-validated against the injected hardened clock
//!   (`scp_mls::lifetime::validate_key_package_lifetime`) wherever openmls
//!   exposes the accepted `Lifetime` — post-`KeyPackageIn::validate`
//!   (add-member / key-package-DID) and pre-merge on staged-commit Add proposals
//!   — and the RFC 9420 maximum-range bound openmls never enforces is added
//!   there too.
//! - **Residual (V3).** openmls's own internal `Lifetime::is_valid` on the
//!   *Welcome tree-leaf* validation path is NOT injectable and NOT bracketable —
//!   but not because the accessor is private. `LeafNode::life_time()` is
//!   `pub(crate)`, yet `leaf_node_source()` IS public and its public
//!   `LeafNodeSource::KeyPackage(Lifetime)` variant hands back the `Lifetime`
//!   whenever you hold the `LeafNode`. The real blocker is that a *joined*
//!   `MlsGroup` gives no public way to reach another member's `LeafNode`:
//!   `members()`/`member_at()` yield `Member` (no lifetime),
//!   `export_ratchet_tree()`'s `RatchetTree` has no public node iterator,
//!   `public_group()` is `pub(crate)`, and only `own_leaf_node()`/`own_leaf()`
//!   are public — and that own leaf is SCP-minted anyway, so bracketing it is
//!   possible but pointless (it is not the attacker-supplied Welcome leaf).
//!   openmls 0.8 also exposes no time-provider seam, so the internal check still
//!   reads openmls's internal clock. Do NOT "fix" V3 by calling the public
//!   `leaf_node_source()` on the wrong object — there is no object that yields
//!   the joining peers' leaves. Closing this residual requires an upstream
//!   openmls change — a time-provider seam on `OpenMlsProvider` covering
//!   `Lifetime::new`/`is_valid` — requested upstream (see this change's PR body /
//!   report for the filed feature-request text). Until then, page same-origin
//!   integrity (CSP/SRI/COOP/COEP) remains load-bearing for the Welcome-leaf
//!   freshness check, exactly as it already is for the wall clock this module
//!   hardens.

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
