//! `KeyPackage` `Lifetime` minting and validation routed through the injected
//! [`scp_clock::Clock`] (ADR-057 Prerequisite 1).
//!
//! # Why this module exists
//!
//! `openmls` mints and validates `KeyPackage` [`Lifetime`]s from *its own*
//! internal clock. [`Lifetime::new`](openmls::prelude::Lifetime) and
//! [`Lifetime::default`](openmls::prelude::Lifetime) read `SystemTime::now()`;
//! [`Lifetime::is_valid`](openmls::prelude::Lifetime) re-reads the same clock at
//! validation time. Under the `openmls` `js` feature (the wasm build) that
//! `SystemTime` is `fluvio_wasm_timer::SystemTime`, which reads a *live,
//! un-captured* `Date.now()` — a **second, unhardened clock**, distinct from the
//! SCP-layer hardened [`Clock`](scp_clock::Clock) injected through the rest of
//! the client, and fully attacker-overridable in-tab. Left as-is, a hostile
//! same-origin script can mint or accept `KeyPackage`s with forged `Lifetime`s
//! (expiry / `not_before` manipulation). This does not break MLS
//! confidentiality — group secrets stay sound — but it defeats `KeyPackage`
//! freshness/expiry as a defense.
//!
//! `openmls` 0.8 exposes **no** clock-injection seam on `Lifetime`. The
//! real seam the cryptographer review identified is
//! [`Lifetime::init`](openmls::prelude::Lifetime) — a pure constructor that
//! takes caller-supplied `not_before`/`not_after` bounds and bypasses the
//! internal `SystemTime::now()`. This module:
//!
//! - **Mints** every `Lifetime` SCP generates via [`key_package_lifetime`],
//!   which reads the injected [`Clock`](scp_clock::Clock) and calls
//!   `Lifetime::init` with bounds derived from it (never the openmls default).
//! - **Validates** every `Lifetime` SCP accepts via
//!   [`validate_key_package_lifetime`], which re-checks temporal validity
//!   against the injected [`Clock`](scp_clock::Clock) wherever openmls exposes
//!   the accepted `Lifetime` (post-`validate` on `KeyPackageIn`, pre-merge on
//!   staged-commit Add proposals), and additionally enforces the RFC 9420
//!   maximum-total-range bound that openmls's own `validate` path never checks.
//!
//! # Residual: openmls's un-injectable internal check still runs
//!
//! openmls's own `Lifetime::is_valid` (called inside `KeyPackageIn::validate`
//! and the Welcome tree-leaf validation) is **not** injectable and still runs
//! against openmls's internal clock (the real wall clock natively; the
//! attacker-overridable `Date.now()` on wasm). The SCP checks in this module
//! sit *in addition to* that internal check — they never replace or weaken it.
//! The remaining residual (openmls validating Welcome tree leaves against its
//! own clock, with no public accessor to bracket) is tracked upstream; see the
//! `SECURITY (ADR-057 §Prereq-1)` notes in [`crate::group`] and the browser
//! surface's `time.rs`.
//!
//! # Test-clock realism constraint (IMPORTANT)
//!
//! Because openmls's un-injectable internal `is_valid`/`Lifetime::new` still
//! runs against the **real** system clock at every openmls validation/generation
//! site, an injected [`Clock`](scp_clock::Clock) used in a test must sit within
//! `(real_now - KEY_PACKAGE_LIFETIME_SECS, real_now + KEY_PACKAGE_LIFETIME_MARGIN_SECS)`
//! of the real clock — otherwise a `KeyPackage` minted from the injected clock is
//! rejected by openmls's *own* internal validation before this module's check
//! ever runs. Seed test clocks from `SystemClock.now_secs()` and apply small
//! relative offsets; do not use absolute fixed epochs far from the real present.

use openmls::prelude::Lifetime;
use scp_clock::Clock;

use crate::error::MlsError;

/// Default `KeyPackage` lifetime, in seconds: `3 * 28` days (~3 months).
///
/// Mirrors openmls's private `DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS`
/// (`60 * 60 * 24 * 28 * 3`). Kept in sync deliberately so an SCP-minted
/// `Lifetime` matches the shape openmls's own default would have produced,
/// only sourced from the injected [`Clock`](scp_clock::Clock) instead of
/// openmls's internal one.
pub const KEY_PACKAGE_LIFETIME_SECS: u64 = 60 * 60 * 24 * 28 * 3;

/// Backdating margin applied to `not_before`, in seconds: 1h.
///
/// Mirrors openmls's private `DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS`
/// (`60 * 60`). The `not_before` bound is set to `now - margin` to tolerate
/// modest clock skew between peers, matching openmls's `Lifetime::new`.
pub const KEY_PACKAGE_LIFETIME_MARGIN_SECS: u64 = 60 * 60;

/// Maximum acceptable total lifetime range (`not_after - not_before`), in
/// seconds.
///
/// Mirrors openmls's private `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS`
/// (`DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS + DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS`).
/// RFC 9420 (ValSem/openmls annotations #32) requires applications to define a
/// maximum acceptable total lifetime and reject any leaf whose range exceeds it.
/// openmls *has* a `Lifetime::has_acceptable_range` helper but does **not** call
/// it inside `KeyPackageIn::validate`, so an over-long (but temporally valid,
/// legitimately signed) `Lifetime` passes openmls's own validation. SCP enforces
/// the bound explicitly in [`validate_key_package_lifetime`].
pub const KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS: u64 =
    KEY_PACKAGE_LIFETIME_MARGIN_SECS + KEY_PACKAGE_LIFETIME_SECS;

/// Mints a `KeyPackage` [`Lifetime`] from the injected [`Clock`](scp_clock::Clock).
///
/// Reads `now` from the hardened clock and constructs the `Lifetime` via
/// [`Lifetime::init`](openmls::prelude::Lifetime) — the pure constructor that
/// bypasses openmls's internal `SystemTime::now()`. The bounds match openmls's
/// own `Lifetime::new(KEY_PACKAGE_LIFETIME_SECS)` shape:
///
/// - `not_before = now - KEY_PACKAGE_LIFETIME_MARGIN_SECS` (1h backdate for skew)
/// - `not_after  = now + KEY_PACKAGE_LIFETIME_SECS` (~3 months)
///
/// Saturating arithmetic keeps a `now` near 0 (e.g. `TestClock::new(0)`) from
/// panicking: `not_before` saturates to 0 rather than underflowing.
#[must_use]
pub fn key_package_lifetime(clock: &dyn Clock) -> Lifetime {
    let now = clock.now_secs();
    let not_before = now.saturating_sub(KEY_PACKAGE_LIFETIME_MARGIN_SECS);
    let not_after = now.saturating_add(KEY_PACKAGE_LIFETIME_SECS);
    Lifetime::init(not_before, not_after)
}

/// Validates a `KeyPackage` [`Lifetime`] against the injected
/// [`Clock`](scp_clock::Clock).
///
/// This is SCP's hardened counterpart to openmls's `Lifetime::is_valid`, which
/// reads openmls's un-injectable internal clock. It performs two checks:
///
/// 1. **Temporal validity** — mirrors openmls's `is_valid` *exactly* (strict
///    inequalities): `not_before < now && now < not_after`, with `now` read from
///    the injected clock.
/// 2. **Maximum range** — enforces the RFC 9420 bound that openmls's own
///    `validate` path never applies: `not_after - not_before <=
///    KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS`. A legitimately-signed `Lifetime`
///    with an over-long range (which openmls would accept) is rejected here.
///
/// Both checks must pass. This runs *in addition to* openmls's own internal
/// validation, never in place of it.
///
/// # Errors
///
/// Returns [`MlsError::KeyPackageLifetimeInvalid`] if the lifetime is expired,
/// not yet valid, or exceeds the maximum acceptable total range. The error
/// carries `not_before`, `not_after`, and the observed `now` for diagnostics.
pub fn validate_key_package_lifetime(
    lifetime: &Lifetime,
    clock: &dyn Clock,
) -> Result<(), MlsError> {
    let now = clock.now_secs();
    let not_before = lifetime.not_before();
    let not_after = lifetime.not_after();

    // Mirror openmls `Lifetime::is_valid` exactly: strict `<` on both bounds.
    let temporally_valid = not_before < now && now < not_after;

    // RFC 9420 (ValSem / openmls annotations #32) maximum-range bound. openmls
    // exposes `has_acceptable_range` but does NOT call it in `validate`, so we
    // enforce it explicitly here. Saturating so an inverted range can't wrap.
    let range_acceptable =
        not_after.saturating_sub(not_before) <= KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS;

    if temporally_valid && range_acceptable {
        Ok(())
    } else {
        Err(MlsError::KeyPackageLifetimeInvalid {
            not_before,
            not_after,
            now,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_clock::TestClock;

    #[test]
    fn mint_pins_bounds_relative_to_injected_clock() {
        let clock = TestClock::new(1_000_000);
        let lt = key_package_lifetime(&clock);
        assert_eq!(
            lt.not_before(),
            1_000_000 - KEY_PACKAGE_LIFETIME_MARGIN_SECS
        );
        assert_eq!(lt.not_after(), 1_000_000 + KEY_PACKAGE_LIFETIME_SECS);
    }

    #[test]
    fn mint_saturates_at_zero_without_panic() {
        let clock = TestClock::new(0);
        let lt = key_package_lifetime(&clock);
        assert_eq!(lt.not_before(), 0, "not_before must saturate to 0");
        assert_eq!(lt.not_after(), KEY_PACKAGE_LIFETIME_SECS);
    }

    #[test]
    fn validate_accepts_freshly_minted_lifetime() {
        let clock = TestClock::new(2_000_000);
        let lt = key_package_lifetime(&clock);
        assert!(validate_key_package_lifetime(&lt, &clock).is_ok());
    }

    #[test]
    fn validate_rejects_expired_lifetime() {
        let clock = TestClock::new(2_000_000);
        let lt = key_package_lifetime(&clock);
        // Advance well past not_after.
        let later = TestClock::new(2_000_000 + KEY_PACKAGE_LIFETIME_SECS + 10);
        let err = validate_key_package_lifetime(&lt, &later).unwrap_err();
        assert!(matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }));
    }

    #[test]
    fn validate_rejects_not_yet_valid_lifetime() {
        // Lifetime minted for a far-future clock: not_before is in the future
        // relative to the validation clock.
        let mint_clock = TestClock::new(5_000_000);
        let lt = key_package_lifetime(&mint_clock);
        let early = TestClock::new(1_000);
        let err = validate_key_package_lifetime(&lt, &early).unwrap_err();
        assert!(matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }));
    }

    #[test]
    fn validate_rejects_over_long_range_that_openmls_would_accept() {
        // Temporally valid (not_before < now < not_after) but the total range
        // exceeds the max — openmls's own is_valid would accept this, our check
        // rejects it.
        let now = 10_000_000u64;
        let clock = TestClock::new(now);
        let lt = Lifetime::init(now - 10, now + KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS + 10);
        let err = validate_key_package_lifetime(&lt, &clock).unwrap_err();
        assert!(matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }));
    }

    #[test]
    fn validate_accepts_exact_max_range() {
        let now = 10_000_000u64;
        let clock = TestClock::new(now);
        // Range exactly at the bound: not_after - not_before == MAX.
        let lt = Lifetime::init(now - 10, now - 10 + KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS);
        assert!(validate_key_package_lifetime(&lt, &clock).is_ok());
    }
}
