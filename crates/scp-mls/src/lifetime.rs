//! `KeyPackage` `Lifetime` minting and validation routed through the injected
//! [`scp_clock::Clock`] (ADR-057 Prerequisite 1).
//!
//! # Why this module exists
//!
//! `openmls` mints and validates `KeyPackage` [`Lifetime`]s from *its own*
//! internal clock. [`Lifetime::new`](openmls::prelude::Lifetime) and
//! [`Lifetime::default`](openmls::prelude::Lifetime) read `SystemTime::now()`;
//! [`Lifetime::validate`](openmls::prelude::Lifetime) re-reads the same clock at
//! validation time. Under the `openmls` `js` feature (the wasm build) that
//! `SystemTime` is `web_time::SystemTime` (openmls 0.9.0), which reads a *live,
//! un-captured* `Date.now()` — a **second, unhardened clock**, distinct from the
//! SCP-layer hardened [`Clock`] injected through the rest of
//! the client, and fully attacker-overridable in-tab. Left as-is, a hostile
//! same-origin script can mint or accept `KeyPackage`s with forged `Lifetime`s
//! (expiry / `not_before` manipulation). This does not break MLS
//! confidentiality — group secrets stay sound — but it defeats `KeyPackage`
//! freshness/expiry as a defense.
//!
//! `openmls` 0.9.0 reads its own clock in `Lifetime::new`, `Lifetime::default`,
//! and the `Lifetime::validate` its internal checks run, and offers no way to
//! route those reads through a caller's clock. Of the checks SCP reaches, only
//! the Welcome tree-leaf check can be switched off, and SCP switches it off
//! (see below). It exposes two
//! caller-side entry points that take the time from the caller, and this module
//! uses both:
//! [`Lifetime::init`](openmls::prelude::Lifetime), a pure constructor that takes
//! caller-supplied `not_before`/`not_after` bounds, and
//! `Lifetime::validate_with_time(now)`, new in 0.9.0. This module:
//!
//! - **Mints** every `Lifetime` SCP generates via [`key_package_lifetime`],
//!   which reads the injected [`Clock`] and calls
//!   `Lifetime::init` with bounds derived from it (never the openmls default).
//! - **Validates** every `Lifetime` SCP accepts via
//!   [`validate_key_package_lifetime`], which runs `validate_with_time` with a
//!   `now` built from the injected [`Clock`] wherever openmls exposes
//!   the accepted `Lifetime` (post-`validate` on `KeyPackageIn`, pre-merge on
//!   staged-commit Add proposals, and on Welcome tree leaves post-`into_group`
//!   and pre-adoption), and additionally enforces the RFC 9420
//!   maximum-total-range bound that openmls's own `validate` path never checks.
//!   One exception: [`crate::ratchet::process_commit`]
//!   (`crates/scp-mls/src/ratchet.rs`), a path only tests call, merges a
//!   Commit's staged Add proposals without the pre-merge check.
//!
//! # openmls's internal check, bracketed or switched off
//!
//! openmls's own `Lifetime::validate` still runs inside `KeyPackageIn::validate`
//! and `process_message`, against openmls's internal clock (the real wall clock
//! natively; the attacker-overridable `Date.now()` through `web_time` on wasm),
//! because those checks call `validate`, never `validate_with_time` with a
//! caller's time, and neither can be switched off. This is the residual ADR-057
//! Prerequisite 1 records: there are still two clocks. SCP brackets both paths
//! against the injected clock, in addition to that internal check and never in
//! place of it, so an accept decision needs both checks to pass and openmls's
//! clock can only add rejections. A page script that overrides `Date.now()`
//! after the browser client's clock module initializes can make an honest
//! `KeyPackage` or commit fail, but cannot get a forged `Lifetime` accepted.
//! In [`crate::group::join_group_from_bytes`] openmls's tree-leaf check is
//! switched off and SCP's check is the only one, so there openmls's clock is
//! never read for a `Lifetime`. The residual closes when openmls lets the
//! caller supply the clock that `KeyPackageIn::validate` and
//! `process_message` read. The paths:
//!
//! - `KeyPackageIn::validate`: [`crate::group::add_member`],
//!   [`crate::group::key_package_in_did`],
//!   [`crate::group::key_package_in_wrapping_key`], and the runtime backend's
//!   `validate_key_package` in `scp-runtime` (`crypto/mls/production_backend.rs`
//!   and `crypto/mls/provider.rs`). Also `ProductionMlsBackend::join_from_welcome`
//!   → `consumed_init_key_key` in `scp-runtime`, which validates the joiner's own
//!   `KeyPackage`, on native only, with no SCP bracket, so openmls's clock there
//!   can reject a join before `join_group_from_bytes` runs.
//! - `process_message`: the staged-commit Add proposals in
//!   [`crate::encrypt::decrypt_with_sender_did`] and
//!   [`crate::encrypt::decrypt_with_membership_changes`], checked before the
//!   merge.
//! - Welcome tree leaves, the one check: [`crate::group::join_group_from_bytes`]
//!   builds the staged Welcome through
//!   `StagedWelcome::build_from_welcome(...)?.skip_lifetime_validation().build()`,
//!   which switches off openmls's tree-leaf `Lifetime` check and keeps the rest
//!   of its leaf validation, then calls `validate_tree_leaf_lifetimes` after
//!   `StagedWelcome::into_group` and before it builds the `ScpMlsGroup`.
//!   openmls 0.9.0 exposes `MlsGroup::treesync()`, and `TreeSync::full_leaves()`
//!   yields every non-blank leaf of the joined tree with its
//!   `LeafNodeSource::KeyPackage(Lifetime)`, the same leaf set openmls's
//!   switched-off check covered.
//!
//! # Test-clock realism constraint (IMPORTANT)
//!
//! Because openmls's un-injectable internal `validate`/`Lifetime::new` still
//! runs against the **real** system clock at every openmls validation/generation
//! site (every one except a Welcome's tree leaves), an injected [`Clock`] used in a test must sit within
//! `(real_now - KEY_PACKAGE_LIFETIME_SECS, real_now + KEY_PACKAGE_LIFETIME_MARGIN_SECS)`
//! of the real clock — otherwise a `KeyPackage` minted from the injected clock is
//! rejected by openmls's *own* internal validation before this module's check
//! ever runs. Seed test clocks from `SystemClock.now_secs()` and apply small
//! relative offsets; do not use absolute fixed epochs far from the real present.

use core::time::Duration;

use openmls::prelude::{Lifetime, MlsGroup};
use openmls::treesync::LeafNodeSource;
use scp_clock::Clock;

use crate::error::MlsError;

/// Default `KeyPackage` lifetime, in seconds: `3 * 28` days (~3 months).
///
/// Mirrors openmls's private `DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS`
/// (`60 * 60 * 24 * 28 * 3`). Kept in sync deliberately so an SCP-minted
/// `Lifetime` matches the shape openmls's own default would have produced,
/// only sourced from the injected [`Clock`] instead of
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

/// Mints a `KeyPackage` [`Lifetime`] from the injected [`Clock`].
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
/// [`Clock`].
///
/// This is SCP's hardened counterpart to openmls's `Lifetime::validate`, which
/// reads openmls's un-injectable internal clock. It performs two checks:
///
/// 1. **Temporal validity** — openmls 0.9.0 `Lifetime::validate_with_time`,
///    which accepts `not_before <= now && now < not_after`, called with `now`
///    read from the injected clock. SCP calls openmls's comparison instead of
///    keeping its own, so SCP's temporal rule cannot drift from openmls's (a
///    hand-written copy went stale when openmls 0.9.0 moved the `not_before`
///    bound from strict `<` to `<=`). The call compiles on both targets because
///    `now` is a `web_time::SystemTime`, the type `validate_with_time` takes on
///    every target: `web_time` re-exports
///    `std::time::SystemTime` natively and supplies its own type on
///    `wasm32-unknown-unknown`, where openmls uses it. One call therefore
///    compiles on both without a cfg branch.
/// 2. **Maximum range** — enforces the RFC 9420 bound that openmls's own
///    `validate` path never applies: `not_after - not_before <=
///    KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS`. A legitimately-signed `Lifetime`
///    with an over-long range (which openmls would accept) is rejected here.
///
/// Both checks must pass. On the `KeyPackageIn::validate` and staged-commit Add
/// paths this runs in addition to openmls's own internal validation. On the
/// Welcome tree-leaf path (`validate_tree_leaf_lifetimes`) openmls's check is
/// switched off and this is the only one.
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

    // openmls 0.9.0 rejects `not_after <= now` (expired) and `not_before > now`
    // (not yet valid). A `now` too large for `SystemTime` fails closed.
    let temporally_valid = web_time::UNIX_EPOCH
        .checked_add(Duration::from_secs(now))
        .is_some_and(|at| lifetime.validate_with_time(at).is_ok());

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

/// Validates the `Lifetime` of every KeyPackage-sourced leaf in a joined
/// group's tree against the injected [`Clock`], through
/// [`validate_key_package_lifetime`] (ADR-057 §Prereq-1).
///
/// `MlsGroup::treesync().full_leaves()` (openmls 0.9.0
/// `group/mls_group/mod.rs:417`, `treesync/mod.rs:685`) yields every non-blank
/// leaf, the joiner's own included. A leaf whose source is
/// `LeafNodeSource::Update` or `LeafNodeSource::Commit` carries no `Lifetime`
/// (RFC 9420 §7.2) and is skipped.
///
/// # Errors
///
/// Returns [`MlsError::KeyPackageLifetimeInvalid`] for the first leaf whose
/// `Lifetime` fails the temporal or maximum-range check.
pub(crate) fn validate_tree_leaf_lifetimes(
    group: &MlsGroup,
    clock: &dyn Clock,
) -> Result<(), MlsError> {
    for (_index, leaf) in group.treesync().full_leaves() {
        if let LeafNodeSource::KeyPackage(lifetime) = leaf.leaf_node_source() {
            validate_key_package_lifetime(lifetime, clock)?;
        }
    }
    Ok(())
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
        // Temporally valid (not_before <= now < not_after) but the total range
        // exceeds the max — openmls's own validate would accept this, our check
        // rejects it.
        let now = 10_000_000u64;
        let clock = TestClock::new(now);
        let lt = Lifetime::init(now - 10, now + KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS + 10);
        let err = validate_key_package_lifetime(&lt, &clock).unwrap_err();
        assert!(matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }));
    }

    #[test]
    fn validate_accepts_now_equal_to_not_before() {
        let now = 10_000_000u64;
        let lt = Lifetime::init(now, now + 100);
        assert!(validate_key_package_lifetime(&lt, &TestClock::new(now)).is_ok());
    }

    #[test]
    fn validate_rejects_now_equal_to_not_after() {
        let now = 10_000_000u64;
        let lt = Lifetime::init(now - 100, now);
        let err = validate_key_package_lifetime(&lt, &TestClock::new(now)).unwrap_err();
        assert!(matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }));
    }

    #[test]
    fn validate_rejects_now_one_second_before_not_before() {
        let not_before = 10_000_000u64;
        let lt = Lifetime::init(not_before, not_before + 100);
        let err = validate_key_package_lifetime(&lt, &TestClock::new(not_before - 1)).unwrap_err();
        assert!(matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }));
    }

    /// A clock reading too large for `SystemTime` fails closed rather than
    /// panicking in `UNIX_EPOCH + now`. `TestClock` stores milliseconds and
    /// cannot reach that range, so this clock reports seconds directly.
    #[test]
    fn validate_rejects_now_beyond_system_time_range() {
        const FAR_NOW: u64 = u64::MAX - 5;
        struct FarClock;
        impl Clock for FarClock {
            fn now_secs(&self) -> u64 {
                FAR_NOW
            }
            fn now_millis(&self) -> u64 {
                u64::MAX
            }
        }
        // The bounds hold (`not_before <= FAR_NOW < not_after`) and the range
        // is 10s, so only the `SystemTime` overflow can reject this lifetime.
        let lt = Lifetime::init(FAR_NOW - 5, FAR_NOW + 5);
        let err = validate_key_package_lifetime(&lt, &FarClock).unwrap_err();
        assert!(matches!(
            err,
            MlsError::KeyPackageLifetimeInvalid { now, .. } if now == FAR_NOW
        ));
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
