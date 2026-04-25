//! UCAN-side trust surface — invocation caveats integration with capability
//! stems.
//!
//! The protocol's typed UCAN surface is split between three modules:
//!
//! - [`crate::crypto::ucan`] — the historic, signature/CID-side UCAN
//!   primitives (token format, attenuation rules for raw capability strings,
//!   spending caps, revocation, validation).
//! - [`crate::context::roles::Capability`] — the structural enum of
//!   capabilities that may be referenced inside a UCAN's `att` block.
//! - [`crate::trust::caveats`] — the typed `InvocationCaveats` record that
//!   travels in a UCAN's `nb` field and attenuates outlet-targeted
//!   capabilities (§7.3.8).
//!
//! This module is the bridge between the second and the third: it provides
//! the typed surface a UCAN library uses to compute the `origin_kind` that
//! a root token's caveat set must agree with, and is the home for further
//! UCAN/caveat integration helpers (e.g., the caveat verifier surface that
//! lands in SCP-OUT-019's `narrow()` work).
//!
//! See `.docs/specs/07-trust-validation-and-capabilities.md` §7.3.8 and
//! `.docs/adrs/ADR-049-outlet-redesign.md` §3.

use crate::context::outlets::OutletKind;
use crate::context::roles::Capability;

// Re-export the caveat types under the `trust::ucan::` path so a UCAN
// library that imports `scp_protocol::trust::ucan::*` finds the typed
// caveat surface in the place a UCAN library would expect it. The
// canonical home is `trust::caveats`; this is a convenience alias only.
pub use crate::trust::caveats::{
    AttenuationViolation, CAVEAT_MINT_LIMIT_EXCEEDED_CODE, CaveatField, CaveatMintError,
    CaveatSerError, DaysOfWeekMask, HoursOfDayMask, InvocationCaveats,
    JSON_SCHEMA_NARROWING_WHITELIST, MAX_INPUT_SCHEMA_BYTES, MAX_INPUT_SCHEMA_DEPTH,
    MAX_LIST_ENTRIES, MAX_POPULATED_CAVEATS, MAX_RATE_WINDOW_SECS, MaskWidthError, RateWindow,
    assert_mask_widths, json_schema_narrows,
};

// ---------------------------------------------------------------------------
// Stem → OutletKind derivation
// ---------------------------------------------------------------------------

/// Attempts to map a capability stem to its corresponding [`OutletKind`].
///
/// Returns `Some(OutletKind::Query)` for any `outlet_query:*` stem
/// ([`Capability::OutletQuery`] / [`Capability::OutletQueryAll`]).
/// Returns `Some(OutletKind::Action)` for any `outlet_call:*` stem
/// ([`Capability::OutletCall`] / [`Capability::OutletCallAll`]).
/// Returns `None` for any other capability — the caller decides whether the
/// non-outlet stem is a separate concern or an error.
///
/// Used by [`InvocationCaveats::try_new_for_root`] (in [`super::caveats`])
/// to enforce the §7.3.8 root-UCAN single-kind invariant.
#[must_use]
pub const fn outlet_kind_for_stem(stem: &Capability) -> Option<OutletKind> {
    match stem {
        Capability::OutletQuery(_) | Capability::OutletQueryAll => Some(OutletKind::Query),
        Capability::OutletCall(_) | Capability::OutletCallAll => Some(OutletKind::Action),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_stems_map_to_query_kind() {
        assert_eq!(
            outlet_kind_for_stem(&Capability::OutletQueryAll),
            Some(OutletKind::Query)
        );
        assert_eq!(
            outlet_kind_for_stem(&Capability::OutletQuery("foo".to_owned())),
            Some(OutletKind::Query)
        );
    }

    #[test]
    fn call_stems_map_to_action_kind() {
        assert_eq!(
            outlet_kind_for_stem(&Capability::OutletCallAll),
            Some(OutletKind::Action)
        );
        assert_eq!(
            outlet_kind_for_stem(&Capability::OutletCall("bar".to_owned())),
            Some(OutletKind::Action)
        );
    }

    #[test]
    fn non_outlet_stems_return_none() {
        assert_eq!(outlet_kind_for_stem(&Capability::MessagesRead), None);
        assert_eq!(outlet_kind_for_stem(&Capability::OutletRegister), None);
        assert_eq!(
            outlet_kind_for_stem(&Capability::Custom("x".to_owned())),
            None
        );
    }

    #[test]
    fn caveat_types_re_exported() {
        // Compile-time re-export check.
        let _ = InvocationCaveats::empty();
        let _: Option<HoursOfDayMask> = HoursOfDayMask::from_bits(0);
        let _: Option<DaysOfWeekMask> = DaysOfWeekMask::from_bits(0);
        assert_eq!(MAX_POPULATED_CAVEATS, 8);
    }
}
