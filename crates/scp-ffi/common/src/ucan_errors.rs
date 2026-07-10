//! Canonical `UcanError` → `error_code` mapping shared by all FFI bridges.
//!
//! Every bridge (`PyO3`, `napi-rs`, `UniFFI`) previously inlined
//! its own `From<UcanError>` impl, all returning the same `SCP-PERM-3001`
//! code. That duplication let the bridges silently drift (as they did
//! before the round-11 fix that consolidated the ad-hoc
//! paths onto this code).
//!
//! This module exposes one function — [`ucan_error_code`] — that every
//! bridge routes through. Any change to the UCAN error classification
//! (e.g. splitting `TokenExpired` off `PERM_3001` onto `PERM_3007`)
//! happens here exactly once and propagates to every bridge.
//!
//! `UcanError` lives in `scp-protocol`, which every bridge
//! already depends on, so this function has no additional
//! feature gate.
//!
//! Provenance: `.docs/adrs/ADR-046-bridge-parity-harness.md` round 11
//! MINOR-1 (adversarial), tracking back to the cross-bridge parity
//! harness gate on `ucan_validate_malformed` in
//! `bindings/python/tests/bridge_parity/seed_operations.py`.

use crate::error_codes as codes;
use scp_protocol::crypto::ucan::UcanError;

/// Maps a [`UcanError`] to its canonical SCP error code string.
///
/// Every current variant maps to [`codes::PERM_3001`] ("generic UCAN
/// validation failure"). The exhaustive `match` is deliberate — any
/// new variant added to [`UcanError`] in `scp-protocol` becomes a
/// compile error here until a classification decision is made and the
/// match arm is added. A blanket `_ => PERM_3001` catch-all would
/// silently route new failure modes through the generic bucket.
///
/// Downstream splits (`TokenExpired` → `PERM_3007`, `TokenRevoked` →
/// `PERM_3008`) are intentionally held back until the companion test
/// updates (`bindings/python/tests/test_trust.py`) land in the same
/// change. The arms below already call out those PERM codes so the
/// refinement PR is a ~3-line diff.
#[must_use]
// Every arm currently routes to `PERM_3001` — that is deliberate, not
// redundant. The groupings document classification buckets (structural,
// scope, expiry, nonce, capability, revocation) so a future refinement
// PR can split one bucket onto a new code without re-doing the match.
// Collapsing the arms to `_ =>` would silently bypass the enforcement
// (new variants route to `PERM_3001` with no type-system prompt).
#[allow(clippy::match_same_arms)]
pub const fn ucan_error_code(err: &UcanError) -> &'static str {
    match err {
        // Structural / signature failures.
        UcanError::MalformedToken(_)
        | UcanError::DeserializationFailed(_)
        | UcanError::UnsupportedAlgorithm(_)
        | UcanError::UnsupportedVersion(_)
        | UcanError::SignatureInvalid => codes::PERM_3001,

        // Issuer / audience / scope mismatches.
        UcanError::InvalidIssuer { .. }
        | UcanError::AudienceMismatch { .. }
        | UcanError::KeyScopeMismatch { .. }
        | UcanError::SelfDelegationWithoutKeyScope
        | UcanError::CategoryAViolation { .. } => codes::PERM_3001,

        // Expiry / validity window. Natural `PERM_3007` candidates —
        // held back pending test_trust.py update (see fn doc).
        UcanError::ExpiryTooFar(_)
        | UcanError::TokenExpired
        | UcanError::TokenNotYetValid
        | UcanError::InvalidTimeRange { .. } => codes::PERM_3001,

        // Nonce failures.
        UcanError::NonceReused(_)
        | UcanError::NonceTooOld(_)
        | UcanError::NonceFuture(_)
        | UcanError::NonceFormatInvalid(_)
        | UcanError::NonceTrackerFull(_) => codes::PERM_3001,

        // Capability / delegation failures. The two caveat variants are
        // per-edge caveat-narrowing (§7.3.8 Step 7b) and time-box (Step 11b)
        // enforcement failures surfaced by the outlet-invocation validation
        // path's `TokenNbCaveatResolver`.
        UcanError::CapabilityOutsideCeiling(_)
        | UcanError::CapabilityNotGranted(_)
        | UcanError::AttenuationViolation(_)
        | UcanError::CaveatAttenuationViolation(_)
        | UcanError::CaveatTimeBoxViolation(_)
        | UcanError::DelegationChainBroken(_)
        | UcanError::CircularDelegation(_) => codes::PERM_3001,

        // Revocation. `TokenRevoked` is a natural `PERM_3008` candidate —
        // held back per fn doc. `RevocationUnauthorized` and
        // `RevocationFailed` cover the revoke-operation-side errors.
        UcanError::TokenRevoked(_)
        | UcanError::RevocationUnauthorized(_)
        | UcanError::RevocationFailed(_) => codes::PERM_3001,

        // Capability URI parsing.
        UcanError::InvalidCapabilityUri(_) => codes::PERM_3001,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mapped_variant_currently_routes_to_perm_3001() {
        // Spot-check one per classification bucket. The exhaustive
        // match in `ucan_error_code` is the primary guard — this test
        // is a secondary belt-and-braces check that the current
        // classification is coherent.
        for err in [
            UcanError::MalformedToken("bad".to_owned()),
            UcanError::SignatureInvalid,
            UcanError::TokenExpired,
            UcanError::NonceReused("nonce".to_owned()),
            UcanError::CapabilityNotGranted("cap".to_owned()),
            UcanError::CaveatTimeBoxViolation("time-box".to_owned()),
            UcanError::TokenRevoked("cid".to_owned()),
        ] {
            assert_eq!(ucan_error_code(&err), codes::PERM_3001);
        }
    }
}
