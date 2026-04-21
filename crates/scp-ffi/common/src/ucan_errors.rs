//! Canonical `UcanError` → `error_code` mapping shared by all FFI bridges.
//!
//! Every bridge (`PyO3`, `napi-rs`, `UniFFI`, WASM) previously inlined
//! its own `From<UcanError>` impl, all returning the same `SCP-PERM-3001`
//! code. That duplication let the bridges silently drift (as they did
//! before the round-11 fix that consolidated the WASM / `UniFFI`
//! ad-hoc paths onto this code).
//!
//! This module exposes one function — [`ucan_error_code`] — that every
//! bridge routes through. Any change to the UCAN error classification
//! (e.g. splitting `TokenExpired` off `PERM_3001` onto `PERM_3007`)
//! happens here exactly once and propagates to every bridge.
//!
//! `UcanError` lives in `scp-protocol`, which every bridge (including
//! WASM) already depends on, so this function has no additional
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
/// Currently every variant maps to [`codes::PERM_3001`] (`"SCP-PERM-3001"`,
/// generic UCAN validation failure). A future refinement pass can
/// promote individual variants (e.g. `TokenExpired` → `PERM_3007`) —
/// any such change should happen HERE so every bridge picks it up.
#[must_use]
pub const fn ucan_error_code(_err: &UcanError) -> &'static str {
    // `UcanError`'s variants all represent validation-class failures.
    // The harness gate in `seed_operations.py::OP_UCAN_VALIDATE_MALFORMED`
    // is parametrised on this constant, so bridges MUST NOT override it.
    codes::PERM_3001
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_variants_to_perm_3001() {
        // Spot-check two variants — the mapping is exhaustive because
        // `ucan_error_code` takes a `&UcanError` by reference without
        // matching; any added variant gets the same code by construction
        // until the mapping is refined.
        let e1 = UcanError::MalformedToken("bad".to_owned());
        assert_eq!(ucan_error_code(&e1), codes::PERM_3001);
        let e2 = UcanError::SignatureInvalid;
        assert_eq!(ucan_error_code(&e2), codes::PERM_3001);
    }
}
