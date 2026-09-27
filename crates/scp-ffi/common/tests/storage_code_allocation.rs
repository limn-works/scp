//! `SCP-STORAGE-` band allocation: the selection layer's codes take no number
//! another backend owns.
//!
//! `.docs/standards/sdk-common.md` §Registered SCP-STORAGE- codes allocates the
//! band per owner and states the rule in prose: "never reuse a number assigned
//! to a different backend, even across languages". This file asserts that rule
//! for the two codes `scp-ffi-common` defines, because a violation is invisible
//! at the Rust layer — the colliding owner, `scp-kt-android` `AndroidStorage`,
//! is Kotlin, and an Android app links it and the `UniFFI` bridge into one
//! process.
//!
//! These assertions live outside `src/error_codes.rs` because
//! `scripts/check-error-codes.sh` Phase 3 requires each quoted
//! `"SCP-<PREFIX>-<NUMBER>"` literal to appear exactly once inside that
//! registry file, one literal per constant. A test module holding the same
//! literals would read as a second constant claiming the same number.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_ffi_common::error_codes::{STORAGE_8000, STORAGE_8004};

/// Numbers the `scp-kt-android` `AndroidStorage` backend owns
/// (`.docs/standards/sdk-common.md` §Registered SCP-STORAGE- codes):
/// `ERROR_KEY_NOT_FOUND`, `ERROR_STORAGE_OPERATION_FAILED`, and
/// `ERROR_KEY_DERIVATION_FAILED` in
/// `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/AndroidStorage.kt`.
const ANDROID_OWNED: [&str; 3] = ["SCP-STORAGE-8001", "SCP-STORAGE-8002", "SCP-STORAGE-8003"];

/// Numbers the `scp-client-wasm` browser participant owns
/// (`.docs/standards/sdk-common.md` §Registered SCP-STORAGE- codes).
const BROWSER_OWNED: [&str; 4] = [
    "SCP-STORAGE-8010",
    "SCP-STORAGE-8011",
    "SCP-STORAGE-8012",
    "SCP-STORAGE-8013",
];

/// The two codes the storage-selection layer raises across all three bridges
/// carry the numbers `.docs/standards/sdk-common.md` allocates to that layer.
#[test]
fn selection_layer_codes_carry_their_registered_numbers() {
    assert_eq!(STORAGE_8000, "SCP-STORAGE-8000");
    assert_eq!(STORAGE_8004, "SCP-STORAGE-8004");
}

/// Neither selection-layer code takes a number another backend owns. An
/// Android app links `AndroidStorage` and the `UniFFI` bridge into one process,
/// so a selection-layer code inside `8001`--`8003` would make one code string
/// name two conditions in that app.
#[test]
fn selection_layer_codes_avoid_every_other_owner_sub_block() {
    for code in [STORAGE_8000, STORAGE_8004] {
        assert!(
            !ANDROID_OWNED.contains(&code),
            "{code} collides with a number scp-kt-android AndroidStorage owns"
        );
        assert!(
            !BROWSER_OWNED.contains(&code),
            "{code} collides with a number the scp-client-wasm participant owns"
        );
    }
}
