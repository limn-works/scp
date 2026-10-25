//! Every [`CustodyFailureKind`] reaches a bridge with its registered code.
//!
//! A custody failure from a crate below the bridges, such as a key-event
//! signer's `KeyEventSignError::Substrate`, carries a typed
//! [`CustodyFailure`]; its code comes only from
//! [`custody_failure_code`], so this file checks that one table kind by kind,
//! `TimedOut` included (`.docs/standards/sdk-common.md`; SCP-345).
//!
//! The expected codes are the registry constants, not string literals,
//! because `scripts/check-error-codes.sh` Phase 3 reads each quoted literal
//! as a constant claiming that number.

use scp_crypto::{CustodyFailure, CustodyFailureKind};
use scp_ffi_common::error_codes::{
    ATTEST_9001, CRYPTO_4006, CRYPTO_4060, CRYPTO_4061, CRYPTO_4062, IDENT_1055, STORAGE_8005,
    STORAGE_8006, TRANS_5080, TRANS_5081, TRANS_5082, TRANS_5083, TRANS_5084, custody_failure_code,
};

/// One list of `kind => registered code` rows generates both the exhaustive
/// `registered` match and `ALL_KINDS`, the kinds the test compares. A kind
/// left out of the list leaves the match non-exhaustive (E0004), so no kind
/// can be in the match and missing from the comparison.
macro_rules! kind_table {
    ($($kind:ident => $code:ident,)+) => {
        /// The registered code for `kind`.
        const fn registered(kind: CustodyFailureKind) -> &'static str {
            match kind {
                $(CustodyFailureKind::$kind => $code,)+
            }
        }

        /// Every kind, in the list's order.
        const ALL_KINDS: &[CustodyFailureKind] = &[$(CustodyFailureKind::$kind,)+];
    };
}

kind_table! {
    KeyNotFound => CRYPTO_4006,
    PseudonymRejected => IDENT_1055,
    StorageClosed => STORAGE_8006,
    StorageLockHeld => STORAGE_8005,
    TimedOut => CRYPTO_4062,
    AttestationFailed => ATTEST_9001,
    Unsupported => CRYPTO_4061,
    PushWakePayloadInvalid => TRANS_5080,
    PushRegistrationRejected => TRANS_5081,
    PushVerifierUnavailable => TRANS_5082,
    PushPlatformUnavailable => TRANS_5083,
    PushProviderFailed => TRANS_5084,
    Failed => CRYPTO_4060,
}

#[test]
fn every_custody_failure_kind_reports_its_registered_code() {
    for (index, kind) in ALL_KINDS.iter().copied().enumerate() {
        assert!(!ALL_KINDS[..index].contains(&kind), "{kind:?} listed twice");
        let failure = CustodyFailure {
            kind,
            detail: "x".to_owned(),
        };
        assert_eq!(custody_failure_code(&failure), registered(kind), "{kind:?}");
    }
}
