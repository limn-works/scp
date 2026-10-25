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

/// The registered code for `kind`. The match names every kind, so a new kind
/// does not compile until it has a row here.
const fn registered(kind: CustodyFailureKind) -> &'static str {
    match kind {
        CustodyFailureKind::KeyNotFound => CRYPTO_4006,
        CustodyFailureKind::PseudonymRejected => IDENT_1055,
        CustodyFailureKind::StorageClosed => STORAGE_8006,
        CustodyFailureKind::StorageLockHeld => STORAGE_8005,
        CustodyFailureKind::TimedOut => CRYPTO_4062,
        CustodyFailureKind::AttestationFailed => ATTEST_9001,
        CustodyFailureKind::Unsupported => CRYPTO_4061,
        CustodyFailureKind::PushWakePayloadInvalid => TRANS_5080,
        CustodyFailureKind::PushRegistrationRejected => TRANS_5081,
        CustodyFailureKind::PushVerifierUnavailable => TRANS_5082,
        CustodyFailureKind::PushPlatformUnavailable => TRANS_5083,
        CustodyFailureKind::PushProviderFailed => TRANS_5084,
        CustodyFailureKind::Failed => CRYPTO_4060,
    }
}

/// Every kind. A new kind first fails to compile in `registered`, and the
/// author who adds its row there adds it here.
const ALL_KINDS: [CustodyFailureKind; 13] = [
    CustodyFailureKind::KeyNotFound,
    CustodyFailureKind::PseudonymRejected,
    CustodyFailureKind::StorageClosed,
    CustodyFailureKind::StorageLockHeld,
    CustodyFailureKind::TimedOut,
    CustodyFailureKind::AttestationFailed,
    CustodyFailureKind::Unsupported,
    CustodyFailureKind::PushWakePayloadInvalid,
    CustodyFailureKind::PushRegistrationRejected,
    CustodyFailureKind::PushVerifierUnavailable,
    CustodyFailureKind::PushPlatformUnavailable,
    CustodyFailureKind::PushProviderFailed,
    CustodyFailureKind::Failed,
];

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
