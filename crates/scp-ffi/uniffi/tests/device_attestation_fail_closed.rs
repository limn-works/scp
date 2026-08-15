//! Device attestation declines the capability on a shipped build
//! (`.docs/specs/09-agents-and-attestation.md` §9:187,
//! `.docs/specs/17-persistence-and-storage.md` §17.17.1 SCP-CAPSEL-8001,
//! ADR-062 §Decision 3).
//!
//! Device attestation has NO production backend. `InMemoryDeviceAttestation` is
//! the only implementation of `scp_platform::traits::DeviceAttestation` in the
//! workspace, and ADR-062 §Decision 3 severed it behind
//! `#[cfg(feature = "testing")]`. A shipped build therefore answers the
//! capability with a typed decline, and this test holds the shipped arm to that
//! decline: a `true` would tell a relying party the device passed an
//! attestation no backend ever performed, which §17.17.2 classifies as a
//! security nullifier.
//!
//! The whole file is `#[cfg(not(feature = "testing"))]` because the shipped arm
//! is the one being asserted; a `testing` build compiles the in-memory double
//! instead. It lives in its own integration target rather than in
//! `bridge.rs`'s `mod tests`, because that module references `testing`-gated
//! items and so does not compile in a bare build.

#![cfg(not(feature = "testing"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_ffi_uniffi::ScpError;
use scp_ffi_uniffi::bridge::identity_verify_device_attestation;

/// The device-attestation verify surface returns `ScpError::Identity` carrying
/// `SCP-IDENT-1016` on a shipped build, never a silently-valid `true`.
#[tokio::test]
async fn verify_device_attestation_declines_with_ident_1016() {
    let result = identity_verify_device_attestation(
        "did:dht:z6MkExampleShippedBuild".to_owned(),
        "dGVzdC10b2tlbg==".to_owned(),
    )
    .await;

    match result {
        Err(ScpError::Identity { code, msg }) => {
            assert_eq!(
                code,
                scp_ffi_common::error_codes::IDENT_1016,
                "the shipped verify surface must decline with SCP-IDENT-1016, got: {msg}"
            );
        }
        Err(other) => panic!("expected ScpError::Identity, got {other:?}"),
        Ok(verified) => panic!(
            "the shipped device-attestation verify surface must decline with SCP-IDENT-1016; it \
             returned {verified} instead, which reports an attestation no backend performed \
             (spec §9:187, ADR-062 §Decision 3)"
        ),
    }
}
