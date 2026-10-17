//! Positive control for the `compile_fail` doctest on
//! `instance_active_key_resolver`: the instance resolver, built inside
//! `run_blocking_resolution`, fills the `ActiveKeyResolver` slot that
//! `BridgeDidResolver` cannot, and without an initialized DID resolver it
//! fails closed with an infrastructure fault.

use scp_core::trust::TrustError;
use scp_core::trust::attestation::ActiveKeyResolver;

fn verify_with(resolver: &dyn ActiveKeyResolver) -> Result<Vec<u8>, TrustError> {
    resolver.resolve_active_key("did:dht:zcontrol")
}

#[tokio::test]
async fn the_instance_resolver_fills_the_active_key_slot_and_fails_closed_uninitialized() {
    let joined = scp_ffi_common::run_blocking_resolution(|scope| {
        verify_with(scp_ffi_common::instance_active_key_resolver(scope, None))
    })
    .await;
    let Ok(result) = joined else {
        unreachable!("the blocking task does not panic: {joined:?}");
    };
    assert!(
        matches!(&result, Err(TrustError::KeyResolutionUnavailable { did, .. }) if did == "did:dht:zcontrol"),
        "{result:?}"
    );
    assert!(
        result.is_err_and(|e| !e.is_record_rejection()),
        "an outage is not a rejection"
    );
}
