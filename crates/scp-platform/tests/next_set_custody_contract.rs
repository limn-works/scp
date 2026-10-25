//! Positive control for the `compile_fail,E0046` doctest on
//! `scp_platform::NextSetCustody` (SCP-345).
//!
//! The doctest proves that an implementor omitting `sign_change` does not
//! compile. This test is the same implementor with `sign_change` present, so
//! the doctest fails for the missing method and for nothing else. It lives in
//! an integration test as well as in the rustdoc twin because `cargo nextest`
//! runs no doctests.

use scp_platform::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, NextSetCustody,
    NextSetCustodyError, NextSetKeyHandle, PreRotationCustodyKind, ProbeSignature, SigningChange,
};

struct Complete;

impl KeyEventSigner for Complete {
    type Member = NextSetKeyHandle;

    async fn sign_change(
        &self,
        _member: &NextSetKeyHandle,
        _change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        Err(KeyEventSignError::MemberNotFound)
    }

    async fn sign_probe(
        &self,
        _member: &NextSetKeyHandle,
        _probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        Err(KeyEventSignError::MemberNotFound)
    }
}

impl NextSetCustody for Complete {
    async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        Err(NextSetCustodyError::HandleNotFound)
    }

    async fn reveal_public_key(
        &self,
        _handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError> {
        Err(NextSetCustodyError::HandleNotFound)
    }

    async fn destroy(&self, _handle: &NextSetKeyHandle) -> Result<(), NextSetCustodyError> {
        Err(NextSetCustodyError::HandleNotFound)
    }

    fn custody_kind(&self) -> PreRotationCustodyKind {
        PreRotationCustodyKind::Callback
    }
}

async fn probe_through<C: NextSetCustody>(
    custody: &C,
    probe: &CustodyProbe,
) -> Result<ProbeSignature, KeyEventSignError> {
    custody.sign_probe(&NextSetKeyHandle::new(1), probe).await
}

#[tokio::test]
async fn a_complete_implementor_compiles_and_dispatches() -> Result<(), Box<dyn std::error::Error>>
{
    let custody = Complete;
    let probe = CustodyProbe::fresh()?;
    assert_eq!(
        probe_through(&custody, &probe).await,
        Err(KeyEventSignError::MemberNotFound)
    );
    assert_eq!(custody.custody_kind(), PreRotationCustodyKind::Callback);
    Ok(())
}
