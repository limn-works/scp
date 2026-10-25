//! Positive control for the two `compile_fail,E0046` doctests on
//! `scp_platform::KeyCustody` (SCP-345).
//!
//! The doctests prove that an implementor omitting `sign_change` or
//! `generate_key_event_keypair` does not compile. This test is the same
//! implementor with both present, so each doctest fails for its missing
//! method and for nothing else. It lives in an integration test as well as in
//! the rustdoc twin because `cargo nextest` runs no doctests.

use core::future::{Future, ready};
use scp_platform::{
    CustodyProbe, CustodyType, IndexedSignature, KeyCustody, KeyEventSignError, KeyEventSigner,
    KeyHandle, KeyType, MaybeSend, PlatformError, ProbeSignature, Pseudonym, PublicKey,
    SharedSecret, Signature, SigningChange,
};

struct Custody;

impl KeyEventSigner for Custody {
    type Member = KeyHandle;

    fn sign_change(
        &self,
        _member: &KeyHandle,
        _change: &SigningChange,
    ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
        ready(Err(KeyEventSignError::MemberNotFound))
    }

    fn sign_probe(
        &self,
        _member: &KeyHandle,
        _probe: &CustodyProbe,
    ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
        ready(Err(KeyEventSignError::MemberNotFound))
    }
}

impl KeyCustody for Custody {
    fn generate_keypair(
        &self,
        _key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no key")))
    }

    fn generate_key_event_keypair(
        &self,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no key-event key")))
    }

    fn generate_identity_keypair(
        &self,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no identity key")))
    }

    fn sign(
        &self,
        _key: &KeyHandle,
        _data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no sign")))
    }

    fn public_key(
        &self,
        _key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no public key")))
    }

    fn destroy_key(
        &self,
        _key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no destroy")))
    }

    fn dh_agree(
        &self,
        _key: &KeyHandle,
        _peer_public: &[u8],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no agreement")))
    }

    fn derive_pseudonym(
        &self,
        _key: &KeyHandle,
        _context_id: &[u8],
    ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no pseudonym")))
    }

    fn derive_rotatable_pseudonym(
        &self,
        _key: &KeyHandle,
        _context_id: &[u8],
        _pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
        ready(Err(PlatformError::Unsupported("no pseudonym")))
    }

    fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
        CustodyType::Software
    }
}

#[tokio::test]
async fn complete_key_custody_compiles_and_its_mint_answers() {
    assert!(matches!(
        Custody.generate_key_event_keypair().await,
        Err(PlatformError::Unsupported(_))
    ));
    assert_eq!(
        Custody.custody_type(&KeyHandle::new(1)),
        CustodyType::Software
    );
}
