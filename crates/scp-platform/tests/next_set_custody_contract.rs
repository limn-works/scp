//! Positive control for the `compile_fail,E0046` doctest on
//! `scp_platform::NextSetCustody` (SCP-345).
//!
//! The doctest proves that an implementor omitting `sign_change` does not
//! compile. This test is the same implementor with `sign_change` present, so
//! the doctest fails for the missing method and for nothing else. It lives in
//! an integration test as well as in the rustdoc twin because `cargo nextest`
//! runs no doctests.

use core::future::{Future, ready};

use scp_platform::{
    BackupArtifact, BackupRequest, CustodyProbe, IndexedSignature, KeyEventSignError,
    KeyEventSigner, MaybeSend, NextSetCustody, NextSetCustodyError, NextSetKeyHandle,
    PreRotationCustodyKind, ProbeSignature, SigningChange,
};

struct Complete;

// The signatures are the doctest's, `fn -> impl Future + MaybeSend` for the
// signer and `+ Send` for the custody. The bodies are ready futures where the
// doctest has async blocks; the signatures are what the doctest checks.
impl KeyEventSigner for Complete {
    type Member = NextSetKeyHandle;

    fn sign_change(
        &self,
        _member: &NextSetKeyHandle,
        _change: &SigningChange,
    ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
        ready(Err(KeyEventSignError::MemberNotFound))
    }

    fn sign_probe(
        &self,
        _member: &NextSetKeyHandle,
        _probe: &CustodyProbe,
    ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
        ready(Err(KeyEventSignError::MemberNotFound))
    }
}

impl NextSetCustody for Complete {
    fn generate(
        &self,
    ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
        ready(Err(NextSetCustodyError::HandleNotFound))
    }

    fn reveal_public_key(
        &self,
        _handle: &NextSetKeyHandle,
    ) -> impl Future<Output = Result<[u8; 33], NextSetCustodyError>> + Send {
        ready(Err(NextSetCustodyError::HandleNotFound))
    }

    fn destroy(
        &self,
        _handle: &NextSetKeyHandle,
    ) -> impl Future<Output = Result<(), NextSetCustodyError>> + Send {
        ready(Err(NextSetCustodyError::HandleNotFound))
    }

    fn seal_backup(
        &self,
        _handle: &NextSetKeyHandle,
        _request: BackupRequest,
    ) -> impl Future<Output = Result<BackupArtifact, NextSetCustodyError>> + Send {
        ready(Err(NextSetCustodyError::MethodNotOffered))
    }

    fn restore(
        &self,
        _artifact: BackupArtifact,
        _expected_commitment: [u8; 32],
    ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
        ready(Err(NextSetCustodyError::MethodNotOffered))
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

/// `BackupArtifact`, `BackupRequest` and `PassphraseSource` name the method
/// in their `Debug` output and never the secret.
#[test]
fn backup_types_redact_their_secrets() {
    use scp_platform::{ENCRYPTED_BACKUP_BYTES, PassphraseSource, SHAMIR_SHARE_BYTES};
    use zeroize::Zeroizing;

    let secret = "hunter2-secret";
    let rendered = [
        format!(
            "{:?}",
            BackupArtifact::Encrypted {
                backup: [0xAB; ENCRYPTED_BACKUP_BYTES],
                passphrase: Zeroizing::new(secret.to_owned()),
            }
        ),
        format!(
            "{:?}",
            BackupArtifact::Shamir {
                shares: vec![Zeroizing::new([0xAB; SHAMIR_SHARE_BYTES]); 3],
            }
        ),
        format!(
            "{:?}",
            BackupArtifact::Paper {
                words: Zeroizing::new(secret.to_owned()),
            }
        ),
        format!(
            "{:?}",
            BackupRequest::Encrypted {
                passphrase: PassphraseSource::Supplied(Zeroizing::new(secret.to_owned())),
            }
        ),
    ];
    for text in &rendered {
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("171"), "{text}");
        assert!(!text.to_lowercase().contains("ab, "), "{text}");
    }
    assert!(rendered[1].contains("share_count: 3"), "{}", rendered[1]);
}
