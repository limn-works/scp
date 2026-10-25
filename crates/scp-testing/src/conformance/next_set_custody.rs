//! Conformance suite for `scp_platform::NextSetCustody`
//! (`16-test-infrastructure.md` §16.12.3a).
//!
//! Each case is a function generic over the custody, so a meta-test can run
//! one against a broken implementor and require it to fail.
//! [`next_set_custody_conformance!`](crate::next_set_custody_conformance)
//! expands to one `#[tokio::test]` per case. A case returns
//! [`ConformanceFailure`] instead of panicking, so the suite needs neither
//! `unwrap` nor `expect`.

use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use scp_kel::verify_indexed;
use scp_platform::{
    BackupArtifact, BackupRequest, CustodyProbe, ENCRYPTED_BACKUP_BYTES, IndexedSignature,
    KeyEventSignError, NextSetCustody, NextSetCustodyError, NextSetKeyHandle, PassphraseSource,
    PreRotationCustodyKind, ProbeSignature, SHAMIR_SHARE_BYTES, SigningChange,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::key_custody::{V41_DIGEST_HEX, V41_PREIMAGE_HEX};

/// A conformance case found the custody out of contract. The message names
/// the check that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("next-set custody conformance: {0}")]
pub struct ConformanceFailure(String);

fn failure(message: impl Into<String>) -> ConformanceFailure {
    ConformanceFailure(message.into())
}

fn ensure(holds: bool, message: &str) -> Result<(), ConformanceFailure> {
    if holds { Ok(()) } else { Err(failure(message)) }
}

fn context<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> ConformanceFailure + '_ {
    move |error| failure(format!("{what}: {error:?}"))
}

/// Spec 25 Vector 41's inception change, whose digest `D` is
/// [`V41_DIGEST_HEX`].
///
/// # Errors
///
/// [`ConformanceFailure`] when the fixture no longer decodes to that change.
pub fn v41_change() -> Result<SigningChange, ConformanceFailure> {
    let preimage = hex::decode(V41_PREIMAGE_HEX).map_err(context("Vector 41's preimage"))?;
    let change = SigningChange::inception(&preimage).map_err(context("Vector 41's preimage"))?;
    ensure(
        hex::encode(change.digest()) == V41_DIGEST_HEX,
        "Vector 41's digest drifted",
    )?;
    Ok(change)
}

/// A handle no conforming custody issues in these cases: each case generates
/// at most two keys.
const UNISSUED: u64 = u64::MAX;

/// The handles are distinct, and each reveals a distinct 33-byte compressed
/// SEC1 point that decodes.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn generate_then_reveal_gives_compressed_point<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let first = custody.generate().await.map_err(context("generate"))?;
    let second = custody.generate().await.map_err(context("generate"))?;
    ensure(first != second, "two generates returned one handle")?;
    let point = custody
        .reveal_public_key(&first)
        .await
        .map_err(context("reveal_public_key"))?;
    ensure(
        matches!(point[0], 0x02 | 0x03),
        "the revealed key is not a compressed point",
    )?;
    P256PublicKey::from_sec1(&point).map_err(context("the revealed point"))?;
    let other = custody
        .reveal_public_key(&second)
        .await
        .map_err(context("reveal_public_key"))?;
    ensure(point != other, "two keys revealed one point")
}

/// A change signature verifies under the revealed key over `D`, in the form
/// it carries, and a raw one is not a signature over the hash of the
/// assertion challenge.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn sign_change_verifies<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let handle = custody.generate().await.map_err(context("generate"))?;
    let point = custody
        .reveal_public_key(&handle)
        .await
        .map_err(context("reveal_public_key"))?;
    let change = v41_change()?;
    let signature = custody
        .sign_change(&handle, &change)
        .await
        .map_err(context("sign_change"))?;
    verify_indexed(&point, &change.digest(), signature.form(), &signature)
        .map_err(context("the change signature over D"))?;
    if let IndexedSignature::Raw { signature } = signature {
        let key = P256PublicKey::from_sec1(&point).map_err(context("the revealed point"))?;
        let challenge_hash: [u8; 32] = Sha256::digest(change.key_event_challenge()).into();
        ensure(
            verify_prehash_strict(&key, &challenge_hash, &signature).is_err(),
            "the raw signature covers the assertion challenge's hash, not D",
        )?;
    }
    Ok(())
}

/// A probe signature verifies against its own probe only, and a change
/// signature by the same key is not a probe signature.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn sign_probe_signs_the_probe_preimage_only<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let handle = custody.generate().await.map_err(context("generate"))?;
    let point = custody
        .reveal_public_key(&handle)
        .await
        .map_err(context("reveal_public_key"))?;
    let probe = CustodyProbe::fresh().map_err(context("CustodyProbe::fresh"))?;
    let signature = custody
        .sign_probe(&handle, &probe)
        .await
        .map_err(context("sign_probe"))?;
    // `verify` recomputes the probe's digest or challenge, so a signature
    // over the nonce, an event digest or a key-event challenge fails here.
    signature
        .verify(&probe, &point)
        .map_err(context("the probe signature"))?;
    let other = CustodyProbe::fresh().map_err(context("CustodyProbe::fresh"))?;
    ensure(
        signature.verify(&other, &point).is_err(),
        "the probe signature verifies against another probe",
    )?;
    let over_event = match custody
        .sign_change(&handle, &v41_change()?)
        .await
        .map_err(context("sign_change"))?
    {
        IndexedSignature::Raw { signature } => ProbeSignature::raw(signature),
        IndexedSignature::WebAuthnAssertion(assertion) => ProbeSignature::assertion(assertion),
    };
    ensure(
        over_event.verify(&probe, &point).is_err(),
        "a change signature verifies as a probe signature",
    )
}

/// After `destroy`, the key signs nothing, reveals nothing and cannot be
/// destroyed again, and a second key still signs.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn destroy_prevents_sign<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let handle = custody.generate().await.map_err(context("generate"))?;
    let kept = custody.generate().await.map_err(context("generate"))?;
    let change = v41_change()?;
    custody
        .sign_change(&handle, &change)
        .await
        .map_err(context("sign_change before destroy"))?;
    custody.destroy(&handle).await.map_err(context("destroy"))?;
    check_gone(custody, &handle, &change, "a destroyed handle").await?;
    custody
        .sign_change(&kept, &change)
        .await
        .map_err(context("sign_change by the key destroy left"))?;
    Ok(())
}

/// A handle the custody did not issue errors on every method.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn invalid_handle_errors<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    custody.generate().await.map_err(context("generate"))?;
    let unknown = NextSetKeyHandle::new(UNISSUED);
    check_gone(custody, &unknown, &v41_change()?, "an unissued handle").await
}

async fn check_gone<C: NextSetCustody>(
    custody: &C,
    handle: &NextSetKeyHandle,
    change: &SigningChange,
    what: &str,
) -> Result<(), ConformanceFailure> {
    let probe = CustodyProbe::fresh().map_err(context("CustodyProbe::fresh"))?;
    let sign_change = custody.sign_change(handle, change).await;
    let sign_probe = custody.sign_probe(handle, &probe).await;
    let reveal = custody.reveal_public_key(handle).await;
    let destroy = custody.destroy(handle).await;
    let checks = [
        (
            matches!(sign_change, Err(KeyEventSignError::MemberNotFound)),
            format!("sign_change on {what}: {sign_change:?}"),
        ),
        (
            matches!(sign_probe, Err(KeyEventSignError::MemberNotFound)),
            format!("sign_probe on {what}: {sign_probe:?}"),
        ),
        (
            matches!(reveal, Err(NextSetCustodyError::HandleNotFound)),
            format!("reveal_public_key on {what}: {reveal:?}"),
        ),
        (
            matches!(destroy, Err(NextSetCustodyError::HandleNotFound)),
            format!("destroy on {what}: {destroy:?}"),
        ),
    ];
    match checks.into_iter().find(|(holds, _)| !holds) {
        Some((_, message)) => Err(failure(message)),
        None => Ok(()),
    }
}

/// Whether the custody is one of the three headless copyable custodies,
/// the only ones §9.7.4.1 item 4 lets seal and restore.
const fn is_headless(kind: PreRotationCustodyKind) -> bool {
    matches!(
        kind,
        PreRotationCustodyKind::EncryptedOfflineBackup
            | PreRotationCustodyKind::ShamirSecretSharing
            | PreRotationCustodyKind::PaperBackupBip39
    )
}

/// The headless branch of the seal and restore cases needs the errors and
/// the custody the headless-backup pull request adds, so a headless custody
/// fails the case until then instead of passing unchecked.
// Stub — see SCP-311: the headless branch asserts `BackupWindowClosed` and
// `CommitmentMismatch` once the headless custody lands.
fn headless_branch_unwritten() -> ConformanceFailure {
    failure("the headless seal and restore branch is not written yet")
}

fn every_request() -> [BackupRequest; 4] {
    [
        BackupRequest::Encrypted {
            passphrase: PassphraseSource::Generate,
        },
        BackupRequest::Encrypted {
            passphrase: PassphraseSource::Supplied(Zeroizing::new(
                "correct horse battery staple".to_owned(),
            )),
        },
        BackupRequest::Shamir,
        BackupRequest::Paper,
    ]
}

fn every_artifact() -> [BackupArtifact; 3] {
    [
        BackupArtifact::Encrypted {
            backup: [0x01; ENCRYPTED_BACKUP_BYTES],
            passphrase: Zeroizing::new("correct horse battery staple".to_owned()),
        },
        BackupArtifact::Shamir {
            shares: (1..=3)
                .map(|x| {
                    let mut share = [0u8; SHAMIR_SHARE_BYTES];
                    share[0] = 0x01;
                    share[1] = x;
                    Zeroizing::new(share)
                })
                .collect(),
        },
        BackupArtifact::Paper {
            words: Zeroizing::new(["abandon"; 24].join(" ")),
        },
    ]
}

/// A custody that is not headless refuses `seal_backup` with
/// `MethodNotOffered` for every request, and the refusal leaves the key
/// signing.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails, and for a
/// headless custody until its branch is written.
pub async fn seal_backup_refused_off_headless_or_outside_window<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    if is_headless(custody.custody_kind()) {
        return Err(headless_branch_unwritten());
    }
    let handle = custody.generate().await.map_err(context("generate"))?;
    for request in every_request() {
        let label = format!("{request:?}");
        let result = custody.seal_backup(&handle, request).await;
        ensure(
            matches!(result, Err(NextSetCustodyError::MethodNotOffered)),
            &format!("seal_backup({label}) off headless: {result:?}"),
        )?;
    }
    custody
        .sign_change(&handle, &v41_change()?)
        .await
        .map_err(context("sign_change after a refused seal"))?;
    Ok(())
}

/// A custody that is not headless refuses `restore` with
/// `MethodNotOffered` for every artifact kind.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails, and for a
/// headless custody until its branch is written.
pub async fn restore_refuses_commitment_mismatch<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    if is_headless(custody.custody_kind()) {
        return Err(headless_branch_unwritten());
    }
    for artifact in every_artifact() {
        let label = format!("{artifact:?}");
        let result = custody.restore(artifact, [0x42; 32]).await;
        ensure(
            matches!(result, Err(NextSetCustodyError::MethodNotOffered)),
            &format!("restore({label}) off headless: {result:?}"),
        )?;
    }
    Ok(())
}

/// Generates the `16-test-infrastructure.md` §16.12.3a suite for a
/// `scp_platform::NextSetCustody` implementor.
///
/// `$constructor` builds a fresh custody; each test calls it once. The
/// caller's crate must depend on `scp-platform` and `tokio`.
#[macro_export]
macro_rules! next_set_custody_conformance {
    ($constructor:expr) => {
        fn next_set_custody_conformance_constructor() -> impl ::scp_platform::NextSetCustody {
            $constructor
        }

        mod next_set_custody_conformance {
            use $crate::conformance::next_set_custody as cases;
            use $crate::conformance::next_set_custody::ConformanceFailure;

            #[tokio::test]
            async fn generate_then_reveal_gives_compressed_point() -> Result<(), ConformanceFailure>
            {
                cases::generate_then_reveal_gives_compressed_point(
                    &super::next_set_custody_conformance_constructor(),
                )
                .await
            }

            #[tokio::test]
            async fn sign_change_verifies() -> Result<(), ConformanceFailure> {
                cases::sign_change_verifies(&super::next_set_custody_conformance_constructor())
                    .await
            }

            #[tokio::test]
            async fn sign_probe_signs_the_probe_preimage_only() -> Result<(), ConformanceFailure> {
                cases::sign_probe_signs_the_probe_preimage_only(
                    &super::next_set_custody_conformance_constructor(),
                )
                .await
            }

            #[tokio::test]
            async fn destroy_prevents_sign() -> Result<(), ConformanceFailure> {
                cases::destroy_prevents_sign(&super::next_set_custody_conformance_constructor())
                    .await
            }

            #[tokio::test]
            async fn invalid_handle_errors() -> Result<(), ConformanceFailure> {
                cases::invalid_handle_errors(&super::next_set_custody_conformance_constructor())
                    .await
            }

            #[tokio::test]
            async fn seal_backup_refused_off_headless_or_outside_window()
            -> Result<(), ConformanceFailure> {
                cases::seal_backup_refused_off_headless_or_outside_window(
                    &super::next_set_custody_conformance_constructor(),
                )
                .await
            }

            #[tokio::test]
            async fn restore_refuses_commitment_mismatch() -> Result<(), ConformanceFailure> {
                cases::restore_refuses_commitment_mismatch(
                    &super::next_set_custody_conformance_constructor(),
                )
                .await
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use scp_platform::testing::InMemoryNextSetCustody;
    use scp_platform::{
        BackupArtifact, BackupRequest, CustodyProbe, IndexedSignature, KeyEventSignError,
        KeyEventSigner, MaybeSend, NextSetCustody, NextSetCustodyError, NextSetKeyHandle,
        PreRotationCustodyKind, ProbeSignature, SigningChange,
    };

    use super::{ConformanceFailure, sign_probe_signs_the_probe_preimage_only, v41_change};

    crate::next_set_custody_conformance!(InMemoryNextSetCustody::new());

    /// An implementor whose `sign_probe` signs Vector 41's event digest `D`
    /// in place of the probe's digest, and is otherwise `InMemory`.
    struct ProbeSignsD(InMemoryNextSetCustody);

    impl KeyEventSigner for ProbeSignsD {
        type Member = NextSetKeyHandle;

        fn sign_change(
            &self,
            member: &NextSetKeyHandle,
            change: &SigningChange,
        ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
            self.0.sign_change(member, change)
        }

        async fn sign_probe(
            &self,
            member: &NextSetKeyHandle,
            _probe: &CustodyProbe,
        ) -> Result<ProbeSignature, KeyEventSignError> {
            let change = v41_change().map_err(|_| KeyEventSignError::MemberNotFound)?;
            match self.0.sign_change(member, &change).await? {
                IndexedSignature::Raw { signature } => Ok(ProbeSignature::raw(signature)),
                IndexedSignature::WebAuthnAssertion(assertion) => {
                    Ok(ProbeSignature::assertion(assertion))
                }
            }
        }
    }

    impl NextSetCustody for ProbeSignsD {
        fn generate(
            &self,
        ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
            self.0.generate()
        }

        fn reveal_public_key(
            &self,
            handle: &NextSetKeyHandle,
        ) -> impl Future<Output = Result<[u8; 33], NextSetCustodyError>> + Send {
            self.0.reveal_public_key(handle)
        }

        fn destroy(
            &self,
            handle: &NextSetKeyHandle,
        ) -> impl Future<Output = Result<(), NextSetCustodyError>> + Send {
            self.0.destroy(handle)
        }

        fn seal_backup(
            &self,
            handle: &NextSetKeyHandle,
            request: BackupRequest,
        ) -> impl Future<Output = Result<BackupArtifact, NextSetCustodyError>> + Send {
            self.0.seal_backup(handle, request)
        }

        fn restore(
            &self,
            artifact: BackupArtifact,
            expected_commitment: [u8; 32],
        ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
            self.0.restore(artifact, expected_commitment)
        }

        fn custody_kind(&self) -> PreRotationCustodyKind {
            self.0.custody_kind()
        }
    }

    #[tokio::test]
    async fn a_custody_whose_probe_signs_d_fails_the_probe_case() {
        let result =
            sign_probe_signs_the_probe_preimage_only(&ProbeSignsD(InMemoryNextSetCustody::new()))
                .await;
        assert!(
            matches!(&result, Err(ConformanceFailure(message)) if message.contains("the probe signature")),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn the_unbroken_custody_passes_the_probe_case() -> Result<(), ConformanceFailure> {
        sign_probe_signs_the_probe_preimage_only(&InMemoryNextSetCustody::new()).await
    }
}
