//! Conformance suite for `scp_platform::NextSetCustody`
//! (`16-test-infrastructure.md` §16.12.3a).
//!
//! Each case is a function generic over the custody. One case list,
//! [`__next_set_custody_cases!`](crate::__next_set_custody_cases), expands
//! both into one `#[tokio::test]` per case under
//! [`next_set_custody_conformance!`](crate::next_set_custody_conformance)
//! and into [`run_every_case`], which the meta-tests run against broken
//! implementors. A case dropped from the list therefore drops out of both,
//! and the meta-tests, which name every case, turn red. A case returns
//! [`ConformanceFailure`] instead of panicking, so the suite needs neither
//! `unwrap` nor `expect`.

use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use scp_kel::verify_indexed;
use scp_platform::{
    BackupRequest, CustodyProbe, ENCRYPTED_BACKUP_BYTES, IndexedSignature, KeyEventSignError,
    NextSetCustody, NextSetCustodyError, NextSetKeyHandle, PassphraseSource,
    PreRotationCustodyKind, ProbeSignature, RestoreMaterial, SHAMIR_SHARE_BYTES, SigningChange,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::key_custody::{V41_DIGEST_HEX, V41_PREIMAGE_HEX};

/// A conformance case found the custody out of contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("next-set custody conformance: {check}{detail}")]
pub struct ConformanceFailure {
    check: String,
    detail: String,
}

impl ConformanceFailure {
    /// The check that failed, without the value the case saw.
    #[must_use]
    pub fn check(&self) -> &str {
        &self.check
    }
}

fn failure(check: impl Into<String>) -> ConformanceFailure {
    ConformanceFailure {
        check: check.into(),
        detail: String::new(),
    }
}

fn failure_saw(check: impl Into<String>, saw: &impl std::fmt::Debug) -> ConformanceFailure {
    ConformanceFailure {
        check: check.into(),
        detail: format!(": {saw:?}"),
    }
}

fn ensure(holds: bool, check: &str) -> Result<(), ConformanceFailure> {
    if holds { Ok(()) } else { Err(failure(check)) }
}

fn context<E: std::fmt::Debug>(check: &str) -> impl FnOnce(E) -> ConformanceFailure + '_ {
    move |error| failure_saw(check, &error)
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

/// The request for the method `kind` declares. A custody that is not
/// headless refuses every request, so for it the method is arbitrary.
const fn request_for(kind: PreRotationCustodyKind) -> BackupRequest {
    match kind {
        PreRotationCustodyKind::EncryptedOfflineBackup => BackupRequest::Encrypted {
            passphrase: PassphraseSource::Generate,
        },
        PreRotationCustodyKind::ShamirSecretSharing => BackupRequest::Shamir,
        _ => BackupRequest::Paper,
    }
}

/// Generates a key the custody will reveal and sign with. A headless custody
/// refuses both until the key is sealed (§9.7.4.1 item 4, the sealing
/// window), so on one this seals the key by its own method first and drops
/// the artifact.
async fn generate_ready<C: NextSetCustody>(
    custody: &C,
) -> Result<NextSetKeyHandle, ConformanceFailure> {
    let handle = custody.generate().await.map_err(context("generate"))?;
    let kind = custody.custody_kind();
    if is_headless(kind) {
        custody
            .seal_backup(&handle, request_for(kind))
            .await
            .map_err(context("seal_backup before the key's first use"))?;
    }
    Ok(handle)
}

/// The handles are distinct, and each reveals a distinct 33-byte compressed
/// SEC1 point that decodes.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn generate_then_reveal_gives_compressed_point<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let first = generate_ready(custody).await?;
    let second = generate_ready(custody).await?;
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
    let handle = generate_ready(custody).await?;
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
    let handle = generate_ready(custody).await?;
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

/// After `destroy`, the key signs nothing, reveals nothing, seals nothing
/// and cannot be destroyed again, and a second key still signs.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn destroy_prevents_sign<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let handle = generate_ready(custody).await?;
    let kept = generate_ready(custody).await?;
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

/// A handle the custody did not issue errors on every method that takes a
/// handle.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails.
pub async fn invalid_handle_errors<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    generate_ready(custody).await?;
    let unknown = NextSetKeyHandle::new(UNISSUED);
    check_gone(custody, &unknown, &v41_change()?, "an unissued handle").await
}

/// Calls every method that takes a handle and requires each to refuse it.
/// `seal_backup` names the custody's own method, so a headless custody
/// refuses it for the handle with `HandleNotFound`; every other custody
/// refuses every seal with `MethodNotOffered`.
async fn check_gone<C: NextSetCustody>(
    custody: &C,
    handle: &NextSetKeyHandle,
    change: &SigningChange,
    what: &str,
) -> Result<(), ConformanceFailure> {
    let probe = CustodyProbe::fresh().map_err(context("CustodyProbe::fresh"))?;
    let kind = custody.custody_kind();
    let sign_change = custody.sign_change(handle, change).await;
    if !matches!(sign_change, Err(KeyEventSignError::MemberNotFound)) {
        return Err(failure_saw(format!("sign_change on {what}"), &sign_change));
    }
    let sign_probe = custody.sign_probe(handle, &probe).await;
    if !matches!(sign_probe, Err(KeyEventSignError::MemberNotFound)) {
        return Err(failure_saw(format!("sign_probe on {what}"), &sign_probe));
    }
    let reveal = custody.reveal_public_key(handle).await;
    if !matches!(reveal, Err(NextSetCustodyError::HandleNotFound)) {
        return Err(failure_saw(format!("reveal_public_key on {what}"), &reveal));
    }
    let destroy = custody.destroy(handle).await;
    if !matches!(destroy, Err(NextSetCustodyError::HandleNotFound)) {
        return Err(failure_saw(format!("destroy on {what}"), &destroy));
    }
    let seal = custody.seal_backup(handle, request_for(kind)).await;
    let refused = if is_headless(kind) {
        matches!(seal, Err(NextSetCustodyError::HandleNotFound))
    } else {
        matches!(seal, Err(NextSetCustodyError::MethodNotOffered))
    };
    if !refused {
        return Err(failure_saw(format!("seal_backup on {what}"), &seal));
    }
    Ok(())
}

/// The headless branch of the seal and restore cases needs the errors and
/// the custody the headless-backup change adds, so a headless custody fails
/// the case until then instead of passing unchecked.
// Stub — see SCP-311: the headless branch asserts `BackupWindowClosed` and
// `CommitmentMismatch` once the headless custody lands.
fn headless_branch_unwritten() -> ConformanceFailure {
    failure(HEADLESS_BRANCH_UNWRITTEN)
}

const HEADLESS_BRANCH_UNWRITTEN: &str = "the headless seal and restore branch is not written yet";

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

fn every_material() -> [RestoreMaterial; 3] {
    let share = |x: u8| {
        let mut share = [0u8; SHAMIR_SHARE_BYTES];
        share[0] = 0x01;
        share[1] = x;
        Zeroizing::new(share)
    };
    [
        RestoreMaterial::Encrypted {
            backup: [0x01; ENCRYPTED_BACKUP_BYTES],
            passphrase: Zeroizing::new("correct horse battery staple".to_owned()),
        },
        RestoreMaterial::Shamir {
            shares: [share(1), share(2), share(3)],
        },
        RestoreMaterial::Paper {
            words: Zeroizing::new(["abandon"; 24].join(" ")),
        },
    ]
}

/// A custody that is not headless refuses `seal_backup` with
/// `MethodNotOffered` for every request, and the refusal leaves the key
/// signing.
///
/// A headless custody refuses, with `MethodNotOffered`, every
/// request whose method differs from its own kind.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails, and for a
/// headless custody until its branch is written.
pub async fn seal_backup_refused_off_headless_or_outside_window<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let kind = custody.custody_kind();
    let handle = custody.generate().await.map_err(context("generate"))?;
    if is_headless(kind) {
        for request in every_request() {
            let method = request.custody_kind();
            if method == kind {
                continue;
            }
            let result = custody.seal_backup(&handle, request).await;
            if !matches!(result, Err(NextSetCustodyError::MethodNotOffered)) {
                return Err(failure_saw(
                    format!("seal_backup by the {method:?} method on the {kind:?} custody"),
                    &result,
                ));
            }
        }
        return Err(headless_branch_unwritten());
    }
    for request in every_request() {
        let label = format!("{request:?}");
        let result = custody.seal_backup(&handle, request).await;
        if !matches!(result, Err(NextSetCustodyError::MethodNotOffered)) {
            return Err(failure_saw(
                format!("seal_backup({label}) off headless"),
                &result,
            ));
        }
    }
    custody
        .sign_change(&handle, &v41_change()?)
        .await
        .map_err(context("sign_change after a refused seal"))?;
    Ok(())
}

/// A custody that is not headless refuses `restore` with
/// `MethodNotOffered` for every kind of material.
///
/// A headless custody
/// refuses, with `MethodNotOffered`, material whose method differs from its
/// own kind.
///
/// # Errors
///
/// [`ConformanceFailure`] naming the first check that fails, and for a
/// headless custody until its branch is written.
pub async fn restore_refuses_commitment_mismatch<C: NextSetCustody>(
    custody: &C,
) -> Result<(), ConformanceFailure> {
    let kind = custody.custody_kind();
    let headless = is_headless(kind);
    for material in every_material() {
        let method = material.custody_kind();
        if headless && method == kind {
            continue;
        }
        let result = custody.restore(material, [0x42; 32]).await;
        if !matches!(result, Err(NextSetCustodyError::MethodNotOffered)) {
            let check = if headless {
                format!("restore by the {method:?} method on the {kind:?} custody")
            } else {
                format!("restore by the {method:?} method off headless")
            };
            return Err(failure_saw(check, &result));
        }
    }
    if headless {
        return Err(headless_branch_unwritten());
    }
    Ok(())
}

/// Every case's name and outcome against a fresh custody from `construct`,
/// in the order of the one case list the conformance macro also expands.
pub async fn run_every_case<C: NextSetCustody>(
    construct: impl Fn() -> C,
) -> Vec<(&'static str, Result<(), ConformanceFailure>)> {
    crate::__next_set_custody_cases!(@each run (construct))
}

/// The one list of §16.12.3a cases. `@each tests (path)` expands one
/// `#[tokio::test]` per case calling the constructor at `path`;
/// `@each run (ident)` expands a `Vec` of every case's outcome. Internal to
/// [`next_set_custody_conformance!`](crate::next_set_custody_conformance)
/// and [`run_every_case`](crate::conformance::next_set_custody::run_every_case).
#[doc(hidden)]
#[macro_export]
macro_rules! __next_set_custody_cases {
    (@each $mode:ident ($($args:tt)*)) => {
        $crate::__next_set_custody_cases! { @$mode ($($args)*)
            generate_then_reveal_gives_compressed_point
            sign_change_verifies
            sign_probe_signs_the_probe_preimage_only
            destroy_prevents_sign
            invalid_handle_errors
            seal_backup_refused_off_headless_or_outside_window
            restore_refuses_commitment_mismatch
        }
    };
    (@tests ($constructor:path) $($case:ident)*) => {
        $(
            #[tokio::test]
            async fn $case() -> ::core::result::Result<
                (),
                $crate::conformance::next_set_custody::ConformanceFailure,
            > {
                $crate::conformance::next_set_custody::$case(&$constructor()).await
            }
        )*
    };
    (@run ($construct:ident) $($case:ident)*) => {
        ::std::vec![$(
            (
                ::core::stringify!($case),
                $crate::conformance::next_set_custody::$case(&$construct()).await,
            )
        ),*]
    };
}

/// Generates the `16-test-infrastructure.md` §16.12.3a suite for a
/// `scp_platform::NextSetCustody` implementor.
///
/// `$constructor` is an expression that builds a fresh custody; each test
/// evaluates it once. The caller's crate must depend on `scp-platform` and
/// on `tokio` with the `macros` and `rt` features.
#[macro_export]
macro_rules! next_set_custody_conformance {
    ($constructor:expr) => {
        fn next_set_custody_conformance_constructor() -> impl ::scp_platform::NextSetCustody {
            $constructor
        }

        mod next_set_custody_conformance {
            $crate::__next_set_custody_cases!(
                @each tests (super::next_set_custody_conformance_constructor)
            );
        }
    };
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use scp_platform::testing::InMemoryNextSetCustody;
    use scp_platform::{
        BackupArtifact, BackupRequest, CustodyProbe, ENCRYPTED_BACKUP_BYTES, IndexedSignature,
        KeyEventSignError, KeyEventSigner, MaybeSend, NextSetCustody, NextSetCustodyError,
        NextSetKeyHandle, PreRotationCustodyKind, ProbeSignature, RestoreMaterial, SigningChange,
    };
    use zeroize::Zeroizing;

    use super::{HEADLESS_BRANCH_UNWRITTEN, run_every_case, v41_change};

    crate::next_set_custody_conformance!(InMemoryNextSetCustody::new());

    /// The one way each meta-test implementor departs from
    /// `InMemoryNextSetCustody`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Flaw {
        /// None: the positive control.
        Unbroken,
        /// `sign_probe` signs Vector 41's event digest `D` in place of the
        /// probe's digest.
        ProbeSignsD,
        /// `seal_backup` emits an artifact for a handle the custody does not
        /// hold.
        SealsUnknownHandle,
        /// Declares the encrypted-backup kind, seals and refuses as a
        /// headless custody would, and otherwise delegates.
        HeadlessKind,
        /// Declares the encrypted-backup kind, and seals and restores by
        /// every method.
        HeadlessAnyMethod,
    }

    struct Mutant {
        inner: InMemoryNextSetCustody,
        flaw: Flaw,
    }

    impl Mutant {
        fn new(flaw: Flaw) -> Self {
            Self {
                inner: InMemoryNextSetCustody::new(),
                flaw,
            }
        }

        fn headless(&self) -> bool {
            matches!(self.flaw, Flaw::HeadlessKind | Flaw::HeadlessAnyMethod)
        }
    }

    fn encrypted_artifact() -> BackupArtifact {
        BackupArtifact::Encrypted {
            backup: [0; ENCRYPTED_BACKUP_BYTES],
            passphrase: Zeroizing::new("passphrase".to_owned()),
        }
    }

    impl KeyEventSigner for Mutant {
        type Member = NextSetKeyHandle;

        fn sign_change(
            &self,
            member: &NextSetKeyHandle,
            change: &SigningChange,
        ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
            self.inner.sign_change(member, change)
        }

        async fn sign_probe(
            &self,
            member: &NextSetKeyHandle,
            probe: &CustodyProbe,
        ) -> Result<ProbeSignature, KeyEventSignError> {
            if self.flaw != Flaw::ProbeSignsD {
                return self.inner.sign_probe(member, probe).await;
            }
            let change = v41_change().map_err(|_| KeyEventSignError::MemberNotFound)?;
            match self.inner.sign_change(member, &change).await? {
                IndexedSignature::Raw { signature } => Ok(ProbeSignature::raw(signature)),
                IndexedSignature::WebAuthnAssertion(assertion) => {
                    Ok(ProbeSignature::assertion(assertion))
                }
            }
        }
    }

    impl NextSetCustody for Mutant {
        fn generate(
            &self,
        ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
            self.inner.generate()
        }

        fn reveal_public_key(
            &self,
            handle: &NextSetKeyHandle,
        ) -> impl Future<Output = Result<[u8; 33], NextSetCustodyError>> + Send {
            self.inner.reveal_public_key(handle)
        }

        fn destroy(
            &self,
            handle: &NextSetKeyHandle,
        ) -> impl Future<Output = Result<(), NextSetCustodyError>> + Send {
            self.inner.destroy(handle)
        }

        async fn seal_backup(
            &self,
            handle: &NextSetKeyHandle,
            request: BackupRequest,
        ) -> Result<BackupArtifact, NextSetCustodyError> {
            match self.flaw {
                Flaw::Unbroken | Flaw::ProbeSignsD => self.inner.seal_backup(handle, request).await,
                Flaw::SealsUnknownHandle => {
                    if self.inner.reveal_public_key(handle).await.is_err() {
                        return Ok(encrypted_artifact());
                    }
                    self.inner.seal_backup(handle, request).await
                }
                Flaw::HeadlessKind | Flaw::HeadlessAnyMethod => {
                    if self.flaw == Flaw::HeadlessKind
                        && request.custody_kind() != self.custody_kind()
                    {
                        return Err(NextSetCustodyError::MethodNotOffered);
                    }
                    self.inner.reveal_public_key(handle).await?;
                    Ok(encrypted_artifact())
                }
            }
        }

        async fn restore(
            &self,
            material: RestoreMaterial,
            expected_commitment: [u8; 32],
        ) -> Result<NextSetKeyHandle, NextSetCustodyError> {
            if self.flaw == Flaw::HeadlessAnyMethod {
                return Ok(NextSetKeyHandle::new(0));
            }
            self.inner.restore(material, expected_commitment).await
        }

        fn custody_kind(&self) -> PreRotationCustodyKind {
            if self.headless() {
                PreRotationCustodyKind::EncryptedOfflineBackup
            } else {
                self.inner.custody_kind()
            }
        }
    }

    /// Every case's name and the check it failed, `None` for a pass.
    async fn checks(flaw: Flaw) -> Vec<(&'static str, Option<String>)> {
        run_every_case(|| Mutant::new(flaw))
            .await
            .into_iter()
            .map(|(case, outcome)| (case, outcome.err().map(|f| f.check().to_owned())))
            .collect()
    }

    /// The seven cases in list order, each failing the check given for it.
    fn expected(failing: &[(&str, &str)]) -> Vec<(&'static str, Option<String>)> {
        [
            "generate_then_reveal_gives_compressed_point",
            "sign_change_verifies",
            "sign_probe_signs_the_probe_preimage_only",
            "destroy_prevents_sign",
            "invalid_handle_errors",
            "seal_backup_refused_off_headless_or_outside_window",
            "restore_refuses_commitment_mismatch",
        ]
        .into_iter()
        .map(|case| {
            let check = failing
                .iter()
                .find(|(name, _)| *name == case)
                .map(|(_, check)| (*check).to_owned());
            (case, check)
        })
        .collect()
    }

    #[tokio::test]
    async fn the_unbroken_custody_passes_every_case() {
        assert_eq!(checks(Flaw::Unbroken).await, expected(&[]));
    }

    #[tokio::test]
    async fn a_custody_whose_probe_signs_d_fails_the_probe_case_at_its_first_check() {
        assert_eq!(
            checks(Flaw::ProbeSignsD).await,
            expected(&[(
                "sign_probe_signs_the_probe_preimage_only",
                "the probe signature"
            )])
        );
    }

    #[tokio::test]
    async fn a_custody_that_seals_a_gone_handle_fails_both_handle_cases() {
        assert_eq!(
            checks(Flaw::SealsUnknownHandle).await,
            expected(&[
                ("destroy_prevents_sign", "seal_backup on a destroyed handle"),
                ("invalid_handle_errors", "seal_backup on an unissued handle"),
            ])
        );
    }

    /// A custody of a headless kind reaches the stub branch of the seal and
    /// restore cases, which fail it, after passing the method checks.
    #[tokio::test]
    async fn a_headless_custody_fails_the_unwritten_branch() {
        assert_eq!(
            checks(Flaw::HeadlessKind).await,
            expected(&[
                (
                    "seal_backup_refused_off_headless_or_outside_window",
                    HEADLESS_BRANCH_UNWRITTEN
                ),
                (
                    "restore_refuses_commitment_mismatch",
                    HEADLESS_BRANCH_UNWRITTEN
                ),
            ])
        );
    }

    #[tokio::test]
    async fn a_headless_custody_that_serves_another_method_fails_the_method_checks() {
        assert_eq!(
            checks(Flaw::HeadlessAnyMethod).await,
            expected(&[
                (
                    "seal_backup_refused_off_headless_or_outside_window",
                    "seal_backup by the ShamirSecretSharing method on the \
                     EncryptedOfflineBackup custody"
                ),
                (
                    "restore_refuses_commitment_mismatch",
                    "restore by the ShamirSecretSharing method on the \
                     EncryptedOfflineBackup custody"
                ),
            ])
        );
    }
}
