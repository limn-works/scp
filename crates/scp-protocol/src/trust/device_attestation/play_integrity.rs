//! The Play Integrity checks and the `PlayIntegrityVerifier` entry
//! (`09-security-model.md` §9.3.1, "Play Integrity checks" 1 through 6 and
//! "The verifier's service-record entry").
//!
//! [`read_play_integrity`] runs every check on one entry's token and verdict
//! and returns the verified attestation or the first failing check's
//! [`PlayIntegrityFailure`]. Procedure steps 1 through 5 (the challenge, the
//! service record, the tag and the entry fields) belong to the full reader,
//! which computes the binding digest `D` and calls this function. The function
//! is private to the device-attestation module and takes `D` only as a
//! [`BindingDigest`], which only
//! [`device_attestation_binding_digest`](super::device_attestation_binding_digest)
//! builds and which carries the identifier it covers, so no caller verifies a
//! verdict against a `D` or a subject it chose.
//!
//! The checks run in [`PLAY_INTEGRITY_CHECKS`] order, one function per
//! condition §9.3.1 names, so the record of checks that ran shows which
//! condition stopped a run. A check that needs the parsed verdict or the
//! verifier's key state reads it through a [`State`] accessor. When the check
//! that admits that part is missing from the array, the accessor reads the part
//! leniently instead, and when even that fails it stops the run with
//! [`Stop::Prerequisite`]. Production always runs the whole array, where each
//! accessor's input has already passed the strict check before it, so
//! `Prerequisite` cannot occur there; [`read_play_integrity`] still maps it to
//! the failure the missing check returns, failing closed. Only the test harness
//! runs a shortened array.

use std::time::{Duration, SystemTime};

use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use scp_did::{Identifier, KeyCondition, KeyRole};
use scp_kel::ResolvedState;
use sha2::{Digest, Sha256};

use super::digest::BindingDigest;
use super::{
    DeviceAttestationPlatform, DeviceAttestationRejection, DeviceAttestationUnverifiable,
    VerifiedDeviceAttestation,
};
use crate::trust::sybil::ValidatedSybilPolicy;

/// The clock skew §9.3.1 allows when it compares a platform time with the
/// reader's current time.
const CLOCK_SKEW_SECS: u64 = 300;

/// The verdict's length: `verifier ‖ package_hash ‖ cert_digest ‖
/// BE64(token_issued_at) ‖ BE64(checked_at) ‖ signature`.
pub(super) const VERDICT_LEN: usize = 176;

/// The verdict signature's separator (§9.18.2), with no length prefix.
const VERDICT_SEPARATOR: &[u8; 30] = b"SCP-PLAY-INTEGRITY-VERDICT-V1:";

/// The signed preimage's length: the separator, six 32-byte values and two
/// 8-byte timestamps.
pub(super) const PREIMAGE_LEN: usize = 238;

/// The `id` fragment a `PlayIntegrityVerifier` entry carries before its index.
const VERIFIER_ENTRY_FRAGMENT: &str = "#play-integrity-verifier-";

/// The scheme and authority prefix a verdict endpoint URL starts with.
const HTTPS_PREFIX: &str = "https://";

/// A Play Integrity read that did not verify: a check the reader ran to
/// completion failed, or the reader could not run one (§9.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlayIntegrityFailure {
    /// `Rejected { cause }`.
    Rejected(DeviceAttestationRejection),
    /// `Unverifiable { cause }`.
    Unverifiable(DeviceAttestationUnverifiable),
}

/// The inputs of one Play Integrity read.
#[derive(Debug, Clone, Copy)]
pub(super) struct PlayIntegrityRead<'a> {
    /// The integrity token's UTF-8 bytes, decoded from the entry's base64url
    /// field.
    pub(super) token: &'a [u8],
    /// The verdict field, decoded from the entry's base64url field, of any
    /// length: check 1 rejects every length but 176.
    pub(super) verdict: &'a [u8],
    /// The binding digest `D` the full reader computed for the identifier
    /// being read, the context id and the context's challenge. Its identifier
    /// is the preimage's `subject`.
    pub(super) binding: &'a BindingDigest,
    /// The context's validated Sybil policy.
    pub(super) policy: ValidatedSybilPolicy<'a>,
    /// The key states the caller resolved for verifiers, each from a
    /// `Confirmed` or `Adopted` resolution, the only verdicts that yield one.
    pub(super) verifiers: &'a [&'a ResolvedState],
    /// The reader's current time since the Unix epoch. Check 4 compares it
    /// with the verdict's whole-second timestamps, and check 5 with the
    /// resolution instant, both at full precision, never truncated to whole
    /// seconds. One value serves both, so the two checks cannot read
    /// different clocks.
    pub(super) now: Duration,
    /// The service-record entry's `id`, which a `Verified` outcome carries.
    pub(super) entry_id: &'a str,
}

/// Runs Play Integrity checks 1 through 6.
///
/// # Errors
///
/// The first failing check's [`PlayIntegrityFailure`].
pub(super) fn read_play_integrity(
    read: &PlayIntegrityRead<'_>,
) -> Result<VerifiedDeviceAttestation, PlayIntegrityFailure> {
    run(read, &PLAY_INTEGRITY_CHECKS)
        .result
        .map_err(|stop| match stop {
            Stop::Fail(failure) => failure,
            // Unreachable with the full array (see the module documentation);
            // the missing check's own failure, so the read fails closed.
            Stop::Prerequisite(check) => check.prerequisite_failure(),
        })
}

/// One condition of a Play Integrity check, in §9.3.1 order. Check 1 is three
/// entries and check 4 is three, one per condition each states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PlayIntegrityCheck {
    /// Check 1: `accepted_android_packages` names a verifier.
    VerifierNamed,
    /// Check 1: the verdict field is not 176 bytes of `0x00`.
    VerdictPresent,
    /// Check 1: the verdict field is 176 bytes.
    VerdictLength,
    /// Check 2: an element matches `package_hash` and `cert_digest`.
    Package,
    /// Check 3: a matching element names the verdict's `verifier`.
    Verifier,
    /// Check 4: `token_issued_at` is at most `checked_at`.
    TimestampOrder,
    /// Check 4: `checked_at` is within the skew of the reader's time.
    NotYetValid,
    /// Check 4: the maximum age.
    MaxAge,
    /// Check 5: the verifier's key state is supplied and fresh.
    VerifierKeyState,
    /// Check 6: the signature under the verifier's Current `Active` key.
    Signature,
}

impl PlayIntegrityCheck {
    /// Every check, in run order.
    #[cfg(test)]
    pub(super) const ALL: [Self; 10] = [
        Self::VerifierNamed,
        Self::VerdictPresent,
        Self::VerdictLength,
        Self::Package,
        Self::Verifier,
        Self::TimestampOrder,
        Self::NotYetValid,
        Self::MaxAge,
        Self::VerifierKeyState,
        Self::Signature,
    ];

    /// The failure a check returns for the part it admits, which a run
    /// returns when a later check needed that part and this check was not in
    /// the array.
    const fn prerequisite_failure(self) -> PlayIntegrityFailure {
        match self {
            Self::VerifierKeyState => {
                unverifiable(DeviceAttestationUnverifiable::VerifierKeyStateUnresolved)
            }
            Self::VerifierNamed
            | Self::VerdictPresent
            | Self::VerdictLength
            | Self::Package
            | Self::Verifier
            | Self::TimestampOrder
            | Self::NotYetValid
            | Self::MaxAge
            | Self::Signature => rejected(DeviceAttestationRejection::MalformedEntry),
        }
    }
}

/// Why a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    /// A check failed with this outcome.
    Fail(PlayIntegrityFailure),
    /// A check needed a part that the named check admits, that check was not
    /// in the array, and the part could not be read leniently.
    Prerequisite(PlayIntegrityCheck),
}

/// The signature of one check.
pub(super) type CheckFn = fn(&mut State<'_>) -> Result<(), Stop>;

/// Every Play Integrity check, in §9.3.1 order.
pub(super) const PLAY_INTEGRITY_CHECKS: [(PlayIntegrityCheck, CheckFn); 10] = [
    (PlayIntegrityCheck::VerifierNamed, check_verifier_named),
    (PlayIntegrityCheck::VerdictPresent, check_verdict_present),
    (PlayIntegrityCheck::VerdictLength, check_verdict_length),
    (PlayIntegrityCheck::Package, check_package),
    (PlayIntegrityCheck::Verifier, check_verifier),
    (PlayIntegrityCheck::TimestampOrder, check_timestamp_order),
    (PlayIntegrityCheck::NotYetValid, check_not_yet_valid),
    (PlayIntegrityCheck::MaxAge, check_max_age),
    (
        PlayIntegrityCheck::VerifierKeyState,
        check_verifier_key_state,
    ),
    (PlayIntegrityCheck::Signature, check_signature),
];

/// The outcome of a run and the checks that ran, in order, the check that
/// stopped the run included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Run {
    /// The verified attestation, or why the run stopped.
    pub(super) result: Result<VerifiedDeviceAttestation, Stop>,
    /// The checks that ran.
    pub(super) ran: Vec<PlayIntegrityCheck>,
}

/// Runs `checks` in order on one read.
pub(super) fn run(read: &PlayIntegrityRead<'_>, checks: &[(PlayIntegrityCheck, CheckFn)]) -> Run {
    let mut state = State {
        read: *read,
        key_state: None,
    };
    let mut ran = Vec::with_capacity(checks.len());
    for (id, check) in checks {
        ran.push(*id);
        if let Err(stop) = check(&mut state) {
            return Run {
                result: Err(stop),
                ran,
            };
        }
    }
    Run {
        result: state.verified(),
        ran,
    }
}

/// The verdict's fields (§9.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Verdict {
    /// The verifier's identifier.
    pub(super) verifier: Identifier,
    /// SHA-256 of the package name's UTF-8 bytes.
    pub(super) package_hash: [u8; 32],
    /// The SHA-256 of the app's signing certificate.
    pub(super) cert_digest: [u8; 32],
    /// `requestDetails.timestampMillis` divided by 1,000.
    pub(super) token_issued_at: u64,
    /// The Unix second at which the verifier decoded the token.
    pub(super) checked_at: u64,
    /// The raw `r ‖ s` signature over the preimage's digest.
    pub(super) signature: [u8; 64],
}

impl Verdict {
    /// Splits a 176-byte verdict field into its fields; `None` for any other
    /// length.
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; VERDICT_LEN] = bytes.try_into().ok()?;
        let (verifier, rest) = bytes.split_first_chunk::<32>()?;
        let (package_hash, rest) = rest.split_first_chunk::<32>()?;
        let (cert_digest, rest) = rest.split_first_chunk::<32>()?;
        let (token_issued_at, rest) = rest.split_first_chunk::<8>()?;
        let (checked_at, signature) = rest.split_first_chunk::<8>()?;
        Some(Self {
            verifier: Identifier::from_bytes(*verifier),
            package_hash: *package_hash,
            cert_digest: *cert_digest,
            token_issued_at: u64::from_be_bytes(*token_issued_at),
            checked_at: u64::from_be_bytes(*checked_at),
            signature: signature.try_into().ok()?,
        })
    }
}

/// The values the verdict signature covers (§9.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PreimageFields {
    /// The verifier's identifier.
    pub(super) verifier: [u8; 32],
    /// The attesting identifier.
    pub(super) subject: [u8; 32],
    /// The binding digest `D`.
    pub(super) binding: [u8; 32],
    /// `SHA-256(token)`.
    pub(super) token_digest: [u8; 32],
    /// SHA-256 of the package name.
    pub(super) package_hash: [u8; 32],
    /// The signing certificate's SHA-256.
    pub(super) cert_digest: [u8; 32],
    /// `token_issued_at`.
    pub(super) token_issued_at: u64,
    /// `checked_at`.
    pub(super) checked_at: u64,
}

impl PreimageFields {
    /// The fields check 6 recomputes: `subject` and `D` from the binding
    /// digest the reader computed, the token's digest from the entry, and
    /// every other value from the verdict.
    fn of(verdict: &Verdict, binding: &BindingDigest, token: &[u8]) -> Self {
        Self {
            verifier: *verdict.verifier.as_bytes(),
            subject: *binding.subject().as_bytes(),
            binding: *binding.as_bytes(),
            token_digest: Sha256::digest(token).into(),
            package_hash: verdict.package_hash,
            cert_digest: verdict.cert_digest,
            token_issued_at: verdict.token_issued_at,
            checked_at: verdict.checked_at,
        }
    }

    /// The 238-byte preimage ([`PREIMAGE_LEN`]).
    pub(super) fn preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(PREIMAGE_LEN);
        preimage.extend_from_slice(VERDICT_SEPARATOR);
        preimage.extend_from_slice(&self.verifier);
        preimage.extend_from_slice(&self.subject);
        preimage.extend_from_slice(&self.binding);
        preimage.extend_from_slice(&self.token_digest);
        preimage.extend_from_slice(&self.package_hash);
        preimage.extend_from_slice(&self.cert_digest);
        preimage.extend_from_slice(&self.token_issued_at.to_be_bytes());
        preimage.extend_from_slice(&self.checked_at.to_be_bytes());
        preimage
    }

    /// The digest the verifier's `#active` key signs.
    pub(super) fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.preimage()).into()
    }
}

/// Check 6's verification: `signature` over `digest` under the one key
/// `resolved` lists `Current` in the `Active` role, by
/// [`verify_prehash_strict`] (raw `r ‖ s`, low `s`). A key state that lists
/// no such key, or more than one, or a key that is not a valid point, fails.
pub(super) fn verify_under_current_active(
    resolved: &ResolvedState,
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    let mut current_active =
        resolved.key_state().keys.iter().filter(|entry| {
            entry.role == KeyRole::Active && entry.condition == KeyCondition::Current
        });
    let (Some(entry), None) = (current_active.next(), current_active.next()) else {
        return false;
    };
    P256PublicKey::from_sec1(&entry.key)
        .and_then(|key| verify_prehash_strict(&key, digest, signature))
        .is_ok()
}

/// The parts of one read the checks decode, each decoded once.
pub(super) struct State<'a> {
    read: PlayIntegrityRead<'a>,
    /// Check 5's selection.
    key_state: Option<&'a ResolvedState>,
}

impl<'a> State<'a> {
    /// The verdict's fields. Check 1 admits only a 176-byte field, so this
    /// fails only when check 1's length condition did not run.
    fn verdict(&self) -> Result<Verdict, Stop> {
        Verdict::parse(self.read.verdict)
            .ok_or(Stop::Prerequisite(PlayIntegrityCheck::VerdictLength))
    }

    /// The first supplied key state of the verdict's `verifier`.
    fn verifier_key_state(&self) -> Result<Option<&'a ResolvedState>, Stop> {
        let verifier = self.verdict()?.verifier;
        Ok(self
            .read
            .verifiers
            .iter()
            .copied()
            .find(|resolved| *resolved.identifier() == verifier))
    }

    /// Check 5's key state, or, when check 5 did not run, the first supplied
    /// key state of the verdict's `verifier` whatever its age.
    fn key_state(&self) -> Result<&'a ResolvedState, Stop> {
        match self.key_state {
            Some(resolved) => Ok(resolved),
            None => self
                .verifier_key_state()?
                .ok_or(Stop::Prerequisite(PlayIntegrityCheck::VerifierKeyState)),
        }
    }

    /// The elements of `accepted_android_packages` whose package name hashes
    /// to the verdict's `package_hash` and whose certificate digest equals its
    /// `cert_digest`.
    fn matching_packages(
        &self,
        verdict: &Verdict,
    ) -> impl Iterator<Item = &'a crate::trust::sybil::AcceptedAndroidPackage> {
        let (package_hash, cert_digest) = (verdict.package_hash, verdict.cert_digest);
        self.read
            .policy
            .policy()
            .accepted_android_packages
            .iter()
            .filter(move |package| {
                Sha256::digest(package.package_name.as_bytes()).as_slice() == package_hash
                    && package.signing_cert_sha256 == cert_digest
            })
    }

    fn verified(&self) -> Result<VerifiedDeviceAttestation, Stop> {
        let verdict = self.verdict()?;
        Ok(VerifiedDeviceAttestation::new(
            DeviceAttestationPlatform::PlayIntegrity,
            self.read.entry_id.to_owned(),
            Sha256::digest(self.read.token).into(),
            verdict.token_issued_at,
        ))
    }
}

const fn rejected(cause: DeviceAttestationRejection) -> PlayIntegrityFailure {
    PlayIntegrityFailure::Rejected(cause)
}

const fn unverifiable(cause: DeviceAttestationUnverifiable) -> PlayIntegrityFailure {
    PlayIntegrityFailure::Unverifiable(cause)
}

const fn reject(cause: DeviceAttestationRejection) -> Stop {
    Stop::Fail(rejected(cause))
}

const fn unverified(cause: DeviceAttestationUnverifiable) -> Stop {
    Stop::Fail(unverifiable(cause))
}

/// Check 1: an empty `accepted_android_packages` names no verifier.
const fn check_verifier_named(state: &mut State<'_>) -> Result<(), Stop> {
    if state
        .read
        .policy
        .policy()
        .accepted_android_packages
        .is_empty()
    {
        return Err(unverified(DeviceAttestationUnverifiable::NoVerifierNamed));
    }
    Ok(())
}

/// Check 1: 176 bytes of `0x00` is the verdict an owner publishes while it
/// holds none.
fn check_verdict_present(state: &mut State<'_>) -> Result<(), Stop> {
    let verdict = state.read.verdict;
    if verdict.len() == VERDICT_LEN && verdict.iter().all(|byte| *byte == 0) {
        return Err(unverified(DeviceAttestationUnverifiable::VerdictAbsent));
    }
    Ok(())
}

/// Check 1: any length other than 176 bytes.
const fn check_verdict_length(state: &mut State<'_>) -> Result<(), Stop> {
    if state.read.verdict.len() != VERDICT_LEN {
        return Err(reject(DeviceAttestationRejection::MalformedEntry));
    }
    Ok(())
}

/// Check 2: some element matches `package_hash` and `cert_digest`.
fn check_package(state: &mut State<'_>) -> Result<(), Stop> {
    let verdict = state.verdict()?;
    if state.matching_packages(&verdict).next().is_none() {
        return Err(reject(DeviceAttestationRejection::PackageNotAccepted));
    }
    Ok(())
}

/// Check 3: some element matching `package_hash` and `cert_digest` names the
/// verdict's `verifier`; that element is the entry's package.
fn check_verifier(state: &mut State<'_>) -> Result<(), Stop> {
    let verdict = state.verdict()?;
    if !state
        .matching_packages(&verdict)
        .any(|package| package.verifier_identifier == verdict.verifier)
    {
        return Err(unverified(
            DeviceAttestationUnverifiable::VerdictFromUnnamedVerifier,
        ));
    }
    Ok(())
}

/// Check 4: `token_issued_at` exceeds `checked_at`.
fn check_timestamp_order(state: &mut State<'_>) -> Result<(), Stop> {
    let verdict = state.verdict()?;
    if verdict.token_issued_at > verdict.checked_at {
        return Err(reject(DeviceAttestationRejection::MalformedEntry));
    }
    Ok(())
}

/// Check 4: `checked_at` exceeds the reader's time plus the skew; with
/// `token_issued_at` at most `checked_at`, this bounds both.
fn check_not_yet_valid(state: &mut State<'_>) -> Result<(), Stop> {
    let verdict = state.verdict()?;
    let skew = Duration::from_secs(CLOCK_SKEW_SECS);
    if Duration::from_secs(verdict.checked_at) > state.read.now.saturating_add(skew) {
        return Err(reject(DeviceAttestationRejection::NotYetValid));
    }
    Ok(())
}

/// Check 4: the reader's time exceeds `token_issued_at` plus the maximum age,
/// compared at the reader's full precision.
fn check_max_age(state: &mut State<'_>) -> Result<(), Stop> {
    let verdict = state.verdict()?;
    let expiry = state
        .read
        .policy
        .device_attestation_expiry(verdict.token_issued_at);
    if state.read.now > Duration::from_secs(expiry) {
        return Err(reject(DeviceAttestationRejection::Expired));
    }
    Ok(())
}

/// Check 5: the caller supplied a key state of the verdict's `verifier`, from
/// a `Confirmed` or `Adopted` resolution, and fresh under
/// `ResolvedState::is_fresh` (`03-identity.md`): resolved less than
/// `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` before the reader's time, and
/// not after it.
fn check_verifier_key_state(state: &mut State<'_>) -> Result<(), Stop> {
    let unresolved = unverified(DeviceAttestationUnverifiable::VerifierKeyStateUnresolved);
    let resolved = state.verifier_key_state()?.ok_or(unresolved)?;
    // A time past `SystemTime`'s range has no resolution within the bound.
    let now = SystemTime::UNIX_EPOCH
        .checked_add(state.read.now)
        .ok_or(unresolved)?;
    if !resolved.is_fresh(now) {
        return Err(unresolved);
    }
    state.key_state = Some(resolved);
    Ok(())
}

/// Check 6: the signature over the recomputed preimage, under the verifier's
/// Current `Active` key and no other.
fn check_signature(state: &mut State<'_>) -> Result<(), Stop> {
    let verdict = state.verdict()?;
    let resolved = state.key_state()?;
    let digest = PreimageFields::of(&verdict, state.read.binding, state.read.token).digest();
    if !verify_under_current_active(resolved, &digest, &verdict.signature) {
        return Err(reject(DeviceAttestationRejection::VerdictSignatureInvalid));
    }
    Ok(())
}

/// A verifier's `PlayIntegrityVerifier` service-record entry (§9.3.1, "The
/// verifier's service-record entry").
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlayIntegrityVerifierEntry {
    /// The zero-based index the entry's `id` ends with.
    pub(super) index: u64,
    /// The Android package the verifier serves.
    pub(super) package_name: String,
    /// The Google Cloud project number the owner requests the token under.
    pub(super) cloud_project_number: u64,
    /// The HTTPS URL of the verdict endpoint.
    pub(super) verdict_url: String,
}

/// Why a `PlayIntegrityVerifier` entry does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum VerifierEntryFault {
    /// The `id` is not the verifier's identifier text form followed by
    /// `#play-integrity-verifier-`.
    #[error("the id is not <identifier>#play-integrity-verifier-<index>")]
    IdNotOfVerifier,
    /// The index is not a decimal integer in its one canonical form.
    #[error("the id's index is not a canonical decimal integer")]
    IndexNotCanonical,
    /// The `serviceEndpoint` is not three non-empty fields joined by single
    /// spaces.
    #[error("the serviceEndpoint is not three fields joined by single spaces")]
    FieldsNotThree,
    /// The Cloud project number is not a decimal integer without leading
    /// zeros.
    #[error("the Cloud project number is not a canonical decimal integer")]
    ProjectNumberNotCanonical,
    /// The URL's scheme is not `https`, or it names no authority.
    #[error("the verdict URL is not an https URL")]
    UrlNotHttps,
}

/// Parses a decimal integer in its one canonical form: ASCII digits only, no
/// sign, and no leading zero unless the value is zero.
fn canonical_decimal(text: &str) -> Option<u64> {
    let digits_only = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let leading_zero = text.len() > 1 && text.starts_with('0');
    if !digits_only || leading_zero {
        return None;
    }
    text.parse().ok()
}

/// Parses a `PlayIntegrityVerifier` entry of `verifier`'s service record from
/// its `id` and `serviceEndpoint`.
///
/// # Errors
///
/// The first [`VerifierEntryFault`] the entry shows.
pub(super) fn parse_play_integrity_verifier_entry(
    verifier: &Identifier,
    id: &str,
    service_endpoint: &str,
) -> Result<PlayIntegrityVerifierEntry, VerifierEntryFault> {
    let index = id
        .strip_prefix(verifier.to_string().as_str())
        .and_then(|rest| rest.strip_prefix(VERIFIER_ENTRY_FRAGMENT))
        .ok_or(VerifierEntryFault::IdNotOfVerifier)?;
    let index = canonical_decimal(index).ok_or(VerifierEntryFault::IndexNotCanonical)?;
    let fields: Vec<&str> = service_endpoint.split(' ').collect();
    let [package_name, project, url] = fields.as_slice() else {
        return Err(VerifierEntryFault::FieldsNotThree);
    };
    if package_name.is_empty() || project.is_empty() || url.is_empty() {
        return Err(VerifierEntryFault::FieldsNotThree);
    }
    let cloud_project_number =
        canonical_decimal(project).ok_or(VerifierEntryFault::ProjectNumberNotCanonical)?;
    let authority = url
        .strip_prefix(HTTPS_PREFIX)
        .ok_or(VerifierEntryFault::UrlNotHttps)?;
    if authority.is_empty() || authority.starts_with('/') {
        return Err(VerifierEntryFault::UrlNotHttps);
    }
    Ok(PlayIntegrityVerifierEntry {
        index,
        package_name: (*package_name).to_owned(),
        cloud_project_number,
        verdict_url: (*url).to_owned(),
    })
}

#[cfg(test)]
#[path = "tests/play_integrity.rs"]
mod tests;
