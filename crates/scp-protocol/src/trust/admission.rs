//! Context admission capability requirements with verification levels.
//!
//! [`CapabilityRequirement`] names a capability an agent must hold to join a
//! context, the [`VerificationLevel`] it must reach, the challengers the
//! context trusts for it, and an optional [`RetryCap`] stricter than the
//! capability's definition. [`CapabilityRequirements`] is a context's bounded
//! list. Both validate on construction and on deserialize (spec 07
//! §7.3.4.4).
//!
//! [`check_capability_requirements`] checks an agent's self-attested
//! capabilities and challenge records against a list, returning the first
//! unmet requirement as an [`AdmissionError`].

use scp_clock::Clock;
use scp_did::DID;
use serde::{Deserialize, Serialize};

use super::TrustError;
use super::attestation::ActiveKeyResolver;
use super::capability_definition::CapabilityDefinitionSource;
use super::capability_uri::CapabilityUri;
use super::challenge::{
    ChallengeVerification, MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT,
    MAX_TRUSTED_VERIFIERS_PER_REQUIREMENT, verify_challenge_verification,
};
use super::identifier::CanonicalIdentifier;

// ---------------------------------------------------------------------------
// VerificationLevel
// ---------------------------------------------------------------------------

/// How a capability must be verified for admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// The agent claims the capability (present in their capability list).
    SelfAttested,
    /// The capability has been verified through the challenge-response protocol.
    /// Also satisfies `SelfAttested`.
    ChallengeVerified,
}

// ---------------------------------------------------------------------------
// CapabilityRequirement
// ---------------------------------------------------------------------------

/// A governance cap on the policy a counted record may carry: at most
/// `max_retries` retries and at least `min_cooldown_secs` between attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryCap {
    /// The most retries a counted record may allow.
    pub max_retries: u32,
    /// The shortest cooldown a counted record may carry.
    pub min_cooldown_secs: u32,
}

impl RetryCap {
    /// Whether `self` is at least as strict as `other`.
    const fn at_least_as_strict_as(self, other: Self) -> bool {
        let fewer_retries = self.max_retries <= other.max_retries;
        let longer_cooldown = self.min_cooldown_secs >= other.min_cooldown_secs;
        fewer_retries && longer_cooldown
    }

    /// Whether a record's signed policy respects this cap.
    const fn admits(self, record: &ChallengeVerification) -> bool {
        let retries_within = record.max_retries <= self.max_retries;
        let cooldown_within = self.min_cooldown_secs <= record.cooldown_secs;
        retries_within && cooldown_within
    }
}

/// The unvalidated wire form of a [`CapabilityRequirement`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCapabilityRequirement {
    /// The capability that must be present.
    pub capability: CapabilityUri,
    /// The minimum verification level required.
    pub verification_level: VerificationLevel,
    /// The challengers whose records count: 1 to
    /// [`MAX_TRUSTED_VERIFIERS_PER_REQUIREMENT`] canonical identifiers under
    /// `ChallengeVerified`, empty under `SelfAttested`.
    #[serde(default)]
    pub trusted_verifiers: Vec<DID>,
    /// A cap stricter than the definition's; absent under `SelfAttested`.
    #[serde(default)]
    pub retry_cap: Option<RetryCap>,
}

/// A validated admission requirement.
///
/// Built only through `TryFrom<RawCapabilityRequirement>`, which serde also
/// runs on deserialize, so every value holds:
/// - under `ChallengeVerified`, 1 to [`MAX_TRUSTED_VERIFIERS_PER_REQUIREMENT`]
///   trusted verifiers, each a canonical identifier, no two naming one key;
/// - under `SelfAttested`, no trusted verifiers and no retry cap.
///
/// A retry cap takes any `u32` for both fields (RULING 15(b) sets no
/// protocol ceiling).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "RawCapabilityRequirement",
    into = "RawCapabilityRequirement"
)]
pub struct CapabilityRequirement {
    raw: RawCapabilityRequirement,
    trusted: Vec<CanonicalIdentifier>,
}

impl TryFrom<RawCapabilityRequirement> for CapabilityRequirement {
    type Error = AdmissionError;

    fn try_from(raw: RawCapabilityRequirement) -> Result<Self, Self::Error> {
        let invalid = |reason: &str| AdmissionError::InvalidRequirement {
            uri: raw.capability.to_string(),
            reason: reason.to_owned(),
        };
        match raw.verification_level {
            VerificationLevel::SelfAttested => {
                if !raw.trusted_verifiers.is_empty() || raw.retry_cap.is_some() {
                    return Err(invalid(
                        "a SelfAttested requirement names no verifiers and no retry cap",
                    ));
                }
            }
            VerificationLevel::ChallengeVerified => {
                if raw.trusted_verifiers.is_empty() {
                    return Err(invalid("a ChallengeVerified requirement names a verifier"));
                }
                if raw.trusted_verifiers.len() > MAX_TRUSTED_VERIFIERS_PER_REQUIREMENT {
                    return Err(invalid("too many trusted verifiers"));
                }
            }
        }
        let mut trusted: Vec<CanonicalIdentifier> = Vec::with_capacity(raw.trusted_verifiers.len());
        for did in &raw.trusted_verifiers {
            let id = CanonicalIdentifier::parse(did).map_err(|e| match e {
                TrustError::NonCanonicalIdentifier { identifier, reason } => {
                    AdmissionError::NonCanonicalIdentifier { identifier, reason }
                }
                other => AdmissionError::NonCanonicalIdentifier {
                    identifier: did.to_string(),
                    reason: other.to_string(),
                },
            })?;
            if trusted.contains(&id) {
                return Err(invalid("two trusted verifiers name one key"));
            }
            trusted.push(id);
        }
        Ok(Self { raw, trusted })
    }
}

impl From<CapabilityRequirement> for RawCapabilityRequirement {
    fn from(requirement: CapabilityRequirement) -> Self {
        requirement.raw
    }
}

impl CapabilityRequirement {
    /// The capability that must be present.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityUri {
        &self.raw.capability
    }

    /// The minimum verification level required.
    #[must_use]
    pub const fn verification_level(&self) -> VerificationLevel {
        self.raw.verification_level
    }

    /// The trusted challengers, as written.
    #[must_use]
    pub fn trusted_verifiers(&self) -> &[DID] {
        &self.raw.trusted_verifiers
    }

    /// The governance retry cap, if any.
    #[must_use]
    pub const fn retry_cap(&self) -> Option<RetryCap> {
        self.raw.retry_cap
    }

    /// Whether `verifier` names a trusted challenger's key.
    fn trusts(&self, verifier: &CanonicalIdentifier) -> bool {
        self.trusted.contains(verifier)
    }

    /// Whether `self` is at least as strict as `old` for the same capability.
    fn tightens(&self, old: &Self) -> bool {
        if self.raw.capability != old.raw.capability
            || self.verification_level() < old.verification_level()
        {
            return false;
        }
        // A level raised from SelfAttested had no verifier set to narrow.
        let verifiers_narrowed = old.verification_level() == VerificationLevel::SelfAttested
            || self.trusted.iter().all(|id| old.trusted.contains(id));
        let cap_tightened = match (old.raw.retry_cap, self.raw.retry_cap) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(old_cap), Some(new_cap)) => new_cap.at_least_as_strict_as(old_cap),
        };
        verifiers_narrowed && cap_tightened
    }
}

/// A context's admission requirements: at most
/// [`MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT`] validated entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "Vec<CapabilityRequirement>",
    into = "Vec<CapabilityRequirement>"
)]
pub struct CapabilityRequirements(Vec<CapabilityRequirement>);

impl TryFrom<Vec<CapabilityRequirement>> for CapabilityRequirements {
    type Error = AdmissionError;

    fn try_from(requirements: Vec<CapabilityRequirement>) -> Result<Self, Self::Error> {
        if requirements.len() > MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT {
            return Err(AdmissionError::TooManyCapabilityRequirements {
                count: requirements.len(),
                max: MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT,
            });
        }
        Ok(Self(requirements))
    }
}

impl From<CapabilityRequirements> for Vec<CapabilityRequirement> {
    fn from(requirements: CapabilityRequirements) -> Self {
        requirements.0
    }
}

impl CapabilityRequirements {
    /// The requirements in order.
    #[must_use]
    pub fn as_slice(&self) -> &[CapabilityRequirement] {
        &self.0
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of requirements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether replacing `old` with `self` only restricts admission: every
    /// old requirement has a new one for the same capability with a level
    /// not lower, a trusted-verifier set inside the old one (unless the
    /// level rose from `SelfAttested`), and a retry cap at least as strict
    /// (an absent old cap accepts any). Added requirements only restrict,
    /// because admission requires every requirement.
    #[must_use]
    pub fn is_tightening_of(&self, old: &Self) -> bool {
        old.0.iter().all(|o| self.0.iter().any(|n| n.tightens(o)))
    }
}

// ---------------------------------------------------------------------------
// AdmissionError
// ---------------------------------------------------------------------------

/// Errors produced when an agent fails to meet admission requirements, or a
/// requirement is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// The agent does not possess the required capability at all.
    #[error("missing required capability: {uri}")]
    MissingCapability {
        /// The capability URI that is missing.
        uri: String,
    },

    /// The agent possesses the capability but lacks challenge verification.
    #[error("challenge verification required for capability: {uri}")]
    VerificationRequired {
        /// The capability URI that needs challenge verification.
        uri: String,
    },

    /// The only valid passing record for the capability comes from a
    /// challenger the requirement does not trust.
    #[error("capability {uri}: verifier {verifier} is not trusted")]
    UntrustedVerifier {
        /// The capability URI.
        uri: String,
        /// The record's verifier.
        verifier: String,
    },

    /// The only record for the capability names its subject as its verifier.
    #[error("capability {uri}: the verifier graded itself")]
    SelfChallenge {
        /// The capability URI.
        uri: String,
    },

    /// The only trusted passing record for the capability carries a looser
    /// policy than the requirement's retry cap.
    #[error("capability {uri}: record policy exceeds the retry cap")]
    RetryCapExceeded {
        /// The capability URI.
        uri: String,
    },

    /// An identifier is not the canonical spelling of a key.
    #[error("non-canonical identifier {identifier}: {reason}")]
    NonCanonicalIdentifier {
        /// The identifier as given.
        identifier: String,
        /// Why it is refused.
        reason: String,
    },

    /// A context names more than [`MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT`]
    /// requirements.
    #[error("{count} capability requirements exceed the maximum {max}")]
    TooManyCapabilityRequirements {
        /// The number supplied.
        count: usize,
        /// The maximum.
        max: usize,
    },

    /// A requirement breaks a shape rule of spec 07 §7.3.4.4.
    #[error("invalid capability requirement for {uri}: {reason}")]
    InvalidRequirement {
        /// The capability URI.
        uri: String,
        /// The broken rule.
        reason: String,
    },

    /// `subject_did` was empty.
    ///
    /// An empty subject is invalid input, not a "no match" condition: no
    /// record can be bound to it. It is refused up front, mirroring
    /// [`ParticipationAdmissionError::EmptyExpectedSubject`].
    ///
    /// [`ParticipationAdmissionError::EmptyExpectedSubject`]: crate::trust::participation::ParticipationAdmissionError::EmptyExpectedSubject
    #[error("subject_did must not be empty")]
    EmptySubjectDid,

    /// A supplied [`ChallengeVerification`] could not be checked because the
    /// check itself failed, for example because the verifier's key or the
    /// capability definition could not be obtained. This is not a judgment
    /// on the record: the admission decision is unknown, so it fails closed
    /// instead of dropping the record.
    #[error("challenge verification could not be checked: {reason}")]
    VerificationUnavailable {
        /// The underlying failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// check_capability_requirements
// ---------------------------------------------------------------------------

/// What an admission check binds records to and checks them with.
pub struct AdmissionCheck<'a> {
    /// The context being joined; a record counts only when it signs this
    /// `context_id`.
    pub context_id: &'a str,
    /// The joining agent; a record counts only when it signs this subject,
    /// compared by key.
    pub subject_did: &'a str,
    /// Resolves each record's verifier to its active key.
    pub resolver: &'a dyn ActiveKeyResolver,
    /// Supplies each record's capability definition.
    pub definitions: &'a dyn CapabilityDefinitionSource,
    /// Current time, for record expiry and the clock-skew bound.
    pub clock: &'a dyn Clock,
}

/// How one record stands against one requirement.
enum RecordStanding {
    Satisfies,
    Refused(AdmissionError),
    Irrelevant,
}

/// One record after the requirement-independent checks.
struct CheckedRecord<'a> {
    record: &'a ChallengeVerification,
    /// `Ok(verifier)` when the record passed every step-5 check.
    verdict: Result<CanonicalIdentifier, TrustError>,
}

fn standing(requirement: &CapabilityRequirement, checked: &CheckedRecord<'_>) -> RecordStanding {
    let uri = requirement.capability().to_string();
    if checked.record.capability_uri != uri {
        return RecordStanding::Irrelevant;
    }
    let verifier = match &checked.verdict {
        Ok(verifier) => verifier,
        Err(TrustError::SelfChallenge { .. }) => {
            return RecordStanding::Refused(AdmissionError::SelfChallenge { uri });
        }
        Err(_) => return RecordStanding::Irrelevant,
    };
    if !checked.record.passed {
        return RecordStanding::Irrelevant;
    }
    if requirement.verification_level() == VerificationLevel::SelfAttested {
        // A passing signed record is at least a claim; the requirement
        // names no challengers to trust.
        return RecordStanding::Satisfies;
    }
    if !requirement.trusts(verifier) {
        return RecordStanding::Refused(AdmissionError::UntrustedVerifier {
            uri,
            verifier: checked.record.verifier.to_string(),
        });
    }
    if let Some(cap) = requirement.retry_cap()
        && !cap.admits(checked.record)
    {
        return RecordStanding::Refused(AdmissionError::RetryCapExceeded { uri });
    }
    RecordStanding::Satisfies
}

/// Checks that an agent meets every capability requirement for admission.
///
/// Every record first runs through [`verify_challenge_verification`] (spec 07
/// §7.3.4 step 5: signature, context, subject, expiry, window, definition,
/// consistency, verifier ≠ subject). A record that check rejects does not
/// count; a check that could not run fails the admission closed. Then, per
/// requirement, a record counts only when it names the requirement's
/// capability, passed, and (under `ChallengeVerified`) its verifier is in
/// `trusted_verifiers` by key and its policy respects `retry_cap`.
///
/// - [`VerificationLevel::SelfAttested`]: the capability is in
///   `agent_capabilities`, or a counted record exists.
/// - [`VerificationLevel::ChallengeVerified`]: a counted record exists.
///
/// # Errors
///
/// - [`AdmissionError::EmptySubjectDid`] or
///   [`AdmissionError::NonCanonicalIdentifier`] for the subject.
/// - [`AdmissionError::VerificationUnavailable`] when checking a record
///   fails for a reason other than the record
///   ([`TrustError::is_record_rejection`] is `false`).
/// - For the first unmet requirement: the refusal of the first record that
///   named its capability ([`AdmissionError::UntrustedVerifier`],
///   [`AdmissionError::SelfChallenge`], [`AdmissionError::RetryCapExceeded`]),
///   otherwise [`AdmissionError::MissingCapability`] or
///   [`AdmissionError::VerificationRequired`].
pub fn check_capability_requirements(
    requirements: &CapabilityRequirements,
    agent_capabilities: &[CapabilityUri],
    challenge_verifications: &[ChallengeVerification],
    check: &AdmissionCheck<'_>,
) -> Result<(), AdmissionError> {
    if check.subject_did.is_empty() {
        return Err(AdmissionError::EmptySubjectDid);
    }
    if let Err(e) = CanonicalIdentifier::parse(check.subject_did) {
        return Err(AdmissionError::NonCanonicalIdentifier {
            identifier: check.subject_did.to_owned(),
            reason: e.to_string(),
        });
    }

    let mut checked = Vec::with_capacity(challenge_verifications.len());
    for record in challenge_verifications {
        let verdict = verify_challenge_verification(
            record,
            check.resolver,
            check.definitions,
            check.context_id,
            check.subject_did,
            check.clock,
        )
        .and_then(|()| CanonicalIdentifier::parse(&record.verifier));
        if let Err(e) = &verdict
            && !e.is_record_rejection()
        {
            return Err(AdmissionError::VerificationUnavailable {
                reason: e.to_string(),
            });
        }
        checked.push(CheckedRecord { record, verdict });
    }

    for requirement in requirements.as_slice() {
        let mut refusal = None;
        let mut satisfied = false;
        for record in &checked {
            match standing(requirement, record) {
                RecordStanding::Satisfies => {
                    satisfied = true;
                    break;
                }
                RecordStanding::Refused(e) => {
                    refusal.get_or_insert(e);
                }
                RecordStanding::Irrelevant => {}
            }
        }
        if satisfied {
            continue;
        }
        let uri = requirement.capability().to_string();
        match requirement.verification_level() {
            VerificationLevel::SelfAttested => {
                if !agent_capabilities.contains(requirement.capability()) {
                    return Err(refusal.unwrap_or(AdmissionError::MissingCapability { uri }));
                }
            }
            VerificationLevel::ChallengeVerified => {
                return Err(refusal.unwrap_or(AdmissionError::VerificationRequired { uri }));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::trust::challenge_fixtures::{CONTEXT, FIXTURE_URI, Fixture, Party, cases, fixture};

    fn cap(s: &str) -> CapabilityUri {
        s.parse().unwrap()
    }

    fn fixture_cap() -> CapabilityUri {
        cap(FIXTURE_URI)
    }

    fn self_attested(uri: &CapabilityUri) -> CapabilityRequirement {
        RawCapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
            trusted_verifiers: Vec::new(),
            retry_cap: None,
        }
        .try_into()
        .unwrap()
    }

    fn verified_by(
        uri: &CapabilityUri,
        verifiers: &[&DID],
        retry_cap: Option<RetryCap>,
    ) -> CapabilityRequirement {
        RawCapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
            trusted_verifiers: verifiers.iter().map(|d| (*d).clone()).collect(),
            retry_cap,
        }
        .try_into()
        .unwrap()
    }

    fn list(requirements: Vec<CapabilityRequirement>) -> CapabilityRequirements {
        requirements.try_into().unwrap()
    }

    fn admit(
        fx: &Fixture,
        requirements: &CapabilityRequirements,
        capabilities: &[CapabilityUri],
        records: &[ChallengeVerification],
    ) -> Result<(), AdmissionError> {
        check_capability_requirements(
            requirements,
            capabilities,
            records,
            &AdmissionCheck {
                context_id: CONTEXT,
                subject_did: &fx.subject.did,
                resolver: &fx.resolver,
                definitions: &fx.definitions,
                clock: &fx.clock,
            },
        )
    }

    /// A resolver whose backend is down.
    struct Offline;

    impl ActiveKeyResolver for Offline {
        fn resolve_active_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            Err(TrustError::KeyResolutionUnavailable {
                did: did.to_owned(),
                reason: "offline".to_owned(),
            })
        }
    }

    fn record(fx: &Fixture) -> ChallengeVerification {
        fx.genuine_record(FIXTURE_URI, cases(2)).unwrap()
    }

    #[test]
    fn empty_requirements_always_pass() {
        let fx = fixture();
        admit(&fx, &CapabilityRequirements::default(), &[], &[]).unwrap();
    }

    #[test]
    fn empty_or_noncanonical_subject_is_rejected() {
        let fx = fixture();
        let check = |subject_did| {
            check_capability_requirements(
                &CapabilityRequirements::default(),
                &[],
                &[],
                &AdmissionCheck {
                    context_id: CONTEXT,
                    subject_did,
                    resolver: &fx.resolver,
                    definitions: &fx.definitions,
                    clock: &fx.clock,
                },
            )
        };
        assert_eq!(check(""), Err(AdmissionError::EmptySubjectDid));
        assert!(matches!(
            check(&fx.subject.padding_alias()),
            Err(AdmissionError::NonCanonicalIdentifier { .. })
        ));
    }

    #[test]
    fn self_attested_passes_when_declared_and_fails_when_missing() {
        let fx = fixture();
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = list(vec![self_attested(&uri)]);
        admit(&fx, &reqs, std::slice::from_ref(&uri), &[]).unwrap();
        assert_eq!(
            admit(&fx, &reqs, &[], &[]),
            Err(AdmissionError::MissingCapability {
                uri: uri.to_string()
            })
        );
    }

    #[test]
    fn challenge_verified_passes_with_trusted_record_and_not_on_a_claim() {
        let fx = fixture();
        let uri = fixture_cap();
        let reqs = list(vec![verified_by(&uri, &[&fx.verifier.did], None)]);
        admit(&fx, &reqs, &[], &[record(&fx)]).unwrap();
        assert_eq!(
            admit(&fx, &reqs, std::slice::from_ref(&uri), &[]),
            Err(AdmissionError::VerificationRequired {
                uri: uri.to_string()
            })
        );
    }

    #[test]
    fn challenge_verified_satisfies_self_attested() {
        let fx = fixture();
        let reqs = list(vec![self_attested(&fixture_cap())]);
        admit(&fx, &reqs, &[], &[record(&fx)]).unwrap();
    }

    #[test]
    fn forged_signature_satisfies_nothing() {
        let fx = fixture();
        let mut forged = record(&fx);
        forged.verifier_signature = vec![0u8; 64];
        let verified = list(vec![verified_by(&fixture_cap(), &[&fx.verifier.did], None)]);
        assert!(matches!(
            admit(&fx, &verified, &[], std::slice::from_ref(&forged)),
            Err(AdmissionError::VerificationRequired { .. })
        ));
        let claimed = list(vec![self_attested(&fixture_cap())]);
        assert!(matches!(
            admit(&fx, &claimed, &[], &[forged]),
            Err(AdmissionError::MissingCapability { .. })
        ));
    }

    #[test]
    fn first_unmet_requirement_is_returned() {
        let fx = fixture();
        let a = cap("scp:capability:schema-validation/v1");
        let b = cap("scp:capability:content-safety/v1");
        let reqs = list(vec![self_attested(&a), self_attested(&b)]);
        assert_eq!(
            admit(&fx, &reqs, &[a], &[]),
            Err(AdmissionError::MissingCapability { uri: b.to_string() })
        );
    }

    #[test]
    fn mixed_levels_all_pass() {
        let fx = fixture();
        let a = cap("scp:capability:schema-validation/v1");
        let reqs = list(vec![
            self_attested(&a),
            verified_by(&fixture_cap(), &[&fx.verifier.did], None),
        ]);
        admit(&fx, &reqs, &[a], &[record(&fx)]).unwrap();
    }

    #[test]
    fn expired_failed_other_context_and_other_subject_records_do_not_count() {
        let fx = fixture();
        let reqs = list(vec![verified_by(&fixture_cap(), &[&fx.verifier.did], None)]);
        let genuine = record(&fx);
        let refused = |records: &[ChallengeVerification], fx: &Fixture| {
            assert!(matches!(
                admit(fx, &reqs, &[], records),
                Err(AdmissionError::VerificationRequired { .. })
            ));
        };

        let mut failed = genuine.clone();
        failed.passed = false;
        failed.score = 0;
        failed.pass_count = 0;
        fx.resign(&mut failed).unwrap();
        refused(&[failed], &fx);

        let mut other_context = genuine.clone();
        other_context.context_id = "ctx-other".to_owned();
        fx.resign(&mut other_context).unwrap();
        refused(&[other_context], &fx);

        let mut other_subject = genuine.clone();
        other_subject.subject = fx.other.did.clone();
        fx.resign(&mut other_subject).unwrap();
        refused(&[other_subject], &fx);

        fx.clock.set(genuine.expires_at);
        refused(&[genuine], &fx);
    }

    /// Test 26.
    #[test]
    fn admission_ignores_untrusted_verifier() {
        let fx = fixture();
        let reqs = list(vec![verified_by(&fixture_cap(), &[&fx.other.did], None)]);
        assert_eq!(
            admit(&fx, &reqs, &[], &[record(&fx)]),
            Err(AdmissionError::UntrustedVerifier {
                uri: FIXTURE_URI.to_owned(),
                verifier: fx.verifier.did.to_string(),
            })
        );
        let both = list(vec![verified_by(
            &fixture_cap(),
            &[&fx.other.did, &fx.verifier.did],
            None,
        )]);
        admit(&fx, &both, &[], &[record(&fx)]).unwrap();
    }

    /// A record whose verifier is its subject never counts, even
    /// when governance lists that party as trusted.
    #[test]
    fn admission_rejects_self_signed_even_if_trusted() {
        use crate::trust::challenge::{
            ChallengeSigner, challenge_verification_id, challenge_verification_signing_digest,
        };
        let fx = fixture();
        // Create refuses a self-challenge, so the subject forges one from a
        // genuine record and signs it with its own key.
        let mut v = record(&fx);
        v.verifier = fx.subject.did.clone();
        v.verification_id = challenge_verification_id(
            &v.verifier,
            &v.subject,
            &v.capability_uri,
            &v.challenge_id,
            v.attempt,
            v.timestamp,
        )
        .unwrap();
        v.verifier_signature = fx
            .subject
            .sign(&challenge_verification_signing_digest(&v).unwrap())
            .unwrap();
        let reqs = list(vec![verified_by(
            &fixture_cap(),
            &[&fx.subject.did, &fx.verifier.did],
            None,
        )]);
        assert_eq!(
            admit(&fx, &reqs, &[], &[v]),
            Err(AdmissionError::SelfChallenge {
                uri: FIXTURE_URI.to_owned()
            })
        );
    }

    /// Test 27b.
    #[test]
    fn admission_applies_retry_cap() {
        let fx = fixture();
        let genuine = record(&fx);
        assert_eq!((genuine.max_retries, genuine.cooldown_secs), (2, 3600));
        let capped = |max_retries, min_cooldown_secs| {
            list(vec![verified_by(
                &fixture_cap(),
                &[&fx.verifier.did],
                Some(RetryCap {
                    max_retries,
                    min_cooldown_secs,
                }),
            )])
        };
        admit(&fx, &capped(2, 3600), &[], std::slice::from_ref(&genuine)).unwrap();
        for reqs in [capped(1, 3600), capped(2, 3601)] {
            assert_eq!(
                admit(&fx, &reqs, &[], std::slice::from_ref(&genuine)),
                Err(AdmissionError::RetryCapExceeded {
                    uri: FIXTURE_URI.to_owned()
                })
            );
        }
    }

    #[test]
    fn admission_fails_closed_when_a_record_cannot_be_checked() {
        let fx = fixture();
        let genuine = record(&fx);
        // The verifier's key cannot be obtained.
        let reqs = list(vec![verified_by(&fixture_cap(), &[&fx.verifier.did], None)]);
        let result = check_capability_requirements(
            &reqs,
            &[],
            &[genuine],
            &AdmissionCheck {
                context_id: CONTEXT,
                subject_did: &fx.subject.did,
                resolver: &Offline,
                definitions: &fx.definitions,
                clock: &fx.clock,
            },
        );
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationUnavailable { .. })
        ));
    }

    /// Test 28.
    #[test]
    fn requirement_try_from_rejects_empty_noncanonical_and_out_of_bound() {
        let fx = fixture();
        let raw = |verification_level, trusted_verifiers: Vec<DID>, retry_cap| {
            CapabilityRequirement::try_from(RawCapabilityRequirement {
                capability: fixture_cap(),
                verification_level,
                trusted_verifiers,
                retry_cap,
            })
        };
        let verified = VerificationLevel::ChallengeVerified;
        let invalid = |r: Result<CapabilityRequirement, AdmissionError>| {
            assert!(
                matches!(r, Err(AdmissionError::InvalidRequirement { .. })),
                "{r:?}"
            );
        };
        invalid(raw(verified, Vec::new(), None));
        invalid(raw(
            verified,
            (0..=MAX_TRUSTED_VERIFIERS_PER_REQUIREMENT)
                .map(|i| Party::new(u8::try_from(i + 10).unwrap()).did)
                .collect(),
            None,
        ));
        // The same key twice, once by its did:key test form.
        let same_key = DID::from(format!("did:key:{}", hex::encode(fx.verifier.public())));
        invalid(raw(verified, vec![fx.verifier.did.clone(), same_key], None));
        assert!(matches!(
            raw(
                verified,
                vec![DID::from(fx.verifier.padding_alias().as_str())],
                None
            ),
            Err(AdmissionError::NonCanonicalIdentifier { .. })
        ));
        // A retry cap has no protocol ceiling.
        let cap_ok = RetryCap {
            max_retries: u32::MAX,
            min_cooldown_secs: u32::MAX,
        };
        raw(verified, vec![fx.verifier.did.clone()], Some(cap_ok)).unwrap();
        // SelfAttested names no verifiers and no cap.
        invalid(raw(
            VerificationLevel::SelfAttested,
            vec![fx.verifier.did],
            None,
        ));
        invalid(raw(
            VerificationLevel::SelfAttested,
            Vec::new(),
            Some(cap_ok),
        ));
        // 65 requirements.
        let one = self_attested(&fixture_cap());
        let too_many = vec![one.clone(); MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT + 1];
        assert_eq!(
            CapabilityRequirements::try_from(too_many),
            Err(AdmissionError::TooManyCapabilityRequirements {
                count: MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT + 1,
                max: MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT,
            })
        );
        CapabilityRequirements::try_from(vec![one; MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT])
            .unwrap();
    }

    #[test]
    fn deserialize_runs_validation() {
        let fx = fixture();
        let good = list(vec![verified_by(
            &fixture_cap(),
            &[&fx.verifier.did],
            Some(RetryCap {
                max_retries: 1,
                min_cooldown_secs: 7200,
            }),
        )]);
        let json = serde_json::to_string(&good).unwrap();
        let back: CapabilityRequirements = serde_json::from_str(&json).unwrap();
        assert_eq!(back, good);
        let empty_verifiers = format!(
            r#"[{{"capability":"{FIXTURE_URI}","verification_level":"ChallengeVerified","trusted_verifiers":[]}}]"#
        );
        assert!(serde_json::from_str::<CapabilityRequirements>(&empty_verifiers).is_err());
        let alias = format!(
            r#"[{{"capability":"{FIXTURE_URI}","verification_level":"ChallengeVerified","trusted_verifiers":["{}"]}}]"#,
            fx.verifier.padding_alias()
        );
        assert!(serde_json::from_str::<CapabilityRequirements>(&alias).is_err());
    }

    #[test]
    fn tightening_is_decided_by_delta() {
        let fx = fixture();
        let uri = fixture_cap();
        let retry = |max_retries, min_cooldown_secs| {
            Some(RetryCap {
                max_retries,
                min_cooldown_secs,
            })
        };
        let base = list(vec![verified_by(
            &uri,
            &[&fx.verifier.did, &fx.other.did],
            retry(2, 300),
        )]);
        let tighter = [
            list(vec![verified_by(&uri, &[&fx.verifier.did], retry(2, 300))]),
            list(vec![verified_by(
                &uri,
                &[&fx.verifier.did, &fx.other.did],
                retry(1, 600),
            )]),
            list(vec![
                verified_by(&uri, &[&fx.verifier.did, &fx.other.did], retry(2, 300)),
                self_attested(&cap("scp:capability:content-safety/v1")),
            ]),
        ];
        for new in &tighter {
            assert!(new.is_tightening_of(&base), "{new:?}");
        }
        let looser = [
            CapabilityRequirements::default(),
            list(vec![self_attested(&uri)]),
            list(vec![verified_by(
                &uri,
                &[&fx.verifier.did, &fx.subject.did],
                retry(2, 300),
            )]),
            list(vec![verified_by(&uri, &[&fx.verifier.did], retry(3, 300))]),
            list(vec![verified_by(&uri, &[&fx.verifier.did], retry(2, 299))]),
            list(vec![verified_by(&uri, &[&fx.verifier.did], None)]),
        ];
        for new in &looser {
            assert!(!new.is_tightening_of(&base), "{new:?}");
        }
        // Raising SelfAttested to ChallengeVerified tightens with any set.
        let claimed = list(vec![self_attested(&uri)]);
        assert!(list(vec![verified_by(&uri, &[&fx.subject.did], None)]).is_tightening_of(&claimed));
        // An absent cap accepts any new cap.
        let uncapped = list(vec![verified_by(&uri, &[&fx.verifier.did], None)]);
        assert!(
            list(vec![verified_by(&uri, &[&fx.verifier.did], retry(9, 0))])
                .is_tightening_of(&uncapped)
        );
    }
}
