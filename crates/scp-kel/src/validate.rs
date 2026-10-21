//! §9.7.4.2 R3's check order over a served chain, and the types that only
//! it constructs: [`ValidatedChain`], [`ValidatedChange`] and
//! [`SigningChange`].
//!
//! Every defect in an event past the inception is a discard: the verifier
//! leaves the position open, reads the next unit as a candidate for it, and
//! reports every unit it discards. The one invalid case is an inception that
//! recomputes to the served identifier and fails R2 or an R3 indicator,
//! which [`EntryOutcome::InceptionInvalid`] alone carries.
//!
//! [`validate_entry`] is the one reader of an entry's served units: it
//! assembles them by predecessor digest before any check runs, so no caller
//! can hand the check order an unassembled list and read a fork as a
//! discard.

mod chain;
mod change;
mod check;
mod content;
mod defect;
mod entry;
mod head;
mod verdicts;

use scp_did::Identifier;

pub use chain::ValidatedChain;
pub use change::{ChangeEffect, NamedKey, SignerGroupSpec, ValidatedChange};
pub use defect::{
    CheckStep, ContentDefect, Discarded, DistinctList, EventDefect, FailureClass, InceptionDefect,
    ThresholdField,
};
pub use entry::{EntryOutcome, EntryValidation, ValidChains, validate_entry};
pub use head::{
    HeldHead, HeldHeadMarker, HeldHeadMarkerError, MarkerMode, SigningChange, SigningRefusal,
};

use check::{InceptionFailure, Signing, check_inception, check_successor};
use verdicts::Strict;

/// Why [`validate_inception`] refuses a candidate inception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InceptionRefusal {
    /// The candidate fails R2 or an R3 indicator: an identifier it derived
    /// would name no valid chain.
    Invalid(InceptionDefect),
    /// The candidate fails before its content is read: no separator, or
    /// bytes no unit frames.
    Discarded(Discarded),
}

impl InceptionRefusal {
    /// The step the refusal reports, for `IdentityError::IllegalKeyEvent`
    /// (`03-identity.md` §3.10.10): an inception header defect reports
    /// `Header` and a content defect `Content`, the steps step 3's second
    /// half applies at position zero.
    #[must_use]
    pub const fn stage(&self) -> CheckStep {
        match self {
            Self::Invalid(InceptionDefect::ZeroCheck(_) | InceptionDefect::Header(_)) => {
                CheckStep::Header
            }
            Self::Invalid(InceptionDefect::Content(_)) => CheckStep::Content,
            Self::Discarded(discarded) => discarded.stage(),
        }
    }
}

/// Runs R2 and R3's check order through step 8 on an unsigned candidate
/// inception (§9.7.4.2 R10).
///
/// The candidate is the signed preimage, separator included, checked
/// against the identifier it derives: the code [`validate_entry`] runs at
/// position zero, without the walk, sub-check 7b and step 9. A
/// [`Discarded`] names the candidate as served index zero, read for
/// position zero.
///
/// # Errors
///
/// [`InceptionRefusal`] where the candidate fails.
pub fn validate_inception(candidate_preimage: &[u8]) -> Result<ValidatedChange, InceptionRefusal> {
    check_inception(candidate_preimage, None, Signing::Unsigned, &mut Strict)
        .map(ValidatedChange::from_accepted)
        .map_err(|failure| match failure {
            InceptionFailure::Invalid(defect) => InceptionRefusal::Invalid(defect),
            InceptionFailure::Discard(defect) => {
                InceptionRefusal::Discarded(Discarded::read(0, 0, defect))
            }
        })
}

/// The copies of one event, in served order: units that share an event
/// digest (R9). Never empty.
#[derive(Debug, Clone)]
struct Copies<'u> {
    first: &'u [u8],
    rest: Vec<&'u [u8]>,
}

impl<'u> Copies<'u> {
    const fn one(unit: &'u [u8]) -> Self {
        Self {
            first: unit,
            rest: Vec::new(),
        }
    }
}

/// The first copy that passes every step past `chain`'s head, or the first
/// copy's failure where none passes (R9, merged copies).
fn successor(chain: &ValidatedChain, copies: &Copies<'_>) -> Result<check::Accepted, EventDefect> {
    let failure = match check_successor(chain, copies.first, Signing::Signed, &mut Strict) {
        Ok(accepted) => return Ok(accepted),
        Err(defect) => defect,
    };
    for copy in &copies.rest {
        if let Ok(accepted) = check_successor(chain, copy, Signing::Signed, &mut Strict) {
            return Ok(accepted);
        }
    }
    Err(failure)
}

/// The first copy that passes every step at position zero, or the first
/// copy's failure where none passes. An `Invalid` from any copy is every
/// copy's, because the digest binds the preimage step 3 reads.
fn inception(
    identifier: Identifier,
    copies: &Copies<'_>,
) -> Result<check::Accepted, InceptionFailure> {
    let check = |copy: &[u8]| check_inception(copy, Some(identifier), Signing::Signed, &mut Strict);
    let failure = match check(copies.first) {
        Ok(accepted) => return Ok(accepted),
        Err(failure @ InceptionFailure::Invalid(_)) => return Err(failure),
        Err(failure @ InceptionFailure::Discard(_)) => failure,
    };
    for copy in &copies.rest {
        match check(copy) {
            Ok(accepted) => return Ok(accepted),
            Err(failure @ InceptionFailure::Invalid(_)) => return Err(failure),
            Err(InceptionFailure::Discard(_)) => {}
        }
    }
    Err(failure)
}
