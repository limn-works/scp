//! §9.7.4.2 R3's check order over a served chain, and the types that only
//! it constructs: [`ValidatedChain`], [`ValidatedChange`] and
//! [`SigningChange`].
//!
//! Every defect in an event past the inception is a discard: the verifier
//! leaves the position open, reads the next unit as a candidate for it, and
//! reports every unit it discards. The one invalid case is an inception that
//! recomputes to the served identifier and fails R2 or an R3 indicator,
//! which [`ChainValidation::InceptionInvalid`] alone carries.

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
pub use entry::{EntryValidation, validate_entry};
pub use head::{
    HeldHead, HeldHeadMarker, HeldHeadMarkerError, MarkerMode, SigningChange, SigningRefusal,
};

use check::{InceptionFailure, Signing, check_inception, check_successor};
use verdicts::Strict;

/// What R3's check order makes of one assembled chain path (§9.7.4.2 R3).
///
/// No variant carries a sequence together with an invalid class: only the
/// inception can make an identifier invalid.
///
/// ```compile_fail,E0559
/// # use scp_kel::{ChainValidation, InceptionDefect};
/// fn invalid(defect: InceptionDefect) -> ChainValidation {
///     ChainValidation::InceptionInvalid { defect, at_sequence: 3 }
/// }
/// ```
///
/// The positive control:
///
/// ```
/// # use scp_kel::{ChainValidation, InceptionDefect};
/// fn invalid(defect: InceptionDefect) -> ChainValidation {
///     ChainValidation::InceptionInvalid { defect }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainValidation {
    /// A unit served for position zero recomputes to the served identifier
    /// and fails R2 or an R3 indicator (step 3's second half): the
    /// identifier names no valid chain, R14's `Invalid`.
    InceptionInvalid {
        /// The defect.
        defect: InceptionDefect,
    },
    /// No unit served for position zero passed every step; each is
    /// reported, in served order.
    NoInception {
        /// Every unit discarded, in served order.
        discarded: Vec<Discarded>,
    },
    /// The inception is valid; `chain` holds every unit that passed every
    /// step, in position order.
    Valid {
        /// The valid chain.
        chain: ValidatedChain,
        /// Every unit discarded, in served order.
        discarded: Vec<Discarded>,
    },
}

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

/// Runs R3's check order over one assembled chain path served under
/// `identifier` (§9.7.4.2 R3).
///
/// Each unit is read as a candidate for the first open
/// position, a unit that passes every step fills it, and a unit that fails
/// is discarded and leaves it open (the candidate rule).
///
/// Each unit is one event unit, `BE32(len) ‖ signed preimage ‖ signature
/// field`. The input is one path a reader already assembled by predecessor
/// digest; a reader holding an entry's unassembled units calls
/// [`validate_entry`], so two events at one position become two chains and
/// never a discard.
#[must_use]
pub fn validate_chain(identifier: &Identifier, units: &[&[u8]]) -> ChainValidation {
    let mut builder = Builder::new(*identifier);
    for unit in units {
        if let Err(defect) = builder.offer(&Copies::one(unit)) {
            return ChainValidation::InceptionInvalid { defect };
        }
    }
    builder.finish()
}

/// Runs R2 and R3's check order through step 8 on an unsigned candidate
/// inception (§9.7.4.2 R10).
///
/// The candidate is the signed preimage, separator included, checked
/// against the identifier it derives: the code [`validate_chain`] runs at position zero, without
/// the walk, sub-check 7b and step 9.
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
                InceptionRefusal::Discarded(Discarded::new(0, defect))
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

/// One chain path under construction: the valid chain so far, absent until
/// an inception passes, and every discard in served order.
#[derive(Debug, Clone)]
struct Builder {
    identifier: Identifier,
    chain: Option<ValidatedChain>,
    discarded: Vec<Discarded>,
}

impl Builder {
    const fn new(identifier: Identifier) -> Self {
        Self {
            identifier,
            chain: None,
            discarded: Vec::new(),
        }
    }

    /// Offers one event's copies at the open position: a copy that passes
    /// fills it, and otherwise the first copy's failure is reported and the
    /// position stays open (the candidate rule).
    ///
    /// # Errors
    ///
    /// The inception's defect where the copies, offered at position zero,
    /// recompute to the identifier and fail R2 or R3.
    fn offer(&mut self, copies: &Copies<'_>) -> Result<(), InceptionDefect> {
        match self.chain.as_mut() {
            Some(chain) => match successor(chain, copies) {
                Ok(accepted) => chain.push(&accepted),
                Err(defect) => {
                    let position = chain.next_position();
                    self.discarded.push(Discarded::new(position, defect));
                }
            },
            None => match inception(self.identifier, copies) {
                Ok(accepted) => {
                    self.chain = Some(ValidatedChain::from_inception(self.identifier, &accepted));
                }
                Err(InceptionFailure::Invalid(defect)) => return Err(defect),
                Err(InceptionFailure::Discard(defect)) => {
                    self.discarded.push(Discarded::new(0, defect));
                }
            },
        }
        Ok(())
    }

    fn finish(self) -> ChainValidation {
        match self.chain {
            Some(chain) => ChainValidation::Valid {
                chain,
                discarded: self.discarded,
            },
            None => ChainValidation::NoInception {
                discarded: self.discarded,
            },
        }
    }
}
