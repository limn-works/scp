//! The chain a store that validates key-event frames holds as accepted, and
//! the divergent suffixes it retains beside it (§9.7.4.2 R9).

use super::retention::{
    Admission, Bounds, Rerank, RetainedSuffix, RetentionBasis, RetentionError, RetentionSet,
};
use super::{
    ChainPairing, Decision, ForkRank, NoResolution, ResolveError, Tournament, pair_chains,
};
use crate::validate::ValidatedChain;

/// What holding one more chain did.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub enum HoldOutcome {
    /// The chain is, or is a prefix of, a chain already held, compared by
    /// digest: nothing changed.
    AlreadyHeld,
    /// The chain is the accepted chain: the first chain held, or an
    /// extension of the chain accepted before it.
    AcceptedExtended {
        /// What re-ranking the retained suffixes against the extension did.
        rerank: Rerank,
    },
    /// Another chain is accepted now, and the chain accepted before it is
    /// re-admitted as a divergent suffix.
    AcceptedReplaced {
        /// The head of the chain accepted before.
        displaced: [u8; 32],
        /// What admitting the arriving chain did, or `None` where it
        /// extended the chain accepted before.
        admission: Option<Admission>,
        /// What re-ranking every retained chain against the new accepted
        /// chain did, the displaced chain included.
        rerank: Rerank,
    },
    /// The accepted chain is unchanged, and the chain is retained as a
    /// divergent suffix of it.
    HeldDivergent {
        /// [`Admission::Retained`] or [`Admission::Extended`].
        admission: Admission,
    },
    /// The retention bounds refused the chain: nothing changed, it takes no
    /// part in deciding the accepted chain, and the caller counts it in its
    /// residue.
    Refused {
        /// The chain's eviction rank.
        rank: ForkRank,
    },
}

/// Why [`AcceptedChainHolder::hold`] held nothing. The holder is then
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HoldError {
    /// The chain is of another identifier, or the comparisons reached none
    /// of R6's outcomes.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// Admitting or re-ranking a chain reached a [`RetentionError`].
    #[error(transparent)]
    Retention(#[from] RetentionError),
}

/// The chains of one identifier a store that validates key-event frames
/// holds: the accepted chain, and the divergent suffixes a [`RetentionSet`]
/// retains against it under R9's bounds (§9.7.4.2 R9).
///
/// R9: "At a validating relay the accepted chain follows R6's rank: after
/// every frame it accepts, the relay holds as accepted the chain that wins
/// every pairwise R6 comparison against every other chain it holds at that
/// routing id, and the displaced chain's events past the shared prefix
/// become a divergent suffix carrying the rank R6 gave it, which is 2 or 3.
/// Where no chain wins every pairwise comparison, the relay keeps as
/// accepted the chain it held first". The rule applies to any store that
/// validates key-event frames.
///
/// Every chain other than the accepted one goes through
/// [`RetentionSet::admit`], so the chains held are the accepted chain and
/// the retained suffixes, and nothing else: a chain the bounds refuse or
/// evict takes no part in deciding the accepted chain. One moment counter,
/// the set's, orders every chain: a chain extending a held one keeps its
/// moment, and "held first" is the earliest moment among the chains no
/// other chain beats. R9: "a suffix a party evicted and a party presents
/// again later is re-ranked as if the party saw it for the first time", so
/// it takes a new moment.
///
/// S5 (SCP-007 part) is the caller that wires this holder into a validating
/// store.
#[derive(Debug, Clone)]
pub struct AcceptedChainHolder {
    /// The accepted chain as the set's basis, and the retained suffixes;
    /// `None` before the first chain is held.
    set: Option<RetentionSet>,
    bounds: Bounds,
}

impl Default for AcceptedChainHolder {
    fn default() -> Self {
        Self::new()
    }
}

impl AcceptedChainHolder {
    /// A holder that holds no chain, under the registered bounds.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_bounds(Bounds::REGISTERED)
    }

    pub(super) const fn with_bounds(bounds: Bounds) -> Self {
        Self { set: None, bounds }
    }

    /// The accepted chain, or `None` before the first chain is held.
    #[must_use]
    pub fn accepted(&self) -> Option<&ValidatedChain> {
        self.set.as_ref().map(|set| set.basis().chain())
    }

    /// The accepted chain and the retained suffixes, or `None` before the
    /// first chain is held.
    #[must_use]
    pub const fn retention(&self) -> Option<&RetentionSet> {
        self.set.as_ref()
    }

    /// Every held chain, the accepted chain included, in the order of the
    /// moment the holder first held each.
    pub fn held(&self) -> impl Iterator<Item = &ValidatedChain> {
        let mut held: Vec<(u64, &ValidatedChain)> = self
            .set
            .iter()
            .flat_map(|set| {
                std::iter::once((set.basis_observed(), set.basis().chain())).chain(
                    set.suffixes()
                        .iter()
                        .map(|suffix| (suffix.observed(), suffix.chain())),
                )
            })
            .collect();
        held.sort_by_key(|(observed, _)| *observed);
        held.into_iter().map(|(_, chain)| chain)
    }

    /// Holds `chain` and re-decides the accepted chain under R9.
    ///
    /// A chain extending the accepted chain becomes the accepted chain and
    /// re-ranks the retained suffixes against it. Any other chain goes
    /// through [`RetentionSet::admit`]; a refusal returns
    /// [`HoldOutcome::Refused`] and changes nothing. The holder then runs R6
    /// over the accepted chain and the retained suffixes, and where another
    /// chain wins, or ties and was held first, moves acceptance to it
    /// through [`RetentionSet::rerank`], which re-admits the chain accepted
    /// before.
    ///
    /// S5 (SCP-007 part) is the caller that wires this into a validating
    /// store, which calls it after every frame it accepts.
    ///
    /// # Errors
    ///
    /// [`HoldError::Resolve`] where `chain` is of another identifier or the
    /// comparisons reach none of R6's outcomes, which valid chains of one
    /// identifier never do, and [`HoldError::Retention`] where admitting or
    /// re-ranking does. On any error the holder is unchanged.
    pub fn hold(&mut self, chain: ValidatedChain) -> Result<HoldOutcome, HoldError> {
        let Some(set) = &self.set else {
            self.set = Some(RetentionSet::with_bounds(
                RetentionBasis::Accepted(chain),
                self.bounds,
            ));
            return Ok(HoldOutcome::AcceptedExtended {
                rerank: Rerank::default(),
            });
        };
        let mut next = set.clone();
        let accepted = next.basis().chain();
        let (admission, mut rerank) =
            match pair_chains(&chain, accepted).map_err(ResolveError::from)? {
                ChainPairing::Identical | ChainPairing::LeftPrefixOfRight => {
                    return Ok(HoldOutcome::AlreadyHeld);
                }
                ChainPairing::RightPrefixOfLeft => {
                    let extended = RetentionBasis::Accepted(accepted.extended_by(chain));
                    (None, next.rerank(extended)?)
                }
                ChainPairing::Diverged(_) => match next.admit(chain)? {
                    Admission::AlreadyHeld => return Ok(HoldOutcome::AlreadyHeld),
                    Admission::Refused { rank } => return Ok(HoldOutcome::Refused { rank }),
                    admission => (Some(admission), Rerank::default()),
                },
            };
        let displaced = next.basis().chain().head_digest();
        let outcome = match (winner(&next)?, admission) {
            (None, None) => HoldOutcome::AcceptedExtended { rerank },
            (None, Some(admission)) => HoldOutcome::HeldDivergent { admission },
            (Some(index), admission) => {
                let chain = next
                    .suffixes()
                    .get(index)
                    .ok_or(NoResolution)
                    .map_err(ResolveError::from)?
                    .chain()
                    .clone();
                rerank.absorb(next.rerank(RetentionBasis::Accepted(chain))?);
                HoldOutcome::AcceptedReplaced {
                    displaced,
                    admission,
                    rerank,
                }
            }
        };
        self.set = Some(next);
        Ok(outcome)
    }
}

/// R6 and R9's held-first rule over `set`'s basis and retained suffixes:
/// `None` where the basis stays accepted, else the index of the suffix that
/// becomes accepted.
fn winner(set: &RetentionSet) -> Result<Option<usize>, ResolveError> {
    let chains: Vec<&ValidatedChain> = std::iter::once(set.basis().chain())
        .chain(set.suffixes().iter().map(RetainedSuffix::chain))
        .collect();
    let moments: Vec<u64> = std::iter::once(set.basis_observed())
        .chain(set.suffixes().iter().map(RetainedSuffix::observed))
        .collect();
    let index = match Tournament::of(&chains)?.decide()? {
        Decision::Winner(winner) => winner,
        Decision::Tie { undefeated, .. } => undefeated
            .into_iter()
            .min_by_key(|&index| moments.get(index).copied().unwrap_or(u64::MAX))
            .ok_or(NoResolution)?,
    };
    Ok(index.checked_sub(1))
}
