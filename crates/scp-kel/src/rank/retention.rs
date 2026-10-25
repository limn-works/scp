//! The divergent suffixes a party retains per identifier, under R9's count
//! and byte bounds and its eviction rule (`09-security-model.md` §9.7.4.2
//! R9).
//!
//! R9: "An event is identified by its preimage digest, and every comparison
//! reads that digest and never the bytes, so a party holding a valid event
//! that receives a byte-different valid event with the same digest keeps
//! the copy it holds. A chain and a divergent suffix are identified by the
//! digests of their events."
//!
//! The set keeps no residue of its own: a refusal is returned to the caller,
//! which counts the refusals of one resolution (R9: "the party counts that
//! candidate in its residue n").

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use scp_did::Identifier;

use super::{ChainPairing, ForkRank, UnrelatedChains, pair_chains, rank_past};
use crate::constants::{MAX_RETAINED_BYTES, MAX_RETAINED_SUFFIXES};
use crate::validate::ValidatedChain;
use crate::{Discarded, EntryVerdict, InceptionDefect, validate_entry};

/// The chain the eviction rank and both retention bounds read.
///
/// R9: "The accepted chain is not one of the divergent suffixes a party
/// retains, and it carries no eviction rank." "Where a first-contact
/// resolution returns `Contested`, which adopts nothing, the shared prefix
/// that `Contested` names, which R7 makes the verification basis, is the
/// chain the eviction rank and both retention bounds read. That prefix is no
/// accepted baseline".
///
/// The two differ in one case: a chain that extends the basis. Extending the
/// accepted chain makes it "that chain or suffix, extended", which the caller
/// adopts and never retains; extending the shared prefix makes it a
/// divergent suffix past that prefix, which is what each tied head is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionBasis {
    /// The accepted chain.
    Accepted(ValidatedChain),
    /// The shared prefix a first-contact `Contested` names.
    ContestedPrefix(ValidatedChain),
}

impl RetentionBasis {
    /// The basis chain.
    #[must_use]
    pub const fn chain(&self) -> &ValidatedChain {
        match self {
            Self::Accepted(chain) | Self::ContestedPrefix(chain) => chain,
        }
    }

    /// Which basis this is.
    #[must_use]
    pub const fn kind(&self) -> BasisKind {
        match self {
            Self::Accepted(_) => BasisKind::Accepted,
            Self::ContestedPrefix(_) => BasisKind::ContestedPrefix,
        }
    }
}

/// Which chain a [`RetentionBasis`] is, as persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BasisKind {
    /// The accepted chain.
    Accepted,
    /// The shared prefix a first-contact `Contested` names.
    ContestedPrefix,
}

/// One retained divergent suffix: the evidence chain from the inception to
/// the suffix's head, and what R9 reads of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedSuffix {
    chain: ValidatedChain,
    fork_position: u64,
    slot: Slot,
}

impl RetainedSuffix {
    /// The chain from the inception to the suffix's head.
    #[must_use]
    pub const fn chain(&self) -> &ValidatedChain {
        &self.chain
    }

    /// The suffix's head digest, which identifies it with the digests
    /// before it.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.chain.head_digest()
    }

    /// The position of the suffix's first event past the basis.
    #[must_use]
    pub const fn fork_position(&self) -> u64 {
        self.fork_position
    }

    /// The suffix's eviction rank.
    #[must_use]
    pub const fn rank(&self) -> ForkRank {
        self.slot.rank
    }

    /// The moment the party first held or observed the suffix: a counter the
    /// set keeps, never wall-clock time.
    #[must_use]
    pub const fn observed(&self) -> u64 {
        self.slot.observed
    }
}

/// What [`RetentionSet::admit`] did with a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub enum Admission {
    /// The candidate is retained as a new divergent suffix.
    Retained {
        /// The candidate's eviction rank.
        rank: ForkRank,
        /// The head of every suffix evicted to fit it, in the order of the
        /// moment the set first held each.
        evicted: Vec<[u8; 32]>,
    },
    /// The candidate extends a retained suffix and replaced it.
    Extended {
        /// The candidate's eviction rank.
        rank: ForkRank,
        /// The head of the suffix it replaced.
        replaced: [u8; 32],
        /// The head of every other suffix evicted to fit it, in the order of
        /// the moment the set first held each.
        evicted: Vec<[u8; 32]>,
    },
    /// The party holds every event of the candidate: nothing changed.
    AlreadyHeld,
    /// No suffix the party may evict makes room: nothing changed, and the
    /// caller counts the candidate in its residue.
    Refused {
        /// The candidate's eviction rank.
        rank: ForkRank,
    },
}

/// Why [`RetentionSet::admit`] or [`RetentionSet::rerank`] placed nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RetentionError {
    /// The candidate is of another identifier than the basis.
    #[error(transparent)]
    Unrelated(#[from] UnrelatedChains),
    /// The candidate extends the accepted chain, so it is the accepted chain
    /// extended, which the caller adopts and never retains (R9).
    #[error("the chain extends the accepted chain at {head:02x?}, which is adopted, not retained")]
    ExtendsAccepted {
        /// The accepted chain's head digest.
        head: [u8; 32],
    },
    /// The moment counter has no next moment, so a new chain would share a
    /// moment with a held one and the eviction tie-break could not read it.
    #[error("the retention set's moment counter is exhausted")]
    ObservedExhausted,
    /// A contested prefix was offered as the basis of a set whose basis is
    /// the accepted chain. R9 makes a contested prefix the basis only
    /// "Where a first-contact resolution returns `Contested`", where the
    /// party holds no accepted chain, so the move would drop the accepted
    /// baseline into the set as a ranked suffix.
    #[error("a contested prefix cannot replace the accepted chain at {accepted:02x?}")]
    ContestedAfterAccepted {
        /// The accepted chain's head digest.
        accepted: [u8; 32],
    },
}

/// What [`RetentionSet::rerank`] did with each chain it re-admitted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct Rerank {
    /// The heads every event of which the new basis or an earlier
    /// re-admitted suffix holds.
    pub already_held: Vec<[u8; 32]>,
    /// The heads evicted to fit a later re-admission.
    pub evicted: Vec<[u8; 32]>,
    /// The heads refused, which the caller counts in its residue.
    pub refused: Vec<[u8; 32]>,
}

impl Rerank {
    /// Appends `later`'s report to this one.
    pub(super) fn absorb(&mut self, later: Self) {
        self.already_held.extend(later.already_held);
        self.evicted.extend(later.evicted);
        self.refused.extend(later.refused);
    }
}

/// A [`RetentionSet`] as its owner persists it: raw units it re-validates
/// on [`RetentionSet::restore`], and the heads and moments that name what it
/// retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedRetention {
    /// The basis.
    pub basis: PersistedBasis,
    /// Every unit of the basis and of every retained suffix's chain from
    /// its inception, one per digest, the held copy, in chain order.
    pub units: Vec<Arc<[u8]>>,
    /// Every retained suffix.
    pub suffixes: Vec<PersistedSuffix>,
}

/// The basis of a persisted [`RetentionSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PersistedBasis {
    /// Which chain the basis is.
    pub kind: BasisKind,
    /// The basis head digest.
    pub head: [u8; 32],
    /// The moment the party first held the basis.
    pub observed: u64,
}

/// One persisted retained suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PersistedSuffix {
    /// The suffix's head digest.
    pub head: [u8; 32],
    /// The moment the party first held or observed it.
    pub observed: u64,
}

/// Why [`RetentionSet::restore`] rebuilt nothing. Every arm fails closed:
/// no partial set is returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreError {
    /// A persisted unit failed R3's check order or placed on no chain.
    #[error("{} persisted units were discarded", .0.len())]
    Discarded(Vec<Discarded>),
    /// The persisted inception is invalid.
    #[error("the persisted inception is invalid: {0}")]
    InceptionInvalid(InceptionDefect),
    /// Units were persisted and none is a valid inception.
    #[error("no persisted unit is a valid inception")]
    NoInception,
    /// No rebuilt chain holds a persisted head.
    #[error("no persisted chain holds the head {head:02x?}")]
    MissingHead {
        /// The head no chain holds.
        head: [u8; 32],
    },
    /// Two persisted entries carry one `observed` moment.
    #[error("two persisted entries carry the moment {observed}")]
    DuplicateObserved {
        /// The repeated moment.
        observed: u64,
    },
    /// The persisted moments leave no next moment.
    #[error("the persisted moments leave no next moment")]
    ObservedExhausted,
    /// A persisted suffix is not admissible as a new suffix within the
    /// bounds, so the persisted set is not one `admit` built.
    #[error("the persisted suffix {head:02x?} re-admits as {admission:?}")]
    Inadmissible {
        /// The suffix's head.
        head: [u8; 32],
        /// What re-admitting it did.
        admission: Admission,
    },
    /// A persisted unit is on no retained chain.
    #[error("{persisted} units persisted and {referenced} referenced")]
    UnreferencedUnits {
        /// The count of units persisted.
        persisted: usize,
        /// The count the rebuilt set references.
        referenced: usize,
    },
    /// Re-admitting a persisted suffix reached a [`RetentionError`].
    #[error(transparent)]
    Retention(#[from] RetentionError),
}

/// The divergent suffixes a party retains for one identifier, against one
/// [`RetentionBasis`].
///
/// R9: "A verifier retains per identifier at most `MAX_RETAINED_SUFFIXES`
/// divergent suffixes and at most `MAX_RETAINED_BYTES` of divergent-suffix
/// bytes. Each bound reads the eviction rank below, and neither refuses a
/// suffix on arrival without reading that rank. Both count divergent
/// suffixes and count no byte of the accepted chain."
///
/// No retained suffix is a prefix of another or of the basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionSet {
    basis: RetentionBasis,
    basis_observed: u64,
    suffixes: Vec<RetainedSuffix>,
    next_observed: u64,
    bounds: Bounds,
}

impl RetentionSet {
    /// A set retaining nothing against `basis`, which the party holds from
    /// moment zero: R9's accepted chain "is the chain the verifier held
    /// before it observed any divergence".
    #[must_use]
    pub const fn new(basis: RetentionBasis) -> Self {
        Self::with_bounds(basis, Bounds::REGISTERED)
    }

    pub(super) const fn with_bounds(basis: RetentionBasis, bounds: Bounds) -> Self {
        Self {
            basis,
            basis_observed: 0,
            suffixes: Vec::new(),
            next_observed: 1,
            bounds,
        }
    }

    /// The basis.
    #[must_use]
    pub const fn basis(&self) -> &RetentionBasis {
        &self.basis
    }

    /// The moment the party first held the basis, on the counter every
    /// suffix's [`observed`](RetainedSuffix::observed) moment reads.
    #[must_use]
    pub const fn basis_observed(&self) -> u64 {
        self.basis_observed
    }

    /// Every retained suffix.
    #[must_use]
    pub fn suffixes(&self) -> &[RetainedSuffix] {
        &self.suffixes
    }

    /// The divergent-suffix bytes the byte bound counts, rank-1 bytes
    /// included, each retained event once (R9: "The byte bound counts each
    /// retained event once").
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        union_bytes(self.suffixes.iter().map(|suffix| &suffix.slot))
    }

    /// Admits `candidate`, a valid chain of the basis's identifier, under
    /// R9's identity, retention bound and eviction rule. The holder of the
    /// accepted chain admits here every chain it holds other than the
    /// accepted one; S5 (SCP-007 part) is the caller that wires that holder
    /// into a validating store.
    ///
    /// Identity, R9: "An arrival every event of which the party already
    /// holds changes nothing." A candidate the basis or a retained suffix
    /// leads, compared by digest, is [`Admission::AlreadyHeld`].
    ///
    /// Extension, R9: "An arrival whose events extend a chain or suffix the
    /// party holds is that chain or suffix, extended. It replaces what the
    /// party holds, its bytes count once at the extended length, and it
    /// keeps the moment the party first held or observed it." "An extension
    /// the retention bound refuses leaves the held suffix in place and
    /// counts in the residue."
    ///
    /// Copy, R9: "a party holding a valid event that receives a
    /// byte-different valid event with the same digest keeps the copy it
    /// holds": the retained chain carries the held copy of every event it
    /// shares with the basis or a retained suffix.
    ///
    /// Eviction rank, R9: "It is a scalar: the R6 rank the suffix carries
    /// against the accepted chain, read against the commitment standing at
    /// that suffix's own fork position."
    ///
    /// Bounds and eviction: R9's eviction rule, quoted on the planner this
    /// calls. The set changes only where the candidate is placed; a refusal
    /// evicts nothing.
    ///
    /// # Errors
    ///
    /// [`RetentionError::Unrelated`] for a candidate of another identifier,
    /// and [`RetentionError::ExtendsAccepted`] for an extension of an
    /// accepted basis. Either leaves the set unchanged.
    pub fn admit(&mut self, candidate: ValidatedChain) -> Result<Admission, RetentionError> {
        self.place(candidate, None)
    }

    /// Places `candidate` at `observed`, or at the next moment where it is
    /// new and `observed` is `None`.
    fn place(
        &mut self,
        candidate: ValidatedChain,
        observed: Option<u64>,
    ) -> Result<Admission, RetentionError> {
        let basis = self.basis.chain();
        let (rank, fork_position) = match pair_chains(&candidate, basis)? {
            ChainPairing::Identical | ChainPairing::LeftPrefixOfRight => {
                return Ok(Admission::AlreadyHeld);
            }
            ChainPairing::Diverged(divergence) => (divergence.ranks[0], divergence.fork_position),
            ChainPairing::RightPrefixOfLeft => match &self.basis {
                RetentionBasis::Accepted(accepted) => {
                    return Err(RetentionError::ExtendsAccepted {
                        head: accepted.head_digest(),
                    });
                }
                RetentionBasis::ContestedPrefix(prefix) => (
                    rank_past(&candidate, prefix.len()),
                    prefix.head_sequence().saturating_add(1),
                ),
            },
        };
        let mut extends = None;
        for (index, held) in self.suffixes.iter().enumerate() {
            match pair_chains(&candidate, &held.chain)? {
                ChainPairing::Identical | ChainPairing::LeftPrefixOfRight => {
                    return Ok(Admission::AlreadyHeld);
                }
                ChainPairing::RightPrefixOfLeft => extends = Some(index),
                ChainPairing::Diverged(_) => {}
            }
        }
        let candidate = self.held_copies(candidate);
        let fresh = extends.is_none() && observed.is_none();
        let slot = Slot {
            rank,
            observed: extends
                .and_then(|index| self.suffixes.get(index))
                .map(RetainedSuffix::observed)
                .or(observed)
                .unwrap_or(self.next_observed),
            events: candidate.unit_lens_from(fork_position).collect(),
        };
        let next_observed = if fresh {
            self.next_observed
                .checked_add(1)
                .ok_or(RetentionError::ObservedExhausted)?
        } else {
            self.next_observed
        };
        let held: Vec<&Slot> = self.suffixes.iter().map(|suffix| &suffix.slot).collect();
        let Some(evict) = plan_evictions(&held, extends, &slot, self.bounds) else {
            return Ok(Admission::Refused { rank });
        };
        let retained = RetainedSuffix {
            chain: candidate,
            fork_position,
            slot,
        };
        let mut evicted = Vec::with_capacity(evict.len());
        let mut replaced = None;
        let mut kept = Vec::with_capacity(self.suffixes.len().saturating_add(1));
        for (index, suffix) in std::mem::take(&mut self.suffixes).into_iter().enumerate() {
            if evict.contains(&index) {
                evicted.push(suffix.head());
            } else if extends == Some(index) {
                replaced = Some(suffix.head());
            } else {
                kept.push(suffix);
            }
        }
        kept.push(retained);
        self.suffixes = kept;
        self.next_observed = next_observed;
        Ok(match replaced {
            Some(replaced) => Admission::Extended {
                rank,
                replaced,
                evicted,
            },
            None => Admission::Retained { rank, evicted },
        })
    }

    /// `candidate` with the held copy of every leading event it shares with
    /// the basis or a retained suffix: the chain sharing the most events
    /// with it, which carries the held copies of the events it shares with
    /// the basis, because it took them when it was placed.
    fn held_copies(&self, candidate: ValidatedChain) -> ValidatedChain {
        let mut source = self.basis.chain();
        let mut shared = source.shared_prefix_len(&candidate);
        for suffix in &self.suffixes {
            let len = suffix.chain.shared_prefix_len(&candidate);
            if len > shared {
                source = &suffix.chain;
                shared = len;
            }
        }
        source.extended_by(candidate)
    }

    /// Moves the set to `basis` after an adoption changes it, re-admitting
    /// every retained suffix and the old basis, in ascending order of the
    /// moment the party first held each, through [`admit`](Self::admit)'s
    /// one rule; each keeps its moment.
    ///
    /// R9: "a suffix a party evicted and a party presents again later is
    /// re-ranked as if the party saw it for the first time"; a suffix the
    /// party kept keeps the moment it first observed it. The eviction rank
    /// reads the basis, so moving the basis re-reads every rank and every
    /// fork-relative byte tally. A chain on the new basis leaves the set,
    /// and the new basis takes the earliest moment among them, or the next
    /// moment where it is new.
    ///
    /// # Errors
    ///
    /// [`RetentionError::ContestedAfterAccepted`] where `basis` is a
    /// contested prefix and the set's basis is the accepted chain, and
    /// otherwise the first [`RetentionError`] a re-admission reaches. The set
    /// is then unchanged.
    pub fn rerank(&mut self, basis: RetentionBasis) -> Result<Rerank, RetentionError> {
        if let (RetentionBasis::Accepted(accepted), RetentionBasis::ContestedPrefix(_)) =
            (&self.basis, &basis)
        {
            return Err(RetentionError::ContestedAfterAccepted {
                accepted: accepted.head_digest(),
            });
        }
        let mut entries: Vec<(u64, ValidatedChain)> = self
            .suffixes
            .iter()
            .map(|suffix| (suffix.slot.observed, suffix.chain.clone()))
            .chain(std::iter::once((
                self.basis_observed,
                self.basis.chain().clone(),
            )))
            .collect();
        entries.sort_by_key(|(observed, _)| *observed);
        let mut on_basis = None;
        for (observed, chain) in &entries {
            if matches!(
                pair_chains(chain, basis.chain())?,
                ChainPairing::Identical | ChainPairing::LeftPrefixOfRight
            ) {
                on_basis =
                    Some(on_basis.map_or(*observed, |earliest: u64| earliest.min(*observed)));
            }
        }
        let (basis_observed, next_observed) = match on_basis {
            Some(earliest) => (earliest, self.next_observed),
            None => (
                self.next_observed,
                self.next_observed
                    .checked_add(1)
                    .ok_or(RetentionError::ObservedExhausted)?,
            ),
        };
        let mut moved = Self {
            basis,
            basis_observed,
            suffixes: Vec::new(),
            next_observed,
            bounds: self.bounds,
        };
        let mut report = Rerank::default();
        for (observed, chain) in entries {
            let head = chain.head_digest();
            match moved.place(chain, Some(observed))? {
                Admission::AlreadyHeld => report.already_held.push(head),
                Admission::Retained { evicted, .. } | Admission::Extended { evicted, .. } => {
                    report.evicted.extend(evicted);
                }
                Admission::Refused { .. } => report.refused.push(head),
            }
        }
        *self = moved;
        Ok(report)
    }

    /// The set as its owner persists it.
    ///
    /// R9's eviction tie-break reads "the suffix it observed most recently",
    /// so every moment is persisted; R9 keeps "the copy it holds", so every
    /// unit is the held copy. The basis is persisted with the suffixes, so
    /// its kind alone says which chain it is.
    #[must_use]
    pub fn persisted(&self) -> PersistedRetention {
        let mut seen = BTreeSet::new();
        let mut units = Vec::new();
        let mut ordered: Vec<&RetainedSuffix> = self.suffixes.iter().collect();
        ordered.sort_by_key(|suffix| suffix.slot.observed);
        for chain in
            std::iter::once(self.basis.chain()).chain(ordered.iter().map(|suffix| &suffix.chain))
        {
            for (digest, unit) in chain.units() {
                if seen.insert(digest) {
                    units.push(unit);
                }
            }
        }
        PersistedRetention {
            basis: PersistedBasis {
                kind: self.basis.kind(),
                head: self.basis.chain().head_digest(),
                observed: self.basis_observed,
            },
            units,
            suffixes: ordered
                .iter()
                .map(|suffix| PersistedSuffix {
                    head: suffix.head(),
                    observed: suffix.slot.observed,
                })
                .collect(),
        }
    }

    /// Rebuilds a persisted set: one [`validate_entry`] over its units, and
    /// the basis and each suffix the prefix through its head of the chain
    /// holding that head. Every suffix is then
    /// re-admitted in ascending moment order through [`admit`](Self::admit)'s
    /// one rule, so a persisted set that rule would not have built is
    /// refused. The moment counter restarts past the largest persisted
    /// moment.
    ///
    /// # Errors
    ///
    /// Each [`RestoreError`] arm; none returns a partial set.
    pub fn restore(
        identifier: &Identifier,
        saved: &PersistedRetention,
    ) -> Result<Self, RestoreError> {
        let chains = rebuild(identifier, &saved.units)?;
        let find = |head: [u8; 32]| {
            chains
                .iter()
                .find_map(|chain| {
                    let sequence = chain.events().find(|event| event.digest == head)?.sequence;
                    chain.prefix(sequence)
                })
                .ok_or(RestoreError::MissingHead { head })
        };
        let chain = find(saved.basis.head)?;
        let basis = match saved.basis.kind {
            BasisKind::Accepted => RetentionBasis::Accepted(chain),
            BasisKind::ContestedPrefix => RetentionBasis::ContestedPrefix(chain),
        };
        let mut moments = BTreeSet::from([saved.basis.observed]);
        for suffix in &saved.suffixes {
            if !moments.insert(suffix.observed) {
                return Err(RestoreError::DuplicateObserved {
                    observed: suffix.observed,
                });
            }
        }
        let next_observed = moments
            .last()
            .and_then(|last| last.checked_add(1))
            .ok_or(RestoreError::ObservedExhausted)?;
        let mut set = Self {
            basis,
            basis_observed: saved.basis.observed,
            suffixes: Vec::new(),
            next_observed,
            bounds: Bounds::REGISTERED,
        };
        let mut ordered: Vec<&PersistedSuffix> = saved.suffixes.iter().collect();
        ordered.sort_by_key(|suffix| suffix.observed);
        for suffix in ordered {
            match set.place(find(suffix.head)?, Some(suffix.observed))? {
                Admission::Retained { evicted, .. } if evicted.is_empty() => {}
                admission => {
                    return Err(RestoreError::Inadmissible {
                        head: suffix.head,
                        admission,
                    });
                }
            }
        }
        let referenced = set.persisted().units.len();
        if referenced != saved.units.len() {
            return Err(RestoreError::UnreferencedUnits {
                persisted: saved.units.len(),
                referenced,
            });
        }
        Ok(set)
    }
}

/// Every valid chain `units` hold, failing closed on any discard.
fn rebuild(
    identifier: &Identifier,
    units: &[Arc<[u8]>],
) -> Result<Vec<ValidatedChain>, RestoreError> {
    if units.is_empty() {
        return Ok(Vec::new());
    }
    let refs: Vec<&[u8]> = units.iter().map(|unit| &**unit).collect();
    let validation = validate_entry(identifier, &refs);
    // The verdict first: without a valid inception every other unit is
    // discarded too, and the inception's own failure is the cause.
    let chains: Vec<ValidatedChain> = match validation.verdict {
        EntryVerdict::Valid { chains } => chains.iter().cloned().collect(),
        EntryVerdict::InceptionInvalid { defect } => {
            return Err(RestoreError::InceptionInvalid(defect));
        }
        EntryVerdict::NoInception => return Err(RestoreError::NoInception),
    };
    if !validation.discarded.is_empty() {
        return Err(RestoreError::Discarded(validation.discarded));
    }
    Ok(chains)
}

/// R9's two bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Bounds {
    /// The count bound, `MAX_RETAINED_SUFFIXES`.
    pub(super) suffixes: u32,
    /// The byte bound, `MAX_RETAINED_BYTES`.
    pub(super) bytes: u64,
}

impl Bounds {
    /// The registered values (§9.18.17).
    pub(super) const REGISTERED: Self = Self {
        suffixes: MAX_RETAINED_SUFFIXES,
        bytes: MAX_RETAINED_BYTES as u64,
    };
}

/// What the eviction rule and the bounds read of one suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Slot {
    pub(super) rank: ForkRank,
    pub(super) observed: u64,
    /// Each event past the suffix's fork from the basis: its preimage
    /// digest and the length of the held unit that carried it.
    pub(super) events: Vec<([u8; 32], u64)>,
}

/// The bytes of the union of `slots`' events, each digest once (R9: "The
/// byte bound counts each retained event once").
fn union_bytes<'s>(slots: impl IntoIterator<Item = &'s Slot>) -> u64 {
    let mut lens = BTreeMap::new();
    for slot in slots {
        lens.extend(slot.events.iter().copied());
    }
    lens.values()
        .fold(0, |sum: u64, len| sum.saturating_add(*len))
}

/// The indices of `held` to evict so `candidate` fits both bounds, in
/// eviction order, or `None` where the candidate is refused. `replacing` is
/// the index of the held suffix the candidate extends, which leaves only
/// where the candidate is placed and is never evicted for it.
///
/// R9, the eviction rule: "A candidate that would exceed the count bound or
/// the byte bound is admitted wherever the verifier already retains a
/// suffix it may evict whose rank number is at least the candidate's, and
/// the verifier evicts the retained suffix carrying the highest rank
/// number, breaking a tie among equal ranks by evicting the suffix it
/// observed most recently … A rank-1 suffix is never evicted. A candidate
/// the party can evict no suffix for is refused".
///
/// R9, the byte bound: "Rank-1 bytes count toward `MAX_RETAINED_BYTES`, and
/// the byte bound never evicts a rank-1 suffix: a rank-1 candidate that
/// would exceed the byte bound evicts rank-2 and rank-3 suffixes until it
/// fits, and the verifier refuses it … only where the rank-1 bytes alone,
/// the candidate's included, would exceed `MAX_RETAINED_BYTES`." The loop
/// evicts one suffix at a time until both bounds hold, so a rank-1
/// candidate runs out of evictable suffixes exactly where the rank-1 bytes
/// alone exceed the bound.
///
/// R9, the rank-1 flood: "Where the rank-1 suffixes a party retains fill
/// either bound and another rank-1 candidate arrives, the verifier keeps
/// the suffixes it holds".
///
/// R9, counting: "The byte bound counts each retained event once", so the
/// tally is the union of the kept suffixes' events and the candidate's, and
/// an eviction frees only the events no kept suffix or the candidate also
/// holds.
pub(super) fn plan_evictions(
    held: &[&Slot],
    replacing: Option<usize>,
    candidate: &Slot,
    bounds: Bounds,
) -> Option<Vec<usize>> {
    let mut kept: Vec<bool> = (0..held.len())
        .map(|index| Some(index) != replacing)
        .collect();
    let mut evicted = Vec::new();
    loop {
        let kept_slots = || {
            held.iter()
                .zip(&kept)
                .filter(|(_, kept)| **kept)
                .map(|(slot, _)| *slot)
        };
        let count = kept_slots().count().saturating_add(1);
        let bytes = union_bytes(kept_slots().chain(std::iter::once(candidate)));
        if u64::try_from(count).unwrap_or(u64::MAX) <= u64::from(bounds.suffixes)
            && bytes <= bounds.bytes
        {
            return Some(evicted);
        }
        let (victim, _) = held
            .iter()
            .enumerate()
            .zip(&kept)
            .filter(|((_, slot), kept)| {
                **kept
                    && slot.rank != ForkRank::Rank1
                    && slot.rank.number() >= candidate.rank.number()
            })
            .map(|(entry, _)| entry)
            .max_by_key(|(_, slot)| (slot.rank.number(), slot.observed))?;
        if let Some(flag) = kept.get_mut(victim) {
            *flag = false;
        }
        evicted.push(victim);
    }
}
