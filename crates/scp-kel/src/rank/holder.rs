//! The chain a store that validates key-event frames holds as accepted
//! (§9.7.4.2 R9).

use super::{
    ChainPairing, Decision, Divergence, ForkRank, NoResolution, ResolveError, Tournament,
    pair_chains,
};
use crate::validate::ValidatedChain;

/// A displaced accepted chain's suffix past the shared prefix it shares with
/// the chain that displaced it (R9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisplacedSuffix {
    /// The displaced chain's head digest.
    pub head: [u8; 32],
    /// The rank R6 gives the displaced suffix against the new accepted
    /// chain: 2 or 3 where a winner displaced it, and the rank of the tie,
    /// 1 or 2, where R9's held-first rule moved acceptance to an
    /// earlier-held chain tied with it.
    pub rank: ForkRank,
    /// The preimage digest of the last event the two chains share.
    pub shared_prefix_head: [u8; 32],
    /// The position of the displaced suffix's first event.
    pub fork_position: u64,
    /// The summed lengths of the units that carried the displaced suffix's
    /// events, which R9's byte bound counts against the identifier.
    pub bytes: u64,
}

/// The summed unit lengths of `chain`'s events at and past `fork_position`
/// (R9's byte bound).
fn suffix_bytes(chain: &ValidatedChain, fork_position: u64) -> u64 {
    chain
        .events()
        .filter(|event| event.sequence >= fork_position)
        .fold(0_u64, |bytes, event| bytes.saturating_add(event.unit_len))
}

/// What holding one more chain did to the accepted chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoldOutcome {
    /// The chain is, or is a prefix of, a chain already held, compared by
    /// digest: nothing changed.
    AlreadyHeld,
    /// The chain is the accepted chain: the first chain held, or an
    /// extension of the chain accepted before it.
    AcceptedExtended,
    /// Another chain is accepted now, and the chain accepted before it is a
    /// divergent suffix.
    AcceptedReplaced {
        /// The suffix of the chain accepted before.
        displaced: DisplacedSuffix,
    },
    /// The accepted chain is unchanged, and the chain is held as a divergent
    /// suffix of it.
    HeldDivergent {
        /// The rank R6 gives the held suffix against the accepted chain.
        rank: ForkRank,
    },
}

/// The chains of one identifier a store that validates key-event frames
/// holds, and the one among them it holds as accepted (§9.7.4.2 R9).
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
/// A chain is held from the first event of its own past every chain held
/// before it: a chain that extends a held chain replaces it in place, keeps
/// its place in receipt order and keeps the held copy of every event the two
/// share, so a chain delivered frame by frame is one chain. "Held first" is
/// the earliest-held chain among the chains no other chain beats.
///
/// The holder bounds nothing it holds, so it stays crate-private until R9's
/// count and byte bounds on the divergent suffixes land with it.
#[derive(Debug, Clone, Default)]
pub struct AcceptedChainHolder {
    /// The held chains in receipt order, none a prefix of another.
    held: Vec<ValidatedChain>,
    /// Every pairwise comparison over `held`, by index.
    tournament: Tournament,
    /// The index in `held` of the accepted chain; `None` while empty.
    accepted: Option<usize>,
}

impl AcceptedChainHolder {
    /// A holder that holds no chain.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            held: Vec::new(),
            tournament: Tournament {
                divergences: Vec::new(),
            },
            accepted: None,
        }
    }

    /// The accepted chain, or `None` before the first chain is held.
    #[must_use]
    pub fn accepted(&self) -> Option<&ValidatedChain> {
        self.accepted.and_then(|i| self.held.get(i))
    }

    /// Every held chain in receipt order, the accepted chain included.
    pub fn held(&self) -> impl Iterator<Item = &ValidatedChain> {
        self.held.iter()
    }

    /// Holds `chain` and re-decides the accepted chain under R9.
    ///
    /// Each call compares `chain` with every held chain once and updates
    /// only the comparisons of the slot `chain` takes.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Unrelated`] where `chain` is of another identifier
    /// than the chains held, and [`ResolveError::NoResolution`] where the
    /// comparisons reach none of R6's outcomes, which valid chains of one
    /// identifier never do. On either error the holder is unchanged.
    pub fn hold(&mut self, chain: ValidatedChain) -> Result<HoldOutcome, ResolveError> {
        let mut extends = None;
        let mut row = Vec::with_capacity(self.held.len().saturating_add(1));
        for (i, held) in self.held.iter().enumerate() {
            match pair_chains(&chain, held)? {
                ChainPairing::Identical | ChainPairing::LeftPrefixOfRight => {
                    return Ok(HoldOutcome::AlreadyHeld);
                }
                ChainPairing::RightPrefixOfLeft => {
                    extends = Some(i);
                    row.push(None);
                }
                ChainPairing::Diverged(divergence) => row.push(Some(divergence)),
            }
        }
        // No held chain is a prefix of another, so at most one is a prefix
        // of `chain`, and `chain` takes that one's slot.
        let (slot, chain) =
            if let Some((i, held)) = extends.and_then(|i| Some((i, self.held.get(i)?))) {
                (i, held.extended_by(chain))
            } else {
                row.push(None);
                (self.held.len(), chain)
            };
        let mut tournament = self.tournament.clone();
        tournament.set(slot, &row);
        let after = match tournament.decide()? {
            Decision::Winner(winner) => winner,
            Decision::Tie { undefeated, .. } => *undefeated.first().ok_or(NoResolution)?,
        };
        let before = self.accepted;
        let outcome = match before {
            None => HoldOutcome::AcceptedExtended,
            Some(before) if before == after && slot == after => HoldOutcome::AcceptedExtended,
            Some(before) if before == after => HoldOutcome::HeldDivergent {
                rank: tournament
                    .divergence(slot, after)
                    .ok_or(NoResolution)?
                    .ranks[0],
            },
            Some(before) => {
                let displaced = if before == slot {
                    &chain
                } else {
                    self.held.get(before).ok_or(NoResolution)?
                };
                let divergence: Divergence =
                    tournament.divergence(before, after).ok_or(NoResolution)?;
                HoldOutcome::AcceptedReplaced {
                    displaced: DisplacedSuffix {
                        head: displaced.head_digest(),
                        rank: divergence.ranks[0],
                        shared_prefix_head: divergence.shared_prefix_head,
                        fork_position: divergence.fork_position,
                        bytes: suffix_bytes(displaced, divergence.fork_position),
                    },
                }
            }
        };
        match self.held.get_mut(slot) {
            Some(held) => *held = chain,
            None => self.held.push(chain),
        }
        self.tournament = tournament;
        self.accepted = Some(after);
        Ok(outcome)
    }
}

impl Tournament {
    /// Sets the comparisons of the chain at `slot`: `row[j]` is its
    /// divergence against chain `j`, and chain `j`'s against it is the same
    /// divergence with the ranks swapped. A `slot` one past the last chain
    /// appends it.
    fn set(&mut self, slot: usize, row: &[Option<Divergence>]) {
        if slot == self.divergences.len() {
            for existing in &mut self.divergences {
                existing.push(None);
            }
            self.divergences.push(vec![None; row.len()]);
        }
        for (j, divergence) in row.iter().enumerate() {
            let swapped = divergence.map(|divergence| Divergence {
                ranks: [divergence.ranks[1], divergence.ranks[0]],
                ..divergence
            });
            if let Some(cell) = self.divergences.get_mut(slot).and_then(|r| r.get_mut(j)) {
                *cell = *divergence;
            }
            if let Some(cell) = self.divergences.get_mut(j).and_then(|r| r.get_mut(slot)) {
                *cell = swapped;
            }
        }
    }
}
