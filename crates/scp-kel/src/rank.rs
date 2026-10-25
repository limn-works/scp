//! Fork rank and set resolution (`09-security-model.md` §9.7.4.2 R6, R7,
//! R9): the rank of a divergent suffix, the comparison of two chains of one
//! identifier, the resolution of a set of them, and the chain a store that
//! validates key-event frames holds as accepted.
//!
//! Every comparison reads event preimage digests and never bytes (R9), so
//! two byte-different copies of one event are one event here.

use std::fmt;

use scp_did::{Identifier, StandingCommitment};

use crate::validate::ValidatedChain;

/// The rank R6 gives a divergent suffix against the shared prefix it
/// diverges from. A lower number wins.
///
/// R6: "it lets C be the standing commitment at the shared prefix, locates
/// on each suffix the first event that reveals C, and ranks: **rank 1** where
/// that event also carries a root signature verifying against the root
/// standing at that event's predecessor; **rank 2** where that event carries
/// no such root signature; **rank 3** where the suffix reveals nothing."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkRank {
    /// The suffix's first C-revealing event carries a root signature that
    /// verifies against the root standing at its predecessor.
    Rank1,
    /// The suffix's first C-revealing event carries no such root signature.
    Rank2,
    /// The suffix reveals nothing.
    Rank3,
}

impl ForkRank {
    /// The rank's number: 1, 2 or 3. R6: "A lower rank number beats a
    /// higher one".
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Rank1 => 1,
            Self::Rank2 => 2,
            Self::Rank3 => 3,
        }
    }

    /// Whether this rank beats `other` (R6: "A lower rank number beats a
    /// higher one").
    const fn beats(self, other: Self) -> bool {
        self.number() < other.number()
    }
}

/// The class of a tie R7 names (`03-identity.md` §3.10.10's `TieClass`).
///
/// R7: "A tie at rank 1 is terminal by key material … A tie at rank 2 is
/// terminal … A tie at rank 3 is pending, and a later reveal decides or
/// escalates it."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TieClass {
    /// Both suffixes carry a root-cosigned reveal of C: terminal.
    Rank1Terminal,
    /// Both suffixes reveal C with no root signature: terminal.
    Rank2Terminal,
    /// Neither suffix reveals C: pending.
    Rank3Pending,
}

impl TieClass {
    /// The class of a tie at `rank` (R7).
    const fn of(rank: ForkRank) -> Self {
        match rank {
            ForkRank::Rank1 => Self::Rank1Terminal,
            ForkRank::Rank2 => Self::Rank2Terminal,
            ForkRank::Rank3 => Self::Rank3Pending,
        }
    }
}

/// Two chains compared that share no inception, so no shared prefix exists
/// to rank against: chains of two identifiers (§9.7.4.2 R13, the identifier
/// derivation, fixes the inception from the identifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("chains of {left} and {right} share no prefix")]
pub struct UnrelatedChains {
    /// The identifier of the chain compared first.
    pub left: Identifier,
    /// The identifier of the chain compared against it.
    pub right: Identifier,
}

impl UnrelatedChains {
    fn of(left: &ValidatedChain, right: &ValidatedChain) -> Self {
        Self {
            left: left.identifier(),
            right: right.identifier(),
        }
    }
}

/// Where two chains diverge and how R6 ranks each suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Divergence {
    /// The preimage digest of the last event both chains hold.
    pub shared_prefix_head: [u8; 32],
    /// The position of the first event past the shared prefix: the shared
    /// prefix head's sequence plus one.
    pub fork_position: u64,
    /// The rank of each chain's suffix, in argument order.
    pub ranks: [ForkRank; 2],
}

/// How two chains of one identifier relate (§9.7.4.2 R6, R9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainPairing {
    /// Both chains hold the same events, compared by digest.
    Identical,
    /// The left chain is a proper prefix of the right one.
    LeftPrefixOfRight,
    /// The right chain is a proper prefix of the left one.
    RightPrefixOfLeft,
    /// The chains diverge past a shared prefix.
    Diverged(Divergence),
}

/// What R6 and R7 make of a set of chains of one identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SetResolution {
    /// One chain wins every pairwise comparison.
    Winner {
        /// The winning chain's head digest.
        head: [u8; 32],
    },
    /// No chain wins every pairwise comparison, and the identity is
    /// contested (R7).
    Tie {
        /// The class of the strictest tied pair (R6, "the composite tie
        /// takes the class of the strictest pair").
        class: TieClass,
        /// The head digest of every chain no other chain beats, in ascending
        /// byte order, so the value is a function of the set alone.
        heads: Vec<[u8; 32]>,
        /// The shared prefix head of the strictest tied pair.
        shared_prefix_head: [u8; 32],
        /// The fork position of the strictest tied pair.
        fork_position: u64,
    },
    /// The set holds no chain.
    Empty,
}

/// The rank of `chain`'s suffix past its first `shared_prefix_len` events,
/// or `None` where `shared_prefix_len` is zero and no prefix exists to rank
/// against.
///
/// R6: "it lets C be the standing commitment at the shared prefix, locates
/// on each suffix the first event that reveals C, and ranks: rank 1 where
/// that event also carries a root signature verifying against the root
/// standing at that event's predecessor; rank 2 where that event carries no
/// such root signature; rank 3 where the suffix reveals nothing."
///
/// "Rank is monotone. Once a suffix carries a C-revealing event its rank is
/// fixed and extending that suffix does not change it. A reveal consuming a
/// commitment the suffix itself fixed confers no rank": the walk stops at
/// the first event that reveals C, and an event revealing a commitment the
/// suffix fixed never has C standing at its predecessor.
///
/// "A verifier MUST NOT decide a divergence by head sequence or by the first
/// event after the shared prefix": the walk reads neither.
fn rank_suffix(chain: &ValidatedChain, shared_prefix_len: usize) -> Option<ForkRank> {
    let last_shared = shared_prefix_len.checked_sub(1)?;
    let mut events = chain.events().skip(last_shared);
    let commitment = events.next()?.commitment_after;
    if matches!(commitment, StandingCommitment::Abandoned { .. }) {
        return Some(ForkRank::Rank3);
    }
    let revealing = events.find(|event| {
        event.kind.is_reveal_authorized() && event.commitment_before == Some(commitment)
    });
    Some(match revealing {
        Some(event) if event.reveal_root_cosigned => ForkRank::Rank1,
        Some(_) => ForkRank::Rank2,
        None => ForkRank::Rank3,
    })
}

/// How `left` and `right` relate: identical, one a prefix of the other, or
/// diverged with each suffix ranked against the shared prefix.
///
/// R6: "Where a verifier holds two valid chains that diverge from a shared
/// prefix, it lets C be the standing commitment at the shared prefix,
/// locates on each suffix the first event that reveals C, and ranks". R9:
/// "An event is identified by its preimage digest, and every comparison
/// reads that digest and never the bytes".
///
/// # Errors
///
/// [`UnrelatedChains`] where the chains share no inception, which only
/// chains of two identifiers can show.
pub fn pair_chains(
    left: &ValidatedChain,
    right: &ValidatedChain,
) -> Result<ChainPairing, UnrelatedChains> {
    let shared = left.shared_prefix_len(right);
    let unrelated = || UnrelatedChains::of(left, right);
    let head = shared
        .checked_sub(1)
        .and_then(|last| left.events().nth(last))
        .ok_or_else(unrelated)?;
    let (left_len, right_len) = (left.len(), right.len());
    if shared == left_len && shared == right_len {
        return Ok(ChainPairing::Identical);
    }
    if shared == left_len {
        return Ok(ChainPairing::LeftPrefixOfRight);
    }
    if shared == right_len {
        return Ok(ChainPairing::RightPrefixOfLeft);
    }
    let (Some(left_rank), Some(right_rank)) =
        (rank_suffix(left, shared), rank_suffix(right, shared))
    else {
        return Err(unrelated());
    };
    Ok(ChainPairing::Diverged(Divergence {
        shared_prefix_head: head.digest,
        fork_position: head.sequence.saturating_add(1),
        ranks: [left_rank, right_rank],
    }))
}

/// What R6 and R7 make of `chains`, read as a set: input order, duplicates
/// by head digest, and chains that are prefixes of another chain change
/// nothing.
///
/// R6: "With more than two chains a verifier ranks every pair against that
/// pair's own shared prefix, the winner wins every pairwise comparison, and
/// the composite tie takes the class of the strictest pair." R7: "Equal rank
/// resolves no winner and the identity is contested."
///
/// Without a winner, `heads` names every chain no other chain beats; where
/// every chain is beaten, every chain of the cycles nothing outside beats.
/// The strictest pair is the pair among `heads` with the lowest rank
/// number, then the lowest fork position, then the lowest shared prefix
/// head digest.
///
/// # Errors
///
/// [`UnrelatedChains`] where two chains share no inception.
pub fn resolve_set(chains: &[ValidatedChain]) -> Result<SetResolution, UnrelatedChains> {
    let refs: Vec<&ValidatedChain> = chains.iter().collect();
    let Some(tournament) = Tournament::of(&reduce(&refs)?)? else {
        return Ok(SetResolution::Empty);
    };
    Ok(tournament.resolution())
}

/// `chains` with every duplicate by head digest and every proper prefix of
/// another chain dropped, in input order: a prefix lies on the chain it
/// prefixes and contributes no suffix (R9, R11).
fn reduce<'c>(chains: &[&'c ValidatedChain]) -> Result<Vec<&'c ValidatedChain>, UnrelatedChains> {
    let mut kept: Vec<&ValidatedChain> = Vec::with_capacity(chains.len());
    'chains: for &chain in chains {
        for slot in &mut kept {
            match pair_chains(chain, slot)? {
                ChainPairing::Identical | ChainPairing::LeftPrefixOfRight => continue 'chains,
                ChainPairing::RightPrefixOfLeft => {
                    *slot = chain;
                    continue 'chains;
                }
                ChainPairing::Diverged(_) => {}
            }
        }
        kept.push(chain);
    }
    Ok(kept)
}

/// Every pairwise R6 comparison over chains no one of which is a prefix of
/// another.
struct Tournament<'c> {
    chains: Vec<&'c ValidatedChain>,
    /// `divergences[i][j]` is the divergence of chain `i` against chain `j`,
    /// ranks in that order; `None` on the diagonal.
    divergences: Vec<Vec<Option<Divergence>>>,
}

impl<'c> Tournament<'c> {
    /// The tournament over `chains`, or `None` for an empty set.
    fn of(chains: &[&'c ValidatedChain]) -> Result<Option<Self>, UnrelatedChains> {
        if chains.is_empty() {
            return Ok(None);
        }
        let mut divergences = vec![vec![None; chains.len()]; chains.len()];
        for (i, left) in chains.iter().enumerate() {
            for (j, right) in chains.iter().enumerate() {
                if i == j {
                    continue;
                }
                match pair_chains(left, right)? {
                    ChainPairing::Diverged(divergence) => {
                        if let Some(cell) = divergences.get_mut(i).and_then(|row| row.get_mut(j)) {
                            *cell = Some(divergence);
                        }
                    }
                    // `reduce` leaves no prefix pair; were one here, it is
                    // no divergence and ranks nothing.
                    ChainPairing::Identical
                    | ChainPairing::LeftPrefixOfRight
                    | ChainPairing::RightPrefixOfLeft => {}
                }
            }
        }
        Ok(Some(Self {
            chains: chains.to_vec(),
            divergences,
        }))
    }

    fn divergence(&self, i: usize, j: usize) -> Option<Divergence> {
        self.divergences
            .get(i)
            .and_then(|row| row.get(j))
            .copied()
            .flatten()
    }

    /// Whether chain `i` beats chain `j` (R6).
    fn beats(&self, i: usize, j: usize) -> bool {
        self.divergence(i, j)
            .is_some_and(|divergence| divergence.ranks[0].beats(divergence.ranks[1]))
    }

    /// The first comparison chain `i` does not win: a divergence it ties or
    /// loses, ranks in the order `i`, other.
    fn unwon(&self, i: usize) -> Option<Divergence> {
        (0..self.chains.len())
            .filter_map(|j| self.divergence(i, j))
            .find(|divergence| !divergence.ranks[0].beats(divergence.ranks[1]))
    }

    /// The chain that wins every pairwise comparison, or else the first
    /// comparison the first chain does not win. A chain that diverges from
    /// no other lies on one line with every chain and wins.
    fn contest(&self) -> Contest {
        let mut unwon = None;
        for i in 0..self.chains.len() {
            match self.unwon(i) {
                None => return Contest::Winner(i),
                Some(divergence) => {
                    unwon.get_or_insert(divergence);
                }
            }
        }
        // `unwon` is `None` only for an empty set, whose index 0 names no
        // chain.
        unwon.map_or(Contest::Winner(0), Contest::Unwon)
    }

    /// The chains no other chain beats; where every chain is beaten, the
    /// chains of every cycle no chain outside it beats (Q7: "on a cycle,
    /// every chain in the cycle").
    fn undefeated(&self) -> Vec<usize> {
        let n = self.chains.len();
        let unbeaten: Vec<usize> = (0..n)
            .filter(|&i| (0..n).all(|j| !self.beats(j, i)))
            .collect();
        if !unbeaten.is_empty() {
            return unbeaten;
        }
        // Reachability over "beats": a chain belongs to a source cycle when
        // every chain that reaches it is reached from it.
        let mut reach = vec![vec![false; n]; n];
        for (i, row) in reach.iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                *cell = self.beats(i, j);
            }
        }
        for k in 0..n {
            for i in 0..n {
                for j in 0..n {
                    let through = reach
                        .get(i)
                        .and_then(|row| row.get(k))
                        .copied()
                        .unwrap_or(false)
                        && reach
                            .get(k)
                            .and_then(|row| row.get(j))
                            .copied()
                            .unwrap_or(false);
                    if through && let Some(cell) = reach.get_mut(i).and_then(|row| row.get_mut(j)) {
                        *cell = true;
                    }
                }
            }
        }
        let reaches = |from: usize, to: usize| {
            reach
                .get(from)
                .and_then(|row| row.get(to))
                .copied()
                .unwrap_or(false)
        };
        (0..n)
            .filter(|&i| (0..n).all(|j| !reaches(j, i) || reaches(i, j)))
            .collect()
    }

    /// The earliest chain in input order that no other chain beats (Q6:
    /// "the earliest-held chain among those no other chain beats").
    fn undefeated_in_receipt_order(&self) -> Option<usize> {
        let n = self.chains.len();
        (0..n).find(|&i| (0..n).all(|j| !self.beats(j, i)))
    }

    /// The strictest pair among `among`: lowest rank number, then lowest
    /// fork position, then lowest shared prefix head digest. A tied pair's
    /// rank is the rank both carry; a pair one side wins carries the
    /// winner's rank, which only a cycle places among the undefeated.
    fn strictest(&self, among: &[usize]) -> Option<Divergence> {
        let mut best: Option<(u8, u64, [u8; 32], Divergence)> = None;
        for &i in among {
            for &j in among {
                let Some(divergence) = self.divergence(i, j).filter(|_| i < j) else {
                    continue;
                };
                let rank = divergence.ranks[0]
                    .number()
                    .min(divergence.ranks[1].number());
                let key = (
                    rank,
                    divergence.fork_position,
                    divergence.shared_prefix_head,
                );
                if best.as_ref().is_none_or(|(r, f, h, _)| key < (*r, *f, *h)) {
                    best = Some((key.0, key.1, key.2, divergence));
                }
            }
        }
        best.map(|(.., divergence)| divergence)
    }

    fn head(&self, i: usize) -> Option<[u8; 32]> {
        self.chains.get(i).map(|chain| chain.head_digest())
    }

    fn resolution(&self) -> SetResolution {
        let unwon = match self.contest() {
            Contest::Winner(i) => {
                return self
                    .head(i)
                    .map_or(SetResolution::Empty, |head| SetResolution::Winner { head });
            }
            Contest::Unwon(divergence) => divergence,
        };
        let undefeated = self.undefeated();
        // Two undefeated chains neither of which beats the other form a
        // tied pair; only a set whose undefeated chains are one chain, which
        // a cycle elsewhere leaves, has none, and then the first comparison
        // no chain wins is the strictest pair it holds.
        let strictest = self.strictest(&undefeated).unwrap_or(unwon);
        let mut heads: Vec<[u8; 32]> = undefeated.iter().filter_map(|&i| self.head(i)).collect();
        heads.sort_unstable();
        SetResolution::Tie {
            class: TieClass::of(rank_of_pair(strictest)),
            heads,
            shared_prefix_head: strictest.shared_prefix_head,
            fork_position: strictest.fork_position,
        }
    }
}

/// The chain that wins every comparison, or a comparison no chain wins.
enum Contest {
    Winner(usize),
    Unwon(Divergence),
}

/// The better rank of a pair: the rank both carry where tied.
const fn rank_of_pair(divergence: Divergence) -> ForkRank {
    if divergence.ranks[1].beats(divergence.ranks[0]) {
        divergence.ranks[1]
    } else {
        divergence.ranks[0]
    }
}

/// A displaced accepted chain's suffix past the shared prefix it shares with
/// the chain that displaced it (R9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisplacedSuffix {
    /// The displaced chain's head digest.
    pub head: [u8; 32],
    /// The rank R6 gives the displaced suffix against the new accepted
    /// chain: 2 or 3 where a winner displaced it, and the rank of the tie
    /// where R9's held-first rule moved acceptance among tied chains.
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
/// before it: a chain that extends a held chain replaces it in place and
/// keeps its place in receipt order, so a chain delivered frame by frame is
/// one chain. "Held first" is the earliest-held chain among the chains no
/// other chain beats, and where every chain is beaten the accepted chain
/// stays.
///
/// The holder bounds nothing it holds; R9's count and byte bounds on the
/// divergent suffixes are the caller's.
#[derive(Debug, Clone, Default)]
pub struct AcceptedChainHolder {
    /// The held chains in receipt order, none a prefix of another.
    held: Vec<ValidatedChain>,
    /// The index in `held` of the accepted chain; `None` while empty.
    accepted: Option<usize>,
}

impl AcceptedChainHolder {
    /// A holder that holds no chain.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            held: Vec::new(),
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
    /// # Errors
    ///
    /// [`UnrelatedChains`] where `chain` is of another identifier than the
    /// chains held; the holder is unchanged.
    pub fn hold(&mut self, chain: ValidatedChain) -> Result<HoldOutcome, UnrelatedChains> {
        let mut extends = None;
        for (i, held) in self.held.iter().enumerate() {
            match pair_chains(&chain, held)? {
                ChainPairing::Identical | ChainPairing::LeftPrefixOfRight => {
                    return Ok(HoldOutcome::AlreadyHeld);
                }
                ChainPairing::RightPrefixOfLeft => extends = Some(i),
                ChainPairing::Diverged(_) => {}
            }
        }
        // No held chain is a prefix of another, so at most one is a prefix
        // of `chain`.
        let extended = extends.and_then(|i| Some((i, self.held.get_mut(i)?)));
        let slot = if let Some((i, held)) = extended {
            *held = chain;
            i
        } else {
            self.held.push(chain);
            self.held.len().saturating_sub(1)
        };
        let refs: Vec<&ValidatedChain> = self.held.iter().collect();
        let Some(tournament) = Tournament::of(&refs)? else {
            // `held` holds `chain` at `slot`, so the set is not empty.
            self.accepted = Some(slot);
            return Ok(HoldOutcome::AcceptedExtended);
        };
        let before = self.accepted;
        let after = match tournament.contest() {
            Contest::Winner(winner) => winner,
            Contest::Unwon(_) => tournament
                .undefeated_in_receipt_order()
                .or(before)
                .unwrap_or(slot),
        };
        self.accepted = Some(after);
        Ok(match before {
            None => HoldOutcome::AcceptedExtended,
            Some(before) if before == after && slot == after => HoldOutcome::AcceptedExtended,
            // Two held chains that do not diverge lie on one line: the held
            // chain adds no suffix.
            Some(before) if before == after => {
                tournament
                    .divergence(slot, after)
                    .map_or(HoldOutcome::AlreadyHeld, |divergence| {
                        HoldOutcome::HeldDivergent {
                            rank: divergence.ranks[0],
                        }
                    })
            }
            Some(before) => match (refs.get(before), tournament.divergence(before, after)) {
                (Some(displaced), Some(divergence)) => HoldOutcome::AcceptedReplaced {
                    displaced: DisplacedSuffix {
                        head: displaced.head_digest(),
                        bytes: suffix_bytes(displaced, divergence.fork_position),
                        rank: divergence.ranks[0],
                        shared_prefix_head: divergence.shared_prefix_head,
                        fork_position: divergence.fork_position,
                    },
                },
                // The chain accepted before lies on the line of the one
                // accepted now: the accepted chain extended. (`before`
                // indexes `held`, which only grows.)
                _ => HoldOutcome::AcceptedExtended,
            },
        })
    }
}

impl fmt::Display for ForkRank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rank {}", self.number())
    }
}
