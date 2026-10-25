//! Fork rank and set resolution (`09-security-model.md` §9.7.4.2 R6, R7,
//! R9): the rank of a divergent suffix, the comparison of two chains of one
//! identifier, the resolution of a set of them, and the chain a store that
//! validates key-event frames holds as accepted.
//!
//! Every comparison reads event preimage digests and never bytes (R9), so
//! two byte-different copies of one event are one event here.

use std::fmt;

use scp_did::Identifier;

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

/// A set of chains over which R6's pairwise comparisons reach none of R6's
/// outcomes: no chain wins every comparison, and fewer than two chains are
/// beaten by none.
///
/// Valid chains of one identifier never reach it. R6 ranks a suffix by its
/// first reveal-authorized event past the fork, because only such an event
/// changes the standing commitment (R1), so "beats" is transitive: where
/// three chains fork at two points, the pair sharing the deeper prefix
/// compares the same at the shallower fork unless their shared segment
/// reveals C, and then both carry one rank there. A transitive "beats" over
/// a finite set has an unbeaten chain; one unbeaten chain beats every other
/// chain, and two unbeaten chains tie. The error reports a broken invariant
/// instead of fabricating a resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("R6's pairwise comparisons over the set name no winner and no tie")]
pub struct NoResolution;

/// Why [`resolve_set`] resolved nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// Two chains of the set are of two identifiers.
    #[error(transparent)]
    Unrelated(#[from] UnrelatedChains),
    /// The comparisons reach none of R6's outcomes.
    #[error(transparent)]
    NoResolution(#[from] NoResolution),
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
/// The first reveal-authorized event of the suffix is the first event that
/// reveals C. A `KeyState` carries no continuation (field 12's sentinel), so
/// only a reveal-authorized event changes the standing commitment, and each
/// one reveals the commitment standing at its predecessor (R1); C stands
/// until the suffix's first reveal-authorized event. Where C is abandoned,
/// no chain diverges past it: the standing commitment's definition in
/// §9.7.4.2 states that it "is `StandingCommitment::Abandoned` from that
/// rollover's position on, and no later event is valid on that chain".
///
/// "Rank is monotone. Once a suffix carries a C-revealing event its rank is
/// fixed and extending that suffix does not change it. A reveal consuming a
/// commitment the suffix itself fixed confers no rank": the walk stops at
/// the first reveal-authorized event, and every later one reveals a
/// commitment the suffix fixed.
///
/// "A verifier MUST NOT decide a divergence by head sequence or by the first
/// event after the shared prefix": the walk reads neither.
fn rank_suffix(chain: &ValidatedChain, shared_prefix_len: usize) -> Option<ForkRank> {
    shared_prefix_len.checked_sub(1)?;
    let revealing = chain
        .events()
        .skip(shared_prefix_len)
        .find(|event| event.kind.is_reveal_authorized());
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
/// Without a winner, `heads` names every chain no other chain beats, and
/// every two of them tie. The strictest pair is the tied pair among `heads`
/// with the lowest rank number, then the lowest fork position, then the
/// lowest shared prefix head digest.
///
/// # Errors
///
/// [`ResolveError::Unrelated`] where two chains share no inception, and
/// [`ResolveError::NoResolution`] where the comparisons reach none of R6's
/// outcomes, which valid chains of one identifier never do.
pub fn resolve_set(chains: &[ValidatedChain]) -> Result<SetResolution, ResolveError> {
    let refs: Vec<&ValidatedChain> = chains.iter().collect();
    let kept = reduce(&refs)?;
    if kept.is_empty() {
        return Ok(SetResolution::Empty);
    }
    let tournament = Tournament::of(&kept)?;
    let head = |i: usize| kept.get(i).map(|chain| chain.head_digest());
    Ok(match tournament.decide()? {
        Decision::Winner(i) => SetResolution::Winner {
            head: head(i).ok_or(NoResolution)?,
        },
        Decision::Tie {
            undefeated,
            strictest,
        } => {
            let mut heads = undefeated
                .iter()
                .map(|&i| head(i))
                .collect::<Option<Vec<[u8; 32]>>>()
                .ok_or(NoResolution)?;
            heads.sort_unstable();
            SetResolution::Tie {
                class: TieClass::of(strictest.ranks[0]),
                heads,
                shared_prefix_head: strictest.shared_prefix_head,
                fork_position: strictest.fork_position,
            }
        }
    })
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
/// another, by index into the chains it was built over.
#[derive(Debug, Clone, Default)]
struct Tournament {
    /// `divergences[i][j]` is the divergence of chain `i` against chain `j`,
    /// ranks in that order; `None` on the diagonal and for a pair that does
    /// not diverge.
    divergences: Vec<Vec<Option<Divergence>>>,
}

/// What R6 decides over a [`Tournament`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    /// The chain that wins every pairwise comparison.
    Winner(usize),
    /// No chain wins every comparison.
    Tie {
        /// The chains no other chain beats, two or more, in index order.
        undefeated: Vec<usize>,
        /// The strictest tied pair among them.
        strictest: Divergence,
    },
}

impl Tournament {
    /// The tournament over `chains`.
    fn of(chains: &[&ValidatedChain]) -> Result<Self, UnrelatedChains> {
        let mut divergences = Vec::with_capacity(chains.len());
        for left in chains {
            let mut row = Vec::with_capacity(chains.len());
            for right in chains {
                row.push(match pair_chains(left, right)? {
                    ChainPairing::Diverged(divergence) => Some(divergence),
                    ChainPairing::Identical
                    | ChainPairing::LeftPrefixOfRight
                    | ChainPairing::RightPrefixOfLeft => None,
                });
            }
            divergences.push(row);
        }
        Ok(Self { divergences })
    }

    const fn len(&self) -> usize {
        self.divergences.len()
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

    /// R6's outcome: the one chain no other chain beats where it beats every
    /// other chain, else the two or more chains no other chain beats and
    /// their strictest pair. [`NoResolution`] documents why no third case
    /// arises.
    fn decide(&self) -> Result<Decision, NoResolution> {
        let n = self.len();
        let undefeated: Vec<usize> = (0..n)
            .filter(|&i| (0..n).all(|j| !self.beats(j, i)))
            .collect();
        match undefeated.as_slice() {
            [winner] if (0..n).all(|j| j == *winner || self.beats(*winner, j)) => {
                Ok(Decision::Winner(*winner))
            }
            [_, _, ..] => {
                let strictest = self.strictest(&undefeated).ok_or(NoResolution)?;
                Ok(Decision::Tie {
                    undefeated,
                    strictest,
                })
            }
            _ => Err(NoResolution),
        }
    }

    /// The strictest pair among `among`, every pair of which ties: lowest
    /// rank number, then lowest fork position, then lowest shared prefix
    /// head digest. Tied pairs with one key carry one class, prefix and
    /// fork position, so the choice among them changes nothing.
    fn strictest(&self, among: &[usize]) -> Option<Divergence> {
        among
            .iter()
            .flat_map(|&i| among.iter().map(move |&j| (i, j)))
            .filter(|(i, j)| i < j)
            .filter_map(|(i, j)| self.divergence(i, j))
            .min_by_key(|divergence| {
                (
                    divergence.ranks[0].number(),
                    divergence.fork_position,
                    divergence.shared_prefix_head,
                )
            })
    }
}

// `AcceptedChainHolder` is crate-private until R9's count and byte bounds
// land with it, so no exported path holds divergent suffixes unbounded.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "AcceptedChainHolder stays unexported until R9's retention bounds land with it (SCP-310)"
    )
)]
mod holder;

#[cfg(test)]
mod tests;

impl fmt::Display for ForkRank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rank {}", self.number())
    }
}
