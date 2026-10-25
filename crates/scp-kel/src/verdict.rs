//! The verdict a resolution returns: R11's classification of the candidate
//! head, R12's baseline, R14's six verdicts, and the key state a
//! `Confirmed` or `Adopted` verdict accepts (`09-security-model.md`
//! §9.7.4.2 R9, R11, R12, R14; `03-identity.md` §3.10.10).
//!
//! [`classify`] is pure: it reads what the sources served and the
//! [`RetentionSet`] the verifier holds, and returns the verdict with the set
//! the verifier persists next. R14's order, persisting before acting on the
//! verdict, is its caller's.

#![deny(clippy::wildcard_enum_match_arm)]

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use scp_did::{Identifier, KeyState, StandingCommitment};

use crate::constants::MAX_ATTESTATION_KEY_RESOLUTION_STALENESS;
use crate::rank::{
    Admission, ChainPairing, NoResolution, Rerank, ResolveError, RetainedSuffix, RetentionBasis,
    RetentionError, RetentionSet, SetResolution, TieClass, pair_chains, resolve_set,
};
use crate::validate::{EntryVerdict, ReplayedState, ValidatedChain, replay, validate_entry};

/// [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`] as a duration.
const STALENESS: Duration = Duration::from_secs(MAX_ATTESTATION_KEY_RESOLUTION_STALENESS);

/// The six verdicts a resolution returns (`09-security-model.md` §9.7.4.2
/// R14). Every SDK binding carries the type name and all six variant names
/// verbatim.
///
/// `Invalid` carries no position: only the inception makes an identifier
/// invalid.
///
/// ```compile_fail,E0559
/// let _ = scp_kel::ResolutionVerdict::Invalid { at_event: 3 };
/// ```
///
/// The positive control:
///
/// ```
/// let v = scp_kel::ResolutionVerdict::Invalid;
/// assert!(matches!(v, scp_kel::ResolutionVerdict::Invalid));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionVerdict {
    /// The candidate head equals the accepted head at an equal sequence.
    Confirmed,
    /// The verifier replaced its baseline. `baseline_decreased` is true where
    /// the adopted head sits at a lower sequence than the head it replaced.
    Adopted {
        /// The adopted head's digest.
        head: [u8; 32],
        /// Whether the adopted head's sequence is below the replaced head's.
        baseline_decreased: bool,
    },
    /// R6 ranked two suffixes as a tie and R7 classified it. `residue` counts
    /// the candidates the verifier could not retain under R9's bounds.
    Contested {
        /// R7's class of the strictest tied pair.
        tie: TieClass,
        /// Every tied head, in ascending byte order.
        heads: Vec<[u8; 32]>,
        /// The strictest tied pair's shared prefix head.
        shared_prefix_head: [u8; 32],
        /// The strictest tied pair's fork position.
        fork_position: u64,
        /// The candidates this resolution could not retain.
        residue: u32,
    },
    /// The verifier reached no verdict on the bytes it read.
    Inconclusive {
        /// Why.
        cause: InconclusiveCause,
    },
    /// The inception event recomputes to the served identifier and fails
    /// R2 or R3, so the identifier names no valid chain.
    Invalid,
    /// The candidate head sat at a strictly lower sequence on the accepted
    /// chain, so the verifier changed no stored state.
    Discarded {
        /// The accepted head's digest.
        accepted_head: [u8; 32],
    },
}

/// Why a resolution was inconclusive (`09-security-model.md` §9.7.4.2 R14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InconclusiveCause {
    /// The verifier holds no event for the sequences `range` names.
    /// `failed_sources` holds the relay URLs that failed to serve, and it is
    /// empty where R9's fetch bound stopped the verifier itself.
    MissingEvents {
        /// The sequences the verifier holds no event for.
        range: SequenceRange,
        /// The sources that failed to serve.
        failed_sources: Vec<String>,
    },
    /// The resolution did not meet R11's first-contact floor.
    SingleSource {
        /// The sources that did not fail.
        reached_sources: u32,
        /// The distinct operator keys whose proof verified, over the sources
        /// that did not fail.
        proven_sources: u32,
        /// The sources whose proof the verifier's own clock rejected.
        clock_skew_rejected: u32,
    },
}

/// The sequences a verifier holds no event for.
///
/// `from` is absent where the verifier holds an event at every sequence of the chain it assembled, which
/// is what a verifier that read a complete chain and stopped while reading
/// beyond it holds. `to` is absent where the stop left the chain's head
/// sequence unknown (`09-security-model.md` §9.7.4.2 R9's fetch bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceRange {
    /// The first sequence the verifier holds no event for.
    pub from: Option<u64>,
    /// The last such sequence.
    pub to: Option<u64>,
}

/// How far the verifier read one source (`09-security-model.md` §9.7.4.2
/// R9's page walk and fetch bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceExhaustion {
    /// The page walk read the source to its end: the one reading a verdict
    /// rests on.
    Exhausted,
    /// The verifier stopped itself at R9's fetch bound with frames unread.
    StoppedAtFetchBound,
    /// The source failed to serve before the walk ended; it is named in
    /// `MissingEvents.failed_sources`.
    Failed,
}

/// What the verifier made of a source's relay proof of control
/// (`09-security-model.md` §9.7.4.2 R11's first-contact floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorProof {
    /// Every page the source served carried a proof that verified under
    /// this 33-byte operator key.
    Verified {
        /// The operator key the proof verified under.
        operator_key: [u8; 33],
    },
    /// The verifier's own clock rejected the proof, the degree R11 counts
    /// apart.
    ClockSkewRejected,
    /// No proof verified: absent, invalid, or missing from a page.
    Unverified,
}

/// What one source served in one resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRead {
    /// The relay URL, which `MissingEvents.failed_sources` reports.
    pub name: String,
    /// Every unit the source served, in served order.
    pub units: Vec<Vec<u8>>,
    /// How far the verifier read the source.
    pub exhaustion: SourceExhaustion,
    /// The source's proof of control.
    pub proof: OperatorProof,
}

/// What [`classify`] reads.
#[derive(Debug, Clone, Copy)]
pub struct ResolutionInput<'a> {
    /// The identifier resolved.
    pub identifier: Identifier,
    /// The set the verifier holds, restored against its persisted verdict,
    /// or `None` before its first resolution. An accepted basis is the
    /// verifier's baseline; a contested prefix is no baseline (R9).
    pub held: Option<&'a RetentionSet>,
    /// What each source served.
    pub reads: &'a [SourceRead],
    /// The resolution instant, which a [`ResolvedState`] records.
    pub now: SystemTime,
}

/// What [`classify`] returns.
#[derive(Debug, Clone)]
pub struct Classification {
    /// R14's verdict.
    pub verdict: ResolutionVerdict,
    /// The key state a `Confirmed` or `Adopted` verdict accepts; `None` for
    /// every other verdict.
    pub key_state: Option<ResolvedState>,
    /// The set the verifier persists before it acts on the verdict, or
    /// `None` where it holds none. Its basis is the basis the verdict names:
    /// the accepted chain, or the shared prefix of a `Contested` verdict.
    pub retention: Option<RetentionSet>,
    /// The candidates this resolution could not retain under R9's bounds;
    /// `Contested.residue` equals it.
    pub residue: u32,
}

/// Why [`classify`] classified nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClassifyError {
    /// The held set is of another identifier than the one resolved.
    #[error("the held set is of {held}, not of the resolved {resolved}")]
    HeldOfAnotherIdentifier {
        /// The identifier resolved.
        resolved: Identifier,
        /// The held set's identifier.
        held: Identifier,
    },
    /// R6's comparisons reached none of their outcomes, which valid chains
    /// of one identifier never do.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// Retaining a chain reached a [`RetentionError`].
    #[error(transparent)]
    Retention(#[from] RetentionError),
}

/// The key state a resolution accepted.
///
/// It holds the state replaying the validated chain derived, and the
/// instant of the resolution. Only [`classify`]
/// constructs it, on `Confirmed` or `Adopted`, so every verification
/// decision that reads key state reads one a resolution accepted
/// (`03-identity.md` §3.10.10).
///
/// ```compile_fail,E0451
/// let _ = scp_kel::ResolvedState {
///     replayed: todo!(),
///     identifier: todo!(),
///     head_digest: [0; 32],
///     head_sequence: 0,
///     resolved_at: std::time::SystemTime::UNIX_EPOCH,
/// };
/// ```
///
/// The positive control:
///
/// ```
/// fn read(s: &scp_kel::ResolvedState) -> u64 {
///     s.head_sequence()
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedState {
    replayed: ReplayedState,
    identifier: Identifier,
    head_digest: [u8; 32],
    head_sequence: u64,
    resolved_at: SystemTime,
}

impl ResolvedState {
    /// The state `chain` replays to, resolved at `resolved_at`.
    fn of(chain: &ValidatedChain, resolved_at: SystemTime) -> Self {
        Self {
            replayed: replay(chain),
            identifier: chain.identifier(),
            head_digest: chain.head_digest(),
            head_sequence: chain.head_sequence(),
            resolved_at,
        }
    }

    /// The identifier the resolved chain's inception recomputes to.
    #[must_use]
    pub const fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// The preimage digest of the resolved chain's head event.
    #[must_use]
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    /// The sequence of the resolved chain's head event.
    #[must_use]
    pub const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    /// The derived key state.
    #[must_use]
    pub const fn key_state(&self) -> &KeyState {
        self.replayed.key_state()
    }

    /// The commitment the latest reveal-authorized event fixed, or the
    /// abandonment that ended the chain.
    #[must_use]
    pub const fn standing_commitment(&self) -> &StandingCommitment {
        self.replayed.standing_commitment()
    }

    /// False once [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`]
    /// (`09-security-model.md` §9.18.7) has passed since the resolution, and
    /// false where `now` precedes the resolution instant, because a clock
    /// stepped backward would otherwise extend that bound.
    #[must_use]
    pub fn is_fresh(&self, now: SystemTime) -> bool {
        now.duration_since(self.resolved_at)
            .is_ok_and(|d| d < STALENESS)
    }
}

/// Classifies one resolution under R9, R11, R12 and R14.
///
/// 1. Each source's units go through [`validate_entry`]. An inception that
///    recomputes to the identifier and fails R2 or R3 is `Invalid` from any
///    source, because the identifier fixes that inception's preimage.
/// 2. R9's early stop: where a source stopped at the fetch bound, R6 over
///    every chain held (the basis, the retained suffixes and every chain any
///    source served) ties at rank 1, and the strictest pair's shared prefix
///    reveals only under root signatures, the verdict is
///    `Contested{Rank1Terminal}` from the unexhausted read.
/// 3. Otherwise a verdict rests on the exhausted sources alone; where none
///    served a chain, `Inconclusive{MissingEvents}`.
/// 4. With no accepted baseline, R11's floor: fewer than two distinct
///    proven operator keys over the exhausted sources that served a chain
///    is `Inconclusive{SingleSource}`.
/// 5. R12's candidate head is the R6 winner over the basis, every retained
///    suffix and every chain an exhausted source served, ranked before and
///    independent of what R9 then retains: a chain R9 refuses still wins.
///    A tie is `Contested`, and the set moves to the tie's shared prefix
///    (R7) and retains every tied chain. A winner at the baseline head is
///    `Confirmed`, or `Discarded` where every served chain is a proper
///    prefix of the baseline; any other winner is `Adopted`, and the set
///    moves to it. Every losing chain is retained.
///
/// # Errors
///
/// [`ClassifyError::HeldOfAnotherIdentifier`] where `held` is of another
/// identifier, and a [`ResolveError`] or [`RetentionError`] where ranking or
/// retaining reaches one, which valid chains of one identifier never do.
pub fn classify(input: ResolutionInput<'_>) -> Result<Classification, ClassifyError> {
    let ResolutionInput {
        identifier,
        held,
        reads,
        now,
    } = input;
    if let Some(set) = held {
        let held_identifier = set.basis().chain().identifier();
        if held_identifier != identifier {
            return Err(ClassifyError::HeldOfAnotherIdentifier {
                resolved: identifier,
                held: held_identifier,
            });
        }
    }
    let Some(served) = Served::read(&identifier, reads) else {
        return Ok(unchanged(held, ResolutionVerdict::Invalid));
    };
    let held_chains: Vec<ValidatedChain> = held.map_or_else(Vec::new, |set| {
        std::iter::once(set.basis().chain().clone())
            .chain(set.suffixes().iter().map(|suffix| suffix.chain().clone()))
            .collect()
    });
    if let Some(contest) = early_stop(&served, &held_chains)? {
        return contested(held, contest);
    }
    let exhausted: Vec<ValidatedChain> = served.exhausted().cloned().collect();
    if exhausted.is_empty() {
        return Ok(unchanged(held, served.missing_events(held)));
    }
    let baseline = held.and_then(|set| match set.basis() {
        RetentionBasis::Accepted(chain) => Some(chain),
        RetentionBasis::ContestedPrefix(_) => None,
    });
    if baseline.is_none()
        && let Some(cause) = served.below_floor()
    {
        return Ok(unchanged(held, ResolutionVerdict::Inconclusive { cause }));
    }
    let mut ranked = held_chains;
    ranked.extend(exhausted.iter().cloned());
    match resolve_set(&ranked)? {
        SetResolution::Tie {
            class,
            heads,
            shared_prefix_head,
            fork_position,
        } => contested(
            held,
            Contest {
                class,
                heads,
                shared_prefix_head,
                fork_position,
                chains: ranked,
            },
        ),
        SetResolution::Winner { head } => {
            let winner = ranked
                .iter()
                .find(|chain| chain.head_digest() == head)
                .cloned()
                .ok_or(NoResolution)
                .map_err(ResolveError::from)?;
            match (held, baseline) {
                (Some(set), Some(baseline)) => {
                    on_baseline(set, baseline, winner, &exhausted, &ranked, now)
                }
                (held, _) => adopted(held, None, winner, &ranked, now),
            }
        }
        SetResolution::Empty => Err(ResolveError::from(NoResolution).into()),
    }
}

/// Every source's valid chains, with how far each was read.
struct Served<'r> {
    reads: &'r [SourceRead],
    chains: Vec<Vec<ValidatedChain>>,
}

impl<'r> Served<'r> {
    /// Validates every source's units: `None` where an inception that
    /// recomputes to `identifier` failed R2 or R3.
    fn read(identifier: &Identifier, reads: &'r [SourceRead]) -> Option<Self> {
        let mut chains = Vec::with_capacity(reads.len());
        for read in reads {
            let units: Vec<&[u8]> = read.units.iter().map(Vec::as_slice).collect();
            chains.push(match validate_entry(identifier, &units).verdict {
                EntryVerdict::InceptionInvalid { .. } => return None,
                EntryVerdict::NoInception => Vec::new(),
                EntryVerdict::Valid { chains } => chains.iter().cloned().collect(),
            });
        }
        Some(Self { reads, chains })
    }

    fn sources(&self) -> impl Iterator<Item = (&'r SourceRead, &[ValidatedChain])> + '_ {
        self.reads.iter().zip(self.chains.iter().map(Vec::as_slice))
    }

    /// Every chain an exhausted source served.
    fn exhausted(&self) -> impl Iterator<Item = &ValidatedChain> + '_ {
        self.sources()
            .filter(|(read, _)| read.exhaustion == SourceExhaustion::Exhausted)
            .flat_map(|(_, chains)| chains)
    }

    /// R9's `MissingEvents` where no exhausted source served a chain: `from`
    /// absent where an unexhausted source assembled a chain, which runs
    /// from the inception without a gap, and otherwise the first sequence
    /// past the basis the verifier holds (zero where it holds none); `to`
    /// absent, because no source the verifier read to its end fixed a head.
    fn missing_events(&self, held: Option<&RetentionSet>) -> ResolutionVerdict {
        let assembled = self.chains.iter().any(|chains| !chains.is_empty());
        let from = (!assembled).then(|| {
            held.map_or(0, |set| {
                set.basis().chain().head_sequence().saturating_add(1)
            })
        });
        ResolutionVerdict::Inconclusive {
            cause: InconclusiveCause::MissingEvents {
                range: SequenceRange { from, to: None },
                failed_sources: self
                    .reads
                    .iter()
                    .filter(|read| read.exhaustion == SourceExhaustion::Failed)
                    .map(|read| read.name.clone())
                    .collect(),
            },
        }
    }

    /// R11's first-contact floor: the `SingleSource` cause where fewer than
    /// two distinct proven operator keys sit over the exhausted sources that
    /// served a valid chain. An unexhausted source counts at no degree.
    fn below_floor(&self) -> Option<InconclusiveCause> {
        let counted: BTreeSet<[u8; 33]> = self
            .sources()
            .filter(|(read, chains)| {
                read.exhaustion == SourceExhaustion::Exhausted && !chains.is_empty()
            })
            .filter_map(|(read, _)| operator_key(read.proof))
            .collect();
        if counted.len() >= 2 {
            return None;
        }
        let reached: Vec<&SourceRead> = self
            .reads
            .iter()
            .filter(|read| read.exhaustion != SourceExhaustion::Failed)
            .collect();
        let proven: BTreeSet<[u8; 33]> = reached
            .iter()
            .filter_map(|read| operator_key(read.proof))
            .collect();
        let skewed = reached
            .iter()
            .filter(|read| read.proof == OperatorProof::ClockSkewRejected)
            .count();
        Some(InconclusiveCause::SingleSource {
            reached_sources: count(reached.len()),
            proven_sources: count(proven.len()),
            clock_skew_rejected: count(skewed),
        })
    }
}

/// The operator key a verified proof names.
const fn operator_key(proof: OperatorProof) -> Option<[u8; 33]> {
    match proof {
        OperatorProof::Verified { operator_key } => Some(operator_key),
        OperatorProof::ClockSkewRejected | OperatorProof::Unverified => None,
    }
}

/// `n` as a reported count, saturating at `u32::MAX`.
fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// A verdict that changes no stored state.
fn unchanged(held: Option<&RetentionSet>, verdict: ResolutionVerdict) -> Classification {
    Classification {
        verdict,
        key_state: None,
        retention: held.cloned(),
        residue: 0,
    }
}

/// R6's tie over `chains` and R7's class of it.
struct Contest {
    class: TieClass,
    heads: Vec<[u8; 32]>,
    shared_prefix_head: [u8; 32],
    fork_position: u64,
    chains: Vec<ValidatedChain>,
}

/// R9: "One verdict is allowed from an unexhausted source: a resolver
/// holding two suffixes that R6 ranks 1 against each other MAY stop fetching
/// and return `Contested{Rank1Terminal}`, where R6 over every chain it holds,
/// its accepted chain and the suffixes it retains under this rule included,
/// resolves no winner, and every reveal-authorized event on that pair's
/// shared prefix past the inception carries a root signature verifying
/// against the root standing at its predecessor."
///
/// The pair read is R6's strictest tied pair, which `Contested` names: the
/// tie's class must be `Rank1Terminal`, and its shared prefix must pass the
/// root-signature condition.
fn early_stop(
    served: &Served<'_>,
    held_chains: &[ValidatedChain],
) -> Result<Option<Contest>, ClassifyError> {
    let stopped = served
        .reads
        .iter()
        .any(|read| read.exhaustion == SourceExhaustion::StoppedAtFetchBound);
    if !stopped {
        return Ok(None);
    }
    let mut chains = held_chains.to_vec();
    chains.extend(served.chains.iter().flatten().cloned());
    let (heads, shared_prefix_head, fork_position) = match resolve_set(&chains)? {
        SetResolution::Tie {
            class: TieClass::Rank1Terminal,
            heads,
            shared_prefix_head,
            fork_position,
        } => (heads, shared_prefix_head, fork_position),
        SetResolution::Tie {
            class: TieClass::Rank2Terminal | TieClass::Rank3Pending,
            ..
        }
        | SetResolution::Winner { .. }
        | SetResolution::Empty => return Ok(None),
    };
    let prefix = prefix_of(&chains, shared_prefix_head, fork_position)?;
    if !prefix.reveals_root_cosigned_through(prefix.head_sequence()) {
        return Ok(None);
    }
    Ok(Some(Contest {
        class: TieClass::Rank1Terminal,
        heads,
        shared_prefix_head,
        fork_position,
        chains,
    }))
}

/// The shared prefix through `fork_position - 1` of the chain among
/// `chains` holding `shared_prefix_head` there.
fn prefix_of(
    chains: &[ValidatedChain],
    shared_prefix_head: [u8; 32],
    fork_position: u64,
) -> Result<ValidatedChain, ClassifyError> {
    let position = fork_position.saturating_sub(1);
    chains
        .iter()
        .filter_map(|chain| chain.prefix(position))
        .find(|prefix| prefix.head_digest() == shared_prefix_head)
        .ok_or_else(|| ResolveError::from(NoResolution).into())
}

/// R7: "For a contested identity a verifier MUST return `Contested`, MUST
/// NOT adopt any tied suffix as its key state, and MUST retain every tied
/// head and suffix as evidence. It uses the shared prefix's key state as the
/// verification basis". The set moves to the tie's shared prefix, the
/// verifier's accepted chain included (R9: "The accepted chain … is the
/// chain the verifier held before it observed any divergence"), and every
/// tied chain is admitted against it.
fn contested(
    held: Option<&RetentionSet>,
    contest: Contest,
) -> Result<Classification, ClassifyError> {
    let prefix = prefix_of(
        &contest.chains,
        contest.shared_prefix_head,
        contest.fork_position,
    )?;
    let mut dropped = Dropped::default();
    let mut set = match held {
        Some(held) => {
            let mut set = held.clone();
            dropped.rerank(set.contest(prefix)?);
            set
        }
        None => RetentionSet::new(RetentionBasis::ContestedPrefix(prefix)),
    };
    for chain in contest
        .chains
        .into_iter()
        .filter(|chain| contest.heads.contains(&chain.head_digest()))
    {
        dropped.admit(&mut set, chain)?;
    }
    let residue = dropped.residue(&set);
    Ok(Classification {
        verdict: ResolutionVerdict::Contested {
            tie: contest.class,
            heads: contest.heads,
            shared_prefix_head: contest.shared_prefix_head,
            fork_position: contest.fork_position,
            residue,
        },
        key_state: None,
        retention: Some(set),
        residue,
    })
}

/// The heads of the chains R9's bounds refused or evicted while one
/// resolution placed its candidates. A head counts once however often it was
/// dropped, and not at all where the final set holds it.
#[derive(Default)]
struct Dropped(BTreeSet<[u8; 32]>);

impl Dropped {
    fn rerank(&mut self, rerank: Rerank) {
        self.0.extend(rerank.refused);
        self.0.extend(rerank.evicted);
    }

    /// Admits `chain` into `set`, recording what R9 dropped.
    fn admit(
        &mut self,
        set: &mut RetentionSet,
        chain: ValidatedChain,
    ) -> Result<(), ClassifyError> {
        let head = chain.head_digest();
        match set.admit(chain)? {
            Admission::Refused { .. } => {
                self.0.insert(head);
            }
            Admission::Retained { evicted, .. } | Admission::Extended { evicted, .. } => {
                self.0.extend(evicted);
            }
            Admission::AlreadyHeld => {}
        }
        Ok(())
    }

    /// R9's residue: the dropped heads `set` does not hold.
    fn residue(&self, set: &RetentionSet) -> u32 {
        let holds = |head: &[u8; 32]| {
            std::iter::once(set.basis().chain())
                .chain(set.suffixes().iter().map(RetainedSuffix::chain))
                .any(|chain| chain.events().any(|event| event.digest == *head))
        };
        count(self.0.iter().filter(|head| !holds(head)).count())
    }
}

/// R12 where the verifier holds `baseline` as its accepted chain: the
/// winner at its head is `Confirmed`, or `Discarded` where every chain an
/// exhausted source served is a proper prefix of it; any other winner is
/// adopted.
fn on_baseline(
    set: &RetentionSet,
    baseline: &ValidatedChain,
    winner: ValidatedChain,
    exhausted: &[ValidatedChain],
    ranked: &[ValidatedChain],
    now: SystemTime,
) -> Result<Classification, ClassifyError> {
    if winner.head_digest() != baseline.head_digest() {
        return adopted(Some(set), Some(baseline), winner, ranked, now);
    }
    let mut stale = true;
    for chain in exhausted {
        stale &= matches!(
            pair_chains(chain, baseline).map_err(ResolveError::from)?,
            ChainPairing::LeftPrefixOfRight
        );
    }
    if stale {
        return Ok(unchanged(
            Some(set),
            ResolutionVerdict::Discarded {
                accepted_head: baseline.head_digest(),
            },
        ));
    }
    let mut next = set.clone();
    let mut dropped = Dropped::default();
    retain_losers(&mut next, ranked, &mut dropped)?;
    let residue = dropped.residue(&next);
    Ok(Classification {
        verdict: ResolutionVerdict::Confirmed,
        key_state: Some(ResolvedState::of(next.basis().chain(), now)),
        retention: Some(next),
        residue,
    })
}

/// R12's adoption of `winner`: the set moves to it, the replaced basis and
/// every losing chain are re-admitted against it, and refusals count in the
/// residue. Where `winner` extends `baseline`, the baseline's held copies
/// stay (R9's copy rule).
fn adopted(
    held: Option<&RetentionSet>,
    baseline: Option<&ValidatedChain>,
    winner: ValidatedChain,
    ranked: &[ValidatedChain],
    now: SystemTime,
) -> Result<Classification, ClassifyError> {
    let adopted_head = winner.head_digest();
    let decreased =
        baseline.is_some_and(|replaced| winner.head_sequence() < replaced.head_sequence());
    let winner = match baseline {
        Some(baseline)
            if pair_chains(&winner, baseline).map_err(ResolveError::from)?
                == ChainPairing::RightPrefixOfLeft =>
        {
            baseline.extended_by(winner)
        }
        Some(_) | None => winner,
    };
    let mut dropped = Dropped::default();
    let mut next = match held {
        Some(held) => {
            let mut next = held.clone();
            dropped.rerank(next.rerank(RetentionBasis::Accepted(winner))?);
            next
        }
        None => RetentionSet::new(RetentionBasis::Accepted(winner)),
    };
    retain_losers(&mut next, ranked, &mut dropped)?;
    let residue = dropped.residue(&next);
    Ok(Classification {
        verdict: ResolutionVerdict::Adopted {
            head: adopted_head,
            baseline_decreased: decreased,
        },
        key_state: Some(ResolvedState::of(next.basis().chain(), now)),
        retention: Some(next),
        residue,
    })
}

/// R12: "the verifier retains each losing chain as a divergent suffix under
/// R9". Chains on the basis are already held.
fn retain_losers(
    set: &mut RetentionSet,
    ranked: &[ValidatedChain],
    dropped: &mut Dropped,
) -> Result<(), ClassifyError> {
    for chain in ranked {
        dropped.admit(set, chain.clone())?;
    }
    Ok(())
}
