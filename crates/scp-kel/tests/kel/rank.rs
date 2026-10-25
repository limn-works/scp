//! Fork rank and set resolution (`09-security-model.md` §9.7.4.2 R6, R7,
//! R9): `pair_chains`, `resolve_set` and `AcceptedChainHolder` over chains
//! that fork from Vector 41, each suffix signed here.
//!
//! Every expected rank is the test's own model of R6: a suffix whose first
//! C-revealing event carries a standing-root group is rank 1, one whose
//! first C-revealing event carries none is rank 2, and one revealing nothing
//! is rank 3.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use scp_did::KeyCondition;
use scp_kel::{
    AcceptedChainHolder, ChainPairing, CommitmentRolloverFields, Divergence, EventPreimage,
    ForkRank, HoldOutcome, KeyStateSnapshot, SetResolution, TieClass, UnrelatedChains,
    ValidatedChain, pair_chains, resolve_set,
};

use super::chain_support::{
    Base, Error, Ring, Wire, fixes, group, key_state_on, point, sign_on, v41, v41_changed,
    v41_next, v41_v54, v41_v55, v42, v53_with, v54_with, v55_with,
};
use super::chain_valid::chain_of;
use super::fixtures::{TestResult, V41_DIGEST, V54_DIGEST, V55_DIGEST, array};

/// The keys a `CommitmentRollover` variant on Vector 41 fixes, Vector 53's
/// own first.
const ROLLOVER_NEXT: [&str; 3] = ["scp-25-rollover-next", "pr3-next-0", "pr3-next-1"];

/// The first event of a suffix forking from Vector 41, and its variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum First {
    /// A root-signed `KeyState`: reveals nothing.
    KeyState(u8),
    /// Vector 53 or a variant: a `CommitmentRollover` revealing Vector 41's
    /// commitment under its root.
    Rollover(u8),
    /// Vector 54 or a variant: `RootRecovery{CoSigns}`.
    CoSigns(u8),
    /// Vector 55 or a variant: `RootRecovery{Lost}`.
    Lost(u8),
}

/// One event after a suffix's first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// A `KeyState` signed by the standing root, changing the interval.
    KeyState,
    /// A `CommitmentRollover` revealing the commitment standing at its
    /// predecessor, signed by the standing root.
    Reveal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SuffixPlan {
    first: First,
    steps: Vec<Step>,
}

impl SuffixPlan {
    /// R6's rank of the suffix's first `events` events, by the test's model.
    fn rank(&self, events: usize) -> ForkRank {
        match self.first {
            First::Rollover(_) | First::CoSigns(_) => ForkRank::Rank1,
            First::Lost(_) => ForkRank::Rank2,
            // Only a reveal that consumes Vector 41's commitment ranks, and
            // after a `KeyState` the first reveal is that one.
            First::KeyState(_) => {
                let revealed = self
                    .steps
                    .iter()
                    .take(events.saturating_sub(1))
                    .any(|step| *step == Step::Reveal);
                if revealed {
                    ForkRank::Rank1
                } else {
                    ForkRank::Rank3
                }
            }
        }
    }
}

fn arb_first() -> impl Strategy<Value = First> {
    (0_u8..4, 0_u8..3).prop_map(|(kind, variant)| match kind {
        0 => First::KeyState(variant),
        1 => First::Rollover(variant),
        2 => First::CoSigns(variant),
        _ => First::Lost(variant),
    })
}

/// Up to three `KeyState`s, with at most one reveal among them.
fn arb_steps() -> impl Strategy<Value = Vec<Step>> {
    (0_usize..4, proptest::option::of(0_usize..4)).prop_map(|(key_states, reveal_at)| {
        let mut steps = vec![Step::KeyState; key_states];
        if let Some(at) = reveal_at {
            steps.insert(at.min(key_states), Step::Reveal);
        }
        steps
    })
}

fn arb_suffix() -> impl Strategy<Value = SuffixPlan> {
    (arb_first(), arb_steps()).prop_map(|(first, steps)| SuffixPlan { first, steps })
}

/// A suffix under construction: the chain so far, the snapshot its next
/// `KeyState` changes, and the key its standing commitment names.
struct Branch {
    base: Base,
    snapshot: KeyStateSnapshot,
    next: [u8; 33],
    key_states: u32,
}

impl Branch {
    fn push(&mut self, ring: &Ring, preimage: &EventPreimage, root: Vec<[u8; 33]>) -> TestResult {
        let unit = sign_on(ring, &self.base, preimage)?;
        self.base = self.base.then(&Wire::of(preimage).fields(), unit, root);
        Ok(())
    }

    fn key_state(&mut self, ring: &Ring) -> TestResult {
        self.key_states += 1;
        let mut snapshot = self.snapshot.clone();
        snapshot.witnessing_interval = 9_000 + 300 * self.key_states;
        let preimage = key_state_on(&self.base, snapshot.clone());
        self.push(ring, &preimage, self.base.root.clone())?;
        self.snapshot = snapshot;
        Ok(())
    }

    fn reveal(&mut self, ring: &Ring) -> TestResult {
        let fresh = point("rank-fresh-commitment");
        let preimage = EventPreimage::commitment_rollover(CommitmentRolloverFields {
            identifier: self.base.identifier,
            sequence: self.base.len(),
            predecessor_digest: self.base.head,
            reveal_group: group(&[0]),
            standing_root_group: group(&[0]),
            revealed_keys: vec![self.next],
            continuation: fixes(&[fresh], 1),
        });
        self.push(ring, &preimage, self.base.root.clone())?;
        self.next = fresh;
        Ok(())
    }
}

/// A snapshot naming only the `Current` keys of `snapshot`, at `interval`.
fn current_only(snapshot: &KeyStateSnapshot, interval: u32) -> KeyStateSnapshot {
    let mut out = snapshot.clone();
    out.keys
        .retain(|entry| entry.condition == KeyCondition::Current);
    out.witnessing_interval = interval;
    out
}

/// An edit giving a recovery's own snapshot the variant's interval.
fn interval_edit(variant: u8) -> impl FnOnce(&mut EventPreimage) {
    move |preimage: &mut EventPreimage| {
        if variant > 0
            && let Some(snapshot) = preimage.key_state.as_mut()
        {
            snapshot.witnessing_interval = 3_600 + 600 * u32::from(variant);
        }
    }
}

/// Every prefix of `plan`'s suffix on Vector 41, the first event's chain
/// first.
fn build(ring: &Ring, plan: &SuffixPlan) -> Result<Vec<Base>, Error> {
    let v41 = v41()?;
    let v41_snapshot = v41_changed()?;
    let mut branch = Branch {
        base: v41.clone(),
        snapshot: v41_snapshot.clone(),
        next: v41_next()?,
        key_states: 0,
    };
    match plan.first {
        First::KeyState(variant) => {
            let mut snapshot = v41_snapshot;
            snapshot.witnessing_interval = 7_200 + 600 * u32::from(variant);
            let preimage = key_state_on(&v41, snapshot.clone());
            branch.push(ring, &preimage, v41.root)?;
            branch.snapshot = snapshot;
        }
        First::Rollover(variant) => {
            let label = ROLLOVER_NEXT[usize::from(variant)];
            let preimage = v53_with(|preimage| {
                if variant > 0 {
                    preimage.continuation = Some(fixes(&[point(label)], 1));
                }
            })?;
            branch.push(ring, &preimage, v41.root)?;
            branch.next = point(label);
        }
        First::CoSigns(variant) => {
            let preimage = v54_with(interval_edit(variant))?;
            let snapshot = preimage.key_state.clone().ok_or("V54 carries a snapshot")?;
            branch.push(ring, &preimage, vec![point("scp-25-recovery-cosigns-root")])?;
            branch.snapshot = current_only(&snapshot, snapshot.witnessing_interval);
            branch.next = point("scp-25-recovery-cosigns-next");
        }
        First::Lost(variant) => {
            let preimage = v55_with(interval_edit(variant))?;
            let snapshot = preimage.key_state.clone().ok_or("V55 carries a snapshot")?;
            branch.push(ring, &preimage, vec![point("scp-25-recovery-lost-root")])?;
            branch.snapshot = current_only(&snapshot, snapshot.witnessing_interval);
            branch.next = point("scp-25-recovery-lost-next");
        }
    }
    let mut prefixes = vec![branch.base.clone()];
    for step in &plan.steps {
        match step {
            Step::KeyState => branch.key_state(ring)?,
            Step::Reveal => branch.reveal(ring)?,
        }
        prefixes.push(branch.base.clone());
    }
    Ok(prefixes)
}

/// A rank-3 suffix on Vector 41 that no generated suffix equals.
fn comparator(ring: &Ring) -> Result<ValidatedChain, Error> {
    let v41 = v41()?;
    let mut snapshot = v41_changed()?;
    snapshot.witnessing_interval = 30_000;
    let preimage = key_state_on(&v41, snapshot);
    let unit = sign_on(ring, &v41, &preimage)?;
    chain_of(&v41.then(&Wire::of(&preimage).fields(), unit, v41.root.clone()))
}

fn diverged(pairing: ChainPairing) -> Result<Divergence, Error> {
    match pairing {
        ChainPairing::Diverged(divergence) => Ok(divergence),
        other => Err(format!("expected a divergence, got {other:?}").into()),
    }
}

fn fail(error: &Error) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

/// AC1: once a suffix reveals C, extending it never changes its rank, and
/// every prefix of it carries the rank the model gives.
fn rank_is_fixed(plan: &SuffixPlan) -> TestResult {
    let ring = Ring::new()?;
    let other = comparator(&ring)?;
    let mut fixed = None;
    for (index, base) in build(&ring, plan)?.iter().enumerate() {
        let divergence = diverged(pair_chains(&chain_of(base)?, &other)?)?;
        let rank = divergence.ranks[0];
        assert_eq!(rank, plan.rank(index + 1), "{plan:?} at {index}");
        assert_eq!(divergence.ranks[1], ForkRank::Rank3);
        assert_eq!(divergence.fork_position, 1);
        assert_eq!(divergence.shared_prefix_head, array::<32>(V41_DIGEST)?);
        match fixed {
            Some(fixed) => assert_eq!(rank, fixed, "{plan:?} changed rank at {index}"),
            None if rank != ForkRank::Rank3 => fixed = Some(rank),
            None => {}
        }
    }
    Ok(())
}

/// AC1's must-fail input: Vector 55 then a root-signed rollover of the
/// commitment Vector 55 itself fixed stays rank 2.
#[test]
fn lost_recovery_then_its_own_rollover_stays_rank_2() -> TestResult {
    rank_is_fixed(&SuffixPlan {
        first: First::Lost(0),
        steps: vec![Step::Reveal, Step::KeyState],
    })
}

/// A rank-3 suffix ranks 1 once it reveals Vector 41's commitment under
/// Vector 41's root.
#[test]
fn key_state_then_root_signed_reveal_ranks_1() -> TestResult {
    rank_is_fixed(&SuffixPlan {
        first: First::KeyState(0),
        steps: vec![Step::KeyState, Step::Reveal, Step::KeyState],
    })
}

/// Every pairing and resolution of `chains` in every order.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for index in 0..items.len() {
        let mut rest = items.to_vec();
        let item = rest.remove(index);
        for mut tail in permutations(&rest) {
            tail.insert(0, item.clone());
            out.push(tail);
        }
    }
    out
}

/// AC2: `resolve_set` reads the set, never the input order.
fn ignores_input_order(plans: &[SuffixPlan]) -> TestResult {
    let ring = Ring::new()?;
    let mut chains = Vec::new();
    for plan in plans {
        let bases = build(&ring, plan)?;
        chains.push(chain_of(bases.last().ok_or("a suffix has a first event")?)?);
    }
    let expected = resolve_set(&chains)?;
    if let SetResolution::Tie { heads, .. } = &expected {
        assert!(heads.windows(2).all(|pair| pair[0] < pair[1]), "{heads:?}");
    }
    for order in permutations(&chains) {
        assert_eq!(resolve_set(&order)?, expected, "{plans:?}");
    }
    Ok(())
}

/// AC3: the accepted chain after every frame of the suffixes has arrived,
/// in a prefix-closed order `choices` draws: R6's winner where one exists,
/// otherwise the undefeated chain whose first suffix frame arrived first.
fn accepted_ignores_frame_order(plans: &[SuffixPlan], choices: &[u8]) -> TestResult {
    let ring = Ring::new()?;
    let mut frames: Vec<Vec<ValidatedChain>> = Vec::new();
    for plan in plans {
        frames.push(
            build(&ring, plan)?
                .iter()
                .map(chain_of)
                .collect::<Result<_, _>>()?,
        );
    }
    let mut holder = AcceptedChainHolder::new();
    assert_eq!(
        holder.hold(chain_of(&v41()?)?)?,
        HoldOutcome::AcceptedExtended
    );
    let mut delivered = vec![0_usize; frames.len()];
    let mut first_arrival = vec![usize::MAX; frames.len()];
    let mut choices = choices.iter().cycle();
    for arrival in 0.. {
        let open: Vec<usize> = (0..frames.len())
            .filter(|&suffix| delivered[suffix] < frames[suffix].len())
            .collect();
        if open.is_empty() {
            break;
        }
        let pick = usize::from(*choices.next().ok_or("choices")?) % open.len();
        let suffix = open[pick];
        if delivered[suffix] == 0 {
            first_arrival[suffix] = arrival;
        }
        let outcome = holder.hold(frames[suffix][delivered[suffix]].clone())?;
        assert_ne!(outcome, HoldOutcome::AlreadyHeld, "{plans:?}");
        delivered[suffix] += 1;
    }
    let leaves: Vec<ValidatedChain> = frames
        .iter()
        .map(|chains| chains.last().cloned().ok_or("a suffix has a first event"))
        .collect::<Result<_, _>>()?;
    let expected = match resolve_set(&leaves)? {
        SetResolution::Winner { head } => head,
        SetResolution::Tie { heads, .. } => leaves
            .iter()
            .enumerate()
            .filter(|(_, leaf)| heads.contains(&leaf.head_digest()))
            .min_by_key(|(suffix, _)| first_arrival[*suffix])
            .map(|(_, leaf)| leaf.head_digest())
            .ok_or("a tie names a head")?,
        SetResolution::Empty => return Err("suffixes resolve".into()),
    };
    let accepted = holder.accepted().ok_or("the holder holds a chain")?;
    assert_eq!(
        accepted.head_digest(),
        expected,
        "{plans:?} {first_arrival:?}"
    );
    assert_eq!(
        holder.held().count(),
        plans.len(),
        "one held chain per suffix"
    );
    Ok(())
}

/// Two to four suffixes with distinct first events.
fn arb_distinct_suffixes() -> impl Strategy<Value = Vec<SuffixPlan>> {
    let firsts: Vec<First> = (0_u8..3)
        .flat_map(|variant| {
            [
                First::KeyState(variant),
                First::Rollover(variant),
                First::CoSigns(variant),
                First::Lost(variant),
            ]
        })
        .collect();
    proptest::sample::subsequence(firsts, 2..=4).prop_flat_map(|firsts| {
        let count = firsts.len();
        proptest::collection::vec(arb_steps(), count).prop_map(move |steps| {
            firsts
                .iter()
                .zip(steps)
                .map(|(first, steps)| SuffixPlan {
                    first: *first,
                    steps,
                })
                .collect()
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn rank_is_fixed_once_suffix_reveals(plan in arb_suffix()) {
        rank_is_fixed(&plan).map_err(|error| fail(&error))?;
    }

    #[test]
    fn resolve_set_ignores_input_order(
        plans in proptest::collection::vec(arb_suffix(), 2..=4),
    ) {
        ignores_input_order(&plans).map_err(|error| fail(&error))?;
    }

    #[test]
    fn accepted_chain_ignores_arrival_order_except_first_held_tie(
        plans in arb_distinct_suffixes(),
        choices in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        accepted_ignores_frame_order(&plans, &choices).map_err(|error| fail(&error))?;
    }
}

/// AC3's must-fail inputs, fixed: two rank-1 suffixes tie terminally, and
/// the one whose first frame arrived first stays accepted while the other
/// extends before and after it.
#[test]
fn held_first_tie_survives_extensions_in_any_frame_order() -> TestResult {
    let plans = [
        SuffixPlan {
            first: First::Rollover(1),
            steps: vec![Step::KeyState, Step::KeyState],
        },
        SuffixPlan {
            first: First::CoSigns(0),
            steps: vec![Step::KeyState],
        },
    ];
    // A first, then B, then A's extensions last: under head-digest identity
    // A's extensions would count as received after B.
    accepted_ignores_frame_order(&plans, &[0, 1, 1, 0, 0])?;
    // B first, then A and its extensions: B stays.
    accepted_ignores_frame_order(&plans, &[1, 0, 0, 0, 0])
}

/// AC7: Vector 54 (rank 1) beats Vector 55 (rank 2) at fork position 1, in
/// either argument order and either input order.
#[test]
fn vector_54_beats_vector_55_in_either_order() -> TestResult {
    let v54 = chain_of(&v41_v54()?)?;
    let v55 = chain_of(&v41_v55()?)?;
    let v41_digest: [u8; 32] = array(V41_DIGEST)?;
    let v54_digest: [u8; 32] = array(V54_DIGEST)?;
    assert_eq!(
        pair_chains(&v54, &v55)?,
        ChainPairing::Diverged(Divergence {
            shared_prefix_head: v41_digest,
            fork_position: 1,
            ranks: [ForkRank::Rank1, ForkRank::Rank2],
        })
    );
    assert_eq!(
        pair_chains(&v55, &v54)?,
        ChainPairing::Diverged(Divergence {
            shared_prefix_head: v41_digest,
            fork_position: 1,
            ranks: [ForkRank::Rank2, ForkRank::Rank1],
        })
    );
    for chains in [[v54.clone(), v55.clone()], [v55, v54]] {
        assert_eq!(
            resolve_set(&chains)?,
            SetResolution::Winner { head: v54_digest }
        );
    }
    Ok(())
}

/// R9 at a store: Vector 54 displaces an earlier-held Vector 55, and a later
/// Vector 55 is held as a rank-2 divergent suffix.
#[test]
fn holder_accepts_vector_54_in_either_arrival_order() -> TestResult {
    let v41 = chain_of(&v41()?)?;
    let v54 = chain_of(&v41_v54()?)?;
    let v55 = chain_of(&v41_v55()?)?;
    let v41_digest: [u8; 32] = array(V41_DIGEST)?;
    let v54_digest: [u8; 32] = array(V54_DIGEST)?;
    let v55_digest: [u8; 32] = array(V55_DIGEST)?;

    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.accepted(), None);
    assert_eq!(holder.hold(v55.clone())?, HoldOutcome::AcceptedExtended);
    assert_eq!(holder.hold(v41.clone())?, HoldOutcome::AlreadyHeld);
    assert_eq!(holder.hold(v55.clone())?, HoldOutcome::AlreadyHeld);
    let HoldOutcome::AcceptedReplaced { displaced } = holder.hold(v54.clone())? else {
        return Err("Vector 54 displaces Vector 55".into());
    };
    assert_eq!(displaced.head, v55_digest);
    assert_eq!(displaced.rank, ForkRank::Rank2);
    assert_eq!(displaced.shared_prefix_head, v41_digest);
    assert_eq!(displaced.fork_position, 1);
    let v55_unit_len = super::chain_support::v41_v55()?
        .units
        .last()
        .map(Vec::len)
        .ok_or("V55 has a unit")?;
    assert_eq!(displaced.bytes, u64::try_from(v55_unit_len)?);
    assert_eq!(
        holder.accepted().map(ValidatedChain::head_digest),
        Some(v54_digest)
    );

    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.hold(v41)?, HoldOutcome::AcceptedExtended);
    assert_eq!(holder.hold(v54)?, HoldOutcome::AcceptedExtended);
    assert_eq!(
        holder.hold(v55)?,
        HoldOutcome::HeldDivergent {
            rank: ForkRank::Rank2
        }
    );
    assert_eq!(
        holder.accepted().map(ValidatedChain::head_digest),
        Some(v54_digest)
    );
    Ok(())
}

/// R7: two rank-3 suffixes tie pending, two rank-1 suffixes tie terminally,
/// and the class is the strictest pair's.
#[test]
fn tie_class_is_the_strictest_pairs() -> TestResult {
    let ring = Ring::new()?;
    let leaf = |plan: SuffixPlan| -> Result<ValidatedChain, Error> {
        chain_of(build(&ring, &plan)?.last().ok_or("a first event")?)
    };
    let key_state = |variant| SuffixPlan {
        first: First::KeyState(variant),
        steps: Vec::new(),
    };
    let pending = resolve_set(&[leaf(key_state(0))?, leaf(key_state(1))?])?;
    let SetResolution::Tie {
        class,
        heads,
        fork_position,
        ..
    } = pending
    else {
        return Err(format!("expected a tie, got {pending:?}").into());
    };
    assert_eq!(class, TieClass::Rank3Pending);
    assert_eq!(heads.len(), 2);
    assert_eq!(fork_position, 1);

    let rollover = SuffixPlan {
        first: First::Rollover(0),
        steps: Vec::new(),
    };
    let cosigns = SuffixPlan {
        first: First::CoSigns(0),
        steps: Vec::new(),
    };
    let terminal = resolve_set(&[leaf(rollover)?, leaf(cosigns)?, leaf(key_state(0))?])?;
    let SetResolution::Tie { class, heads, .. } = terminal else {
        return Err(format!("expected a tie, got {terminal:?}").into());
    };
    assert_eq!(class, TieClass::Rank1Terminal);
    assert_eq!(heads.len(), 2, "the rank-3 suffix is beaten");
    Ok(())
}

/// Chains of two identifiers share no prefix: every entry point refuses
/// them with a typed error and the holder keeps what it held.
#[test]
fn chains_of_two_identifiers_are_refused() -> TestResult {
    let v41 = chain_of(&v41()?)?;
    let v42 = chain_of(&v42()?)?;
    let unrelated = UnrelatedChains {
        left: v41.identifier(),
        right: v42.identifier(),
    };
    assert_eq!(pair_chains(&v41, &v42), Err(unrelated));
    assert!(resolve_set(&[v41.clone(), v42.clone()]).is_err());
    let mut holder = AcceptedChainHolder::new();
    holder.hold(v41.clone())?;
    assert_eq!(
        holder.hold(v42.clone()),
        Err(UnrelatedChains {
            left: v42.identifier(),
            right: v41.identifier(),
        })
    );
    assert_eq!(holder.held().count(), 1);
    assert_eq!(holder.accepted(), Some(&v41));
    assert_eq!(resolve_set(&[])?, SetResolution::Empty);
    Ok(())
}
