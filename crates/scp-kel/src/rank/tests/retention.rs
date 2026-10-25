//! R9's retention: identity by digest, extension in place, the held copy,
//! both bounds, the eviction rule, persistence, and the holder that keeps
//! its divergent suffixes under them (`09-security-model.md` §9.7.4.2 R9),
//! over chains that fork from Vector 41.
//!
//! The accepted basis is Vector 41 followed by owner 0's `KeyState`, so a
//! suffix forking at Vector 41 ranks by its own first reveal: rank 1 for a
//! rollover or a `{CoSigns}` recovery, rank 2 for a `{Lost}` recovery and
//! rank 3 for none.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRng, TestRunner};

use super::super::holder::{AcceptedChainHolder, HoldOutcome};
use super::super::retention::{Bounds, Guard, RetainedSuffix, Slot, plan_evictions};
use super::super::{
    Admission, AdoptedBasis, BasisKind, ForkRank, PersistedSuffix, Rerank, RestoreError,
    RetentionBasis, RetentionError, RetentionSet,
};
use super::chain_support::{group, identifier_of, sign_inception, signed_of, vector};
use super::fixtures::V41_PREIMAGE;
use super::{
    Branch, Error, Keys, Kind, TestResult, Wire, assertion_copies, chain_of, first_held,
    key_state_on, v41_digest,
};
use super::{v41, v41_changed};
use crate::ValidatedChain;

/// The accepted basis: Vector 41, then owner 0's `KeyState`.
fn basis(keys: &mut Keys) -> Result<Branch, Error> {
    Branch::of(keys, &[Kind::KeyState], 0)
}

/// An accepted basis every rank-2 and rank-3 fork at Vector 41 loses to:
/// Vector 41, then owner 0's root-signed rollover. No such fork is a tied
/// head, so R9's tied-head rule leaves the rank rule and the tie-break
/// alone to decide its eviction.
fn beating_basis(keys: &mut Keys) -> Result<Branch, Error> {
    Branch::of(keys, &[Kind::Reveal], 0)
}

fn accepted(branch: &Branch) -> RetentionBasis {
    RetentionBasis::Accepted(branch.chain.clone())
}

/// A set with R9's registered bounds against `basis`.
fn registered(basis: &Branch) -> RetentionSet {
    RetentionSet::new(accepted(basis))
}

/// A set against `basis` with the bounds a test names.
fn bounded(basis: &Branch, suffixes: u32, bytes: u64) -> RetentionSet {
    RetentionSet::with_bounds(accepted(basis), Bounds { suffixes, bytes })
}

/// The heads the set retains.
fn heads(set: &RetentionSet) -> BTreeSet<[u8; 32]> {
    set.suffixes().iter().map(RetainedSuffix::head).collect()
}

/// The retained suffix whose head is `head`.
fn by_head(set: &RetentionSet, head: [u8; 32]) -> Result<RetainedSuffix, Error> {
    Ok(set
        .suffixes()
        .iter()
        .find(|suffix| suffix.head() == head)
        .cloned()
        .ok_or("a retained suffix")?)
}

/// Admits `chain` and expects it retained with no eviction.
fn retain(set: &mut RetentionSet, chain: &ValidatedChain) -> TestResult {
    match set.admit(chain.clone())? {
        Admission::Retained { evicted, .. } if evicted.is_empty() => Ok(()),
        other => Err(format!("expected a plain retention, got {other:?}").into()),
    }
}

/// The bytes the byte bound counts for a suffix forking at Vector 41.
fn suffix_bytes(branch: &Branch) -> u64 {
    branch.unit_lens.iter().skip(1).sum()
}

/// The length of the branch's last unit.
fn tail(branch: &Branch) -> u64 {
    branch.unit_lens.last().copied().unwrap_or(0)
}

/// The test's own model of R9's byte tally: the unit lengths of every event
/// `chains` hold that `basis` does not, each digest once.
fn distinct_bytes<'c>(
    basis: &ValidatedChain,
    chains: impl IntoIterator<Item = &'c ValidatedChain>,
) -> u64 {
    let on_basis: BTreeSet<[u8; 32]> = basis.events().map(|event| event.digest).collect();
    let mut lens = BTreeMap::new();
    for chain in chains {
        for event in chain.events() {
            if !on_basis.contains(&event.digest) {
                lens.insert(event.digest, event.unit.len());
            }
        }
    }
    lens.values().map(|len| *len as u64).sum()
}

/// R9: an extension "replaces what the party holds, its bytes count once at
/// the extended length, and it keeps the moment the party first held or
/// observed it". Nine extensions of one rank-1 suffix take one slot.
///
/// Mutant (run, then restored): `place` ignores `RightPrefixOfLeft`, so each
/// extension takes a slot of its own; the ninth is refused at the count
/// bound and this test fails.
#[test]
fn extending_a_rank_one_suffix_nine_times_keeps_one_slot() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut set = registered(&basis);
    let mut suffix = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    retain(&mut set, &suffix.chain)?;
    for _ in 0..9 {
        let before = suffix.head();
        suffix.push(&mut keys, Kind::KeyState, 1)?;
        assert_eq!(
            set.admit(suffix.chain.clone())?,
            Admission::Extended {
                rank: ForkRank::Rank1,
                replaced: before,
                evicted: Vec::new(),
            }
        );
    }
    let [only] = set.suffixes() else {
        return Err(format!("{} slots", set.suffixes().len()).into());
    };
    assert_eq!(only.head(), suffix.head());
    assert_eq!(only.observed(), 1);
    assert_eq!(set.retained_bytes(), suffix_bytes(&suffix));
    Ok(())
}

/// R9: "breaking a tie among equal ranks by evicting the suffix it observed
/// most recently … Evicting the earliest-observed equal-rank suffix would
/// evict the owner's own chain first". The owner's rank-2 suffix, extended
/// after seven attacker suffixes arrived, keeps its first moment, so a
/// rank-2 candidate at the full count bound evicts the latest attacker
/// suffix. The basis beats every suffix, so none is a tied head.
///
/// Mutants (each run, then restored): an extension takes the next moment
/// instead of inheriting one, so the owner's suffix is the most recent and
/// is evicted; and `place` plans without excluding the extended suffix's
/// slot, so the extension at the full count bound evicts a suffix.
#[test]
fn owner_extension_keeps_its_moment_so_the_latest_attacker_is_evicted() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = beating_basis(&mut keys)?;
    let mut set = registered(&basis);
    let mut owner = Branch::of(&mut keys, &[Kind::Lost], 1)?;
    retain(&mut set, &owner.chain)?;
    let mut attackers = Vec::new();
    for attacker in 2..=8 {
        let branch = Branch::of(&mut keys, &[Kind::Lost], attacker)?;
        retain(&mut set, &branch.chain)?;
        attackers.push(branch.head());
    }
    assert_eq!(set.suffixes().len(), 8);
    let before = owner.head();
    owner.push(&mut keys, Kind::KeyState, 1)?;
    assert_eq!(
        set.admit(owner.chain.clone())?,
        Admission::Extended {
            rank: ForkRank::Rank2,
            replaced: before,
            evicted: Vec::new(),
        }
    );
    let late = Branch::of(&mut keys, &[Kind::Lost], 9)?;
    let latest = *attackers.last().ok_or("an attacker")?;
    assert_eq!(
        set.admit(late.chain)?,
        Admission::Retained {
            rank: ForkRank::Rank2,
            evicted: vec![latest],
        }
    );
    assert!(heads(&set).contains(&owner.head()));
    Ok(())
}

/// R9: "An extension the retention bound refuses leaves the held suffix in
/// place and counts in the residue."
///
/// Mutant (run, then restored): a refused extension removes the suffix it
/// extends.
#[test]
fn refused_extension_leaves_the_prefix_held() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut held = Branch::of(&mut keys, &[Kind::Lost], 1)?;
    let rank_one = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    let mut set = bounded(&basis, 8, suffix_bytes(&held) + suffix_bytes(&rank_one));
    retain(&mut set, &held.chain)?;
    retain(&mut set, &rank_one.chain)?;
    let before = set.clone();
    let prefix = held.head();
    held.push(&mut keys, Kind::KeyState, 1)?;
    assert_eq!(
        set.admit(held.chain.clone())?,
        Admission::Refused {
            rank: ForkRank::Rank2
        }
    );
    assert_eq!(set, before);
    assert!(heads(&set).contains(&prefix));
    Ok(())
}

/// R9's eviction rank reads the accepted chain, so an adoption that moves
/// it re-reads every rank and every fork-relative byte tally, and the
/// displaced accepted chain becomes a suffix. Persisting and restoring the
/// moved set gives back the basis, every suffix and every moment.
///
/// A is Vector 41 → a1 → a2, each owner 0's `KeyState`; S forks from A at
/// a2 with a `{Lost}` recovery; W forks at Vector 41 with a rollover. Past
/// W's fork, A and S share a1, which the byte bound counts once.
///
/// Mutant (run, then restored): `persisted` cuts every chain's units
/// before its first event, the inception, so restore finds no inception.
#[test]
fn persist_restore_after_adoption() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState, Kind::KeyState], 0)?;
    let mut s = Branch::v41()?;
    s.push(&mut keys, Kind::KeyState, 0)?;
    s.push(&mut keys, Kind::Lost, 3)?;
    let w = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    assert_eq!(s.digests.get(1), a.digests.get(1), "S shares a1 with A");

    let mut set = registered(&a);
    assert_eq!(
        set.admit(s.chain.clone())?,
        Admission::Retained {
            rank: ForkRank::Rank2,
            evicted: Vec::new(),
        }
    );
    let [held] = set.suffixes() else {
        return Err("one suffix".into());
    };
    assert_eq!(held.fork_position(), 2);
    assert_eq!(set.retained_bytes(), tail(&s));

    assert_eq!(set.rerank(accepted(&w))?, Rerank::default());
    let displaced = by_head(&set, a.head())?;
    assert_eq!(
        (
            displaced.rank(),
            displaced.fork_position(),
            displaced.observed()
        ),
        (ForkRank::Rank3, 1, 0)
    );
    let moved = by_head(&set, s.head())?;
    assert_eq!(
        (moved.rank(), moved.fork_position(), moved.observed()),
        (ForkRank::Rank2, 1, 1)
    );
    assert_eq!(set.retained_bytes(), suffix_bytes(&a) + tail(&s));
    assert_eq!(set.basis_observed(), 2);

    let saved = set.persisted();
    assert_eq!(saved.basis.kind, BasisKind::Accepted);
    assert_eq!(saved.basis.head, w.head());
    assert_eq!(saved.basis.observed, 2);
    let identifier = w.chain.identifier();
    let restored = RetentionSet::restore(
        &identifier,
        &saved,
        AdoptedBasis::Accepted { head: w.head() },
    )?;
    assert_eq!(restored, set);
    assert_eq!(restored.persisted(), saved);
    Ok(())
}

/// R9: "a party holding a valid event that receives a byte-different valid
/// event with the same digest keeps the copy it holds". A copy served
/// second, alone or under an extension, never displaces the held copy in
/// what the set persists.
///
/// Mutant (run, then restored): `held_copies` returns the candidate as
/// served, so the second copy reaches `persisted()`.
#[test]
fn byte_different_copy_served_second_never_displaces_the_held_copy() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let (preimage, first, second) = assertion_copies(&keys)?;
    assert_ne!(first, second);
    let v41 = v41()?;
    let fields = Wire::of(&preimage).fields();
    let held = v41.then(&fields, first.clone(), v41.root.clone());
    let copied = v41.then(&fields, second.clone(), v41.root.clone());
    let mut later = v41_changed()?;
    later.witnessing_interval = 7_400;
    let next = key_state_on(&copied, later);
    let next_unit = keys.sign(&copied, &next)?;
    let extension = copied.then(&Wire::of(&next).fields(), next_unit, v41.root);

    let mut set = registered(&basis);
    retain(&mut set, &chain_of(&held)?)?;
    assert_eq!(set.admit(chain_of(&copied)?)?, Admission::AlreadyHeld);
    assert!(matches!(
        set.admit(chain_of(&extension)?)?,
        Admission::Extended { .. }
    ));
    let units = set.persisted().units;
    assert!(units.iter().any(|unit| **unit == *first));
    assert!(units.iter().all(|unit| **unit != *second));
    let [suffix] = set.suffixes() else {
        return Err("one suffix".into());
    };
    let shared = suffix.chain().events().nth(1).ok_or("the shared event")?;
    assert_eq!(shared.unit, first.as_slice());
    Ok(())
}

/// R9's copy rule on a move: a new basis the set already holds events of
/// carries the held copy, so a byte-different copy served under the
/// adopted chain never reaches what the set persists.
///
/// Mutant (run, then restored): `move_to` takes the new basis as served.
#[test]
fn moved_basis_keeps_the_held_copy() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let (preimage, first, second) = assertion_copies(&keys)?;
    let v41 = v41()?;
    let fields = Wire::of(&preimage).fields();
    let held = v41.then(&fields, first.clone(), v41.root.clone());
    let copied = v41.then(&fields, second.clone(), v41.root.clone());
    let mut later = v41_changed()?;
    later.witnessing_interval = 7_400;
    let next = key_state_on(&copied, later);
    let next_unit = keys.sign(&copied, &next)?;
    let extension = copied.then(&Wire::of(&next).fields(), next_unit, v41.root);

    let mut set = registered(&basis);
    retain(&mut set, &chain_of(&held)?)?;
    let _ = set.rerank(RetentionBasis::Accepted(chain_of(&extension)?))?;
    let shared = set
        .basis()
        .chain()
        .events()
        .nth(1)
        .ok_or("the shared event")?;
    assert_eq!(shared.unit, first.as_slice());
    let units = set.persisted().units;
    assert!(units.iter().all(|unit| **unit != *second));
    Ok(())
}

/// R9: "A candidate the party can evict no suffix for is refused — a
/// rank-3 candidate against rank-2 suffixes alone, for one". The basis
/// beats every suffix, so the rank rule alone refuses.
///
/// Mutant (run, then restored): the planner drops "whose rank number is at
/// least the candidate's", so the rank-3 candidate evicts a rank-2 suffix.
#[test]
fn rank_three_candidate_against_eight_rank_two_suffixes_is_refused() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = beating_basis(&mut keys)?;
    let mut set = registered(&basis);
    for owner in 1..=8 {
        retain(
            &mut set,
            &Branch::of(&mut keys, &[Kind::Lost], owner)?.chain,
        )?;
    }
    let before = set.clone();
    let candidate = Branch::of(&mut keys, &[Kind::KeyState], 9)?;
    assert_eq!(
        set.admit(candidate.chain)?,
        Admission::Refused {
            rank: ForkRank::Rank3
        }
    );
    assert_eq!(set, before);
    Ok(())
}

/// R9: "breaking a tie among equal ranks by evicting the suffix it observed
/// most recently". The basis beats every suffix, so none is a tied head.
///
/// Mutant (run, then restored): the tie-break evicts the earliest-observed
/// suffix.
#[test]
fn equal_rank_eviction_takes_the_most_recently_observed() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = beating_basis(&mut keys)?;
    let mut set = registered(&basis);
    let mut latest = None;
    for owner in 1..=8 {
        let branch = Branch::of(&mut keys, &[Kind::KeyState], owner)?;
        retain(&mut set, &branch.chain)?;
        latest = Some(branch.head());
    }
    let candidate = Branch::of(&mut keys, &[Kind::KeyState], 9)?;
    assert_eq!(
        set.admit(candidate.chain)?,
        Admission::Retained {
            rank: ForkRank::Rank3,
            evicted: vec![latest.ok_or("a suffix")?],
        }
    );
    assert_eq!(set.suffixes().len(), 8);
    Ok(())
}

/// R9: "the verifier evicts the retained suffix carrying the highest rank
/// number": a rank-3 suffix observed first goes before rank-2 suffixes
/// observed after it.
///
/// Mutant (run, then restored): the planner orders victims by moment alone.
#[test]
fn rank_two_candidate_evicts_a_rank_three_suffix_first() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut set = registered(&basis);
    let rank_three = Branch::of(&mut keys, &[Kind::KeyState], 1)?;
    retain(&mut set, &rank_three.chain)?;
    for owner in 2..=8 {
        retain(
            &mut set,
            &Branch::of(&mut keys, &[Kind::Lost], owner)?.chain,
        )?;
    }
    let candidate = Branch::of(&mut keys, &[Kind::Lost], 9)?;
    assert_eq!(
        set.admit(candidate.chain)?,
        Admission::Retained {
            rank: ForkRank::Rank2,
            evicted: vec![rank_three.head()],
        }
    );
    Ok(())
}

/// R9: "a rank-1 candidate that would exceed the byte bound evicts rank-2
/// and rank-3 suffixes until it fits, and the verifier refuses it … only
/// where the rank-1 bytes alone, the candidate's included, would exceed
/// `MAX_RETAINED_BYTES`."
///
/// Mutant (run, then restored): the planner may evict a rank-1 suffix; the
/// over-bound candidate then evicts the retained rank-1 suffix instead of
/// being refused.
#[test]
fn rank_one_candidate_over_the_byte_bound_evicts_rank_two_and_three() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let rank_three = Branch::of(&mut keys, &[Kind::KeyState], 1)?;
    let rank_two = Branch::of(&mut keys, &[Kind::Lost], 2)?;
    let rank_one = Branch::of(&mut keys, &[Kind::Reveal], 3)?;
    // The candidate carries at least the rank-2 and rank-3 bytes, so the
    // bound below fits all three retained suffixes and fits the candidate
    // only once both are evicted.
    let mut candidate = Branch::of(&mut keys, &[Kind::CoSigns], 4)?;
    while suffix_bytes(&candidate) < suffix_bytes(&rank_three) + suffix_bytes(&rank_two) {
        candidate.push(&mut keys, Kind::KeyState, 4)?;
    }
    let rank_one_bytes = suffix_bytes(&rank_one) + suffix_bytes(&candidate);

    let mut set = bounded(&basis, 8, rank_one_bytes);
    for branch in [&rank_three, &rank_two, &rank_one] {
        retain(&mut set, &branch.chain)?;
    }
    assert_eq!(
        set.suffixes().len(),
        3,
        "the bound fits all three until the candidate"
    );
    assert_eq!(
        set.admit(candidate.chain.clone())?,
        Admission::Retained {
            rank: ForkRank::Rank1,
            evicted: vec![rank_three.head(), rank_two.head()],
        }
    );
    assert_eq!(
        heads(&set),
        BTreeSet::from([rank_one.head(), candidate.head()])
    );
    assert_eq!(set.retained_bytes(), rank_one_bytes);

    let mut tight = bounded(&basis, 8, rank_one_bytes - 1);
    for branch in [&rank_three, &rank_two, &rank_one] {
        retain(&mut tight, &branch.chain)?;
    }
    let before = tight.clone();
    assert_eq!(
        tight.admit(candidate.chain)?,
        Admission::Refused {
            rank: ForkRank::Rank1
        }
    );
    assert_eq!(tight, before, "a refusal evicts nothing");
    Ok(())
}

/// R9: "The byte bound counts each retained event once". Two rank-1
/// siblings share a rollover and three key states past Vector 41 and differ
/// in their last event: the second is admitted where the distinct bytes
/// fit, though the two suffixes' own bytes summed would not, and refused
/// one byte below.
///
/// Mutant (run, then restored): the tally sums each suffix's own bytes, so
/// the second sibling is refused at the distinct bound.
#[test]
fn rank_one_siblings_sharing_a_body_count_it_once() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let body = Branch::of(
        &mut keys,
        &[Kind::Reveal, Kind::KeyState, Kind::KeyState, Kind::KeyState],
        1,
    )?;
    let mut left = body.clone();
    left.push(&mut keys, Kind::KeyState, 2)?;
    let mut right = body.clone();
    right.push(&mut keys, Kind::KeyState, 3)?;
    let distinct = suffix_bytes(&body) + tail(&left) + tail(&right);
    assert!(distinct < suffix_bytes(&left) + suffix_bytes(&right));

    let mut set = bounded(&basis, 8, distinct);
    retain(&mut set, &left.chain)?;
    assert_eq!(
        set.admit(right.chain.clone())?,
        Admission::Retained {
            rank: ForkRank::Rank1,
            evicted: Vec::new(),
        }
    );
    assert_eq!(set.retained_bytes(), distinct);

    let mut tight = bounded(&basis, 8, distinct - 1);
    retain(&mut tight, &left.chain)?;
    assert_eq!(
        tight.admit(right.chain)?,
        Admission::Refused {
            rank: ForkRank::Rank1
        }
    );
    Ok(())
}

/// R9: an eviction frees only the events no kept suffix also holds. Two
/// rank-3 siblings share a body; evicting the later one frees its last
/// event alone, which does not fit the rank-2 candidate, so the planner
/// evicts the earlier sibling too. The report lists both in the order the
/// set held them.
///
/// Mutant (run, then restored): the tally sums each suffix's own bytes, so
/// evicting the later sibling frees the shared body as well and the
/// earlier one stays.
#[test]
fn evicting_a_sibling_frees_only_its_own_events() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let body = Branch::of(
        &mut keys,
        &[Kind::KeyState, Kind::KeyState, Kind::KeyState],
        1,
    )?;
    let mut left = body.clone();
    left.push(&mut keys, Kind::KeyState, 2)?;
    let mut right = body.clone();
    right.push(&mut keys, Kind::KeyState, 3)?;
    let distinct = suffix_bytes(&body) + tail(&left) + tail(&right);
    let mut candidate = Branch::of(&mut keys, &[Kind::Lost], 4)?;
    while suffix_bytes(&candidate) <= tail(&right) {
        candidate.push(&mut keys, Kind::KeyState, 4)?;
    }
    assert!(suffix_bytes(&candidate) <= distinct);
    // The siblings' own bytes summed exceed the bound, so the mutant cannot
    // build this set; the bound counts the shared body once.
    let mut set = bounded(&basis, 8, distinct);
    retain(&mut set, &left.chain)?;
    retain(&mut set, &right.chain)?;
    assert_eq!(
        set.admit(candidate.chain.clone())?,
        Admission::Retained {
            rank: ForkRank::Rank2,
            evicted: vec![left.head(), right.head()],
        }
    );
    assert_eq!(heads(&set), BTreeSet::from([candidate.head()]));
    Ok(())
}

/// R9: "An arrival every event of which the party already holds changes
/// nothing", compared by digest: the same suffix, a prefix of it, and a
/// prefix of the basis.
///
/// Mutant (run, then restored): `place` skips the identity arm of the
/// suffix loop, so the same suffix arriving again takes a second slot.
#[test]
fn same_digest_arrival_is_already_held() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut set = registered(&basis);
    let suffix = Branch::of(&mut keys, &[Kind::Lost, Kind::KeyState], 1)?;
    retain(&mut set, &suffix.chain)?;
    let before = set.clone();
    let prefix = suffix.chain.prefix(1).ok_or("the suffix's first event")?;
    for candidate in [
        suffix.chain.clone(),
        prefix,
        basis.chain,
        Branch::v41()?.chain,
    ] {
        assert_eq!(set.admit(candidate)?, Admission::AlreadyHeld);
    }
    assert_eq!(set, before);
    Ok(())
}

/// R9: an arrival extending the accepted chain "is that chain … extended",
/// which the caller adopts; the set refuses to retain it as a suffix, and a
/// chain of another identifier is unrelated. Both leave the set unchanged.
///
/// Mutant (run, then restored): `place` retains the accepted chain's
/// extension as a suffix past the accepted head.
#[test]
fn accepted_extension_and_other_identifier_are_typed_errors() -> TestResult {
    let mut keys = Keys::new()?;
    let mut extended = basis(&mut keys)?;
    let mut set = registered(&extended);
    retain(&mut set, &Branch::of(&mut keys, &[Kind::Lost], 1)?.chain)?;
    let before = set.clone();
    let head = extended.head();
    extended.push(&mut keys, Kind::KeyState, 0)?;
    assert_eq!(
        set.admit(extended.chain),
        Err(RetentionError::ExtendsAccepted { head })
    );
    assert_eq!(set, before);
    let other = chain_of(&super::v42()?)?;
    assert!(matches!(
        set.admit(other),
        Err(RetentionError::Unrelated(_))
    ));
    assert_eq!(set, before);
    Ok(())
}

/// R9: "Where a first-contact resolution returns `Contested`, which adopts
/// nothing, the shared prefix that `Contested` names … is the chain the
/// eviction rank and both retention bounds read." Each tied head extends
/// that prefix and is a divergent suffix past it, and the set persists the
/// prefix with them.
#[test]
fn contested_prefix_retains_the_tied_heads_past_it() -> TestResult {
    let mut keys = Keys::new()?;
    let prefix = Branch::v41()?;
    let left = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let right = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    let mut set = RetentionSet::new(RetentionBasis::ContestedPrefix(prefix.chain.clone()));
    for branch in [&left, &right] {
        assert_eq!(
            set.admit(branch.chain.clone())?,
            Admission::Retained {
                rank: ForkRank::Rank1,
                evicted: Vec::new(),
            }
        );
    }
    assert!(
        set.suffixes()
            .iter()
            .all(|suffix| suffix.fork_position() == 1)
    );
    let saved = set.persisted();
    assert_eq!(saved.basis.kind, BasisKind::ContestedPrefix);
    assert_eq!(saved.basis.head, prefix.head());
    let identifier = prefix.chain.identifier();
    assert_eq!(
        RetentionSet::restore(
            &identifier,
            &saved,
            AdoptedBasis::ContestedPrefix {
                head: prefix.head()
            }
        )?,
        set
    );
    Ok(())
}

/// `restore` takes the basis from the verifier's persisted verdict, never
/// from the persisted bytes: a basis of the other kind is refused either
/// way, a contested prefix persisted as an accepted basis included, and a
/// basis of the named kind at another head is refused.
///
/// Mutants (each run, then restored): `restore` compares only the kinds,
/// so a contested prefix at another head restores; and `restore` accepts
/// an accepted basis where the verdict names a contested prefix.
#[test]
fn restore_refuses_a_basis_the_verifier_did_not_adopt() -> TestResult {
    let mut keys = Keys::new()?;
    let prefix = Branch::v41()?;
    let mut set = RetentionSet::new(RetentionBasis::ContestedPrefix(prefix.chain.clone()));
    retain(&mut set, &Branch::of(&mut keys, &[Kind::Reveal], 1)?.chain)?;
    retain(&mut set, &Branch::of(&mut keys, &[Kind::Reveal], 2)?.chain)?;
    let identifier = prefix.chain.identifier();
    let saved = set.persisted();
    let contested = AdoptedBasis::ContestedPrefix {
        head: prefix.head(),
    };
    let mut flipped = saved.clone();
    flipped.basis.kind = BasisKind::Accepted;
    assert_eq!(
        RetentionSet::restore(&identifier, &flipped, contested),
        Err(RestoreError::BasisDisagrees {
            adopted: contested,
            kind: BasisKind::Accepted,
            head: prefix.head(),
        })
    );
    let accepted = AdoptedBasis::Accepted {
        head: prefix.head(),
    };
    assert_eq!(
        RetentionSet::restore(&identifier, &saved, accepted),
        Err(RestoreError::BasisDisagrees {
            adopted: accepted,
            kind: BasisKind::ContestedPrefix,
            head: prefix.head(),
        })
    );
    let elsewhere = AdoptedBasis::ContestedPrefix { head: [0x5a; 32] };
    assert_eq!(
        RetentionSet::restore(&identifier, &saved, elsewhere),
        Err(RestoreError::BasisDisagrees {
            adopted: elsewhere,
            kind: BasisKind::ContestedPrefix,
            head: prefix.head(),
        })
    );
    let basis = basis(&mut keys)?;
    let accepted_set = registered(&basis).persisted();
    // An accepted basis restored where the verifier's verdict names a
    // contested prefix, a first contact's among them.
    let first_contact = AdoptedBasis::ContestedPrefix { head: basis.head() };
    assert_eq!(
        RetentionSet::restore(&identifier, &accepted_set, first_contact),
        Err(RestoreError::BasisDisagrees {
            adopted: first_contact,
            kind: BasisKind::Accepted,
            head: basis.head(),
        })
    );
    let stale = AdoptedBasis::Accepted { head: v41_digest() };
    assert_eq!(
        RetentionSet::restore(&identifier, &accepted_set, stale),
        Err(RestoreError::BasisDisagrees {
            adopted: stale,
            kind: BasisKind::Accepted,
            head: basis.head(),
        })
    );
    Ok(())
}

/// `restore` refuses an accepted basis that R9 would not hold as accepted
/// over its retained suffixes: A, owner 0's `KeyState` past Vector 41,
/// against a retained rollover X, which R6 ranks 1 to A's 3. `admit` keeps
/// X without comparing it to the basis; the holder would have adopted it.
///
/// Mutant (run, then restored): `restore` skips the tournament, so the
/// beaten basis restores.
#[test]
fn restore_refuses_an_accepted_basis_a_suffix_beats() -> TestResult {
    let mut keys = Keys::new()?;
    let a = basis(&mut keys)?;
    let x = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let mut set = registered(&a);
    retain(&mut set, &x.chain)?;
    let identifier = a.chain.identifier();
    assert_eq!(
        RetentionSet::restore(
            &identifier,
            &set.persisted(),
            AdoptedBasis::Accepted { head: a.head() }
        ),
        Err(RestoreError::AcceptedDisplaced {
            accepted: a.head(),
            by: x.head(),
        })
    );
    Ok(())
}

/// R9 adopts a contested prefix's successor: moving a contested-prefix
/// basis to an accepted chain off it re-admits the old prefix first, at its
/// moment, and the tied head that extends it then replaces it in place and
/// keeps that moment ("it keeps the moment the party first held or
/// observed it"); the other tied head keeps its own, and the new accepted
/// chain, which no held chain leads, takes the next moment.
///
/// P is Vector 41 → owner 0's `KeyState`; the tied heads L and R each add a
/// rollover; W forks at Vector 41 with a rollover of its own.
///
/// Mutants (each run, then restored): an extension takes its own moment
/// instead of the extended suffix's, so L reads 1; and the new basis takes
/// moment zero instead of the next moment.
#[test]
fn contested_prefix_moves_to_an_accepted_chain_with_each_moment() -> TestResult {
    let mut keys = Keys::new()?;
    let prefix = basis(&mut keys)?;
    let mut left = prefix.clone();
    left.push(&mut keys, Kind::Reveal, 1)?;
    let mut right = prefix.clone();
    right.push(&mut keys, Kind::Reveal, 2)?;
    let w = Branch::of(&mut keys, &[Kind::Reveal], 5)?;
    let mut set = RetentionSet::new(RetentionBasis::ContestedPrefix(prefix.chain));
    retain(&mut set, &left.chain)?;
    retain(&mut set, &right.chain)?;
    assert_eq!(set.basis_observed(), 0);
    assert_eq!(by_head(&set, left.head())?.fork_position(), 2);

    assert_eq!(set.rerank(accepted(&w))?, Rerank::default());
    assert_eq!(set.basis(), &accepted(&w));
    assert_eq!(set.basis_observed(), 3);
    assert_eq!(heads(&set), BTreeSet::from([left.head(), right.head()]));
    for (branch, observed) in [(&left, 0), (&right, 2)] {
        let suffix = by_head(&set, branch.head())?;
        assert_eq!(
            (suffix.rank(), suffix.fork_position(), suffix.observed()),
            (ForkRank::Rank1, 1, observed)
        );
    }
    Ok(())
}

/// `rerank`'s report at small bounds, where the adoption extends a retained
/// suffix X. The new basis takes X's moment, and X, which it leads, is
/// already held. The displaced accepted chain A, a large `{Lost}` suffix
/// against W, is re-admitted first and fills the byte bound, so the two
/// rank-3 suffixes after it are refused and the rank-2 suffix after them
/// evicts A.
///
/// Mutants (each run, then restored): `rerank` drops refused heads; drops
/// already-held heads; drops evicted heads; and gives the new basis the
/// next moment instead of X's.
#[test]
fn rerank_reports_already_held_evicted_and_refused() -> TestResult {
    let mut keys = Keys::new()?;
    let x = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let s2 = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    let s3 = Branch::of(&mut keys, &[Kind::KeyState], 3)?;
    let s4 = Branch::of(&mut keys, &[Kind::Lost], 4)?;
    let others = [&x, &s2, &s3, &s4].map(suffix_bytes).iter().sum::<u64>();
    let mut a = Branch::of(&mut keys, &[Kind::Lost], 0)?;
    while suffix_bytes(&a) < others {
        a.push(&mut keys, Kind::KeyState, 0)?;
    }
    let mut set = bounded(&a, 8, suffix_bytes(&a));
    for branch in [&x, &s2, &s3, &s4] {
        retain(&mut set, &branch.chain)?;
    }
    let mut w = x.clone();
    w.push(&mut keys, Kind::KeyState, 1)?;

    assert_eq!(
        set.rerank(accepted(&w))?,
        Rerank {
            already_held: vec![x.head()],
            evicted: vec![a.head()],
            refused: vec![s2.head(), s3.head()],
        }
    );
    assert_eq!(set.basis_observed(), 1);
    let [kept] = set.suffixes() else {
        return Err("one suffix".into());
    };
    assert_eq!(
        (kept.head(), kept.rank(), kept.observed()),
        (s4.head(), ForkRank::Rank2, 4)
    );
    Ok(())
}

/// A rerank that fails leaves the set unchanged: R9 makes a contested
/// prefix the basis only at a first contact, so an accepted basis never
/// moves to one, and a basis of another identifier is unrelated.
///
/// Mutant (run, then restored): `rerank` skips the basis-kind check, so the
/// accepted chain becomes a ranked suffix of the prefix.
#[test]
fn failed_rerank_leaves_the_set_unchanged() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut set = registered(&basis);
    retain(&mut set, &Branch::of(&mut keys, &[Kind::Lost], 1)?.chain)?;
    let before = set.clone();
    assert_eq!(
        set.rerank(RetentionBasis::ContestedPrefix(Branch::v41()?.chain)),
        Err(RetentionError::ContestedAfterAccepted {
            accepted: basis.head()
        })
    );
    assert_eq!(set, before);
    let other = chain_of(&super::v42()?)?;
    assert!(matches!(
        set.rerank(RetentionBasis::Accepted(other)),
        Err(RetentionError::Unrelated(_))
    ));
    assert_eq!(set, before);
    Ok(())
}

/// `restore` fails closed on a persisted set `admit` could not have built:
/// a tampered unit, an invalid inception, no inception, a missing head, a
/// repeated moment, a moment with no next, a head listed twice, an accepted
/// basis a suffix extends, and a unit no retained chain holds.
///
/// Mutants (each run, then restored): `rebuild` reads the discards before
/// the verdict, so the headless units report `Discarded`; and `restore`
/// accepts any re-admission, so the head listed twice restores.
#[test]
fn restore_fails_closed() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut set = registered(&basis);
    // Both suffixes rank 3 and were held after the basis, so it stays accepted.
    let first = Branch::of(&mut keys, &[Kind::KeyState, Kind::KeyState], 1)?;
    let second = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    retain(&mut set, &first.chain)?;
    retain(&mut set, &second.chain)?;
    let saved = set.persisted();
    let identifier = basis.chain.identifier();
    let adopted = AdoptedBasis::Accepted { head: basis.head() };
    let restore = |saved: &_| RetentionSet::restore(&identifier, saved, adopted);
    assert_eq!(restore(&saved)?, set);

    let mut tampered = saved.clone();
    let last = tampered.units.last_mut().ok_or("a unit")?;
    let mut bytes = last.to_vec();
    let end = bytes.last_mut().ok_or("a byte")?;
    *end ^= 1;
    *last = bytes.into();
    assert!(matches!(
        restore(&tampered),
        Err(RestoreError::Discarded(_))
    ));

    let mut invalid = vector(V41_PREIMAGE)?;
    invalid.signer_groups = vec![group(&[0, 0])];
    let unit = sign_inception(&keys.ring, &invalid)?;
    let invalid_identifier = identifier_of(signed_of(&unit)?);
    let mut lone = saved.clone();
    lone.units = vec![unit.into()];
    assert!(matches!(
        RetentionSet::restore(&invalid_identifier, &lone, adopted),
        Err(RestoreError::InceptionInvalid(_))
    ));

    let mut headless = saved.clone();
    headless.units.remove(0);
    assert_eq!(restore(&headless), Err(RestoreError::NoInception));

    let mut missing = saved.clone();
    let suffix = missing.suffixes.first_mut().ok_or("a suffix")?;
    suffix.head = [7; 32];
    assert_eq!(
        restore(&missing),
        Err(RestoreError::MissingHead { head: [7; 32] })
    );

    let mut repeated = saved.clone();
    let moment = repeated.basis.observed;
    repeated.suffixes.first_mut().ok_or("a suffix")?.observed = moment;
    assert_eq!(
        restore(&repeated),
        Err(RestoreError::DuplicateObserved { observed: moment })
    );

    let mut exhausted = saved.clone();
    exhausted.suffixes.first_mut().ok_or("a suffix")?.observed = u64::MAX;
    assert_eq!(restore(&exhausted), Err(RestoreError::ObservedExhausted));

    let mut twice = saved.clone();
    let listed = *twice.suffixes.first().ok_or("a suffix")?;
    twice.suffixes.push(PersistedSuffix {
        observed: 99,
        ..listed
    });
    assert_eq!(
        restore(&twice),
        Err(RestoreError::Inadmissible {
            head: listed.head,
            admission: Admission::AlreadyHeld,
        })
    );

    let mut short = saved.clone();
    short.basis.head = v41_digest();
    assert_eq!(
        RetentionSet::restore(
            &identifier,
            &short,
            AdoptedBasis::Accepted { head: v41_digest() }
        ),
        Err(RestoreError::Retention(RetentionError::ExtendsAccepted {
            head: v41_digest()
        }))
    );

    let mut extra = saved;
    extra.suffixes.retain(|suffix| suffix.head == first.head());
    assert!(matches!(
        restore(&extra),
        Err(RestoreError::UnreferencedUnits { .. })
    ));
    Ok(())
}

/// The digest standing for generated event `id`.
const fn digest(id: u8) -> [u8; 32] {
    [id; 32]
}

/// The planner's contract over arbitrary held slots sharing events, with
/// or without a replaced slot: it never evicts a rank-1 suffix, one whose
/// rank number is below the candidate's, a protected one (a tied head the
/// candidate does not beat), or the replaced one; its victims
/// are the first k of the eviction order (highest rank number, then latest
/// moment); the result fits both bounds with each event counted once;
/// putting back the last victim breaks a bound; and it refuses only where
/// evicting every suffix it may evict would still not fit.
///
/// Mutants (each run, then restored): the planner ignores `protected`;
/// the planner evicts every suffix it
/// may evict once over a bound, which breaks minimality; and it evicts the
/// most recent regardless of rank, which breaks the order and the rank
/// floor.
#[test]
fn plan_evictions_holds_the_eviction_rule() {
    let rank = prop_oneof![
        Just(ForkRank::Rank1),
        Just(ForkRank::Rank2),
        Just(ForkRank::Rank3)
    ];
    let events = proptest::collection::btree_set(0_u8..16, 1..=4);
    let slot = (rank, events);
    let strategy = (
        proptest::collection::vec(slot.clone(), 0..12),
        slot,
        proptest::option::of(0_usize..12),
        proptest::collection::vec(1_u64..40, 16),
        1_u32..10,
        1_u64..300,
        proptest::collection::vec(proptest::bool::weighted(0.25), 0..12),
    );
    let mut runner = TestRunner::new(Config::with_cases(4_000));
    let outcome = runner.run(
        &strategy,
        |(held, candidate, replacing, sizes, suffixes, bytes, protected)| {
            let size = |id: u8| sizes.get(usize::from(id)).copied().unwrap_or(0);
            let slot_of = |(rank, ids): (ForkRank, BTreeSet<u8>), observed| Slot {
                rank,
                observed,
                events: ids.into_iter().map(|id| (digest(id), size(id))).collect(),
            };
            let held: Vec<Slot> = held
                .into_iter()
                .zip(0_u64..)
                .map(|(slot, observed)| slot_of(slot, observed))
                .collect();
            let candidate = slot_of(candidate, u64::MAX);
            let replacing = replacing.filter(|index| *index < held.len());
            let bounds = Bounds { suffixes, bytes };
            let fits = |kept: &BTreeSet<usize>| {
                let mut lens = BTreeMap::new();
                for slot in kept
                    .iter()
                    .filter_map(|index| held.get(*index))
                    .chain([&candidate])
                {
                    lens.extend(slot.events.iter().copied());
                }
                kept.len() < usize::try_from(suffixes).unwrap_or(usize::MAX)
                    && lens.values().sum::<u64>() <= bytes
            };
            let initial: BTreeSet<usize> = (0..held.len())
                .filter(|index| Some(*index) != replacing)
                .collect();
            let mut order: Vec<usize> = initial
                .iter()
                .copied()
                .filter(|index| {
                    !protected.get(*index).copied().unwrap_or(false)
                        && held.get(*index).is_some_and(|slot| {
                            slot.rank != ForkRank::Rank1
                                && slot.rank.number() >= candidate.rank.number()
                        })
                })
                .collect();
            order.sort_by_key(|index| {
                held.get(*index)
                    .map(|slot| std::cmp::Reverse((slot.rank.number(), slot.observed)))
            });
            let without = |victims: &[usize]| -> BTreeSet<usize> {
                initial
                    .iter()
                    .copied()
                    .filter(|index| !victims.contains(index))
                    .collect()
            };
            let refs: Vec<&Slot> = held.iter().collect();
            let guards: Vec<Guard> = protected
                .iter()
                .map(|protected| {
                    if *protected {
                        Guard::Tied {
                            beaten_by: Vec::new(),
                        }
                    } else {
                        Guard::Open
                    }
                })
                .collect();
            match plan_evictions(&refs, &guards, replacing, &candidate, bounds) {
                Some(evicted) => {
                    prop_assert_eq!(order.get(..evicted.len()), Some(evicted.as_slice()));
                    prop_assert!(fits(&without(&evicted)));
                    if let Some((_, fewer)) = evicted.split_last() {
                        prop_assert!(!fits(&without(fewer)));
                    }
                }
                None => prop_assert!(!fits(&without(&order))),
            }
            Ok(())
        },
    );
    assert!(outcome.is_ok(), "{outcome:?}");
}

/// The pool `admit_matches_the_refusal_model` draws from: every frame of
/// every lineage below, and the basis they fork from.
///
/// The basis is owner 0's trunk of three `KeyState` events. Lineages fork
/// at positions 1, 2 and 3; nine of them are rank 1, more than the count
/// bound's four slots; and two pairs of siblings share a body past their
/// fork, one rank 1 and one rank 2.
fn flood_pool(keys: &mut Keys) -> Result<(Branch, Vec<ValidatedChain>), Error> {
    let mut trunk = vec![Branch::v41()?];
    for _ in 0..3 {
        let mut next = trunk.last().ok_or("the trunk")?.clone();
        next.push(keys, Kind::KeyState, 0)?;
        trunk.push(next);
    }
    let lineages: [(usize, &[Kind]); 13] = [
        (0, &[Kind::Reveal]),
        (0, &[Kind::Reveal, Kind::KeyState]),
        (0, &[Kind::CoSigns]),
        (0, &[Kind::CoSigns, Kind::KeyState, Kind::KeyState]),
        (0, &[Kind::KeyState, Kind::Reveal]),
        (0, &[Kind::Lost]),
        (0, &[Kind::Lost, Kind::KeyState]),
        (0, &[Kind::KeyState]),
        (0, &[Kind::KeyState, Kind::KeyState]),
        (1, &[Kind::Reveal]),
        (1, &[Kind::Lost, Kind::KeyState]),
        (2, &[Kind::CoSigns]),
        (2, &[Kind::KeyState]),
    ];
    let mut pool = Vec::new();
    let mut owner = 1_u32;
    for (fork_at, shape) in lineages {
        let mut branch = trunk.get(fork_at).ok_or("a fork point")?.clone();
        for kind in shape {
            branch.push(keys, *kind, owner)?;
            pool.push(branch.chain.clone());
        }
        owner += 1;
    }
    for body in [[Kind::Reveal, Kind::KeyState], [Kind::Lost, Kind::KeyState]] {
        let mut shared = Branch::v41()?;
        for kind in body {
            shared.push(keys, kind, owner)?;
            pool.push(shared.clone().chain);
        }
        owner += 1;
        for _ in 0..2 {
            let mut sibling = shared.clone();
            sibling.push(keys, Kind::KeyState, owner)?;
            pool.push(sibling.chain);
            owner += 1;
        }
    }
    let basis = trunk.pop().ok_or("the trunk's head")?;
    Ok((basis, pool))
}

/// R9's bounds under arbitrary admit order, over real chains of every rank
/// forking at positions 1 to 3, siblings sharing a body, and more rank-1
/// lineages than slots: after every admission the result is the test's own
/// model of refusal, which keeps every suffix the candidate may not evict
/// (rank 1, a rank number below the candidate's, or a tied head no held
/// chain and not the candidate beats under R6) and refuses exactly
/// where that floor and the candidate exceed the count bound or, each event
/// once, the byte bound. Both bounds hold, the byte tally is the model's,
/// no rank-1 suffix leaves except by its own extension, a refusal changes
/// nothing, and no suffix is a prefix of another. The run must reach a
/// rank-1 candidate refused by the count bound, one refused by the byte
/// bound, and a set holding two suffixes that share an event.
///
/// Mutants (each run, then restored): the planner evicts the most recently
/// observed suffix regardless of rank, which evicts rank-1 suffixes; the
/// tally sums each suffix's own bytes, which refuses where the model
/// admits; and `protected` protects no suffix, which admits where the model
/// refuses.
#[test]
fn admit_matches_the_refusal_model() -> TestResult {
    let mut keys = Keys::new()?;
    let (basis, pool) = flood_pool(&mut keys)?;
    let mut rank_one_leaves: Vec<u64> = pool
        .iter()
        .filter(|chain| {
            RetentionSet::new(accepted(&basis))
                .admit((*chain).clone())
                .is_ok_and(|admission| {
                    matches!(
                        admission,
                        Admission::Retained {
                            rank: ForkRank::Rank1,
                            ..
                        }
                    )
                })
        })
        .map(|chain| distinct_bytes(&basis.chain, [chain]))
        .collect();
    rank_one_leaves.sort_unstable();
    // The six smallest rank-1 suffixes' bytes: four small ones flood the
    // count bound first, larger ones flood the byte bound below the rank-1
    // sum, and the room left lets siblings sharing a body be held together.
    let bytes = rank_one_leaves.iter().take(6).sum::<u64>();
    assert!(bytes < rank_one_leaves.iter().sum::<u64>());
    let model = RefusalModel {
        basis: &basis.chain,
        bounds: Bounds { suffixes: 4, bytes },
        by_count: Cell::new(0),
        by_bytes: Cell::new(0),
        sharing: Cell::new(0),
    };
    let indices = proptest::collection::vec(0..pool.len(), 1..=24);
    let config = Config::with_cases(128);
    let mut runner = TestRunner::new_with_rng(
        config.clone(),
        TestRng::deterministic_rng(config.rng_algorithm),
    );
    let outcome = runner.run(&indices, |order| {
        let mut set = RetentionSet::with_bounds(accepted(&basis), model.bounds);
        for index in order {
            let candidate = pool
                .get(index)
                .cloned()
                .ok_or_else(|| TestCaseError::fail("a pool index"))?;
            let before = set.clone();
            let admission = set
                .admit(candidate.clone())
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            model.check(&before, &set, &candidate, &admission)?;
        }
        Ok(())
    });
    if let Err(failure) = outcome {
        return Err(format!("{failure}").into());
    }
    assert!(
        model.by_count.get() > 0,
        "no rank-1 candidate met a full count bound"
    );
    assert!(
        model.by_bytes.get() > 0,
        "no rank-1 candidate met a full byte bound"
    );
    assert!(
        model.sharing.get() > 0,
        "no two retained suffixes shared an event"
    );
    Ok(())
}

/// Whether `left` beats `right` under R6: two diverged chains, `left`'s
/// rank number the lower.
fn beats(left: &ValidatedChain, right: &ValidatedChain) -> bool {
    matches!(
        super::pair_chains(left, right),
        Ok(super::ChainPairing::Diverged(divergence))
            if divergence.ranks[0].number() < divergence.ranks[1].number()
    )
}

/// R9's tied-head rule read after each victim: the byte bound needs two
/// evictions among three rank-3 suffixes, and Y is a tied head once X, the
/// one suffix beating it, leaves. The plan evicts X, the most recently
/// observed, then W, never Y.
///
/// Mutant (run, then restored): `guarded` protects a tied head only where
/// nothing held beats it, read once before the plan, so the plan evicts X
/// and then Y.
#[test]
fn plan_protects_a_tied_head_its_first_victim_beat() {
    let slot = |id: u8, observed| Slot {
        rank: ForkRank::Rank3,
        observed,
        events: vec![(digest(id), 10)],
    };
    let w = slot(1, 1);
    let y = slot(2, 2);
    let x = slot(3, 3);
    let candidate = slot(4, 4);
    let guards = [Guard::Open, Guard::Tied { beaten_by: vec![2] }, Guard::Open];
    let bounds = Bounds {
        suffixes: 8,
        bytes: 20,
    };
    assert_eq!(
        plan_evictions(&[&w, &y, &x], &guards, None, &candidate, bounds),
        Some(vec![2, 0])
    );
}

/// R9's tie prefix where the bounds refuse every chain carrying it while a
/// chain extending the accepted chain A is retained: the byte bound holds
/// L, one event past A, and refuses both tied chains, which carry the tie
/// prefix P's event past A. The set records the longest prefix of P a held
/// chain carries, A itself, so L keeps its rank, the set persists no event
/// of P past A, and it restores with L and that prefix.
///
/// Mutant (run, then restored): `settled` records no prefix wherever no
/// held chain carries the whole one, so `restore` refuses L as an
/// extension of the accepted chain.
#[test]
fn tie_prefix_settles_to_the_longest_carried_prefix() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::Reveal], 0)?;
    let mut p = a.clone();
    p.push(&mut keys, Kind::KeyState, 0)?;
    let mut t1 = p.clone();
    t1.push(&mut keys, Kind::Reveal, 1)?;
    let mut t2 = p.clone();
    t2.push(&mut keys, Kind::CoSigns, 2)?;
    let mut l = a.clone();
    l.push(&mut keys, Kind::KeyState, 3)?;
    let mut set = bounded(&a, 8, tail(&l));
    let report = set.after_contest(
        p.chain.clone(),
        [t1.chain.clone(), t2.chain.clone(), l.chain.clone()],
    )?;
    assert_eq!(report.refused, vec![t1.head(), t2.head()]);
    assert_eq!(heads(&set), BTreeSet::from([l.head()]));
    assert_eq!(set.tie_prefix(), Some(&a.chain));
    let retained = by_head(&set, l.head())?;
    assert_eq!(
        (retained.rank(), retained.fork_position()),
        (ForkRank::Rank3, 2)
    );
    let saved = set.persisted();
    let stored: u64 = saved.units.iter().map(|unit| unit.len() as u64).sum();
    assert_eq!(
        stored,
        a.unit_lens.iter().sum::<u64>() + set.retained_bytes()
    );
    let restored = RetentionSet::restore(
        &a.chain.identifier(),
        &saved,
        AdoptedBasis::Accepted { head: a.head() },
    )?;
    assert_eq!(restored.suffixes(), set.suffixes());
    assert_eq!(restored.tie_prefix(), Some(&a.chain));
    Ok(())
}

/// R9's tie prefix after an admission evicts its last carrier: two
/// `{Lost}` recoveries off the accepted chain A beat both tied chains past
/// the prefix P and, at a count bound of two, evict them one at a time. No
/// held chain then carries P, both recoveries extend A, so the set records
/// A and restores.
///
/// Mutant (run, then restored): `admit` skips settling the tie prefix, so
/// the set keeps P, which no held chain carries, and `restore` refuses it.
#[test]
fn admission_evicting_the_last_carrier_settles_the_tie_prefix() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::Reveal], 0)?;
    let mut p = a.clone();
    p.push(&mut keys, Kind::KeyState, 0)?;
    let mut t1 = p.clone();
    t1.push(&mut keys, Kind::KeyState, 1)?;
    let mut t2 = p.clone();
    t2.push(&mut keys, Kind::KeyState, 2)?;
    let mut set = bounded(&a, 2, u64::MAX);
    let report = set.after_contest(p.chain.clone(), [t1.chain.clone(), t2.chain.clone()])?;
    assert!(report.refused.is_empty());
    assert_eq!(set.tie_prefix(), Some(&p.chain));
    for owner in [3, 4] {
        let mut recovery = a.clone();
        recovery.push(&mut keys, Kind::Lost, owner)?;
        assert!(matches!(
            set.admit(recovery.chain)?,
            Admission::Retained { ref evicted, .. } if evicted.len() == 1
        ));
    }
    assert!(!heads(&set).contains(&t1.head()) && !heads(&set).contains(&t2.head()));
    assert_eq!(set.tie_prefix(), Some(&a.chain));
    let restored = RetentionSet::restore(
        &a.chain.identifier(),
        &set.persisted(),
        AdoptedBasis::Accepted { head: a.head() },
    )?;
    assert_eq!(restored.suffixes(), set.suffixes());
    assert_eq!(restored.tie_prefix(), set.tie_prefix());
    Ok(())
}

/// The test's own model of R9's refusal, and what a run reached.
struct RefusalModel<'b> {
    basis: &'b ValidatedChain,
    bounds: Bounds,
    /// Rank-1 candidates the count bound refused.
    by_count: Cell<u32>,
    /// Rank-1 candidates the byte bound refused.
    by_bytes: Cell<u32>,
    /// Sets holding two suffixes that share an event.
    sharing: Cell<u32>,
}

impl RefusalModel<'_> {
    /// Checks one admission of `candidate`, which moved `before` to `set`.
    fn check(
        &self,
        before: &RetentionSet,
        set: &RetentionSet,
        candidate: &ValidatedChain,
        admission: &Admission,
    ) -> Result<(), TestCaseError> {
        let rank = match admission {
            Admission::AlreadyHeld => {
                prop_assert_eq!(set, before);
                return Ok(());
            }
            Admission::Refused { rank }
            | Admission::Retained { rank, .. }
            | Admission::Extended { rank, .. } => *rank,
        };
        let replaced = before
            .suffixes()
            .iter()
            .find(|suffix| suffix.chain().shared_prefix_len(candidate) == suffix.chain().len())
            .map(RetainedSuffix::head);
        let held: Vec<&ValidatedChain> = std::iter::once(self.basis)
            .chain(before.suffixes().iter().map(RetainedSuffix::chain))
            .collect();
        let protected = |suffix: &RetainedSuffix| {
            held.iter()
                .chain([&candidate])
                .all(|other| !beats(other, suffix.chain()))
        };
        let floor: Vec<&ValidatedChain> = before
            .suffixes()
            .iter()
            .filter(|suffix| Some(suffix.head()) != replaced)
            .filter(|suffix| {
                suffix.rank() == ForkRank::Rank1
                    || suffix.rank().number() < rank.number()
                    || protected(suffix)
            })
            .map(RetainedSuffix::chain)
            .collect();
        let over_count = floor.len() + 1 > 4;
        let over_bytes =
            distinct_bytes(self.basis, floor.into_iter().chain([candidate])) > self.bounds.bytes;
        let refused = matches!(admission, Admission::Refused { .. });
        prop_assert_eq!(refused, over_count || over_bytes, "{:?}", admission);
        if refused {
            prop_assert_eq!(set, before);
            if rank == ForkRank::Rank1 && over_count {
                self.by_count.set(self.by_count.get() + 1);
            }
            if rank == ForkRank::Rank1 && over_bytes {
                self.by_bytes.set(self.by_bytes.get() + 1);
            }
        }
        if let Admission::Retained { evicted, .. } | Admission::Extended { evicted, .. } = admission
        {
            let evictable = evicted.iter().all(|head| {
                before.suffixes().iter().any(|suffix| {
                    suffix.head() == *head && suffix.rank() != ForkRank::Rank1 && !protected(suffix)
                })
            });
            prop_assert!(evictable, "evicted a rank-1, protected or unheld suffix");
        }
        let own_sum: u64 = set
            .suffixes()
            .iter()
            .map(|suffix| distinct_bytes(self.basis, [suffix.chain()]))
            .sum();
        if own_sum > set.retained_bytes() {
            self.sharing.set(self.sharing.get() + 1);
        }
        let now = heads(set);
        let rank_one_kept = before
            .suffixes()
            .iter()
            .filter(|suffix| suffix.rank() == ForkRank::Rank1)
            .all(|suffix| now.contains(&suffix.head()) || replaced == Some(suffix.head()));
        prop_assert!(rank_one_kept, "a rank-1 suffix left");
        prop_assert!(set.suffixes().len() <= 4);
        prop_assert_eq!(
            set.retained_bytes(),
            distinct_bytes(self.basis, set.suffixes().iter().map(RetainedSuffix::chain))
        );
        prop_assert!(set.retained_bytes() <= self.bounds.bytes);
        for left in set.suffixes() {
            for right in set.suffixes() {
                prop_assert!(
                    left.head() == right.head()
                        || left.chain().shared_prefix_len(right.chain()) < left.chain().len()
                );
            }
        }
        Ok(())
    }
}

/// R9 at a store: every chain other than the accepted one is a divergent
/// suffix under the count bound. Nine rank-3 forks tie the accepted chain,
/// which was held first and stays accepted; each fork is a tied head the
/// ninth does not beat, so R9's tied-head rule refuses the ninth, and the
/// holder holds the first eight forks and the accepted chain.
///
/// Mutant (run, then restored): the planner checks the byte bound alone, so
/// the holder keeps all nine forks.
#[test]
fn holder_keeps_at_most_eight_of_nine_rank_three_forks() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut holder = AcceptedChainHolder::new();
    assert_eq!(holder.hold(basis.chain.clone())?, first_held());
    let forks: Vec<Branch> = (1..=9)
        .map(|owner| Branch::of(&mut keys, &[Kind::KeyState], owner))
        .collect::<Result<_, _>>()?;
    let ninth = forks.get(8).ok_or("a ninth fork")?.head();
    for (index, fork) in forks.iter().enumerate() {
        let expected = if index == 8 {
            HoldOutcome::Refused {
                rank: ForkRank::Rank3,
            }
        } else {
            HoldOutcome::HeldDivergent {
                admission: Admission::Retained {
                    rank: ForkRank::Rank3,
                    evicted: Vec::new(),
                },
            }
        };
        assert_eq!(holder.hold(fork.chain.clone())?, expected);
    }
    assert_eq!(holder.held().count(), 9);
    assert_eq!(
        holder.accepted().map(ValidatedChain::head_digest),
        Some(basis.head())
    );
    let expected: BTreeSet<[u8; 32]> = forks
        .iter()
        .map(Branch::head)
        .filter(|head| *head != ninth)
        .collect();
    assert_eq!(heads(holder.retention().ok_or("a set")?), expected);
    Ok(())
}

/// R9: "a suffix a party evicted and a party presents again later is
/// re-ranked as if the party saw it for the first time". E is held before W
/// becomes accepted, then evicted; extended to tie W at rank 1 and
/// presented again, it takes a new moment, so W, held earlier, stays
/// accepted under the held-first rule.
///
/// Mutant (run, then restored): a new suffix takes the smallest moment no
/// held chain carries, which is E's old one, so E is held first and becomes
/// accepted.
#[test]
fn evicted_chain_presented_again_cannot_win_held_first() -> TestResult {
    let mut keys = Keys::new()?;
    let a0 = basis(&mut keys)?;
    let e = Branch::of(&mut keys, &[Kind::KeyState], 1)?;
    let w = Branch::of(&mut keys, &[Kind::CoSigns], 2)?;
    let lost = Branch::of(&mut keys, &[Kind::Lost], 3)?;
    let mut holder = AcceptedChainHolder::with_bounds(Bounds {
        suffixes: 2,
        bytes: u64::MAX,
    });
    assert_eq!(holder.hold(a0.chain.clone())?, first_held());
    assert_eq!(
        holder.hold(e.chain.clone())?,
        HoldOutcome::HeldDivergent {
            admission: Admission::Retained {
                rank: ForkRank::Rank3,
                evicted: Vec::new(),
            }
        }
    );
    assert!(matches!(
        holder.hold(w.chain.clone())?,
        HoldOutcome::AcceptedReplaced { displaced, .. } if displaced == a0.head()
    ));
    assert_eq!(
        holder.hold(lost.chain)?,
        HoldOutcome::HeldDivergent {
            admission: Admission::Retained {
                rank: ForkRank::Rank2,
                evicted: vec![e.head()],
            }
        }
    );
    let mut again = e;
    again.push(&mut keys, Kind::CoSigns, 1)?;
    assert_eq!(
        holder.hold(again.chain.clone())?,
        HoldOutcome::HeldDivergent {
            admission: Admission::Retained {
                rank: ForkRank::Rank1,
                evicted: vec![a0.head()],
            }
        }
    );
    assert_eq!(
        holder.accepted().map(ValidatedChain::head_digest),
        Some(w.head())
    );
    let set = holder.retention().ok_or("a set")?;
    assert_eq!(set.basis_observed(), 2);
    assert_eq!(by_head(set, again.head())?.observed(), 4);
    Ok(())
}
