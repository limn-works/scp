//! R9's retention: identity by digest, extension in place, the held copy,
//! both bounds, the eviction rule and persistence (`09-security-model.md`
//! §9.7.4.2 R9), over chains that fork from Vector 41.
//!
//! The accepted basis is Vector 41 followed by owner 0's `KeyState`, so a
//! suffix forking at Vector 41 ranks by its own first reveal: rank 1 for a
//! rollover or a `{CoSigns}` recovery, rank 2 for a `{Lost}` recovery and
//! rank 3 for none.

use std::collections::BTreeSet;

use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

use super::super::retention::{Bounds, Slot, plan_evictions};
use super::super::{
    Admission, BasisKind, ForkRank, Rerank, RestoreError, RetentionBasis, RetentionError,
    RetentionSet,
};
use super::{
    Branch, Error, Keys, Kind, TestResult, Wire, assertion_copies, chain_of, key_state_on,
};
use super::{v41, v41_changed};
use crate::ValidatedChain;

/// The accepted basis: Vector 41, then owner 0's `KeyState`.
fn basis(keys: &mut Keys) -> Result<Branch, Error> {
    Branch::of(keys, &[Kind::KeyState], 0)
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
    set.suffixes()
        .iter()
        .map(super::super::retention::RetainedSuffix::head)
        .collect()
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
    assert_eq!(only.bytes(), suffix_bytes(&suffix));
    assert_eq!(set.retained_bytes(), suffix_bytes(&suffix));
    Ok(())
}

/// R9: "breaking a tie among equal ranks by evicting the suffix it observed
/// most recently … Evicting the earliest-observed equal-rank suffix would
/// evict the owner's own chain first". The owner's rank-2 suffix, extended
/// after seven attacker suffixes arrived, keeps its first moment, so a
/// rank-2 candidate at the full count bound evicts the latest attacker
/// suffix.
///
/// Mutants (each run, then restored): an extension takes the next moment
/// instead of inheriting one, so the owner's suffix is the most recent and
/// is evicted; and `place` plans without excluding the extended suffix's
/// slot, so the extension at the full count bound evicts a suffix.
#[test]
fn owner_extension_keeps_its_moment_so_the_latest_attacker_is_evicted() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
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
/// moved set gives back every suffix and every moment.
///
/// A is Vector 41 → a1 → a2, each owner 0's `KeyState`; S forks from A at
/// a2 with a `{Lost}` recovery; W forks at Vector 41 with a rollover.
///
/// Mutant (run, then restored): `persisted` cuts every chain's units
/// before its first event, the inception, so restore places no unit and
/// fails with `Discarded`.
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
    let s_tail = s.unit_lens.last().copied().ok_or("S's last unit")?;
    assert_eq!(held.bytes(), s_tail);

    assert_eq!(set.rerank(accepted(&w))?, Rerank::default());
    let by_head = |head: [u8; 32]| {
        set.suffixes()
            .iter()
            .find(|suffix| suffix.head() == head)
            .cloned()
            .ok_or("a retained suffix")
    };
    let displaced = by_head(a.head())?;
    assert_eq!(
        (
            displaced.rank(),
            displaced.fork_position(),
            displaced.observed()
        ),
        (ForkRank::Rank3, 1, 0)
    );
    assert_eq!(displaced.bytes(), suffix_bytes(&a));
    let moved = by_head(s.head())?;
    assert_eq!(
        (moved.rank(), moved.fork_position(), moved.observed()),
        (ForkRank::Rank2, 1, 1)
    );
    assert_eq!(moved.bytes(), suffix_bytes(&s));

    let saved = set.persisted();
    assert_eq!(saved.basis.kind, BasisKind::Accepted);
    assert_eq!(saved.basis.head, w.head());
    assert_eq!(saved.basis.observed, 2);
    let identifier = w.chain.identifier();
    let restored = RetentionSet::restore(&identifier, Some(&w.chain), &saved)?;
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

/// R9: "A candidate the party can evict no suffix for is refused — a
/// rank-3 candidate against rank-2 suffixes alone, for one".
///
/// Mutant (run, then restored): the planner drops "whose rank number is at
/// least the candidate's", so the rank-3 candidate evicts a rank-2 suffix.
#[test]
fn rank_three_candidate_against_eight_rank_two_suffixes_is_refused() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
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
/// most recently".
///
/// Mutant (run, then restored): the tie-break evicts the earliest-observed
/// suffix.
#[test]
fn equal_rank_eviction_takes_the_most_recently_observed() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
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
#[test]
fn accepted_extension_and_other_identifier_are_typed_errors() -> TestResult {
    let mut keys = Keys::new()?;
    let mut extended = basis(&mut keys)?;
    let mut set = registered(&extended);
    let head = extended.head();
    extended.push(&mut keys, Kind::KeyState, 0)?;
    assert_eq!(
        set.admit(extended.chain),
        Err(RetentionError::ExtendsAccepted { head })
    );
    let other = chain_of(&super::v42()?)?;
    assert!(matches!(
        set.admit(other),
        Err(RetentionError::Unrelated(_))
    ));
    assert!(set.suffixes().is_empty());
    Ok(())
}

/// R9: "Where a first-contact resolution returns `Contested`, which adopts
/// nothing, the shared prefix that `Contested` names … is the chain the
/// eviction rank and both retention bounds read." Each tied head extends
/// that prefix and is a divergent suffix past it; the set persists the
/// prefix itself and restores without a baseline.
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
    assert_eq!(RetentionSet::restore(&identifier, None, &saved)?, set);
    assert_eq!(
        RetentionSet::restore(&identifier, Some(&prefix.chain), &saved),
        Err(RestoreError::BasisMismatch {
            kind: BasisKind::ContestedPrefix
        })
    );
    Ok(())
}

/// `restore` fails closed on a persisted set `admit` could not have built:
/// a tampered unit, a missing head, a repeated moment, a moment with no
/// next, a wrong baseline, and a unit no retained chain holds.
#[test]
fn restore_fails_closed() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let mut set = registered(&basis);
    let first = Branch::of(&mut keys, &[Kind::Lost], 1)?;
    let second = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    retain(&mut set, &first.chain)?;
    retain(&mut set, &second.chain)?;
    let saved = set.persisted();
    let identifier = basis.chain.identifier();
    let restore = |saved: &_| RetentionSet::restore(&identifier, Some(&basis.chain), saved);
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

    assert_eq!(
        RetentionSet::restore(&identifier, Some(&first.chain), &saved),
        Err(RestoreError::BasisMismatch {
            kind: BasisKind::Accepted
        })
    );
    assert_eq!(
        RetentionSet::restore(&identifier, None, &saved),
        Err(RestoreError::BasisMismatch {
            kind: BasisKind::Accepted
        })
    );

    let mut extra = saved;
    extra.suffixes.retain(|suffix| suffix.head == first.head());
    assert!(matches!(
        restore(&extra),
        Err(RestoreError::UnreferencedUnits { .. })
    ));
    Ok(())
}

/// The planner's contract over arbitrary held slots and candidates: it
/// never evicts a rank-1 suffix or one whose rank number is below the
/// candidate's, it evicts by highest rank number then latest moment, the
/// result fits both bounds, and it refuses only where evicting every
/// suffix it may evict would still not fit.
///
/// Mutant (run, then restored): "evict the most recent regardless of rank"
/// fails the rank-1 and rank-floor checks.
#[test]
fn plan_evictions_holds_the_eviction_rule() {
    let rank = prop_oneof![
        Just(ForkRank::Rank1),
        Just(ForkRank::Rank2),
        Just(ForkRank::Rank3)
    ];
    let slot = (rank, 1_u64..40);
    let strategy = (
        proptest::collection::vec(slot.clone(), 0..12),
        slot,
        1_u32..10,
        1_u64..200,
    );
    let mut runner = TestRunner::new(Config::with_cases(2_000));
    let outcome = runner.run(&strategy, |(held, candidate, suffixes, bytes)| {
        let held: Vec<Slot> = held
            .into_iter()
            .zip(0_u64..)
            .map(|((rank, bytes), observed)| Slot {
                rank,
                bytes,
                observed,
            })
            .collect();
        let candidate = Slot {
            rank: candidate.0,
            bytes: candidate.1,
            observed: u64::MAX,
        };
        let bounds = Bounds { suffixes, bytes };
        let fits = |kept: &[&Slot]| {
            kept.len() < usize::try_from(suffixes).unwrap_or(usize::MAX)
                && kept.iter().map(|slot| slot.bytes).sum::<u64>() + candidate.bytes <= bytes
        };
        let may_evict = |slot: &Slot| {
            slot.rank != ForkRank::Rank1 && slot.rank.number() >= candidate.rank.number()
        };
        if let Some(evicted) = plan_evictions(&held, None, candidate, bounds) {
            let kept: Vec<&Slot> = held
                .iter()
                .enumerate()
                .filter(|(index, _)| !evicted.contains(index))
                .map(|(_, slot)| slot)
                .collect();
            prop_assert!(fits(&kept));
            let order: Vec<(u8, u64)> = evicted
                .iter()
                .filter_map(|index| held.get(*index))
                .map(|slot| {
                    prop_assert!(may_evict(slot));
                    Ok((slot.rank.number(), slot.observed))
                })
                .collect::<Result<_, _>>()?;
            prop_assert!(order.windows(2).all(|pair| pair[0] > pair[1]));
        } else {
            let kept: Vec<&Slot> = held.iter().filter(|slot| !may_evict(slot)).collect();
            prop_assert!(!fits(&kept));
        }
        Ok(())
    });
    assert!(outcome.is_ok(), "{outcome:?}");
}

/// R9's bounds under arbitrary admit order, over real chains of mixed ranks
/// and sizes, some extending others: after every admission both bounds
/// hold, no rank-1 suffix leaves except by its own extension, a refusal
/// changes nothing, and no suffix is a prefix of another.
///
/// Mutant (run, then restored): the planner evicts the most recently
/// observed suffix regardless of rank, which evicts rank-1 suffixes.
#[test]
fn admit_never_evicts_rank_one() -> TestResult {
    let mut keys = Keys::new()?;
    let basis = basis(&mut keys)?;
    let shapes: [&[Kind]; 10] = [
        &[Kind::Reveal],
        &[Kind::Reveal, Kind::KeyState],
        &[Kind::CoSigns],
        &[Kind::CoSigns, Kind::KeyState, Kind::KeyState],
        &[Kind::Lost],
        &[Kind::Lost, Kind::KeyState],
        &[Kind::KeyState],
        &[Kind::KeyState, Kind::KeyState],
        &[Kind::KeyState, Kind::Reveal],
        &[Kind::KeyState, Kind::Lost, Kind::KeyState],
    ];
    let mut pool = Vec::new();
    for (owner, shape) in (1_u32..).zip(shapes) {
        let mut branch = Branch::v41()?;
        for kind in shape {
            branch.push(&mut keys, *kind, owner)?;
            pool.push(branch.chain.clone());
        }
    }
    let typical = pool
        .iter()
        .map(|chain| chain.unit_bytes_from(1))
        .max()
        .ok_or("a pooled chain")?;
    let bounds = Bounds {
        suffixes: 4,
        bytes: typical * 3,
    };
    let indices = proptest::collection::vec(0..pool.len(), 1..=20);
    let mut runner = TestRunner::new(Config::with_cases(64));
    let outcome = runner.run(&indices, |order| {
        let mut set = RetentionSet::with_bounds(accepted(&basis), bounds);
        for index in order {
            let candidate = pool
                .get(index)
                .cloned()
                .ok_or_else(|| TestCaseError::fail("a pool index"))?;
            let before = set.clone();
            let rank_one: BTreeSet<[u8; 32]> = set
                .suffixes()
                .iter()
                .filter(|suffix| suffix.rank() == ForkRank::Rank1)
                .map(super::super::retention::RetainedSuffix::head)
                .collect();
            let admission = set
                .admit(candidate)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let replaced = match &admission {
                Admission::Refused { .. } | Admission::AlreadyHeld => {
                    prop_assert_eq!(&set, &before);
                    None
                }
                Admission::Extended { replaced, .. } => Some(*replaced),
                Admission::Retained { .. } => None,
            };
            if let Admission::Retained { evicted, .. } | Admission::Extended { evicted, .. } =
                &admission
            {
                prop_assert!(evicted.iter().all(|head| !rank_one.contains(head)));
            }
            let now = heads(&set);
            prop_assert!(
                rank_one
                    .iter()
                    .all(|head| now.contains(head) || replaced == Some(*head))
            );
            prop_assert!(set.suffixes().len() <= 4);
            prop_assert!(set.retained_bytes() <= bounds.bytes);
            for left in set.suffixes() {
                for right in set.suffixes() {
                    prop_assert!(
                        left.head() == right.head()
                            || left.chain().shared_prefix_len(right.chain()) < left.chain().len()
                    );
                }
            }
        }
        Ok(())
    });
    if let Err(failure) = outcome {
        return Err(format!("{failure}").into());
    }
    Ok(())
}
