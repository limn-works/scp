//! R9's early stop and residue, R11's first-contact floor, R12's baseline
//! and R14's six verdicts, through `classify` (`09-security-model.md`
//! §9.7.4.2 R7, R9, R11, R12, R14; `03-identity.md` §3.10.10), over chains
//! that fork from Vector 41.
//!
//! These tests sit beside the rank and retention tests because they build
//! their chains with the same `Branch` model.

use std::time::{Duration, SystemTime};

use super::super::{
    AdoptedBasis, ForkRank, RetainedSuffix, RetentionBasis, RetentionSet, TieClass,
};
use scp_did::Identifier;

use super::chain_support::{
    Ring, group, identifier_of, sign_inception, signed_of, v41_v50, v41_v54, v41_v55, vector,
};
use super::fixtures::{
    self, TestResult, V41_IDENTIFIER, V41_PREIMAGE, V50_DIGEST, V54_DIGEST, V55_DIGEST,
};
use super::{Branch, ChainPairing, Error, Keys, Kind, chain_of, pair_chains, v41_digest};
use crate::{
    Classification, ClassifyError, InconclusiveCause, OperatorProof, ResolutionInput,
    ResolutionVerdict, ResolvedState, SequenceRange, SourceExhaustion, SourceRead, classify,
    replay,
};

/// The resolution instant every test reads.
fn now() -> Result<SystemTime, Error> {
    Ok(SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .ok_or("a representable instant")?)
}

/// A proof verified under the operator key `n` names.
const fn operator(n: u8) -> OperatorProof {
    OperatorProof::Verified {
        operator_key: [n; 33],
    }
}

/// One source serving every unit of `branches`, each once, in order.
fn source(
    name: &str,
    branches: &[&Branch],
    exhaustion: SourceExhaustion,
    proof: OperatorProof,
) -> SourceRead {
    let mut units: Vec<Vec<u8>> = Vec::new();
    for unit in branches.iter().flat_map(|branch| &branch.base.units) {
        if !units.contains(unit) {
            units.push(unit.clone());
        }
    }
    SourceRead {
        name: name.to_owned(),
        units,
        exhaustion,
        proof,
    }
}

/// An exhausted source proven under operator key `n`.
fn exhausted(name: &str, branches: &[&Branch], n: u8) -> SourceRead {
    source(name, branches, SourceExhaustion::Exhausted, operator(n))
}

/// Two exhausted sources under two operator keys, each serving `branches`:
/// a read that meets R11's floor.
fn two_sources(branches: &[&Branch]) -> Vec<SourceRead> {
    vec![exhausted("a", branches, 1), exhausted("b", branches, 2)]
}

fn run_for(
    identifier: Identifier,
    held: Option<&RetentionSet>,
    reads: &[SourceRead],
) -> Result<Classification, Error> {
    Ok(classify(ResolutionInput {
        identifier,
        held,
        reads,
        now: now()?,
    })?)
}

fn run(held: Option<&RetentionSet>, reads: &[SourceRead]) -> Result<Classification, Error> {
    run_for(fixtures::identifier(V41_IDENTIFIER)?, held, reads)
}

fn accepted(branch: &Branch) -> RetentionSet {
    RetentionSet::new(RetentionBasis::Accepted(branch.chain.clone()))
}

/// The set persisted and restored against the basis it names.
fn round_trip(set: &RetentionSet) -> Result<RetentionSet, Error> {
    let identifier = set.basis().chain().identifier();
    Ok(RetentionSet::restore(
        &identifier,
        &set.persisted(),
        AdoptedBasis::of(set.basis()),
    )?)
}

fn retention(classification: &Classification) -> Result<&RetentionSet, Error> {
    Ok(classification.retention.as_ref().ok_or("a retention set")?)
}

fn suffix_heads(set: &RetentionSet) -> Vec<[u8; 32]> {
    let mut heads: Vec<[u8; 32]> = set.suffixes().iter().map(RetainedSuffix::head).collect();
    heads.sort_unstable();
    heads
}

fn sorted(mut heads: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    heads.sort_unstable();
    heads
}

fn key_state(classification: &Classification) -> Result<&ResolvedState, Error> {
    Ok(classification
        .key_state
        .as_ref()
        .ok_or("a resolved key state")?)
}

/// R11: two distinct proven operator keys over exhausted sources meet the
/// first-contact floor, and the winner is adopted as the accepted chain.
///
/// Mutant (run, then restored): the floor demands more than two keys, so
/// this read is `SingleSource`.
#[test]
fn first_contact_adopts_over_two_proven_sources() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let result = run(None, &two_sources(&[&o]))?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Adopted {
            head: o.head(),
            baseline_decreased: false,
        }
    );
    assert_eq!(key_state(&result)?.head_digest(), o.head());
    let set = retention(&result)?;
    assert_eq!(set.basis(), &RetentionBasis::Accepted(o.chain));
    assert!(set.suffixes().is_empty());
    assert_eq!(result.residue, 0);
    Ok(())
}

/// R11: one proven operator key, however many sources share it, is below
/// the floor; a failed source is not reached, a source the verifier's clock
/// rejected is counted apart, and nothing is stored.
///
/// Mutant (run, then restored): the floor counts sources instead of
/// distinct keys, so the two sources under one key meet it.
#[test]
fn one_operator_key_is_single_source() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let reads = vec![
        exhausted("a", &[&o], 1),
        exhausted("b", &[&o], 1),
        source(
            "c",
            &[&o],
            SourceExhaustion::Exhausted,
            OperatorProof::ClockSkewRejected,
        ),
        source("d", &[], SourceExhaustion::Failed, operator(2)),
    ];
    let result = run(None, &reads)?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Inconclusive {
            cause: InconclusiveCause::SingleSource {
                reached_sources: 3,
                proven_sources: 1,
                clock_skew_rejected: 1,
            },
        }
    );
    assert!(result.key_state.is_none());
    assert!(result.retention.is_none());
    Ok(())
}

/// R14: an inception that recomputes to the served identifier and fails R3
/// (Vector 41 with a repeated root index) is `Invalid` whichever source
/// served it, an unexhausted or failed one included.
///
/// Mutant (run, then restored): `InceptionInvalid` contributes no chain like
/// `NoInception`, so the read is `MissingEvents`.
#[test]
fn an_invalid_inception_from_any_source_is_invalid() -> TestResult {
    let mut preimage = vector(V41_PREIMAGE)?;
    preimage.signer_groups = vec![group(&[0, 0])];
    let forged = sign_inception(&Ring::new()?, &preimage)?;
    let identifier = identifier_of(signed_of(&forged)?);
    let serving = |exhaustion| SourceRead {
        name: "a".to_owned(),
        units: vec![forged.clone()],
        exhaustion,
        proof: operator(1),
    };
    for exhaustion in [
        SourceExhaustion::Exhausted,
        SourceExhaustion::StoppedAtFetchBound,
        SourceExhaustion::Failed,
    ] {
        let reads = [
            source("b", &[], SourceExhaustion::Exhausted, operator(2)),
            serving(exhaustion),
        ];
        let result = run_for(identifier, None, &reads)?;
        assert_eq!(result.verdict, ResolutionVerdict::Invalid, "{exhaustion:?}");
        assert!(result.key_state.is_none());
        assert!(result.retention.is_none());
    }
    Ok(())
}

/// R9: where no exhausted source served a chain, the verdict is
/// `MissingEvents` from the first sequence past what the verifier holds,
/// naming every failed source.
///
/// Mutant (run, then restored): `from` reads the basis head itself, so the
/// held case reports sequence 1.
#[test]
fn no_inception_anywhere_is_missing_events() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let headless = SourceRead {
        name: "a".to_owned(),
        units: o.base.units.iter().skip(1).cloned().collect(),
        exhaustion: SourceExhaustion::Exhausted,
        proof: operator(1),
    };
    let reads = vec![
        headless,
        source("b", &[], SourceExhaustion::Failed, operator(2)),
    ];
    let missing = |from| ResolutionVerdict::Inconclusive {
        cause: InconclusiveCause::MissingEvents {
            range: SequenceRange { from, to: None },
            failed_sources: vec!["b".to_owned()],
        },
    };
    assert_eq!(run(None, &reads)?.verdict, missing(Some(0)));
    let held = accepted(&o);
    let result = run(Some(&held), &reads)?;
    assert_eq!(result.verdict, missing(Some(2)));
    assert_eq!(result.retention.as_ref(), Some(&held));
    Ok(())
}

/// R12: every served chain a proper prefix of the accepted chain is
/// `Discarded`, which changes no stored state.
///
/// Mutants (each run, then restored): `Discarded` requires nothing of the
/// served chains, and an identical chain counts as stale; under either the
/// equal chain is `Discarded`.
#[test]
fn stale_chain_is_discarded_and_equal_chain_confirmed() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let mut o2 = o.clone();
    o2.push(&mut keys, Kind::KeyState, 0)?;
    let held = accepted(&o2);
    let stale = run(Some(&held), &[exhausted("a", &[&o], 1)])?;
    assert_eq!(
        stale.verdict,
        ResolutionVerdict::Discarded {
            accepted_head: o2.head()
        }
    );
    assert!(stale.key_state.is_none());
    assert_eq!(stale.retention.as_ref(), Some(&held));

    let equal = run(Some(&held), &[exhausted("a", &[&o2], 1)])?;
    assert_eq!(equal.verdict, ResolutionVerdict::Confirmed);
    assert_eq!(key_state(&equal)?.head_digest(), o2.head());
    assert_eq!(key_state(&equal)?.head_sequence(), 2);
    assert_eq!(equal.retention.as_ref(), Some(&held));
    Ok(())
}

/// R12: with an accepted baseline, one source suffices; an extension is
/// adopted with `baseline_decreased` false, and a divergent winner at a lower
/// sequence is adopted with it true, the replaced chain retained.
///
/// Mutant (run, then restored): `baseline_decreased` compares with `<=`, so
/// the divergent winner at an equal sequence reports a decrease.
#[test]
fn adopted_reports_a_decreased_baseline() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let mut o2 = o.clone();
    o2.push(&mut keys, Kind::KeyState, 0)?;
    let extended = run(Some(&accepted(&o)), &[exhausted("a", &[&o2], 1)])?;
    assert_eq!(
        extended.verdict,
        ResolutionVerdict::Adopted {
            head: o2.head(),
            baseline_decreased: false,
        }
    );
    assert_eq!(retention(&extended)?.basis().chain(), &o2.chain);

    let b = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    let diverged = run(Some(&accepted(&o2)), &[exhausted("a", &[&b], 1)])?;
    assert_eq!(
        diverged.verdict,
        ResolutionVerdict::Adopted {
            head: b.head(),
            baseline_decreased: true,
        }
    );
    let set = retention(&diverged)?;
    assert_eq!(set.basis(), &RetentionBasis::Accepted(b.chain.clone()));
    assert_eq!(suffix_heads(set), vec![o2.head()]);
    assert_eq!(key_state(&diverged)?.head_digest(), b.head());

    // A divergent winner at the replaced head's sequence is no decrease.
    let level = run(Some(&accepted(&o)), &[exhausted("a", &[&b], 1)])?;
    assert_eq!(
        level.verdict,
        ResolutionVerdict::Adopted {
            head: b.head(),
            baseline_decreased: false,
        }
    );
    Ok(())
}

/// AC7, the verdict half: over the accepted Vector 41, Vector 54 (rank 1)
/// is adopted over Vector 55 (rank 2) whichever a source serves first, and
/// Vector 55 is retained as a rank-2 suffix.
///
/// Mutant (run, then restored): the classifier takes the first exhausted
/// chain as the winner, so one order adopts Vector 55.
#[test]
fn vector_54_beats_vector_55_in_either_order_through_classify() -> TestResult {
    let v41 = Branch::v41()?;
    let v54 = v41_v54()?;
    let v55 = v41_v55()?;
    let v54_digest: [u8; 32] = fixtures::array(V54_DIGEST)?;
    let v55_digest: [u8; 32] = fixtures::array(V55_DIGEST)?;
    for (first, second) in [(&v54, &v55), (&v55, &v54)] {
        let mut units = first.units.clone();
        units.extend(second.units.iter().skip(1).cloned());
        let read = SourceRead {
            name: "a".to_owned(),
            units,
            exhaustion: SourceExhaustion::Exhausted,
            proof: operator(1),
        };
        let result = run(Some(&accepted(&v41)), &[read])?;
        assert_eq!(
            result.verdict,
            ResolutionVerdict::Adopted {
                head: v54_digest,
                baseline_decreased: false,
            }
        );
        let set = retention(&result)?;
        assert_eq!(set.basis().chain(), &chain_of(&v54)?);
        let retained = set.suffixes().first().ok_or("Vector 55 retained")?;
        assert_eq!(
            (retained.head(), retained.rank(), set.suffixes().len()),
            (v55_digest, ForkRank::Rank2, 1)
        );
    }
    Ok(())
}

/// `03-identity.md` §3.10.10: a `ResolvedState` reads what replaying the
/// adopted chain derived.
///
/// Mutant (run, then restored): `ResolvedState::of` reads the head digest
/// of the chain's prefix one event short.
#[test]
fn resolved_state_accessors_on_vector_41_50() -> TestResult {
    let v50 = v41_v50()?;
    let chain = chain_of(&v50)?;
    let read = |name: &str, n| SourceRead {
        name: name.to_owned(),
        units: v50.units.clone(),
        exhaustion: SourceExhaustion::Exhausted,
        proof: operator(n),
    };
    let result = run(None, &[read("a", 1), read("b", 2)])?;
    let state = key_state(&result)?;
    let replayed = replay(&chain);
    assert_eq!(state.identifier(), &fixtures::identifier(V41_IDENTIFIER)?);
    assert_eq!(state.head_digest(), fixtures::array::<32>(V50_DIGEST)?);
    assert_eq!(state.head_sequence(), 1);
    assert_eq!(state.key_state(), replayed.key_state());
    assert_eq!(state.standing_commitment(), replayed.standing_commitment());
    Ok(())
}

/// §9.18.7 and A10: a resolved state is fresh from its resolution instant
/// for fewer than 300 seconds, and never at an instant before it.
///
/// Mutants (each run, then restored): `map_or(true, …)`, which keeps a state
/// read before its resolution fresh; `d <= STALENESS`, which keeps it fresh
/// at 300 seconds.
#[test]
fn is_fresh_bounds() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let result = run(None, &two_sources(&[&o]))?;
    let state = key_state(&result)?;
    let at = |offset: i64| -> Result<SystemTime, Error> {
        let delta = Duration::from_secs(offset.unsigned_abs());
        Ok(if offset < 0 {
            now()?.checked_sub(delta)
        } else {
            now()?.checked_add(delta)
        }
        .ok_or("a representable instant")?)
    };
    assert!(!state.is_fresh(at(-1)?));
    assert!(state.is_fresh(at(0)?));
    assert!(state.is_fresh(at(299)?));
    assert!(!state.is_fresh(at(300)?));
    Ok(())
}

/// R9: a verdict rests on exhausted sources; a complete chain read from a
/// source stopped at the fetch bound is `MissingEvents` with no range,
/// because the verifier holds every sequence of the chain it assembled.
///
/// Mutant (run, then restored): `exhausted` keeps every source's chains, so
/// the stopped read is adopted.
#[test]
fn unexhausted_complete_chain_is_inconclusive() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let stopped = |name: &str, n| {
        source(
            name,
            &[&o],
            SourceExhaustion::StoppedAtFetchBound,
            operator(n),
        )
    };
    let result = run(None, &[stopped("a", 1), stopped("b", 2)])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Inconclusive {
            cause: InconclusiveCause::MissingEvents {
                range: SequenceRange {
                    from: None,
                    to: None
                },
                failed_sources: Vec::new(),
            },
        }
    );
    assert!(result.retention.is_none());
    Ok(())
}

/// R9's early stop at a first contact: R11's floor binds first, so a stopped
/// source alone, or beside one exhausted source, reaches no verdict past the
/// floor; with two proven exhausted sources serving the shared prefix, the
/// two rank-1 suffixes the stopped source served are
/// `Contested{Rank1Terminal}`, retained against that prefix.
///
/// Mutants (each run, then restored): `early_stop` returns `None`, so the
/// read is `MissingEvents`; the floor runs only past the early stop, so the
/// one-exhausted-source read is `Contested`.
#[test]
fn unexhausted_two_rank_one_suffixes_contest() -> TestResult {
    let mut keys = Keys::new()?;
    let v41 = Branch::v41()?;
    let a = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let b = Branch::of(&mut keys, &[Kind::CoSigns], 2)?;
    let stopped = source(
        "s",
        &[&a, &b],
        SourceExhaustion::StoppedAtFetchBound,
        operator(3),
    );
    let alone = run(None, std::slice::from_ref(&stopped))?;
    assert!(matches!(
        alone.verdict,
        ResolutionVerdict::Inconclusive {
            cause: InconclusiveCause::MissingEvents { .. }
        }
    ));
    let one = run(None, &[exhausted("a", &[&v41], 1), stopped.clone()])?;
    assert_eq!(
        one.verdict,
        ResolutionVerdict::Inconclusive {
            cause: InconclusiveCause::SingleSource {
                reached_sources: 2,
                proven_sources: 2,
                clock_skew_rejected: 0,
            }
        }
    );
    assert!(one.retention.is_none());
    let mut reads = two_sources(&[&v41]);
    reads.push(stopped);
    let result = run(None, &reads)?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank1Terminal,
            heads: sorted(vec![a.head(), b.head()]),
            shared_prefix_head: v41_digest(),
            fork_position: 1,
            residue: 0,
        }
    );
    let set = retention(&result)?;
    assert_eq!(set.basis(), &RetentionBasis::ContestedPrefix(v41.chain));
    assert_eq!(suffix_heads(set), sorted(vec![a.head(), b.head()]));
    Ok(())
}

/// R9's early stop requires every reveal on the tied pair's shared prefix to
/// carry a root signature: past a `{Lost}` recovery the stopped read is
/// `MissingEvents`, whether the verifier held the Vector 41 baseline, a
/// rank-3 baseline the tied chains beat, or a root-signed rollover that
/// beats them.
///
/// Mutant (run, then restored): `reveals_root_cosigned_through` returns
/// true, so the read is `Contested`.
#[test]
fn early_stop_refused_past_lost_prefix() -> TestResult {
    let mut keys = Keys::new()?;
    let lost = Branch::of(&mut keys, &[Kind::Lost], 0)?;
    let mut a = lost.clone();
    a.push(&mut keys, Kind::Reveal, 1)?;
    let mut b = lost;
    b.push(&mut keys, Kind::Reveal, 2)?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 3)?;
    let rollover = Branch::of(&mut keys, &[Kind::Reveal], 4)?;
    let read = source(
        "a",
        &[&a, &b],
        SourceExhaustion::StoppedAtFetchBound,
        operator(1),
    );
    let missing = ResolutionVerdict::Inconclusive {
        cause: InconclusiveCause::MissingEvents {
            range: SequenceRange {
                from: None,
                to: None,
            },
            failed_sources: Vec::new(),
        },
    };
    for baseline in [Branch::v41()?, o, rollover] {
        let held = accepted(&baseline);
        let result = run(Some(&held), std::slice::from_ref(&read))?;
        assert_eq!(result.verdict, missing);
        assert_eq!(result.retention.as_ref(), Some(&held));
    }
    Ok(())
}

/// R9's early stop ranks every chain the verifier holds: a stopped source
/// serving one rank-1 suffix ties a rank-1 suffix the set already retains.
///
/// Mutant (run, then restored): the ranking input leaves out the held
/// chains, so the served suffix wins alone and the read is `MissingEvents`.
#[test]
fn early_stop_reads_retained() -> TestResult {
    let mut keys = Keys::new()?;
    let v41 = Branch::v41()?;
    let a = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let b = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    let mut held = RetentionSet::new(RetentionBasis::ContestedPrefix(v41.chain.clone()));
    let _ = held.admit(a.chain.clone())?;
    let mut reads = two_sources(&[&v41]);
    reads.push(source(
        "s",
        &[&b],
        SourceExhaustion::StoppedAtFetchBound,
        operator(3),
    ));
    let result = run(Some(&held), &reads)?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank1Terminal,
            heads: sorted(vec![a.head(), b.head()]),
            shared_prefix_head: v41_digest(),
            fork_position: 1,
            residue: 0,
        }
    );
    assert_eq!(
        suffix_heads(retention(&result)?),
        sorted(vec![a.head(), b.head()])
    );
    Ok(())
}

/// R12: the candidate is ranked before R9 retains anything, so a winner R9
/// would refuse as a suffix is still adopted. The accepted chain runs one
/// event past a `{Lost}` recovery, and eight rank-1 rollovers forking after
/// that recovery fill the count bound, so a `{CoSigns}` recovery at Vector
/// 41 has no room as a suffix; it beats every held chain and is adopted.
///
/// Mutants (each run, then restored): the winner is ranked over the held
/// chains alone, where the eight rollovers beat the accepted chain and tie;
/// the residue counts the head the move evicted.
#[test]
fn refused_winner_still_adopted() -> TestResult {
    let mut keys = Keys::new()?;
    let lost = Branch::of(&mut keys, &[Kind::Lost], 0)?;
    let mut basis = lost.clone();
    basis.push(&mut keys, Kind::KeyState, 0)?;
    let mut held = accepted(&basis);
    for owner in 1..=8 {
        let mut attacker = lost.clone();
        attacker.push(&mut keys, Kind::Reveal, owner)?;
        let _ = held.admit(attacker.chain.clone())?;
    }
    assert_eq!(held.suffixes().len(), 8);
    assert!(
        held.suffixes()
            .iter()
            .all(|suffix| suffix.rank() == ForkRank::Rank1)
    );
    let o = Branch::of(&mut keys, &[Kind::CoSigns], 9)?;
    assert!(matches!(
        held.clone().admit(o.chain.clone())?,
        crate::Admission::Refused { .. }
    ));
    let result = run(Some(&held), &[exhausted("a", &[&o], 1)])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Adopted {
            head: o.head(),
            baseline_decreased: true,
        }
    );
    let set = retention(&result)?;
    assert_eq!(set.basis(), &RetentionBasis::Accepted(o.chain.clone()));
    // The replaced chain and the eight rollovers now fork at Vector 41 at
    // rank 2: nine held chains for eight places, so the move evicts one,
    // which R9's residue does not count: it was retained before.
    assert_eq!(set.suffixes().len(), 8);
    assert_eq!(result.residue, 0);
    // The set is the move's alone: the evicted chain is not re-admitted at
    // a new moment to evict another held chain in its place.
    let mut moved = held.clone();
    let _ = moved.rerank(RetentionBasis::Accepted(o.chain))?;
    assert_eq!(*set, moved);
    Ok(())
}

/// R7 at a first contact: two rank-3 suffixes tie as `Rank3Pending`, the set
/// is built against their shared prefix with both retained, and after a
/// persist and restore the same read classifies to the same verdict.
///
/// Mutant (run, then restored): `contested` admits no tied chain, so the set
/// retains nothing.
#[test]
fn first_contact_contest_retains_against_tie_prefix() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 1)?;
    let b = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    let reads = two_sources(&[&a, &b]);
    let first = run(None, &reads)?;
    let expected = ResolutionVerdict::Contested {
        tie: TieClass::Rank3Pending,
        heads: sorted(vec![a.head(), b.head()]),
        shared_prefix_head: v41_digest(),
        fork_position: 1,
        residue: 0,
    };
    assert_eq!(first.verdict, expected);
    assert!(first.key_state.is_none());
    let set = retention(&first)?;
    assert_eq!(
        set.basis(),
        &RetentionBasis::ContestedPrefix(Branch::v41()?.chain)
    );
    assert_eq!(suffix_heads(set), sorted(vec![a.head(), b.head()]));

    let restored = round_trip(set)?;
    assert_eq!(&restored, set);
    let again = run(Some(&restored), &reads)?;
    assert_eq!(again.verdict, expected);
    assert_eq!(suffix_heads(retention(&again)?), suffix_heads(set));
    Ok(())
}

/// R12 after a restart: a contested set restored from what it persisted
/// adopts a suffix that beats every chain it holds, and retains the tied
/// chains as losers.
///
/// Mutant (run, then restored): `classify` reads a held contested set as no
/// set, so the adopted set retains neither tied chain.
#[test]
fn restored_contest_adopts_a_suffix_beating_all() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 1)?;
    let b = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    let contest = run(None, &two_sources(&[&a, &b]))?;
    let restored = round_trip(retention(&contest)?)?;
    let c = Branch::of(&mut keys, &[Kind::Reveal], 3)?;
    let result = run(Some(&restored), &two_sources(&[&c]))?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Adopted {
            head: c.head(),
            baseline_decreased: false,
        }
    );
    let set = retention(&result)?;
    assert_eq!(set.basis(), &RetentionBasis::Accepted(c.chain));
    assert_eq!(suffix_heads(set), sorted(vec![a.head(), b.head()]));
    assert_eq!(round_trip(set)?, *set);
    Ok(())
}

/// R9 where the verifier holds an accepted chain A and two rank-1 chains
/// extending A tie: the verdict is `Contested`, A stays the accepted basis
/// ("A verifier never evicts the accepted chain") with the shared prefix,
/// A itself, recorded beside it, and both tied chains are retained as
/// suffixes past A's head at the tie's rank; the set survives a persist and
/// a restore against A.
///
/// Mutant (run, then restored): `after_contest` moves an accepted basis to
/// the shared prefix, so the basis is a contested prefix.
#[test]
fn baselined_contest_on_ties_extending_the_accepted_chain() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let mut t1 = a.clone();
    t1.push(&mut keys, Kind::Reveal, 1)?;
    let mut t2 = a.clone();
    t2.push(&mut keys, Kind::CoSigns, 2)?;
    let result = run(Some(&accepted(&a)), &[exhausted("a", &[&t1, &t2], 1)])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank1Terminal,
            heads: sorted(vec![t1.head(), t2.head()]),
            shared_prefix_head: a.head(),
            fork_position: 2,
            residue: 0,
        }
    );
    assert!(result.key_state.is_none());
    let set = retention(&result)?;
    assert_eq!(set.basis(), &RetentionBasis::Accepted(a.chain.clone()));
    assert_eq!(set.tie_prefix(), Some(&a.chain));
    assert_eq!(suffix_heads(set), sorted(vec![t1.head(), t2.head()]));
    assert!(
        set.suffixes()
            .iter()
            .all(|suffix| (suffix.rank(), suffix.fork_position()) == (ForkRank::Rank1, 2))
    );
    assert_eq!(round_trip(set)?, *set);
    Ok(())
}

/// R9 where both tied rank-1 chains beat the accepted chain A at Vector 41:
/// the verdict is `Contested`, A stays the accepted basis with Vector 41
/// recorded as the tie prefix, both tied chains are retained against A, and
/// `restore` against A accepts the set: a tie displaces no accepted chain,
/// only a suffix winning outright does.
///
/// Mutants (each run, then restored): `after_contest` records no tie
/// prefix; `restore` refuses an accepted basis a held-first tie displaces.
#[test]
fn baselined_contest_on_ties_beating_the_accepted_chain() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let t1 = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let t2 = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    let result = run(Some(&accepted(&a)), &[exhausted("a", &[&t1, &t2], 1)])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank1Terminal,
            heads: sorted(vec![t1.head(), t2.head()]),
            shared_prefix_head: v41_digest(),
            fork_position: 1,
            residue: 0,
        }
    );
    let set = retention(&result)?;
    assert_eq!(set.basis(), &RetentionBasis::Accepted(a.chain.clone()));
    assert_eq!(set.tie_prefix(), Some(&Branch::v41()?.chain));
    assert_eq!(suffix_heads(set), sorted(vec![t1.head(), t2.head()]));
    assert!(
        set.suffixes()
            .iter()
            .all(|suffix| (suffix.rank(), suffix.fork_position()) == (ForkRank::Rank1, 1))
    );
    let identifier = a.chain.identifier();
    assert_eq!(
        RetentionSet::restore(
            &identifier,
            &set.persisted(),
            AdoptedBasis::Accepted { head: a.head() }
        )?,
        *set
    );
    Ok(())
}

/// R9's downgrade guard: after a contest over the verifier's accepted chain
/// A, eight `RootRecovery{Lost}` forks below the tie prefix, served one per
/// resolution, never evict A and never make the prefix's state a served key
/// state; every read stays `Contested` over the same tie, the forks only
/// filling the room the tied chains leave.
///
/// Mutant (run, then restored): `after_contest` moves an accepted basis to
/// the shared prefix, so the basis is a contested prefix.
#[test]
fn baselined_contest_survives_lost_forks_below_the_prefix() -> TestResult {
    let mut keys = Keys::new()?;
    let p = Branch::of(&mut keys, &[Kind::Reveal], 0)?;
    let mut a = p.clone();
    a.push(&mut keys, Kind::KeyState, 0)?;
    let mut t1 = p.clone();
    t1.push(&mut keys, Kind::Reveal, 1)?;
    let mut t2 = p.clone();
    t2.push(&mut keys, Kind::Reveal, 2)?;
    let tie = ResolutionVerdict::Contested {
        tie: TieClass::Rank1Terminal,
        heads: sorted(vec![t1.head(), t2.head()]),
        shared_prefix_head: p.head(),
        fork_position: 2,
        residue: 0,
    };
    let first = run(Some(&accepted(&a)), &[exhausted("a", &[&t1, &t2], 1)])?;
    assert_eq!(first.verdict, tie);
    let mut set = retention(&first)?.clone();
    for owner in 3..=10 {
        let fork = Branch::of(&mut keys, &[Kind::Lost], owner)?;
        let result = run(Some(&set), &[exhausted("a", &[&fork], 1)])?;
        assert!(
            matches!(&result.verdict, ResolutionVerdict::Contested { heads, shared_prefix_head, .. }
                if *heads == sorted(vec![t1.head(), t2.head()]) && *shared_prefix_head == p.head())
        );
        assert!(result.key_state.is_none());
        set = retention(&result)?.clone();
        assert_eq!(set.basis(), &RetentionBasis::Accepted(a.chain.clone()));
        assert_eq!(set.tie_prefix(), Some(&p.chain));
        assert_eq!(round_trip(&set)?, set);
    }
    assert_eq!(set.suffixes().len(), 8);
    Ok(())
}

/// R9's fetch bound and R12: a verdict rests on chains the verifier read to
/// the end. A thief T served by two exhausted sources and a controller K
/// that beats T served only by a source stopped at the fetch bound is
/// `MissingEvents`, never `Adopted{T}`, and the same holds where a rank-2
/// tie's other head sits only on the stopped source.
///
/// Mutants (each run, then restored): the ranking input reads the exhausted
/// sources alone, so T is adopted; a winner on no read-through chain is
/// adopted; a tied head on no read-through chain is contested.
#[test]
fn winner_only_on_a_stopped_source_is_missing_events() -> TestResult {
    let mut keys = Keys::new()?;
    let thief = Branch::of(&mut keys, &[Kind::Lost], 1)?;
    let controller = Branch::of(&mut keys, &[Kind::CoSigns], 2)?;
    let rival = Branch::of(&mut keys, &[Kind::Lost], 3)?;
    let missing = ResolutionVerdict::Inconclusive {
        cause: InconclusiveCause::MissingEvents {
            range: SequenceRange {
                from: None,
                to: None,
            },
            failed_sources: Vec::new(),
        },
    };
    for other in [&controller, &rival] {
        let mut reads = two_sources(&[&thief]);
        reads.push(source(
            "padded",
            &[other],
            SourceExhaustion::StoppedAtFetchBound,
            operator(3),
        ));
        let result = run(None, &reads)?;
        assert_eq!(result.verdict, missing);
        assert!(result.retention.is_none());
    }
    Ok(())
}

/// R11: a source that served no valid chain counts toward the floor at no
/// degree, and neither does a source stopped at the fetch bound, however
/// its proof verified.
///
/// Mutants (each run, then restored): the floor counts a chainless
/// exhausted source; the floor counts a stopped source.
#[test]
fn floor_counts_only_exhausted_sources_serving_a_chain() -> TestResult {
    let mut keys = Keys::new()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let single = |reached| ResolutionVerdict::Inconclusive {
        cause: InconclusiveCause::SingleSource {
            reached_sources: reached,
            proven_sources: 2,
            clock_skew_rejected: 0,
        },
    };
    let chainless = run(None, &[exhausted("a", &[&o], 1), exhausted("b", &[], 2)])?;
    assert_eq!(chainless.verdict, single(2));
    let stopped = run(
        None,
        &[
            exhausted("a", &[&o], 1),
            source(
                "b",
                &[&o],
                SourceExhaustion::StoppedAtFetchBound,
                operator(2),
            ),
        ],
    )?;
    assert_eq!(stopped.verdict, single(2));
    Ok(())
}

/// R9's early stop needs a source stopped at the fetch bound: a source that
/// failed after serving two rank-1 suffixes leaves the baselined verifier
/// with no read-through chain, which is `MissingEvents`.
///
/// Mutant (run, then restored): `early_stop` drops the stopped-source
/// guard, so the failed read is `Contested`.
#[test]
fn early_stop_needs_a_stopped_source() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let b = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    let held = accepted(&Branch::v41()?);
    let read = source("f", &[&a, &b], SourceExhaustion::Failed, operator(1));
    let result = run(Some(&held), &[read])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Inconclusive {
            cause: InconclusiveCause::MissingEvents {
                range: SequenceRange {
                    from: None,
                    to: None,
                },
                failed_sources: vec!["f".to_owned()],
            },
        }
    );
    assert_eq!(result.retention.as_ref(), Some(&held));
    Ok(())
}

/// R9: a contested prefix is no accepted baseline, so R11's floor binds a
/// verifier holding one: a single proven source serving a chain that beats
/// every held chain is `SingleSource`, not `Adopted`.
///
/// Mutant (run, then restored): a contested-prefix basis reads as the
/// baseline, so the floor is skipped and the chain is adopted.
#[test]
fn contested_prefix_is_no_baseline() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 1)?;
    let b = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    let contest = run(None, &two_sources(&[&a, &b]))?;
    let held = retention(&contest)?;
    let c = Branch::of(&mut keys, &[Kind::Reveal], 3)?;
    let result = run(Some(held), &[exhausted("a", &[&c], 1)])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Inconclusive {
            cause: InconclusiveCause::SingleSource {
                reached_sources: 1,
                proven_sources: 1,
                clock_skew_rejected: 0,
            }
        }
    );
    assert_eq!(result.retention.as_ref(), Some(held));
    Ok(())
}

/// A held set of another identifier than the one resolved is refused with
/// a typed error before any source is read.
///
/// Mutant (run, then restored): the identifier check is skipped.
#[test]
fn held_set_of_another_identifier_is_refused() -> TestResult {
    let mut keys = Keys::new()?;
    let other = chain_of(&super::v42()?)?;
    let held = RetentionSet::new(RetentionBasis::Accepted(other.clone()));
    let o = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let reads = two_sources(&[&o]);
    let resolved = fixtures::identifier(V41_IDENTIFIER)?;
    let result = classify(ResolutionInput {
        identifier: resolved,
        held: Some(&held),
        reads: &reads,
        now: now()?,
    });
    assert_eq!(
        result.err(),
        Some(ClassifyError::HeldOfAnotherIdentifier {
            resolved,
            held: other.identifier(),
        })
    );
    Ok(())
}

/// R9's residue on a `Contested` verdict: nine rank-1 heads tie at a first
/// contact, eight fill the count bound, and the ninth is refused; the
/// verdict's residue and the classification's both report it.
///
/// Mutants (each run, then restored): `Contested.residue` reports zero;
/// `Classification.residue` reports zero.
#[test]
fn contested_residue_reports_refused_heads() -> TestResult {
    let mut keys = Keys::new()?;
    let mut branches = Vec::new();
    for owner in 1..=9 {
        branches.push(Branch::of(&mut keys, &[Kind::Reveal], owner)?);
    }
    let refs: Vec<&Branch> = branches.iter().collect();
    let result = run(None, &two_sources(&refs))?;
    let ResolutionVerdict::Contested { residue, heads, .. } = &result.verdict else {
        return Err("a contested verdict".into());
    };
    assert_eq!(heads.len(), 9);
    assert_eq!((*residue, result.residue), (1, 1));
    assert_eq!(retention(&result)?.suffixes().len(), 8);
    Ok(())
}

/// R12's `Discarded` needs every exhausted chain to be a proper prefix of
/// the accepted chain: one source serving the accepted chain itself and a
/// later one serving its prefix is `Confirmed`.
///
/// Mutant (run, then restored): the staleness fold keeps only the last
/// chain's answer, so the read is `Discarded`.
#[test]
fn one_current_source_beside_a_stale_one_confirms() -> TestResult {
    let mut keys = Keys::new()?;
    let v41 = Branch::v41()?;
    let o = Branch::of(&mut keys, &[Kind::KeyState, Kind::KeyState], 0)?;
    let reads = vec![exhausted("a", &[&o], 1), exhausted("b", &[&v41], 2)];
    let result = run(Some(&accepted(&o)), &reads)?;
    assert_eq!(result.verdict, ResolutionVerdict::Confirmed);
    Ok(())
}

/// Worked example 1 (R6, "Root compromised, P copied"): the controller's
/// chain is a root-signed rollover then a `{Lost}` recovery; the thief forks
/// at Vector 41 with a `{CoSigns}` recovery under Vector 41's root. Both
/// suffixes rank 1, so a first contact is `Contested{Rank1Terminal}`.
///
/// Mutant (run, then restored): `rank_past` ranks by the last reveal, so the
/// controller ranks 2 and the thief is adopted.
#[test]
fn worked_example_1_root_thief_forks_early() -> TestResult {
    let mut keys = Keys::new()?;
    let controller = Branch::of(&mut keys, &[Kind::Reveal, Kind::Lost], 0)?;
    let thief = Branch::of(&mut keys, &[Kind::CoSigns], 1)?;
    let result = run(None, &two_sources(&[&controller, &thief]))?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank1Terminal,
            heads: sorted(vec![controller.head(), thief.head()]),
            shared_prefix_head: v41_digest(),
            fork_position: 1,
            residue: 0,
        }
    );
    Ok(())
}

/// Worked example 2 (R6, "The controller wins outright"): the controller
/// holds Vector 54, a root-signed rollover (rank 1); the holder of a copied
/// pre-rotation key forks at Vector 41 with a `{Lost}` recovery (rank 2). A
/// verifier holding the controller's chain confirms it, and a first contact
/// adopts it.
///
/// Mutant (run, then restored): `rank_past` ranks a reveal without a root
/// signature at rank 1, so both tie and the verdict is `Contested`.
#[test]
fn worked_example_2_copied_pre_rotation_key_against_intact_root() -> TestResult {
    let mut keys = Keys::new()?;
    let v54 = v41_v54()?;
    let controller = chain_of(&v54)?;
    let copy = Branch::of(&mut keys, &[Kind::Lost], 1)?;
    let mut units = v54.units;
    units.extend(copy.base.units.iter().skip(1).cloned());
    let read = |name: &str, n| SourceRead {
        name: name.to_owned(),
        units: units.clone(),
        exhaustion: SourceExhaustion::Exhausted,
        proof: operator(n),
    };
    let held = RetentionSet::new(RetentionBasis::Accepted(controller.clone()));
    let baselined = run(Some(&held), &[read("a", 1)])?;
    assert_eq!(baselined.verdict, ResolutionVerdict::Confirmed);
    assert_eq!(suffix_heads(retention(&baselined)?), vec![copy.head()]);
    let first = run(None, &[read("a", 1), read("b", 2)])?;
    assert_eq!(
        first.verdict,
        ResolutionVerdict::Adopted {
            head: controller.head_digest(),
            baseline_decreased: false,
        }
    );
    Ok(())
}

/// Worked example 3 (R6, root-only suffixes): two root-signed `KeyState`
/// suffixes at Vector 41, one a `KeyState` longer, reveal nothing, so they
/// tie as `Contested{Rank3Pending}`.
///
/// Mutant (run, then restored): `rank_past` ranks a longer revealing-nothing
/// suffix above a shorter one, deciding by head sequence, so the longer one
/// is adopted.
#[test]
fn worked_example_3_two_root_only_suffixes() -> TestResult {
    let mut keys = Keys::new()?;
    let longer = Branch::of(&mut keys, &[Kind::KeyState, Kind::KeyState], 1)?;
    let shorter = Branch::of(&mut keys, &[Kind::KeyState], 2)?;
    let result = run(None, &two_sources(&[&longer, &shorter]))?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank3Pending,
            heads: sorted(vec![longer.head(), shorter.head()]),
            shared_prefix_head: v41_digest(),
            fork_position: 1,
            residue: 0,
        }
    );
    Ok(())
}

/// Worked example 4 (R6, "P copied, root lost"): the controller recovers
/// with `{Lost}` (rank 2); the thief, holding a copy of the spent key, forks
/// at Vector 41 and can only compose `{Lost}` too. Both rank 2, so the
/// verdict is `Contested{Rank2Terminal}`, for the controller's own verifier
/// as for a first contact.
///
/// Mutant (run, then restored): `rank_past` ranks a reveal without a root
/// signature at rank 1, so the class is `Rank1Terminal`.
#[test]
fn worked_example_4_spent_key_backup_reaches_root_thief() -> TestResult {
    let mut keys = Keys::new()?;
    let controller = Branch::of(&mut keys, &[Kind::Lost], 0)?;
    let thief = Branch::of(&mut keys, &[Kind::Lost], 1)?;
    let expected = ResolutionVerdict::Contested {
        tie: TieClass::Rank2Terminal,
        heads: sorted(vec![controller.head(), thief.head()]),
        shared_prefix_head: v41_digest(),
        fork_position: 1,
        residue: 0,
    };
    let reads = two_sources(&[&controller, &thief]);
    assert_eq!(run(None, &reads)?.verdict, expected);
    let held = accepted(&controller);
    let baselined = run(Some(&held), &reads)?;
    assert_eq!(baselined.verdict, expected);
    let set = retention(&baselined)?;
    assert_eq!(set.basis(), &RetentionBasis::Accepted(controller.chain));
    assert_eq!(set.tie_prefix(), Some(&Branch::v41()?.chain));
    assert_eq!(suffix_heads(set), vec![thief.head()]);
    Ok(())
}

/// Worked example 5 (R6, witnesses go silent): over the Vector 41 baseline,
/// Vector 50, a `KeyState` naming a new key state, extends the accepted
/// chain; no divergence exists and no rank is read, so it is adopted.
///
/// Mutant (run, then restored): `pair_chains` treats a chain extended by a
/// `KeyState` as diverged, so the two tie at rank 3 and the verdict is
/// `Contested{Rank3Pending}`.
#[test]
fn worked_example_5_witnesses_go_silent() -> TestResult {
    let v41 = Branch::v41()?;
    let v50 = v41_v50()?;
    let served = chain_of(&v50)?;
    assert_eq!(
        pair_chains(&served, &v41.chain)?,
        ChainPairing::RightPrefixOfLeft
    );
    let read = SourceRead {
        name: "a".to_owned(),
        units: v50.units,
        exhaustion: SourceExhaustion::Exhausted,
        proof: operator(1),
    };
    let result = run(Some(&accepted(&v41)), &[read])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Adopted {
            head: served.head_digest(),
            baseline_decreased: false,
        }
    );
    assert_eq!(retention(&result)?.basis().chain(), &served);
    Ok(())
}

/// R9's fetch bound across resolutions: a losing chain U that only a source
/// stopped at the fetch bound served is never retained. U beats the
/// accepted chain A and loses to both tied chains, so once the tied chains
/// leave the set, a held U would win and count as read; U is adopted only
/// after an exhausted source serves it.
///
/// Mutant (run, then restored): `contested` admits every ranked chain, so U
/// is retained and the second read adopts it.
#[test]
fn losing_chain_from_a_stopped_source_is_never_retained() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let shared = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let mut b = shared.clone();
    b.push(&mut keys, Kind::KeyState, 2)?;
    let mut c = shared.clone();
    c.push(&mut keys, Kind::KeyState, 3)?;
    let u = Branch::of(&mut keys, &[Kind::Lost], 4)?;
    let stopped = source(
        "s",
        &[&u],
        SourceExhaustion::StoppedAtFetchBound,
        operator(2),
    );
    let first = run(
        Some(&accepted(&a)),
        &[exhausted("a", &[&b, &c], 1), stopped],
    )?;
    assert_eq!(
        first.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank3Pending,
            heads: sorted(vec![b.head(), c.head()]),
            shared_prefix_head: shared.head(),
            fork_position: 2,
            residue: 0,
        }
    );
    let set = retention(&first)?;
    assert_eq!(suffix_heads(set), sorted(vec![b.head(), c.head()]));
    assert_eq!(set.tie_prefix(), Some(&shared.chain));
    assert_eq!(round_trip(set)?, *set);
    // The chains that beat U leave the set; every other suffix stays.
    let mut later = accepted(&a);
    for suffix in set.suffixes() {
        if suffix.head() != b.head() && suffix.head() != c.head() {
            let _ = later.admit(suffix.chain().clone())?;
        }
    }
    let again = run(Some(&later), &[exhausted("a", &[&a], 1)])?;
    assert_eq!(again.verdict, ResolutionVerdict::Confirmed);
    let served = run(Some(&later), &[exhausted("a", &[&u], 1)])?;
    assert_eq!(
        served.verdict,
        ResolutionVerdict::Adopted {
            head: u.head(),
            baseline_decreased: false,
        }
    );
    Ok(())
}

/// R9's eviction rank at the tie's fork: the accepted chain A rotates
/// between the tie prefix P and its head, so a tied chain T extending A
/// reads its rank against the commitment standing at P, which A's rotation
/// reveals under a root signature (rank 1). Against the commitment standing
/// at its own fork past A's head, where T reveals nothing, it would be rank
/// 3.
///
/// Mutant (run, then restored): `place` ranks an extension of the accepted
/// chain past the accepted head, so T is retained at rank 3.
#[test]
fn extension_of_a_rotated_accepted_chain_ranks_at_the_tie_fork() -> TestResult {
    let mut keys = Keys::new()?;
    let p = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let mut a = p.clone();
    a.push(&mut keys, Kind::Reveal, 0)?;
    let mut t = a.clone();
    t.push(&mut keys, Kind::KeyState, 0)?;
    let mut s = p.clone();
    s.push(&mut keys, Kind::Reveal, 1)?;
    let result = run(Some(&accepted(&a)), &[exhausted("a", &[&t, &s], 1)])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank1Terminal,
            heads: sorted(vec![t.head(), s.head()]),
            shared_prefix_head: p.head(),
            fork_position: 2,
            residue: 0,
        }
    );
    let set = retention(&result)?;
    assert_eq!(set.tie_prefix(), Some(&p.chain));
    let tied = set
        .suffixes()
        .iter()
        .find(|suffix| suffix.head() == t.head())
        .ok_or("T is retained")?;
    assert_eq!((tied.rank(), tied.fork_position()), (ForkRank::Rank1, 3));
    assert_eq!(round_trip(set)?, *set);
    Ok(())
}

/// A set over the accepted chain A after a `Rank3Pending` tie between A and
/// C past the prefix P, filled to the count bound by seven `{Lost}` forks
/// at Vector 41 that A beats (rank 2): C is the one rank-3 suffix.
struct RankThreeTie {
    keys: Keys,
    p: Branch,
    a: Branch,
    c: Branch,
    set: RetentionSet,
}

fn rank_three_tie() -> Result<RankThreeTie, Error> {
    let mut keys = Keys::new()?;
    let p = Branch::of(&mut keys, &[Kind::Reveal], 0)?;
    let mut a = p.clone();
    a.push(&mut keys, Kind::KeyState, 0)?;
    let mut c = p.clone();
    c.push(&mut keys, Kind::KeyState, 1)?;
    let mut forks = Vec::new();
    for owner in 2..=8 {
        forks.push(Branch::of(&mut keys, &[Kind::Lost], owner)?);
    }
    let first = run(Some(&accepted(&a)), &[exhausted("a", &[&c], 1)])?;
    let refs: Vec<&Branch> = forks.iter().collect();
    let filled = run(Some(retention(&first)?), &[exhausted("a", &refs, 1)])?;
    let set = retention(&filled)?.clone();
    assert_eq!(set.suffixes().len(), 8);
    assert_eq!(set.tie_prefix(), Some(&p.chain));
    assert!(set.suffixes().iter().all(|suffix| {
        let rank = if suffix.head() == c.head() {
            ForkRank::Rank3
        } else {
            ForkRank::Rank2
        };
        suffix.rank() == rank
    }));
    Ok(RankThreeTie { keys, p, a, c, set })
}

/// R7 and R9's tied-head rule: a `Rank3Pending` tied head C survives a
/// flood of rank-3 chains that tie with it, because none beats it under R6
/// and the rank-2 forks filling the set are not evictable for them; each
/// refused chain counts in the residue.
///
/// Mutant (run, then restored): `protected` protects no suffix, so the
/// first flood chain evicts C, the one rank-3 suffix.
#[test]
fn tied_head_survives_a_rank_3_flood() -> TestResult {
    let RankThreeTie {
        mut keys,
        p,
        a,
        c,
        set,
    } = rank_three_tie()?;
    let mut flood = Vec::new();
    for owner in 10..13 {
        let mut chain = p.clone();
        chain.push(&mut keys, Kind::KeyState, owner)?;
        flood.push(chain);
    }
    let refs: Vec<&Branch> = flood.iter().collect();
    let result = run(Some(&set), &[exhausted("a", &refs, 1)])?;
    let mut heads = vec![a.head(), c.head()];
    heads.extend(flood.iter().map(Branch::head));
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank3Pending,
            heads: sorted(heads),
            shared_prefix_head: p.head(),
            fork_position: 2,
            residue: 3,
        }
    );
    assert_eq!(result.residue, 3);
    assert_eq!(retention(&result)?.suffixes(), set.suffixes());
    Ok(())
}

/// R9's tied-head rule admits a candidate that beats the tied head: a
/// `{Lost}` recovery D at the tie's fork ranks 2 against C's 3, so it
/// evicts C, the suffix with the highest rank number, and no rank-2 fork.
///
/// Mutant (run, then restored): `protected` ignores whether the candidate
/// beats the tied head, so D evicts the latest rank-2 fork instead.
#[test]
fn candidate_beating_a_tied_head_may_evict_it() -> TestResult {
    let RankThreeTie {
        mut keys,
        p,
        c,
        mut set,
        ..
    } = rank_three_tie()?;
    let mut d = p;
    d.push(&mut keys, Kind::Lost, 9)?;
    assert_eq!(
        set.admit(d.chain)?,
        crate::Admission::Retained {
            rank: ForkRank::Rank2,
            evicted: vec![c.head()],
        }
    );
    Ok(())
}

/// R9's tied-head rule never blocks the controller: with the count bound
/// full of eight tied rank-3 heads at a first contact, the controller's
/// root-signed rollover beats every one of them, so it is admitted and
/// evicts the latest; the same read is adopted.
///
/// Mutant (run, then restored): `protected` ignores whether the candidate
/// beats the tied head, so the rollover is refused.
#[test]
fn controller_reveal_is_admitted_over_tied_rank_3_heads() -> TestResult {
    let mut keys = Keys::new()?;
    let mut heads = Vec::new();
    for owner in 1..=8 {
        heads.push(Branch::of(&mut keys, &[Kind::KeyState], owner)?);
    }
    let refs: Vec<&Branch> = heads.iter().collect();
    let contest = run(None, &two_sources(&refs))?;
    assert!(matches!(
        contest.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank3Pending,
            residue: 0,
            ..
        }
    ));
    let set = retention(&contest)?;
    assert_eq!(set.suffixes().len(), 8);
    let latest = set
        .suffixes()
        .iter()
        .max_by_key(|suffix| suffix.observed())
        .ok_or("a retained suffix")?
        .head();
    let reveal = Branch::of(&mut keys, &[Kind::Reveal], 9)?;
    assert_eq!(
        set.clone().admit(reveal.chain.clone())?,
        crate::Admission::Retained {
            rank: ForkRank::Rank1,
            evicted: vec![latest],
        }
    );
    let adopted = run(Some(set), &two_sources(&[&reveal]))?;
    assert_eq!(
        adopted.verdict,
        ResolutionVerdict::Adopted {
            head: reveal.head(),
            baseline_decreased: false,
        }
    );
    Ok(())
}

/// R12's `Confirmed` drops the tie prefix a `Contested` verdict recorded.
/// Eight `{Lost}` forks that the accepted chain A beats fill the count
/// bound, so the rank-3 chain tying A is refused (residue 1) and A then
/// beats every chain the set holds.
///
/// Mutant (run, then restored): `on_baseline` keeps the tie prefix, so the
/// confirmed set still records it.
#[test]
fn confirmed_after_a_refused_tie_drops_the_tie_prefix() -> TestResult {
    let mut keys = Keys::new()?;
    let p = Branch::of(&mut keys, &[Kind::Reveal], 0)?;
    let mut a = p.clone();
    a.push(&mut keys, Kind::KeyState, 0)?;
    let mut forks = Vec::new();
    for owner in 1..=8 {
        forks.push(Branch::of(&mut keys, &[Kind::Lost], owner)?);
    }
    let refs: Vec<&Branch> = forks.iter().collect();
    let filled = run(Some(&accepted(&a)), &[exhausted("a", &refs, 1)])?;
    assert_eq!(filled.verdict, ResolutionVerdict::Confirmed);
    let mut s = p.clone();
    s.push(&mut keys, Kind::KeyState, 9)?;
    let contest = run(Some(retention(&filled)?), &[exhausted("a", &[&s], 1)])?;
    assert!(matches!(
        contest.verdict,
        ResolutionVerdict::Contested { residue: 1, .. }
    ));
    let contested = retention(&contest)?;
    assert_eq!(contested.tie_prefix(), Some(&p.chain));
    let confirmed = run(Some(contested), &[exhausted("a", &[&a], 1)])?;
    assert_eq!(confirmed.verdict, ResolutionVerdict::Confirmed);
    let set = retention(&confirmed)?;
    assert_eq!(set.tie_prefix(), None);
    assert_eq!(set.suffixes(), contested.suffixes());
    Ok(())
}

/// `restore` refuses a tie prefix on no chain the set holds: a `{Lost}`
/// fork's head, persisted with its unit beside a contest whose tied chains
/// fork at Vector 41, is neither a prefix of the accepted chain nor of a
/// retained suffix.
///
/// Mutant (run, then restored): `restore` skips the check, so the set
/// restores with the stray prefix.
#[test]
fn restore_refuses_a_tie_prefix_off_the_held_chains() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let t1 = Branch::of(&mut keys, &[Kind::Reveal], 1)?;
    let t2 = Branch::of(&mut keys, &[Kind::Reveal], 2)?;
    let stray = Branch::of(&mut keys, &[Kind::Lost], 3)?;
    let result = run(Some(&accepted(&a)), &[exhausted("a", &[&t1, &t2], 1)])?;
    let set = retention(&result)?;
    assert_eq!(set.tie_prefix(), Some(&Branch::v41()?.chain));
    let mut saved = set.persisted();
    let unit = stray.base.units.last().ok_or("the fork's unit")?;
    saved.units.push(std::sync::Arc::from(unit.as_slice()));
    saved.basis.tie_prefix = Some(stray.head());
    assert_eq!(
        RetentionSet::restore(
            &a.chain.identifier(),
            &saved,
            AdoptedBasis::Accepted { head: a.head() },
        ),
        Err(super::super::RestoreError::TiePrefixOffHeldChains { head: stray.head() })
    );
    Ok(())
}

/// R9's byte bound where the tie prefix P extends the accepted chain A: both
/// tied suffixes start past A's head, so each holds P's event past A, and
/// the byte bound counts that event once.
///
/// Mutant (run, then restored): the tally sums each suffix's events, so
/// P's event counts twice.
#[test]
fn tied_suffixes_past_the_accepted_head_count_the_prefix_once() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::KeyState], 0)?;
    let mut p = a.clone();
    p.push(&mut keys, Kind::KeyState, 0)?;
    let mut t1 = p.clone();
    t1.push(&mut keys, Kind::Reveal, 1)?;
    let mut t2 = p.clone();
    t2.push(&mut keys, Kind::CoSigns, 2)?;
    let result = run(Some(&accepted(&a)), &[exhausted("a", &[&t1, &t2], 1)])?;
    assert!(matches!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank1Terminal,
            fork_position: 3,
            ..
        }
    ));
    let set = retention(&result)?;
    assert_eq!(set.tie_prefix(), Some(&p.chain));
    assert!(
        set.suffixes()
            .iter()
            .all(|suffix| suffix.fork_position() == 2)
    );
    let len = |branch: &Branch, index: usize| branch.unit_lens.get(index).copied();
    let expected = [len(&p, 2), len(&t1, 3), len(&t2, 3)]
        .into_iter()
        .sum::<Option<u64>>()
        .ok_or("three unit lengths")?;
    assert_eq!(set.retained_bytes(), expected);
    Ok(())
}

/// R9's tie prefix where the bounds refuse every tied chain: eight `{Lost}`
/// forks that the accepted chain A beats fill the count bound, and the
/// tied chains past the prefix P, which extends A, rank 3 and evict no
/// rank-2 fork. The set records no tie prefix, persists no event of P past
/// A, and round-trips; the stored bytes are A's and the tally's.
///
/// Mutant (run, then restored): `after_contest` skips settling the tie
/// prefix, so the set records P, which no held chain carries, and
/// `restore` refuses it.
#[test]
fn refused_tie_records_no_prefix_and_round_trips() -> TestResult {
    let mut keys = Keys::new()?;
    let a = Branch::of(&mut keys, &[Kind::Reveal], 0)?;
    let mut p = a.clone();
    p.push(&mut keys, Kind::KeyState, 0)?;
    let mut t1 = p.clone();
    t1.push(&mut keys, Kind::KeyState, 1)?;
    let mut t2 = p.clone();
    t2.push(&mut keys, Kind::KeyState, 2)?;
    let mut forks = Vec::new();
    for owner in 3..=10 {
        forks.push(Branch::of(&mut keys, &[Kind::Lost], owner)?);
    }
    let refs: Vec<&Branch> = forks.iter().collect();
    let filled = run(Some(&accepted(&a)), &[exhausted("a", &refs, 1)])?;
    assert_eq!(filled.verdict, ResolutionVerdict::Confirmed);
    let result = run(Some(retention(&filled)?), &[exhausted("a", &[&t1, &t2], 1)])?;
    assert_eq!(
        result.verdict,
        ResolutionVerdict::Contested {
            tie: TieClass::Rank3Pending,
            heads: sorted(vec![t1.head(), t2.head()]),
            shared_prefix_head: p.head(),
            fork_position: 3,
            residue: 2,
        }
    );
    let set = retention(&result)?;
    assert_eq!(set.tie_prefix(), None);
    assert_eq!(set.suffixes().len(), 8);
    assert_eq!(round_trip(set)?, *set);
    let stored: u64 = set
        .persisted()
        .units
        .iter()
        .map(|unit| unit.len() as u64)
        .sum();
    assert_eq!(
        stored,
        a.unit_lens.iter().sum::<u64>() + set.retained_bytes()
    );
    Ok(())
}
