//! The candidate rule, assembly by predecessor digest, and the signing rule
//! (`09-security-model.md` §9.7.4.2 R3, R9, R10).

use scp_did::Identifier;
use scp_kel::{
    CheckStep, Discarded, EntryVerdict, EventKind, FailureClass, HeldHead, HeldHeadMarker,
    HeldHeadMarkerError, InceptionDefect, InceptionRefusal, MarkerMode, SigningChange,
    SigningRefusal, ValidatedChain, validate_entry,
};

use super::chain_rows::a26_on_v41;
use super::chain_support::{
    Base, Error, Ring, flip, key_state_on, sha256, sign_on, signature_field_at, signed_of, v41,
    v41_changed, v41_digest, v41_v50, v41_v53, v41_v54, v41_v55,
};
use super::chain_valid::{chain_of, valid};
use super::fixtures::{TestResult, V41_IDENTIFIER, identifier};

/// The units the tests in this module serve.
struct Units {
    v41: Vec<u8>,
    /// Vector 50, the §25.26 `KeyState` at position 1.
    v50: Vec<u8>,
    /// Another legal `KeyState` at position 1, signed by Vector 41's root.
    other: Vec<u8>,
    /// A third legal `KeyState` at position 1.
    third: Vec<u8>,
    /// C16-on-V41: a `KeyState` at position 1 carrying two `Current`
    /// `#active` keys.
    a26: Vec<u8>,
    /// A `KeyState` at position 2 on `other`, its signature damaged.
    damaged_on_other: Vec<u8>,
}

impl Units {
    fn new() -> Result<Self, Error> {
        let ring = Ring::new()?;
        let base = v41()?;
        let v50 = v41_v50()?.units.last().ok_or("no V50 unit")?.clone();
        let mut changed = v41_changed()?;
        changed.witnessing_interval = 86_400;
        let other = sign_on(&ring, &base, &key_state_on(&base, changed.clone()))?;
        changed.witnessing_interval = 172_800;
        let third = sign_on(&ring, &base, &key_state_on(&base, changed.clone()))?;
        let v41 = base.units.first().ok_or("no V41 unit")?.clone();
        let on_other = Base {
            name: "V41,other",
            identifier: base.identifier,
            units: vec![v41.clone(), other.clone()],
            head: sha256(&[signed_of(&other)?]),
            root: base.root,
        };
        changed.witnessing_interval = 3_600;
        let next = sign_on(&ring, &on_other, &key_state_on(&on_other, changed))?;
        let damaged_on_other = flip(&next, signature_field_at(&next)? + 10)?;
        Ok(Self {
            v41,
            v50,
            other,
            third,
            a26: a26_on_v41(&ring)?,
            damaged_on_other,
        })
    }
}

fn served() -> Result<Identifier, Error> {
    identifier(V41_IDENTIFIER)
}

/// The digest of a unit's signed preimage, hashed here rather than by the
/// helper `Discarded` is compared against elsewhere.
fn hash_of(unit: &[u8]) -> Result<[u8; 32], Error> {
    Ok(sha256(&[signed_of(unit)?]))
}

/// What one discard carries.
struct Expected {
    served_index: usize,
    /// The position the unit was read for; `None` where it joined no chain.
    read_for: Option<u64>,
    stage: CheckStep,
    class: FailureClass,
    digest: Option<[u8; 32]>,
}

fn assert_discard(discard: &Discarded, expected: &Expected) -> TestResult {
    let found = (
        discard.served_index(),
        discard.read_for(),
        discard.stage(),
        discard.class(),
        discard.digest(),
    );
    let wanted = (
        expected.served_index,
        expected.read_for,
        expected.stage,
        expected.class,
        expected.digest,
    );
    if found == wanted {
        Ok(())
    } else {
        Err(format!("wanted {wanted:?}, found {discard:?}").into())
    }
}

/// A separator flipped: the unit joins no chain.
const fn unseparated_at(served_index: usize) -> Expected {
    Expected {
        served_index,
        read_for: None,
        stage: CheckStep::Separator,
        class: FailureClass::Illegal,
        digest: None,
    }
}

/// C16-on-V41, read for position 1 and illegal there.
fn a26_at(served_index: usize, units: &Units) -> Result<Expected, Error> {
    Ok(Expected {
        served_index,
        read_for: Some(1),
        stage: CheckStep::Content,
        class: FailureClass::Illegal,
        digest: Some(hash_of(&units.a26)?),
    })
}

/// C18: a unit discarded at position 1 leaves it open, and the next unit
/// fills it.
#[test]
fn a_discarded_candidate_leaves_its_position_open() -> TestResult {
    let units = Units::new()?;
    let (chain, discarded) = valid(&served()?, &[&units.v41, &units.a26, &units.v50])?;
    assert_eq!(chain, chain_of(&v41_v50()?)?);
    let [discard] = discarded.as_slice() else {
        return Err(format!("C18: {discarded:?}").into());
    };
    assert_discard(discard, &a26_at(1, &units)?)
}

/// C19: a unit that never reached step 6 carries no digest, and one whose
/// predecessor digest never decoded joins no chain.
#[test]
fn a_unit_without_a_separator_carries_no_digest() -> TestResult {
    let units = Units::new()?;
    let unseparated = flip(&units.v50, 4)?;
    let (chain, discarded) = valid(&served()?, &[&units.v41, &unseparated, &units.v50])?;
    assert_eq!(chain, chain_of(&v41_v50()?)?);
    let [discard] = discarded.as_slice() else {
        return Err(format!("C19: {discarded:?}").into());
    };
    assert_discard(discard, &unseparated_at(1))
}

/// C20: the candidate rule at position zero.
#[test]
fn a_discarded_inception_candidate_leaves_position_zero_open() -> TestResult {
    let units = Units::new()?;
    let rebound = flip(&units.v41, signature_field_at(&units.v41)? - 1)?;
    let (chain, discarded) = valid(&served()?, &[&rebound, &units.v41, &units.v50])?;
    assert_eq!(chain, chain_of(&v41_v50()?)?);
    let [discard] = discarded.as_slice() else {
        return Err(format!("C20: {discarded:?}").into());
    };
    assert_discard(
        discard,
        &Expected {
            served_index: 0,
            read_for: Some(0),
            stage: CheckStep::InceptionBinding,
            class: FailureClass::ProvesNothing,
            digest: None,
        },
    )
}

/// A unit naming the all-zero predecessor is read for position zero, where
/// it recomputes to another identifier.
#[test]
fn a_later_event_naming_the_zero_predecessor_is_read_for_position_zero() -> TestResult {
    let ring = Ring::new()?;
    let units = Units::new()?;
    let base = v41()?;
    let mut zero = key_state_on(&base, v41_changed()?);
    zero.predecessor_digest = [0; 32];
    let zero = sign_on(&ring, &base, &zero)?;
    let (chain, discarded) = valid(&served()?, &[&units.v41, &zero])?;
    assert_eq!(chain, chain_of(&base)?);
    let [discard] = discarded.as_slice() else {
        return Err(format!("{discarded:?}").into());
    };
    assert_discard(
        discard,
        &Expected {
            served_index: 1,
            read_for: Some(0),
            stage: CheckStep::InceptionBinding,
            class: FailureClass::ProvesNothing,
            digest: None,
        },
    )
}

/// Two discards at one position, then the unit that fills it.
#[test]
fn every_discard_at_an_open_position_is_reported_in_served_order() -> TestResult {
    let units = Units::new()?;
    let junk = flip(&units.v50, 4)?;
    let (chain, discarded) = valid(&served()?, &[&units.v41, &junk, &units.a26, &units.v50])?;
    assert_eq!(chain.head_digest(), hash_of(&units.v50)?);
    let [first, second] = discarded.as_slice() else {
        return Err(format!("{discarded:?}").into());
    };
    assert_discard(first, &unseparated_at(1))?;
    assert_discard(second, &a26_at(2, &units)?)
}

/// A unit naming `[0x44; 32]` as its predecessor, which no chain holds.
fn orphan() -> Result<Vec<u8>, Error> {
    let ring = Ring::new()?;
    let base = v41()?;
    let mut orphan = key_state_on(&base, v41_changed()?);
    orphan.predecessor_digest = [0x44; 32];
    sign_on(&ring, &base, &orphan)
}

const fn orphan_at(served_index: usize) -> Expected {
    Expected {
        served_index,
        read_for: None,
        stage: CheckStep::Header,
        class: FailureClass::ProvesNothing,
        digest: None,
    }
}

/// Discards found at assembly, on a path, and after the walk are reported
/// once each, in served order, whatever order they were found in.
#[test]
fn discards_are_reported_in_served_order() -> TestResult {
    let units = Units::new()?;
    let unseparated = flip(&units.v50, 4)?;
    let (chain, discarded) = valid(
        &served()?,
        &[&units.v41, &orphan()?, &units.a26, &unseparated, &units.v50],
    )?;
    assert_eq!(chain, chain_of(&v41_v50()?)?);
    let [first, second, third] = discarded.as_slice() else {
        return Err(format!("{discarded:?}").into());
    };
    assert_discard(first, &orphan_at(1))?;
    assert_discard(second, &a26_at(2, &units)?)?;
    assert_discard(third, &unseparated_at(3))
}

/// The chains of a `Valid` verdict, in the order `validate_entry` returns
/// them, and its discards.
fn entry_chains(units: &[&[u8]]) -> Result<(Vec<ValidatedChain>, Vec<Discarded>), Error> {
    let validation = validate_entry(&served()?, units);
    match validation.verdict {
        EntryVerdict::Valid { chains } => {
            Ok((chains.iter().cloned().collect(), validation.discarded))
        }
        other => Err(format!("expected Valid, got {other:?}").into()),
    }
}

/// C21: legal events at one position are one chain each, never a discard,
/// and the chains come in served order, unsorted.
#[test]
fn a_fork_is_one_chain_per_event_in_served_order() -> TestResult {
    let units = Units::new()?;
    let (v50, other, third) = (&units.v50, &units.other, &units.third);
    for served in [
        [v50, other, third],
        [third, other, v50],
        [other, v50, third],
    ] {
        let (chains, discarded) = entry_chains(&[&units.v41, served[0], served[1], served[2]])?;
        assert!(discarded.is_empty(), "{discarded:?}");
        let heads: Vec<[u8; 32]> = chains.iter().map(ValidatedChain::head_digest).collect();
        let expected = served
            .iter()
            .map(|unit| hash_of(unit))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(heads, expected);
    }
    Ok(())
}

/// A fork reports a discard at the fork and one on the later branch, once
/// each, and each chain holds its own branch.
#[test]
fn discards_at_and_below_a_fork_are_reported_once() -> TestResult {
    let units = Units::new()?;
    let (chains, discarded) = entry_chains(&[
        &units.v41,
        &units.v50,
        &units.a26,
        &units.other,
        &units.damaged_on_other,
    ])?;
    let heads: Vec<[u8; 32]> = chains.iter().map(ValidatedChain::head_digest).collect();
    assert_eq!(heads, vec![hash_of(&units.v50)?, hash_of(&units.other)?]);
    let [at_fork, on_branch] = discarded.as_slice() else {
        return Err(format!("{discarded:?}").into());
    };
    assert_discard(at_fork, &a26_at(2, &units)?)?;
    assert_discard(
        on_branch,
        &Expected {
            served_index: 4,
            read_for: Some(2),
            stage: CheckStep::VerifiedCount,
            class: FailureClass::CopyDamage,
            digest: Some(hash_of(&units.damaged_on_other)?),
        },
    )
}

/// C23: a unit naming a predecessor no chain holds joins no chain.
#[test]
fn a_unit_naming_no_held_predecessor_is_unplaced() -> TestResult {
    let units = Units::new()?;
    let (chain, discarded) = valid(&served()?, &[&units.v41, &orphan()?])?;
    assert_eq!(chain.head_digest(), v41_digest()?);
    let [unplaced] = discarded.as_slice() else {
        return Err(format!("C23: {discarded:?}").into());
    };
    assert_discard(unplaced, &orphan_at(1))
}

/// Criterion 33: copies sharing an event digest merge before forks split,
/// in either served order and at either position, and the chain carries the
/// copy that verifies.
#[test]
fn copies_of_one_event_merge_in_either_order() -> TestResult {
    let units = Units::new()?;
    let damaged = flip(&units.v50, signature_field_at(&units.v50)? + 10)?;
    let damaged_v41 = flip(&units.v41, signature_field_at(&units.v41)? + 10)?;
    let expected = chain_of(&v41_v50()?)?;
    for order in [
        [&units.v41, &damaged, &units.v50],
        [&units.v41, &units.v50, &damaged],
        [&damaged_v41, &units.v41, &units.v50],
        [&units.v41, &damaged_v41, &units.v50],
    ] {
        let units: Vec<&[u8]> = order.iter().map(|unit| unit.as_slice()).collect();
        let (chain, discarded) = valid(&served()?, &units)?;
        assert!(discarded.is_empty(), "{discarded:?}");
        assert_eq!(chain, expected);
    }
    Ok(())
}

/// The head a device holds after adopting `chain`.
fn held(chain: &ValidatedChain, mode: MarkerMode) -> HeldHead {
    HeldHead::from_marker(&HeldHeadMarker::adopt(chain, mode))
}

/// R10: a device signs a legal event at the head it holds.
#[test]
fn the_held_head_signs_a_legal_next_event() -> TestResult {
    let units = Units::new()?;
    let chain = chain_of(&v41()?)?;
    let change = held(&chain, MarkerMode::Any)
        .check_next(&chain, signed_of(&units.v50)?)
        .map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(change.change().effect().kind, EventKind::KeyState);
    assert_eq!(change.change().preimage(), signed_of(&units.v50)?);
    Ok(())
}

/// A chain handed at the held head's height that ends at another event is
/// stale.
#[test]
fn an_equal_height_chain_at_another_head_is_stale() -> TestResult {
    let units = Units::new()?;
    let (held_chain, _) = valid(&served()?, &[&units.v41, &units.other])?;
    let (handed, _) = valid(&served()?, &[&units.v41, &units.v50])?;
    assert_eq!(held_chain.head_sequence(), handed.head_sequence());
    let refusal = held(&held_chain, MarkerMode::Any).check_next(&handed, signed_of(&units.a26)?);
    assert_eq!(
        refusal,
        Err(SigningRefusal::Stale {
            handed: handed.head_digest(),
            held: held_chain.head_digest(),
        })
    );
    Ok(())
}

/// A chain handed below the held head, here its own prefix, is stale.
#[test]
fn a_truncated_chain_is_stale() -> TestResult {
    let units = Units::new()?;
    let whole = chain_of(&v41_v50()?)?;
    let truncated = chain_of(&v41()?)?;
    let refusal = held(&whole, MarkerMode::Any).check_next(&truncated, signed_of(&units.other)?);
    assert_eq!(
        refusal,
        Err(SigningRefusal::Stale {
            handed: v41_digest()?,
            held: hash_of(&units.v50)?,
        })
    );
    Ok(())
}

#[test]
fn the_held_head_refuses_an_illegal_event() -> TestResult {
    let units = Units::new()?;
    let chain = chain_of(&v41()?)?;
    match held(&chain, MarkerMode::Any).check_next(&chain, signed_of(&units.a26)?) {
        Err(SigningRefusal::Illegal(discard)) => assert_discard(
            &discard,
            &Expected {
                served_index: 0,
                ..a26_at(0, &units)?
            },
        ),
        other => Err(format!("{other:?}").into()),
    }
}

/// A legal next event on Vector 41 of each kind, or `None` for a kind no
/// event past the inception takes.
fn next_of_kind(kind: EventKind) -> Result<Option<Vec<u8>>, Error> {
    let last = |units: Vec<Vec<u8>>| units.last().cloned().ok_or("no unit");
    Ok(match kind {
        EventKind::Inception => None,
        EventKind::KeyState => Some(last(v41_v50()?.units)?),
        EventKind::CommitmentRollover => Some(last(v41_v53()?.units)?),
        EventKind::RootRecovery => Some(last(v41_v54()?.units)?),
    })
}

/// Under `RevealOnly` the head signs a reveal-authorized event alone: a
/// `CommitmentRollover` and either `RootRecovery`, never a `KeyState`. An
/// inception is illegal at any later position under either mode.
#[test]
fn a_reveal_only_marker_signs_reveals_alone() -> TestResult {
    let units = Units::new()?;
    let chain = chain_of(&v41()?)?;
    let reveal_only = held(&chain, MarkerMode::RevealOnly);
    let any = held(&chain, MarkerMode::Any);
    for kind in [
        EventKind::Inception,
        EventKind::KeyState,
        EventKind::CommitmentRollover,
        EventKind::RootRecovery,
    ] {
        let reveal_authorized = match kind {
            EventKind::Inception | EventKind::KeyState => false,
            EventKind::CommitmentRollover | EventKind::RootRecovery => true,
        };
        let Some(unit) = next_of_kind(kind)? else {
            for head in [&reveal_only, &any] {
                assert!(
                    matches!(
                        head.check_next(&chain, signed_of(&units.v41)?),
                        Err(SigningRefusal::Illegal(_))
                    ),
                    "{kind:?}"
                );
            }
            continue;
        };
        let signed = signed_of(&unit)?;
        let accepted = any
            .check_next(&chain, signed)
            .map_err(|refusal| format!("{kind:?}: {refusal:?}"))?;
        assert_eq!(accepted.change().effect().kind, kind);
        let under_reveal_only = reveal_only.check_next(&chain, signed);
        if reveal_authorized {
            assert_eq!(under_reveal_only, Ok(accepted), "{kind:?}");
        } else {
            assert_eq!(
                under_reveal_only,
                Err(SigningRefusal::RevealOnly {
                    held: v41_digest()?,
                }),
                "{kind:?}"
            );
        }
    }
    let lost = v41_v55()?.units.last().cloned().ok_or("no V55 unit")?;
    let change = reveal_only
        .check_next(&chain, signed_of(&lost)?)
        .map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(change.change().effect().kind, EventKind::RootRecovery);
    Ok(())
}

/// The marker a device adopts names the chain's head, round-trips through
/// its bytes, and refuses bad bytes.
#[test]
fn the_marker_round_trips_and_refuses_bad_bytes() -> TestResult {
    let chain = chain_of(&v41_v50()?)?;
    for mode in [MarkerMode::Any, MarkerMode::RevealOnly] {
        let marker = HeldHeadMarker::adopt(&chain, mode);
        assert_eq!(marker.identifier(), served()?);
        assert_eq!(marker.sequence(), 1);
        assert_eq!(marker.event_digest(), chain.head_digest());
        assert_eq!(marker.mode(), mode);
        assert_eq!(HeldHead::from_marker(&marker).marker(), marker);
        let bytes = marker.to_bytes();
        assert_eq!(bytes.len(), 73);
        assert_eq!(
            bytes.last(),
            Some(&u8::from(mode == MarkerMode::RevealOnly))
        );
        assert_eq!(HeldHeadMarker::from_bytes(&bytes), Ok(marker));
        assert_eq!(
            HeldHeadMarker::from_bytes(bytes.get(..72).ok_or("short")?),
            Err(HeldHeadMarkerError::Length { len: 72 })
        );
        let mut bad = bytes;
        if let Some(last) = bad.last_mut() {
            *last = 0x02;
        }
        assert_eq!(
            HeldHeadMarker::from_bytes(&bad),
            Err(HeldHeadMarkerError::Mode { byte: 0x02 })
        );
    }
    Ok(())
}

#[test]
fn signing_an_inception_runs_r2() -> TestResult {
    let units = Units::new()?;
    let change = SigningChange::inception(signed_of(&units.v41)?)
        .map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(change.change().effect().kind, EventKind::Inception);
    let mut nonzero = signed_of(&units.v41)?.to_vec();
    // Field 3, the sequence, ends at separator + 1 + 32 + 8.
    let last_sequence_byte = 17 + 1 + 32 + 7;
    let byte = nonzero.get_mut(last_sequence_byte).ok_or("short")?;
    *byte = 0x01;
    match SigningChange::inception(&nonzero) {
        Err(InceptionRefusal::Invalid(InceptionDefect::ZeroCheck(defect))) => {
            assert_eq!(defect, scp_kel::InceptionHeaderDefect::NonzeroSequence);
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}
