//! The candidate rule, assembly by predecessor digest, and the signing rule
//! (`09-security-model.md` §9.7.4.2 R3, R9, R10).

use scp_did::Identifier;
use scp_kel::{
    ChainValidation, CheckStep, Discarded, EntryValidation, EventKind, HeldHead, HeldHeadMarker,
    HeldHeadMarkerError, InceptionDefect, InceptionRefusal, MarkerMode, SigningChange,
    SigningRefusal, ValidatedChain, validate_chain, validate_entry,
};

use super::chain_rows::a26_on_v41;
use super::chain_support::{
    Error, Ring, flip, key_state_on, sha256, sign_on, signature_field_at, signed_of, v41,
    v41_changed, v41_digest, v41_v50, v41_v53,
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
    /// C16-on-V41: a `KeyState` at position 1 carrying two `Current`
    /// `#active` keys.
    a26: Vec<u8>,
}

impl Units {
    fn new() -> Result<Self, Error> {
        let ring = Ring::new()?;
        let base = v41()?;
        let v50 = v41_v50()?.units.last().ok_or("no V50 unit")?.clone();
        let mut changed = v41_changed()?;
        changed.witnessing_interval = 86_400;
        let other = sign_on(&ring, &base, &key_state_on(&base, changed))?;
        Ok(Self {
            v41: base.units.first().ok_or("no V41 unit")?.clone(),
            v50,
            other,
            a26: a26_on_v41(&ring)?,
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

fn assert_discard(
    discard: &Discarded,
    at: u64,
    stage: CheckStep,
    digest: Option<[u8; 32]>,
) -> TestResult {
    let found = (discard.at_position(), discard.stage(), discard.digest());
    if found == (at, stage, digest) {
        Ok(())
    } else {
        Err(format!("wanted {:?}, found {discard:?}", (at, stage, digest)).into())
    }
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
    assert_discard(discard, 1, CheckStep::Content, Some(hash_of(&units.a26)?))
}

/// C19: a unit that never reached step 6 carries no digest.
#[test]
fn a_unit_without_a_separator_carries_no_digest() -> TestResult {
    let units = Units::new()?;
    let unseparated = flip(&units.v50, 4)?;
    let (chain, discarded) = valid(&served()?, &[&units.v41, &unseparated, &units.v50])?;
    assert_eq!(chain, chain_of(&v41_v50()?)?);
    let [discard] = discarded.as_slice() else {
        return Err(format!("C19: {discarded:?}").into());
    };
    assert_discard(discard, 1, CheckStep::Separator, None)
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
    assert_discard(discard, 0, CheckStep::InceptionBinding, None)
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
    assert_discard(first, 1, CheckStep::Separator, None)?;
    assert_discard(second, 1, CheckStep::Content, Some(hash_of(&units.a26)?))
}

fn entry_chains(units: &[&[u8]]) -> Result<EntryValidation, Error> {
    Ok(validate_entry(&served()?, units))
}

fn valid_chain(verdict: &ChainValidation) -> Result<&ValidatedChain, Error> {
    match verdict {
        ChainValidation::Valid { chain, discarded } if discarded.is_empty() => Ok(chain),
        other => Err(format!("expected Valid without discards, got {other:?}").into()),
    }
}

/// C21: two legal events at one position are two chains, never a discard.
#[test]
fn a_fork_is_two_chains() -> TestResult {
    let units = Units::new()?;
    let entry = entry_chains(&[&units.v41, &units.v50, &units.other])?;
    assert!(entry.unplaced.is_empty(), "{:?}", entry.unplaced);
    let mut heads = entry
        .chains
        .iter()
        .map(|verdict| valid_chain(verdict).map(ValidatedChain::head_digest))
        .collect::<Result<Vec<_>, _>>()?;
    heads.sort_unstable();
    let mut expected = vec![hash_of(&units.v50)?, hash_of(&units.other)?];
    expected.sort_unstable();
    assert_eq!(heads, expected);
    Ok(())
}

/// C22: a unit whose predecessor digest never decoded joins no chain.
#[test]
fn an_undecodable_unit_is_unplaced() -> TestResult {
    let units = Units::new()?;
    let unseparated = flip(&units.v50, 4)?;
    let entry = entry_chains(&[&units.v41, &unseparated, &units.v50])?;
    let [verdict] = entry.chains.as_slice() else {
        return Err(format!("C22: {:?}", entry.chains).into());
    };
    assert_eq!(valid_chain(verdict)?, &chain_of(&v41_v50()?)?);
    let [unplaced] = entry.unplaced.as_slice() else {
        return Err(format!("C22: {:?}", entry.unplaced).into());
    };
    assert_discard(unplaced, 1, CheckStep::Separator, None)
}

/// C23: a unit naming a predecessor no chain holds joins no chain.
#[test]
fn a_unit_naming_no_held_predecessor_is_unplaced() -> TestResult {
    let ring = Ring::new()?;
    let units = Units::new()?;
    let base = v41()?;
    let mut orphan = key_state_on(&base, v41_changed()?);
    orphan.predecessor_digest = [0x44; 32];
    let orphan = sign_on(&ring, &base, &orphan)?;
    let entry = entry_chains(&[&units.v41, &orphan])?;
    let [verdict] = entry.chains.as_slice() else {
        return Err(format!("C23: {:?}", entry.chains).into());
    };
    assert_eq!(valid_chain(verdict)?.head_digest(), v41_digest()?);
    let [unplaced] = entry.unplaced.as_slice() else {
        return Err(format!("C23: {:?}", entry.unplaced).into());
    };
    assert_discard(unplaced, 1, CheckStep::Header, None)
}

/// Criterion 33: copies sharing an event digest merge before forks split,
/// in either served order, and the chain carries the copy that verifies.
#[test]
fn copies_of_one_event_merge_in_either_order() -> TestResult {
    let units = Units::new()?;
    let damaged = flip(&units.v50, signature_field_at(&units.v50)? + 10)?;
    let expected = chain_of(&v41_v50()?)?;
    for order in [
        [&units.v41, &damaged, &units.v50],
        [&units.v41, &units.v50, &damaged],
    ] {
        let units: Vec<&[u8]> = order.iter().map(|unit| unit.as_slice()).collect();
        let entry = entry_chains(&units)?;
        assert!(entry.unplaced.is_empty(), "{:?}", entry.unplaced);
        let [verdict] = entry.chains.as_slice() else {
            return Err(format!("{:?}", entry.chains).into());
        };
        assert_eq!(valid_chain(verdict)?, &expected);
    }
    Ok(())
}

/// R10: a device signs a legal event at the head it holds.
#[test]
fn the_held_head_signs_a_legal_next_event() -> TestResult {
    let units = Units::new()?;
    let chain = chain_of(&v41()?)?;
    let change = HeldHead::of_log(&chain)
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
    let refusal = HeldHead::of_log(&held_chain).check_next(&handed, signed_of(&units.a26)?);
    assert_eq!(
        refusal,
        Err(SigningRefusal::Stale {
            handed: handed.head_digest(),
            held: held_chain.head_digest(),
        })
    );
    Ok(())
}

#[test]
fn the_held_head_refuses_an_illegal_event() -> TestResult {
    let units = Units::new()?;
    let chain = chain_of(&v41()?)?;
    match HeldHead::of_log(&chain).check_next(&chain, signed_of(&units.a26)?) {
        Err(SigningRefusal::Illegal(discard)) => {
            assert_discard(&discard, 1, CheckStep::Content, Some(hash_of(&units.a26)?))
        }
        other => Err(format!("{other:?}").into()),
    }
}

/// Under `RevealOnly` the head signs a reveal-authorized event alone.
#[test]
fn a_reveal_only_marker_signs_reveals_alone() -> TestResult {
    let units = Units::new()?;
    let chain = chain_of(&v41()?)?;
    let marker = HeldHeadMarker {
        mode: MarkerMode::RevealOnly,
        ..HeldHead::of_log(&chain).marker()
    };
    let held = HeldHead::from_marker(&marker);
    assert_eq!(
        held.check_next(&chain, signed_of(&units.v50)?),
        Err(SigningRefusal::RevealOnly {
            held: v41_digest()?,
        })
    );
    let v53 = v41_v53()?.units.last().ok_or("no V53 unit")?.clone();
    let change = held
        .check_next(&chain, signed_of(&v53)?)
        .map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(change.change().effect().kind, EventKind::CommitmentRollover);
    Ok(())
}

#[test]
fn the_marker_round_trips_and_refuses_bad_bytes() -> TestResult {
    let chain = chain_of(&v41()?)?;
    for mode in [MarkerMode::Any, MarkerMode::RevealOnly] {
        let marker = HeldHeadMarker {
            mode,
            ..HeldHead::of_log(&chain).marker()
        };
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
    assert!(matches!(
        validate_chain(&served()?, &[&units.v41]),
        ChainValidation::Valid { .. }
    ));
    Ok(())
}
