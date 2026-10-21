//! `replay` and `key_state_at` (`09-security-model.md` §9.7.4.2 R8): the
//! key state at a position is that position's latest snapshot with the
//! standing commitment at that position, and nothing else.
//!
//! Every expected key state is assembled here from spec 25 constants, from
//! the fixture builders that assemble a vector from the values it prints,
//! or from the decoded bytes spec 25 prints; none is a key state scp-kel
//! composed.

use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole, KeyState, StandingCommitment,
};
use scp_kel::{
    CheckStep, ContentDefect, Continuation, EventDefect, KeyStateSnapshot, NotOnChain,
    ReplayedState, ValidatedChain, key_state_at, replay,
};

use super::chain_support::{
    Base, Error, Ring, Wire, current, digest_of, entry, key_state_on, point, sign_on, signed_of,
    snapshot, v41, v41_changed, v41_v50, v41_v53, v41_v54, v41_v68, v41_v69, vector,
};
use super::chain_valid::{chain_of, valid};
use super::fixtures::{
    TestResult, V41_ACTIVE, V41_DIGEST, V41_IDENTIFIER, V41_ROOT, V41_WITNESS, V47A_COMMITMENT,
    V50_DIGEST, V53_DIGEST, V53_PREIMAGE, V54_DIGEST, V54_PREIMAGE, V68_DIGEST, V69_ACTIVE,
    V69_DIGEST, array, identifier, v50_key_state,
};

/// The key state a snapshot and a standing commitment compose, field by
/// field, as R8 states it.
fn compose(snapshot: KeyStateSnapshot, standing_commitment: StandingCommitment) -> KeyState {
    let KeyStateSnapshot {
        root_threshold,
        keys,
        witnesses,
        witnessing_interval,
        service_key_role,
        delegator,
    } = snapshot;
    KeyState {
        root_threshold,
        keys,
        witnesses,
        witnessing_interval,
        service_key_role,
        delegator,
        standing_commitment,
    }
}

/// Vector 41's printed key state: its snapshot with the commitment to
/// Vector 47's first point.
fn v41_key_state() -> Result<KeyState, Error> {
    let entry = |key, role| -> Result<KeyEntry, Error> {
        Ok(KeyEntry {
            key: array(key)?,
            role,
            condition: KeyCondition::Current,
            compromised_from: 0,
            custody_type: CustodyType::Passkey,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        })
    };
    Ok(KeyState {
        root_threshold: 1,
        keys: vec![
            entry(V41_ROOT, KeyRole::RootMember)?,
            entry(V41_ACTIVE, KeyRole::Active)?,
        ],
        witnesses: vec![identifier(V41_WITNESS)?],
        witnessing_interval: 3600,
        service_key_role: KeyRole::Active,
        delegator: Identifier::ZERO,
        standing_commitment: v41_commitment()?,
    })
}

/// Vector 41's standing commitment.
fn v41_commitment() -> Result<StandingCommitment, Error> {
    Ok(StandingCommitment::Fixed(FixedCommitment {
        commitments: vec![CommitmentEntry {
            commitment: array(V47A_COMMITMENT)?,
            custody_type: CustodyType::Passkey,
            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
        }],
        next_threshold: 1,
    }))
}

/// The commitment a printed reveal-authorized event fixes.
fn fixed_by(preimage_hex: &str) -> Result<StandingCommitment, Error> {
    match vector(preimage_hex)?.continuation {
        Some(Continuation::FixesCommitment(fixed)) => Ok(StandingCommitment::Fixed(fixed)),
        other => Err(format!("expected a fixed commitment, got {other:?}").into()),
    }
}

/// The snapshot a printed state-carrying event carries.
fn snapshot_of(preimage_hex: &str) -> Result<KeyStateSnapshot, Error> {
    vector(preimage_hex)?
        .key_state
        .ok_or_else(|| "expected a snapshot".into())
}

/// The replay of a base chain `validate_entry` accepts with no discard.
fn replayed(base: &Base) -> Result<(ValidatedChain, ReplayedState), Error> {
    let chain = chain_of(base)?;
    let state = replay(&chain);
    Ok((chain, state))
}

/// Asserts the identifier and the position a replayed state was read at.
fn assert_read_at(state: &ReplayedState, digest: &str, sequence: u64) -> TestResult {
    assert_eq!(state.identifier(), identifier(V41_IDENTIFIER)?);
    assert_eq!(state.head_digest(), array::<32>(digest)?);
    assert_eq!(state.head_sequence(), sequence);
    Ok(())
}

/// [Vector 41] replays to the key state Vector 41 prints.
#[test]
fn replay_of_vector_41_is_its_printed_key_state() -> TestResult {
    let (_, state) = replayed(&v41()?)?;
    assert_eq!(state.key_state(), &v41_key_state()?);
    assert_eq!(state.standing_commitment(), &v41_commitment()?);
    assert_read_at(&state, V41_DIGEST, 0)
}

/// [Vector 41, Vector 50]: a `KeyState` replaces the snapshot and keeps
/// Vector 41's commitment.
#[test]
fn key_state_takes_its_snapshot_and_the_standing_commitment() -> TestResult {
    let (_, state) = replayed(&v41_v50()?)?;
    let snapshot = v50_key_state()?
        .key_state
        .ok_or("Vector 50 carries a snapshot")?;
    assert_eq!(state.key_state(), &compose(snapshot, v41_commitment()?));
    assert_eq!(state.key_state().witnessing_interval, 7200);
    assert_read_at(&state, V50_DIGEST, 1)
}

/// [Vector 41, Vector 53]: a `CommitmentRollover` replaces the commitment
/// alone, and the snapshot stays Vector 41's.
#[test]
fn rollover_takes_its_commitment_and_the_standing_snapshot() -> TestResult {
    let (chain, state) = replayed(&v41_v53()?)?;
    let v53 = fixed_by(V53_PREIMAGE)?;
    assert_ne!(v53, v41_commitment()?);
    let expected = KeyState {
        standing_commitment: v53,
        ..v41_key_state()?
    };
    assert_eq!(state.key_state(), &expected);
    assert_read_at(&state, V53_DIGEST, 1)?;

    // At Vector 41's digest the commitment is Vector 41's, whatever follows.
    let at_v41 = key_state_at(&chain, &array(V41_DIGEST)?)?;
    assert_eq!(at_v41.key_state(), &v41_key_state()?);
    assert_read_at(&at_v41, V41_DIGEST, 0)?;
    // At the head it is the replay.
    assert_eq!(key_state_at(&chain, &array(V53_DIGEST)?)?, state);
    Ok(())
}

/// [Vector 41, Vector 54]: a `RootRecovery` replaces the whole key state:
/// K′ is installed, Vector 41's keys are `Superseded`, and no Vector 41
/// entry survives `Current`.
#[test]
fn root_recovery_replaces_the_whole_key_state() -> TestResult {
    let (_, state) = replayed(&v41_v54()?)?;
    let expected = compose(snapshot_of(V54_PREIMAGE)?, fixed_by(V54_PREIMAGE)?);
    assert_eq!(state.key_state(), &expected);
    assert_read_at(&state, V54_DIGEST, 1)?;

    let keys = &state.key_state().keys;
    let condition = |key: [u8; 33]| {
        keys.iter()
            .find(|entry| entry.key == key)
            .map(|entry| (entry.role, entry.condition))
    };
    assert_eq!(
        condition(point("scp-25-recovery-cosigns-root")),
        Some((KeyRole::RootMember, KeyCondition::Current))
    );
    assert_eq!(
        condition(array(V41_ROOT)?),
        Some((KeyRole::RootMember, KeyCondition::Superseded))
    );
    assert_eq!(
        condition(array(V41_ACTIVE)?),
        Some((KeyRole::Active, KeyCondition::Superseded))
    );
    assert_eq!(
        state.key_state().root_threshold,
        expected.root_threshold,
        "the threshold is K′'s"
    );
    assert_ne!(state.standing_commitment(), &v41_commitment()?);
    Ok(())
}

/// [Vector 41, Vector 68]: the abandoning rollover leaves
/// `Abandoned { at_sequence: 1, event_digest: D(V68) }` standing, and at
/// Vector 41's digest the commitment is still `Fixed`.
#[test]
fn abandoning_rollover_replays_as_abandoned() -> TestResult {
    let (chain, state) = replayed(&v41_v68()?)?;
    assert_eq!(
        state.standing_commitment(),
        &StandingCommitment::Abandoned {
            at_sequence: 1,
            event_digest: array(V68_DIGEST)?,
        }
    );
    // The rollover carries no snapshot, so the snapshot stays Vector 41's.
    let expected = KeyState {
        standing_commitment: state.standing_commitment().clone(),
        ..v41_key_state()?
    };
    assert_eq!(state.key_state(), &expected);
    assert_read_at(&state, V68_DIGEST, 1)?;

    let at_v41 = key_state_at(&chain, &array(V41_DIGEST)?)?;
    assert_eq!(at_v41.standing_commitment(), &v41_commitment()?);
    assert!(matches!(
        at_v41.standing_commitment(),
        StandingCommitment::Fixed(_)
    ));
    Ok(())
}

/// [Vector 41, Vector 68, a `KeyState` signed by Vector 41's root]: R4
/// discards the event after the abandonment (A34), and the replay stays
/// `Abandoned`.
#[test]
fn event_after_abandonment_is_discarded_and_replay_stays_abandoned() -> TestResult {
    let ring = Ring::new()?;
    let abandoned = v41_v68()?;
    let after = sign_on(&ring, &abandoned, &key_state_on(&abandoned, v41_changed()?))?;
    let (chain, discarded) = valid(&abandoned.identifier, &abandoned.with(&after))?;
    let [discard] = discarded.as_slice() else {
        return Err(format!("expected one discard, got {discarded:?}").into());
    };
    assert_eq!(discard.served_index(), 2);
    assert_eq!(discard.read_for(), Some(2));
    assert_eq!(discard.stage(), CheckStep::Content);
    assert_eq!(
        discard.defect(),
        &EventDefect::Content {
            digest: digest_of(signed_of(&after)?),
            defect: ContentDefect::AfterAbandonment,
        }
    );
    assert_eq!(chain.head_digest(), array::<32>(V68_DIGEST)?);
    assert_eq!(
        replay(&chain).standing_commitment(),
        &StandingCommitment::Abandoned {
            at_sequence: 1,
            event_digest: array(V68_DIGEST)?,
        }
    );
    Ok(())
}

/// [Vector 41, Vector 69]: the replay keeps the `Compromised` drop entry
/// with its `compromised_from`, beside the new `#active` key.
#[test]
fn compromised_entry_survives_replay() -> TestResult {
    let (_, state) = replayed(&v41_v69()?)?;
    let keys = &state.key_state().keys;
    let (old_key, new_key) = (array::<33>(V41_ACTIVE)?, array::<33>(V69_ACTIVE)?);
    let old = keys
        .iter()
        .find(|entry| entry.key == old_key)
        .ok_or("Vector 41's #active key is in the replayed state")?;
    assert_eq!(old.role, KeyRole::Active);
    assert_eq!(old.condition, KeyCondition::Compromised);
    assert_eq!(old.compromised_from, 1);
    let new = keys
        .iter()
        .find(|entry| entry.key == new_key)
        .ok_or("Vector 69's #active key is in the replayed state")?;
    assert_eq!(new.condition, KeyCondition::Current);
    assert_eq!(keys.len(), 3);
    assert_eq!(state.standing_commitment(), &v41_commitment()?);
    assert_read_at(&state, V69_DIGEST, 1)
}

/// `key_state_at` refuses a digest no event of the chain carries, and a
/// digest on another chain of the same identity.
#[test]
fn key_state_at_refuses_a_digest_off_the_chain() -> TestResult {
    let chain = chain_of(&v41_v53()?)?;
    let elsewhere = array::<32>(V50_DIGEST)?;
    assert_eq!(
        key_state_at(&chain, &elsewhere),
        Err(NotOnChain { digest: elsewhere })
    );
    assert_eq!(
        key_state_at(&chain, &[0; 32]),
        Err(NotOnChain { digest: [0; 32] })
    );
    Ok(())
}

/// CONF-003 at chain level (§9.7.4.2 R8): Vector 41 extended by a
/// `KeyState` that Vector 41's root re-signs, installing a new `#active` key
/// and dropping the old one `Superseded`, replays with the old key
/// `Superseded` and the new one the state's `#active` key. The fingerprint
/// half of CONF-003 is scp-protocol's `rotation_changes_the_fingerprint`,
/// over the one §9.11 construction.
#[test]
fn conf_003_rotation_replays_the_old_active_key_superseded() -> TestResult {
    let ring = Ring::new()?;
    let base = v41()?;
    let old_active = array::<33>(V41_ACTIVE)?;
    let new_active = point("pr4-conf-003-active");
    let rotation = snapshot(
        vec![
            current(array(V41_ROOT)?, KeyRole::RootMember),
            current(new_active, KeyRole::Active),
            entry(old_active, KeyRole::Active, KeyCondition::Superseded),
        ],
        1,
    )?;
    let unit = sign_on(&ring, &base, &key_state_on(&base, rotation))?;
    let (rotated, discarded) = valid(&base.identifier, &base.with(&unit))?;
    assert!(discarded.is_empty(), "{discarded:?}");
    assert_eq!(rotated.head_sequence(), 1);

    let before = replay(&chain_of(&base)?);
    let after = replay(&rotated);
    let condition = |state: &ReplayedState, key: [u8; 33]| {
        state
            .key_state()
            .keys
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.condition)
    };
    assert_eq!(condition(&before, old_active), Some(KeyCondition::Current));
    assert_eq!(
        condition(&after, old_active),
        Some(KeyCondition::Superseded)
    );
    assert_eq!(condition(&after, new_active), Some(KeyCondition::Current));
    assert_eq!(before.active_key(), &old_active);
    assert_eq!(after.active_key(), &new_active);
    assert_eq!(after.standing_commitment(), before.standing_commitment());
    Ok(())
}

/// Asserts every part of the state `key_state_at` read: Vector 41's
/// identifier, the position, the composed key state and its commitment,
/// the `#active` key and the root members with their count.
fn assert_whole(
    state: &ReplayedState,
    (digest, sequence): ([u8; 32], u64),
    key_state: &KeyState,
    active: [u8; 33],
    root: &[[u8; 33]],
) -> TestResult {
    assert_eq!(state.identifier(), identifier(V41_IDENTIFIER)?);
    assert_eq!(state.head_digest(), digest);
    assert_eq!(state.head_sequence(), sequence);
    assert_eq!(state.key_state(), key_state);
    assert_eq!(state.standing_commitment(), &key_state.standing_commitment);
    assert_eq!(state.active_key(), &active);
    assert_eq!(state.root_members().copied().collect::<Vec<_>>(), root);
    assert_eq!(usize::try_from(state.root_count())?, root.len());
    Ok(())
}

/// R8 at every position of a three-event chain: Vector 41, then a
/// `KeyState` that rotates `#active` from A to X and lists A `Superseded`,
/// then a `KeyState` that rotates X to Y, lists X `Superseded` and omits A.
/// At each position `key_state_at` reads that position's own snapshot with
/// the commitment standing there, Vector 41's: the third position does not
/// carry A forward from the second, and the second is not the head's
/// state. `replay` is the last position's state.
#[test]
fn key_state_at_reads_every_position_of_a_three_event_chain() -> TestResult {
    let ring = Ring::new()?;
    let root = array::<33>(V41_ROOT)?;
    let (a, x, y) = (
        array::<33>(V41_ACTIVE)?,
        point("pr4-r8-table-x"),
        point("pr4-r8-table-y"),
    );
    let to_x = snapshot(
        vec![
            current(root, KeyRole::RootMember),
            current(x, KeyRole::Active),
            entry(a, KeyRole::Active, KeyCondition::Superseded),
        ],
        1,
    )?;
    let to_y = snapshot(
        vec![
            current(root, KeyRole::RootMember),
            current(y, KeyRole::Active),
            entry(x, KeyRole::Active, KeyCondition::Superseded),
        ],
        1,
    )?;
    let first = v41()?;
    let event = key_state_on(&first, to_x.clone());
    let second = first.then(
        &Wire::of(&event).fields(),
        sign_on(&ring, &first, &event)?,
        first.root.clone(),
    );
    let event = key_state_on(&second, to_y.clone());
    let third = second.then(
        &Wire::of(&event).fields(),
        sign_on(&ring, &second, &event)?,
        second.root.clone(),
    );
    let chain = chain_of(&third)?;
    assert_eq!(chain.head_digest(), third.head);

    let rows = [
        ((first.head, 0), v41_key_state()?, a),
        ((second.head, 1), compose(to_x, v41_commitment()?), x),
        ((third.head, 2), compose(to_y, v41_commitment()?), y),
    ];
    for (position, key_state, active) in &rows {
        assert_whole(
            &key_state_at(&chain, &position.0)?,
            *position,
            key_state,
            *active,
            &[root],
        )?;
    }
    assert_eq!(replay(&chain), key_state_at(&chain, &third.head)?);
    Ok(())
}
