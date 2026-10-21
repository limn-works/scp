//! Step 8 of §9.7.4.2 R3's check order past the inception, and the content
//! half of step 3 at the inception: R1 through R4, R8 and every R3
//! indicator over a decoded preimage and the chain at its predecessor.
//!
//! Every check here reads only the preimage, which the event digest binds,
//! and the chain at the predecessor, so every failure is an illegality
//! failure (§9.7.4.2, the illegality criterion).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use scp_crypto::p256::P256PublicKey;
use scp_did::{FixedCommitment, Identifier, KeyCondition, KeyEntry, KeyRole, StandingCommitment};

use super::chain::{ChainEvent, ValidatedChain};
use super::change::{ChangeEffect, NamedKey, SignerGroupSpec};
use super::defect::{ContentDefect, DistinctList, ThresholdField};
use super::verdicts::KeySet;
use crate::constants::{MAX_ROOT_SET_SIZE, MAX_WITNESSING_INTERVAL, MIN_WITNESSING_INTERVAL};
use crate::{
    Continuation, EventHeader, EventKind, EventPreimage, HeaderGroup, InstalledRootSet,
    KeyStateSnapshot, SignerGroupRole, prerotation_commitment,
};

/// Where the event sits: the inception, bound to the identifier its signed
/// preimage recomputes to, or the next position of a valid chain.
#[derive(Clone, Copy)]
pub(super) enum Position<'c> {
    Inception { identifier: Identifier },
    Next(&'c ValidatedChain),
}

impl Position<'_> {
    fn identifier(&self) -> Identifier {
        match self {
            Self::Inception { identifier } => *identifier,
            Self::Next(chain) => chain.identifier(),
        }
    }
}

/// What an event that passed step 8 adds to the chain.
pub(super) struct Applied {
    pub(super) root: Arc<InstalledRootSet>,
    pub(super) commitment: Arc<StandingCommitment>,
    pub(super) snapshot: Arc<KeyStateSnapshot>,
    /// The keys the event installs, with their roles.
    pub(super) installed: Vec<([u8; 33], KeyRole)>,
    /// The commitments the event fixes.
    pub(super) fixed: Vec<[u8; 32]>,
    /// The keys the event reveals.
    pub(super) revealed: Vec<[u8; 33]>,
    /// One key set per header group, in group order, which step 9 verifies
    /// every named index against.
    pub(super) key_sets: Vec<KeySet>,
    pub(super) signers: Vec<SignerGroupSpec>,
    pub(super) effect: ChangeEffect,
}

/// The key set a root-indexed group verifies against: the members by
/// position, at the set's threshold.
pub(super) fn root_key_set(root: &InstalledRootSet) -> KeySet {
    KeySet {
        keys: root
            .members
            .iter()
            .enumerate()
            .filter_map(|(index, key)| u8::try_from(index).ok().map(|index| (index, *key)))
            .collect(),
        threshold: root.threshold,
    }
}

/// The reveal group's key set: at each index the group names, the key at the
/// first position naming it where that key's commitment is the standing
/// list's member at the index, at the standing next threshold. An abandoned
/// commitment has no key set.
pub(super) fn reveal_key_set(
    standing: &StandingCommitment,
    group: &HeaderGroup,
    revealed_keys: &[[u8; 33]],
) -> Option<KeySet> {
    let commitment = match standing {
        StandingCommitment::Fixed(commitment) => commitment,
        StandingCommitment::Abandoned { .. } => return None,
    };
    let mut first: BTreeMap<u8, Option<[u8; 33]>> = BTreeMap::new();
    for (signer, key) in group.signers().iter().zip(revealed_keys) {
        let index = signer.index();
        first.entry(index).or_insert_with(|| {
            commitment
                .commitments
                .get(usize::from(index))
                .filter(|entry| entry.commitment == prerotation_commitment(key))
                .map(|_| *key)
        });
    }
    Some(KeySet {
        keys: first
            .into_iter()
            .filter_map(|(index, key)| key.map(|key| (index, key)))
            .collect(),
        threshold: commitment.next_threshold,
    })
}

/// Step 8 (or step 3's second half at the inception) over `preimage`, whose
/// header is `header` and whose digest is `digest`.
pub(super) fn check_content(
    position: Position<'_>,
    header: &EventHeader,
    preimage: &EventPreimage,
    digest: [u8; 32],
) -> Result<Applied, ContentDefect> {
    if let Position::Next(chain) = position {
        check_link(chain, preimage)?;
    }
    check_sentinels(preimage)?;
    check_points(preimage)?;
    let continuation = check_continuation_present(preimage)?;
    let installed_root = check_installed_root(preimage)?;

    // The root standing after the event: the set field 9 installs, or the
    // root standing at the predecessor.
    let root_after = match (installed_root, position) {
        (Some(root), _) => Arc::new(root.clone()),
        (None, Position::Next(chain)) => Arc::clone(&chain.head().root),
        // The sentinel check requires field 9 of every inception.
        (None, Position::Inception { .. }) => return Err(ContentDefect::FieldAbsent { field: 9 }),
    };

    let key_sets = check_groups(position, header, preimage, installed_root)?;

    let snapshot = check_snapshot(position, preimage, installed_root)?;
    let continuation =
        check_next_commitment(position, preimage, continuation, &root_after, digest)?;
    check_freshness(position, preimage, snapshot.as_ref(), continuation.as_ref())?;

    let (snapshot_after, installed, dropped) = match &snapshot {
        Some(applied) => (
            Arc::new(applied.snapshot.clone()),
            applied.installed.clone(),
            applied.dropped.clone(),
        ),
        None => match position {
            Position::Next(chain) => (Arc::clone(&chain.head().snapshot), Vec::new(), Vec::new()),
            Position::Inception { .. } => return Err(ContentDefect::FieldAbsent { field: 10 }),
        },
    };
    let commitment_after = match (&continuation, position) {
        (Some(standing), _) => Arc::new(standing.clone()),
        (None, Position::Next(chain)) => Arc::clone(&chain.head().commitment),
        (None, Position::Inception { .. }) => {
            return Err(ContentDefect::InceptionFixesNoCommitment);
        }
    };
    let fixed = match continuation.as_ref() {
        Some(StandingCommitment::Fixed(commitment)) => commitment
            .commitments
            .iter()
            .map(|entry| entry.commitment)
            .collect(),
        Some(StandingCommitment::Abandoned { .. }) | None => Vec::new(),
    };

    let head = match position {
        Position::Next(chain) => Some(chain.head()),
        Position::Inception { .. } => None,
    };
    let signers = header
        .groups()
        .iter()
        .zip(&key_sets)
        .map(|(group, keys)| SignerGroupSpec {
            role: group.role(),
            threshold: keys.threshold,
            key_set: keys
                .keys
                .iter()
                .map(|(&index, &key)| NamedKey { index, key })
                .collect(),
            indices: group
                .signers()
                .iter()
                .map(super::super::event_codec::NamedSigner::index)
                .collect(),
        })
        .collect();
    let effect = ChangeEffect {
        kind: preimage.kind,
        sequence: preimage.sequence,
        installed_keys: installed
            .iter()
            .filter_map(|(key, _)| snapshot_entry(&snapshot_after, key))
            .collect(),
        dropped_keys: dropped,
        continuation: preimage.continuation.clone(),
        root_before: head.map(|event| (*event.root).clone()),
        root_after: (*root_after).clone(),
        witnesses_before: head.map(|event| event.snapshot.witnesses.clone()),
        witnesses_after: snapshot_after.witnesses.clone(),
    };
    Ok(Applied {
        root: root_after,
        commitment: commitment_after,
        snapshot: snapshot_after,
        installed,
        fixed,
        revealed: preimage.revealed_keys.clone(),
        key_sets,
        signers,
        effect,
    })
}

fn snapshot_entry(snapshot: &KeyStateSnapshot, key: &[u8; 33]) -> Option<KeyEntry> {
    snapshot
        .keys
        .iter()
        .find(|entry| entry.key == *key)
        .copied()
}

/// The checks that read the chain at the predecessor alone: abandonment
/// (R4), the kind at its position, the identifier field and the sequence.
fn check_link(chain: &ValidatedChain, preimage: &EventPreimage) -> Result<(), ContentDefect> {
    match *chain.head().commitment {
        StandingCommitment::Fixed(_) => {}
        StandingCommitment::Abandoned { .. } => return Err(ContentDefect::AfterAbandonment),
    }
    if preimage.kind == EventKind::Inception {
        return Err(ContentDefect::KindAtPosition {
            kind: preimage.kind,
        });
    }
    if preimage.identifier != chain.identifier() {
        return Err(ContentDefect::IdentifierFieldMismatch);
    }
    // A valid chain's sequence equals its position, so the predecessor's
    // sequence plus one is the chain's length.
    let expected = chain.next_position();
    if preimage.sequence != expected {
        return Err(ContentDefect::SequenceNotNext {
            expected,
            found: preimage.sequence,
        });
    }
    Ok(())
}

/// Each field the kind carries as a sentinel holds it, and each field it
/// carries in substance holds a value (§9.7.4.2, *Which fields each kind
/// carries in substance*). Field 12 is checked by
/// [`check_continuation_present`].
fn check_sentinels(preimage: &EventPreimage) -> Result<(), ContentDefect> {
    let kind = preimage.kind;
    let reveals = kind.is_reveal_authorized();
    let installs_root = matches!(kind, EventKind::Inception | EventKind::RootRecovery);
    let carries_snapshot = kind != EventKind::CommitmentRollover;
    let carries_seals = kind == EventKind::KeyState;

    if kind != EventKind::RootRecovery && preimage.standing_root.is_some() {
        return Err(ContentDefect::SentinelHeld { field: 5 });
    }
    match (reveals, preimage.revealed_keys.is_empty()) {
        (false, false) => return Err(ContentDefect::SentinelHeld { field: 8 }),
        (true, true) => return Err(ContentDefect::FieldAbsent { field: 8 }),
        _ => {}
    }
    match (installs_root, preimage.installed_root_set.is_some()) {
        (false, true) => return Err(ContentDefect::SentinelHeld { field: 9 }),
        (true, false) => return Err(ContentDefect::FieldAbsent { field: 9 }),
        _ => {}
    }
    match (carries_snapshot, preimage.key_state.is_some()) {
        (false, true) => return Err(ContentDefect::SentinelHeld { field: 10 }),
        (true, false) => return Err(ContentDefect::FieldAbsent { field: 10 }),
        _ => {}
    }
    if !carries_seals && !preimage.seals.is_empty() {
        return Err(ContentDefect::SentinelHeld { field: 11 });
    }
    Ok(())
}

/// Every 33-byte key the preimage carries, the revealed keys (field 8), the
/// installed root set (field 9) and the snapshot's keys (field 10), is a
/// valid compressed P-256 point (§9.5, point validation). Field 9 repeats
/// the snapshot's root members, and the check order reads each anyway, so
/// no key reaches a verification or a key set unvalidated.
fn check_points(preimage: &EventPreimage) -> Result<(), ContentDefect> {
    let installed = preimage
        .installed_root_set
        .iter()
        .flat_map(|root| root.members.iter());
    let listed = preimage
        .key_state
        .iter()
        .flat_map(|snapshot| snapshot.keys.iter().map(|entry| &entry.key));
    preimage
        .revealed_keys
        .iter()
        .chain(installed)
        .chain(listed)
        .find(|key| P256PublicKey::from_sec1(key.as_slice()).is_err())
        .map_or(Ok(()), |key| Err(ContentDefect::InvalidPoint { key: *key }))
}

/// Field 12 by kind: R2's commitment at the inception, R1's sentinel on a
/// `KeyState`, and R4's fix-or-abandon on a reveal-authorized event, where
/// only a `CommitmentRollover` abandons.
const fn check_continuation_present(
    preimage: &EventPreimage,
) -> Result<Option<&Continuation>, ContentDefect> {
    match (preimage.kind, &preimage.continuation) {
        (EventKind::KeyState, None) => Ok(None),
        (EventKind::KeyState, Some(_)) => Err(ContentDefect::SentinelHeld { field: 12 }),
        (EventKind::Inception, Some(Continuation::Abandons) | None) => {
            Err(ContentDefect::InceptionFixesNoCommitment)
        }
        (EventKind::CommitmentRollover | EventKind::RootRecovery, None) => {
            Err(ContentDefect::ContinuationMissing)
        }
        (EventKind::RootRecovery, Some(Continuation::Abandons)) => {
            Err(ContentDefect::RecoveryAbandons)
        }
        (EventKind::Inception, Some(continuation @ Continuation::FixesCommitment(_)))
        | (EventKind::CommitmentRollover | EventKind::RootRecovery, Some(continuation)) => {
            Ok(Some(continuation))
        }
    }
}

/// Field 9: pairwise distinct members and a threshold within one to its
/// size. The decoder bounds its count at `MAX_ROOT_SET_SIZE`.
fn check_installed_root(
    preimage: &EventPreimage,
) -> Result<Option<&InstalledRootSet>, ContentDefect> {
    let Some(root) = &preimage.installed_root_set else {
        return Ok(None);
    };
    if !distinct(root.members.iter()) {
        return Err(ContentDefect::NotDistinct {
            list: DistinctList::RootSet,
        });
    }
    check_threshold(ThresholdField::Root, root.threshold, root.members.len())?;
    Ok(Some(root))
}

fn check_threshold(
    field: ThresholdField,
    threshold: u32,
    size: usize,
) -> Result<(), ContentDefect> {
    let within =
        threshold >= 1 && usize::try_from(threshold).is_ok_and(|threshold| threshold <= size);
    if within {
        Ok(())
    } else {
        Err(ContentDefect::ThresholdOutOfRange {
            field,
            threshold,
            size,
        })
    }
}

fn distinct<T: Ord>(items: impl Iterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    items.into_iter().all(|item| seen.insert(item))
}

/// Each signer group against the key set the table *The key set each signer
/// group verifies against* names: no repeated index, no index outside the
/// set, at least its threshold of indices, and for the reveal group, one
/// revealed key per index, each matching the standing commitment.
fn check_groups(
    position: Position<'_>,
    header: &EventHeader,
    preimage: &EventPreimage,
    installed_root: Option<&InstalledRootSet>,
) -> Result<Vec<KeySet>, ContentDefect> {
    let mut key_sets = Vec::new();
    for group in header.groups() {
        let role = group.role();
        let keys = match (role, position) {
            (SignerGroupRole::Reveal, Position::Next(chain)) => {
                let commitment = match &*chain.head().commitment {
                    StandingCommitment::Fixed(commitment) => commitment,
                    StandingCommitment::Abandoned { .. } => {
                        return Err(ContentDefect::AfterAbandonment);
                    }
                };
                check_reveal(group, commitment, &preimage.revealed_keys)?;
                reveal_key_set(&chain.head().commitment, group, &preimage.revealed_keys)
                    .ok_or(ContentDefect::AfterAbandonment)?
            }
            (SignerGroupRole::Root | SignerGroupRole::StandingRoot, Position::Next(chain)) => {
                root_key_set(&chain.head().root)
            }
            (SignerGroupRole::Root | SignerGroupRole::ReplacementRoot, _) => {
                root_key_set(installed_root.ok_or(ContentDefect::FieldAbsent { field: 9 })?)
            }
            // An inception carries one root group; the decoder reads no
            // other group for it.
            (
                SignerGroupRole::Reveal | SignerGroupRole::StandingRoot,
                Position::Inception { .. },
            ) => {
                return Err(ContentDefect::KindAtPosition {
                    kind: preimage.kind,
                });
            }
        };
        let mut seen = BTreeSet::new();
        for signer in group.signers() {
            let index = signer.index();
            if !seen.insert(index) {
                return Err(ContentDefect::RepeatedIndex { role, index });
            }
            // The index names a key of the set the group verifies against,
            // the one map 7a, 7b and step 9 read too.
            if !keys.keys.contains_key(&index) {
                return Err(ContentDefect::IndexOutOfRange { role, index });
            }
        }
        if !super::verdicts::reaches(seen.len(), keys.threshold) {
            return Err(ContentDefect::IndexCountBelowThreshold {
                role,
                named: seen.len(),
                threshold: keys.threshold,
            });
        }
        key_sets.push(keys);
    }
    Ok(key_sets)
}

/// The reveal group's own indicators: as many revealed keys as indices, and
/// each key's commitment the standing list's member at its index.
fn check_reveal(
    group: &HeaderGroup,
    commitment: &FixedCommitment,
    revealed_keys: &[[u8; 33]],
) -> Result<(), ContentDefect> {
    if group.signers().len() != revealed_keys.len() {
        return Err(ContentDefect::RevealCountMismatch {
            indices: group.signers().len(),
            keys: revealed_keys.len(),
        });
    }
    for (signer, key) in group.signers().iter().zip(revealed_keys) {
        let index = signer.index();
        let matches = commitment
            .commitments
            .get(usize::from(index))
            .is_some_and(|entry| entry.commitment == prerotation_commitment(key));
        if !matches {
            return Err(ContentDefect::RevealMismatch { index });
        }
    }
    Ok(())
}

/// A snapshot that passed its checks, with what it installs and drops.
struct AppliedSnapshot {
    snapshot: KeyStateSnapshot,
    installed: Vec<([u8; 33], KeyRole)>,
    dropped: Vec<KeyEntry>,
}

/// Where an entry of the key list sits relative to the predecessor's.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Segment {
    /// `Current` here and at the predecessor, at its position there.
    Kept(usize),
    /// `Current` here and not at the predecessor.
    Added,
    /// `Current` at the predecessor and dropped here, at its position there.
    Dropped(usize),
}

/// Field 10: R8, the snapshot's own indicators, and its key list against
/// the predecessor's.
fn check_snapshot(
    position: Position<'_>,
    preimage: &EventPreimage,
    installed_root: Option<&InstalledRootSet>,
) -> Result<Option<AppliedSnapshot>, ContentDefect> {
    let Some(snapshot) = &preimage.key_state else {
        return Ok(None);
    };
    let root = snapshot.root_set();
    // The size runs first: field 9 and the standing root are each bounded
    // at `MAX_ROOT_SET_SIZE`, so after either equality an oversized
    // snapshot root could only report the mismatch.
    if u32::try_from(root.members.len()).map_or(true, |size| size > MAX_ROOT_SET_SIZE) {
        return Err(ContentDefect::RootSetTooLarge {
            size: root.members.len(),
        });
    }
    match (installed_root, position) {
        (Some(installed), _) if *installed != root => {
            return Err(ContentDefect::InstalledRootMismatch);
        }
        (None, Position::Next(chain)) if *chain.head().root != root => {
            return Err(ContentDefect::KeyStateRootChanged);
        }
        _ => {}
    }
    let mut listed = BTreeSet::new();
    for entry in &snapshot.keys {
        if !listed.insert(entry.key) {
            return Err(ContentDefect::KeyListedTwice { key: entry.key });
        }
    }
    let mut operational = HashSet::new();
    for entry in &snapshot.keys {
        if entry.condition == KeyCondition::Current
            && entry.role != KeyRole::RootMember
            && !operational.insert(entry.role)
        {
            return Err(ContentDefect::TwoCurrentInRole { role: entry.role });
        }
    }
    if snapshot.service_key_role != KeyRole::Active {
        return Err(ContentDefect::ServiceRoleNotActive {
            role: snapshot.service_key_role,
        });
    }
    if !(MIN_WITNESSING_INTERVAL..=MAX_WITNESSING_INTERVAL).contains(&snapshot.witnessing_interval)
    {
        return Err(ContentDefect::WitnessIntervalOutOfRange {
            interval: snapshot.witnessing_interval,
        });
    }
    if !distinct(snapshot.witnesses.iter()) {
        return Err(ContentDefect::NotDistinct {
            list: DistinctList::Witnesses,
        });
    }
    if snapshot.witnesses.contains(&position.identifier()) {
        return Err(ContentDefect::WitnessNamesSubject);
    }
    if snapshot.delegator != Identifier::ZERO {
        return Err(ContentDefect::NonzeroDelegator);
    }
    for entry in &snapshot.keys {
        if entry.condition == KeyCondition::Compromised
            && entry.compromised_from > preimage.sequence
        {
            return Err(ContentDefect::CompromisedFromAfterSequence {
                key: entry.key,
                from: entry.compromised_from,
                sequence: preimage.sequence,
            });
        }
    }
    let applied = match position {
        Position::Inception { .. } => inception_key_list(snapshot)?,
        Position::Next(chain) => successor_key_list(chain, preimage.kind, snapshot)?,
    };
    // The service role resolves after the key list: the only drop that
    // leaves no successor in its role is the `#active` key's, so run first
    // this check would report every `Superseded` drop without a successor
    // and `SupersededWithoutSuccessor` could never be found.
    if !operational.contains(&snapshot.service_key_role) {
        return Err(ContentDefect::ServiceRoleUnresolved);
    }
    Ok(Some(applied))
}

/// The inception's key list: every entry is a key the inception installs,
/// so every entry is `Current`.
fn inception_key_list(snapshot: &KeyStateSnapshot) -> Result<AppliedSnapshot, ContentDefect> {
    let mut installed = Vec::new();
    for entry in &snapshot.keys {
        if entry.condition != KeyCondition::Current {
            return Err(ContentDefect::KeyNotCurrentNorDropped { key: entry.key });
        }
        installed.push((entry.key, entry.role));
    }
    Ok(AppliedSnapshot {
        snapshot: snapshot.clone(),
        installed,
        dropped: Vec::new(),
    })
}

/// A later snapshot's key list against the predecessor's (R8 and the
/// definitions' snapshot order).
fn successor_key_list(
    chain: &ValidatedChain,
    kind: EventKind,
    snapshot: &KeyStateSnapshot,
) -> Result<AppliedSnapshot, ContentDefect> {
    let previous = &chain.head().snapshot;
    if **previous == *snapshot {
        return Err(ContentDefect::SnapshotUnchanged);
    }
    let previous_current: BTreeMap<[u8; 33], usize> = previous
        .keys
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.condition == KeyCondition::Current)
        .map(|(position, entry)| (entry.key, position))
        .collect();

    let mut segments = Vec::new();
    let mut installed = Vec::new();
    let mut dropped = Vec::new();
    for entry in &snapshot.keys {
        if let Some(role) = chain.installed_role(&entry.key)
            && role != entry.role
        {
            return Err(ContentDefect::RoleChanged {
                key: entry.key,
                installed: role,
                listed: entry.role,
            });
        }
        let at_predecessor = previous_current.get(&entry.key).copied();
        let segment = match (entry.condition, at_predecessor) {
            (KeyCondition::Current, Some(position)) => Segment::Kept(position),
            (KeyCondition::Current, None) => Segment::Added,
            (_, Some(position)) => Segment::Dropped(position),
            (_, None) => return Err(ContentDefect::KeyNotCurrentNorDropped { key: entry.key }),
        };
        // A key `Current` here and not `Current` at the predecessor is an
        // installation, so a dropped key listed `Current` again fails below
        // as installed twice: a dropped key "signs nothing new" (§9.7.4.2
        // key conditions) and a key "is installed by at most one event".
        // A kept key is listed, not installed, whatever the kind: "listing
        // an already-installed key in a later snapshot is not an
        // installation". A `RootRecovery` may re-list an uncompromised
        // operational key (§9.12, "the controller's own key re-listed
        // otherwise"). Whether it may keep a root member, which would sit in
        // field 9 that installs K′, is open (`00-open-questions.md`), so
        // that case alone fails closed with its own defect.
        if kind == EventKind::RootRecovery
            && entry.role == KeyRole::RootMember
            && matches!(segment, Segment::Kept(_))
        {
            return Err(ContentDefect::KeptRootMember { key: entry.key });
        }
        if segment == Segment::Added {
            if chain.installed_role(&entry.key).is_some() {
                return Err(ContentDefect::KeyInstalledTwice { key: entry.key });
            }
            installed.push((entry.key, entry.role));
        }
        if matches!(segment, Segment::Dropped(_)) {
            dropped.push(*entry);
        }
        segments.push((segment, entry.key));
    }
    for key in previous_current.keys() {
        if !snapshot.keys.iter().any(|entry| entry.key == *key) {
            return Err(ContentDefect::SilentDrop { key: *key });
        }
    }
    for entry in &dropped {
        let successor = installed.iter().any(|(_, role)| *role == entry.role);
        match entry.condition {
            KeyCondition::Superseded if !successor => {
                return Err(ContentDefect::SupersededWithoutSuccessor { key: entry.key });
            }
            KeyCondition::Retired if successor => {
                return Err(ContentDefect::RetiredWithSuccessor { key: entry.key });
            }
            KeyCondition::Current
            | KeyCondition::Superseded
            | KeyCondition::Retired
            | KeyCondition::Compromised => {}
        }
    }
    // Kept entries in their existing order, then added keys, then dropped
    // entries in their existing order: the segment sequence never steps
    // back. `Segment`'s order ranks `Kept` below `Added` below `Dropped`,
    // and positions within `Kept` and `Dropped`.
    for pair in segments.windows(2) {
        if let [(before, _), (after, key)] = pair {
            let in_order = match (before, after) {
                (Segment::Added, Segment::Added) => true,
                _ => before < after,
            };
            if !in_order {
                return Err(ContentDefect::SnapshotOrder { key: *key });
            }
        }
    }
    Ok(AppliedSnapshot {
        snapshot: snapshot.clone(),
        installed,
        dropped,
    })
}

/// Field 12's commitment: a pairwise distinct list, a next threshold within
/// one to its size and at least the root threshold after the event (R4 and
/// the R3 indicators). The decoder bounds the list at `MAX_NEXT_SET_SIZE`.
fn check_next_commitment(
    position: Position<'_>,
    preimage: &EventPreimage,
    continuation: Option<&Continuation>,
    root_after: &InstalledRootSet,
    digest: [u8; 32],
) -> Result<Option<StandingCommitment>, ContentDefect> {
    match continuation {
        None => Ok(None),
        Some(Continuation::Abandons) => {
            // Only a `CommitmentRollover` reaches here (field 12 by kind),
            // and never at the inception.
            if matches!(position, Position::Inception { .. }) {
                return Err(ContentDefect::InceptionFixesNoCommitment);
            }
            Ok(Some(StandingCommitment::Abandoned {
                at_sequence: preimage.sequence,
                event_digest: digest,
            }))
        }
        Some(Continuation::FixesCommitment(commitment)) => {
            if !distinct(commitment.commitments.iter().map(|entry| entry.commitment)) {
                return Err(ContentDefect::NotDistinct {
                    list: DistinctList::Commitments,
                });
            }
            check_threshold(
                ThresholdField::Next,
                commitment.next_threshold,
                commitment.commitments.len(),
            )?;
            if commitment.next_threshold < root_after.threshold {
                return Err(ContentDefect::NextThresholdBelowRoot {
                    next_threshold: commitment.next_threshold,
                    root_threshold: root_after.threshold,
                });
            }
            Ok(Some(StandingCommitment::Fixed(commitment.clone())))
        }
    }
}

/// The reveals, installations and fixed commitments at or before an event:
/// the event's own over the chain's through its predecessor. Every
/// freshness rule reads "at or before the event" through this one view, so
/// no rule can read the chain's half without the event's.
///
/// The event's own installations carry no set here: a commitment the event
/// fixes that equals the commitment of a key the event installs is that
/// key's `InstalledKeyCommitted`, which [`check_freshness`] tests first, so
/// [`commits_to_installed`](Self::commits_to_installed) reads the chain's
/// installations alone.
struct AtOrBefore<'c> {
    chain: Option<&'c ValidatedChain>,
    revealed: BTreeSet<[u8; 33]>,
    revealed_commitments: BTreeSet<[u8; 32]>,
    fixed: BTreeSet<[u8; 32]>,
}

impl AtOrBefore<'_> {
    fn was_revealed(&self, key: &[u8; 33]) -> bool {
        self.revealed.contains(key) || self.chain.is_some_and(|chain| chain.was_revealed(key))
    }

    fn was_fixed(&self, commitment: &[u8; 32]) -> bool {
        self.fixed.contains(commitment)
            || self.chain.is_some_and(|chain| chain.was_fixed(commitment))
    }

    fn commits_to_installed(&self, commitment: &[u8; 32]) -> bool {
        self.chain
            .is_some_and(|chain| chain.installed_commitment(commitment))
    }

    fn commits_to_revealed(&self, commitment: &[u8; 32]) -> bool {
        self.revealed_commitments.contains(commitment)
            || self
                .chain
                .is_some_and(|chain| chain.revealed_commitment(commitment))
    }
}

/// Commitment freshness and the installed-key rules (R4, R3): no installed
/// key was revealed, installed keys and fixed commitments are disjoint in
/// both directions at or before the event, and no fixed commitment commits
/// to a revealed key.
fn check_freshness(
    position: Position<'_>,
    preimage: &EventPreimage,
    snapshot: Option<&AppliedSnapshot>,
    continuation: Option<&StandingCommitment>,
) -> Result<(), ContentDefect> {
    let installed: &[([u8; 33], KeyRole)] =
        snapshot.map_or(&[], |applied| applied.installed.as_slice());
    let fixed: Vec<[u8; 32]> = match continuation {
        Some(StandingCommitment::Fixed(commitment)) => commitment
            .commitments
            .iter()
            .map(|entry| entry.commitment)
            .collect(),
        Some(StandingCommitment::Abandoned { .. }) | None => Vec::new(),
    };
    let seen = AtOrBefore {
        chain: match position {
            Position::Next(chain) => Some(chain),
            Position::Inception { .. } => None,
        },
        revealed: preimage.revealed_keys.iter().copied().collect(),
        revealed_commitments: preimage
            .revealed_keys
            .iter()
            .map(prerotation_commitment)
            .collect(),
        fixed: fixed.iter().copied().collect(),
    };
    for (key, _) in installed {
        if seen.was_revealed(key) {
            return Err(ContentDefect::InstalledKeyRevealed { key: *key });
        }
        if seen.was_fixed(&prerotation_commitment(key)) {
            return Err(ContentDefect::InstalledKeyCommitted { key: *key });
        }
    }
    for commitment in &fixed {
        if seen.commits_to_installed(commitment) {
            return Err(ContentDefect::CommitmentToInstalledKey {
                commitment: *commitment,
            });
        }
        if seen.commits_to_revealed(commitment) {
            return Err(ContentDefect::CommitmentToRevealedKey {
                commitment: *commitment,
            });
        }
    }
    Ok(())
}

/// The event this content adds, as a chain entry.
pub(super) fn chain_event(
    applied: &Applied,
    digest: [u8; 32],
    preimage: &EventPreimage,
) -> ChainEvent {
    ChainEvent {
        digest,
        sequence: preimage.sequence,
        kind: preimage.kind,
        root: Arc::clone(&applied.root),
        commitment: Arc::clone(&applied.commitment),
        snapshot: Arc::clone(&applied.snapshot),
    }
}
