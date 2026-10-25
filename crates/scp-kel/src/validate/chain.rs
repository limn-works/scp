//! [`ValidatedChain`]: a chain every event of which passed R3's check order
//! from the inception (§9.7.4.2), and the only way to hold one.

use std::collections::BTreeMap;
use std::sync::Arc;

use scp_did::{Identifier, KeyRole, StandingCommitment};

use super::change::ValidatedChange;
use super::check::{Accepted, Signing, check_successor};
use super::defect::Discarded;
use super::verdicts::Strict;
use crate::{EventKind, InstalledRootSet, KeyStateSnapshot, prerotation_commitment};

/// One event of a valid chain and the state standing after it. The three
/// states are shared with every chain that holds the event, so a fork or a
/// prefix copies no state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChainEvent {
    pub(super) digest: [u8; 32],
    pub(super) sequence: u64,
    pub(super) kind: EventKind,
    /// Whether this event carries a `StandingRoot` signer group: on a
    /// validated event, a threshold of signatures verifying against the root
    /// standing at its predecessor (§9.7.4.2 R6's rank-1 test). Only a
    /// `CommitmentRollover` and a `RootRecovery{CoSigns}` carry one. On the
    /// unsigned-candidate path no signature was verified, and no reader of a
    /// `ValidatedChange` sees this flag.
    pub(super) reveal_root_cosigned: bool,
    /// The event unit that carried the event, byte for byte: the copy R9
    /// keeps, persists, and counts toward its byte bound.
    pub(super) unit: Arc<[u8]>,
    /// The root standing after the event.
    pub(super) root: Arc<InstalledRootSet>,
    /// The commitment standing after the event.
    pub(super) commitment: Arc<StandingCommitment>,
    /// The latest snapshot at or before the event.
    pub(super) snapshot: Arc<KeyStateSnapshot>,
    /// What R3 resolved in that snapshot.
    pub(super) resolved: ResolvedKeys,
}

/// What R3's snapshot checks resolve in a snapshot they accept, kept so no
/// reader of the key state re-derives it fallibly: the one `Current` key in
/// the service role, which must be `#active`, and the count of `Current`
/// root members, which R3 bounds at `MAX_ROOT_SET_SIZE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ResolvedKeys {
    /// The one `Current` `#active` key.
    pub(super) active: [u8; 33],
    /// The count of `Current` `RootMember` entries.
    pub(super) root_count: u32,
}

/// One event of a [`ValidatedChain`], as fork ranking and retention read it
/// (§9.7.4.2 R6, R9). `pub` only inside the private `validate` module: no
/// caller outside scp-kel reads a chain's events.
#[derive(Debug, Clone, Copy)]
pub struct EventView<'c> {
    /// The event's preimage digest, which every comparison reads (R9).
    pub digest: [u8; 32],
    /// The event's sequence.
    pub sequence: u64,
    /// The event's kind.
    pub kind: EventKind,
    /// Whether this event carries a `StandingRoot` signer group, which on a
    /// validated chain verified against the root standing at its
    /// predecessor (R6).
    pub reveal_root_cosigned: bool,
    /// The unit that carried the event, byte for byte: the copy R9 keeps,
    /// persists, and counts toward its byte bound.
    pub unit: &'c [u8],
}

/// What one position of a valid chain leaves standing, read by
/// [`replay`](crate::replay) and [`key_state_at`](crate::key_state_at).
/// Private to the validator: a caller reads a position through those two.
pub(super) struct StandingState<'c> {
    /// The position's event digest.
    pub(super) digest: [u8; 32],
    /// The position's sequence.
    pub(super) sequence: u64,
    /// The latest snapshot at or before the position (R8).
    pub(super) snapshot: &'c KeyStateSnapshot,
    /// The standing commitment at the position (R8, R4).
    pub(super) commitment: &'c StandingCommitment,
    /// What R3 resolved in the snapshot.
    pub(super) resolved: ResolvedKeys,
}

impl<'c> StandingState<'c> {
    fn of(event: &'c ChainEvent) -> Self {
        Self {
            digest: event.digest,
            sequence: event.sequence,
            snapshot: &event.snapshot,
            commitment: &event.commitment,
            resolved: event.resolved,
        }
    }
}

/// A chain every event of which passed every step of R3's check order, from
/// an inception that recomputes to the chain's identifier (§9.7.4.2 R2, R3).
///
/// Its fields are private and it has no `new`, `Default`, `From` or
/// deserializer: [`validate_entry`](super::validate_entry),
/// [`extend`](Self::extend) and [`prefix`](Self::prefix) are the only ways
/// to hold one, and it is never empty.
///
/// ```compile_fail,E0451
/// # use scp_kel::ValidatedChain;
/// let chain = ValidatedChain { state: todo!() };
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::ValidatedChain;
/// let chain = ValidatedChain::new();
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::ValidatedChain;
/// let chain = ValidatedChain::default();
/// ```
///
/// The positive control: [`validate_entry`](super::validate_entry) holds
/// one.
///
/// ```
/// # use scp_kel::{EntryVerdict, validate_entry};
/// # use scp_kel::ValidatedChain;
/// fn head(verdict: &EntryVerdict) -> Option<[u8; 32]> {
///     match verdict {
///         EntryVerdict::Valid { chains } => chains.single().map(ValidatedChain::head_digest),
///         EntryVerdict::InceptionInvalid { .. } | EntryVerdict::NoInception => None,
///     }
/// }
/// let units: [&[u8]; 0] = [];
/// assert_eq!(head(&validate_entry(&scp_did::Identifier::ZERO, &units).verdict), None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChain {
    /// Boxed, so a chain moves as one pointer through `extend` and every
    /// verdict that carries it.
    state: Box<State>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    identifier: Identifier,
    inception: ChainEvent,
    later: Vec<ChainEvent>,
    /// Every key an event installed, with its role and the installing
    /// position.
    installed: BTreeMap<[u8; 33], (KeyRole, u64)>,
    /// The commitment of every installed key, at the installing position.
    installed_commitments: BTreeMap<[u8; 32], u64>,
    /// Every commitment an event fixed, at the first fixing position.
    fixed: BTreeMap<[u8; 32], u64>,
    /// Every revealed key, at the revealing position.
    revealed: BTreeMap<[u8; 33], u64>,
    /// The commitment of every revealed key, at the revealing position.
    revealed_commitments: BTreeMap<[u8; 32], u64>,
}

impl ValidatedChain {
    /// The chain holding one accepted inception.
    pub(super) fn from_inception(identifier: Identifier, accepted: &Accepted) -> Self {
        let mut chain = Self {
            state: Box::new(State {
                identifier,
                inception: accepted.event.clone(),
                later: Vec::new(),
                installed: BTreeMap::new(),
                installed_commitments: BTreeMap::new(),
                fixed: BTreeMap::new(),
                revealed: BTreeMap::new(),
                revealed_commitments: BTreeMap::new(),
            }),
        };
        chain.record(accepted);
        chain
    }

    /// Appends an event [`check_successor`] accepted at the next position.
    pub(super) fn push(&mut self, accepted: &Accepted) {
        self.state.later.push(accepted.event.clone());
        self.record(accepted);
    }

    fn record(&mut self, accepted: &Accepted) {
        let position = accepted.event.sequence;
        for (key, role) in &accepted.installed {
            self.state
                .installed
                .entry(*key)
                .or_insert((*role, position));
            self.state
                .installed_commitments
                .entry(prerotation_commitment(key))
                .or_insert(position);
        }
        for commitment in &accepted.fixed {
            self.state.fixed.entry(*commitment).or_insert(position);
        }
        for key in &accepted.revealed {
            self.state.revealed.entry(*key).or_insert(position);
            self.state
                .revealed_commitments
                .entry(prerotation_commitment(key))
                .or_insert(position);
        }
    }

    /// The identifier the chain's inception recomputes to.
    #[must_use]
    pub fn identifier(&self) -> Identifier {
        self.state.identifier
    }

    /// The digest of the chain's last event.
    #[must_use]
    pub fn head_digest(&self) -> [u8; 32] {
        self.head().digest
    }

    /// The sequence of the chain's last event, which is its position.
    #[must_use]
    pub fn head_sequence(&self) -> u64 {
        self.head().sequence
    }

    pub(super) fn head(&self) -> &ChainEvent {
        self.state.later.last().unwrap_or(&self.state.inception)
    }

    /// The state standing after the head: R8's latest snapshot and the
    /// standing commitment, which [`replay`](crate::replay) composes.
    pub(super) fn head_state(&self) -> StandingState<'_> {
        StandingState::of(self.head())
    }

    /// The state standing after the event whose preimage digest is
    /// `digest`, where that event is on the chain. Digests along one chain
    /// are distinct, because each binds its predecessor's.
    pub(super) fn state_at(&self, digest: &[u8; 32]) -> Option<StandingState<'_>> {
        std::iter::once(&self.state.inception)
            .chain(&self.state.later)
            .find(|event| event.digest == *digest)
            .map(StandingState::of)
    }

    /// Every event of the chain, from the inception to the head.
    pub(crate) fn events(&self) -> impl Iterator<Item = EventView<'_>> + '_ {
        std::iter::once(&self.state.inception)
            .chain(&self.state.later)
            .map(|event| EventView {
                digest: event.digest,
                sequence: event.sequence,
                kind: event.kind,
                reveal_root_cosigned: event.reveal_root_cosigned,
                unit: &event.unit,
            })
    }

    /// Whether every reveal-authorized event at sequences 1 through
    /// `position` carries a root signature verifying against the root
    /// standing at its predecessor: R9's early-stop condition on a tied
    /// pair's shared prefix past the inception (§9.7.4.2 R9, the fetch
    /// bound).
    pub(crate) fn reveals_root_cosigned_through(&self, position: u64) -> bool {
        self.events()
            .skip(1)
            .take_while(|event| event.sequence <= position)
            .filter(|event| event.kind.is_reveal_authorized())
            .all(|event| event.reveal_root_cosigned)
    }

    /// Every event's preimage digest and the unit that carried it, from the
    /// inception to the head: the copies R9 keeps and persists.
    pub(crate) fn units(&self) -> impl Iterator<Item = ([u8; 32], Arc<[u8]>)> + '_ {
        std::iter::once(&self.state.inception)
            .chain(&self.state.later)
            .map(|event| (event.digest, Arc::clone(&event.unit)))
    }

    /// The count of leading events this chain and `other` share, compared
    /// by preimage digest and never by bytes (§9.7.4.2 R9: "An event is
    /// identified by its preimage digest, and every comparison reads that
    /// digest and never the bytes"). Zero where the inceptions differ,
    /// which only chains of two identifiers can show.
    pub(crate) fn shared_prefix_len(&self, other: &Self) -> usize {
        self.events()
            .zip(other.events())
            .take_while(|(left, right)| left.digest == right.digest)
            .count()
    }

    /// `longer` with this chain's copy of every leading event the two share
    /// by preimage digest, and `longer`'s own events past them: where this
    /// chain is a prefix of `longer`, this chain extended by `longer`'s
    /// further events.
    ///
    /// §9.7.4.2 R9: "a party holding a valid event that receives a
    /// byte-different valid event with the same digest keeps the copy it
    /// holds". Two events of one digest carry one preimage, so every state
    /// `longer` derived from them is the state this chain derived; only the
    /// copy, which [`EventView::unit`] reads, differs.
    pub(crate) fn extended_by(&self, longer: Self) -> Self {
        let mut state = longer.state;
        if state.inception.digest == self.state.inception.digest {
            state.inception = self.state.inception.clone();
            for (theirs, mine) in state.later.iter_mut().zip(&self.state.later) {
                if theirs.digest != mine.digest {
                    break;
                }
                *theirs = mine.clone();
            }
        }
        Self { state }
    }

    /// Each event at and past `position`, as its preimage digest and the
    /// length of the unit that carried it: what R9's byte bound counts for a
    /// divergent suffix whose first event sits at `position`, once per
    /// digest across every suffix retained.
    pub(crate) fn unit_lens_from(
        &self,
        position: u64,
    ) -> impl Iterator<Item = ([u8; 32], u64)> + '_ {
        self.events()
            .filter(move |event| event.sequence >= position)
            .map(|event| {
                (
                    event.digest,
                    u64::try_from(event.unit.len()).unwrap_or(u64::MAX),
                )
            })
    }

    /// The count of events the chain holds, the inception included.
    pub(crate) fn len(&self) -> usize {
        self.state.later.len().saturating_add(1)
    }

    /// The position the next event takes: the count of events held.
    pub(super) fn next_position(&self) -> u64 {
        self.head().sequence.saturating_add(1)
    }

    /// The role a key was installed in, where an event of the chain
    /// installed it.
    pub(super) fn installed_role(&self, key: &[u8; 33]) -> Option<KeyRole> {
        self.state.installed.get(key).map(|(role, _)| *role)
    }

    pub(super) fn was_revealed(&self, key: &[u8; 33]) -> bool {
        self.state.revealed.contains_key(key)
    }

    pub(super) fn was_fixed(&self, commitment: &[u8; 32]) -> bool {
        self.state.fixed.contains_key(commitment)
    }

    pub(super) fn installed_commitment(&self, commitment: &[u8; 32]) -> bool {
        self.state.installed_commitments.contains_key(commitment)
    }

    pub(super) fn revealed_commitment(&self, commitment: &[u8; 32]) -> bool {
        self.state.revealed_commitments.contains_key(commitment)
    }

    /// Runs steps 1 through 9 of R3's check order on one event unit as the
    /// next position, and returns the chain extended by it, or the chain
    /// unchanged with the unit's [`Discarded`] (§9.7.4.2 R3, R10). The chain
    /// moves through, so neither outcome copies it.
    ///
    /// It runs the code [`validate_entry`](super::validate_entry) runs for
    /// a unit read for that position. The [`Discarded`] names the unit as
    /// served index zero.
    ///
    /// # Errors
    ///
    /// The chain, unchanged, and the [`Discarded`] the unit's first failing
    /// check reports.
    pub fn extend(mut self, unit: &[u8]) -> Result<Self, (Self, Discarded)> {
        match check_successor(&self, unit, Signing::Signed, &mut Strict) {
            Ok(accepted) => {
                self.push(&accepted);
                Ok(self)
            }
            Err(defect) => {
                let position = self.next_position();
                Err((self, Discarded::read(0, position, defect)))
            }
        }
    }

    /// The valid chain through `position`, inclusive: a prefix of a valid
    /// chain is valid (§9.7.4.2 R3). `None` past the head.
    #[must_use]
    pub fn prefix(&self, position: u64) -> Option<Self> {
        if position > self.head_sequence() {
            return None;
        }
        let keep = |at: &u64| *at <= position;
        Some(Self {
            state: Box::new(State {
                identifier: self.state.identifier,
                inception: self.state.inception.clone(),
                later: self
                    .state
                    .later
                    .iter()
                    .filter(|event| event.sequence <= position)
                    .cloned()
                    .collect(),
                installed: self
                    .state
                    .installed
                    .iter()
                    .filter(|(_, (_, at))| keep(at))
                    .map(|(key, value)| (*key, *value))
                    .collect(),
                installed_commitments: filter_positions(
                    &self.state.installed_commitments,
                    position,
                ),
                fixed: filter_positions(&self.state.fixed, position),
                revealed: filter_positions(&self.state.revealed, position),
                revealed_commitments: filter_positions(&self.state.revealed_commitments, position),
            }),
        })
    }

    /// Runs R3's check order through step 8 on an unsigned candidate's
    /// signed preimage, separator included, as the next position: the code
    /// [`extend`](Self::extend) runs, without the walk, sub-check 7b and
    /// step 9, which read signatures the candidate does not carry yet
    /// (§9.7.4.2 R10).
    ///
    /// # Errors
    ///
    /// The [`Discarded`] the candidate's first failing check reports.
    pub fn validate_change(&self, candidate_preimage: &[u8]) -> Result<ValidatedChange, Discarded> {
        check_successor(self, candidate_preimage, Signing::Unsigned, &mut Strict)
            .map(ValidatedChange::from_accepted)
            .map_err(|defect| Discarded::read(0, self.next_position(), defect))
    }
}

fn filter_positions<K: Ord + Copy>(map: &BTreeMap<K, u64>, position: u64) -> BTreeMap<K, u64> {
    map.iter()
        .filter(|(_, at)| **at <= position)
        .map(|(key, at)| (*key, *at))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::ValidatedChain;
    use crate::{EntryVerdict, EventKind, validate_entry};

    /// Spec 25 Vector 41's preimage.
    const V41_PREIMAGE: &str = concat!(
        "5343502d4b454c2d4556454e542d56313a010000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000100",
        "00000001010000000000000001033b1cac23f45cf1cdfdf0b32f8f777b99166c",
        "1b69649c2295b1517883d47f3027000000010000000100000002033b1cac23f4",
        "5cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30270101000000",
        "000000000001010223702a648232f2d00713de9289753c2fbd4c4efa7e1e3390",
        "5e3723a412b20aea020100000000000000000101000000019d94df95bc0a13f1",
        "963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e1002000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a51",
        "5de80a3e43eb010100000001",
    );
    /// Spec 25 Vector 41's raw signature.
    const V41_SIGNATURE: &str = concat!(
        "274e7cf73b6807ec53619491a1cc094a5fa2a649b4a04a043965597c7faa5e96",
        "7e7b499be2e9750521b4bfec6fa65bfdd14c8e5c940bb60884d040da9d1e70a0",
    );
    /// Spec 25 Vector 41's identifier.
    const V41_IDENTIFIER: &str = "2c0f7f4478be94db0078311ef51ba3cc9934362b0f154dcbf9c597572e46cf32";
    /// Spec 25 Vector 54's preimage: `RootRecovery{CoSigns}` on Vector 41.
    const V54_PREIMAGE: &str = concat!(
        "5343502d4b454c2d4556454e542d56313a042c0f7f4478be94db0078311ef51b",
        "a3cc9934362b0f154dcbf9c597572e46cf320000000000000001d8ba4ebad526",
        "57208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7010000000100",
        "0000000100000000010000000001010000000101000000010100000001026fc6",
        "523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a6700000",
        "0001034c3e84e8da62f05b0a280d5a0426e24bde13c6fa023c567333bece3bc1",
        "497c53000000010000000100000004034c3e84e8da62f05b0a280d5a0426e24b",
        "de13c6fa023c567333bece3bc1497c53010100000000000000000101026188be",
        "77992cb98024f995da162f844f534e4a7f8fca8dc7b1d0cb4b54ce4c64020100",
        "000000000000000101033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c",
        "2295b1517883d47f30270102000000000000000001010223702a648232f2d007",
        "13de9289753c2fbd4c4efa7e1e33905e3723a412b20aea020200000000000000",
        "000101000000019d94df95bc0a13f1963f484414c320354c73c75bb86e96559e",
        "97765f5bc2d31300000e10020000000000000000000000000000000000000000",
        "00000000000000000000000000000000010000000141def207e7438655edf276",
        "6aa2fe0c96ef5f898233fb5ba16c56a3f7765aa8bd010100000001",
    );
    /// Spec 25 Vector 54's signature field.
    const V54_SIGNATURE_FIELD: &str = concat!(
        "204c74ab4383ec683537666c4ce57caebf914ac76a9d380a21d2d961bd3efe21",
        "1e0e595901be6599c1f92da4c6a364c81daef87e55b297eef68b9a571de12e5d",
        "78021d7367db675090416cb6d3536562230f10ae4eaf044eb08bdde1f3a1126e",
        "4f22c6960e73a527b9c74bb7e27d4a6ab54d2f14a99419cea6e20d1b6bd1c3e6",
        "c229bc09518a2d95af6a51939d0ff57e16ba4cfa317fe8fa24e37d3dc91bc688",
        "43bb5b6b587f38ead74215bdcb3f7d0982d32a1ef2948df40914a6695eb833d9",
    );
    /// Spec 25 Vector 55's preimage: `RootRecovery{Lost}` on Vector 41.
    const V55_PREIMAGE: &str = concat!(
        "5343502d4b454c2d4556454e542d56313a042c0f7f4478be94db0078311ef51b",
        "a3cc9934362b0f154dcbf9c597572e46cf320000000000000001d8ba4ebad526",
        "57208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7020000000100",
        "00000001000000000101000000010100000001026fc6523b7b1e22ff3fbce874",
        "0cfbb7cbc816501864bf40f683db69c860d1a67000000001026bf1355bb40ab8",
        "6b1f3d2e776e08da67e754a5dfeeb706b67d7483d09451c4ce00000001000000",
        "0100000004026bf1355bb40ab86b1f3d2e776e08da67e754a5dfeeb706b67d74",
        "83d09451c4ce01010000000000000000010103b7fe460356f0d94ff2bb085ed1",
        "6157ae327b7769f2823ca829077110f05fb4a502010000000000000000010103",
        "3b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027",
        "0102000000000000000001010223702a648232f2d00713de9289753c2fbd4c4e",
        "fa7e1e33905e3723a412b20aea020200000000000000000101000000019d94df",
        "95bc0a13f1963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e",
        "1002000000000000000000000000000000000000000000000000000000000000",
        "0000000000000100000001cb05862aec3a89bd73c5e2d10a61d6483d945c7203",
        "6bdf62dd880a9ff7d4d6f0010100000001",
    );
    /// Spec 25 Vector 55's signature field.
    const V55_SIGNATURE_FIELD: &str = concat!(
        "ce66db7b17acff6ea1c3501cd0380b0e011af13ebef9da42d4a5ce934506edfe",
        "12fafa63880841e9a3ec7c142944a1c6f1b805257c5ac92a46e74912fa035b6d",
        "7e9cb3011690ef40c1a3502350f2e2f05a40c0be0fe388b9482aca92f04b9b17",
        "0536c755a6468d57c12d68de76f970e7e16e615de6ce68f7825edf337ad13842",
    );

    fn unit(preimage_hex: &str, signature_hex: &str) -> Vec<u8> {
        let preimage = hex::decode(preimage_hex).unwrap();
        let mut unit = u32::try_from(preimage.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        unit.extend_from_slice(&preimage);
        unit.extend_from_slice(&hex::decode(signature_hex).unwrap());
        unit
    }

    /// Vector 41 followed by the unit, validated as one chain.
    fn on_v41(successor: &[u8]) -> (ValidatedChain, usize) {
        let identifier = scp_did::Identifier::from_bytes(
            hex::decode(V41_IDENTIFIER).unwrap().try_into().unwrap(),
        );
        let v41 = unit(V41_PREIMAGE, V41_SIGNATURE);
        let units: [&[u8]; 2] = [&v41, successor];
        let validation = validate_entry(&identifier, &units);
        assert!(
            validation.discarded.is_empty(),
            "{:?}",
            validation.discarded
        );
        let chain = match &validation.verdict {
            EntryVerdict::Valid { chains } => chains.single().cloned(),
            EntryVerdict::InceptionInvalid { .. } | EntryVerdict::NoInception => None,
        };
        (chain.expect("one valid chain"), v41.len())
    }

    #[test]
    fn vector_54_revealing_event_is_root_cosigned() {
        let v54 = unit(V54_PREIMAGE, V54_SIGNATURE_FIELD);
        let (chain, v41_len) = on_v41(&v54);
        let events: Vec<_> = chain.events().collect();
        assert_eq!(events.len(), 2);
        assert!(
            !events[0].reveal_root_cosigned,
            "the inception has no predecessor"
        );
        assert_eq!(events[0].unit.len(), v41_len);
        assert_eq!(events[1].kind, EventKind::RootRecovery);
        assert!(events[1].reveal_root_cosigned);
        assert_eq!(events[1].unit, v54.as_slice());
    }

    #[test]
    fn vector_55_lost_recovery_is_not_root_cosigned() {
        let v55 = unit(V55_PREIMAGE, V55_SIGNATURE_FIELD);
        let (chain, _) = on_v41(&v55);
        let events: Vec<_> = chain.events().collect();
        assert_eq!(events[1].kind, EventKind::RootRecovery);
        assert!(!events[1].reveal_root_cosigned);
        assert_eq!(events[1].unit, v55.as_slice());
    }

    #[test]
    fn shared_prefix_len_reads_digests() {
        let (v54, _) = on_v41(&unit(V54_PREIMAGE, V54_SIGNATURE_FIELD));
        let (v55, _) = on_v41(&unit(V55_PREIMAGE, V55_SIGNATURE_FIELD));
        assert_eq!(v54.shared_prefix_len(&v55), 1);
        assert_eq!(v54.shared_prefix_len(&v54), 2);
        let v41 = v54.prefix(0).unwrap();
        assert_eq!(v41.shared_prefix_len(&v55), 1);
        assert_eq!(v55.shared_prefix_len(&v41), 1);
        assert_eq!(v41.len(), 1);
        assert_eq!(v54.len(), 2);
    }
}
