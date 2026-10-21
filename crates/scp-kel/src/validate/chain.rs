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

/// The commitment standing after an event: the list and threshold the
/// latest commitment-fixing event fixed, or the abandonment that ended the
/// chain (R4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Standing {
    Fixed(StandingCommitment),
    Abandoned {
        at_sequence: u64,
        event_digest: [u8; 32],
    },
}

/// One event of a valid chain and the state standing after it. The three
/// states are shared with every chain that holds the event, so a fork or a
/// prefix copies no state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChainEvent {
    pub(super) digest: [u8; 32],
    pub(super) sequence: u64,
    pub(super) kind: EventKind,
    /// The root standing after the event.
    pub(super) root: Arc<InstalledRootSet>,
    /// The commitment standing after the event.
    pub(super) commitment: Arc<Standing>,
    /// The latest snapshot at or before the event.
    pub(super) snapshot: Arc<KeyStateSnapshot>,
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
/// # use scp_kel::{EntryOutcome, validate_entry};
/// fn head(outcome: EntryOutcome) -> Option<[u8; 32]> {
///     match outcome {
///         EntryOutcome::Valid { chains } => Some(chains.first().head_digest()),
///         EntryOutcome::InceptionInvalid { .. } | EntryOutcome::NoInception => None,
///     }
/// }
/// let units: [&[u8]; 0] = [];
/// assert_eq!(head(validate_entry(&scp_did::Identifier::ZERO, &units).outcome), None);
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
