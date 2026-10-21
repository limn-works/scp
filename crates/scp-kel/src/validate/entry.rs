//! [`validate_entry`]: assembly by predecessor digest, then R3's check order
//! on every inception-to-leaf path (§9.7.4.2 R3, R9).

use std::collections::{BTreeMap, BTreeSet};

use scp_did::Identifier;

use super::check::{Accepted, InceptionFailure};
use super::defect::{Discarded, EventDefect, InceptionDefect};
use super::{Copies, ValidatedChain, inception, successor};
use crate::{EventUnit, decode_event};

/// What R3's check order makes of every unit one entry served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryValidation {
    /// What the entry's units prove about the identifier.
    pub outcome: EntryOutcome,
    /// Every served unit no chain holds, once each, in served order: a
    /// unit discarded where it was read, one that joined no chain, and one
    /// that names a predecessor no chain holds. Copies merged by event
    /// digest (R9) report once, as their first copy, and only where no copy
    /// passed.
    pub discarded: Vec<Discarded>,
}

/// What an entry's units prove about the identifier they were served under
/// (§9.7.4.2 R3, R14).
///
/// Only the inception can make an identifier invalid, so no variant carries
/// a later position together with an invalid class, and `Valid` holds at
/// least one chain.
///
/// ```compile_fail,E0559
/// # use scp_kel::{EntryOutcome, InceptionDefect};
/// fn invalid(defect: InceptionDefect) -> EntryOutcome {
///     EntryOutcome::InceptionInvalid { defect, at_sequence: 3 }
/// }
/// ```
///
/// The positive control:
///
/// ```
/// # use scp_kel::{EntryOutcome, InceptionDefect};
/// fn invalid(defect: InceptionDefect) -> EntryOutcome {
///     EntryOutcome::InceptionInvalid { defect }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryOutcome {
    /// A unit read for position zero recomputes to the served identifier
    /// and fails R2 or an R3 indicator (step 3's second half): the
    /// identifier names no valid chain, R14's `Invalid`.
    InceptionInvalid {
        /// The defect.
        defect: InceptionDefect,
    },
    /// No unit read for position zero passed every step.
    NoInception,
    /// The inception is valid; each chain is one inception-to-leaf path.
    Valid {
        /// Every valid chain, at least one.
        chains: ValidChains,
    },
}

/// One valid chain per inception-to-leaf path, in the order the paths
/// branch, depth first with sibling events in served order. Never empty:
/// the fields are private and only [`validate_entry`] builds one.
///
/// Two events that name one predecessor with different digests start two
/// chains, so a fork is two chains and never a discard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidChains {
    first: ValidatedChain,
    rest: Vec<ValidatedChain>,
}

impl ValidChains {
    /// The first path: the inception's first passing successor, and so on
    /// to a leaf.
    #[must_use]
    pub const fn first(&self) -> &ValidatedChain {
        &self.first
    }

    /// Every path, first included.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatedChain> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

/// One event's copies, the served index of its first copy, and the
/// identifier they recompute to.
struct Group<'u> {
    copies: Copies<'u>,
    first_served: usize,
    recomputed: Identifier,
}

/// The served units, merged by event digest and assembled by predecessor
/// digest.
#[derive(Default)]
struct Assembly<'u> {
    groups: Vec<Group<'u>>,
    by_digest: BTreeMap<[u8; 32], usize>,
    /// Groups read for position zero, in served order: every unit that
    /// recomputes to the served identifier, and every unit naming the
    /// all-zero predecessor.
    inception: Vec<usize>,
    /// Groups by the predecessor digest they name, in served order.
    children: BTreeMap<[u8; 32], Vec<usize>>,
    /// The predecessor each later group names.
    named: BTreeMap<usize, [u8; 32]>,
    unplaced: Vec<Discarded>,
}

impl<'u> Assembly<'u> {
    fn new(identifier: Identifier, units: &[&'u [u8]]) -> Self {
        let mut assembly = Self::default();
        for (index, unit) in units.iter().enumerate() {
            assembly.place(identifier, index, unit);
        }
        assembly
    }

    /// Places one unit by the bytes its decode read. A unit whose field 4
    /// decoded, whether or not step 4 passed, goes below the event it
    /// names; a unit that recomputes to the served identifier is read for
    /// position zero; any other unit joins no chain.
    fn place(&mut self, identifier: Identifier, index: usize, unit: &'u [u8]) {
        let (raw, predecessor) = match decode_event(unit, 0) {
            EventUnit::Unframed => {
                self.unplaced
                    .push(Discarded::unplaced(index, EventDefect::Unframed));
                return;
            }
            EventUnit::NoSeparator => {
                self.unplaced
                    .push(Discarded::unplaced(index, EventDefect::NoSeparator));
                return;
            }
            EventUnit::HeaderFailed(failed) => {
                let predecessor = failed.predecessor().copied();
                if predecessor.is_none() && failed.raw().identifier() != identifier {
                    self.unplaced.push(Discarded::unplaced(
                        index,
                        EventDefect::Header(failed.error().clone()),
                    ));
                    return;
                }
                (failed.raw().clone(), predecessor)
            }
            EventUnit::Read(read) => (
                read.raw().clone(),
                Some(*read.header().predecessor_digest()),
            ),
        };
        let digest = raw.event_digest();
        if let Some(group) = self
            .by_digest
            .get(&digest)
            .and_then(|&group| self.groups.get_mut(group))
        {
            group.copies.rest.push(unit);
            return;
        }
        let group = self.groups.len();
        self.groups.push(Group {
            copies: Copies::one(unit),
            first_served: index,
            recomputed: raw.identifier(),
        });
        self.by_digest.insert(digest, group);
        match predecessor {
            Some(named) if named != [0; 32] && raw.identifier() != identifier => {
                self.children.entry(named).or_default().push(group);
                self.named.insert(group, named);
            }
            _ => self.inception.push(group),
        }
    }

    /// The groups naming `head`, in served order.
    fn children_of(&self, head: &[u8; 32]) -> impl Iterator<Item = (usize, &Group<'u>)> {
        self.children
            .get(head)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter_map(|&group| self.groups.get(group).map(|found| (group, found)))
    }
}

/// Assembles every unit one entry served into chains by predecessor digest,
/// merging units that share an event digest, then runs R3's check order on
/// every inception-to-leaf path (§9.7.4.2 R3, R9).
///
/// This is the one reader of an entry's units. Two units that name one
/// predecessor and carry different digests start two chains, so a fork is
/// never a discard, and each served unit no chain holds is reported once in
/// [`EntryValidation::discarded`]. Each unit is one event unit, `BE32(len)
/// ‖ signed preimage ‖ signature field`.
#[must_use]
pub fn validate_entry(identifier: &Identifier, units: &[&[u8]]) -> EntryValidation {
    let assembly = Assembly::new(*identifier, units);
    let mut visited = BTreeSet::new();
    let mut discarded = Vec::new();
    let mut root = None;
    let mut invalid = None;
    for &index in &assembly.inception {
        visited.insert(index);
        let Some(group) = assembly.groups.get(index) else {
            continue;
        };
        // The identifier binds the whole signed preimage, as the digest
        // does, so at most one merged group recomputes to it; every other
        // group read for position zero fails step 3's first half.
        if group.recomputed != *identifier {
            discarded.push(Discarded::read(
                group.first_served,
                0,
                EventDefect::IdentifierMismatch {
                    recomputed: group.recomputed,
                },
            ));
            continue;
        }
        match inception(*identifier, &group.copies) {
            Ok(accepted) => root = Some(ValidatedChain::from_inception(*identifier, &accepted)),
            Err(InceptionFailure::Invalid(defect)) => invalid = Some(defect),
            Err(InceptionFailure::Discard(defect)) => {
                discarded.push(Discarded::read(group.first_served, 0, defect));
            }
        }
    }
    let outcome = match (invalid, root) {
        (Some(defect), _) => EntryOutcome::InceptionInvalid { defect },
        (None, Some(root)) => EntryOutcome::Valid {
            chains: branches(&assembly, root, &mut visited, &mut discarded),
        },
        (None, None) => EntryOutcome::NoInception,
    };
    discarded.extend(assembly.unplaced.iter().cloned());
    for (group, named) in &assembly.named {
        if visited.contains(group) {
            continue;
        }
        if let Some(found) = assembly.groups.get(*group) {
            discarded.push(Discarded::unplaced(
                found.first_served,
                EventDefect::PredecessorMismatch { named: *named },
            ));
        }
    }
    discarded.sort_by_key(Discarded::served_index);
    EntryValidation { outcome, discarded }
}

/// Runs the check order down every path from the inception, depth first.
/// The first path is followed to its leaf before any sibling, so the result
/// holds at least one chain by construction.
fn branches(
    assembly: &Assembly<'_>,
    root: ValidatedChain,
    visited: &mut BTreeSet<usize>,
    discarded: &mut Vec<Discarded>,
) -> ValidChains {
    let mut stack = Vec::new();
    let first = descend(assembly, root, visited, discarded, &mut stack);
    let mut rest = Vec::new();
    while let Some(branch) = stack.pop() {
        rest.push(descend(assembly, branch, visited, discarded, &mut stack));
    }
    ValidChains { first, rest }
}

/// Extends `chain` by its first passing successor until none passes, and
/// returns the leaf. At each head, every group naming it is offered once at
/// the next position: the first that passes extends `chain`, each later
/// one that passes starts a branch on `stack`, and each that fails is
/// discarded there.
fn descend(
    assembly: &Assembly<'_>,
    mut chain: ValidatedChain,
    visited: &mut BTreeSet<usize>,
    discarded: &mut Vec<Discarded>,
    stack: &mut Vec<ValidatedChain>,
) -> ValidatedChain {
    loop {
        let position = chain.next_position();
        let mut passed: Vec<Accepted> = Vec::new();
        for (index, group) in assembly.children_of(&chain.head_digest()) {
            if !visited.insert(index) {
                continue;
            }
            match successor(&chain, &group.copies) {
                Ok(accepted) => passed.push(accepted),
                Err(defect) => {
                    discarded.push(Discarded::read(group.first_served, position, defect));
                }
            }
        }
        let mut passed = passed.into_iter();
        let Some(next) = passed.next() else {
            return chain;
        };
        // Pushed in reverse so the branches pop in served order.
        stack.extend(passed.rev().map(|accepted| {
            let mut branch = chain.clone();
            branch.push(&accepted);
            branch
        }));
        chain.push(&next);
    }
}
