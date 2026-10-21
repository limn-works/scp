//! [`validate_entry`]: assembly by predecessor digest, then R3's check order
//! on every inception-to-leaf path (§9.7.4.2 R3, R9).

use std::collections::{BTreeMap, BTreeSet};

use scp_did::Identifier;

use super::defect::{Discarded, EventDefect};
use super::{Builder, ChainValidation, Copies, successor};
use crate::{EventUnit, decode_event};

/// What R3's check order makes of every unit one entry served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryValidation {
    /// One verdict per inception-to-leaf path, in the order the paths
    /// branch. Where the inception is invalid or absent, one verdict.
    pub chains: Vec<ChainValidation>,
    /// Every unit that joined no chain, at its index in the served list: a
    /// unit that failed before its predecessor digest decoded, or that names
    /// a predecessor no chain holds.
    pub unplaced: Vec<Discarded>,
}

/// One event's copies, the served index of each, and the identifier they
/// recompute to.
struct Group<'u> {
    copies: Copies<'u>,
    served: Vec<usize>,
    recomputed: Identifier,
}

impl<'u> Group<'u> {
    fn add(&mut self, unit: &'u [u8], index: usize) {
        self.copies.rest.push(unit);
        self.served.push(index);
    }
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

    /// Places one unit by the bytes its decode read: a unit that stopped
    /// before its predecessor digest decoded joins no chain, unless it
    /// recomputes to the served identifier and so is the inception.
    fn place(&mut self, identifier: Identifier, index: usize, unit: &'u [u8]) {
        let at = u64::try_from(index).unwrap_or(u64::MAX);
        let (raw, predecessor) = match decode_event(unit, 0) {
            EventUnit::Unframed => {
                self.unplaced
                    .push(Discarded::new(at, EventDefect::Unframed));
                return;
            }
            EventUnit::NoSeparator => {
                self.unplaced
                    .push(Discarded::new(at, EventDefect::NoSeparator));
                return;
            }
            EventUnit::HeaderFailed(failed) => {
                if failed.raw().identifier() != identifier {
                    self.unplaced.push(Discarded::new(
                        at,
                        EventDefect::Header(failed.error().clone()),
                    ));
                    return;
                }
                (failed.raw().clone(), None)
            }
            EventUnit::Read(read) => (
                read.raw().clone(),
                Some(*read.header().predecessor_digest()),
            ),
        };
        let digest = raw.event_digest();
        if let Some(&group) = self.by_digest.get(&digest) {
            if let Some(group) = self.groups.get_mut(group) {
                group.add(unit, index);
            }
            return;
        }
        let group = self.groups.len();
        self.groups.push(Group {
            copies: Copies::one(unit),
            served: vec![index],
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
}

/// Assembles every unit one entry served into chains by predecessor digest,
/// merging units that share an event digest, then runs R3's check order on
/// every inception-to-leaf path (§9.7.4.2 R3, R9).
///
/// Two units that name one predecessor and carry different digests start
/// two chains, each reported as its own [`ChainValidation::Valid`], so a
/// fork is never a discard. Each unit is one event unit, `BE32(len) ‖
/// signed preimage ‖ signature field`.
#[must_use]
pub fn validate_entry(identifier: &Identifier, units: &[&[u8]]) -> EntryValidation {
    let assembly = Assembly::new(*identifier, units);
    let mut visited = BTreeSet::new();
    let mut builder = Builder::new(*identifier);
    for &group in &assembly.inception {
        visited.insert(group);
        let Some(group) = assembly.groups.get(group) else {
            continue;
        };
        // The identifier binds the whole signed preimage, as the digest
        // does, so at most one merged group recomputes to it; every other
        // group read for position zero fails step 3's first half.
        if group.recomputed != *identifier {
            builder.discarded.push(Discarded::new(
                0,
                EventDefect::IdentifierMismatch {
                    recomputed: group.recomputed,
                },
            ));
        } else if let Err(defect) = builder.offer(&group.copies) {
            return EntryValidation {
                chains: vec![ChainValidation::InceptionInvalid { defect }],
                unplaced: unvisited(assembly, &visited),
            };
        }
    }
    let chains = if builder.chain.is_some() {
        branches(&assembly, builder, &mut visited)
    } else {
        vec![builder.finish()]
    };
    let unplaced = unvisited(assembly, &visited);
    EntryValidation { chains, unplaced }
}

/// Runs the check order down every path from the inception, depth first
/// over an explicit stack. At each head, the groups naming it are each
/// offered at the next position; each that passes starts its own branch,
/// and each that fails is a discard every branch below that head carries.
fn branches(
    assembly: &Assembly<'_>,
    root: Builder,
    visited: &mut BTreeSet<usize>,
) -> Vec<ChainValidation> {
    let mut chains = Vec::new();
    let mut stack = vec![root];
    while let Some(builder) = stack.pop() {
        let Some(chain) = builder.chain.as_ref() else {
            chains.push(builder.finish());
            continue;
        };
        let position = chain.next_position();
        let mut passed = Vec::new();
        let mut failed = Vec::new();
        for &group in assembly
            .children
            .get(&chain.head_digest())
            .map_or(&[][..], Vec::as_slice)
        {
            if !visited.insert(group) {
                continue;
            }
            let Some(copies) = assembly.groups.get(group).map(|group| &group.copies) else {
                continue;
            };
            match successor(chain, copies) {
                Ok(accepted) => passed.push(accepted),
                Err(defect) => failed.push(Discarded::new(position, defect)),
            }
        }
        if passed.is_empty() {
            let mut leaf = builder;
            leaf.discarded.extend(failed);
            chains.push(leaf.finish());
            continue;
        }
        // Pushed in reverse so the branches pop in served order.
        for accepted in passed.iter().rev() {
            let mut branch = builder.clone();
            branch.discarded.extend(failed.iter().cloned());
            if let Some(chain) = branch.chain.as_mut() {
                chain.push(accepted);
            }
            stack.push(branch);
        }
    }
    chains
}

/// Every unit no path reached: one naming a predecessor no chain holds, at
/// its served index, in served order.
fn unvisited(assembly: Assembly<'_>, visited: &BTreeSet<usize>) -> Vec<Discarded> {
    let mut unplaced = assembly.unplaced;
    for (group, named) in &assembly.named {
        if visited.contains(group) {
            continue;
        }
        let Some(served) = assembly.groups.get(*group).map(|group| &group.served) else {
            continue;
        };
        for index in served {
            unplaced.push(Discarded::new(
                u64::try_from(*index).unwrap_or(u64::MAX),
                EventDefect::PredecessorMismatch { named: *named },
            ));
        }
    }
    unplaced.sort_by_key(Discarded::at_position);
    unplaced
}
