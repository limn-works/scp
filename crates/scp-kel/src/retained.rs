//! The key-event log a validating store holds, and the key state it reads
//! from each chain the log retains under R9.
//!
//! Sources: `03-identity.md` §3.10.10 `ResolvedState`, `RetainedLog` and
//! `RetainedChain`; `09-security-model.md` §9.7.4.2 R3, R9 and R10's frame
//! admission, §9.10.12.
//!
//! A party's verification decision reads a [`ResolvedState`](crate::ResolvedState),
//! which only the verdict classifier constructs. A validating store (a node's
//! public-record store, §9.10.12) is not a party: it holds every chain it
//! retains under R9, accepted or suffix, and admits and selects per chain,
//! for availability only. [`RetainedLog`] is one identifier's log as the store
//! holds it, and [`RetainedChain`] is the key state of one chain the log
//! retains. A `RetainedLog` takes event units and never a chain, and it is the
//! only constructor of a `RetainedChain`, so a store reads only chains it
//! validated and ranked itself.

use scp_did::{Identifier, KeyState};

use crate::rank::{AcceptedChainHolder, HoldError, HoldOutcome};
use crate::validate::{
    Discarded, EntryVerdict, InceptionDefect, NotOnChain, ReplayedState, ValidatedChain,
    key_state_at, replay, validate_entry,
};
use crate::{EventKind, EventUnit, decode_event};

/// One chain a validating store retains under `09-security-model.md`
/// §9.7.4.2 R9, accepted or suffix, with the key state replaying it derives
/// (`03-identity.md` §3.10.10).
///
/// Only [`RetainedLog::retained`] constructs it. Its fields are private, it
/// has no `Deserialize`, and no conversion from a [`ValidatedChain`] exists:
///
/// ```compile_fail,E0277
/// fn build(chain: scp_kel::ValidatedChain) -> scp_kel::RetainedChain {
///     chain.into()
/// }
/// ```
///
/// ```compile_fail,E0451
/// fn build(chain: scp_kel::ValidatedChain) -> scp_kel::RetainedChain {
///     scp_kel::RetainedChain {
///         identifier: chain.identifier(),
///         replayed: scp_kel::replay(&chain),
///         chain,
///     }
/// }
/// ```
///
/// The R9 holder, whose `hold` takes any [`ValidatedChain`], has no path to a
/// `RetainedChain`:
///
/// ```compile_fail,E0599
/// fn build(chain: scp_kel::ValidatedChain) -> Vec<scp_kel::RetainedChain> {
///     let mut holder = scp_kel::AcceptedChainHolder::new();
///     let _ = holder.hold(chain);
///     holder.retained()
/// }
/// ```
///
/// The positive control reads one from a log:
///
/// ```
/// fn heads(log: &scp_kel::RetainedLog) -> Vec<[u8; 32]> {
///     log.retained().iter().map(scp_kel::RetainedChain::head_digest).collect()
/// }
/// assert!(heads(&scp_kel::RetainedLog::new(scp_did::Identifier::ZERO)).is_empty());
/// ```
///
/// It carries no verdict and no resolution instant: a store admits a record
/// for availability, and no party's trust decision reads a `RetainedChain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedChain {
    chain: ValidatedChain,
    replayed: ReplayedState,
    identifier: Identifier,
}

impl RetainedChain {
    /// The key state `chain` replays to. Private to this module: its one
    /// caller is [`RetainedLog::retained`].
    fn of(chain: &ValidatedChain) -> Self {
        Self {
            chain: chain.clone(),
            replayed: replay(chain),
            identifier: chain.identifier(),
        }
    }

    /// The identifier the retained chain's inception recomputes to.
    #[must_use]
    pub const fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// The preimage digest of the retained chain's head event.
    #[must_use]
    pub fn head_digest(&self) -> [u8; 32] {
        self.chain.head_digest()
    }

    /// The sequence of the retained chain's head event.
    #[must_use]
    pub fn head_sequence(&self) -> u64 {
        self.chain.head_sequence()
    }

    /// Each event's preimage digest, from the inception to the head.
    pub fn event_digests(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.chain.event_digests()
    }

    /// Whether the retained chain's event at `sequence` has the preimage
    /// digest `digest`.
    #[must_use]
    pub fn holds(&self, sequence: u64, digest: &[u8; 32]) -> bool {
        self.chain.digest_at(sequence) == Some(*digest)
    }

    /// The key state at the retained chain's head.
    #[must_use]
    pub const fn key_state(&self) -> &KeyState {
        self.replayed.key_state()
    }

    /// The key state at the retained chain's head with the keys R3 resolved
    /// there.
    #[must_use]
    pub const fn replayed(&self) -> &ReplayedState {
        &self.replayed
    }

    /// The key state at the retained chain's event whose preimage digest
    /// (`09-security-model.md` §9.5.1) is `digest`, read as
    /// [`ResolvedState::key_state_at`](crate::ResolvedState::key_state_at)
    /// reads it.
    ///
    /// # Errors
    ///
    /// [`NotOnChain`] where no event of the retained chain has that digest.
    pub fn key_state_at(&self, digest: &[u8; 32]) -> Result<KeyState, NotOnChain> {
        key_state_at(&self.chain, digest).map(|state| state.key_state().clone())
    }
}

/// Why [`RetainedLog::admit`] held nothing. The log is then unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameRefusal {
    /// The frame carries no event unit.
    #[error("the frame carries no event")]
    Empty,
    /// The first unit does not decode to an event header.
    #[error("the frame's first event does not decode")]
    Undecodable,
    /// R10's frame admission: the first event is one the log holds.
    #[error("the frame's first event is one the log holds")]
    FirstHeld,
    /// R10's frame admission: the first event is neither the identifier's
    /// inception nor the successor of an event the log holds.
    #[error(
        "the frame's first event is neither the inception of the identifier nor the successor \
         of an event the log holds"
    )]
    Unanchored,
    /// The inception fails R2 or an R3 indicator: the identifier names no
    /// valid chain (R14's `Invalid`).
    #[error("the inception is invalid: {0}")]
    InceptionInvalid(InceptionDefect),
    /// Unit `index` of the frame fails R3's check order against the chain
    /// the units before it extend, a predecessor naming another event than
    /// the unit before it included.
    #[error("event {index} of the frame fails R3: {}", discarded.defect())]
    Illegal {
        /// The unit's position in the frame.
        index: usize,
        /// The check that failed.
        discarded: Discarded,
    },
    /// The R9 holder reached an error, which valid chains of one identifier
    /// never do.
    #[error(transparent)]
    Hold(#[from] HoldError),
}

/// One identifier's key-event log as a validating store holds it
/// (`03-identity.md` §3.10.10, `09-security-model.md` §9.10.12).
///
/// It holds the chains it retains under §9.7.4.2 R9, built from the event
/// units of the frames the store admitted, in the order it admitted them.
///
/// It takes event units and never a chain, so a caller cannot present a
/// chain the log did not validate:
///
/// ```compile_fail,E0308
/// fn build(chain: scp_kel::ValidatedChain) -> scp_kel::RetainedLog {
///     let mut log = scp_kel::RetainedLog::new(chain.identifier());
///     let _ = log.admit(chain);
///     log
/// }
/// ```
///
/// The positive control admits units:
///
/// ```
/// let mut log = scp_kel::RetainedLog::new(scp_did::Identifier::ZERO);
/// let units: [&[u8]; 0] = [];
/// assert_eq!(log.admit(&units), Err(scp_kel::FrameRefusal::Empty));
/// ```
#[derive(Debug, Clone)]
pub struct RetainedLog {
    identifier: Identifier,
    holder: AcceptedChainHolder,
}

impl RetainedLog {
    /// A log of `identifier` that holds no chain.
    #[must_use]
    pub const fn new(identifier: Identifier) -> Self {
        Self {
            identifier,
            holder: AcceptedChainHolder::new(),
        }
    }

    /// The identifier the log holds chains of.
    #[must_use]
    pub const fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// Whether some chain the log holds carries the event `digest` at
    /// `position`.
    #[must_use]
    pub fn holds(&self, position: u64, digest: &[u8; 32]) -> bool {
        self.holder
            .held()
            .any(|chain| chain.digest_at(position) == Some(*digest))
    }

    /// Admits one frame's event units, `BE32(len) ‖ signed preimage ‖
    /// signature field` each, in frame order.
    ///
    /// R10's frame admission first: the first unit is not an event the log
    /// holds, and it is either the identifier's inception or the successor
    /// of an event a held chain carries. Then R3's check order runs on each
    /// unit once, against the chain the units before it extend, so a unit
    /// whose predecessor is not the unit before it fails there. The extended
    /// chain is then held under R9. The log validates each unit once and
    /// never replays what it holds.
    ///
    /// # Errors
    ///
    /// [`FrameRefusal`] names the rule the frame breaks; on any error the
    /// log is unchanged. A frame the retention bounds refuse is
    /// `Ok(HoldOutcome::Refused)`.
    pub fn admit(&mut self, units: &[&[u8]]) -> Result<HoldOutcome, FrameRefusal> {
        let Some((first, rest)) = units.split_first() else {
            return Err(FrameRefusal::Empty);
        };
        let EventUnit::Read(read) = decode_event(first, 0) else {
            return Err(FrameRefusal::Undecodable);
        };
        let header = read.header();
        let sequence = header.sequence();
        if self.holds(sequence, &read.raw().event_digest()) {
            return Err(FrameRefusal::FirstHeld);
        }
        let mut chain = if header.kind() == EventKind::Inception {
            if read.raw().identifier() != self.identifier {
                return Err(FrameRefusal::Unanchored);
            }
            let validation = validate_entry(&self.identifier, &[first]);
            match validation.verdict {
                EntryVerdict::Valid { chains } => chains.iter().next().cloned(),
                EntryVerdict::InceptionInvalid { defect } => {
                    return Err(FrameRefusal::InceptionInvalid(defect));
                }
                EntryVerdict::NoInception => None,
            }
            .ok_or_else(|| {
                validation.discarded.into_iter().next().map_or(
                    FrameRefusal::Undecodable,
                    |discarded| FrameRefusal::Illegal {
                        index: 0,
                        discarded,
                    },
                )
            })?
        } else {
            let predecessor = sequence
                .checked_sub(1)
                .and_then(|position| self.chain_through(position, header.predecessor_digest()))
                .ok_or(FrameRefusal::Unanchored)?;
            predecessor
                .extend(first)
                .map_err(|(_, discarded)| FrameRefusal::Illegal {
                    index: 0,
                    discarded,
                })?
        };
        for (offset, unit) in rest.iter().enumerate() {
            chain = chain
                .extend(unit)
                .map_err(|(_, discarded)| FrameRefusal::Illegal {
                    index: offset.saturating_add(1),
                    discarded,
                })?;
        }
        Ok(self.holder.hold(chain)?)
    }

    /// The held chain through `position`, where its event there is `digest`.
    fn chain_through(&self, position: u64, digest: &[u8; 32]) -> Option<ValidatedChain> {
        self.holder
            .held()
            .find(|chain| chain.digest_at(position) == Some(*digest))
            .and_then(|chain| chain.prefix(position))
    }

    /// Every chain the log retains under R9, the accepted chain included, in
    /// the order of the moment the log first held each, as the key state a
    /// validating store's admission and selection read (`03-identity.md`
    /// §3.10.10, `09-security-model.md` §9.10.12).
    #[must_use]
    pub fn retained(&self) -> Vec<RetainedChain> {
        self.holder.held().map(RetainedChain::of).collect()
    }
}
