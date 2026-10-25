//! R10's self-observation relations: what the valid prefix of each chain one
//! entry of the publication set served holds to the controller's own
//! retained log, and the one chain the entry adopts
//! (`09-security-model.md` §9.7.4.2 R10, *The prefix a relation reads*,
//! *The five relations, each naming an act* and *One entry adopts at most
//! one chain*; `03-identity.md` §3.10.10's `ChainRelation` and
//! `ExtendingAct`).
//!
//! [`classify_relation`] is pure: it decides each relation, keeps the one
//! validated copy of each served chain every act reads, and decides the
//! entry's adoption once. The caller performs every act R10 names: the
//! re-publication, the alert, the confirmation and the adoption into the
//! retained log.

#![deny(clippy::wildcard_enum_match_arm)]

use crate::rank::{
    ChainPairing, Divergence, NoResolution, ResolveError, SetResolution, TieClass, UnrelatedChains,
    pair_chains, resolve_set,
};
use crate::validate::{Discarded, EntryVerdict, ValidatedChain, validate_entry};
use crate::{EventKind, StandingRootDeclaration};

/// The five relations `09-security-model.md` §9.7.4.2 R10 names, which that
/// rule decides over each chain's valid prefix.
///
/// R10: "The five relations partition what a valid prefix can hold to the
/// controller's own retained log."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainRelation {
    /// The entry served no chain.
    Absent,
    /// The chain's head is the head the controller's own log holds.
    Identical,
    /// The chain is a proper prefix of the controller's own retained log.
    Superseded,
    /// The controller's own retained log is a proper prefix of the valid
    /// prefix.
    Extending(ExtendingAct),
    /// The valid prefix is neither a prefix of the controller's own retained
    /// log nor an extension of it.
    Diverged,
}

/// What the extending arm did with the served chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtendingAct {
    /// The chain carried no `RootRecovery{Lost}` the SDK did not author, and
    /// the SDK adopted the whole valid prefix.
    Adopted,
    /// The SDK adopted the prefix before the first such event and withheld
    /// that event and every event past it.
    Withheld,
}

/// Why [`classify_relation`] decided no relation. Valid chains of one
/// identifier reach no variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelationError {
    /// A served chain shares no inception with the controller's own log.
    #[error(transparent)]
    Unrelated(#[from] UnrelatedChains),
    /// The extending arm found no valid prefix of the served chain ending
    /// before the withheld event at `withheld_sequence`.
    #[error("no valid prefix of the served chain ends before sequence {withheld_sequence}")]
    NoPrefixBefore {
        /// The withheld `RootRecovery{Lost}`'s sequence.
        withheld_sequence: u64,
    },
    /// R6 over the own log and the entry's adoption candidates resolved
    /// nothing, or named a winner that is neither.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
}

/// What one entry's answer holds to the controller's own retained log: one
/// reading per chain the entry served, every unit no chain holds, and the
/// one adoption the entry makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRelations {
    /// One reading per valid chain the entry served, in
    /// [`ValidChains::iter`](crate::ValidChains::iter) order, or one
    /// `Absent` reading where the entry's units hold no valid chain
    /// (`03-identity.md` §3.10.10: one observation per chain).
    pub readings: Vec<ServedChainReading>,
    /// [`EntryValidation::discarded`](crate::EntryValidation::discarded),
    /// passed through unchanged: every served unit no chain holds, which R10
    /// treats as unserved and which the caller reads for R10's alerts.
    pub discarded: Vec<Discarded>,
    /// Whether the entry served any unit. An `Absent` reading with this
    /// false is an empty entry; with it true, the entry's frames chain to
    /// nothing (`03-identity.md` §3.10.10, `EntryReach::Answered`).
    pub served_any_unit: bool,
    /// The one chain the entry adopts, which R6 picks from the set of the
    /// own log and every reading's [`ServedChainReading::candidate`].
    pub adoption: EntryAdoption,
}

/// The entry's one adoption decision.
///
/// R10: "It ranks one set under R6: the controller's own retained log, the
/// prefix each extending arm adopts, and each diverged valid prefix that R6
/// ranks above that log. Where the set has a winner, the SDK adopts the
/// winner and no other chain, so the order in which the entry served its
/// chains decides nothing. Where R7 leaves the set tied, the SDK adopts no
/// chain of the set, treats the identity as contested under R7, and retains
/// every tied head."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryAdoption {
    /// No reading names a chain to adopt, or every candidate's head is the
    /// own log's head.
    Keep,
    /// R6 picks this chain from the set; the caller adopts it into the
    /// retained log.
    Adopt(ValidatedChain),
    /// R7 leaves the set tied: the caller adopts nothing and retains every
    /// tied head (R7: "MUST NOT adopt any tied suffix as its key state, and
    /// MUST retain every tied head and suffix as evidence").
    Contested {
        /// The class of the strictest tied pair.
        class: TieClass,
        /// Every tied chain, in ascending head-digest order, so the value
        /// is a function of the set alone.
        tied: Vec<ValidatedChain>,
        /// The shared prefix head of the strictest tied pair.
        shared_prefix_head: [u8; 32],
        /// The fork position of the strictest tied pair.
        fork_position: u64,
    },
}

/// The withheld `RootRecovery{Lost}` of an `Extending(Withheld)` reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WithheldEvent {
    /// The withheld event's sequence: the served chain's events from here
    /// to its head are the withheld suffix.
    pub sequence: u64,
    /// The withheld event's preimage digest, which the confirm-as-own
    /// decision names.
    pub digest: [u8; 32],
}

/// The relation of one chain an entry served.
///
/// It carries the one validated copy of that chain every act R10 names
/// reads: the confirm-as-own
/// decision, the maximum-severity alert, R9's retention of the suffix, and
/// the re-publication from the first event the entry lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedChainReading(Reading);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Reading {
    Absent,
    Identical(ValidatedChain),
    Superseded(ValidatedChain),
    Adopted(ValidatedChain),
    Withheld {
        served: ValidatedChain,
        /// The prefix of `served` ending before `withheld`, cut once when
        /// the reading is decided.
        adopted: ValidatedChain,
        withheld: WithheldEvent,
    },
    Diverged {
        served: ValidatedChain,
        divergence: Divergence,
    },
}

impl ServedChainReading {
    /// R10's relation, decided over the valid prefix.
    #[must_use]
    pub const fn relation(&self) -> ChainRelation {
        match &self.0 {
            Reading::Absent => ChainRelation::Absent,
            Reading::Identical(_) => ChainRelation::Identical,
            Reading::Superseded(_) => ChainRelation::Superseded,
            Reading::Adopted(_) => ChainRelation::Extending(ExtendingAct::Adopted),
            Reading::Withheld { .. } => ChainRelation::Extending(ExtendingAct::Withheld),
            Reading::Diverged { .. } => ChainRelation::Diverged,
        }
    }

    /// The served valid prefix; `None` under `Absent` alone.
    #[must_use]
    pub const fn served(&self) -> Option<&ValidatedChain> {
        match &self.0 {
            Reading::Absent => None,
            Reading::Identical(served)
            | Reading::Superseded(served)
            | Reading::Adopted(served)
            | Reading::Withheld { served, .. }
            | Reading::Diverged { served, .. } => Some(served),
        }
    }

    /// The head digest of the served valid prefix; `None` under `Absent`.
    #[must_use]
    pub fn head(&self) -> Option<[u8; 32]> {
        self.served().map(ValidatedChain::head_digest)
    }

    /// Where the served valid prefix diverges from the own log and how R6
    /// ranks each suffix, in the order own, served; `Some` under `Diverged`
    /// alone.
    #[must_use]
    pub const fn divergence(&self) -> Option<&Divergence> {
        match &self.0 {
            Reading::Diverged { divergence, .. } => Some(divergence),
            Reading::Absent
            | Reading::Identical(_)
            | Reading::Superseded(_)
            | Reading::Adopted(_)
            | Reading::Withheld { .. } => None,
        }
    }

    /// Whether R6 ranks the served valid prefix above the own log, which
    /// R10's diverged arm reads. False under every relation but `Diverged`.
    #[must_use]
    pub fn served_outranks_own(&self) -> bool {
        self.divergence().is_some_and(|divergence| {
            let [own_rank, served_rank] = divergence.ranks;
            served_rank.beats(own_rank)
        })
    }

    /// The withheld `{Lost}` under `Extending(Withheld)`; the withheld
    /// suffix is [`Self::served`] from its sequence to the head.
    #[must_use]
    pub const fn withheld(&self) -> Option<WithheldEvent> {
        match &self.0 {
            Reading::Withheld { withheld, .. } => Some(*withheld),
            Reading::Absent
            | Reading::Identical(_)
            | Reading::Superseded(_)
            | Reading::Adopted(_)
            | Reading::Diverged { .. } => None,
        }
    }

    /// The chain this reading's arm names for adoption, which R6 ranks
    /// against the own log and every other candidate the entry served
    /// ([`EntryRelations::adoption`]): the whole valid prefix under
    /// `Extending(Adopted)`, the prefix before the withheld event under
    /// `Extending(Withheld)`, and the served valid prefix under `Diverged`
    /// where R6 ranks it above the own log. `None` under every other
    /// relation, whose arm adopts nothing.
    #[must_use]
    pub fn candidate(&self) -> Option<&ValidatedChain> {
        match &self.0 {
            Reading::Adopted(served) => Some(served),
            Reading::Withheld { adopted, .. } => Some(adopted),
            Reading::Diverged { served, .. } => self.served_outranks_own().then_some(served),
            Reading::Absent | Reading::Identical(_) | Reading::Superseded(_) => None,
        }
    }
}

/// Decides R10's relation of each chain one entry served to `own`, the
/// controller's own retained log, over each chain's valid prefix, and the
/// one chain the entry adopts.
///
/// `served` is every unit the entry returned, as
/// [`validate_entry`] reads them, and `authored` the preimage digest of
/// every event the SDK authored.
///
/// The prefix a relation reads. R10: "The SDK decides each relation over the
/// longest prefix of the served chain that is valid under R1 through R4 from
/// the inception event, and never over the bytes the entry served. It
/// verifies each signer group against the key set R3's table *The key set
/// each signer group verifies against* names for that group, and never
/// against the key state the reading device holds, discards what R3 directs
/// it to discard, and treats a discarded position as unserved." The units go
/// through [`validate_entry`] under `own`'s identifier, which verifies each
/// group against the chain at the event's predecessor, and every relation
/// reads only a [`ValidatedChain`] it returns. Its discards pass through
/// unchanged as [`EntryRelations::discarded`] and decide nothing.
///
/// "The SDK also runs R3's check order over its own retained log, which no
/// relay orders": `own` is a [`ValidatedChain`], which only R3's check order
/// builds.
///
/// Each relation compares events by preimage digest and never by bytes
/// (R9: "An event is identified by its preimage digest, and every
/// comparison reads that digest and never the bytes"), through
/// [`pair_chains`].
///
/// # Errors
///
/// [`RelationError::Unrelated`] where a served chain shares no inception
/// with `own`: every chain [`validate_entry`] returns has an inception that
/// recomputes to `own`'s identifier, and the identifier binds the
/// inception's whole signed preimage, so a valid `own` never reaches it.
/// [`RelationError::NoPrefixBefore`] where the extending arm cuts no prefix
/// before the event it withholds, which an event of the served chain past
/// `own`'s head never reaches. [`RelationError::Resolve`] where R6 over the
/// own log and the candidates resolves nothing or names a chain outside the
/// set, which valid chains of one identifier never reach.
pub fn classify_relation(
    own: &ValidatedChain,
    served: &[&[u8]],
    authored: &[[u8; 32]],
) -> Result<EntryRelations, RelationError> {
    let validation = validate_entry(&own.identifier(), served);
    let readings: Vec<ServedChainReading> = match &validation.verdict {
        // R10: "**Absent** — the entry served no chain." A discarded
        // position is unserved, so units that hold no valid inception serve
        // no chain.
        EntryVerdict::NoInception | EntryVerdict::InceptionInvalid { .. } => {
            vec![ServedChainReading(Reading::Absent)]
        }
        EntryVerdict::Valid { chains } => chains
            .iter()
            .map(|chain| read_chain(own, chain, authored))
            .collect::<Result<_, _>>()?,
    };
    let adoption = adopt(own, &readings)?;
    Ok(EntryRelations {
        readings,
        discarded: validation.discarded,
        served_any_unit: !served.is_empty(),
        adoption,
    })
}

/// The entry's one adoption: R6 over `own` and every reading's candidate.
///
/// R10: "The SDK does not let either arm adopt alone. It ranks one set
/// under R6 … Where the set has a winner, the SDK adopts the winner and no
/// other chain … Where R7 leaves the set tied, the SDK adopts no chain of
/// the set, treats the identity as contested under R7, and retains every
/// tied head." [`resolve_set`] reads its input as a set, so the order the
/// entry served its chains in changes nothing.
fn adopt(
    own: &ValidatedChain,
    readings: &[ServedChainReading],
) -> Result<EntryAdoption, RelationError> {
    let candidates: Vec<&ValidatedChain> = readings
        .iter()
        .filter_map(ServedChainReading::candidate)
        .collect();
    if candidates.is_empty() {
        return Ok(EntryAdoption::Keep);
    }
    let mut set: Vec<ValidatedChain> = Vec::with_capacity(candidates.len() + 1);
    set.push(own.clone());
    set.extend(candidates.iter().map(|chain| (*chain).clone()));
    let by_head = |head: &[u8; 32]| {
        set.iter()
            .find(|chain| chain.head_digest() == *head)
            .cloned()
            .ok_or(ResolveError::NoResolution(NoResolution))
    };
    Ok(match resolve_set(&set)? {
        SetResolution::Winner { head } if head == own.head_digest() => EntryAdoption::Keep,
        SetResolution::Winner { head } => EntryAdoption::Adopt(by_head(&head)?),
        SetResolution::Tie {
            class,
            heads,
            shared_prefix_head,
            fork_position,
        } => EntryAdoption::Contested {
            class,
            tied: heads.iter().map(by_head).collect::<Result<_, _>>()?,
            shared_prefix_head,
            fork_position,
        },
        // The set holds `own`, so it is never empty.
        SetResolution::Empty => return Err(ResolveError::NoResolution(NoResolution).into()),
    })
}

/// The relation of one served valid prefix to `own`.
fn read_chain(
    own: &ValidatedChain,
    chain: &ValidatedChain,
    authored: &[[u8; 32]],
) -> Result<ServedChainReading, RelationError> {
    let served = chain.clone();
    Ok(ServedChainReading(match pair_chains(own, chain)? {
        // R10: "**Identical** — the chain's head is the head the
        // controller's own log holds. The SDK performs no act."
        ChainPairing::Identical => Reading::Identical(served),
        // R10: "**Superseded** — the chain is a proper prefix of the
        // controller's own retained log."
        ChainPairing::RightPrefixOfLeft => Reading::Superseded(served),
        // R10: "**Extending** — the controller's own retained log is a
        // proper prefix of the valid prefix."
        ChainPairing::LeftPrefixOfRight => extending(own, served, authored)?,
        // R10: "**Diverged** — the valid prefix is neither a prefix of the
        // controller's own retained log nor an extension of it. … Where R6
        // ranks the served valid prefix above the controller's own retained
        // log, the SDK still records and alerts, but it re-publishes nothing
        // to that entry and instead adopts the served prefix under the
        // signing rule's marker clause above." The ranks are own's, then
        // the served chain's, in `pair_chains`' argument order.
        ChainPairing::Diverged(divergence) => Reading::Diverged { served, divergence },
    }))
}

/// The extending arm's reading of a served `chain` that `own` is a proper
/// prefix of.
///
/// R10: "The SDK adopts the longest prefix of the served chain that ends
/// before the first `RootRecovery{Lost}` the SDK did not author, which is
/// the whole valid prefix where the chain carries no such event. … It
/// withholds that `{Lost}` event and every event past it."
///
/// The walk reads only the events past `own`'s head: every event at or
/// before it is already in the retained log, so the adopted prefix always
/// holds `own`. A `{Lost}` is read off field 5, and a `RootRecovery{CoSigns}`
/// the SDK did not author is adopted, because its standing-root group
/// carries the root's signature: "The SDK takes the adopted events without
/// asking, because every one of them carries a signature by the standing
/// root".
fn extending(
    own: &ValidatedChain,
    served: ValidatedChain,
    authored: &[[u8; 32]],
) -> Result<Reading, RelationError> {
    let own_head = own.head_sequence();
    let withheld = served
        .events()
        .find(|event| {
            event.sequence > own_head
                && event.kind == EventKind::RootRecovery
                && event.standing_root == Some(StandingRootDeclaration::Lost)
                && !authored.contains(&event.digest)
        })
        .map(|event| WithheldEvent {
            sequence: event.sequence,
            digest: event.digest,
        });
    let Some(withheld) = withheld else {
        return Ok(Reading::Adopted(served));
    };
    // The withheld event sits past `own`'s head, at a sequence of at least
    // one, so the prefix before it exists and holds `own`.
    let no_prefix = RelationError::NoPrefixBefore {
        withheld_sequence: withheld.sequence,
    };
    let before = withheld.sequence.checked_sub(1).ok_or(no_prefix)?;
    let adopted = served.prefix(before).ok_or(no_prefix)?;
    Ok(Reading::Withheld {
        served,
        adopted,
        withheld,
    })
}
