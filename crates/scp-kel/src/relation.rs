//! R10's self-observation relations: what the valid prefix of each chain one
//! entry of the publication set served holds to the controller's own
//! retained log, and the chain each relation's arm adopts
//! (`09-security-model.md` §9.7.4.2 R10, *The prefix a relation reads* and
//! *The five relations, each naming an act*; `03-identity.md` §3.10.10's
//! `ChainRelation` and `ExtendingAct`).
//!
//! [`classify_relation`] is pure: it decides each relation and names the
//! chain to adopt, and the caller performs every act R10 names, the
//! re-publication, the alert and the adoption into the retained log.

#![deny(clippy::wildcard_enum_match_arm)]

use crate::rank::{ChainPairing, UnrelatedChains, pair_chains};
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
/// identifier reach neither variant.
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
}

/// What one entry's answer holds to the controller's own retained log: one
/// reading per chain the entry served, and every unit no chain holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRelations {
    /// One reading per valid chain the entry served, in
    /// [`ValidChains::iter`](crate::ValidChains::iter) order, or one
    /// `Absent` reading where the entry's units hold no valid chain.
    pub readings: Vec<ServedChainReading>,
    /// [`EntryValidation::discarded`](crate::EntryValidation::discarded),
    /// passed through unchanged: every served unit no chain holds, which R10
    /// treats as unserved and which the caller reads for R10's alerts.
    pub discarded: Vec<Discarded>,
    /// Whether the entry served any unit. An `Absent` reading with this
    /// false is an empty entry; with it true, the entry's frames chain to
    /// nothing (`03-identity.md` §3.10.10, `EntryReach::Answered`).
    pub served_any_unit: bool,
}

/// The relation of one chain an entry served, and the chain its arm adopts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedChainReading {
    /// The head digest of the chain's valid prefix; `None` under `Absent`.
    pub head: Option<[u8; 32]>,
    /// R10's relation, decided over the valid prefix.
    pub relation: ChainRelation,
    /// The chain the relation's arm adopts into the retained log: the
    /// adopted prefix under `Extending`, and the served valid prefix under
    /// `Diverged` where R6 ranks it above the controller's own retained log.
    /// `None` under every other relation, whose arm adopts nothing.
    pub adopt: Option<ValidatedChain>,
    /// Whether R6 ranks the served valid prefix above the controller's own
    /// retained log, which R10's diverged arm reads. False under every
    /// relation but `Diverged`, where R6 ranks no divergence.
    pub served_outranks_own: bool,
}

/// Decides R10's relation of each chain one entry served to `own`, the
/// controller's own retained log, over each chain's valid prefix.
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
/// `own`'s head never reaches.
pub fn classify_relation(
    own: &ValidatedChain,
    served: &[&[u8]],
    authored: &[[u8; 32]],
) -> Result<EntryRelations, RelationError> {
    let validation = validate_entry(&own.identifier(), served);
    let readings = match &validation.verdict {
        // R10: "**Absent** — the entry served no chain." A discarded
        // position is unserved, so units that hold no valid inception serve
        // no chain.
        EntryVerdict::NoInception | EntryVerdict::InceptionInvalid { .. } => {
            vec![ServedChainReading {
                head: None,
                relation: ChainRelation::Absent,
                adopt: None,
                served_outranks_own: false,
            }]
        }
        EntryVerdict::Valid { chains } => chains
            .iter()
            .map(|chain| read_chain(own, chain, authored))
            .collect::<Result<_, _>>()?,
    };
    Ok(EntryRelations {
        readings,
        discarded: validation.discarded,
        served_any_unit: !served.is_empty(),
    })
}

/// The relation of one served valid prefix to `own`.
fn read_chain(
    own: &ValidatedChain,
    chain: &ValidatedChain,
    authored: &[[u8; 32]],
) -> Result<ServedChainReading, RelationError> {
    let reading = |relation, adopt, served_outranks_own| ServedChainReading {
        head: Some(chain.head_digest()),
        relation,
        adopt,
        served_outranks_own,
    };
    Ok(match pair_chains(own, chain)? {
        // R10: "**Identical** — the chain's head is the head the
        // controller's own log holds. The SDK performs no act."
        ChainPairing::Identical => reading(ChainRelation::Identical, None, false),
        // R10: "**Superseded** — the chain is a proper prefix of the
        // controller's own retained log."
        ChainPairing::RightPrefixOfLeft => reading(ChainRelation::Superseded, None, false),
        // R10: "**Extending** — the controller's own retained log is a
        // proper prefix of the valid prefix."
        ChainPairing::LeftPrefixOfRight => {
            let (act, adopt) = extending(own, chain, authored)?;
            reading(ChainRelation::Extending(act), Some(adopt), false)
        }
        // R10: "**Diverged** — the valid prefix is neither a prefix of the
        // controller's own retained log nor an extension of it. … Where R6
        // ranks the served valid prefix above the controller's own retained
        // log, the SDK still records and alerts, but it re-publishes nothing
        // to that entry and instead adopts the served prefix under the
        // signing rule's marker clause above."
        ChainPairing::Diverged(divergence) => {
            let [own_rank, served_rank] = divergence.ranks;
            let outranks = served_rank.beats(own_rank);
            reading(
                ChainRelation::Diverged,
                outranks.then(|| chain.clone()),
                outranks,
            )
        }
    })
}

/// The extending arm's act and the prefix it adopts, for a served `chain`
/// that `own` is a proper prefix of.
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
    chain: &ValidatedChain,
    authored: &[[u8; 32]],
) -> Result<(ExtendingAct, ValidatedChain), RelationError> {
    let own_head = own.head_sequence();
    let withheld = chain.events().find(|event| {
        event.sequence > own_head
            && event.kind == EventKind::RootRecovery
            && event.standing_root == Some(StandingRootDeclaration::Lost)
            && !authored.contains(&event.digest)
    });
    let Some(event) = withheld else {
        return Ok((ExtendingAct::Adopted, chain.clone()));
    };
    // The withheld event sits past `own`'s head, at a sequence of at least
    // one, so the prefix before it exists and holds `own`.
    let no_prefix = RelationError::NoPrefixBefore {
        withheld_sequence: event.sequence,
    };
    let before = event.sequence.checked_sub(1).ok_or(no_prefix)?;
    let adopt = chain.prefix(before).ok_or(no_prefix)?;
    Ok((ExtendingAct::Withheld, adopt))
}
