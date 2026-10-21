//! What a verifier reports about a unit it does not accept (§9.7.4.2 R3):
//! the defect, the step of the check order that found it, and which side of
//! R3's illegality test the failing check falls on.

use scp_did::{Identifier, KeyRole};

use crate::{
    BodyError, EventKind, HeaderError, InceptionHeaderDefect, IndexedSignatureError,
    SignatureFieldError, SignerGroupRole,
};

/// The step of §9.7.4.2 R3's check order at which an event failed
/// (`03-identity.md` §3.10.10).
///
/// Step 6 computes the digest and cannot fail, so it has no variant.
/// `InceptionBinding` is step 3's first half; a failure at step 3's second
/// half is [`EntryVerdict::InceptionInvalid`](super::EntryVerdict) and
/// never a discard. `NamedCount` is sub-check 7a and `VerifiedCount`
/// sub-check 7b.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckStep {
    /// Step 1: the unit's length prefix lies within the frame's `value`.
    Unit,
    /// Step 2: the prefixed bytes begin with `SCP-KEL-EVENT-V1:`.
    Separator,
    /// Step 3's first half: the identifier the raw signed preimage
    /// recomputes to is the served identifier.
    InceptionBinding,
    /// Step 4: fields 1 through 7, the form-list lengths, the encoded-length
    /// bound, and the predecessor digest.
    Header,
    /// Step 5: the signature field walks under fields 6 and 7.
    Walk,
    /// Sub-check 7a: some group names its threshold, before any signature
    /// is verified.
    NamedCount,
    /// Sub-check 7b: some group that passed 7a reaches its threshold of
    /// verifying signatures.
    VerifiedCount,
    /// Step 8: fields 8 through 12 decode and the event meets R1 through
    /// R4, R8 and every R3 indicator.
    Content,
    /// Step 9: every remaining named index carries a verifying signature.
    Signatures,
}

/// Which side of §9.7.4.2 R3's illegality test a failure falls on, decided
/// by the bytes the failing check reads and never by its step number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// The failing check reads only bytes the event's digest binds and the
    /// chain at its predecessor, so every copy of the event fails it: an
    /// illegality failure.
    Illegal,
    /// The failing check reads the signature field, which a relay can strip
    /// or corrupt without changing the digest.
    CopyDamage,
    /// The failing check reads something else: the frame's length prefix,
    /// the served identifier, or a predecessor the verifier does not hold.
    ProvesNothing,
}

/// Which threshold is outside the range one to the size of the set it
/// indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThresholdField {
    /// The installed root set's threshold (field 9).
    Root,
    /// The next threshold the continuation fixes (field 12).
    Next,
}

/// Which list holds two equal entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistinctList {
    /// The installed root set (field 9).
    RootSet,
    /// The commitment list (field 12).
    Commitments,
    /// The snapshot's witness set (field 10).
    Witnesses,
}

/// A defect step 8 finds in fields 8 through 12, or in the inception's
/// content at step 3's second half: R1 through R4, R8 and the R3 indicators
/// (§9.7.4.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentDefect {
    /// Fields 8 through 12 do not decode.
    #[error(transparent)]
    Body(BodyError),
    /// The predecessor chain holds an abandonment (R4).
    #[error("the predecessor chain holds an abandoning rollover")]
    AfterAbandonment,
    /// An `Inception` past position zero.
    #[error("a {kind:?} at a position past the inception")]
    KindAtPosition {
        /// The event's kind.
        kind: EventKind,
    },
    /// The identifier field differs from the chain's identifier.
    #[error("the identifier field differs from the chain's identifier")]
    IdentifierFieldMismatch,
    /// The sequence is not the predecessor's plus one.
    #[error("the sequence is {found}, and the predecessor's plus one is {expected}")]
    SequenceNotNext {
        /// The predecessor's sequence plus one.
        expected: u64,
        /// The event's sequence.
        found: u64,
    },
    /// A field the kind carries as a sentinel holds another value.
    #[error("field {field} holds a value where the kind carries its sentinel")]
    SentinelHeld {
        /// The field number.
        field: u8,
    },
    /// A field the kind carries in substance holds its sentinel.
    #[error("field {field} holds its sentinel where the kind carries it in substance")]
    FieldAbsent {
        /// The field number.
        field: u8,
    },
    /// An inception that fixes no commitment (R2).
    #[error("the inception fixes no commitment")]
    InceptionFixesNoCommitment,
    /// A reveal-authorized event that neither fixes nor abandons (R4).
    #[error("the reveal-authorized event neither fixes a commitment nor abandons")]
    ContinuationMissing,
    /// A `RootRecovery` that declares abandonment (R4).
    #[error("a RootRecovery declares abandonment")]
    RecoveryAbandons,
    /// A signer index list repeats an index.
    #[error("the {role:?} group names index {index} more than once")]
    RepeatedIndex {
        /// The group.
        role: SignerGroupRole,
        /// The repeated index.
        index: u8,
    },
    /// A signer index names no member of the group's key set.
    #[error("the {role:?} group names index {index}, outside its key set")]
    IndexOutOfRange {
        /// The group.
        role: SignerGroupRole,
        /// The index.
        index: u8,
    },
    /// A signer index list names fewer indices than its set's threshold.
    #[error("the {role:?} group names {named} indices, below its threshold {threshold}")]
    IndexCountBelowThreshold {
        /// The group.
        role: SignerGroupRole,
        /// The number of indices named.
        named: usize,
        /// The key set's threshold.
        threshold: u32,
    },
    /// The revealed-keys count differs from the reveal group's index count.
    #[error("{keys} revealed keys for {indices} reveal indices")]
    RevealCountMismatch {
        /// The reveal group's index count.
        indices: usize,
        /// The revealed-keys count.
        keys: usize,
    },
    /// A revealed key's commitment is not the standing list's member at its
    /// named index.
    #[error("the key revealed at index {index} does not match the standing commitment")]
    RevealMismatch {
        /// The named index.
        index: u8,
    },
    /// A threshold outside one to the size of the set it indexes.
    #[error("the {field:?} threshold {threshold} is outside 1..={size}")]
    ThresholdOutOfRange {
        /// Which threshold.
        field: ThresholdField,
        /// Its value.
        threshold: u32,
        /// The size of the set it indexes.
        size: usize,
    },
    /// A list whose entries are not pairwise distinct.
    #[error("the {list:?} holds two equal entries")]
    NotDistinct {
        /// The list.
        list: DistinctList,
    },
    /// An `Inception` or `RootRecovery` whose field 9 differs from the
    /// snapshot's `Current` root members and threshold.
    #[error("the installed root set differs from the snapshot's root")]
    InstalledRootMismatch,
    /// A snapshot whose root set exceeds `MAX_ROOT_SET_SIZE`.
    #[error("the snapshot's root set has {size} members")]
    RootSetTooLarge {
        /// The root set's size.
        size: usize,
    },
    /// A `KeyState` whose root differs from the root standing at its
    /// predecessor.
    #[error("a KeyState changes the standing root")]
    KeyStateRootChanged,
    /// A 33-byte key in field 8, 9 or 10 that is not a valid compressed
    /// P-256 point: a leading byte other than `0x02` or `0x03`, or no point
    /// on the curve (§9.5, point validation).
    #[error("a key is not a valid compressed P-256 point")]
    InvalidPoint {
        /// The key.
        key: [u8; 33],
    },
    /// A snapshot listing one key more than once.
    #[error("the snapshot lists a key more than once")]
    KeyListedTwice {
        /// The key.
        key: [u8; 33],
    },
    /// More than one key `Current` in an operational role.
    #[error("more than one key is Current in the {role:?} role")]
    TwoCurrentInRole {
        /// The role.
        role: KeyRole,
    },
    /// A service-key role other than `Active`, the one registered value.
    #[error("the service-key role is {role:?}")]
    ServiceRoleNotActive {
        /// The role the snapshot names.
        role: KeyRole,
    },
    /// The service-key role resolves to no `Current` key.
    #[error("the service-key role resolves to no Current key")]
    ServiceRoleUnresolved,
    /// A witnessing interval outside its bounds.
    #[error("the witnessing interval {interval} is out of range")]
    WitnessIntervalOutOfRange {
        /// The interval.
        interval: u32,
    },
    /// A witness set naming the subject identifier.
    #[error("the witness set names the subject identifier")]
    WitnessNamesSubject,
    /// A nonzero delegator.
    #[error("the delegator is not zero")]
    NonzeroDelegator,
    /// A snapshot identical to its predecessor's.
    #[error("the snapshot is identical to its predecessor's")]
    SnapshotUnchanged,
    /// A listed key neither `Current` at the predecessor nor kept `Current`.
    #[error("the snapshot lists a key it neither keeps Current nor drops")]
    KeyNotCurrentNorDropped {
        /// The key.
        key: [u8; 33],
    },
    /// A key `Current` at the predecessor that the snapshot does not list.
    #[error("the snapshot silently drops a Current key")]
    SilentDrop {
        /// The key.
        key: [u8; 33],
    },
    /// A dropped entry `Superseded` where no installed key takes its role.
    #[error("a Superseded key has no successor in its role")]
    SupersededWithoutSuccessor {
        /// The key.
        key: [u8; 33],
    },
    /// A dropped entry `Retired` where an installed key takes its role.
    #[error("a Retired key has a successor in its role")]
    RetiredWithSuccessor {
        /// The key.
        key: [u8; 33],
    },
    /// A key listed in a role other than the one it was installed in.
    #[error("a key is listed as {listed:?}, and was installed as {installed:?}")]
    RoleChanged {
        /// The key.
        key: [u8; 33],
        /// The role it was installed in.
        installed: KeyRole,
        /// The role the snapshot lists.
        listed: KeyRole,
    },
    /// A key installed by a second event.
    #[error("a key an earlier event installed is installed again")]
    KeyInstalledTwice {
        /// The key.
        key: [u8; 33],
    },
    /// A `RootRecovery` whose snapshot keeps a root member `Current` from
    /// its predecessor. Whether a recovery may keep one is open in
    /// `00-open-questions.md` (a kept root member sits in field 9, which
    /// installs K′), so the verifier fails closed on that case alone; a kept
    /// operational key is valid (§9.12, "the controller's own key re-listed
    /// otherwise").
    #[error("a RootRecovery keeps a root member Current")]
    KeptRootMember {
        /// The kept key.
        key: [u8; 33],
    },
    /// An installed key that a reveal on the chain revealed.
    #[error("an installed key was revealed as a next-set key")]
    InstalledKeyRevealed {
        /// The key.
        key: [u8; 33],
    },
    /// An installed key whose commitment was fixed at or before the event.
    #[error("an installed key's commitment was fixed on the chain")]
    InstalledKeyCommitted {
        /// The key.
        key: [u8; 33],
    },
    /// A fixed commitment equal to the commitment of a key installed at or
    /// before the event.
    #[error("a fixed commitment commits to an installed key")]
    CommitmentToInstalledKey {
        /// The commitment.
        commitment: [u8; 32],
    },
    /// A fixed commitment equal to the commitment of a revealed key.
    #[error("a fixed commitment commits to a revealed key")]
    CommitmentToRevealedKey {
        /// The commitment.
        commitment: [u8; 32],
    },
    /// A next threshold below the threshold of the root standing after the
    /// event.
    #[error("the next threshold {next_threshold} is below the root threshold {root_threshold}")]
    NextThresholdBelowRoot {
        /// The next threshold.
        next_threshold: u32,
        /// The root threshold after the event.
        root_threshold: u32,
    },
    /// `Compromised{from: N}` with N past the event's sequence (R8).
    #[error("a key is Compromised from {from}, past the sequence {sequence}")]
    CompromisedFromAfterSequence {
        /// The key.
        key: [u8; 33],
        /// N.
        from: u64,
        /// The event's sequence.
        sequence: u64,
    },
    /// A key list out of the snapshot order: kept `Current` entries in
    /// their existing order, then installed keys, then dropped entries in
    /// their existing order.
    #[error("the key list is out of the snapshot order")]
    SnapshotOrder {
        /// The first key out of order.
        key: [u8; 33],
    },
}

/// Why an inception that recomputes to the served identifier names no
/// valid chain: step 3's second half (§9.7.4.2 R2, R3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InceptionDefect {
    /// Field 1 is not `Inception`, or field 2, 3 or 4 is not zero.
    #[error(transparent)]
    ZeroCheck(InceptionHeaderDefect),
    /// Fields 1 through 7, the form lists or the encoded length.
    #[error(transparent)]
    Header(HeaderError),
    /// Fields 8 through 12: R2 or an R3 indicator.
    #[error(transparent)]
    Content(ContentDefect),
}

/// Why a verifier discarded a unit. Each variant is the failing check; the
/// event digest rides every variant from step 6 on, so a unit that never
/// reached step 6 carries none.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventDefect {
    /// Step 1: the length prefix, or the bytes it covers, run past `value`.
    #[error("the unit's length prefix runs past the frame")]
    Unframed,
    /// Step 2: the prefixed bytes do not begin with the separator.
    #[error("the prefixed bytes do not begin with SCP-KEL-EVENT-V1:")]
    NoSeparator,
    /// Step 3's first half: the raw signed preimage recomputes to another
    /// identifier.
    #[error("the inception recomputes to another identifier")]
    IdentifierMismatch {
        /// The identifier the raw signed preimage recomputes to.
        recomputed: Identifier,
    },
    /// Step 4: fields 1 through 7, the form lists or the encoded length.
    #[error(transparent)]
    Header(HeaderError),
    /// Step 4: the predecessor digest is not the digest at p − 1.
    #[error("the predecessor digest names an event the chain does not hold there")]
    PredecessorMismatch {
        /// The predecessor digest the event names.
        named: [u8; 32],
    },
    /// Step 5: an indexed signature does not read.
    #[error(transparent)]
    Walk(SignatureFieldError),
    /// Step 5: bytes past the last indexed signature the form lists account
    /// for.
    #[error("{trailing} bytes follow the signature field")]
    UnconsumedBytes {
        /// The count of trailing bytes.
        trailing: usize,
    },
    /// Sub-check 7a: no root or standing-root group names its threshold and
    /// the reveal group holds too few matching reveals.
    #[error("no group names its threshold")]
    NamedCountShort {
        /// The event digest.
        digest: [u8; 32],
    },
    /// Sub-check 7b: no group that passed 7a reaches its threshold of
    /// verifying signatures.
    #[error("no group reaches its threshold of verifying signatures")]
    VerifiedCountShort {
        /// The event digest.
        digest: [u8; 32],
    },
    /// Step 8.
    #[error("{defect}")]
    Content {
        /// The event digest.
        digest: [u8; 32],
        /// The defect.
        defect: ContentDefect,
    },
    /// Step 9: a named index whose signature does not verify.
    #[error("the {role:?} signature at index {index} does not verify: {error}")]
    Signature {
        /// The event digest.
        digest: [u8; 32],
        /// The group.
        role: SignerGroupRole,
        /// The index.
        index: u8,
        /// Why it does not verify.
        error: IndexedSignatureError,
    },
}

impl EventDefect {
    /// The step that found the defect.
    #[must_use]
    pub const fn stage(&self) -> CheckStep {
        match self {
            Self::Unframed => CheckStep::Unit,
            Self::NoSeparator => CheckStep::Separator,
            Self::IdentifierMismatch { .. } => CheckStep::InceptionBinding,
            Self::Header(_) | Self::PredecessorMismatch { .. } => CheckStep::Header,
            Self::Walk(_) | Self::UnconsumedBytes { .. } => CheckStep::Walk,
            Self::NamedCountShort { .. } => CheckStep::NamedCount,
            Self::VerifiedCountShort { .. } => CheckStep::VerifiedCount,
            Self::Content { .. } => CheckStep::Content,
            Self::Signature { .. } => CheckStep::Signatures,
        }
    }

    /// The bytes the failing check read decide the class (§9.7.4.2 R3,
    /// "A failure proves an event illegal exactly when…").
    #[must_use]
    pub const fn class(&self) -> FailureClass {
        match self {
            // The separator opens the signed preimage; step 4 reads fields
            // 1 through 7 and the preimage's length; 7a reads fields 6
            // through 8 and the standing commitment; step 8 reads fields 8
            // through 12.
            Self::NoSeparator
            | Self::Header(_)
            | Self::NamedCountShort { .. }
            | Self::Content { .. } => FailureClass::Illegal,
            // The walk, 7b and step 9 read the signature field.
            Self::Walk(_)
            | Self::UnconsumedBytes { .. }
            | Self::VerifiedCountShort { .. }
            | Self::Signature { .. } => FailureClass::CopyDamage,
            // Step 1 reads the frame's length prefix, the binding reads the
            // served identifier, and the link reads a predecessor the
            // verifier does not hold at p − 1.
            Self::Unframed | Self::IdentifierMismatch { .. } | Self::PredecessorMismatch { .. } => {
                FailureClass::ProvesNothing
            }
        }
    }

    /// The event digest, which exists from step 6 on.
    #[must_use]
    pub const fn digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::NamedCountShort { digest }
            | Self::VerifiedCountShort { digest }
            | Self::Content { digest, .. }
            | Self::Signature { digest, .. } => Some(*digest),
            Self::Unframed
            | Self::NoSeparator
            | Self::IdentifierMismatch { .. }
            | Self::Header(_)
            | Self::PredecessorMismatch { .. }
            | Self::Walk(_)
            | Self::UnconsumedBytes { .. } => None,
        }
    }
}

/// One unit a verifier discarded (§9.7.4.2 R3, the candidate rule).
///
/// It names the unit by its index in the units the call was given, and
/// separately the chain position the unit was read for, which is `None`
/// for a unit that joined no chain: one that failed before its predecessor
/// digest decoded, or that names a predecessor no chain holds. Its stage,
/// class and digest are read off the defect, so no discard can carry a
/// digest before step 6 or a stage its defect does not name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discarded {
    served_index: usize,
    read_for: Option<u64>,
    defect: EventDefect,
}

impl Discarded {
    /// A unit read for chain position `position` that failed there.
    pub(super) const fn read(served_index: usize, position: u64, defect: EventDefect) -> Self {
        Self {
            served_index,
            read_for: Some(position),
            defect,
        }
    }

    /// A unit that joined no chain.
    pub(super) const fn unplaced(served_index: usize, defect: EventDefect) -> Self {
        Self {
            served_index,
            read_for: None,
            defect,
        }
    }

    /// The unit's index in the units the call was given: the served list
    /// for [`validate_entry`](super::validate_entry), and zero for the one
    /// unit or candidate `extend`, `validate_change` and
    /// `validate_inception` take.
    #[must_use]
    pub const fn served_index(&self) -> usize {
        self.served_index
    }

    /// The chain position the unit was read for, or `None` where it joined
    /// no chain.
    #[must_use]
    pub const fn read_for(&self) -> Option<u64> {
        self.read_for
    }

    /// The failing check.
    #[must_use]
    pub const fn defect(&self) -> &EventDefect {
        &self.defect
    }

    /// The step that found the defect.
    #[must_use]
    pub const fn stage(&self) -> CheckStep {
        self.defect.stage()
    }

    /// The illegality class of the failing check.
    #[must_use]
    pub const fn class(&self) -> FailureClass {
        self.defect.class()
    }

    /// SHA-256 of the raw signed preimage, where the unit reached step 6.
    #[must_use]
    pub const fn digest(&self) -> Option<[u8; 32]> {
        self.defect.digest()
    }
}
