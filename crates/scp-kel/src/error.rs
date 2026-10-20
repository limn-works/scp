//! The typed errors of the key-event codec.
//!
//! Each names the field or list it was reading, so the verifier maps a
//! decode failure to its R3 cause without re-parsing (`09-security-model.md`
//! §9.7.4.2).

use std::fmt;

use scp_did::{KeyCondition, UnknownDiscriminator};

use crate::event::EventKind;

/// One of the preimage's twelve fields (§9.7.4.2), named where a decode
/// runs out of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreimageField {
    /// Field 1, `event_type`.
    EventType,
    /// Field 2, `identifier`.
    Identifier,
    /// Field 3, `sequence`.
    Sequence,
    /// Field 4, `predecessor_digest`.
    PredecessorDigest,
    /// Field 5, `standing_root`.
    StandingRoot,
    /// Field 6, the signer index lists.
    SignerIndices,
    /// Field 7, the signature-form lists.
    SignatureForms,
    /// Field 8, the revealed keys.
    RevealedKeys,
    /// Field 9, the installed root set and its threshold.
    InstalledRootSet,
    /// Field 10, the key-state snapshot.
    KeyState,
    /// Field 11, the key-event seals.
    Seals,
    /// Field 12, the continuation.
    Continuation,
}

impl fmt::Display for PreimageField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EventType => "event_type",
            Self::Identifier => "identifier",
            Self::Sequence => "sequence",
            Self::PredecessorDigest => "predecessor_digest",
            Self::StandingRoot => "standing_root",
            Self::SignerIndices => "signer index list",
            Self::SignatureForms => "signature-form list",
            Self::RevealedKeys => "revealed keys",
            Self::InstalledRootSet => "installed root set",
            Self::KeyState => "key-state snapshot",
            Self::Seals => "key-event seals",
            Self::Continuation => "continuation",
        })
    }
}

/// A count-prefixed list of the preimage (§9.7.4.2, the count-bound rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListField {
    /// One group's signer index list (field 6).
    SignerIndices,
    /// One group's signature-form list (field 7).
    SignatureForms,
    /// The revealed keys (field 8).
    RevealedKeys,
    /// The installed root set's members (field 9).
    InstalledRootSet,
    /// The key-state snapshot's key list (field 10).
    SnapshotKeys,
    /// The key-state snapshot's witness set (field 10).
    Witnesses,
    /// The key-event seals (field 11).
    Seals,
    /// The continuation's commitment list (field 12).
    Commitments,
}

impl fmt::Display for ListField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SignerIndices => "signer index list",
            Self::SignatureForms => "signature-form list",
            Self::RevealedKeys => "revealed keys",
            Self::InstalledRootSet => "installed root set",
            Self::SnapshotKeys => "snapshot key list",
            Self::Witnesses => "witness set",
            Self::Seals => "key-event seals",
            Self::Commitments => "commitment list",
        })
    }
}

/// A key-state field whose byte is an `scp_did` name-bound enumeration
/// (§9.7.4.2, the key-state snapshot's order and the continuation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscriminatorField {
    /// A key entry's `role`, a `KeyRole`.
    Role,
    /// A key entry's `condition`, a `KeyCondition`.
    Condition,
    /// A key entry's or commitment entry's `custody_type`, a `CustodyType`.
    CustodyType,
    /// A key entry's or commitment entry's `key_algorithm`, a `KeyAlgorithm`.
    KeyAlgorithm,
    /// The snapshot's `service_key_role`, a `KeyRole`.
    ServiceKeyRole,
}

impl fmt::Display for DiscriminatorField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Role => "role",
            Self::Condition => "condition",
            Self::CustodyType => "custody_type",
            Self::KeyAlgorithm => "key_algorithm",
            Self::ServiceKeyRole => "service_key_role",
        })
    }
}

/// A preimage field whose byte is one of this crate's discriminators
/// (§9.7.4.2 fields 1, 5, 7 and 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventDiscriminatorField {
    /// Field 1, `event_type`.
    EventType,
    /// Field 5, `standing_root`.
    StandingRoot,
    /// One entry of a field 7 signature-form list.
    SignatureForm,
    /// Field 12's leading byte.
    Continuation,
}

impl fmt::Display for EventDiscriminatorField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EventType => "event_type",
            Self::StandingRoot => "standing_root",
            Self::SignatureForm => "signature form",
            Self::Continuation => "continuation",
        })
    }
}

/// Why a preimage cannot be encoded.
///
/// The encoder writes every preimage whose bytes decode back to it. It does
/// not apply the parse bounds or R3's defect list: a writer may encode a
/// preimage a verifier rejects, and the verifier classifies it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// A list is too long for its 4-byte count.
    #[error("the {list} has {len} entries, more than a 4-byte count carries")]
    CountOverflow {
        /// The list.
        list: ListField,
        /// Its length.
        len: usize,
    },
    /// A `RootRecovery` carries no standing-root declaration, so its signer
    /// group count is undefined (§9.7.4.2 field 5).
    #[error("a RootRecovery carries no standing_root declaration")]
    RootRecoveryWithoutStandingRoot,
    /// The preimage carries a different number of signer groups than its
    /// kind names (§9.7.4.2, "Which fields each kind carries in substance").
    #[error("a {kind:?} preimage names {expected} signer groups, not {actual}")]
    SignerGroupCount {
        /// The preimage's kind.
        kind: EventKind,
        /// The count the kind names.
        expected: usize,
        /// The count the preimage carries.
        actual: usize,
    },
    /// An installed root set with no members would encode as field 9's
    /// four-byte absent sentinel (§9.7.4.2, "The absent-field sentinel").
    #[error("an installed root set with no members encodes as field 9's absent sentinel")]
    EmptyInstalledRootSet,
    /// A snapshot whose root threshold is zero would begin with field 10's
    /// absent sentinel `BE32(0)` (§9.7.4.2, "The absent-field sentinel").
    #[error("a key-state snapshot with root_threshold 0 encodes as field 10's absent sentinel")]
    ZeroRootThreshold,
    /// A key entry carries a nonzero `compromised_from` without the
    /// `Compromised` condition; the field is "zero otherwise" (§9.7.4.2, the
    /// key-state snapshot's order).
    #[error(
        "key entry {entry} is {condition} with compromised_from {compromised_from}, which is zero for every condition but Compromised"
    )]
    CompromisedFromWithoutCompromise {
        /// The entry's index in the snapshot key list.
        entry: usize,
        /// The entry's condition.
        condition: KeyCondition,
        /// The nonzero position it carries.
        compromised_from: u64,
    },
}

/// Why bytes are not a key-event preimage (§9.7.4.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input is longer than `MAX_EVENT_BYTES` (§9.18.17).
    #[error("the preimage is {len} bytes, over MAX_EVENT_BYTES")]
    EventTooLong {
        /// The input's length.
        len: usize,
    },
    /// The input ends inside a field.
    #[error("the preimage ends inside its {field}")]
    Truncated {
        /// The field being read.
        field: PreimageField,
    },
    /// A list's count exceeds the `MAX_*` constant §9.18.17 registers for it.
    #[error("the {list} declares {count} entries, over its maximum {max}")]
    CountOverMax {
        /// The list.
        list: ListField,
        /// The declared count.
        count: u32,
        /// The registered maximum.
        max: u32,
    },
    /// A list's count implies more bytes than remain in the preimage.
    #[error("the {list} declares {count} entries, more than the {remaining} remaining bytes hold")]
    CountOverRemaining {
        /// The list.
        list: ListField,
        /// The declared count.
        count: u32,
        /// The bytes left after the count.
        remaining: usize,
    },
    /// A key-state byte is no registered value of its `scp_did` enumeration.
    #[error("unregistered {field} byte: {source}")]
    UnknownDiscriminator {
        /// The field being read.
        field: DiscriminatorField,
        /// The enumeration and the byte.
        source: UnknownDiscriminator,
    },
    /// A preimage byte is no registered value of this crate's
    /// discriminators.
    #[error("unregistered {field} byte 0x{value:02x}")]
    UnknownEventDiscriminator {
        /// The field being read.
        field: EventDiscriminatorField,
        /// The byte.
        value: u8,
    },
    /// A `RootRecovery` carries the absent standing-root byte, so its signer
    /// group count is undefined and the rest of the preimage cannot be
    /// parsed (§9.7.4.2 fields 5 and 6).
    #[error("a RootRecovery carries no standing_root declaration")]
    RootRecoveryWithoutStandingRoot,
    /// A key entry carries a nonzero `compromised_from` without the
    /// `Compromised` condition (§9.7.4.2, the key-state snapshot's order:
    /// "the position a `Compromised` entry carries and zero otherwise").
    #[error(
        "key entry {entry} is {condition} with compromised_from {compromised_from}, which is zero for every condition but Compromised"
    )]
    CompromisedFromWithoutCompromise {
        /// The entry's index in the snapshot key list.
        entry: usize,
        /// The entry's condition.
        condition: KeyCondition,
        /// The nonzero position it carries.
        compromised_from: u64,
    },
    /// Bytes remain after field 12.
    #[error("{count} bytes follow the continuation")]
    TrailingBytes {
        /// How many.
        count: usize,
    },
}

/// Why an identifier cannot be derived from a preimage (§9.7.4.2 R13).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeriveIdentifierError {
    /// Only an inception event derives an identifier.
    #[error("a {kind:?} event derives no identifier; only an Inception does")]
    NotInception {
        /// The preimage's kind.
        kind: EventKind,
    },
    /// The inception's identifier field is not all-zero (§9.7.4.2 field 2).
    #[error("an inception's identifier field must be all-zero")]
    NonzeroIdentifier,
    /// The inception's sequence is not zero.
    #[error("an inception's sequence must be 0, not {sequence}")]
    NonzeroSequence {
        /// The sequence it carries.
        sequence: u64,
    },
    /// The inception's predecessor digest is not all-zero (§9.7.4.2 field 4).
    #[error("an inception's predecessor_digest must be all-zero")]
    NonzeroPredecessor,
    /// The preimage cannot be encoded.
    #[error(transparent)]
    Encode(#[from] EncodeError),
}
