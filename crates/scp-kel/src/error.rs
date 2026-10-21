//! The typed errors of the key-event codec.
//!
//! Each names the field or list it was reading, so the verifier maps a
//! decode failure to its R3 cause without re-parsing (`09-security-model.md`
//! §9.7.4.2). The decode errors split where the check order splits: a
//! [`HeaderError`] is step 4 (fields 1 through 7, the form-list lengths and
//! the encoded length), a [`BodyError`] is the decode of fields 8 through
//! 12, and each admits only the failures its own stage can produce.

use std::fmt;

use scp_did::{KeyCondition, UnknownDiscriminator};

use crate::event::{EventKind, SignerGroupRole};
use crate::signature::IndexedSignatureReadError;

/// One of the preimage's header fields, 1 through 7 (§9.7.4.2), named where
/// the header runs out of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderField {
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
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EventType => "event_type",
            Self::Identifier => "identifier",
            Self::Sequence => "sequence",
            Self::PredecessorDigest => "predecessor_digest",
            Self::StandingRoot => "standing_root",
            Self::SignerIndices => "signer index list",
            Self::SignatureForms => "signature-form list",
        })
    }
}

/// One of the preimage's body fields, 8 through 12 (§9.7.4.2), named where
/// the body runs out of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyField {
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

impl fmt::Display for BodyField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RevealedKeys => "revealed keys",
            Self::InstalledRootSet => "installed root set",
            Self::KeyState => "key-state snapshot",
            Self::Seals => "key-event seals",
            Self::Continuation => "continuation",
        })
    }
}

impl fmt::Display for SignerGroupRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Root => "root group",
            Self::Reveal => "reveal group",
            Self::ReplacementRoot => "K′ group",
            Self::StandingRoot => "standing-root group",
        })
    }
}

/// One signer group's count-prefixed list in the header (§9.7.4.2 fields 6
/// and 7). Each carries the group's role, so an error names which group's
/// list failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerList {
    /// The group's signer index list (field 6).
    Indices(SignerGroupRole),
    /// The group's signature-form list (field 7).
    Forms(SignerGroupRole),
}

impl fmt::Display for SignerList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Indices(role) => write!(f, "{role}'s signer index list"),
            Self::Forms(role) => write!(f, "{role}'s signature-form list"),
        }
    }
}

/// A count-prefixed list of the body (§9.7.4.2 fields 8 through 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyList {
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

impl fmt::Display for BodyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RevealedKeys => "revealed keys",
            Self::InstalledRootSet => "installed root set",
            Self::SnapshotKeys => "snapshot key list",
            Self::Witnesses => "witness set",
            Self::Seals => "key-event seals",
            Self::Commitments => "commitment list",
        })
    }
}

/// Any count-prefixed list of the preimage (§9.7.4.2, the count-bound
/// rule): what the encoder, which writes every field, names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListField {
    /// A list of fields 6 and 7.
    Signer(SignerList),
    /// A list of fields 8 through 12.
    Body(BodyList),
}

impl From<SignerList> for ListField {
    fn from(list: SignerList) -> Self {
        Self::Signer(list)
    }
}

impl From<BodyList> for ListField {
    fn from(list: BodyList) -> Self {
        Self::Body(list)
    }
}

impl fmt::Display for ListField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signer(list) => list.fmt(f),
            Self::Body(list) => list.fmt(f),
        }
    }
}

/// A preimage byte that is one of `scp_did`'s name-bound enumerations
/// (`KeyRole`, `KeyCondition`, `CustodyType`, `KeyAlgorithm`), in the
/// key-state snapshot or the continuation (§9.7.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DidDiscriminatorField {
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

impl fmt::Display for DidDiscriminatorField {
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

/// A header byte that is one of this crate's own discriminators
/// ([`EventKind`], `StandingRootDeclaration`, `SignatureForm`; §9.7.4.2
/// fields 1, 5 and 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderDiscriminator {
    /// Field 1, `event_type`.
    EventType,
    /// Field 5, `standing_root`.
    StandingRoot,
    /// One entry of a field 7 signature-form list.
    SignatureForm,
}

impl fmt::Display for HeaderDiscriminator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EventType => "event_type",
            Self::StandingRoot => "standing_root",
            Self::SignatureForm => "signature form",
        })
    }
}

/// A signer group whose form list differs in length from its index list.
///
/// §9.7.4.2's check order fails it at step 4. The encoded length sums one
/// form's ceiling per named index, so it is undefined for such a group, and
/// the signature-field walk has no form for some index or no index for
/// some form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the {role} names {indices} indices but {forms} forms")]
pub struct FormListLength {
    /// The group.
    pub role: SignerGroupRole,
    /// The index list's length.
    pub indices: usize,
    /// The form list's length.
    pub forms: usize,
}

/// Why a preimage cannot be encoded.
///
/// The encoder refuses exactly the preimages whose bytes the decoder would
/// reject or decode to a different value, reading the decoder's own count
/// bounds, form-list check and length ceiling, so `encode_preimage`
/// succeeding means `decode_preimage` of its bytes returns the same
/// preimage. It does not apply the rest of R3's defect list: a writer may
/// encode a defective preimage, and the verifier classifies it.
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
    /// A list is longer than the `MAX_*` constant §9.18.17 registers for it,
    /// which the decoder rejects (§9.7.4.2, the count-bound rule).
    #[error("the {list} has {len} entries, over its maximum {max}")]
    CountOverMax {
        /// The list.
        list: ListField,
        /// Its length.
        len: usize,
        /// The registered maximum.
        max: u32,
    },
    /// A signer group's form list differs in length from its index list,
    /// which the decoder rejects at step 4.
    #[error(transparent)]
    FormListLength(FormListLength),
    /// The event's encoded length exceeds `MAX_EVENT_BYTES` (§9.18.17;
    /// §9.7.4.2 step 4): the signed preimage, separator included, plus the
    /// reserved ceiling of each named index's form, 64 bytes for `Raw` and
    /// 840 for `WebAuthnAssertion`.
    #[error("the event's encoded length is {encoded_len} bytes, over MAX_EVENT_BYTES")]
    EventTooLong {
        /// The encoded length, exactly.
        encoded_len: u64,
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

/// Why an event's header fails the check order's step 4 (§9.7.4.2).
///
/// Fields 1 through 7 do not decode, a form list differs in length from
/// its index list, or the encoded length exceeds `MAX_EVENT_BYTES`, checked
/// in that order. Every variant reads only the signed preimage, which the
/// event's digest binds, so every one is an illegality failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// The bytes end inside a header field.
    #[error("the preimage ends inside its {field}")]
    Truncated {
        /// The field being read.
        field: HeaderField,
    },
    /// A signer list's count exceeds the `MAX_*` constant §9.18.17 registers
    /// for it.
    #[error("the {list} declares {count} entries, over its maximum {max}")]
    CountOverMax {
        /// The list.
        list: SignerList,
        /// The declared count.
        count: u32,
        /// The registered maximum.
        max: u32,
    },
    /// A signer list's count implies more bytes than remain in the preimage.
    #[error("the {list} declares {count} entries, more than the {remaining} remaining bytes hold")]
    CountOverRemaining {
        /// The list.
        list: SignerList,
        /// The declared count.
        count: u32,
        /// The bytes left after the count.
        remaining: usize,
    },
    /// A header byte is no registered value of its discriminator.
    #[error("unregistered {field} byte 0x{value:02x}")]
    UnknownDiscriminator {
        /// The field being read.
        field: HeaderDiscriminator,
        /// The byte.
        value: u8,
    },
    /// A `RootRecovery` carries the absent standing-root byte, so its signer
    /// group count is undefined and fields 6 and 7 cannot be parsed
    /// (§9.7.4.2 fields 5 and 6).
    #[error("a RootRecovery carries no standing_root declaration")]
    RootRecoveryWithoutStandingRoot,
    /// A signer group's form list differs in length from its index list.
    #[error(transparent)]
    FormListLength(FormListLength),
    /// The event's encoded length exceeds `MAX_EVENT_BYTES` (§9.18.17): the
    /// signed preimage, separator included, plus the reserved ceiling of each
    /// named index's form, 64 bytes for `Raw` and 840 for
    /// `WebAuthnAssertion`.
    #[error("the event's encoded length is {encoded_len} bytes, over MAX_EVENT_BYTES")]
    EventTooLong {
        /// The encoded length, exactly: it is computed only once fields 1
        /// through 7 decode and every form list has passed.
        encoded_len: u64,
    },
}

/// Why fields 8 through 12 of an event whose header passed do not decode
/// (§9.7.4.2, the decode of step 8, and at chain position zero the content
/// step 3 reads).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyError {
    /// The bytes end inside a body field.
    #[error("the preimage ends inside its {field}")]
    Truncated {
        /// The field being read.
        field: BodyField,
    },
    /// A body list's count exceeds the `MAX_*` constant §9.18.17 registers
    /// for it.
    #[error("the {list} declares {count} entries, over its maximum {max}")]
    CountOverMax {
        /// The list.
        list: BodyList,
        /// The declared count.
        count: u32,
        /// The registered maximum.
        max: u32,
    },
    /// A body list's count implies more bytes than remain in the preimage.
    #[error("the {list} declares {count} entries, more than the {remaining} remaining bytes hold")]
    CountOverRemaining {
        /// The list.
        list: BodyList,
        /// The declared count.
        count: u32,
        /// The bytes left after the count.
        remaining: usize,
    },
    /// A byte is no registered value of its `scp_did` enumeration.
    #[error("unregistered {field} byte: {source}")]
    UnknownDidDiscriminator {
        /// The field being read.
        field: DidDiscriminatorField,
        /// The enumeration and the byte.
        source: UnknownDiscriminator,
    },
    /// Field 12's leading byte is neither the abandonment byte nor the
    /// commitment-list byte, and the field is not the absent sentinel.
    #[error("unregistered continuation byte 0x{value:02x}")]
    UnknownContinuation {
        /// The byte.
        value: u8,
    },
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

/// Why bytes are not a key-event preimage (§9.7.4.2): the header fails, or
/// the header passes and the body fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input begins with the `"SCP-KEL-EVENT-V1:"` separator: it is the
    /// signed preimage, and the decoder reads the twelve field bytes that
    /// follow the separator.
    #[error(
        "the input begins with the SCP-KEL-EVENT-V1: separator; decode the field bytes after it"
    )]
    SignedPreimage,
    /// The header fails step 4.
    #[error(transparent)]
    Header(#[from] HeaderError),
    /// Fields 8 through 12 do not decode.
    #[error(transparent)]
    Body(#[from] BodyError),
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

/// Why an event unit's signature field does not walk under fields 6 and 7
/// (§9.7.4.2, the check order's step 5; §9.10.12). The check reads the
/// signature field, which the event's digest does not bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the {role}'s indexed signature at position {position}, by index {index}, does not read: {error}"
)]
pub struct SignatureFieldError {
    /// The group being walked.
    pub role: SignerGroupRole,
    /// The signature's position in that group's index list.
    pub position: usize,
    /// The index the signature is by: the index list's entry at `position`.
    pub index: u8,
    /// Why it does not read.
    pub error: IndexedSignatureReadError,
}

/// Which header field of a raw inception preimage is not the value R3 fixes
/// for an inception.
///
/// §9.7.4.2 R3: "an `Inception` whose identifier, sequence or predecessor
/// digest is not zero", and "an event other than an `Inception` at position
/// zero".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InceptionHeaderDefect {
    /// The bytes end before field 4 does.
    #[error("the preimage ends inside its {field}")]
    Truncated {
        /// The field being read.
        field: HeaderField,
    },
    /// Field 1 is not the `Inception` byte.
    #[error("event_type is 0x{value:02x}, not Inception")]
    NotInception {
        /// The byte field 1 carries.
        value: u8,
    },
    /// Field 2 is not zero.
    #[error("an inception's identifier field is not zero")]
    NonzeroIdentifier,
    /// Field 3 is not zero.
    #[error("an inception's sequence is not zero")]
    NonzeroSequence,
    /// Field 4 is not zero.
    #[error("an inception's predecessor digest is not zero")]
    NonzeroPredecessor,
}
