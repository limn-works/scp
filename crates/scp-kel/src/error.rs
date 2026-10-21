//! The typed errors of the key-event codec.
//!
//! Each names the field or list it was reading, so the verifier maps a
//! decode failure to its R3 cause without re-parsing (`09-security-model.md`
//! §9.7.4.2).

use std::fmt;

use scp_did::{KeyCondition, UnknownDiscriminator};

use crate::event::{EventKind, SignerGroupRole};
use crate::signature::IndexedSignatureReadError;

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

/// A count-prefixed list of the preimage (§9.7.4.2, the count-bound rule).
/// A signer group's two lists carry the group's role, so an error names
/// which group's list failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListField {
    /// One group's signer index list (field 6).
    SignerIndices(SignerGroupRole),
    /// One group's signature-form list (field 7).
    SignatureForms(SignerGroupRole),
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
        match self {
            Self::SignerIndices(role) => write!(f, "{role}'s signer index list"),
            Self::SignatureForms(role) => write!(f, "{role}'s signature-form list"),
            Self::RevealedKeys => f.write_str("revealed keys"),
            Self::InstalledRootSet => f.write_str("installed root set"),
            Self::SnapshotKeys => f.write_str("snapshot key list"),
            Self::Witnesses => f.write_str("witness set"),
            Self::Seals => f.write_str("key-event seals"),
            Self::Commitments => f.write_str("commitment list"),
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

/// A preimage byte that is one of this crate's own discriminators
/// ([`EventKind`], `StandingRootDeclaration`, `SignatureForm`, the
/// continuation byte; §9.7.4.2 fields 1, 5, 7 and 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KelDiscriminatorField {
    /// Field 1, `event_type`.
    EventType,
    /// Field 5, `standing_root`.
    StandingRoot,
    /// One entry of a field 7 signature-form list.
    SignatureForm,
    /// Field 12's leading byte.
    Continuation,
}

impl fmt::Display for KelDiscriminatorField {
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
/// The encoder refuses exactly the preimages whose bytes the decoder would
/// reject or decode to a different value, reading the decoder's own count
/// bounds and length ceiling, so `encode_preimage` succeeding means
/// `decode_preimage` of its bytes returns the same preimage. It does not
/// apply R3's defect list: a writer may encode a preimage a verifier rejects,
/// and the verifier classifies it.
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
    /// The event's encoded length exceeds `MAX_EVENT_BYTES` (§9.18.17;
    /// §9.7.4.2 R3): the signed preimage, separator included, plus the
    /// reserved ceiling of each named index's form, 64 bytes for `Raw` and
    /// 840 for `WebAuthnAssertion`. An index its form list gives no form is
    /// counted at 840, the larger ceiling.
    #[error("the event's encoded length is {encoded_len} bytes, over MAX_EVENT_BYTES")]
    EventTooLong {
        /// The encoded length.
        encoded_len: usize,
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
    /// The event's encoded length exceeds `MAX_EVENT_BYTES` (§9.18.17;
    /// §9.7.4.2 R3): the signed preimage, separator included, plus the
    /// reserved ceiling of each named index's form, 64 bytes for `Raw` and
    /// 840 for `WebAuthnAssertion`, an index with no form counted at 840.
    /// Where the signed preimage alone exceeds the constant, the decoder
    /// reads no field and `encoded_len` is the signed preimage's length, a
    /// lower bound on the encoded length.
    #[error("the event's encoded length is at least {encoded_len} bytes, over MAX_EVENT_BYTES")]
    EventTooLong {
        /// The encoded length, or the signed preimage's length where the
        /// fields were not read.
        encoded_len: usize,
    },
    /// The input begins with the `"SCP-KEL-EVENT-V1:"` separator: it is the
    /// signed preimage, and the decoder reads the twelve field bytes that
    /// follow the separator.
    #[error(
        "the input begins with the SCP-KEL-EVENT-V1: separator; decode the field bytes after it"
    )]
    SignedPreimage,
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
    /// A byte is no registered value of its `scp_did` enumeration.
    #[error("unregistered {field} byte: {source}")]
    UnknownDidDiscriminator {
        /// The field being read.
        field: DidDiscriminatorField,
        /// The enumeration and the byte.
        source: UnknownDiscriminator,
    },
    /// A byte is no registered value of this crate's own discriminators.
    #[error("unregistered {field} byte 0x{value:02x}")]
    UnknownKelDiscriminator {
        /// The field being read.
        field: KelDiscriminatorField,
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

/// Why an event unit's signed preimage yields no header (§9.7.4.2, the
/// check order's steps 2 and 4). Each variant names the check that failed,
/// and every one reads only bytes the event's digest binds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// The prefixed bytes do not begin with `"SCP-KEL-EVENT-V1:"` (step 2:
    /// "A decoder MUST reject an event whose prefixed bytes do not begin
    /// with `SCP-KEL-EVENT-V1:`").
    #[error("the prefixed bytes do not begin with the SCP-KEL-EVENT-V1: separator")]
    Separator,
    /// Fields 1 through 7 do not decode (step 4).
    #[error("fields 1 through 7 do not decode: {0}")]
    Fields(DecodeError),
    /// A signer group's form list differs in length from its index list
    /// (R3: "a form list whose length differs from its index list"), so the
    /// signature-field walk has no form for some index or no index for some
    /// form.
    #[error("the {role} group names {indices} indices but {forms} forms")]
    FormListLength {
        /// The group.
        role: SignerGroupRole,
        /// The index list's length.
        indices: usize,
        /// The form list's length.
        forms: usize,
    },
}

/// Why an event unit's signature field does not walk under fields 6 and 7
/// (§9.7.4.2, the check order's step 5; §9.10.12). The check reads the
/// signature field, which the event's digest does not bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the {role} group's indexed signature at position {position} does not read: {error}")]
pub struct SignatureFieldError {
    /// The group being walked.
    pub role: SignerGroupRole,
    /// The signature's position in that group's index list.
    pub position: usize,
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
    /// The bytes do not begin with `"SCP-KEL-EVENT-V1:"`.
    #[error("the bytes do not begin with the SCP-KEL-EVENT-V1: separator")]
    Separator,
    /// The bytes end before field 4 does.
    #[error("the bytes end before the predecessor digest does")]
    Truncated,
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
