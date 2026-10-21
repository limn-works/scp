//! One event unit of a §9.10.12 key-event record frame, decoded stage by
//! stage (`09-security-model.md` §9.7.4.2, the check order).
//!
//! A frame's `events` field carries each event as a 4-byte big-endian
//! length, the signed preimage that length covers (separator included),
//! and the signature field. No length covers the signature field: its
//! extent is the walk of fields 6 and 7, one indexed signature per named
//! index in the form its form list declares (§9.10.12; §9.7.4.2, "The
//! signature layout is closed").
//!
//! [`decode_event`] runs each byte-level stage the check order names and
//! returns an [`EventUnit`] whose variant is the stage that stopped it:
//! step 1 (the prefix lies within `value`), step 2 (the separator), step 4
//! (fields 1 through 7, the form-list lengths and the encoded length), and
//! past step 4 both step 5 (the signature-field walk) and the decode of
//! fields 8 through 12, which step 8 and the inception's step 3 read. The
//! verifier classifies a failure by the bytes the failing check reads, which
//! is §9.7.4.2's illegality test: the separator, the header and the body
//! read only bytes the event's digest binds, the walk reads the signature
//! field, and step 1 reads the frame's length prefix. No stage verifies a
//! signature or reads another event.

use scp_did::Identifier;

use crate::error::{
    BodyError, FormListLength, HeaderError, InceptionHeaderDefect, SignatureFieldError,
};
use crate::event::{
    EventKind, EventPreimage, SignatureForm, SignerGroupRole, StandingRootDeclaration,
};
use crate::preimage::{
    encoded_event_len, event_digest_of, field_bytes, identifier_of, read_event,
    read_inception_zero_checks, signed_len_of, signed_preimage_of, within_event_bytes,
};
use crate::signature::IndexedSignature;

/// The event unit's preimage length prefix: a big-endian `u32` (§9.10.12).
const LENGTH_PREFIX_BYTES: usize = 4;

/// The bytes an event unit's length prefix covers, which begin with
/// `"SCP-KEL-EVENT-V1:"`: steps 1 and 2 of §9.7.4.2's check order passed.
///
/// Only [`decode_event`] builds one, and its one constructor strips the
/// separator, so it holds the field bytes as received and implies the
/// separator they followed. The digest and the identifier are computed over
/// these bytes and never over a re-encode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawSignedPreimage {
    fields: Vec<u8>,
}

impl RawSignedPreimage {
    /// Step 2: `None` where `bytes` do not begin with the separator.
    fn new(bytes: &[u8]) -> Option<Self> {
        field_bytes(bytes).map(|fields| Self {
            fields: fields.to_vec(),
        })
    }

    /// The signed preimage, separator included, as received.
    #[must_use]
    pub fn signed_preimage(&self) -> Vec<u8> {
        signed_preimage_of(&self.fields)
    }

    /// The signed preimage's length, separator included.
    #[must_use]
    pub fn signed_len(&self) -> usize {
        signed_len_of(&self.fields)
    }

    /// The field bytes after the separator.
    #[must_use]
    pub fn fields(&self) -> &[u8] {
        &self.fields
    }

    /// Step 6: the event digest, `SHA-256` of the signed preimage (ADR-063;
    /// §9.7.4.2).
    #[must_use]
    pub fn event_digest(&self) -> [u8; 32] {
        event_digest_of(&self.fields)
    }

    /// Step 3's first half: the identifier these bytes recompute to,
    /// `SHA-256("SCP-KEL-ID-V1:" ‖ signed preimage)` (§9.7.4.2 R2;
    /// `03-identity.md` §3.1).
    ///
    /// It reads no field, so it exists for every unit past step 2, whatever
    /// its kind and whether or not its header or body decodes.
    #[must_use]
    pub fn identifier(&self) -> Identifier {
        identifier_of(&self.fields)
    }

    /// The inception header checks R3 fixes: field 1 is the `Inception`
    /// byte and fields 2, 3 and 4 are zero (§9.7.4.2 R3: "an `Inception`
    /// whose identifier, sequence or predecessor digest is not zero", and
    /// "an event other than an `Inception` at position zero").
    ///
    /// It reads fields 1 through 4 with the header's own reader, so it needs
    /// no other field to decode.
    ///
    /// # Errors
    ///
    /// [`InceptionHeaderDefect`] naming the first field, in field order,
    /// that does not hold its value, or the field the bytes end inside.
    pub fn inception_zero_checks(&self) -> Result<(), InceptionHeaderDefect> {
        read_inception_zero_checks(self.fields())
    }
}

/// One named signer of a signer group: an index of field 6 and the form
/// field 7 declares for it, at the same position (§9.7.4.2 fields 6 and 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamedSigner {
    index: u8,
    form: SignatureForm,
}

impl NamedSigner {
    /// The member index into the group's key set.
    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// The form of the indexed signature by that index.
    #[must_use]
    pub const fn form(&self) -> SignatureForm {
        self.form
    }
}

/// One signer group of an event's header: its role, which the kind and
/// `standing_root` fix, and its named signers in index-list order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderGroup {
    role: SignerGroupRole,
    signers: Vec<NamedSigner>,
}

impl HeaderGroup {
    /// Pairs a group's index list with its form list: the one check that a
    /// form list is as long as its index list (§9.7.4.2 step 4), and the
    /// one way to build a group.
    pub(crate) fn pair(
        role: SignerGroupRole,
        indices: &[u8],
        forms: &[SignatureForm],
    ) -> Result<Self, FormListLength> {
        if indices.len() != forms.len() {
            return Err(FormListLength {
                role,
                indices: indices.len(),
                forms: forms.len(),
            });
        }
        let signers = indices
            .iter()
            .zip(forms)
            .map(|(index, form)| NamedSigner {
                index: *index,
                form: *form,
            })
            .collect();
        Ok(Self { role, signers })
    }

    /// The group's role.
    #[must_use]
    pub const fn role(&self) -> SignerGroupRole {
        self.role
    }

    /// The group's named signers, in index-list order.
    #[must_use]
    pub fn signers(&self) -> &[NamedSigner] {
        &self.signers
    }
}

/// Fields 1 through 5 of an event, as the header reads them.
#[derive(Clone, Copy)]
pub struct HeaderPrefix {
    pub(crate) kind: EventKind,
    pub(crate) identifier: Identifier,
    pub(crate) sequence: u64,
    pub(crate) predecessor_digest: [u8; 32],
    pub(crate) standing_root: Option<StandingRootDeclaration>,
}

/// An event's header: fields 1 through 7 once the check order's step 4 has
/// passed on them (§9.7.4.2).
///
/// Its one constructor runs step 4's checks after the fields decode, so
/// every header holds signer groups that number what its kind and
/// `standing_root` name, in that order, each with one form per index, and an
/// encoded length within `MAX_EVENT_BYTES`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventHeader {
    kind: EventKind,
    identifier: Identifier,
    sequence: u64,
    predecessor_digest: [u8; 32],
    standing_root: Option<StandingRootDeclaration>,
    groups: Vec<HeaderGroup>,
    encoded_len: u64,
}

impl EventHeader {
    /// Step 4's checks past the decode of fields 1 through 7: `groups` are
    /// already paired, so the encoded length is defined, and it must be
    /// within `MAX_EVENT_BYTES` (§9.18.17).
    pub(crate) fn new(
        prefix: HeaderPrefix,
        groups: Vec<HeaderGroup>,
        signed_len: usize,
    ) -> Result<Self, HeaderError> {
        let encoded_len = encoded_event_len(signed_len, &groups);
        if !within_event_bytes(encoded_len) {
            return Err(HeaderError::EventTooLong { encoded_len });
        }
        Ok(Self {
            kind: prefix.kind,
            identifier: prefix.identifier,
            sequence: prefix.sequence,
            predecessor_digest: prefix.predecessor_digest,
            standing_root: prefix.standing_root,
            groups,
            encoded_len,
        })
    }

    /// Field 1, the event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// Field 2, the identifier field as carried: zero on an inception that
    /// meets R3, and the chain's identifier on every later event. It is
    /// never the identifier an inception recomputes to; that is
    /// [`RawSignedPreimage::identifier`].
    #[must_use]
    pub const fn identifier_field(&self) -> Identifier {
        self.identifier
    }

    /// Field 3, the sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Field 4, the predecessor digest.
    #[must_use]
    pub const fn predecessor_digest(&self) -> &[u8; 32] {
        &self.predecessor_digest
    }

    /// Field 5, the standing-root declaration.
    #[must_use]
    pub const fn standing_root(&self) -> Option<StandingRootDeclaration> {
        self.standing_root
    }

    /// Fields 6 and 7: one group per role the kind and `standing_root` name,
    /// in that order.
    #[must_use]
    pub fn groups(&self) -> &[HeaderGroup] {
        &self.groups
    }

    /// The event's encoded length (§9.18.17), within `MAX_EVENT_BYTES`.
    #[must_use]
    pub const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }
}

/// One indexed signature the walk read, with the index it is by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSignature {
    index: u8,
    signature: IndexedSignature,
}

impl NamedSignature {
    /// The index the signature is by.
    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// The indexed signature as the signature field carries it.
    #[must_use]
    pub const fn signature(&self) -> &IndexedSignature {
        &self.signature
    }
}

/// One signer group's walked signatures, read through its header group.
///
/// The signatures are in the group's index-list order (§9.7.4.2 fields 6
/// and 7). The role and the signers are the header group's, so a walked
/// group cannot name a role its header group does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerGroupSignatures<'a> {
    group: &'a HeaderGroup,
    signatures: &'a [NamedSignature],
}

impl<'a> SignerGroupSignatures<'a> {
    /// The role of the header group the walk ran over.
    #[must_use]
    pub const fn role(&self) -> SignerGroupRole {
        self.group.role
    }

    /// The header group the walk ran over.
    #[must_use]
    pub const fn group(&self) -> &'a HeaderGroup {
        self.group
    }

    /// The group's indexed signatures, each with its index, one per named
    /// signer of [`group`](Self::group).
    #[must_use]
    pub const fn signatures(&self) -> &'a [NamedSignature] {
        self.signatures
    }
}

/// A signature field that walked under fields 6 and 7 (§9.7.4.2 step 5).
/// [`ReadUnit::walked_groups`] reads its signatures with the header groups
/// they were walked under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureField {
    /// One list per header group, in the header's group order.
    signatures: Vec<Vec<NamedSignature>>,
    consumed: usize,
}

impl SignatureField {
    /// The bytes the unit took from `value` at its offset: the 4-byte
    /// prefix, the signed preimage and the walked signature field. The next
    /// unit starts there.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }
}

/// A unit whose header failed step 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderFailedUnit {
    raw: RawSignedPreimage,
    error: HeaderError,
}

impl HeaderFailedUnit {
    /// The signed preimage, which steps 1 and 2 passed.
    #[must_use]
    pub const fn raw(&self) -> &RawSignedPreimage {
        &self.raw
    }

    /// Why step 4 failed.
    #[must_use]
    pub const fn error(&self) -> &HeaderError {
        &self.error
    }
}

/// A unit whose header passed step 4: the walk and the decode of fields 8
/// through 12 each ran, and each outcome is kept apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadUnit {
    raw: RawSignedPreimage,
    header: EventHeader,
    signature_field: Result<SignatureField, SignatureFieldError>,
    preimage: Result<EventPreimage, BodyError>,
}

impl ReadUnit {
    /// The signed preimage, which steps 1 and 2 passed.
    #[must_use]
    pub const fn raw(&self) -> &RawSignedPreimage {
        &self.raw
    }

    /// Step 4: fields 1 through 7.
    #[must_use]
    pub const fn header(&self) -> &EventHeader {
        &self.header
    }

    /// Step 5: the signature field walked under fields 6 and 7. Only a
    /// walked field says where the next unit starts.
    ///
    /// # Errors
    ///
    /// The [`SignatureFieldError`] of the first indexed signature that does
    /// not read.
    pub const fn signature_field(&self) -> Result<&SignatureField, &SignatureFieldError> {
        self.signature_field.as_ref()
    }

    /// Step 5's walked signatures, one entry per header group in the
    /// header's group order, each read through the group it was walked
    /// under.
    ///
    /// # Errors
    ///
    /// The [`SignatureFieldError`] of the first indexed signature that does
    /// not read.
    pub fn walked_groups(
        &self,
    ) -> Result<impl ExactSizeIterator<Item = SignerGroupSignatures<'_>>, &SignatureFieldError>
    {
        let field = self.signature_field.as_ref()?;
        Ok(self
            .header
            .groups()
            .iter()
            .zip(&field.signatures)
            .map(|(group, signatures)| SignerGroupSignatures { group, signatures }))
    }

    /// The whole preimage, fields 1 through 12, where fields 8 through 12
    /// decode: step 8's decode past the inception, and the inception's
    /// content read at step 3. It does not wait on the walk, because at
    /// chain position zero step 3 runs before step 5.
    ///
    /// # Errors
    ///
    /// The [`BodyError`] where fields 8 through 12 do not decode.
    pub const fn preimage(&self) -> Result<&EventPreimage, &BodyError> {
        self.preimage.as_ref()
    }
}

/// One event unit read at an offset into a frame's `value` (§9.10.12).
///
/// Each variant is a stage of §9.7.4.2's check order that stopped the
/// read, or [`Read`](Self::Read) where every stage through step 4 passed.
///
/// Only [`decode_event`] builds the payloads, so every stage a variant
/// carries ran over this unit's own bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventUnit {
    /// Step 1 failed: the length prefix, or the bytes it covers, run past
    /// `value`. The frame ends.
    Unframed,
    /// Step 2 failed: the prefixed bytes do not begin with
    /// `"SCP-KEL-EVENT-V1:"`. The frame ends.
    NoSeparator,
    /// Step 4 failed. The frame ends, because no form list says where the
    /// signature field ends.
    HeaderFailed(HeaderFailedUnit),
    /// Step 4 passed. Boxed, since it carries the decoded body.
    Read(Box<ReadUnit>),
}

impl EventUnit {
    /// The signed preimage, where steps 1 and 2 passed.
    #[must_use]
    pub const fn raw(&self) -> Option<&RawSignedPreimage> {
        match self {
            Self::Unframed | Self::NoSeparator => None,
            Self::HeaderFailed(unit) => Some(&unit.raw),
            Self::Read(unit) => Some(&unit.raw),
        }
    }
}

/// Reads the event unit at `offset` in a frame's `value` (§9.10.12) and
/// runs each byte-level stage of §9.7.4.2's check order on it (see
/// [`EventUnit`]).
///
/// Fields 1 through 12 are parsed once: the body resumes the header's
/// reader after field 7. No stage allocates from a wire count before
/// checking it against the bytes that remain: the prefix is checked against
/// `value`, every list count against its cap and the bytes left in the
/// preimage, and each indexed signature's declared lengths against their
/// §9.18.17 bounds and the bytes left in `value`, with one signature pushed
/// at a time. The walk runs only once the encoded length is within
/// `MAX_EVENT_BYTES`, so no unit names more signatures than one legal-size
/// event carries.
///
/// The bytes from the end of the walk to the end of `value` are the next
/// unit's; the rule that a frame ends exactly at `value`'s end belongs to
/// the frame decoder.
#[must_use]
pub fn decode_event(value: &[u8], offset: usize) -> EventUnit {
    let Some((prefixed, field)) = prefixed_bytes(value, offset) else {
        return EventUnit::Unframed;
    };
    let Some(raw) = RawSignedPreimage::new(prefixed) else {
        return EventUnit::NoSeparator;
    };
    let (header, preimage) = match read_event(raw.fields(), raw.signed_len()) {
        Ok(read) => read,
        Err(error) => return EventUnit::HeaderFailed(HeaderFailedUnit { raw, error }),
    };
    let signature_field =
        walk_signature_field(&header, field).map(|(signatures, rest)| SignatureField {
            signatures,
            // Each term is a disjoint part of `value[offset..]`, so the sum
            // is at most `value.len()`.
            consumed: LENGTH_PREFIX_BYTES + prefixed.len() + (field.len() - rest.len()),
        });
    EventUnit::Read(Box::new(ReadUnit {
        raw,
        header,
        signature_field,
        preimage,
    }))
}

/// Step 1: the bytes the length prefix at `offset` covers and the bytes of
/// `value` after them, or `None` where the prefix or those bytes run past
/// `value` (a length past `usize` runs past every `value`).
fn prefixed_bytes(value: &[u8], offset: usize) -> Option<(&[u8], &[u8])> {
    let (prefix, rest) = value
        .get(offset..)?
        .split_first_chunk::<LENGTH_PREFIX_BYTES>()?;
    let length = usize::try_from(u32::from_be_bytes(*prefix)).ok()?;
    rest.split_at_checked(length)
}

/// Step 5: reads one indexed signature per named signer, in group order and
/// in the form field 7 declares for that signer's index, and returns one
/// signature list per group with the bytes of `field` left after the walk.
fn walk_signature_field<'a>(
    header: &EventHeader,
    field: &'a [u8],
) -> Result<(Vec<Vec<NamedSignature>>, &'a [u8]), SignatureFieldError> {
    let mut rest = field;
    let mut groups = Vec::new();
    for group in header.groups() {
        let mut signatures = Vec::new();
        for (position, signer) in group.signers().iter().enumerate() {
            let signature;
            (signature, rest) =
                IndexedSignature::read_front(signer.form, rest).map_err(|error| {
                    SignatureFieldError {
                        role: group.role,
                        position,
                        index: signer.index,
                        error,
                    }
                })?;
            signatures.push(NamedSignature {
                index: signer.index,
                signature,
            });
        }
        groups.push(signatures);
    }
    Ok((groups, rest))
}
