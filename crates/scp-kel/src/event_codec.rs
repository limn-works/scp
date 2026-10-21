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
//! keeps each outcome apart in an [`EventUnit`]: step 1 (the prefix lies
//! within `value`), step 2 (the separator), step 4 (fields 1 through 7),
//! step 5 (the signature-field walk), and the full decode step 8 and the
//! inception's step 3 read. The verifier then classifies a failure by the
//! bytes the failing check reads, which is §9.7.4.2's illegality test: the
//! separator, the header and the body read only bytes the event's digest
//! binds, the walk reads the signature field, and step 1 reads the frame's
//! length prefix. No stage verifies a signature or reads another event.

use scp_did::Identifier;

use crate::constants::{KEL_EVENT_SEPARATOR, KEL_ID_SEPARATOR};
use crate::error::{DecodeError, HeaderError, InceptionHeaderDefect, SignatureFieldError};
use crate::event::{EventKind, SignerGroup, SignerGroupRole, StandingRootDeclaration};
use crate::preimage::{EncodedPreimage, decode_header, decode_preimage, kind_byte, sha256};
use crate::signature::IndexedSignature;

/// The event unit's preimage length prefix: a big-endian `u32` (§9.10.12).
const LENGTH_PREFIX_BYTES: usize = 4;

/// Fields 1 through 7 of an event (§9.7.4.2): what the check order's step 4
/// decodes, and what the signature-field walk reads.
///
/// Only the decoder builds one, so its signer groups always number what
/// its kind and `standing_root` name, in that order, and under
/// [`decode_event`] each group's form list is as long as its index list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventHeader {
    pub(crate) kind: EventKind,
    pub(crate) identifier: Identifier,
    pub(crate) sequence: u64,
    pub(crate) predecessor_digest: [u8; 32],
    pub(crate) standing_root: Option<StandingRootDeclaration>,
    pub(crate) signer_groups: Vec<SignerGroup>,
    pub(crate) roles: &'static [SignerGroupRole],
}

impl EventHeader {
    /// Field 1, the event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// Field 2, the identifier field as carried (zero on an inception that
    /// meets R3).
    #[must_use]
    pub const fn identifier(&self) -> Identifier {
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

    /// Fields 6 and 7, one group per role [`roles`](Self::roles) names, in
    /// that order.
    #[must_use]
    pub fn signer_groups(&self) -> &[SignerGroup] {
        &self.signer_groups
    }

    /// The roles of the signer groups, which the kind and `standing_root`
    /// fix (§9.7.4.2, "Which fields each kind carries in substance").
    #[must_use]
    pub const fn roles(&self) -> &'static [SignerGroupRole] {
        self.roles
    }
}

/// One signer group's indexed signatures as the signature field carries
/// them, in the group's index-list order (§9.7.4.2 fields 6 and 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerGroupSignatures {
    role: SignerGroupRole,
    signatures: Vec<IndexedSignature>,
}

impl SignerGroupSignatures {
    /// The group's role.
    #[must_use]
    pub const fn role(&self) -> SignerGroupRole {
        self.role
    }

    /// The group's indexed signatures, the one at position `i` by the index
    /// at position `i` of the group's index list.
    #[must_use]
    pub fn signatures(&self) -> &[IndexedSignature] {
        &self.signatures
    }
}

/// One event unit read at an offset into a frame's `value`, each check-order
/// stage's outcome kept apart (§9.7.4.2; §9.10.12).
///
/// Only [`decode_event`] builds one, so every stage present ran over this
/// unit's own bytes. A stage is `None` where an earlier stage it depends on
/// failed:
///
/// | Stage | `None` when |
/// |---|---|
/// | [`raw_signed_preimage`](Self::raw_signed_preimage), step 1 | the length prefix, or the bytes it covers, run past `value` |
/// | [`header`](Self::header), steps 2 and 4 | step 1 failed |
/// | [`signatures`](Self::signatures), step 5 | the header failed |
/// | [`body`](Self::body), the full decode | the header failed |
/// | [`consumed`](Self::consumed) | step 1, the header or the walk failed |
///
/// The body does not wait on the walk, because at chain position zero the
/// inception's content (step 3) runs before the walk (step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventUnit {
    raw_signed_preimage: Option<Vec<u8>>,
    header: Option<Result<EventHeader, HeaderError>>,
    signatures: Option<Result<Vec<SignerGroupSignatures>, SignatureFieldError>>,
    body: Option<Result<EncodedPreimage, DecodeError>>,
    consumed: Option<usize>,
}

impl EventUnit {
    /// The bytes the unit's length prefix covers, separator included, as
    /// received: what the digest, the raw identifier and every signature
    /// read. `None` when step 1 failed.
    #[must_use]
    pub fn raw_signed_preimage(&self) -> Option<&[u8]> {
        self.raw_signed_preimage.as_deref()
    }

    /// Steps 2 and 4: the separator, then fields 1 through 7 with each
    /// form list as long as its index list.
    #[must_use]
    pub fn header(&self) -> Option<Result<&EventHeader, &HeaderError>> {
        self.header.as_ref().map(Result::as_ref)
    }

    /// Step 5: the signature field walked under fields 6 and 7, one entry
    /// per signer group in the header's group order.
    #[must_use]
    pub fn signatures(&self) -> Option<Result<&[SignerGroupSignatures], &SignatureFieldError>> {
        self.signatures
            .as_ref()
            .map(|walk| walk.as_ref().map(Vec::as_slice))
    }

    /// The full decode of fields 1 through 12, with the encoded-length
    /// ceiling (`MAX_EVENT_BYTES`): step 8 past the inception, and the
    /// inception's content read at step 3.
    #[must_use]
    pub fn body(&self) -> Option<Result<&EncodedPreimage, &DecodeError>> {
        self.body.as_ref().map(Result::as_ref)
    }

    /// The bytes the unit took from `value` at its offset: the 4-byte
    /// prefix, the signed preimage and the walked signature field. The next
    /// unit starts there. `None` ends the frame.
    #[must_use]
    pub const fn consumed(&self) -> Option<usize> {
        self.consumed
    }
}

/// Reads the event unit at `offset` in a frame's `value` (§9.10.12) and
/// runs each byte-level stage of §9.7.4.2's check order on it, keeping
/// each outcome apart (see [`EventUnit`]).
///
/// No stage allocates from a wire count before checking it against the
/// bytes that remain: the prefix is checked against `value`, every list
/// count against its cap and the bytes left in the preimage, and each
/// indexed signature's declared lengths against their §9.18.17 bounds and
/// the bytes left in `value`, with one signature pushed at a time.
///
/// The bytes from the end of the walk to the end of `value` are the next
/// unit's; the rule that a frame ends exactly at `value`'s end belongs to
/// the frame decoder.
#[must_use]
pub fn decode_event(value: &[u8], offset: usize) -> EventUnit {
    let Some((raw, preimage_end)) = prefixed_bytes(value, offset) else {
        return EventUnit {
            raw_signed_preimage: None,
            header: None,
            signatures: None,
            body: None,
            consumed: None,
        };
    };
    let header = read_header(raw);
    // A failed header leaves no form list to walk and no body worth
    // reading: every later stage is absent.
    let (signatures, body, consumed) = header.as_ref().map_or((None, None, None), |header| {
        let field = value.get(preimage_end..).unwrap_or_default();
        let walk = walk_signature_field(header, field);
        let consumed = walk
            .as_ref()
            .ok()
            .and_then(|(_, walked)| preimage_end.checked_add(*walked))
            .and_then(|end| end.checked_sub(offset));
        let body = decode_preimage(raw.get(KEL_EVENT_SEPARATOR.len()..).unwrap_or_default());
        (Some(walk.map(|(groups, _)| groups)), Some(body), consumed)
    });
    EventUnit {
        raw_signed_preimage: Some(raw.to_vec()),
        header: Some(header),
        signatures,
        body,
        consumed,
    }
}

/// Step 1: the bytes the length prefix at `offset` covers and the offset in
/// `value` where they end, or `None` where the prefix or those bytes run
/// past `value`.
fn prefixed_bytes(value: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let prefix_end = offset.checked_add(LENGTH_PREFIX_BYTES)?;
    let prefix = value.get(offset..prefix_end)?;
    let mut length = [0u8; LENGTH_PREFIX_BYTES];
    length.copy_from_slice(prefix);
    let length = usize::try_from(u32::from_be_bytes(length)).ok()?;
    let preimage_end = prefix_end.checked_add(length)?;
    Some((value.get(prefix_end..preimage_end)?, preimage_end))
}

/// Steps 2 and 4, and the form-list length the walk needs.
fn read_header(raw: &[u8]) -> Result<EventHeader, HeaderError> {
    let fields = raw
        .strip_prefix(KEL_EVENT_SEPARATOR)
        .ok_or(HeaderError::Separator)?;
    let header = decode_header(fields).map_err(HeaderError::Fields)?;
    for (group, role) in header.signer_groups.iter().zip(header.roles) {
        if group.forms.len() != group.indices.len() {
            return Err(HeaderError::FormListLength {
                role: *role,
                indices: group.indices.len(),
                forms: group.forms.len(),
            });
        }
    }
    Ok(header)
}

/// Step 5: reads one indexed signature per named index, in group order and
/// in the form field 7 declares for it, and returns the groups with the
/// bytes walked.
fn walk_signature_field(
    header: &EventHeader,
    field: &[u8],
) -> Result<(Vec<SignerGroupSignatures>, usize), SignatureFieldError> {
    let mut walked = 0usize;
    let mut groups = Vec::new();
    for (group, role) in header.signer_groups.iter().zip(header.roles) {
        let mut signatures = Vec::new();
        for (position, form) in group.forms.iter().enumerate() {
            let rest = field.get(walked..).unwrap_or_default();
            let (signature, taken) =
                IndexedSignature::read(*form, rest).map_err(|error| SignatureFieldError {
                    role: *role,
                    position,
                    error,
                })?;
            walked = walked.saturating_add(taken);
            signatures.push(signature);
        }
        groups.push(SignerGroupSignatures {
            role: *role,
            signatures,
        });
    }
    Ok((groups, walked))
}

/// The identifier a raw inception preimage recomputes to (§9.7.4.2 R2).
///
/// It is `SHA-256("SCP-KEL-ID-V1:" ‖ raw_signed_preimage)` over the bytes as
/// received (`03-identity.md` §3.1).
///
/// It reads no field and needs no decode, so it returns a value for every
/// input, an inception whose body fails to decode included. It is distinct
/// from [`EncodedPreimage::identifier`], which reads a decoded preimage.
#[must_use]
pub fn raw_identifier(raw_signed_preimage: &[u8]) -> Identifier {
    Identifier::from_bytes(sha256(&[KEL_ID_SEPARATOR, raw_signed_preimage]))
}

/// Checks the inception header bytes R3 fixes (§9.7.4.2 R3).
///
/// It reads a raw signed preimage at fixed offsets, without decoding it:
/// field 1 is the `Inception` byte and fields 2, 3 and 4 (the 72 bytes after
/// it) are zero.
///
/// # Errors
///
/// [`InceptionHeaderDefect`] naming the first field, in field order, that
/// does not hold its value, or why the fields cannot be read.
pub fn inception_header_zero_checks(
    raw_signed_preimage: &[u8],
) -> Result<(), InceptionHeaderDefect> {
    let fields = raw_signed_preimage
        .strip_prefix(KEL_EVENT_SEPARATOR)
        .ok_or(InceptionHeaderDefect::Separator)?;
    let (&kind, rest) = fields
        .split_first()
        .ok_or(InceptionHeaderDefect::Truncated)?;
    let (identifier, rest) = rest
        .split_first_chunk::<32>()
        .ok_or(InceptionHeaderDefect::Truncated)?;
    let (sequence, rest) = rest
        .split_first_chunk::<8>()
        .ok_or(InceptionHeaderDefect::Truncated)?;
    let (predecessor, _) = rest
        .split_first_chunk::<32>()
        .ok_or(InceptionHeaderDefect::Truncated)?;
    if kind != kind_byte(EventKind::Inception) {
        return Err(InceptionHeaderDefect::NotInception { value: kind });
    }
    if identifier.iter().any(|byte| *byte != 0) {
        return Err(InceptionHeaderDefect::NonzeroIdentifier);
    }
    if sequence.iter().any(|byte| *byte != 0) {
        return Err(InceptionHeaderDefect::NonzeroSequence);
    }
    if predecessor.iter().any(|byte| *byte != 0) {
        return Err(InceptionHeaderDefect::NonzeroPredecessor);
    }
    Ok(())
}
