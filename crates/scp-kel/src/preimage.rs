//! The key-event preimage's byte constructions (`09-security-model.md`
//! §9.7.4.2) — the one module ADR-063's implementation constraints allow
//! each of them in: the event-kind byte, the event digest
//! `SHA-256("SCP-KEL-EVENT-V1:" ‖ fields)`, and the identifier derivation
//! `SHA-256("SCP-KEL-ID-V1:" ‖ inception signed preimage)`.
//!
//! Every integer is big-endian at a fixed width. A count is a `u32` taken
//! from a length with `u32::try_from`, never an `as` cast, and no pointer-width
//! integer or float reaches the bytes.

use scp_did::{
    CommitmentEntry, CustodyType, Identifier, KeyAlgorithm, KeyCondition, KeyEntry, KeyRole,
    StandingCommitment, UnknownDiscriminator,
};
use sha2::{Digest, Sha256};

use crate::constants::{
    KEL_EVENT_SEPARATOR, KEL_ID_SEPARATOR, KEL_SEAL_SEPARATOR, MAX_AUTHENTICATOR_DATA_BYTES,
    MAX_CLIENT_DATA_JSON_BYTES, MAX_EVENT_BYTES, MAX_NEXT_SET_SIZE, MAX_ROOT_SET_SIZE,
    MAX_WITNESS_SET_SIZE, PREROTATION_SEPARATOR, RAW_SIGNATURE_BYTES,
};
use crate::error::{
    BodyError, BodyField, BodyList, DecodeError, DeriveIdentifierError, DidDiscriminatorField,
    EncodeError, HeaderDiscriminator, HeaderError, HeaderField, InceptionHeaderDefect, ListField,
    SignerList,
};
use crate::event::{
    Continuation, EventKind, EventPreimage, InstalledRootSet, KeyStateSnapshot, SignatureForm,
    SignerGroup, SignerGroupRole, StandingRootDeclaration, signer_group_roles,
};
use crate::event_codec::{EventHeader, HeaderGroup, HeaderPrefix, NamedSigner};

/// A 33-byte SEC1 compressed point.
const POINT_BYTES: usize = 33;
/// A 32-byte digest or identifier.
const DIGEST_BYTES: usize = 32;
/// One snapshot key entry: key 33, role 1, condition 1, `compromised_from`
/// 8, custody 1, algorithm 1 (§9.7.4.2, the key-state snapshot's order).
const KEY_ENTRY_BYTES: usize = 45;
/// One continuation commitment entry: commitment 32, custody 1, algorithm 1
/// (§9.7.4.2 field 12).
const COMMITMENT_ENTRY_BYTES: usize = 34;
/// The four-byte `BE32(0)` absent sentinel of fields 9, 10 and 12.
const COMPOSITE_SENTINEL: [u8; 4] = [0; 4];

/// The absent byte of field 5.
const STANDING_ROOT_ABSENT: u8 = 0x00;
/// Field 12's abandonment byte.
const CONTINUATION_ABANDONS: u8 = 0x00;
/// Field 12's commitment-list byte.
const CONTINUATION_FIXES_COMMITMENT: u8 = 0x01;

/// The count bound of every count-prefixed list in the preimage and its
/// key-state snapshot: the one table the encoder and the decoder read.
///
/// §9.7.4.2's count-bound rule: "The list is bounded by the `MAX_*` constant
/// §9.18.17 registers for it … Where §9.18.17 registers no `MAX_*` for a
/// list, the enclosing field's remaining bytes are its whole bound." A list
/// maps to `Some(max)` exactly where a §9.18.17 row's "Read by" column names
/// it, directly or through the R3 defect-list clause that caps it, and to
/// `None` otherwise. Every list is also held to the bytes remaining.
const fn count_cap(list: ListField) -> Option<u32> {
    match list {
        // §9.18.17 `MAX_NEXT_SET_SIZE`, read by "§9.7.4.2 R3's defect list;
        // the reveal group; the next-threshold recommendation of §9.7.4.1
        // item 4". The reveal group's index list: "the same one-byte signer
        // index ceiling of 255 binds the reveal group's indices". The
        // commitment list: R3's clause "a next set or commitment list over
        // `MAX_NEXT_SET_SIZE` members, which the verifier reads in the
        // continuation field of the preimage".
        ListField::Signer(SignerList::Indices(SignerGroupRole::Reveal))
        | ListField::Body(BodyList::Commitments) => Some(MAX_NEXT_SET_SIZE),
        // §9.18.17 `MAX_ROOT_SET_SIZE`, read by "§9.7.4.2 R3's defect list;
        // the installed-root-set field of the key-event preimage".
        ListField::Body(BodyList::InstalledRootSet) => Some(MAX_ROOT_SET_SIZE),
        // §9.18.17 `MAX_WITNESS_SET_SIZE`, read by "§9.7.4.2 R3's defect list
        // and R9's retained-object bound", whose R3 clause is "a witness set
        // over `MAX_WITNESS_SET_SIZE` entries", derived as "The witness set
        // is a repeated field of the preimage the key entries sit in".
        ListField::Body(BodyList::Witnesses) => Some(MAX_WITNESS_SET_SIZE),
        // No §9.18.17 row names these lists. The snapshot key list is bounded
        // by `MAX_EVENT_BYTES` (R3: "an event whose encoded length exceeds
        // `MAX_EVENT_BYTES`, which is what bounds the snapshot's key list").
        // The other signer groups' index lists, every form list and the
        // revealed keys reach R3 as defects.
        ListField::Signer(
            SignerList::Indices(
                SignerGroupRole::Root
                | SignerGroupRole::ReplacementRoot
                | SignerGroupRole::StandingRoot,
            )
            | SignerList::Forms(_),
        )
        | ListField::Body(BodyList::RevealedKeys | BodyList::SnapshotKeys | BodyList::Seals) => {
            None
        }
    }
}

/// The ceiling §9.18.17 reserves for one `WebAuthnAssertion` indexed
/// signature: 4 + `MAX_AUTHENTICATOR_DATA_BYTES` + 4 +
/// `MAX_CLIENT_DATA_JSON_BYTES` + 64 = 840 bytes.
const ASSERTION_CEILING: usize = 4
    + MAX_AUTHENTICATOR_DATA_BYTES as usize
    + 4
    + MAX_CLIENT_DATA_JSON_BYTES as usize
    + RAW_SIGNATURE_BYTES as usize;

/// The ceiling §9.18.17 reserves for one named index whose form is `form`:
/// 64 bytes for `Raw` and 840 for `WebAuthnAssertion`.
const fn index_ceiling(form: SignatureForm) -> u64 {
    match form {
        SignatureForm::Raw => RAW_SIGNATURE_BYTES as u64,
        SignatureForm::WebAuthnAssertion => ASSERTION_CEILING as u64,
    }
}

/// An event's encoded length (§9.18.17 `MAX_EVENT_BYTES`; §9.7.4.2 step
/// 4): the length of its signed preimage, separator included, plus, for
/// each named signer, the ceiling of its form. No term is a length a relay
/// controls: the forms and indices are fields 6 and 7.
///
/// It takes paired groups, so it is defined only where every form list is
/// as long as its index list, which §9.18.17 requires. It is the one
/// computation of that length: the encoder and the header decode both call
/// it, so the encoder cannot emit an event the decoder rejects for its
/// length.
///
/// The sum is a `u64` so it is exact on every target: a signed preimage
/// fits a `u32` length prefix and names at most one index per byte, so the
/// sum stays under 2^42 where a 32-bit `usize` would overflow.
pub fn encoded_event_len(signed_len: usize, groups: &[HeaderGroup]) -> u64 {
    let ceilings: u64 = groups
        .iter()
        .flat_map(HeaderGroup::signers)
        .map(|signer| index_ceiling(signer.form()))
        .sum();
    // `usize` is at most 64 bits on every target Rust supports.
    signed_len as u64 + ceilings
}

/// Whether an encoded length is within `MAX_EVENT_BYTES` (§9.18.17).
pub fn within_event_bytes(encoded_len: u64) -> bool {
    encoded_len <= u64::from(MAX_EVENT_BYTES)
}

/// The event-kind byte (§9.7.4.2 field 1). The one table it is written from.
pub const fn kind_byte(kind: EventKind) -> u8 {
    match kind {
        EventKind::Inception => 0x01,
        EventKind::KeyState => 0x02,
        EventKind::CommitmentRollover => 0x03,
        EventKind::RootRecovery => 0x04,
    }
}

/// The inverse of [`kind_byte`], `None` for an unregistered byte.
const fn kind_from_byte(byte: u8) -> Option<EventKind> {
    match byte {
        0x01 => Some(EventKind::Inception),
        0x02 => Some(EventKind::KeyState),
        0x03 => Some(EventKind::CommitmentRollover),
        0x04 => Some(EventKind::RootRecovery),
        _ => None,
    }
}

const fn standing_root_byte(declaration: StandingRootDeclaration) -> u8 {
    match declaration {
        StandingRootDeclaration::CoSigns => 0x01,
        StandingRootDeclaration::Lost => 0x02,
    }
}

const fn form_byte(form: SignatureForm) -> u8 {
    match form {
        SignatureForm::Raw => 0x01,
        SignatureForm::WebAuthnAssertion => 0x02,
    }
}

const fn form_from_byte(byte: u8) -> Option<SignatureForm> {
    match byte {
        0x01 => Some(SignatureForm::Raw),
        0x02 => Some(SignatureForm::WebAuthnAssertion),
        _ => None,
    }
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// The encoded preimage
// ---------------------------------------------------------------------------

/// A key-event preimage with its bytes: the value and the signed preimage
/// `"SCP-KEL-EVENT-V1:" ‖ fields` it encodes to (§9.7.4.2 R13).
///
/// Only [`encode_preimage`] and [`decode_preimage`] construct one, and each
/// guarantees that the bytes decode to the value and the value encodes to
/// the bytes. It holds the field bytes and implies the separator, so no
/// accessor strips one; the digest and the identifier therefore read bytes
/// that exist and cannot fail, and a verifier digests the bytes it received
/// with no re-encode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncodedPreimage {
    preimage: EventPreimage,
    fields: Vec<u8>,
}

impl EncodedPreimage {
    /// The preimage these bytes encode.
    #[must_use]
    pub const fn preimage(&self) -> &EventPreimage {
        &self.preimage
    }

    /// The preimage these bytes encode, by value.
    #[must_use]
    pub fn into_preimage(self) -> EventPreimage {
        self.preimage
    }

    /// The signed preimage `"SCP-KEL-EVENT-V1:" ‖ fields`: the bytes every
    /// signature, digest and identifier derivation reads, and the bytes
    /// spec 25 prints as each vector's preimage (§9.7.4.2 R13).
    #[must_use]
    pub fn signed_preimage(&self) -> Vec<u8> {
        signed_preimage_of(&self.fields)
    }

    /// The twelve field bytes, without the separator: what
    /// [`decode_preimage`] reads (§9.7.4.2 field order).
    #[must_use]
    pub fn fields(&self) -> &[u8] {
        &self.fields
    }

    /// The event digest, `SHA-256(signed_preimage)` (ADR-063; §9.7.4.2).
    #[must_use]
    pub fn event_digest(&self) -> [u8; 32] {
        event_digest_of(&self.fields)
    }

    /// The identifier an inception derives, R13's
    /// `SHA-256("SCP-KEL-ID-V1:" ‖ signed_preimage)` (`03-identity.md`
    /// §3.1), and `None` for every other kind.
    ///
    /// A later event's field 2 is the identifier it claims, not one it
    /// derives, so this never returns it: a chain walker binds a later
    /// event to the identifier its inception derives, and reads field 2
    /// through [`EventPreimage::identifier`] when it compares the two.
    ///
    /// R13 derives the identifier over an inception whose identifier,
    /// sequence and predecessor are zero. An inception carrying a nonzero
    /// one still derives here, over its own bytes, and R3 rejects it; a
    /// writer that must refuse it calls [`derive_identifier`].
    #[must_use]
    pub fn inception_identifier(&self) -> Option<Identifier> {
        match self.preimage.kind {
            EventKind::Inception => Some(identifier_of(&self.fields)),
            EventKind::KeyState | EventKind::CommitmentRollover | EventKind::RootRecovery => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encodes a key-event preimage (§9.7.4.2 field order and absent-field
/// sentinel).
///
/// # Errors
///
/// [`EncodeError`] exactly where [`decode_preimage`] would reject the bytes
/// or decode them to a different preimage: a list over its §9.18.17 maximum
/// or too long for its count, a form list whose length differs from its
/// index list, an encoded event length over `MAX_EVENT_BYTES`, a signer
/// group count its kind does not name, a field
/// whose value would encode as that field's absent sentinel, or a nonzero
/// `compromised_from` on an entry that is not `Compromised`.
pub fn encode_preimage(preimage: &EventPreimage) -> Result<EncodedPreimage, EncodeError> {
    let mut fields = Vec::new();
    let groups = write_fields(preimage, &mut fields)?;
    let encoded_len = encoded_event_len(signed_len_of(&fields), &groups);
    if !within_event_bytes(encoded_len) {
        return Err(EncodeError::EventTooLong { encoded_len });
    }
    Ok(EncodedPreimage {
        preimage: preimage.clone(),
        fields,
    })
}

/// The identifier an inception event derives (§9.7.4.2 R13).
///
/// It is `SHA-256("SCP-KEL-ID-V1:" ‖ signed_preimage)` (`03-identity.md`
/// §3.1), and this function refuses any preimage that is not an inception
/// with identifier, sequence and predecessor digest all zero.
///
/// # Errors
///
/// [`DeriveIdentifierError`] unless the preimage is an `Inception` whose
/// identifier, sequence and predecessor digest are all zero, or where it
/// cannot be encoded.
pub fn derive_identifier(preimage: &EventPreimage) -> Result<Identifier, DeriveIdentifierError> {
    if preimage.kind != EventKind::Inception {
        return Err(DeriveIdentifierError::NotInception {
            kind: preimage.kind,
        });
    }
    if preimage.identifier != Identifier::ZERO {
        return Err(DeriveIdentifierError::NonzeroIdentifier);
    }
    if preimage.sequence != 0 {
        return Err(DeriveIdentifierError::NonzeroSequence {
            sequence: preimage.sequence,
        });
    }
    if preimage.predecessor_digest != [0; 32] {
        return Err(DeriveIdentifierError::NonzeroPredecessor);
    }
    Ok(identifier_of(encode_preimage(preimage)?.fields()))
}

/// A next-set member's commitment,
/// `SHA-256("SCP-PREROTATION-COMMITMENT-V1:" ‖ point)` over the 33-byte SEC1
/// compressed point with no length prefix (§9.7.4.2 definitions).
#[must_use]
pub fn prerotation_commitment(point: &[u8; 33]) -> [u8; 32] {
    sha256(&[PREROTATION_SEPARATOR, point])
}

/// A key-event seal over a sealed event's digest,
/// `SHA-256("SCP-KEL-SEAL-V1:" ‖ digest)` (§9.7.4.2 field 11).
#[must_use]
pub fn key_event_seal(sealed_event_digest: &[u8; 32]) -> [u8; 32] {
    sha256(&[KEL_SEAL_SEPARATOR, sealed_event_digest])
}

/// Writes a list's 4-byte count after checking it against [`count_cap`], the
/// table the decoder reads.
fn put_count(out: &mut Vec<u8>, list: ListField, len: usize) -> Result<(), EncodeError> {
    if let Some(max) = count_cap(list)
        && u64::try_from(len).map_or(true, |len| len > u64::from(max))
    {
        return Err(EncodeError::CountOverMax { list, len, max });
    }
    let count = u32::try_from(len).map_err(|_| EncodeError::CountOverflow { list, len })?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

/// Writes fields 1 through 12 and returns the signer groups paired, which
/// the encoded length reads.
fn write_fields(
    preimage: &EventPreimage,
    out: &mut Vec<u8>,
) -> Result<Vec<HeaderGroup>, EncodeError> {
    let roles = preimage
        .signer_group_roles()
        .ok_or(EncodeError::RootRecoveryWithoutStandingRoot)?;
    if preimage.signer_groups.len() != roles.len() {
        return Err(EncodeError::SignerGroupCount {
            kind: preimage.kind,
            expected: roles.len(),
            actual: preimage.signer_groups.len(),
        });
    }
    // Fields 1 to 5.
    out.push(kind_byte(preimage.kind));
    out.extend_from_slice(preimage.identifier.as_bytes());
    out.extend_from_slice(&preimage.sequence.to_be_bytes());
    out.extend_from_slice(&preimage.predecessor_digest);
    out.push(
        preimage
            .standing_root
            .map_or(STANDING_ROOT_ABSENT, standing_root_byte),
    );

    // Field 6, then field 7, each in the kind's group order.
    for (group, role) in preimage.signer_groups.iter().zip(roles) {
        put_count(out, SignerList::Indices(*role).into(), group.indices.len())?;
        out.extend_from_slice(&group.indices);
    }
    for (group, role) in preimage.signer_groups.iter().zip(roles) {
        put_count(out, SignerList::Forms(*role).into(), group.forms.len())?;
        out.extend(group.forms.iter().map(|form| form_byte(*form)));
    }
    // Step 4's order: each count's cap, then each group's pairing.
    let mut groups = Vec::new();
    for (group, role) in preimage.signer_groups.iter().zip(roles) {
        groups.push(
            HeaderGroup::pair(*role, &group.indices, &group.forms)
                .map_err(EncodeError::FormListLength)?,
        );
    }

    // Field 8.
    put_count(
        out,
        BodyList::RevealedKeys.into(),
        preimage.revealed_keys.len(),
    )?;
    for key in &preimage.revealed_keys {
        out.extend_from_slice(key);
    }

    // Field 9: `BE32(0)` alone where absent, with no threshold after it.
    match &preimage.installed_root_set {
        None => out.extend_from_slice(&COMPOSITE_SENTINEL),
        Some(root_set) => write_installed_root_set(root_set, out)?,
    }

    // Field 10: `BE32(0)` in place of the whole snapshot where absent.
    match &preimage.key_state {
        None => out.extend_from_slice(&COMPOSITE_SENTINEL),
        Some(snapshot) => write_snapshot(snapshot, out)?,
    }

    // Field 11.
    put_count(out, BodyList::Seals.into(), preimage.seals.len())?;
    for seal in &preimage.seals {
        out.extend_from_slice(seal);
    }

    // Field 12: `BE32(0)` where absent, never the one byte `0x00`, which is
    // the registered abandonment value.
    match &preimage.continuation {
        None => out.extend_from_slice(&COMPOSITE_SENTINEL),
        Some(Continuation::Abandons) => out.push(CONTINUATION_ABANDONS),
        Some(Continuation::FixesCommitment(commitment)) => {
            out.push(CONTINUATION_FIXES_COMMITMENT);
            put_count(
                out,
                BodyList::Commitments.into(),
                commitment.commitments.len(),
            )?;
            for entry in &commitment.commitments {
                out.extend_from_slice(&entry.commitment);
                out.push(entry.custody_type.to_byte());
                out.push(entry.key_algorithm.to_byte());
            }
            out.extend_from_slice(&commitment.next_threshold.to_be_bytes());
        }
    }
    Ok(groups)
}

fn write_installed_root_set(
    root_set: &InstalledRootSet,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    if root_set.members.is_empty() {
        return Err(EncodeError::EmptyInstalledRootSet);
    }
    put_count(
        out,
        BodyList::InstalledRootSet.into(),
        root_set.members.len(),
    )?;
    for member in &root_set.members {
        out.extend_from_slice(member);
    }
    out.extend_from_slice(&root_set.threshold.to_be_bytes());
    Ok(())
}

fn write_snapshot(snapshot: &KeyStateSnapshot, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if snapshot.root_threshold == 0 {
        return Err(EncodeError::ZeroRootThreshold);
    }
    out.extend_from_slice(&snapshot.root_threshold.to_be_bytes());
    put_count(out, BodyList::SnapshotKeys.into(), snapshot.keys.len())?;
    for (entry_index, entry) in snapshot.keys.iter().enumerate() {
        if entry.condition != KeyCondition::Compromised && entry.compromised_from != 0 {
            return Err(EncodeError::CompromisedFromWithoutCompromise {
                entry: entry_index,
                condition: entry.condition,
                compromised_from: entry.compromised_from,
            });
        }
        out.extend_from_slice(&entry.key);
        out.push(entry.role.to_byte());
        out.push(entry.condition.to_byte());
        out.extend_from_slice(&entry.compromised_from.to_be_bytes());
        out.push(entry.custody_type.to_byte());
        out.push(entry.key_algorithm.to_byte());
    }
    put_count(out, BodyList::Witnesses.into(), snapshot.witnesses.len())?;
    for witness in &snapshot.witnesses {
        out.extend_from_slice(witness.as_bytes());
    }
    out.extend_from_slice(&snapshot.witnessing_interval.to_be_bytes());
    out.push(snapshot.service_key_role.to_byte());
    out.extend_from_slice(snapshot.delegator.as_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decodes the twelve field bytes, without the separator, over an exact
/// slice (§9.7.4.2), into the preimage and its bytes.
///
/// It runs the parse `decode_event` runs: fields 1 through 7 and step 4's
/// checks on them (the form-list lengths, then the encoded length, the
/// signed preimage plus each named index's form ceiling, against
/// `MAX_EVENT_BYTES`), then fields 8 through 12 from where field 7 ended.
/// Every count is checked against the bound [`count_cap`] gives it and
/// against the bytes remaining before any element is read, and no allocation
/// is sized from a wire count (§9.7.4.2, the count-bound rule). The decoder
/// is otherwise structural: a preimage whose fields its kind does not carry,
/// or that breaks any other R3 rule, decodes, and the verifier classifies
/// it. It rejects a nonzero `compromised_from` on an entry that is not
/// `Compromised`, because the snapshot order defines that field as "zero
/// otherwise".
///
/// Field 12's absent sentinel `BE32(0)` and its abandonment byte `0x00` are
/// told apart by where the slice ends, so the slice must hold exactly one
/// preimage.
///
/// # Errors
///
/// [`DecodeError::SignedPreimage`] where the slice still begins with the
/// separator, [`DecodeError::Header`] where step 4 fails, and
/// [`DecodeError::Body`] where fields 8 through 12 do not decode.
pub fn decode_preimage(bytes: &[u8]) -> Result<EncodedPreimage, DecodeError> {
    // No field byte string begins with the separator: its first byte, `S`,
    // is no event kind.
    if bytes.starts_with(KEL_EVENT_SEPARATOR) {
        return Err(DecodeError::SignedPreimage);
    }
    let (_, preimage) = read_event(bytes, signed_len_of(bytes))?;
    Ok(EncodedPreimage {
        preimage: preimage?,
        fields: bytes.to_vec(),
    })
}

/// The field bytes after the separator, or `None` where `signed` does not
/// begin with it: the one place the separator is stripped. Every type that
/// holds a preimage's bytes holds the field bytes this returns and implies
/// the separator, so none strips it again.
pub fn field_bytes(signed: &[u8]) -> Option<&[u8]> {
    signed.strip_prefix(KEL_EVENT_SEPARATOR)
}

/// The signed preimage `"SCP-KEL-EVENT-V1:" ‖ fields`.
pub fn signed_preimage_of(fields: &[u8]) -> Vec<u8> {
    [KEL_EVENT_SEPARATOR, fields].concat()
}

/// The signed preimage's length, separator included. A slice is at most
/// `isize::MAX` bytes, so adding the 17-byte separator cannot overflow.
pub const fn signed_len_of(fields: &[u8]) -> usize {
    KEL_EVENT_SEPARATOR.len() + fields.len()
}

/// The event digest, `SHA-256("SCP-KEL-EVENT-V1:" ‖ fields)`: the digest
/// of the signed preimage (ADR-063; §9.7.4.2).
pub fn event_digest_of(fields: &[u8]) -> [u8; 32] {
    sha256(&[KEL_EVENT_SEPARATOR, fields])
}

/// The identifier a signed preimage derives,
/// `SHA-256("SCP-KEL-ID-V1:" ‖ "SCP-KEL-EVENT-V1:" ‖ fields)` (§9.7.4.2
/// R13; `03-identity.md` §3.1).
pub fn identifier_of(fields: &[u8]) -> Identifier {
    Identifier::from_bytes(sha256(&[KEL_ID_SEPARATOR, KEL_EVENT_SEPARATOR, fields]))
}

/// The one parse of an event's fields: fields 1 through 7 and step 4's
/// checks on them (§9.7.4.2), then fields 8 through 12 from where field 7
/// ended. `signed_len` is the signed preimage's length, separator included,
/// which the encoded length starts from.
///
/// The body's outcome is kept apart from the header's, because a header
/// that passes step 4 bounds the signature-field walk whether or not the
/// body decodes.
pub fn read_event(
    fields: &[u8],
    signed_len: usize,
) -> Result<(EventHeader, Result<EventPreimage, BodyError>), HeaderError> {
    let mut reader = Reader { rest: fields };
    let header = read_header(&mut reader, signed_len)?;
    let preimage = read_body(&mut reader, &header);
    Ok((header, preimage))
}

/// Fields 1 through 4 as bytes: the reads the header and the inception zero
/// checks share.
struct Leading {
    kind: u8,
    identifier: [u8; DIGEST_BYTES],
    sequence: u64,
    predecessor_digest: [u8; DIGEST_BYTES],
}

fn read_leading(reader: &mut Reader<'_>) -> Result<Leading, HeaderField> {
    Ok(Leading {
        kind: reader.u8(HeaderField::EventType)?,
        identifier: reader.array(HeaderField::Identifier)?,
        sequence: u64::from_be_bytes(reader.array(HeaderField::Sequence)?),
        predecessor_digest: reader.array(HeaderField::PredecessorDigest)?,
    })
}

/// R3's inception header checks over the field bytes (see
/// `RawSignedPreimage::inception_zero_checks`): fields 1 through 4 read as
/// the header reads them, then checked in field order.
pub fn read_inception_zero_checks(fields: &[u8]) -> Result<(), InceptionHeaderDefect> {
    let leading = read_leading(&mut Reader { rest: fields })
        .map_err(|field| InceptionHeaderDefect::Truncated { field })?;
    if leading.kind != kind_byte(EventKind::Inception) {
        return Err(InceptionHeaderDefect::NotInception {
            value: leading.kind,
        });
    }
    if leading.identifier != [0; DIGEST_BYTES] {
        return Err(InceptionHeaderDefect::NonzeroIdentifier);
    }
    if leading.sequence != 0 {
        return Err(InceptionHeaderDefect::NonzeroSequence);
    }
    if leading.predecessor_digest != [0; DIGEST_BYTES] {
        return Err(InceptionHeaderDefect::NonzeroPredecessor);
    }
    Ok(())
}

/// Step 4: fields 1 through 7 decode, then each form list pairs with its
/// index list, then the encoded length is within `MAX_EVENT_BYTES`.
fn read_header(reader: &mut Reader<'_>, signed_len: usize) -> Result<EventHeader, HeaderError> {
    let leading = read_leading(reader).map_err(|field| HeaderError::Truncated { field })?;
    let kind = kind_from_byte(leading.kind).ok_or(HeaderError::UnknownDiscriminator {
        field: HeaderDiscriminator::EventType,
        value: leading.kind,
    })?;
    let standing_root = match reader.u8(HeaderField::StandingRoot)? {
        STANDING_ROOT_ABSENT => None,
        0x01 => Some(StandingRootDeclaration::CoSigns),
        0x02 => Some(StandingRootDeclaration::Lost),
        value => {
            return Err(HeaderError::UnknownDiscriminator {
                field: HeaderDiscriminator::StandingRoot,
                value,
            });
        }
    };
    let roles = signer_group_roles(kind, standing_root)
        .ok_or(HeaderError::RootRecoveryWithoutStandingRoot)?;

    let mut index_lists = Vec::new();
    for role in roles {
        let count = reader.count(HeaderField::SignerIndices, SignerList::Indices(*role), 1)?;
        index_lists.push(reader.bytes(count, HeaderField::SignerIndices)?);
    }
    let mut form_lists = Vec::new();
    for role in roles {
        let count = reader.count(HeaderField::SignatureForms, SignerList::Forms(*role), 1)?;
        let mut forms = Vec::new();
        for &value in reader.bytes(count, HeaderField::SignatureForms)? {
            forms.push(
                form_from_byte(value).ok_or(HeaderError::UnknownDiscriminator {
                    field: HeaderDiscriminator::SignatureForm,
                    value,
                })?,
            );
        }
        form_lists.push(forms);
    }

    // Fields 1 through 7 decoded; now the form-list lengths, in group order.
    let mut groups = Vec::new();
    for ((role, indices), forms) in roles.iter().zip(index_lists).zip(&form_lists) {
        groups.push(HeaderGroup::pair(*role, indices, forms).map_err(HeaderError::FormListLength)?);
    }
    EventHeader::new(
        HeaderPrefix {
            kind,
            identifier: Identifier::from_bytes(leading.identifier),
            sequence: leading.sequence,
            predecessor_digest: leading.predecessor_digest,
            standing_root,
        },
        groups,
        signed_len,
    )
}

/// Fields 8 through 12, from where field 7 ended, into the whole preimage.
fn read_body(reader: &mut Reader<'_>, header: &EventHeader) -> Result<EventPreimage, BodyError> {
    let revealed_keys = reader.points(BodyField::RevealedKeys, BodyList::RevealedKeys)?;
    let installed_root_set = read_installed_root_set(reader)?;
    let key_state = read_snapshot(reader)?;
    let seal_count = reader.count(BodyField::Seals, BodyList::Seals, DIGEST_BYTES)?;
    let mut seals = Vec::new();
    for _ in 0..seal_count {
        seals.push(reader.array(BodyField::Seals)?);
    }
    let continuation = read_continuation(reader)?;

    Ok(EventPreimage {
        kind: header.kind(),
        identifier: header.identifier_field(),
        sequence: header.sequence(),
        predecessor_digest: *header.predecessor_digest(),
        standing_root: header.standing_root(),
        signer_groups: header
            .groups()
            .iter()
            .map(|group| SignerGroup {
                indices: group.signers().iter().map(NamedSigner::index).collect(),
                forms: group.signers().iter().map(NamedSigner::form).collect(),
            })
            .collect(),
        revealed_keys,
        installed_root_set,
        key_state,
        seals,
        continuation,
    })
}

fn read_installed_root_set(reader: &mut Reader<'_>) -> Result<Option<InstalledRootSet>, BodyError> {
    let field = BodyField::InstalledRootSet;
    let count = reader.count(field, BodyList::InstalledRootSet, POINT_BYTES)?;
    if count == 0 {
        // The four-byte sentinel: no members and no threshold.
        return Ok(None);
    }
    let mut members = Vec::new();
    for _ in 0..count {
        members.push(reader.array(field)?);
    }
    let threshold = u32::from_be_bytes(reader.array(field)?);
    Ok(Some(InstalledRootSet { members, threshold }))
}

fn read_snapshot(reader: &mut Reader<'_>) -> Result<Option<KeyStateSnapshot>, BodyError> {
    let field = BodyField::KeyState;
    // A snapshot begins with its root threshold, so `BE32(0)` there is the
    // whole field's absent sentinel.
    let root_threshold = u32::from_be_bytes(reader.array(field)?);
    if root_threshold == 0 {
        return Ok(None);
    }
    let key_count = reader.count(field, BodyList::SnapshotKeys, KEY_ENTRY_BYTES)?;
    let mut keys = Vec::new();
    for _ in 0..key_count {
        keys.push(read_key_entry(reader, keys.len())?);
    }
    let witness_count = reader.count(field, BodyList::Witnesses, DIGEST_BYTES)?;
    let mut witnesses = Vec::new();
    for _ in 0..witness_count {
        witnesses.push(Identifier::from_bytes(reader.array(field)?));
    }
    let witnessing_interval = u32::from_be_bytes(reader.array(field)?);
    let service_key_role =
        discriminator::<KeyRole>(reader, field, DidDiscriminatorField::ServiceKeyRole)?;
    let delegator = Identifier::from_bytes(reader.array(field)?);
    Ok(Some(KeyStateSnapshot {
        root_threshold,
        keys,
        witnesses,
        witnessing_interval,
        service_key_role,
        delegator,
    }))
}

fn read_key_entry(reader: &mut Reader<'_>, entry_index: usize) -> Result<KeyEntry, BodyError> {
    let field = BodyField::KeyState;
    let key = reader.array(field)?;
    let role = discriminator::<KeyRole>(reader, field, DidDiscriminatorField::Role)?;
    let condition = discriminator::<KeyCondition>(reader, field, DidDiscriminatorField::Condition)?;
    let compromised_from = u64::from_be_bytes(reader.array(field)?);
    if condition != KeyCondition::Compromised && compromised_from != 0 {
        return Err(BodyError::CompromisedFromWithoutCompromise {
            entry: entry_index,
            condition,
            compromised_from,
        });
    }
    let custody_type =
        discriminator::<CustodyType>(reader, field, DidDiscriminatorField::CustodyType)?;
    let key_algorithm =
        discriminator::<KeyAlgorithm>(reader, field, DidDiscriminatorField::KeyAlgorithm)?;
    Ok(KeyEntry {
        key,
        role,
        condition,
        compromised_from,
        custody_type,
        key_algorithm,
    })
}

fn read_continuation(reader: &mut Reader<'_>) -> Result<Option<Continuation>, BodyError> {
    let rest = reader.rest;
    if let Some((sentinel, trailing)) = rest.split_first_chunk::<4>()
        && *sentinel == COMPOSITE_SENTINEL
    {
        return trailing_free(trailing).map(|()| None);
    }
    match rest.split_first() {
        None => Err(BodyError::Truncated {
            field: BodyField::Continuation,
        }),
        Some((&CONTINUATION_ABANDONS, trailing)) => {
            // One to three zero bytes are a cut-off sentinel; anything else
            // after the abandonment byte trails it.
            if !trailing.is_empty() && trailing.iter().all(|byte| *byte == 0) {
                return Err(BodyError::Truncated {
                    field: BodyField::Continuation,
                });
            }
            trailing_free(trailing).map(|()| Some(Continuation::Abandons))
        }
        Some((&CONTINUATION_FIXES_COMMITMENT, after)) => {
            reader.rest = after;
            let commitment = read_commitment(reader)?;
            trailing_free(reader.rest).map(|()| Some(Continuation::FixesCommitment(commitment)))
        }
        Some((&value, _)) => Err(BodyError::UnknownContinuation { value }),
    }
}

fn read_commitment(reader: &mut Reader<'_>) -> Result<StandingCommitment, BodyError> {
    let field = BodyField::Continuation;
    let count = reader.count(field, BodyList::Commitments, COMMITMENT_ENTRY_BYTES)?;
    let mut commitments = Vec::new();
    for _ in 0..count {
        let commitment = reader.array(field)?;
        let custody_type =
            discriminator::<CustodyType>(reader, field, DidDiscriminatorField::CustodyType)?;
        let key_algorithm =
            discriminator::<KeyAlgorithm>(reader, field, DidDiscriminatorField::KeyAlgorithm)?;
        commitments.push(CommitmentEntry {
            commitment,
            custody_type,
            key_algorithm,
        });
    }
    let next_threshold = u32::from_be_bytes(reader.array(field)?);
    Ok(StandingCommitment {
        commitments,
        next_threshold,
    })
}

const fn trailing_free(trailing: &[u8]) -> Result<(), BodyError> {
    if trailing.is_empty() {
        Ok(())
    } else {
        Err(BodyError::TrailingBytes {
            count: trailing.len(),
        })
    }
}

/// Reads one byte as an `scp_did` name-bound enumeration, naming the field
/// in the error.
fn discriminator<T>(
    reader: &mut Reader<'_>,
    enclosing: BodyField,
    field: DidDiscriminatorField,
) -> Result<T, BodyError>
where
    T: TryFrom<u8, Error = UnknownDiscriminator>,
{
    let value = reader.u8(enclosing)?;
    T::try_from(value).map_err(|source| BodyError::UnknownDidDiscriminator { field, source })
}

/// A field name a stage's reader reports a truncation in. Each stage's
/// field type converts to that stage's own error, so the header reader can
/// produce only header errors and the body reader only body errors.
trait ReadField: Copy {
    /// The stage's error.
    type Error;
    /// The bytes ended inside this field.
    fn truncated(self) -> Self::Error;
}

/// A count-prefixed list a stage's reader bounds.
trait ReadList: Copy + Into<ListField> {
    /// The stage's error.
    type Error;
    /// The count exceeds the list's registered maximum.
    fn over_max(self, count: u32, max: u32) -> Self::Error;
    /// The count implies more bytes than remain.
    fn over_remaining(self, count: u32, remaining: usize) -> Self::Error;
}

/// The leading-field reads report the bare field, which the inception zero
/// checks and the header each wrap in their own error.
impl ReadField for HeaderField {
    type Error = Self;
    fn truncated(self) -> Self {
        self
    }
}

impl From<HeaderField> for HeaderError {
    fn from(field: HeaderField) -> Self {
        Self::Truncated { field }
    }
}

impl ReadList for SignerList {
    type Error = HeaderError;
    fn over_max(self, count: u32, max: u32) -> HeaderError {
        HeaderError::CountOverMax {
            list: self,
            count,
            max,
        }
    }
    fn over_remaining(self, count: u32, remaining: usize) -> HeaderError {
        HeaderError::CountOverRemaining {
            list: self,
            count,
            remaining,
        }
    }
}

impl ReadField for BodyField {
    type Error = BodyError;
    fn truncated(self) -> BodyError {
        BodyError::Truncated { field: self }
    }
}

impl ReadList for BodyList {
    type Error = BodyError;
    fn over_max(self, count: u32, max: u32) -> BodyError {
        BodyError::CountOverMax {
            list: self,
            count,
            max,
        }
    }
    fn over_remaining(self, count: u32, remaining: usize) -> BodyError {
        BodyError::CountOverRemaining {
            list: self,
            count,
            remaining,
        }
    }
}

/// A cursor over the unread bytes: one per event, so the body resumes where
/// the header stopped.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn bytes<F: ReadField>(&mut self, len: u32, field: F) -> Result<&'a [u8], F::Error> {
        let (taken, rest) = usize::try_from(len)
            .ok()
            .and_then(|len| self.rest.split_at_checked(len))
            .ok_or_else(|| field.truncated())?;
        self.rest = rest;
        Ok(taken)
    }

    fn array<F: ReadField, const N: usize>(&mut self, field: F) -> Result<[u8; N], F::Error> {
        let (taken, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or_else(|| field.truncated())?;
        self.rest = rest;
        Ok(*taken)
    }

    fn u8<F: ReadField>(&mut self, field: F) -> Result<u8, F::Error> {
        let [value] = self.array::<F, 1>(field)?;
        Ok(value)
    }

    /// Reads a 4-byte count and checks it against [`count_cap`] and against
    /// the bytes left, before the caller reads or allocates any element.
    fn count<F, L>(&mut self, field: F, list: L, element_bytes: usize) -> Result<u32, L::Error>
    where
        F: ReadField,
        L: ReadList,
        L::Error: From<F::Error>,
    {
        let count = u32::from_be_bytes(self.array(field)?);
        if let Some(max) = count_cap(list.into())
            && count > max
        {
            return Err(list.over_max(count, max));
        }
        let remaining = self.rest.len();
        let fits = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(element_bytes))
            .is_some_and(|needed| needed <= remaining);
        if !fits {
            return Err(list.over_remaining(count, remaining));
        }
        Ok(count)
    }

    fn points(&mut self, field: BodyField, list: BodyList) -> Result<Vec<[u8; 33]>, BodyError> {
        let count = self.count(field, list, POINT_BYTES)?;
        let mut points = Vec::new();
        for _ in 0..count {
            points.push(self.array(field)?);
        }
        Ok(points)
    }
}
