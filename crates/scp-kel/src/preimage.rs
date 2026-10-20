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
    KEL_EVENT_SEPARATOR, KEL_ID_SEPARATOR, KEL_SEAL_SEPARATOR, MAX_EVENT_BYTES, MAX_NEXT_SET_SIZE,
    MAX_ROOT_SET_SIZE, MAX_WITNESS_SET_SIZE, PREROTATION_SEPARATOR,
};
use crate::error::{
    DecodeError, DeriveIdentifierError, DiscriminatorField, EncodeError, EventDiscriminatorField,
    ListField, PreimageField,
};
use crate::event::{
    Continuation, EventKind, EventPreimage, InstalledRootSet, KeyStateSnapshot, SignatureForm,
    SignerGroup, StandingRootDeclaration,
};

/// The bound on one signer index list and one signature-form list. An index
/// list indexes a root set or a next set, and §9.18.17 caps both, so a list
/// longer than the larger cap repeats an index. Both caps are at most 255,
/// the one-byte index ceiling §9.18.17 states.
const MAX_SIGNER_LIST: u32 = if MAX_ROOT_SET_SIZE > MAX_NEXT_SET_SIZE {
    MAX_ROOT_SET_SIZE
} else {
    MAX_NEXT_SET_SIZE
};

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

/// The event-kind byte (§9.7.4.2 field 1). The one table it is written from.
const fn kind_byte(kind: EventKind) -> u8 {
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

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// The twelve field bytes of a key-event preimage, without the separator
/// (§9.7.4.2 field order and absent-field sentinel).
///
/// # Errors
///
/// [`EncodeError`] where the preimage has no encoding that decodes back to it:
/// a list too long for its count, a signer group count its kind does not
/// name, a field whose value would encode as that field's absent sentinel,
/// or a nonzero `compromised_from` on an entry that is not `Compromised`.
pub fn encode_preimage(preimage: &EventPreimage) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    write_fields(preimage, &mut out)?;
    Ok(out)
}

/// `"SCP-KEL-EVENT-V1:" ‖ encode_preimage(preimage)`: the bytes every
/// signature, digest and identifier derivation reads (§9.7.4.2 R13; spec 25
/// prints these bytes as each vector's preimage).
///
/// # Errors
///
/// As [`encode_preimage`].
pub fn signed_preimage(preimage: &EventPreimage) -> Result<Vec<u8>, EncodeError> {
    let mut out = KEL_EVENT_SEPARATOR.to_vec();
    write_fields(preimage, &mut out)?;
    Ok(out)
}

/// The event digest, `SHA-256(signed_preimage)` (ADR-063; §9.7.4.2).
///
/// # Errors
///
/// As [`encode_preimage`].
pub fn event_digest(preimage: &EventPreimage) -> Result<[u8; 32], EncodeError> {
    Ok(sha256(&[&signed_preimage(preimage)?]))
}

/// The identifier an inception event derives,
/// `SHA-256("SCP-KEL-ID-V1:" ‖ signed_preimage)` (§9.7.4.2 R13;
/// `03-identity.md` §3.1).
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
    let signed = signed_preimage(preimage)?;
    Ok(Identifier::from_bytes(sha256(&[KEL_ID_SEPARATOR, &signed])))
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

fn put_count(out: &mut Vec<u8>, list: ListField, len: usize) -> Result<(), EncodeError> {
    let count = u32::try_from(len).map_err(|_| EncodeError::CountOverflow { list, len })?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn write_fields(preimage: &EventPreimage, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let expected = preimage
        .expected_signer_group_count()
        .ok_or(EncodeError::RootRecoveryWithoutStandingRoot)?;
    if preimage.signer_groups.len() != expected {
        return Err(EncodeError::SignerGroupCount {
            kind: preimage.kind,
            expected,
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
    for group in &preimage.signer_groups {
        put_count(out, ListField::SignerIndices, group.indices.len())?;
        out.extend_from_slice(&group.indices);
    }
    for group in &preimage.signer_groups {
        put_count(out, ListField::SignatureForms, group.forms.len())?;
        out.extend(group.forms.iter().map(|form| form_byte(*form)));
    }

    // Field 8.
    put_count(out, ListField::RevealedKeys, preimage.revealed_keys.len())?;
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
    put_count(out, ListField::Seals, preimage.seals.len())?;
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
            put_count(out, ListField::Commitments, commitment.commitments.len())?;
            for entry in &commitment.commitments {
                out.extend_from_slice(&entry.commitment);
                out.push(entry.custody_type.to_byte());
                out.push(entry.key_algorithm.to_byte());
            }
            out.extend_from_slice(&commitment.next_threshold.to_be_bytes());
        }
    }
    Ok(())
}

fn write_installed_root_set(
    root_set: &InstalledRootSet,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    if root_set.members.is_empty() {
        return Err(EncodeError::EmptyInstalledRootSet);
    }
    put_count(out, ListField::InstalledRootSet, root_set.members.len())?;
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
    put_count(out, ListField::SnapshotKeys, snapshot.keys.len())?;
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
    put_count(out, ListField::Witnesses, snapshot.witnesses.len())?;
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

/// Decodes the twelve field bytes [`encode_preimage`] writes, over an exact
/// slice (§9.7.4.2).
///
/// Every count is checked against its §9.18.17 `MAX_*` and against the bytes
/// remaining before any element is read, and no allocation is sized from a
/// wire count (§9.7.4.2, the count-bound rule). The decoder is structural: a
/// preimage whose fields its kind does not carry, or that breaks any other
/// R3 rule, decodes, and the verifier classifies it. It rejects a nonzero
/// `compromised_from` on an entry that is not `Compromised`, because the
/// snapshot order defines that field as "zero otherwise".
///
/// Field 12's absent sentinel `BE32(0)` and its abandonment byte `0x00` are
/// told apart by where the slice ends, so the slice must hold exactly one
/// preimage.
///
/// # Errors
///
/// [`DecodeError`] naming the field or list where the bytes stop being a
/// preimage.
pub fn decode_preimage(bytes: &[u8]) -> Result<EventPreimage, DecodeError> {
    if u32::try_from(bytes.len()).map_or(true, |len| len > MAX_EVENT_BYTES) {
        return Err(DecodeError::EventTooLong { len: bytes.len() });
    }
    let mut reader = Reader { rest: bytes };

    let kind_value = reader.u8(PreimageField::EventType)?;
    let kind = kind_from_byte(kind_value).ok_or(DecodeError::UnknownEventDiscriminator {
        field: EventDiscriminatorField::EventType,
        value: kind_value,
    })?;
    let identifier = Identifier::from_bytes(reader.array(PreimageField::Identifier)?);
    let sequence = u64::from_be_bytes(reader.array(PreimageField::Sequence)?);
    let predecessor_digest = reader.array(PreimageField::PredecessorDigest)?;
    let standing_root = match reader.u8(PreimageField::StandingRoot)? {
        STANDING_ROOT_ABSENT => None,
        0x01 => Some(StandingRootDeclaration::CoSigns),
        0x02 => Some(StandingRootDeclaration::Lost),
        value => {
            return Err(DecodeError::UnknownEventDiscriminator {
                field: EventDiscriminatorField::StandingRoot,
                value,
            });
        }
    };
    let group_count = match (kind.fixed_signer_group_count(), standing_root) {
        (Some(count), _) => count,
        (None, Some(declaration)) => declaration.signer_group_count(),
        (None, None) => return Err(DecodeError::RootRecoveryWithoutStandingRoot),
    };

    let mut index_lists = Vec::new();
    for _ in 0..group_count {
        let count = reader.count(
            PreimageField::SignerIndices,
            ListField::SignerIndices,
            Some(MAX_SIGNER_LIST),
            1,
        )?;
        index_lists.push(reader.bytes(count, PreimageField::SignerIndices)?.to_vec());
    }
    let mut signer_groups = Vec::new();
    for indices in index_lists {
        let count = reader.count(
            PreimageField::SignatureForms,
            ListField::SignatureForms,
            Some(MAX_SIGNER_LIST),
            1,
        )?;
        let mut forms = Vec::new();
        for &value in reader.bytes(count, PreimageField::SignatureForms)? {
            forms.push(
                form_from_byte(value).ok_or(DecodeError::UnknownEventDiscriminator {
                    field: EventDiscriminatorField::SignatureForm,
                    value,
                })?,
            );
        }
        signer_groups.push(SignerGroup { indices, forms });
    }

    let revealed_keys = reader.points(
        PreimageField::RevealedKeys,
        ListField::RevealedKeys,
        Some(MAX_NEXT_SET_SIZE),
    )?;
    let installed_root_set = read_installed_root_set(&mut reader)?;
    let key_state = read_snapshot(&mut reader)?;
    let seal_count = reader.count(PreimageField::Seals, ListField::Seals, None, DIGEST_BYTES)?;
    let mut seals = Vec::new();
    for _ in 0..seal_count {
        seals.push(reader.array(PreimageField::Seals)?);
    }
    let continuation = read_continuation(&mut reader)?;

    Ok(EventPreimage {
        kind,
        identifier,
        sequence,
        predecessor_digest,
        standing_root,
        signer_groups,
        revealed_keys,
        installed_root_set,
        key_state,
        seals,
        continuation,
    })
}

fn read_installed_root_set(
    reader: &mut Reader<'_>,
) -> Result<Option<InstalledRootSet>, DecodeError> {
    let count = reader.count(
        PreimageField::InstalledRootSet,
        ListField::InstalledRootSet,
        Some(MAX_ROOT_SET_SIZE),
        POINT_BYTES,
    )?;
    if count == 0 {
        // The four-byte sentinel: no members and no threshold.
        return Ok(None);
    }
    let mut members = Vec::new();
    for _ in 0..count {
        members.push(reader.array(PreimageField::InstalledRootSet)?);
    }
    let threshold = u32::from_be_bytes(reader.array(PreimageField::InstalledRootSet)?);
    Ok(Some(InstalledRootSet { members, threshold }))
}

fn read_snapshot(reader: &mut Reader<'_>) -> Result<Option<KeyStateSnapshot>, DecodeError> {
    let field = PreimageField::KeyState;
    // A snapshot begins with its root threshold, so `BE32(0)` there is the
    // whole field's absent sentinel.
    let root_threshold = u32::from_be_bytes(reader.array(field)?);
    if root_threshold == 0 {
        return Ok(None);
    }
    let key_count = reader.count(field, ListField::SnapshotKeys, None, KEY_ENTRY_BYTES)?;
    let mut keys = Vec::new();
    for _ in 0..key_count {
        keys.push(read_key_entry(reader, keys.len())?);
    }
    let witness_count = reader.count(
        field,
        ListField::Witnesses,
        Some(MAX_WITNESS_SET_SIZE),
        DIGEST_BYTES,
    )?;
    let mut witnesses = Vec::new();
    for _ in 0..witness_count {
        witnesses.push(Identifier::from_bytes(reader.array(field)?));
    }
    let witnessing_interval = u32::from_be_bytes(reader.array(field)?);
    let service_key_role =
        discriminator::<KeyRole>(reader, field, DiscriminatorField::ServiceKeyRole)?;
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

fn read_key_entry(reader: &mut Reader<'_>, entry_index: usize) -> Result<KeyEntry, DecodeError> {
    let field = PreimageField::KeyState;
    let key = reader.array(field)?;
    let role = discriminator::<KeyRole>(reader, field, DiscriminatorField::Role)?;
    let condition = discriminator::<KeyCondition>(reader, field, DiscriminatorField::Condition)?;
    let compromised_from = u64::from_be_bytes(reader.array(field)?);
    if condition != KeyCondition::Compromised && compromised_from != 0 {
        return Err(DecodeError::CompromisedFromWithoutCompromise {
            entry: entry_index,
            condition,
            compromised_from,
        });
    }
    let custody_type =
        discriminator::<CustodyType>(reader, field, DiscriminatorField::CustodyType)?;
    let key_algorithm =
        discriminator::<KeyAlgorithm>(reader, field, DiscriminatorField::KeyAlgorithm)?;
    Ok(KeyEntry {
        key,
        role,
        condition,
        compromised_from,
        custody_type,
        key_algorithm,
    })
}

fn read_continuation(reader: &mut Reader<'_>) -> Result<Option<Continuation>, DecodeError> {
    let rest = reader.rest;
    if let Some((sentinel, trailing)) = rest.split_first_chunk::<4>()
        && *sentinel == COMPOSITE_SENTINEL
    {
        return trailing_free(trailing).map(|()| None);
    }
    match rest.split_first() {
        None => Err(DecodeError::Truncated {
            field: PreimageField::Continuation,
        }),
        Some((&CONTINUATION_ABANDONS, trailing)) => {
            // One to three zero bytes are a cut-off sentinel; anything else
            // after the abandonment byte trails it.
            if !trailing.is_empty() && trailing.iter().all(|byte| *byte == 0) {
                return Err(DecodeError::Truncated {
                    field: PreimageField::Continuation,
                });
            }
            trailing_free(trailing).map(|()| Some(Continuation::Abandons))
        }
        Some((&CONTINUATION_FIXES_COMMITMENT, after)) => {
            reader.rest = after;
            let commitment = read_commitment(reader)?;
            trailing_free(reader.rest).map(|()| Some(Continuation::FixesCommitment(commitment)))
        }
        Some((&value, _)) => Err(DecodeError::UnknownEventDiscriminator {
            field: EventDiscriminatorField::Continuation,
            value,
        }),
    }
}

fn read_commitment(reader: &mut Reader<'_>) -> Result<StandingCommitment, DecodeError> {
    let field = PreimageField::Continuation;
    let count = reader.count(
        field,
        ListField::Commitments,
        Some(MAX_NEXT_SET_SIZE),
        COMMITMENT_ENTRY_BYTES,
    )?;
    let mut commitments = Vec::new();
    for _ in 0..count {
        let commitment = reader.array(field)?;
        let custody_type =
            discriminator::<CustodyType>(reader, field, DiscriminatorField::CustodyType)?;
        let key_algorithm =
            discriminator::<KeyAlgorithm>(reader, field, DiscriminatorField::KeyAlgorithm)?;
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

const fn trailing_free(trailing: &[u8]) -> Result<(), DecodeError> {
    if trailing.is_empty() {
        Ok(())
    } else {
        Err(DecodeError::TrailingBytes {
            count: trailing.len(),
        })
    }
}

/// Reads one byte as an `scp_did` name-bound enumeration, naming the field
/// in the error.
fn discriminator<T>(
    reader: &mut Reader<'_>,
    enclosing: PreimageField,
    field: DiscriminatorField,
) -> Result<T, DecodeError>
where
    T: TryFrom<u8, Error = UnknownDiscriminator>,
{
    let value = reader.u8(enclosing)?;
    T::try_from(value).map_err(|source| DecodeError::UnknownDiscriminator { field, source })
}

/// A cursor over the unread bytes.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, len: u32, field: PreimageField) -> Result<&'a [u8], DecodeError> {
        let len = usize::try_from(len).map_err(|_| DecodeError::Truncated { field })?;
        let (taken, rest) = self
            .rest
            .split_at_checked(len)
            .ok_or(DecodeError::Truncated { field })?;
        self.rest = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self, field: PreimageField) -> Result<[u8; N], DecodeError> {
        let (taken, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(DecodeError::Truncated { field })?;
        self.rest = rest;
        Ok(*taken)
    }

    fn u8(&mut self, field: PreimageField) -> Result<u8, DecodeError> {
        let [value] = self.array::<1>(field)?;
        Ok(value)
    }

    /// Reads a 4-byte count and checks it against `max` and against the
    /// bytes left, before the caller reads or allocates any element.
    fn count(
        &mut self,
        field: PreimageField,
        list: ListField,
        max: Option<u32>,
        element_bytes: usize,
    ) -> Result<u32, DecodeError> {
        let count = u32::from_be_bytes(self.array(field)?);
        if let Some(max) = max
            && count > max
        {
            return Err(DecodeError::CountOverMax { list, count, max });
        }
        let remaining = self.rest.len();
        let fits = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(element_bytes))
            .is_some_and(|needed| needed <= remaining);
        if !fits {
            return Err(DecodeError::CountOverRemaining {
                list,
                count,
                remaining,
            });
        }
        Ok(count)
    }

    fn points(
        &mut self,
        field: PreimageField,
        list: ListField,
        max: Option<u32>,
    ) -> Result<Vec<[u8; 33]>, DecodeError> {
        let count = self.count(field, list, max, POINT_BYTES)?;
        let mut points = Vec::new();
        for _ in 0..count {
            points.push(self.array(field)?);
        }
        Ok(points)
    }
}
